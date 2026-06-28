//! Parallel upstream DNS query — fan out to all servers, return the fastest.

use std::{io, net::SocketAddr, time::Duration};

use rustylink_outbound::Dialer;
use snafu::prelude::*;
use tokio::net::UdpSocket;

/// Timeout for a single upstream DNS query.
const DNS_TIMEOUT: Duration = Duration::from_secs(3);
/// Maximum UDP DNS response size.
const MAX_DNS_PACKET: usize = 4096;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed to bind UDP socket for query to {server}: {source}"))]
    BindSocket {
        server: SocketAddr,
        source: io::Error,
    },

    #[snafu(display("failed to bind directed UDP socket for query to {server}: {source}"))]
    BindDirected {
        server: SocketAddr,
        source: rustylink_outbound::DialerError,
    },

    #[snafu(display("DNS send to {server} failed: {source}"))]
    Send {
        server: SocketAddr,
        source: io::Error,
    },

    #[snafu(display("DNS recv from {server} failed: {source}"))]
    Recv {
        server: SocketAddr,
        source: io::Error,
    },

    #[snafu(display("DNS query to {server} timed out"))]
    Timeout { server: SocketAddr },

    #[snafu(display("all DNS servers failed for query"))]
    AllFailed,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Query a single upstream server and return the response.
async fn query_single(socket: UdpSocket, server: SocketAddr, request: &[u8]) -> Result<Vec<u8>> {
    socket
        .send_to(request, server)
        .await
        .context(SendSnafu { server })?;
    let mut response = vec![0_u8; MAX_DNS_PACKET];
    let (len, _) = tokio::time::timeout(DNS_TIMEOUT, socket.recv_from(&mut response))
        .await
        .map_err(|_| TimeoutSnafu { server }.build())?
        .context(RecvSnafu { server })?;
    response.truncate(len);
    Ok(response)
}

/// Pick an unspecified bind address matching the server's address family.
fn unspecified_bind_addr(server: SocketAddr) -> SocketAddr {
    if server.is_ipv4() {
        SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0))
    }
}

/// Query all `servers` in parallel (routed path — regular sockets, OS routes
/// through TUN). Returns the first successful response.
pub async fn parallel_query_routed(servers: &[SocketAddr], request: &[u8]) -> Result<Vec<u8>> {
    if servers.is_empty() {
        return AllFailedSnafu.fail();
    }
    if servers.len() == 1 {
        let server = servers[0];
        let bind_addr = unspecified_bind_addr(server);
        let socket = UdpSocket::bind(bind_addr)
            .await
            .context(BindSocketSnafu { server })?;
        return query_single(socket, server, request).await;
    }

    // Fan out to all servers and take the first Ok.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<Vec<u8>>>(servers.len());
    for &server in servers {
        let tx = tx.clone();
        let request = request.to_vec();
        tokio::spawn(async move {
            let bind_addr = unspecified_bind_addr(server);
            let result = match UdpSocket::bind(bind_addr).await {
                Ok(socket) => query_single(socket, server, &request).await,
                Err(source) => Err(Error::BindSocket { server, source }),
            };
            let _ = tx.send(result).await;
        });
    }
    drop(tx);

    while let Some(result) = rx.recv().await {
        if let Ok(response) = result {
            return Ok(response);
        }
    }
    AllFailedSnafu.fail()
}

/// Query all `servers` in parallel (non-routed path — sockets bound to the
/// physical outbound interface via the `Dialer`). Returns the first successful
/// response.
pub async fn parallel_query_directed(
    servers: &[SocketAddr], request: &[u8], dialer: &Dialer,
) -> Result<Vec<u8>> {
    if servers.is_empty() {
        return AllFailedSnafu.fail();
    }
    if servers.len() == 1 {
        let server = servers[0];
        let socket = dialer
            .bind_udp_to(server)
            .context(BindDirectedSnafu { server })?;
        return query_single(socket, server, request).await;
    }

    let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<Vec<u8>>>(servers.len());
    for &server in servers {
        let tx = tx.clone();
        let request = request.to_vec();
        let dialer = dialer.clone();
        tokio::spawn(async move {
            let result = match dialer.bind_udp_to(server) {
                Ok(socket) => query_single(socket, server, &request).await,
                Err(source) => Err(Error::BindDirected { server, source }),
            };
            let _ = tx.send(result).await;
        });
    }
    drop(tx);

    while let Some(result) = rx.recv().await {
        if let Ok(response) = result {
            return Ok(response);
        }
    }
    AllFailedSnafu.fail()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use tokio::net::UdpSocket;

    use super::*;

    /// Spawn a mock DNS server that replies with a fixed response.
    async fn mock_server(response: &[u8]) -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        let response = response.to_vec();
        tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_DNS_PACKET];
            let (len, src) = socket.recv_from(&mut buf).await.unwrap();
            let _ = len;
            socket.send_to(&response, src).await.unwrap();
        });
        addr
    }

    /// Spawn a mock DNS server that never replies (simulates timeout).
    async fn slow_server() -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();
        tokio::spawn(async move {
            // Hold socket open but never respond.
            let mut buf = vec![0u8; MAX_DNS_PACKET];
            let _ = socket.recv_from(&mut buf).await;
            tokio::time::sleep(Duration::from_mins(1)).await;
        });
        addr
    }

    #[tokio::test]
    async fn single_server_success() {
        let server = mock_server(b"ok-response").await;
        let result = parallel_query_routed(&[server], b"query").await;
        assert_eq!(result.unwrap(), b"ok-response");
    }

    #[tokio::test]
    async fn parallel_picks_fastest() {
        let fast = mock_server(b"fast-reply").await;
        let slow = slow_server().await;
        let result = parallel_query_routed(&[slow, fast], b"query").await;
        assert_eq!(result.unwrap(), b"fast-reply");
    }

    #[tokio::test]
    async fn all_servers_timeout_returns_all_failed() {
        let s1 = slow_server().await;
        let result = parallel_query_routed(&[s1], b"query").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn empty_servers_returns_all_failed() {
        let result = parallel_query_routed(&[], b"query").await;
        assert!(result.is_err());
    }
}
