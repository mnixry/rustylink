//! Optional UDP DNS server — binds to a configurable address, delegates
//! resolution to [`DnsResolver`].

use std::{io, net::SocketAddr, sync::Arc};

use snafu::prelude::*;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use crate::resolver::DnsResolver;

const MAX_DNS_PACKET: usize = 4096;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed to bind DNS server to {address}: {source}"))]
    Bind {
        address: SocketAddr,
        source: io::Error,
    },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// A running DNS server instance. Shares the same [`DnsResolver`] as the
/// TUN hijack path.
pub struct DnsServer {
    shutdown: CancellationToken,
    handle_v4: Option<tokio::task::JoinHandle<()>>,
    handle_v6: Option<tokio::task::JoinHandle<()>>,
}

impl DnsServer {
    /// Start the DNS server on the given IPv4 and IPv6 addresses.
    pub fn start(
        bind_v4: SocketAddr, bind_v6: SocketAddr, resolver: Arc<DnsResolver>,
    ) -> Result<Self> {
        let socket_v4 = bind_udp(bind_v4)?;
        let socket_v6 = bind_udp(bind_v6)?;

        tracing::info!(%bind_v4, %bind_v6, "DNS server started");

        let shutdown = CancellationToken::new();

        let handle_v4 = tokio::spawn(serve_loop(socket_v4, resolver.clone(), shutdown.clone()));
        let handle_v6 = tokio::spawn(serve_loop(socket_v6, resolver, shutdown.clone()));

        Ok(Self {
            shutdown,
            handle_v4: Some(handle_v4),
            handle_v6: Some(handle_v6),
        })
    }

    /// Gracefully stop the DNS server.
    pub async fn shutdown(mut self) {
        self.shutdown.cancel();
        if let Some(h) = self.handle_v4.take() {
            let _ = h.await;
        }
        if let Some(h) = self.handle_v6.take() {
            let _ = h.await;
        }
        tracing::info!("DNS server stopped");
    }
}

impl Drop for DnsServer {
    fn drop(&mut self) {
        self.shutdown.cancel();
        if let Some(h) = self.handle_v4.take() {
            h.abort();
        }
        if let Some(h) = self.handle_v6.take() {
            h.abort();
        }
    }
}

fn bind_udp(addr: SocketAddr) -> Result<UdpSocket> {
    let socket = socket2::Socket::new(
        if addr.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        },
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .context(BindSnafu { address: addr })?;
    socket
        .set_reuse_address(true)
        .context(BindSnafu { address: addr })?;
    if addr.is_ipv6() {
        socket
            .set_only_v6(true)
            .context(BindSnafu { address: addr })?;
    }
    socket
        .set_nonblocking(true)
        .context(BindSnafu { address: addr })?;
    socket
        .bind(&addr.into())
        .context(BindSnafu { address: addr })?;
    UdpSocket::from_std(socket.into()).context(BindSnafu { address: addr })
}

/// Main receive loop for a single socket.
async fn serve_loop(socket: UdpSocket, resolver: Arc<DnsResolver>, shutdown: CancellationToken) {
    let socket = Arc::new(socket);
    loop {
        let mut buf = vec![0u8; MAX_DNS_PACKET];
        let (len, client) = tokio::select! {
            () = shutdown.cancelled() => break,
            result = socket.recv_from(&mut buf) => {
                match result {
                    Ok(pair) => pair,
                    Err(error) => {
                        tracing::warn!(%error, "DNS server recv failed");
                        continue;
                    }
                }
            }
        };
        buf.truncate(len);

        let resolver = resolver.clone();
        let socket = socket.clone();
        tokio::spawn(async move {
            let response = resolver.resolve(&buf).await;
            if let Err(error) = socket.send_to(&response, client).await {
                tracing::warn!(%client, %error, "DNS server send failed");
            }
        });
    }
}
