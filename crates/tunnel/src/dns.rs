//! DNS hijacking on the TUN path + liveness probe.
//!
//! [`VpnTun`] intercepts UDP/53 packets from the TUN device and resolves them
//! through the [`DnsResolver`](rustylink_dns::DnsResolver) in the `dns` crate.
//! The resolver handles synthesis, routing rules, and parallel upstream
//! forwarding. [`LivenessProbe`] sends periodic queries through the routed
//! transport to trigger `WireGuard` handshakes and detect stalled tunnels.

use std::{
    io, iter,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use etherparse::{NetSlice, PacketBuilder, SlicedPacket, TransportSlice};
use gotatun::{
    packet::{Ip, Packet, PacketBufPool},
    tun::{IpRecv, IpSend, MtuWatcher},
};
use hickory_proto::{
    op::{Message as DnsMessage, MessageType, OpCode, Query},
    rr::{Name, RecordType},
};
use rustylink_dns::DnsResolver;
use rustylink_outbound::Dialer;
use snafu::prelude::*;

const DNS_PORT: u16 = 53;
const DNS_RESPONSE_HOP_LIMIT: u8 = 64;
const DNS_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_DNS_PACKET: usize = 4096;

/// Errors raised by the TUN device adapter.
#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("failed to bind DNS query socket: {source}"))]
    BindSocket {
        source: rustylink_outbound::DialerError,
    },

    #[snafu(display("failed to send DNS query to `{server}`: {source}"))]
    SendQuery {
        server: SocketAddr,
        source: io::Error,
    },

    #[snafu(display("failed to receive DNS reply from `{server}`: {source}"))]
    RecvReply {
        server: SocketAddr,
        source: io::Error,
    },

    #[snafu(display("DNS query to `{server}` timed out"))]
    QueryTimeout { server: SocketAddr },

    #[snafu(display("failed to build DNS response packet: {source}"))]
    BuildResponse {
        source: etherparse::err::packet::BuildWriteError,
    },

    #[snafu(display("DNS response IP family mismatch"))]
    AddressFamilyMismatch,

    #[snafu(display("malformed IP packet from TUN: {reason}"))]
    InvalidIpPacket { reason: String },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

impl From<Error> for io::Error {
    fn from(error: Error) -> Self {
        Self::other(error)
    }
}

// ---------------------------------------------------------------------------
// DNS query transport (kept for LivenessProbe)
// ---------------------------------------------------------------------------

/// Sends a DNS wire query to an upstream and returns the wire response.
#[async_trait]
pub trait DnsQueryTransport: Send + Sync {
    async fn query(&self, server: SocketAddr, request: &[u8]) -> Result<Vec<u8>>;
}

/// UDP DNS transport bound to a fixed interface via the `Dialer`.
#[derive(Clone, Debug)]
pub struct UdpDnsTransport {
    dialer: Dialer,
}

impl UdpDnsTransport {
    #[must_use]
    pub fn new(dialer: Dialer) -> Self {
        Self { dialer }
    }
}

#[async_trait]
impl DnsQueryTransport for UdpDnsTransport {
    async fn query(&self, server: SocketAddr, request: &[u8]) -> Result<Vec<u8>> {
        let socket = self.dialer.bind_udp_to(server).context(BindSocketSnafu)?;
        socket
            .send_to(request, server)
            .await
            .context(SendQuerySnafu { server })?;
        let mut response = vec![0_u8; MAX_DNS_PACKET];
        let (len, _) = tokio::time::timeout(DNS_TIMEOUT, socket.recv_from(&mut response))
            .await
            .map_err(|_| QueryTimeoutSnafu { server }.build())?
            .context(RecvReplySnafu { server })?;
        response.truncate(len);
        Ok(response)
    }
}

// ---------------------------------------------------------------------------
// Liveness probe
// ---------------------------------------------------------------------------

const PROBE_INTERVAL: Duration = Duration::from_secs(3);

/// Active-liveness probe owned by the [`crate::TunnelSession`].
pub struct LivenessProbe {
    last_rx: Arc<Mutex<Option<Instant>>>,
    handle: tokio::task::JoinHandle<()>,
}

impl LivenessProbe {
    #[must_use]
    pub fn start(routed: Arc<dyn DnsQueryTransport>, servers: Vec<SocketAddr>) -> Self {
        let last_rx = Arc::new(Mutex::new(None));
        let handle = tokio::spawn(run_probe(routed, servers, last_rx.clone()));
        Self { last_rx, handle }
    }

    /// Elapsed time since the most recent probe reply.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned.
    #[must_use]
    pub fn last_rx_elapsed(&self) -> Option<Duration> {
        let now = Instant::now();
        self.last_rx
            .lock()
            .expect("liveness probe state lock poisoned")
            .map(|rx| now.saturating_duration_since(rx))
    }
}

impl Drop for LivenessProbe {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

async fn run_probe(
    routed: Arc<dyn DnsQueryTransport>, servers: Vec<SocketAddr>,
    last_rx: Arc<Mutex<Option<Instant>>>,
) {
    let query = liveness_probe_query();
    let mut tick = tokio::time::interval(PROBE_INTERVAL);
    loop {
        tick.tick().await;
        for &server in &servers {
            match routed.query(server, &query).await {
                Ok(_) => {
                    *last_rx.lock().expect("liveness probe state lock poisoned") =
                        Some(Instant::now());
                    break;
                }
                Err(error) => {
                    tracing::debug!(%server, %error, "liveness probe attempt failed");
                }
            }
        }
    }
}

fn liveness_probe_query() -> Vec<u8> {
    let mut message = DnsMessage::new(0, MessageType::Query, OpCode::Query);
    message.add_query(Query::query(
        Name::from_ascii("localhost.").expect("static name"),
        RecordType::A,
    ));
    message.to_vec().expect("static probe message serializes")
}

// ---------------------------------------------------------------------------
// VpnTun — TUN device wrapper with DNS hijacking
// ---------------------------------------------------------------------------

/// The TUN device, merged with the DNS hijacker.
///
/// Intercepts UDP/53 packets, resolves them through the [`DnsResolver`] in the
/// dns crate, and injects the response back into the TUN. Non-DNS packets pass
/// through to `WireGuard`.
#[derive(Clone)]
pub struct VpnTun {
    device: Arc<tun_rs::AsyncDevice>,
    name: String,
    mtu: MtuWatcher,
    resolver: Option<Arc<DnsResolver>>,
}

impl VpnTun {
    pub fn new(
        device: tun_rs::AsyncDevice, resolver: Option<Arc<DnsResolver>>,
    ) -> io::Result<Self> {
        let name = device.name()?;
        let mtu = MtuWatcher::new(device.mtu()?);
        Ok(Self {
            device: Arc::new(device),
            name,
            mtu,
            resolver,
        })
    }

    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl IpSend for VpnTun {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        self.device.send(&packet.into_bytes()).await?;
        Ok(())
    }
}

impl IpRecv for VpnTun {
    async fn recv<'a>(
        &'a mut self, pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        loop {
            let mut packet = pool.get();
            let len = self.device.recv(&mut packet).await?;
            packet.truncate(len);

            // DNS hijack: intercept UDP:53, resolve, inject response.
            if let Some(resolver) = self.resolver.clone()
                && let Some(query) = DnsWireQuery::from_ip_packet(&packet)
                && !resolver.vpn_dns_ips().contains(&query.destination)
            {
                let device = self.device.clone();
                tokio::spawn(async move {
                    let response = resolver.resolve(&query.payload).await;
                    match query.response_packet(&response) {
                        Ok(bytes) => {
                            if let Err(error) = device.send(&bytes).await {
                                tracing::warn!(%error, "failed to write DNS response to TUN");
                            }
                        }
                        Err(error) => tracing::warn!(%error, "failed to build DNS response packet"),
                    }
                });
                continue;
            }

            let packet = packet.try_into_ip().map_err(|error| {
                InvalidIpPacketSnafu {
                    reason: error.to_string(),
                }
                .build()
            })?;
            return Ok(iter::once(packet));
        }
    }

    fn mtu(&self) -> MtuWatcher {
        self.mtu.clone()
    }
}

// ---------------------------------------------------------------------------
// DNS wire query parsing + response packet building
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct DnsWireQuery {
    source: IpAddr,
    destination: IpAddr,
    source_port: u16,
    destination_port: u16,
    payload: Vec<u8>,
}

impl DnsWireQuery {
    fn from_ip_packet(packet: &[u8]) -> Option<Self> {
        let sliced = SlicedPacket::from_ip(packet).ok()?;
        let TransportSlice::Udp(udp) = sliced.transport? else {
            return None;
        };
        let destination_port = udp.destination_port();
        if destination_port != DNS_PORT {
            return None;
        }
        let (source, destination) = match sliced.net? {
            NetSlice::Ipv4(ipv4) => (
                IpAddr::V4(ipv4.header().source_addr()),
                IpAddr::V4(ipv4.header().destination_addr()),
            ),
            NetSlice::Ipv6(ipv6) => (
                IpAddr::V6(ipv6.header().source_addr()),
                IpAddr::V6(ipv6.header().destination_addr()),
            ),
            NetSlice::Arp(_) => return None,
        };
        let payload = udp.payload().to_vec();
        Some(Self {
            source,
            destination,
            source_port: udp.source_port(),
            destination_port,
            payload,
        })
    }

    fn response_packet(&self, dns_payload: &[u8]) -> Result<Vec<u8>> {
        match (self.source, self.destination) {
            (IpAddr::V4(source), IpAddr::V4(destination)) => {
                let builder = PacketBuilder::ipv4(
                    destination.octets(),
                    source.octets(),
                    DNS_RESPONSE_HOP_LIMIT,
                )
                .udp(self.destination_port, self.source_port);
                write_udp_packet(builder, dns_payload)
            }
            (IpAddr::V6(source), IpAddr::V6(destination)) => {
                let builder = PacketBuilder::ipv6(
                    destination.octets(),
                    source.octets(),
                    DNS_RESPONSE_HOP_LIMIT,
                )
                .udp(self.destination_port, self.source_port);
                write_udp_packet(builder, dns_payload)
            }
            _ => AddressFamilyMismatchSnafu.fail(),
        }
    }
}

fn write_udp_packet(
    builder: etherparse::PacketBuilderStep<etherparse::UdpHeader>, payload: &[u8],
) -> Result<Vec<u8>> {
    let mut packet = Vec::with_capacity(builder.size(payload.len()));
    builder
        .write(&mut packet, payload)
        .context(BuildResponseSnafu)?;
    Ok(packet)
}
