//! DNS hijacking on the TUN path.
//!
//! [`VpnTun`] is the gotatun TUN device (merging the old `IpTun` + hijacker):
//! it forwards normal IP packets and intercepts UDP/53, handing the query to a
//! [`DnsResolver`]. The resolver routes each query over one of two pluggable
//! [`DnsQueryTransport`]s — **routed** (bound to the TUN, reaches the VPN
//! resolver through the tunnel, used for intranet / full-tunnel) or
//! **directed** (bound to the physical outbound interface, reaches the system
//! resolver directly, used for public split-tunnel names) — and always returns
//! a DNS response (the upstream answer, or a synthesized `SERVFAIL`).

use std::{
    collections::BTreeSet,
    io, iter,
    net::{IpAddr, Ipv4Addr, SocketAddr},
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
    op::{Message as DnsMessage, MessageType, OpCode, Query, ResponseCode},
    rr::{Name, RecordType},
};
use rustylink_api::VpnConnResponse;
use rustylink_outbound::Dialer;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use snafu::prelude::*;
use tokio::net::lookup_host;
use url::{Host, Url};
use wildmatch::WildMatch;

const DNS_PORT: u16 = 53;
const DNS_RESPONSE_HOP_LIMIT: u8 = 64;
const DNS_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_DNS_PACKET: usize = 4096;
/// Used for directed (public) resolution when the OS exposes no system
/// resolver.
const DEFAULT_SYSTEM_DNS: IpAddr = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));

/// Errors raised while hijacking and forwarding DNS over the TUN path.
///
/// Socket failures keep their originating [`std::io::Error`] as `source`. The
/// gotatun [`IpRecv`] / [`IpSend`] adapters require [`std::io::Result`], so
/// [`From<Error>`] for [`std::io::Error`] re-wraps these (preserving the snafu
/// source chain) at that boundary.
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

    #[snafu(display("failed to resolve DNS server `{server}`: {source}"))]
    ResolveServer { server: String, source: io::Error },

    #[snafu(display("DNS server `{server}` resolved to no usable address"))]
    NoServerAddress { server: String },

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

/// Parsed, serializable DNS configuration carried in [`crate::TunnelConfig`].
///
/// Built once from the `/vpn/conn` response (plus optional local DNS override)
/// and consumed by [`DnsResolver::build`] at session start.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct DnsHijackPlan {
    /// `host:port` VPN resolver endpoints, de-duplicated, used by the routed
    /// (intranet) transport.
    pub vpn_servers: Vec<String>,
    /// Normalized lowercase domain patterns; each matches both `domain` and
    /// `*.domain` and routes the query through the VPN resolver.
    pub split_domains: Vec<String>,
}

impl DnsHijackPlan {
    #[must_use]
    pub fn from_vpn_conn(conn: &VpnConnResponse, local_dns: Option<&str>) -> Self {
        let setting = &conn.setting;
        let vpn_servers = collect_vpn_servers([
            local_dns,
            setting.vpn_dns.as_deref(),
            setting.vpn_dns_backup.as_deref(),
        ]);
        let mut split_domains = BTreeSet::new();
        if let Some(list) = setting.vpn_dns_domain_split.as_deref() {
            for raw in list {
                accept_domain(raw, &mut split_domains);
            }
        }
        for raw in [
            setting.vpn_dynamic_domain_route_split.as_deref(),
            setting.v6_vpn_dynamic_domain_route_split.as_deref(),
            setting.vpn_wildcard_dynamic_domain_route_split.as_deref(),
            setting
                .suffix_wildcard_dynamic_domain_route_split
                .as_deref(),
            setting.dynamic_domain.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            extract_domains(raw, &mut split_domains);
        }
        Self {
            vpn_servers,
            split_domains: split_domains.into_iter().collect(),
        }
    }
}

/// Sends a DNS wire query to an upstream and returns the wire response. A trait
/// so non-UDP transports can be added later.
#[async_trait]
pub trait DnsQueryTransport: Send + Sync {
    async fn query(&self, server: SocketAddr, request: &[u8]) -> Result<Vec<u8>>;
}

/// UDP DNS transport bound to a fixed interface via `IP_BOUND_IF`. Two are
/// used: **directed** (physical outbound interface) and **routed** (TUN
/// interface).
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

/// Routes DNS queries to the VPN resolver (routed) or the system resolver
/// (directed) by rule, and always yields a DNS response.
pub struct DnsResolver {
    full_tunnel: bool,
    vpn_servers: Vec<String>,
    /// Pre-extracted IPs of the VPN resolver(s). Used by [`VpnTun`] to skip
    /// hijacking the routed transport's own forwarding traffic (which would
    /// otherwise re-enter the TUN and loop indefinitely).
    vpn_dns_ips: Vec<IpAddr>,
    system_servers: Vec<String>,
    matchers: Vec<WildMatch>,
    directed: Arc<dyn DnsQueryTransport>,
    routed: Arc<dyn DnsQueryTransport>,
}

impl DnsResolver {
    /// Build the resolver. Returns `None` (hijack disabled) when the VPN
    /// provided no resolver. `system_servers` is read once via
    /// [`system_dns_servers`] so the same set can also be host-routed into
    /// the tunnel (split mode).
    #[must_use]
    pub fn build(
        plan: &DnsHijackPlan, full_tunnel: bool, system_servers: &[IpAddr],
        directed: Arc<dyn DnsQueryTransport>, routed: Arc<dyn DnsQueryTransport>,
    ) -> Option<Self> {
        if plan.vpn_servers.is_empty() {
            tracing::info!("DNS hijack disabled: VPN provided no resolver");
            return None;
        }
        let vpn_dns_ips = plan
            .vpn_servers
            .iter()
            .filter_map(|server| server.parse::<SocketAddr>().ok().map(|addr| addr.ip()))
            .collect();
        let system_servers = system_servers
            .iter()
            .map(|ip| SocketAddr::new(*ip, DNS_PORT).to_string())
            .collect();
        let matchers = plan
            .split_domains
            .iter()
            .flat_map(|domain| {
                [
                    WildMatch::new(domain),
                    WildMatch::new(&format!("*.{domain}")),
                ]
            })
            .collect();
        Some(Self {
            full_tunnel,
            vpn_servers: plan.vpn_servers.clone(),
            vpn_dns_ips,
            system_servers,
            matchers,
            directed,
            routed,
        })
    }

    /// Resolve a hijacked query, always returning a DNS wire response (the
    /// upstream answer, or a synthesized `SERVFAIL`).
    async fn resolve(&self, query: &DnsWireQuery) -> Vec<u8> {
        let domain = query
            .domain
            .clone()
            .or_else(|| parse_dns_question_domain(&query.payload));
        let routed = self.full_tunnel
            || domain
                .as_deref()
                .is_some_and(|value| self.matches_split_domain(value));
        let (transport, servers, route) = if routed {
            (self.routed.as_ref(), &self.vpn_servers, "routed")
        } else {
            (self.directed.as_ref(), &self.system_servers, "directed")
        };
        let name = domain.as_deref().unwrap_or("<unknown>");

        let start = Instant::now();
        for server in servers {
            match query_server(transport, server, &query.payload).await {
                Ok(response) => {
                    tracing::debug!(
                        domain = name,
                        route,
                        %server,
                        rtt_ms = start.elapsed().as_millis(),
                        rcode = ?response_code(&response),
                        "DNS resolved"
                    );
                    return response;
                }
                Err(error) => {
                    tracing::warn!(domain = name, route, %server, %error, "DNS upstream failed");
                }
            }
        }
        tracing::warn!(
            domain = name,
            route,
            "DNS resolution failed; returning SERVFAIL"
        );
        synthesize_failure(&query.payload, ResponseCode::ServFail)
    }

    fn matches_split_domain(&self, domain: &str) -> bool {
        let domain = normalize_domain(domain);
        self.matchers.iter().any(|matcher| matcher.matches(&domain))
    }
}

/// Read the host's configured system DNS servers (via `hickory-resolver`'s
/// system config). Falls back to a public default if none are configured.
#[must_use]
pub fn system_dns_servers() -> Vec<IpAddr> {
    let servers = match hickory_resolver::system_conf::read_system_conf() {
        Ok((config, _opts)) => {
            let mut seen = BTreeSet::new();
            config
                .name_servers()
                .iter()
                .map(|server| server.ip)
                .filter(|ip| seen.insert(*ip))
                .collect::<Vec<_>>()
        }
        Err(error) => {
            tracing::warn!(%error, "failed to read system DNS config");
            Vec::new()
        }
    };
    if servers.is_empty() {
        tracing::warn!(default = %DEFAULT_SYSTEM_DNS, "no system DNS servers; using default");
        vec![DEFAULT_SYSTEM_DNS]
    } else {
        servers
    }
}

/// Probe interval. A constant DNS query is sent through the routed transport
/// every tick; the first one also triggers gotatun's lazy `WireGuard`
/// handshake (gotatun has no force-handshake API and only handshakes when an
/// outbound TUN packet asks for the first transport).
const PROBE_INTERVAL: Duration = Duration::from_secs(3);

/// Active-liveness probe owned by the [`crate::TunnelSession`].
///
/// Sends a constant `localhost. IN A` query through the routed (TUN-pinned)
/// transport every [`PROBE_INTERVAL`]. Any reply updates `last_rx`, which the
/// supervisor reads via `TunnelSession::last_probe_rx_elapsed` to detect a
/// stalled tunnel (no probe traffic returning).
pub struct LivenessProbe {
    last_rx: Arc<Mutex<Option<Instant>>>,
    handle: tokio::task::JoinHandle<()>,
}

impl LivenessProbe {
    #[must_use]
    pub fn start(routed: Arc<dyn DnsQueryTransport>, servers: Vec<String>) -> Self {
        let last_rx = Arc::new(Mutex::new(None));
        let handle = tokio::spawn(run_probe(routed, servers, last_rx.clone()));
        Self { last_rx, handle }
    }

    /// Elapsed time since the most recent probe reply. `None` if no probe has
    /// yet succeeded (initial-connect window).
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex is poisoned (i.e. the probe task itself
    /// panicked while holding it — a programming error).
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
    routed: Arc<dyn DnsQueryTransport>, servers: Vec<String>, last_rx: Arc<Mutex<Option<Instant>>>,
) {
    let query = liveness_probe_query();
    let mut tick = tokio::time::interval(PROBE_INTERVAL);
    loop {
        tick.tick().await;
        for server in &servers {
            match query_server(routed.as_ref(), server, &query).await {
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

/// Pre-encoded `localhost. IN A` query payload — constant across probes so the
/// VPN DNS sees an obviously synthetic request (NXDOMAIN/NOERROR both count as
/// liveness).
fn liveness_probe_query() -> Vec<u8> {
    let mut message = DnsMessage::new(0, MessageType::Query, OpCode::Query);
    message.add_query(Query::query(
        Name::from_ascii("localhost.").expect("static name"),
        RecordType::A,
    ));
    message.to_vec().expect("static probe message serializes")
}

async fn query_server(
    transport: &dyn DnsQueryTransport, server: &str, request: &[u8],
) -> Result<Vec<u8>> {
    let mut last_error = None;
    for addr in lookup_host(server)
        .await
        .context(ResolveServerSnafu { server })?
    {
        match transport.query(addr, request).await {
            Ok(response) => return Ok(response),
            Err(error) => last_error = Some(error),
        }
    }
    last_error.map_or_else(|| NoServerAddressSnafu { server }.fail(), Err)
}

/// The TUN device, merging the basic gotatun adapter with the DNS hijacker.
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

            if let Some(resolver) = self.resolver.clone()
                && let Some(query) = DnsWireQuery::from_ip_packet(&packet)
                && !resolver.vpn_dns_ips.contains(&query.destination)
            {
                let device = self.device.clone();
                tokio::spawn(async move {
                    let response = resolver.resolve(&query).await;
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

#[derive(Clone, Debug)]
struct DnsWireQuery {
    source: IpAddr,
    destination: IpAddr,
    source_port: u16,
    destination_port: u16,
    payload: Vec<u8>,
    domain: Option<String>,
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
            domain: parse_dns_question_domain(&payload),
            payload,
        })
    }

    fn response_packet(&self, dns_payload: &[u8]) -> Result<Vec<u8>> {
        match (self.source, self.destination) {
            (IpAddr::V4(source), IpAddr::V4(destination)) => build_ipv4_udp_response(
                destination.octets(),
                source.octets(),
                self.destination_port,
                self.source_port,
                dns_payload,
            ),
            (IpAddr::V6(source), IpAddr::V6(destination)) => build_ipv6_udp_response(
                destination.octets(),
                source.octets(),
                self.destination_port,
                self.source_port,
                dns_payload,
            ),
            _ => AddressFamilyMismatchSnafu.fail(),
        }
    }
}

fn build_ipv4_udp_response(
    source: [u8; 4], destination: [u8; 4], source_port: u16, destination_port: u16, payload: &[u8],
) -> Result<Vec<u8>> {
    write_udp_packet(
        PacketBuilder::ipv4(source, destination, DNS_RESPONSE_HOP_LIMIT)
            .udp(source_port, destination_port),
        payload,
    )
}

fn build_ipv6_udp_response(
    source: [u8; 16], destination: [u8; 16], source_port: u16, destination_port: u16,
    payload: &[u8],
) -> Result<Vec<u8>> {
    write_udp_packet(
        PacketBuilder::ipv6(source, destination, DNS_RESPONSE_HOP_LIMIT)
            .udp(source_port, destination_port),
        payload,
    )
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

fn parse_dns_question_domain(payload: &[u8]) -> Option<String> {
    let message = DnsMessage::from_vec(payload).ok()?;
    first_query_domain(&message)
}

fn first_query_domain(message: &DnsMessage) -> Option<String> {
    message
        .queries
        .first()
        .map(|query| normalize_domain(&query.name().to_ascii()))
}

fn response_code(payload: &[u8]) -> ResponseCode {
    DnsMessage::from_vec(payload).map_or(ResponseCode::ServFail, |message| {
        message.metadata.response_code
    })
}

/// Turn a query into a response with the given code (e.g. `SERVFAIL`).
fn synthesize_failure(query_payload: &[u8], code: ResponseCode) -> Vec<u8> {
    match DnsMessage::from_vec(query_payload) {
        Ok(mut message) => {
            message.metadata.message_type = MessageType::Response;
            message.metadata.response_code = code;
            message.metadata.recursion_available = true;
            message.to_vec().unwrap_or_else(|_| query_payload.to_vec())
        }
        Err(_) => query_payload.to_vec(),
    }
}

/// Parse VPN DNS resolver endpoints from a set of free-form config values
/// (`vpn_dns`/`vpn_dns_backup`/local override). Each value may be a single
/// `host[:port]` token, a `dns://` or `udp://` URL, or a comma/semicolon/
/// whitespace-separated list of those. Returns de-duplicated `host:port`
/// strings ready for [`tokio::net::lookup_host`].
fn collect_vpn_servers<const N: usize>(sources: [Option<&str>; N]) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut servers = Vec::new();
    for raw in sources.into_iter().flatten() {
        for token in split_config_tokens(raw) {
            if let Some(endpoint) = parse_dns_endpoint(&token)
                && seen.insert(endpoint.clone())
            {
                servers.push(endpoint);
            }
        }
    }
    servers
}

/// Parse a single token into a `host:port` DNS endpoint, accepting bare IPs,
/// `socket_addr`, hostnames, and `dns://` / `udp://` URLs. Returns `None` for
/// path-bearing URLs (e.g. `DoH`) or non-DNS schemes.
fn parse_dns_endpoint(value: &str) -> Option<String> {
    let value = value.trim().trim_matches('"').trim_matches('\'');
    if value.is_empty() || value.contains('/') && !value.contains("://") {
        return None;
    }
    if value.parse::<SocketAddr>().is_ok() {
        return Some(value.to_owned());
    }
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, DNS_PORT).to_string());
    }
    let url = if value.contains("://") {
        Url::parse(value).ok()?
    } else {
        Url::parse(&format!("dns://{value}")).ok()?
    };
    if !matches!(url.scheme(), "dns" | "udp") || !matches!(url.path(), "" | "/") {
        return None;
    }
    let port = url.port().unwrap_or(DNS_PORT);
    Some(match url.host()? {
        Host::Domain(domain) => format!("{domain}:{port}"),
        Host::Ipv4(ip) => SocketAddr::from((ip, port)).to_string(),
        Host::Ipv6(ip) => SocketAddr::from((ip, port)).to_string(),
    })
}

/// Extract split-tunnel domain patterns from a config value that may itself be
/// JSON (string / array / object of strings) or a comma/semicolon-separated
/// list. Accepts entries that look like real domains and rejects IPs, CIDRs,
/// and host:port forms.
fn extract_domains(raw: &str, out: &mut BTreeSet<String>) {
    if let Ok(value) = serde_json::from_str::<Value>(raw) {
        walk_json_for_domains(&value, out);
    } else {
        for token in split_config_tokens(raw) {
            accept_domain(&token, out);
        }
    }
}

fn walk_json_for_domains(value: &Value, out: &mut BTreeSet<String>) {
    match value {
        Value::String(value) => accept_domain(value, out),
        Value::Array(values) => values.iter().for_each(|v| walk_json_for_domains(v, out)),
        Value::Object(values) => values.values().for_each(|v| walk_json_for_domains(v, out)),
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn accept_domain(value: &str, out: &mut BTreeSet<String>) {
    let domain = normalize_domain(value);
    if domain.is_empty()
        || domain.contains('/')
        || !domain.contains('.')
        || domain.parse::<IpAddr>().is_ok()
        || domain.parse::<SocketAddr>().is_ok()
    {
        return;
    }
    out.insert(domain);
}

fn normalize_domain(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim_start_matches("*.")
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_lowercase()
}

fn split_config_tokens(value: &str) -> impl Iterator<Item = String> + '_ {
    value
        .split(|ch: char| ch == ';' || ch == ',' || ch.is_whitespace())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use hickory_proto::{
        op::{Message as DnsMessage, MessageType, OpCode, Query},
        rr::{Name, RecordType},
    };

    use super::{normalize_domain, parse_dns_endpoint, parse_dns_question_domain};

    #[test]
    fn normalizes_dns_upstreams() {
        assert_eq!(
            parse_dns_endpoint("8.8.8.8"),
            Some("8.8.8.8:53".to_string())
        );
        assert_eq!(
            parse_dns_endpoint("2001:4860:4860::8888"),
            Some("[2001:4860:4860::8888]:53".to_string())
        );
        assert_eq!(
            parse_dns_endpoint("dns.example:5353"),
            Some("dns.example:5353".to_string())
        );
        assert_eq!(
            parse_dns_endpoint("udp://8.8.8.8:5353"),
            Some("8.8.8.8:5353".to_string())
        );
        assert_eq!(parse_dns_endpoint("https://dns.example/dns-query"), None);
    }

    #[test]
    fn normalizes_domain_patterns() {
        assert_eq!(normalize_domain("*.Example.COM."), "example.com");
    }

    #[test]
    fn parses_dns_question_domain() {
        let mut message = DnsMessage::new(1, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(
            Name::from_ascii("example.com.").unwrap(),
            RecordType::A,
        ));
        let payload = message.to_vec().unwrap();
        assert_eq!(
            parse_dns_question_domain(&payload),
            Some("example.com".to_string())
        );
    }
}
