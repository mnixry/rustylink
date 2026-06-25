//! DNS hijacking on the TUN path.
//!
//! [`VpnTun`] is the gotatun TUN device (merging the old `IpTun` + hijacker):
//! it forwards normal IP packets and intercepts UDP/53, handing the query to a
//! [`DnsResolver`]. The resolver first tries to **synthesize** an answer from
//! the dynamic-domain answer tables ([`DnsConfig::synthesize`]); failing that
//! it routes the query over one of two pluggable [`DnsQueryTransport`]s —
//! **routed** (bound to the TUN, reaches the VPN resolver through the tunnel,
//! used for intranet / full-tunnel) or **directed** (bound to the physical
//! outbound interface, reaches the system resolver directly, used for public
//! split-tunnel names) — and always returns a DNS response (the upstream
//! answer, a synthesized answer, or a synthesized `SERVFAIL`).
//!
//! Config parsing is split into two phases. [`DnsConfig::from_vpn_conn`] is
//! sync and network-free: it compiles split-domain matchers and the
//! dynamic-domain tables from the `/vpn/conn` response. [`DnsResolver::build`]
//! runs at session start and binds the (pre-resolved) upstreams to the two
//! transports.

use std::{
    collections::{BTreeSet, HashMap},
    io, iter,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
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
    rr::{Name, RData, Record, RecordType},
};
use rustylink_api::{CentralDns, IpNat, VpnConnResponse};
use rustylink_outbound::Dialer;
use snafu::prelude::*;
use tokio::net::lookup_host;
use url::{Host, Url};
use wildmatch::WildMatch;

const DNS_PORT: u16 = 53;
const DNS_RESPONSE_HOP_LIMIT: u8 = 64;
const DNS_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_DNS_PACKET: usize = 4096;
/// TTL (seconds) for records synthesized from the dynamic-domain answer tables.
/// Matches the native client's dynamic-domain answer TTL.
const DYNAMIC_TTL: u32 = 3600;
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

/// Dynamic-domain answer tables (the native client's first three DNS lookup
/// layers).
///
/// A query whose name hits one of these tables is answered locally from the
/// table's IP values rather than forwarded upstream. Exact tables are genuine
/// keyed lookups (`HashMap`); wildcard/suffix tables are scanned linearly, so
/// they are `Vec<(pattern, answers)>` — a `HashMap` would buy nothing when
/// every entry is visited.
#[derive(Clone, Debug, Default)]
pub struct DynamicDomainTables {
    /// `dynamic_domain` + `vpn_dynamic_domain_route_split` → A answers.
    exact_v4: HashMap<String, Vec<String>>,
    /// `v6_vpn_dynamic_domain_route_split` → AAAA answers.
    exact_v6: HashMap<String, Vec<String>>,
    /// `vpn_wildcard_dynamic_domain_route_split` → A answers (linear scan).
    wildcard_v4: Vec<(String, Vec<String>)>,
    /// `suffix_wildcard_dynamic_domain_route_split` → A answers (linear scan).
    suffix_v4: Vec<(String, Vec<String>)>,
}

impl DynamicDomainTables {
    /// IPv4 answer values for `name`: exact table, then wildcard, then suffix
    /// pattern lists. A pattern matches `name` exactly or as a parent domain
    /// (`name` ends with `.pattern`).
    fn lookup_v4(&self, name: &str) -> Option<&[String]> {
        if let Some(values) = self.exact_v4.get(name) {
            return Some(values);
        }
        for table in [&self.wildcard_v4, &self.suffix_v4] {
            if let Some((_, values)) = table.iter().find(|(pattern, _)| {
                !pattern.is_empty()
                    && (name == pattern.as_str() || name.ends_with(&format!(".{pattern}")))
            }) {
                return Some(values);
            }
        }
        None
    }

    /// IPv6 answer values for `name` (exact table only — there are no v6
    /// wildcard/suffix fields).
    fn lookup_v6(&self, name: &str) -> Option<&[String]> {
        self.exact_v6.get(name).map(Vec::as_slice)
    }

    fn is_empty(&self) -> bool {
        self.exact_v4.is_empty()
            && self.exact_v6.is_empty()
            && self.wildcard_v4.is_empty()
            && self.suffix_v4.is_empty()
    }
}

/// Parsed DNS configuration from `/vpn/conn`.
///
/// Holds no transports and performs no network I/O: built once (sync) by
/// [`DnsConfig::from_vpn_conn`] and consumed by [`DnsResolver::build`] at
/// session start. The matching/synthesis methods are pure so they can be
/// unit-tested without sockets.
#[derive(Clone, Debug)]
pub struct DnsConfig {
    /// True in full-tunnel mode (all queries route through the VPN resolver).
    full_tunnel: bool,
    /// `host:port` VPN resolver endpoints; resolved to addresses at session
    /// start by [`DnsConfig::resolve_vpn_servers`].
    vpn_servers: Vec<String>,
    /// Compiled split-domain matchers (layer 6): each split domain yields a
    /// matcher for `domain` and one for `*.domain`.
    split_matchers: Vec<WildMatch>,
    /// Dynamic-domain answer tables (layers 1-3).
    dynamic: DynamicDomainTables,
    /// `central_dns` DNAT policy (parsed; matching deferred).
    central_dns: Option<CentralDns>,
    /// `ip_nats` NAT route-match rules (parsed; rewriting deferred).
    ip_nats: Vec<IpNat>,
}

impl DnsConfig {
    /// Parse the DNS configuration from a `/vpn/conn` response. Sync and
    /// network-free.
    #[must_use]
    pub fn from_vpn_conn(
        conn: &VpnConnResponse, local_dns: Option<&str>, full_tunnel: bool,
    ) -> Self {
        let setting = &conn.setting;
        let vpn_servers = collect_vpn_servers([
            local_dns,
            setting.vpn_dns.as_deref(),
            setting.vpn_dns_backup.as_deref(),
        ]);

        // Layer 6: split-domain routing list.
        let mut split = BTreeSet::new();
        if let Some(list) = setting.vpn_dns_domain_split.as_deref() {
            for raw in list {
                accept_domain(raw, &mut split);
            }
        }
        let split_matchers = split
            .iter()
            .flat_map(|domain| {
                [
                    WildMatch::new(domain),
                    WildMatch::new(&format!("*.{domain}")),
                ]
            })
            .collect();

        // Layers 1-3: dynamic-domain answer tables. The top-level
        // `dynamic_domain` and `vpn_dynamic_domain_route_split` both feed the
        // exact IPv4 table.
        let mut exact_v4: HashMap<String, Vec<String>> = HashMap::new();
        for (domain, values) in normalized_entries(setting.dynamic_domain.as_ref()).chain(
            normalized_entries(setting.vpn_dynamic_domain_route_split.as_ref()),
        ) {
            exact_v4.entry(domain).or_default().extend(values);
        }
        let dynamic = DynamicDomainTables {
            exact_v4,
            exact_v6: normalized_entries(setting.v6_vpn_dynamic_domain_route_split.as_ref())
                .collect(),
            wildcard_v4: normalized_entries(
                setting.vpn_wildcard_dynamic_domain_route_split.as_ref(),
            )
            .collect(),
            suffix_v4: normalized_entries(
                setting.suffix_wildcard_dynamic_domain_route_split.as_ref(),
            )
            .collect(),
        };

        Self {
            full_tunnel,
            vpn_servers,
            split_matchers,
            dynamic,
            central_dns: setting.central_dns.clone(),
            ip_nats: setting.ip_nats.clone().unwrap_or_default(),
        }
    }

    /// True when no resolver endpoints were provided (DNS hijack disabled).
    #[must_use]
    pub fn is_hijack_disabled(&self) -> bool {
        self.vpn_servers.is_empty()
    }

    /// Number of compiled split-domain matchers (for logging).
    #[must_use]
    pub fn split_matcher_count(&self) -> usize {
        self.split_matchers.len()
    }

    /// Parsed `central_dns` DNAT policy, if any.
    ///
    /// Currently informational only: the bloom-filter DNS matching path it
    /// describes is not implemented (see [`DnsResolver::resolve`]).
    #[must_use]
    pub fn central_dns(&self) -> Option<&CentralDns> {
        self.central_dns.as_ref()
    }

    /// Parsed `ip_nats` NAT route-match rules.
    ///
    /// Currently informational only: IP-NAT rewriting is not implemented (see
    /// [`DnsResolver::resolve`]).
    #[must_use]
    pub fn ip_nats(&self) -> &[IpNat] {
        &self.ip_nats
    }

    /// Resolve the `host:port` VPN resolver endpoints to concrete socket
    /// addresses, once, at session start. Unresolvable specs are logged and
    /// skipped; results are de-duplicated.
    pub async fn resolve_vpn_servers(&self) -> Vec<SocketAddr> {
        let mut seen = BTreeSet::new();
        let mut servers = Vec::new();
        for spec in &self.vpn_servers {
            match lookup_host(spec).await {
                Ok(addrs) => {
                    for addr in addrs {
                        if seen.insert(addr) {
                            servers.push(addr);
                        }
                    }
                }
                Err(error) => {
                    tracing::warn!(%spec, %error, "failed to resolve DNS server");
                }
            }
        }
        servers
    }

    /// Layers 1-3: try to answer `query` locally from the dynamic-domain answer
    /// tables. Returns the synthesized DNS wire response, or `None` to fall
    /// through to the forward path. Pure (no network).
    fn synthesize(&self, query: &DnsWireQuery) -> Option<Vec<u8>> {
        if self.dynamic.is_empty() {
            return None;
        }
        let request = DnsMessage::from_vec(&query.payload).ok()?;
        let question = request.queries.first()?;
        let name = normalize_domain(&question.name().to_ascii());
        if name.is_empty() {
            return None;
        }
        match question.query_type() {
            RecordType::A => {
                let qname = question.name().clone();
                let answers: Vec<Record> = self
                    .dynamic
                    .lookup_v4(&name)?
                    .iter()
                    .filter_map(|value| value_token(value).parse::<Ipv4Addr>().ok())
                    .map(|ip| Record::from_rdata(qname.clone(), DYNAMIC_TTL, RData::A(ip.into())))
                    .collect();
                if answers.is_empty() {
                    return None;
                }
                build_response(&request, answers)
            }
            RecordType::AAAA => match self.dynamic.lookup_v6(&name) {
                Some(values) => {
                    let qname = question.name().clone();
                    let answers: Vec<Record> = values
                        .iter()
                        .filter_map(|value| value_token(value).parse::<Ipv6Addr>().ok())
                        .map(|ip| {
                            Record::from_rdata(qname.clone(), DYNAMIC_TTL, RData::AAAA(ip.into()))
                        })
                        .collect();
                    build_response(&request, answers)
                }
                // Domain is managed for IPv4 only: suppress AAAA with an empty
                // NOERROR (NODATA) answer so the client falls back to the
                // synthesized A record (matches the native client).
                None if self.dynamic.lookup_v4(&name).is_some() => {
                    build_response(&request, Vec::new())
                }
                None => None,
            },
            _ => None,
        }
    }

    /// Layer 6: should `domain` route through the VPN resolver (routed) rather
    /// than the system resolver (directed)? Full-tunnel forces routed.
    fn route_through_vpn(&self, domain: Option<&str>) -> bool {
        self.full_tunnel || domain.is_some_and(|domain| self.matches_split(domain))
    }

    fn matches_split(&self, domain: &str) -> bool {
        let domain = normalize_domain(domain);
        self.split_matchers
            .iter()
            .any(|matcher| matcher.matches(&domain))
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

/// Routes DNS queries to a synthesized answer (dynamic-domain tables), the VPN
/// resolver (routed), or the system resolver (directed), and always yields a
/// DNS response.
pub struct DnsResolver {
    config: DnsConfig,
    /// Pre-resolved VPN resolver endpoints (routed transport).
    vpn_servers: Vec<SocketAddr>,
    /// Pre-resolved system resolver endpoints (directed transport).
    system_servers: Vec<SocketAddr>,
    /// IPs of the VPN resolver(s). Used by [`VpnTun`] to skip hijacking the
    /// routed transport's own forwarding traffic (which would otherwise
    /// re-enter the TUN and loop indefinitely).
    vpn_dns_ips: Vec<IpAddr>,
    directed: Arc<dyn DnsQueryTransport>,
    routed: Arc<dyn DnsQueryTransport>,
}

impl DnsResolver {
    /// Build the resolver from a parsed [`DnsConfig`] and the pre-resolved
    /// upstreams. Returns `None` (hijack disabled) when the VPN provided no
    /// resolver. `vpn_servers` is resolved once by
    /// [`DnsConfig::resolve_vpn_servers`]; `system_servers` is read once via
    /// [`system_dns_servers`] (so the same set can be host-routed into the
    /// tunnel in split mode).
    #[must_use]
    pub fn build(
        config: DnsConfig, vpn_servers: Vec<SocketAddr>, system_servers: &[IpAddr],
        directed: Arc<dyn DnsQueryTransport>, routed: Arc<dyn DnsQueryTransport>,
    ) -> Option<Self> {
        if config.is_hijack_disabled() {
            tracing::info!("DNS hijack disabled: VPN provided no resolver");
            return None;
        }
        let vpn_dns_ips = vpn_servers.iter().map(SocketAddr::ip).collect();
        let system_servers = system_servers
            .iter()
            .map(|ip| SocketAddr::new(*ip, DNS_PORT))
            .collect();
        Some(Self {
            config,
            vpn_servers,
            system_servers,
            vpn_dns_ips,
            directed,
            routed,
        })
    }

    /// Resolve a hijacked query, always returning a DNS wire response (a
    /// synthesized answer, the upstream answer, or a synthesized `SERVFAIL`).
    ///
    /// DNAT is intentionally not applied here. The native client matches a DNS
    /// query against the bloom filters carried in `central_dns` and rewrites
    /// the response's A records to the translation target IP picked from
    /// `ip_nats`. Both fields are parsed into [`DnsConfig`] but unused until
    /// that path is implemented. See `docs/vpn-dns-dnat-behavior.md`.
    async fn resolve(&self, query: &DnsWireQuery) -> Vec<u8> {
        // Layers 1-3: synthesize from the dynamic-domain answer tables.
        if let Some(answer) = self.config.synthesize(query) {
            tracing::debug!(
                domain = query.domain.as_deref().unwrap_or("<unknown>"),
                "DNS answered from dynamic-domain table"
            );
            return answer;
        }

        // Layer 6: forward to the routed (VPN) or directed (system) resolver.
        let domain = query.domain.as_deref();
        let (transport, servers, route) = if self.config.route_through_vpn(domain) {
            (self.routed.as_ref(), &self.vpn_servers, "routed")
        } else {
            (self.directed.as_ref(), &self.system_servers, "directed")
        };
        let name = domain.unwrap_or("<unknown>");

        let start = Instant::now();
        for &server in servers {
            match transport.query(server, &query.payload).await {
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
    pub fn start(routed: Arc<dyn DnsQueryTransport>, servers: Vec<SocketAddr>) -> Self {
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

/// The leading `/`-delimited token of a dynamic-table value (the address part).
fn value_token(value: &str) -> &str {
    value.split('/').next().unwrap_or(value).trim()
}

/// Turn a parsed query [`DnsMessage`] into a NOERROR response carrying
/// `answers` (an empty `answers` yields a NODATA response).
fn build_response(request: &DnsMessage, answers: Vec<Record>) -> Option<Vec<u8>> {
    let mut response = request.clone();
    response.metadata.message_type = MessageType::Response;
    response.metadata.response_code = ResponseCode::NoError;
    response.metadata.recursion_available = true;
    for record in answers {
        response.add_answer(record);
    }
    response.to_vec().ok()
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

/// Yield `(domain, values)` pairs from a typed answer table with each domain
/// key normalized (lowercased, `*.`/dots trimmed). Empty keys are skipped.
fn normalized_entries(
    map: Option<&HashMap<String, Vec<String>>>,
) -> impl Iterator<Item = (String, Vec<String>)> + '_ {
    map.into_iter().flatten().filter_map(|(key, values)| {
        let domain = normalize_domain(key);
        (!domain.is_empty()).then(|| (domain, values.clone()))
    })
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
    use std::collections::HashMap;

    use hickory_proto::{
        op::{Message as DnsMessage, MessageType, OpCode, Query, ResponseCode},
        rr::{Name, RData, RecordType},
    };
    use rustylink_api::{CentralDns, IpNat, VpnConnResponse, models::vpn::VpnConnSetting};

    use super::{
        DYNAMIC_TTL, DnsConfig, DnsWireQuery, normalize_domain, parse_dns_endpoint,
        parse_dns_question_domain,
    };

    fn map(pairs: &[(&str, &[&str])]) -> HashMap<String, Vec<String>> {
        pairs
            .iter()
            .map(|(key, values)| {
                (
                    (*key).to_string(),
                    values.iter().map(|v| (*v).to_string()).collect(),
                )
            })
            .collect()
    }

    fn setting() -> VpnConnSetting {
        VpnConnSetting {
            vpn_mtu: 1400,
            vpn_dns: Some("10.0.0.53".to_string()),
            vpn_dns_backup: None,
            vpn_dns_domain_split: None,
            vpn_route_full: None,
            vpn_route_split: None,
            v6_route_full: None,
            v6_route_split: None,
            vpn_dynamic_domain_route_split: None,
            v6_vpn_dynamic_domain_route_split: None,
            vpn_wildcard_dynamic_domain_route_split: None,
            suffix_wildcard_dynamic_domain_route_split: None,
            dynamic_domain: None,
            central_dns: None,
            ip_nats: None,
        }
    }

    fn conn(setting: VpnConnSetting) -> VpnConnResponse {
        VpnConnResponse {
            ip: "10.0.0.2".to_string(),
            ipv6: None,
            ip_mask: Some(24),
            public_key: "server-public-key".to_string(),
            preshared_key: None,
            sign_token: None,
            protocol_version: None,
            setting,
            raw: None,
        }
    }

    fn query_payload(name: &str, record_type: RecordType) -> Vec<u8> {
        let mut message = DnsMessage::new(0x1234, MessageType::Query, OpCode::Query);
        message.add_query(Query::query(
            Name::from_ascii(name).expect("valid name"),
            record_type,
        ));
        message.to_vec().expect("serialize query")
    }

    fn wire_query(name: &str, record_type: RecordType) -> DnsWireQuery {
        DnsWireQuery {
            source: "10.0.0.2".parse().unwrap(),
            destination: "10.0.0.53".parse().unwrap(),
            source_port: 40000,
            destination_port: 53,
            domain: Some(normalize_domain(name)),
            payload: query_payload(name, record_type),
        }
    }

    fn answers(payload: &[u8]) -> Vec<RData> {
        DnsMessage::from_vec(payload)
            .expect("decode response")
            .answers
            .iter()
            .map(|record| record.data.clone())
            .collect()
    }

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
        let payload = query_payload("example.com.", RecordType::A);
        assert_eq!(
            parse_dns_question_domain(&payload),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn dynamic_fields_do_not_leak_into_split_matchers() {
        let mut s = setting();
        s.vpn_dynamic_domain_route_split = Some(map(&[("intranet.corp", &["10.1.2.3"])]));
        s.central_dns = Some(CentralDns {
            tenant_id: "t".to_string(),
            dns: vec!["10.0.0.9".to_string()],
            ..CentralDns::default()
        });
        s.ip_nats = Some(vec![IpNat {
            ips: vec!["10.0.0.0/8".to_string()],
            nat_ip: "100.64.0.1".to_string(),
            ..IpNat::default()
        }]);
        let config = DnsConfig::from_vpn_conn(&conn(s), None, false);
        // The dynamic domain must not become a split matcher.
        assert!(!config.matches_split("intranet.corp"));
        // It must be answered from the dynamic table instead.
        assert!(
            config
                .synthesize(&wire_query("intranet.corp.", RecordType::A))
                .is_some()
        );
    }

    #[test]
    fn parses_central_dns_and_ip_nats() {
        let mut s = setting();
        s.central_dns = Some(CentralDns {
            tenant_id: "tenant-1".to_string(),
            dnat_ip: "100.64.0.1".to_string(),
            dns: vec!["10.0.0.9".to_string()],
            ..CentralDns::default()
        });
        s.ip_nats = Some(vec![IpNat {
            ips: vec!["10.0.0.0/8".to_string(), "172.16.0.0/12".to_string()],
            is_default_nat: true,
            nat_ip: "100.64.0.1".to_string(),
        }]);
        let config = DnsConfig::from_vpn_conn(&conn(s), None, false);
        let central = config.central_dns.expect("central_dns parsed");
        assert_eq!(central.tenant_id, "tenant-1");
        assert_eq!(central.dnat_ip, "100.64.0.1");
        assert_eq!(config.ip_nats.len(), 1);
        assert_eq!(config.ip_nats[0].ips.len(), 2);
        assert!(config.ip_nats[0].is_default_nat);
        assert_eq!(config.ip_nats[0].nat_ip, "100.64.0.1");
    }

    #[test]
    fn synthesizes_exact_a_record_with_dynamic_ttl() {
        let mut s = setting();
        s.dynamic_domain = Some(map(&[("git.corp", &["10.9.9.9"])]));
        let config = DnsConfig::from_vpn_conn(&conn(s), None, false);
        let payload = config
            .synthesize(&wire_query("git.corp.", RecordType::A))
            .expect("synthesized");
        let message = DnsMessage::from_vec(&payload).unwrap();
        assert_eq!(message.metadata.message_type, MessageType::Response);
        assert_eq!(message.metadata.response_code, ResponseCode::NoError);
        let records = message.answers;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].ttl, DYNAMIC_TTL);
        assert_eq!(
            records[0].data.clone(),
            RData::A("10.9.9.9".parse().unwrap())
        );
    }

    #[test]
    fn synthesizes_wildcard_and_suffix_matches() {
        let mut s = setting();
        s.vpn_wildcard_dynamic_domain_route_split = Some(map(&[("*.wild.corp", &["10.1.1.1"])]));
        s.suffix_wildcard_dynamic_domain_route_split = Some(map(&[("suffix.corp", &["10.2.2.2"])]));
        let config = DnsConfig::from_vpn_conn(&conn(s), None, false);

        let wild = config
            .synthesize(&wire_query("host.wild.corp.", RecordType::A))
            .expect("wildcard synthesized");
        assert_eq!(answers(&wild), vec![RData::A("10.1.1.1".parse().unwrap())]);

        let suffix = config
            .synthesize(&wire_query("deep.host.suffix.corp.", RecordType::A))
            .expect("suffix synthesized");
        assert_eq!(
            answers(&suffix),
            vec![RData::A("10.2.2.2".parse().unwrap())]
        );
    }

    #[test]
    fn aaaa_for_v4_only_domain_returns_nodata() {
        let mut s = setting();
        s.vpn_dynamic_domain_route_split = Some(map(&[("v4only.corp", &["10.3.3.3"])]));
        let config = DnsConfig::from_vpn_conn(&conn(s), None, false);
        let payload = config
            .synthesize(&wire_query("v4only.corp.", RecordType::AAAA))
            .expect("nodata response");
        let message = DnsMessage::from_vec(&payload).unwrap();
        assert_eq!(message.metadata.message_type, MessageType::Response);
        assert_eq!(message.metadata.response_code, ResponseCode::NoError);
        assert!(message.answers.is_empty());
    }

    #[test]
    fn synthesizes_aaaa_from_v6_table() {
        let mut s = setting();
        s.v6_vpn_dynamic_domain_route_split = Some(map(&[("v6.corp", &["fd00::1"])]));
        let config = DnsConfig::from_vpn_conn(&conn(s), None, false);
        let payload = config
            .synthesize(&wire_query("v6.corp.", RecordType::AAAA))
            .expect("aaaa synthesized");
        assert_eq!(
            answers(&payload),
            vec![RData::AAAA("fd00::1".parse().unwrap())]
        );
    }

    #[test]
    fn unmatched_domain_is_not_synthesized() {
        let mut s = setting();
        s.dynamic_domain = Some(map(&[("git.corp", &["10.9.9.9"])]));
        let config = DnsConfig::from_vpn_conn(&conn(s), None, false);
        assert!(
            config
                .synthesize(&wire_query("example.com.", RecordType::A))
                .is_none()
        );
    }

    #[test]
    fn split_matchers_route_through_vpn() {
        let mut s = setting();
        s.vpn_dns_domain_split = Some(vec!["corp.example".to_string()]);
        let config = DnsConfig::from_vpn_conn(&conn(s), None, false);
        assert!(config.route_through_vpn(Some("corp.example")));
        assert!(config.route_through_vpn(Some("host.corp.example")));
        assert!(!config.route_through_vpn(Some("example.com")));
        assert!(!config.route_through_vpn(None));
    }

    #[test]
    fn full_tunnel_routes_everything_through_vpn() {
        let config = DnsConfig::from_vpn_conn(&conn(setting()), None, true);
        assert!(config.route_through_vpn(Some("anything.example")));
        assert!(config.route_through_vpn(None));
    }
}
