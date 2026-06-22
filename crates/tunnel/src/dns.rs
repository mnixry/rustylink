use std::{
    collections::BTreeSet,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use etherparse::{NetSlice, PacketBuilder, SlicedPacket, TransportSlice};
use gotatun::{
    packet::{Ip, Packet, PacketBufPool},
    tun::{IpRecv, IpSend, MtuWatcher},
};
use hickory_proto::op::Message as DnsMessage;
use rustylink_api::VpnConnResponse;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use snafu::prelude::*;
use tokio::{
    net::{UdpSocket, lookup_host},
    task::JoinHandle,
};
use url::{Host, Url};

use crate::{IpTun, OutboundInterface};

const DNS_PORT: u16 = 53;
const DNS_PROXY_PORT: u16 = 2913;
const DNS_RESPONSE_HOP_LIMIT: u8 = 64;
const DNS_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_DNS_PACKET: usize = 4096;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("failed to bind DNS proxy listener at {bind_addr}: {source}"))]
    BindProxy {
        bind_addr: SocketAddr,
        source: io::Error,
    },

    #[snafu(display("no DNS proxy listener started"))]
    NoProxyListener,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct DnsRule {
    pub domain: String,
    pub endpoint: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct DnsHijackPlan {
    pub primary_dns: Option<String>,
    pub backup_dns: Option<String>,
    pub local_dns: Option<String>,
    pub central_dns: Option<String>,
    pub ip_nats: Option<String>,
    pub dynamic_domain_split: Option<String>,
    pub dynamic_domain_split_v6: Option<String>,
    pub dynamic_domain_split_wildcard: Option<String>,
    pub dynamic_suffix_wildcard_domain: Option<String>,
    pub dynamic_domain: Option<String>,
    pub domain_rules: Vec<DnsRule>,
    pub proxy_port: u16,
}

#[derive(Clone)]
pub struct DnsHijacker {
    plan: Arc<DnsHijackPlan>,
    outbound_interface: Option<OutboundInterface>,
}

pub struct DnsProxyRuntime {
    tasks: Vec<JoinHandle<()>>,
}

#[derive(Clone)]
pub struct DnsHijackTun {
    inner: IpTun,
    hijacker: Option<DnsHijacker>,
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

impl DnsHijackPlan {
    #[must_use]
    pub fn from_vpn_conn(conn: &VpnConnResponse) -> Self {
        let primary_dns = clean_string(conn.setting.vpn_dns.clone());
        let backup_dns = clean_string(conn.setting.vpn_dns_backup.clone());
        let central_dns = clean_string(conn.setting.central_dns.clone());
        let ip_nats = clean_string(conn.setting.ip_nats.clone());
        let dynamic_domain_split =
            clean_string(conn.setting.vpn_dynamic_domain_route_split.clone());
        let dynamic_domain_split_v6 =
            clean_string(conn.setting.v6_vpn_dynamic_domain_route_split.clone());
        let dynamic_domain_split_wildcard =
            clean_string(conn.setting.vpn_wildcard_dynamic_domain_route_split.clone());
        let dynamic_suffix_wildcard_domain = clean_string(
            conn.setting
                .suffix_wildcard_dynamic_domain_route_split
                .clone(),
        );
        let dynamic_domain = clean_string(conn.setting.dynamic_domain.clone());

        let mut domains = BTreeSet::new();
        for domain in conn
            .setting
            .vpn_dns_domain_split
            .as_deref()
            .unwrap_or_default()
        {
            add_domain_pattern(&mut domains, domain);
        }
        for raw in [
            dynamic_domain_split.as_deref(),
            dynamic_domain_split_v6.as_deref(),
            dynamic_domain_split_wildcard.as_deref(),
            dynamic_suffix_wildcard_domain.as_deref(),
            dynamic_domain.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            collect_domain_patterns(&mut domains, raw);
        }

        let endpoint = primary_dns
            .clone()
            .or_else(|| backup_dns.clone())
            .unwrap_or_else(|| "127.0.0.1:53".to_string());
        let domain_rules = domains
            .into_iter()
            .map(|domain| DnsRule {
                domain,
                endpoint: endpoint.clone(),
            })
            .collect();

        Self {
            primary_dns,
            backup_dns,
            local_dns: None,
            central_dns,
            ip_nats,
            dynamic_domain_split,
            dynamic_domain_split_v6,
            dynamic_domain_split_wildcard,
            dynamic_suffix_wildcard_domain,
            dynamic_domain,
            domain_rules,
            proxy_port: DNS_PROXY_PORT,
        }
    }

    #[must_use]
    pub fn with_local_dns(mut self, local_dns: Option<String>) -> Self {
        self.local_dns = clean_string(local_dns);
        self
    }

    #[must_use]
    pub fn enabled(&self) -> bool {
        !self.upstreams_for_domain(None).is_empty()
    }

    #[must_use]
    pub fn hijacker(&self, outbound_interface: Option<OutboundInterface>) -> Option<DnsHijacker> {
        self.enabled().then(|| DnsHijacker {
            plan: Arc::new(self.clone()),
            outbound_interface,
        })
    }

    fn upstreams_for_domain(&self, domain: Option<&str>) -> Vec<String> {
        let mut upstreams = Vec::new();
        if domain.is_some_and(|value| self.matches_split_domain(value)) {
            for rule in &self.domain_rules {
                push_dns_endpoints(&mut upstreams, &rule.endpoint);
            }
        } else {
            push_optional_dns_endpoints(&mut upstreams, self.local_dns.as_deref());
        }
        push_optional_dns_endpoints(&mut upstreams, self.primary_dns.as_deref());
        push_optional_dns_endpoints(&mut upstreams, self.backup_dns.as_deref());
        dedupe(upstreams)
    }

    fn matches_split_domain(&self, domain: &str) -> bool {
        let domain = normalize_domain(domain);
        self.domain_rules.iter().any(|rule| {
            let rule_domain = normalize_domain(&rule.domain);
            domain == rule_domain || domain.ends_with(&format!(".{rule_domain}"))
        })
    }
}

impl DnsProxyRuntime {
    pub async fn start(
        plan: &DnsHijackPlan, outbound_interface: Option<OutboundInterface>,
    ) -> Result<Option<Self>> {
        let Some(hijacker) = plan.hijacker(outbound_interface) else {
            tracing::info!("DNS hijack disabled because no DNS upstream was configured");
            return Ok(None);
        };

        let mut tasks = Vec::new();
        let mut last_error = None;
        for bind_addr in [
            SocketAddr::from((Ipv4Addr::LOCALHOST, plan.proxy_port)),
            SocketAddr::from((Ipv6Addr::LOCALHOST, plan.proxy_port)),
        ] {
            match UdpSocket::bind(bind_addr).await {
                Ok(socket) => {
                    tracing::info!(%bind_addr, "started FeiLian-compatible DNS proxy");
                    tasks.push(tokio::spawn(run_dns_proxy(
                        Arc::new(socket),
                        hijacker.clone(),
                    )));
                }
                Err(error) => {
                    tracing::warn!(%bind_addr, %error, "failed to bind DNS proxy listener");
                    last_error = Some((bind_addr, error));
                }
            }
        }

        if tasks.is_empty() {
            return match last_error {
                Some((bind_addr, source)) => Err(Error::BindProxy { bind_addr, source }),
                None => NoProxyListenerSnafu.fail(),
            };
        }
        Ok(Some(Self { tasks }))
    }

    pub fn stop(self) {
        for task in self.tasks {
            task.abort();
        }
    }
}

impl DnsHijackTun {
    #[must_use]
    pub fn new(
        inner: IpTun, plan: &DnsHijackPlan, outbound_interface: Option<OutboundInterface>,
    ) -> Self {
        Self {
            inner,
            hijacker: plan.hijacker(outbound_interface),
        }
    }
}

impl IpSend for DnsHijackTun {
    async fn send(&mut self, packet: Packet<Ip>) -> io::Result<()> {
        self.inner.send(packet).await
    }
}

impl IpRecv for DnsHijackTun {
    async fn recv<'a>(
        &'a mut self, pool: &mut PacketBufPool,
    ) -> io::Result<impl Iterator<Item = Packet<Ip>> + Send + 'a> {
        loop {
            let packets = self.inner.recv(pool).await?.collect::<Vec<_>>();
            let mut forward = Vec::new();
            for packet in packets {
                let raw_packet = packet.into_bytes();
                let Some(hijacker) = self.hijacker.clone() else {
                    forward.push(raw_packet.try_into_ip().map_err(to_io_error)?);
                    continue;
                };
                let Some(query) = DnsWireQuery::from_ip_packet(&raw_packet) else {
                    forward.push(raw_packet.try_into_ip().map_err(to_io_error)?);
                    continue;
                };
                tracing::debug!(
                    source = %query.source,
                    destination = %query.destination,
                    source_port = query.source_port,
                    destination_port = query.destination_port,
                    domain = query.domain.as_deref().unwrap_or("<unknown>"),
                    "DNS hijack triggered for TUN packet"
                );
                let mut tun = self.inner.clone();
                tokio::spawn(async move {
                    match hijacker.resolve_wire_query(query).await {
                        Ok(Some(response)) => {
                            if let Err(error) = tun.send(response).await {
                                tracing::warn!(%error, "failed to write DNS hijack response to TUN");
                            }
                        }
                        Ok(None) => {}
                        Err(error) => tracing::warn!(%error, "DNS hijack query failed"),
                    }
                });
            }
            if !forward.is_empty() {
                return Ok(forward.into_iter());
            }
        }
    }

    fn mtu(&self) -> MtuWatcher {
        self.inner.mtu()
    }
}

impl DnsHijacker {
    async fn resolve_wire_query(&self, query: DnsWireQuery) -> io::Result<Option<Packet<Ip>>> {
        let Some(response_payload) = self
            .resolve_dns_payload(&query.payload, query.domain.as_deref())
            .await?
        else {
            return Ok(None);
        };
        let response = query.response_packet(&response_payload)?;
        let packet = Packet::copy_from(response.as_slice())
            .try_into_ip()
            .map_err(to_io_error)?;
        Ok(Some(packet))
    }

    async fn resolve_dns_payload(
        &self, payload: &[u8], domain_hint: Option<&str>,
    ) -> io::Result<Option<Vec<u8>>> {
        let domain = domain_hint
            .map(ToOwned::to_owned)
            .or_else(|| parse_dns_question_domain(payload));
        let request_payload = normalize_dns_payload(payload)?;
        let upstreams = self.plan.upstreams_for_domain(domain.as_deref());
        if upstreams.is_empty() {
            return Ok(None);
        }
        tracing::trace!(
            domain = domain.as_deref().unwrap_or("<unknown>"),
            upstream_count = upstreams.len(),
            "selected DNS upstreams"
        );

        let mut last_error = None;
        for upstream in upstreams {
            match query_dns_upstream(
                &upstream,
                &request_payload,
                self.outbound_interface.as_ref(),
            )
            .await
            {
                Ok(response) => {
                    tracing::debug!(
                        domain = domain.as_deref().unwrap_or("<unknown>"),
                        upstream,
                        "DNS hijack query resolved"
                    );
                    return Ok(Some(response));
                }
                Err(error) => {
                    tracing::warn!(
                        domain = domain.as_deref().unwrap_or("<unknown>"),
                        upstream,
                        %error,
                        "DNS upstream query failed"
                    );
                    last_error = Some(error);
                }
            }
        }
        Err(last_error
            .unwrap_or_else(|| io::Error::other("DNS query failed without an upstream error")))
    }
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

    fn response_packet(&self, dns_payload: &[u8]) -> io::Result<Vec<u8>> {
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
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "DNS response IP family mismatch",
            )),
        }
    }
}

async fn run_dns_proxy(socket: Arc<UdpSocket>, hijacker: DnsHijacker) {
    let mut buf = [0_u8; MAX_DNS_PACKET];
    loop {
        let (len, peer) = match socket.recv_from(&mut buf).await {
            Ok(value) => value,
            Err(error) => {
                tracing::warn!(%error, "DNS proxy listener stopped");
                return;
            }
        };
        let payload = buf[..len].to_vec();
        let domain = parse_dns_question_domain(&payload);
        tracing::debug!(
            %peer,
            domain = domain.as_deref().unwrap_or("<unknown>"),
            "DNS hijack triggered for proxy query"
        );
        let socket = socket.clone();
        let hijacker = hijacker.clone();
        tokio::spawn(async move {
            match hijacker
                .resolve_dns_payload(&payload, domain.as_deref())
                .await
            {
                Ok(Some(response)) => {
                    if let Err(error) = socket.send_to(&response, peer).await {
                        tracing::warn!(%peer, %error, "failed to send DNS proxy response");
                    }
                }
                Ok(None) => {}
                Err(error) => tracing::warn!(%peer, %error, "DNS proxy query failed"),
            }
        });
    }
}

async fn query_dns_upstream(
    upstream: &str, payload: &[u8], outbound_interface: Option<&OutboundInterface>,
) -> io::Result<Vec<u8>> {
    let addrs = lookup_host(upstream).await?;
    let mut last_error = None;
    for addr in addrs {
        let bind_addr = if addr.is_ipv4() {
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
        } else {
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
        };
        match query_dns_addr(bind_addr, addr, payload, outbound_interface).await {
            Ok(response) => return Ok(response),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            format!("DNS upstream `{upstream}` resolved to no addresses"),
        )
    }))
}

async fn query_dns_addr(
    bind_addr: SocketAddr, upstream: SocketAddr, payload: &[u8],
    outbound_interface: Option<&OutboundInterface>,
) -> io::Result<Vec<u8>> {
    let socket = crate::outbound::bind_udp_socket(bind_addr, outbound_interface)?;
    tracing::trace!(
        %upstream,
        outbound_interface = outbound_interface
            .map_or("<default>", |interface| interface.name.as_str()),
        "sending DNS hijack query to upstream"
    );
    socket.send_to(payload, upstream).await?;
    let mut response = vec![0_u8; MAX_DNS_PACKET];
    let (len, _) = tokio::time::timeout(DNS_TIMEOUT, socket.recv_from(&mut response))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS upstream timed out"))??;
    response.truncate(len);
    normalize_dns_payload(&response)
}

fn build_ipv4_udp_response(
    source: [u8; 4], destination: [u8; 4], source_port: u16, destination_port: u16, payload: &[u8],
) -> io::Result<Vec<u8>> {
    write_udp_packet(
        PacketBuilder::ipv4(source, destination, DNS_RESPONSE_HOP_LIMIT)
            .udp(source_port, destination_port),
        payload,
    )
}

fn build_ipv6_udp_response(
    source: [u8; 16], destination: [u8; 16], source_port: u16, destination_port: u16,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    write_udp_packet(
        PacketBuilder::ipv6(source, destination, DNS_RESPONSE_HOP_LIMIT)
            .udp(source_port, destination_port),
        payload,
    )
}

fn write_udp_packet(
    builder: etherparse::PacketBuilderStep<etherparse::UdpHeader>, payload: &[u8],
) -> io::Result<Vec<u8>> {
    let mut packet = Vec::with_capacity(builder.size(payload.len()));
    builder.write(&mut packet, payload).map_err(to_io_error)?;
    Ok(packet)
}

fn parse_dns_question_domain(payload: &[u8]) -> Option<String> {
    let message = DnsMessage::from_vec(payload).ok()?;
    first_query_domain(&message)
}

fn normalize_dns_payload(payload: &[u8]) -> io::Result<Vec<u8>> {
    let message = DnsMessage::from_vec(payload).map_err(to_io_error)?;
    message.to_vec().map_err(to_io_error)
}

fn first_query_domain(message: &DnsMessage) -> Option<String> {
    message
        .queries
        .first()
        .map(|query| normalize_domain(&query.name().to_ascii()))
}

fn push_optional_dns_endpoints(upstreams: &mut Vec<String>, value: Option<&str>) {
    if let Some(value) = value {
        push_dns_endpoints(upstreams, value);
    }
}

fn push_dns_endpoints(upstreams: &mut Vec<String>, value: &str) {
    for token in split_config_tokens(value) {
        if let Some(endpoint) = dns_endpoint(&token) {
            upstreams.push(endpoint);
        }
    }
}

fn dns_endpoint(value: &str) -> Option<String> {
    let value = value.trim().trim_matches('"').trim_matches('\'');
    if value.is_empty() {
        return None;
    }
    if value.contains("://") {
        return dns_endpoint_from_url(value);
    }
    if value.contains('/') {
        return None;
    }
    if value.parse::<SocketAddr>().is_ok() {
        return Some(value.to_string());
    }
    if let Ok(ip) = value.parse::<IpAddr>() {
        let host = match ip {
            IpAddr::V4(ip) => Host::Ipv4(ip),
            IpAddr::V6(ip) => Host::Ipv6(ip),
        };
        return Some(format_dns_host_port(host, DNS_PORT));
    }
    dns_endpoint_from_url(&format!("dns://{value}")).or_else(|| {
        Host::parse(value)
            .ok()
            .map(|host| format_dns_host_port(host, DNS_PORT))
    })
}

fn dns_endpoint_from_url(value: &str) -> Option<String> {
    let url = Url::parse(value).ok()?;
    if !matches!(url.scheme(), "dns" | "udp") {
        return None;
    }
    if !url.path().is_empty() && url.path() != "/" {
        return None;
    }
    let host = url.host()?.to_owned();
    Some(format_dns_host_port(host, url.port().unwrap_or(DNS_PORT)))
}

fn format_dns_host_port(host: Host<String>, port: u16) -> String {
    match host {
        Host::Domain(domain) => format!("{domain}:{port}"),
        Host::Ipv4(ip) => SocketAddr::from((ip, port)).to_string(),
        Host::Ipv6(ip) => SocketAddr::from((ip, port)).to_string(),
    }
}

fn dedupe(values: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(value.clone()))
        .collect()
}

fn clean_string(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let value = value.trim().to_string();
        (!value.is_empty()).then_some(value)
    })
}

fn collect_domain_patterns(domains: &mut BTreeSet<String>, raw: &str) {
    if let Ok(value) = serde_json::from_str::<Value>(raw) {
        collect_json_domain_patterns(domains, &value);
    } else {
        for token in split_config_tokens(raw) {
            add_domain_pattern(domains, &token);
        }
    }
}

fn collect_json_domain_patterns(domains: &mut BTreeSet<String>, value: &Value) {
    match value {
        Value::String(value) => add_domain_pattern(domains, value),
        Value::Array(values) => {
            for value in values {
                collect_json_domain_patterns(domains, value);
            }
        }
        Value::Object(values) => {
            for value in values.values() {
                collect_json_domain_patterns(domains, value);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

fn add_domain_pattern(domains: &mut BTreeSet<String>, value: &str) {
    let domain = normalize_domain(value);
    if domain.is_empty()
        || domain.contains('/')
        || domain.parse::<IpAddr>().is_ok()
        || domain.parse::<SocketAddr>().is_ok()
    {
        return;
    }
    if domain.contains('.') {
        domains.insert(domain);
    }
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

fn to_io_error(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[cfg(test)]
mod tests {
    use hickory_proto::{
        op::{Message as DnsMessage, MessageType, OpCode, Query},
        rr::{Name, RecordType},
    };

    use super::{dns_endpoint, normalize_domain, parse_dns_question_domain};

    #[test]
    fn normalizes_dns_upstreams() {
        assert_eq!(dns_endpoint("8.8.8.8"), Some("8.8.8.8:53".to_string()));
        assert_eq!(
            dns_endpoint("2001:4860:4860::8888"),
            Some("[2001:4860:4860::8888]:53".to_string())
        );
        assert_eq!(
            dns_endpoint("dns.example:5353"),
            Some("dns.example:5353".to_string())
        );
        assert_eq!(
            dns_endpoint("udp://8.8.8.8:5353"),
            Some("8.8.8.8:5353".to_string())
        );
        assert_eq!(
            dns_endpoint("dns://[2001:4860:4860::8888]:5353"),
            Some("[2001:4860:4860::8888]:5353".to_string())
        );
        assert_eq!(dns_endpoint("https://dns.example/dns-query"), None);
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
