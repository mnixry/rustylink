use std::{
    collections::BTreeSet,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use gotatun::{
    packet::{Ip, Packet, PacketBufPool},
    tun::{IpRecv, IpSend, MtuWatcher, tun_async_device::TunDevice},
};
use rustylink_api::VpnConnResponse;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{
    net::{UdpSocket, lookup_host},
    task::JoinHandle,
};

const DNS_PORT: u16 = 53;
const DNS_PROXY_PORT: u16 = 2913;
const DNS_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_DNS_PACKET: usize = 4096;

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
}

pub struct DnsProxyRuntime {
    tasks: Vec<JoinHandle<()>>,
}

#[derive(Clone)]
pub struct DnsHijackTun {
    inner: TunDevice,
    hijacker: Option<DnsHijacker>,
}

#[derive(Clone, Debug)]
struct DnsWireQuery {
    family: IpFamily,
    source: IpAddr,
    destination: IpAddr,
    source_port: u16,
    destination_port: u16,
    payload: Vec<u8>,
    domain: Option<String>,
}

#[derive(Clone, Copy, Debug)]
enum IpFamily {
    V4,
    V6,
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
        for domain in &conn.setting.vpn_dns_domain_split {
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
    pub fn hijacker(&self) -> Option<DnsHijacker> {
        self.enabled().then(|| DnsHijacker {
            plan: Arc::new(self.clone()),
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
    pub async fn start(plan: &DnsHijackPlan) -> io::Result<Option<Self>> {
        let Some(hijacker) = plan.hijacker() else {
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
                    last_error = Some(error);
                }
            }
        }

        if tasks.is_empty() {
            return Err(last_error.unwrap_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "no DNS proxy listener started",
                )
            }));
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
    pub fn new(inner: TunDevice, plan: &DnsHijackPlan) -> Self {
        Self {
            inner,
            hijacker: plan.hijacker(),
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
        let upstreams = self.plan.upstreams_for_domain(domain.as_deref());
        if upstreams.is_empty() {
            return Ok(None);
        }

        let mut last_error = None;
        for upstream in upstreams {
            match query_dns_upstream(&upstream, payload).await {
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
        match packet.first()? >> 4 {
            4 => Self::from_ipv4_packet(packet),
            6 => Self::from_ipv6_packet(packet),
            _ => None,
        }
    }

    fn from_ipv4_packet(packet: &[u8]) -> Option<Self> {
        if packet.len() < 28 || packet[9] != 17 {
            return None;
        }
        let ihl = usize::from(packet[0] & 0x0F) * 4;
        if ihl < 20 || packet.len() < ihl + 8 {
            return None;
        }
        let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
        if total_len < ihl + 8 || total_len > packet.len() {
            return None;
        }
        let udp = &packet[ihl..total_len];
        let source_port = u16::from_be_bytes([udp[0], udp[1]]);
        let destination_port = u16::from_be_bytes([udp[2], udp[3]]);
        if destination_port != DNS_PORT {
            return None;
        }
        let udp_len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
        if udp_len < 8 || udp_len > udp.len() {
            return None;
        }
        let payload = udp[8..udp_len].to_vec();
        Some(Self {
            family: IpFamily::V4,
            source: IpAddr::V4(Ipv4Addr::new(
                packet[12], packet[13], packet[14], packet[15],
            )),
            destination: IpAddr::V4(Ipv4Addr::new(
                packet[16], packet[17], packet[18], packet[19],
            )),
            source_port,
            destination_port,
            domain: parse_dns_question_domain(&payload),
            payload,
        })
    }

    fn from_ipv6_packet(packet: &[u8]) -> Option<Self> {
        if packet.len() < 48 || packet[6] != 17 {
            return None;
        }
        let payload_len = usize::from(u16::from_be_bytes([packet[4], packet[5]]));
        let total_len = 40 + payload_len;
        if payload_len < 8 || total_len > packet.len() {
            return None;
        }
        let udp = &packet[40..total_len];
        let source_port = u16::from_be_bytes([udp[0], udp[1]]);
        let destination_port = u16::from_be_bytes([udp[2], udp[3]]);
        if destination_port != DNS_PORT {
            return None;
        }
        let udp_len = usize::from(u16::from_be_bytes([udp[4], udp[5]]));
        if udp_len < 8 || udp_len > udp.len() {
            return None;
        }
        let payload = udp[8..udp_len].to_vec();
        let source = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?);
        let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?);
        Some(Self {
            family: IpFamily::V6,
            source: IpAddr::V6(source),
            destination: IpAddr::V6(destination),
            source_port,
            destination_port,
            domain: parse_dns_question_domain(&payload),
            payload,
        })
    }

    fn response_packet(&self, dns_payload: &[u8]) -> io::Result<Vec<u8>> {
        match (self.family, self.source, self.destination) {
            (IpFamily::V4, IpAddr::V4(source), IpAddr::V4(destination)) => build_ipv4_udp_response(
                destination,
                source,
                self.destination_port,
                self.source_port,
                dns_payload,
            ),
            (IpFamily::V6, IpAddr::V6(source), IpAddr::V6(destination)) => build_ipv6_udp_response(
                destination,
                source,
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
        let socket = socket.clone();
        let hijacker = hijacker.clone();
        tokio::spawn(async move {
            match hijacker.resolve_dns_payload(&payload, None).await {
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

async fn query_dns_upstream(upstream: &str, payload: &[u8]) -> io::Result<Vec<u8>> {
    let addrs = lookup_host(upstream).await?;
    let mut last_error = None;
    for addr in addrs {
        let bind_addr = if addr.is_ipv4() {
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
        } else {
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
        };
        match query_dns_addr(bind_addr, addr, payload).await {
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
) -> io::Result<Vec<u8>> {
    let socket = UdpSocket::bind(bind_addr).await?;
    socket.send_to(payload, upstream).await?;
    let mut response = vec![0_u8; MAX_DNS_PACKET];
    let (len, _) = tokio::time::timeout(DNS_TIMEOUT, socket.recv_from(&mut response))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "DNS upstream timed out"))??;
    response.truncate(len);
    Ok(response)
}

fn build_ipv4_udp_response(
    source: Ipv4Addr, destination: Ipv4Addr, source_port: u16, destination_port: u16,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let udp_len = 8_usize
        .checked_add(payload.len())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "DNS response too large"))?;
    let total_len = 20_usize
        .checked_add(udp_len)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "DNS response too large"))?;
    let total_len_u16 = u16::try_from(total_len).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "IPv4 DNS response exceeds u16 length",
        )
    })?;
    let udp_len_u16 = u16::try_from(udp_len).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "UDP DNS response exceeds u16 length",
        )
    })?;

    let mut packet = vec![0_u8; total_len];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&total_len_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source.octets());
    packet[16..20].copy_from_slice(&destination.octets());
    let ip_checksum = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    write_udp_header(
        &mut packet[20..28],
        source_port,
        destination_port,
        udp_len_u16,
    );
    packet[28..].copy_from_slice(payload);
    let udp_checksum = ipv4_udp_checksum(source, destination, &packet[20..]);
    packet[26..28].copy_from_slice(&udp_checksum.to_be_bytes());
    Ok(packet)
}

fn build_ipv6_udp_response(
    source: Ipv6Addr, destination: Ipv6Addr, source_port: u16, destination_port: u16,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let udp_len = 8_usize
        .checked_add(payload.len())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "DNS response too large"))?;
    let udp_len_u16 = u16::try_from(udp_len).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "UDP DNS response exceeds u16 length",
        )
    })?;
    let mut packet = vec![0_u8; 40 + udp_len];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&udp_len_u16.to_be_bytes());
    packet[6] = 17;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source.octets());
    packet[24..40].copy_from_slice(&destination.octets());

    write_udp_header(
        &mut packet[40..48],
        source_port,
        destination_port,
        udp_len_u16,
    );
    packet[48..].copy_from_slice(payload);
    let udp_checksum = ipv6_udp_checksum(source, destination, &packet[40..]);
    packet[46..48].copy_from_slice(&udp_checksum.to_be_bytes());
    Ok(packet)
}

fn write_udp_header(header: &mut [u8], source_port: u16, destination_port: u16, udp_len: u16) {
    header[0..2].copy_from_slice(&source_port.to_be_bytes());
    header[2..4].copy_from_slice(&destination_port.to_be_bytes());
    header[4..6].copy_from_slice(&udp_len.to_be_bytes());
    header[6..8].copy_from_slice(&0_u16.to_be_bytes());
}

fn ipv4_udp_checksum(source: Ipv4Addr, destination: Ipv4Addr, udp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + udp.len());
    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&destination.octets());
    pseudo.push(0);
    pseudo.push(17);
    pseudo.extend_from_slice(&(u16::try_from(udp.len()).unwrap_or(u16::MAX)).to_be_bytes());
    pseudo.extend_from_slice(udp);
    nonzero_checksum(&pseudo)
}

fn ipv6_udp_checksum(source: Ipv6Addr, destination: Ipv6Addr, udp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + udp.len());
    pseudo.extend_from_slice(&source.octets());
    pseudo.extend_from_slice(&destination.octets());
    pseudo.extend_from_slice(&(u32::try_from(udp.len()).unwrap_or(u32::MAX)).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 17]);
    pseudo.extend_from_slice(udp);
    nonzero_checksum(&pseudo)
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0_u32;
    for chunk in bytes.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]])
        } else {
            u16::from(chunk[0]) << 8
        };
        sum += u32::from(word);
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !u16::try_from(sum).expect("checksum sum is folded into u16")
}

fn nonzero_checksum(bytes: &[u8]) -> u16 {
    match checksum(bytes) {
        0 => 0xFFFF,
        value => value,
    }
}

fn parse_dns_question_domain(payload: &[u8]) -> Option<String> {
    if payload.len() < 12 || u16::from_be_bytes([payload[4], payload[5]]) == 0 {
        return None;
    }
    let mut offset = 12;
    let mut labels = Vec::new();
    while offset < payload.len() {
        let len = usize::from(payload[offset]);
        if len == 0 {
            return (!labels.is_empty()).then(|| labels.join("."));
        }
        if (len & 0xC0) != 0 || len > 63 {
            return None;
        }
        offset += 1;
        if offset + len > payload.len() {
            return None;
        }
        labels.push(String::from_utf8_lossy(&payload[offset..offset + len]).to_lowercase());
        offset += len;
    }
    None
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
    if value.is_empty() || value.contains('/') {
        return None;
    }
    let value = value
        .split_once("://")
        .map_or(value, |(_, rest)| rest)
        .trim_matches('/');
    if value.parse::<SocketAddr>().is_ok() {
        return Some(value.to_string());
    }
    if let Ok(ip) = value.parse::<IpAddr>() {
        return Some(SocketAddr::from((ip, DNS_PORT)).to_string());
    }
    let colon_count = value.matches(':').count();
    if colon_count == 1
        && value
            .rsplit_once(':')
            .and_then(|(_, port)| port.parse::<u16>().ok())
            .is_some()
    {
        return Some(value.to_string());
    }
    if colon_count > 1 {
        Some(format!("[{value}]:{DNS_PORT}"))
    } else {
        Some(format!("{value}:{DNS_PORT}"))
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
    }

    #[test]
    fn normalizes_domain_patterns() {
        assert_eq!(normalize_domain("*.Example.COM."), "example.com");
    }

    #[test]
    fn parses_dns_question_domain() {
        let payload = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p',
            b'l', b'e', 3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
        ];
        assert_eq!(
            parse_dns_question_domain(&payload),
            Some("example.com".to_string())
        );
    }
}
