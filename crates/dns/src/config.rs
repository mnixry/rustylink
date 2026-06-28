//! DNS configuration parsed from the `/vpn/conn` response.
//!
//! [`DnsConfig`] holds compiled split-domain matchers and the dynamic-domain
//! answer tables. It is sync and network-free: built once by
//! [`DnsConfig::from_vpn_conn`] and consumed by the DNS server at session
//! start.

use std::{
    collections::{BTreeSet, HashMap},
    net::{IpAddr, SocketAddr},
};

use rustylink_api::{CentralDns, IpNat, VpnConnResponse};
use snafu::prelude::*;
use tokio::net::lookup_host;
use url::{Host, Url};
use wildmatch::WildMatch;

const DNS_PORT: u16 = 53;

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed to parse DNS endpoint `{value}`"))]
    InvalidEndpoint { value: String },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Dynamic-domain answer tables (the native client's first three DNS lookup
/// layers).
///
/// A query whose name hits one of these tables is answered locally from the
/// table's IP values rather than forwarded upstream.
#[derive(Clone, Debug, Default)]
pub struct DynamicDomainTables {
    /// `dynamic_domain` + `vpn_dynamic_domain_route_split` → A answers.
    pub(crate) exact_v4: HashMap<String, Vec<String>>,
    /// `v6_vpn_dynamic_domain_route_split` → AAAA answers.
    pub(crate) exact_v6: HashMap<String, Vec<String>>,
    /// `vpn_wildcard_dynamic_domain_route_split` → A answers (linear scan).
    pub(crate) wildcard_v4: Vec<(String, Vec<String>)>,
    /// `suffix_wildcard_dynamic_domain_route_split` → A answers (linear scan).
    pub(crate) suffix_v4: Vec<(String, Vec<String>)>,
}

impl DynamicDomainTables {
    /// IPv4 answer values for `name`: exact table, then wildcard, then suffix.
    pub(crate) fn lookup_v4(&self, name: &str) -> Option<&[String]> {
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

    /// IPv6 answer values for `name` (exact table only).
    pub(crate) fn lookup_v6(&self, name: &str) -> Option<&[String]> {
        self.exact_v6.get(name).map(Vec::as_slice)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.exact_v4.is_empty()
            && self.exact_v6.is_empty()
            && self.wildcard_v4.is_empty()
            && self.suffix_v4.is_empty()
    }
}

/// Parsed DNS configuration from `/vpn/conn`.
///
/// Holds no transports and performs no network I/O.
#[derive(Clone, Debug)]
pub struct DnsConfig {
    /// True in full-tunnel mode (all queries route through the VPN resolver).
    pub(crate) full_tunnel: bool,
    /// `host:port` VPN resolver endpoints.
    vpn_servers: Vec<String>,
    /// Compiled split-domain matchers.
    pub(crate) split_matchers: Vec<WildMatch>,
    /// Dynamic-domain answer tables (layers 1-3).
    pub(crate) dynamic: DynamicDomainTables,
    /// `central_dns` DNAT policy (parsed; matching deferred).
    central_dns: Option<CentralDns>,
    /// `ip_nats` NAT route-match rules (parsed; rewriting deferred).
    ip_nats: Vec<IpNat>,
}

impl DnsConfig {
    /// Parse DNS configuration from a `/vpn/conn` response. Sync and
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

    /// True when no resolver endpoints were provided.
    #[must_use]
    pub fn is_disabled(&self) -> bool {
        self.vpn_servers.is_empty()
    }

    /// Number of compiled split-domain matchers (for logging).
    #[must_use]
    pub fn split_matcher_count(&self) -> usize {
        self.split_matchers.len()
    }

    /// Parsed `central_dns` DNAT policy, if any.
    #[must_use]
    pub fn central_dns(&self) -> Option<&CentralDns> {
        self.central_dns.as_ref()
    }

    /// Parsed `ip_nats` NAT route-match rules.
    #[must_use]
    pub fn ip_nats(&self) -> &[IpNat] {
        &self.ip_nats
    }

    /// Resolve VPN resolver endpoints to concrete socket addresses.
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

    /// Should `domain` route through the VPN resolver?
    pub(crate) fn route_through_vpn(&self, domain: Option<&str>) -> bool {
        self.full_tunnel || domain.is_some_and(|domain| self.matches_split(domain))
    }

    pub(crate) fn matches_split(&self, domain: &str) -> bool {
        let domain = normalize_domain(domain);
        self.split_matchers
            .iter()
            .any(|matcher| matcher.matches(&domain))
    }
}

// ---------------------------------------------------------------------------
// Helpers (ported from tunnel/dns.rs)
// ---------------------------------------------------------------------------

pub(crate) fn normalize_domain(value: &str) -> String {
    value
        .trim()
        .trim_matches('"')
        .trim_matches('\'')
        .trim_start_matches("*.")
        .trim_start_matches('.')
        .trim_end_matches('.')
        .to_lowercase()
}

/// Parse VPN DNS resolver endpoints from config values. Each value may be a
/// single `host[:port]` token, a `dns://` or `udp://` URL, or a
/// comma/semicolon/whitespace-separated list.
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

/// Parse a single token into a `host:port` DNS endpoint.
pub(crate) fn parse_dns_endpoint(value: &str) -> Option<String> {
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

pub(crate) fn accept_domain(value: &str, out: &mut BTreeSet<String>) {
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

fn normalized_entries(
    map: Option<&HashMap<String, Vec<String>>>,
) -> impl Iterator<Item = (String, Vec<String>)> + '_ {
    map.into_iter().flatten().filter_map(|(key, values)| {
        let domain = normalize_domain(key);
        (!domain.is_empty()).then(|| (domain, values.clone()))
    })
}

/// The leading `/`-delimited token of a dynamic-table value (the address part).
pub(crate) fn value_token(value: &str) -> &str {
    value.split('/').next().unwrap_or(value).trim()
}

fn split_config_tokens(value: &str) -> impl Iterator<Item = String> + '_ {
    value
        .split(|ch: char| ch == ';' || ch == ',' || ch.is_whitespace())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use rustylink_api::{CentralDns, IpNat, VpnConnResponse, models::vpn::VpnConnSetting};

    use super::{DnsConfig, normalize_domain, parse_dns_endpoint};

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
        assert_eq!(config.ip_nats.len(), 1);
        assert!(config.ip_nats[0].is_default_nat);
    }
}
