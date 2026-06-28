//! DNS resolution for TUN-level hijacking + optional standalone DNS server.
//!
//! The [`DnsResolver`] is the main entry point, consumed by
//! `VpnTun::recv()` in the tunnel crate. It routes DNS queries through:
//! 1. Dynamic-domain synthesis (answer tables from the VPN server)
//! 2. Route decision: routed (VPN DNS) vs non-routed (system DNS)
//! 3. Parallel upstream query, pick fastest response
//!
//! An optional [`DnsServer`] on localhost shares the same resolution pipeline
//! and can accept explicit DNS queries when configured.

pub mod config;
pub mod forwarder;
pub mod resolver;
pub mod server;
pub mod synthesis;

// Re-exports with `XxxError` aliases (outbound crate convention).
use std::{
    collections::BTreeSet,
    net::{IpAddr, Ipv4Addr},
};

pub use config::{DnsConfig, DynamicDomainTables, Error as ConfigError};
pub use forwarder::Error as ForwarderError;
pub use resolver::DnsResolver;
pub use server::{DnsServer, Error as ServerError};

/// Default fallback DNS server.
const DEFAULT_FALLBACK_DNS: IpAddr = IpAddr::V4(Ipv4Addr::new(223, 5, 5, 5));

/// Standard DNS port.
pub const DNS_PORT: u16 = 53;

/// Read system DNS servers, filtering out loopback and unspecified addresses.
/// If the filtered list is empty, falls back to the provided list or
/// [`DEFAULT_FALLBACK_DNS`].
#[must_use]
pub fn capture_system_dns(fallback: Option<&[String]>) -> Vec<IpAddr> {
    let raw_servers = read_system_dns_ips();

    let servers: Vec<IpAddr> = raw_servers
        .into_iter()
        .filter(|ip| !ip.is_loopback() && !ip.is_unspecified())
        .collect();

    if !servers.is_empty() {
        return servers;
    }

    tracing::warn!("system DNS empty or all-loopback after filtering; using fallback");

    if let Some(overrides) = fallback {
        let parsed: Vec<IpAddr> = overrides
            .iter()
            .filter_map(|s| s.parse::<IpAddr>().ok())
            .collect();
        if !parsed.is_empty() {
            return parsed;
        }
    }

    vec![DEFAULT_FALLBACK_DNS]
}

/// Read raw system DNS server IPs from OS configuration.
fn read_system_dns_ips() -> Vec<IpAddr> {
    match hickory_resolver::system_conf::read_system_conf() {
        Ok((config, _opts)) => {
            let mut seen = BTreeSet::new();
            config
                .name_servers()
                .iter()
                .map(|server| server.ip)
                .filter(|ip| seen.insert(*ip))
                .collect()
        }
        Err(error) => {
            tracing::warn!(%error, "failed to read system DNS config");
            Vec::new()
        }
    }
}
