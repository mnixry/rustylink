//! Interface-bound DNS resolver.
//!
//! Resolves hostnames by sending raw DNS A/AAAA queries over interface-bound
//! UDP sockets (via the [`Dialer`](crate::Dialer)), bypassing `libc`'s
//! `getaddrinfo` and `tokio::net::lookup_host`.  This makes hostname
//! resolution immune to TUN routing state regardless of when it runs.

use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use hickory_proto::{
    op::{Message, Query},
    rr::{Name, RData, RecordType},
    serialize::binary::BinDecodable,
};
use snafu::prelude::*;

use crate::Dialer;

const DNS_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_DNS_RESPONSE: usize = 4096;
const DEFAULT_DNS_PORT: u16 = 53;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("no DNS servers configured"))]
    NoServers,

    #[snafu(display("failed to read system DNS configuration: {source}"))]
    SystemConfig {
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[snafu(display("failed to bind DNS socket for query to {server}: {source}"))]
    Bind {
        server: SocketAddr,
        source: crate::dialer::Error,
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
    QueryTimeout { server: SocketAddr },

    #[snafu(display("DNS response from {server} could not be decoded: {source}"))]
    Decode {
        server: SocketAddr,
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[snafu(display("failed to serialize DNS query: {source}"))]
    QueryBuild {
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[snafu(display("no DNS records found for `{host}`"))]
    NoRecords { host: String },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

// ---------------------------------------------------------------------------
// Resolver
// ---------------------------------------------------------------------------

/// An interface-bound DNS resolver that sends raw UDP queries through the
/// [`Dialer`]'s outbound interface.
///
/// An optional static override map can pin specific hostnames to fixed
/// addresses (bypassing DNS entirely for those names).  This is used by the
/// API client's per-dot TLS pinning, where the request URL carries the tenant
/// `vpn_domain` (for correct SNI / cert validation) but the socket must
/// connect to the dot's raw IP.
#[derive(Clone, Debug)]
pub struct Resolver {
    dialer: Dialer,
    servers: Vec<SocketAddr>,
    overrides: HashMap<String, Vec<SocketAddr>>,
}

impl Resolver {
    /// Create a resolver with explicit DNS server addresses.
    #[must_use]
    pub fn new(dialer: Dialer, servers: Vec<SocketAddr>) -> Self {
        Self {
            dialer,
            servers,
            overrides: HashMap::new(),
        }
    }

    /// Create a resolver using the system's configured DNS servers.
    pub fn from_system(dialer: Dialer) -> Result<Self> {
        let servers = system_dns_servers()?;
        if servers.is_empty() {
            return Err(Error::NoServers);
        }
        Ok(Self {
            dialer,
            servers,
            overrides: HashMap::new(),
        })
    }

    /// Return a clone of this resolver with a static host→addr override.
    ///
    /// When `resolve_host` is called with `hostname`, the pinned address is
    /// returned immediately — no DNS query is sent.  All other hostnames
    /// resolve normally.
    ///
    /// This mirrors reqwest's `.resolve(host, addr)` and is used for per-dot
    /// TLS pinning: the request URL carries `vpn_domain` (for SNI / cert
    /// validation) while the socket connects to the dot's raw IP.
    #[must_use]
    pub fn with_override(mut self, hostname: impl Into<String>, pinned_addr: SocketAddr) -> Self {
        self.overrides
            .entry(hostname.into())
            .or_default()
            .push(pinned_addr);
        self
    }

    /// The DNS server addresses this resolver queries.
    #[must_use]
    pub fn servers(&self) -> &[SocketAddr] {
        &self.servers
    }

    /// Resolve a hostname to socket addresses (A + AAAA), querying each
    /// configured server in turn until one succeeds.
    ///
    /// Static overrides (from [`with_override`](Self::with_override)) are
    /// checked first and returned without hitting DNS.
    pub async fn resolve_host(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        // Check static overrides first.
        if let Some(addrs) = self.overrides.get(host) {
            return Ok(addrs.clone());
        }

        // If the host is already an IP literal, return it directly.
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![SocketAddr::new(ip, port)]);
        }

        let name = Name::from_ascii(host).map_err(|e| Error::NoRecords {
            host: format!("{host}: {e}"),
        })?;

        let mut all_addrs = Vec::new();
        let mut last_err: Option<Error> = None;

        // Query A records.
        match self.query_record(&name, RecordType::A).await {
            Ok(addrs) => {
                for ip in addrs {
                    all_addrs.push(SocketAddr::new(ip, port));
                }
            }
            Err(e) => last_err = Some(e),
        }

        // Query AAAA records.
        match self.query_record(&name, RecordType::AAAA).await {
            Ok(addrs) => {
                for ip in addrs {
                    all_addrs.push(SocketAddr::new(ip, port));
                }
            }
            Err(e) => {
                if last_err.is_none() {
                    last_err = Some(e);
                }
            }
        }

        if all_addrs.is_empty() {
            return Err(last_err.unwrap_or_else(|| Error::NoRecords {
                host: host.to_string(),
            }));
        }

        Ok(all_addrs)
    }

    async fn query_record(&self, name: &Name, record_type: RecordType) -> Result<Vec<IpAddr>> {
        let wire_query = build_query(name, record_type)?;
        let mut last_err = None;

        for server in &self.servers {
            match self.send_query(*server, &wire_query).await {
                Ok(response) => {
                    let addrs = extract_addrs(&response, record_type);
                    if !addrs.is_empty() {
                        return Ok(addrs);
                    }
                }
                Err(e) => {
                    tracing::debug!(%server, %e, "DNS query failed, trying next server");
                    last_err = Some(e);
                }
            }
        }

        last_err.map_or_else(|| Ok(Vec::new()), Err)
    }

    async fn send_query(&self, server: SocketAddr, wire_query: &[u8]) -> Result<Message> {
        let socket = self
            .dialer
            .bind_udp_to(server)
            .context(BindSnafu { server })?;
        socket
            .send_to(wire_query, server)
            .await
            .context(SendSnafu { server })?;

        let mut buf = vec![0u8; MAX_DNS_RESPONSE];
        let (len, _) = tokio::time::timeout(DNS_TIMEOUT, socket.recv_from(&mut buf))
            .await
            .map_err(|_| Error::QueryTimeout { server })?
            .context(RecvSnafu { server })?;

        Message::from_bytes(&buf[..len]).map_err(|e| Error::Decode {
            server,
            source: Box::new(e),
        })
    }
}

// ---------------------------------------------------------------------------
// Wire-format helpers
// ---------------------------------------------------------------------------

fn build_query(name: &Name, record_type: RecordType) -> Result<Vec<u8>> {
    let mut message = Message::query();
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(name.clone(), record_type));
    message.to_vec().map_err(|e| Error::QueryBuild {
        source: Box::new(e),
    })
}

fn extract_addrs(message: &Message, record_type: RecordType) -> Vec<IpAddr> {
    message
        .answers
        .iter()
        .filter(|r| r.record_type() == record_type)
        .filter_map(|r| match &r.data {
            RData::A(a) => Some(IpAddr::V4(Ipv4Addr::from(*a))),
            RData::AAAA(aaaa) => Some(IpAddr::V6(Ipv6Addr::from(*aaaa))),
            _ => None,
        })
        .collect()
}

/// Discover system DNS servers from the OS configuration.
///
/// This is the **single** DNS-discovery entry point for the crate — callers
/// should use this (or [`Resolver::from_system`]) rather than reading the
/// system config independently.
pub fn system_dns_servers() -> Result<Vec<SocketAddr>> {
    let (config, _opts) =
        hickory_resolver::system_conf::read_system_conf().map_err(|e| Error::SystemConfig {
            source: Box::new(e),
        })?;

    let servers: Vec<SocketAddr> = config
        .name_servers()
        .iter()
        .map(|ns| SocketAddr::new(ns.ip, DEFAULT_DNS_PORT))
        // Defensive: skip loopback/unspecified addresses, which may appear if
        // the local DNS server previously set system DNS to 127.0.0.1 and the
        // daemon restarted without restoring.
        .filter(|addr| !addr.ip().is_loopback() && !addr.ip().is_unspecified())
        .collect();

    if servers.is_empty() {
        Ok(vec![SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            DEFAULT_DNS_PORT,
        )])
    } else {
        Ok(servers)
    }
}

// ---------------------------------------------------------------------------
// Unit tests (pure logic only)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use hickory_proto::{
        op::{Message, MessageType, OpCode},
        rr::{Name, RData, Record, RecordType, rdata::A},
        serialize::binary::BinDecodable,
    };

    use super::{build_query, extract_addrs};
    use crate::Dialer;

    #[test]
    fn build_query_produces_valid_wire_format() {
        let name = Name::from_ascii("example.com").unwrap();
        let wire = build_query(&name, RecordType::A).unwrap();
        let parsed = Message::from_bytes(&wire).expect("parse query");
        assert_eq!(parsed.message_type, MessageType::Query);
        assert!(parsed.recursion_desired);
        assert_eq!(parsed.queries.len(), 1);
        assert_eq!(parsed.queries[0].query_type(), RecordType::A);
    }

    #[test]
    fn extract_addrs_from_response() {
        let mut msg = Message::new(0, MessageType::Response, OpCode::Query);
        let name = Name::from_ascii("example.com").unwrap();
        let record = Record::from_rdata(name, 300, RData::A(A(Ipv4Addr::new(93, 184, 215, 14))));
        msg.add_answer(record);
        let addrs = extract_addrs(&msg, RecordType::A);
        assert_eq!(addrs, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 215, 14))]);
    }

    #[test]
    fn ip_literal_resolves_directly() {
        let dialer = Dialer::default();
        let resolver = super::Resolver::new(dialer, vec![]);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let addrs = rt.block_on(resolver.resolve_host("10.0.0.1", 443)).unwrap();
        assert_eq!(
            addrs,
            vec![SocketAddr::new("10.0.0.1".parse().unwrap(), 443)]
        );
    }

    #[tokio::test]
    async fn no_servers_returns_error() {
        let dialer = Dialer::default();
        let resolver = super::Resolver::new(dialer, vec![]);
        let err = resolver.resolve_host("example.com", 443).await.unwrap_err();
        // With no servers, build_query succeeds but query_record returns empty
        // -> NoRecords (or QueryBuild if something else fails).
        assert!(
            matches!(err, super::Error::NoRecords { .. }),
            "unexpected error: {err:?}"
        );
    }

    #[tokio::test]
    async fn static_override_bypasses_dns() {
        let dialer = Dialer::default();
        let pinned = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42)), 8443);
        let resolver =
            super::Resolver::new(dialer, vec![]).with_override("vpn.example.com", pinned);
        let addrs = resolver
            .resolve_host("vpn.example.com", 8443)
            .await
            .unwrap();
        assert_eq!(addrs, vec![pinned]);
    }
}
