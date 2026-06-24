//! Session-level outbound networking context.
//!
//! [`OutboundContext`] is a single handle built once per connect that owns the
//! resolved outbound interface, both dialers (directed + routed), and the
//! endpoint resolver.  It replaces the ad-hoc multi-Dialer assembly in the
//! tunnel session.

use std::{net::SocketAddr, time::Duration};

use snafu::prelude::*;

use crate::{Dialer, OutboundInterface, Resolver};

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("outbound interface selection failed: {source}"))]
    Interface { source: crate::interface::Error },

    #[snafu(display("system DNS discovery failed: {source}"))]
    DnsDiscovery { source: crate::resolver::Error },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

// ---------------------------------------------------------------------------
// OutboundConfig
// ---------------------------------------------------------------------------

/// Configuration for building an [`OutboundContext`].
pub struct OutboundConfig {
    /// User-configured outbound interface name, or `None` for auto-detect.
    pub configured_interface: Option<String>,
    /// The TUN device name to exclude from interface selection (prevents
    /// self-loop).
    pub excluded_tun: String,
    /// Whether the tunnel is full-tunnel (all traffic routed via TUN).
    /// When true and no usable WAN interface is found, `build` returns an
    /// error instead of `Ok(None)` to prevent a routing loop.
    pub full_tunnel: bool,
    /// TCP connect timeout applied to the directed dialer.
    pub connect_timeout: Duration,
}

// ---------------------------------------------------------------------------
// OutboundContext
// ---------------------------------------------------------------------------

/// Session-level networking context built once per connect.
///
/// Owns the resolved outbound interface, both dialers (directed = physical NIC,
/// routed = TUN), and the endpoint resolver.  All bypass traffic paths
/// (`WireGuard`, `FeiLian` TCP, DNS transports, `HyperConnector`) consume
/// dialers from this context.
#[derive(Clone, Debug)]
pub struct OutboundContext {
    directed: Dialer,
    routed: Dialer,
    resolver: Resolver,
    interface: Option<OutboundInterface>,
}

/// How many times to retry looking up the TUN interface (it may not be visible
/// to the OS immediately after creation).
const TUN_LOOKUP_RETRIES: u32 = 3;
/// Delay between TUN lookup retries.
const TUN_LOOKUP_DELAY: Duration = Duration::from_millis(100);

impl OutboundContext {
    /// Build the outbound context for a tunnel session.
    ///
    /// 1. Resolves the physical outbound interface (route-based,
    ///    self-loop-safe).
    /// 2. Looks up the TUN interface index (with a short retry for the race).
    /// 3. Constructs the directed + routed [`Dialer`]s.
    /// 4. Discovers system DNS servers.
    /// 5. Constructs the [`Resolver`] with the directed dialer.
    pub async fn build(config: OutboundConfig) -> Result<Self> {
        // (1) Resolve the physical outbound interface.
        let interface = OutboundInterface::resolve(
            config.configured_interface.as_deref(),
            Some(&config.excluded_tun),
            config.full_tunnel,
        )
        .await
        .context(InterfaceSnafu)?;

        if let Some(iface) = &interface {
            tracing::info!(
                outbound_interface = %iface.name,
                outbound_interface_index = iface.index,
                tunnel_interface = %config.excluded_tun,
                "binding tunnel outbound sockets to physical interface"
            );
        } else {
            tracing::warn!(
                tunnel_interface = %config.excluded_tun,
                "no outbound interface selected; tunnel sockets will use OS routing"
            );
        }

        // (2) Look up the TUN interface index (retry for the race).
        let tun_outbound = lookup_tun_with_retry(&config.excluded_tun).await;

        // (3) Build dialers.
        let directed = Dialer::new(interface.clone()).with_connect_timeout(config.connect_timeout);
        let routed = Dialer::new(tun_outbound);

        // (4) Discover system DNS servers.
        let servers = crate::resolver::system_dns_servers().context(DnsDiscoverySnafu)?;

        // (5) Build the resolver.
        let resolver = Resolver::new(directed.clone(), servers);

        Ok(Self {
            directed,
            routed,
            resolver,
            interface,
        })
    }

    /// The directed (physical-NIC-bound) dialer for bypass traffic.
    #[must_use]
    pub fn directed(&self) -> &Dialer {
        &self.directed
    }

    /// The routed (TUN-bound) dialer for in-tunnel traffic.
    #[must_use]
    pub fn routed(&self) -> &Dialer {
        &self.routed
    }

    /// The interface-bound DNS resolver (uses the directed dialer).
    #[must_use]
    pub fn resolver(&self) -> &Resolver {
        &self.resolver
    }

    /// The resolved physical outbound interface, if any.
    #[must_use]
    pub fn interface(&self) -> Option<&OutboundInterface> {
        self.interface.as_ref()
    }

    /// The outbound interface name, or `"<default>"` when unbound.
    #[must_use]
    pub fn interface_name_or_default(&self) -> &str {
        self.directed.interface_name_or_default()
    }

    /// Resolve a hostname via the directed (physical-NIC-bound) DNS resolver.
    pub async fn resolve_host(
        &self, host: &str, port: u16,
    ) -> std::result::Result<Vec<SocketAddr>, crate::resolver::Error> {
        self.resolver.resolve_host(host, port).await
    }

    /// The system DNS server addresses discovered during build.
    #[must_use]
    pub fn dns_servers(&self) -> &[SocketAddr] {
        self.resolver.servers()
    }
}

async fn lookup_tun_with_retry(tun_name: &str) -> Option<OutboundInterface> {
    for attempt in 0..TUN_LOOKUP_RETRIES {
        if let Some(iface) = OutboundInterface::lookup(tun_name).await {
            return Some(iface);
        }
        if attempt + 1 < TUN_LOOKUP_RETRIES {
            tracing::debug!(
                tun = %tun_name,
                attempt = attempt + 1,
                max_attempts = TUN_LOOKUP_RETRIES,
                "TUN interface not yet visible, retrying"
            );
            tokio::time::sleep(TUN_LOOKUP_DELAY).await;
        }
    }
    tracing::warn!(
        tun = %tun_name,
        "TUN interface index not visible after {TUN_LOOKUP_RETRIES} attempts; \
         routed DNS will use OS routing only"
    );
    None
}
