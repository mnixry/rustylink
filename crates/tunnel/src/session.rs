use std::{
    net::{Ipv4Addr, Ipv6Addr, UdpSocket},
    sync::Arc,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use gotatun::{
    device::{Device, DeviceBuilder, Peer},
    noise::ProtocolIdentifier,
    x25519::{PublicKey, StaticSecret},
};
use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use rustylink_api::{ProtocolMode, VpnConnResponse};
use rustylink_dns::{DnsConfig, DnsResolver, DnsServer};
use rustylink_outbound::{Dialer, OutboundConfig, OutboundContext, Resolver, RouteBypass};
use serde::{Deserialize, Serialize};
use snafu::prelude::*;
use url::{Host, Url};

use crate::{
    BoundUdpSocketFactory, DnsQueryTransport, FeilianTcpTransportFactory, LivenessProbe,
    UdpDnsTransport, VpnTun,
    route::{self, AppliedRoutes, VpnRouteMode},
};

const ANDROID_LOCAL_PORT_START: u16 = 12912;
const WIREGUARD_KEEPALIVE_SECS: u16 = 25;
const TCP_DIAL_TIMEOUT: Duration = Duration::from_secs(3);
const STANDARD_NOISE_CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const FEILIAN_V2_PROTOCOL_IDENTIFIER: &[u8] = b"CorpLink v1 vpn@feilian-----------";

type UdpTunnelDevice = Device<(BoundUdpSocketFactory, VpnTun, VpnTun)>;
type TcpTunnelDevice = Device<(FeilianTcpTransportFactory, VpnTun, VpnTun)>;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("invalid tunnel config: {reason}"))]
    InvalidConfig { reason: String },

    #[snafu(display("invalid tunnel IPv4 address `{value}`: {source}"))]
    InvalidIpv4Address {
        value: String,
        source: std::net::AddrParseError,
    },

    #[snafu(display("invalid IPv4 prefix length `{prefix}`"))]
    InvalidIpv4Prefix { prefix: i32 },

    #[snafu(display("invalid tunnel IPv4 network `{address}/{prefix}`: {source}"))]
    InvalidIpv4Network {
        address: Ipv4Addr,
        prefix: u8,
        source: ipnetwork::IpNetworkError,
    },

    #[snafu(display("invalid tunnel MTU `{mtu}`"))]
    InvalidMtu { mtu: i32 },

    #[snafu(display("invalid tunnel IPv6 address `{value}`: {source}"))]
    InvalidIpv6Address {
        value: String,
        source: std::net::AddrParseError,
    },

    #[snafu(display("invalid tunnel IPv6 network `{value}`: {source}"))]
    InvalidIpv6Network {
        value: String,
        source: ipnetwork::IpNetworkError,
    },

    #[snafu(display("invalid tunnel IPv6 network `{value}`: expected IPv6"))]
    InvalidIpv6NetworkFamily { value: String },

    #[snafu(display("route manager failed: {source}"))]
    Route { source: crate::route::Error },

    #[snafu(display("TUN device creation failed: {source}"))]
    TunCreate { source: std::io::Error },

    #[snafu(display("outbound setup failed: {source}"))]
    Outbound {
        source: rustylink_outbound::ContextError,
    },

    #[snafu(display("route bypass setup failed: {source}"))]
    Bypass {
        source: rustylink_outbound::BypassError,
    },

    #[snafu(display("gotatun device setup failed: {source}"))]
    Device { source: gotatun::device::Error },

    #[snafu(display("failed to resolve WireGuard endpoint `{endpoint}`: {source}"))]
    ResolveEndpoint {
        endpoint: String,
        source: rustylink_outbound::ResolverError,
    },

    #[snafu(display("WireGuard endpoint `{endpoint}` did not resolve to any address"))]
    EmptyEndpointResolution { endpoint: String },

    #[snafu(display("invalid WireGuard key `{name}`"))]
    InvalidKey { name: &'static str },

    #[snafu(display("DNS server failed: {source}"))]
    DnsServer { source: rustylink_dns::ServerError },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LocalTunnelParams {
    pub local_private_key: String,
    pub local_public_key: String,
    pub local_port: u16,
    pub local_dns: Option<String>,
}

#[derive(Clone, Debug)]
pub struct TunnelConfig {
    pub interface_name: String,
    pub local_addr: String,
    pub local_addr_v6: Option<String>,
    pub local_prefix: Option<i32>,
    pub mtu: i32,
    pub local_private_key: String,
    pub local_public_key: String,
    pub local_port: u16,
    pub server_public_key: String,
    pub server_preshared_key: Option<String>,
    pub endpoint: Url,
    pub protocol_mode: ProtocolMode,
    pub protocol_version: Option<String>,
    pub outbound_interface: Option<String>,
    pub routes: Vec<IpNetwork>,
    pub full_tunnel: bool,
    pub ipv6_enabled: bool,
    pub dns: DnsConfig,
    /// Split-tunnel system DNS hijack: when `true` (default), the system DNS
    /// server IP(s) are routed into the TUN so the OS's DNS queries are
    /// intercepted. When `false`, those host routes are not installed (UDP:53
    /// packets that still reach the TUN are hijacked as usual). No effect in
    /// full-tunnel mode.
    pub route_system_dns: bool,
    /// Port for the optional local DNS server. 0 = disabled.
    pub dns_listen_port: u16,
    /// Host/IP for the optional local DNS server. Default = loopback.
    pub dns_listen_host: Option<String>,
    /// Fallback DNS servers when system DNS is empty/all-loopback.
    pub fallback_dns: Option<Vec<String>>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TunnelStatus {
    Created,
    RoutesApplied,
    Running,
    Stopped,
}

pub struct TunnelSession {
    pub config: TunnelConfig,
    pub status: TunnelStatus,
    device: Option<TunnelDevice>,
    routes: Option<AppliedRoutes>,
    bypass: Option<RouteBypass>,
    probe: Option<LivenessProbe>,
    dns_server: Option<DnsServer>,
}

enum TunnelDevice {
    Udp(UdpTunnelDevice),
    FeilianTcp(TcpTunnelDevice),
}

impl LocalTunnelParams {
    #[must_use]
    pub fn generate() -> Self {
        let secret = StaticSecret::from(rand::random::<[u8; 32]>());
        Self::from_secret(&secret)
    }

    pub fn from_private_key(value: &str) -> Result<Self> {
        let secret = StaticSecret::from(decode_key("local_private_key", value)?);
        Ok(Self::from_secret(&secret))
    }

    fn from_secret(secret: &StaticSecret) -> Self {
        let public = PublicKey::from(secret);
        Self {
            local_private_key: STANDARD.encode(secret.to_bytes()),
            local_public_key: STANDARD.encode(public.as_bytes()),
            local_port: choose_local_port(),
            local_dns: None,
        }
    }
}

impl TunnelConfig {
    pub fn from_vpn_conn(
        conn: &VpnConnResponse, local_params: LocalTunnelParams, endpoint: Url,
        protocol_mode: ProtocolMode, route_mode: VpnRouteMode,
    ) -> Result<Self> {
        if conn.setting.vpn_mtu <= 0 {
            return InvalidConfigSnafu {
                reason: "vpn_mtu must be positive".to_string(),
            }
            .fail();
        }
        let ipv6_enabled = conn
            .ipv6
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty());
        let full_tunnel = matches!(route_mode, VpnRouteMode::Full);
        let dns = DnsConfig::from_vpn_conn(conn, local_params.local_dns.as_deref(), full_tunnel);
        let routes =
            route::networks_from_vpn_conn(conn, route_mode, ipv6_enabled).context(RouteSnafu)?;
        tracing::info!(
            %route_mode,
            ipv6_enabled,
            routes = routes.len(),
            "selected VPN routes from config"
        );
        Ok(Self {
            interface_name: default_interface_name(),
            local_addr: conn.ip.clone(),
            local_addr_v6: conn.ipv6.clone(),
            local_prefix: conn.ip_mask,
            mtu: conn.setting.vpn_mtu,
            local_private_key: local_params.local_private_key,
            local_public_key: local_params.local_public_key,
            local_port: local_params.local_port,
            server_public_key: conn.public_key.clone(),
            server_preshared_key: conn.preshared_key.clone(),
            endpoint,
            protocol_mode,
            protocol_version: conn.protocol_version.clone(),
            outbound_interface: None,
            routes,
            full_tunnel,
            ipv6_enabled,
            dns,
            route_system_dns: true,
            dns_listen_port: 0,
            dns_listen_host: None,
            fallback_dns: None,
        })
    }
}

impl TunnelSession {
    #[must_use]
    pub fn new(config: TunnelConfig) -> Self {
        Self {
            config,
            status: TunnelStatus::Created,
            device: None,
            routes: None,
            bypass: None,
            probe: None,
            dns_server: None,
        }
    }

    pub async fn start(&mut self) -> Result<()> {
        if let Err(error) = self.start_inner().await {
            if let Err(cleanup_error) = self.stop().await {
                tracing::warn!(
                    %cleanup_error,
                    "failed to clean up partially started tunnel session"
                );
            }
            return Err(error);
        }
        Ok(())
    }

    /// In split-tunnel mode, route the system DNS server IP(s) into the TUN as
    /// host routes so the OS's own DNS queries enter the tunnel and can be
    /// intercepted by the hijacker.
    fn route_system_dns_into_tunnel(&mut self, system_servers: &[std::net::IpAddr]) {
        if self.config.full_tunnel {
            return;
        }
        if !self.config.route_system_dns {
            tracing::info!(
                "system DNS hijack disabled: not routing system DNS into tunnel (split mode)"
            );
            return;
        }
        let dns_host_routes = route::dns_host_routes(system_servers, self.config.ipv6_enabled);
        if dns_host_routes.is_empty() {
            return;
        }
        tracing::info!(
            dns_host_routes = ?dns_host_routes
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            "routing system DNS servers into tunnel for split-tunnel DNS interception"
        );
        self.config.routes.extend(dns_host_routes);
    }

    /// Build the routed DNS transport, the `DnsResolver`, and the `VpnTun`.
    async fn build_vpn_tun(
        &self, tun_device: tun_rs::AsyncDevice, directed_dialer: &Dialer, routed_dialer: &Dialer,
        system_servers: &[std::net::IpAddr],
    ) -> Result<(
        VpnTun,
        Arc<dyn DnsQueryTransport>,
        Vec<std::net::SocketAddr>,
    )> {
        let routed_dns: Arc<dyn DnsQueryTransport> =
            Arc::new(UdpDnsTransport::new(routed_dialer.clone()));
        let vpn_servers = self.config.dns.resolve_vpn_servers().await;
        let resolver = DnsResolver::build(
            self.config.dns.clone(),
            vpn_servers.clone(),
            system_servers,
            directed_dialer.clone(),
        )
        .map(Arc::new);
        let tun = VpnTun::new(tun_device, resolver).context(TunCreateSnafu)?;
        Ok((tun, routed_dns, vpn_servers))
    }

    #[allow(clippy::too_many_lines)]
    async fn start_inner(&mut self) -> Result<()> {
        tracing::info!(
            interface = %self.config.interface_name,
            mtu = self.config.mtu,
            endpoint = %self.config.endpoint,
            "starting tunnel session"
        );
        tracing::info!(
            protocol_mode = %self.config.protocol_mode,
            protocol_version = ?self.config.protocol_version,
            full_tunnel = self.config.full_tunnel,
            vpn_routes = self.config.routes.len(),
            split_domain_rules = self.config.dns.split_matcher_count(),
            "selected tunnel runtime options"
        );
        let private_key = StaticSecret::from(decode_key(
            "local_private_key",
            &self.config.local_private_key,
        )?);

        let (tun_device, actual_interface_name) = self.open_tun()?;

        let ctx = OutboundContext::build(OutboundConfig {
            configured_interface: self.config.outbound_interface.clone(),
            excluded_tun: actual_interface_name.clone(),
            full_tunnel: self.config.full_tunnel,
            connect_timeout: TCP_DIAL_TIMEOUT,
        })
        .await
        .context(OutboundSnafu)?;

        // Capture system DNS for non-routed forwarding + split-tunnel host routes.
        let system_servers = rustylink_dns::capture_system_dns(self.config.fallback_dns.as_deref());
        tracing::info!(
            system_dns = ?system_servers,
            "captured system DNS for directed forwarding"
        );
        self.route_system_dns_into_tunnel(&system_servers);

        let endpoint = resolve_endpoint(&self.config.endpoint, ctx.resolver()).await?;
        let peer = tunnel_peer(&self.config, endpoint)?;

        // Install route bypass (macOS: scoped default route, Linux: fwmark
        // policy routing) so that interface-bound sockets can reach
        // destinations despite /1 full-tunnel routes.  Must happen BEFORE
        // TUN routes are applied.
        if let Some(iface) = ctx.interface() {
            match RouteBypass::setup(iface, self.config.full_tunnel).await {
                Ok(bypass) => self.bypass = Some(bypass),
                Err(e) => {
                    tracing::warn!(
                        %e,
                        interface = %iface.name,
                        full_tunnel = self.config.full_tunnel,
                        "route bypass setup failed; bypass traffic may be unreachable"
                    );
                }
            }
        }

        let routes = self.config.routes.as_slice();
        let routes = route::apply(&actual_interface_name, routes)
            .await
            .context(RouteSnafu)?;
        self.routes = Some(routes);
        self.status = TunnelStatus::RoutesApplied;
        let (tun, routed_dns, vpn_servers) = self
            .build_vpn_tun(tun_device, ctx.directed(), ctx.routed(), &system_servers)
            .await?;

        // Optional DNS server (if dns_listen_port is configured). Fail-fast.
        if self.config.dns_listen_port > 0
            && let Some(resolver) = DnsResolver::build(
                self.config.dns.clone(),
                vpn_servers.clone(),
                &system_servers,
                ctx.directed().clone(),
            )
        {
            let host = self
                .config
                .dns_listen_host
                .as_deref()
                .unwrap_or("127.0.0.1");
            let port = self.config.dns_listen_port;
            let bind_v4: std::net::SocketAddr = format!("{host}:{port}")
                .parse()
                .unwrap_or_else(|_| ([127, 0, 0, 1], port).into());
            let bind_v6: std::net::SocketAddr = ([0, 0, 0, 0, 0, 0, 0, 1], port).into();
            let server =
                DnsServer::start(bind_v4, bind_v6, Arc::new(resolver)).context(DnsServerSnafu)?;
            tracing::info!(%bind_v4, %bind_v6, "optional DNS server started");
            self.dns_server = Some(server);
        }

        let device = match self.config.protocol_mode {
            ProtocolMode::Udp => {
                let builder = DeviceBuilder::new()
                    .with_udp(BoundUdpSocketFactory::new(ctx.directed().clone()))
                    .with_ip(tun)
                    .with_private_key(private_key)
                    .with_listen_port(self.config.local_port)
                    .with_peer(peer);
                let builder = with_feilian_protocol_identifier(builder, &self.config);
                TunnelDevice::Udp(builder.build().await.context(DeviceSnafu)?)
            }
            ProtocolMode::FeilianTcp => {
                let builder = DeviceBuilder::new()
                    .with_udp(FeilianTcpTransportFactory::new(ctx.directed().clone()))
                    .with_ip(tun)
                    .with_private_key(private_key)
                    .with_listen_port(self.config.local_port)
                    .with_peer(peer);
                let builder = with_feilian_protocol_identifier(builder, &self.config);
                TunnelDevice::FeilianTcp(builder.build().await.context(DeviceSnafu)?)
            }
        };
        self.device = Some(device);
        self.probe = Some(LivenessProbe::start(routed_dns, vpn_servers));
        self.status = TunnelStatus::Running;
        tracing::info!(
            interface = %self.config.interface_name,
            protocol_mode = %self.config.protocol_mode,
            "gotatun WireGuard device started"
        );
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
        tracing::info!(interface = %self.config.interface_name, "stopping tunnel session");
        // Drop the probe before tearing down the device so its spawned task
        // (which sends through routed_dns → TUN → gotatun) is cancelled before
        // the receive end disappears.
        drop(self.probe.take());

        // Stop the optional DNS server.
        if let Some(server) = self.dns_server.take() {
            server.shutdown().await;
        }

        if let Some(routes) = self.routes.take() {
            routes.remove().await.context(RouteSnafu)?;
        }
        // Remove route bypass (macOS scoped default, Linux fwmark rules)
        // after TUN routes are gone.
        if let Some(bypass) = self.bypass.take()
            && let Err(e) = bypass.teardown().await
        {
            tracing::warn!(%e, "failed to tear down route bypass");
        }
        if let Some(device) = self.device.take() {
            device.stop().await;
        }
        self.status = TunnelStatus::Stopped;
        Ok(())
    }

    /// Elapsed time since the most recent reply to the routed liveness probe,
    /// or `None` if no probe has succeeded yet (initial-connect window).
    /// The supervisor uses this to detect a stalled tunnel
    /// (`HandshakeTimeout`).
    #[must_use]
    pub fn last_probe_rx_elapsed(&self) -> Option<std::time::Duration> {
        self.probe.as_ref().and_then(LivenessProbe::last_rx_elapsed)
    }

    pub async fn wait(&mut self) {
        if let Some(device) = self.device.as_mut() {
            device.wait().await;
            self.status = TunnelStatus::Stopped;
        }
    }

    /// Elapsed time since the most recent successful `WireGuard` handshake with
    /// the configured peer, or `None` if no handshake has completed yet (or the
    /// device is not running).  Used by the daemon supervisor to detect a
    /// stalled tunnel (`HandshakeTimeout`).
    pub async fn last_handshake(&self) -> Option<std::time::Duration> {
        match self.device.as_ref()? {
            TunnelDevice::Udp(device) => peer_last_handshake(device.peers().await),
            TunnelDevice::FeilianTcp(device) => peer_last_handshake(device.peers().await),
        }
    }

    /// Per-peer transport counters (`tx_bytes` / `rx_bytes` / `last_handshake`)
    /// for diagnostics. Empty when the device is not running. Used by the
    /// daemon supervisor to log whether handshake bytes are leaving and
    /// whether the server is replying.
    pub async fn peer_stats(&self) -> Vec<gotatun::device::configure::PeerStats> {
        match self.device.as_ref() {
            Some(TunnelDevice::Udp(device)) => device.peers().await,
            Some(TunnelDevice::FeilianTcp(device)) => device.peers().await,
            None => Vec::new(),
        }
    }

    fn open_tun(&mut self) -> Result<(tun_rs::AsyncDevice, String)> {
        let local_addr =
            self.config
                .local_addr
                .parse::<Ipv4Addr>()
                .context(InvalidIpv4AddressSnafu {
                    value: self.config.local_addr.clone(),
                })?;
        let local_prefix = self.config.local_prefix.unwrap_or(32);
        let local_prefix = u8::try_from(local_prefix)
            .ok()
            .filter(|prefix| *prefix <= 32)
            .context(InvalidIpv4PrefixSnafu {
                prefix: local_prefix,
            })?;
        let local_network =
            Ipv4Network::new(local_addr, local_prefix).context(InvalidIpv4NetworkSnafu {
                address: local_addr,
                prefix: local_prefix,
            })?;
        let mtu = u16::try_from(self.config.mtu)
            .ok()
            .filter(|mtu| *mtu > 0)
            .context(InvalidMtuSnafu {
                mtu: self.config.mtu,
            })?;

        let requested_interface_name = self.config.interface_name.clone();
        let mut tun_builder = tun_rs::DeviceBuilder::new()
            .ipv4(
                local_network.ip(),
                local_network.prefix(),
                Some(local_network.ip()),
            )
            .mtu(mtu);
        if let Some(local_addr_v6) = self
            .config
            .local_addr_v6
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
        {
            let local_network_v6 = if local_addr_v6.contains('/') {
                match local_addr_v6
                    .parse::<IpNetwork>()
                    .context(InvalidIpv6NetworkSnafu {
                        value: local_addr_v6.to_string(),
                    })? {
                    IpNetwork::V6(network) => network,
                    IpNetwork::V4(_) => {
                        return InvalidIpv6NetworkFamilySnafu {
                            value: local_addr_v6.to_string(),
                        }
                        .fail();
                    }
                }
            } else {
                Ipv6Network::new(
                    local_addr_v6
                        .parse::<Ipv6Addr>()
                        .context(InvalidIpv6AddressSnafu {
                            value: local_addr_v6.to_string(),
                        })?,
                    64,
                )
                .context(InvalidIpv6NetworkSnafu {
                    value: format!("{local_addr_v6}/64"),
                })?
            };
            tun_builder = tun_builder.ipv6(local_network_v6.ip(), local_network_v6.prefix());
        }
        if !cfg!(target_os = "macos") || requested_interface_name != "utun" {
            tun_builder = tun_builder.name(&requested_interface_name);
        }
        #[cfg(target_os = "macos")]
        {
            tun_builder = tun_builder.associate_route(false).packet_information(false);
        }

        let device = tun_builder.build_async().context(TunCreateSnafu)?;
        let actual_interface_name = device.name().context(TunCreateSnafu)?;
        if actual_interface_name != requested_interface_name {
            if !cfg!(target_os = "macos") || requested_interface_name != "utun" {
                return InvalidConfigSnafu {
                    reason: format!(
                        "requested TUN interface `{requested_interface_name}` but OS assigned `{actual_interface_name}`"
                    ),
                }
                .fail();
            }
            tracing::info!(
                requested_interface = %requested_interface_name,
                actual_interface = %actual_interface_name,
                "TUN device assigned OS interface name"
            );
            self.config
                .interface_name
                .clone_from(&actual_interface_name);
        }
        Ok((device, actual_interface_name))
    }
}

fn peer_last_handshake(
    peers: Vec<gotatun::device::configure::PeerStats>,
) -> Option<std::time::Duration> {
    peers
        .into_iter()
        .filter_map(|peer| peer.stats.last_handshake)
        .min()
}

impl TunnelDevice {
    async fn stop(self) {
        match self {
            Self::Udp(device) => device.stop().await,
            Self::FeilianTcp(device) => device.stop().await,
        }
    }

    async fn wait(&mut self) {
        match self {
            Self::Udp(device) => device.wait().await,
            Self::FeilianTcp(device) => device.wait().await,
        }
    }
}

fn default_interface_name() -> String {
    if cfg!(target_os = "macos") {
        "utun".to_string()
    } else {
        "wg0".to_string()
    }
}

fn choose_local_port() -> u16 {
    for port in ANDROID_LOCAL_PORT_START..u16::MAX {
        if UdpSocket::bind(("0.0.0.0", port)).is_ok() {
            return port;
        }
    }
    0
}

fn with_feilian_protocol_identifier<Udp, TunTx, TunRx>(
    builder: DeviceBuilder<Udp, TunTx, TunRx>, config: &TunnelConfig,
) -> DeviceBuilder<Udp, TunTx, TunRx> {
    let Some(identifier) = feilian_protocol_identifier(config) else {
        return builder;
    };
    builder.with_protocol_identifier(identifier)
}

fn feilian_protocol_identifier(config: &TunnelConfig) -> Option<ProtocolIdentifier> {
    match config.protocol_version.as_deref().map(str::trim) {
        Some("v2") => {
            tracing::info!("using FeiLian CorpLink WireGuard protocol identifier");
            Some(ProtocolIdentifier::new(
                STANDARD_NOISE_CONSTRUCTION,
                FEILIAN_V2_PROTOCOL_IDENTIFIER,
            ))
        }
        Some(value) if !value.is_empty() => {
            tracing::warn!(
                protocol_version = value,
                "unknown FeiLian WireGuard identifier version; using standard WireGuard identifier"
            );
            None
        }
        _ => None,
    }
}

async fn resolve_endpoint(endpoint: &Url, resolver: &Resolver) -> Result<std::net::SocketAddr> {
    let host = endpoint.host().context(InvalidConfigSnafu {
        reason: "WireGuard endpoint URL must include a host".to_string(),
    })?;
    let port = endpoint
        .port_or_known_default()
        .context(InvalidConfigSnafu {
            reason: "WireGuard endpoint URL must include a port".to_string(),
        })?;
    let host_str = match host {
        Host::Domain(domain) => domain.to_string(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => address.to_string(),
    };
    let addrs = resolver
        .resolve_host(&host_str, port)
        .await
        .context(ResolveEndpointSnafu {
            endpoint: endpoint.to_string(),
        })?;
    let mut addrs = addrs.into_iter();
    addrs.next().context(EmptyEndpointResolutionSnafu {
        endpoint: endpoint.to_string(),
    })
}

fn tunnel_peer(config: &TunnelConfig, endpoint: std::net::SocketAddr) -> Result<Peer> {
    let server_public_key =
        PublicKey::from(decode_key("server_public_key", &config.server_public_key)?);
    let mut peer = Peer::new(server_public_key)
        .with_endpoint(endpoint)
        .with_allowed_ips(config.routes.clone());
    peer.keepalive = Some(WIREGUARD_KEEPALIVE_SECS);
    if let Some(preshared_key) = config
        .server_preshared_key
        .as_deref()
        .filter(|value| !value.is_empty())
    {
        peer = peer.with_preshared_key(decode_key("server_preshared_key", preshared_key)?);
    }
    Ok(peer)
}

fn decode_key(name: &'static str, value: &str) -> Result<[u8; 32]> {
    let trimmed = value.trim();
    let bytes = match STANDARD.decode(trimmed) {
        Ok(bytes) => bytes,
        Err(_) => match hex::decode(trimmed) {
            Ok(bytes) => bytes,
            Err(_) => return InvalidKeySnafu { name }.fail(),
        },
    };
    let Ok(key) = bytes.try_into() else {
        return InvalidKeySnafu { name }.fail();
    };
    Ok(key)
}
