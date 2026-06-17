use std::net::UdpSocket;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use gotatun::{
    device::{Device, DeviceBuilder, Peer},
    noise::ProtocolIdentifier,
    tun::tun_async_device::TunDevice,
    x25519::{PublicKey, StaticSecret},
};
use ipnetwork::IpNetwork;
use rustylink_api::VpnConnResponse;
use serde::{Deserialize, Serialize};
use snafu::prelude::*;
use strum::{Display, EnumIter, FromRepr};
use tokio::net::lookup_host;
use url::{Host, Url};

use crate::{
    BoundUdpSocketFactory, DnsHijackPlan, DnsHijackTun, DnsProxyRuntime,
    FeilianTcpTransportFactory, OutboundInterface, RoutePlan, route::AppliedRoutes,
};

const ANDROID_LOCAL_PORT_START: u16 = 12912;
const WIREGUARD_KEEPALIVE_SECS: u16 = 25;
const STANDARD_NOISE_CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const FEILIAN_V2_PROTOCOL_IDENTIFIER: &[u8] = b"CorpLink v1 vpn@feilian-----------";

type UdpTunnelDevice = Device<(BoundUdpSocketFactory, DnsHijackTun, DnsHijackTun)>;
type TcpTunnelDevice = Device<(FeilianTcpTransportFactory, DnsHijackTun, DnsHijackTun)>;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("invalid tunnel config: {reason}"))]
    InvalidConfig { reason: String },

    #[snafu(display("route manager failed"))]
    Route { source: crate::route::Error },

    #[snafu(display("TUN device setup failed"))]
    TunDevice {
        source: gotatun::tun::tun_async_device::Error,
    },

    #[snafu(display("DNS hijack setup failed"))]
    Dns { source: crate::dns::Error },

    #[snafu(display("outbound interface selection failed"))]
    Outbound { source: crate::outbound::Error },

    #[snafu(display("gotatun device setup failed"))]
    Device { source: gotatun::device::Error },

    #[snafu(display("failed to resolve WireGuard endpoint `{endpoint}`"))]
    ResolveEndpoint {
        endpoint: String,
        source: std::io::Error,
    },

    #[snafu(display("WireGuard endpoint `{endpoint}` did not resolve to any address"))]
    EmptyEndpointResolution { endpoint: String },

    #[snafu(display("invalid WireGuard key `{name}`"))]
    InvalidKey { name: &'static str },

    #[snafu(display("invalid route CIDR `{cidr}`"))]
    InvalidRoute {
        cidr: String,
        source: ipnetwork::IpNetworkError,
    },

    #[snafu(display("custom WireGuard engine failed: {message}"))]
    WireGuard { message: String },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct LocalTunnelParams {
    pub local_private_key: String,
    pub local_public_key: String,
    pub local_port: u16,
    pub local_dns: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
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
    pub protocol_mode: Option<i32>,
    pub protocol_version: Option<String>,
    pub protocol_detect_enable: bool,
    pub outbound_interface: Option<String>,
    pub route_plan: RoutePlan,
    pub dns_plan: DnsHijackPlan,
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
    dns_proxy: Option<DnsProxyRuntime>,
    routes: Option<AppliedRoutes>,
}

enum TunnelDevice {
    Udp(UdpTunnelDevice),
    FeilianTcp(TcpTunnelDevice),
}

#[derive(Clone, Copy, Debug)]
enum TunnelTransport {
    Udp,
    FeilianTcp,
}

#[derive(Clone, Copy, Debug, Display, EnumIter, Eq, FromRepr, PartialEq)]
#[repr(i32)]
enum ProtocolMode {
    Udp        = 0,
    FeilianTcp = 1,
    Dual       = 2,
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
        protocol_mode: Option<i32>, protocol_detect_enable: bool,
    ) -> Result<Self> {
        if conn.setting.vpn_mtu <= 0 {
            return InvalidConfigSnafu {
                reason: "vpn_mtu must be positive".to_string(),
            }
            .fail();
        }
        let dns_plan =
            DnsHijackPlan::from_vpn_conn(conn).with_local_dns(local_params.local_dns.clone());
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
            protocol_detect_enable,
            outbound_interface: None,
            route_plan: RoutePlan::from_vpn_conn(conn),
            dns_plan,
        })
    }
}

impl TunnelSession {
    #[must_use]
    pub const fn new(config: TunnelConfig) -> Self {
        Self {
            config,
            status: TunnelStatus::Created,
            device: None,
            dns_proxy: None,
            routes: None,
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

    async fn start_inner(&mut self) -> Result<()> {
        tracing::info!(
            interface = %self.config.interface_name,
            mtu = self.config.mtu,
            endpoint = %self.config.endpoint,
            "starting tunnel session"
        );
        validate_protocol_mode(&self.config)?;
        let transport = tunnel_transport(&self.config);
        tracing::info!(
            transport = ?transport,
            protocol_mode = ?self.config.protocol_mode,
            protocol_version = ?self.config.protocol_version,
            dns_proxy_port = self.config.dns_plan.proxy_port,
            split_domain_rules = self.config.dns_plan.domain_rules.len(),
            "selected tunnel runtime options"
        );
        let endpoint = resolve_endpoint(&self.config.endpoint).await?;
        let private_key = StaticSecret::from(decode_key(
            "local_private_key",
            &self.config.local_private_key,
        )?);
        let peer = tunnel_peer(&self.config, endpoint)?;

        let tun = TunDevice::from_name(&self.config.interface_name).context(TunDeviceSnafu)?;
        let actual_interface_name = tun.name().context(TunDeviceSnafu)?;
        if actual_interface_name != self.config.interface_name {
            tracing::info!(
                requested_interface = %self.config.interface_name,
                actual_interface = %actual_interface_name,
                "TUN device assigned OS interface name"
            );
            self.config
                .interface_name
                .clone_from(&actual_interface_name);
        }
        let outbound_interface = OutboundInterface::resolve(
            self.config.outbound_interface.as_deref(),
            Some(&actual_interface_name),
        )
        .context(OutboundSnafu)?;
        if let Some(outbound_interface) = &outbound_interface {
            tracing::info!(
                outbound_interface = %outbound_interface.name,
                outbound_interface_index = outbound_interface.index,
                tunnel_interface = %actual_interface_name,
                "binding tunnel outbound sockets to physical interface"
            );
        } else {
            tracing::warn!(
                tunnel_interface = %actual_interface_name,
                "no outbound interface selected; tunnel sockets will use OS routing"
            );
        }
        let routes = self
            .config
            .route_plan
            .apply(&actual_interface_name)
            .await
            .context(RouteSnafu)?;
        self.routes = Some(routes);
        self.status = TunnelStatus::RoutesApplied;
        self.dns_proxy = DnsProxyRuntime::start(&self.config.dns_plan, outbound_interface.clone())
            .await
            .context(DnsSnafu)?;
        let tun = DnsHijackTun::new(tun, &self.config.dns_plan, outbound_interface.clone());
        let device = match transport {
            TunnelTransport::Udp => {
                let builder = DeviceBuilder::new()
                    .with_udp(BoundUdpSocketFactory::new(outbound_interface.clone()))
                    .with_ip(tun)
                    .with_private_key(private_key)
                    .with_listen_port(self.config.local_port)
                    .with_peer(peer);
                let builder = with_feilian_protocol_identifier(builder, &self.config);
                TunnelDevice::Udp(builder.build().await.context(DeviceSnafu)?)
            }
            TunnelTransport::FeilianTcp => {
                let builder = DeviceBuilder::new()
                    .with_udp(FeilianTcpTransportFactory::new(outbound_interface.clone()))
                    .with_ip(tun)
                    .with_private_key(private_key)
                    .with_listen_port(self.config.local_port)
                    .with_peer(peer);
                let builder = with_feilian_protocol_identifier(builder, &self.config);
                TunnelDevice::FeilianTcp(builder.build().await.context(DeviceSnafu)?)
            }
        };
        self.device = Some(device);
        self.status = TunnelStatus::Running;
        tracing::info!(
            interface = %self.config.interface_name,
            transport = ?self.config.protocol_mode,
            "gotatun WireGuard device started"
        );
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
        tracing::info!(interface = %self.config.interface_name, "stopping tunnel session");
        if let Some(device) = self.device.take() {
            device.stop().await;
        }
        if let Some(dns_proxy) = self.dns_proxy.take() {
            dns_proxy.stop();
        }
        if let Some(routes) = self.routes.take() {
            routes.remove().await.context(RouteSnafu)?;
        }
        self.status = TunnelStatus::Stopped;
        Ok(())
    }

    pub async fn wait(&mut self) {
        if let Some(device) = self.device.as_mut() {
            device.wait().await;
            self.status = TunnelStatus::Stopped;
        }
    }
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

fn validate_protocol_mode(config: &TunnelConfig) -> Result<()> {
    if config.protocol_detect_enable {
        tracing::warn!(
            protocol_version = ?config.protocol_version,
            protocol_mode = ?config.protocol_mode,
            "protocol detection switch thresholds are native-app specific; tunnel starts with the dot's advertised transport"
        );
    }
    if let Some(mode) = config.protocol_mode
        && ProtocolMode::from_repr(mode).is_none()
    {
        return WireGuardSnafu {
            message: format!("unsupported protocol_mode={mode}"),
        }
        .fail();
    }
    Ok(())
}

fn tunnel_transport(config: &TunnelConfig) -> TunnelTransport {
    match config.protocol_mode.and_then(ProtocolMode::from_repr) {
        Some(ProtocolMode::FeilianTcp) => TunnelTransport::FeilianTcp,
        Some(ProtocolMode::Udp | ProtocolMode::Dual) | None => TunnelTransport::Udp,
    }
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

async fn resolve_endpoint(endpoint: &Url) -> Result<std::net::SocketAddr> {
    let host = endpoint.host().context(InvalidConfigSnafu {
        reason: "WireGuard endpoint URL must include a host".to_string(),
    })?;
    let port = endpoint
        .port_or_known_default()
        .context(InvalidConfigSnafu {
            reason: "WireGuard endpoint URL must include a port".to_string(),
        })?;
    let addrs = match host {
        Host::Domain(domain) => lookup_host((domain, port))
            .await
            .context(ResolveEndpointSnafu {
                endpoint: endpoint.to_string(),
            })?
            .collect::<Vec<_>>(),
        Host::Ipv4(address) => lookup_host((address, port))
            .await
            .context(ResolveEndpointSnafu {
                endpoint: endpoint.to_string(),
            })?
            .collect::<Vec<_>>(),
        Host::Ipv6(address) => lookup_host((address, port))
            .await
            .context(ResolveEndpointSnafu {
                endpoint: endpoint.to_string(),
            })?
            .collect::<Vec<_>>(),
    };
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
        .with_allowed_ips(allowed_ips(&config.route_plan)?);
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

fn allowed_ips(route_plan: &RoutePlan) -> Result<Vec<IpNetwork>> {
    let mut networks = route_plan
        .rules
        .iter()
        .map(|rule| {
            rule.cidr.parse::<IpNetwork>().context(InvalidRouteSnafu {
                cidr: rule.cidr.clone(),
            })
        })
        .collect::<Result<Vec<_>>>()?;
    if networks.is_empty() {
        networks.push("0.0.0.0/0".parse().expect("static IPv4 CIDR is valid"));
    }
    Ok(networks)
}

fn decode_key(name: &'static str, value: &str) -> Result<[u8; 32]> {
    let trimmed = value.trim();
    let bytes = STANDARD
        .decode(trimmed)
        .or_else(|_| hex::decode(trimmed))
        .map_err(|_| InvalidKeySnafu { name }.build())?;
    bytes
        .try_into()
        .map_err(|_| InvalidKeySnafu { name }.build())
}
