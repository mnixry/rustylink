use std::net::UdpSocket;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use gotatun::{
    device::{Device, DeviceBuilder, Peer},
    noise::ProtocolIdentifier,
    tun::tun_async_device::TunDevice,
    udp::socket::UdpSocketFactory,
    x25519::{PublicKey, StaticSecret},
};
use ipnetwork::IpNetwork;
use rustylink_api::VpnConnResponse;
use serde::{Deserialize, Serialize};
use snafu::prelude::*;
use tokio::net::lookup_host;

use crate::{
    DnsHijackPlan, DnsHijackTun, DnsProxyRuntime, FeilianTcpTransportFactory, RoutePlan, error,
    error::Result,
};

const ANDROID_LOCAL_PORT_START: u16 = 12912;
const WIREGUARD_KEEPALIVE_SECS: u16 = 25;
const STANDARD_NOISE_CONSTRUCTION: &[u8] = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
const FEILIAN_V2_PROTOCOL_IDENTIFIER: &[u8] = b"CorpLink v1 vpn@feilian-----------";

type UdpTunnelDevice = Device<(UdpSocketFactory, DnsHijackTun, DnsHijackTun)>;
type TcpTunnelDevice = Device<(FeilianTcpTransportFactory, DnsHijackTun, DnsHijackTun)>;

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
    pub endpoint: String,
    pub protocol_mode: Option<i32>,
    pub protocol_version: Option<String>,
    pub protocol_detect_enable: bool,
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
}

enum TunnelDevice {
    Udp(UdpTunnelDevice),
    FeilianTcp(TcpTunnelDevice),
}

enum TunnelTransport {
    Udp,
    FeilianTcp,
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
        conn: &VpnConnResponse, local_params: LocalTunnelParams, endpoint: String,
        protocol_mode: Option<i32>, protocol_detect_enable: bool,
    ) -> Result<Self> {
        if conn.setting.vpn_mtu <= 0 {
            return error::InvalidConfig {
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
        }
    }

    pub async fn start(&mut self) -> Result<()> {
        tracing::info!(
            interface = %self.config.interface_name,
            mtu = self.config.mtu,
            endpoint = %self.config.endpoint,
            "starting tunnel session"
        );
        validate_protocol_mode(&self.config)?;
        let transport = tunnel_transport(&self.config);
        let endpoint = resolve_endpoint(&self.config.endpoint).await?;
        let private_key = StaticSecret::from(decode_key(
            "local_private_key",
            &self.config.local_private_key,
        )?);
        let server_public_key = PublicKey::from(decode_key(
            "server_public_key",
            &self.config.server_public_key,
        )?);
        let mut peer = Peer::new(server_public_key)
            .with_endpoint(endpoint)
            .with_allowed_ips(allowed_ips(&self.config.route_plan)?);
        peer.keepalive = Some(WIREGUARD_KEEPALIVE_SECS);
        if let Some(preshared_key) = self
            .config
            .server_preshared_key
            .as_deref()
            .filter(|value| !value.is_empty())
        {
            peer = peer.with_preshared_key(decode_key("server_preshared_key", preshared_key)?);
        }

        self.config.route_plan.apply()?;
        self.status = TunnelStatus::RoutesApplied;
        self.dns_proxy = DnsProxyRuntime::start(&self.config.dns_plan)
            .await
            .context(error::Dns)?;
        let tun = TunDevice::from_name(&self.config.interface_name).context(error::TunDevice)?;
        let tun = DnsHijackTun::new(tun, &self.config.dns_plan);
        let device = match transport {
            TunnelTransport::Udp => {
                let builder = DeviceBuilder::new()
                    .with_default_udp()
                    .with_ip(tun)
                    .with_private_key(private_key)
                    .with_listen_port(self.config.local_port)
                    .with_peer(peer);
                let builder = with_feilian_protocol_identifier(builder, &self.config);
                TunnelDevice::Udp(builder.build().await.context(error::Device)?)
            }
            TunnelTransport::FeilianTcp => {
                let builder = DeviceBuilder::new()
                    .with_udp(FeilianTcpTransportFactory)
                    .with_ip(tun)
                    .with_private_key(private_key)
                    .with_listen_port(self.config.local_port)
                    .with_peer(peer);
                let builder = with_feilian_protocol_identifier(builder, &self.config);
                TunnelDevice::FeilianTcp(builder.build().await.context(error::Device)?)
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
        && !matches!(mode, 0..=2)
    {
        return error::WireGuard {
            message: format!("unsupported protocol_mode={mode}"),
        }
        .fail();
    }
    Ok(())
}

const fn tunnel_transport(config: &TunnelConfig) -> TunnelTransport {
    match config.protocol_mode {
        Some(1) => TunnelTransport::FeilianTcp,
        _ => TunnelTransport::Udp,
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

async fn resolve_endpoint(endpoint: &str) -> Result<std::net::SocketAddr> {
    let mut addrs = lookup_host(endpoint)
        .await
        .context(error::ResolveEndpoint {
            endpoint: endpoint.to_string(),
        })?;
    addrs.next().context(error::EmptyEndpointResolution {
        endpoint: endpoint.to_string(),
    })
}

fn allowed_ips(route_plan: &RoutePlan) -> Result<Vec<IpNetwork>> {
    let mut networks = route_plan
        .rules
        .iter()
        .map(|rule| {
            rule.cidr.parse::<IpNetwork>().context(error::InvalidRoute {
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
        .map_err(|_| error::InvalidKey { name }.build())?;
    bytes
        .try_into()
        .map_err(|_| error::InvalidKey { name }.build())
}
