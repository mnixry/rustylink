use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroU32,
    sync::Arc,
    time::Duration,
};

use gotatun::{
    packet::{Packet, PacketBufPool},
    udp::{UdpRecv, UdpSend, UdpTransportFactory, UdpTransportFactoryParams},
};
use serde::{Deserialize, Serialize};
use snafu::prelude::*;
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

const BIND_MAX_RETRIES: u32 = 10;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("outbound interface `{name}` was not found"))]
    InterfaceNotFound { name: String },

    #[snafu(display("outbound interface `{name}` is not usable for WAN traffic"))]
    UnusableInterface { name: String },

    #[snafu(display("outbound interface `{name}` has no OS interface index"))]
    MissingInterfaceIndex { name: String },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OutboundInterface {
    pub name: String,
    pub index: u32,
}

#[derive(Clone, Debug, Default)]
pub struct BoundUdpSocketFactory {
    outbound_interface: Option<OutboundInterface>,
}

#[derive(Clone)]
pub struct BoundUdpSocket {
    inner: Arc<UdpSocket>,
}

#[derive(Clone, Copy, Debug)]
enum SocketFamily {
    V4,
    V6,
}

impl OutboundInterface {
    pub fn resolve(
        configured: Option<&str>, excluded_interface: Option<&str>,
    ) -> Result<Option<Self>> {
        let configured = configured.map(str::trim).filter(|value| !value.is_empty());
        let interfaces = default_net::get_interfaces();

        if let Some(name) = configured {
            let interface = interfaces
                .into_iter()
                .find(|interface| interface.name == name)
                .context(InterfaceNotFoundSnafu {
                    name: name.to_string(),
                })?;
            if !is_wan_candidate(&interface, excluded_interface) {
                return UnusableInterfaceSnafu {
                    name: name.to_string(),
                }
                .fail();
            }
            let outbound = Self::from_interface(interface)?;
            tracing::info!(
                outbound_interface = %outbound.name,
                outbound_interface_index = outbound.index,
                "using configured outbound interface"
            );
            return Ok(Some(outbound));
        }

        match default_net::get_default_interface() {
            Ok(interface) if is_wan_candidate(&interface, excluded_interface) => {
                let outbound = Self::from_interface(interface)?;
                tracing::info!(
                    outbound_interface = %outbound.name,
                    outbound_interface_index = outbound.index,
                    "selected default outbound interface"
                );
                Ok(Some(outbound))
            }
            Ok(interface) => {
                tracing::warn!(
                    interface = %interface.name,
                    "default interface is not usable for VPN outbound traffic"
                );
                Ok(best_fallback_interface(interfaces, excluded_interface))
            }
            Err(error) => {
                tracing::warn!(%error, "failed to detect default outbound interface");
                Ok(best_fallback_interface(interfaces, excluded_interface))
            }
        }
    }

    fn from_interface(interface: default_net::Interface) -> Result<Self> {
        if interface.index == 0 {
            return MissingInterfaceIndexSnafu {
                name: interface.name,
            }
            .fail();
        }
        Ok(Self {
            name: interface.name,
            index: interface.index,
        })
    }

    /// Look up an interface by name (used to pin the routed DNS transport to
    /// the TUN device, so its packets egress the tunnel rather than racing
    /// the system routing table). Returns `None` if the interface is not
    /// found or its OS index isn't populated yet.
    #[must_use]
    pub fn lookup(name: &str) -> Option<Self> {
        default_net::get_interfaces()
            .into_iter()
            .find(|interface| interface.name == name && interface.index > 0)
            .and_then(|interface| Self::from_interface(interface).ok())
    }
}

impl BoundUdpSocketFactory {
    #[must_use]
    pub const fn new(outbound_interface: Option<OutboundInterface>) -> Self {
        Self { outbound_interface }
    }
}

impl UdpTransportFactory for BoundUdpSocketFactory {
    type SendV4 = BoundUdpSocket;
    type SendV6 = BoundUdpSocket;
    type RecvV4 = BoundUdpSocket;
    type RecvV6 = BoundUdpSocket;

    async fn bind(
        &mut self, params: &UdpTransportFactoryParams,
    ) -> io::Result<((Self::SendV4, Self::RecvV4), (Self::SendV6, Self::RecvV6))> {
        let (udp_v4, udp_v6) = bind_udp_pair(
            params.addr_v4,
            params.addr_v6,
            params.port,
            self.outbound_interface.as_ref(),
        )?;
        Ok(((udp_v4.clone(), udp_v4), (udp_v6.clone(), udp_v6)))
    }
}

impl UdpSend for BoundUdpSocket {
    type SendManyBuf = ();

    async fn send_to(&self, packet: Packet, destination: SocketAddr) -> io::Result<()> {
        self.inner.send_to(&packet, destination).await?;
        Ok(())
    }

    fn local_addr(&self) -> io::Result<Option<SocketAddr>> {
        self.inner.local_addr().map(Some)
    }
}

impl UdpRecv for BoundUdpSocket {
    type RecvManyBuf = ();

    async fn recv_from(&mut self, pool: &mut PacketBufPool) -> io::Result<(Packet, SocketAddr)> {
        let mut buf = vec![0_u8; u16::MAX as usize];
        let (len, source) = self.inner.recv_from(&mut buf).await?;
        let mut packet = pool.get();
        packet.buf_mut().clear();
        packet.buf_mut().extend_from_slice(&buf[..len]);
        Ok((packet, source))
    }
}

pub fn bind_udp(
    bind_addr: SocketAddr, outbound_interface: Option<&OutboundInterface>,
) -> io::Result<UdpSocket> {
    let family = SocketFamily::from_addr(bind_addr);
    let socket = new_socket2(family, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    bind_socket_to_interface(&socket, family, outbound_interface)?;
    socket.bind(&bind_addr.into())?;
    UdpSocket::from_std(socket.into())
}

pub async fn connect_tcp(
    destination: SocketAddr, outbound_interface: Option<&OutboundInterface>, timeout: Duration,
) -> io::Result<TcpStream> {
    let family = SocketFamily::from_addr(destination);
    let socket = new_socket2(family, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    bind_socket_to_interface(&socket, family, outbound_interface)?;
    let socket = TcpSocket::from_std_stream(socket.into());
    tokio::time::timeout(timeout, socket.connect(destination))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TCP dial timed out"))?
}

/// Bind the matching IPv4/IPv6 `WireGuard` UDP socket pair on a shared local
/// port. A fixed `port` is bound directly; an ephemeral port (`0`) is resolved
/// from the IPv4 socket and copied to IPv6, retrying that copy if the OS hands
/// the same number to another socket first.
fn bind_udp_pair(
    addr_v4: Ipv4Addr, addr_v6: Ipv6Addr, port: u16, outbound_interface: Option<&OutboundInterface>,
) -> io::Result<(BoundUdpSocket, BoundUdpSocket)> {
    let mut retries = 0_u32;
    loop {
        let udp_v4 = bind_bound_udp(SocketAddr::from((addr_v4, port)), outbound_interface)?;
        let bound_port = udp_v4.inner.local_addr()?.port();
        match bind_bound_udp(SocketAddr::from((addr_v6, bound_port)), outbound_interface) {
            Ok(udp_v6) => return Ok((udp_v4, udp_v6)),
            // Only an ephemeral bind can race for its port; a fixed port that
            // fails on IPv6 is a genuine error.
            Err(error)
                if port == 0 && is_bind_retry_error(&error) && retries < BIND_MAX_RETRIES =>
            {
                retries += 1;
                tracing::debug!(
                    bound_port,
                    retries,
                    max_retries = BIND_MAX_RETRIES,
                    "IPv6 UDP port already in use, retrying WireGuard UDP bind"
                );
            }
            Err(error) => return Err(error),
        }
    }
}

fn bind_bound_udp(
    bind_addr: SocketAddr, outbound_interface: Option<&OutboundInterface>,
) -> io::Result<BoundUdpSocket> {
    Ok(BoundUdpSocket {
        inner: Arc::new(bind_udp(bind_addr, outbound_interface)?),
    })
}

fn new_socket2(
    family: SocketFamily, socket_type: socket2::Type, protocol: Option<socket2::Protocol>,
) -> io::Result<socket2::Socket> {
    let domain = match family {
        SocketFamily::V4 => socket2::Domain::IPV4,
        SocketFamily::V6 => socket2::Domain::IPV6,
    };
    let socket = socket2::Socket::new(domain, socket_type, protocol)?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

fn bind_socket_to_interface(
    socket: &socket2::Socket, family: SocketFamily, outbound_interface: Option<&OutboundInterface>,
) -> io::Result<()> {
    let Some(interface) = outbound_interface else {
        return Ok(());
    };
    bind_socket_to_interface_inner(socket, family, interface)?;
    tracing::trace!(
        outbound_interface = %interface.name,
        outbound_interface_index = interface.index,
        ?family,
        "bound socket to outbound interface"
    );
    Ok(())
}

#[cfg(any(
    target_os = "android",
    target_os = "ios",
    target_os = "linux",
    target_os = "macos",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos",
    target_os = "illumos",
    target_os = "solaris",
))]
fn bind_socket_to_interface_inner(
    socket: &socket2::Socket, family: SocketFamily, interface: &OutboundInterface,
) -> io::Result<()> {
    let index = NonZeroU32::new(interface.index).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("interface `{}` has no OS index", interface.name),
        )
    })?;
    match family {
        SocketFamily::V4 => socket.bind_device_by_index_v4(Some(index)),
        SocketFamily::V6 => socket.bind_device_by_index_v6(Some(index)),
    }
}

#[cfg(not(any(
    target_os = "android",
    target_os = "ios",
    target_os = "linux",
    target_os = "macos",
    target_os = "tvos",
    target_os = "visionos",
    target_os = "watchos",
    target_os = "illumos",
    target_os = "solaris",
)))]
fn bind_socket_to_interface_inner(
    _socket: &socket2::Socket, _family: SocketFamily, interface: &OutboundInterface,
) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        format!(
            "binding sockets to outbound interface `{}` is not supported on this target",
            interface.name
        ),
    ))
}

impl SocketFamily {
    fn from_addr(addr: SocketAddr) -> Self {
        if addr.is_ipv4() { Self::V4 } else { Self::V6 }
    }
}

fn best_fallback_interface(
    interfaces: Vec<default_net::Interface>, excluded_interface: Option<&str>,
) -> Option<OutboundInterface> {
    let mut candidates = interfaces
        .into_iter()
        .filter(|interface| is_wan_candidate(interface, excluded_interface))
        .collect::<Vec<_>>();
    candidates.sort_by_key(|interface| interface.gateway.is_none());
    let selected = candidates.into_iter().next()?;
    match OutboundInterface::from_interface(selected) {
        Ok(outbound) => {
            tracing::info!(
                outbound_interface = %outbound.name,
                outbound_interface_index = outbound.index,
                "selected fallback outbound interface"
            );
            Some(outbound)
        }
        Err(error) => {
            tracing::warn!(%error, "fallback outbound interface was unusable");
            None
        }
    }
}

fn is_wan_candidate(interface: &default_net::Interface, excluded_interface: Option<&str>) -> bool {
    if excluded_interface.is_some_and(|excluded| interface.name == excluded) {
        return false;
    }
    interface.is_up()
        && !interface.is_loopback()
        && !interface.is_tun()
        && (!interface.ipv4.is_empty() || !interface.ipv6.is_empty())
}

fn is_bind_retry_error(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::AddrInUse
        || (cfg!(target_os = "windows") && error.kind() == io::ErrorKind::PermissionDenied)
}
