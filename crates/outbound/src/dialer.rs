//! Reusable socket dialer bound to a specific outbound network interface.
//!
//! The [`Dialer`] is the central handle consumed by every bypass-traffic path:
//! `WireGuard` UDP/TCP, DNS transports, and the hyper connector.  It is
//! **immutable** — interface changes are handled by rebuilding the Dialer via
//! a full reconnect.
//!
//! ## Socket binding lifecycle
//!
//! 1. `socket2::Socket::new()` + `set_nonblocking(true)`
//! 2. (if [`should_bind`]) `bind_device_by_index_v{4,6}(index)` — **before**
//!    any `bind()`/`connect()`
//! 3. Socket options: `TCP_NODELAY=true`, `SO_REUSEADDR` (UDP)
//! 4. `bind(local)` (UDP) or `connect(dst)` with timeout (TCP)
//! 5. Wrap into `tokio::net::{UdpSocket, TcpStream}`
//!
//! Teardown is just `drop` — the sockopt is per-socket, no system state.

use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    num::NonZeroU32,
    time::Duration,
};

use snafu::prelude::*;
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

use crate::OutboundInterface;

const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const BIND_MAX_RETRIES: u32 = 10;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Typed errors from socket creation, binding, and connection operations.
#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed to create socket: {source}"))]
    SocketCreate { source: io::Error },

    #[snafu(display("failed to bind socket to interface `{interface}`: {source}"))]
    InterfaceBind {
        interface: String,
        source: io::Error,
    },

    #[snafu(display("failed to bind socket to {address}: {source}"))]
    SocketBind {
        address: SocketAddr,
        source: io::Error,
    },

    #[snafu(display("TCP connect to {destination} timed out after {timeout:?}"))]
    ConnectTimeout {
        destination: SocketAddr,
        timeout: Duration,
    },

    #[snafu(display("TCP connect to {destination} failed: {source}"))]
    Connect {
        destination: SocketAddr,
        source: io::Error,
    },

    #[snafu(display("failed to set socket option: {source}"))]
    SetOption { source: io::Error },

    #[snafu(display("interface binding not supported on this platform for `{interface}`"))]
    Unsupported { interface: String },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

// ---------------------------------------------------------------------------
// Dialer
// ---------------------------------------------------------------------------

/// An immutable handle that creates sockets bound to a specific outbound
/// network interface.  Cheap to clone (plain data).
#[derive(Clone, Debug)]
pub struct Dialer {
    interface: Option<OutboundInterface>,
    connect_timeout: Duration,
    tcp_nodelay: bool,
}

impl Default for Dialer {
    fn default() -> Self {
        Self {
            interface: None,
            connect_timeout: DEFAULT_CONNECT_TIMEOUT,
            tcp_nodelay: true,
        }
    }
}

impl Dialer {
    /// Create a dialer optionally bound to a physical interface.
    #[must_use]
    pub fn new(interface: Option<OutboundInterface>) -> Self {
        Self {
            interface,
            ..Self::default()
        }
    }

    /// Override the TCP connect timeout (default: 10 s).
    #[must_use]
    pub const fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    /// Override the `TCP_NODELAY` setting (default: true).
    #[must_use]
    pub const fn with_tcp_nodelay(mut self, nodelay: bool) -> Self {
        self.tcp_nodelay = nodelay;
        self
    }

    /// The bound outbound interface, if any.
    #[must_use]
    pub fn interface(&self) -> Option<&OutboundInterface> {
        self.interface.as_ref()
    }

    /// The bound outbound interface name, or `"<default>"` when unbound.
    #[must_use]
    pub fn interface_name_or_default(&self) -> &str {
        self.interface
            .as_ref()
            .map_or("<default>", |i| i.name.as_str())
    }

    // -----------------------------------------------------------------------
    // TCP
    // -----------------------------------------------------------------------

    /// Dial a TCP connection to `dst`, binding to the outbound interface when
    /// [`should_bind`] allows it.  Sets `TCP_NODELAY`.
    pub async fn connect_tcp(&self, dst: SocketAddr) -> Result<TcpStream> {
        let family = SocketFamily::from_addr(dst);
        let socket = new_socket2(family, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
        if should_bind(dst.ip()) {
            bind_socket_to_interface(&socket, family, self.interface.as_ref())?;
        }
        if self.tcp_nodelay {
            socket.set_tcp_nodelay(true).context(SetOptionSnafu)?;
        }
        let socket = TcpSocket::from_std_stream(socket.into());
        tokio::time::timeout(self.connect_timeout, socket.connect(dst))
            .await
            .map_err(|_| Error::ConnectTimeout {
                destination: dst,
                timeout: self.connect_timeout,
            })?
            .context(ConnectSnafu { destination: dst })
    }

    // -----------------------------------------------------------------------
    // UDP — WireGuard listen sockets (always bind)
    // -----------------------------------------------------------------------

    /// Bind a UDP socket to `bind_addr`, **always** applying interface binding
    /// (used for `WireGuard` listen sockets where the peer endpoint is unknown
    /// at bind time).
    pub fn bind_udp(&self, bind_addr: SocketAddr) -> Result<UdpSocket> {
        let family = SocketFamily::from_addr(bind_addr);
        let socket = new_socket2(family, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
        socket.set_reuse_address(true).context(SetOptionSnafu)?;
        bind_socket_to_interface(&socket, family, self.interface.as_ref())?;
        socket
            .bind(&bind_addr.into())
            .context(SocketBindSnafu { address: bind_addr })?;
        UdpSocket::from_std(socket.into()).context(SocketCreateSnafu)
    }

    /// Bind a matching IPv4 + IPv6 `WireGuard` UDP socket pair on a shared
    /// local port.  Returns **plain** `tokio::net::UdpSocket`s (gotatun
    /// wrapping stays in the tunnel crate).
    pub fn bind_udp_pair(
        &self, addr_v4: Ipv4Addr, addr_v6: Ipv6Addr, port: u16,
    ) -> Result<(UdpSocket, UdpSocket)> {
        let mut retries = 0_u32;
        loop {
            let udp_v4 = self.bind_udp(SocketAddr::from((addr_v4, port)))?;
            let bound_port = udp_v4.local_addr().context(SocketCreateSnafu)?.port();
            match self.bind_udp(SocketAddr::from((addr_v6, bound_port))) {
                Ok(udp_v6) => return Ok((udp_v4, udp_v6)),
                Err(error) if port == 0 && retries < BIND_MAX_RETRIES && is_bind_retry(&error) => {
                    retries += 1;
                    tracing::debug!(
                        bound_port, retries, max_retries = BIND_MAX_RETRIES, %error,
                        "IPv6 UDP port already in use, retrying bind"
                    );
                }
                Err(error) => return Err(error),
            }
        }
    }

    // -----------------------------------------------------------------------
    // UDP — DNS queries (skip bind for non-routable servers)
    // -----------------------------------------------------------------------

    /// Bind a UDP socket for sending a DNS query to `server`.  The local
    /// address is `0.0.0.0:0` or `[::]:0` (by family).  Interface binding is
    /// applied only when [`should_bind`] allows it — so loopback resolvers
    /// like `127.0.0.53` (systemd-resolved) work without binding errors.
    pub fn bind_udp_to(&self, server: SocketAddr) -> Result<UdpSocket> {
        let bind_addr = if server.is_ipv4() {
            SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
        } else {
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
        };
        let family = SocketFamily::from_addr(bind_addr);
        let socket = new_socket2(family, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
        socket.set_reuse_address(true).context(SetOptionSnafu)?;
        if should_bind(server.ip()) {
            bind_socket_to_interface(&socket, family, self.interface.as_ref())?;
        }
        socket
            .bind(&bind_addr.into())
            .context(SocketBindSnafu { address: bind_addr })?;
        UdpSocket::from_std(socket.into()).context(SocketCreateSnafu)
    }
}

// ---------------------------------------------------------------------------
// should_bind — destination classification
// ---------------------------------------------------------------------------

/// Returns `true` if the destination address is routable and should have
/// interface binding applied.  Returns `false` for non-routable addresses
/// where binding would fail or is meaningless.
///
/// Skips: loopback, link-local, multicast, unspecified, broadcast.
/// Binds: global unicast **and** private/ULA/CGNAT (so private corporate
/// endpoints and DNS servers correctly pin to the physical NIC).
#[must_use]
pub fn should_bind(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            !v4.is_loopback()
                && !v4.is_link_local()
                && !v4.is_multicast()
                && !v4.is_unspecified()
                && !v4.is_broadcast()
        }
        IpAddr::V6(v6) => {
            let is_link_local = (v6.segments()[0] & 0xFFC0) == 0xFE80;
            !v6.is_loopback() && !is_link_local && !v6.is_multicast() && !v6.is_unspecified()
        }
    }
}

// ---------------------------------------------------------------------------
// Socket internals
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub(crate) enum SocketFamily {
    V4,
    V6,
}

impl SocketFamily {
    pub(crate) fn from_addr(addr: SocketAddr) -> Self {
        if addr.is_ipv4() { Self::V4 } else { Self::V6 }
    }
}

fn new_socket2(
    family: SocketFamily, socket_type: socket2::Type, protocol: Option<socket2::Protocol>,
) -> Result<socket2::Socket> {
    let domain = match family {
        SocketFamily::V4 => socket2::Domain::IPV4,
        SocketFamily::V6 => socket2::Domain::IPV6,
    };
    let socket = socket2::Socket::new(domain, socket_type, protocol).context(SocketCreateSnafu)?;
    socket.set_nonblocking(true).context(SetOptionSnafu)?;
    Ok(socket)
}

fn bind_socket_to_interface(
    socket: &socket2::Socket, family: SocketFamily, outbound_interface: Option<&OutboundInterface>,
) -> Result<()> {
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

// --- Per-OS binding implementation ---

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn bind_socket_to_interface_inner(
    socket: &socket2::Socket, family: SocketFamily, interface: &OutboundInterface,
) -> Result<()> {
    let index = NonZeroU32::new(interface.index).ok_or_else(|| Error::InterfaceBind {
        interface: interface.name.clone(),
        source: io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("interface `{}` has no OS index", interface.name),
        ),
    })?;
    match family {
        SocketFamily::V4 => socket.bind_device_by_index_v4(Some(index)),
        SocketFamily::V6 => socket.bind_device_by_index_v6(Some(index)),
    }
    .context(InterfaceBindSnafu {
        interface: interface.name.clone(),
    })?;

    // On Linux, also set SO_MARK so packets are tagged with the bypass
    // fwmark. The policy routing rules installed by bypass/linux.rs match
    // on this mark to route bypass traffic through the main table.
    #[cfg(target_os = "linux")]
    {
        use crate::bypass::BYPASS_FWMARK;
        socket.set_mark(BYPASS_FWMARK).context(SetOptionSnafu)?;
    }

    Ok(())
}

#[cfg(target_os = "windows")]
#[allow(unsafe_code)]
fn bind_socket_to_interface_inner(
    socket: &socket2::Socket, family: SocketFamily, interface: &OutboundInterface,
) -> Result<()> {
    use std::os::windows::io::AsRawSocket;

    const IP_UNICAST_IF: i32 = 31;
    const IPV6_UNICAST_IF: i32 = 31;

    let fd = socket.as_raw_socket() as windows_sys::Win32::Networking::WinSock::SOCKET;
    let idx = interface.index;

    // SAFETY: `fd` is a valid socket owned by the `socket2::Socket`; the option
    // value is a stack-allocated `[u8; 4]` with the correct size for the socket
    // option. The socket remains valid for the duration of the setsockopt call.
    let result = match family {
        SocketFamily::V4 => {
            let bytes = idx.to_be_bytes();
            unsafe {
                windows_sys::Win32::Networking::WinSock::setsockopt(
                    fd,
                    windows_sys::Win32::Networking::WinSock::IPPROTO_IP as i32,
                    IP_UNICAST_IF,
                    bytes.as_ptr().cast(),
                    4,
                )
            }
        }
        SocketFamily::V6 => {
            let bytes = idx.to_ne_bytes();
            unsafe {
                windows_sys::Win32::Networking::WinSock::setsockopt(
                    fd,
                    windows_sys::Win32::Networking::WinSock::IPPROTO_IPV6 as i32,
                    IPV6_UNICAST_IF,
                    bytes.as_ptr().cast(),
                    4,
                )
            }
        }
    };
    if result == 0 {
        Ok(())
    } else {
        Err(Error::InterfaceBind {
            interface: interface.name.clone(),
            source: io::Error::last_os_error(),
        })
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn bind_socket_to_interface_inner(
    _socket: &socket2::Socket, _family: SocketFamily, interface: &OutboundInterface,
) -> Result<()> {
    UnsupportedSnafu {
        interface: interface.name.clone(),
    }
    .fail()
}

fn is_bind_retry(error: &Error) -> bool {
    match error {
        Error::SocketBind { source, .. } => {
            source.kind() == io::ErrorKind::AddrInUse
                || (cfg!(target_os = "windows") && source.kind() == io::ErrorKind::PermissionDenied)
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Unit tests (pure logic only — networking tests in tests/integration.rs)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use super::should_bind;

    #[test]
    fn should_bind_classification() {
        // Non-routable -> skip
        assert!(!should_bind(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!should_bind(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))));
        assert!(!should_bind(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1))));
        assert!(!should_bind(IpAddr::V4(Ipv4Addr::UNSPECIFIED)));
        assert!(!should_bind(IpAddr::V4(Ipv4Addr::BROADCAST)));
        assert!(!should_bind(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(!should_bind("fe80::1".parse().unwrap()));
        assert!(!should_bind(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));

        // Routable -> bind (including private ranges)
        assert!(should_bind(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(should_bind(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(should_bind(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(should_bind(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        assert!(should_bind(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(should_bind("2001:4860::1".parse().unwrap()));
        assert!(should_bind("fd00::1".parse().unwrap()));
    }
}
