//! Outbound network interface selection.
//!
//! [`OutboundInterface`] identifies the physical NIC that bypass traffic
//! (encrypted `WireGuard`, DNS, HTTP) must egress through.  Selection is
//! **route-based** (via `default_net::get_default_interface()`, which does
//! `UdpSocket::connect("1.1.1.1:80") + local_addr()` — the same sentinel-
//! connect / getsockname technique used by mihomo/sing-tun) and **self-loop-
//! safe** (the excluded TUN interface is filtered at every step).

use std::net::IpAddr;

use serde::{Deserialize, Serialize};
use snafu::prelude::*;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("outbound interface `{name}` was not found"))]
    InterfaceNotFound { name: String },

    #[snafu(display("outbound interface `{name}` is not usable for WAN traffic"))]
    UnusableInterface { name: String },

    #[snafu(display("outbound interface `{name}` has no OS interface index"))]
    MissingInterfaceIndex { name: String },

    #[snafu(display(
        "no usable outbound interface found; full-tunnel requires a physical WAN interface"
    ))]
    NoUsableInterface,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

// ---------------------------------------------------------------------------
// OutboundInterface
// ---------------------------------------------------------------------------

/// A resolved physical network interface for bypass-traffic egress.
///
/// Carries the OS interface **index** used by the per-socket `setsockopt`
/// binding (`SO_BINDTOIFINDEX` on Linux, `IP_BOUND_IF` on macOS,
/// `IP_UNICAST_IF` on Windows).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct OutboundInterface {
    pub name: String,
    pub index: u32,
}

impl OutboundInterface {
    /// Select the outbound interface using a layered, self-loop-safe strategy:
    ///
    /// 1. **Configured name** (explicit pin): must be a WAN candidate; errors
    ///    on not-found / unusable rather than silently falling back (the user
    ///    pinned it).
    /// 2. **Route-based default**: `default_net::get_default_interface()` (the
    ///    OS routing table's choice); used if it passes the WAN-candidate
    ///    check.
    /// 3. **Fallback**: among remaining WAN candidates, prefer those with a
    ///    gateway (a default route exists).
    ///
    /// At every step, the `excluded_tun` interface (the VPN's own TUN device)
    /// is filtered out.  When `full_tunnel` is true and no usable WAN interface
    /// is found, returns [`Error::NoUsableInterface`] instead of `Ok(None)` —
    /// because `Ok(None)` means "use OS routing" which, under full-tunnel /1
    /// routes, would loop back into the TUN.
    pub async fn resolve(
        configured: Option<&str>, excluded_tun: Option<&str>, full_tunnel: bool,
    ) -> Result<Option<Self>> {
        let configured = configured
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .map(str::to_owned);
        let excluded = excluded_tun.map(str::to_owned);

        tokio::task::spawn_blocking(move || {
            resolve_blocking(configured.as_deref(), excluded.as_deref(), full_tunnel)
        })
        .await
        .unwrap_or(Err(Error::NoUsableInterface))
    }

    /// Look up an interface by exact name (used to pin the routed DNS transport
    /// to the TUN device).  Returns `None` if the interface is missing or its
    /// OS index is zero.
    pub async fn lookup(name: &str) -> Option<Self> {
        let name = name.to_owned();
        tokio::task::spawn_blocking(move || {
            default_net::get_interfaces()
                .into_iter()
                .find(|i| i.name == name && i.index > 0)
                .and_then(|i| Self::from_interface(i).ok())
        })
        .await
        .ok()
        .flatten()
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
}

// ---------------------------------------------------------------------------
// Blocking helpers (run inside spawn_blocking)
// ---------------------------------------------------------------------------

fn resolve_blocking(
    configured: Option<&str>, excluded_tun: Option<&str>, full_tunnel: bool,
) -> Result<Option<OutboundInterface>> {
    let interfaces = default_net::get_interfaces();

    // (1) Explicit pin
    if let Some(name) = configured {
        let interface =
            interfaces
                .into_iter()
                .find(|i| i.name == name)
                .context(InterfaceNotFoundSnafu {
                    name: name.to_string(),
                })?;
        if !is_wan_candidate(&interface, excluded_tun) {
            return UnusableInterfaceSnafu {
                name: name.to_string(),
            }
            .fail();
        }
        let outbound = OutboundInterface::from_interface(interface)?;
        tracing::info!(
            outbound_interface = %outbound.name,
            outbound_interface_index = outbound.index,
            "using configured outbound interface"
        );
        return Ok(Some(outbound));
    }

    // (2) Route-based default
    match default_net::get_default_interface() {
        Ok(interface) if is_wan_candidate(&interface, excluded_tun) => {
            let outbound = OutboundInterface::from_interface(interface)?;
            tracing::info!(
                outbound_interface = %outbound.name,
                outbound_interface_index = outbound.index,
                "selected default outbound interface"
            );
            return Ok(Some(outbound));
        }
        Ok(interface) => {
            tracing::warn!(
                interface = %interface.name,
                "default interface is not usable for VPN outbound traffic"
            );
        }
        Err(error) => {
            tracing::warn!(%error, "failed to detect default outbound interface");
        }
    }

    // (3) Fallback: WAN candidates, prefer those with a gateway
    let result = best_fallback_interface(interfaces, excluded_tun);
    if result.is_none() && full_tunnel {
        return Err(Error::NoUsableInterface);
    }
    Ok(result)
}

fn best_fallback_interface(
    interfaces: Vec<default_net::Interface>, excluded_tun: Option<&str>,
) -> Option<OutboundInterface> {
    let mut candidates: Vec<_> = interfaces
        .into_iter()
        .filter(|i| is_wan_candidate(i, excluded_tun))
        .collect();
    // Prefer interfaces with a gateway (they have a default route).
    candidates.sort_by_key(|i| i.gateway.is_none());
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

/// Returns `true` if `interface` is a plausible WAN egress candidate:
/// up, not loopback, not a TUN, has at least one IP address, and is not the
/// excluded TUN device.
pub(crate) fn is_wan_candidate(
    interface: &default_net::Interface, excluded_tun: Option<&str>,
) -> bool {
    if excluded_tun.is_some_and(|excluded| interface.name == excluded) {
        return false;
    }
    interface.is_up()
        && !interface.is_loopback()
        && !interface.is_tun()
        && (!interface.ipv4.is_empty() || !interface.ipv6.is_empty())
}

/// Enumerate all system network interfaces with their key properties.
pub async fn list_interfaces() -> Vec<InterfaceInfo> {
    tokio::task::spawn_blocking(|| {
        let default_iface = default_net::get_default_interface().ok();
        default_net::get_interfaces()
            .into_iter()
            .map(|i| {
                let is_default = default_iface.as_ref().is_some_and(|d| d.index == i.index);
                let is_up = i.is_up();
                let is_loopback = i.is_loopback();
                let is_tun = i.is_tun();
                let has_gateway = i.gateway.is_some();
                let ipv4_addrs = i.ipv4.iter().map(|n| IpAddr::V4(n.addr)).collect();
                let ipv6_addrs = i.ipv6.iter().map(|n| IpAddr::V6(n.addr)).collect();
                InterfaceInfo {
                    name: i.name,
                    index: i.index,
                    is_up,
                    is_loopback,
                    is_tun,
                    has_gateway,
                    is_default,
                    ipv4_addrs,
                    ipv6_addrs,
                }
            })
            .collect()
    })
    .await
    .unwrap_or_default()
}

/// Summary of a system network interface (for UI / RPC enumeration).
#[derive(Clone, Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct InterfaceInfo {
    pub name: String,
    pub index: u32,
    pub is_up: bool,
    pub is_loopback: bool,
    pub is_tun: bool,
    pub has_gateway: bool,
    pub is_default: bool,
    pub ipv4_addrs: Vec<IpAddr>,
    pub ipv6_addrs: Vec<IpAddr>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::fn_params_excessive_bools)]
    fn mock_interface(
        name: &str, up: bool, loopback: bool, tun: bool, has_addr: bool, gateway: bool,
    ) -> default_net::Interface {
        use std::net::Ipv4Addr;

        use default_net::ip::Ipv4Net;

        // Interface flag constants (from POSIX / default_net::sys).
        const IFF_UP: u32 = 0x1;
        const IFF_LOOPBACK: u32 = 0x8;
        const IFF_POINTOPOINT: u32 = 0x10;
        const IFF_BROADCAST: u32 = 0x2;

        let mut iface = default_net::Interface::dummy();
        iface.name = name.to_string();
        iface.index = 1;
        let mut flags: u32 = 0;
        if up {
            flags |= IFF_UP;
        }
        if loopback {
            flags |= IFF_LOOPBACK;
        }
        if tun {
            flags |= IFF_UP | IFF_POINTOPOINT;
            flags &= !IFF_BROADCAST;
            flags &= !IFF_LOOPBACK;
        }
        iface.flags = flags;
        if has_addr {
            iface.ipv4 = vec![Ipv4Net {
                addr: Ipv4Addr::new(192, 168, 1, 100),
                prefix_len: 24,
                netmask: Ipv4Addr::new(255, 255, 255, 0),
            }];
        }
        if gateway {
            iface.gateway = Some(default_net::Gateway {
                mac_addr: default_net::mac::MacAddr::zero(),
                ip_addr: std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            });
        }
        iface
    }

    #[test]
    fn wan_candidate_truth_table() {
        // up + not loopback + not tun + has addr + not excluded => true
        assert!(is_wan_candidate(
            &mock_interface("en0", true, false, false, true, true),
            None
        ));
        // excluded => false
        assert!(!is_wan_candidate(
            &mock_interface("utun0", true, false, false, true, true),
            Some("utun0")
        ));
        // down => false
        assert!(!is_wan_candidate(
            &mock_interface("en0", false, false, false, true, true),
            None
        ));
        // loopback => false
        assert!(!is_wan_candidate(
            &mock_interface("lo0", true, true, false, true, false),
            None
        ));
        // tun => false
        assert!(!is_wan_candidate(
            &mock_interface("utun1", false, false, true, true, false),
            None
        ));
        // no address => false
        assert!(!is_wan_candidate(
            &mock_interface("en0", true, false, false, false, true),
            None
        ));
    }

    #[test]
    fn fallback_prefers_gateway() {
        let with_gw = mock_interface("en1", true, false, false, true, true);
        let no_gw = mock_interface("en2", true, false, false, true, false);
        let result = best_fallback_interface(vec![no_gw, with_gw], None);
        assert_eq!(result.as_ref().map(|i| i.name.as_str()), Some("en1"));
    }

    #[test]
    fn self_loop_guard_never_yields_tun() {
        let tun = mock_interface("utun0", false, false, true, true, false);
        let result = best_fallback_interface(vec![tun], None);
        assert!(result.is_none());
    }

    #[test]
    fn from_interface_rejects_zero_index() {
        let mut iface = default_net::Interface::dummy();
        iface.name = "test".to_string();
        iface.index = 0;
        assert!(OutboundInterface::from_interface(iface).is_err());
    }
}
