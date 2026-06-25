//! Cross-platform route-bypass for full-tunnel VPN.
//!
//! On macOS, `IP_BOUND_IF` restricts a socket to an interface but does **not**
//! bypass the routing table.  When full-tunnel `/1` routes capture all traffic
//! to the TUN, sockets bound to the physical NIC have no valid route and
//! `connect()` returns `ENETUNREACH`.  A **scoped default route** (`route add
//! -ifscope <iface> 0/0 <gateway>`) restores reachability for bound sockets
//! without affecting unbound traffic.
//!
//! On Linux, `SO_BINDTODEVICE` is sufficient for socket-level bypass, but for
//! robustness this module also installs policy routing rules (`ip rule` +
//! `fwmark`) so marked packets bypass the TUN routing table entirely.
//!
//! On Windows, `IP_UNICAST_IF` effectively overrides the routing table; no
//! route-level bypass is needed.
//!
//! # Architecture
//!
//! Follows the mullvad `talpid-dns` pattern: a **private trait**
//! [`RouteBypassT`] defines the per-platform contract.  `#[cfg]` + `#[path]`
//! selects exactly one platform module compiled as `mod imp`.  The public
//! [`RouteBypass`] wrapper delegates to `imp::RouteBypass`.

#[cfg(target_os = "macos")]
#[path = "bypass/macos.rs"]
mod imp;

#[cfg(target_os = "linux")]
#[path = "bypass/linux.rs"]
mod imp;

#[cfg(target_os = "windows")]
#[path = "bypass/windows.rs"]
mod imp;

#[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
#[path = "bypass/unsupported.rs"]
mod imp;

pub use imp::Error;

use crate::OutboundInterface;

/// Private contract each platform must satisfy.
#[async_trait::async_trait]
trait RouteBypassT: Sized + Send {
    type Error: std::error::Error + Send + Sync + 'static;

    /// Install route-table entries that allow interface-bound sockets to
    /// reach destinations despite `/1` full-tunnel routes.
    ///
    /// A no-op when `full_tunnel` is false (split-tunnel mode needs no
    /// route bypass).
    async fn setup(interface: &OutboundInterface, full_tunnel: bool) -> Result<Self, Self::Error>;

    /// Remove any route-table entries installed by [`setup`].
    async fn teardown(self) -> Result<(), Self::Error>;
}

/// Cross-platform route-bypass handle.
///
/// Constructed during tunnel setup (before `/1` routes are applied), dropped
/// during teardown (after `/1` routes are removed).  On platforms where no
/// route-level bypass is needed the handle is a zero-cost no-op.
pub struct RouteBypass {
    inner: imp::RouteBypass,
}

impl RouteBypass {
    /// Install the platform-specific route bypass for the given outbound
    /// interface.
    pub async fn setup(interface: &OutboundInterface, full_tunnel: bool) -> Result<Self, Error> {
        let inner = imp::RouteBypass::setup(interface, full_tunnel).await?;
        Ok(Self { inner })
    }

    /// Remove any route-table entries installed by [`setup`].
    pub async fn teardown(self) -> Result<(), Error> {
        self.inner.teardown().await
    }
}
