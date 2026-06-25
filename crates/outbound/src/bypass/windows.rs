//! Windows route bypass: no-op.
//!
//! `IP_UNICAST_IF` / `IPV6_UNICAST_IF` effectively overrides the routing
//! table on Windows.  No route-level bypass is needed.

use crate::OutboundInterface;

pub type Error = std::convert::Infallible;

pub struct RouteBypass;

#[async_trait::async_trait]
impl super::RouteBypassT for RouteBypass {
    type Error = Error;

    async fn setup(_interface: &OutboundInterface, _full_tunnel: bool) -> Result<Self, Error> {
        Ok(Self)
    }

    async fn teardown(self) -> Result<(), Error> {
        Ok(())
    }
}
