//! Unsupported-platform route bypass: stub that always errors.

use snafu::prelude::*;

use crate::OutboundInterface;

#[derive(Debug, Snafu)]
#[snafu(display("route bypass is not supported on this platform"))]
pub struct Error;

pub struct RouteBypass;

#[async_trait::async_trait]
impl super::RouteBypassT for RouteBypass {
    type Error = Error;

    async fn setup(_interface: &OutboundInterface, _full_tunnel: bool) -> Result<Self, Error> {
        UnsupportedSnafu.fail()
    }

    async fn teardown(self) -> Result<(), Error> {
        Ok(())
    }
}
