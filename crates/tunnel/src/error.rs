use snafu::prelude::*;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)), context(suffix(false)))]
pub enum Error {
    #[snafu(display("invalid tunnel config: {reason}"))]
    InvalidConfig { reason: String },

    #[snafu(display("route manager failed: {message}"))]
    RouteManager { message: String },

    #[snafu(display("TUN setup failed"))]
    Tun { source: std::io::Error },

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
