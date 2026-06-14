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

    #[snafu(display("custom WireGuard engine failed: {message}"))]
    WireGuard { message: String },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
