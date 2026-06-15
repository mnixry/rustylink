use std::path::PathBuf;

use snafu::prelude::*;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)), context(suffix(false)))]
pub enum Error {
    #[snafu(display("API operation failed"))]
    Api {
        #[snafu(source(from(rustylink_api::Error, Box::new)))]
        source: Box<rustylink_api::Error>,
    },

    #[snafu(display("failed to read state file {}", path.display()))]
    ReadState {
        path: PathBuf,
        source: std::io::Error,
    },

    #[snafu(display("failed to write state file {}", path.display()))]
    WriteState {
        path: PathBuf,
        source: std::io::Error,
    },

    #[snafu(display("failed to create state directory {}", path.display()))]
    CreateStateDir {
        path: PathBuf,
        source: std::io::Error,
    },

    #[snafu(display("failed to parse state file {}", path.display()))]
    ParseState {
        path: PathBuf,
        source: serde_json::Error,
    },

    #[snafu(display("failed to serialize state"))]
    SerializeState { source: serde_json::Error },

    #[snafu(display("no tenant base URL configured; run activate with --base-url first"))]
    MissingBaseUrl,

    #[snafu(display("no OAuth verifier is stored; run login oauth-start first"))]
    MissingOAuthVerifier,

    #[snafu(display("invalid URL `{value}`"))]
    InvalidUrl {
        value: String,
        source: url::ParseError,
    },

    #[snafu(display("no VPN dots were returned by /api/vpn/list"))]
    NoVpnDots,

    #[snafu(display("no VPN dot supports requested mode `{mode}`"))]
    NoSupportedVpnDot { mode: String },

    #[snafu(display("VPN config response did not contain data"))]
    MissingVpnConfigData,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
