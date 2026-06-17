use std::path::PathBuf;

use snafu::Snafu;

#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub))]
pub enum CliError {
    #[snafu(display("application context operation failed"))]
    CoreContext {
        #[snafu(source(from(rustylink_core::context::Error, Box::new)))]
        source: Box<rustylink_core::context::Error>,
    },

    #[snafu(display("authentication operation failed"))]
    Auth {
        #[snafu(source(from(rustylink_core::auth::Error, Box::new)))]
        source: Box<rustylink_core::auth::Error>,
    },

    #[snafu(display("VPN core operation failed"))]
    Vpn {
        #[snafu(source(from(rustylink_core::vpn::Error, Box::new)))]
        source: Box<rustylink_core::vpn::Error>,
    },

    #[snafu(display("security report operation failed"))]
    Security {
        #[snafu(source(from(rustylink_core::security::Error, Box::new)))]
        source: Box<rustylink_core::security::Error>,
    },

    #[snafu(display("tunnel operation failed"))]
    Tunnel { source: rustylink_tunnel::Error },

    #[snafu(display("outbound interface selection failed"))]
    OutboundInterface {
        source: rustylink_tunnel::outbound::Error,
    },

    #[snafu(display("failed to read {}", path.display()))]
    ReadFile {
        path: PathBuf,
        source: std::io::Error,
    },

    #[snafu(display("failed to parse JSON from {}", path.display()))]
    ParseJson {
        path: PathBuf,
        source: serde_json::Error,
    },

    #[snafu(display("failed to render JSON output"))]
    RenderJson { source: serde_json::Error },

    #[snafu(display("invalid VPN mode `{value}`; expected one of: {expected}"))]
    InvalidVpnMode { value: String, expected: String },

    #[snafu(display("no export_id was provided and /api/setting did not return one"))]
    MissingExportId,

    #[snafu(display("third-party login response did not include any providers"))]
    MissingThirdPartyProviders,

    #[snafu(display(
        "multiple third-party login providers were returned ({count}); pass --alias, --alias-key, or --index"
    ))]
    AmbiguousThirdPartyProvider { count: usize },

    #[snafu(display("third-party provider selection `{value}` is invalid; choose 1..={max}"))]
    InvalidThirdPartySelection { value: String, max: usize },

    #[snafu(display("third-party provider `{provider}` is missing a login URL"))]
    MissingThirdPartyLoginUrl { provider: String },

    #[snafu(display("third-party provider `{provider}` is missing an OAuth alias_key"))]
    MissingThirdPartyAliasKey { provider: String },

    #[snafu(display("third-party provider `{provider}` is missing a polling token"))]
    MissingThirdPartyToken { provider: String },

    #[snafu(display("OAuth callback input is missing `{param}`"))]
    MissingOAuthCallbackParam { param: &'static str },

    #[snafu(display("invalid OAuth callback URL/input `{value}`"))]
    InvalidOAuthCallbackInput {
        value: String,
        source: url::ParseError,
    },

    #[snafu(display("poll interval must be greater than 0 milliseconds"))]
    InvalidPollInterval,

    #[snafu(display(
        "third-party login token was not accepted within {timeout_seconds}s; last response: {last_error}"
    ))]
    ThirdPartyPollTimeout {
        timeout_seconds: u64,
        last_error: String,
    },

    #[snafu(display("failed to wait for Ctrl-C"))]
    WaitForSignal { source: std::io::Error },
}

pub type Result<T, E = CliError> = std::result::Result<T, E>;
