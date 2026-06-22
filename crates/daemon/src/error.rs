//! Daemon error types and their mapping to Connect RPC errors.
//!
//! Errors are split into two enums:
//!
//! * [`RpcFault`] — *expected*, client-actionable outcomes (bad input, missing
//!   precondition, upstream auth/availability). Each maps to a specific Connect
//!   [`ErrorCode`] and carries a human-readable message; logged at **debug**.
//! * [`InternalError`] — failures the client cannot act on (tunnel,
//!   persistence, unexpected upstream/transport errors). Always surfaced as
//!   [`ErrorCode::Internal`] with an opaque message; logged in full at
//!   **error** when converted to a [`ConnectError`].
//!
//! Handlers return [`DaemonError`], a carrier that is either a fault or an
//! internal error. Core (`auth`/`vpn`) errors are classified on the way in: an
//! upstream auth/availability failure becomes a fault, everything else is
//! internal.

use connectrpc::{ConnectError, ErrorCode};
use rustylink_api::Error as ApiError;
use snafu::prelude::*;

// ---------------------------------------------------------------------------
// Expected faults — Connect code + client-facing message (logged at debug)
// ---------------------------------------------------------------------------

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum RpcFault {
    #[snafu(display("invalid argument: {message}"))]
    InvalidArgument { message: String },

    #[snafu(display("no tenant configured; call Activate first"))]
    NotConfigured,

    #[snafu(display("not authenticated; complete login first"))]
    NotAuthenticated,

    #[snafu(display("upstream authentication failed: {message}"))]
    Unauthenticated { message: String },

    #[snafu(display("upstream temporarily unavailable: {message}"))]
    Unavailable { message: String },
}

impl RpcFault {
    const fn code(&self) -> ErrorCode {
        match self {
            Self::InvalidArgument { .. } => ErrorCode::InvalidArgument,
            Self::NotConfigured | Self::NotAuthenticated => ErrorCode::FailedPrecondition,
            Self::Unauthenticated { .. } => ErrorCode::Unauthenticated,
            Self::Unavailable { .. } => ErrorCode::Unavailable,
        }
    }
}

// ---------------------------------------------------------------------------
// Internal errors — opaque to the client (logged at error)
// ---------------------------------------------------------------------------

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum InternalError {
    #[snafu(display("tunnel error: {message}"))]
    Tunnel { message: String },

    #[snafu(display("state persistence failed: {source}"))]
    Persist {
        #[snafu(source(from(crate::persist::Error, Box::new)))]
        source: Box<crate::persist::Error>,
    },

    #[snafu(display("authentication flow error: {source}"))]
    Auth {
        #[snafu(source(from(rustylink_core::auth::Error, Box::new)))]
        source: Box<rustylink_core::auth::Error>,
    },

    #[snafu(display("VPN flow error: {source}"))]
    Vpn {
        #[snafu(source(from(rustylink_core::vpn::Error, Box::new)))]
        source: Box<rustylink_core::vpn::Error>,
    },
}

// ---------------------------------------------------------------------------
// Carrier
// ---------------------------------------------------------------------------

/// The error returned by every RPC handler: an expected [`RpcFault`] or an
/// opaque [`InternalError`].
///
/// Both variants are `#[snafu(transparent)]`: `Display` and `Error::source`
/// delegate to the inner error (no redundant wrapper in the chain), and
/// `transparent` generates the `From<RpcFault>` / `From<InternalError>`
/// conversions the handlers rely on.
#[derive(Debug, Snafu)]
pub enum DaemonError {
    #[snafu(transparent)]
    Fault { source: RpcFault },
    #[snafu(transparent)]
    Internal { source: InternalError },
}

pub type Result<T, E = DaemonError> = std::result::Result<T, E>;

impl From<crate::persist::Error> for DaemonError {
    fn from(error: crate::persist::Error) -> Self {
        Self::Internal {
            source: InternalError::Persist {
                source: Box::new(error),
            },
        }
    }
}

impl From<rustylink_core::auth::Error> for DaemonError {
    fn from(error: rustylink_core::auth::Error) -> Self {
        auth_api(&error).and_then(classify_api).map_or_else(
            || Self::Internal {
                source: InternalError::Auth {
                    source: Box::new(error),
                },
            },
            |fault| Self::Fault { source: fault },
        )
    }
}

impl From<rustylink_core::state::auth::Error> for DaemonError {
    fn from(error: rustylink_core::state::auth::Error) -> Self {
        use rustylink_core::state::auth::Error as AuthFlow;
        match error {
            // Reuse the upstream-API classification for the wrapped call.
            AuthFlow::Auth { source } => Self::from(*source),
            // Provider-selection problems are client-actionable bad input.
            other => Self::Fault {
                source: RpcFault::InvalidArgument {
                    message: other.to_string(),
                },
            },
        }
    }
}

impl From<rustylink_core::vpn::Error> for DaemonError {
    fn from(error: rustylink_core::vpn::Error) -> Self {
        vpn_api(&error).and_then(classify_api).map_or_else(
            || Self::Internal {
                source: InternalError::Vpn {
                    source: Box::new(error),
                },
            },
            |fault| Self::Fault { source: fault },
        )
    }
}

// ---------------------------------------------------------------------------
// Classification of upstream API errors
// ---------------------------------------------------------------------------

/// Map an upstream API error to an expected fault, or `None` when it should be
/// treated as internal (5xx, decode, signing, …).
fn classify_api(error: &ApiError) -> Option<RpcFault> {
    let message = error.to_string();
    match error {
        // Transport/network failures — retryable.
        ApiError::Request { .. } | ApiError::BuildHttpClient { .. } => {
            Some(RpcFault::Unavailable { message })
        }
        // Upstream HTTP 401/403 — session/permission failure.
        ApiError::HttpStatus { status, .. } if matches!(status.as_u16(), 401 | 403) => {
            Some(RpcFault::Unauthenticated { message })
        }
        // CorpLink negative status codes are auth/permission failures.
        ApiError::ApiStatus { code, .. } if *code < 0 => {
            Some(RpcFault::Unauthenticated { message })
        }
        _ => None,
    }
}

fn auth_api(error: &rustylink_core::auth::Error) -> Option<&ApiError> {
    match error {
        rustylink_core::auth::Error::Api { source } => Some(source),
        _ => None,
    }
}

fn vpn_api(error: &rustylink_core::vpn::Error) -> Option<&ApiError> {
    match error {
        rustylink_core::vpn::Error::Api { source } => Some(source),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Connect mapping — debug for faults, error for internal failures
// ---------------------------------------------------------------------------

impl From<DaemonError> for ConnectError {
    fn from(error: DaemonError) -> Self {
        match error {
            DaemonError::Fault { source: fault } => {
                tracing::debug!(%fault, "rpc fault");
                Self::new(fault.code(), fault.to_string())
            }
            DaemonError::Internal { source: internal } => {
                tracing::error!(error = ?internal, "internal rpc failure");
                Self::new(ErrorCode::Internal, "internal error")
            }
        }
    }
}
