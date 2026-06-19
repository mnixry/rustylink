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

    #[snafu(display("state persistence failed"))]
    Persist {
        #[snafu(source(from(crate::persist::Error, Box::new)))]
        source: Box<crate::persist::Error>,
    },

    #[snafu(display("authentication flow error"))]
    Auth {
        #[snafu(source(from(rustylink_core::auth::Error, Box::new)))]
        source: Box<rustylink_core::auth::Error>,
    },

    #[snafu(display("VPN flow error"))]
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
#[derive(Debug)]
pub enum DaemonError {
    Fault(RpcFault),
    Internal(InternalError),
}

pub type Result<T, E = DaemonError> = std::result::Result<T, E>;

impl std::fmt::Display for DaemonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fault(fault) => write!(f, "{fault}"),
            Self::Internal(internal) => write!(f, "{internal}"),
        }
    }
}

impl std::error::Error for DaemonError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Fault(fault) => fault.source(),
            Self::Internal(internal) => internal.source(),
        }
    }
}

impl From<RpcFault> for DaemonError {
    fn from(fault: RpcFault) -> Self {
        Self::Fault(fault)
    }
}

impl From<InternalError> for DaemonError {
    fn from(error: InternalError) -> Self {
        Self::Internal(error)
    }
}

impl From<crate::persist::Error> for DaemonError {
    fn from(error: crate::persist::Error) -> Self {
        Self::Internal(InternalError::Persist {
            source: Box::new(error),
        })
    }
}

impl From<rustylink_core::auth::Error> for DaemonError {
    fn from(error: rustylink_core::auth::Error) -> Self {
        auth_api(&error).and_then(classify_api).map_or_else(
            || {
                Self::Internal(InternalError::Auth {
                    source: Box::new(error),
                })
            },
            Self::Fault,
        )
    }
}

impl From<rustylink_core::vpn::Error> for DaemonError {
    fn from(error: rustylink_core::vpn::Error) -> Self {
        vpn_api(&error).and_then(classify_api).map_or_else(
            || {
                Self::Internal(InternalError::Vpn {
                    source: Box::new(error),
                })
            },
            Self::Fault,
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
            DaemonError::Fault(fault) => {
                tracing::debug!(%fault, "rpc fault");
                Self::new(fault.code(), fault.to_string())
            }
            DaemonError::Internal(internal) => {
                tracing::error!(error = ?internal, "internal rpc failure");
                Self::new(ErrorCode::Internal, "internal error")
            }
        }
    }
}
