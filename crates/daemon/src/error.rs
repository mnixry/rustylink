//! Daemon error type and its mapping to Connect RPC errors.
//!
//! A single [`DaemonError`] wraps every fallible operation in the daemon
//! (core auth/vpn/security flows, tunnel, state machine violations, and
//! request validation). `From<DaemonError> for ConnectError` performs an
//! exhaustive match, logs the full error chain server-side, and returns a
//! canonical Connect code + human-readable message to clients (no structured
//! `ErrorInfo` details — per the plan's D4/A6 decision).

use connectrpc::{ConnectError, ErrorCode};
use rustylink_api::Error as ApiError;
use snafu::prelude::*;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum DaemonError {
    #[snafu(display("invalid argument: {message}"))]
    InvalidArgument { message: String },

    #[snafu(display("no tenant configured; call Activate first"))]
    NotConfigured,

    #[snafu(display("not authenticated; complete login first"))]
    NotAuthenticated,

    #[snafu(display("tunnel is not connected"))]
    NotConnected,

    #[snafu(display("authentication flow error"))]
    #[snafu(context(false))]
    Auth {
        #[snafu(source(from(rustylink_core::auth::Error, Box::new)))]
        source: Box<rustylink_core::auth::Error>,
    },

    #[snafu(display("VPN flow error"))]
    #[snafu(context(false))]
    Vpn {
        #[snafu(source(from(rustylink_core::vpn::Error, Box::new)))]
        source: Box<rustylink_core::vpn::Error>,
    },

    #[snafu(display("security report error"))]
    #[snafu(context(false))]
    Security {
        #[snafu(source(from(rustylink_core::security::Error, Box::new)))]
        source: Box<rustylink_core::security::Error>,
    },

    #[snafu(display("context error"))]
    Context {
        #[snafu(source(from(rustylink_core::context::Error, Box::new)))]
        source: Box<rustylink_core::context::Error>,
    },

    #[snafu(display("tunnel error: {message}"))]
    Tunnel { message: String },

    #[snafu(display("TOTP error: {message}"))]
    Totp { message: String },

    #[snafu(display("state persistence failed"))]
    Persist {
        #[snafu(source(from(crate::state::Error, Box::new)))]
        source: Box<crate::state::Error>,
    },
}

pub type Result<T, E = DaemonError> = std::result::Result<T, E>;

impl DaemonError {
    /// Find the underlying API-layer error in this error's source chain, if any.
    fn api_error(&self) -> Option<&ApiError> {
        match self {
            Self::Auth { source } => match source.as_ref() {
                rustylink_core::auth::Error::Api { source } => Some(source),
                _ => None,
            },
            Self::Vpn { source } => match source.as_ref() {
                rustylink_core::vpn::Error::Api { source } => Some(source),
                _ => None,
            },
            Self::Security { source } => match source.as_ref() {
                rustylink_core::security::Error::Api { source } => Some(source),
                rustylink_core::security::Error::Context { .. } => None,
            },
            Self::Context { source } => match source.as_ref() {
                rustylink_core::context::Error::Api { source } => Some(source),
                rustylink_core::context::Error::MissingBaseUrl => None,
            },
            _ => None,
        }
    }
}

/// Map an API-layer error to a canonical Connect code.
fn api_error_code(error: &ApiError) -> ErrorCode {
    match error {
        // Transport/network failures — retryable.
        ApiError::Request { .. } | ApiError::BuildHttpClient { .. } => ErrorCode::Unavailable,
        // Upstream HTTP error: map 401/403 to Unauthenticated, else Internal.
        ApiError::HttpStatus { status, .. } => {
            if status.as_u16() == 401 || status.as_u16() == 403 {
                ErrorCode::Unauthenticated
            } else {
                ErrorCode::Internal
            }
        }
        // Upstream API status code: negative codes are auth/permission failures
        // in the CorpLink protocol; treat as Unauthenticated, else Internal.
        ApiError::ApiStatus { code, .. } => {
            if *code < 0 {
                ErrorCode::Unauthenticated
            } else {
                ErrorCode::Internal
            }
        }
        _ => ErrorCode::Internal,
    }
}

impl From<DaemonError> for ConnectError {
    fn from(error: DaemonError) -> Self {
        // Log the full error chain server-side for debugging.
        tracing::error!(error = ?error, "RPC failed");

        let code = match &error {
            DaemonError::InvalidArgument { .. } => ErrorCode::InvalidArgument,
            DaemonError::NotConfigured
            | DaemonError::NotAuthenticated
            | DaemonError::NotConnected => ErrorCode::FailedPrecondition,
            DaemonError::Tunnel { .. }
            | DaemonError::Totp { .. }
            | DaemonError::Persist { .. } => ErrorCode::Internal,
            DaemonError::Auth { .. }
            | DaemonError::Vpn { .. }
            | DaemonError::Security { .. }
            | DaemonError::Context { .. } => error
                .api_error()
                .map_or(ErrorCode::Internal, api_error_code),
        };

        Self::new(code, error.to_string())
    }
}
