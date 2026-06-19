//! Loopback + bearer-token request validation, implemented as a tower-http
//! [`ValidateRequest`] so it composes as a standard `ValidateRequestHeaderLayer`
//! rather than a hand-rolled middleware.
//!
//! It requires `Host` to be a loopback address, rejects non-loopback `Origin`
//! (DNS-rebinding guard), and verifies the `Authorization: Bearer` token against
//! the stored argon2 hash.  A verified-token cache avoids paying the argon2 cost
//! on every request (verify-once-per-token, per D11).

use std::sync::{Arc, Mutex};

use axum::body::Body;
use http::{Request, Response, StatusCode, header};
use tower_http::validate_request::ValidateRequest;

use crate::token::verify_token;

#[derive(Clone)]
pub struct AuthState {
    token_hash: Arc<String>,
    verified: Arc<Mutex<Option<String>>>,
}

impl AuthState {
    #[must_use]
    pub fn new(token_hash: String) -> Self {
        Self {
            token_hash: Arc::new(token_hash),
            verified: Arc::new(Mutex::new(None)),
        }
    }

    /// Verify a token, using a fast-path cache to skip argon2 for a token that
    /// was already verified this run.
    fn check(&self, token: &str) -> bool {
        if let Ok(guard) = self.verified.lock()
            && guard.as_deref() == Some(token)
        {
            return true;
        }
        if verify_token(token, &self.token_hash) {
            if let Ok(mut guard) = self.verified.lock() {
                *guard = Some(token.to_string());
            }
            return true;
        }
        false
    }
}

impl<B> ValidateRequest<B> for AuthState {
    type ResponseBody = Body;

    fn validate(&mut self, request: &mut Request<B>) -> Result<(), Response<Self::ResponseBody>> {
        let headers = request.headers();

        // 1. Host must be loopback.
        let host_ok = headers
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .is_none_or(is_loopback_authority);
        if !host_ok {
            tracing::warn!("rejected request with non-loopback Host");
            return Err(deny(StatusCode::FORBIDDEN));
        }

        // 2. Origin, if present, must be loopback (DNS-rebinding guard).
        if let Some(origin) = headers.get(header::ORIGIN).and_then(|v| v.to_str().ok())
            && !is_loopback_origin(origin)
        {
            tracing::warn!(origin, "rejected request with non-loopback Origin");
            return Err(deny(StatusCode::FORBIDDEN));
        }

        // 3. Bearer token.
        let token = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .map(str::trim);
        match token {
            Some(token) if self.check(token) => Ok(()),
            _ => Err(deny(StatusCode::UNAUTHORIZED)),
        }
    }
}

fn deny(status: StatusCode) -> Response<Body> {
    Response::builder()
        .status(status)
        .body(Body::empty())
        .expect("static deny response is valid")
}

/// True if an authority (`host[:port]`) refers to loopback.
fn is_loopback_authority(authority: &str) -> bool {
    is_loopback_host(strip_port(authority))
}

/// True if an `Origin` (`scheme://host[:port]`) refers to loopback.
fn is_loopback_origin(origin: &str) -> bool {
    let after_scheme = origin.split_once("://").map_or(origin, |(_, rest)| rest);
    is_loopback_authority(after_scheme)
}

fn strip_port(authority: &str) -> &str {
    // Handle bracketed IPv6 `[::1]:7878`.
    if let Some(rest) = authority.strip_prefix('[') {
        return rest.split_once(']').map_or(rest, |(host, _)| host);
    }
    authority.split_once(':').map_or(authority, |(host, _)| host)
}

fn is_loopback_host(host: &str) -> bool {
    host == "localhost"
        || host == "::1"
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}
