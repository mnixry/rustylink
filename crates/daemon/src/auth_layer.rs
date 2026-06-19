//! Bearer-token request validation, implemented as a tower-http
//! [`ValidateRequest`] so it composes as a standard
//! `ValidateRequestHeaderLayer`.
//!
//! Network isolation is provided by binding the listener to loopback (see
//! `main`), and browser-based cross-origin / DNS-rebinding attacks are blocked
//! by a restrictive CORS layer.  This layer's sole job is to verify the
//! `Authorization: Bearer` token against the stored argon2 hash, with a
//! verified-token cache to avoid paying the argon2 cost on every request
//! (verify-once-per-token, per D11).

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
        let token = request
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.strip_prefix("Bearer "))
            .map(str::trim);
        match token {
            Some(token) if self.check(token) => Ok(()),
            _ => Err(deny(StatusCode::UNAUTHORIZED)),
        }
    }
}

fn deny(status: StatusCode) -> Response<Body> {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = status;
    response
}
