//! Bearer-token generation.
//!
//! A fresh 256-bit token is generated on every startup, printed to the log, and
//! kept only in memory — it is never written to disk (Jupyter-notebook style).
//! Validation is handled by tower-http's `ValidateRequestHeaderLayer::bearer`.

/// Generate a fresh 256-bit bearer token, hex-encoded.
#[must_use]
pub fn generate_token() -> String {
    hex::encode(rand::random::<[u8; 32]>())
}
