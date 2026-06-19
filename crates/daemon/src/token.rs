//! Bearer-token generation, hashing (argon2), and verification.
//!
//! On first run a 256-bit token is generated, printed once to stderr, and only
//! its argon2 hash is persisted in `DaemonState.token_hash` (D11). Subsequent
//! runs reuse the hash; `--rotate-token` regenerates.

use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher as _, PasswordVerifier as _, SaltString, rand_core::OsRng},
};

/// Generate a fresh 256-bit bearer token, hex-encoded.
#[must_use]
pub fn generate_token() -> String {
    hex::encode(rand::random::<[u8; 32]>())
}

/// Hash a token with argon2id, returning a PHC-format string.
#[must_use]
pub fn hash_token(token: &str) -> Option<String> {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(token.as_bytes(), &salt)
        .ok()
        .map(|hash| hash.to_string())
}

/// Verify a presented token against a stored argon2 hash (constant-time).
#[must_use]
pub fn verify_token(token: &str, hash: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(token.as_bytes(), &parsed)
        .is_ok()
}
