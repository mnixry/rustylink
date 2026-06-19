use std::collections::HashMap;

use rustylink_proto::proto::rustylink::daemon::persist::v1 as persist;

// ---------------------------------------------------------------------------
// StateChange — returned by core functions, applied by the daemon actor.
//
// Variants carry proto types directly: the daemon's `apply()` writes them into
// the canonical `PersistedState` without any conversion.  Only variants that
// are actually produced by core are included.
// ---------------------------------------------------------------------------

/// A state mutation produced by a core function.
#[derive(Clone, Debug)]
pub enum StateChange {
    /// Tenant configured after activation.
    TenantConfigured {
        tenant: persist::PersistedTenant,
        signing: persist::PersistedSigning,
    },
    /// Cookies updated from an HTTP response `Set-Cookie` header (full set).
    CookiesUpdated { cookies: HashMap<String, String> },
    /// CSRF token updated.
    CsrfTokenUpdated { token: Option<String> },
    /// Signing config updated (from tenant config).
    SigningConfigUpdated { config: persist::PersistedSigning },
    /// OAuth state set (starting third-party login flow).
    OAuthStateSet {
        alias_key: String,
        state: String,
        code_verifier: String,
    },
    /// OAuth state cleared (after callback or logout).
    OAuthCleared,
    /// Session expired (401 or force-logout from server).
    SessionExpired,
    /// Logged out (session cleared).
    LoggedOut,
}
