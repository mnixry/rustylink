use std::{fs, path::Path};

use jiff::Timestamp;
use rustylink_api::{ClientIdentity, SessionCookies, SigningConfig, UserInfo};
use serde::{Deserialize, Serialize};
use snafu::prelude::*;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("failed to read state file {}", path.display()))]
    ReadState {
        path: std::path::PathBuf,
        source: std::io::Error,
    },

    #[snafu(display("failed to write state file {}", path.display()))]
    WriteState {
        path: std::path::PathBuf,
        source: std::io::Error,
    },

    #[snafu(display("failed to create state directory {}", path.display()))]
    CreateStateDir {
        path: std::path::PathBuf,
        source: std::io::Error,
    },

    #[snafu(display("failed to parse state file {}", path.display()))]
    ParseState {
        path: std::path::PathBuf,
        source: serde_json::Error,
    },

    #[snafu(display("failed to serialize state"))]
    SerializeState { source: serde_json::Error },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

// ---------------------------------------------------------------------------
// Tenant / OAuth state
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TenantState {
    pub base_url: Option<String>,
    pub backup_url: Option<String>,
    pub use_backup: bool,
    pub name: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct OAuthState {
    pub alias_key: Option<String>,
    pub state: Option<String>,
    pub code_verifier: Option<String>,
}

// ---------------------------------------------------------------------------
// TOTP config — persisted secret for auto-reconnect
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TotpConfig {
    pub secret: String,
    pub algorithm: String,
    pub digits: u32,
    pub period: u32,
}

// ---------------------------------------------------------------------------
// RustylinkState — the auth/session state snapshot
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RustylinkState {
    pub tenant: TenantState,
    pub identity: ClientIdentity,
    pub cookies: SessionCookies,
    pub csrf_token: Option<String>,
    pub knock_token: Option<String>,
    pub signing: SigningConfig,
    pub oauth: OAuthState,
    #[serde(default)]
    pub totp: Option<TotpConfig>,
    pub updated_at_unix: i64,
}

impl RustylinkState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            tenant: TenantState::default(),
            identity: ClientIdentity::default(),
            cookies: SessionCookies::default(),
            csrf_token: None,
            knock_token: None,
            signing: SigningConfig::default(),
            oauth: OAuthState::default(),
            totp: None,
            updated_at_unix: Timestamp::now().as_second(),
        }
    }

    /// Load state from disk, or return a fresh default if the file does not exist.
    pub fn load_or_default(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let bytes = fs::read(path).context(ReadStateSnafu {
            path: path.to_path_buf(),
        })?;
        serde_json::from_slice(&bytes).context(ParseStateSnafu {
            path: path.to_path_buf(),
        })
    }

    /// Persist state to disk (used by the daemon actor).
    pub fn save(&mut self, path: &Path) -> Result<()> {
        self.updated_at_unix = Timestamp::now().as_second();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).context(CreateStateDirSnafu {
                path: parent.to_path_buf(),
            })?;
        }
        let bytes = serde_json::to_vec_pretty(self).context(SerializeStateSnafu)?;
        fs::write(path, bytes).context(WriteStateSnafu {
            path: path.to_path_buf(),
        })
    }

    #[must_use]
    pub fn selected_base_url(&self) -> Option<&str> {
        if self.tenant.use_backup {
            self.tenant
                .backup_url
                .as_deref()
                .or(self.tenant.base_url.as_deref())
        } else {
            self.tenant.base_url.as_deref()
        }
    }
}

impl Default for RustylinkState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// StateChange — returned by core functions, applied by the daemon actor
// ---------------------------------------------------------------------------

/// A state mutation produced by a core function.  The daemon actor applies
/// these to `DaemonState`, persists, and broadcasts.
#[derive(Clone, Debug)]
pub enum StateChange {
    /// Tenant configured after activation.
    TenantConfigured {
        tenant: TenantState,
        signing: SigningConfig,
    },
    /// Cookies updated from an HTTP response `Set-Cookie` header.
    CookiesUpdated { cookies: SessionCookies },
    /// CSRF token updated.
    CsrfTokenUpdated { token: Option<String> },
    /// Knock token updated.
    KnockTokenUpdated { token: Option<String> },
    /// Signing config updated (from tenant config).
    SigningConfigUpdated { config: SigningConfig },
    /// Login API version detected from `LoginSetting.v1_login`.
    LoginApiDetected { v1_login: bool },
    /// Login succeeded; user info available.
    LoginSuccess { user_info: UserInfo },
    /// OTP challenge pending (SMS/email code required).
    OtpChallengePending {
        masked_target: String,
        login_type: String,
    },
    /// MFA challenge pending.
    MfaChallengePending {
        mfa_type: String,
        auth_list: Vec<String>,
        can_skip: bool,
    },
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
    /// TOTP config fetched after login.
    TotpConfigFetched { config: TotpConfig },
}
