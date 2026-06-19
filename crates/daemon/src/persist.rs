//! On-disk persistence for daemon-local config and auth credentials.
//!
//! Two separate files:
//! - `config.json`      — daemon-local settings; survives logout.
//! - `credentials.json` — auth session data; deleted on logout / expiry.
//!
//! Both use atomic writes (temp file → fsync → chmod 0o600 → rename) so a
//! crash mid-write never leaves a corrupt file on disk.

use std::{
    collections::BTreeMap,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use snafu::prelude::*;
use tokio::io::AsyncWriteExt as _;

use crate::token;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("failed to read {}", path.display()))]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },

    #[snafu(display("failed to write {}", path.display()))]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },

    #[snafu(display("failed to create directory {}", path.display()))]
    CreateDir {
        path: PathBuf,
        source: std::io::Error,
    },

    #[snafu(display("failed to parse {}", path.display()))]
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },

    #[snafu(display("failed to serialize data"))]
    Serialize { source: serde_json::Error },

    #[snafu(display("failed to delete {}", path.display()))]
    Delete {
        path: PathBuf,
        source: std::io::Error,
    },

    #[snafu(display("failed to generate initial token hash"))]
    TokenHash,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

// ---------------------------------------------------------------------------
// DaemonConfig (config.json) — survives logout
// ---------------------------------------------------------------------------

/// Daemon-local configuration persisted in `config.json`.
///
/// Contains the bearer-token hash, device identity overrides, and
/// runtime preferences.  This file survives logout and session expiry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// Argon2 hash of the bearer token (the plaintext is shown once at first
    /// run and never stored).
    pub token_hash: String,
    /// Device identity overrides — a subset of what [`ClientIdentity`] carries.
    pub identity: DeviceIdentityConfig,
    /// Bind outbound HTTP/tunnel sockets to a specific interface.
    pub outbound_interface: Option<String>,
    /// Bind DNS resolver sockets to a specific interface.
    pub dns_interface: Option<String>,
    /// Whether to automatically reconnect the VPN tunnel on daemon start.
    pub auto_reconnect: bool,
}

/// Device identity overrides persisted with the daemon config.
///
/// Fields left as `None` inherit from the built-in Android-profile default
/// in [`ClientIdentity::default()`](rustylink_api::ClientIdentity::default).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DeviceIdentityConfig {
    /// A stable, per-install device identifier (SHA-256 of the machine UID).
    pub device_id: String,
    /// OS name override (e.g. `"android"`).
    pub os: Option<String>,
    /// OS version override (e.g. `"35"`).
    pub os_version: Option<String>,
    /// App version override (e.g. `"3.2.16"`).
    pub app_version: Option<String>,
    /// Device brand override (e.g. `"Google"`).
    pub brand: Option<String>,
    /// Device model override (e.g. `"Pixel 8"`).
    pub model: Option<String>,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        let plain_token = token::generate_token();
        let token_hash = token::hash_token(&plain_token).unwrap_or_default();

        let default_identity = rustylink_api::ClientIdentity::default();
        Self {
            token_hash,
            identity: DeviceIdentityConfig {
                device_id: default_identity.device_id,
                ..DeviceIdentityConfig::default()
            },
            outbound_interface: None,
            dns_interface: None,
            auto_reconnect: false,
        }
    }
}

impl DaemonConfig {
    /// Load from `path`, returning `Default` if the file does not exist.
    pub async fn load_or_default(path: &Path) -> Result<Self> {
        match tokio::fs::read(path).await {
            Ok(bytes) => serde_json::from_slice(&bytes).context(ParseSnafu {
                path: path.to_path_buf(),
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(source) => Err(Error::Read {
                path: path.to_path_buf(),
                source,
            }),
        }
    }

    /// Atomically write to `path` (temp + fsync + chmod 0o600 + rename).
    pub async fn save(&self, path: &Path) -> Result<()> {
        let data = serde_json::to_vec_pretty(self).context(SerializeSnafu)?;
        atomic_write(path, &data).await
    }
}

// ---------------------------------------------------------------------------
// PersistedCredentials (credentials.json) — deleted on logout / expiry
// ---------------------------------------------------------------------------

/// Tenant configuration (part of credentials).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TenantConfig {
    /// Primary API base URL for the tenant.
    pub base_url: String,
    /// Backup API URL, used when `use_backup` is `true`.
    pub backup_url: Option<String>,
    /// Whether to prefer the backup URL.
    pub use_backup: bool,
    /// Human-readable tenant name.
    pub name: String,
}

/// Signing configuration (part of credentials).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersistedSigningConfig {
    pub enabled: bool,
    pub activation_code: String,
    pub device_id: String,
}

/// TOTP provisioning data (part of credentials).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersistedTotpConfig {
    /// The `otpauth://` URI.
    pub url: String,
    /// Server clock offset (server − local) in seconds.
    pub time_diff_seconds: i64,
}

/// Last VPN connect parameters (for auto-reconnect).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersistedVpnRequest {
    /// VPN connect mode name (e.g. `"Full"`, `"Split"`, `"Relay"`).
    pub mode: String,
    /// Export ID for the connection.
    pub export_id: i32,
    /// Preferred dot ID, if any.
    pub preferred_dot_id: Option<i32>,
    /// Protocol mode (0 = UDP, 1 = `FeiLian` TCP, 2 = Dual/Auto).
    pub protocol_mode: i32,
    /// Whether this is a reconnect attempt.
    pub reconnect: bool,
}

/// Login API version detected from `/api/login/setting`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoginApiVersion {
    /// Legacy login flow (`/api/login`, `/api/login/code/*`, `/api/mfa/*`).
    #[default]
    Legacy,
    /// V1 login flow (`/api/v1/login`, `/api/v1/login/*`).
    V1,
}

/// Persisted auth credentials (`credentials.json`).
///
/// Contains all session data required to resume an authenticated session:
/// tenant info, signing keys, HTTP cookies, CSRF/knock tokens, TOTP config,
/// and the last VPN request (for auto-reconnect).
///
/// **Deleted on logout or session expiry.**
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PersistedCredentials {
    /// Tenant connection parameters.
    pub tenant: TenantConfig,
    /// Signing / HMAC configuration.
    pub signing: PersistedSigningConfig,
    /// HTTP session cookies (`name → value`).
    pub cookies: BTreeMap<String, String>,
    /// CSRF token from `Set-Cookie: csrf-token=…`.
    pub csrf_token: Option<String>,
    /// Knock token for API request decoration.
    pub knock_token: Option<String>,
    /// TOTP provisioning for auto-reconnect OTP generation.
    pub totp: Option<PersistedTotpConfig>,
    /// Which login API variant the tenant uses.
    pub login_api_version: LoginApiVersion,
    /// Last VPN connect parameters (for auto-reconnect after restart).
    pub last_vpn_request: Option<PersistedVpnRequest>,
    /// ISO 8601 timestamp of when this file was last written.
    pub saved_at: String,
}

impl PersistedCredentials {
    /// Load from `path`, returning `None` if the file does not exist.
    pub async fn load(path: &Path) -> Result<Option<Self>> {
        match tokio::fs::read(path).await {
            Ok(bytes) => {
                let creds = serde_json::from_slice(&bytes).context(ParseSnafu {
                    path: path.to_path_buf(),
                })?;
                Ok(Some(creds))
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(Error::Read {
                path: path.to_path_buf(),
                source,
            }),
        }
    }

    /// Atomically write to `path` (temp + fsync + chmod 0o600 + rename).
    pub async fn save(&self, path: &Path) -> Result<()> {
        let data = serde_json::to_vec_pretty(self).context(SerializeSnafu)?;
        atomic_write(path, &data).await
    }

    /// Delete the credentials file at `path`.
    ///
    /// Returns `Ok(())` if the file does not exist.
    pub async fn delete(path: &Path) -> Result<()> {
        match tokio::fs::remove_file(path).await {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(Error::Delete {
                path: path.to_path_buf(),
                source,
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Private helpers
// ---------------------------------------------------------------------------

/// Atomically write `data` to `path`:
///
/// 1. Ensure the parent directory exists.
/// 2. Write to a sibling `.tmp` file with mode 0o600.
/// 3. `fsync` the temp file.
/// 4. `rename` over the target (atomic on POSIX).
async fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .context(CreateDirSnafu {
                path: parent.to_path_buf(),
            })?;
    }

    let tmp_path = path.with_extension("tmp");
    let mut tmp = tokio::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp_path)
        .await
        .context(WriteSnafu {
            path: tmp_path.clone(),
        })?;
    tmp.write_all(data).await.context(WriteSnafu {
        path: tmp_path.clone(),
    })?;
    tmp.sync_all().await.context(WriteSnafu {
        path: tmp_path.clone(),
    })?;
    drop(tmp);

    tokio::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o600))
        .await
        .context(WriteSnafu {
            path: tmp_path.clone(),
        })?;
    tokio::fs::rename(&tmp_path, path)
        .await
        .context(WriteSnafu {
            path: path.to_path_buf(),
        })
}
