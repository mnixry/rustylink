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

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("failed to read {}: {source}", path.display()))]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },

    #[snafu(display("failed to write {}: {source}", path.display()))]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },

    #[snafu(display("failed to create directory {}: {source}", path.display()))]
    CreateDir {
        path: PathBuf,
        source: std::io::Error,
    },

    #[snafu(display("failed to parse {}: {source}", path.display()))]
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },

    #[snafu(display("failed to serialize data: {source}"))]
    Serialize { source: serde_json::Error },

    #[snafu(display("failed to delete {}: {source}", path.display()))]
    Delete {
        path: PathBuf,
        source: std::io::Error,
    },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Daemon-local configuration persisted in `config.json`.
///
/// Holds device identity overrides and runtime preferences. The bearer token
/// is generated fresh each run and never stored here. This file survives logout
/// and session expiry.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct DaemonConfig {
    /// Device identity overrides — a subset of what [`ClientIdentity`] carries.
    pub identity: DeviceIdentityConfig,
    /// Bind outbound HTTP/tunnel sockets to a specific interface.
    pub outbound_interface: Option<String>,
    /// Bind DNS resolver sockets to a specific interface.
    pub dns_interface: Option<String>,
    /// Name of the TUN device to create (empty/unset = platform default).
    pub tun_interface: Option<String>,
    /// Whether to automatically reconnect the VPN tunnel on daemon start.
    pub auto_reconnect: bool,
}

/// The persisted device identity.
///
/// A complete identity (after
/// [`ensure_full`](DeviceIdentityConfig::ensure_full))
/// mirrors [`ClientIdentity`](rustylink_api::ClientIdentity). Optional fields
/// left unset are merged from the built-in Android-profile default on load.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct DeviceIdentityConfig {
    /// A stable, per-install device identifier (SHA-256 of the machine UID).
    pub device_id: String,
    /// OS name (e.g. `"Android"`).
    pub os: Option<String>,
    /// OS version (e.g. `"35"`).
    pub os_version: Option<String>,
    /// App version (e.g. `"3.2.16"`).
    pub app_version: Option<String>,
    /// Device brand (e.g. `"google"`).
    pub brand: Option<String>,
    /// Device model (e.g. `"Pixel 8"`).
    pub model: Option<String>,
    /// Build number (e.g. `"2008"`).
    pub build_number: Option<String>,
    /// OS security-patch date (e.g. `"2025-05-05"`).
    pub os_version_patch: Option<String>,
    /// Client source identifier (e.g. `"FeiLian"`).
    pub client_source: Option<String>,
    /// UI language (e.g. `"en"`).
    pub language: Option<String>,
    /// HTTP `User-Agent` string.
    pub user_agent: Option<String>,
}

impl DeviceIdentityConfig {
    /// True when the device id and every identity field is populated.
    #[must_use]
    pub fn is_full(&self) -> bool {
        !self.device_id.trim().is_empty()
            && [
                &self.os,
                &self.os_version,
                &self.app_version,
                &self.brand,
                &self.model,
                &self.build_number,
                &self.os_version_patch,
                &self.client_source,
                &self.language,
                &self.user_agent,
            ]
            .into_iter()
            .all(|field| {
                field
                    .as_deref()
                    .is_some_and(|value| !value.trim().is_empty())
            })
    }

    /// Ensure every field is populated by merging a freshly-generated full
    /// default identity (with a stable device id) into any missing field.
    ///
    /// Returns `true` when anything was filled, so the caller can overwrite the
    /// persisted config with the now-complete identity.
    pub fn ensure_full(&mut self) -> bool {
        if self.is_full() {
            return false;
        }
        let default = rustylink_api::ClientIdentity::default();
        if self.device_id.trim().is_empty() {
            self.device_id = default.device_id;
        }
        merge_field(&mut self.os, default.os);
        merge_field(&mut self.os_version, default.os_version);
        merge_field(&mut self.app_version, default.app_version);
        merge_field(&mut self.brand, default.brand);
        merge_field(&mut self.model, default.model);
        merge_field(&mut self.build_number, default.build_number);
        merge_field(&mut self.os_version_patch, default.os_version_patch);
        merge_field(&mut self.client_source, default.client_source);
        merge_field(&mut self.language, default.language);
        merge_field(&mut self.user_agent, default.user_agent);
        true
    }
}

/// Set `slot` from `default` when it is unset or blank.
fn merge_field(slot: &mut Option<String>, default: String) {
    if slot.as_deref().is_none_or(|value| value.trim().is_empty()) {
        *slot = Some(default);
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
