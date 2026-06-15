use std::{fs, path::Path};

use rustylink_api::{ClientIdentity, SessionCookies, SigningConfig};
use serde::{Deserialize, Serialize};
use snafu::prelude::*;
use time::OffsetDateTime;

use crate::{error, error::Result};

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

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct RustylinkState {
    pub tenant: TenantState,
    pub identity: ClientIdentity,
    pub cookies: SessionCookies,
    pub csrf_token: Option<String>,
    pub knock_token: Option<String>,
    pub signing: SigningConfig,
    pub oauth: OAuthState,
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
            updated_at_unix: OffsetDateTime::now_utc().unix_timestamp(),
        }
    }

    pub fn load_or_default(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let bytes = fs::read(path).context(error::ReadState {
            path: path.to_path_buf(),
        })?;
        serde_json::from_slice(&bytes).context(error::ParseState {
            path: path.to_path_buf(),
        })
    }

    pub fn save(&mut self, path: &Path) -> Result<()> {
        self.updated_at_unix = OffsetDateTime::now_utc().unix_timestamp();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).context(error::CreateStateDir {
                path: parent.to_path_buf(),
            })?;
        }
        let bytes = serde_json::to_vec_pretty(self).context(error::SerializeState)?;
        fs::write(path, bytes).context(error::WriteState {
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
