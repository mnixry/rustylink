use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClientIdentity {
    pub os: String,
    pub os_version: String,
    pub app_version: String,
    pub brand: String,
    pub model: String,
    pub device_id: String,
    pub build_number: String,
    pub os_version_patch: String,
    pub client_source: String,
    pub language: String,
    pub user_agent: String,
}
impl Default for ClientIdentity {
    fn default() -> Self {
        let device_id = stable_device_id();
        Self {
            os: "android".to_string(),
            os_version: "35".to_string(),
            app_version: "3.2.16".to_string(),
            brand: "Google".to_string(),
            model: "Pixel 8".to_string(),
            device_id,
            build_number: "2008".to_string(),
            os_version_patch: "2026-01-01".to_string(),
            client_source: "FeiLian".to_string(),
            language: "en".to_string(),
            user_agent: "CorpLink/3.2.16 (Android; Rustylink)".to_string(),
        }
    }
}

impl ClientIdentity {
    #[must_use]
    pub fn query_pairs(&self, now: Timestamp) -> Vec<(&'static str, String)> {
        vec![
            ("os", self.os.clone()),
            ("os_version", self.os_version.clone()),
            ("app_version", self.app_version.clone()),
            ("brand", self.brand.clone()),
            ("model", self.model.clone()),
            ("language", self.language.clone()),
            ("build_number", self.build_number.clone()),
            ("os_version_patch", self.os_version_patch.clone()),
            ("timestamp", now.as_second().to_string()),
            ("client_source", self.client_source.clone()),
        ]
    }
}

fn stable_device_id() -> String {
    let machine_uid = match machine_uid::get() {
        Ok(value) => value,
        Err(error) => {
            tracing::warn!(
                %error,
                "failed to read machine UID; using deterministic fallback device id"
            );
            String::new()
        }
    };
    let mut hasher = Sha256::new();
    hasher.update(b"device-id-v1");
    hasher.update(machine_uid.trim().as_bytes());
    let digest = hex::encode(hasher.finalize());
    digest[..32].to_string()
}

// ---------------------------------------------------------------------------
// Proto bridge: ClientIdentity <-> PersistedIdentity
// ---------------------------------------------------------------------------

use rustylink_proto::proto::rustylink::daemon::persist::v1 as persist;

/// Project a persisted identity onto the working `ClientIdentity`, filling any
/// unset field from the built-in Android-profile [`Default`]
/// (partial-merge-with-default).  The reverse direction is intentionally
/// absent: the daemon writes `PersistedIdentity` fields directly (only
/// per-install overrides such as `device_id`), so a whole-struct round-trip is
/// never needed.
impl From<&persist::PersistedIdentity> for ClientIdentity {
    fn from(p: &persist::PersistedIdentity) -> Self {
        let default = Self::default();
        Self {
            os: p.os.clone().unwrap_or(default.os),
            os_version: p.os_version.clone().unwrap_or(default.os_version),
            app_version: p.app_version.clone().unwrap_or(default.app_version),
            brand: p.brand.clone().unwrap_or(default.brand),
            model: p.model.clone().unwrap_or(default.model),
            device_id: p.device_id.clone().unwrap_or(default.device_id),
            build_number: p.build_number.clone().unwrap_or(default.build_number),
            os_version_patch: p
                .os_version_patch
                .clone()
                .unwrap_or(default.os_version_patch),
            client_source: p.client_source.clone().unwrap_or(default.client_source),
            language: p.language.clone().unwrap_or(default.language),
            user_agent: p.user_agent.clone().unwrap_or(default.user_agent),
        }
    }
}
