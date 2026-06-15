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

impl ClientIdentity {
    #[must_use]
    pub fn android_compatible_default() -> Self {
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
            "rustylink-machine-uid-unavailable".to_string()
        }
    };
    let mut hasher = Sha256::new();
    hasher.update(b"rustylink-feilian-device-id-v1");
    hasher.update(machine_uid.trim().as_bytes());
    let digest = hex::encode(hasher.finalize());
    digest[..32].to_string()
}

impl Default for ClientIdentity {
    fn default() -> Self {
        Self::android_compatible_default()
    }
}
