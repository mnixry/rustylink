use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ClientIdentity {
    pub os: String,
    pub os_version: String,
    pub app_version: String,
    pub brand: String,
    pub model: String,
    pub did: String,
    pub build_number: String,
    pub os_version_patch: String,
    pub client_source: String,
    pub language: String,
    pub user_agent: String,
}

impl ClientIdentity {
    #[must_use]
    pub fn android_compatible_default() -> Self {
        let did = Uuid::new_v4().simple().to_string();
        Self {
            os: "android".to_string(),
            os_version: "35".to_string(),
            app_version: "3.2.16".to_string(),
            brand: "Google".to_string(),
            model: "Pixel 8".to_string(),
            did,
            build_number: "2008".to_string(),
            os_version_patch: "2026-01-01".to_string(),
            client_source: "FeiLian".to_string(),
            language: "en-US".to_string(),
            user_agent: "CorpLink/3.2.16 (Android; Rustylink)".to_string(),
        }
    }

    #[must_use]
    pub fn query_pairs(&self, now: OffsetDateTime) -> Vec<(&'static str, String)> {
        vec![
            ("os", self.os.clone()),
            ("os_version", self.os_version.clone()),
            ("app_version", self.app_version.clone()),
            ("brand", self.brand.clone()),
            ("model", self.model.clone()),
            ("did", self.did.clone()),
            ("build_number", self.build_number.clone()),
            ("os_version_patch", self.os_version_patch.clone()),
            ("timestamp", now.unix_timestamp().to_string()),
            ("client_source", self.client_source.clone()),
        ]
    }
}

impl Default for ClientIdentity {
    fn default() -> Self {
        Self::android_compatible_default()
    }
}
