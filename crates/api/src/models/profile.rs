use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use super::{BaseResponse, JsonObject};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GetLoginSettingRequest;

impl_empty_request!(
    GetLoginSettingRequest,
    GET,
    "/api/login/setting",
    BaseResponse<LoginSetting>
);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GetUserInfoRequest;

impl_empty_request!(
    GetUserInfoRequest,
    GET,
    "/api/info/me",
    BaseResponse<UserInfo>
);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GetTenantConfigRequest;

impl_empty_request!(
    GetTenantConfigRequest,
    GET,
    "/api/tenant/config",
    BaseResponse<TenantConfig>
);

#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LoginSetting {
    /// Login flow version. `"v1"` selects the `/api/v1/login/*` endpoints.
    /// (Android: `LoginSettingBean.login_version`, `isV1Login()`.)
    pub login_version: Option<String>,
    pub raw: Option<JsonObject>,
}

impl LoginSetting {
    /// Whether the tenant uses the v1 login flow (`login_version == "v1"`).
    #[must_use]
    pub fn is_v1(&self) -> bool {
        self.login_version.as_deref() == Some("v1")
    }
}

#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct UserInfo {
    pub uid: Option<String>,
    pub name: Option<String>,
    pub email: Option<String>,
    pub mobile: Option<String>,
    pub raw: Option<JsonObject>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TenantConfig {
    #[serde(rename = "signingConfig", alias = "signing_config")]
    pub signing_config: Option<TenantSigningConfig>,
    pub raw: Option<JsonObject>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TenantSigningConfig {
    pub enable: Option<bool>,
    pub algorithms: Option<Vec<String>>,
    pub rules: Option<Vec<SigningRule>>,
    #[serde(rename = "rulesMap", alias = "rules_map")]
    pub rules_map: Option<JsonObject>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SigningRule {
    pub urls: Option<Vec<String>>,
    #[serde(rename = "enable_signing", alias = "enableSigning")]
    pub enable_signing: Option<bool>,
    #[serde(rename = "signing_input_params", alias = "signingInputParams")]
    pub signing_input_params: Option<i32>,
    #[serde(rename = "max_time_desync", alias = "maxTimeDesync")]
    pub max_time_desync: Option<i32>,
}
