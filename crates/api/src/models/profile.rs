use serde::{Deserialize, Serialize};

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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginSetting {
    #[serde(
        default,
        rename = "v1Login",
        alias = "v1_login",
        skip_serializing_if = "Option::is_none"
    )]
    pub v1_login: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<JsonObject>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mobile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<JsonObject>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantConfig {
    #[serde(
        default,
        rename = "signingConfig",
        alias = "signing_config",
        skip_serializing_if = "Option::is_none"
    )]
    pub signing_config: Option<TenantSigningConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<JsonObject>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantSigningConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub algorithms: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<Vec<SigningRule>>,
    #[serde(
        default,
        rename = "rulesMap",
        alias = "rules_map",
        skip_serializing_if = "Option::is_none"
    )]
    pub rules_map: Option<JsonObject>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SigningRule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub urls: Option<Vec<String>>,
    #[serde(
        default,
        rename = "enable_signing",
        alias = "enableSigning",
        skip_serializing_if = "Option::is_none"
    )]
    pub enable_signing: Option<bool>,
    #[serde(
        default,
        rename = "signing_input_params",
        alias = "signingInputParams",
        skip_serializing_if = "Option::is_none"
    )]
    pub signing_input_params: Option<i32>,
    #[serde(
        default,
        rename = "max_time_desync",
        alias = "maxTimeDesync",
        skip_serializing_if = "Option::is_none"
    )]
    pub max_time_desync: Option<i32>,
}
