use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub type JsonObject = BTreeMap<String, Value>;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(bound(deserialize = "T: Deserialize<'de>", serialize = "T: Serialize"))]
pub struct BaseResponse<T> {
    pub code: i32,
    #[serde(default)]
    pub message: Option<String>,
    #[serde(default)]
    pub data: Option<T>,
    #[serde(default, flatten)]
    pub extra: JsonObject,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ActivateRequest {
    pub code: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct ActivateInfo {
    #[serde(default)]
    pub activate_host: Option<String>,
    #[serde(default)]
    pub activate_backup_domain: Option<String>,
    #[serde(default)]
    pub activate_enable_backup_domain: Option<bool>,
    #[serde(flatten)]
    pub raw: JsonObject,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct PasswordLoginRequest {
    pub login_scene: String,
    pub account_type: String,
    pub account: String,
    pub password: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SendCodeRequest {
    pub login_scene: String,
    pub account_type: String,
    pub login_type: String,
    pub account: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifyCodeRequest {
    pub login_scene: String,
    pub account_type: String,
    pub login_type: String,
    pub account: String,
    pub code: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VerifyMfaRequest {
    pub login_scene: String,
    pub mfa_type: String,
    pub account: String,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OAuthCallbackRequest {
    pub alias_key: String,
    pub code: String,
    pub state: String,
    pub code_verifier: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct LoginResult {
    #[serde(default)]
    pub token: Option<String>,
    #[serde(default)]
    pub uid: Option<String>,
    #[serde(default)]
    pub need_mfa: Option<bool>,
    #[serde(default)]
    pub mfa_token: Option<String>,
    #[serde(flatten)]
    pub raw: JsonObject,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct LoginSetting {
    #[serde(default, alias = "v1Login")]
    pub is_v1_login: Option<bool>,
    #[serde(flatten)]
    pub raw: JsonObject,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct TenantConfig {
    #[serde(default, alias = "signingConfig")]
    pub signing_config: Option<SigningConfigModel>,
    #[serde(flatten)]
    pub raw: JsonObject,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SigningConfigModel {
    #[serde(default)]
    pub enable: Option<bool>,
    #[serde(default)]
    pub algorithms: Vec<String>,
    #[serde(default)]
    pub rules: Vec<SigningRule>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct SigningRule {
    #[serde(default)]
    pub urls: Vec<String>,
    #[serde(default, alias = "enableSigning")]
    pub enable_signing: Option<bool>,
    #[serde(default, alias = "signingInputParams")]
    pub signing_input_params: Option<i32>,
    #[serde(default, alias = "maxTimeDesync")]
    pub max_time_desync: Option<i32>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct UserInfo {
    #[serde(default)]
    pub uid: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub mobile: Option<String>,
    #[serde(flatten)]
    pub raw: JsonObject,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct VpnSetting {
    #[serde(default)]
    pub enable: Option<bool>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub export_id: Option<i32>,
    #[serde(flatten)]
    pub raw: JsonObject,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct VpnLocation {
    #[serde(default)]
    pub id: Option<i32>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub is_auto: Option<bool>,
    #[serde(default)]
    pub dots: Vec<VpnDot>,
    #[serde(flatten)]
    pub raw: JsonObject,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct VpnDot {
    #[serde(default)]
    pub id: Option<i32>,
    #[serde(default, alias = "apiIp")]
    pub api_ip: Option<String>,
    #[serde(default, alias = "apiPort")]
    pub api_port: Option<i32>,
    #[serde(default, alias = "vpnIp")]
    pub vpn_ip: Option<String>,
    #[serde(default, alias = "vpnPort")]
    pub vpn_port: Option<i32>,
    #[serde(default, alias = "protocolMode")]
    pub protocol_mode: Option<i32>,
    #[serde(default)]
    pub timeout: Option<i32>,
    #[serde(flatten)]
    pub raw: JsonObject,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VpnConnRequest {
    #[serde(default)]
    pub mode: Option<String>,
    pub public_key: String,
    #[serde(default)]
    pub otp: Option<String>,
    pub export_id: i32,
    #[serde(default)]
    pub sign_token: Option<String>,
    #[serde(default)]
    pub not_auto: Option<bool>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct VpnConnResponse {
    pub ip: String,
    #[serde(default)]
    pub ipv6: Option<String>,
    #[serde(default)]
    pub ip_mask: Option<i32>,
    pub public_key: String,
    #[serde(default)]
    pub preshared_key: Option<String>,
    #[serde(default)]
    pub sign_token: Option<String>,
    #[serde(default)]
    pub protocol_version: Option<String>,
    pub setting: VpnConnSetting,
    #[serde(flatten)]
    pub raw: JsonObject,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
pub struct VpnConnSetting {
    pub vpn_mtu: i32,
    #[serde(default)]
    pub vpn_dns: Option<String>,
    #[serde(default)]
    pub vpn_dns_backup: Option<String>,
    #[serde(default)]
    pub vpn_dns_domain_split: Vec<String>,
    #[serde(default)]
    pub vpn_route_full: Vec<String>,
    #[serde(default)]
    pub vpn_route_split: Vec<String>,
    #[serde(default)]
    pub v6_route_full: Vec<String>,
    #[serde(default)]
    pub v6_route_split: Vec<String>,
    #[serde(default)]
    pub vpn_dynamic_domain_route_split: Option<String>,
    #[serde(default)]
    pub v6_vpn_dynamic_domain_route_split: Option<String>,
    #[serde(default)]
    pub vpn_wildcard_dynamic_domain_route_split: Option<String>,
    #[serde(default)]
    pub suffix_wildcard_dynamic_domain_route_split: Option<String>,
    #[serde(default)]
    pub dynamic_domain: Option<String>,
    #[serde(default)]
    pub central_dns: Option<String>,
    #[serde(default)]
    pub ip_nats: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SecurityReportRequest {
    pub status: String,
    pub items: Vec<SecurityReportItem>,
    #[serde(flatten)]
    pub raw: JsonObject,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SecurityReportItem {
    pub name: String,
    pub level: i32,
    pub passed: bool,
    #[serde(default)]
    pub message: Option<String>,
}
