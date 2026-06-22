use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use super::{BaseResponse, JsonObject};

pub type VpnExportInfo = JsonObject;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GetVpnSettingRequest;

impl_empty_request!(
    GetVpnSettingRequest,
    GET,
    "/api/setting",
    BaseResponse<VpnSetting>
);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GetVpnLocationsRequest;

impl_empty_request!(
    GetVpnLocationsRequest,
    GET,
    "/api/vpn/list",
    BaseResponse<Vec<VpnDot>>
);

#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct VpnSetting {
    #[serde(rename = "vpn_enable", alias = "enable")]
    pub enable: Option<bool>,
    pub mode: Option<String>,
    pub export_id: Option<i32>,
    #[serde(rename = "vpn_split_only", alias = "vpnSplitOnly")]
    pub split_only: Option<bool>,
    #[serde(rename = "vpn_status", alias = "vpnStatus")]
    pub vpn_status: Option<i32>,
    #[serde(rename = "admin_enable", alias = "adminEnable")]
    pub admin_enable: Option<bool>,
    /// Tenant VPN domain. Dots are reached by IP but present a TLS cert valid
    /// for this domain; the client validates the cert against it.
    /// (Android: `VpnSettingBean.vpn_domain`, used by the dot hostname
    /// verifier.)
    pub vpn_domain: Option<String>,
    pub raw: Option<JsonObject>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct VpnLocation {
    pub name: Option<String>,
    pub ip: Option<String>,
    pub r#type: Option<String>,
    #[serde(rename = "isAuto", alias = "is_auto")]
    pub is_auto: Option<bool>,
    #[serde(rename = "currentDotBean", alias = "current_dot_bean")]
    pub current_dot_bean: Option<VpnDot>,
    #[serde(rename = "vpnDotBeans", alias = "vpn_dot_beans")]
    pub vpn_dot_beans: Option<Vec<VpnDot>>,
    pub raw: Option<JsonObject>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct VpnDot {
    pub id: Option<i32>,
    #[serde(rename = "apiIp", alias = "api_ip")]
    pub api_ip: Option<String>,
    pub api_port: Option<i32>,
    pub ip: Option<String>,
    pub vpn_port: Option<i32>,
    pub protocol_mode: Option<i32>,
    #[serde(alias = "protocolDetectConfig")]
    pub protocol_detect_config: Option<VpnProtocolDetectConfig>,
    pub timeout: Option<i32>,
    pub mode: Option<i32>,
    pub r#type: Option<String>,
    pub name: Option<String>,
    pub display_name: Option<String>,
    pub domain_name: Option<String>,
    #[serde(rename = "fastIp", alias = "fast_ip")]
    pub fast_ip: Option<String>,
    #[serde(rename = "ip4Domain", alias = "ip4_domain")]
    pub ip4_domain: Option<String>,
    pub reconnect: Option<bool>,
    pub exclude: Option<bool>,
    pub dedicated: Option<bool>,
    pub backup_ips: Option<Vec<String>>,
    #[serde(alias = "ipDelayRoutingPolicy")]
    pub ip_delay_routing_policy: Option<IpDelayRoutingPolicy>,
    pub raw: Option<JsonObject>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct IpDelayRoutingPolicy {
    #[serde(alias = "isOperator")]
    pub is_operator: Option<bool>,
    #[serde(alias = "policyType")]
    pub policy_type: Option<i32>,
}

impl IpDelayRoutingPolicy {
    /// `policy_type` value that marks operator-specific IP-delay routing.
    pub const OPERATOR: i32 = 1;

    /// Whether this policy selects operator IP-delay routing — the signal used
    /// to decide whether the dot's VPN IP should be used for the config API.
    #[must_use]
    pub fn is_operator_routing(&self) -> bool {
        self.is_operator.unwrap_or(false) && self.policy_type == Some(Self::OPERATOR)
    }
}

#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct VpnProtocolDetectConfig {
    pub enable: Option<bool>,
    #[serde(alias = "badNetworkCount")]
    pub bad_network_count: Option<i32>,
    #[serde(alias = "refreshTimeoutCount")]
    pub refresh_timeout_count: Option<i32>,
    #[serde(alias = "tcp2udpAvailableCount")]
    pub tcp2udp_available_count: Option<i32>,
    #[serde(alias = "udp2tcpTimeoutCount")]
    pub udp2tcp_timeout_count: Option<i32>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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

impl_json_request!(
    VpnConnRequest,
    POST,
    "/vpn/conn",
    BaseResponse<VpnConnResponse>
);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VpnPingRequest;

impl_empty_request!(VpnPingRequest, GET, "/vpn/ping", BaseResponse<JsonObject>);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GetVpnExportsRequest;

impl_empty_request!(
    GetVpnExportsRequest,
    GET,
    "/vpn/export",
    BaseResponse<VpnExportListInfo>
);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnReportRequest {
    pub r#type: String,
    pub ip: String,
    pub public_key: String,
    pub mode: String,
}

impl_json_request!(
    VpnReportRequest,
    POST,
    "/vpn/report",
    BaseResponse<serde_json::Value>
);

/// `/vpn/report` event type. The Android client posts `100` periodically while
/// connected and `101` once on disconnect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(i32)]
pub enum VpnReportType {
    /// Periodic keepalive while connected.
    Connected    = 100,
    /// Sent once on disconnect / teardown.
    Disconnected = 101,
}

impl VpnReportType {
    /// The numeric value rendered as the wire string (`"100"` / `"101"`).
    #[must_use]
    pub fn wire(self) -> String {
        (self as i32).to_string()
    }
}

#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct VpnExportListInfo {
    pub exports: Option<Vec<VpnExportInfo>>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnConnResponse {
    pub ip: String,
    #[serde(default)]
    pub ipv6: Option<String>,
    #[serde(default, deserialize_with = "deserialize_flexible_opt_i32")]
    pub ip_mask: Option<i32>,
    pub public_key: String,
    #[serde(default)]
    pub preshared_key: Option<String>,
    #[serde(default)]
    pub sign_token: Option<String>,
    #[serde(default)]
    pub protocol_version: Option<String>,
    pub setting: VpnConnSetting,
    #[serde(default)]
    pub raw: Option<JsonObject>,
}

/// Deserialize an optional `i32` that the server may encode as a JSON string
/// (e.g. `ip_mask: "24"`), a number, or null. Mirrors the Android client's
/// `optInt`, which coerces a string field to an integer.
fn deserialize_flexible_opt_i32<'de, D>(deserializer: D) -> Result<Option<i32>, D::Error>
where
    D: serde::Deserializer<'de>, {
    use serde::Deserialize as _;
    match Option::<serde_json::Value>::deserialize(deserializer)? {
        Some(serde_json::Value::Number(number)) => {
            Ok(number.as_i64().and_then(|value| i32::try_from(value).ok()))
        }
        Some(serde_json::Value::String(text)) => Ok(text.trim().parse::<i32>().ok()),
        _ => Ok(None),
    }
}

/// Deserialize an optional string, tolerating the server sending a non-string
/// (e.g. a map for `vpn_dynamic_domain_route_split`). Mirrors the Android
/// client's `optString`, which yields an empty/absent value for non-strings.
fn deserialize_flexible_opt_string<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>, {
    use serde::Deserialize as _;
    match Option::<serde_json::Value>::deserialize(deserializer)? {
        Some(serde_json::Value::String(text)) => Ok(Some(text)),
        _ => Ok(None),
    }
}

#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnConnSetting {
    pub vpn_mtu: i32,
    #[serde(default)]
    pub vpn_dns: Option<String>,
    #[serde(default)]
    pub vpn_dns_backup: Option<String>,
    #[serde(default)]
    pub vpn_dns_domain_split: Option<Vec<String>>,
    #[serde(default)]
    pub vpn_route_full: Option<Vec<String>>,
    #[serde(default)]
    pub vpn_route_split: Option<Vec<String>>,
    #[serde(default)]
    pub v6_route_full: Option<Vec<String>>,
    #[serde(default)]
    pub v6_route_split: Option<Vec<String>>,
    #[serde(default, deserialize_with = "deserialize_flexible_opt_string")]
    pub vpn_dynamic_domain_route_split: Option<String>,
    #[serde(default, deserialize_with = "deserialize_flexible_opt_string")]
    pub v6_vpn_dynamic_domain_route_split: Option<String>,
    #[serde(default, deserialize_with = "deserialize_flexible_opt_string")]
    pub vpn_wildcard_dynamic_domain_route_split: Option<String>,
    #[serde(default, deserialize_with = "deserialize_flexible_opt_string")]
    pub suffix_wildcard_dynamic_domain_route_split: Option<String>,
    #[serde(default, deserialize_with = "deserialize_flexible_opt_string")]
    pub dynamic_domain: Option<String>,
    #[serde(default, deserialize_with = "deserialize_flexible_opt_string")]
    pub central_dns: Option<String>,
    #[serde(default, deserialize_with = "deserialize_flexible_opt_string")]
    pub ip_nats: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vpn_report_request_uses_android_wire_names() {
        let request = VpnReportRequest {
            r#type: "100".to_string(),
            ip: "10.0.0.2".to_string(),
            public_key: "server".to_string(),
            mode: "Full".to_string(),
        };

        let value = serde_json::to_value(request).expect("serialize");
        assert_eq!(
            value,
            serde_json::json!({
                "type": "100",
                "ip": "10.0.0.2",
                "public_key": "server",
                "mode": "Full",
            })
        );
    }

    #[test]
    fn vpn_report_response_accepts_untyped_data_payload() {
        type Response = <VpnReportRequest as crate::models::SendableRequest>::Response;

        serde_json::from_str::<Response>(r#"{"code":0,"data":{"result":"success"}}"#)
            .expect("decode object payload");
        serde_json::from_str::<Response>(r#"{"code":0,"data":"success"}"#)
            .expect("decode string payload");
    }
}
