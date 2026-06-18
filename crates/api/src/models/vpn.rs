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

impl_json_request!(VpnReportRequest, POST, "/vpn/report", BaseResponse<String>);

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
    #[serde(default)]
    pub raw: Option<JsonObject>,
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
}
