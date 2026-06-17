use serde::{Deserialize, Serialize};

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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnSetting {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export_id: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<JsonObject>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnLocation {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    #[serde(
        default,
        rename = "isAuto",
        alias = "is_auto",
        skip_serializing_if = "Option::is_none"
    )]
    pub is_auto: Option<bool>,
    #[serde(
        default,
        rename = "currentDotBean",
        alias = "current_dot_bean",
        skip_serializing_if = "Option::is_none"
    )]
    pub current_dot_bean: Option<VpnDot>,
    #[serde(
        default,
        rename = "vpnDotBeans",
        alias = "vpn_dot_beans",
        skip_serializing_if = "Option::is_none"
    )]
    pub vpn_dot_beans: Option<Vec<VpnDot>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<JsonObject>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnDot {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<i32>,
    #[serde(
        default,
        rename = "apiIp",
        alias = "api_ip",
        skip_serializing_if = "Option::is_none"
    )]
    pub api_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_port: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpn_port: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_mode: Option<i32>,
    #[serde(
        default,
        alias = "protocolDetectConfig",
        skip_serializing_if = "Option::is_none"
    )]
    pub protocol_detect_config: Option<VpnProtocolDetectConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_name: Option<String>,
    #[serde(
        default,
        rename = "fastIp",
        alias = "fast_ip",
        skip_serializing_if = "Option::is_none"
    )]
    pub fast_ip: Option<String>,
    #[serde(
        default,
        rename = "ip4Domain",
        alias = "ip4_domain",
        skip_serializing_if = "Option::is_none"
    )]
    pub ip4_domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconnect: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exclude: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dedicated: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_ips: Option<Vec<String>>,
    #[serde(
        default,
        alias = "ipDelayRoutingPolicy",
        skip_serializing_if = "Option::is_none"
    )]
    pub ip_delay_routing_policy: Option<IpDelayRoutingPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<JsonObject>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IpDelayRoutingPolicy {
    #[serde(default, alias = "isOperator", skip_serializing_if = "Option::is_none")]
    pub is_operator: Option<bool>,
    #[serde(default, alias = "policyType", skip_serializing_if = "Option::is_none")]
    pub policy_type: Option<i32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnProtocolDetectConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable: Option<bool>,
    #[serde(
        default,
        alias = "badNetworkCount",
        skip_serializing_if = "Option::is_none"
    )]
    pub bad_network_count: Option<i32>,
    #[serde(
        default,
        alias = "refreshTimeoutCount",
        skip_serializing_if = "Option::is_none"
    )]
    pub refresh_timeout_count: Option<i32>,
    #[serde(
        default,
        alias = "tcp2udpAvailableCount",
        skip_serializing_if = "Option::is_none"
    )]
    pub tcp2udp_available_count: Option<i32>,
    #[serde(
        default,
        alias = "udp2tcpTimeoutCount",
        skip_serializing_if = "Option::is_none"
    )]
    pub udp2tcp_timeout_count: Option<i32>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnConnRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub otp: Option<String>,
    pub export_id: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnExportListInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exports: Option<Vec<VpnExportInfo>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnConnResponse {
    pub ip: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip_mask: Option<i32>,
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preshared_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sign_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,
    pub setting: VpnConnSetting,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<JsonObject>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VpnConnSetting {
    pub vpn_mtu: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpn_dns: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpn_dns_backup: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpn_dns_domain_split: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpn_route_full: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpn_route_split: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v6_route_full: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v6_route_split: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpn_dynamic_domain_route_split: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v6_vpn_dynamic_domain_route_split: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpn_wildcard_dynamic_domain_route_split: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suffix_wildcard_dynamic_domain_route_split: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dynamic_domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub central_dns: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
