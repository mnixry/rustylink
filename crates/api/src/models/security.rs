use serde::{Deserialize, Serialize};

use super::{BaseResponse, JsonObject};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityReportItem {
    pub key: String,
    pub level: i32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<JsonObject>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityReportRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    pub items: Vec<SecurityReportItem>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<JsonObject>,
}

impl_json_request!(
    SecurityReportRequest,
    POST,
    "/api/security/report",
    BaseResponse<String>
);
