use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use super::{BaseResponse, JsonObject};

#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityReportItem {
    pub key: String,
    pub level: i32,
    #[serde(default)]
    pub data: Option<JsonObject>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecurityReportRequest {
    #[serde(default)]
    pub status: Option<String>,
    pub items: Vec<SecurityReportItem>,
    #[serde(default)]
    pub raw: Option<JsonObject>,
}

impl_json_request!(
    SecurityReportRequest,
    POST,
    "/api/security/report",
    BaseResponse<String>
);
