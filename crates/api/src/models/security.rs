use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use super::{BaseResponse, CommonStringResult, JsonObject};

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
    BaseResponse<CommonStringResult>
);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::SendableRequest;

    #[test]
    fn security_report_response_accepts_android_common_string_result() {
        type Response = <SecurityReportRequest as SendableRequest>::Response;

        let response = serde_json::from_str::<Response>(
            r#"{"code":0,"action":"","message":"","data":{"result":"success"}}"#,
        )
        .expect("decode");

        assert_eq!(
            response.data.and_then(|data| data.result),
            Some("success".to_string())
        );
    }
}
