use rustylink_api::{
    ApiClient, BaseResponse, CommonStringResult, SecurityReportRequest, SendableRequest,
};
use snafu::prelude::*;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("API operation failed: {source}"))]
    Api {
        #[snafu(source(from(rustylink_api::Error, Box::new)))]
        source: Box<rustylink_api::Error>,
    },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

pub async fn report_security(
    client: &ApiClient, report: &SecurityReportRequest,
) -> Result<BaseResponse<CommonStringResult>> {
    report.clone().send(client).await.context(ApiSnafu)
}

/// Build the "all safe" device security report.
///
/// Byte-for-byte matches the Android `SecurityConfigViewModel.reportResult`
/// wire shape: one item per check (level 0 = safe), with the per-key `data`
/// objects the app attaches — `network` carries the (empty, no-proxy) HTTP
/// proxy info, and `debug_off`/`debug_on` carry the battery/USB charging status
/// (`-1` = not USB-charging). The top-level object contains only `items`.
///
/// # Panics
///
/// Never in practice: the payload is a fixed literal that always deserializes
/// into a [`SecurityReportRequest`]. A panic would indicate a programmer error
/// (the literal was edited into an invalid shape).
#[must_use]
pub fn all_green_security_report() -> SecurityReportRequest {
    // One item per check (level 0 = safe). `network` carries the empty
    // (no-proxy) HTTP proxy info; `debug_off`/`debug_on` carry `usbStatus: -1`
    // (= not USB-charging, the expected state for a headless client).
    serde_json::from_value(serde_json::json!({
        "items": [
            { "key": "root", "level": 0 },
            { "key": "certificate", "level": 0 },
            { "key": "wifi", "level": 0 },
            { "key": "wifi_wep", "level": 0 },
            { "key": "network", "level": 0, "data": {} },
            { "key": "password", "level": 0 },
            { "key": "lock_image", "level": 0 },
            { "key": "debug_off", "level": 0, "data": { "usbStatus": -1 } },
            { "key": "debug_on", "level": 0, "data": { "usbStatus": -1 } },
        ]
    }))
    .expect("static all-green security report is valid")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn green_report_matches_android_all_safe_wire_shape() {
        let report = all_green_security_report();

        assert_eq!(report.status, None);
        assert_eq!(report.raw, None);
        let serialized = serde_json::to_value(&report).expect("serialize report");
        assert_eq!(
            serialized,
            serde_json::json!({
                "items": [
                    { "key": "root", "level": 0 },
                    { "key": "certificate", "level": 0 },
                    { "key": "wifi", "level": 0 },
                    { "key": "wifi_wep", "level": 0 },
                    { "key": "network", "level": 0, "data": {} },
                    { "key": "password", "level": 0 },
                    { "key": "lock_image", "level": 0 },
                    { "key": "debug_off", "level": 0, "data": { "usbStatus": -1 } },
                    { "key": "debug_on", "level": 0, "data": { "usbStatus": -1 } },
                ]
            })
        );
    }
}
