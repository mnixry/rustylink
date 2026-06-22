use rustylink_api::{
    ApiClient, BaseResponse, JsonObject, ResponseMeta, SecurityReportItem, SecurityReportRequest,
    SendableRequest,
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
) -> Result<(BaseResponse<String>, ResponseMeta)> {
    let (response, meta) = report
        .clone()
        .send_with_meta(client)
        .await
        .context(ApiSnafu)?;
    Ok((response, meta))
}

/// Build the "all safe" device security report.
///
/// Byte-for-byte matches the Android `SecurityConfigViewModel.reportResult`
/// wire shape: one item per check (level 0 = safe), with the per-key `data`
/// objects the app attaches — `network` carries the (empty, no-proxy) HTTP
/// proxy info, and `debug_off`/`debug_on` carry the battery/USB charging status
/// (`-1` = not USB-charging). The top-level object contains only `items`.
#[must_use]
pub fn all_green_security_report() -> SecurityReportRequest {
    let items = [
        ("root", None),
        ("certificate", None),
        ("wifi", None),
        ("wifi_wep", None),
        // No system proxy → the app emits `data: {}` for `network`.
        ("network", Some(JsonObject::new())),
        ("password", None),
        ("lock_image", None),
        ("debug_off", Some(usb_status_data())),
        ("debug_on", Some(usb_status_data())),
    ]
    .into_iter()
    .map(|(key, data)| SecurityReportItem {
        data,
        key: key.to_string(),
        level: 0,
    })
    .collect();

    SecurityReportRequest {
        items,
        raw: None,
        status: None,
    }
}

/// `data: { "usbStatus": -1 }` — the value `zd1.t` returns when the device is
/// not charging over USB (the expected state for a headless client).
fn usb_status_data() -> JsonObject {
    let mut data = JsonObject::new();
    data.insert("usbStatus".to_string(), serde_json::Value::from(-1));
    data
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
