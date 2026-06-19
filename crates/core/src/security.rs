use rustylink_api::{
    ApiClient, BaseResponse, ResponseMeta, SecurityReportItem, SecurityReportRequest,
    SendableRequest,
};
use snafu::prelude::*;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("API operation failed"))]
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

#[must_use]
pub fn all_green_security_report() -> SecurityReportRequest {
    let items = [
        "root",
        "certificate",
        "wifi",
        "wifi_wep",
        "network",
        "password",
        "lock_image",
        "debug_off",
        "debug_on",
    ]
    .into_iter()
    .map(|key| SecurityReportItem {
        data: None,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn green_report_matches_android_all_safe_wire_shape() {
        let report = all_green_security_report();
        let items = report
            .items
            .iter()
            .map(|item| (item.key.as_str(), item.level, item.data.is_none()))
            .collect::<Vec<_>>();

        assert_eq!(report.status, None);
        assert_eq!(report.raw, None);
        assert_eq!(
            items,
            [
                ("root", 0, true),
                ("certificate", 0, true),
                ("wifi", 0, true),
                ("wifi_wep", 0, true),
                ("network", 0, true),
                ("password", 0, true),
                ("lock_image", 0, true),
                ("debug_off", 0, true),
                ("debug_on", 0, true),
            ]
        );

        let serialized = serde_json::to_value(&report).expect("serialize report");
        assert_eq!(
            serialized,
            serde_json::json!({
                "items": [
                    { "key": "root", "level": 0 },
                    { "key": "certificate", "level": 0 },
                    { "key": "wifi", "level": 0 },
                    { "key": "wifi_wep", "level": 0 },
                    { "key": "network", "level": 0 },
                    { "key": "password", "level": 0 },
                    { "key": "lock_image", "level": 0 },
                    { "key": "debug_off", "level": 0 },
                    { "key": "debug_on", "level": 0 },
                ]
            })
        );
    }
}
