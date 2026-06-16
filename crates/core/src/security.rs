use rustylink_api::{
    JsonObject, ReportSecurityResponse, SecurityReportItem, SecurityReportRequest,
};
use snafu::prelude::*;

use crate::AppContext;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("application context operation failed"))]
    Context {
        #[snafu(source(from(crate::context::Error, Box::new)))]
        source: Box<crate::context::Error>,
    },

    #[snafu(display("API operation failed"))]
    Api {
        #[snafu(source(from(rustylink_api::Error, Box::new)))]
        source: Box<rustylink_api::Error>,
    },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

pub async fn report_security(
    ctx: &mut AppContext, report: &SecurityReportRequest,
) -> Result<ReportSecurityResponse> {
    let client = ctx.api_client().context(ContextSnafu)?;
    let response = client.report_security(report).await.context(ApiSnafu)?;
    ctx.sync_from_client(&client);
    ctx.save().context(ContextSnafu)?;
    Ok(response)
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
        data: JsonObject::new(),
        key: key.to_string(),
        level: 0,
    })
    .collect();

    SecurityReportRequest {
        items,
        raw: JsonObject::new(),
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
            .map(|item| (item.key.as_str(), item.level, item.data.is_empty()))
            .collect::<Vec<_>>();

        assert_eq!(report.status, None);
        assert!(report.raw.is_empty());
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
