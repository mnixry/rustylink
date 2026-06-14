use rustylink_api::{BaseResponse, JsonObject, SecurityReportItem, SecurityReportRequest};
use snafu::prelude::*;

use crate::{AppContext, error, error::Result};

pub async fn report_security(
    ctx: &mut AppContext, report: &SecurityReportRequest,
) -> Result<BaseResponse<String>> {
    let client = ctx.api_client()?;
    let response = client.report_security(report).await.context(error::Api)?;
    ctx.sync_from_client(&client);
    ctx.save()?;
    Ok(response)
}

#[must_use]
pub fn all_green_security_report() -> SecurityReportRequest {
    let items = [
        ("root", 3),
        ("certificate", 2),
        ("wifi", 2),
        ("wifi_wep", 1),
        ("network", 1),
        ("password", 3),
        ("lock_image", 1),
        ("debug_off", 1),
        ("debug_on", 2),
    ]
    .into_iter()
    .map(|(name, level)| SecurityReportItem {
        name: name.to_string(),
        level,
        passed: true,
        message: Some("configured green default".to_string()),
    })
    .collect();

    SecurityReportRequest {
        status: "green".to_string(),
        items,
        raw: JsonObject::new(),
    }
}
