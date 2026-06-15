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
