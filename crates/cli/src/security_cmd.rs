use std::{fs, path::PathBuf};

use rustylink_api::SecurityReportRequest;
use rustylink_core::{AppContext, security};
use snafu::prelude::*;

use crate::{
    args::SecuritySubcommand,
    error::{Result, cli_error},
    output::print_json,
};

pub async fn handle(ctx: &mut AppContext, command: SecuritySubcommand) -> Result<()> {
    match command {
        SecuritySubcommand::Report(args) => {
            let report = match args.status_file {
                Some(path) => read_security_report(path)?,
                None => security::all_green_security_report(),
            };
            let response = security::report_security(ctx, &report)
                .await
                .context(cli_error::SecuritySnafu)?;
            print_json(&response)?;
        }
    }
    Ok(())
}

fn read_security_report(path: PathBuf) -> Result<SecurityReportRequest> {
    let bytes = fs::read(&path).context(cli_error::ReadFileSnafu { path: path.clone() })?;
    serde_json::from_slice(&bytes).context(cli_error::ParseJsonSnafu { path })
}
