use snafu::prelude::*;
use tracing_subscriber::{EnvFilter, fmt};

use crate::error::{Result, cli_error};

pub fn print_json(value: &impl serde::Serialize) -> Result<()> {
    let rendered = serde_json::to_string_pretty(value).context(cli_error::RenderJsonSnafu)?;
    println!("{rendered}");
    Ok(())
}

pub fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    fmt().with_env_filter(filter).init();
}
