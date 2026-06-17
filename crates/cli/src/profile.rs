use rustylink_core::{AppContext, vpn};
use snafu::prelude::*;

use crate::{
    args::ProfileSubcommand,
    error::{Result, cli_error},
    output::print_json,
};

pub async fn handle(ctx: &mut AppContext, command: ProfileSubcommand) -> Result<()> {
    match command {
        ProfileSubcommand::LoginSetting => {
            let response = vpn::login_setting(ctx).await.context(cli_error::VpnSnafu)?;
            print_json(&response)?;
        }
        ProfileSubcommand::User => {
            let response = vpn::user_info(ctx).await.context(cli_error::VpnSnafu)?;
            print_json(&response)?;
        }
        ProfileSubcommand::Tenant => {
            let response = vpn::tenant_config(ctx).await.context(cli_error::VpnSnafu)?;
            print_json(&response)?;
        }
    }
    Ok(())
}
