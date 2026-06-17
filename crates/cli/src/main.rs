mod args;
mod error;
mod login;
mod output;
mod profile;
mod security_cmd;
mod vpn_cmd;

use clap::Parser as _;
use rustylink_api::ApiClientOptions;
use rustylink_core::{AppContext, auth};
use serde_json::json;
use snafu::prelude::*;

use crate::{
    args::{Cli, Command, StateSubcommand},
    error::{Result, cli_error},
    output::{init_tracing, print_json},
};

#[tokio::main]
#[snafu::report]
async fn main() -> Result<()> {
    init_tracing();

    let cli = Cli::parse();
    let api_options = ApiClientOptions {
        outbound_interface: cli.outbound_interface,
    };
    let mut ctx = AppContext::load_with_api_options(cli.state_path, api_options)
        .context(cli_error::CoreContextSnafu)?;

    match cli.command {
        Command::Activate(args) => {
            let response = auth::activate(
                &mut ctx,
                args.code,
                args.base_url,
                args.backup_url,
                args.match_base_url,
            )
            .await
            .context(cli_error::AuthSnafu)?;
            print_json(&json!({ "state": &ctx.state, "response": response }))?;
        }
        Command::Login(command) => login::handle(&mut ctx, command.command).await?,
        Command::Profile(command) => profile::handle(&mut ctx, command.command).await?,
        Command::Vpn(command) => vpn_cmd::handle(&mut ctx, command.command).await?,
        Command::Security(command) => security_cmd::handle(&mut ctx, command.command).await?,
        Command::State(command) => match command.command {
            StateSubcommand::Show => print_json(&ctx.state)?,
        },
    }
    Ok(())
}
