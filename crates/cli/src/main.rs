use std::{fs, path::PathBuf};

use clap::{Args, Parser, Subcommand};
use rustylink_api::{SecurityReportRequest, VpnConnRequest};
use rustylink_core::{AppContext, auth, security, vpn};
use rustylink_tunnel::{TunnelConfig, TunnelSession};
use serde_json::json;
use snafu::prelude::*;
use tracing_subscriber::{EnvFilter, fmt};

#[derive(Debug, Snafu)]
#[snafu(module, context(suffix(false)))]
enum CliError {
    #[snafu(display("core operation failed"))]
    Core { source: rustylink_core::Error },

    #[snafu(display("tunnel operation failed"))]
    Tunnel { source: rustylink_tunnel::Error },

    #[snafu(display("failed to read {}", path.display()))]
    ReadFile {
        path: PathBuf,
        source: std::io::Error,
    },

    #[snafu(display("failed to parse JSON from {}", path.display()))]
    ParseJson {
        path: PathBuf,
        source: serde_json::Error,
    },

    #[snafu(display("failed to render JSON output"))]
    RenderJson { source: serde_json::Error },
}

type Result<T, E = CliError> = std::result::Result<T, E>;

#[derive(Debug, Parser)]
#[command(
    name = "rustylink",
    version,
    about = "Cleanroom CorpLink-compatible VPN client"
)]
struct Cli {
    #[arg(long, env = "RUSTYLINK_STATE")]
    state_path: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Activate(ActivateArgs),
    Login(LoginCommand),
    Profile(ProfileCommand),
    Vpn(VpnCommand),
    Security(SecurityCommand),
    State(StateCommand),
}

#[derive(Debug, Args)]
struct ActivateArgs {
    #[arg(long)]
    code: Option<String>,
    #[arg(long)]
    base_url: Option<String>,
    #[arg(long)]
    backup_url: Option<String>,
}

#[derive(Debug, Args)]
struct LoginCommand {
    #[command(subcommand)]
    command: LoginSubcommand,
}

#[derive(Debug, Subcommand)]
enum LoginSubcommand {
    Password(PasswordArgs),
    OtpSend(CodeSendArgs),
    OtpVerify(CodeVerifyArgs),
    MfaVerify(MfaVerifyArgs),
    OauthStart(OAuthStartArgs),
    OauthCallback(OAuthCallbackArgs),
}

#[derive(Debug, Args)]
struct PasswordArgs {
    #[arg(long, default_value = "login")]
    scene: String,
    #[arg(long, default_value = "account")]
    account_type: String,
    #[arg(long)]
    account: String,
    #[arg(long, env = "RUSTYLINK_PASSWORD")]
    password: String,
}

#[derive(Debug, Args)]
struct CodeSendArgs {
    #[arg(long, default_value = "login")]
    scene: String,
    #[arg(long, default_value = "account")]
    account_type: String,
    #[arg(long, default_value = "otp")]
    login_type: String,
    #[arg(long)]
    account: String,
}

#[derive(Debug, Args)]
struct CodeVerifyArgs {
    #[arg(long, default_value = "login")]
    scene: String,
    #[arg(long, default_value = "account")]
    account_type: String,
    #[arg(long, default_value = "otp")]
    login_type: String,
    #[arg(long)]
    account: String,
    #[arg(long)]
    code: String,
}

#[derive(Debug, Args)]
struct MfaVerifyArgs {
    #[arg(long, default_value = "login")]
    scene: String,
    #[arg(long)]
    mfa_type: String,
    #[arg(long)]
    account: String,
    #[arg(long)]
    code: Option<String>,
    #[arg(long, env = "RUSTYLINK_MFA_PASSWORD")]
    password: Option<String>,
}

#[derive(Debug, Args)]
struct OAuthStartArgs {
    #[arg(long)]
    auth_url: String,
    #[arg(long)]
    alias_key: String,
    #[arg(long, default_value = "corplink://oauth/callback")]
    redirect_uri: String,
    #[arg(long)]
    state: Option<String>,
}

#[derive(Debug, Args)]
struct OAuthCallbackArgs {
    #[arg(long)]
    alias_key: Option<String>,
    #[arg(long)]
    code: String,
    #[arg(long)]
    state: Option<String>,
}

#[derive(Debug, Args)]
struct ProfileCommand {
    #[command(subcommand)]
    command: ProfileSubcommand,
}

#[derive(Debug, Subcommand)]
enum ProfileSubcommand {
    LoginSetting,
    User,
    Tenant,
}

#[derive(Debug, Args)]
struct VpnCommand {
    #[command(subcommand)]
    command: VpnSubcommand,
}

#[derive(Debug, Subcommand)]
enum VpnSubcommand {
    Setting,
    Locations,
    Conn(VpnConnArgs),
    Connect(VpnConnArgs),
}

#[derive(Debug, Args)]
struct VpnConnArgs {
    #[arg(long)]
    public_key: String,
    #[arg(long)]
    export_id: i32,
    #[arg(long)]
    mode: Option<String>,
    #[arg(long)]
    otp: Option<String>,
    #[arg(long)]
    sign_token: Option<String>,
    #[arg(long)]
    not_auto: Option<bool>,
    #[arg(long)]
    api_base_url: Option<String>,
}

#[derive(Debug, Args)]
struct SecurityCommand {
    #[command(subcommand)]
    command: SecuritySubcommand,
}

#[derive(Debug, Subcommand)]
enum SecuritySubcommand {
    Report(SecurityReportArgs),
}

#[derive(Debug, Args)]
struct SecurityReportArgs {
    #[arg(long)]
    status_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct StateCommand {
    #[command(subcommand)]
    command: StateSubcommand,
}

#[derive(Debug, Subcommand)]
enum StateSubcommand {
    Show,
}

#[tokio::main]
async fn main() {
    init_tracing();
    if let Err(error) = run().await {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<()> {
    let cli = Cli::parse();
    let mut ctx = AppContext::load(cli.state_path).context(cli_error::Core)?;

    match cli.command {
        Command::Activate(args) => {
            let response = auth::activate(&mut ctx, args.code, args.base_url, args.backup_url)
                .await
                .context(cli_error::Core)?;
            print_json(&json!({ "state": &ctx.state, "response": response }))?;
        }
        Command::Login(command) => handle_login(&mut ctx, command.command).await?,
        Command::Profile(command) => handle_profile(&mut ctx, command.command).await?,
        Command::Vpn(command) => handle_vpn(&mut ctx, command.command).await?,
        Command::Security(command) => handle_security(&mut ctx, command.command).await?,
        Command::State(command) => match command.command {
            StateSubcommand::Show => print_json(&ctx.state)?,
        },
    }
    Ok(())
}

async fn handle_login(ctx: &mut AppContext, command: LoginSubcommand) -> Result<()> {
    match command {
        LoginSubcommand::Password(args) => {
            let response = auth::login_password(
                ctx,
                args.scene,
                args.account_type,
                args.account,
                args.password,
            )
            .await
            .context(cli_error::Core)?;
            print_json(&response)?;
        }
        LoginSubcommand::OtpSend(args) => {
            let response = auth::send_code(
                ctx,
                args.scene,
                args.account_type,
                args.login_type,
                args.account,
            )
            .await
            .context(cli_error::Core)?;
            print_json(&response)?;
        }
        LoginSubcommand::OtpVerify(args) => {
            let response = auth::verify_code(
                ctx,
                args.scene,
                args.account_type,
                args.login_type,
                args.account,
                args.code,
            )
            .await
            .context(cli_error::Core)?;
            print_json(&response)?;
        }
        LoginSubcommand::MfaVerify(args) => {
            let response = auth::verify_mfa(
                ctx,
                args.scene,
                args.mfa_type,
                args.account,
                args.code,
                args.password,
            )
            .await
            .context(cli_error::Core)?;
            print_json(&response)?;
        }
        LoginSubcommand::OauthStart(args) => {
            let url = auth::start_oauth(
                ctx,
                &args.auth_url,
                args.alias_key,
                args.state,
                &args.redirect_uri,
            )
            .context(cli_error::Core)?;
            print_json(&json!({ "url": url }))?;
        }
        LoginSubcommand::OauthCallback(args) => {
            let response = auth::oauth_callback(ctx, args.alias_key, args.code, args.state)
                .await
                .context(cli_error::Core)?;
            print_json(&response)?;
        }
    }
    Ok(())
}

async fn handle_profile(ctx: &mut AppContext, command: ProfileSubcommand) -> Result<()> {
    match command {
        ProfileSubcommand::LoginSetting => {
            let response = vpn::login_setting(ctx).await.context(cli_error::Core)?;
            print_json(&response)?;
        }
        ProfileSubcommand::User => {
            let response = vpn::user_info(ctx).await.context(cli_error::Core)?;
            print_json(&response)?;
        }
        ProfileSubcommand::Tenant => {
            let response = vpn::tenant_config(ctx).await.context(cli_error::Core)?;
            print_json(&response)?;
        }
    }
    Ok(())
}

async fn handle_vpn(ctx: &mut AppContext, command: VpnSubcommand) -> Result<()> {
    match command {
        VpnSubcommand::Setting => {
            let response = vpn::vpn_setting(ctx).await.context(cli_error::Core)?;
            print_json(&response)?;
        }
        VpnSubcommand::Locations => {
            let response = vpn::vpn_locations(ctx).await.context(cli_error::Core)?;
            print_json(&response)?;
        }
        VpnSubcommand::Conn(args) => {
            let request = vpn_conn_request(args);
            let response = vpn::vpn_conn(ctx, request.1.as_deref(), &request.0)
                .await
                .context(cli_error::Core)?;
            print_json(&response)?;
        }
        VpnSubcommand::Connect(args) => {
            let request = vpn_conn_request(args);
            let response = vpn::vpn_conn(ctx, request.1.as_deref(), &request.0)
                .await
                .context(cli_error::Core)?;
            let Some(data) = response.data.clone() else {
                print_json(&json!({ "response": response, "tunnel": null }))?;
                return Ok(());
            };
            let config = TunnelConfig::from_vpn_conn(&data).context(cli_error::Tunnel)?;
            let mut session = TunnelSession::new(config);
            session.start().await.context(cli_error::Tunnel)?;
            print_json(&json!({ "response": response, "tunnel_status": session.status }))?;
        }
    }
    Ok(())
}

async fn handle_security(ctx: &mut AppContext, command: SecuritySubcommand) -> Result<()> {
    match command {
        SecuritySubcommand::Report(args) => {
            let report = match args.status_file {
                Some(path) => read_security_report(path)?,
                None => security::all_green_security_report(),
            };
            let response = security::report_security(ctx, &report)
                .await
                .context(cli_error::Core)?;
            print_json(&response)?;
        }
    }
    Ok(())
}

fn vpn_conn_request(args: VpnConnArgs) -> (VpnConnRequest, Option<String>) {
    (
        VpnConnRequest {
            mode: args.mode,
            public_key: args.public_key,
            otp: args.otp,
            export_id: args.export_id,
            sign_token: args.sign_token,
            not_auto: args.not_auto,
        },
        args.api_base_url,
    )
}

fn read_security_report(path: PathBuf) -> Result<SecurityReportRequest> {
    let bytes = fs::read(&path).context(cli_error::ReadFile { path: path.clone() })?;
    serde_json::from_slice(&bytes).context(cli_error::ParseJson { path })
}

fn print_json(value: &impl serde::Serialize) -> Result<()> {
    let rendered = serde_json::to_string_pretty(value).context(cli_error::RenderJson)?;
    println!("{rendered}");
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    fmt().with_env_filter(filter).init();
}
