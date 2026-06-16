use std::{fs, path::PathBuf, str::FromStr};

use clap::{Args, Parser, Subcommand};
use rustylink_api::{ApiClientOptions, SecurityReportRequest, VpnConnRequest, VpnReportRequest};
use rustylink_core::{
    AppContext, auth, security,
    vpn::{self, VpnConfigRequest, VpnConnectMode},
};
use rustylink_tunnel::{LocalTunnelParams, OutboundInterface, TunnelConfig, TunnelSession};
use serde_json::json;
use snafu::prelude::*;
use strum::IntoEnumIterator;
use tracing_subscriber::{EnvFilter, fmt};

#[derive(Debug, Snafu)]
#[snafu(module, visibility(pub(crate)))]
enum CliError {
    #[snafu(display("application context operation failed"))]
    CoreContext {
        #[snafu(source(from(rustylink_core::context::Error, Box::new)))]
        source: Box<rustylink_core::context::Error>,
    },

    #[snafu(display("authentication operation failed"))]
    Auth {
        #[snafu(source(from(rustylink_core::auth::Error, Box::new)))]
        source: Box<rustylink_core::auth::Error>,
    },

    #[snafu(display("VPN core operation failed"))]
    Vpn {
        #[snafu(source(from(rustylink_core::vpn::Error, Box::new)))]
        source: Box<rustylink_core::vpn::Error>,
    },

    #[snafu(display("security report operation failed"))]
    Security {
        #[snafu(source(from(rustylink_core::security::Error, Box::new)))]
        source: Box<rustylink_core::security::Error>,
    },

    #[snafu(display("tunnel operation failed"))]
    Tunnel { source: rustylink_tunnel::Error },

    #[snafu(display("outbound interface selection failed"))]
    OutboundInterface {
        source: rustylink_tunnel::outbound::Error,
    },

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

    #[snafu(display("invalid VPN mode `{value}`; expected one of: {expected}"))]
    InvalidVpnMode { value: String, expected: String },

    #[snafu(display("no export_id was provided and /api/setting did not return one"))]
    MissingExportId,

    #[snafu(display("failed to wait for Ctrl-C"))]
    WaitForSignal { source: std::io::Error },
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

    #[arg(long, env = "RUSTYLINK_OUTBOUND_INTERFACE")]
    outbound_interface: Option<String>,

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
    #[arg(long, env = "RUSTYLINK_MATCH_BASE_URL")]
    match_base_url: Option<String>,
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
    OauthQueryCallback(OAuthQueryCallbackArgs),
    QrStart(QrStartArgs),
    QrCheck(QrCheckArgs),
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
struct OAuthQueryCallbackArgs {
    #[arg(long)]
    alias: String,
    #[arg(long)]
    code: String,
    #[arg(long)]
    state: String,
}

#[derive(Debug, Args)]
struct QrStartArgs {}

#[derive(Debug, Args)]
struct QrCheckArgs {
    #[arg(long)]
    token: String,
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
    public_key: Option<String>,
    #[arg(long)]
    local_private_key: Option<String>,
    #[arg(long)]
    export_id: Option<i32>,
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
    #[arg(long)]
    dot_id: Option<i32>,
    #[arg(long)]
    reconnect: bool,
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
            .context(cli_error::AuthSnafu)?;
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
            .context(cli_error::AuthSnafu)?;
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
            .context(cli_error::AuthSnafu)?;
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
            .context(cli_error::AuthSnafu)?;
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
            .context(cli_error::AuthSnafu)?;
            print_json(&json!({ "url": url }))?;
        }
        LoginSubcommand::OauthCallback(args) => {
            let response = auth::oauth_callback(ctx, args.alias_key, args.code, args.state)
                .await
                .context(cli_error::AuthSnafu)?;
            print_json(&response)?;
        }
        LoginSubcommand::OauthQueryCallback(args) => {
            let response = auth::oauth_query_callback(ctx, args.alias, args.code, args.state)
                .await
                .context(cli_error::AuthSnafu)?;
            print_json(&response)?;
        }
        LoginSubcommand::QrStart(_args) => {
            let response = auth::third_party_login_links(ctx)
                .await
                .context(cli_error::AuthSnafu)?;
            print_json(&response)?;
        }
        LoginSubcommand::QrCheck(args) => {
            let response = auth::check_third_party_login_token(ctx, args.token)
                .await
                .context(cli_error::AuthSnafu)?;
            print_json(&response)?;
        }
    }
    Ok(())
}

async fn handle_profile(ctx: &mut AppContext, command: ProfileSubcommand) -> Result<()> {
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

async fn handle_vpn(ctx: &mut AppContext, command: VpnSubcommand) -> Result<()> {
    match command {
        VpnSubcommand::Setting => {
            let response = vpn::vpn_setting(ctx).await.context(cli_error::VpnSnafu)?;
            print_json(&response)?;
        }
        VpnSubcommand::Locations => {
            let response = vpn::vpn_locations(ctx).await.context(cli_error::VpnSnafu)?;
            print_json(&response)?;
        }
        VpnSubcommand::Conn(args) => {
            let request = vpn_conn_request(ctx, args).await?;
            let response = vpn::vpn_conn(ctx, request.1.as_deref(), &request.0)
                .await
                .context(cli_error::VpnSnafu)?;
            print_json(&response)?;
        }
        VpnSubcommand::Connect(args) => {
            let outbound_interface = ensure_outbound_interface(ctx)?;
            let mode = parse_vpn_mode(args.mode.as_deref())?;
            let export_id = resolve_export_id(ctx, args.export_id).await?;
            let local_params = local_params_for_connect(&args)?;
            let config_request = VpnConfigRequest {
                mode,
                public_key: local_params.local_public_key.clone(),
                export_id,
                otp: args.otp,
                sign_token: args.sign_token,
                not_auto: args.not_auto.unwrap_or(true),
                reconnect: args.reconnect,
                preferred_dot_id: args.dot_id,
            };
            let config_result = vpn::vpn_config_from_dot_list(ctx, &config_request)
                .await
                .context(cli_error::VpnSnafu)?;
            let data = config_result
                .response
                .data
                .clone()
                .expect("core checked config data exists");
            let mut config = TunnelConfig::from_vpn_conn(
                &data,
                local_params.clone(),
                config_result.servers.wireguard_endpoint.clone(),
                config_result.dot.protocol_mode,
                config_result.dot.protocol_detect_enabled(),
            )
            .context(cli_error::TunnelSnafu)?;
            config.outbound_interface = outbound_interface.map(|interface| interface.name);
            let mut session = TunnelSession::new(config);
            session.start().await.context(cli_error::TunnelSnafu)?;
            let connect_report =
                vpn_report_request(100, &data.ip, &local_params.local_public_key, mode);
            let connect_report_response =
                match vpn::report_vpn(ctx, &config_result.dot, &connect_report).await {
                    Ok(response) => Some(response),
                    Err(error) => {
                        tracing::warn!(%error, "failed to report VPN connection");
                        None
                    }
                };
            print_json(&json!({
                "response": &config_result.response,
                "dot": &config_result.dot,
                "servers": &config_result.servers,
                "local_public_key": &local_params.local_public_key,
                "outbound_interface": ctx.outbound_interface(),
                "connect_report": connect_report_response,
                "tunnel_status": session.status,
            }))?;
            tokio::signal::ctrl_c()
                .await
                .context(cli_error::WaitForSignalSnafu)?;
            let disconnect_report =
                vpn_report_request(101, &data.ip, &local_params.local_public_key, mode);
            if let Err(error) = vpn::report_vpn(ctx, &config_result.dot, &disconnect_report).await {
                tracing::warn!(%error, "failed to report VPN disconnection");
            }
            session.stop().await.context(cli_error::TunnelSnafu)?;
        }
    }
    Ok(())
}

fn ensure_outbound_interface(ctx: &mut AppContext) -> Result<Option<OutboundInterface>> {
    let outbound_interface = OutboundInterface::resolve(ctx.outbound_interface(), None)
        .context(cli_error::OutboundInterfaceSnafu)?;
    if let Some(outbound_interface) = &outbound_interface {
        ctx.set_outbound_interface(Some(outbound_interface.name.clone()));
    }
    Ok(outbound_interface)
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
                .context(cli_error::SecuritySnafu)?;
            print_json(&response)?;
        }
    }
    Ok(())
}

async fn vpn_conn_request(
    ctx: &mut AppContext, args: VpnConnArgs,
) -> Result<(VpnConnRequest, Option<String>)> {
    let mode = parse_vpn_mode(args.mode.as_deref())?;
    let export_id = resolve_export_id(ctx, args.export_id).await?;
    let public_key = args
        .public_key
        .unwrap_or_else(|| LocalTunnelParams::generate().local_public_key);
    Ok((
        VpnConnRequest {
            mode: Some(mode.android_name()),
            public_key,
            otp: args.otp,
            export_id,
            sign_token: args.sign_token,
            not_auto: args.not_auto,
        },
        args.api_base_url,
    ))
}

async fn resolve_export_id(ctx: &mut AppContext, export_id: Option<i32>) -> Result<i32> {
    if let Some(export_id) = export_id {
        return Ok(export_id);
    }
    let setting = vpn::vpn_setting(ctx).await.context(cli_error::VpnSnafu)?;
    setting
        .data
        .and_then(|data| data.export_id)
        .context(cli_error::MissingExportIdSnafu)
}

fn local_params_for_connect(args: &VpnConnArgs) -> Result<LocalTunnelParams> {
    if let Some(private_key) = &args.local_private_key {
        return LocalTunnelParams::from_private_key(private_key).context(cli_error::TunnelSnafu);
    }
    Ok(LocalTunnelParams::generate())
}

fn parse_vpn_mode(value: Option<&str>) -> Result<VpnConnectMode> {
    let Some(value) = value else {
        return Ok(VpnConnectMode::Full);
    };
    VpnConnectMode::from_str(value).map_err(|_| {
        cli_error::InvalidVpnModeSnafu {
            value: value.to_string(),
            expected: vpn_mode_names(),
        }
        .build()
    })
}

fn vpn_mode_names() -> String {
    VpnConnectMode::iter()
        .map(VpnConnectMode::android_name)
        .collect::<Vec<_>>()
        .join(", ")
}

fn vpn_report_request(
    report_type: i32, ip: &str, public_key: &str, mode: VpnConnectMode,
) -> VpnReportRequest {
    VpnReportRequest {
        ip: ip.to_string(),
        mode: mode.android_name(),
        public_key: public_key.to_string(),
        type_: report_type.to_string(),
    }
}

fn read_security_report(path: PathBuf) -> Result<SecurityReportRequest> {
    let bytes = fs::read(&path).context(cli_error::ReadFileSnafu { path: path.clone() })?;
    serde_json::from_slice(&bytes).context(cli_error::ParseJsonSnafu { path })
}

fn print_json(value: &impl serde::Serialize) -> Result<()> {
    let rendered = serde_json::to_string_pretty(value).context(cli_error::RenderJsonSnafu)?;
    println!("{rendered}");
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    fmt().with_env_filter(filter).init();
}
