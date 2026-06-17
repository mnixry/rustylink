use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "rustylink",
    version,
    about = "Cleanroom CorpLink-compatible VPN client"
)]
pub struct Cli {
    #[arg(long, env = "RUSTYLINK_STATE")]
    pub state_path: Option<PathBuf>,

    #[arg(long, env = "RUSTYLINK_OUTBOUND_INTERFACE")]
    pub outbound_interface: Option<String>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Activate(ActivateArgs),
    Login(LoginCommand),
    Profile(ProfileCommand),
    Vpn(VpnCommand),
    Security(SecurityCommand),
    State(StateCommand),
}

#[derive(Debug, Args)]
pub struct ActivateArgs {
    #[arg(long)]
    pub code: Option<String>,
    #[arg(long)]
    pub base_url: Option<String>,
    #[arg(long)]
    pub backup_url: Option<String>,
    #[arg(long, env = "RUSTYLINK_MATCH_BASE_URL")]
    pub match_base_url: Option<String>,
}

#[derive(Debug, Args)]
pub struct LoginCommand {
    #[command(subcommand)]
    pub command: LoginSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum LoginSubcommand {
    Password(PasswordArgs),
    OtpSend(CodeSendArgs),
    OtpVerify(CodeVerifyArgs),
    MfaVerify(MfaVerifyArgs),
    QrAuth(QrAuthArgs),
}

#[derive(Debug, Args)]
pub struct PasswordArgs {
    #[arg(long, default_value = "login")]
    pub scene: String,
    #[arg(long, default_value = "account")]
    pub account_type: String,
    #[arg(long)]
    pub account: String,
    #[arg(long, env = "RUSTYLINK_PASSWORD")]
    pub password: String,
}

#[derive(Debug, Args)]
pub struct CodeSendArgs {
    #[arg(long, default_value = "login")]
    pub scene: String,
    #[arg(long, default_value = "account")]
    pub account_type: String,
    #[arg(long, default_value = "otp")]
    pub login_type: String,
    #[arg(long)]
    pub account: String,
}

#[derive(Debug, Args)]
pub struct CodeVerifyArgs {
    #[arg(long, default_value = "login")]
    pub scene: String,
    #[arg(long, default_value = "account")]
    pub account_type: String,
    #[arg(long, default_value = "otp")]
    pub login_type: String,
    #[arg(long)]
    pub account: String,
    #[arg(long)]
    pub code: String,
}

#[derive(Debug, Args)]
pub struct MfaVerifyArgs {
    #[arg(long, default_value = "login")]
    pub scene: String,
    #[arg(long)]
    pub mfa_type: String,
    #[arg(long)]
    pub account: String,
    #[arg(long)]
    pub code: Option<String>,
    #[arg(long, env = "RUSTYLINK_MFA_PASSWORD")]
    pub password: Option<String>,
}

#[derive(Debug, Args)]
pub struct QrAuthArgs {
    #[arg(long)]
    pub alias: Option<String>,
    #[arg(long)]
    pub alias_key: Option<String>,
    #[arg(long)]
    pub index: Option<usize>,
    #[arg(long)]
    pub callback_url: Option<String>,
    #[arg(long)]
    pub code: Option<String>,
    #[arg(long)]
    pub state: Option<String>,
    #[arg(long, default_value_t = 1_000)]
    pub poll_interval_ms: u64,
    #[arg(long, default_value_t = 120)]
    pub poll_timeout_seconds: u64,
    #[arg(long)]
    pub no_qr: bool,
}

#[derive(Debug, Args)]
pub struct ProfileCommand {
    #[command(subcommand)]
    pub command: ProfileSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum ProfileSubcommand {
    LoginSetting,
    User,
    Tenant,
}

#[derive(Debug, Args)]
pub struct VpnCommand {
    #[command(subcommand)]
    pub command: VpnSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum VpnSubcommand {
    Setting,
    Locations,
    Conn(VpnConnArgs),
    Connect(VpnConnArgs),
}

#[derive(Debug, Args)]
pub struct VpnConnArgs {
    #[arg(long)]
    pub public_key: Option<String>,
    #[arg(long)]
    pub local_private_key: Option<String>,
    #[arg(long)]
    pub export_id: Option<i32>,
    #[arg(long)]
    pub mode: Option<String>,
    #[arg(long)]
    pub otp: Option<String>,
    #[arg(long)]
    pub sign_token: Option<String>,
    #[arg(long)]
    pub not_auto: Option<bool>,
    #[arg(long)]
    pub api_base_url: Option<String>,
    #[arg(long)]
    pub dot_id: Option<i32>,
    #[arg(long)]
    pub reconnect: bool,
}

#[derive(Debug, Args)]
pub struct SecurityCommand {
    #[command(subcommand)]
    pub command: SecuritySubcommand,
}

#[derive(Debug, Subcommand)]
pub enum SecuritySubcommand {
    Report(SecurityReportArgs),
}

#[derive(Debug, Args)]
pub struct SecurityReportArgs {
    #[arg(long)]
    pub status_file: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct StateCommand {
    #[command(subcommand)]
    pub command: StateSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum StateSubcommand {
    Show,
}
