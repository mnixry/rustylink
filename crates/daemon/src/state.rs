//! Daemon state machine: `DaemonState` embeds the core `RustylinkState`
//! (the auth source of truth, per D7) and adds the auth/VPN phase machine,
//! configuration, and the hashed bearer token.  The actor owns the canonical
//! `DaemonState`, persists it atomically after each transition, and projects
//! redacted views to the proto wire types (secrets never leave the daemon).

use std::{
    fs,
    io::Write as _,
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
};

use jiff::Timestamp;
use rustylink_core::{RustylinkState, vpn::VpnConnectMode};
use rustylink_proto::proto::rustylink::daemon::v1 as pb;
use serde::{Deserialize, Serialize};
use snafu::prelude::*;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("failed to read state file {}", path.display()))]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[snafu(display("failed to write state file {}", path.display()))]
    Write {
        path: PathBuf,
        source: std::io::Error,
    },
    #[snafu(display("failed to create state directory {}", path.display()))]
    CreateDir {
        path: PathBuf,
        source: std::io::Error,
    },
    #[snafu(display("failed to parse state file {}", path.display()))]
    Parse {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[snafu(display("failed to serialize state"))]
    Serialize { source: serde_json::Error },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

const STATE_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Phase enums
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthPhase {
    #[default]
    Unconfigured,
    Configured,
    Authenticating,
    Authenticated,
    Expired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LoginApi {
    V1,
    Legacy,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VpnPhase {
    #[default]
    Disconnected,
    Connecting,
    Configuring,
    Connected,
    Reconnecting,
    Disconnecting,
    Failed,
}

// ---------------------------------------------------------------------------
// Pending auth challenge (daemon-internal; OAuth verifier is secret)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingChallenge {
    Otp {
        masked_target: String,
        login_type: String,
    },
    Mfa {
        mfa_type: String,
        auth_list: Vec<String>,
        can_skip: bool,
    },
    Oauth {
        alias_key: String,
        state: String,
        poll_token: Option<String>,
    },
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind", content = "name")]
pub enum OutboundSelector {
    #[default]
    Auto,
    Name(String),
}

impl OutboundSelector {
    #[must_use]
    pub fn name(&self) -> Option<&str> {
        match self {
            Self::Auto => None,
            Self::Name(name) => Some(name),
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ConfigState {
    pub outbound_interface: OutboundSelector,
    pub auto_reconnect_on_start: bool,
}

// ---------------------------------------------------------------------------
// VPN state
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VpnRequest {
    pub mode: VpnConnectMode,
    pub export_id: i32,
    pub preferred_dot_id: Option<i32>,
    pub otp: Option<String>,
    pub reconnect: bool,
    pub protocol_mode: Option<i32>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ActiveTunnel {
    pub dot_id: i32,
    pub dot_name: String,
    pub endpoint: String,
    pub assigned_ip: String,
    pub connected_at_unix: Option<i64>,
    pub last_handshake_unix: Option<i64>,
    pub protocol_mode: Option<i32>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VpnState {
    pub phase: VpnPhase,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<VpnRequest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<ActiveTunnel>,
    pub reconnect_attempts: u32,
    pub last_error: Option<String>,
}

// ---------------------------------------------------------------------------
// DaemonState
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DaemonState {
    pub version: u32,
    pub updated_at_unix: i64,
    #[serde(default)]
    pub token_hash: Option<String>,
    #[serde(default)]
    pub auth_phase: AuthPhase,
    #[serde(default)]
    pub login_api: Option<LoginApi>,
    #[serde(default)]
    pub pending_challenge: Option<PendingChallenge>,
    /// Embedded core auth state (tenant, identity, cookies, signing, totp...).
    pub core: RustylinkState,
    #[serde(default)]
    pub config: ConfigState,
    #[serde(default)]
    pub vpn: VpnState,
}

impl Default for DaemonState {
    fn default() -> Self {
        Self::new()
    }
}

impl DaemonState {
    #[must_use]
    pub fn new() -> Self {
        Self {
            version: STATE_VERSION,
            updated_at_unix: Timestamp::now().as_second(),
            token_hash: None,
            auth_phase: AuthPhase::Unconfigured,
            login_api: None,
            pending_challenge: None,
            core: RustylinkState::new(),
            config: ConfigState::default(),
            vpn: VpnState::default(),
        }
    }

    /// Load state from disk, or return a fresh default if the file is absent.
    pub fn load_or_default(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let bytes = fs::read(path).context(ReadSnafu {
            path: path.to_path_buf(),
        })?;
        serde_json::from_slice(&bytes).context(ParseSnafu {
            path: path.to_path_buf(),
        })
    }

    /// Persist state atomically (temp file + rename) with mode 0600.
    pub fn save(&mut self, path: &Path) -> Result<()> {
        self.updated_at_unix = Timestamp::now().as_second();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).context(CreateDirSnafu {
                path: parent.to_path_buf(),
            })?;
        }
        let bytes = serde_json::to_vec_pretty(self).context(SerializeSnafu)?;

        let tmp_path = path.with_extension("json.tmp");
        let mut tmp = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp_path)
            .context(WriteSnafu {
                path: tmp_path.clone(),
            })?;
        tmp.write_all(&bytes).context(WriteSnafu {
            path: tmp_path.clone(),
        })?;
        tmp.sync_all().context(WriteSnafu {
            path: tmp_path.clone(),
        })?;
        drop(tmp);
        // Ensure mode is 0600 even if the file pre-existed.
        fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600)).context(WriteSnafu {
            path: tmp_path.clone(),
        })?;
        fs::rename(&tmp_path, path).context(WriteSnafu {
            path: path.to_path_buf(),
        })
    }

    // -----------------------------------------------------------------------
    // Proto projections (redacted — secrets are never projected)
    // -----------------------------------------------------------------------

    #[must_use]
    pub fn to_session(&self) -> pb::Session {
        let state = match self.auth_phase {
            AuthPhase::Unconfigured => pb::session::State::Unconfigured,
            AuthPhase::Configured => pb::session::State::Configured,
            AuthPhase::Authenticating => pb::session::State::Authenticating,
            AuthPhase::Authenticated => pb::session::State::Authenticated,
            AuthPhase::Expired => pb::session::State::Expired,
        };
        let pending = self.pending_challenge.as_ref().map(project_challenge);
        pb::Session {
            state: state.into(),
            tenant_name: self.core.tenant.name.clone().unwrap_or_default(),
            base_url: self
                .core
                .selected_base_url()
                .unwrap_or_default()
                .to_string(),
            pending_challenge: pending.into(),
            ..Default::default()
        }
    }

    #[must_use]
    pub fn to_tunnel(&self) -> pb::Tunnel {
        let state = match self.vpn.phase {
            VpnPhase::Disconnected => pb::tunnel::State::Disconnected,
            VpnPhase::Connecting => pb::tunnel::State::Connecting,
            VpnPhase::Configuring => pb::tunnel::State::Configuring,
            VpnPhase::Connected => pb::tunnel::State::Connected,
            VpnPhase::Reconnecting => pb::tunnel::State::Reconnecting,
            VpnPhase::Disconnecting => pb::tunnel::State::Disconnecting,
            VpnPhase::Failed => pb::tunnel::State::Failed,
        };
        let mode = self
            .vpn
            .request
            .as_ref()
            .map_or(pb::VpnMode::Unspecified, |r| vpn_mode_to_proto(r.mode));
        let active = self.vpn.active.as_ref();
        pb::Tunnel {
            state: state.into(),
            mode: mode.into(),
            dot_id: active.map(|a| a.dot_id).unwrap_or_default(),
            dot_name: active.map(|a| a.dot_name.clone()).unwrap_or_default(),
            endpoint: active.map(|a| a.endpoint.clone()).unwrap_or_default(),
            assigned_ip: active.map(|a| a.assigned_ip.clone()).unwrap_or_default(),
            connected_at: active
                .and_then(|a| a.connected_at_unix)
                .map(timestamp_from_unix)
                .into(),
            last_handshake_at: active
                .and_then(|a| a.last_handshake_unix)
                .map(timestamp_from_unix)
                .into(),
            reconnect_attempts: self.vpn.reconnect_attempts,
            error: self.vpn.last_error.clone().unwrap_or_default(),
            ..Default::default()
        }
    }

    #[must_use]
    pub fn to_configuration(&self) -> pb::Configuration {
        let outbound = match &self.config.outbound_interface {
            OutboundSelector::Auto => pb::OutboundInterface {
                selector: Some(pb::outbound_interface::Selector::from(buffa_types_empty())),
                ..Default::default()
            },
            OutboundSelector::Name(name) => pb::OutboundInterface {
                selector: Some(pb::outbound_interface::Selector::Name(name.clone())),
                ..Default::default()
            },
        };
        pb::Configuration {
            outbound_interface: outbound.into(),
            auto_reconnect_on_start: self.config.auto_reconnect_on_start,
            ..Default::default()
        }
    }

    #[must_use]
    pub fn to_watch_response(&self) -> pb::WatchStateResponse {
        pb::WatchStateResponse {
            session: self.to_session().into(),
            tunnel: self.to_tunnel().into(),
            configuration: self.to_configuration().into(),
            updated_at: timestamp_from_unix(self.updated_at_unix).into(),
            ..Default::default()
        }
    }
}

// ---------------------------------------------------------------------------
// Projection helpers
// ---------------------------------------------------------------------------

fn project_challenge(challenge: &PendingChallenge) -> pb::PendingChallenge {
    let inner: Option<pb::pending_challenge::Challenge> = match challenge {
        PendingChallenge::Otp {
            masked_target,
            login_type,
        } => Some(
            pb::OtpChallenge {
                masked_target: masked_target.clone(),
                login_type: login_type.clone(),
                ..Default::default()
            }
            .into(),
        ),
        PendingChallenge::Mfa {
            mfa_type,
            auth_list,
            can_skip,
        } => Some(
            pb::MfaChallenge {
                mfa_type: mfa_type.clone(),
                auth_list: auth_list.clone(),
                can_skip: *can_skip,
                ..Default::default()
            }
            .into(),
        ),
        PendingChallenge::Oauth {
            alias_key,
            state,
            poll_token,
        } => Some(
            pb::OauthChallenge {
                alias_key: alias_key.clone(),
                state: state.clone(),
                poll_token: poll_token.clone().unwrap_or_default(),
                ..Default::default()
            }
            .into(),
        ),
    };
    pb::PendingChallenge {
        challenge: inner,
        ..Default::default()
    }
}

#[must_use]
pub fn vpn_mode_to_proto(mode: VpnConnectMode) -> pb::VpnMode {
    match mode {
        VpnConnectMode::Full => pb::VpnMode::Full,
        VpnConnectMode::Split => pb::VpnMode::Split,
        VpnConnectMode::Relay => pb::VpnMode::Relay,
    }
}

fn timestamp_from_unix(seconds: i64) -> buffa_types::google::protobuf::Timestamp {
    buffa_types::google::protobuf::Timestamp {
        seconds,
        nanos: 0,
        ..Default::default()
    }
}

fn buffa_types_empty() -> buffa_types::google::protobuf::Empty {
    buffa_types::google::protobuf::Empty::default()
}
