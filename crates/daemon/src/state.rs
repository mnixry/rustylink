//! Daemon state — a thin wrapper around the canonical proto `PersistedState`.
//!
//! The persisted proto **is** the state machine: a two-level oneof where each
//! variant carries exactly the data valid in that state.  Invalid combinations
//! (e.g. VPN Connected while Unconfigured) are unrepresentable.  All state
//! transitions are methods on [`DaemonState`] that navigate the oneof directly
//! — there is no parallel Rust state type and no whole-state conversion.
//!
//! Persisted as buffa JSON (camelCase, RFC 3339 timestamps, enum names).

use std::{
    collections::HashMap,
    fs,
    io::Write as _,
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
};

use buffa::MessageField;
use jiff::Timestamp;
use persist::{persisted_authenticated::VpnState as PV, persisted_state::AuthState as PA};
use rustylink_core::vpn::VpnConnectMode;
use rustylink_proto::proto::rustylink::daemon::{persist::v1 as persist, v1 as pb};
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

const STATE_VERSION: u32 = 2;

// =========================================================================
// Live working types (kept for behavior; persisted via proto conversion)
// =========================================================================

/// A VPN connect request — the working form that drives the connect loop.
///
/// Kept as a Rust type for the `From<ConnectTunnelRequest>` bridge and the
/// `VpnConnectMode` enum (consumed directly by core).  Converted to/from
/// `PersistedVpnRequest` only at the persisted `vpn_state` boundary.
#[derive(Clone, Debug)]
pub struct VpnRequest {
    pub mode: VpnConnectMode,
    pub export_id: i32,
    pub preferred_dot_id: Option<i32>,
    pub otp: Option<String>,
    pub reconnect: bool,
    pub protocol_mode: Option<i32>,
}

impl From<pb::ConnectTunnelRequest> for VpnRequest {
    fn from(request: pb::ConnectTunnelRequest) -> Self {
        let mode = match request.mode {
            buffa::EnumValue::Known(pb::VpnMode::Split) => VpnConnectMode::Split,
            buffa::EnumValue::Known(pb::VpnMode::Relay) => VpnConnectMode::Relay,
            _ => VpnConnectMode::Full,
        };
        let protocol_mode = match request.protocol_mode {
            buffa::EnumValue::Known(pb::ProtocolMode::Udp) => Some(0),
            buffa::EnumValue::Known(pb::ProtocolMode::Tcp) => Some(1),
            buffa::EnumValue::Known(pb::ProtocolMode::Auto) => Some(2),
            _ => None,
        };
        Self {
            mode,
            export_id: request.export_id,
            preferred_dot_id: request.preferred_dot_id,
            otp: request.otp,
            reconnect: request.reconnect,
            protocol_mode,
        }
    }
}

/// A live, connected tunnel — the working form recorded on connect.
///
/// Kept for `jiff::Timestamp` (handshake age in the supervisor).  Converted to
/// `PersistedActiveTunnel` when written into the `vpn_state` oneof.
#[derive(Clone, Debug, Default)]
pub struct ActiveTunnel {
    pub dot_id: i32,
    pub dot_name: String,
    pub endpoint: String,
    pub assigned_ip: String,
    pub connected_at: Option<Timestamp>,
    pub last_handshake_at: Option<Timestamp>,
    pub protocol_mode: Option<i32>,
}

// =========================================================================
// DaemonState — thin wrapper around the canonical proto
// =========================================================================

#[derive(Clone, Debug)]
pub struct DaemonState {
    pub proto: persist::PersistedState,
}

impl Default for DaemonState {
    fn default() -> Self {
        Self::new()
    }
}

impl DaemonState {
    #[must_use]
    pub fn new() -> Self {
        // Persist only the per-install device id; the rest of the identity is
        // filled from the built-in Android-profile default on read
        // (partial-merge-with-default), so the profile tracks the code.
        let identity = persist::PersistedIdentity {
            device_id: Some(rustylink_api::ClientIdentity::default().device_id),
            ..Default::default()
        };
        Self {
            proto: persist::PersistedState {
                version: STATE_VERSION,
                updated_at: MessageField::some(proto_timestamp(Timestamp::now())),
                identity: MessageField::some(identity),
                auth_state: Some(PA::from(persist::PersistedUnconfigured::default())),
                ..Default::default()
            },
        }
    }

    // ------- persistence -------

    pub fn load_or_default(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::new());
        }
        let bytes = fs::read(path).context(ReadSnafu {
            path: path.to_path_buf(),
        })?;
        let proto: persist::PersistedState =
            serde_json::from_slice(&bytes).context(ParseSnafu {
                path: path.to_path_buf(),
            })?;
        Ok(Self { proto })
    }

    pub fn save(&mut self, path: &Path) -> Result<()> {
        self.proto.updated_at = MessageField::some(proto_timestamp(Timestamp::now()));
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).context(CreateDirSnafu {
                path: parent.to_path_buf(),
            })?;
        }
        let bytes = serde_json::to_vec_pretty(&self.proto).context(SerializeSnafu)?;
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
        fs::set_permissions(&tmp_path, fs::Permissions::from_mode(0o600)).context(WriteSnafu {
            path: tmp_path.clone(),
        })?;
        fs::rename(&tmp_path, path).context(WriteSnafu {
            path: path.to_path_buf(),
        })
    }

    // ------- projections (proto-to-proto From impls in the proto crate) -------

    #[must_use]
    pub fn to_session(&self) -> pb::Session {
        pb::Session::from(&self.proto)
    }

    #[must_use]
    pub fn to_tunnel(&self) -> pb::Tunnel {
        pb::Tunnel::from(&self.proto)
    }

    #[must_use]
    pub fn to_configuration(&self) -> pb::Configuration {
        pb::Configuration::from(&self.proto)
    }

    // ------- top-level config accessors -------

    #[must_use]
    pub fn auto_reconnect_on_start(&self) -> bool {
        self.proto.auto_reconnect_on_start
    }

    pub fn set_auto_reconnect_on_start(&mut self, value: bool) {
        self.proto.auto_reconnect_on_start = value;
    }

    #[must_use]
    pub fn outbound_interface_name(&self) -> Option<String> {
        self.proto
            .outbound_interface
            .as_option()
            .and_then(|o| match &o.selector {
                Some(pb::outbound_interface::Selector::Name(name)) if !name.is_empty() => {
                    Some(name.clone())
                }
                _ => None,
            })
    }

    pub fn set_outbound_interface_name(&mut self, name: Option<String>) {
        let selector = match name {
            Some(n) if !n.is_empty() => pb::outbound_interface::Selector::Name(n),
            _ => pb::outbound_interface::Selector::from(
                buffa_types::google::protobuf::Empty::default(),
            ),
        };
        self.proto.outbound_interface = MessageField::some(pb::OutboundInterface {
            selector: Some(selector),
            ..Default::default()
        });
    }

    // ------- auth-state queries -------

    #[must_use]
    pub fn configured_base(&self) -> Option<&persist::PersistedConfiguredBase> {
        match self.proto.auth_state.as_ref()? {
            PA::Unconfigured(_) => None,
            PA::Configured(d) => d.base.as_option(),
            PA::Authenticating(d) => d.base.as_option(),
            PA::Authenticated(d) => d.base.as_option(),
            PA::Expired(d) => d.base.as_option(),
        }
    }

    fn configured_base_mut(&mut self) -> Option<&mut persist::PersistedConfiguredBase> {
        match self.proto.auth_state.as_mut()? {
            PA::Unconfigured(_) => None,
            PA::Configured(d) => d.base.as_option_mut(),
            PA::Authenticating(d) => d.base.as_option_mut(),
            PA::Authenticated(d) => d.base.as_option_mut(),
            PA::Expired(d) => d.base.as_option_mut(),
        }
    }

    #[must_use]
    pub fn authenticated(&self) -> Option<&persist::PersistedAuthenticated> {
        match self.proto.auth_state.as_ref()? {
            PA::Authenticated(d) => Some(&**d),
            _ => None,
        }
    }

    fn authenticated_mut(&mut self) -> Option<&mut persist::PersistedAuthenticated> {
        match self.proto.auth_state.as_mut()? {
            PA::Authenticated(d) => Some(&mut **d),
            _ => None,
        }
    }

    #[must_use]
    pub fn is_authenticated(&self) -> bool {
        matches!(self.proto.auth_state.as_ref(), Some(PA::Authenticated(_)))
    }

    #[must_use]
    pub fn is_v1(&self) -> bool {
        matches!(
            self.configured_base().map(|b| b.login_api.as_known()),
            Some(Some(persist::PersistedLoginApi::V1))
        )
    }

    pub fn set_login_api(&mut self, v1: bool) {
        if let Some(base) = self.configured_base_mut() {
            base.login_api = if v1 {
                persist::PersistedLoginApi::V1
            } else {
                persist::PersistedLoginApi::Legacy
            }
            .into();
        }
    }

    #[must_use]
    pub fn oauth_state_value(&self) -> Option<String> {
        match self.proto.auth_state.as_ref()? {
            PA::Authenticating(d) => d.oauth.as_option().and_then(|o| o.state.clone()),
            _ => None,
        }
    }

    // ------- auth-state transitions (the state machine) -------

    /// Tenant configured after activation: promote Unconfigured → Configured,
    /// or update the base of an already-configured state in place.
    pub fn set_tenant_configured(
        &mut self, tenant: persist::PersistedTenant, signing: persist::PersistedSigning,
    ) {
        if matches!(self.proto.auth_state, Some(PA::Unconfigured(_)) | None) {
            self.proto.auth_state = Some(PA::from(persist::PersistedConfigured {
                base: MessageField::some(make_base(tenant, signing, None)),
                ..Default::default()
            }));
        } else if let Some(base) = self.configured_base_mut() {
            base.tenant = MessageField::some(tenant);
            base.signing = MessageField::some(signing);
        }
    }

    /// Replace the full cookie set (Authenticating or Authenticated).
    pub fn set_cookies(&mut self, cookies: HashMap<String, String>) {
        match self.proto.auth_state.as_mut() {
            Some(PA::Authenticating(d)) => d.cookies = cookies,
            Some(PA::Authenticated(d)) => d.cookies = cookies,
            _ => {}
        }
    }

    pub fn set_csrf_token(&mut self, token: Option<String>) {
        match self.proto.auth_state.as_mut() {
            Some(PA::Authenticating(d)) => d.csrf_token = token,
            Some(PA::Authenticated(d)) => d.csrf_token = token,
            _ => {}
        }
    }

    pub fn set_signing(&mut self, config: persist::PersistedSigning) {
        if let Some(base) = self.configured_base_mut() {
            base.signing = MessageField::some(config);
        }
    }

    /// Set OAuth state + pending challenge, promoting Configured →
    /// Authenticating if necessary.
    pub fn set_oauth(&mut self, alias_key: String, state: String, code_verifier: String) {
        let challenge = oauth_pending_challenge(&alias_key, &state);
        let oauth = persist::PersistedOauth {
            alias_key: Some(alias_key),
            state: Some(state),
            code_verifier: Some(code_verifier),
            ..Default::default()
        };
        if let Some(PA::Authenticating(d)) = self.proto.auth_state.as_mut() {
            d.oauth = MessageField::some(oauth);
            d.pending_challenge = MessageField::some(challenge);
        } else {
            self.proto.auth_state = match self.proto.auth_state.take() {
                Some(PA::Configured(d)) => Some(PA::from(persist::PersistedAuthenticating {
                    base: d.base,
                    oauth: MessageField::some(oauth),
                    pending_challenge: MessageField::some(challenge),
                    ..Default::default()
                })),
                other => other,
            };
        }
    }

    pub fn clear_oauth(&mut self) {
        if let Some(PA::Authenticating(d)) = self.proto.auth_state.as_mut() {
            d.oauth = MessageField::some(persist::PersistedOauth::default());
        }
    }

    /// Session expired: Authenticated/Authenticating → Expired (keep base).
    pub fn expire(&mut self) {
        self.proto.auth_state = match self.proto.auth_state.take() {
            Some(PA::Authenticated(d)) => Some(PA::from(persist::PersistedExpired {
                base: d.base,
                ..Default::default()
            })),
            Some(PA::Authenticating(d)) => Some(PA::from(persist::PersistedExpired {
                base: d.base,
                ..Default::default()
            })),
            other => other,
        };
    }

    /// Logged out: drop session, fall back to Configured (or Unconfigured).
    pub fn logout(&mut self) {
        self.proto.auth_state = Some(match self.proto.auth_state.take() {
            None | Some(PA::Unconfigured(_)) => PA::from(persist::PersistedUnconfigured::default()),
            Some(other) => into_base(other).map_or_else(
                || PA::from(persist::PersistedUnconfigured::default()),
                |base| {
                    PA::from(persist::PersistedConfigured {
                        base,
                        ..Default::default()
                    })
                },
            ),
        });
    }

    /// Set the pending challenge (login step), promoting Configured →
    /// Authenticating if necessary.
    pub fn set_pending_challenge(&mut self, challenge: pb::PendingChallenge) {
        if let Some(PA::Authenticating(d)) = self.proto.auth_state.as_mut() {
            d.pending_challenge = MessageField::some(challenge);
        } else {
            self.proto.auth_state = match self.proto.auth_state.take() {
                Some(PA::Configured(d)) => Some(PA::from(persist::PersistedAuthenticating {
                    base: d.base,
                    pending_challenge: MessageField::some(challenge),
                    ..Default::default()
                })),
                other => other,
            };
        }
    }

    /// Login succeeded: Authenticating/Configured → Authenticated (Disconnected
    /// VPN), preserving the session credentials when present.
    pub fn complete_login(&mut self) {
        self.proto.auth_state = match self.proto.auth_state.take() {
            Some(PA::Authenticating(d)) => Some(PA::from(persist::PersistedAuthenticated {
                base: d.base,
                cookies: d.cookies,
                csrf_token: d.csrf_token,
                knock_token: d.knock_token,
                totp: d.totp,
                vpn_state: Some(PV::from(persist::PersistedVpnDisconnected::default())),
                ..Default::default()
            })),
            Some(PA::Configured(d)) => Some(PA::from(persist::PersistedAuthenticated {
                base: d.base,
                vpn_state: Some(PV::from(persist::PersistedVpnDisconnected::default())),
                ..Default::default()
            })),
            other => other,
        };
    }

    // ------- TOTP -------

    #[must_use]
    pub fn totp(&self) -> Option<&persist::PersistedTotp> {
        match self.proto.auth_state.as_ref()? {
            PA::Authenticating(d) => d.totp.as_option(),
            PA::Authenticated(d) => d.totp.as_option(),
            _ => None,
        }
    }

    #[must_use]
    pub fn needs_totp(&self) -> bool {
        matches!(self.proto.auth_state.as_ref(), Some(PA::Authenticated(d)) if d.totp.is_unset())
    }

    pub fn set_totp(&mut self, totp: persist::PersistedTotp) {
        match self.proto.auth_state.as_mut() {
            Some(PA::Authenticating(d)) => d.totp = MessageField::some(totp),
            Some(PA::Authenticated(d)) => d.totp = MessageField::some(totp),
            _ => {}
        }
    }

    // ------- VPN-state transitions (nested in Authenticated) -------

    fn vpn_state(&self) -> Option<&PV> {
        self.authenticated().and_then(|d| d.vpn_state.as_ref())
    }

    fn set_vpn(&mut self, next: PV) {
        if let Some(d) = self.authenticated_mut() {
            d.vpn_state = Some(next);
        }
    }

    fn current_vpn_request(&self) -> Option<persist::PersistedVpnRequest> {
        self.vpn_state().and_then(persisted_request)
    }

    fn vpn_attempts(&self) -> u32 {
        match self.vpn_state() {
            Some(PV::VpnReconnecting(d)) => d.reconnect_attempts,
            Some(PV::VpnFailed(d)) => d.reconnect_attempts,
            _ => 0,
        }
    }

    /// The live VPN request, if any (read as a working `VpnRequest`).
    #[must_use]
    pub fn vpn_request(&self) -> Option<VpnRequest> {
        self.current_vpn_request().map(vpn_request_from_proto)
    }

    /// True when a connect may start (no active or in-flight tunnel).
    #[must_use]
    pub fn vpn_can_connect(&self) -> bool {
        matches!(
            self.vpn_state(),
            None | Some(PV::VpnDisconnected(_) | PV::VpnFailed(_))
        )
    }

    pub fn vpn_set_connecting(&mut self, request: &VpnRequest) {
        self.set_vpn(PV::from(persist::PersistedVpnConnecting {
            request: MessageField::some(vpn_request_to_proto(request)),
            ..Default::default()
        }));
    }

    pub fn vpn_set_configuring(&mut self) {
        let request = self
            .current_vpn_request()
            .unwrap_or_else(default_request_proto);
        self.set_vpn(PV::from(persist::PersistedVpnConfiguring {
            request: MessageField::some(request),
            ..Default::default()
        }));
    }

    pub fn vpn_set_connected(&mut self, active: &ActiveTunnel) {
        let request = self
            .current_vpn_request()
            .unwrap_or_else(default_request_proto);
        self.set_vpn(PV::from(persist::PersistedVpnConnected {
            request: MessageField::some(request),
            active: MessageField::some(active_to_proto(active)),
            ..Default::default()
        }));
    }

    pub fn vpn_set_reconnecting(&mut self) {
        let request = self
            .current_vpn_request()
            .unwrap_or_else(default_request_proto);
        let attempts = self.vpn_attempts().saturating_add(1);
        self.set_vpn(PV::from(persist::PersistedVpnReconnecting {
            request: MessageField::some(request),
            reconnect_attempts: attempts,
            ..Default::default()
        }));
    }

    pub fn vpn_set_disconnecting(&mut self) {
        let request = self
            .current_vpn_request()
            .unwrap_or_else(default_request_proto);
        self.set_vpn(PV::from(persist::PersistedVpnDisconnecting {
            request: MessageField::some(request),
            ..Default::default()
        }));
    }

    pub fn vpn_set_disconnected(&mut self) {
        self.set_vpn(PV::from(persist::PersistedVpnDisconnected::default()));
    }

    pub fn vpn_set_failed(&mut self, error: String) {
        let request = self
            .current_vpn_request()
            .unwrap_or_else(default_request_proto);
        self.set_vpn(PV::from(persist::PersistedVpnFailed {
            request: MessageField::some(request),
            error,
            reconnect_attempts: 0,
            ..Default::default()
        }));
    }
}

// =========================================================================
// Free helpers
// =========================================================================

fn make_base(
    tenant: persist::PersistedTenant, signing: persist::PersistedSigning,
    login_api: Option<persist::PersistedLoginApi>,
) -> persist::PersistedConfiguredBase {
    persist::PersistedConfiguredBase {
        tenant: MessageField::some(tenant),
        signing: MessageField::some(signing),
        login_api: login_api
            .unwrap_or(persist::PersistedLoginApi::Unspecified)
            .into(),
        ..Default::default()
    }
}

fn into_base(auth: PA) -> Option<MessageField<persist::PersistedConfiguredBase>> {
    match auth {
        PA::Unconfigured(_) => None,
        PA::Configured(d) => Some(d.base),
        PA::Authenticating(d) => Some(d.base),
        PA::Authenticated(d) => Some(d.base),
        PA::Expired(d) => Some(d.base),
    }
}

fn oauth_pending_challenge(alias_key: &str, state: &str) -> pb::PendingChallenge {
    pb::PendingChallenge {
        challenge: Some(
            pb::OauthChallenge {
                alias_key: alias_key.to_string(),
                state: state.to_string(),
                poll_token: String::new(),
                ..Default::default()
            }
            .into(),
        ),
        ..Default::default()
    }
}

fn persisted_request(vpn: &PV) -> Option<persist::PersistedVpnRequest> {
    match vpn {
        PV::VpnDisconnected(_) => None,
        PV::VpnConnecting(d) => d.request.as_option().cloned(),
        PV::VpnConfiguring(d) => d.request.as_option().cloned(),
        PV::VpnConnected(d) => d.request.as_option().cloned(),
        PV::VpnReconnecting(d) => d.request.as_option().cloned(),
        PV::VpnFailed(d) => d.request.as_option().cloned(),
        PV::VpnDisconnecting(d) => d.request.as_option().cloned(),
    }
}

fn default_request_proto() -> persist::PersistedVpnRequest {
    persist::PersistedVpnRequest {
        mode: pb::VpnMode::Full.into(),
        export_id: 0,
        preferred_dot_id: None,
        otp: None,
        reconnect: true,
        protocol_mode: None,
        ..Default::default()
    }
}

fn vpn_request_to_proto(r: &VpnRequest) -> persist::PersistedVpnRequest {
    persist::PersistedVpnRequest {
        mode: vpn_mode_to_proto(r.mode).into(),
        export_id: r.export_id,
        preferred_dot_id: r.preferred_dot_id,
        otp: r.otp.clone(),
        reconnect: r.reconnect,
        protocol_mode: r.protocol_mode,
        ..Default::default()
    }
}

fn vpn_request_from_proto(p: persist::PersistedVpnRequest) -> VpnRequest {
    let mode = match p.mode.as_known() {
        Some(pb::VpnMode::Split) => VpnConnectMode::Split,
        Some(pb::VpnMode::Relay) => VpnConnectMode::Relay,
        _ => VpnConnectMode::Full,
    };
    VpnRequest {
        mode,
        export_id: p.export_id,
        preferred_dot_id: p.preferred_dot_id,
        otp: p.otp,
        reconnect: p.reconnect,
        protocol_mode: p.protocol_mode,
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

fn active_to_proto(a: &ActiveTunnel) -> persist::PersistedActiveTunnel {
    persist::PersistedActiveTunnel {
        dot_id: a.dot_id,
        dot_name: a.dot_name.clone(),
        endpoint: a.endpoint.clone(),
        assigned_ip: a.assigned_ip.clone(),
        connected_at: a.connected_at.map(proto_timestamp).into(),
        last_handshake_at: a.last_handshake_at.map(proto_timestamp).into(),
        protocol_mode: a.protocol_mode,
        ..Default::default()
    }
}

fn proto_timestamp(timestamp: Timestamp) -> buffa_types::google::protobuf::Timestamp {
    buffa_types::google::protobuf::Timestamp {
        seconds: timestamp.as_second(),
        nanos: timestamp.subsec_nanosecond(),
        ..Default::default()
    }
}
