//! Daemon core: shared state container for the three RPC services.
//!
//! The [`Daemon`] handle wraps `Arc<Mutex<DaemonInner>>` — it holds the statig
//! auth state machine, VPN state machine, daemon config, and a `watch` channel
//! for tunnel state broadcasts.  It does **not** implement any RPC service
//! trait; the three service wrappers (`AuthServiceImpl`, `VpnServiceImpl`,
//! `MetaServiceImpl`) clone the handle and delegate to the inner state.
//!
//! VPN connect/disconnect logic lives here as Daemon methods — the background
//! connect loop, supervisor, reconnect, and reporting.

use std::{collections::BTreeMap, path::PathBuf, sync::Arc};

use rustylink_api::{
    ApiClient, ClientIdentity, DotEndpoint, UserInfo, VpnConnResponse, VpnDot, VpnReportRequest,
};
use rustylink_core::vpn::{VpnConfigRequest, VpnConfigResult, VpnConnectMode};
use rustylink_proto::proto::rustylink::daemon::v1 as pb;
use rustylink_tunnel::{
    LocalTunnelParams, ReconnectController, ReconnectDecision, ReconnectEvent, ReconnectPolicy,
    TunnelConfig, TunnelSession,
};
use snafu::prelude::*;
use statig::prelude::*;
use tokio::{
    sync::{Mutex, watch},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use crate::{
    error::{DaemonError, Result, RpcFault, TunnelSnafu},
    persist::{DaemonConfig, LoginApiVersion, PersistedCredentials},
    state::{ActiveTunnel, AuthEvent, AuthMachine, State, VpnMachine, VpnRequest},
    supervisor::{self, SupervisorOutcome},
};

// ---------------------------------------------------------------------------
// DaemonInner — serialised inner state
// ---------------------------------------------------------------------------

/// The serialised inner state owned by the daemon.
pub struct DaemonInner {
    /// Statig auth state machine.
    pub(crate) auth: statig::awaitable::StateMachine<AuthMachine>,
    /// VPN state machine (present once auth is available).
    pub(crate) vpn: Option<VpnMachine>,
    /// Daemon configuration (survives logout).
    pub(crate) config: DaemonConfig,
    /// Path to `config.json`.
    pub(crate) config_path: PathBuf,
    /// Path to `credentials.json`.
    pub(crate) credential_path: PathBuf,
    /// Broadcast sender for tunnel state changes.
    pub(crate) vpn_watch_tx: watch::Sender<pb::Tunnel>,
    /// Handle to the active connect/supervise background task.
    pub(crate) tunnel_task: Option<JoinHandle<()>>,
}

// ---------------------------------------------------------------------------
// Daemon — Clone-able handle
// ---------------------------------------------------------------------------

/// Cloneable handle to the daemon core.
#[derive(Clone)]
pub struct Daemon {
    pub(crate) inner: Arc<Mutex<DaemonInner>>,
    pub(crate) vpn_watch_rx: watch::Receiver<pb::Tunnel>,
    pub(crate) started_at: tokio::time::Instant,
}

/// Parameters for a `/vpn/report` call, bundled to keep helper signatures
/// small.
#[derive(Clone)]
struct ReportParams {
    dot: VpnDot,
    assigned_ip: String,
    pub_key: String,
    mode: VpnConnectMode,
}

impl Daemon {
    /// Build the daemon core from config, paths, and optional restored
    /// credentials.
    pub fn new(
        config: DaemonConfig, config_path: PathBuf, credential_path: PathBuf,
        credentials: Option<PersistedCredentials>,
    ) -> Self {
        let identity = config.to_client_identity();
        let http_pool = reqwest::Client::new();
        let (vpn_watch_tx, vpn_watch_rx) = watch::channel(pb::Tunnel::default());

        let auth_machine = if let Some(creds) = credentials {
            AuthMachine::restore_from_credentials(creds, http_pool, identity)
        } else {
            AuthMachine {
                http_pool,
                identity,
                tenant: None,
                signing: None,
                cookies: BTreeMap::default(),
                csrf_token: None,
                knock_token: None,
                totp: None,
                login_api_version: LoginApiVersion::default(),
                oauth_pending: None,
                device_login_pending: None,
                last_error: None,
            }
        };

        // Wrap in statig state machine (lazily initialized on first handle()).
        let sm = auth_machine.state_machine();

        let inner = DaemonInner {
            auth: sm,
            vpn: None,
            config,
            config_path,
            credential_path,
            vpn_watch_tx,
            tunnel_task: None,
        };

        Self {
            inner: Arc::new(Mutex::new(inner)),
            vpn_watch_rx,
            started_at: tokio::time::Instant::now(),
        }
    }

    #[must_use]
    pub fn uptime_seconds(&self) -> i64 {
        i64::try_from(self.started_at.elapsed().as_secs()).unwrap_or(i64::MAX)
    }

    /// Subscribe to tunnel state changes (for `WatchTunnel`).
    #[must_use]
    pub fn subscribe_tunnel(&self) -> watch::Receiver<pb::Tunnel> {
        self.vpn_watch_rx.clone()
    }

    // -----------------------------------------------------------------------
    // Persistence helpers
    // -----------------------------------------------------------------------

    /// Persist current auth credentials to disk.  Only saves when in the
    /// `Authenticated` state (the machine can produce credentials).
    pub async fn persist_credentials(&self) {
        let inner = self.inner.lock().await;
        let vpn_request = inner
            .vpn
            .as_ref()
            .and_then(VpnMachine::current_persisted_request);
        if let Some(creds) = inner.auth.to_credentials_with_vpn(vpn_request) {
            let path = inner.credential_path.clone();
            drop(inner);
            if let Err(error) = creds.save(&path).await {
                tracing::warn!(%error, "failed to persist credentials");
            }
        }
    }

    /// Delete the credentials file (on logout / session expiry).
    pub async fn delete_credentials(&self) {
        let path = {
            let inner = self.inner.lock().await;
            inner.credential_path.clone()
        };
        if let Err(error) = PersistedCredentials::delete(&path).await {
            tracing::warn!(%error, "failed to delete credentials");
        }
    }

    /// Persist daemon config to disk.
    pub async fn persist_config(&self) {
        let (config, path) = {
            let inner = self.inner.lock().await;
            (inner.config.clone(), inner.config_path.clone())
        };
        if let Err(error) = config.save(&path).await {
            tracing::warn!(%error, "failed to persist config");
        }
    }

    // -----------------------------------------------------------------------
    // Auth helpers
    // -----------------------------------------------------------------------

    /// Check that the auth machine is at least configured.
    pub(crate) async fn require_configured(&self) -> Result<()> {
        let inner = self.inner.lock().await;
        match inner.auth.state() {
            State::Unconfigured {} => Err(RpcFault::NotConfigured.into()),
            _ => Ok(()),
        }
    }

    /// Check that the auth machine is authenticated.
    pub(crate) async fn require_authenticated(&self) -> Result<()> {
        let inner = self.inner.lock().await;
        match inner.auth.state() {
            State::Authenticated {} => Ok(()),
            _ => Err(RpcFault::NotAuthenticated.into()),
        }
    }

    // -----------------------------------------------------------------------
    // Tunnel connect / disconnect
    // -----------------------------------------------------------------------

    /// On startup, re-establish the tunnel if it was active and auto-reconnect
    /// is enabled.
    pub async fn maybe_auto_resume(&self) {
        let request = {
            let inner = self.inner.lock().await;
            if !inner.config.auto_reconnect {
                return;
            }
            // Restore from the credentials' last_vpn_request.
            let Some(creds) = inner.auth.to_credentials() else {
                return;
            };
            drop(inner);
            match creds.last_vpn_request {
                Some(persisted) => VpnRequest {
                    mode: persisted.mode.parse().unwrap_or(VpnConnectMode::Full),
                    export_id: persisted.export_id,
                    preferred_dot_id: persisted.preferred_dot_id,
                    otp: None,
                    reconnect: persisted.reconnect,
                },
                None => return,
            }
        };
        tracing::info!("auto-resuming tunnel from persisted request");
        if let Err(error) = self.connect_tunnel(request).await {
            tracing::warn!(%error, "auto-resume failed");
        }
    }

    /// Start a tunnel connection.  Returns immediately with `CONNECTING`; the
    /// connect + supervise flow runs in a background task.
    pub async fn connect_tunnel(&self, request: VpnRequest) -> Result<pb::Tunnel> {
        let mut inner = self.inner.lock().await;
        if !matches!(inner.auth.state(), State::Authenticated {}) {
            return Err(RpcFault::NotAuthenticated.into());
        }

        // Ensure a VpnMachine exists — build the client before calling
        // get_or_insert to avoid a shared/mutable borrow conflict.
        if inner.vpn.is_none() {
            let client = inner
                .auth
                .build_tenant_client()
                .ok_or_else(|| DaemonError::from(RpcFault::NotAuthenticated))?;
            inner.vpn = Some(VpnMachine::new(client));
        }

        {
            let vpn = inner.vpn.as_ref().unwrap();
            if !vpn.can_connect() {
                return Err(RpcFault::InvalidArgument {
                    message: "tunnel is already connecting or connected; disconnect first"
                        .to_owned(),
                }
                .into());
            }
        }

        // Refresh the VPN machine's API client with current auth state.
        if let Some(client) = inner.auth.build_tenant_client() {
            inner.vpn.as_mut().unwrap().api_client = client;
        }

        let vpn = inner.vpn.as_mut().unwrap();
        vpn.set_connecting(request.clone());
        let tunnel = vpn.to_tunnel_proto();
        let cancel = vpn.cancel_token.clone();
        let _ = inner.vpn_watch_tx.send(tunnel.clone());

        // Spawn the connect/supervise loop.
        let daemon = self.clone();
        let handle = tokio::spawn(async move {
            daemon.run_connect_loop(request, cancel).await;
        });
        inner.tunnel_task = Some(handle);
        drop(inner);
        Ok(tunnel)
    }

    /// Disconnect the tunnel: cancel the supervise task (which tears down the
    /// session + reports 101) and reset VPN state.
    pub async fn disconnect_tunnel(&self) -> Result<pb::Tunnel> {
        let task = {
            let mut inner = self.inner.lock().await;
            if let Some(vpn) = &mut inner.vpn {
                vpn.set_disconnecting();
                vpn.cancel_token.cancel();
                let tunnel = vpn.to_tunnel_proto();
                let _ = inner.vpn_watch_tx.send(tunnel);
            }
            inner.tunnel_task.take()
        };
        if let Some(task) = task {
            let _ = task.await;
        }
        let mut inner = self.inner.lock().await;
        if let Some(vpn) = &mut inner.vpn {
            vpn.set_disconnected();
            let tunnel = vpn.to_tunnel_proto();
            let _ = inner.vpn_watch_tx.send(tunnel);
        }
        let tunnel = inner
            .vpn
            .as_ref()
            .map_or_else(pb::Tunnel::default, VpnMachine::to_tunnel_proto);
        drop(inner);
        Ok(tunnel)
    }

    // -----------------------------------------------------------------------
    // Connect/supervise background loop + helpers
    // -----------------------------------------------------------------------

    async fn run_connect_loop(self, request: VpnRequest, cancel: CancellationToken) {
        let mut controller =
            ReconnectController::new(ReconnectPolicy::android_compatible_default());
        loop {
            match self.connect_once(&request, &cancel).await {
                Ok(SupervisorOutcome::Cancelled) => {
                    self.mark_disconnected().await;
                    return;
                }
                Ok(SupervisorOutcome::ServerKickOut) => {
                    let decision = controller.record(ReconnectEvent::ServerKickOut);
                    if !self.handle_decision(decision, &cancel).await {
                        return;
                    }
                }
                Ok(SupervisorOutcome::Trigger(event)) => {
                    let decision = controller.record(event);
                    if !self.handle_decision(decision, &cancel).await {
                        return;
                    }
                }
                Err(error) => {
                    tracing::warn!(%error, "tunnel connect attempt failed");
                    self.mark_failed(error.to_string()).await;
                    if cancel.is_cancelled() {
                        return;
                    }
                    let decision = controller.record(ReconnectEvent::TransportFailed);
                    if !self.handle_decision(decision, &cancel).await {
                        return;
                    }
                }
            }
        }
    }

    /// Perform a single connect attempt and supervise it until a trigger or
    /// cancellation.  Tears down the session and reports 101 before returning.
    async fn connect_once(
        &self, request: &VpnRequest, cancel: &CancellationToken,
    ) -> Result<SupervisorOutcome> {
        self.vpn_transition(VpnMachine::set_configuring).await;

        let client = {
            let inner = self.inner.lock().await;
            inner
                .auth
                .build_tenant_client()
                .ok_or_else(|| DaemonError::from(RpcFault::NotAuthenticated))?
        };
        let local_params = LocalTunnelParams::generate();
        let otp = self.compute_otp(request.otp.clone()).await;

        let config_request = VpnConfigRequest {
            mode: request.mode,
            public_key: local_params.local_public_key.clone(),
            export_id: request.export_id,
            otp,
            sign_token: None,
            not_auto: true,
            reconnect: request.reconnect,
            preferred_dot_id: request.preferred_dot_id,
        };

        let build_dot_client = {
            let inner = self.inner.lock().await;
            let hooks = inner.auth.build_hooks();
            let pool = inner.auth.http_pool.clone();
            drop(inner);
            move |endpoint: &DotEndpoint| {
                ApiClient::for_endpoint(endpoint, pool.clone(), hooks.clone())
            }
        };

        let config_result = rustylink_core::vpn::vpn_config_from_dot_list(
            &client,
            &config_request,
            build_dot_client,
        )
        .await
        .map_err(DaemonError::from)?;

        // Merge response meta (cookies) via event dispatch.
        {
            let event = AuthEvent::MergeResponseMeta {
                cookies: config_result
                    .meta
                    .cookies
                    .as_ref()
                    .map(|c| c.values.clone())
                    .unwrap_or_default(),
                csrf_token: config_result.meta.csrf_token.clone(),
            };
            let mut inner = self.inner.lock().await;
            inner.auth.handle(&event).await;
            drop(inner);
        }

        let data = config_result.response.data.clone().context(TunnelSnafu {
            message: "/vpn/conn returned no data",
        })?;

        let mut session = self
            .start_session(&config_result, &data, &local_params)
            .await?;

        self.mark_connected(&config_result, &data.ip).await;

        let report = ReportParams {
            dot: config_result.dot.clone(),
            assigned_ip: data.ip.clone(),
            pub_key: local_params.local_public_key.clone(),
            mode: request.mode,
        };

        // report(100) — connected.
        let _ = self.send_report(&client, &report, 100).await;

        // Supervise until a trigger / cancellation.
        let outcome = self.supervise(&mut session, &client, &report, cancel).await;

        // Teardown: stop the device + report(101).
        let _ = session.stop().await;
        let _ = self.send_report(&client, &report, 101).await;
        Ok(outcome)
    }

    /// Build the tunnel config from a `/vpn/conn` result and bring the device
    /// up.
    async fn start_session(
        &self, config_result: &VpnConfigResult, data: &VpnConnResponse,
        local_params: &LocalTunnelParams,
    ) -> Result<TunnelSession> {
        let outbound_iface = {
            let inner = self.inner.lock().await;
            inner.config.outbound_interface.clone()
        };

        let mut tunnel_config = TunnelConfig::from_vpn_conn(
            data,
            local_params.clone(),
            config_result.endpoint.wireguard_endpoint.clone(),
            config_result.dot.protocol_mode,
            config_result.dot.protocol_detect_enabled(),
        )
        .map_err(|error| {
            TunnelSnafu {
                message: format!("failed to build tunnel config: {error}"),
            }
            .build()
        })?;
        tunnel_config.outbound_interface = outbound_iface;

        let mut session = TunnelSession::new(tunnel_config);
        session.start().await.map_err(|error| {
            TunnelSnafu {
                message: format!("failed to start tunnel: {error}"),
            }
            .build()
        })?;
        Ok(session)
    }

    /// Record the connected tunnel in `VpnMachine`.
    async fn mark_connected(&self, config_result: &VpnConfigResult, assigned_ip: &str) {
        let dot = &config_result.dot;
        let active = ActiveTunnel {
            dot_id: dot.id.unwrap_or_default(),
            dot_name: dot.name.clone().unwrap_or_default(),
            endpoint: config_result.endpoint.wireguard_endpoint.to_string(),
            assigned_ip: assigned_ip.to_string(),
        };
        self.vpn_transition(move |vpn| vpn.set_connected(active))
            .await;
        self.persist_credentials().await;
    }

    /// Run the supervisor over a live session with a periodic `/vpn/report`.
    async fn supervise(
        &self, session: &mut TunnelSession, client: &ApiClient, report: &ReportParams,
        cancel: &CancellationToken,
    ) -> SupervisorOutcome {
        let outbound = {
            let inner = self.inner.lock().await;
            inner.config.outbound_interface.clone()
        };
        let protocol_mode = report.dot.protocol_mode;
        let report_daemon = self.clone();
        let report_client = client.clone();
        let report = report.clone();
        supervisor::run(
            session,
            protocol_mode,
            outbound,
            cancel.clone(),
            move || {
                let daemon = report_daemon.clone();
                let client = report_client.clone();
                let report = report.clone();
                async move { daemon.send_report(&client, &report, 100).await }
            },
        )
        .await
    }

    /// Send a `/vpn/report` (type 100 keepalive / 101 disconnect).  Returns
    /// `true` if the server signalled a force-logout (kickout).
    async fn send_report(
        &self, client: &ApiClient, report: &ReportParams, report_type: i32,
    ) -> bool {
        let request = VpnReportRequest {
            r#type: report_type.to_string(),
            ip: report.assigned_ip.clone(),
            public_key: report.pub_key.clone(),
            mode: report.mode.android_name(),
        };
        match rustylink_core::vpn::report_vpn(client, &request).await {
            Ok((response, meta)) => {
                {
                    let event = AuthEvent::MergeResponseMeta {
                        cookies: meta
                            .cookies
                            .as_ref()
                            .map(|c| c.values.clone())
                            .unwrap_or_default(),
                        csrf_token: meta.csrf_token.clone(),
                    };
                    let mut inner = self.inner.lock().await;
                    inner.auth.handle(&event).await;
                    drop(inner);
                }
                response.is_force_logout()
            }
            Err(error) => {
                tracing::warn!(%error, report_type, "vpn report failed (non-fatal)");
                false
            }
        }
    }

    /// Compute the OTP for `/vpn/conn`: a manual code if supplied, else a fresh
    /// TOTP derived from the stored secret.
    async fn compute_otp(&self, manual: Option<String>) -> Option<String> {
        if let Some(code) = manual {
            return Some(code);
        }
        let config = {
            let inner = self.inner.lock().await;
            inner.auth.totp.clone()?
        };
        let now = jiff::Timestamp::now().as_second();
        let totp_config = rustylink_core::vpn::TotpConfig {
            url: config.url,
            time_diff_seconds: config.time_diff_seconds,
        };
        rustylink_core::vpn::generate_totp(&totp_config, now)
    }

    /// Apply a reconnect decision: sleep (interruptibly) and continue, or stop.
    /// Returns `true` to continue the connect loop, `false` to terminate.
    async fn handle_decision(
        &self, decision: ReconnectDecision, cancel: &CancellationToken,
    ) -> bool {
        match decision {
            ReconnectDecision::Retry { after, .. }
            | ReconnectDecision::SwitchNode { after, .. } => {
                self.vpn_transition(VpnMachine::set_reconnecting).await;
                tokio::select! {
                    () = cancel.cancelled() => {
                        self.mark_disconnected().await;
                        false
                    }
                    () = tokio::time::sleep(after) => true,
                }
            }
            ReconnectDecision::Stop => {
                self.mark_failed("maximum reconnect attempts exceeded".to_string())
                    .await;
                false
            }
        }
    }

    async fn mark_disconnected(&self) {
        self.vpn_transition(VpnMachine::set_disconnected).await;
    }

    async fn mark_failed(&self, error: String) {
        self.vpn_transition(move |vpn| vpn.set_failed(error)).await;
    }

    /// Mutate the VPN machine via a transition method, then broadcast.
    async fn vpn_transition(&self, f: impl FnOnce(&mut VpnMachine)) {
        let mut inner = self.inner.lock().await;
        if let Some(vpn) = &mut inner.vpn {
            f(vpn);
            let tunnel = vpn.to_tunnel_proto();
            let _ = inner.vpn_watch_tx.send(tunnel);
        }
    }
}

// ---------------------------------------------------------------------------
// DaemonConfig → ClientIdentity conversion
// ---------------------------------------------------------------------------

impl DaemonConfig {
    /// Build a [`ClientIdentity`] from the daemon config, using the built-in
    /// default for any field not overridden.
    #[must_use]
    pub fn to_client_identity(&self) -> ClientIdentity {
        let default = ClientIdentity::default();
        ClientIdentity {
            device_id: self.identity.device_id.clone(),
            os: self.identity.os.clone().unwrap_or(default.os),
            os_version: self
                .identity
                .os_version
                .clone()
                .unwrap_or(default.os_version),
            app_version: self
                .identity
                .app_version
                .clone()
                .unwrap_or(default.app_version),
            brand: self.identity.brand.clone().unwrap_or(default.brand),
            model: self.identity.model.clone().unwrap_or(default.model),
            ..default
        }
    }

    /// Project to the RPC [`Configuration`](pb::Configuration) message.
    #[must_use]
    pub fn to_configuration_proto(&self) -> pb::Configuration {
        let outbound = self.outbound_interface.as_ref().map_or_else(
            || pb::OutboundInterface {
                selector: Some(pb::outbound_interface::Selector::Auto(Box::default())),
                ..Default::default()
            },
            |name| pb::OutboundInterface {
                selector: Some(pb::outbound_interface::Selector::Name(name.clone())),
                ..Default::default()
            },
        );
        let dns = self.dns_interface.as_ref().map_or_else(
            || pb::OutboundInterface {
                selector: Some(pb::outbound_interface::Selector::Auto(Box::default())),
                ..Default::default()
            },
            |name| pb::OutboundInterface {
                selector: Some(pb::outbound_interface::Selector::Name(name.clone())),
                ..Default::default()
            },
        );
        pb::Configuration {
            outbound_interface: outbound.into(),
            dns_interface: dns.into(),
            auto_reconnect_on_start: self.auto_reconnect,
            ..Default::default()
        }
    }
}

// ---------------------------------------------------------------------------
// Projection helpers (shared across services)
// ---------------------------------------------------------------------------

/// Project a core [`UserInfo`] to the wire type.
pub fn project_user_info(user: Option<UserInfo>) -> pb::UserInfo {
    let user = user.unwrap_or_default();
    pb::UserInfo {
        uid: user.uid.unwrap_or_default(),
        name: user.name.unwrap_or_default(),
        email: user.email.unwrap_or_default(),
        mobile: user.mobile.unwrap_or_default(),
        ..Default::default()
    }
}

/// Project a core [`VpnDot`] to the wire type.
pub fn project_vpn_location(dot: VpnDot) -> pb::VpnLocation {
    pb::VpnLocation {
        id: dot.id.unwrap_or_default(),
        name: dot.name.clone().unwrap_or_default(),
        display_name: dot.name.unwrap_or_default(),
        mode: mode_from_dot(dot.mode).into(),
        delay_ms: 0,
        ..Default::default()
    }
}

fn mode_from_dot(mode: Option<i32>) -> pb::VpnMode {
    match mode {
        Some(0) => pb::VpnMode::Full,
        Some(1) => pb::VpnMode::Split,
        Some(2) => pb::VpnMode::Relay,
        _ => pb::VpnMode::Unspecified,
    }
}

/// Return `value` if non-empty, otherwise the `default`.
pub fn nonempty_or(value: &str, default: &str) -> String {
    if value.is_empty() {
        default.to_string()
    } else {
        value.to_string()
    }
}
