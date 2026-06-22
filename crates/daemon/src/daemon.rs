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

use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

use rustylink_api::{
    ApiClient, ApiHooks, ClientIdentity, DotEndpoint, UserInfo, VpnConnResponse, VpnDot,
    VpnReportRequest, VpnReportType,
};
use rustylink_core::vpn::{VpnConfigRequest, VpnConfigResult, VpnConnectMode};
use rustylink_proto::proto::rustylink::daemon::v1 as pb;
use rustylink_tunnel::{
    LocalTunnelParams, OutboundInterface, ProtocolMode, ReconnectController, ReconnectDecision,
    ReconnectEvent, ReconnectPolicy, TunnelConfig, TunnelSession,
};
use snafu::prelude::*;
use statig::prelude::*;
use tokio::{
    sync::{Mutex, watch},
    task::JoinHandle,
    time::Instant,
};
use tokio_util::sync::CancellationToken;

use crate::{
    error::{DaemonError, Result, RpcFault, TunnelSnafu},
    persist::{DaemonConfig, LoginApiVersion, PersistedCredentials},
    state::{ActiveTunnel, AuthEvent, AuthMachine, State, VpnMachine, VpnRequest},
    supervisor::{self, SupervisorOutcome},
};

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
                cookies: rustylink_api::CookieStore::empty(),
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

    /// Resolve the picked outbound interface (the configured one, or the
    /// system default) used to bind tunnel and latency-probe sockets.
    ///
    /// Returns `None` when no usable interface is found, in which case sockets
    /// use the OS default routing.
    pub(crate) async fn resolve_outbound_interface(&self) -> Option<OutboundInterface> {
        let configured = {
            let inner = self.inner.lock().await;
            inner.config.outbound_interface.clone()
        };
        OutboundInterface::resolve(configured.as_deref(), None)
            .ok()
            .flatten()
    }

    /// Persist current auth credentials to disk.  Only saves an authenticated
    /// session (the machine can produce a complete, restorable snapshot).
    pub async fn persist_credentials(&self) {
        let inner = self.inner.lock().await;
        if !matches!(inner.auth.state(), State::Authenticated {}) {
            return;
        }
        let vpn_request = inner
            .vpn
            .as_ref()
            .and_then(VpnMachine::current_persisted_request);
        if let Some(creds) = inner.auth.to_credentials_with_vpn(vpn_request).await {
            let path = inner.credential_path.clone();
            drop(inner);
            if let Err(error) = creds.save(&path).await {
                tracing::warn!(%error, "failed to persist credentials");
            }
        }
    }

    /// Install a hook so the shared cookie jar persists the session whenever it
    /// absorbs a change (e.g. a refreshed `vpn-token`), without an explicit
    /// save call. Persistence is deferred to a task so it never re-enters a
    /// held lock.
    pub async fn install_cookie_persist_listener(&self) {
        let jar = {
            let inner = self.inner.lock().await;
            inner.auth.cookies.clone()
        };
        let daemon = self.clone();
        jar.set_listener(Arc::new(move || {
            let daemon = daemon.clone();
            tokio::spawn(async move {
                daemon.persist_credentials().await;
            });
        }));
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

    /// Restore the auth session state from credentials loaded at startup.
    ///
    /// Must be called once after construction: the statig machine always starts
    /// in `Unconfigured`, so without this a previously-authenticated session
    /// (restored from `credentials.json`) would not be recognised and the UI
    /// would prompt for login again (notably after `--rotate-token`).
    pub async fn restore_auth_state(&self) {
        let mut inner = self.inner.lock().await;
        inner.auth.handle(&AuthEvent::RestoreSession).await;
        drop(inner);
    }

    /// On startup, re-establish the tunnel if it was active and auto-reconnect
    /// is enabled.
    pub async fn maybe_auto_resume(&self) {
        let request = {
            let inner = self.inner.lock().await;
            if !inner.config.auto_reconnect {
                return;
            }
            // Restore from the credentials' last_vpn_request.
            let Some(creds) = inner.auth.to_credentials().await else {
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

    async fn run_connect_loop(self, request: VpnRequest, cancel: CancellationToken) {
        let mut controller =
            ReconnectController::new(ReconnectPolicy::android_compatible_default());
        let mut forced_protocol = None;
        let mut last_udp_to_tcp = None;
        loop {
            match self
                .connect_once(&request, &cancel, forced_protocol, last_udp_to_tcp)
                .await
            {
                Ok(SupervisorOutcome::Cancelled) => {
                    self.mark_disconnected().await;
                    return;
                }
                Ok(SupervisorOutcome::ProtocolSwitch(protocol)) => {
                    tracing::info!(protocol = ?protocol, "protocol detection requested transport switch");
                    if protocol == ProtocolMode::FeilianTcp {
                        last_udp_to_tcp = Some(Instant::now());
                    }
                    forced_protocol = Some(protocol);
                    controller.reset();
                    if cancel.is_cancelled() {
                        return;
                    }
                }
                Ok(SupervisorOutcome::ServerKickOut) => {
                    let decision = controller.record(ReconnectEvent::ServerKickOut);
                    if !self.handle_decision(decision, &cancel).await {
                        return;
                    }
                }
                Ok(SupervisorOutcome::Trigger(event)) => {
                    if event == ReconnectEvent::NetworkChanged {
                        forced_protocol = None;
                        last_udp_to_tcp = None;
                    }
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
        forced_protocol: Option<ProtocolMode>, last_udp_to_tcp: Option<Instant>,
    ) -> Result<SupervisorOutcome> {
        self.vpn_transition(VpnMachine::set_configuring).await;

        let client = {
            let inner = self.inner.lock().await;
            inner
                .auth
                .build_tenant_client()
                .ok_or_else(|| DaemonError::from(RpcFault::NotAuthenticated))?
        };

        // Dots are reached by IP but present a TLS cert valid for the tenant's
        // `vpn_domain`; fetch it so the dot config client validates the cert
        // against the right name (matching the Android client) rather than the
        // IP we dial.
        let vpn_domain = rustylink_core::vpn::vpn_setting(&client)
            .await
            .ok()
            .and_then(|(resp, _meta)| resp.data)
            .and_then(|setting| setting.vpn_domain)
            .filter(|domain| !domain.trim().is_empty());

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
            let vpn_domain = vpn_domain.clone();
            move |endpoint: &DotEndpoint| {
                build_dot_api_client(endpoint, &pool, &hooks, vpn_domain.as_deref())
            }
        };

        // Auto dot selection probes through the picked outbound interface.
        let outbound = self.resolve_outbound_interface().await;
        let config_result = rustylink_core::vpn::vpn_config_from_dot_list(
            &client,
            &config_request,
            build_dot_client,
            move |dots| crate::latency::rank_dots_by_latency(dots, outbound),
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
            .start_session(&config_result, &data, &local_params, forced_protocol)
            .await?;

        self.mark_connected(&config_result, &data.ip).await;

        let report = ReportParams {
            dot: config_result.dot.clone(),
            assigned_ip: data.ip.clone(),
            pub_key: local_params.local_public_key.clone(),
            mode: request.mode,
        };

        // report(100) — connected.
        let _ = self
            .send_report(&client, &report, VpnReportType::Connected)
            .await;

        // Supervise until a trigger / cancellation.
        let outcome = self
            .supervise(&mut session, &client, &report, cancel, last_udp_to_tcp)
            .await;

        // Teardown: stop the device + report(101).
        let _ = session.stop().await;
        let _ = self
            .send_report(&client, &report, VpnReportType::Disconnected)
            .await;
        Ok(outcome)
    }

    /// Build the tunnel config from a `/vpn/conn` result and bring the device
    /// up.
    async fn start_session(
        &self, config_result: &VpnConfigResult, data: &VpnConnResponse,
        local_params: &LocalTunnelParams, forced_protocol: Option<ProtocolMode>,
    ) -> Result<TunnelSession> {
        let (outbound_iface, tun_interface) = {
            let inner = self.inner.lock().await;
            (
                inner.config.outbound_interface.clone(),
                inner.config.tun_interface.clone(),
            )
        };

        let effective_protocol_mode = forced_protocol
            .filter(|protocol| {
                match (
                    config_result
                        .dot
                        .protocol_mode
                        .and_then(ProtocolMode::from_repr),
                    *protocol,
                ) {
                    (Some(ProtocolMode::Dual), ProtocolMode::Udp | ProtocolMode::FeilianTcp)
                    | (None, ProtocolMode::Udp) => true,
                    (Some(dot_protocol), requested) => dot_protocol == requested,
                    _ => false,
                }
            })
            .map(|protocol| protocol as i32)
            .or(config_result.dot.protocol_mode);
        if let Some(protocol) = forced_protocol
            && Some(protocol as i32) == effective_protocol_mode
        {
            tracing::info!(
                protocol = ?protocol,
                dot_protocol_mode = ?config_result.dot.protocol_mode,
                "forcing tunnel transport after protocol-detect switch"
            );
        }

        let mut tunnel_config = TunnelConfig::from_vpn_conn(
            data,
            local_params.clone(),
            config_result.endpoint.wireguard_endpoint.clone(),
            effective_protocol_mode,
            config_result.dot.protocol_detect_enabled(),
        )
        .map_err(|error| {
            TunnelSnafu {
                message: format!("failed to build tunnel config: {error}"),
            }
            .build()
        })?;
        tunnel_config.outbound_interface = outbound_iface;
        // Override the default TUN device name when one is configured.
        if let Some(name) = tun_interface.filter(|name| !name.trim().is_empty()) {
            tunnel_config.interface_name = name;
        }

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
        cancel: &CancellationToken, last_udp_to_tcp: Option<Instant>,
    ) -> SupervisorOutcome {
        let outbound = {
            let inner = self.inner.lock().await;
            inner.config.outbound_interface.clone()
        };
        let protocol_mode = report.dot.protocol_mode.and_then(ProtocolMode::from_repr);
        let runtime_protocol_mode = session
            .config
            .protocol_mode
            .and_then(ProtocolMode::from_repr);
        let protocol_detect_options = supervisor::ProtocolDetectOptions {
            config: report.dot.protocol_detect_config.clone(),
            dot_protocol_mode: protocol_mode,
            last_udp_to_tcp,
        };
        let report_daemon = self.clone();
        let report_client = client.clone();
        let report = report.clone();
        supervisor::run(
            session,
            runtime_protocol_mode,
            outbound,
            protocol_detect_options,
            cancel.clone(),
            move || {
                let daemon = report_daemon.clone();
                let client = report_client.clone();
                let report = report.clone();
                async move {
                    daemon
                        .send_report(&client, &report, VpnReportType::Connected)
                        .await
                }
            },
        )
        .await
    }

    /// Send a `/vpn/report` (`Connected` keepalive / `Disconnected`).  Returns
    /// `true` if the server signalled a force-logout (kickout).
    async fn send_report(
        &self, client: &ApiClient, report: &ReportParams, report_type: VpnReportType,
    ) -> bool {
        let request = VpnReportRequest {
            r#type: report_type.wire(),
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
                tracing::warn!(%error, ?report_type, "vpn report failed (non-fatal)");
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

impl DaemonConfig {
    /// Build a [`ClientIdentity`] from the daemon config.
    ///
    /// The persisted identity is completed via
    /// [`DeviceIdentityConfig::ensure_full`](crate::persist::DeviceIdentityConfig::ensure_full)
    /// on startup; this still falls back to the built-in default per field for
    /// robustness (e.g. configs loaded without that step).
    #[must_use]
    pub fn to_client_identity(&self) -> ClientIdentity {
        let default = ClientIdentity::default();
        let id = &self.identity;
        let or_default = |value: &Option<String>, fallback: String| {
            value
                .clone()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or(fallback)
        };
        ClientIdentity {
            device_id: if id.device_id.trim().is_empty() {
                default.device_id
            } else {
                id.device_id.clone()
            },
            os: or_default(&id.os, default.os),
            os_version: or_default(&id.os_version, default.os_version),
            app_version: or_default(&id.app_version, default.app_version),
            brand: or_default(&id.brand, default.brand),
            model: or_default(&id.model, default.model),
            build_number: or_default(&id.build_number, default.build_number),
            os_version_patch: or_default(&id.os_version_patch, default.os_version_patch),
            client_source: or_default(&id.client_source, default.client_source),
            language: or_default(&id.language, default.language),
            user_agent: or_default(&id.user_agent, default.user_agent),
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
            tun_interface: self.tun_interface.clone(),
            ..Default::default()
        }
    }
}

/// Build the API client for a dot's config call.
///
/// A dot is reached by IP, but its TLS certificate is issued for the tenant's
/// `vpn_domain`. To keep full certificate-chain validation (no `unsafe`, no
/// disabled verification) while matching the Android client — which validates
/// the cert against `vpn_domain`, not the dialed IP — we address the request to
/// `https://{vpn_domain}:{port}` and override DNS so that name resolves to the
/// dot's IP. rustls then validates the chain and the name against `vpn_domain`.
///
/// Falls back to a plain client against the original (IP) endpoint when no
/// `vpn_domain` is known or the host is not a bare IP.
fn build_dot_api_client(
    endpoint: &DotEndpoint, pool: &reqwest::Client, hooks: &ApiHooks, vpn_domain: Option<&str>,
) -> ApiClient {
    if let Some(domain) = vpn_domain
        && let Some(host) = endpoint.api_base_url.host_str()
        && let Ok(ip) = host.parse::<IpAddr>()
        && let Some(port) = endpoint.api_base_url.port_or_known_default()
    {
        let tls_host = tls_host_for(domain);
        if let Ok(tls_url) = url::Url::parse(&format!("https://{tls_host}:{port}"))
            && let Ok(client) = reqwest::Client::builder()
                .resolve(&tls_host, SocketAddr::new(ip, port))
                .build()
        {
            let tls_endpoint = DotEndpoint {
                api_base_url: tls_url,
                wireguard_endpoint: endpoint.wireguard_endpoint.clone(),
            };
            return ApiClient::for_endpoint(&tls_endpoint, client, hooks.clone());
        }
    }
    ApiClient::for_endpoint(endpoint, pool.clone(), hooks.clone())
}

/// A concrete hostname for TLS validation, derived from the tenant's
/// `vpn_domain`.
///
/// `vpn_domain` is often a wildcard (e.g. `*.msh.team`) which can't be used as
/// a URL host / SNI. The leading `*` label is replaced with a concrete label
/// that still validates against the wildcard certificate (a wildcard matches
/// any single leftmost label). Concrete domains are used unchanged.
fn tls_host_for(vpn_domain: &str) -> String {
    vpn_domain
        .strip_prefix("*.")
        .map_or_else(|| vpn_domain.to_owned(), |rest| format!("vpn.{rest}"))
}

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
    match mode.and_then(VpnConnectMode::from_repr) {
        Some(VpnConnectMode::Full) => pb::VpnMode::Full,
        Some(VpnConnectMode::Split) => pb::VpnMode::Split,
        Some(VpnConnectMode::Relay) => pb::VpnMode::Relay,
        None => pb::VpnMode::Unspecified,
    }
}

/// Use a value unless it equals its type's [`Default`].
///
/// A small extension trait that replaces ad-hoc `nonempty_or`-style helpers.
/// For `&str`/`String` the default is empty, so `value.non_default_or(other)`
/// yields `other` only when `value` is empty.
pub trait DefaultOrExt: Default + PartialEq + Sized {
    /// Return `self` when it differs from the type default, else `fallback`.
    #[must_use]
    fn non_default_or(self, fallback: Self) -> Self {
        if self == Self::default() {
            fallback
        } else {
            self
        }
    }
}

impl<T: Default + PartialEq> DefaultOrExt for T {}

#[cfg(test)]
mod tests {
    use super::DefaultOrExt;

    #[test]
    fn non_default_or_falls_back_only_on_default() {
        assert_eq!("".non_default_or("login"), "login");
        assert_eq!("scan".non_default_or("login"), "scan");
        assert_eq!(0_i32.non_default_or(7), 7);
        assert_eq!(3_i32.non_default_or(7), 3);
    }

    /// Live, network + real-credentials check (run with
    /// `cargo test -p rustylinkd -- --ignored --nocapture live_dot_connect`).
    /// Loads the on-disk session, fetches the dot list, and exercises the dot
    /// config TLS path — proving the cert validates against `vpn_domain` rather
    /// than failing `NotValidForName` on the dialed IP.
    #[tokio::test]
    #[ignore = "requires network and an authenticated credentials.json"]
    async fn live_dot_connect() {
        use rustylink_api::{ClientIdentity, SendableRequest as _, VpnConnRequest};

        use crate::{
            daemon::build_dot_api_client, persist::PersistedCredentials, state::AuthMachine,
        };

        let path = dirs::config_dir()
            .expect("config dir")
            .join("rustylink")
            .join("credentials.json");
        let creds = PersistedCredentials::load(&path)
            .await
            .expect("read creds")
            .expect("credentials.json present");

        let pool = reqwest::Client::new();
        let machine =
            AuthMachine::restore_from_credentials(creds, pool.clone(), ClientIdentity::default());
        let client = machine.build_tenant_client().expect("tenant client");
        // The tenant client and every dot client share this machine's live
        // cookie jar, so Set-Cookie mutations propagate automatically.
        let hooks = machine.build_hooks();
        let snapshot = |label: &str, jar: rustylink_api::SessionCookies| {
            eprintln!("{label}: {:?}", jar.values.keys().collect::<Vec<_>>());
        };
        snapshot("initial cookies", hooks.cookies.snapshot().await);

        // Authenticated tenant APIs — confirm the session is valid; the shared
        // jar absorbs any Set-Cookie mutations (e.g. open-time, vpn-token).
        let (setting, _) = rustylink_core::vpn::vpn_setting(&client)
            .await
            .expect("vpn setting");
        snapshot("after /api/setting", hooks.cookies.snapshot().await);
        let vpn_domain = setting.data.and_then(|s| s.vpn_domain);
        eprintln!("vpn_domain = {vpn_domain:?}");

        let (locations, _) = rustylink_core::vpn::vpn_locations(&client)
            .await
            .expect("vpn locations");
        snapshot("after /api/vpn/list", hooks.cookies.snapshot().await);
        let dots = locations.data.unwrap_or_default();
        eprintln!("dots = {}", dots.len());

        // With the device_id cookie now sent on every request, /api/vpn/list
        // re-issues a device-bound `vpn-token` (non-empty `did`), so /vpn/conn
        // returns the WireGuard config (code 0) instead of "session expired".
        let mut any_ok = false;
        for dot in dots.iter().take(2) {
            let use_vpn_ip = dot.should_use_vpn_ip_for_config_api(false);
            let Ok(endpoint) = rustylink_api::DotEndpoint::from_dot(dot, use_vpn_ip) else {
                continue;
            };
            let dot_client = build_dot_api_client(&endpoint, &pool, &hooks, vpn_domain.as_deref());
            let body = VpnConnRequest {
                mode: Some("Full".to_owned()),
                public_key: rustylink_tunnel::LocalTunnelParams::generate().local_public_key,
                otp: None,
                export_id: dot.id.unwrap_or_default(),
                sign_token: None,
                not_auto: Some(true),
            };
            match body.send_with_meta(&dot_client).await {
                Ok((resp, _)) => {
                    eprintln!("dot {:?}: /vpn/conn code={}", dot.id, resp.code);
                    any_ok |= resp.code == 0;
                }
                Err(error) => eprintln!("dot {:?}: /vpn/conn err = {error}", dot.id),
            }
        }
        assert!(any_ok, "no dot returned a successful /vpn/conn");
    }
}
