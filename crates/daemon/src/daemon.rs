//! Daemon core: shared state container for the three RPC services.
//!
//! The [`Daemon`] handle wraps `Arc<Mutex<DaemonInner>>` — it holds the auth
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
    ApiClient, ApiHooks, ClientIdentity, DotEndpoint, GetVpnSettingRequest, ProtocolMode,
    SendableRequest as _, UserInfo, VpnConnResponse, VpnDot, VpnReportRequest, VpnReportType,
};
use rustylink_core::vpn::{VpnConfigRequest, VpnConfigResult, VpnConnectMode};
use rustylink_proto::proto::rustylink::daemon::v1 as pb;
use rustylink_tunnel::{
    LocalTunnelParams, ReconnectController, ReconnectDecision, ReconnectEvent, ReconnectPolicy,
    TunnelConfig, TunnelSession, VpnRouteMode,
};
use snafu::prelude::*;
use tokio::{
    sync::{Mutex, watch},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use crate::{
    error::{DaemonError, Result, RpcFault, TunnelSnafu},
    persist::{DaemonConfig, LoginApiVersion, PersistedCredentials},
    state::{ActiveTunnel, AuthMachine, AuthState, VpnMachine, VpnRequest},
    supervisor::{self, SupervisorOutcome},
};

/// The serialised inner state owned by the daemon.
pub struct DaemonInner {
    /// Auth coordinator (pure state + runtime resources).
    pub(crate) auth: AuthMachine,
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
    /// The outbound interface that was active when the current tunnel session
    /// started.  Compared against `config.outbound_interface` to detect
    /// mid-session config changes that require a reconnect.
    pub(crate) active_outbound: Option<String>,
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
    assigned_ip: String,
    pub_key: String,
    mode: VpnConnectMode,
}

impl Daemon {
    /// Build the daemon core from config, paths, and optional restored
    /// credentials.
    pub async fn new(
        config: DaemonConfig, config_path: PathBuf, credential_path: PathBuf,
        credentials: Option<PersistedCredentials>,
    ) -> Self {
        let identity = config.to_client_identity();
        let http_pool = match rustylink_api::build_http_client(&rustylink_api::ApiClientOptions {
            outbound_interface: config.outbound_interface.clone(),
        })
        .await
        {
            Ok(client) => client,
            Err(e) => {
                tracing::warn!(%e, "failed to build HTTP client with interface binding; falling back to default");
                rustylink_api::build_http_client(&rustylink_api::ApiClientOptions::default())
                    .await
                    .expect("failed to build default HTTP client")
            }
        };
        let (vpn_watch_tx, vpn_watch_rx) = watch::channel(pb::Tunnel::default());

        let auth_machine = if let Some(creds) = credentials {
            AuthMachine::restore_from_credentials(creds, http_pool, identity)
        } else {
            AuthMachine {
                state: AuthState::Unconfigured,
                http_pool,
                identity,
                tenant: None,
                signing: None,
                cookies: rustylink_api::CookieStore::empty(),
                knock_token: None,
                totp: None,
                login_api_version: LoginApiVersion::default(),
                oauth_pending: None,
                device_login_pending: None,
            }
        };

        let inner = DaemonInner {
            auth: auth_machine,
            vpn: None,
            config,
            config_path,
            credential_path,
            vpn_watch_tx,
            tunnel_task: None,
            active_outbound: None,
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

    /// Persist current auth credentials to disk.  Only saves an authenticated
    /// session (the machine can produce a complete, restorable snapshot).
    pub async fn persist_credentials(&self) {
        let inner = self.inner.lock().await;
        if !matches!(inner.auth.state, AuthState::Authenticated) {
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
        match inner.auth.state {
            AuthState::Unconfigured => Err(RpcFault::NotConfigured.into()),
            _ => Ok(()),
        }
    }

    /// Check that the auth machine is authenticated.
    pub(crate) async fn require_authenticated(&self) -> Result<()> {
        let inner = self.inner.lock().await;
        match inner.auth.state {
            AuthState::Authenticated => Ok(()),
            _ => Err(RpcFault::NotAuthenticated.into()),
        }
    }

    /// Restore the auth session state from credentials loaded at startup.
    ///
    /// Must be called once after construction: a restored machine always starts
    /// in `Unconfigured`, so without this a previously-authenticated session
    /// (restored from `credentials.json`) would not be recognised and the UI
    /// would prompt for login again (notably after `--rotate-token`).
    pub async fn restore_auth_state(&self) {
        let mut inner = self.inner.lock().await;
        inner.auth.restore_session().await;
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
                    protocol_mode: persisted.protocol_mode,
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
        if !matches!(inner.auth.state, AuthState::Authenticated) {
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

    /// If the configured outbound interface has changed since the current
    /// tunnel session was started, cancel the running connect/supervise loop
    /// and restart with the updated config.  No-op when no tunnel is active or
    /// when the interface hasn't changed.
    #[allow(clippy::significant_drop_tightening)]
    pub async fn reconnect_if_outbound_changed(&self) {
        let (request, cancel, task) = {
            let mut inner = self.inner.lock().await;
            if inner.config.outbound_interface == inner.active_outbound {
                return;
            }
            // Rebuild the HTTP pool with the new outbound interface so
            // tenant API calls (vpn/list, vpn/setting, info/me) use the
            // updated Dialer + Resolver.
            match rustylink_api::build_http_client(&rustylink_api::ApiClientOptions {
                outbound_interface: inner.config.outbound_interface.clone(),
            })
            .await
            {
                Ok(pool) => {
                    tracing::info!("rebuilt HTTP pool for new outbound interface");
                    inner.auth.http_pool = pool;
                }
                Err(e) => {
                    tracing::warn!(%e, "failed to rebuild HTTP pool for new outbound interface");
                }
            }
            let request = inner
                .vpn
                .as_ref()
                .and_then(|vpn| vpn.state.current_request().cloned());
            let Some(request) = request else {
                return;
            };
            let vpn = inner.vpn.as_mut().unwrap();
            let cancel = vpn.cancel_token.clone();
            let task = inner.tunnel_task.take();
            (request, cancel, task)
        };
        cancel.cancel();
        if let Some(task) = task {
            let _ = task.await;
        }
        tracing::info!("outbound interface changed; reconnecting tunnel");
        if let Err(error) = self.connect_tunnel(request).await {
            tracing::warn!(%error, "reconnect after outbound change failed");
        }
    }

    async fn run_connect_loop(self, request: VpnRequest, cancel: CancellationToken) {
        let mut controller =
            ReconnectController::new(ReconnectPolicy::android_compatible_default());
        loop {
            match self.connect_once(&request, &cancel).await {
                Ok(SupervisorOutcome::Cancelled) => {
                    self.mark_disconnected().await;
                    return;
                }
                Ok(SupervisorOutcome::ServerKickOut { was_healthy }) => {
                    if was_healthy {
                        controller.reset();
                    }
                    let decision = controller.record(ReconnectEvent::ServerKickOut);
                    if !self.handle_decision(decision, &cancel).await {
                        return;
                    }
                }
                Ok(SupervisorOutcome::Trigger { event, was_healthy }) => {
                    if was_healthy {
                        controller.reset();
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
        let vpn_domain = GetVpnSettingRequest
            .send(&client)
            .await
            .ok()
            .and_then(|resp| resp.data)
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

        let (pool, hooks, outbound_interface) = {
            let inner = self.inner.lock().await;
            (
                inner.auth.http_pool.clone(),
                inner.auth.build_hooks(),
                inner.config.outbound_interface.clone(),
            )
        };
        let (build_dot_client, probe_client) =
            dot_client_builders(pool, hooks, vpn_domain.clone(), outbound_interface);
        let config_result = rustylink_core::vpn::vpn_config_from_dot_list(
            &client,
            &config_request,
            build_dot_client,
            move |dots| crate::latency::rank_dots_by_latency(dots, probe_client),
        )
        .await
        .map_err(DaemonError::from)?;

        // Set-Cookie from the dot config call was already absorbed into the
        // shared jar by the API client middleware — nothing to merge here.
        let data = config_result.response.data.clone().context(TunnelSnafu {
            message: "/vpn/conn returned no data",
        })?;

        let mut session = self
            .start_session(&config_result, &data, &local_params, request)
            .await?;

        self.mark_connected(&config_result, &data.ip).await;

        // `/vpn/report` is a VPN-control API: like `/vpn/conn`, the Android
        // client (`VpnReportOperator.report`) posts it to the *selected dot's*
        // API host (`https://{apiIp}:{apiPort}/vpn/report`), not the tenant
        // host. Reuse the dot endpoint + TLS handling from the config call so
        // the report reaches the dot; the tenant host has no such route and
        // answers 405 Method Not Allowed.
        let report_client = {
            let inner = self.inner.lock().await;
            let hooks = inner.auth.build_hooks();
            let pool = inner.auth.http_pool.clone();
            let outbound_interface = inner.config.outbound_interface.clone();
            drop(inner);
            build_dot_api_client(
                &config_result.endpoint,
                &pool,
                &hooks,
                vpn_domain.as_deref(),
                outbound_interface.as_deref(),
            )
            .await
        };

        let report = ReportParams {
            assigned_ip: data.ip.clone(),
            pub_key: local_params.local_public_key.clone(),
            mode: request.mode,
        };

        // report(100) — connected.
        let _ = self
            .send_report(&report_client, &report, VpnReportType::Connected)
            .await;

        // Supervise until a trigger / cancellation.
        let outcome = self
            .supervise(&mut session, &report_client, &report, cancel)
            .await;

        // Teardown: stop the device + report(101).
        let _ = session.stop().await;
        let _ = self
            .send_report(&report_client, &report, VpnReportType::Disconnected)
            .await;
        Ok(outcome)
    }

    /// Build the tunnel config from a `/vpn/conn` result and bring the device
    /// up.
    async fn start_session(
        &self, config_result: &VpnConfigResult, data: &VpnConnResponse,
        local_params: &LocalTunnelParams, request: &VpnRequest,
    ) -> Result<TunnelSession> {
        let (outbound_iface, tun_interface) = {
            let mut inner = self.inner.lock().await;
            let outbound = inner.config.outbound_interface.clone();
            inner.active_outbound = outbound;
            (
                inner.config.outbound_interface.clone(),
                inner.config.tun_interface.clone(),
            )
        };

        let effective_protocol_mode =
            effective_transport(config_result.dot.protocol_mode, request.protocol_mode);

        let mut tunnel_config = TunnelConfig::from_vpn_conn(
            data,
            local_params.clone(),
            config_result.endpoint.wireguard_endpoint.clone(),
            effective_protocol_mode,
            vpn_route_mode(request.mode),
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
    ///
    /// `dot_client` must address the selected dot's API host (the periodic
    /// keepalive report is posted through it).
    async fn supervise(
        &self, session: &mut TunnelSession, dot_client: &ApiClient, report: &ReportParams,
        cancel: &CancellationToken,
    ) -> SupervisorOutcome {
        let outbound = {
            let inner = self.inner.lock().await;
            inner.config.outbound_interface.clone()
        };
        let report_daemon = self.clone();
        let report_client = dot_client.clone();
        let report = report.clone();
        supervisor::run(session, outbound, cancel.clone(), move || {
            let daemon = report_daemon.clone();
            let client = report_client.clone();
            let report = report.clone();
            async move {
                daemon
                    .send_report(&client, &report, VpnReportType::Connected)
                    .await
            }
        })
        .await
    }

    /// Send a `/vpn/report` (`Connected` keepalive / `Disconnected`).  Returns
    /// `true` if the server signalled a force-logout (kickout).
    ///
    /// `dot_client` must address the *selected dot's* API host (built via
    /// [`build_dot_api_client`]), matching the Android `VpnReportOperator`.
    /// The tenant host has no `/vpn/report` route and answers 405.
    async fn send_report(
        &self, dot_client: &ApiClient, report: &ReportParams, report_type: VpnReportType,
    ) -> bool {
        let request = VpnReportRequest {
            r#type: report_type.wire(),
            ip: report.assigned_ip.clone(),
            public_key: report.pub_key.clone(),
            mode: report.mode.android_name(),
        };
        match request.clone().send(dot_client).await {
            Ok(response) => response.is_force_logout(),
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
        let mut inner = self.inner.lock().await;
        inner.active_outbound = None;
        if let Some(vpn) = &mut inner.vpn {
            vpn.set_disconnected();
            let tunnel = vpn.to_tunnel_proto();
            let _ = inner.vpn_watch_tx.send(tunnel);
        }
    }

    async fn mark_failed(&self, error: String) {
        let mut inner = self.inner.lock().await;
        inner.active_outbound = None;
        if let Some(vpn) = &mut inner.vpn {
            vpn.set_failed(error);
            let tunnel = vpn.to_tunnel_proto();
            let _ = inner.vpn_watch_tx.send(tunnel);
        }
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
/// Per-attempt dot API client factories:
/// - `config` builds the client for `POST /vpn/conn` (called per selected dot).
/// - `probe` resolves a [`VpnDot`] to its endpoint and builds the client used
///   to time `GET /vpn/ping` for latency ranking. Auto dot selection feeds it
///   into [`crate::latency::rank_dots_by_latency`].
fn dot_client_builders(
    pool: rustylink_api::HttpClient, hooks: ApiHooks, vpn_domain: Option<String>,
    outbound_interface: Option<String>,
) -> (
    impl Fn(&DotEndpoint) -> ApiClient + Clone,
    impl Fn(&VpnDot) -> Option<ApiClient> + Clone,
) {
    let probe = {
        let pool = pool.clone();
        let hooks = hooks.clone();
        let vpn_domain = vpn_domain.clone();
        let outbound_interface = outbound_interface.clone();
        move |dot: &VpnDot| {
            DotEndpoint::from_dot(dot, false).ok().map(|endpoint| {
                tokio::task::block_in_place(|| {
                    tokio::runtime::Handle::current().block_on(build_dot_api_client(
                        &endpoint,
                        &pool,
                        &hooks,
                        vpn_domain.as_deref(),
                        outbound_interface.as_deref(),
                    ))
                })
            })
        }
    };
    let config = move |endpoint: &DotEndpoint| {
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(build_dot_api_client(
                endpoint,
                &pool,
                &hooks,
                vpn_domain.as_deref(),
                outbound_interface.as_deref(),
            ))
        })
    };
    (config, probe)
}

/// Falls back to a plain client against the original (IP) endpoint when no
/// `vpn_domain` is known or the host is not a bare IP.
pub async fn build_dot_api_client(
    endpoint: &DotEndpoint, pool: &rustylink_api::HttpClient, hooks: &ApiHooks,
    vpn_domain: Option<&str>, outbound_interface: Option<&str>,
) -> ApiClient {
    if let Some(domain) = vpn_domain
        && let Some(host) = endpoint.api_base_url.host_str()
        && let Ok(ip) = host.parse::<IpAddr>()
        && let Some(port) = endpoint.api_base_url.port_or_known_default()
    {
        let tls_host = tls_host_for(domain);
        if let Ok(tls_url) = url::Url::parse(&format!("https://{tls_host}:{port}"))
            && let Ok(client) = rustylink_api::build_dot_http_client(
                &tls_host,
                SocketAddr::new(ip, port),
                outbound_interface,
            )
            .await
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
    let (protocol_mode, supported_protocols) = protocol_modes_from_dot(dot.protocol_mode);
    pb::VpnLocation {
        id: dot.id.unwrap_or_default(),
        name: dot.name.clone().unwrap_or_default(),
        display_name: dot.name.unwrap_or_default(),
        mode: mode_from_dot(dot.mode).into(),
        protocol_mode: protocol_mode.into(),
        supported_protocols: supported_protocols.into_iter().map(Into::into).collect(),
        delay_ms: 0,
        ..Default::default()
    }
}

/// Map the dot's wire `protocol_mode` (Udp=0, FeilianTcp=1, Dual=2 — the dual
/// value is api-only) to the proto `ProtocolMode` (UDP=0/TCP=1) plus the
/// supported-protocol set this dot accepts. Unknown / missing → UDP.
fn protocol_modes_from_dot(mode: Option<i32>) -> (pb::ProtocolMode, Vec<pb::ProtocolMode>) {
    use pb::ProtocolMode as P;
    match mode {
        Some(DOT_PROTOCOL_TCP) => (P::Tcp, vec![P::Tcp]),
        Some(DOT_PROTOCOL_DUAL) => (P::Udp, vec![P::Udp, P::Tcp]),
        Some(DOT_PROTOCOL_UDP | _) | None => (P::Udp, vec![P::Udp]),
    }
}

/// Decide which transport to bring up given the dot's advertised protocol mode
/// and the caller's request. A dual-capable dot (api wire value 2) honors the
/// caller's choice. A single-protocol dot serves only its own mode (a
/// mismatched request is silently overridden — it can't make the dot something
/// it isn't).
fn effective_transport(dot_mode: Option<i32>, requested: ProtocolMode) -> ProtocolMode {
    match dot_mode {
        Some(DOT_PROTOCOL_UDP) => ProtocolMode::Udp,
        Some(DOT_PROTOCOL_TCP) => ProtocolMode::FeilianTcp,
        // Dual or unknown: caller's choice wins.
        _ => requested,
    }
}

/// Dot capability wire values from `VpnDot.protocol_mode`. Matches both the
/// `rustylink_tunnel` and Android `IProtocol` ids; `Dual` is api-only because
/// the tunnel itself only ever runs as UDP or TCP.
const DOT_PROTOCOL_UDP: i32 = ProtocolMode::Udp as i32;
const DOT_PROTOCOL_TCP: i32 = ProtocolMode::FeilianTcp as i32;
const DOT_PROTOCOL_DUAL: i32 = 2;

fn mode_from_dot(mode: Option<i32>) -> pb::VpnMode {
    match mode.and_then(VpnConnectMode::from_repr) {
        Some(VpnConnectMode::Full) => pb::VpnMode::Full,
        Some(VpnConnectMode::Split) => pb::VpnMode::Split,
        None => pb::VpnMode::Unspecified,
    }
}

fn vpn_route_mode(mode: VpnConnectMode) -> VpnRouteMode {
    match mode {
        VpnConnectMode::Full => VpnRouteMode::Full,
        VpnConnectMode::Split => VpnRouteMode::Split,
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
    use rustylink_api::ProtocolMode;

    use super::{
        DOT_PROTOCOL_DUAL, DOT_PROTOCOL_TCP, DOT_PROTOCOL_UDP, DefaultOrExt, effective_transport,
    };

    #[test]
    fn non_default_or_falls_back_only_on_default() {
        assert_eq!("".non_default_or("login"), "login");
        assert_eq!("scan".non_default_or("login"), "scan");
        assert_eq!(0_i32.non_default_or(7), 7);
        assert_eq!(3_i32.non_default_or(7), 3);
    }

    #[test]
    fn effective_transport_honors_request_only_on_dual_dots() {
        let udp = ProtocolMode::Udp;
        let tcp = ProtocolMode::FeilianTcp;

        // Dual dot (wire value 2) honors the caller's choice.
        assert_eq!(effective_transport(Some(DOT_PROTOCOL_DUAL), udp), udp);
        assert_eq!(effective_transport(Some(DOT_PROTOCOL_DUAL), tcp), tcp);

        // Single-protocol dots ignore mismatched requests (dot wins).
        assert_eq!(effective_transport(Some(DOT_PROTOCOL_UDP), tcp), udp);
        assert_eq!(effective_transport(Some(DOT_PROTOCOL_TCP), udp), tcp);
        assert_eq!(effective_transport(Some(DOT_PROTOCOL_UDP), udp), udp);

        // No dot mode advertised: caller wins.
        assert_eq!(effective_transport(None, tcp), tcp);
        assert_eq!(effective_transport(None, udp), udp);
    }

    /// Live, network + real-credentials check (run with
    /// `cargo test -p rustylinkd -- --ignored --nocapture live_dot_connect`).
    /// Loads the on-disk session, fetches the dot list, and exercises the dot
    /// config TLS path — proving the cert validates against `vpn_domain` rather
    /// than failing `NotValidForName` on the dialed IP.
    #[tokio::test]
    #[ignore = "requires network and an authenticated credentials.json"]
    async fn live_dot_connect() {
        use rustylink_api::{
            ClientIdentity, GetVpnLocationsRequest, GetVpnSettingRequest, SendableRequest as _,
            VpnConnRequest,
        };

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

        let pool = rustylink_api::build_http_client(&rustylink_api::ApiClientOptions::default())
            .await
            .expect("build http client");
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
        let setting = GetVpnSettingRequest
            .send(&client)
            .await
            .expect("vpn setting");
        snapshot("after /api/setting", hooks.cookies.snapshot().await);
        let vpn_domain = setting.data.and_then(|s| s.vpn_domain);
        eprintln!("vpn_domain = {vpn_domain:?}");

        let locations = GetVpnLocationsRequest
            .send(&client)
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
            let dot_client =
                build_dot_api_client(&endpoint, &pool, &hooks, vpn_domain.as_deref(), None).await;
            let body = VpnConnRequest {
                mode: Some("Full".to_owned()),
                public_key: rustylink_tunnel::LocalTunnelParams::generate().local_public_key,
                otp: None,
                export_id: dot.id.unwrap_or_default(),
                sign_token: None,
                not_auto: Some(true),
            };
            match body.send(&dot_client).await {
                Ok(resp) => {
                    eprintln!("dot {:?}: /vpn/conn code={}", dot.id, resp.code);
                    any_ok |= resp.code == 0;
                }
                Err(error) => eprintln!("dot {:?}: /vpn/conn err = {error}", dot.id),
            }
        }
        assert!(any_ok, "no dot returned a successful /vpn/conn");
    }
}
