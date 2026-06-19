//! Daemon core: the single serialized owner of `DaemonState` + `AppContext`.
//!
//! Realizes the plan's single-owner intent (A5/A7) via
//! `Arc<Mutex<DaemonInner>>` rather than an mpsc command actor — RPC handlers
//! and the supervisor lock the same inner, mutate, persist atomically, and
//! broadcast a fresh snapshot over a `tokio::watch` channel. Core functions are
//! pure (`&AppContext` → `(result, Vec<StateChange>)`); the daemon applies the
//! changes.

use std::{path::PathBuf, sync::Arc, time::Instant};

use connectrpc::{RequestContext, Response, ServiceRequest, ServiceResult, ServiceStream};
use rustylink_api::{
    ApiClientOptions, LoginSetting, LoginV2Next, LoginV2Result, UserInfo, VpnConnResponse, VpnDot,
    VpnReportRequest,
};
use rustylink_core::{
    AppContext, StateChange,
    vpn::{VpnConfigRequest, VpnConfigResult, VpnConnectMode},
};
use rustylink_proto::proto::rustylink::daemon::{
    persist::v1 as persist,
    v1::{self as pb, RustylinkService},
};
use rustylink_tunnel::{
    LocalTunnelParams, ReconnectController, ReconnectDecision, ReconnectEvent, ReconnectPolicy,
    TunnelConfig, TunnelSession,
};
use snafu::prelude::*;
use tokio::{
    sync::{Mutex, watch},
    task::JoinHandle,
};
use tokio_stream::{StreamExt as _, wrappers::WatchStream};
use tokio_util::sync::CancellationToken;

use crate::{
    error::{DaemonError, Result, RpcFault, TunnelSnafu},
    state::{ActiveTunnel, DaemonState, VpnRequest},
    supervisor::{self, SupervisorOutcome},
};

/// The serialized inner state owned by the daemon.
struct DaemonInner {
    state: DaemonState,
    ctx: AppContext,
    state_path: PathBuf,
    watch_tx: watch::Sender<Arc<persist::PersistedState>>,
    /// Cancellation token for the active connect/supervise task, if any.
    tunnel_cancel: Option<CancellationToken>,
    /// Handle to the active connect/supervise task, if any.
    tunnel_task: Option<JoinHandle<()>>,
}

/// Cloneable handle to the daemon core.
#[derive(Clone)]
pub struct Daemon {
    inner: Arc<Mutex<DaemonInner>>,
    watch_rx: watch::Receiver<Arc<persist::PersistedState>>,
    started_at: Instant,
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
    /// Build the daemon core from a loaded state and its on-disk path.
    pub fn new(state: DaemonState, state_path: PathBuf) -> Result<Self> {
        let api_options = ApiClientOptions {
            outbound_interface: state.outbound_interface_name(),
        };
        let ctx = AppContext::new(&state.proto, api_options).map_err(DaemonError::from)?;
        let (watch_tx, watch_rx) = watch::channel(Arc::new(state.proto.clone()));
        let inner = DaemonInner {
            state,
            ctx,
            state_path,
            watch_tx,
            tunnel_cancel: None,
            tunnel_task: None,
        };
        Ok(Self {
            inner: Arc::new(Mutex::new(inner)),
            watch_rx,
            started_at: Instant::now(),
        })
    }

    /// Subscribe to state snapshots (for `WatchState`).
    #[must_use]
    pub fn subscribe(&self) -> watch::Receiver<Arc<persist::PersistedState>> {
        self.watch_rx.clone()
    }

    #[must_use]
    pub fn uptime_seconds(&self) -> i64 {
        i64::try_from(self.started_at.elapsed().as_secs()).unwrap_or(i64::MAX)
    }

    // -----------------------------------------------------------------------
    // Tunnel connect / disconnect (non-blocking; progress via WatchState)
    // -----------------------------------------------------------------------

    /// On startup, re-establish the tunnel if it was active and auto-reconnect
    /// is enabled.  Re-runs the full connect flow (fresh `/vpn/conn`, keypair,
    /// TOTP) rather than reusing stale tunnel config (F2).
    pub async fn maybe_auto_resume(&self) {
        let request = {
            let inner = self.inner.lock().await;
            if !inner.state.auto_reconnect_on_start() {
                return;
            }
            inner.state.vpn_request()
        };
        if let Some(request) = request {
            tracing::info!("auto-resuming tunnel from persisted request");
            if let Err(error) = self.connect_tunnel(request).await {
                tracing::warn!(%error, "auto-resume failed");
            }
        }
    }

    /// Start a tunnel connection.  Returns immediately with `CONNECTING`; the
    /// connect + supervise flow runs in a background task.
    pub async fn connect_tunnel(&self, request: VpnRequest) -> Result<pb::Tunnel> {
        let mut inner = self.inner.lock().await;
        inner.require_authenticated()?;
        if !inner.state.vpn_can_connect() {
            return Err(RpcFault::InvalidArgument {
                message: "tunnel is already connecting or connected; disconnect first".to_owned(),
            }
            .into());
        }
        inner.state.vpn_set_connecting(&request);
        inner.persist_and_broadcast()?;
        let tunnel = inner.state.to_tunnel();

        // Cancel any stale task, then spawn the connect/supervise loop.
        if let Some(cancel) = inner.tunnel_cancel.take() {
            cancel.cancel();
        }
        let cancel = CancellationToken::new();
        inner.tunnel_cancel = Some(cancel.clone());
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
        let (cancel, task) = {
            let mut inner = self.inner.lock().await;
            inner.state.vpn_set_disconnecting();
            inner.persist_and_broadcast()?;
            (inner.tunnel_cancel.take(), inner.tunnel_task.take())
        };
        if let Some(cancel) = cancel {
            cancel.cancel();
        }
        if let Some(task) = task {
            let _ = task.await;
        }
        let mut inner = self.inner.lock().await;
        inner.state.vpn_set_disconnected();
        inner.persist_and_broadcast()?;
        Ok(inner.state.to_tunnel())
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
        self.vpn_transition(DaemonState::vpn_set_configuring)
            .await?;

        let ctx = self.snapshot_ctx().await;
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
        let (config_result, changes) =
            rustylink_core::vpn::vpn_config_from_dot_list(&ctx, &config_request).await?;
        self.apply_changes(changes).await?;

        let data = config_result.response.data.clone().context(TunnelSnafu {
            message: "/vpn/conn returned no data",
        })?;

        let mut session = self
            .start_session(&config_result, &data, &local_params)
            .await?;

        self.mark_connected(&config_result, &data.ip).await?;

        let report = ReportParams {
            dot: config_result.dot.clone(),
            assigned_ip: data.ip.clone(),
            pub_key: local_params.local_public_key.clone(),
            mode: request.mode,
        };

        // report(100) — connected.
        let _ = self.send_report(&ctx, &report, 100).await;

        // Supervise until a trigger / cancellation.
        let outcome = self.supervise(&mut session, &ctx, &report, cancel).await;

        // Teardown: stop the device + report(101).
        let _ = session.stop().await;
        let _ = self.send_report(&ctx, &report, 101).await;
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
            inner.state.outbound_interface_name()
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

    /// Record the connected tunnel in `DaemonState`.
    async fn mark_connected(
        &self, config_result: &VpnConfigResult, assigned_ip: &str,
    ) -> Result<()> {
        let dot = &config_result.dot;
        let active = ActiveTunnel {
            dot_id: dot.id.unwrap_or_default(),
            dot_name: dot.name.clone().unwrap_or_default(),
            endpoint: config_result.endpoint.wireguard_endpoint.to_string(),
            assigned_ip: assigned_ip.to_string(),
            connected_at: Some(jiff::Timestamp::now()),
            last_handshake_at: None,
            protocol_mode: dot.protocol_mode,
        };
        self.vpn_transition(move |s| s.vpn_set_connected(&active))
            .await
    }

    /// Run the supervisor over a live session with a periodic `/vpn/report`.
    async fn supervise(
        &self, session: &mut TunnelSession, ctx: &AppContext, report: &ReportParams,
        cancel: &CancellationToken,
    ) -> SupervisorOutcome {
        let outbound = {
            let inner = self.inner.lock().await;
            inner.state.outbound_interface_name()
        };
        let protocol_mode = report.dot.protocol_mode;
        let report_daemon = self.clone();
        let report_ctx = ctx.clone();
        let report = report.clone();
        supervisor::run(
            session,
            protocol_mode,
            outbound,
            cancel.clone(),
            move || {
                let daemon = report_daemon.clone();
                let ctx = report_ctx.clone();
                let report = report.clone();
                async move { daemon.send_report(&ctx, &report, 100).await }
            },
        )
        .await
    }

    /// Send a `/vpn/report` (type 100 keepalive / 101 disconnect).  Returns
    /// `true` if the server signalled a force-logout (kickout).
    async fn send_report(&self, ctx: &AppContext, report: &ReportParams, report_type: i32) -> bool {
        let request = VpnReportRequest {
            r#type: report_type.to_string(),
            ip: report.assigned_ip.clone(),
            public_key: report.pub_key.clone(),
            mode: report.mode.android_name(),
        };
        match rustylink_core::vpn::report_vpn(ctx, &report.dot, &request).await {
            Ok((response, changes)) => {
                let _ = self.apply_changes(changes).await;
                response.is_force_logout()
            }
            Err(error) => {
                tracing::warn!(%error, report_type, "vpn report failed (non-fatal)");
                false
            }
        }
    }

    /// Compute the OTP for `/vpn/conn`: a manual code if supplied, else a fresh
    /// TOTP derived from the stored secret (best-effort).
    async fn compute_otp(&self, manual: Option<String>) -> Option<String> {
        if let Some(code) = manual {
            return Some(code);
        }
        let config = {
            let inner = self.inner.lock().await;
            inner.state.totp().cloned()?
        };
        let now = jiff::Timestamp::now().as_second();
        rustylink_core::vpn::generate_totp(&config, now)
    }

    /// Apply a reconnect decision: sleep (interruptibly) and continue, or stop.
    /// Returns `true` to continue the connect loop, `false` to terminate.
    async fn handle_decision(
        &self, decision: ReconnectDecision, cancel: &CancellationToken,
    ) -> bool {
        match decision {
            ReconnectDecision::Retry { after, .. }
            | ReconnectDecision::SwitchNode { after, .. } => {
                let _ = self.vpn_transition(DaemonState::vpn_set_reconnecting).await;
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
        let _ = self.vpn_transition(DaemonState::vpn_set_disconnected).await;
    }

    async fn mark_failed(&self, error: String) {
        let _ = self.vpn_transition(move |s| s.vpn_set_failed(error)).await;
    }

    /// Snapshot the current `AppContext` (cheap clone; shares the HTTP pool).
    async fn snapshot_ctx(&self) -> AppContext {
        self.inner.lock().await.ctx.clone()
    }

    /// Apply core state changes + persist + broadcast.
    async fn apply_changes(&self, changes: Vec<StateChange>) -> Result<()> {
        let mut inner = self.inner.lock().await;
        inner.apply(changes);
        inner.persist_and_broadcast()
    }

    /// Mutate the daemon state via a transition method, then persist +
    /// broadcast.
    async fn vpn_transition(&self, f: impl FnOnce(&mut DaemonState)) -> Result<()> {
        let mut inner = self.inner.lock().await;
        f(&mut inner.state);
        inner.persist_and_broadcast()
    }
}

// ---------------------------------------------------------------------------
// DaemonInner — state mutation, persistence, broadcast
// ---------------------------------------------------------------------------

impl DaemonInner {
    fn require_configured(&self) -> Result<()> {
        match self.state.configured_base() {
            Some(_) => Ok(()),
            None => Err(RpcFault::NotConfigured.into()),
        }
    }

    fn require_authenticated(&self) -> Result<()> {
        if self.state.is_authenticated() {
            Ok(())
        } else {
            Err(RpcFault::NotAuthenticated.into())
        }
    }

    fn is_v1(&self) -> bool {
        self.state.is_v1()
    }

    fn apply(&mut self, changes: Vec<StateChange>) {
        for change in changes {
            match change {
                StateChange::TenantConfigured { tenant, signing } => {
                    self.state.set_tenant_configured(tenant, signing);
                }
                StateChange::CookiesUpdated { cookies } => {
                    self.state.set_cookies(cookies);
                }
                StateChange::CsrfTokenUpdated { token } => {
                    self.state.set_csrf_token(token);
                }
                StateChange::SigningConfigUpdated { config } => {
                    self.state.set_signing(config);
                }
                StateChange::OAuthStateSet {
                    alias_key,
                    state,
                    code_verifier,
                } => {
                    self.state.set_oauth(alias_key, state, code_verifier);
                }
                StateChange::OAuthCleared => self.state.clear_oauth(),
                StateChange::SessionExpired => self.state.expire(),
                StateChange::LoggedOut => self.state.logout(),
            }
        }
        self.ctx.refresh(&self.state.proto);
    }

    fn apply_login_outcome(&mut self, result: Option<&LoginV2Result>) {
        if let Some(next) = result.and_then(|r| r.next.as_ref()) {
            self.state.set_pending_challenge(challenge_from_next(next));
        } else {
            self.state.complete_login();
        }
    }

    async fn maybe_fetch_totp(&mut self) {
        if !self.state.needs_totp() {
            return;
        }
        match rustylink_core::vpn::fetch_totp(&self.ctx).await {
            Ok((Some(config), changes)) => {
                self.apply(changes);
                self.state.set_totp(config);
            }
            Ok((None, changes)) => self.apply(changes),
            Err(error) => {
                tracing::warn!(%error, "failed to fetch TOTP secret (non-fatal)");
            }
        }
    }

    /// Report device security posture, mirroring the Android client's
    /// `MainActivity.onCreate` → `/api/security/report` after the home screen
    /// (post-login) loads.  Best-effort: failures are non-fatal.
    async fn maybe_report_security(&mut self) {
        if !self.state.is_authenticated() {
            return;
        }
        let report = rustylink_core::security::all_green_security_report();
        match rustylink_core::security::report_security(&self.ctx, &report).await {
            Ok((_response, changes)) => self.apply(changes),
            Err(error) => {
                tracing::warn!(%error, "security report failed (non-fatal)");
            }
        }
    }

    /// Run the post-login side effects once authentication completes: fetch the
    /// TOTP secret (for auto-reconnect) and report device security posture.
    async fn post_login(&mut self) {
        self.maybe_fetch_totp().await;
        self.maybe_report_security().await;
    }

    fn persist_and_broadcast(&mut self) -> Result<()> {
        self.state
            .save(&self.state_path)
            .map_err(DaemonError::from)?;
        let _ = self.watch_tx.send(Arc::new(self.state.proto.clone()));
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Interpretation + projection helpers
// ---------------------------------------------------------------------------

fn login_setting_is_v1(setting: &LoginSetting) -> bool {
    setting.v1_login.unwrap_or(false)
}

fn challenge_from_next(next: &LoginV2Next) -> pb::PendingChallenge {
    let action = next.action.clone().unwrap_or_default();
    let challenge = if action.eq_ignore_ascii_case("mfa") {
        pb::pending_challenge::Challenge::from(pb::MfaChallenge {
            mfa_type: action,
            auth_list: next.auth_list.clone().unwrap_or_default(),
            can_skip: next.can_skip.unwrap_or(false),
            ..Default::default()
        })
    } else {
        let masked = next
            .mobile
            .clone()
            .or_else(|| next.email.clone())
            .unwrap_or_default();
        pb::pending_challenge::Challenge::from(pb::OtpChallenge {
            masked_target: masked,
            login_type: action,
            ..Default::default()
        })
    };
    pb::PendingChallenge {
        challenge: Some(challenge),
        ..Default::default()
    }
}

fn project_user_info(user: Option<UserInfo>) -> pb::UserInfo {
    let user = user.unwrap_or_default();
    pb::UserInfo {
        uid: user.uid.unwrap_or_default(),
        name: user.name.unwrap_or_default(),
        email: user.email.unwrap_or_default(),
        mobile: user.mobile.unwrap_or_default(),
        ..Default::default()
    }
}

fn project_vpn_location(dot: VpnDot) -> pb::VpnLocation {
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

// ---------------------------------------------------------------------------
// RustylinkService implementation — the RPC surface lives directly on `Daemon`
// (no separate service wrapper).  Handlers extract the request, run the logic
// against the locked inner state, and project the result to the wire types.
//
// Core errors are mapped through `DaemonError` (local to this crate) on the way
// to `ConnectError`, because the orphan rule forbids `impl From<core::Error>
// for ConnectError` and `impl From<&DaemonState> for pb::*` directly.
// ---------------------------------------------------------------------------

// Handlers return concrete response types, which are more specific than the
// generated trait's `impl Encodable<...>` bound — intentional refinement (a
// rustc lint, unavoidable when implementing connectrpc's RPITIT trait).
#[allow(refining_impl_trait_reachable)]
impl RustylinkService for Daemon {
    // ----- meta -----

    async fn ping(
        &self, _ctx: RequestContext, _request: ServiceRequest<'_, pb::PingRequest>,
    ) -> ServiceResult<pb::PingResponse> {
        Response::ok(pb::PingResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_seconds: self.uptime_seconds(),
            ..Default::default()
        })
    }

    async fn watch_state(
        &self, _ctx: RequestContext, _request: ServiceRequest<'_, pb::WatchStateRequest>,
    ) -> ServiceResult<ServiceStream<pb::WatchStateResponse>> {
        let stream = WatchStream::new(self.subscribe())
            .map(|state| Ok(pb::WatchStateResponse::from(state.as_ref())));
        Response::stream_ok(stream)
    }

    // ----- session -----

    async fn get_session(
        &self, _ctx: RequestContext, _request: ServiceRequest<'_, pb::GetSessionRequest>,
    ) -> ServiceResult<pb::GetSessionResponse> {
        let session = self.inner.lock().await.state.to_session();
        Response::ok(pb::GetSessionResponse {
            session: session.into(),
            ..Default::default()
        })
    }

    async fn activate(
        &self, _ctx: RequestContext, request: ServiceRequest<'_, pb::ActivateRequest>,
    ) -> ServiceResult<pb::ActivateResponse> {
        let code = request.code.map(ToOwned::to_owned);
        let base_url = request.base_url.map(ToOwned::to_owned);
        let backup_url = request.backup_url.map(ToOwned::to_owned);
        let match_base_url = request.match_base_url.map(ToOwned::to_owned);
        let mut inner = self.inner.lock().await;
        let (_resp, changes) =
            rustylink_core::auth::activate(&inner.ctx, code, base_url, backup_url, match_base_url)
                .await
                .map_err(DaemonError::from)?;
        inner.apply(changes);
        // TenantConfigured in apply already promotes Unconfigured → Configured.
        // Auto-detect the login API from /api/login/setting (best-effort).
        if let Ok((setting, setting_changes)) = rustylink_core::vpn::login_setting(&inner.ctx).await
        {
            inner.apply(setting_changes);
            if let Some(data) = setting.data.as_ref() {
                inner.state.set_login_api(login_setting_is_v1(data));
            }
        }
        inner.persist_and_broadcast()?;
        let session = inner.state.to_session();
        drop(inner);
        Response::ok(pb::ActivateResponse {
            session: session.into(),
            ..Default::default()
        })
    }

    async fn login(
        &self, _ctx: RequestContext, request: ServiceRequest<'_, pb::LoginRequest>,
    ) -> ServiceResult<pb::LoginResponse> {
        let login_scene = nonempty_or(request.login_scene, "login");
        let account_type = nonempty_or(request.account_type, "account");
        let account = request.account.to_string();
        let password = request.password.to_string();
        let mut inner = self.inner.lock().await;
        inner.require_configured()?;
        let is_v1 = inner.is_v1();
        let (resp, changes) = if is_v1 {
            rustylink_core::auth::v1_login_password(
                &inner.ctx,
                login_scene,
                account_type,
                account,
                password,
            )
            .await
            .map_err(DaemonError::from)?
        } else {
            rustylink_core::auth::login_password(
                &inner.ctx,
                login_scene,
                account_type,
                account,
                password,
            )
            .await
            .map_err(DaemonError::from)?
        };
        inner.apply(changes);
        inner.apply_login_outcome(resp.data.as_ref());
        inner.post_login().await;
        inner.persist_and_broadcast()?;
        let session = inner.state.to_session();
        drop(inner);
        Response::ok(pb::LoginResponse {
            session: session.into(),
            ..Default::default()
        })
    }

    async fn request_login_code(
        &self, _ctx: RequestContext, request: ServiceRequest<'_, pb::RequestLoginCodeRequest>,
    ) -> ServiceResult<pb::RequestLoginCodeResponse> {
        let login_scene = nonempty_or(request.login_scene, "login");
        let account_type = nonempty_or(request.account_type, "account");
        let login_type = request.login_type.to_string();
        let account = request.account.to_string();
        let mut inner = self.inner.lock().await;
        inner.require_configured()?;
        let is_v1 = inner.is_v1();
        let (resp, changes) = if is_v1 {
            rustylink_core::auth::v1_send_code(
                &inner.ctx,
                login_scene,
                account_type,
                login_type,
                account,
            )
            .await
            .map_err(DaemonError::from)?
        } else {
            rustylink_core::auth::send_code(
                &inner.ctx,
                login_scene,
                account_type,
                login_type,
                account,
            )
            .await
            .map_err(DaemonError::from)?
        };
        inner.apply(changes);
        inner.persist_and_broadcast()?;
        drop(inner);
        Response::ok(pb::RequestLoginCodeResponse {
            code: resp.data.and_then(|d| d.result).unwrap_or_default(),
            ..Default::default()
        })
    }

    async fn verify_login_code(
        &self, _ctx: RequestContext, request: ServiceRequest<'_, pb::VerifyLoginCodeRequest>,
    ) -> ServiceResult<pb::VerifyLoginCodeResponse> {
        let login_scene = nonempty_or(request.login_scene, "login");
        let account_type = nonempty_or(request.account_type, "account");
        let login_type = request.login_type.to_string();
        let account = request.account.to_string();
        let code = request.code.to_string();
        let mut inner = self.inner.lock().await;
        inner.require_configured()?;
        let is_v1 = inner.is_v1();
        let (resp, changes) = if is_v1 {
            rustylink_core::auth::v1_verify_code(
                &inner.ctx,
                login_scene,
                account_type,
                login_type,
                account,
                code,
            )
            .await
            .map_err(DaemonError::from)?
        } else {
            rustylink_core::auth::verify_code(
                &inner.ctx,
                login_scene,
                account_type,
                login_type,
                account,
                code,
            )
            .await
            .map_err(DaemonError::from)?
        };
        inner.apply(changes);
        inner.apply_login_outcome(resp.data.as_ref());
        inner.post_login().await;
        inner.persist_and_broadcast()?;
        let session = inner.state.to_session();
        drop(inner);
        Response::ok(pb::VerifyLoginCodeResponse {
            session: session.into(),
            ..Default::default()
        })
    }

    async fn request_mfa_code(
        &self, _ctx: RequestContext, request: ServiceRequest<'_, pb::RequestMfaCodeRequest>,
    ) -> ServiceResult<pb::RequestMfaCodeResponse> {
        let login_scene = nonempty_or(request.login_scene, "login");
        let mfa_type = request.mfa_type.to_string();
        let account = request.account.to_string();
        let mut inner = self.inner.lock().await;
        inner.require_configured()?;
        let (resp, changes) =
            rustylink_core::auth::v1_mfa_send(&inner.ctx, login_scene, mfa_type, account)
                .await
                .map_err(DaemonError::from)?;
        inner.apply(changes);
        inner.persist_and_broadcast()?;
        drop(inner);
        Response::ok(pb::RequestMfaCodeResponse {
            code: resp.data.and_then(|d| d.result).unwrap_or_default(),
            ..Default::default()
        })
    }

    async fn verify_mfa(
        &self, _ctx: RequestContext, request: ServiceRequest<'_, pb::VerifyMfaRequest>,
    ) -> ServiceResult<pb::VerifyMfaResponse> {
        let login_scene = nonempty_or(request.login_scene, "login");
        let mfa_type = request.mfa_type.to_string();
        let account = request.account.to_string();
        let code = request.code.map(ToOwned::to_owned);
        let password = request.password.map(ToOwned::to_owned);
        let mut inner = self.inner.lock().await;
        inner.require_configured()?;
        let is_v1 = inner.is_v1();
        let (resp, changes) = if is_v1 {
            rustylink_core::auth::v1_mfa_verify(
                &inner.ctx,
                login_scene,
                mfa_type,
                account,
                code,
                password,
            )
            .await
            .map_err(DaemonError::from)?
        } else {
            rustylink_core::auth::verify_mfa(
                &inner.ctx,
                login_scene,
                mfa_type,
                account,
                code,
                password,
            )
            .await
            .map_err(DaemonError::from)?
        };
        inner.apply(changes);
        inner.apply_login_outcome(resp.data.as_ref());
        inner.post_login().await;
        inner.persist_and_broadcast()?;
        let session = inner.state.to_session();
        drop(inner);
        Response::ok(pb::VerifyMfaResponse {
            session: session.into(),
            ..Default::default()
        })
    }

    async fn skip_pending_challenge(
        &self, _ctx: RequestContext, request: ServiceRequest<'_, pb::SkipPendingChallengeRequest>,
    ) -> ServiceResult<pb::SkipPendingChallengeResponse> {
        let login_scene = nonempty_or(request.login_scene, "login");
        let mut inner = self.inner.lock().await;
        inner.require_configured()?;
        let (resp, changes) =
            rustylink_core::auth::v1_login_skip(&inner.ctx, login_scene, String::new())
                .await
                .map_err(DaemonError::from)?;
        inner.apply(changes);
        inner.apply_login_outcome(resp.data.as_ref());
        inner.post_login().await;
        inner.persist_and_broadcast()?;
        let session = inner.state.to_session();
        drop(inner);
        Response::ok(pb::SkipPendingChallengeResponse {
            session: session.into(),
            ..Default::default()
        })
    }

    async fn list_third_party_providers(
        &self, _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::ListThirdPartyProvidersRequest>,
    ) -> ServiceResult<pb::ListThirdPartyProvidersResponse> {
        let mut inner = self.inner.lock().await;
        inner.require_configured()?;
        let (links, changes) = rustylink_core::auth::third_party_login_links(&inner.ctx)
            .await
            .map_err(DaemonError::from)?;
        inner.apply(changes);
        inner.persist_and_broadcast()?;
        drop(inner);
        let providers = links
            .response
            .data
            .unwrap_or_default()
            .into_iter()
            .map(|info| pb::ThirdPartyProvider {
                alias_key: info.alias_key.unwrap_or_default(),
                name: info.name.unwrap_or_default(),
                login_url: info.login_url.or(info.url).unwrap_or_default(),
                is_custom: info.is_custom.unwrap_or(false),
                supports_poll: info.token.is_some(),
                ..Default::default()
            })
            .collect();
        Response::ok(pb::ListThirdPartyProvidersResponse {
            providers,
            ..Default::default()
        })
    }

    async fn start_third_party_login(
        &self, _ctx: RequestContext, request: ServiceRequest<'_, pb::StartThirdPartyLoginRequest>,
    ) -> ServiceResult<pb::StartThirdPartyLoginResponse> {
        let alias_key = request.alias_key.to_string();
        let redirect_uri = request.redirect_uri.to_string();
        let mut inner = self.inner.lock().await;
        inner.require_configured()?;
        let (links, link_changes) = rustylink_core::auth::third_party_login_links(&inner.ctx)
            .await
            .map_err(DaemonError::from)?;
        inner.apply(link_changes);
        let auth_url = links
            .response
            .data
            .unwrap_or_default()
            .into_iter()
            .find(|info| info.alias_key.as_deref() == Some(alias_key.as_str()))
            .and_then(|info| info.login_url.or(info.url))
            .ok_or_else(|| {
                DaemonError::from(RpcFault::InvalidArgument {
                    message: format!("unknown third-party provider alias `{alias_key}`"),
                })
            })?;
        let (url, changes) = rustylink_core::auth::start_oauth(
            &inner.ctx,
            &auth_url,
            alias_key,
            None,
            &redirect_uri,
        )
        .map_err(DaemonError::from)?;
        let state_value = inner.state.oauth_state_value().unwrap_or_default();
        inner.apply(changes);
        inner.persist_and_broadcast()?;
        drop(inner);
        Response::ok(pb::StartThirdPartyLoginResponse {
            auth_url: url,
            state: state_value,
            polling: false,
            ..Default::default()
        })
    }

    async fn complete_third_party_login(
        &self, _ctx: RequestContext,
        request: ServiceRequest<'_, pb::CompleteThirdPartyLoginRequest>,
    ) -> ServiceResult<pb::CompleteThirdPartyLoginResponse> {
        let alias_key = request.alias_key.to_string();
        let code = request.code.to_string();
        let state = request.state.to_string();
        let mut inner = self.inner.lock().await;
        inner.require_configured()?;
        let (_resp, changes) =
            rustylink_core::auth::oauth_callback(&inner.ctx, Some(alias_key), code, Some(state))
                .await
                .map_err(DaemonError::from)?;
        inner.apply(changes);
        // Promote to Authenticated (OAuth callback succeeded).
        inner.state.complete_login();
        inner.post_login().await;
        inner.persist_and_broadcast()?;
        let session = inner.state.to_session();
        drop(inner);
        Response::ok(pb::CompleteThirdPartyLoginResponse {
            session: session.into(),
            ..Default::default()
        })
    }

    async fn logout(
        &self, _ctx: RequestContext, request: ServiceRequest<'_, pb::LogoutRequest>,
    ) -> ServiceResult<pb::LogoutResponse> {
        let logout_all = request.logout_all;
        let mut inner = self.inner.lock().await;
        inner.require_configured()?;
        let (_resp, changes) = rustylink_core::auth::logout(&inner.ctx, logout_all)
            .await
            .map_err(DaemonError::from)?;
        inner.apply(changes);
        inner.persist_and_broadcast()?;
        let session = inner.state.to_session();
        drop(inner);
        Response::ok(pb::LogoutResponse {
            session: session.into(),
            ..Default::default()
        })
    }

    // ----- tunnel -----

    async fn get_tunnel(
        &self, _ctx: RequestContext, _request: ServiceRequest<'_, pb::GetTunnelRequest>,
    ) -> ServiceResult<pb::GetTunnelResponse> {
        let tunnel = self.inner.lock().await.state.to_tunnel();
        Response::ok(pb::GetTunnelResponse {
            tunnel: tunnel.into(),
            ..Default::default()
        })
    }

    async fn connect_tunnel(
        &self, _ctx: RequestContext, request: ServiceRequest<'_, pb::ConnectTunnelRequest>,
    ) -> ServiceResult<pb::ConnectTunnelResponse> {
        let tunnel = self
            .connect_tunnel(VpnRequest::from(request.to_owned_message()))
            .await?;
        Response::ok(pb::ConnectTunnelResponse {
            tunnel: tunnel.into(),
            ..Default::default()
        })
    }

    async fn disconnect_tunnel(
        &self, _ctx: RequestContext, _request: ServiceRequest<'_, pb::DisconnectTunnelRequest>,
    ) -> ServiceResult<pb::DisconnectTunnelResponse> {
        let tunnel = self.disconnect_tunnel().await?;
        Response::ok(pb::DisconnectTunnelResponse {
            tunnel: tunnel.into(),
            ..Default::default()
        })
    }

    async fn list_vpn_locations(
        &self, _ctx: RequestContext, _request: ServiceRequest<'_, pb::ListVpnLocationsRequest>,
    ) -> ServiceResult<pb::ListVpnLocationsResponse> {
        let mut inner = self.inner.lock().await;
        inner.require_authenticated()?;
        let (resp, changes) = rustylink_core::vpn::vpn_locations(&inner.ctx)
            .await
            .map_err(DaemonError::from)?;
        inner.apply(changes);
        inner.persist_and_broadcast()?;
        drop(inner);
        let locations = resp
            .data
            .unwrap_or_default()
            .into_iter()
            .map(project_vpn_location)
            .collect();
        Response::ok(pb::ListVpnLocationsResponse {
            locations,
            ..Default::default()
        })
    }

    // ----- profile + configuration -----

    async fn get_user_info(
        &self, _ctx: RequestContext, _request: ServiceRequest<'_, pb::GetUserInfoRequest>,
    ) -> ServiceResult<pb::GetUserInfoResponse> {
        let mut inner = self.inner.lock().await;
        inner.require_authenticated()?;
        let (resp, changes) = rustylink_core::vpn::user_info(&inner.ctx)
            .await
            .map_err(DaemonError::from)?;
        inner.apply(changes);
        inner.persist_and_broadcast()?;
        drop(inner);
        Response::ok(pb::GetUserInfoResponse {
            user_info: project_user_info(resp.data).into(),
            ..Default::default()
        })
    }

    async fn get_configuration(
        &self, _ctx: RequestContext, _request: ServiceRequest<'_, pb::GetConfigurationRequest>,
    ) -> ServiceResult<pb::GetConfigurationResponse> {
        let configuration = self.inner.lock().await.state.to_configuration();
        Response::ok(pb::GetConfigurationResponse {
            configuration: configuration.into(),
            ..Default::default()
        })
    }

    async fn update_configuration(
        &self, _ctx: RequestContext, request: ServiceRequest<'_, pb::UpdateConfigurationRequest>,
    ) -> ServiceResult<pb::UpdateConfigurationResponse> {
        // Without a field mask we treat each present field as authoritative.
        let owned = request.to_owned_message();
        let config = owned.configuration;
        let outbound_name =
            config
                .outbound_interface
                .selector
                .as_ref()
                .map(|selector| match selector {
                    pb::outbound_interface::Selector::Name(name) if !name.is_empty() => {
                        Some(name.clone())
                    }
                    _ => None,
                });

        let mut inner = self.inner.lock().await;
        inner
            .state
            .set_auto_reconnect_on_start(config.auto_reconnect_on_start);
        if let Some(name) = outbound_name {
            inner.state.set_outbound_interface_name(name);
            let options = ApiClientOptions {
                outbound_interface: inner.state.outbound_interface_name(),
            };
            inner.ctx.rebuild_http(options).map_err(DaemonError::from)?;
        }
        inner.persist_and_broadcast()?;
        let configuration = inner.state.to_configuration();
        drop(inner);
        Response::ok(pb::UpdateConfigurationResponse {
            configuration: configuration.into(),
            ..Default::default()
        })
    }
}

/// Return `value` if non-empty, otherwise the `default`.
fn nonempty_or(value: &str, default: &str) -> String {
    if value.is_empty() {
        default.to_string()
    } else {
        value.to_string()
    }
}
