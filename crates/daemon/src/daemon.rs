//! Daemon core: the single serialized owner of `DaemonState` + `AppContext`.
//!
//! Realizes the plan's single-owner intent (A5/A7) via
//! `Arc<Mutex<DaemonInner>>` rather than an mpsc command actor — RPC handlers
//! and the supervisor lock the same inner, mutate, persist atomically, and
//! broadcast a fresh snapshot over a `tokio::watch` channel. Core functions are
//! pure (`&AppContext` → `(result, Vec<StateChange>)`); the daemon applies the
//! changes.

use std::{path::PathBuf, sync::Arc, time::Instant};

use rustylink_api::{
    ApiClientOptions, LoginSetting, LoginV2Next, LoginV2Result, UserInfo, VpnConnResponse, VpnDot,
    VpnReportRequest,
};
use rustylink_core::{
    AppContext, StateChange,
    vpn::{VpnConfigRequest, VpnConfigResult, VpnConnectMode},
};
use rustylink_proto::proto::rustylink::daemon::v1 as pb;
use rustylink_tunnel::{
    LocalTunnelParams, ReconnectController, ReconnectDecision, ReconnectEvent, ReconnectPolicy,
    TunnelConfig, TunnelSession,
};
use snafu::prelude::*;
use tokio::{
    sync::{Mutex, watch},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

use crate::{
    error::{
        ContextSnafu, InvalidArgumentSnafu, NotConfiguredSnafu, PersistSnafu, Result, TunnelSnafu,
    },
    state::{
        ActiveTunnel, AuthPhase, DaemonState, LoginApi, OutboundSelector, PendingChallenge,
        VpnPhase, VpnRequest,
    },
    supervisor::{self, SupervisorOutcome},
};

/// The serialized inner state owned by the daemon.
struct DaemonInner {
    state: DaemonState,
    ctx: AppContext,
    state_path: PathBuf,
    watch_tx: watch::Sender<Arc<DaemonState>>,
    /// Cancellation token for the active connect/supervise task, if any.
    tunnel_cancel: Option<CancellationToken>,
    /// Handle to the active connect/supervise task, if any.
    tunnel_task: Option<JoinHandle<()>>,
}

/// Cloneable handle to the daemon core.
#[derive(Clone)]
pub struct Daemon {
    inner: Arc<Mutex<DaemonInner>>,
    watch_rx: watch::Receiver<Arc<DaemonState>>,
    started_at: Instant,
}

/// Parameters for a `/vpn/report` call, bundled to keep helper signatures small.
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
            outbound_interface: state
                .config
                .outbound_interface
                .name()
                .map(ToOwned::to_owned),
        };
        let ctx = AppContext::new(state.core.clone(), api_options).context(ContextSnafu)?;
        let (watch_tx, watch_rx) = watch::channel(Arc::new(state.clone()));
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
    pub fn subscribe(&self) -> watch::Receiver<Arc<DaemonState>> {
        self.watch_rx.clone()
    }

    #[must_use]
    pub fn uptime_seconds(&self) -> i64 {
        i64::try_from(self.started_at.elapsed().as_secs()).unwrap_or(i64::MAX)
    }

    // -----------------------------------------------------------------------
    // Read RPCs
    // -----------------------------------------------------------------------

    pub async fn session(&self) -> pb::Session {
        self.inner.lock().await.state.to_session()
    }

    pub async fn tunnel(&self) -> pb::Tunnel {
        self.inner.lock().await.state.to_tunnel()
    }

    pub async fn configuration(&self) -> pb::Configuration {
        self.inner.lock().await.state.to_configuration()
    }

    // -----------------------------------------------------------------------
    // Activation + login-API detection
    // -----------------------------------------------------------------------

    pub async fn activate(
        &self, code: Option<String>, base_url: Option<String>, backup_url: Option<String>,
        match_base_url: Option<String>,
    ) -> Result<pb::Session> {
        let mut inner = self.inner.lock().await;
        let (_resp, changes) =
            rustylink_core::auth::activate(&inner.ctx, code, base_url, backup_url, match_base_url)
                .await?;
        inner.apply(changes);
        if inner.state.auth_phase == AuthPhase::Unconfigured {
            inner.state.auth_phase = AuthPhase::Configured;
        }
        // Auto-detect login API from /api/login/setting (best-effort).
        if let Ok((setting, setting_changes)) = rustylink_core::vpn::login_setting(&inner.ctx).await
        {
            inner.apply(setting_changes);
            let v1 = setting.data.as_ref().is_some_and(login_setting_is_v1);
            inner.state.login_api = Some(if v1 { LoginApi::V1 } else { LoginApi::Legacy });
        }
        inner.persist_and_broadcast()?;
        Ok(inner.state.to_session())
    }

    // -----------------------------------------------------------------------
    // Login (auto v1/legacy)
    // -----------------------------------------------------------------------

    pub async fn login(
        &self, login_scene: String, account_type: String, account: String, password: String,
    ) -> Result<pb::Session> {
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
            .await?
        } else {
            rustylink_core::auth::login_password(
                &inner.ctx,
                login_scene,
                account_type,
                account,
                password,
            )
            .await?
        };
        inner.apply(changes);
        inner.apply_login_outcome(resp.data.as_ref());
        inner.maybe_fetch_totp().await;
        inner.persist_and_broadcast()?;
        Ok(inner.state.to_session())
    }

    pub async fn request_login_code(
        &self, login_scene: String, account_type: String, login_type: String, account: String,
    ) -> Result<String> {
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
            .await?
        } else {
            rustylink_core::auth::send_code(
                &inner.ctx,
                login_scene,
                account_type,
                login_type,
                account,
            )
            .await?
        };
        inner.apply(changes);
        inner.persist_and_broadcast()?;
        drop(inner);
        Ok(resp.data.and_then(|d| d.result).unwrap_or_default())
    }

    pub async fn verify_login_code(
        &self, login_scene: String, account_type: String, login_type: String, account: String,
        code: String,
    ) -> Result<pb::Session> {
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
            .await?
        } else {
            rustylink_core::auth::verify_code(
                &inner.ctx,
                login_scene,
                account_type,
                login_type,
                account,
                code,
            )
            .await?
        };
        inner.apply(changes);
        inner.apply_login_outcome(resp.data.as_ref());
        inner.maybe_fetch_totp().await;
        inner.persist_and_broadcast()?;
        Ok(inner.state.to_session())
    }

    pub async fn request_mfa_code(
        &self, login_scene: String, mfa_type: String, account: String,
    ) -> Result<String> {
        let mut inner = self.inner.lock().await;
        inner.require_configured()?;
        // MFA code send only exists in the v1 flow.
        let (resp, changes) =
            rustylink_core::auth::v1_mfa_send(&inner.ctx, login_scene, mfa_type, account).await?;
        inner.apply(changes);
        inner.persist_and_broadcast()?;
        drop(inner);
        Ok(resp.data.and_then(|d| d.result).unwrap_or_default())
    }

    pub async fn verify_mfa(
        &self, login_scene: String, mfa_type: String, account: String, code: Option<String>,
        password: Option<String>,
    ) -> Result<pb::Session> {
        let mut inner = self.inner.lock().await;
        inner.require_configured()?;
        if code.is_none() && password.is_none() {
            return InvalidArgumentSnafu {
                message: "VerifyMfa requires either code or password",
            }
            .fail();
        }
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
            .await?
        } else {
            rustylink_core::auth::verify_mfa(
                &inner.ctx,
                login_scene,
                mfa_type,
                account,
                code,
                password,
            )
            .await?
        };
        inner.apply(changes);
        inner.apply_login_outcome(resp.data.as_ref());
        inner.maybe_fetch_totp().await;
        inner.persist_and_broadcast()?;
        Ok(inner.state.to_session())
    }

    pub async fn skip_pending_challenge(&self, login_scene: String) -> Result<pb::Session> {
        let mut inner = self.inner.lock().await;
        inner.require_configured()?;
        // Skip is a v1 concept; reuse v1_login_skip with the stored account is
        // not tracked, so we require the client to drive the account via login.
        let account = String::new();
        let (resp, changes) =
            rustylink_core::auth::v1_login_skip(&inner.ctx, login_scene, account).await?;
        inner.apply(changes);
        inner.apply_login_outcome(resp.data.as_ref());
        inner.persist_and_broadcast()?;
        Ok(inner.state.to_session())
    }

    // -----------------------------------------------------------------------
    // Third-party (OAuth) login
    // -----------------------------------------------------------------------

    pub async fn list_third_party_providers(&self) -> Result<Vec<pb::ThirdPartyProvider>> {
        let mut inner = self.inner.lock().await;
        inner.require_configured()?;
        let (links, changes) = rustylink_core::auth::third_party_login_links(&inner.ctx).await?;
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
        Ok(providers)
    }

    pub async fn start_third_party_login(
        &self, alias_key: String, redirect_uri: String,
    ) -> Result<pb::StartThirdPartyLoginResponse> {
        let mut inner = self.inner.lock().await;
        inner.require_configured()?;
        // Look up the provider's auth URL by alias.
        let (links, link_changes) =
            rustylink_core::auth::third_party_login_links(&inner.ctx).await?;
        inner.apply(link_changes);
        let auth_url = links
            .response
            .data
            .unwrap_or_default()
            .into_iter()
            .find(|info| info.alias_key.as_deref() == Some(alias_key.as_str()))
            .and_then(|info| info.login_url.or(info.url))
            .ok_or_else(|| {
                InvalidArgumentSnafu {
                    message: format!("unknown third-party provider alias `{alias_key}`"),
                }
                .build()
            })?;
        let (url, changes) = rustylink_core::auth::start_oauth(
            &inner.ctx,
            &auth_url,
            alias_key,
            None,
            &redirect_uri,
        )?;
        let state = inner.state.core.oauth.state.clone().unwrap_or_default();
        inner.apply(changes);
        inner.persist_and_broadcast()?;
        drop(inner);
        Ok(pb::StartThirdPartyLoginResponse {
            auth_url: url,
            state,
            polling: false,
            ..Default::default()
        })
    }

    pub async fn complete_third_party_login(
        &self, alias_key: String, code: String, state: String,
    ) -> Result<pb::Session> {
        let mut inner = self.inner.lock().await;
        inner.require_configured()?;
        let (_resp, changes) =
            rustylink_core::auth::oauth_callback(&inner.ctx, Some(alias_key), code, Some(state))
                .await?;
        inner.apply(changes);
        inner.state.auth_phase = AuthPhase::Authenticated;
        inner.state.pending_challenge = None;
        inner.maybe_fetch_totp().await;
        inner.persist_and_broadcast()?;
        Ok(inner.state.to_session())
    }

    pub async fn logout(&self, logout_all: bool) -> Result<pb::Session> {
        let mut inner = self.inner.lock().await;
        inner.require_configured()?;
        let (_resp, changes) = rustylink_core::auth::logout(&inner.ctx, logout_all).await?;
        inner.apply(changes);
        inner.persist_and_broadcast()?;
        Ok(inner.state.to_session())
    }

    // -----------------------------------------------------------------------
    // Profile + configuration
    // -----------------------------------------------------------------------

    pub async fn user_info(&self) -> Result<pb::UserInfo> {
        let mut inner = self.inner.lock().await;
        inner.require_authenticated()?;
        let (resp, changes) = rustylink_core::vpn::user_info(&inner.ctx).await?;
        inner.apply(changes);
        inner.persist_and_broadcast()?;
        drop(inner);
        Ok(project_user_info(resp.data))
    }

    pub async fn set_outbound_interface(&self, name: Option<String>) -> Result<pb::Configuration> {
        let mut inner = self.inner.lock().await;
        inner.state.config.outbound_interface =
            name.map_or(OutboundSelector::Auto, OutboundSelector::Name);
        let api_options = ApiClientOptions {
            outbound_interface: inner
                .state
                .config
                .outbound_interface
                .name()
                .map(ToOwned::to_owned),
        };
        inner.ctx.rebuild_http(api_options).context(ContextSnafu)?;
        inner.persist_and_broadcast()?;
        Ok(inner.state.to_configuration())
    }

    pub async fn set_auto_reconnect(&self, enabled: bool) -> Result<pb::Configuration> {
        let mut inner = self.inner.lock().await;
        inner.state.config.auto_reconnect_on_start = enabled;
        inner.persist_and_broadcast()?;
        Ok(inner.state.to_configuration())
    }

    // -----------------------------------------------------------------------
    // VPN reads
    // -----------------------------------------------------------------------

    pub async fn list_vpn_locations(&self) -> Result<Vec<pb::VpnLocation>> {
        let mut inner = self.inner.lock().await;
        inner.require_authenticated()?;
        let (resp, changes) = rustylink_core::vpn::vpn_locations(&inner.ctx).await?;
        inner.apply(changes);
        inner.persist_and_broadcast()?;
        drop(inner);
        Ok(resp
            .data
            .unwrap_or_default()
            .into_iter()
            .map(project_vpn_location)
            .collect())
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
            let resume = inner.state.config.auto_reconnect_on_start
                && inner.state.auth_phase == AuthPhase::Authenticated
                && inner.state.vpn.request.is_some();
            if !resume {
                return;
            }
            inner.state.vpn.request.clone()
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
        if matches!(
            inner.state.vpn.phase,
            VpnPhase::Connecting
                | VpnPhase::Configuring
                | VpnPhase::Connected
                | VpnPhase::Reconnecting
        ) {
            return InvalidArgumentSnafu {
                message: "tunnel is already connecting or connected; disconnect first",
            }
            .fail();
        }

        inner.state.vpn.phase = VpnPhase::Connecting;
        inner.state.vpn.request = Some(request.clone());
        inner.state.vpn.active = None;
        inner.state.vpn.reconnect_attempts = 0;
        inner.state.vpn.last_error = None;
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
            inner.state.vpn.phase = VpnPhase::Disconnecting;
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
        inner.state.vpn.phase = VpnPhase::Disconnected;
        inner.state.vpn.request = None;
        inner.state.vpn.active = None;
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
        self.vpn_update(|state| state.vpn.phase = VpnPhase::Configuring)
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

        let mut session = self.start_session(&config_result, &data, &local_params).await?;

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

    /// Build the tunnel config from a `/vpn/conn` result and bring the device up.
    async fn start_session(
        &self, config_result: &VpnConfigResult, data: &VpnConnResponse,
        local_params: &LocalTunnelParams,
    ) -> Result<TunnelSession> {
        let outbound_iface = {
            let inner = self.inner.lock().await;
            inner
                .state
                .config
                .outbound_interface
                .name()
                .map(ToOwned::to_owned)
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
            connected_at_unix: Some(jiff::Timestamp::now().as_second()),
            last_handshake_unix: None,
            protocol_mode: dot.protocol_mode,
        };
        self.vpn_update(|state| {
            state.vpn.phase = VpnPhase::Connected;
            state.vpn.active = Some(active);
            state.vpn.last_error = None;
        })
        .await
    }

    /// Run the supervisor over a live session with a periodic `/vpn/report`.
    async fn supervise(
        &self, session: &mut TunnelSession, ctx: &AppContext, report: &ReportParams,
        cancel: &CancellationToken,
    ) -> SupervisorOutcome {
        let outbound = {
            let inner = self.inner.lock().await;
            inner.state.config.outbound_interface.clone()
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
        if manual.is_some() {
            return manual;
        }
        let config = {
            let inner = self.inner.lock().await;
            inner.state.core.totp.clone()?
        };
        let now = u64::try_from(jiff::Timestamp::now().as_second()).unwrap_or(0);
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
                let _ = self
                    .vpn_update(|state| {
                        state.vpn.phase = VpnPhase::Reconnecting;
                        state.vpn.reconnect_attempts =
                            state.vpn.reconnect_attempts.saturating_add(1);
                    })
                    .await;
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
        let _ = self
            .vpn_update(|state| {
                state.vpn.phase = VpnPhase::Disconnected;
                state.vpn.request = None;
                state.vpn.active = None;
            })
            .await;
    }

    async fn mark_failed(&self, error: String) {
        let _ = self
            .vpn_update(|state| {
                state.vpn.phase = VpnPhase::Failed;
                state.vpn.active = None;
                state.vpn.last_error = Some(error);
            })
            .await;
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

    /// Mutate `DaemonState` under the lock, then persist + broadcast.
    async fn vpn_update(&self, f: impl FnOnce(&mut DaemonState)) -> Result<()> {
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
        if self.state.auth_phase == AuthPhase::Unconfigured {
            return NotConfiguredSnafu.fail();
        }
        Ok(())
    }

    fn require_authenticated(&self) -> Result<()> {
        if self.state.auth_phase == AuthPhase::Authenticated {
            Ok(())
        } else {
            crate::error::NotAuthenticatedSnafu.fail()
        }
    }

    fn is_v1(&self) -> bool {
        matches!(self.state.login_api, Some(LoginApi::V1))
    }

    /// Apply core state changes to `DaemonState`, then refresh the API context
    /// so subsequent calls see the new cookies/signing.
    fn apply(&mut self, changes: Vec<StateChange>) {
        for change in changes {
            match change {
                StateChange::TenantConfigured { tenant, signing } => {
                    self.state.core.tenant = tenant;
                    self.state.core.signing = signing;
                }
                StateChange::CookiesUpdated { cookies } => {
                    self.state.core.cookies = cookies;
                }
                StateChange::CsrfTokenUpdated { token } => {
                    self.state.core.csrf_token = token;
                }
                StateChange::KnockTokenUpdated { token } => {
                    self.state.core.knock_token = token;
                }
                StateChange::SigningConfigUpdated { config } => {
                    self.state.core.signing = config;
                }
                StateChange::LoginApiDetected { v1_login } => {
                    self.state.login_api = Some(if v1_login {
                        LoginApi::V1
                    } else {
                        LoginApi::Legacy
                    });
                }
                StateChange::LoginSuccess { .. } => {
                    self.state.auth_phase = AuthPhase::Authenticated;
                    self.state.pending_challenge = None;
                }
                StateChange::OtpChallengePending {
                    masked_target,
                    login_type,
                } => {
                    self.state.auth_phase = AuthPhase::Authenticating;
                    self.state.pending_challenge = Some(PendingChallenge::Otp {
                        masked_target,
                        login_type,
                    });
                }
                StateChange::MfaChallengePending {
                    mfa_type,
                    auth_list,
                    can_skip,
                } => {
                    self.state.auth_phase = AuthPhase::Authenticating;
                    self.state.pending_challenge = Some(PendingChallenge::Mfa {
                        mfa_type,
                        auth_list,
                        can_skip,
                    });
                }
                StateChange::OAuthStateSet {
                    alias_key,
                    state,
                    code_verifier,
                } => {
                    self.state.core.oauth.alias_key = Some(alias_key.clone());
                    self.state.core.oauth.state = Some(state.clone());
                    self.state.core.oauth.code_verifier = Some(code_verifier);
                    self.state.auth_phase = AuthPhase::Authenticating;
                    self.state.pending_challenge = Some(PendingChallenge::Oauth {
                        alias_key,
                        state,
                        poll_token: None,
                    });
                }
                StateChange::OAuthCleared => {
                    self.state.core.oauth = rustylink_core::OAuthState::default();
                }
                StateChange::SessionExpired => {
                    self.state.auth_phase = AuthPhase::Expired;
                }
                StateChange::LoggedOut => {
                    self.state.core.cookies = rustylink_api::SessionCookies::default();
                    self.state.core.csrf_token = None;
                    self.state.core.knock_token = None;
                    self.state.core.oauth = rustylink_core::OAuthState::default();
                    self.state.auth_phase = AuthPhase::Configured;
                    self.state.pending_challenge = None;
                }
                StateChange::TotpConfigFetched { config } => {
                    self.state.core.totp = Some(config);
                }
            }
        }
        self.ctx.refresh(&self.state.core);
    }

    /// Interpret a `LoginV2Result` to set the auth phase / pending challenge.
    fn apply_login_outcome(&mut self, result: Option<&LoginV2Result>) {
        if let Some(next) = result.and_then(|result| result.next.as_ref()) {
            self.state.auth_phase = AuthPhase::Authenticating;
            self.state.pending_challenge = Some(challenge_from_next(next));
        } else {
            self.state.auth_phase = AuthPhase::Authenticated;
            self.state.pending_challenge = None;
        }
    }

    /// After successful authentication, fetch and store the TOTP secret
    /// (best-effort — failures don't block login).
    async fn maybe_fetch_totp(&mut self) {
        if self.state.auth_phase != AuthPhase::Authenticated || self.state.core.totp.is_some() {
            return;
        }
        match rustylink_core::vpn::fetch_totp(&self.ctx).await {
            Ok((Some(config), changes)) => {
                self.apply(changes);
                self.state.core.totp = Some(config);
            }
            Ok((None, changes)) => self.apply(changes),
            Err(error) => {
                tracing::warn!(%error, "failed to fetch TOTP secret (non-fatal)");
            }
        }
    }

    fn persist_and_broadcast(&mut self) -> Result<()> {
        self.state.save(&self.state_path).context(PersistSnafu)?;
        let _ = self.watch_tx.send(Arc::new(self.state.clone()));
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Interpretation + projection helpers
// ---------------------------------------------------------------------------

fn login_setting_is_v1(setting: &LoginSetting) -> bool {
    setting.v1_login.unwrap_or(false)
}

fn challenge_from_next(next: &LoginV2Next) -> PendingChallenge {
    let action = next.action.clone().unwrap_or_default();
    if action.eq_ignore_ascii_case("mfa") {
        PendingChallenge::Mfa {
            mfa_type: action,
            auth_list: next.auth_list.clone().unwrap_or_default(),
            can_skip: next.can_skip.unwrap_or(false),
        }
    } else {
        let masked = next
            .mobile
            .clone()
            .or_else(|| next.email.clone())
            .unwrap_or_default();
        PendingChallenge::Otp {
            masked_target: masked,
            login_type: action,
        }
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
