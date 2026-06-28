//! Daemon auth + VPN coordinators — the imperative shell over the pure
//! [`rustylink_core::state`] machines.
//!
//! ## [`AuthMachine`]
//!
//! Owns the runtime resources the core can't (the shared cookie jar, HTTP pool,
//! device identity) plus the persisted tenant/signing/TOTP data, and the
//! current [`AuthState`].  Each method builds the right [`ApiClient`], calls a
//! pure [`rustylink_core::state::auth`] orchestration function, and applies the
//! returned state — surfacing errors synchronously (no out-of-band error field,
//! no `statig`).
//!
//! ## [`VpnMachine`]
//!
//! Owns the live [`TunnelSession`] and [`CancellationToken`]; its transition
//! methods delegate to the pure [`rustylink_core::state::vpn::VpnState`].

use jiff::Timestamp;
use rustylink_api::{
    ActivateRequest, ApiClient, ApiHooks, ClientIdentity, CookieJar, CookieStore,
    GetLoginSettingRequest, LogoutRequest, MatchEndpoint, ProtocolMode, SendableRequest,
    SigningConfig, SigningContext, TenantEndpoint,
};
pub use rustylink_core::state::{
    auth::{AuthState, LoginApiVersion},
    vpn::{ActiveTunnel, VpnRequest, VpnState},
};
use rustylink_core::{
    state::auth::{self as core_auth, DeviceLoginPending, OAuthPending},
    vpn::VpnConnectMode,
};
use rustylink_proto::proto::rustylink::daemon::v1 as pb;
use rustylink_tunnel::TunnelSession;
use tokio_util::sync::CancellationToken;

use crate::{
    error::{DaemonError, Result, RpcFault},
    persist::{PersistedCredentials, PersistedSigningConfig, PersistedTotpConfig, TenantConfig},
};

/// Auth coordinator: runtime resources + persisted auth data + the current
/// [`AuthState`].  The daemon reads its fields after each method to persist and
/// broadcast.
pub struct AuthMachine {
    /// Current pure auth state.
    pub(crate) state: AuthState,
    /// Shared HTTP connection pool (clone-cheap, `Arc`-backed).
    pub(crate) http_pool: rustylink_api::HttpClient,
    /// Device identity used for API request decoration.
    pub(crate) identity: ClientIdentity,
    /// Tenant connection parameters (set after activation).
    pub(crate) tenant: Option<TenantConfig>,
    /// Signing / HMAC configuration (set after activation).
    pub(crate) signing: Option<PersistedSigningConfig>,
    /// HTTP session cookies, shared as a live jar with every [`ApiClient`]
    /// built from this machine's hooks.  Also holds the `csrf-token`
    /// cookie.
    pub(crate) cookies: CookieJar,
    /// Knock token for API request decoration.
    pub(crate) knock_token: Option<String>,
    /// TOTP provisioning for auto-reconnect OTP generation.
    pub(crate) totp: Option<PersistedTotpConfig>,
    /// Which login API variant the tenant uses.
    pub(crate) login_api_version: LoginApiVersion,
    /// Pending OAuth flow parameters (set while in `AwaitingOauth`).
    pub(crate) oauth_pending: Option<OAuthPending>,
    /// Pending device login flow parameters (set while in
    /// `AwaitingDeviceLogin`).
    pub(crate) device_login_pending: Option<DeviceLoginPending>,
}

impl AuthMachine {
    // ----- state-changing operations (build client, call core, apply state) ---

    /// Tenant activation via the match server, then transition to `Configured`.
    pub async fn activate(
        &mut self, code: &str, base_url: Option<&str>, backup_url: Option<&str>,
        match_base_url: Option<&str>,
    ) -> Result<()> {
        let match_client = self.build_match_client(match_base_url);
        let response = ActivateRequest {
            code: code.to_owned(),
        }
        .send(&match_client)
        .await
        .map_err(|e| {
            DaemonError::from(rustylink_core::auth::Error::Api {
                source: Box::new(e),
            })
        })?;
        if let Some(data) = &response.data {
            let update = rustylink_core::auth::extract_activation_update(data);
            self.tenant = Some(TenantConfig {
                base_url: update
                    .base_url
                    .or_else(|| base_url.map(ToOwned::to_owned))
                    .unwrap_or_default(),
                backup_url: update
                    .backup_url
                    .or_else(|| backup_url.map(ToOwned::to_owned)),
                use_backup: update.use_backup.unwrap_or(false),
                name: update.name.unwrap_or_default(),
            });
            self.signing = Some(PersistedSigningConfig {
                enabled: false,
                activation_code: code.to_owned(),
                device_id: self.identity.device_id.clone(),
            });
        }
        self.state = AuthState::Configured;
        Ok(())
    }

    /// Best-effort detection of the tenant's login API version (post-activate).
    pub async fn refresh_login_api_version(&mut self) {
        let Some(client) = self.build_tenant_client() else {
            return;
        };
        if let Ok(setting) = GetLoginSettingRequest.send(&client).await
            && let Some(data) = setting.data.as_ref()
            && data.is_v1()
        {
            self.login_api_version = LoginApiVersion::V1;
        }
    }

    /// Username + password login.
    pub async fn login(
        &mut self, account: &str, password: &str, login_scene: &str, account_type: &str,
    ) -> Result<()> {
        let client = self.tenant_client()?;
        self.state = core_auth::login(
            &client,
            self.login_api_version,
            login_scene.to_owned(),
            account_type.to_owned(),
            account.to_owned(),
            password.to_owned(),
        )
        .await?;
        Ok(())
    }

    /// Request a login verification code (OTP). Stays in the current state.
    pub async fn send_login_code(
        &self, account: &str, login_type: &str, login_scene: &str, account_type: &str,
    ) -> Result<()> {
        let client = self.tenant_client()?;
        core_auth::send_login_code(
            &client,
            self.login_api_version,
            login_scene.to_owned(),
            account_type.to_owned(),
            login_type.to_owned(),
            account.to_owned(),
        )
        .await?;
        Ok(())
    }

    /// Verify a received login code.
    pub async fn verify_login_code(
        &mut self, account: &str, code: &str, login_type: &str, login_scene: &str,
        account_type: &str,
    ) -> Result<()> {
        let client = self.tenant_client()?;
        self.state = core_auth::verify_login_code(
            &client,
            self.login_api_version,
            login_scene.to_owned(),
            account_type.to_owned(),
            login_type.to_owned(),
            account.to_owned(),
            code.to_owned(),
        )
        .await?;
        Ok(())
    }

    /// Send an MFA challenge code. Stays in the current state.
    pub async fn send_mfa_code(
        &self, mfa_type: &str, account: &str, login_scene: &str,
    ) -> Result<()> {
        let client = self.tenant_client()?;
        core_auth::send_mfa_code(
            &client,
            self.login_api_version,
            login_scene.to_owned(),
            mfa_type.to_owned(),
            account.to_owned(),
        )
        .await?;
        Ok(())
    }

    /// Verify an MFA challenge.
    pub async fn verify_mfa(
        &mut self, mfa_type: &str, account: &str, code: Option<&str>, password: Option<&str>,
        login_scene: &str,
    ) -> Result<()> {
        let client = self.tenant_client()?;
        self.state = core_auth::verify_mfa(
            &client,
            self.login_api_version,
            login_scene.to_owned(),
            mfa_type.to_owned(),
            account.to_owned(),
            code.map(ToOwned::to_owned),
            password.map(ToOwned::to_owned),
        )
        .await?;
        Ok(())
    }

    /// Skip a skippable MFA challenge.
    pub async fn skip_challenge(&mut self, login_scene: &str) -> Result<()> {
        let client = self.tenant_client()?;
        self.state = core_auth::skip_challenge(&client, login_scene.to_owned()).await?;
        Ok(())
    }

    /// Begin a third-party OAuth login flow.
    pub async fn start_oauth(&mut self, alias_key: &str) -> Result<()> {
        let client = self.tenant_client()?;
        self.oauth_pending = Some(core_auth::start_oauth(&client, alias_key).await?);
        self.state = AuthState::AwaitingOauth;
        Ok(())
    }

    /// Complete an OAuth login with the authorization code.
    pub async fn complete_oauth(&mut self, code: &str, state: &str) -> Result<()> {
        let pending = self.oauth_pending.take().ok_or_else(|| {
            DaemonError::from(RpcFault::InvalidArgument {
                message: "no pending OAuth flow".into(),
            })
        })?;
        let client = self.tenant_client()?;
        core_auth::complete_oauth(&client, &pending, code.to_owned(), state.to_owned()).await?;
        self.state = AuthState::Authenticated;
        Ok(())
    }

    /// Begin a device/QR login flow.
    pub async fn start_device_login(&mut self, alias_key: &str) -> Result<()> {
        let client = self.tenant_client()?;
        self.device_login_pending = Some(core_auth::start_device_login(&client, alias_key).await?);
        self.state = AuthState::AwaitingDeviceLogin;
        Ok(())
    }

    /// Complete a device login (the service polled `token/check` to success).
    pub fn complete_device_login(&mut self) {
        self.device_login_pending = None;
        self.state = AuthState::Authenticated;
    }

    /// Log out: best-effort server logout, then clear the local session and
    /// fall back to `Configured`.
    pub async fn logout(&mut self, logout_all: bool) {
        if let Some(client) = self.build_tenant_client()
            && let Err(error) = (LogoutRequest { logout_all }).send(&client).await
        {
            tracing::debug!(
                %error,
                "server-side logout failed during best-effort logout; proceeding locally"
            );
        }
        self.clear_session().await;
        self.oauth_pending = None;
        self.device_login_pending = None;
        self.state = AuthState::Configured;
    }

    /// Restore the session state at startup from already-loaded credentials.
    ///
    /// Credentials are only persisted for an authenticated session, so a tenant
    /// with session cookies → `Authenticated`; a tenant without cookies →
    /// `Configured`; no tenant → stays `Unconfigured`.
    pub async fn restore_session(&mut self) {
        if self.tenant.is_none() {
            return;
        }
        self.state = if self.cookies.is_empty().await {
            AuthState::Configured
        } else {
            AuthState::Authenticated
        };
    }

    /// Store the TOTP provisioning config after a successful fetch.
    pub fn set_totp(&mut self, config: Option<PersistedTotpConfig>) {
        self.totp = config;
    }

    // ----- client construction (runtime concern, stays in the daemon) -------

    /// Build an [`ApiClient`] for the tenant, or a fault if not yet configured.
    fn tenant_client(&self) -> Result<ApiClient> {
        self.build_tenant_client()
            .ok_or_else(|| DaemonError::from(RpcFault::NotConfigured))
    }

    /// Build an [`ApiClient`] pointing at the tenant's base URL with the
    /// current signing/cookie state.  Returns `None` before activation.
    pub fn build_tenant_client(&self) -> Option<ApiClient> {
        let tenant = self.tenant.as_ref()?;
        let endpoint = TenantEndpoint::new(&tenant.base_url).ok()?;
        Some(ApiClient::for_endpoint(
            &endpoint,
            self.http_pool.clone(),
            self.build_hooks(),
        ))
    }

    /// Build an [`ApiClient`] pointing at the match server (for activation).
    pub fn build_match_client(&self, match_url: Option<&str>) -> ApiClient {
        let endpoint = match_url.map_or_else(MatchEndpoint::default, |url| {
            MatchEndpoint::new(url).unwrap_or_default()
        });
        ApiClient::for_endpoint(&endpoint, self.http_pool.clone(), self.build_hooks())
    }

    pub(crate) fn build_hooks(&self) -> ApiHooks {
        let signing_config = self
            .signing
            .as_ref()
            .map(|s| SigningConfig {
                enabled: s.enabled,
                activation_code: Some(s.activation_code.clone()),
                device_id: Some(s.device_id.clone()),
                ..Default::default()
            })
            .unwrap_or_default();

        ApiHooks {
            identity: self.identity.clone(),
            cookies: self.cookies.clone(),
            knock_token: self.knock_token.clone(),
            signer: SigningContext::new(signing_config),
        }
    }

    /// Clear session-specific data (cookies, tokens), keeping tenant + signing
    /// config intact.
    async fn clear_session(&mut self) {
        self.cookies.clear().await;
        self.knock_token = None;
        self.totp = None;
    }

    // ----- projections / persistence snapshots ------------------------------

    /// Project the current auth state to an RPC [`Session`](pb::Session).
    #[must_use]
    pub fn to_session_proto(&self) -> pb::Session {
        let status = match self.state {
            AuthState::Unconfigured => pb::session::State::Unconfigured,
            AuthState::Configured => pb::session::State::Configured,
            AuthState::AwaitingOtp { .. } => pb::session::State::AwaitingOtp,
            AuthState::AwaitingMfa { .. } => pb::session::State::AwaitingMfa,
            AuthState::AwaitingOauth => pb::session::State::AwaitingOauth,
            AuthState::AwaitingDeviceLogin => pb::session::State::AwaitingDeviceLogin,
            AuthState::Authenticated => pb::session::State::Authenticated,
        };
        let mut session = pb::Session {
            state: status.into(),
            tenant_name: self
                .tenant
                .as_ref()
                .map(|t| t.name.clone())
                .unwrap_or_default(),
            base_url: self
                .tenant
                .as_ref()
                .map(|t| t.base_url.clone())
                .unwrap_or_default(),
            ..Default::default()
        };
        match &self.state {
            AuthState::AwaitingOtp {
                masked_target,
                login_type,
            } => {
                session.otp_challenge = pb::OtpChallenge {
                    masked_target: masked_target.clone(),
                    login_type: pb::LoginCodeType::from(login_type.as_str()).into(),
                    ..Default::default()
                }
                .into();
            }
            AuthState::AwaitingMfa {
                mfa_type,
                auth_list,
                can_skip,
                masked_mobile,
                masked_email,
            } => {
                session.mfa_challenge = pb::MfaChallenge {
                    mfa_type: mfa_type.clone(),
                    auth_list: auth_list.clone(),
                    can_skip: *can_skip,
                    masked_mobile: masked_mobile.clone(),
                    masked_email: masked_email.clone(),
                    ..Default::default()
                }
                .into();
            }
            AuthState::AwaitingOauth => {
                if let Some(pending) = &self.oauth_pending {
                    session.oauth_challenge = pb::OauthChallenge {
                        alias_key: pending.alias_key.clone(),
                        state: pending.oauth_state.clone(),
                        poll_token: pending.poll_token.clone(),
                        ..Default::default()
                    }
                    .into();
                }
            }
            AuthState::AwaitingDeviceLogin => {
                if let Some(pending) = &self.device_login_pending {
                    session.device_login_challenge = pb::DeviceLoginChallenge {
                        login_url: pending.login_url.clone(),
                        alias_key: pending.alias_key.clone(),
                        poll_token: pending.poll_token.clone(),
                        ..Default::default()
                    }
                    .into();
                }
            }
            AuthState::Unconfigured | AuthState::Configured | AuthState::Authenticated => {}
        }
        session
    }

    /// Snapshot the current session as [`PersistedCredentials`].
    ///
    /// Returns `Some` only when the machine has a tenant + signing config.
    pub async fn to_credentials(&self) -> Option<PersistedCredentials> {
        let tenant = self.tenant.clone()?;
        let signing = self.signing.clone()?;
        Some(PersistedCredentials {
            tenant,
            signing,
            cookies: self.cookies.values().await,
            knock_token: self.knock_token.clone(),
            totp: self.totp.clone(),
            login_api_version: self.login_api_version,
            last_vpn_request: None,
            saved_at: Timestamp::now().to_string(),
        })
    }

    /// Snapshot credentials, injecting the given VPN request for persistence.
    pub async fn to_credentials_with_vpn(
        &self, vpn_request: Option<crate::persist::PersistedVpnRequest>,
    ) -> Option<PersistedCredentials> {
        let mut creds = self.to_credentials().await?;
        creds.last_vpn_request = vpn_request;
        Some(creds)
    }

    /// Restore an `AuthMachine` from persisted credentials.  Starts in
    /// `Unconfigured`; the daemon calls
    /// [`restore_session`](Self::restore_session) to place it into the
    /// right state.
    #[must_use]
    pub fn restore_from_credentials(
        creds: PersistedCredentials, http_pool: rustylink_api::HttpClient, identity: ClientIdentity,
    ) -> Self {
        Self {
            state: AuthState::Unconfigured,
            http_pool,
            identity,
            tenant: Some(creds.tenant),
            signing: Some(creds.signing),
            cookies: CookieStore::with_values(creds.cookies),
            knock_token: creds.knock_token,
            totp: creds.totp,
            login_api_version: creds.login_api_version,
            oauth_pending: None,
            device_login_pending: None,
        }
    }
}

/// VPN connection machine: the pure [`VpnState`] plus the live OS resources.
///
/// Transition methods delegate to [`VpnState`]'s pure transitions and assign
/// the result in one place; the live [`TunnelSession`] / [`CancellationToken`]
/// are runtime-only and never leak into `core`.
pub struct VpnMachine {
    pub(crate) state: VpnState,
    pub(crate) api_client: ApiClient,
    /// The live `WireGuard` tunnel session (present only in `Connected`).
    pub(crate) tunnel_session: Option<TunnelSession>,
    /// Cancellation token for the active connect/supervise task.
    pub(crate) cancel_token: CancellationToken,
}

impl VpnMachine {
    /// Create a new VPN machine in `Disconnected` state.
    #[must_use]
    pub fn new(api_client: ApiClient) -> Self {
        Self {
            state: VpnState::Disconnected,
            api_client,
            tunnel_session: None,
            cancel_token: CancellationToken::new(),
        }
    }

    // ------- state queries -------

    /// True when a connect may start (no active or in-flight tunnel).
    #[must_use]
    pub const fn can_connect(&self) -> bool {
        self.state.can_connect()
    }

    /// Extract the current VPN request in persisted form (if any).
    #[must_use]
    pub fn current_persisted_request(&self) -> Option<crate::persist::PersistedVpnRequest> {
        self.state
            .current_request()
            .map(|request| crate::persist::PersistedVpnRequest {
                mode: request.mode.to_string(),
                location_id: request.location_id,
                protocol_mode: request.protocol_mode,
                reconnect: request.reconnect,
            })
    }

    // ------- state transitions (delegate to pure `VpnState`) -------

    /// Transition to `Connecting` with a new request (resets the cancel token).
    pub fn set_connecting(&mut self, request: VpnRequest) {
        self.cancel_token = CancellationToken::new();
        self.state = VpnState::into_connecting(request);
    }

    /// Transition to `Configuring` (preserves current request).
    pub fn set_configuring(&mut self) {
        self.transition(VpnState::into_configuring);
    }

    /// Transition to `Connected` with tunnel info.
    pub fn set_connected(&mut self, tunnel_info: ActiveTunnel) {
        self.transition(|state| state.into_connected(tunnel_info));
    }

    /// Transition to `Reconnecting`, incrementing the attempt counter.
    pub fn set_reconnecting(&mut self) {
        self.transition(VpnState::into_reconnecting);
    }

    /// Transition to `Failed` with an error message.
    pub fn set_failed(&mut self, error: String) {
        self.transition(|state| state.into_failed(error));
    }

    /// Transition to `Disconnecting`.
    pub fn set_disconnecting(&mut self) {
        self.transition(VpnState::into_disconnecting);
    }

    /// Transition to `Disconnected`, dropping any tunnel session.
    pub fn set_disconnected(&mut self) {
        self.tunnel_session = None;
        self.state = VpnState::Disconnected;
    }

    /// Apply a pure transition to the current state.
    fn transition(&mut self, f: impl FnOnce(VpnState) -> VpnState) {
        let previous = std::mem::replace(&mut self.state, VpnState::Disconnected);
        self.state = f(previous);
    }

    // ------- proto projection -------

    /// Project the current VPN state to an RPC [`Tunnel`](pb::Tunnel) message.
    #[must_use]
    pub fn to_tunnel_proto(&self) -> pb::Tunnel {
        match &self.state {
            VpnState::Disconnected => pb::Tunnel {
                state: pb::tunnel::State::Disconnected.into(),
                ..Default::default()
            },
            VpnState::Connecting { request, .. } => pb::Tunnel {
                state: pb::tunnel::State::Connecting.into(),
                mode: vpn_mode_to_proto(request.mode).into(),
                protocol_mode: protocol_mode_to_proto(request.protocol_mode).into(),
                ..Default::default()
            },
            VpnState::Configuring { request, .. } => pb::Tunnel {
                state: pb::tunnel::State::Configuring.into(),
                mode: vpn_mode_to_proto(request.mode).into(),
                protocol_mode: protocol_mode_to_proto(request.protocol_mode).into(),
                ..Default::default()
            },
            VpnState::Connected {
                request,
                tunnel_info,
                ..
            } => pb::Tunnel {
                state: pb::tunnel::State::Connected.into(),
                mode: vpn_mode_to_proto(request.mode).into(),
                protocol_mode: protocol_mode_to_proto(tunnel_info.protocol_mode).into(),
                dot_id: tunnel_info.dot_id,
                dot_name: tunnel_info.dot_name.clone(),
                endpoint: tunnel_info.endpoint.clone(),
                assigned_ip: tunnel_info.assigned_ip.clone(),
                ..Default::default()
            },
            VpnState::Reconnecting {
                request, attempts, ..
            } => pb::Tunnel {
                state: pb::tunnel::State::Reconnecting.into(),
                mode: vpn_mode_to_proto(request.mode).into(),
                protocol_mode: protocol_mode_to_proto(request.protocol_mode).into(),
                reconnect_attempts: *attempts,
                ..Default::default()
            },
            VpnState::Failed {
                request,
                error,
                attempts,
                ..
            } => pb::Tunnel {
                state: pb::tunnel::State::Failed.into(),
                mode: vpn_mode_to_proto(request.mode).into(),
                protocol_mode: protocol_mode_to_proto(request.protocol_mode).into(),
                error: error.clone(),
                reconnect_attempts: *attempts,
                ..Default::default()
            },
            VpnState::Disconnecting { request, .. } => pb::Tunnel {
                state: pb::tunnel::State::Disconnecting.into(),
                mode: vpn_mode_to_proto(request.mode).into(),
                protocol_mode: protocol_mode_to_proto(request.protocol_mode).into(),
                ..Default::default()
            },
        }
    }
}

/// Map a [`VpnConnectMode`] to the proto [`VpnMode`](pb::VpnMode).
fn vpn_mode_to_proto(mode: VpnConnectMode) -> pb::VpnMode {
    match mode {
        VpnConnectMode::Full => pb::VpnMode::Full,
        VpnConnectMode::Split => pb::VpnMode::Split,
    }
}

/// Map the api [`ProtocolMode`] to the proto
/// [`ProtocolMode`](pb::ProtocolMode).
fn protocol_mode_to_proto(mode: ProtocolMode) -> pb::ProtocolMode {
    match mode {
        ProtocolMode::Udp => pb::ProtocolMode::Udp,
        ProtocolMode::FeilianTcp => pb::ProtocolMode::Tcp,
    }
}

/// Build a [`VpnRequest`] from a `ConnectTunnel` RPC request.
///
/// A free function rather than a `From` impl because [`VpnRequest`] is a
/// foreign (core) type.
#[must_use]
pub fn vpn_request_from_proto(
    mode: Option<pb::VpnMode>, protocol_mode: Option<pb::ProtocolMode>, location_id: Option<i32>,
    otp: Option<&str>, reconnect: bool,
) -> VpnRequest {
    let mode = match mode {
        Some(pb::VpnMode::Split) => VpnConnectMode::Split,
        _ => VpnConnectMode::Full,
    };
    VpnRequest {
        mode,
        location_id: location_id.filter(|id| *id > 0),
        otp: otp.filter(|s| !s.is_empty()).map(ToOwned::to_owned),
        reconnect,
        protocol_mode: protocol_mode_to_api(protocol_mode),
    }
}

/// Translate the proto `ProtocolMode` (UNSPECIFIED=0/UDP=1/TCP=2) to the api
/// enum. Unspecified or unknown wire values fall back to UDP (the user-facing
/// dropdown never offers `Unspecified`, but proto3 default-zero clients land
/// here).
fn protocol_mode_to_api(mode: Option<pb::ProtocolMode>) -> ProtocolMode {
    match mode {
        Some(pb::ProtocolMode::Tcp) => ProtocolMode::FeilianTcp,
        Some(pb::ProtocolMode::Udp | pb::ProtocolMode::Unspecified) | None => ProtocolMode::Udp,
    }
}
