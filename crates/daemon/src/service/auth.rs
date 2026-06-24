//! `AuthService` — RPC handlers for authentication-related operations.
//!
//! Wraps [`Daemon`] and implements the generated `AuthService` trait.  Each
//! handler extracts parameters from the proto request, calls the auth
//! coordinator (which runs the pure `rustylink_core::state::auth` flow and
//! surfaces errors directly), and projects the result back to a proto response.

use connectrpc::{RequestContext, Response, ServiceRequest, ServiceResult};
use rustylink_proto::proto::rustylink::daemon::{v1 as pb, v1::AuthService};

use crate::{
    daemon::{Daemon, DefaultOrExt as _},
    error::{DaemonError, RpcFault},
    state::AuthState,
};

/// Default `login_scene` for the corplink/FeiLian login flow.
///
/// Every Android login fragment hardcodes `"feilian"` (e.g.
/// `loginByPwd("feilian", …)`, `verifyCode("feilian", …)`); the server only
/// sends/verifies codes for a known scene, so this must match.
const DEFAULT_LOGIN_SCENE: &str = "feilian";

/// Wrapper around [`Daemon`] implementing the `AuthService` trait.
#[derive(Clone)]
pub struct AuthServiceImpl {
    daemon: Daemon,
}

impl AuthServiceImpl {
    #[must_use]
    pub fn new(daemon: Daemon) -> Self {
        Self { daemon }
    }

    /// Lock the inner, extract the current session proto.
    async fn current_session(&self) -> pb::Session {
        let inner = self.daemon.inner.lock().await;
        inner.auth.to_session_proto()
    }

    /// After a successful auth event, persist credentials if authenticated
    /// and broadcast.
    async fn maybe_persist_and_broadcast(&self) {
        let is_authenticated = {
            let inner = self.daemon.inner.lock().await;
            matches!(inner.auth.state, AuthState::Authenticated)
        };
        if is_authenticated {
            self.daemon.persist_credentials().await;
        }
    }
}

#[allow(refining_impl_trait_reachable)]
impl AuthService for AuthServiceImpl {
    async fn get_session(
        &self, _ctx: RequestContext, _request: ServiceRequest<'_, pb::GetSessionRequest>,
    ) -> ServiceResult<pb::GetSessionResponse> {
        let session = self.current_session().await;
        Response::ok(pb::GetSessionResponse {
            session: session.into(),
            ..Default::default()
        })
    }

    async fn activate(
        &self, _ctx: RequestContext, request: ServiceRequest<'_, pb::ActivateRequest>,
    ) -> ServiceResult<pb::ActivateResponse> {
        let code = request.code.map(ToOwned::to_owned).unwrap_or_default();
        let base_url = request.base_url.map(ToOwned::to_owned);
        let backup_url = request.backup_url.map(ToOwned::to_owned);
        let match_base_url = request.match_base_url.map(ToOwned::to_owned);
        {
            let mut inner = self.daemon.inner.lock().await;
            inner
                .auth
                .activate(
                    &code,
                    base_url.as_deref(),
                    backup_url.as_deref(),
                    match_base_url.as_deref(),
                )
                .await
        }?;
        // Activation succeeded; detect the login API version (best-effort).
        {
            let mut inner = self.daemon.inner.lock().await;
            inner.auth.refresh_login_api_version().await;
            drop(inner);
        }
        self.maybe_persist_and_broadcast().await;
        let session = self.current_session().await;
        Response::ok(pb::ActivateResponse {
            session: session.into(),
            ..Default::default()
        })
    }

    async fn login(
        &self, _ctx: RequestContext, request: ServiceRequest<'_, pb::LoginRequest>,
    ) -> ServiceResult<pb::LoginResponse> {
        self.daemon.require_configured().await?;
        let account = request.account.to_string();
        let password = request.password.to_string();
        let login_scene = request
            .login_scene
            .non_default_or(DEFAULT_LOGIN_SCENE)
            .to_owned();
        let account_type = request.account_type.non_default_or("account").to_owned();
        {
            let mut inner = self.daemon.inner.lock().await;
            inner
                .auth
                .login(&account, &password, &login_scene, &account_type)
                .await
        }?;
        // Post-login side effects: TOTP + security report.
        self.post_login().await;
        self.maybe_persist_and_broadcast().await;
        let session = self.current_session().await;
        Response::ok(pb::LoginResponse {
            session: session.into(),
            ..Default::default()
        })
    }

    async fn request_login_code(
        &self, _ctx: RequestContext, request: ServiceRequest<'_, pb::RequestLoginCodeRequest>,
    ) -> ServiceResult<pb::RequestLoginCodeResponse> {
        self.daemon.require_configured().await?;
        let account = request.account.to_string();
        let login_type = request
            .login_type
            .as_known()
            .unwrap_or_default()
            .wire()
            .to_owned();
        let login_scene = request
            .login_scene
            .non_default_or(DEFAULT_LOGIN_SCENE)
            .to_owned();
        let account_type = request.account_type.non_default_or("account").to_owned();
        {
            let inner = self.daemon.inner.lock().await;
            inner
                .auth
                .send_login_code(&account, &login_type, &login_scene, &account_type)
                .await
        }?;
        // SendLoginCode doesn't return a session or a code.
        Response::ok(pb::RequestLoginCodeResponse {
            code: String::new(),
            ..Default::default()
        })
    }

    async fn verify_login_code(
        &self, _ctx: RequestContext, request: ServiceRequest<'_, pb::VerifyLoginCodeRequest>,
    ) -> ServiceResult<pb::VerifyLoginCodeResponse> {
        self.daemon.require_configured().await?;
        let account = request.account.to_string();
        let code = request.code.to_string();
        let login_type = request
            .login_type
            .as_known()
            .unwrap_or_default()
            .wire()
            .to_owned();
        let login_scene = request
            .login_scene
            .non_default_or(DEFAULT_LOGIN_SCENE)
            .to_owned();
        let account_type = request.account_type.non_default_or("account").to_owned();
        {
            let mut inner = self.daemon.inner.lock().await;
            inner
                .auth
                .verify_login_code(&account, &code, &login_type, &login_scene, &account_type)
                .await
        }?;
        self.post_login().await;
        self.maybe_persist_and_broadcast().await;
        let session = self.current_session().await;
        Response::ok(pb::VerifyLoginCodeResponse {
            session: session.into(),
            ..Default::default()
        })
    }

    async fn request_mfa_code(
        &self, _ctx: RequestContext, request: ServiceRequest<'_, pb::RequestMfaCodeRequest>,
    ) -> ServiceResult<pb::RequestMfaCodeResponse> {
        self.daemon.require_configured().await?;
        let mfa_type = request.mfa_type.to_string();
        let account = request.account.to_string();
        let login_scene = request
            .login_scene
            .non_default_or(DEFAULT_LOGIN_SCENE)
            .to_owned();
        {
            let inner = self.daemon.inner.lock().await;
            inner
                .auth
                .send_mfa_code(&mfa_type, &account, &login_scene)
                .await
        }?;
        Response::ok(pb::RequestMfaCodeResponse {
            code: String::new(),
            ..Default::default()
        })
    }

    async fn verify_mfa(
        &self, _ctx: RequestContext, request: ServiceRequest<'_, pb::VerifyMfaRequest>,
    ) -> ServiceResult<pb::VerifyMfaResponse> {
        self.daemon.require_configured().await?;
        let mfa_type = request.mfa_type.to_string();
        let account = request.account.to_string();
        let code = request.code.map(ToOwned::to_owned);
        let password = request.password.map(ToOwned::to_owned);
        let login_scene = request
            .login_scene
            .non_default_or(DEFAULT_LOGIN_SCENE)
            .to_owned();
        {
            let mut inner = self.daemon.inner.lock().await;
            inner
                .auth
                .verify_mfa(
                    &mfa_type,
                    &account,
                    code.as_deref(),
                    password.as_deref(),
                    &login_scene,
                )
                .await
        }?;
        self.post_login().await;
        self.maybe_persist_and_broadcast().await;
        let session = self.current_session().await;
        Response::ok(pb::VerifyMfaResponse {
            session: session.into(),
            ..Default::default()
        })
    }

    async fn skip_pending_challenge(
        &self, _ctx: RequestContext, request: ServiceRequest<'_, pb::SkipPendingChallengeRequest>,
    ) -> ServiceResult<pb::SkipPendingChallengeResponse> {
        self.daemon.require_configured().await?;
        let login_scene = request
            .login_scene
            .non_default_or(DEFAULT_LOGIN_SCENE)
            .to_owned();
        {
            let mut inner = self.daemon.inner.lock().await;
            inner.auth.skip_challenge(&login_scene).await
        }?;
        self.post_login().await;
        self.maybe_persist_and_broadcast().await;
        let session = self.current_session().await;
        Response::ok(pb::SkipPendingChallengeResponse {
            session: session.into(),
            ..Default::default()
        })
    }

    async fn list_third_party_providers(
        &self, _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::ListThirdPartyProvidersRequest>,
    ) -> ServiceResult<pb::ListThirdPartyProvidersResponse> {
        self.daemon.require_configured().await?;
        // This is a query, not a state event — build a client directly.
        let client = {
            let inner = self.daemon.inner.lock().await;
            inner
                .auth
                .build_tenant_client()
                .ok_or_else(|| DaemonError::from(RpcFault::NotConfigured))?
        };
        let links = rustylink_core::auth::third_party_login_links(&client)
            .await
            .map_err(DaemonError::from)?;
        let providers = links
            .response
            .data
            .unwrap_or_default()
            .into_iter()
            .map(|info| pb::ThirdPartyProvider {
                alias_key: info.alias_key.or(info.alias).unwrap_or_default(),
                name: info.name.or(info.full_title).unwrap_or_default(),
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
        self.daemon.require_configured().await?;
        let alias_key = request.alias_key.to_string();
        let (auth_url, state_value) = {
            let mut inner = self.daemon.inner.lock().await;
            inner.auth.start_oauth(&alias_key).await?;
            inner
                .auth
                .oauth_pending
                .as_ref()
                .map_or_else(Default::default, |p| (p.url.clone(), p.oauth_state.clone()))
        };
        Response::ok(pb::StartThirdPartyLoginResponse {
            auth_url,
            state: state_value,
            polling: false,
            ..Default::default()
        })
    }

    async fn complete_third_party_login(
        &self, _ctx: RequestContext,
        request: ServiceRequest<'_, pb::CompleteThirdPartyLoginRequest>,
    ) -> ServiceResult<pb::CompleteThirdPartyLoginResponse> {
        self.daemon.require_configured().await?;
        let code = request.code.to_string();
        let state = request.state.to_string();
        {
            let mut inner = self.daemon.inner.lock().await;
            inner.auth.complete_oauth(&code, &state).await
        }?;
        self.post_login().await;
        self.maybe_persist_and_broadcast().await;
        let session = self.current_session().await;
        Response::ok(pb::CompleteThirdPartyLoginResponse {
            session: session.into(),
            ..Default::default()
        })
    }

    async fn start_device_login(
        &self, _ctx: RequestContext, request: ServiceRequest<'_, pb::StartDeviceLoginRequest>,
    ) -> ServiceResult<pb::StartDeviceLoginResponse> {
        self.daemon.require_configured().await?;
        let alias_key = request.alias_key.to_string();
        let login_url = {
            let mut inner = self.daemon.inner.lock().await;
            inner.auth.start_device_login(&alias_key).await?;
            inner
                .auth
                .device_login_pending
                .as_ref()
                .map(|p| p.login_url.clone())
                .unwrap_or_default()
        };
        let session = self.current_session().await;
        Response::ok(pb::StartDeviceLoginResponse {
            session: session.into(),
            login_url,
            ..Default::default()
        })
    }

    async fn complete_device_login(
        &self, _ctx: RequestContext, _request: ServiceRequest<'_, pb::CompleteDeviceLoginRequest>,
    ) -> ServiceResult<pb::CompleteDeviceLoginResponse> {
        self.daemon.require_configured().await?;

        // Grab the poll token and API client while holding the lock briefly.
        let (client, poll_token) = {
            let inner = self.daemon.inner.lock().await;
            let pending = inner.auth.device_login_pending.as_ref().ok_or_else(|| {
                DaemonError::from(RpcFault::InvalidArgument {
                    message: "no pending device login flow".into(),
                })
            })?;
            let client = inner
                .auth
                .build_tenant_client()
                .ok_or_else(|| DaemonError::from(RpcFault::NotConfigured))?;
            let token = pending.poll_token.clone();
            drop(inner);
            (client, token)
        };

        // Poll token/check in a loop (2 s interval, 120 s timeout).
        let poll_interval = std::time::Duration::from_secs(2);
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_mins(2);

        // Poll token/check until the user authenticates in the provider's app.
        // The server returns a non-zero "user not logged in" code while pending
        // (surfaced here as Err -> keep polling); a code-0 response means the
        // user finished and the session cookies are now set.
        loop {
            if tokio::time::Instant::now() >= deadline {
                return Err(DaemonError::from(RpcFault::Unavailable {
                    message: "device login timed out waiting for user".into(),
                })
                .into());
            }

            match rustylink_core::auth::check_third_party_login_token(&client, poll_token.clone())
                .await
            {
                Ok(_response) => {
                    // Success: the session cookies were absorbed into the shared
                    // jar by the API client middleware; nothing to merge here.
                    break;
                }
                Err(error) => {
                    tracing::debug!(%error, "device login pending, retrying");
                }
            }

            tokio::time::sleep(poll_interval).await;
        }

        // The poll succeeded: the session is established via cookies. Finalize
        // (no separate OAuth callback — corplink-rs style).
        {
            let mut inner = self.daemon.inner.lock().await;
            inner.auth.complete_device_login();
        }
        self.post_login().await;
        self.maybe_persist_and_broadcast().await;
        let session = self.current_session().await;
        Response::ok(pb::CompleteDeviceLoginResponse {
            session: session.into(),
            ..Default::default()
        })
    }

    async fn logout(
        &self, _ctx: RequestContext, request: ServiceRequest<'_, pb::LogoutRequest>,
    ) -> ServiceResult<pb::LogoutResponse> {
        self.daemon.require_configured().await?;
        {
            let mut inner = self.daemon.inner.lock().await;
            inner.auth.logout(request.logout_all).await;
            drop(inner);
        }
        // Delete credentials on logout.
        self.daemon.delete_credentials().await;
        let session = self.current_session().await;
        Response::ok(pb::LogoutResponse {
            session: session.into(),
            ..Default::default()
        })
    }
}

// ---------------------------------------------------------------------------
// Post-login side effects
// ---------------------------------------------------------------------------

impl AuthServiceImpl {
    /// Run post-login side effects: fetch TOTP secret and report device
    /// security posture.
    async fn post_login(&self) {
        let is_authenticated = {
            let inner = self.daemon.inner.lock().await;
            matches!(inner.auth.state, AuthState::Authenticated)
        };
        if !is_authenticated {
            return;
        }
        self.maybe_fetch_totp().await;
        self.maybe_report_security().await;
    }

    /// Fetch the TOTP provisioning secret (for auto-reconnect OTP generation).
    async fn maybe_fetch_totp(&self) {
        let client = {
            let inner = self.daemon.inner.lock().await;
            match inner.auth.build_tenant_client() {
                Some(c) => c,
                None => return,
            }
        };
        match rustylink_core::vpn::fetch_totp(&client).await {
            Ok(Some(config)) => {
                let mut inner = self.daemon.inner.lock().await;
                inner
                    .auth
                    .set_totp(Some(crate::persist::PersistedTotpConfig {
                        url: config.url,
                        time_diff_seconds: config.time_diff_seconds,
                    }));
                drop(inner);
            }
            Ok(None) => {}
            Err(error) => {
                tracing::warn!(%error, "failed to fetch TOTP secret (non-fatal)");
            }
        }
    }

    /// Report device security posture (best-effort).
    async fn maybe_report_security(&self) {
        let client = {
            let inner = self.daemon.inner.lock().await;
            match inner.auth.build_tenant_client() {
                Some(c) => c,
                None => return,
            }
        };
        let report = rustylink_core::security::all_green_security_report();
        match rustylink_core::security::report_security(&client, &report).await {
            Ok(_response) => {}
            Err(error) => {
                tracing::warn!(%error, "security report failed (non-fatal)");
            }
        }
    }
}
