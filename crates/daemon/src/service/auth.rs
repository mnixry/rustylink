//! `AuthService` — RPC handlers for authentication-related operations.
//!
//! Wraps [`Daemon`] and implements the generated `AuthService` trait.  Each
//! handler extracts parameters from the proto request, dispatches an
//! [`AuthEvent`] through the statig state machine, and projects the result
//! back to a proto response.

use connectrpc::{RequestContext, Response, ServiceRequest, ServiceResult};
use rustylink_proto::proto::rustylink::daemon::{v1 as pb, v1::AuthService};

use crate::{
    daemon::{Daemon, nonempty_or},
    error::{DaemonError, RpcFault},
    state::{AuthEvent, State},
};

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
        inner.auth.to_session_proto(inner.auth.state())
    }

    /// After a successful auth event, persist credentials if authenticated
    /// and broadcast.
    async fn maybe_persist_and_broadcast(&self) {
        let is_authenticated = {
            let inner = self.daemon.inner.lock().await;
            matches!(inner.auth.state(), State::Authenticated {})
        };
        if is_authenticated {
            self.daemon.persist_credentials().await;
        }
    }

    /// If the auth machine recorded an error, return it as a `DaemonError`.
    async fn check_last_error(&self) -> Result<(), DaemonError> {
        let inner = self.daemon.inner.lock().await;
        inner.auth.last_error.as_ref().map_or_else(
            || Ok(()),
            |error| {
                Err(DaemonError::Fault(RpcFault::InvalidArgument {
                    message: error.clone(),
                }))
            },
        )
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
        let event = AuthEvent::Activate {
            code: request.code.map(ToOwned::to_owned).unwrap_or_default(),
            base_url: request.base_url.map(ToOwned::to_owned),
            backup_url: request.backup_url.map(ToOwned::to_owned),
            match_base_url: request.match_base_url.map(ToOwned::to_owned),
        };
        {
            let mut inner = self.daemon.inner.lock().await;
            inner.auth.handle(&event).await;
            drop(inner);
        }
        self.check_last_error().await?;
        // After activation, also detect login API version (best-effort).
        {
            let client = {
                let inner = self.daemon.inner.lock().await;
                inner.auth.build_tenant_client()
            };
            if let Some(client) = client
                && let Ok((setting, meta)) = rustylink_core::vpn::login_setting(&client).await
            {
                let mut inner = self.daemon.inner.lock().await;
                let merge = AuthEvent::MergeResponseMeta {
                    cookies: meta
                        .cookies
                        .as_ref()
                        .map(|c| c.values.clone())
                        .unwrap_or_default(),
                    csrf_token: meta.csrf_token.clone(),
                };
                inner.auth.handle(&merge).await;
                if let Some(data) = setting.data.as_ref()
                    && data.v1_login.unwrap_or(false)
                {
                    let version_event = AuthEvent::SetLoginApiVersion {
                        version: crate::persist::LoginApiVersion::V1,
                    };
                    inner.auth.handle(&version_event).await;
                }
                drop(inner);
            }
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
        let event = AuthEvent::Login {
            account: request.account.to_string(),
            password: request.password.to_string(),
            login_scene: nonempty_or(request.login_scene, "login"),
            account_type: nonempty_or(request.account_type, "account"),
        };
        {
            let mut inner = self.daemon.inner.lock().await;
            inner.auth.handle(&event).await;
            drop(inner);
        }
        self.check_last_error().await?;
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
        let event = AuthEvent::SendLoginCode {
            account: request.account.to_string(),
            login_type: request.login_type.to_string(),
            login_scene: nonempty_or(request.login_scene, "login"),
            account_type: nonempty_or(request.account_type, "account"),
        };
        {
            let mut inner = self.daemon.inner.lock().await;
            inner.auth.handle(&event).await;
            drop(inner);
        }
        self.check_last_error().await?;
        // SendLoginCode doesn't return a session — return the code (if any).
        // The state machine doesn't produce a "code" output; return empty.
        Response::ok(pb::RequestLoginCodeResponse {
            code: String::new(),
            ..Default::default()
        })
    }

    async fn verify_login_code(
        &self, _ctx: RequestContext, request: ServiceRequest<'_, pb::VerifyLoginCodeRequest>,
    ) -> ServiceResult<pb::VerifyLoginCodeResponse> {
        self.daemon.require_configured().await?;
        let event = AuthEvent::VerifyLoginCode {
            account: request.account.to_string(),
            code: request.code.to_string(),
            login_type: request.login_type.to_string(),
            login_scene: nonempty_or(request.login_scene, "login"),
            account_type: nonempty_or(request.account_type, "account"),
        };
        {
            let mut inner = self.daemon.inner.lock().await;
            inner.auth.handle(&event).await;
            drop(inner);
        }
        self.check_last_error().await?;
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
        let event = AuthEvent::SendMfaCode {
            mfa_type: request.mfa_type.to_string(),
            account: request.account.to_string(),
            login_scene: nonempty_or(request.login_scene, "login"),
        };
        {
            let mut inner = self.daemon.inner.lock().await;
            inner.auth.handle(&event).await;
            drop(inner);
        }
        self.check_last_error().await?;
        Response::ok(pb::RequestMfaCodeResponse {
            code: String::new(),
            ..Default::default()
        })
    }

    async fn verify_mfa(
        &self, _ctx: RequestContext, request: ServiceRequest<'_, pb::VerifyMfaRequest>,
    ) -> ServiceResult<pb::VerifyMfaResponse> {
        self.daemon.require_configured().await?;
        let event = AuthEvent::VerifyMfa {
            mfa_type: request.mfa_type.to_string(),
            account: request.account.to_string(),
            code: request.code.map(ToOwned::to_owned),
            password: request.password.map(ToOwned::to_owned),
            login_scene: nonempty_or(request.login_scene, "login"),
        };
        {
            let mut inner = self.daemon.inner.lock().await;
            inner.auth.handle(&event).await;
            drop(inner);
        }
        self.check_last_error().await?;
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
        let event = AuthEvent::SkipChallenge {
            login_scene: nonempty_or(request.login_scene, "login"),
        };
        {
            let mut inner = self.daemon.inner.lock().await;
            inner.auth.handle(&event).await;
            drop(inner);
        }
        self.check_last_error().await?;
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
        let (links, meta) = rustylink_core::auth::third_party_login_links(&client)
            .await
            .map_err(DaemonError::from)?;
        {
            let mut inner = self.daemon.inner.lock().await;
            let event = AuthEvent::MergeResponseMeta {
                cookies: meta
                    .cookies
                    .as_ref()
                    .map(|c| c.values.clone())
                    .unwrap_or_default(),
                csrf_token: meta.csrf_token.clone(),
            };
            inner.auth.handle(&event).await;
            drop(inner);
        }
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
        let redirect_uri = request.redirect_uri.to_string();
        let event = AuthEvent::StartOAuth {
            alias_key: alias_key.clone(),
            redirect_uri,
        };
        {
            let mut inner = self.daemon.inner.lock().await;
            inner.auth.handle(&event).await;
            drop(inner);
        }
        self.check_last_error().await?;
        // Extract the OAuth params from the shared storage.
        let inner = self.daemon.inner.lock().await;
        let (auth_url, state_value) = inner
            .auth
            .oauth_pending
            .as_ref()
            .map_or_else(Default::default, |p| (p.url.clone(), p.oauth_state.clone()));
        drop(inner);
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
        let event = AuthEvent::CompleteOAuth {
            code: request.code.to_string(),
            state: request.state.to_string(),
        };
        {
            let mut inner = self.daemon.inner.lock().await;
            inner.auth.handle(&event).await;
            drop(inner);
        }
        self.check_last_error().await?;
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
        let event = AuthEvent::StartDeviceLogin {
            alias_key: request.alias_key.to_string(),
        };
        {
            let mut inner = self.daemon.inner.lock().await;
            inner.auth.handle(&event).await;
            drop(inner);
        }
        self.check_last_error().await?;
        // Read back the login URL from the pending state.
        let login_url = {
            let inner = self.daemon.inner.lock().await;
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

        let (code, state_value) = loop {
            if tokio::time::Instant::now() >= deadline {
                return Err(DaemonError::from(RpcFault::Unavailable {
                    message: "device login timed out waiting for user".into(),
                })
                .into());
            }

            match rustylink_core::auth::check_third_party_login_token(&client, poll_token.clone())
                .await
            {
                Ok((response, meta)) => {
                    // Merge cookies from the poll response.
                    {
                        let mut inner = self.daemon.inner.lock().await;
                        let merge = AuthEvent::MergeResponseMeta {
                            cookies: meta
                                .cookies
                                .as_ref()
                                .map(|c| c.values.clone())
                                .unwrap_or_default(),
                            csrf_token: meta.csrf_token.clone(),
                        };
                        inner.auth.handle(&merge).await;
                        drop(inner);
                    }

                    if let Some(data) = &response.data {
                        // Check for a callback URL containing code + state.
                        if let Some(ref url_str) = data.url
                            && let Ok(parsed) = url::Url::parse(url_str)
                        {
                            let code = parsed
                                .query_pairs()
                                .find(|(k, _)| k == "code")
                                .map(|(_, v)| v.to_string())
                                .unwrap_or_default();
                            let st = parsed
                                .query_pairs()
                                .find(|(k, _)| k == "state")
                                .map(|(_, v)| v.to_string())
                                .unwrap_or_default();
                            if !code.is_empty() {
                                break (code, st);
                            }
                        }
                        // Direct success without a URL — treat as complete.
                        if data.login_result.as_deref() == Some("success") {
                            break (String::new(), String::new());
                        }
                    }
                }
                Err(error) => {
                    tracing::debug!(%error, "device login poll attempt failed, retrying");
                }
            }

            tokio::time::sleep(poll_interval).await;
        };

        // Dispatch the completion event to the state machine.
        let event = AuthEvent::CompleteDeviceLogin {
            code,
            state: state_value,
        };
        {
            let mut inner = self.daemon.inner.lock().await;
            inner.auth.handle(&event).await;
            drop(inner);
        }
        self.check_last_error().await?;
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
        let event = AuthEvent::Logout {
            logout_all: request.logout_all,
        };
        {
            let mut inner = self.daemon.inner.lock().await;
            inner.auth.handle(&event).await;
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
            matches!(inner.auth.state(), State::Authenticated {})
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
            Ok((Some(config), meta)) => {
                let mut inner = self.daemon.inner.lock().await;
                let merge = AuthEvent::MergeResponseMeta {
                    cookies: meta
                        .cookies
                        .as_ref()
                        .map(|c| c.values.clone())
                        .unwrap_or_default(),
                    csrf_token: meta.csrf_token.clone(),
                };
                inner.auth.handle(&merge).await;
                let totp_event = AuthEvent::StoreTotp {
                    config: Some(crate::persist::PersistedTotpConfig {
                        url: config.url,
                        time_diff_seconds: config.time_diff_seconds,
                    }),
                };
                inner.auth.handle(&totp_event).await;
                drop(inner);
            }
            Ok((None, meta)) => {
                let mut inner = self.daemon.inner.lock().await;
                let merge = AuthEvent::MergeResponseMeta {
                    cookies: meta
                        .cookies
                        .as_ref()
                        .map(|c| c.values.clone())
                        .unwrap_or_default(),
                    csrf_token: meta.csrf_token.clone(),
                };
                inner.auth.handle(&merge).await;
                drop(inner);
            }
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
            Ok((_response, meta)) => {
                let mut inner = self.daemon.inner.lock().await;
                let merge = AuthEvent::MergeResponseMeta {
                    cookies: meta
                        .cookies
                        .as_ref()
                        .map(|c| c.values.clone())
                        .unwrap_or_default(),
                    csrf_token: meta.csrf_token.clone(),
                };
                inner.auth.handle(&merge).await;
                drop(inner);
            }
            Err(error) => {
                tracing::warn!(%error, "security report failed (non-fatal)");
            }
        }
    }
}
