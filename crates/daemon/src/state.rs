//! Daemon state machines — auth (statig) and VPN (plain enum).
//!
//! ## `AuthMachine`
//!
//! A [`statig`]-based hierarchical state machine owning all auth-related state
//! (tenant, signing, cookies, tokens).  State handlers call
//! [`rustylink_core::auth`] functions directly — the machine builds an
//! [`ApiClient`] from its own fields for each API call.
//!
//! States: `Unconfigured → Configured → AwaitingOtp / AwaitingMfa /
//! AwaitingOAuth → Authenticated`.
//!
//! ## `VpnMachine`
//!
//! A plain `enum`-based state machine (no statig).  VPN state transitions are
//! driven by background tasks (connect loop, supervisor) which make statig's
//! `&mut self` locking problematic.  Explicit transition methods advance the
//! state.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use jiff::Timestamp;
use rustylink_api::{
    ApiClient, ApiHooks, ClientIdentity, CookieJar, LoginV2Result, MatchEndpoint, ResponseMeta,
    SessionCookies, SigningConfig, SigningContext, TenantEndpoint,
};
use rustylink_core::vpn::VpnConnectMode;
use rustylink_proto::proto::rustylink::daemon::v1 as pb;
use rustylink_tunnel::TunnelSession;
use statig::prelude::*;
use tokio_util::sync::CancellationToken;

use crate::persist::{
    LoginApiVersion, PersistedCredentials, PersistedSigningConfig, PersistedTotpConfig,
    TenantConfig,
};

/// Pending OAuth flow parameters, stored in shared storage because statig
/// state-local `&String` parameters trigger false-positive `ptr_arg` lints.
#[derive(Clone, Debug)]
pub struct OAuthPending {
    pub alias_key: String,
    pub oauth_state: String,
    pub poll_token: String,
    pub pkce_verifier: String,
    /// The fully-built PKCE authorize URL the user must open.
    pub url: String,
}

/// Pending device login flow parameters (QR/headless login).
#[derive(Clone, Debug)]
pub struct DeviceLoginPending {
    pub login_url: String,
    pub alias_key: String,
    pub poll_token: String,
}

// =========================================================================
// `AuthMachine` — statig-based auth state machine
// =========================================================================

/// Shared storage for the auth state machine.
///
/// All fields are updated by state handlers; the daemon reads them after each
/// transition to persist and broadcast.
pub struct AuthMachine {
    /// Shared HTTP connection pool (clone-cheap, `Arc`-backed).
    pub(crate) http_pool: reqwest::Client,
    /// Device identity used for API request decoration.
    pub(crate) identity: ClientIdentity,
    /// Tenant connection parameters (set after activation).
    pub(crate) tenant: Option<TenantConfig>,
    /// Signing / HMAC configuration (set after activation).
    pub(crate) signing: Option<PersistedSigningConfig>,
    /// HTTP session cookies, shared as a live jar with every [`ApiClient`]
    /// built from this machine's hooks (Android-style `CookieJar`).
    pub(crate) cookies: CookieJar,
    /// CSRF token from `Set-Cookie: csrf-token=…`.
    pub(crate) csrf_token: Option<String>,
    /// Knock token for API request decoration.
    pub(crate) knock_token: Option<String>,
    /// TOTP provisioning for auto-reconnect OTP generation.
    pub(crate) totp: Option<PersistedTotpConfig>,
    /// Which login API variant the tenant uses.
    pub(crate) login_api_version: LoginApiVersion,
    /// Pending OAuth flow parameters (set when entering `AwaitingOauth`).
    pub(crate) oauth_pending: Option<OAuthPending>,
    /// Pending device login flow parameters (set when entering
    /// `AwaitingDeviceLogin`).
    pub(crate) device_login_pending: Option<DeviceLoginPending>,
    /// Last error from a state handler (inspected by the daemon after
    /// `handle()`).  Cleared at the start of each handler invocation.
    pub(crate) last_error: Option<String>,
}

// ---------------------------------------------------------------------------
// Auth events
// ---------------------------------------------------------------------------

/// Events consumed by the auth state machine.
#[derive(Debug)]
pub enum AuthEvent {
    /// Tenant activation via the match server.
    Activate {
        code: String,
        /// Fallback tenant base URL (used when the activation response omits
        /// one).
        base_url: Option<String>,
        /// Fallback backup URL.
        backup_url: Option<String>,
        /// Match server URL override (defaults to
        /// [`DEFAULT_MATCH_BASE_URL`]).
        match_base_url: Option<String>,
    },
    /// Username + password login (legacy or v1, dispatched automatically).
    Login {
        account: String,
        password: String,
        login_scene: String,
        account_type: String,
    },
    /// Request a login verification code (OTP via SMS/email).
    SendLoginCode {
        account: String,
        login_type: String,
        login_scene: String,
        account_type: String,
    },
    /// Verify a received login code.
    VerifyLoginCode {
        account: String,
        code: String,
        login_type: String,
        login_scene: String,
        account_type: String,
    },
    /// Send an MFA challenge code.
    SendMfaCode {
        mfa_type: String,
        account: String,
        login_scene: String,
    },
    /// Verify an MFA challenge.
    VerifyMfa {
        mfa_type: String,
        account: String,
        code: Option<String>,
        password: Option<String>,
        login_scene: String,
    },
    /// Skip a skippable MFA challenge.
    SkipChallenge { login_scene: String },
    /// Begin a third-party OAuth login flow.
    StartOAuth {
        alias_key: String,
        redirect_uri: String,
    },
    /// Complete an OAuth login with the authorization code.
    CompleteOAuth { code: String, state: String },
    /// Begin a device/QR login flow (headless CLI).
    #[allow(dead_code)]
    StartDeviceLogin { alias_key: String },
    /// Complete a device login with the authorization code from polling.
    #[allow(dead_code)]
    CompleteDeviceLogin { code: String, state: String },
    /// Log out of the current session.
    Logout { logout_all: bool },

    // -- passthrough events (no state transition; update shared storage) --
    /// Merge cookies/CSRF from an out-of-band API response.
    MergeResponseMeta {
        cookies: BTreeMap<String, String>,
        csrf_token: Option<String>,
    },
    /// Store the TOTP provisioning config after a successful fetch.
    StoreTotp { config: Option<PersistedTotpConfig> },
    /// Update the detected login API version.
    SetLoginApiVersion { version: LoginApiVersion },

    /// Restore the session state from already-loaded credentials at startup.
    ///
    /// Credentials are only persisted for an authenticated session, so a
    /// restored machine with a tenant + session cookies transitions straight
    /// to `Authenticated` (otherwise `Configured`). Without this, a restored
    /// session would sit in the initial `Unconfigured` state and the UI would
    /// ask the user to log in again (e.g. after `--rotate-token`).
    RestoreSession,
}

// ---------------------------------------------------------------------------
// statig state machine — AuthMachine
// ---------------------------------------------------------------------------

#[state_machine(initial = "State::unconfigured()")]
impl AuthMachine {
    // ----- Unconfigured -----

    #[state]
    async fn unconfigured(&mut self, event: &AuthEvent) -> Response<State> {
        self.last_error = None;
        match event {
            AuthEvent::Activate {
                code,
                base_url,
                backup_url,
                match_base_url,
            } => {
                self.handle_activate(
                    code,
                    base_url.as_deref(),
                    backup_url.as_deref(),
                    match_base_url.as_deref(),
                )
                .await
            }
            AuthEvent::RestoreSession => self.handle_restore_session(),
            other => self.handle_passthrough(other),
        }
    }

    // ----- Configured -----

    #[state]
    async fn configured(&mut self, event: &AuthEvent) -> Response<State> {
        self.last_error = None;
        match event {
            AuthEvent::Activate {
                code,
                base_url,
                backup_url,
                match_base_url,
            } => {
                self.handle_activate(
                    code,
                    base_url.as_deref(),
                    backup_url.as_deref(),
                    match_base_url.as_deref(),
                )
                .await
            }
            AuthEvent::Login {
                account,
                password,
                login_scene,
                account_type,
            } => {
                self.handle_login(account, password, login_scene, account_type)
                    .await
            }
            AuthEvent::SendLoginCode {
                account,
                login_type,
                login_scene,
                account_type,
            } => {
                self.handle_send_login_code(account, login_type, login_scene, account_type)
                    .await
            }
            AuthEvent::StartOAuth {
                alias_key,
                redirect_uri,
            } => self.handle_start_oauth(alias_key, redirect_uri).await,
            AuthEvent::StartDeviceLogin { alias_key } => {
                self.handle_start_device_login(alias_key).await
            }
            other => self.handle_passthrough(other),
        }
    }

    // ----- AwaitingOtp (state-local: masked_target, login_type) -----

    #[state]
    async fn awaiting_otp(
        &mut self, masked_target: &String, login_type: &String, event: &AuthEvent,
    ) -> Response<State> {
        self.last_error = None;
        let _ = (masked_target, login_type); // used by proto projection
        match event {
            AuthEvent::VerifyLoginCode {
                account,
                code,
                login_type: lt,
                login_scene,
                account_type,
            } => {
                self.handle_verify_login_code(account, code, lt, login_scene, account_type)
                    .await
            }
            AuthEvent::SendLoginCode {
                account,
                login_type: lt,
                login_scene,
                account_type,
            } => {
                self.handle_send_login_code(account, lt, login_scene, account_type)
                    .await
            }
            AuthEvent::Logout { logout_all } => self.handle_logout(*logout_all).await,
            other => self.handle_passthrough(other),
        }
    }

    // ----- AwaitingMfa (state-local: mfa metadata) -----

    #[state]
    #[allow(clippy::too_many_arguments)]
    async fn awaiting_mfa(
        &mut self, mfa_type: &String, auth_list: &Vec<String>, can_skip: &bool,
        masked_mobile: &String, masked_email: &String, event: &AuthEvent,
    ) -> Response<State> {
        self.last_error = None;
        let _ = (mfa_type, auth_list, can_skip, masked_mobile, masked_email);
        match event {
            AuthEvent::VerifyMfa {
                mfa_type,
                account,
                code,
                password,
                login_scene,
            } => {
                self.handle_verify_mfa(
                    mfa_type,
                    account,
                    code.as_deref(),
                    password.as_deref(),
                    login_scene,
                )
                .await
            }
            AuthEvent::SendMfaCode {
                mfa_type,
                account,
                login_scene,
            } => {
                self.handle_send_mfa_code(mfa_type, account, login_scene)
                    .await
            }
            AuthEvent::SkipChallenge { login_scene } => {
                self.handle_skip_challenge(login_scene).await
            }
            AuthEvent::Logout { logout_all } => self.handle_logout(*logout_all).await,
            other => self.handle_passthrough(other),
        }
    }

    // ----- AwaitingOAuth (params stored in shared `oauth_pending`) -----

    #[state]
    async fn awaiting_oauth(&mut self, event: &AuthEvent) -> Response<State> {
        self.last_error = None;
        match event {
            AuthEvent::CompleteOAuth { code, state, .. } => {
                let pending = self.oauth_pending.take();
                let Some(p) = pending else {
                    self.last_error = Some("no pending OAuth flow".into());
                    return Handled;
                };
                self.handle_complete_oauth(&p.alias_key, code, state, &p.pkce_verifier)
                    .await
            }
            AuthEvent::Logout { logout_all } => {
                self.oauth_pending = None;
                self.handle_logout(*logout_all).await
            }
            other => self.handle_passthrough(other),
        }
    }

    // ----- AwaitingDeviceLogin (params stored in shared
    // `device_login_pending`) -----

    #[state]
    async fn awaiting_device_login(&mut self, event: &AuthEvent) -> Response<State> {
        self.last_error = None;
        match event {
            AuthEvent::CompleteDeviceLogin { .. } => {
                // The token/check poll (in the service handler) already merged
                // the session cookies on success, so device login is complete.
                // No separate OAuth callback is needed — corplink-rs treats a
                // code-0 token/check as logged in.
                self.device_login_pending = None;
                Transition(State::authenticated())
            }
            AuthEvent::Logout { logout_all } => {
                self.device_login_pending = None;
                self.handle_logout(*logout_all).await
            }
            other => self.handle_passthrough(other),
        }
    }

    // ----- Authenticated -----

    #[state]
    async fn authenticated(&mut self, event: &AuthEvent) -> Response<State> {
        self.last_error = None;
        match event {
            AuthEvent::Logout { logout_all } => self.handle_logout(*logout_all).await,
            // Re-activation while authenticated (tenant migration).
            AuthEvent::Activate {
                code,
                base_url,
                backup_url,
                match_base_url,
            } => {
                self.handle_activate(
                    code,
                    base_url.as_deref(),
                    backup_url.as_deref(),
                    match_base_url.as_deref(),
                )
                .await
            }
            other => self.handle_passthrough(other),
        }
    }
}

// ---------------------------------------------------------------------------
// AuthMachine — event handler helpers (called from state handlers)
// ---------------------------------------------------------------------------

impl AuthMachine {
    /// Handle passthrough (side-effect) events that are valid in every state.
    /// These update shared storage without causing state transitions.
    fn handle_passthrough(&mut self, event: &AuthEvent) -> Response<State> {
        match event {
            AuthEvent::MergeResponseMeta {
                cookies,
                csrf_token,
            } => {
                if let Ok(mut jar) = self.cookies.lock() {
                    for (name, value) in cookies {
                        jar.values.insert(name.clone(), value.clone());
                    }
                }
                if let Some(csrf) = csrf_token {
                    self.csrf_token = Some(csrf.clone());
                }
                Handled
            }
            AuthEvent::StoreTotp { config } => {
                self.totp.clone_from(config);
                Handled
            }
            AuthEvent::SetLoginApiVersion { version } => {
                self.login_api_version = *version;
                Handled
            }
            _ => Handled,
        }
    }

    /// Restore the session state at startup from already-loaded credentials.
    ///
    /// Credentials are only persisted for an authenticated session, so a
    /// restored machine with a tenant + session cookies transitions to
    /// `Authenticated`; a tenant without cookies falls back to `Configured`;
    /// with no tenant it stays `Unconfigured`.
    fn handle_restore_session(&self) -> Response<State> {
        if self.tenant.is_none() {
            return Handled;
        }
        if self
            .cookies
            .lock()
            .map_or(true, |jar| jar.values.is_empty())
        {
            return Transition(State::configured());
        }
        Transition(State::authenticated())
    }

    async fn handle_activate(
        &mut self, code: &str, base_url: Option<&str>, backup_url: Option<&str>,
        match_base_url: Option<&str>,
    ) -> Response<State> {
        let match_client = self.build_match_client(match_base_url);
        match rustylink_core::auth::activate(&match_client, code).await {
            Ok((response, meta)) => {
                self.merge_meta(&meta);
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
                Transition(State::configured())
            }
            Err(error) => {
                self.last_error = Some(error.to_string());
                Handled
            }
        }
    }

    async fn handle_login(
        &mut self, account: &str, password: &str, login_scene: &str, account_type: &str,
    ) -> Response<State> {
        let Some(client) = self.build_tenant_client() else {
            self.last_error = Some("no tenant configured".into());
            return Handled;
        };
        let result = if self.login_api_version == LoginApiVersion::V1 {
            rustylink_core::auth::v1_login_password(
                &client,
                login_scene.to_owned(),
                account_type.to_owned(),
                account.to_owned(),
                password.to_owned(),
            )
            .await
        } else {
            rustylink_core::auth::login_password(
                &client,
                login_scene.to_owned(),
                account_type.to_owned(),
                account.to_owned(),
                password.to_owned(),
            )
            .await
        };
        match result {
            Ok((response, meta)) => {
                self.merge_meta(&meta);
                route_login_next(response.data.as_ref())
            }
            Err(error) => {
                self.last_error = Some(error.to_string());
                Handled
            }
        }
    }

    async fn handle_send_login_code(
        &mut self, account: &str, login_type: &str, login_scene: &str, account_type: &str,
    ) -> Response<State> {
        let Some(client) = self.build_tenant_client() else {
            self.last_error = Some("no tenant configured".into());
            return Handled;
        };
        let result = if self.login_api_version == LoginApiVersion::V1 {
            rustylink_core::auth::v1_send_code(
                &client,
                login_scene.to_owned(),
                account_type.to_owned(),
                login_type.to_owned(),
                account.to_owned(),
            )
            .await
        } else {
            rustylink_core::auth::send_code(
                &client,
                login_scene.to_owned(),
                account_type.to_owned(),
                login_type.to_owned(),
                account.to_owned(),
            )
            .await
        };
        match result {
            Ok((_response, meta)) => {
                self.merge_meta(&meta);
                // Stay in current state — the user hasn't entered the code yet.
                Handled
            }
            Err(error) => {
                self.last_error = Some(error.to_string());
                Handled
            }
        }
    }

    async fn handle_verify_login_code(
        &mut self, account: &str, code: &str, login_type: &str, login_scene: &str,
        account_type: &str,
    ) -> Response<State> {
        let Some(client) = self.build_tenant_client() else {
            self.last_error = Some("no tenant configured".into());
            return Handled;
        };
        let result = if self.login_api_version == LoginApiVersion::V1 {
            rustylink_core::auth::v1_verify_code(
                &client,
                login_scene.to_owned(),
                account_type.to_owned(),
                login_type.to_owned(),
                account.to_owned(),
                code.to_owned(),
            )
            .await
        } else {
            rustylink_core::auth::verify_code(
                &client,
                login_scene.to_owned(),
                account_type.to_owned(),
                login_type.to_owned(),
                account.to_owned(),
                code.to_owned(),
            )
            .await
        };
        match result {
            Ok((response, meta)) => {
                self.merge_meta(&meta);
                route_login_next(response.data.as_ref())
            }
            Err(error) => {
                self.last_error = Some(error.to_string());
                Handled
            }
        }
    }

    async fn handle_send_mfa_code(
        &mut self, mfa_type: &str, account: &str, login_scene: &str,
    ) -> Response<State> {
        let Some(client) = self.build_tenant_client() else {
            self.last_error = Some("no tenant configured".into());
            return Handled;
        };
        if self.login_api_version != LoginApiVersion::V1 {
            // Legacy (pre-v1) flow has no separate MFA send endpoint.
            return Handled;
        }
        let result = rustylink_core::auth::v1_mfa_send(
            &client,
            login_scene.to_owned(),
            mfa_type.to_owned(),
            account.to_owned(),
        )
        .await;
        match result {
            Ok((_response, meta)) => {
                self.merge_meta(&meta);
                Handled
            }
            Err(error) => {
                self.last_error = Some(error.to_string());
                Handled
            }
        }
    }

    async fn handle_verify_mfa(
        &mut self, mfa_type: &str, account: &str, code: Option<&str>, password: Option<&str>,
        login_scene: &str,
    ) -> Response<State> {
        let Some(client) = self.build_tenant_client() else {
            self.last_error = Some("no tenant configured".into());
            return Handled;
        };
        let result = if self.login_api_version == LoginApiVersion::V1 {
            rustylink_core::auth::v1_mfa_verify(
                &client,
                login_scene.to_owned(),
                mfa_type.to_owned(),
                account.to_owned(),
                code.map(ToOwned::to_owned),
                password.map(ToOwned::to_owned),
            )
            .await
        } else {
            rustylink_core::auth::verify_mfa(
                &client,
                login_scene.to_owned(),
                mfa_type.to_owned(),
                account.to_owned(),
                code.map(ToOwned::to_owned),
                password.map(ToOwned::to_owned),
            )
            .await
        };
        match result {
            Ok((response, meta)) => {
                self.merge_meta(&meta);
                route_login_next(response.data.as_ref())
            }
            Err(error) => {
                self.last_error = Some(error.to_string());
                Handled
            }
        }
    }

    async fn handle_skip_challenge(&mut self, login_scene: &str) -> Response<State> {
        let Some(client) = self.build_tenant_client() else {
            self.last_error = Some("no tenant configured".into());
            return Handled;
        };
        match rustylink_core::auth::v1_login_skip(&client, login_scene.to_owned(), String::new())
            .await
        {
            Ok((response, meta)) => {
                self.merge_meta(&meta);
                route_login_next(response.data.as_ref())
            }
            Err(error) => {
                self.last_error = Some(error.to_string());
                Handled
            }
        }
    }

    async fn handle_start_oauth(
        &mut self, alias_key: &str, _redirect_uri: &str,
    ) -> Response<State> {
        let Some(client) = self.build_tenant_client() else {
            self.last_error = Some("no tenant configured".into());
            return Handled;
        };
        // Fetch provider list. The returned `login_url` is already a complete,
        // PKCE-bound authorize URL (with the tenant's redirect/return URL — the
        // `corplink://` app scheme — embedded in its state), tied to the
        // `code_challenge` that `third_party_login_links` generated. We must keep
        // the matching `code_verifier` for the callback rather than building a
        // fresh URL.
        let links_result = rustylink_core::auth::third_party_login_links(&client).await;
        let (links, meta) = match links_result {
            Ok((links, meta)) => (links, meta),
            Err(error) => {
                self.last_error = Some(error.to_string());
                return Handled;
            }
        };
        self.merge_meta(&meta);

        let provider = links
            .response
            .data
            .unwrap_or_default()
            .into_iter()
            .find(|info| {
                info.alias_key.as_deref() == Some(alias_key)
                    || info.alias.as_deref() == Some(alias_key)
            });
        let Some(provider) = provider else {
            self.last_error = Some(format!("unknown provider alias `{alias_key}`"));
            return Handled;
        };
        let Some(login_url) = provider.login_url.or(provider.url) else {
            self.last_error = Some(format!("provider `{alias_key}` has no login url"));
            return Handled;
        };

        self.oauth_pending = Some(OAuthPending {
            alias_key: alias_key.to_owned(),
            oauth_state: provider.state.unwrap_or_default(),
            poll_token: provider.token.unwrap_or_default(),
            pkce_verifier: links.code_verifier,
            url: login_url,
        });
        Transition(State::awaiting_oauth())
    }

    async fn handle_complete_oauth(
        &mut self, alias_key: &str, code: &str, state: &str, pkce_verifier: &str,
    ) -> Response<State> {
        let Some(client) = self.build_tenant_client() else {
            self.last_error = Some("no tenant configured".into());
            return Handled;
        };
        match rustylink_core::auth::oauth_callback(
            &client,
            alias_key.to_owned(),
            code.to_owned(),
            state.to_owned(),
            pkce_verifier.to_owned(),
        )
        .await
        {
            Ok((_response, meta)) => {
                self.merge_meta(&meta);
                Transition(State::authenticated())
            }
            Err(error) => {
                self.last_error = Some(error.to_string());
                Handled
            }
        }
    }

    async fn handle_start_device_login(&mut self, alias_key: &str) -> Response<State> {
        let Some(client) = self.build_tenant_client() else {
            self.last_error = Some("no tenant configured".into());
            return Handled;
        };
        // Fetch provider list WITHOUT a PKCE challenge so the server returns a
        // poll `token` for the device/QR flow (`/api/tpslogin/token/check`).
        let (response, meta) = match rustylink_core::auth::device_login_links(&client).await {
            Ok(pair) => pair,
            Err(error) => {
                self.last_error = Some(error.to_string());
                return Handled;
            }
        };
        self.merge_meta(&meta);

        let provider = response.data.unwrap_or_default().into_iter().find(|info| {
            info.alias_key.as_deref() == Some(alias_key) || info.alias.as_deref() == Some(alias_key)
        });
        let Some(provider) = provider else {
            self.last_error = Some(format!("unknown provider alias `{alias_key}`"));
            return Handled;
        };

        let login_url = provider.login_url.or(provider.url).unwrap_or_default();
        let poll_token = provider.token.unwrap_or_default();

        if poll_token.is_empty() {
            self.last_error = Some(format!(
                "provider `{alias_key}` does not support device login"
            ));
            return Handled;
        }

        self.device_login_pending = Some(DeviceLoginPending {
            login_url,
            alias_key: alias_key.to_owned(),
            poll_token,
        });
        Transition(State::awaiting_device_login())
    }

    async fn handle_logout(&mut self, logout_all: bool) -> Response<State> {
        // Best-effort server-side logout.
        if let Some(client) = self.build_tenant_client() {
            match rustylink_core::auth::logout(&client, logout_all).await {
                Ok((_response, meta)) => self.merge_meta(&meta),
                Err(error) => {
                    tracing::warn!(%error, "server-side logout failed (proceeding locally)");
                }
            }
        }
        self.clear_session();
        Transition(State::configured())
    }
}

// ---------------------------------------------------------------------------
// AuthMachine — client construction + state helpers
// ---------------------------------------------------------------------------

impl AuthMachine {
    /// Build an [`ApiClient`] pointing at the tenant's base URL with the
    /// current signing/cookie state.  Returns `None` before activation.
    pub fn build_tenant_client(&self) -> Option<ApiClient> {
        let tenant = self.tenant.as_ref()?;
        let endpoint = TenantEndpoint::new(&tenant.base_url).ok()?;
        let hooks = self.build_hooks();
        Some(ApiClient::for_endpoint(
            &endpoint,
            self.http_pool.clone(),
            hooks,
        ))
    }

    /// Build an [`ApiClient`] pointing at the match server (for activation).
    pub fn build_match_client(&self, match_url: Option<&str>) -> ApiClient {
        let endpoint = match_url.map_or_else(MatchEndpoint::default, |url| {
            MatchEndpoint::new(url).unwrap_or_default()
        });
        let hooks = self.build_hooks();
        ApiClient::for_endpoint(&endpoint, self.http_pool.clone(), hooks)
    }

    /// Merge cookies and CSRF token from an API response into shared storage.
    pub fn merge_meta(&mut self, meta: &ResponseMeta) {
        if let Some(cookies) = &meta.cookies
            && let Ok(mut jar) = self.cookies.lock()
        {
            for (name, value) in &cookies.values {
                jar.values.insert(name.clone(), value.clone());
            }
        }
        if let Some(csrf) = &meta.csrf_token {
            self.csrf_token = Some(csrf.clone());
        }
    }

    /// Project the current auth state to an RPC [`Session`](pb::Session)
    /// message.
    #[must_use]
    pub fn to_session_proto(&self, state: &State) -> pb::Session {
        let status = match state {
            State::Unconfigured {} => pb::session::State::Unconfigured,
            State::Configured {} => pb::session::State::Configured,
            State::AwaitingOtp { .. } => pb::session::State::AwaitingOtp,
            State::AwaitingMfa { .. } => pb::session::State::AwaitingMfa,
            State::AwaitingOauth {} => pb::session::State::AwaitingOauth,
            State::AwaitingDeviceLogin {} => pb::session::State::AwaitingDeviceLogin,
            State::Authenticated {} => pb::session::State::Authenticated,
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
        // Populate state-specific challenge fields.
        match state {
            State::AwaitingOtp {
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
            State::AwaitingMfa {
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
            State::AwaitingOauth {} => {
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
            State::AwaitingDeviceLogin {} => {
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
            _ => {}
        }
        session
    }

    /// Snapshot the current session as [`PersistedCredentials`].
    ///
    /// Returns `Some` only when the machine is in the `Authenticated` state
    /// (i.e. a complete, persistable session exists).
    #[must_use]
    pub fn to_credentials(&self) -> Option<PersistedCredentials> {
        let tenant = self.tenant.clone()?;
        let signing = self.signing.clone()?;
        Some(PersistedCredentials {
            tenant,
            signing,
            cookies: self
                .cookies
                .lock()
                .map(|jar| jar.values.clone())
                .unwrap_or_default(),
            csrf_token: self.csrf_token.clone(),
            knock_token: self.knock_token.clone(),
            totp: self.totp.clone(),
            login_api_version: self.login_api_version,
            last_vpn_request: None,
            saved_at: Timestamp::now().to_string(),
        })
    }

    /// Snapshot credentials, injecting the given VPN request for persistence.
    #[must_use]
    pub fn to_credentials_with_vpn(
        &self, vpn_request: Option<crate::persist::PersistedVpnRequest>,
    ) -> Option<PersistedCredentials> {
        let mut creds = self.to_credentials()?;
        creds.last_vpn_request = vpn_request;
        Some(creds)
    }

    /// Restore an `AuthMachine` from persisted credentials, ready to be
    /// wrapped in a statig state machine.
    ///
    /// **Note:** the statig wrapper will start in its declared initial state
    /// (`Unconfigured`).  The daemon should feed a synthetic transition (or
    /// manage the current state externally) to place the machine into
    /// `Authenticated` after restoration.
    #[must_use]
    pub fn restore_from_credentials(
        creds: PersistedCredentials, http_pool: reqwest::Client, identity: ClientIdentity,
    ) -> Self {
        Self {
            http_pool,
            identity,
            tenant: Some(creds.tenant),
            signing: Some(creds.signing),
            cookies: Arc::new(Mutex::new(SessionCookies {
                values: creds.cookies,
            })),
            csrf_token: creds.csrf_token,
            knock_token: creds.knock_token,
            totp: creds.totp,
            login_api_version: creds.login_api_version,
            oauth_pending: None,
            device_login_pending: None,
            last_error: None,
        }
    }

    // ----- private helpers -----

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
            csrf_token: self.csrf_token.clone(),
            knock_token: self.knock_token.clone(),
            signer: SigningContext::new(signing_config),
        }
    }

    /// Clear session-specific data (cookies, tokens), keeping tenant +
    /// signing config intact.
    fn clear_session(&mut self) {
        if let Ok(mut jar) = self.cookies.lock() {
            jar.values.clear();
        }
        self.csrf_token = None;
        self.knock_token = None;
        self.totp = None;
    }
}

// ---------------------------------------------------------------------------
// route_login_next — centralized 2FA / GoToLink routing
// ---------------------------------------------------------------------------

/// Decide the next auth state from a [`LoginV2Result`].
///
/// This function fixes two bugs present in the old per-handler routing:
///
/// 1. **`GoToLink` bug:** when `result.result == Some("success")` but `.next`
///    contains a `goto_link` action (password-change URL), the old code
///    incorrectly treated it as a pending challenge.  We now check `result ==
///    "success"` **first** and transition to Authenticated.
///
/// 2. **2FA routing bug:** the old code mapped all non-MFA actions to OTP
///    indiscriminately.  We now inspect the action string to distinguish
///    between OTP challenges, MFA, and terminal success.
fn route_login_next(result: Option<&LoginV2Result>) -> Response<State> {
    let Some(result) = result else {
        // No data at all — treat as success (matches Android fallback).
        return Transition(State::authenticated());
    };

    // ① Success explicitly reported — done, regardless of `.next`.
    if result.result.as_deref() == Some("success") {
        return Transition(State::authenticated());
    }

    // ② Process `.next` for multi-step flows.
    if let Some(next) = &result.next {
        let action = next.action.as_deref().unwrap_or_default();

        // MFA challenge.
        if action.eq_ignore_ascii_case("mfa") || action.eq_ignore_ascii_case("verify_mfa") {
            return Transition(State::awaiting_mfa(
                action.to_owned(),
                next.auth_list.clone().unwrap_or_default(),
                next.can_skip.unwrap_or(false),
                next.mobile.clone().unwrap_or_default(),
                next.email.clone().unwrap_or_default(),
            ));
        }

        // GoToLink — the server wants the user to visit a URL (e.g.
        // password reset), but the session is authenticated.
        if action.eq_ignore_ascii_case("goto_link") || action.eq_ignore_ascii_case("goToLink") {
            return Transition(State::authenticated());
        }

        // OTP / verify_code / other verification challenge.
        //
        // The `login_type` we store is the delivery *channel* (mobile vs.
        // email), not the action verb: the UI echoes it back when verifying or
        // resending, and the upstream code endpoints expect `mobile`/`email`.
        // Derive it from whichever masked target the server returned.
        let masked_mobile = next.mobile.clone().filter(|value| !value.is_empty());
        let masked_email = next.email.clone().filter(|value| !value.is_empty());
        let (masked, login_type) = match (masked_mobile, masked_email) {
            (Some(mobile), _) => (mobile, "mobile".to_owned()),
            (None, Some(email)) => (email, "email".to_owned()),
            (None, None) => (String::new(), "mobile".to_owned()),
        };
        return Transition(State::awaiting_otp(masked, login_type));
    }

    // ③ No explicit success AND no `.next` — treat as authenticated
    // (matches Android client fallback).
    Transition(State::authenticated())
}

// =========================================================================
// VpnMachine — plain enum state machine (no statig)
// =========================================================================

/// A VPN connect request — the working form that drives the connect loop.
#[derive(Clone, Debug)]
pub struct VpnRequest {
    pub mode: VpnConnectMode,
    pub export_id: i32,
    pub preferred_dot_id: Option<i32>,
    pub otp: Option<String>,
    pub reconnect: bool,
}

/// A live, connected tunnel — recorded while the tunnel is up.
#[derive(Clone, Debug, Default)]
pub struct ActiveTunnel {
    pub dot_id: i32,
    pub dot_name: String,
    pub endpoint: String,
    pub assigned_ip: String,
}

/// VPN connection state (plain enum, not statig).
#[derive(Debug, Clone)]
pub enum VpnState {
    Disconnected,
    Connecting {
        request: VpnRequest,
    },
    Configuring {
        request: VpnRequest,
    },
    Connected {
        request: VpnRequest,
        tunnel_info: ActiveTunnel,
    },
    Reconnecting {
        request: VpnRequest,
        attempts: u32,
    },
    Failed {
        request: VpnRequest,
        error: String,
        attempts: u32,
    },
    Disconnecting {
        request: VpnRequest,
    },
}

/// VPN state machine with explicit transition methods.
///
/// Owns the live [`TunnelSession`] and a [`CancellationToken`] for the
/// connect/supervise background task.  State transitions are driven by the
/// daemon's connect loop and supervisor — not by external events — which is
/// why statig's `&mut self` locking model is not used here.
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
    pub fn can_connect(&self) -> bool {
        matches!(self.state, VpnState::Disconnected | VpnState::Failed { .. })
    }

    /// Current reconnect attempt count.
    #[must_use]
    pub fn attempts(&self) -> u32 {
        match &self.state {
            VpnState::Reconnecting { attempts, .. } | VpnState::Failed { attempts, .. } => {
                *attempts
            }
            _ => 0,
        }
    }

    /// Extract the current VPN request in persisted form (if any).
    #[must_use]
    pub fn current_persisted_request(&self) -> Option<crate::persist::PersistedVpnRequest> {
        let request = match &self.state {
            VpnState::Connecting { request }
            | VpnState::Configuring { request }
            | VpnState::Connected { request, .. }
            | VpnState::Reconnecting { request, .. }
            | VpnState::Failed { request, .. }
            | VpnState::Disconnecting { request } => request,
            VpnState::Disconnected => return None,
        };
        Some(crate::persist::PersistedVpnRequest {
            mode: request.mode.to_string(),
            export_id: request.export_id,
            preferred_dot_id: request.preferred_dot_id,
            protocol_mode: 0,
            reconnect: request.reconnect,
        })
    }

    // ------- state transitions -------

    /// Transition to `Connecting` with a new request.
    pub fn set_connecting(&mut self, request: VpnRequest) {
        self.cancel_token = CancellationToken::new();
        self.state = VpnState::Connecting { request };
    }

    /// Transition to `Configuring` (preserves current request).
    pub fn set_configuring(&mut self) {
        let request = self.take_request();
        self.state = VpnState::Configuring { request };
    }

    /// Transition to `Connected` with tunnel info.
    pub fn set_connected(&mut self, tunnel_info: ActiveTunnel) {
        let request = self.take_request();
        self.state = VpnState::Connected {
            request,
            tunnel_info,
        };
    }

    /// Transition to `Reconnecting`, incrementing the attempt counter.
    pub fn set_reconnecting(&mut self) {
        let request = self.take_request();
        let attempts = self.attempts().saturating_add(1);
        self.state = VpnState::Reconnecting { request, attempts };
    }

    /// Transition to `Failed` with an error message.
    pub fn set_failed(&mut self, error: String) {
        let request = self.take_request();
        let attempts = self.attempts();
        self.state = VpnState::Failed {
            request,
            error,
            attempts,
        };
    }

    /// Transition to `Disconnecting`.
    pub fn set_disconnecting(&mut self) {
        let request = self.take_request();
        self.state = VpnState::Disconnecting { request };
    }

    /// Transition to `Disconnected`, dropping any tunnel session.
    pub fn set_disconnected(&mut self) {
        self.tunnel_session = None;
        self.state = VpnState::Disconnected;
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
            VpnState::Connecting { .. } => pb::Tunnel {
                state: pb::tunnel::State::Connecting.into(),
                ..Default::default()
            },
            VpnState::Configuring { .. } => pb::Tunnel {
                state: pb::tunnel::State::Configuring.into(),
                ..Default::default()
            },
            VpnState::Connected { tunnel_info, .. } => pb::Tunnel {
                state: pb::tunnel::State::Connected.into(),
                dot_id: tunnel_info.dot_id,
                dot_name: tunnel_info.dot_name.clone(),
                endpoint: tunnel_info.endpoint.clone(),
                assigned_ip: tunnel_info.assigned_ip.clone(),
                ..Default::default()
            },
            VpnState::Reconnecting { attempts, .. } => pb::Tunnel {
                state: pb::tunnel::State::Reconnecting.into(),
                reconnect_attempts: *attempts,
                ..Default::default()
            },
            VpnState::Failed {
                error, attempts, ..
            } => pb::Tunnel {
                state: pb::tunnel::State::Failed.into(),
                error: error.clone(),
                reconnect_attempts: *attempts,
                ..Default::default()
            },
            VpnState::Disconnecting { .. } => pb::Tunnel {
                state: pb::tunnel::State::Disconnecting.into(),
                ..Default::default()
            },
        }
    }

    // ------- private helpers -------

    /// Extract the request from the current state, falling back to a default.
    fn take_request(&mut self) -> VpnRequest {
        match std::mem::replace(&mut self.state, VpnState::Disconnected) {
            VpnState::Disconnected => default_vpn_request(),
            VpnState::Connecting { request }
            | VpnState::Configuring { request }
            | VpnState::Connected { request, .. }
            | VpnState::Reconnecting { request, .. }
            | VpnState::Failed { request, .. }
            | VpnState::Disconnecting { request } => request,
        }
    }
}

fn default_vpn_request() -> VpnRequest {
    VpnRequest {
        mode: VpnConnectMode::Full,
        export_id: 0,
        preferred_dot_id: None,
        otp: None,
        reconnect: true,
    }
}
