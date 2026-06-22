//! Auth flow state and orchestration.
//!
//! [`AuthState`] is the pure, runtime-agnostic auth state.  The orchestration
//! functions take a pre-built [`ApiClient`] (the daemon owns client
//! construction, the cookie jar, and persistence) plus the request parameters,
//! perform the API call(s), and **return the next state** (or the pending-flow
//! data) instead of mutating shared storage.  Errors are returned synchronously
//! so the caller surfaces them in real time — no out-of-band error field.

use rustylink_api::{ApiClient, LoginV2Result};
use serde::{Deserialize, Serialize};
use snafu::prelude::*;

use crate::auth::{LoginStep, next_login_step};

/// Which login API variant the tenant uses.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum LoginApiVersion {
    /// Legacy login flow (`/api/login`, `/api/login/code/*`, `/api/mfa/*`).
    #[default]
    Legacy,
    /// V1 login flow (`/api/v1/login`, `/api/v1/login/*`).
    V1,
}

/// Pending OAuth flow parameters (set when entering [`AuthState::AwaitingOauth`]).
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

/// The pure auth state.  Variant names/data mirror the `Session.State` proto.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum AuthState {
    #[default]
    Unconfigured,
    Configured,
    AwaitingOtp {
        masked_target: String,
        login_type: String,
    },
    AwaitingMfa {
        mfa_type: String,
        auth_list: Vec<String>,
        can_skip: bool,
        masked_mobile: String,
        masked_email: String,
    },
    AwaitingOauth,
    AwaitingDeviceLogin,
    Authenticated,
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("{source}"))]
    Auth {
        #[snafu(source(from(crate::auth::Error, Box::new)))]
        source: Box<crate::auth::Error>,
    },

    #[snafu(display("unknown provider alias `{alias}`"))]
    UnknownProvider { alias: String },

    #[snafu(display("provider `{alias}` has no login url"))]
    ProviderNoLoginUrl { alias: String },

    #[snafu(display("provider `{alias}` does not support device login"))]
    ProviderNoDeviceLogin { alias: String },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Map a login/verify/MFA response onto the next [`AuthState`].
#[must_use]
pub fn next_auth_state(result: Option<&LoginV2Result>) -> AuthState {
    match next_login_step(result) {
        LoginStep::Authenticated => AuthState::Authenticated,
        LoginStep::AwaitingMfa {
            mfa_type,
            auth_list,
            can_skip,
            masked_mobile,
            masked_email,
        } => AuthState::AwaitingMfa {
            mfa_type,
            auth_list,
            can_skip,
            masked_mobile,
            masked_email,
        },
        LoginStep::AwaitingOtp {
            masked_target,
            login_type,
        } => AuthState::AwaitingOtp {
            masked_target,
            login_type,
        },
    }
}

/// Username + password login. Returns the next state (authenticated, or an
/// MFA/OTP challenge).
pub async fn login(
    client: &ApiClient, version: LoginApiVersion, login_scene: String, account_type: String,
    account: String, password: String,
) -> Result<AuthState> {
    let response = if version == LoginApiVersion::V1 {
        crate::auth::v1_login_password(client, login_scene, account_type, account, password).await
    } else {
        crate::auth::login_password(client, login_scene, account_type, account, password).await
    }
    .context(AuthSnafu)?;
    Ok(next_auth_state(response.data.as_ref()))
}

/// Request an OTP (SMS/email). The caller stays in its current state.
pub async fn send_login_code(
    client: &ApiClient, version: LoginApiVersion, login_scene: String, account_type: String,
    login_type: String, account: String,
) -> Result<()> {
    if version == LoginApiVersion::V1 {
        crate::auth::v1_send_code(client, login_scene, account_type, login_type, account).await
    } else {
        crate::auth::send_code(client, login_scene, account_type, login_type, account).await
    }
    .context(AuthSnafu)?;
    Ok(())
}

/// Verify a received OTP. Returns the next state.
pub async fn verify_login_code(
    client: &ApiClient, version: LoginApiVersion, login_scene: String, account_type: String,
    login_type: String, account: String, code: String,
) -> Result<AuthState> {
    let response = if version == LoginApiVersion::V1 {
        crate::auth::v1_verify_code(client, login_scene, account_type, login_type, account, code)
            .await
    } else {
        crate::auth::verify_code(client, login_scene, account_type, login_type, account, code).await
    }
    .context(AuthSnafu)?;
    Ok(next_auth_state(response.data.as_ref()))
}

/// Send an MFA challenge code. Legacy tenants have no separate MFA-send
/// endpoint, so this is a no-op there.
pub async fn send_mfa_code(
    client: &ApiClient, version: LoginApiVersion, login_scene: String, mfa_type: String,
    account: String,
) -> Result<()> {
    if version != LoginApiVersion::V1 {
        return Ok(());
    }
    crate::auth::v1_mfa_send(client, login_scene, mfa_type, account)
        .await
        .context(AuthSnafu)?;
    Ok(())
}

/// Verify an MFA challenge. Returns the next state.
pub async fn verify_mfa(
    client: &ApiClient, version: LoginApiVersion, login_scene: String, mfa_type: String,
    account: String, code: Option<String>, password: Option<String>,
) -> Result<AuthState> {
    let response = if version == LoginApiVersion::V1 {
        crate::auth::v1_mfa_verify(client, login_scene, mfa_type, account, code, password).await
    } else {
        crate::auth::verify_mfa(client, login_scene, mfa_type, account, code, password).await
    }
    .context(AuthSnafu)?;
    Ok(next_auth_state(response.data.as_ref()))
}

/// Skip a skippable MFA challenge (v1 flow). Returns the next state.
pub async fn skip_challenge(client: &ApiClient, login_scene: String) -> Result<AuthState> {
    let response = crate::auth::v1_login_skip(client, login_scene, String::new())
        .await
        .context(AuthSnafu)?;
    Ok(next_auth_state(response.data.as_ref()))
}

/// Begin a third-party OAuth login: fetch the provider list and build the
/// pending flow (PKCE-bound authorize URL + the verifier kept for the callback).
pub async fn start_oauth(client: &ApiClient, alias_key: &str) -> Result<OAuthPending> {
    let links = crate::auth::third_party_login_links(client)
        .await
        .context(AuthSnafu)?;
    let provider = links
        .response
        .data
        .unwrap_or_default()
        .into_iter()
        .find(|info| {
            info.alias_key.as_deref() == Some(alias_key)
                || info.alias.as_deref() == Some(alias_key)
        })
        .context(UnknownProviderSnafu {
            alias: alias_key.to_owned(),
        })?;
    let login_url = provider
        .login_url
        .or(provider.url)
        .context(ProviderNoLoginUrlSnafu {
            alias: alias_key.to_owned(),
        })?;
    Ok(OAuthPending {
        alias_key: alias_key.to_owned(),
        oauth_state: provider.state.unwrap_or_default(),
        poll_token: provider.token.unwrap_or_default(),
        pkce_verifier: links.code_verifier,
        url: login_url,
    })
}

/// Complete an OAuth login with the authorization code from the callback.
pub async fn complete_oauth(
    client: &ApiClient, pending: &OAuthPending, code: String, state: String,
) -> Result<()> {
    crate::auth::oauth_callback(
        client,
        pending.alias_key.clone(),
        code,
        state,
        pending.pkce_verifier.clone(),
    )
    .await
    .context(AuthSnafu)?;
    Ok(())
}

/// Begin a device/QR login: fetch the provider list (without PKCE) so the
/// server returns a poll token, and build the pending flow.
pub async fn start_device_login(client: &ApiClient, alias_key: &str) -> Result<DeviceLoginPending> {
    let response = crate::auth::device_login_links(client)
        .await
        .context(AuthSnafu)?;
    let provider = response
        .data
        .unwrap_or_default()
        .into_iter()
        .find(|info| {
            info.alias_key.as_deref() == Some(alias_key)
                || info.alias.as_deref() == Some(alias_key)
        })
        .context(UnknownProviderSnafu {
            alias: alias_key.to_owned(),
        })?;
    let login_url = provider.login_url.or(provider.url).unwrap_or_default();
    let poll_token = provider.token.unwrap_or_default();
    ensure!(
        !poll_token.is_empty(),
        ProviderNoDeviceLoginSnafu {
            alias: alias_key.to_owned(),
        }
    );
    Ok(DeviceLoginPending {
        login_url,
        alias_key: alias_key.to_owned(),
        poll_token,
    })
}

#[cfg(test)]
mod tests {
    use rustylink_api::{LoginV2Next, LoginV2Result};

    use super::{AuthState, next_auth_state};

    #[test]
    fn success_maps_to_authenticated() {
        let success = LoginV2Result {
            result: Some("success".to_owned()),
            next: None,
        };
        assert_eq!(next_auth_state(Some(&success)), AuthState::Authenticated);
        assert_eq!(next_auth_state(None), AuthState::Authenticated);
    }

    #[test]
    fn mfa_action_maps_to_awaiting_mfa() {
        let mfa = LoginV2Result {
            result: None,
            next: Some(LoginV2Next {
                action: Some("mfa".to_owned()),
                auth_list: Some(vec!["totp".to_owned()]),
                ..Default::default()
            }),
        };
        assert!(matches!(
            next_auth_state(Some(&mfa)),
            AuthState::AwaitingMfa { .. }
        ));
    }
}
