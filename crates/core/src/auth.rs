use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rustylink_api::{
    ActivateInfo, ActivateRequest, ApiClient, BaseResponse, CommonStringResult,
    DeviceOAuthCallbackRequest, GetThirdPartyLoginLinksRequest, LoginResult, LoginV2Result,
    LogoutRequest, OAuthCallbackRequest, OAuthQueryCallbackRequest, PasswordLoginRequest,
    ResponseMeta, SendCodeRequest, SendableRequest, ThirdPartyLoginInfo,
    ThirdPartyTokenCheckRequest, V1LoginRequest, V1LoginSkipRequest, V1MfaSendRequest,
    V1MfaVerifyRequest, V1SendCodeRequest, V1VerifyCodeRequest, VerifyCodeRequest,
    VerifyMfaRequest,
};
use sha2::{Digest as _, Sha256};
use snafu::prelude::*;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("API operation failed: {source}"))]
    Api {
        #[snafu(source(from(rustylink_api::Error, Box::new)))]
        source: Box<rustylink_api::Error>,
    },

    #[snafu(display("no OAuth verifier is stored; run login oauth-start first"))]
    MissingOAuthVerifier,

    #[snafu(display("invalid URL `{value}`: {source}"))]
    InvalidUrl {
        value: String,
        source: url::ParseError,
    },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

// ---------------------------------------------------------------------------
// Activate
// ---------------------------------------------------------------------------

pub async fn activate(
    client: &ApiClient, code: &str,
) -> Result<(BaseResponse<ActivateInfo>, ResponseMeta)> {
    let (response, meta) = ActivateRequest {
        code: code.to_owned(),
    }
    .send_with_meta(client)
    .await
    .context(ApiSnafu)?;
    Ok((response, meta))
}

/// Resolved tenant fields extracted from an [`ActivateInfo`] response.
///
/// The caller is responsible for persisting these values into its own state
/// store.
#[derive(Clone, Debug, Default)]
pub struct ActivationTenantUpdate {
    pub base_url: Option<String>,
    pub backup_url: Option<String>,
    pub use_backup: Option<bool>,
    pub name: Option<String>,
}

/// Extract tenant-relevant fields from an activation response.
///
/// Returns `None`-valued fields when the server didn't provide them — the
/// caller can merge these into its existing tenant record.
#[must_use]
pub fn extract_activation_update(data: &ActivateInfo) -> ActivationTenantUpdate {
    ActivationTenantUpdate {
        base_url: first_non_empty([data.activate_host.as_deref(), data.domain.as_deref()]),
        backup_url: data.activate_backup_domain.clone(),
        use_backup: data.activate_enable_backup_domain,
        name: first_non_empty([
            data.tenant_name.as_deref(),
            data.name.as_deref(),
            data.zh_name.as_deref(),
            data.en_name.as_deref(),
        ]),
    }
}

// ---------------------------------------------------------------------------
// Legacy login flow
// ---------------------------------------------------------------------------

pub async fn login_password(
    client: &ApiClient, login_scene: String, account_type: String, account: String,
    password: String,
) -> Result<(BaseResponse<LoginV2Result>, ResponseMeta)> {
    let (response, meta) =
        PasswordLoginRequest::encrypted(login_scene, account_type, account, &password)
            .context(ApiSnafu)?
            .send_with_meta(client)
            .await
            .context(ApiSnafu)?;
    Ok((response, meta))
}

pub async fn send_code(
    client: &ApiClient, login_scene: String, account_type: String, login_type: String,
    account: String,
) -> Result<(BaseResponse<CommonStringResult>, ResponseMeta)> {
    let (response, meta) = SendCodeRequest {
        login_scene,
        account_type,
        login_type,
        account,
    }
    .send_with_meta(client)
    .await
    .context(ApiSnafu)?;
    Ok((response, meta))
}

pub async fn verify_code(
    client: &ApiClient, login_scene: String, account_type: String, login_type: String,
    account: String, code: String,
) -> Result<(BaseResponse<LoginV2Result>, ResponseMeta)> {
    let (response, meta) = VerifyCodeRequest {
        login_scene,
        account_type,
        login_type,
        account,
        code,
    }
    .send_with_meta(client)
    .await
    .context(ApiSnafu)?;
    Ok((response, meta))
}

pub async fn verify_mfa(
    client: &ApiClient, login_scene: String, mfa_type: String, account: String,
    code: Option<String>, password: Option<String>,
) -> Result<(BaseResponse<LoginV2Result>, ResponseMeta)> {
    let (response, meta) =
        VerifyMfaRequest::encrypted(login_scene, mfa_type, account, code, password)
            .context(ApiSnafu)?
            .send_with_meta(client)
            .await
            .context(ApiSnafu)?;
    Ok((response, meta))
}

/// Result of [`start_oauth`] — the constructed authorization URL and the
/// PKCE/state values that the caller must persist until the callback.
#[derive(Clone, Debug)]
pub struct OAuthStart {
    pub url: String,
    pub alias_key: String,
    pub state: String,
    pub code_verifier: String,
}

pub fn start_oauth(
    auth_url: &str, alias_key: String, state: Option<String>, redirect_uri: &str,
) -> Result<OAuthStart> {
    let state_value = state.unwrap_or_else(random_token);
    let (code_verifier, code_challenge) = pkce_pair();
    let mut url = url::Url::parse(auth_url).context(InvalidUrlSnafu {
        value: auth_url.to_string(),
    })?;
    url.query_pairs_mut()
        .append_pair("code_challenge", &code_challenge)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("state", &state_value);

    Ok(OAuthStart {
        url: url.to_string(),
        alias_key,
        state: state_value,
        code_verifier,
    })
}

/// Result of [`third_party_login_links`] — the PKCE code challenge/verifier
/// and the list of third-party login providers.
#[derive(Clone, Debug, serde::Serialize)]
pub struct ThirdPartyLoginLinks {
    pub code_challenge: String,
    #[serde(skip)]
    pub code_verifier: String,
    pub response: BaseResponse<Vec<ThirdPartyLoginInfo>>,
}

pub async fn third_party_login_links(
    client: &ApiClient,
) -> Result<(ThirdPartyLoginLinks, ResponseMeta)> {
    let (code_verifier, code_challenge) = pkce_pair();
    let (response, meta) = GetThirdPartyLoginLinksRequest {
        code_challenge: Some(code_challenge.clone()),
    }
    .send_with_meta(client)
    .await
    .context(ApiSnafu)?;
    Ok((
        ThirdPartyLoginLinks {
            code_challenge,
            code_verifier,
            response,
        },
        meta,
    ))
}

/// Fetch third-party login links WITHOUT a PKCE challenge. The server then
/// returns a poll `token` per provider for the device/QR login flow
/// (`/api/tpslogin/token/check`), as corplink-rs does.
pub async fn device_login_links(
    client: &ApiClient,
) -> Result<(BaseResponse<Vec<ThirdPartyLoginInfo>>, ResponseMeta)> {
    GetThirdPartyLoginLinksRequest {
        code_challenge: None,
    }
    .send_with_meta(client)
    .await
    .context(ApiSnafu)
}

pub async fn oauth_callback(
    client: &ApiClient, alias_key: String, code: String, state: String, code_verifier: String,
) -> Result<(BaseResponse<LoginResult>, ResponseMeta)> {
    let (response, meta) = OAuthCallbackRequest {
        alias_key,
        code,
        state,
        code_verifier,
    }
    .send_with_meta(client)
    .await
    .context(ApiSnafu)?;
    Ok((response, meta))
}

pub async fn device_oauth_callback(
    client: &ApiClient, alias_key: String, code: String, state: String,
    code_verifier: Option<String>,
) -> Result<(BaseResponse<LoginV2Result>, ResponseMeta)> {
    let (response, meta) = DeviceOAuthCallbackRequest {
        alias_key,
        code,
        state,
        code_verifier,
    }
    .send_with_meta(client)
    .await
    .context(ApiSnafu)?;
    Ok((response, meta))
}

pub async fn oauth_query_callback(
    client: &ApiClient, alias: String, code: String, state: String,
) -> Result<(BaseResponse<LoginResult>, ResponseMeta)> {
    let (response, meta) = OAuthQueryCallbackRequest { alias, code, state }
        .send_with_meta(client)
        .await
        .context(ApiSnafu)?;
    Ok((response, meta))
}

pub async fn check_third_party_login_token(
    client: &ApiClient, token: String,
) -> Result<(BaseResponse<LoginResult>, ResponseMeta)> {
    let (response, meta) = ThirdPartyTokenCheckRequest { token }
        .send_with_meta(client)
        .await
        .context(ApiSnafu)?;
    Ok((response, meta))
}

// ---------------------------------------------------------------------------
// V1 login flow
// ---------------------------------------------------------------------------

pub async fn v1_login_password(
    client: &ApiClient, login_scene: String, account_type: String, account: String,
    password: String,
) -> Result<(BaseResponse<LoginV2Result>, ResponseMeta)> {
    let (response, meta) = V1LoginRequest::encrypted(login_scene, account_type, account, &password)
        .context(ApiSnafu)?
        .send_with_meta(client)
        .await
        .context(ApiSnafu)?;
    Ok((response, meta))
}

pub async fn v1_send_code(
    client: &ApiClient, login_scene: String, account_type: String, login_type: String,
    account: String,
) -> Result<(BaseResponse<CommonStringResult>, ResponseMeta)> {
    let (response, meta) = V1SendCodeRequest {
        login_scene,
        account_type,
        login_type,
        account,
    }
    .send_with_meta(client)
    .await
    .context(ApiSnafu)?;
    Ok((response, meta))
}

pub async fn v1_verify_code(
    client: &ApiClient, login_scene: String, account_type: String, login_type: String,
    account: String, code: String,
) -> Result<(BaseResponse<LoginV2Result>, ResponseMeta)> {
    let (response, meta) = V1VerifyCodeRequest {
        login_scene,
        account_type,
        login_type,
        account,
        code,
    }
    .send_with_meta(client)
    .await
    .context(ApiSnafu)?;
    Ok((response, meta))
}

pub async fn v1_mfa_send(
    client: &ApiClient, login_scene: String, mfa_type: String, account: String,
) -> Result<(BaseResponse<CommonStringResult>, ResponseMeta)> {
    let (response, meta) = V1MfaSendRequest {
        login_scene,
        mfa_type,
        account,
    }
    .send_with_meta(client)
    .await
    .context(ApiSnafu)?;
    Ok((response, meta))
}

pub async fn v1_mfa_verify(
    client: &ApiClient, login_scene: String, mfa_type: String, account: String,
    code: Option<String>, password: Option<String>,
) -> Result<(BaseResponse<LoginV2Result>, ResponseMeta)> {
    let (response, meta) =
        V1MfaVerifyRequest::encrypted(login_scene, mfa_type, account, code, password)
            .context(ApiSnafu)?
            .send_with_meta(client)
            .await
            .context(ApiSnafu)?;
    Ok((response, meta))
}

pub async fn v1_login_skip(
    client: &ApiClient, login_scene: String, account: String,
) -> Result<(BaseResponse<LoginV2Result>, ResponseMeta)> {
    let (response, meta) = V1LoginSkipRequest {
        login_scene,
        account,
    }
    .send_with_meta(client)
    .await
    .context(ApiSnafu)?;
    Ok((response, meta))
}

// ---------------------------------------------------------------------------
// Logout
// ---------------------------------------------------------------------------

pub async fn logout(
    client: &ApiClient, logout_all: bool,
) -> Result<(BaseResponse<CommonStringResult>, ResponseMeta)> {
    let (response, meta) = LogoutRequest { logout_all }
        .send_with_meta(client)
        .await
        .context(ApiSnafu)?;
    Ok((response, meta))
}

// ---------------------------------------------------------------------------
// Login state transition
// ---------------------------------------------------------------------------

/// The next auth step after a login / code-verify / MFA response. This is the
/// transition decision a caller's state machine acts on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LoginStep {
    /// The session is fully authenticated.
    Authenticated,
    /// An MFA challenge must be completed.
    AwaitingMfa {
        mfa_type: String,
        auth_list: Vec<String>,
        can_skip: bool,
        masked_mobile: String,
        masked_email: String,
    },
    /// A one-time code (SMS/email) must be verified.
    AwaitingOtp {
        masked_target: String,
        login_type: String,
    },
}

/// Decide the next [`LoginStep`] from a [`LoginV2Result`], mirroring the Android
/// client's routing:
///
/// - an explicit `result == "success"` is terminal (authenticated), regardless
///   of any `next` action;
/// - a `goto_link` action (e.g. a password-reset URL) is also authenticated;
/// - `mfa` / `verify_mfa` actions become an MFA challenge;
/// - any other `next` action is an OTP challenge, with the delivery channel
///   (`mobile`/`email`) derived from whichever masked target the server
///   returned;
/// - no `next` at all is treated as authenticated.
#[must_use]
pub fn next_login_step(result: Option<&LoginV2Result>) -> LoginStep {
    let Some(result) = result else {
        return LoginStep::Authenticated;
    };
    if result.result.as_deref() == Some("success") {
        return LoginStep::Authenticated;
    }
    let Some(next) = &result.next else {
        return LoginStep::Authenticated;
    };
    let action = next.action.as_deref().unwrap_or_default();
    if action.eq_ignore_ascii_case("mfa") || action.eq_ignore_ascii_case("verify_mfa") {
        return LoginStep::AwaitingMfa {
            mfa_type: action.to_owned(),
            auth_list: next.auth_list.clone().unwrap_or_default(),
            can_skip: next.can_skip.unwrap_or(false),
            masked_mobile: next.mobile.clone().unwrap_or_default(),
            masked_email: next.email.clone().unwrap_or_default(),
        };
    }
    if action.eq_ignore_ascii_case("goto_link") || action.eq_ignore_ascii_case("goToLink") {
        return LoginStep::Authenticated;
    }
    // The stored `login_type` is the delivery channel (mobile vs. email), not
    // the action verb: it is echoed back when verifying/resending codes.
    let masked_mobile = next.mobile.clone().filter(|value| !value.is_empty());
    let masked_email = next.email.clone().filter(|value| !value.is_empty());
    let (masked_target, login_type) = match (masked_mobile, masked_email) {
        (Some(mobile), _) => (mobile, "mobile".to_owned()),
        (None, Some(email)) => (email, "email".to_owned()),
        (None, None) => (String::new(), "mobile".to_owned()),
    };
    LoginStep::AwaitingOtp {
        masked_target,
        login_type,
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn pkce_pair() -> (String, String) {
    let verifier = random_token();
    let challenge = code_challenge(&verifier);
    (verifier, challenge)
}

/// A hex-encoded 256-bit random token (used for PKCE verifiers and OAuth
/// state).
fn random_token() -> String {
    hex::encode(rand::random::<[u8; 32]>())
}

fn code_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

fn first_non_empty<'a>(values: impl IntoIterator<Item = Option<&'a str>>) -> Option<String> {
    values
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use rustylink_api::{LoginV2Next, LoginV2Result};

    use super::{LoginStep, next_login_step};

    fn with_next(next: LoginV2Next) -> LoginV2Result {
        LoginV2Result {
            result: None,
            next: Some(next),
        }
    }

    #[test]
    fn explicit_success_and_missing_data_are_authenticated() {
        assert_eq!(next_login_step(None), LoginStep::Authenticated);
        let success = LoginV2Result {
            result: Some("success".to_owned()),
            next: None,
        };
        assert_eq!(next_login_step(Some(&success)), LoginStep::Authenticated);
    }

    #[test]
    fn goto_link_is_authenticated_not_a_challenge() {
        let goto = with_next(LoginV2Next {
            action: Some("goto_link".to_owned()),
            ..Default::default()
        });
        assert_eq!(next_login_step(Some(&goto)), LoginStep::Authenticated);
    }

    #[test]
    fn mfa_action_becomes_mfa_challenge() {
        let mfa = with_next(LoginV2Next {
            action: Some("mfa".to_owned()),
            can_skip: Some(true),
            auth_list: Some(vec!["totp".to_owned()]),
            mobile: Some("1***".to_owned()),
            ..Default::default()
        });
        assert_eq!(
            next_login_step(Some(&mfa)),
            LoginStep::AwaitingMfa {
                mfa_type: "mfa".to_owned(),
                auth_list: vec!["totp".to_owned()],
                can_skip: true,
                masked_mobile: "1***".to_owned(),
                masked_email: String::new(),
            }
        );
    }

    #[test]
    fn other_action_becomes_otp_with_channel_from_masked_target() {
        let email_otp = with_next(LoginV2Next {
            action: Some("verify_code".to_owned()),
            email: Some("a***@x.com".to_owned()),
            ..Default::default()
        });
        assert_eq!(
            next_login_step(Some(&email_otp)),
            LoginStep::AwaitingOtp {
                masked_target: "a***@x.com".to_owned(),
                login_type: "email".to_owned(),
            }
        );
    }
}
