use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rustylink_api::{
    ActivateInfo, ActivateRequest, BaseResponse, CommonStringResult,
    GetThirdPartyLoginLinksRequest, LoginResult, LoginV2Result, LogoutRequest,
    OAuthCallbackRequest, OAuthQueryCallbackRequest, PasswordLoginRequest, ResponseMeta,
    SendCodeRequest, SendableRequest, ThirdPartyLoginInfo, ThirdPartyTokenCheckRequest,
    V1LoginRequest, V1LoginSkipRequest, V1MfaSendRequest, V1MfaVerifyRequest, V1SendCodeRequest,
    V1VerifyCodeRequest, VerifyCodeRequest, VerifyMfaRequest,
};
use sha2::{Digest as _, Sha256};
use snafu::prelude::*;
use uuid::Uuid;

use crate::{AppContext, state::StateChange};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("application context operation failed"))]
    Context {
        #[snafu(source(from(crate::context::Error, Box::new)))]
        source: Box<crate::context::Error>,
    },

    #[snafu(display("API operation failed"))]
    Api {
        #[snafu(source(from(rustylink_api::Error, Box::new)))]
        source: Box<rustylink_api::Error>,
    },

    #[snafu(display("no OAuth verifier is stored; run login oauth-start first"))]
    MissingOAuthVerifier,

    #[snafu(display("invalid URL `{value}`"))]
    InvalidUrl {
        value: String,
        source: url::ParseError,
    },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

// ---------------------------------------------------------------------------
// Helpers for collecting state changes from response metadata
// ---------------------------------------------------------------------------

fn collect_meta_changes(meta: &ResponseMeta) -> Vec<StateChange> {
    let mut changes = Vec::new();
    if let Some(cookies) = &meta.cookies {
        changes.push(StateChange::CookiesUpdated {
            cookies: cookies.clone(),
        });
    }
    if let Some(csrf) = &meta.csrf_token {
        changes.push(StateChange::CsrfTokenUpdated {
            token: Some(csrf.clone()),
        });
    }
    if meta.is_force_logout {
        changes.push(StateChange::SessionExpired);
    }
    changes
}

// ---------------------------------------------------------------------------
// Activate
// ---------------------------------------------------------------------------

pub async fn activate(
    ctx: &AppContext, code: Option<String>, base_url: Option<String>,
    backup_url: Option<String>, match_base_url: Option<String>,
) -> Result<(Option<BaseResponse<ActivateInfo>>, Vec<StateChange>)> {
    let mut changes = Vec::new();

    // Apply URL overrides to a copy of tenant state
    let mut tenant = ctx.state.tenant.clone();
    if let Some(value) = base_url {
        tenant.base_url = Some(value);
    }
    if let Some(value) = backup_url {
        tenant.backup_url = Some(value);
    }

    let Some(code) = code else {
        // URL-only activation — just persist the tenant URLs
        let mut signing = ctx.state.signing.clone();
        signing.enabled = true;
        changes.push(StateChange::TenantConfigured { tenant, signing });
        return Ok((None, changes));
    };

    let mut signing = ctx.state.signing.clone();
    signing.enabled = true;
    signing.activation_code = Some(code.clone());
    signing.device_id = Some(ctx.state.identity.device_id.clone());

    let client = match match_base_url {
        Some(url) => ctx.match_client_with_url(&url).context(ContextSnafu)?,
        None => ctx.match_client().clone(),
    };
    let (response, meta) = ActivateRequest { code }
        .send_with_meta(&client)
        .await
        .context(ApiSnafu)?;
    changes.extend(collect_meta_changes(&meta));

    if let Some(data) = &response.data {
        merge_activation(&mut tenant, data);
    }
    changes.push(StateChange::TenantConfigured { tenant, signing });

    Ok((Some(response), changes))
}

// ---------------------------------------------------------------------------
// Legacy login flow
// ---------------------------------------------------------------------------

pub async fn login_password(
    ctx: &AppContext, login_scene: String, account_type: String, account: String,
    password: String,
) -> Result<(BaseResponse<LoginV2Result>, Vec<StateChange>)> {
    let client = ctx.tenant_client().context(ContextSnafu)?;
    let (response, meta) =
        PasswordLoginRequest::encrypted(login_scene, account_type, account, &password)
            .context(ApiSnafu)?
            .send_with_meta(client)
            .await
            .context(ApiSnafu)?;
    Ok((response, collect_meta_changes(&meta)))
}

pub async fn send_code(
    ctx: &AppContext, login_scene: String, account_type: String, login_type: String,
    account: String,
) -> Result<(BaseResponse<CommonStringResult>, Vec<StateChange>)> {
    let client = ctx.tenant_client().context(ContextSnafu)?;
    let (response, meta) = SendCodeRequest {
        login_scene,
        account_type,
        login_type,
        account,
    }
    .send_with_meta(client)
    .await
    .context(ApiSnafu)?;
    Ok((response, collect_meta_changes(&meta)))
}

pub async fn verify_code(
    ctx: &AppContext, login_scene: String, account_type: String, login_type: String,
    account: String, code: String,
) -> Result<(BaseResponse<LoginV2Result>, Vec<StateChange>)> {
    let client = ctx.tenant_client().context(ContextSnafu)?;
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
    Ok((response, collect_meta_changes(&meta)))
}

pub async fn verify_mfa(
    ctx: &AppContext, login_scene: String, mfa_type: String, account: String,
    code: Option<String>, password: Option<String>,
) -> Result<(BaseResponse<LoginV2Result>, Vec<StateChange>)> {
    let client = ctx.tenant_client().context(ContextSnafu)?;
    let (response, meta) =
        VerifyMfaRequest::encrypted(login_scene, mfa_type, account, code, password)
            .context(ApiSnafu)?
            .send_with_meta(client)
            .await
            .context(ApiSnafu)?;
    Ok((response, collect_meta_changes(&meta)))
}

pub fn start_oauth(
    _ctx: &AppContext, auth_url: &str, alias_key: String, state: Option<String>,
    redirect_uri: &str,
) -> Result<(String, Vec<StateChange>)> {
    let state_value = state.unwrap_or_else(|| Uuid::new_v4().simple().to_string());
    let (code_verifier, code_challenge) = pkce_pair();
    let mut url = url::Url::parse(auth_url).context(InvalidUrlSnafu {
        value: auth_url.to_string(),
    })?;
    url.query_pairs_mut()
        .append_pair("code_challenge", &code_challenge)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("state", &state_value);

    let changes = vec![StateChange::OAuthStateSet {
        alias_key,
        state: state_value,
        code_verifier,
    }];
    Ok((url.to_string(), changes))
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ThirdPartyLoginLinks {
    pub code_challenge: String,
    pub response: BaseResponse<Vec<ThirdPartyLoginInfo>>,
}

pub async fn third_party_login_links(
    ctx: &AppContext,
) -> Result<(ThirdPartyLoginLinks, Vec<StateChange>)> {
    let (code_verifier, code_challenge) = pkce_pair();
    let client = ctx.tenant_client().context(ContextSnafu)?;
    let (response, meta) = GetThirdPartyLoginLinksRequest {
        code_challenge: code_challenge.clone(),
    }
    .send_with_meta(client)
    .await
    .context(ApiSnafu)?;
    let mut changes = collect_meta_changes(&meta);
    changes.push(StateChange::OAuthStateSet {
        alias_key: String::new(),
        state: String::new(),
        code_verifier,
    });
    Ok((
        ThirdPartyLoginLinks {
            code_challenge,
            response,
        },
        changes,
    ))
}

pub async fn oauth_callback(
    ctx: &AppContext, alias_key: Option<String>, code: String, state: Option<String>,
) -> Result<(BaseResponse<LoginResult>, Vec<StateChange>)> {
    let alias_key = alias_key
        .or_else(|| ctx.state.oauth.alias_key.clone())
        .context(MissingOAuthVerifierSnafu)?;
    let state = state
        .or_else(|| ctx.state.oauth.state.clone())
        .context(MissingOAuthVerifierSnafu)?;
    let verifier = ctx
        .state
        .oauth
        .code_verifier
        .clone()
        .context(MissingOAuthVerifierSnafu)?;
    let client = ctx.tenant_client().context(ContextSnafu)?;
    let (response, meta) = OAuthCallbackRequest {
        alias_key,
        code,
        state,
        code_verifier: verifier,
    }
    .send_with_meta(client)
    .await
    .context(ApiSnafu)?;
    let mut changes = collect_meta_changes(&meta);
    changes.push(StateChange::OAuthCleared);
    Ok((response, changes))
}

pub async fn oauth_query_callback(
    ctx: &AppContext, alias: String, code: String, state: String,
) -> Result<(BaseResponse<LoginResult>, Vec<StateChange>)> {
    let client = ctx.tenant_client().context(ContextSnafu)?;
    let (response, meta) = OAuthQueryCallbackRequest { alias, code, state }
        .send_with_meta(client)
        .await
        .context(ApiSnafu)?;
    let mut changes = collect_meta_changes(&meta);
    changes.push(StateChange::OAuthCleared);
    Ok((response, changes))
}

pub async fn check_third_party_login_token(
    ctx: &AppContext, token: String,
) -> Result<(BaseResponse<LoginResult>, Vec<StateChange>)> {
    let client = ctx.tenant_client().context(ContextSnafu)?;
    let (response, meta) = ThirdPartyTokenCheckRequest { token }
        .send_with_meta(client)
        .await
        .context(ApiSnafu)?;
    Ok((response, collect_meta_changes(&meta)))
}

// ---------------------------------------------------------------------------
// V1 login flow
// ---------------------------------------------------------------------------

pub async fn v1_login_password(
    ctx: &AppContext, login_scene: String, account_type: String, account: String,
    password: String,
) -> Result<(BaseResponse<LoginV2Result>, Vec<StateChange>)> {
    let client = ctx.tenant_client().context(ContextSnafu)?;
    let (response, meta) =
        V1LoginRequest::encrypted(login_scene, account_type, account, &password)
            .context(ApiSnafu)?
            .send_with_meta(client)
            .await
            .context(ApiSnafu)?;
    Ok((response, collect_meta_changes(&meta)))
}

pub async fn v1_send_code(
    ctx: &AppContext, login_scene: String, account_type: String, login_type: String,
    account: String,
) -> Result<(BaseResponse<CommonStringResult>, Vec<StateChange>)> {
    let client = ctx.tenant_client().context(ContextSnafu)?;
    let (response, meta) = V1SendCodeRequest {
        login_scene,
        account_type,
        login_type,
        account,
    }
    .send_with_meta(client)
    .await
    .context(ApiSnafu)?;
    Ok((response, collect_meta_changes(&meta)))
}

pub async fn v1_verify_code(
    ctx: &AppContext, login_scene: String, account_type: String, login_type: String,
    account: String, code: String,
) -> Result<(BaseResponse<LoginV2Result>, Vec<StateChange>)> {
    let client = ctx.tenant_client().context(ContextSnafu)?;
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
    Ok((response, collect_meta_changes(&meta)))
}

pub async fn v1_mfa_send(
    ctx: &AppContext, login_scene: String, mfa_type: String, account: String,
) -> Result<(BaseResponse<CommonStringResult>, Vec<StateChange>)> {
    let client = ctx.tenant_client().context(ContextSnafu)?;
    let (response, meta) = V1MfaSendRequest {
        login_scene,
        mfa_type,
        account,
    }
    .send_with_meta(client)
    .await
    .context(ApiSnafu)?;
    Ok((response, collect_meta_changes(&meta)))
}

pub async fn v1_mfa_verify(
    ctx: &AppContext, login_scene: String, mfa_type: String, account: String,
    code: Option<String>, password: Option<String>,
) -> Result<(BaseResponse<LoginV2Result>, Vec<StateChange>)> {
    let client = ctx.tenant_client().context(ContextSnafu)?;
    let (response, meta) =
        V1MfaVerifyRequest::encrypted(login_scene, mfa_type, account, code, password)
            .context(ApiSnafu)?
            .send_with_meta(client)
            .await
            .context(ApiSnafu)?;
    Ok((response, collect_meta_changes(&meta)))
}

pub async fn v1_login_skip(
    ctx: &AppContext, login_scene: String, account: String,
) -> Result<(BaseResponse<LoginV2Result>, Vec<StateChange>)> {
    let client = ctx.tenant_client().context(ContextSnafu)?;
    let (response, meta) = V1LoginSkipRequest {
        login_scene,
        account,
    }
    .send_with_meta(client)
    .await
    .context(ApiSnafu)?;
    Ok((response, collect_meta_changes(&meta)))
}

// ---------------------------------------------------------------------------
// Logout
// ---------------------------------------------------------------------------

pub async fn logout(
    ctx: &AppContext, logout_all: bool,
) -> Result<(BaseResponse<CommonStringResult>, Vec<StateChange>)> {
    let client = ctx.tenant_client().context(ContextSnafu)?;
    let (response, meta) = LogoutRequest { logout_all }
        .send_with_meta(client)
        .await
        .context(ApiSnafu)?;
    let mut changes = collect_meta_changes(&meta);
    changes.push(StateChange::LoggedOut);
    Ok((response, changes))
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn merge_activation(tenant: &mut crate::state::TenantState, data: &ActivateInfo) {
    if let Some(host) = first_non_empty([data.activate_host.as_deref(), data.domain.as_deref()]) {
        tenant.base_url = Some(host);
    }
    if let Some(host) = &data.activate_backup_domain {
        tenant.backup_url = Some(host.clone());
    }
    if let Some(enable) = data.activate_enable_backup_domain {
        tenant.use_backup = enable;
    }
    if let Some(name) = first_non_empty([
        data.tenant_name.as_deref(),
        data.name.as_deref(),
        data.zh_name.as_deref(),
        data.en_name.as_deref(),
    ]) {
        tenant.name = Some(name);
    }
}

fn pkce_pair() -> (String, String) {
    let verifier = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
    let challenge = code_challenge(&verifier);
    (verifier, challenge)
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
