use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rustylink_api::{
    ActivateInfo, ActivateResponse, DEFAULT_MATCH_BASE_URL, GetThirdPartyLoginLinksResponse,
    LoginByPasswordResponse, OauthCallbackResponse, SendLoginCodeResponse,
    ThirdPartyTokenCheckResponse, VerifyLoginCodeResponse, VerifyMfaResponse, api,
};
use sha2::{Digest as _, Sha256};
use snafu::prelude::*;
use uuid::Uuid;

use crate::{AppContext, state::OAuthState};

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

pub async fn activate(
    ctx: &mut AppContext, code: Option<String>, base_url: Option<String>,
    backup_url: Option<String>, match_base_url: Option<String>,
) -> Result<Option<ActivateResponse>> {
    if let Some(value) = base_url {
        ctx.state.tenant.base_url = Some(value);
    }
    if let Some(value) = backup_url {
        ctx.state.tenant.backup_url = Some(value);
    }

    let Some(code) = code else {
        ctx.save().context(ContextSnafu)?;
        return Ok(None);
    };

    ctx.state.signing.enabled = true;
    ctx.state.signing.activation_code = Some(code.clone());
    ctx.state.signing.device_id = Some(ctx.state.identity.device_id.clone());
    let client = ctx
        .api_client_for_base_url(match_base_url.as_deref().unwrap_or(DEFAULT_MATCH_BASE_URL))
        .context(ContextSnafu)?;
    let response = api::activate(&client, code).await.context(ApiSnafu)?;
    ctx.sync_from_client(&client);
    if let Some(data) = &response.data {
        merge_activation(ctx, data);
    }
    ctx.save().context(ContextSnafu)?;
    Ok(Some(response))
}

pub async fn login_password(
    ctx: &mut AppContext, login_scene: String, account_type: String, account: String,
    password: String,
) -> Result<LoginByPasswordResponse> {
    let client = ctx.api_client().context(ContextSnafu)?;
    let response = api::login_password(&client, login_scene, account_type, account, password)
        .await
        .context(ApiSnafu)?;
    ctx.sync_from_client(&client);
    ctx.save().context(ContextSnafu)?;
    Ok(response)
}

pub async fn send_code(
    ctx: &mut AppContext, login_scene: String, account_type: String, login_type: String,
    account: String,
) -> Result<SendLoginCodeResponse> {
    let client = ctx.api_client().context(ContextSnafu)?;
    let response = api::send_login_code(&client, login_scene, account_type, login_type, account)
        .await
        .context(ApiSnafu)?;
    ctx.sync_from_client(&client);
    ctx.save().context(ContextSnafu)?;
    Ok(response)
}

pub async fn verify_code(
    ctx: &mut AppContext, login_scene: String, account_type: String, login_type: String,
    account: String, code: String,
) -> Result<VerifyLoginCodeResponse> {
    let client = ctx.api_client().context(ContextSnafu)?;
    let response = api::verify_login_code(
        &client,
        login_scene,
        account_type,
        login_type,
        account,
        code,
    )
    .await
    .context(ApiSnafu)?;
    ctx.sync_from_client(&client);
    ctx.save().context(ContextSnafu)?;
    Ok(response)
}

pub async fn verify_mfa(
    ctx: &mut AppContext, login_scene: String, mfa_type: String, account: String,
    code: Option<String>, password: Option<String>,
) -> Result<VerifyMfaResponse> {
    let client = ctx.api_client().context(ContextSnafu)?;
    let response = api::verify_mfa(&client, login_scene, mfa_type, account, code, password)
        .await
        .context(ApiSnafu)?;
    ctx.sync_from_client(&client);
    ctx.save().context(ContextSnafu)?;
    Ok(response)
}

pub fn start_oauth(
    ctx: &mut AppContext, auth_url: &str, alias_key: String, state: Option<String>,
    redirect_uri: &str,
) -> Result<String> {
    let state_value = state.unwrap_or_else(|| Uuid::new_v4().simple().to_string());
    let (code_verifier, code_challenge) = pkce_pair();
    let mut url = url::Url::parse(auth_url).context(InvalidUrlSnafu {
        value: auth_url.to_string(),
    })?;
    url.query_pairs_mut()
        .append_pair("code_challenge", &code_challenge)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("state", &state_value);

    ctx.state.oauth.alias_key = Some(alias_key);
    ctx.state.oauth.state = Some(state_value);
    ctx.state.oauth.code_verifier = Some(code_verifier);
    ctx.save().context(ContextSnafu)?;
    Ok(url.to_string())
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct ThirdPartyLoginLinks {
    pub code_challenge: String,
    pub response: GetThirdPartyLoginLinksResponse,
}

pub async fn third_party_login_links(ctx: &mut AppContext) -> Result<ThirdPartyLoginLinks> {
    let (code_verifier, code_challenge) = pkce_pair();
    let client = ctx.api_client().context(ContextSnafu)?;
    let response = api::third_party_login_links(&client, code_challenge.clone())
        .await
        .context(ApiSnafu)?;
    ctx.sync_from_client(&client);
    ctx.state.oauth.code_verifier = Some(code_verifier);
    ctx.save().context(ContextSnafu)?;
    Ok(ThirdPartyLoginLinks {
        code_challenge,
        response,
    })
}

pub async fn oauth_callback(
    ctx: &mut AppContext, alias_key: Option<String>, code: String, state: Option<String>,
) -> Result<OauthCallbackResponse> {
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
    let client = ctx.api_client().context(ContextSnafu)?;
    let response = api::oauth_callback(&client, alias_key, code, state, verifier)
        .await
        .context(ApiSnafu)?;
    ctx.sync_from_client(&client);
    ctx.state.oauth = OAuthState::default();
    ctx.save().context(ContextSnafu)?;
    Ok(response)
}

pub async fn oauth_query_callback(
    ctx: &mut AppContext, alias: String, code: String, state: String,
) -> Result<OauthCallbackResponse> {
    let client = ctx.api_client().context(ContextSnafu)?;
    let response = api::oauth_query_callback(&client, alias, code, state)
        .await
        .context(ApiSnafu)?;
    ctx.sync_from_client(&client);
    ctx.state.oauth = OAuthState::default();
    ctx.save().context(ContextSnafu)?;
    Ok(response)
}

pub async fn check_third_party_login_token(
    ctx: &mut AppContext, token: String,
) -> Result<ThirdPartyTokenCheckResponse> {
    let client = ctx.api_client().context(ContextSnafu)?;
    let response = api::check_third_party_login_token(&client, token)
        .await
        .context(ApiSnafu)?;
    ctx.sync_from_client(&client);
    ctx.save().context(ContextSnafu)?;
    Ok(response)
}

fn merge_activation(ctx: &mut AppContext, data: &ActivateInfo) {
    if let Some(host) = first_non_empty([data.activate_host.as_deref(), data.domain.as_deref()]) {
        ctx.state.tenant.base_url = Some(host);
    }
    if let Some(host) = &data.activate_backup_domain {
        ctx.state.tenant.backup_url = Some(host.clone());
    }
    if let Some(enable) = data.activate_enable_backup_domain {
        ctx.state.tenant.use_backup = enable;
    }
    if let Some(name) = first_non_empty([
        data.tenant_name.as_deref(),
        data.name.as_deref(),
        data.zh_name.as_deref(),
        data.en_name.as_deref(),
    ]) {
        ctx.state.tenant.name = Some(name);
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
