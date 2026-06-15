use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rustylink_api::{
    ActivateInfo, ActivateResponse, LoginByPasswordResponse, OauthCallbackResponse,
    SendLoginCodeResponse, VerifyLoginCodeResponse, VerifyMfaResponse,
};
use sha2::{Digest as _, Sha256};
use snafu::prelude::*;
use uuid::Uuid;

use crate::{AppContext, error, error::Result, state::OAuthState};

pub async fn activate(
    ctx: &mut AppContext, code: Option<String>, base_url: Option<String>,
    backup_url: Option<String>,
) -> Result<Option<ActivateResponse>> {
    if let Some(value) = base_url {
        ctx.state.tenant.base_url = Some(value);
    }
    if let Some(value) = backup_url {
        ctx.state.tenant.backup_url = Some(value);
    }

    let Some(code) = code else {
        ctx.save()?;
        return Ok(None);
    };

    ctx.state.signing.enabled = true;
    ctx.state.signing.activation_code = Some(code.clone());
    ctx.state.signing.device_id = Some(ctx.state.identity.device_id.clone());
    let client = ctx.api_client()?;
    let response = client.activate(code).await.context(error::Api)?;
    ctx.sync_from_client(&client);
    if let Some(data) = &response.data {
        merge_activation(ctx, data);
    }
    ctx.save()?;
    Ok(Some(response))
}

pub async fn login_password(
    ctx: &mut AppContext, login_scene: String, account_type: String, account: String,
    password: String,
) -> Result<LoginByPasswordResponse> {
    let client = ctx.api_client()?;
    let response = client
        .login_password(login_scene, account_type, account, password)
        .await
        .context(error::Api)?;
    ctx.sync_from_client(&client);
    ctx.save()?;
    Ok(response)
}

pub async fn send_code(
    ctx: &mut AppContext, login_scene: String, account_type: String, login_type: String,
    account: String,
) -> Result<SendLoginCodeResponse> {
    let client = ctx.api_client()?;
    let response = client
        .send_login_code(login_scene, account_type, login_type, account)
        .await
        .context(error::Api)?;
    ctx.sync_from_client(&client);
    ctx.save()?;
    Ok(response)
}

pub async fn verify_code(
    ctx: &mut AppContext, login_scene: String, account_type: String, login_type: String,
    account: String, code: String,
) -> Result<VerifyLoginCodeResponse> {
    let client = ctx.api_client()?;
    let response = client
        .verify_login_code(login_scene, account_type, login_type, account, code)
        .await
        .context(error::Api)?;
    ctx.sync_from_client(&client);
    ctx.save()?;
    Ok(response)
}

pub async fn verify_mfa(
    ctx: &mut AppContext, login_scene: String, mfa_type: String, account: String,
    code: Option<String>, password: Option<String>,
) -> Result<VerifyMfaResponse> {
    let client = ctx.api_client()?;
    let response = client
        .verify_mfa(login_scene, mfa_type, account, code, password)
        .await
        .context(error::Api)?;
    ctx.sync_from_client(&client);
    ctx.save()?;
    Ok(response)
}

pub fn start_oauth(
    ctx: &mut AppContext, auth_url: &str, alias_key: String, state: Option<String>,
    redirect_uri: &str,
) -> Result<String> {
    let state_value = state.unwrap_or_else(|| Uuid::new_v4().simple().to_string());
    let code_verifier = Uuid::new_v4().simple().to_string();
    let code_challenge = code_challenge(&code_verifier);
    let mut url = url::Url::parse(auth_url).context(error::InvalidUrl {
        value: auth_url.to_string(),
    })?;
    url.query_pairs_mut()
        .append_pair("code_challenge", &code_challenge)
        .append_pair("redirect_uri", redirect_uri)
        .append_pair("state", &state_value);

    ctx.state.oauth.alias_key = Some(alias_key);
    ctx.state.oauth.state = Some(state_value);
    ctx.state.oauth.code_verifier = Some(code_verifier);
    ctx.save()?;
    Ok(url.to_string())
}

pub async fn oauth_callback(
    ctx: &mut AppContext, alias_key: Option<String>, code: String, state: Option<String>,
) -> Result<OauthCallbackResponse> {
    let alias_key = alias_key
        .or_else(|| ctx.state.oauth.alias_key.clone())
        .context(error::MissingOAuthVerifier)?;
    let state = state
        .or_else(|| ctx.state.oauth.state.clone())
        .context(error::MissingOAuthVerifier)?;
    let verifier = ctx
        .state
        .oauth
        .code_verifier
        .clone()
        .context(error::MissingOAuthVerifier)?;
    let client = ctx.api_client()?;
    let response = client
        .oauth_callback(alias_key, code, state, verifier)
        .await
        .context(error::Api)?;
    ctx.sync_from_client(&client);
    ctx.state.oauth = OAuthState::default();
    ctx.save()?;
    Ok(response)
}

fn merge_activation(ctx: &mut AppContext, data: &ActivateInfo) {
    if let Some(host) = &data.activate_host {
        ctx.state.tenant.base_url = Some(host.clone());
    }
    if let Some(host) = &data.activate_backup_domain {
        ctx.state.tenant.backup_url = Some(host.clone());
    }
    if let Some(enable) = data.activate_enable_backup_domain {
        ctx.state.tenant.use_backup = enable;
    }
    if let Some(name) = &data.tenant_name {
        ctx.state.tenant.name = Some(name.clone());
    }
}

fn code_challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}
