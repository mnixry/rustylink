use snafu::ResultExt as _;
use tracing::instrument;

use crate::{
    apis::default_api,
    client::{ApiClient, Result, VpnDotServers, openapi_error},
    models::{
        ActivateRequest, ActivateResponse, GetLoginSettingResponse, GetTenantConfigResponse,
        GetThirdPartyLoginLinksResponse, GetUserInfoResponse, GetVpnExportsResponse,
        GetVpnLocationsResponse, GetVpnSettingResponse, LoginByPasswordResponse,
        OAuthCallbackRequest, OauthCallbackResponse, PasswordLoginRequest, ReportSecurityResponse,
        ReportVpnResponse, SecurityReportRequest, SendCodeRequest, SendLoginCodeResponse,
        ThirdPartyTokenCheckRequest, ThirdPartyTokenCheckResponse, VerifyCodeRequest,
        VerifyLoginCodeResponse, VerifyMfaRequest, VerifyMfaResponse, VpnConnEnvelope,
        VpnConnRequest, VpnDot, VpnPingResponse, VpnReportRequest,
    },
    signing::PasswordCipher,
};

trait ApiEnvelope {
    fn code(&self) -> i32;
    fn message(&self) -> Option<&str>;
}

macro_rules! impl_api_envelope {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl ApiEnvelope for $ty {
                fn code(&self) -> i32 {
                    self.code
                }

                fn message(&self) -> Option<&str> {
                    self.message.as_deref()
                }
            }
        )+
    };
}

macro_rules! send_checked {
    ($request:expr) => {{
        let response = $request.await.map_err(openapi_error)?;
        check_api_status(&response)?;
        Ok(response)
    }};
}

impl_api_envelope!(
    ActivateResponse,
    GetLoginSettingResponse,
    GetTenantConfigResponse,
    GetUserInfoResponse,
    GetVpnLocationsResponse,
    GetVpnSettingResponse,
    LoginByPasswordResponse,
    OauthCallbackResponse,
    ThirdPartyTokenCheckResponse,
    GetThirdPartyLoginLinksResponse,
    ReportSecurityResponse,
    SendLoginCodeResponse,
    VerifyLoginCodeResponse,
    VerifyMfaResponse,
    VpnConnEnvelope,
    VpnPingResponse,
    GetVpnExportsResponse,
    ReportVpnResponse,
);

#[instrument(skip(client))]
pub async fn activate(client: &ApiClient, code: String) -> Result<ActivateResponse> {
    let configuration = client.configuration();
    send_checked!(default_api::activate(
        &configuration,
        ActivateRequest { code }
    ))
}

#[instrument(skip(client, password))]
pub async fn login_password(
    client: &ApiClient, login_scene: String, account_type: String, account: String,
    password: String,
) -> Result<LoginByPasswordResponse> {
    let password = PasswordCipher::generated()
        .encrypt_aes_cbc(&password)
        .context(crate::client::EncryptPasswordSnafu)?;
    let configuration = client.configuration();
    let body = PasswordLoginRequest {
        account,
        account_type,
        login_scene,
        password,
    };
    send_checked!(default_api::login_by_password(&configuration, body))
}

pub async fn send_login_code(
    client: &ApiClient, login_scene: String, account_type: String, login_type: String,
    account: String,
) -> Result<SendLoginCodeResponse> {
    let configuration = client.configuration();
    let body = SendCodeRequest {
        account,
        account_type,
        login_scene,
        login_type,
    };
    send_checked!(default_api::send_login_code(&configuration, body))
}

pub async fn verify_login_code(
    client: &ApiClient, login_scene: String, account_type: String, login_type: String,
    account: String, code: String,
) -> Result<VerifyLoginCodeResponse> {
    let configuration = client.configuration();
    let body = VerifyCodeRequest {
        account,
        account_type,
        code,
        login_scene,
        login_type,
    };
    send_checked!(default_api::verify_login_code(&configuration, body))
}

pub async fn verify_mfa(
    client: &ApiClient, login_scene: String, mfa_type: String, account: String,
    code: Option<String>, password: Option<String>,
) -> Result<VerifyMfaResponse> {
    let password = password
        .map(|value| {
            PasswordCipher::generated()
                .encrypt_aes_cbc(&value)
                .context(crate::client::EncryptPasswordSnafu)
        })
        .transpose()?;
    let configuration = client.configuration();
    let body = VerifyMfaRequest {
        account,
        code,
        login_scene,
        mfa_type,
        password,
    };
    send_checked!(default_api::verify_mfa(&configuration, body))
}

pub async fn oauth_callback(
    client: &ApiClient, alias_key: String, code: String, state: String, code_verifier: String,
) -> Result<OauthCallbackResponse> {
    let configuration = client.configuration();
    let body = OAuthCallbackRequest {
        alias_key,
        code,
        code_verifier,
        state,
    };
    send_checked!(default_api::oauth_callback(&configuration, body))
}

pub async fn oauth_query_callback(
    client: &ApiClient, alias: String, code: String, state: String,
) -> Result<OauthCallbackResponse> {
    let configuration = client.configuration();
    send_checked!(default_api::oauth_query_callback(
        &configuration,
        &alias,
        &code,
        &state
    ))
}

pub async fn third_party_login_links(
    client: &ApiClient, code_challenge: String,
) -> Result<GetThirdPartyLoginLinksResponse> {
    let configuration = client.configuration();
    send_checked!(default_api::get_third_party_login_links(
        &configuration,
        &code_challenge
    ))
}

pub async fn check_third_party_login_token(
    client: &ApiClient, token: String,
) -> Result<ThirdPartyTokenCheckResponse> {
    let configuration = client.configuration();
    send_checked!(default_api::check_third_party_login_token(
        &configuration,
        ThirdPartyTokenCheckRequest { token }
    ))
}

pub async fn login_setting(client: &ApiClient) -> Result<GetLoginSettingResponse> {
    let configuration = client.configuration();
    send_checked!(default_api::get_login_setting(&configuration))
}

pub async fn user_info(client: &ApiClient) -> Result<GetUserInfoResponse> {
    let configuration = client.configuration();
    send_checked!(default_api::get_user_info(&configuration))
}

pub async fn tenant_config(client: &ApiClient) -> Result<GetTenantConfigResponse> {
    let configuration = client.configuration();
    send_checked!(default_api::get_tenant_config(&configuration))
}

pub async fn vpn_setting(client: &ApiClient) -> Result<GetVpnSettingResponse> {
    let configuration = client.configuration();
    send_checked!(default_api::get_vpn_setting(&configuration))
}

pub async fn vpn_locations(client: &ApiClient) -> Result<GetVpnLocationsResponse> {
    let configuration = client.configuration();
    send_checked!(default_api::get_vpn_locations(&configuration))
}

pub async fn vpn_conn(
    client: &ApiClient, base_url_override: Option<&str>, body: &VpnConnRequest,
) -> Result<VpnConnEnvelope> {
    let configuration = match base_url_override {
        Some(base_url) => client.configuration_for_base_url(base_url)?,
        None => client.configuration(),
    };
    send_checked!(default_api::vpn_conn(&configuration, body.clone()))
}

pub async fn vpn_conn_for_dot(
    client: &ApiClient, dot: &VpnDot, use_vpn_ip_for_api: bool, body: &VpnConnRequest,
) -> Result<VpnConnEnvelope> {
    let servers = VpnDotServers::from_dot(dot, use_vpn_ip_for_api)?;
    vpn_conn(client, Some(&servers.api_base_url), body).await
}

pub async fn vpn_ping_for_dot(client: &ApiClient, dot: &VpnDot) -> Result<VpnPingResponse> {
    let servers = VpnDotServers::from_dot(dot, false)?;
    let configuration = client.configuration_for_base_url(&servers.api_base_url)?;
    send_checked!(default_api::vpn_ping(&configuration))
}

pub async fn vpn_exports_for_dot(
    client: &ApiClient, dot: &VpnDot,
) -> Result<GetVpnExportsResponse> {
    let servers = VpnDotServers::from_dot(dot, false)?;
    let configuration = client.configuration_for_base_url(&servers.api_base_url)?;
    send_checked!(default_api::get_vpn_exports(&configuration))
}

pub async fn report_vpn_for_dot(
    client: &ApiClient, dot: &VpnDot, body: &VpnReportRequest,
) -> Result<ReportVpnResponse> {
    let servers = VpnDotServers::from_dot(dot, false)?;
    let configuration = client.configuration_for_base_url(&servers.api_base_url)?;
    send_checked!(default_api::report_vpn(&configuration, body.clone()))
}

pub async fn report_security(
    client: &ApiClient, body: &SecurityReportRequest,
) -> Result<ReportSecurityResponse> {
    let configuration = client.configuration();
    send_checked!(default_api::report_security(&configuration, body.clone()))
}

fn check_api_status(response: &impl ApiEnvelope) -> Result<()> {
    if response.code() != 0 {
        let message = response
            .message()
            .unwrap_or("unknown API error")
            .to_string();
        return Err(crate::client::Error::ApiStatus {
            code: response.code(),
            message,
        });
    }
    Ok(())
}
