use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};

use reqwest::header::{
    ACCEPT_LANGUAGE, COOKIE, HeaderMap, HeaderName, HeaderValue, SET_COOKIE, USER_AGENT,
};
use snafu::prelude::*;
use time::OffsetDateTime;
use tracing::instrument;
use url::Url;

use crate::{
    codegen,
    codegen::types::{
        ActivateRequest, ActivateResponse, GetLoginSettingResponse, GetTenantConfigResponse,
        GetUserInfoResponse, GetVpnLocationsResponse, GetVpnSettingResponse,
        LoginByPasswordResponse, OAuthCallbackRequest, OauthCallbackResponse, PasswordLoginRequest,
        ReportSecurityResponse, SecurityReportRequest, SendCodeRequest, SendLoginCodeResponse,
        VerifyCodeRequest, VerifyLoginCodeResponse, VerifyMfaRequest, VerifyMfaResponse,
        VpnConnEnvelope, VpnConnRequest,
    },
    error,
    error::Result,
    identity::ClientIdentity,
    signing::{PasswordCipher, SigningContext},
};

macro_rules! with_device_query {
    ($builder:expr, $query:expr) => {
        $builder
            .app_version($query.app_version.clone())
            .brand($query.brand.clone())
            .build_number($query.build_number.clone())
            .client_source($query.client_source.clone())
            .did($query.did.clone())
            .model($query.model.clone())
            .os($query.os.clone())
            .os_version($query.os_version.clone())
            .os_version_patch($query.os_version_patch.clone())
            .timestamp($query.timestamp.clone())
    };
}

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct SessionCookies {
    pub values: BTreeMap<String, String>,
}

#[derive(Clone, Debug)]
pub struct ApiHooks {
    identity: ClientIdentity,
    cookies: Arc<RwLock<SessionCookies>>,
    csrf_token: Arc<RwLock<Option<String>>>,
    knock_token: Arc<RwLock<Option<String>>>,
    signer: SigningContext,
}

#[derive(Clone)]
pub struct ApiClient {
    http: reqwest::Client,
    generated: codegen::Client,
    hooks: ApiHooks,
}

#[derive(Clone, Debug)]
struct DeviceQuery {
    os: String,
    os_version: String,
    app_version: String,
    brand: String,
    model: String,
    did: String,
    build_number: String,
    os_version_patch: String,
    timestamp: String,
    client_source: String,
}

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

impl_api_envelope!(
    ActivateResponse,
    GetLoginSettingResponse,
    GetTenantConfigResponse,
    GetUserInfoResponse,
    GetVpnLocationsResponse,
    GetVpnSettingResponse,
    LoginByPasswordResponse,
    OauthCallbackResponse,
    ReportSecurityResponse,
    SendLoginCodeResponse,
    VerifyLoginCodeResponse,
    VerifyMfaResponse,
    VpnConnEnvelope,
);

impl ApiClient {
    pub fn new(
        base_url: impl AsRef<str>, identity: ClientIdentity, signer: SigningContext,
        cookies: SessionCookies,
    ) -> Result<Self> {
        let base_url = normalize_base_url(base_url.as_ref())?;
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::limited(10))
            .build()
            .context(error::BuildHttpClient)?;
        let hooks = ApiHooks::new(identity, signer, cookies);
        let generated = codegen::Client::new_with_client(&base_url, http.clone(), hooks.clone());
        Ok(Self {
            http,
            generated,
            hooks,
        })
    }

    #[must_use]
    pub fn cookies(&self) -> SessionCookies {
        self.hooks.cookies()
    }

    pub fn set_csrf_token(&self, token: Option<String>) {
        if let Ok(mut guard) = self.hooks.csrf_token.write() {
            *guard = token;
        }
    }

    pub fn set_knock_token(&self, token: Option<String>) {
        if let Ok(mut guard) = self.hooks.knock_token.write() {
            *guard = token;
        }
    }

    #[instrument(skip(self))]
    pub async fn activate(&self, code: String) -> Result<ActivateResponse> {
        let response = self
            .generated
            .activate()
            .body(ActivateRequest { code })
            .send()
            .await
            .context(error::GeneratedClient)?
            .into_inner();
        check_api_status(&response)?;
        Ok(response)
    }

    #[instrument(skip(self, password))]
    pub async fn login_password(
        &self, login_scene: String, account_type: String, account: String, password: String,
    ) -> Result<LoginByPasswordResponse> {
        let password = PasswordCipher::generated()
            .encrypt_aes_cbc(&password)
            .context(error::EncryptPassword)?;
        let body = PasswordLoginRequest {
            login_scene,
            account_type,
            account,
            password,
        };
        let query = self.device_query();
        let response = with_device_query!(self.generated.login_by_password(), query)
            .body(body)
            .send()
            .await
            .context(error::GeneratedClient)?
            .into_inner();
        check_api_status(&response)?;
        Ok(response)
    }

    pub async fn send_login_code(
        &self, login_scene: String, account_type: String, login_type: String, account: String,
    ) -> Result<SendLoginCodeResponse> {
        let body = SendCodeRequest {
            login_scene,
            account_type,
            login_type,
            account,
        };
        let query = self.device_query();
        let response = with_device_query!(self.generated.send_login_code(), query)
            .body(body)
            .send()
            .await
            .context(error::GeneratedClient)?
            .into_inner();
        check_api_status(&response)?;
        Ok(response)
    }

    pub async fn verify_login_code(
        &self, login_scene: String, account_type: String, login_type: String, account: String,
        code: String,
    ) -> Result<VerifyLoginCodeResponse> {
        let body = VerifyCodeRequest {
            login_scene,
            account_type,
            login_type,
            account,
            code,
        };
        let query = self.device_query();
        let response = with_device_query!(self.generated.verify_login_code(), query)
            .body(body)
            .send()
            .await
            .context(error::GeneratedClient)?
            .into_inner();
        check_api_status(&response)?;
        Ok(response)
    }

    pub async fn verify_mfa(
        &self, login_scene: String, mfa_type: String, account: String, code: Option<String>,
        password: Option<String>,
    ) -> Result<VerifyMfaResponse> {
        let password = password
            .map(|value| {
                PasswordCipher::generated()
                    .encrypt_aes_cbc(&value)
                    .context(error::EncryptPassword)
            })
            .transpose()?;
        let body = VerifyMfaRequest {
            login_scene,
            mfa_type,
            account,
            code,
            password,
        };
        let query = self.device_query();
        let response = with_device_query!(self.generated.verify_mfa(), query)
            .body(body)
            .send()
            .await
            .context(error::GeneratedClient)?
            .into_inner();
        check_api_status(&response)?;
        Ok(response)
    }

    pub async fn oauth_callback(
        &self, alias_key: String, code: String, state: String, code_verifier: String,
    ) -> Result<OauthCallbackResponse> {
        let body = OAuthCallbackRequest {
            alias_key,
            code,
            state,
            code_verifier,
        };
        let query = self.device_query();
        let response = with_device_query!(self.generated.oauth_callback(), query)
            .body(body)
            .send()
            .await
            .context(error::GeneratedClient)?
            .into_inner();
        check_api_status(&response)?;
        Ok(response)
    }

    pub async fn login_setting(&self) -> Result<GetLoginSettingResponse> {
        let query = self.device_query();
        let response = with_device_query!(self.generated.get_login_setting(), query)
            .send()
            .await
            .context(error::GeneratedClient)?
            .into_inner();
        check_api_status(&response)?;
        Ok(response)
    }

    pub async fn user_info(&self) -> Result<GetUserInfoResponse> {
        let query = self.device_query();
        let response = with_device_query!(self.generated.get_user_info(), query)
            .send()
            .await
            .context(error::GeneratedClient)?
            .into_inner();
        check_api_status(&response)?;
        Ok(response)
    }

    pub async fn tenant_config(&self) -> Result<GetTenantConfigResponse> {
        let query = self.device_query();
        let response = with_device_query!(self.generated.get_tenant_config(), query)
            .send()
            .await
            .context(error::GeneratedClient)?
            .into_inner();
        check_api_status(&response)?;
        Ok(response)
    }

    pub async fn vpn_setting(&self) -> Result<GetVpnSettingResponse> {
        let query = self.device_query();
        let response = with_device_query!(self.generated.get_vpn_setting(), query)
            .send()
            .await
            .context(error::GeneratedClient)?
            .into_inner();
        check_api_status(&response)?;
        Ok(response)
    }

    pub async fn vpn_locations(&self) -> Result<GetVpnLocationsResponse> {
        let query = self.device_query();
        let response = with_device_query!(self.generated.get_vpn_locations(), query)
            .send()
            .await
            .context(error::GeneratedClient)?
            .into_inner();
        check_api_status(&response)?;
        Ok(response)
    }

    pub async fn vpn_conn(
        &self, base_url_override: Option<&str>, body: &VpnConnRequest,
    ) -> Result<VpnConnEnvelope> {
        let client = match base_url_override {
            Some(base_url) => self.generated_client_for(base_url)?,
            None => self.generated.clone(),
        };
        let query = self.device_query();
        let response = with_device_query!(client.vpn_conn(), query)
            .body(body.clone())
            .send()
            .await
            .context(error::GeneratedClient)?
            .into_inner();
        check_api_status(&response)?;
        Ok(response)
    }

    pub async fn report_security(
        &self, body: &SecurityReportRequest,
    ) -> Result<ReportSecurityResponse> {
        let query = self.device_query();
        let response = with_device_query!(self.generated.report_security(), query)
            .body(body.clone())
            .send()
            .await
            .context(error::GeneratedClient)?
            .into_inner();
        check_api_status(&response)?;
        Ok(response)
    }

    fn generated_client_for(&self, base_url: &str) -> Result<codegen::Client> {
        let base_url = normalize_base_url(base_url)?;
        Ok(codegen::Client::new_with_client(
            &base_url,
            self.http.clone(),
            self.hooks.clone(),
        ))
    }

    fn device_query(&self) -> DeviceQuery {
        DeviceQuery::from_identity(&self.hooks.identity, OffsetDateTime::now_utc())
    }
}

impl ApiHooks {
    fn new(identity: ClientIdentity, signer: SigningContext, cookies: SessionCookies) -> Self {
        Self {
            identity,
            cookies: Arc::new(RwLock::new(cookies)),
            csrf_token: Arc::new(RwLock::new(None)),
            knock_token: Arc::new(RwLock::new(None)),
            signer,
        }
    }

    fn cookies(&self) -> SessionCookies {
        self.cookies
            .read()
            .map_or_else(|_| SessionCookies::default(), |guard| guard.clone())
    }

    fn base_headers(&self) -> Result<HeaderMap> {
        let mut headers = HeaderMap::new();
        headers.insert(
            ACCEPT_LANGUAGE,
            HeaderValue::from_str(&self.identity.language).context(error::HeaderValue {
                name: "Accept-Language".to_string(),
            })?,
        );
        headers.insert(
            USER_AGENT,
            HeaderValue::from_str(&self.identity.user_agent).context(error::HeaderValue {
                name: "User-Agent".to_string(),
            })?,
        );

        if let Some(cookie_header) = self.cookie_header() {
            headers.insert(
                COOKIE,
                HeaderValue::from_str(&cookie_header).context(error::HeaderValue {
                    name: "Cookie".to_string(),
                })?,
            );
        }
        if let Some(csrf) = self
            .csrf_token
            .read()
            .ok()
            .and_then(|guard| guard.clone())
            .or_else(|| self.cookie_value("csrf-token"))
        {
            headers.insert(
                HeaderName::from_static("csrf-token"),
                HeaderValue::from_str(&csrf).context(error::HeaderValue {
                    name: "csrf-token".to_string(),
                })?,
            );
        }
        if let Some(knock) = self.knock_token.read().ok().and_then(|guard| guard.clone()) {
            headers.insert(
                HeaderName::from_static("knock-token"),
                HeaderValue::from_str(&knock).context(error::HeaderValue {
                    name: "knock-token".to_string(),
                })?,
            );
        }
        Ok(headers)
    }

    fn cookie_value(&self, name: &str) -> Option<String> {
        self.cookies.read().ok()?.values.get(name).cloned()
    }

    fn cookie_header(&self) -> Option<String> {
        let guard = self.cookies.read().ok()?;
        if guard.values.is_empty() {
            return None;
        }
        Some(
            guard
                .values
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("; "),
        )
    }

    fn store_response_cookies(&self, headers: &HeaderMap) {
        let Ok(mut guard) = self.cookies.write() else {
            return;
        };
        for value in &headers.get_all(SET_COOKIE) {
            let Ok(raw) = value.to_str() else {
                continue;
            };
            let Some((name, rest)) = raw.split_once('=') else {
                continue;
            };
            let cookie_value = rest.split(';').next().unwrap_or_default();
            guard
                .values
                .insert(name.trim().to_string(), cookie_value.trim().to_string());
        }
    }
}

impl DeviceQuery {
    fn from_identity(identity: &ClientIdentity, now: OffsetDateTime) -> Self {
        Self {
            os: identity.os.clone(),
            os_version: identity.os_version.clone(),
            app_version: identity.app_version.clone(),
            brand: identity.brand.clone(),
            model: identity.model.clone(),
            did: identity.did.clone(),
            build_number: identity.build_number.clone(),
            os_version_patch: identity.os_version_patch.clone(),
            timestamp: now.unix_timestamp().to_string(),
            client_source: identity.client_source.clone(),
        }
    }
}

pub async fn prepare_generated_request(
    hooks: &ApiHooks, request: &mut reqwest::Request,
) -> Result<()> {
    request.headers_mut().extend(hooks.base_headers()?);
    let body = request
        .body()
        .and_then(reqwest::Body::as_bytes)
        .map_or_else(Vec::new, ToOwned::to_owned);
    for signed in hooks
        .signer
        .sign(
            request.method().as_str(),
            request.url(),
            request.headers(),
            &body,
        )
        .context(error::SignRequest)?
    {
        let name = HeaderName::from_bytes(signed.name.as_bytes()).context(error::HeaderName {
            name: signed.name.clone(),
        })?;
        let value = HeaderValue::from_str(&signed.value)
            .context(error::HeaderValue { name: signed.name })?;
        request.headers_mut().insert(name, value);
    }
    Ok(())
}

pub async fn store_generated_response_cookies(
    hooks: &ApiHooks, result: &reqwest::Result<reqwest::Response>,
) -> Result<()> {
    if let Ok(response) = result {
        hooks.store_response_cookies(response.headers());
    }
    Ok(())
}

fn normalize_base_url(value: &str) -> Result<String> {
    Url::parse(value).context(error::InvalidBaseUrl {
        value: value.to_string(),
    })?;
    Ok(value.trim_end_matches('/').to_string())
}

fn check_api_status(response: &impl ApiEnvelope) -> Result<()> {
    if response.code() != 0 {
        let message = response
            .message()
            .unwrap_or("unknown API error")
            .to_string();
        return error::ApiStatus {
            code: response.code(),
            message,
        }
        .fail();
    }
    Ok(())
}
