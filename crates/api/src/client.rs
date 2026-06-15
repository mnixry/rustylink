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
        GetThirdPartyLoginLinksResponse, GetUserInfoResponse, GetVpnExportsResponse,
        GetVpnLocationsResponse, GetVpnSettingResponse, LoginByPasswordResponse,
        OauthCallbackResponse, PasswordLoginRequest, ReportSecurityResponse, ReportVpnResponse,
        SecurityReportRequest, SendCodeRequest, SendLoginCodeResponse, VerifyCodeRequest,
        VerifyLoginCodeResponse, VerifyMfaRequest, VerifyMfaResponse, VpnConnEnvelope,
        VpnConnRequest, VpnDot, VpnPingResponse, VpnReportRequest,
    },
    identity::ClientIdentity,
    signing::{PasswordCipher, SigningContext},
};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("invalid base URL `{value}`"))]
    InvalidBaseUrl {
        value: String,
        source: url::ParseError,
    },

    #[snafu(display("failed to build HTTP client"))]
    BuildHttpClient { source: reqwest::Error },

    #[snafu(display("generated API request failed"))]
    GeneratedClient {
        #[snafu(source(from(progenitor_client::Error<()>, Box::new)))]
        source: Box<progenitor_client::Error<()>>,
    },

    #[snafu(display("failed to build header `{name}`"))]
    HeaderValue {
        name: String,
        source: reqwest::header::InvalidHeaderValue,
    },

    #[snafu(display("failed to build header name `{name}`"))]
    HeaderName {
        name: String,
        source: reqwest::header::InvalidHeaderName,
    },

    #[snafu(display("failed to sign request"))]
    SignRequest {
        source: crate::signing::SigningError,
    },

    #[snafu(display("failed to encrypt password"))]
    EncryptPassword {
        source: crate::signing::PasswordCipherError,
    },

    #[snafu(display("VPN dot is missing required field `{field}`"))]
    MissingVpnDotField { field: &'static str },

    #[snafu(display("invalid VPN dot port `{port}`"))]
    InvalidPort { port: i32 },

    #[snafu(display("API returned code {code}: {message}"))]
    ApiStatus { code: i32, message: String },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

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

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct VpnDotServers {
    pub api_base_url: String,
    pub wireguard_endpoint: String,
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

impl ApiClient {
    pub fn new(
        base_url: impl AsRef<str>, identity: ClientIdentity, signer: SigningContext,
        cookies: SessionCookies,
    ) -> Result<Self> {
        let base_url = normalize_base_url(base_url.as_ref())?;
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::limited(10))
            .build()
            .context(BuildHttpClientSnafu)?;
        let hooks = ApiHooks::new(identity, signer, cookies);
        let generated = codegen::Client::new_with_client(&base_url, http.clone(), hooks.clone());
        tracing::debug!(%base_url, "created API client");
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
            .context(GeneratedClientSnafu)?
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
            .context(EncryptPasswordSnafu)?;
        let body = PasswordLoginRequest {
            login_scene,
            account_type,
            account,
            password,
        };
        let response = self
            .generated
            .login_by_password()
            .body(body)
            .send()
            .await
            .context(GeneratedClientSnafu)?
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
        let response = self
            .generated
            .send_login_code()
            .body(body)
            .send()
            .await
            .context(GeneratedClientSnafu)?
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
        let response = self
            .generated
            .verify_login_code()
            .body(body)
            .send()
            .await
            .context(GeneratedClientSnafu)?
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
                    .context(EncryptPasswordSnafu)
            })
            .transpose()?;
        let body = VerifyMfaRequest {
            login_scene,
            mfa_type,
            account,
            code,
            password,
        };
        let response = self
            .generated
            .verify_mfa()
            .body(body)
            .send()
            .await
            .context(GeneratedClientSnafu)?
            .into_inner();
        check_api_status(&response)?;
        Ok(response)
    }

    pub async fn oauth_callback(
        &self, alias_key: String, code: String, state: String, code_verifier: String,
    ) -> Result<OauthCallbackResponse> {
        let _ = code_verifier;
        let response = self
            .generated
            .oauth_callback()
            .alias(alias_key)
            .code(code)
            .state(state)
            .send()
            .await
            .context(GeneratedClientSnafu)?
            .into_inner();
        check_api_status(&response)?;
        Ok(response)
    }

    pub async fn third_party_login_links(
        &self, code_challenge: String,
    ) -> Result<GetThirdPartyLoginLinksResponse> {
        let response = self
            .generated
            .get_third_party_login_links()
            .code_challenge(code_challenge)
            .send()
            .await
            .context(GeneratedClientSnafu)?
            .into_inner();
        check_api_status(&response)?;
        Ok(response)
    }

    pub async fn login_setting(&self) -> Result<GetLoginSettingResponse> {
        let response = self
            .generated
            .get_login_setting()
            .send()
            .await
            .context(GeneratedClientSnafu)?
            .into_inner();
        check_api_status(&response)?;
        Ok(response)
    }

    pub async fn user_info(&self) -> Result<GetUserInfoResponse> {
        let response = self
            .generated
            .get_user_info()
            .send()
            .await
            .context(GeneratedClientSnafu)?
            .into_inner();
        check_api_status(&response)?;
        Ok(response)
    }

    pub async fn tenant_config(&self) -> Result<GetTenantConfigResponse> {
        let response = self
            .generated
            .get_tenant_config()
            .send()
            .await
            .context(GeneratedClientSnafu)?
            .into_inner();
        check_api_status(&response)?;
        Ok(response)
    }

    pub async fn vpn_setting(&self) -> Result<GetVpnSettingResponse> {
        let response = self
            .generated
            .get_vpn_setting()
            .send()
            .await
            .context(GeneratedClientSnafu)?
            .into_inner();
        check_api_status(&response)?;
        Ok(response)
    }

    pub async fn vpn_locations(&self) -> Result<GetVpnLocationsResponse> {
        let response = self
            .generated
            .get_vpn_locations()
            .send()
            .await
            .context(GeneratedClientSnafu)?
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
        let response = client
            .vpn_conn()
            .body(body.clone())
            .send()
            .await
            .context(GeneratedClientSnafu)?
            .into_inner();
        check_api_status(&response)?;
        Ok(response)
    }

    pub async fn vpn_conn_for_dot(
        &self, dot: &VpnDot, use_vpn_ip_for_api: bool, body: &VpnConnRequest,
    ) -> Result<VpnConnEnvelope> {
        let servers = VpnDotServers::from_dot(dot, use_vpn_ip_for_api)?;
        self.vpn_conn(Some(&servers.api_base_url), body).await
    }

    pub async fn vpn_ping_for_dot(&self, dot: &VpnDot) -> Result<VpnPingResponse> {
        let servers = VpnDotServers::from_dot(dot, false)?;
        let client = self.generated_client_for(&servers.api_base_url)?;
        let response = client
            .vpn_ping()
            .send()
            .await
            .context(GeneratedClientSnafu)?
            .into_inner();
        check_api_status(&response)?;
        Ok(response)
    }

    pub async fn vpn_exports_for_dot(&self, dot: &VpnDot) -> Result<GetVpnExportsResponse> {
        let servers = VpnDotServers::from_dot(dot, false)?;
        let client = self.generated_client_for(&servers.api_base_url)?;
        let response = client
            .get_vpn_exports()
            .send()
            .await
            .context(GeneratedClientSnafu)?
            .into_inner();
        check_api_status(&response)?;
        Ok(response)
    }

    pub async fn report_vpn_for_dot(
        &self, dot: &VpnDot, body: &VpnReportRequest,
    ) -> Result<ReportVpnResponse> {
        let servers = VpnDotServers::from_dot(dot, false)?;
        let client = self.generated_client_for(&servers.api_base_url)?;
        let response = client
            .report_vpn()
            .body(body.clone())
            .send()
            .await
            .context(GeneratedClientSnafu)?
            .into_inner();
        check_api_status(&response)?;
        Ok(response)
    }

    pub async fn report_security(
        &self, body: &SecurityReportRequest,
    ) -> Result<ReportSecurityResponse> {
        let response = self
            .generated
            .report_security()
            .body(body.clone())
            .send()
            .await
            .context(GeneratedClientSnafu)?
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
        let accept_language = if self.identity.language.contains("zh") {
            "zh-CN"
        } else {
            "en-US"
        };
        headers.insert(
            ACCEPT_LANGUAGE,
            HeaderValue::from_str(accept_language).context(HeaderValueSnafu {
                name: "Accept-Language".to_string(),
            })?,
        );
        headers.insert(
            USER_AGENT,
            HeaderValue::from_str(&self.identity.user_agent).context(HeaderValueSnafu {
                name: "User-Agent".to_string(),
            })?,
        );

        if let Some(cookie_header) = self.cookie_header() {
            headers.insert(
                COOKIE,
                HeaderValue::from_str(&cookie_header).context(HeaderValueSnafu {
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
                HeaderValue::from_str(&csrf).context(HeaderValueSnafu {
                    name: "csrf-token".to_string(),
                })?,
            );
        }
        if let Some(knock) = self.knock_token.read().ok().and_then(|guard| guard.clone()) {
            headers.insert(
                HeaderName::from_static("knock-token"),
                HeaderValue::from_str(&knock).context(HeaderValueSnafu {
                    name: "knock-token".to_string(),
                })?,
            );
        }
        if let Some(vpn_token) = self.cookie_value("vpn-token") {
            headers.insert(
                HeaderName::from_static("jwt-token"),
                HeaderValue::from_str(&vpn_token).context(HeaderValueSnafu {
                    name: "jwt-token".to_string(),
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
            tracing::warn!("failed to acquire cookie jar write lock");
            return;
        };
        let before_count = guard.values.len();
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
        let after_count = guard.values.len();
        tracing::debug!(
            stored_cookie_delta = after_count.saturating_sub(before_count),
            total_cookie_count = after_count,
            "stored response cookies"
        );
    }
}

impl VpnDot {
    #[must_use]
    pub fn api_host(&self) -> Option<&str> {
        self.ip4_domain
            .as_deref()
            .filter(|value| !value.is_empty())
            .or_else(|| self.fast_ip.as_deref().filter(|value| !value.is_empty()))
            .or_else(|| self.api_ip.as_deref().filter(|value| !value.is_empty()))
    }

    #[must_use]
    pub fn config_api_host(&self, use_vpn_ip_for_api: bool) -> Option<&str> {
        if use_vpn_ip_for_api {
            self.ip
                .as_deref()
                .filter(|value| !value.is_empty())
                .or_else(|| self.api_host())
        } else {
            self.api_host()
        }
    }

    #[must_use]
    pub fn should_use_vpn_ip_for_config_api(&self, is_auto_location: bool) -> bool {
        if is_auto_location || self.ip.as_deref().is_none_or(str::is_empty) {
            return false;
        }
        self.ip_delay_routing_policy.as_ref().is_some_and(|policy| {
            policy.is_operator.unwrap_or(false) && policy.policy_type == Some(1)
        })
    }

    #[must_use]
    pub fn supports_reconnect(&self) -> bool {
        self.reconnect.unwrap_or(false)
            && !self.dedicated.unwrap_or(false)
            && !self.exclude.unwrap_or(false)
    }

    #[must_use]
    pub fn supports_android_mode(&self, requested_mode: i32) -> bool {
        !matches!((self.mode, requested_mode), (Some(2), 1) | (Some(1), 0))
    }

    #[must_use]
    pub fn protocol_detect_enabled(&self) -> bool {
        self.protocol_detect_config
            .as_ref()
            .and_then(|config| config.enable)
            .unwrap_or(false)
    }
}

impl VpnDotServers {
    pub fn from_dot(dot: &VpnDot, use_vpn_ip_for_api: bool) -> Result<Self> {
        let api_host = dot.api_host().context(MissingVpnDotFieldSnafu {
            field: "apiIp/ip4Domain/fastIp",
        })?;
        let api_host_for_conn =
            dot.config_api_host(use_vpn_ip_for_api)
                .context(MissingVpnDotFieldSnafu {
                    field: "apiIp/ip4Domain/fastIp",
                })?;
        let api_port = dot
            .api_port
            .context(MissingVpnDotFieldSnafu { field: "api_port" })?;
        let vpn_port = dot
            .vpn_port
            .context(MissingVpnDotFieldSnafu { field: "vpn_port" })?;
        let api_base_url = format_https_host_port(api_host_for_conn, api_port)?;
        let wireguard_endpoint = format_host_port(api_host, vpn_port)?;
        Ok(Self {
            api_base_url,
            wireguard_endpoint,
        })
    }
}

pub async fn prepare_generated_request(
    hooks: &ApiHooks, request: &mut reqwest::Request,
) -> Result<()> {
    {
        let mut query = request.url_mut().query_pairs_mut();
        for (key, value) in hooks.identity.query_pairs(OffsetDateTime::now_utc()) {
            query.append_pair(key, &value);
        }
    }
    request.headers_mut().extend(hooks.base_headers()?);
    let body = request
        .body()
        .and_then(reqwest::Body::as_bytes)
        .map_or_else(Vec::new, ToOwned::to_owned);
    let signed_headers = hooks
        .signer
        .sign(
            request.method().as_str(),
            request.url(),
            request.headers(),
            &body,
        )
        .context(SignRequestSnafu)?;
    let signed_header_count = signed_headers.len();
    for signed in signed_headers {
        let name = HeaderName::from_bytes(signed.name.as_bytes()).context(HeaderNameSnafu {
            name: signed.name.clone(),
        })?;
        let value =
            HeaderValue::from_str(&signed.value).context(HeaderValueSnafu { name: signed.name })?;
        request.headers_mut().insert(name, value);
    }
    tracing::debug!(
        method = %request.method(),
        host = request.url().host_str().unwrap_or("<none>"),
        path = request.url().path(),
        signed_header_count,
        "prepared generated API request"
    );
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
    Url::parse(value).context(InvalidBaseUrlSnafu {
        value: value.to_string(),
    })?;
    Ok(value.trim_end_matches('/').to_string())
}

fn format_https_host_port(host: &str, port: i32) -> Result<String> {
    Ok(format!("https://{}", format_host_port(host, port)?))
}

fn format_host_port(host: &str, port: i32) -> Result<String> {
    if port <= 0 || port > i32::from(u16::MAX) {
        return InvalidPortSnafu { port }.fail();
    }
    let host = host.trim();
    if host.is_empty() {
        return MissingVpnDotFieldSnafu { field: "host" }.fail();
    }
    if host.contains(':') && !(host.starts_with('[') && host.ends_with(']')) {
        Ok(format!("[{host}]:{port}"))
    } else {
        Ok(format!("{host}:{port}"))
    }
}

fn check_api_status(response: &impl ApiEnvelope) -> Result<()> {
    if response.code() != 0 {
        let message = response
            .message()
            .unwrap_or("unknown API error")
            .to_string();
        return ApiStatusSnafu {
            code: response.code(),
            message,
        }
        .fail();
    }
    Ok(())
}
