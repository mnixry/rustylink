use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};

use reqwest::{
    Method, StatusCode,
    header::{ACCEPT_LANGUAGE, COOKIE, HeaderMap, HeaderName, HeaderValue, SET_COOKIE, USER_AGENT},
};
use serde::{Serialize, de::DeserializeOwned};
use snafu::prelude::*;
use time::OffsetDateTime;
use tracing::{debug, instrument};
use url::Url;

use crate::{
    error,
    error::Result,
    identity::ClientIdentity,
    models::{
        ActivateInfo, ActivateRequest, BaseResponse, LoginResult, LoginSetting,
        OAuthCallbackRequest, PasswordLoginRequest, SecurityReportRequest, SendCodeRequest,
        TenantConfig, UserInfo, VerifyCodeRequest, VerifyMfaRequest, VpnConnRequest,
        VpnConnResponse, VpnLocation, VpnSetting,
    },
    signing::{PasswordCipher, SigningContext},
};

#[derive(Clone, Debug, serde::Deserialize, serde::Serialize)]
pub struct EndpointPaths {
    pub activate: String,
    pub login_password: String,
    pub send_login_code: String,
    pub verify_login_code: String,
    pub verify_mfa: String,
    pub oauth_callback: String,
    #[serde(default = "EndpointPaths::default_login_setting_path")]
    pub login_setting: String,
    pub user_info: String,
    pub tenant_config: String,
    pub vpn_setting: String,
    pub vpn_locations: String,
    pub vpn_conn: String,
    pub security_report: String,
}

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct SessionCookies {
    pub values: BTreeMap<String, String>,
}

#[derive(Clone)]
pub struct ApiClient {
    base_url: Url,
    http: reqwest::Client,
    identity: ClientIdentity,
    paths: EndpointPaths,
    cookies: Arc<RwLock<SessionCookies>>,
    csrf_token: Arc<RwLock<Option<String>>>,
    knock_token: Arc<RwLock<Option<String>>>,
    signer: SigningContext,
}

impl EndpointPaths {
    #[must_use]
    pub fn static_evidence_defaults() -> Self {
        Self {
            activate: "/activation/match".to_string(),
            login_password: "/api/login/v2/password".to_string(),
            send_login_code: "/api/login/v2/code/send".to_string(),
            verify_login_code: "/api/login/v2/code/verify".to_string(),
            verify_mfa: "/api/login/v2/mfa/verify".to_string(),
            oauth_callback: "/api/login/v2/oauth/callback".to_string(),
            login_setting: Self::default_login_setting_path(),
            user_info: "/api/user/info".to_string(),
            tenant_config: "/api/tenant/config".to_string(),
            vpn_setting: "/api/vpn/setting".to_string(),
            vpn_locations: "/api/vpn/locations".to_string(),
            vpn_conn: "/vpn/conn".to_string(),
            security_report: "/api/security/report".to_string(),
        }
    }

    fn default_login_setting_path() -> String {
        "/api/login/setting".to_string()
    }
}

impl Default for EndpointPaths {
    fn default() -> Self {
        Self::static_evidence_defaults()
    }
}

impl ApiClient {
    pub fn new(
        base_url: impl AsRef<str>, identity: ClientIdentity, signer: SigningContext,
        paths: EndpointPaths, cookies: SessionCookies,
    ) -> Result<Self> {
        let base_url_value = base_url.as_ref().to_string();
        let base_url = Url::parse(&base_url_value).context(error::InvalidBaseUrl {
            value: base_url_value,
        })?;
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::limited(10))
            .build()
            .context(error::BuildHttpClient)?;
        Ok(Self {
            base_url,
            http,
            identity,
            paths,
            cookies: Arc::new(RwLock::new(cookies)),
            csrf_token: Arc::new(RwLock::new(None)),
            knock_token: Arc::new(RwLock::new(None)),
            signer,
        })
    }

    #[must_use]
    pub fn cookies(&self) -> SessionCookies {
        self.cookies
            .read()
            .map_or_else(|_| SessionCookies::default(), |guard| guard.clone())
    }

    pub fn set_csrf_token(&self, token: Option<String>) {
        if let Ok(mut guard) = self.csrf_token.write() {
            *guard = token;
        }
    }

    pub fn set_knock_token(&self, token: Option<String>) {
        if let Ok(mut guard) = self.knock_token.write() {
            *guard = token;
        }
    }

    pub async fn activate(&self, code: String) -> Result<BaseResponse<ActivateInfo>> {
        self.post_without_device_query(&self.paths.activate, &ActivateRequest { code })
            .await
    }

    pub async fn login_password(
        &self, login_scene: String, account_type: String, account: String, password: String,
    ) -> Result<BaseResponse<LoginResult>> {
        let cipher = PasswordCipher::generated();
        let encrypted = cipher
            .encrypt_aes_cbc(&password)
            .context(error::EncryptPassword)?;
        let body = PasswordLoginRequest {
            login_scene,
            account_type,
            account,
            password: encrypted,
        };
        self.post_json(&self.paths.login_password, &body).await
    }

    pub async fn send_login_code(
        &self, login_scene: String, account_type: String, login_type: String, account: String,
    ) -> Result<BaseResponse<String>> {
        let body = SendCodeRequest {
            login_scene,
            account_type,
            login_type,
            account,
        };
        self.post_json(&self.paths.send_login_code, &body).await
    }

    pub async fn verify_login_code(
        &self, login_scene: String, account_type: String, login_type: String, account: String,
        code: String,
    ) -> Result<BaseResponse<LoginResult>> {
        let body = VerifyCodeRequest {
            login_scene,
            account_type,
            login_type,
            account,
            code,
        };
        self.post_json(&self.paths.verify_login_code, &body).await
    }

    pub async fn verify_mfa(
        &self, login_scene: String, mfa_type: String, account: String, code: Option<String>,
        password: Option<String>,
    ) -> Result<BaseResponse<LoginResult>> {
        let encrypted_password = match password {
            Some(value) => Some(
                PasswordCipher::generated()
                    .encrypt_aes_cbc(&value)
                    .context(error::EncryptPassword)?,
            ),
            None => None,
        };
        let body = VerifyMfaRequest {
            login_scene,
            mfa_type,
            account,
            code,
            password: encrypted_password,
        };
        self.post_json(&self.paths.verify_mfa, &body).await
    }

    pub async fn oauth_callback(
        &self, alias_key: String, code: String, state: String, code_verifier: String,
    ) -> Result<BaseResponse<LoginResult>> {
        let body = OAuthCallbackRequest {
            alias_key,
            code,
            state,
            code_verifier,
        };
        self.post_json(&self.paths.oauth_callback, &body).await
    }

    pub async fn login_setting(&self) -> Result<BaseResponse<LoginSetting>> {
        self.get_json(&self.paths.login_setting).await
    }

    pub async fn user_info(&self) -> Result<BaseResponse<UserInfo>> {
        self.get_json(&self.paths.user_info).await
    }

    pub async fn tenant_config(&self) -> Result<BaseResponse<TenantConfig>> {
        self.get_json(&self.paths.tenant_config).await
    }

    pub async fn vpn_setting(&self) -> Result<BaseResponse<VpnSetting>> {
        self.get_json(&self.paths.vpn_setting).await
    }

    pub async fn vpn_locations(&self) -> Result<BaseResponse<Vec<VpnLocation>>> {
        self.get_json(&self.paths.vpn_locations).await
    }

    pub async fn vpn_conn(
        &self, base_url_override: Option<&str>, body: &VpnConnRequest,
    ) -> Result<BaseResponse<VpnConnResponse>> {
        if let Some(base_url) = base_url_override {
            return self
                .request_json_with_base(
                    Method::POST,
                    base_url,
                    &self.paths.vpn_conn,
                    Some(body),
                    true,
                )
                .await;
        }
        self.post_json(&self.paths.vpn_conn, body).await
    }

    pub async fn report_security(
        &self, body: &SecurityReportRequest,
    ) -> Result<BaseResponse<String>> {
        self.post_json(&self.paths.security_report, body).await
    }

    async fn get_json<T>(&self, path: &str) -> Result<BaseResponse<T>>
    where
        T: DeserializeOwned, {
        self.request_json::<(), T>(Method::GET, path, None, true)
            .await
    }

    async fn post_json<B, T>(&self, path: &str, body: &B) -> Result<BaseResponse<T>>
    where
        B: Serialize + Sync + ?Sized,
        T: DeserializeOwned, {
        self.request_json(Method::POST, path, Some(body), true)
            .await
    }

    async fn post_without_device_query<B, T>(
        &self, path: &str, body: &B,
    ) -> Result<BaseResponse<T>>
    where
        B: Serialize + Sync + ?Sized,
        T: DeserializeOwned, {
        self.request_json(Method::POST, path, Some(body), false)
            .await
    }

    async fn request_json<B, T>(
        &self, method: Method, path: &str, body: Option<&B>, include_device_query: bool,
    ) -> Result<BaseResponse<T>>
    where
        B: Serialize + Sync + ?Sized,
        T: DeserializeOwned, {
        let base_url = self.base_url.as_str().to_string();
        self.request_json_with_base(method, &base_url, path, body, include_device_query)
            .await
    }

    #[instrument(skip(self, body), fields(method = %method, path = path))]
    async fn request_json_with_base<B, T>(
        &self, method: Method, base_url: &str, path: &str, body: Option<&B>,
        include_device_query: bool,
    ) -> Result<BaseResponse<T>>
    where
        B: Serialize + Sync + ?Sized,
        T: DeserializeOwned, {
        let mut url = Url::parse(base_url).context(error::InvalidBaseUrl {
            value: base_url.to_string(),
        })?;
        let absolute_path = format!("/{}", path.trim_start_matches('/'));
        url = url.join(&absolute_path).context(error::InvalidBaseUrl {
            value: format!("{base_url}{path}"),
        })?;
        let now = OffsetDateTime::now_utc();
        if include_device_query {
            let mut pairs = url.query_pairs_mut();
            for (key, value) in self.identity.query_pairs(now) {
                pairs.append_pair(key, &value);
            }
        }

        let body_bytes = match body {
            Some(value) => serde_json::to_vec(value).context(error::EncodeRequest)?,
            None => Vec::new(),
        };

        let mut headers = self.base_headers()?;
        for signed in self
            .signer
            .sign(method.as_str(), &url, &headers, &body_bytes)
            .context(error::SignRequest)?
        {
            let name =
                HeaderName::from_bytes(signed.name.as_bytes()).context(error::HeaderName {
                    name: signed.name.clone(),
                })?;
            let value = HeaderValue::from_str(&signed.value)
                .context(error::HeaderValue { name: signed.name })?;
            headers.insert(name, value);
        }

        let mut request = self
            .http
            .request(method.clone(), url.clone())
            .headers(headers);
        if body.is_some() {
            request = request
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body_bytes);
        }

        debug!("sending API request");
        let response = request.send().await.context(error::HttpRequest {
            method: method.to_string(),
            url: url.to_string(),
        })?;
        self.store_response_cookies(response.headers());
        let status = response.status();
        let decoded = response
            .json::<BaseResponse<T>>()
            .await
            .context(error::DecodeResponse {
                url: url.to_string(),
            })?;
        if status != StatusCode::OK {
            debug!(%status, "non-200 API status");
        }
        if decoded.code != 0 {
            let message = decoded
                .message
                .clone()
                .unwrap_or_else(|| "unknown API error".to_string());
            return error::ApiStatus {
                code: decoded.code,
                message,
            }
            .fail();
        }
        Ok(decoded)
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
