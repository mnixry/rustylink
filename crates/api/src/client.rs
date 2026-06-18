use std::{
    collections::BTreeMap,
    sync::{Arc, RwLock},
};

use jiff::Timestamp;
use reqwest::{
    Request,
    header::{
        ACCEPT, ACCEPT_LANGUAGE, CONTENT_TYPE, COOKIE, HeaderMap, HeaderName, HeaderValue,
        SET_COOKIE, USER_AGENT,
    },
};
use snafu::prelude::*;
use url::Url;

use crate::{
    identity::ClientIdentity,
    models::{ApiResponse, BaseResponse, SendableRequest, VpnDot},
    signing::SigningContext,
};

pub const DEFAULT_MATCH_BASE_URL: &str = "https://corplink.volcengine.cn";

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

    #[snafu(display("failed to encode API request body"))]
    Encode { source: serde_json::Error },

    #[snafu(display("failed to build API request"))]
    BuildRequest { source: reqwest::Error },

    #[snafu(display("API request failed"))]
    Request { source: reqwest::Error },

    #[snafu(display("response decode failed: {source}; content: {content}"))]
    Decode {
        source: serde_json::Error,
        content: String,
    },

    #[snafu(display("HTTP API status {status}: {content}"))]
    HttpStatus {
        status: reqwest::StatusCode,
        content: String,
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
    ApiStatus {
        code: i32,
        message: String,
        response: Box<BaseResponse<serde_json::Value>>,
    },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct SessionCookies {
    pub values: BTreeMap<String, String>,
}

#[derive(Clone, Debug)]
pub(crate) struct ApiHooks {
    identity: ClientIdentity,
    cookies: Arc<RwLock<SessionCookies>>,
    csrf_token: Arc<RwLock<Option<String>>>,
    knock_token: Arc<RwLock<Option<String>>>,
    signer: SigningContext,
}

#[derive(Clone)]
pub struct ApiClient {
    base_url: Url,
    http: reqwest::Client,
    hooks: ApiHooks,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ApiClientOptions {
    pub outbound_interface: Option<String>,
}

pub trait ApiEndpoint: Clone + Send + Sync {
    fn base_url(&self) -> &Url;

    fn client(
        &self, identity: ClientIdentity, signer: SigningContext, cookies: SessionCookies,
    ) -> Result<ApiClient> {
        self.client_with_options(identity, signer, cookies, &ApiClientOptions::from_env())
    }

    fn client_with_options(
        &self, identity: ClientIdentity, signer: SigningContext, cookies: SessionCookies,
        options: &ApiClientOptions,
    ) -> Result<ApiClient> {
        ApiClient::from_endpoint(self, identity, signer, cookies, options)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct MatchEndpoint {
    pub base_url: Url,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct TenantEndpoint {
    pub base_url: Url,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct DotEndpoint {
    pub api_base_url: Url,
    pub wireguard_endpoint: Url,
}

impl ApiEndpoint for MatchEndpoint {
    fn base_url(&self) -> &Url {
        &self.base_url
    }
}

impl ApiEndpoint for TenantEndpoint {
    fn base_url(&self) -> &Url {
        &self.base_url
    }
}

impl ApiEndpoint for DotEndpoint {
    fn base_url(&self) -> &Url {
        &self.api_base_url
    }
}

impl Default for MatchEndpoint {
    fn default() -> Self {
        Self {
            base_url: Url::parse(DEFAULT_MATCH_BASE_URL).expect("default match URL is valid"),
        }
    }
}

impl MatchEndpoint {
    pub fn new(base_url: impl AsRef<str>) -> Result<Self> {
        Ok(Self {
            base_url: parse_base_url(base_url.as_ref())?,
        })
    }
}

impl TenantEndpoint {
    pub fn new(base_url: impl AsRef<str>) -> Result<Self> {
        Ok(Self {
            base_url: parse_base_url(base_url.as_ref())?,
        })
    }
}

impl DotEndpoint {
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
        Ok(Self {
            api_base_url: url_from_host_port("https", api_host_for_conn, api_port)?,
            wireguard_endpoint: url_from_host_port("udp", api_host, vpn_port)?,
        })
    }
}

impl ApiClient {
    pub fn from_endpoint<E: ApiEndpoint>(
        endpoint: &E, identity: ClientIdentity, signer: SigningContext, cookies: SessionCookies,
        options: &ApiClientOptions,
    ) -> Result<Self> {
        let base_url = endpoint.base_url().clone();
        let mut http_builder =
            reqwest::Client::builder().redirect(reqwest::redirect::Policy::limited(10));
        if let Some(interface) = options.outbound_interface.as_deref() {
            tracing::debug!(
                outbound_interface = interface,
                "binding API HTTP client to outbound interface"
            );
            http_builder = http_builder.interface(interface);
        }
        let http = http_builder.build().context(BuildHttpClientSnafu)?;
        let hooks = ApiHooks::new(identity, signer, cookies);
        tracing::debug!(%base_url, "created API client");
        Ok(Self {
            base_url,
            http,
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

    pub async fn send<R>(&self, request: R) -> Result<R::Response>
    where
        R: SendableRequest, {
        let response_body = self.execute(request).await?;
        let decoded = decode_response::<R::Response>(&response_body)?;
        check_api_status(&decoded, &response_body)?;
        Ok(decoded)
    }

    async fn execute<R>(&self, request: R) -> Result<Vec<u8>>
    where
        R: SendableRequest, {
        let url = endpoint_url(&self.base_url, request.path().as_ref())?;
        let endpoint_query = request.query_pairs();
        let body = request.body().context(EncodeSnafu)?;
        let mut builder = self
            .http
            .request(R::METHOD, url)
            .header(ACCEPT, "application/json");
        if let Some(body) = body {
            builder = builder.header(CONTENT_TYPE, "application/json").body(body);
        }
        let mut http_request = builder.build().context(BuildRequestSnafu)?;
        {
            let mut query = http_request.url_mut().query_pairs_mut();
            for (key, value) in endpoint_query {
                query.append_pair(key, &value);
            }
        }
        prepare_api_request(&self.hooks, &mut http_request)?;
        let response = self
            .http
            .execute(http_request)
            .await
            .context(RequestSnafu)?;
        self.hooks.store_response_cookies(response.headers());
        let status = response.status();
        let bytes = response.bytes().await.context(RequestSnafu)?.to_vec();
        if !status.is_success() {
            return HttpStatusSnafu {
                status,
                content: response_content(&bytes),
            }
            .fail();
        }
        Ok(bytes)
    }
}

impl ApiClientOptions {
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            outbound_interface: std::env::var("RUSTYLINK_OUTBOUND_INTERFACE")
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
        }
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

fn parse_base_url(value: &str) -> Result<Url> {
    Url::parse(value).context(InvalidBaseUrlSnafu {
        value: value.to_string(),
    })
}

fn endpoint_url(base_url: &Url, path: &str) -> Result<Url> {
    base_url.join(path).context(InvalidBaseUrlSnafu {
        value: path.to_string(),
    })
}

fn decode_response<T>(bytes: &[u8]) -> Result<T>
where
    T: serde::de::DeserializeOwned, {
    serde_json::from_slice(bytes).context(DecodeSnafu {
        content: response_content(bytes),
    })
}

fn check_api_status(response: &impl ApiResponse, body: &[u8]) -> Result<()> {
    if response.code() == 0 {
        return Ok(());
    }

    let message = response
        .message()
        .unwrap_or("unknown API error")
        .to_string();
    let response = serde_json::from_slice(body).unwrap_or_else(|_| BaseResponse {
        code: response.code(),
        message: Some(message.clone()),
        data: None,
        action: None,
        logout_reason: None,
        extra: None,
    });
    ApiStatusSnafu {
        code: response.code,
        message,
        response: Box::new(response),
    }
    .fail()
}

fn prepare_api_request(hooks: &ApiHooks, request: &mut Request) -> Result<()> {
    {
        let mut query = request.url_mut().query_pairs_mut();
        for (key, value) in hooks.identity.query_pairs(Timestamp::now()) {
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
        "prepared API request"
    );
    Ok(())
}

fn response_content(bytes: &[u8]) -> String {
    const MAX_ERROR_CONTENT_BYTES: usize = 4096;
    if bytes.len() <= MAX_ERROR_CONTENT_BYTES {
        return String::from_utf8_lossy(bytes).into_owned();
    }
    format!(
        "{} ... [truncated {} bytes]",
        String::from_utf8_lossy(&bytes[..MAX_ERROR_CONTENT_BYTES]),
        bytes.len() - MAX_ERROR_CONTENT_BYTES
    )
}

fn url_from_host_port(scheme: &str, host: &str, port: i32) -> Result<Url> {
    if port <= 0 || port > i32::from(u16::MAX) {
        return InvalidPortSnafu { port }.fail();
    }
    let host = host.trim();
    if host.is_empty() {
        return MissingVpnDotFieldSnafu { field: "host" }.fail();
    }
    let mut url = match scheme {
        "https" => Url::parse("https://placeholder.invalid/"),
        "udp" => Url::parse("udp://placeholder.invalid/"),
        _ => {
            return Err(Error::InvalidBaseUrl {
                value: scheme.to_string(),
                source: url::ParseError::RelativeUrlWithoutBase,
            });
        }
    }
    .context(InvalidBaseUrlSnafu {
        value: scheme.to_string(),
    })?;
    url.set_host(Some(host)).context(InvalidBaseUrlSnafu {
        value: host.to_string(),
    })?;
    url.set_port(Some(u16::try_from(port).expect("port range checked")))
        .map_err(|()| Error::InvalidPort { port })?;
    Ok(url)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn endpoint_url_joins_absolute_request_paths() {
        let endpoint = TenantEndpoint::new("https://tenant.example/base").expect("endpoint");
        let url = endpoint_url(&endpoint.base_url, "/api/vpn/list").expect("url");

        assert_eq!(url.as_str(), "https://tenant.example/api/vpn/list");
    }

    #[test]
    fn dot_endpoint_builds_api_and_wireguard_urls() {
        let dot = serde_json::from_value::<VpnDot>(json!({
            "apiIp": "api.example",
            "api_port": 8443,
            "ip": "10.0.0.12",
            "vpn_port": 51820
        }))
        .expect("dot");

        let endpoint = DotEndpoint::from_dot(&dot, true).expect("endpoint");

        assert_eq!(endpoint.api_base_url.as_str(), "https://10.0.0.12:8443/");
        assert_eq!(
            endpoint.wireguard_endpoint.as_str(),
            "udp://api.example:51820/"
        );
    }
}
