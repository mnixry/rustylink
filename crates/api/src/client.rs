use std::{
    collections::BTreeMap,
    fmt,
    sync::{Arc, RwLock},
};

use jiff::Timestamp;
use reqwest::{
    Request, Response,
    header::{ACCEPT_LANGUAGE, COOKIE, HeaderMap, HeaderName, HeaderValue, SET_COOKIE, USER_AGENT},
};
use reqwest_middleware::{ClientBuilder, Middleware, Next};
use snafu::prelude::*;
use url::Url;

use crate::{
    apis::{self, configuration::Configuration},
    identity::ClientIdentity,
    models::VpnDot,
    signing::SigningContext,
};

pub const DEFAULT_MATCH_BASE_URL: &str = "https://corplink.volcengine.cn";

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum RawApiError {
    #[snafu(display("request builder failed: {source}"))]
    Reqwest { source: reqwest::Error },

    #[snafu(display("request middleware failed: {source}"))]
    Middleware { source: reqwest_middleware::Error },

    #[snafu(display("response decode failed: {source}"))]
    Decode { source: serde_json::Error },

    #[snafu(display("response IO failed: {source}"))]
    Io { source: std::io::Error },

    #[snafu(display("HTTP API status {status}: {content}"))]
    Response {
        status: reqwest::StatusCode,
        content: String,
        entity: Option<String>,
    },
}

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

    #[snafu(display("generated API request failed: {source}"))]
    RawApi { source: RawApiError },

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
pub(crate) struct ApiHooks {
    identity: ClientIdentity,
    cookies: Arc<RwLock<SessionCookies>>,
    csrf_token: Arc<RwLock<Option<String>>>,
    knock_token: Arc<RwLock<Option<String>>>,
    signer: SigningContext,
}

#[derive(Clone)]
pub struct ApiClient {
    base_url: String,
    http: reqwest::Client,
    hooks: ApiHooks,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ApiClientOptions {
    pub outbound_interface: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, serde::Deserialize, serde::Serialize)]
pub struct VpnDotServers {
    pub api_base_url: String,
    pub wireguard_endpoint: String,
}

#[derive(Clone, Debug)]
struct ApiMiddleware {
    hooks: ApiHooks,
}

impl ApiClient {
    pub fn new(
        base_url: impl AsRef<str>, identity: ClientIdentity, signer: SigningContext,
        cookies: SessionCookies,
    ) -> Result<Self> {
        Self::new_with_options(
            base_url,
            identity,
            signer,
            cookies,
            &ApiClientOptions::from_env(),
        )
    }

    pub fn new_with_options(
        base_url: impl AsRef<str>, identity: ClientIdentity, signer: SigningContext,
        cookies: SessionCookies, options: &ApiClientOptions,
    ) -> Result<Self> {
        let base_url = normalize_base_url(base_url.as_ref())?;
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

    pub(crate) fn configuration(&self) -> Configuration {
        self.configuration_for_normalized_base_url(self.base_url.clone())
    }

    pub(crate) fn configuration_for_base_url(&self, base_url: &str) -> Result<Configuration> {
        let base_url = normalize_base_url(base_url)?;
        Ok(self.configuration_for_normalized_base_url(base_url))
    }

    fn configuration_for_normalized_base_url(&self, base_url: String) -> Configuration {
        Configuration {
            base_path: base_url,
            user_agent: None,
            client: ClientBuilder::new(self.http.clone())
                .with(ApiMiddleware {
                    hooks: self.hooks.clone(),
                })
                .build(),
            basic_auth: None,
            oauth_access_token: None,
            bearer_access_token: None,
            api_key: None,
        }
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

#[async_trait::async_trait]
impl Middleware for ApiMiddleware {
    async fn handle(
        &self, mut request: Request, extensions: &mut http::Extensions, next: Next<'_>,
    ) -> reqwest_middleware::Result<Response> {
        prepare_openapi_request(&self.hooks, &mut request)
            .map_err(reqwest_middleware::Error::middleware)?;
        let response = next.run(request, extensions).await;
        if let Ok(response) = &response {
            self.hooks.store_response_cookies(response.headers());
        }
        response
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

impl RawApiError {
    pub(crate) fn from_openapi<T: fmt::Debug>(source: apis::Error<T>) -> Self {
        match source {
            apis::Error::Reqwest(source) => Self::Reqwest { source },
            apis::Error::ReqwestMiddleware(source) => Self::Middleware { source },
            apis::Error::Serde(source) => Self::Decode { source },
            apis::Error::Io(source) => Self::Io { source },
            apis::Error::ResponseError(response) => Self::Response {
                status: response.status,
                content: response.content,
                entity: response.entity.map(|entity| format!("{entity:?}")),
            },
        }
    }
}

pub(crate) fn openapi_error<T: fmt::Debug>(source: apis::Error<T>) -> Error {
    Error::RawApi {
        source: RawApiError::from_openapi(source),
    }
}

fn prepare_openapi_request(hooks: &ApiHooks, request: &mut Request) -> Result<()> {
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
        "prepared generated API request"
    );
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
