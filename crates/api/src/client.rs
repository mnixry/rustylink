use std::collections::BTreeMap;

use jiff::Timestamp;
use reqwest::{
    Request,
    header::{
        ACCEPT, ACCEPT_LANGUAGE, CONTENT_TYPE, COOKIE, DATE, HeaderMap, HeaderName, HeaderValue,
        SET_COOKIE, USER_AGENT,
    },
};
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware, Middleware, Next};
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

    #[snafu(display("request middleware failed: {message}"))]
    MiddlewareFailed { message: String },

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

// ---------------------------------------------------------------------------
// Session cookies (plain value type)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct SessionCookies {
    pub values: BTreeMap<String, String>,
}

impl SessionCookies {
    /// Build from a proto `map<string, string>` (`HashMap`).
    #[must_use]
    pub fn from_map(map: &std::collections::HashMap<String, String>) -> Self {
        Self {
            values: map.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
        }
    }

    /// Convert to a proto-compatible `HashMap`.
    #[must_use]
    pub fn to_map(&self) -> std::collections::HashMap<String, String> {
        self.values
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Response metadata — extracted from HTTP response headers
// ---------------------------------------------------------------------------

/// Metadata extracted from an HTTP response, returned alongside the typed body.
///
/// Callers inspect this to determine if cookies, CSRF, or the server `Date`
/// header changed, and emit the appropriate `StateChange` variants.
#[derive(Clone, Debug, Default)]
pub struct ResponseMeta {
    /// Cookies set by `Set-Cookie` headers (merged over the request snapshot).
    pub cookies: Option<SessionCookies>,
    /// CSRF token extracted from a `csrf-token` `Set-Cookie`, if present.
    pub csrf_token: Option<String>,
    /// Server `Date` header value, used for TOTP time-diff calculation.
    pub server_date: Option<String>,
    /// Whether the response signalled a force-logout via `action`.
    pub is_force_logout: bool,
}

// ---------------------------------------------------------------------------
// ApiHooks — snapshot of auth state used to decorate requests
// ---------------------------------------------------------------------------

/// Request-decoration hooks (snapshot). All fields are plain owned values.
/// A new `ApiHooks` is built from the current `PersistedState` each time the
/// actor refreshes the `AppContext`.
#[derive(Clone, Debug)]
pub struct ApiHooks {
    pub identity: ClientIdentity,
    pub cookies: SessionCookies,
    pub csrf_token: Option<String>,
    pub knock_token: Option<String>,
    pub signer: SigningContext,
}

impl ApiHooks {
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

        if let Some(cookie_header) = cookie_header(&self.cookies) {
            headers.insert(
                COOKIE,
                HeaderValue::from_str(&cookie_header).context(HeaderValueSnafu {
                    name: "Cookie".to_string(),
                })?,
            );
        }
        if let Some(csrf) = self
            .csrf_token
            .as_deref()
            .or_else(|| self.cookies.values.get("csrf-token").map(String::as_str))
        {
            headers.insert(
                HeaderName::from_static("csrf-token"),
                HeaderValue::from_str(csrf).context(HeaderValueSnafu {
                    name: "csrf-token".to_string(),
                })?,
            );
        }
        if let Some(knock) = self.knock_token.as_deref() {
            headers.insert(
                HeaderName::from_static("knock-token"),
                HeaderValue::from_str(knock).context(HeaderValueSnafu {
                    name: "knock-token".to_string(),
                })?,
            );
        }
        if let Some(vpn_token) = self.cookies.values.get("vpn-token") {
            headers.insert(
                HeaderName::from_static("jwt-token"),
                HeaderValue::from_str(vpn_token).context(HeaderValueSnafu {
                    name: "jwt-token".to_string(),
                })?,
            );
        }
        Ok(headers)
    }
}

// ---------------------------------------------------------------------------
// SigningMiddleware — decorates + signs each outgoing request
// ---------------------------------------------------------------------------

/// reqwest middleware that signs each outgoing request.
///
/// It decorates the request with identity query params, base headers (UA,
/// Accept-Language, Cookie, csrf-token, knock-token, jwt-token), and an HMAC
/// signature.  It holds an [`ApiHooks`] snapshot captured when the owning
/// [`ApiClient`] was built.
#[derive(Clone, Debug)]
pub struct SigningMiddleware {
    hooks: ApiHooks,
}

impl SigningMiddleware {
    #[must_use]
    pub fn new(hooks: ApiHooks) -> Self {
        Self { hooks }
    }

    fn decorate(&self, request: &mut Request) -> Result<()> {
        {
            let mut query = request.url_mut().query_pairs_mut();
            for (key, value) in self.hooks.identity.query_pairs(Timestamp::now()) {
                query.append_pair(key, &value);
            }
        }
        request.headers_mut().extend(self.hooks.base_headers()?);
        let body = request
            .body()
            .and_then(reqwest::Body::as_bytes)
            .map_or_else(Vec::new, ToOwned::to_owned);
        let signed_headers = self
            .hooks
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
            let value = HeaderValue::from_str(&signed.value)
                .context(HeaderValueSnafu { name: signed.name })?;
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
}

#[async_trait::async_trait]
impl Middleware for SigningMiddleware {
    async fn handle(
        &self, mut request: Request, extensions: &mut http::Extensions, next: Next<'_>,
    ) -> reqwest_middleware::Result<reqwest::Response> {
        self.decorate(&mut request)
            .map_err(reqwest_middleware::Error::middleware)?;
        next.run(request, extensions).await
    }
}

// ---------------------------------------------------------------------------
// ApiClient
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct ApiClient {
    base_url: Url,
    http: ClientWithMiddleware,
    /// Snapshot of the request cookies, used to merge response `Set-Cookie`s
    /// when building [`ResponseMeta`].
    request_cookies: SessionCookies,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ApiClientOptions {
    pub outbound_interface: Option<String>,
}

// ---------------------------------------------------------------------------
// Endpoint types — the addressable API servers
// ---------------------------------------------------------------------------

pub trait ApiEndpoint: Clone + Send + Sync {
    fn base_url(&self) -> &Url;
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

// ---------------------------------------------------------------------------
// Build the shared HTTP client (connection pool)
// ---------------------------------------------------------------------------

/// Build a `reqwest::Client` with optional outbound interface binding.
///
/// The returned client is the shared connection pool — clone it (cheap; it is
/// `Arc`-backed) into each [`ApiClient`] for connection/TLS reuse.
pub fn build_http_client(options: &ApiClientOptions) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder().redirect(reqwest::redirect::Policy::limited(10));
    if let Some(interface) = options.outbound_interface.as_deref() {
        tracing::debug!(
            outbound_interface = interface,
            "binding HTTP client to outbound interface"
        );
        builder = builder.interface(interface);
    }
    builder.build().context(BuildHttpClientSnafu)
}

// ---------------------------------------------------------------------------
// ApiClient — implementation
// ---------------------------------------------------------------------------

impl ApiClient {
    /// Build an `ApiClient` addressing `endpoint`, wrapping a clone of the
    /// shared connection `pool` with a [`SigningMiddleware`] carrying the
    /// given auth hooks snapshot.  This is the canonical constructor.
    #[must_use]
    pub fn for_endpoint(
        endpoint: &impl ApiEndpoint, pool: reqwest::Client, hooks: ApiHooks,
    ) -> Self {
        let base_url = endpoint.base_url().clone();
        let request_cookies = hooks.cookies.clone();
        let http = ClientBuilder::new(pool)
            .with(SigningMiddleware::new(hooks))
            .build();
        tracing::debug!(%base_url, "created API client");
        Self {
            base_url,
            http,
            request_cookies,
        }
    }

    /// Send a typed request and return only the decoded response body.
    pub async fn send<R>(&self, request: R) -> Result<R::Response>
    where
        R: SendableRequest, {
        let (response, _meta) = self.send_with_meta(request).await?;
        Ok(response)
    }

    /// Send a typed request and return **both** the decoded body and
    /// [`ResponseMeta`] (cookies, CSRF, Date header, force-logout flag).
    pub async fn send_with_meta<R>(&self, request: R) -> Result<(R::Response, ResponseMeta)>
    where
        R: SendableRequest, {
        let (response_body, meta) = self.execute(request).await?;
        let decoded = decode_response::<R::Response>(&response_body)?;
        check_api_status(&decoded, &response_body)?;
        let meta = ResponseMeta {
            is_force_logout: decoded.is_force_logout(),
            ..meta
        };
        Ok((decoded, meta))
    }

    async fn execute<R>(&self, request: R) -> Result<(Vec<u8>, ResponseMeta)>
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
        // Request decoration + signing is performed by `SigningMiddleware`.
        let response = self
            .http
            .execute(http_request)
            .await
            .map_err(map_middleware_error)?;

        let meta = extract_response_meta(response.headers(), &self.request_cookies);

        let status = response.status();
        let bytes = response.bytes().await.context(RequestSnafu)?.to_vec();
        if !status.is_success() {
            return HttpStatusSnafu {
                status,
                content: response_content(&bytes),
            }
            .fail();
        }
        Ok((bytes, meta))
    }
}

// ---------------------------------------------------------------------------
// VpnDot helpers (unchanged)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

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

/// Map a `reqwest_middleware::Error` back into our [`Error`], recovering the
/// original signing/decoration error if the middleware produced one.
fn map_middleware_error(error: reqwest_middleware::Error) -> Error {
    match error {
        reqwest_middleware::Error::Reqwest(source) => Error::Request { source },
        reqwest_middleware::Error::Middleware(err) => {
            err.downcast::<Error>()
                .unwrap_or_else(|err| Error::MiddlewareFailed {
                    message: err.to_string(),
                })
        }
    }
}

fn cookie_header(cookies: &SessionCookies) -> Option<String> {
    if cookies.values.is_empty() {
        return None;
    }
    Some(
        cookies
            .values
            .iter()
            .map(|(name, value)| format!("{name}={value}"))
            .collect::<Vec<_>>()
            .join("; "),
    )
}

/// Extract metadata from response headers: cookies, CSRF token, Date header.
fn extract_response_meta(headers: &HeaderMap, request_cookies: &SessionCookies) -> ResponseMeta {
    let mut cookies = request_cookies.clone();
    let mut any_cookie_changed = false;
    let mut csrf_token = None;
    for value in &headers.get_all(SET_COOKIE) {
        let Ok(raw) = value.to_str() else {
            continue;
        };
        let Some((name, rest)) = raw.split_once('=') else {
            continue;
        };
        let cookie_value = rest.split(';').next().unwrap_or_default();
        let name = name.trim().to_string();
        let cookie_value = cookie_value.trim().to_string();
        if name == "csrf-token" {
            csrf_token = Some(cookie_value.clone());
        }
        cookies.values.insert(name, cookie_value);
        any_cookie_changed = true;
    }
    let server_date = headers
        .get(DATE)
        .and_then(|v| v.to_str().ok())
        .map(ToOwned::to_owned);
    ResponseMeta {
        cookies: if any_cookie_changed {
            Some(cookies)
        } else {
            None
        },
        csrf_token,
        server_date,
        is_force_logout: false,
    }
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
    let port_u16 = u16::try_from(port).map_err(|_| Error::InvalidPort { port })?;
    url.set_port(Some(port_u16))
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
