use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use jiff::Timestamp;
use reqwest::{
    Request,
    header::{
        ACCEPT, ACCEPT_LANGUAGE, CONTENT_TYPE, COOKIE, HeaderMap, HeaderName, HeaderValue,
        SET_COOKIE, USER_AGENT,
    },
};
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware, Middleware, Next};
use snafu::prelude::*;
use tracing::Instrument as _;
use url::Url;

use crate::{
    identity::ClientIdentity,
    models::{ApiResponse, BaseResponse, IpDelayRoutingPolicy, SendableRequest, VpnDot},
    signing::SigningContext,
};

pub const DEFAULT_MATCH_BASE_URL: &str = "https://corplink.volcengine.cn";

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("invalid base URL `{value}`: {source}"))]
    InvalidBaseUrl {
        value: String,
        source: url::ParseError,
    },

    #[snafu(display("failed to build HTTP client: {source}"))]
    BuildHttpClient { source: reqwest::Error },

    #[snafu(display("failed to encode API request body: {source}"))]
    Encode { source: serde_json::Error },

    #[snafu(display("failed to build API request: {source}"))]
    BuildRequest { source: reqwest::Error },

    #[snafu(display("API request failed: {source}"))]
    Request { source: reqwest::Error },

    #[snafu(display("request middleware failed: {message}"))]
    MiddlewareFailed { message: String },

    #[snafu(display("failed to decode response (content: {content}): {source}"))]
    Decode {
        source: serde_json::Error,
        content: String,
    },

    #[snafu(display("HTTP API status {status}: {content}"))]
    HttpStatus {
        status: reqwest::StatusCode,
        content: String,
    },

    #[snafu(display("failed to build header `{name}`: {source}"))]
    HeaderValue {
        name: String,
        source: reqwest::header::InvalidHeaderValue,
    },

    #[snafu(display("failed to build header name `{name}`: {source}"))]
    HeaderName {
        name: String,
        source: reqwest::header::InvalidHeaderName,
    },

    #[snafu(display("failed to sign request: {source}"))]
    SignRequest {
        source: crate::signing::SigningError,
    },

    #[snafu(display("failed to encrypt password: {source}"))]
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

/// Listener invoked (outside the cookie lock) after the jar absorbs a change.
/// The daemon installs one to persist the refreshed session to its credentials
/// file.
pub type CookieListener = Arc<dyn Fn() + Send + Sync>;

/// A shared, mutable cookie jar guarded by an async lock.
///
/// Like the Android client's `CookieJar`, this accumulates `Set-Cookie`
/// mutations across every request made by any [`ApiClient`] that shares it, so
/// cookies set mid-flow (e.g. `vpn-token` from `/api/vpn/list`) are present on
/// later requests (e.g. the dot's `/vpn/conn`). The values live behind a
/// [`tokio::sync::Mutex`] so callers await the lock instead of blocking the
/// runtime; every change is logged at debug level and reported to the
/// [`CookieListener`] so it can be persisted.
pub type CookieJar = Arc<CookieStore>;

pub struct CookieStore {
    cookies: tokio::sync::Mutex<SessionCookies>,
    listener: Mutex<Option<CookieListener>>,
}

impl std::fmt::Debug for CookieStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CookieStore").finish_non_exhaustive()
    }
}

impl CookieStore {
    /// Create an empty jar.
    #[must_use]
    pub fn empty() -> CookieJar {
        Arc::new(Self {
            cookies: tokio::sync::Mutex::new(SessionCookies::default()),
            listener: Mutex::new(None),
        })
    }

    /// Create a jar seeded with persisted cookie values.
    #[must_use]
    pub fn with_values(values: BTreeMap<String, String>) -> CookieJar {
        Arc::new(Self {
            cookies: tokio::sync::Mutex::new(SessionCookies { values }),
            listener: Mutex::new(None),
        })
    }

    /// Install the change listener, replacing any previous one.
    pub fn set_listener(&self, listener: CookieListener) {
        if let Ok(mut slot) = self.listener.lock() {
            *slot = Some(listener);
        }
    }

    /// Snapshot the current cookies.
    pub async fn snapshot(&self) -> SessionCookies {
        self.cookies.lock().await.clone()
    }

    /// Snapshot the current cookie values.
    pub async fn values(&self) -> BTreeMap<String, String> {
        self.cookies.lock().await.values.clone()
    }

    /// True when the jar holds no cookies.
    pub async fn is_empty(&self) -> bool {
        self.cookies.lock().await.values.is_empty()
    }

    /// Clear all cookies (on logout). Does not notify — the credentials file is
    /// deleted on logout rather than rewritten.
    pub async fn clear(&self) {
        self.cookies.lock().await.values.clear();
    }

    /// Merge cookie updates into the jar, logging each change at debug level
    /// and notifying the listener once if anything actually changed.
    pub async fn merge(&self, updates: impl IntoIterator<Item = (String, String)>) {
        let mut changed = false;
        let mut jar = self.cookies.lock().await;
        for (name, value) in updates {
            if jar
                .values
                .get(&name)
                .is_some_and(|existing| *existing == value)
            {
                continue;
            }
            tracing::debug!(cookie = %name, "cookie set");
            jar.values.insert(name, value);
            changed = true;
        }
        drop(jar);
        if changed {
            self.notify();
        }
    }

    fn notify(&self) {
        let listener = self.listener.lock().ok().and_then(|slot| slot.clone());
        if let Some(listener) = listener {
            listener();
        }
    }
}

/// Parse `Set-Cookie` response headers into `(name, value)` pairs with the
/// `cookie` crate (which handles attributes, quoting, and whitespace).
fn parse_set_cookies(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .get_all(SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .filter_map(|raw| cookie::Cookie::parse(raw.to_owned()).ok())
        .map(|cookie| (cookie.name().to_owned(), cookie.value().to_owned()))
        .collect()
}

/// Request-decoration hooks (snapshot). All fields are plain owned values.
/// A new `ApiHooks` is built from the current `PersistedState` each time the
/// actor refreshes the `AppContext`.
#[derive(Clone, Debug)]
pub struct ApiHooks {
    pub identity: ClientIdentity,
    pub cookies: CookieJar,
    pub knock_token: Option<String>,
    pub signer: SigningContext,
}

impl ApiHooks {
    async fn base_headers(&self) -> Result<HeaderMap> {
        let cookies = self.cookies.snapshot().await;
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

        // Cookie header: session cookies plus the always-present device
        // identity cookies. Android's `CookieJarImpl.loadAllCookie` injects
        // `device_id`/`device_name` on *every* request (to all hosts), so the
        // login binds the session to a device. The issued session token then
        // carries a non-empty `did`; `/vpn/conn` rejects a session whose `did`
        // is empty with a misleading "session expired" error.
        let cookie_value = device_cookie_header(&cookies, &self.identity);
        headers.insert(
            COOKIE,
            HeaderValue::from_str(&cookie_value).context(HeaderValueSnafu {
                name: "Cookie".to_string(),
            })?,
        );
        // The `csrf-token` cookie is mirrored into a `csrf-token` *header* on
        // every request (Android parity). It lives in the shared jar like any
        // other `Set-Cookie`, so there's no separate CSRF field to track.
        if let Some(csrf) = cookies.values.get("csrf-token") {
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
        if let Some(vpn_token) = cookies.values.get("vpn-token") {
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

    async fn decorate(&self, request: &mut Request) -> Result<()> {
        {
            let mut query = request.url_mut().query_pairs_mut();
            for (key, value) in self.hooks.identity.query_pairs(Timestamp::now()) {
                query.append_pair(key, &value);
            }
        }
        request
            .headers_mut()
            .extend(self.hooks.base_headers().await?);
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
            .await
            .map_err(reqwest_middleware::Error::middleware)?;
        let response = next.run(request, extensions).await?;
        // Absorb any Set-Cookie mutations into the shared jar so later requests
        // (including ones to other hosts, e.g. the dot config call) carry them.
        self.hooks
            .cookies
            .merge(parse_set_cookies(response.headers()))
            .await;
        Ok(response)
    }
}

#[derive(Clone)]
pub struct ApiClient {
    base_url: Url,
    http: ClientWithMiddleware,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ApiClientOptions {
    pub outbound_interface: Option<String>,
}

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
        let api_port = dot
            .api_port
            .context(MissingVpnDotFieldSnafu { field: "api_port" })?;
        let vpn_port = dot
            .vpn_port
            .context(MissingVpnDotFieldSnafu { field: "vpn_port" })?;
        // Config API host: the API frontend (ip4Domain ?: fastIp ?: apiIp ?: ip),
        // unless operator IP-delay routing forces the raw node `ip`. WireGuard
        // always dials the raw `ip` (corplink-rs) — the frontends are HTTPS/CDN
        // endpoints that don't answer the handshake. Empty `ip` is rejected by
        // `url_from_host_port` with a clear `host` error.
        let api_host = if use_vpn_ip_for_api {
            dot.ip.as_str()
        } else {
            dot.api_host()
        };
        Ok(Self {
            api_base_url: url_from_host_port("https", api_host, api_port)?,
            wireguard_endpoint: url_from_host_port("udp", &dot.ip, vpn_port)?,
        })
    }
}

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

impl ApiClient {
    /// Build an `ApiClient` addressing `endpoint`, wrapping a clone of the
    /// shared connection `pool` with a [`SigningMiddleware`] carrying the
    /// given auth hooks snapshot.  This is the canonical constructor.
    #[must_use]
    pub fn for_endpoint(
        endpoint: &impl ApiEndpoint, pool: reqwest::Client, hooks: ApiHooks,
    ) -> Self {
        let base_url = endpoint.base_url().clone();
        let http = ClientBuilder::new(pool)
            .with(SigningMiddleware::new(hooks))
            .build();
        tracing::debug!(%base_url, "created API client");
        Self { base_url, http }
    }

    /// Send a typed request and return the decoded response body.
    ///
    /// Any `Set-Cookie` headers on the response are absorbed into the shared
    /// cookie jar by [`SigningMiddleware`], so callers never need to inspect
    /// response cookies or CSRF tokens directly.
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
        // Span covering the whole request so signing/cookie logs and any error
        // are grouped under the target method + host + path.
        let span = tracing::debug_span!(
            "api_request",
            method = %R::METHOD,
            host = url.host_str().unwrap_or("<unknown>"),
            path = url.path(),
        );
        async move {
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
            // Request decoration + signing is performed by `SigningMiddleware`,
            // which also absorbs `Set-Cookie` into the shared jar.
            let response = self
                .http
                .execute(http_request)
                .await
                .map_err(map_middleware_error)?;

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
        .instrument(span)
        .await
    }
}

/// Android VPN mode ids carried on a dot's `mode` field and the requested
/// connect mode (kept in sync with `rustylink_core::vpn::VpnConnectMode`).
const MODE_FULL: i32 = 0;
const MODE_SPLIT: i32 = 1;

impl VpnDot {
    /// Host for the config API (HTTPS), mirroring Android `getApiIp()`
    /// (ip4Domain ?: fastIp ?: apiIp) with a final fallback to the node `ip`.
    /// Infallible: `ip` is the required address, so a host is always available.
    #[must_use]
    pub fn api_host(&self) -> &str {
        self.ip4_domain
            .as_deref()
            .filter(|value| !value.is_empty())
            .or_else(|| self.fast_ip.as_deref().filter(|value| !value.is_empty()))
            .or_else(|| self.api_ip.as_deref().filter(|value| !value.is_empty()))
            .unwrap_or(&self.ip)
    }

    #[must_use]
    pub fn should_use_vpn_ip_for_config_api(&self, is_auto_location: bool) -> bool {
        if is_auto_location || self.ip.is_empty() {
            return false;
        }
        self.ip_delay_routing_policy
            .as_ref()
            .is_some_and(IpDelayRoutingPolicy::is_operator_routing)
    }

    #[must_use]
    pub fn supports_reconnect(&self) -> bool {
        self.reconnect.unwrap_or(false)
            && !self.dedicated.unwrap_or(false)
            && !self.exclude.unwrap_or(false)
    }

    #[must_use]
    pub fn supports_android_mode(&self, requested_mode: i32) -> bool {
        // Android VPN mode ids (shared with `VpnConnectMode`): 0 = Full,
        // 1 = Split. A node only serves requests at or above its own capability
        // tier, so a Split node can't serve Full.
        !matches!((self.mode, requested_mode), (Some(MODE_SPLIT), MODE_FULL))
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

/// Build the `Cookie` header value: the session cookies followed by the device
/// identity cookies (`device_id`/`device_name`).
///
/// The device cookies mirror Android's `CookieJarImpl`, which appends them to
/// every request. Sending them at login is what binds the session to a device
/// (`did`); `/vpn/conn` requires that binding.
fn device_cookie_header(cookies: &SessionCookies, identity: &ClientIdentity) -> String {
    cookies
        .values
        .iter()
        .map(|(name, value)| cookie::Cookie::new(name.clone(), value.clone()))
        .chain([
            cookie::Cookie::new("device_id", identity.device_id.clone()),
            cookie::Cookie::new("device_name", device_name_cookie_value(identity)),
        ])
        // `Display` renders `name=value` (no attributes set); unlike `encoded()`
        // it does not percent-encode, preserving Android `CookieJarImpl` bytes.
        .map(|cookie| cookie.to_string())
        .collect::<Vec<_>>()
        .join("; ")
}

/// A cookie-safe device name derived from the identity model (spaces replaced),
/// e.g. `"Pixel 8"` → `"Pixel-8"`. Falls back to Android's `"unknow"` (the
/// literal `CookieJarImpl` emits when the device name is unavailable).
fn device_name_cookie_value(identity: &ClientIdentity) -> String {
    let name: String = identity
        .model
        .chars()
        .map(|c| if c.is_ascii_whitespace() { '-' } else { c })
        .filter(|c| !matches!(c, ';' | ',' | '='))
        .collect();
    if name.trim().is_empty() {
        "unknow".to_string()
    } else {
        name
    }
}

/// Clamp response bodies to a sane size before surfacing them in errors/logs.
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
    let port = u16::try_from(port)
        .ok()
        .filter(|port| *port != 0)
        .context(InvalidPortSnafu { port })?;
    let host = host.trim();
    if host.is_empty() {
        return MissingVpnDotFieldSnafu { field: "host" }.fail();
    }
    // Bracket bare IPv6 literals so the authority parses; `url::Url` validates
    // the scheme/host/port for us — no second URL/URI type needed.
    let authority = if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_owned()
    };
    parse_base_url(&format!("{scheme}://{authority}:{port}/"))
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

        let endpoint = DotEndpoint::from_dot(&dot, false).expect("endpoint");

        // Config API uses the API host (apiIp); WireGuard dials the node's raw
        // `ip`, mirroring corplink-rs.
        assert_eq!(endpoint.api_base_url.as_str(), "https://api.example:8443/");
        assert_eq!(
            endpoint.wireguard_endpoint.as_str(),
            "udp://10.0.0.12:51820/"
        );
    }

    #[test]
    fn dot_endpoint_uses_ip4domain_for_api_and_ip_for_wireguard() {
        // When a dot advertises a CDN/HTTPS frontend (ip4Domain/fastIp/apiIp),
        // the config API uses it (ip4Domain wins) while WireGuard still dials the
        // raw node `ip` — matching corplink-rs. Using the frontend for WireGuard
        // caused the handshake timeout.
        let dot = serde_json::from_value::<VpnDot>(json!({
            "ip4Domain": "vpn.example.com",
            "fastIp": "1.1.1.1",
            "apiIp": "2.2.2.2",
            "ip": "3.3.3.3",
            "api_port": 443,
            "vpn_port": 51820
        }))
        .expect("dot");

        let endpoint = DotEndpoint::from_dot(&dot, false).expect("endpoint");

        assert_eq!(endpoint.api_base_url.as_str(), "https://vpn.example.com/");
        assert_eq!(endpoint.wireguard_endpoint.as_str(), "udp://3.3.3.3:51820/");
        assert_eq!(dot.api_host(), "vpn.example.com");
    }

    #[test]
    fn dot_endpoint_uses_ip_when_only_ip_present() {
        // Most dots only populate `ip` (the corplink-rs single-address model);
        // both the API host and the WireGuard endpoint use it.
        let dot = serde_json::from_value::<VpnDot>(json!({
            "ip": "10.0.0.12",
            "api_port": 8443,
            "vpn_port": 51820
        }))
        .expect("dot");

        let endpoint = DotEndpoint::from_dot(&dot, false).expect("endpoint");

        assert_eq!(endpoint.api_base_url.as_str(), "https://10.0.0.12:8443/");
        assert_eq!(
            endpoint.wireguard_endpoint.as_str(),
            "udp://10.0.0.12:51820/"
        );
        assert_eq!(dot.api_host(), "10.0.0.12");
    }

    #[test]
    fn dot_endpoint_rejects_missing_ip() {
        // A dot without `ip` deserializes (struct-level default → ip = "") but
        // cannot build an endpoint: `from_dot` rejects the empty WireGuard host
        // with a single, clear `host` field error.
        let dot = serde_json::from_value::<VpnDot>(json!({
            "apiIp": "api.example",
            "api_port": 8443,
            "vpn_port": 51820
        }))
        .expect("dot deserializes with default ip");
        assert!(dot.ip.is_empty());
        assert!(DotEndpoint::from_dot(&dot, false).is_err());
    }
}
