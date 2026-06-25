use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};

use bytes::Bytes;
use http::header::{
    ACCEPT, ACCEPT_LANGUAGE, CONTENT_TYPE, COOKIE, HeaderMap, HeaderName, HeaderValue, SET_COOKIE,
    USER_AGENT,
};
use http_body_util::{BodyExt, Full};
use hyper_rustls::HttpsConnectorBuilder;
use jiff::Timestamp;
use rustylink_outbound::{Dialer, HyperConnector, OutboundInterface, Resolver};
use snafu::prelude::*;
use tracing::Instrument as _;
use url::Url;

use crate::{
    identity::ClientIdentity,
    models::{ApiResponse, BaseResponse, IpDelayRoutingPolicy, SendableRequest, VpnDot},
    signing::SigningContext,
};

pub const DEFAULT_MATCH_BASE_URL: &str = "https://corplink.volcengine.cn";

// ---------------------------------------------------------------------------
// Type aliases for the hyper-based HTTP client stack
// ---------------------------------------------------------------------------

/// TLS connector wrapping the outbound [`HyperConnector`] with rustls.
pub type HttpsConn = hyper_rustls::HttpsConnector<HyperConnector>;

/// The shared, pooled HTTP client.  Clone-cheap (`Arc`-backed).
pub type HttpClient = hyper_util::client::legacy::Client<HttpsConn, Full<Bytes>>;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("invalid base URL `{value}`: {source}"))]
    InvalidBaseUrl {
        value: String,
        source: url::ParseError,
    },

    #[snafu(display("failed to build HTTP client: {source}"))]
    BuildHttpClient {
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[snafu(display("failed to encode API request body: {source}"))]
    Encode { source: serde_json::Error },

    #[snafu(display("failed to build API request: {source}"))]
    BuildRequest { source: http::Error },

    #[snafu(display("API request failed: {source}"))]
    Request {
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[snafu(display("failed to decode response (content: {content}): {source}"))]
    Decode {
        source: serde_json::Error,
        content: String,
    },

    #[snafu(display("HTTP API status {status}: {content}"))]
    HttpStatus {
        status: http::StatusCode,
        content: String,
    },

    #[snafu(display("failed to build header `{name}`: {source}"))]
    HeaderValue {
        name: String,
        source: http::header::InvalidHeaderValue,
    },

    #[snafu(display("failed to build header name `{name}`: {source}"))]
    HeaderName {
        name: String,
        source: http::header::InvalidHeaderName,
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

// ---------------------------------------------------------------------------
// Cookie jar
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

// ---------------------------------------------------------------------------
// ApiHooks — request decoration (headers, cookies, signing)
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// ApiClient
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct ApiClient {
    base_url: Url,
    client: HttpClient,
    hooks: ApiHooks,
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

// ---------------------------------------------------------------------------
// HTTP client builder
// ---------------------------------------------------------------------------

/// Build a TLS-capable HTTP connector wrapping the outbound [`HyperConnector`].
fn build_https_connector(connector: HyperConnector) -> HttpsConn {
    HttpsConnectorBuilder::new()
        .with_platform_verifier()
        .https_or_http()
        .enable_http1()
        .wrap_connector(connector)
}

/// Build a [`Dialer`] and [`Resolver`] for the given outbound interface.
async fn build_dialer_and_resolver(
    outbound_interface: Option<&str>,
) -> std::result::Result<(Dialer, Resolver), Box<dyn std::error::Error + Send + Sync>> {
    let interface = match outbound_interface {
        Some(name) => {
            tracing::debug!(
                outbound_interface = name,
                "binding HTTP client to outbound interface"
            );
            OutboundInterface::lookup(name).await
        }
        None => None,
    };
    let dialer = Dialer::new(interface);
    let servers = rustylink_outbound::system_dns_servers()
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })?;
    let resolver = Resolver::new(dialer.clone(), servers);
    Ok((dialer, resolver))
}

/// Build a pooled [`HttpClient`] with optional outbound interface binding.
///
/// The returned client is the shared connection pool — clone it (cheap; it is
/// `Arc`-backed) into each [`ApiClient`] for connection/TLS reuse.
///
/// DNS is resolved via the interface-bound [`Resolver`] (raw UDP to system
/// servers over the bound NIC), making it immune to TUN routing state.
pub async fn build_http_client(options: &ApiClientOptions) -> Result<HttpClient> {
    let (dialer, resolver) = build_dialer_and_resolver(options.outbound_interface.as_deref())
        .await
        .context(BuildHttpClientSnafu)?;
    let connector = HyperConnector::new(dialer, resolver);
    let https = build_https_connector(connector);
    let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build(https);
    Ok(client)
}

/// Build a per-dot [`HttpClient`] with DNS pinning for TLS host validation.
///
/// The request URL carries `tls_host` (derived from the tenant's `vpn_domain`)
/// so that rustls validates the certificate against that name, but the
/// [`Resolver`] returns `pinned_addr` for `tls_host` so the socket connects to
/// the dot's raw IP.
pub async fn build_dot_http_client(
    tls_host: &str, pinned_addr: std::net::SocketAddr, outbound_interface: Option<&str>,
) -> Result<HttpClient> {
    let (dialer, resolver) = build_dialer_and_resolver(outbound_interface)
        .await
        .context(BuildHttpClientSnafu)?;
    let resolver = resolver.with_override(tls_host, pinned_addr);
    let connector = HyperConnector::new(dialer, resolver);
    let https = build_https_connector(connector);
    let client = hyper_util::client::legacy::Client::builder(hyper_util::rt::TokioExecutor::new())
        .build(https);
    Ok(client)
}

impl ApiClient {
    /// Build an `ApiClient` addressing `endpoint`, using the given shared
    /// connection `pool` and auth `hooks` snapshot.
    #[must_use]
    pub fn for_endpoint(endpoint: &impl ApiEndpoint, pool: HttpClient, hooks: ApiHooks) -> Self {
        let base_url = endpoint.base_url().clone();
        tracing::debug!(%base_url, "created API client");
        Self {
            base_url,
            client: pool,
            hooks,
        }
    }

    /// Send a typed request and return the decoded response body.
    ///
    /// The request is decorated with identity query params, base headers,
    /// and an HMAC signature.  Any `Set-Cookie` headers on the response are
    /// absorbed into the shared cookie jar.
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
        let mut url = endpoint_url(&self.base_url, request.path().as_ref())?;

        let span = tracing::debug_span!(
            "api_request",
            method = %R::METHOD,
            host = url.host_str().unwrap_or("<unknown>"),
            path = url.path(),
        );

        async move {
            // 1. Append endpoint query pairs + identity query pairs to URL.
            {
                let mut query = url.query_pairs_mut();
                for (key, value) in request.query_pairs() {
                    query.append_pair(key, &value);
                }
                for (key, value) in self.hooks.identity.query_pairs(Timestamp::now()) {
                    query.append_pair(key, &value);
                }
            }

            // 2. Build body bytes.
            let body_bytes = request.body().context(EncodeSnafu)?;

            // 3. Build headers: base headers + Accept + Content-Type.
            let mut headers = self.hooks.base_headers().await?;
            headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
            if body_bytes.is_some() {
                headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            }

            // 4. Sign the request (HMAC over method + url + headers + body).
            let body_for_sign = body_bytes.as_deref().unwrap_or(&[]);
            let signed_headers = self
                .hooks
                .signer
                .sign(R::METHOD.as_str(), &url, &headers, body_for_sign)
                .context(SignRequestSnafu)?;
            let signed_header_count = signed_headers.len();
            for signed in signed_headers {
                let name =
                    HeaderName::from_bytes(signed.name.as_bytes()).context(HeaderNameSnafu {
                        name: signed.name.clone(),
                    })?;
                let value = HeaderValue::from_str(&signed.value)
                    .context(HeaderValueSnafu { name: signed.name })?;
                headers.insert(name, value);
            }

            tracing::debug!(
                method = %R::METHOD,
                host = url.host_str().unwrap_or("<none>"),
                path = url.path(),
                signed_header_count,
                "prepared API request"
            );

            // 5. Build http::Request<Full<Bytes>>.
            let uri: http::Uri = url
                .as_str()
                .parse()
                .map_err(|e: http::uri::InvalidUri| Error::BuildRequest { source: e.into() })?;
            let body = Full::new(Bytes::from(body_bytes.unwrap_or_default()));
            let mut req = http::Request::builder()
                .method(R::METHOD)
                .uri(uri)
                .body(body)
                .context(BuildRequestSnafu)?;
            *req.headers_mut() = headers;

            // 6. Send.
            let response = self.client.request(req).await.map_err(|e| Error::Request {
                source: Box::new(e),
            })?;

            // 7. Absorb Set-Cookie into shared jar.
            self.hooks
                .cookies
                .merge(parse_set_cookies(response.headers()))
                .await;

            // 8. Read response body.
            let status = response.status();
            let collected = response
                .into_body()
                .collect()
                .await
                .map_err(|e| Error::Request {
                    source: Box::new(e),
                })?;
            let bytes = collected.to_bytes().to_vec();

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

// ---------------------------------------------------------------------------
// VpnDot helpers
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Internal helpers
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
