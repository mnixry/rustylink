use rustylink_api::{
    ApiClient, BaseResponse, DotEndpoint, FetchOtpRequest, GetLoginSettingRequest,
    GetTenantConfigRequest, GetUserInfoRequest, GetVpnLocationsRequest, GetVpnSettingRequest,
    LoginSetting, OtpProvision, SendableRequest, TenantConfig, UserInfo, VpnConnRequest,
    VpnConnResponse, VpnDot, VpnPingRequest, VpnReportRequest, VpnSetting,
};
use snafu::prelude::*;
use strum::{Display, EnumIter, EnumString, FromRepr, IntoStaticStr};

const MAX_DOT_ATTEMPTS: usize = 3;
const MAX_CONFIG_ATTEMPTS_PER_DOT: usize = 3;

#[derive(
    Clone,
    Copy,
    Debug,
    Display,
    EnumIter,
    EnumString,
    Eq,
    FromRepr,
    IntoStaticStr,
    PartialEq,
    serde::Deserialize,
    serde::Serialize,
)]
#[repr(i32)]
#[strum(ascii_case_insensitive)]
pub enum VpnConnectMode {
    #[strum(to_string = "Full", serialize = "full")]
    Full  = 0,
    #[strum(to_string = "Split", serialize = "split")]
    Split = 1,
}

#[derive(Clone, Debug)]
pub struct VpnConfigRequest {
    pub mode: VpnConnectMode,
    pub public_key: String,
    pub export_id: i32,
    pub otp: Option<String>,
    pub sign_token: Option<String>,
    pub not_auto: bool,
    pub reconnect: bool,
    pub preferred_dot_id: Option<i32>,
}

#[derive(Clone, Debug)]
pub struct VpnConfigResult {
    pub dot: VpnDot,
    pub endpoint: DotEndpoint,
    pub response: BaseResponse<VpnConnResponse>,
}

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("API operation failed: {source}"))]
    Api {
        #[snafu(source(from(rustylink_api::Error, Box::new)))]
        source: Box<rustylink_api::Error>,
    },

    #[snafu(display("no VPN dots were returned by /api/vpn/list"))]
    NoVpnDots,

    #[snafu(display("no VPN dot supports requested mode `{mode}`"))]
    NoSupportedVpnDot { mode: String },

    #[snafu(display("VPN config response did not contain data"))]
    MissingVpnConfigData,

    #[snafu(display("VPN dot list response did not contain data"))]
    MissingVpnDotListData,
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

impl VpnConnectMode {
    #[must_use]
    pub const fn android_id(self) -> i32 {
        self as i32
    }

    #[must_use]
    pub fn android_name(self) -> String {
        self.to_string()
    }
}

// ---------------------------------------------------------------------------
// Signing config update — pure data extracted from TenantConfig
// ---------------------------------------------------------------------------

/// A signing rule extracted from the tenant config API response.
#[derive(Clone, Debug, Default)]
pub struct SigningRuleUpdate {
    pub urls: Vec<String>,
    pub enable_signing: bool,
    pub signing_input_params: u64,
    pub max_time_desync: Option<u64>,
}

/// Updated signing configuration extracted from a [`TenantConfig`] response.
///
/// The caller is responsible for merging this into its own persisted signing
/// state.
#[derive(Clone, Debug, Default)]
pub struct SigningConfigUpdate {
    pub enabled: bool,
    pub algorithms: Vec<String>,
    pub rules: Vec<SigningRuleUpdate>,
}

/// Build an updated signing configuration from a [`TenantConfig`] response.
///
/// Returns `None` when `data` has no signing config.
#[must_use]
pub fn extract_signing_config_update(
    current_enabled: bool, data: &TenantConfig,
) -> Option<SigningConfigUpdate> {
    let config = data.signing_config.as_ref()?;
    Some(SigningConfigUpdate {
        enabled: config.enable.unwrap_or(current_enabled),
        algorithms: config.algorithms.clone().unwrap_or_default(),
        rules: config
            .rules
            .as_deref()
            .unwrap_or_default()
            .iter()
            .map(|rule| SigningRuleUpdate {
                urls: rule.urls.clone().unwrap_or_default(),
                enable_signing: rule.enable_signing.unwrap_or(false),
                signing_input_params: rule
                    .signing_input_params
                    .and_then(|value| u64::try_from(value).ok())
                    .unwrap_or_default(),
                max_time_desync: rule
                    .max_time_desync
                    .and_then(|value| u64::try_from(value).ok()),
            })
            .collect(),
    })
}

// ---------------------------------------------------------------------------
// TOTP config — pure data for callers to persist
// ---------------------------------------------------------------------------

/// TOTP provisioning data suitable for local persistence.
///
/// Contains the `otpauth://` URI and the server clock offset so codes can be
/// generated offline for auto-reconnect.
#[derive(Clone, Debug, Default)]
pub struct TotpConfig {
    pub url: String,
    pub time_diff_seconds: i64,
}

// ---------------------------------------------------------------------------
// Profile / settings
// ---------------------------------------------------------------------------

pub async fn user_info(client: &ApiClient) -> Result<BaseResponse<UserInfo>> {
    GetUserInfoRequest.send(client).await.context(ApiSnafu)
}

pub async fn tenant_config(client: &ApiClient) -> Result<BaseResponse<TenantConfig>> {
    GetTenantConfigRequest.send(client).await.context(ApiSnafu)
}

pub async fn login_setting(client: &ApiClient) -> Result<BaseResponse<LoginSetting>> {
    GetLoginSettingRequest.send(client).await.context(ApiSnafu)
}

// ---------------------------------------------------------------------------
// VPN settings / locations
// ---------------------------------------------------------------------------

pub async fn vpn_setting(client: &ApiClient) -> Result<BaseResponse<VpnSetting>> {
    GetVpnSettingRequest.send(client).await.context(ApiSnafu)
}

pub async fn vpn_locations(client: &ApiClient) -> Result<BaseResponse<Vec<VpnDot>>> {
    GetVpnLocationsRequest.send(client).await.context(ApiSnafu)
}

// ---------------------------------------------------------------------------
// VPN connection
// ---------------------------------------------------------------------------

pub async fn vpn_conn(
    client: &ApiClient, request: &VpnConnRequest,
) -> Result<BaseResponse<VpnConnResponse>> {
    request.clone().send(client).await.context(ApiSnafu)
}

/// Fetch the dot list, select a suitable dot, and negotiate a VPN config.
///
/// Dot (access-point) selection mirrors the outbound-interface resolution
/// model:
///
/// * **Pinned** — when `request.preferred_dot_id` is `Some`, only that dot is
///   considered (the caller explicitly chose a node; we stick to it).
/// * **Auto** — when `preferred_dot_id` is `None`, all dots that support the
///   requested mode are ranked by measured latency via `rank_dots`, and the
///   fastest-responding nodes are tried first.
///
/// `build_dot_client` is a callback the caller provides to construct an
/// [`ApiClient`] pointing at a particular dot endpoint.  This keeps the core
/// crate free of client-construction concerns (cookie injection, signing
/// middleware, etc.).
///
/// `rank_dots` is a callback that orders candidate dots best-first (e.g. by
/// latency probing).  It is invoked **only** in the auto case with more than
/// one candidate; keeping it in the caller lets the runtime-bound probing live
/// in the daemon while this crate stays runtime-agnostic.
pub async fn vpn_config_from_dot_list<RankFut>(
    tenant_client: &ApiClient, request: &VpnConfigRequest,
    build_dot_client: impl Fn(&DotEndpoint) -> ApiClient,
    rank_dots: impl FnOnce(Vec<VpnDot>) -> RankFut,
) -> Result<VpnConfigResult>
where
    RankFut: std::future::Future<Output = Vec<VpnDot>>, {
    let locations = GetVpnLocationsRequest
        .send(tenant_client)
        .await
        .context(ApiSnafu)?;
    let dots = locations.data.clone().context(MissingVpnDotListDataSnafu)?;
    if dots.is_empty() {
        return NoVpnDotsSnafu.fail();
    }

    let pinned = request.preferred_dot_id.is_some();
    let mut candidates = dots
        .into_iter()
        .filter(|dot| {
            request
                .preferred_dot_id
                .is_none_or(|preferred| dot.id == Some(preferred))
        })
        .filter(|dot| dot.supports_android_mode(request.mode.android_id()))
        .filter(|dot| !request.reconnect || dot.supports_reconnect())
        .collect::<Vec<_>>();

    if candidates.is_empty() {
        return NoSupportedVpnDotSnafu {
            mode: request.mode.android_name(),
        }
        .fail();
    }

    // Auto selection: with no pinned dot, probe and order candidates so the
    // lowest-latency node is attempted first. A pinned dot is used as-is.
    if !pinned && candidates.len() > 1 {
        candidates = rank_dots(candidates).await;
    }

    candidates.truncate(MAX_DOT_ATTEMPTS);
    let mut last_error = None;
    for dot in candidates {
        let use_vpn_ip_for_api = dot.should_use_vpn_ip_for_config_api(!request.not_auto);
        let endpoint = DotEndpoint::from_dot(&dot, use_vpn_ip_for_api).context(ApiSnafu)?;
        let dot_client = build_dot_client(&endpoint);
        let body = VpnConnRequest {
            mode: Some(request.mode.android_name()),
            public_key: request.public_key.clone(),
            otp: request.otp.clone(),
            export_id: request.export_id,
            sign_token: request.sign_token.clone(),
            not_auto: Some(request.not_auto),
        };
        for attempt in 1..=MAX_CONFIG_ATTEMPTS_PER_DOT {
            tracing::info!(
                dot_id = dot.id,
                api_base_url = %endpoint.api_base_url,
                attempt,
                "requesting VPN config from dot"
            );
            match body.clone().send(&dot_client).await {
                Ok(response) => {
                    response.data.as_ref().context(MissingVpnConfigDataSnafu)?;
                    return Ok(VpnConfigResult {
                        dot,
                        endpoint,
                        response,
                    });
                }
                Err(source) => {
                    tracing::warn!(
                        dot_id = dot.id,
                        api_base_url = %endpoint.api_base_url,
                        attempt,
                        error = %source,
                        "VPN config request failed"
                    );
                    last_error = Some(source);
                }
            }
        }
    }

    if let Some(source) = last_error {
        return Err(Error::Api {
            source: Box::new(source),
        });
    }
    NoSupportedVpnDotSnafu {
        mode: request.mode.android_name(),
    }
    .fail()
}

pub async fn report_vpn(
    client: &ApiClient, request: &VpnReportRequest,
) -> Result<BaseResponse<serde_json::Value>> {
    request.clone().send(client).await.context(ApiSnafu)
}

/// Time a `GET /vpn/ping` against a dot's API server, used to measure latency
/// to the access point for dot selection. Returns `Ok(())` on a `2xx` reply.
pub async fn vpn_ping(client: &ApiClient) -> Result<()> {
    VpnPingRequest.send(client).await.context(ApiSnafu)?;
    Ok(())
}

/// Fetch the tenant TOTP provisioning from `POST /api/v2/p/otp`.
///
/// Gated on the Android `User-Agent` we send, the server returns an
/// `otpauth://` URI (carrying the secret/algorithm/digits/period) plus its
/// wall-clock `timestamp`.  We persist the URI and the derived clock offset so
/// codes can be generated locally for auto-reconnect.  Returns `Ok(None)`
/// when the tenant has no OTP requirement (empty `url`).
pub async fn fetch_totp(client: &ApiClient) -> Result<Option<TotpConfig>> {
    let response = FetchOtpRequest.send(client).await.context(ApiSnafu)?;
    Ok(response.data.and_then(totp_from_provision))
}

/// Build a [`TotpConfig`] from the provisioning payload, deriving
/// the server clock offset from its `timestamp` (server − local).
fn totp_from_provision(provision: OtpProvision) -> Option<TotpConfig> {
    let url = (!provision.url.is_empty()).then_some(provision.url)?;
    let now = jiff::Timestamp::now().as_second();
    let time_diff_seconds = match provision.timestamp {
        ts if ts > 0 => ts - now,
        _ => 0,
    };
    Some(TotpConfig {
        url,
        time_diff_seconds,
    })
}

/// Generate a fresh RFC 6238 TOTP code for `/vpn/conn` from the stored
/// `otpauth://` URI, applying the persisted server clock offset.
///
/// Uses totp-rs's `from_url_unchecked` (otpauth feature) to honour the URI's
/// algorithm/digits/period and tolerate short/non-standard tenant secrets
/// (matching the Android client, which does not enforce the RFC minimum).
#[must_use]
pub fn generate_totp(config: &TotpConfig, now_unix: i64) -> Option<String> {
    let corrected = u64::try_from(now_unix + config.time_diff_seconds).ok()?;
    totp_rs::TOTP::from_url_unchecked(&config.url)
        .ok()
        .map(|totp| totp.generate(corrected))
}
