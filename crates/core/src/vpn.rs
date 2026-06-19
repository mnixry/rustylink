use rustylink_api::{
    BaseResponse, DotEndpoint, FetchOtpRequest, GetLoginSettingRequest, GetTenantConfigRequest,
    GetUserInfoRequest, GetVpnLocationsRequest, GetVpnSettingRequest, LoginSetting, OtpProvision,
    SendableRequest, TenantConfig, TenantEndpoint, UserInfo, VpnConnRequest, VpnConnResponse,
    VpnDot, VpnReportRequest, VpnSetting,
};
use rustylink_proto::proto::rustylink::daemon::persist::v1 as persist;
use snafu::prelude::*;
use strum::{Display, EnumIter, EnumString, FromRepr, IntoStaticStr};

use crate::{AppContext, state::StateChange};

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
    #[strum(to_string = "Relay", serialize = "relay", serialize = "relpy")]
    Relay = 2,
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
    #[snafu(display("application context operation failed"))]
    Context {
        #[snafu(source(from(crate::context::Error, Box::new)))]
        source: Box<crate::context::Error>,
    },

    #[snafu(display("API operation failed"))]
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
// Helper to collect meta changes
// ---------------------------------------------------------------------------

fn collect_meta_changes(meta: &rustylink_api::ResponseMeta) -> Vec<StateChange> {
    let mut changes = Vec::new();
    if let Some(cookies) = &meta.cookies {
        changes.push(StateChange::CookiesUpdated {
            cookies: cookies.to_map(),
        });
    }
    if let Some(csrf) = &meta.csrf_token {
        changes.push(StateChange::CsrfTokenUpdated {
            token: Some(csrf.clone()),
        });
    }
    if meta.is_force_logout {
        changes.push(StateChange::SessionExpired);
    }
    changes
}

// ---------------------------------------------------------------------------
// Profile / settings
// ---------------------------------------------------------------------------

pub async fn user_info(ctx: &AppContext) -> Result<(BaseResponse<UserInfo>, Vec<StateChange>)> {
    let client = ctx.tenant_client().context(ContextSnafu)?;
    let (response, meta) = GetUserInfoRequest
        .send_with_meta(client)
        .await
        .context(ApiSnafu)?;
    Ok((response, collect_meta_changes(&meta)))
}

pub async fn tenant_config(
    ctx: &AppContext,
) -> Result<(BaseResponse<TenantConfig>, Vec<StateChange>)> {
    let client = ctx.tenant_client().context(ContextSnafu)?;
    let (response, meta) = GetTenantConfigRequest
        .send_with_meta(client)
        .await
        .context(ApiSnafu)?;
    let mut changes = collect_meta_changes(&meta);
    if let Some(data) = &response.data
        && let Some(signing) = build_signing_config_update(ctx, data)
    {
        changes.push(StateChange::SigningConfigUpdated { config: signing });
    }
    Ok((response, changes))
}

pub async fn login_setting(
    ctx: &AppContext,
) -> Result<(BaseResponse<LoginSetting>, Vec<StateChange>)> {
    let client = ctx.tenant_client().context(ContextSnafu)?;
    let (response, meta) = GetLoginSettingRequest
        .send_with_meta(client)
        .await
        .context(ApiSnafu)?;
    Ok((response, collect_meta_changes(&meta)))
}

fn build_signing_config_update(
    ctx: &AppContext, data: &TenantConfig,
) -> Option<persist::PersistedSigning> {
    let config = data.signing_config.as_ref()?;
    let mut signing = ctx.signing_proto().cloned().unwrap_or_default();
    signing.enabled = config.enable.unwrap_or(signing.enabled);
    signing.algorithms = config.algorithms.clone().unwrap_or_default();
    signing.rules = config
        .rules
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|rule| persist::PersistedSigningRule {
            urls: rule.urls.clone().unwrap_or_default(),
            enable_signing: rule.enable_signing.unwrap_or(false),
            signing_input_params: rule
                .signing_input_params
                .and_then(|value| u64::try_from(value).ok())
                .unwrap_or_default(),
            max_time_desync: rule
                .max_time_desync
                .and_then(|value| u64::try_from(value).ok()),
            ..Default::default()
        })
        .collect();
    Some(signing)
}

// ---------------------------------------------------------------------------
// VPN settings / locations
// ---------------------------------------------------------------------------

pub async fn vpn_setting(ctx: &AppContext) -> Result<(BaseResponse<VpnSetting>, Vec<StateChange>)> {
    let client = ctx.tenant_client().context(ContextSnafu)?;
    let (response, meta) = GetVpnSettingRequest
        .send_with_meta(client)
        .await
        .context(ApiSnafu)?;
    Ok((response, collect_meta_changes(&meta)))
}

pub async fn vpn_locations(
    ctx: &AppContext,
) -> Result<(BaseResponse<Vec<VpnDot>>, Vec<StateChange>)> {
    let client = ctx.tenant_client().context(ContextSnafu)?;
    let (response, meta) = GetVpnLocationsRequest
        .send_with_meta(client)
        .await
        .context(ApiSnafu)?;
    Ok((response, collect_meta_changes(&meta)))
}

// ---------------------------------------------------------------------------
// VPN connection
// ---------------------------------------------------------------------------

pub async fn vpn_conn(
    ctx: &AppContext, base_url_override: Option<&str>, request: &VpnConnRequest,
) -> Result<(BaseResponse<VpnConnResponse>, Vec<StateChange>)> {
    let client = match base_url_override {
        Some(base_url) => {
            let endpoint = TenantEndpoint::new(base_url).context(ApiSnafu)?;
            ctx.client_for_endpoint(&endpoint)
        }
        None => ctx.tenant_client().context(ContextSnafu)?.clone(),
    };
    let (response, meta) = request
        .clone()
        .send_with_meta(&client)
        .await
        .context(ApiSnafu)?;
    Ok((response, collect_meta_changes(&meta)))
}

pub async fn vpn_config_from_dot_list(
    ctx: &AppContext, request: &VpnConfigRequest,
) -> Result<(VpnConfigResult, Vec<StateChange>)> {
    let client = ctx.tenant_client().context(ContextSnafu)?;
    let (locations, meta) = GetVpnLocationsRequest
        .send_with_meta(client)
        .await
        .context(ApiSnafu)?;
    let mut all_changes = collect_meta_changes(&meta);
    let dots = locations.data.clone().context(MissingVpnDotListDataSnafu)?;
    if dots.is_empty() {
        return NoVpnDotsSnafu.fail();
    }

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

    candidates.truncate(MAX_DOT_ATTEMPTS);
    let mut last_error = None;
    for dot in candidates {
        let use_vpn_ip_for_api = dot.should_use_vpn_ip_for_config_api(!request.not_auto);
        let endpoint = DotEndpoint::from_dot(&dot, use_vpn_ip_for_api).context(ApiSnafu)?;
        let dot_client = ctx.dot_client(&endpoint);
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
            match body.clone().send_with_meta(&dot_client).await {
                Ok((response, dot_meta)) => {
                    all_changes.extend(collect_meta_changes(&dot_meta));
                    response.data.as_ref().context(MissingVpnConfigDataSnafu)?;
                    return Ok((
                        VpnConfigResult {
                            dot,
                            endpoint,
                            response,
                        },
                        all_changes,
                    ));
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
    ctx: &AppContext, dot: &VpnDot, request: &VpnReportRequest,
) -> Result<(BaseResponse<String>, Vec<StateChange>)> {
    let endpoint = DotEndpoint::from_dot(dot, false).context(ApiSnafu)?;
    let dot_client = ctx.dot_client(&endpoint);
    let (response, meta) = request
        .clone()
        .send_with_meta(&dot_client)
        .await
        .context(ApiSnafu)?;
    Ok((response, collect_meta_changes(&meta)))
}

/// Fetch the tenant TOTP provisioning from `POST /api/v2/p/otp`.
///
/// Gated on the Android `User-Agent` we send, the server returns an
/// `otpauth://` URI (carrying the secret/algorithm/digits/period) plus its
/// wall-clock `timestamp`.  We persist the URI and the derived clock offset so
/// codes can be generated locally for auto-reconnect.  Returns `Ok((None, _))`
/// when the tenant has no OTP requirement (empty `url`).
pub async fn fetch_totp(
    ctx: &AppContext,
) -> Result<(Option<persist::PersistedTotp>, Vec<StateChange>)> {
    let client = ctx.tenant_client().context(ContextSnafu)?;
    let (response, meta) = FetchOtpRequest
        .send_with_meta(client)
        .await
        .context(ApiSnafu)?;
    let changes = collect_meta_changes(&meta);
    let config = response.data.and_then(totp_from_provision);
    Ok((config, changes))
}

/// Build a [`persist::PersistedTotp`] from the provisioning payload, deriving
/// the server clock offset from its `timestamp` (server − local).
fn totp_from_provision(provision: OtpProvision) -> Option<persist::PersistedTotp> {
    let url = (!provision.url.is_empty()).then_some(provision.url)?;
    let now = jiff::Timestamp::now().as_second();
    let time_diff_seconds = match provision.timestamp {
        ts if ts > 0 => ts - now,
        _ => 0,
    };
    Some(persist::PersistedTotp {
        url,
        time_diff_seconds,
        ..Default::default()
    })
}

/// Generate a fresh RFC 6238 TOTP code for `/vpn/conn` from the stored
/// `otpauth://` URI, applying the persisted server clock offset.
///
/// Uses totp-rs's `from_url_unchecked` (otpauth feature) to honour the URI's
/// algorithm/digits/period and tolerate short/non-standard tenant secrets
/// (matching the Android client, which does not enforce the RFC minimum).
#[must_use]
pub fn generate_totp(config: &persist::PersistedTotp, now_unix: i64) -> Option<String> {
    let corrected = u64::try_from(now_unix + config.time_diff_seconds).ok()?;
    totp_rs::TOTP::from_url_unchecked(&config.url)
        .ok()
        .map(|totp| totp.generate(corrected))
}
