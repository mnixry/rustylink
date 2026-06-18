use rustylink_api::{
    BaseResponse, DotEndpoint, FetchOtpRequest, GetLoginSettingRequest, GetTenantConfigRequest,
    GetUserInfoRequest, GetVpnLocationsRequest, GetVpnSettingRequest, LoginSetting, OtpAccount,
    SendableRequest, TenantConfig, TenantEndpoint, UserInfo, VpnConnRequest, VpnConnResponse,
    VpnDot, VpnReportRequest, VpnSetting,
};
use snafu::prelude::*;
use strum::{Display, EnumIter, EnumString, FromRepr, IntoStaticStr};

use crate::{
    AppContext,
    state::{StateChange, TotpConfig},
};

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
            cookies: cookies.clone(),
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
) -> Option<rustylink_api::SigningConfig> {
    let config = data.signing_config.as_ref()?;
    let mut signing = ctx.state.signing.clone();
    signing.enabled = config.enable.unwrap_or(signing.enabled);
    signing.algorithms = config.algorithms.clone().unwrap_or_default();
    signing.rules = config
        .rules
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|rule| rustylink_api::SigningRuleConfig {
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
                    if response.data.is_none() {
                        return MissingVpnConfigDataSnafu.fail();
                    }
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

/// Fetch the tenant TOTP secret from `POST /api/v2/p/otp`.
///
/// The response envelope is tenant-dependent, so the payload is parsed
/// defensively from a free-form JSON value (see `models::otp`) to extract the
/// default account.  Returns `Ok((None, _))` when no usable OTP account is
/// present (the caller falls back to a manual OTP on connect).
pub async fn fetch_totp(ctx: &AppContext) -> Result<(Option<TotpConfig>, Vec<StateChange>)> {
    let client = ctx.tenant_client().context(ContextSnafu)?;
    let (response, meta) = FetchOtpRequest
        .send_with_meta(client)
        .await
        .context(ApiSnafu)?;
    let changes = collect_meta_changes(&meta);
    let config = response
        .data
        .as_ref()
        .and_then(extract_default_otp_account)
        .and_then(totp_config_from_account);
    Ok((config, changes))
}

/// Locate the default OTP account within a free-form provisioning response.
fn extract_default_otp_account(value: &serde_json::Value) -> Option<OtpAccount> {
    // Collect candidate account objects from common shapes: a bare array, or
    // an object holding a list under a likely key, or a single account object.
    let candidates: Vec<serde_json::Value> = match value {
        serde_json::Value::Array(items) => items.clone(),
        serde_json::Value::Object(map) => {
            let list = ["otp_list", "list", "accounts", "data", "otps", "items"]
                .iter()
                .find_map(|key| map.get(*key))
                .and_then(serde_json::Value::as_array);
            list.map_or_else(|| vec![value.clone()], Clone::clone)
        }
        _ => return None,
    };

    let accounts: Vec<OtpAccount> = candidates
        .into_iter()
        .filter_map(|item| serde_json::from_value::<OtpAccount>(item).ok())
        .filter(|account| account.secret.as_ref().is_some_and(|s| !s.is_empty()))
        .collect();

    accounts
        .iter()
        .find(|account| account.is_default.unwrap_or(false))
        .or_else(|| accounts.first())
        .cloned()
}

fn totp_config_from_account(account: OtpAccount) -> Option<TotpConfig> {
    let secret = account.secret.filter(|s| !s.is_empty())?;
    let digits = account
        .digits
        .and_then(|d| d.parse::<u32>().ok())
        .filter(|d| *d > 0)
        .unwrap_or(6);
    let period = account
        .period
        .and_then(|p| u32::try_from(p).ok())
        .filter(|p| *p > 0)
        .unwrap_or(30);
    let algorithm = account
        .algorithm
        .filter(|a| !a.is_empty())
        .unwrap_or_else(|| "SHA1".to_string());
    Some(TotpConfig {
        secret,
        algorithm,
        digits,
        period,
    })
}

/// Generate a fresh RFC 6238 TOTP code for `/vpn/conn` from a stored config.
///
/// `unix_time` should be the server-corrected wall clock (`now + time_diff`).
/// Uses `new_unchecked` to tolerate short/non-standard tenant secrets (matches
/// the Android app, which does not enforce the RFC minimum length).
#[must_use]
pub fn generate_totp(config: &TotpConfig, unix_time: u64) -> Option<String> {
    use totp_rs::{Algorithm, Secret, TOTP};

    let algorithm = match config.algorithm.to_ascii_uppercase().as_str() {
        "SHA256" => Algorithm::SHA256,
        "SHA512" => Algorithm::SHA512,
        _ => Algorithm::SHA1,
    };
    let secret_bytes = Secret::Encoded(config.secret.clone()).to_bytes().ok()?;
    let digits = usize::try_from(config.digits).unwrap_or(6);
    let period = u64::from(config.period.max(1));
    let totp = TOTP::new_unchecked(
        algorithm,
        digits,
        1,
        period,
        secret_bytes,
        None,
        String::new(),
    );
    Some(totp.generate(unix_time))
}
