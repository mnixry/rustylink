use rustylink_api::{
    BaseResponse, DotEndpoint, GetLoginSettingRequest, GetTenantConfigRequest, GetUserInfoRequest,
    GetVpnLocationsRequest, GetVpnSettingRequest, LoginSetting, SendableRequest, TenantConfig,
    TenantEndpoint, UserInfo, VpnConnRequest, VpnConnResponse, VpnDot, VpnReportRequest,
    VpnSetting,
};
use snafu::prelude::*;
use strum::{Display, EnumIter, EnumString, FromRepr, IntoStaticStr};

use crate::AppContext;

const MAX_DOT_ATTEMPTS: usize = 3;
const MAX_CONFIG_ATTEMPTS_PER_DOT: usize = 3;

#[derive(
    Clone, Copy, Debug, Display, EnumIter, EnumString, Eq, FromRepr, IntoStaticStr, PartialEq,
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

pub async fn user_info(ctx: &mut AppContext) -> Result<BaseResponse<UserInfo>> {
    let client = ctx.api_client().context(ContextSnafu)?;
    let response = GetUserInfoRequest.send(&client).await.context(ApiSnafu)?;
    ctx.sync_from_client(&client);
    ctx.save().context(ContextSnafu)?;
    Ok(response)
}

pub async fn tenant_config(ctx: &mut AppContext) -> Result<BaseResponse<TenantConfig>> {
    let client = ctx.api_client().context(ContextSnafu)?;
    let response = GetTenantConfigRequest
        .send(&client)
        .await
        .context(ApiSnafu)?;
    ctx.sync_from_client(&client);
    if let Some(data) = &response.data {
        merge_signing_config(ctx, data);
    }
    ctx.save().context(ContextSnafu)?;
    Ok(response)
}

pub async fn login_setting(ctx: &mut AppContext) -> Result<BaseResponse<LoginSetting>> {
    let client = ctx.api_client().context(ContextSnafu)?;
    let response = GetLoginSettingRequest
        .send(&client)
        .await
        .context(ApiSnafu)?;
    ctx.sync_from_client(&client);
    ctx.save().context(ContextSnafu)?;
    Ok(response)
}

fn merge_signing_config(ctx: &mut AppContext, data: &TenantConfig) {
    let Some(config) = &data.signing_config else {
        return;
    };

    ctx.state.signing.enabled = config.enable.unwrap_or(ctx.state.signing.enabled);
    ctx.state.signing.algorithms = config.algorithms.clone().unwrap_or_default();
    ctx.state.signing.rules = config
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
}

pub async fn vpn_setting(ctx: &mut AppContext) -> Result<BaseResponse<VpnSetting>> {
    let client = ctx.api_client().context(ContextSnafu)?;
    let response = GetVpnSettingRequest.send(&client).await.context(ApiSnafu)?;
    ctx.sync_from_client(&client);
    ctx.save().context(ContextSnafu)?;
    Ok(response)
}

pub async fn vpn_locations(ctx: &mut AppContext) -> Result<BaseResponse<Vec<VpnDot>>> {
    let client = ctx.api_client().context(ContextSnafu)?;
    let response = GetVpnLocationsRequest
        .send(&client)
        .await
        .context(ApiSnafu)?;
    ctx.sync_from_client(&client);
    ctx.save().context(ContextSnafu)?;
    Ok(response)
}

pub async fn vpn_conn(
    ctx: &mut AppContext, base_url_override: Option<&str>, request: &VpnConnRequest,
) -> Result<BaseResponse<VpnConnResponse>> {
    let client = match base_url_override {
        Some(base_url) => {
            let endpoint = TenantEndpoint::new(base_url).context(ApiSnafu)?;
            ctx.api_client_for_endpoint(&endpoint)
                .context(ContextSnafu)?
        }
        None => ctx.api_client().context(ContextSnafu)?,
    };
    let response = request.clone().send(&client).await.context(ApiSnafu)?;
    ctx.sync_from_client(&client);
    ctx.save().context(ContextSnafu)?;
    Ok(response)
}

pub async fn vpn_config_from_dot_list(
    ctx: &mut AppContext, request: &VpnConfigRequest,
) -> Result<VpnConfigResult> {
    let client = ctx.api_client().context(ContextSnafu)?;
    let locations = GetVpnLocationsRequest
        .send(&client)
        .await
        .context(ApiSnafu)?;
    ctx.sync_from_client(&client);
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
        let dot_client = ctx
            .api_client_for_endpoint(&endpoint)
            .context(ContextSnafu)?;
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
                    ctx.sync_from_client(&dot_client);
                    ctx.save().context(ContextSnafu)?;
                    if response.data.is_none() {
                        return MissingVpnConfigDataSnafu.fail();
                    }
                    return Ok(VpnConfigResult {
                        dot,
                        endpoint,
                        response,
                    });
                }
                Err(source) => {
                    ctx.sync_from_client(&dot_client);
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

    ctx.save().context(ContextSnafu)?;
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
    ctx: &mut AppContext, dot: &VpnDot, request: &VpnReportRequest,
) -> Result<BaseResponse<String>> {
    let endpoint = DotEndpoint::from_dot(dot, false).context(ApiSnafu)?;
    let client = ctx
        .api_client_for_endpoint(&endpoint)
        .context(ContextSnafu)?;
    let response = request.clone().send(&client).await.context(ApiSnafu)?;
    ctx.sync_from_client(&client);
    ctx.save().context(ContextSnafu)?;
    Ok(response)
}
