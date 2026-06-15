use rustylink_api::{
    GetLoginSettingResponse, GetTenantConfigResponse, GetUserInfoResponse, GetVpnLocationsResponse,
    GetVpnSettingResponse, ReportVpnResponse, TenantConfig, VpnConnEnvelope, VpnConnRequest,
    VpnDot, VpnDotServers, VpnReportRequest,
};
use snafu::prelude::*;

use crate::{AppContext, error, error::Result};

const MAX_DOT_ATTEMPTS: usize = 3;
const MAX_CONFIG_ATTEMPTS_PER_DOT: usize = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VpnConnectMode {
    Full,
    Split,
    Relay,
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
    pub servers: VpnDotServers,
    pub response: VpnConnEnvelope,
}

impl VpnConnectMode {
    #[must_use]
    pub const fn android_id(self) -> i32 {
        match self {
            Self::Full => 0,
            Self::Split => 1,
            Self::Relay => 2,
        }
    }

    #[must_use]
    pub const fn android_name(self) -> &'static str {
        match self {
            Self::Full => "Full",
            Self::Split => "Split",
            Self::Relay => "Relay",
        }
    }
}

pub async fn user_info(ctx: &mut AppContext) -> Result<GetUserInfoResponse> {
    let client = ctx.api_client()?;
    let response = client.user_info().await.context(error::Api)?;
    ctx.sync_from_client(&client);
    ctx.save()?;
    Ok(response)
}

pub async fn tenant_config(ctx: &mut AppContext) -> Result<GetTenantConfigResponse> {
    let client = ctx.api_client()?;
    let response = client.tenant_config().await.context(error::Api)?;
    ctx.sync_from_client(&client);
    if let Some(data) = &response.data {
        merge_signing_config(ctx, data);
    }
    ctx.save()?;
    Ok(response)
}

pub async fn login_setting(ctx: &mut AppContext) -> Result<GetLoginSettingResponse> {
    let client = ctx.api_client()?;
    let response = client.login_setting().await.context(error::Api)?;
    ctx.sync_from_client(&client);
    ctx.save()?;
    Ok(response)
}

fn merge_signing_config(ctx: &mut AppContext, data: &TenantConfig) {
    let Some(config) = &data.signing_config else {
        return;
    };

    ctx.state.signing.enabled = config.enable.unwrap_or(ctx.state.signing.enabled);
    ctx.state.signing.algorithms.clone_from(&config.algorithms);
    ctx.state.signing.rules = config
        .rules
        .iter()
        .map(|rule| rustylink_api::SigningRuleConfig {
            urls: rule.urls.clone(),
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

pub async fn vpn_setting(ctx: &mut AppContext) -> Result<GetVpnSettingResponse> {
    let client = ctx.api_client()?;
    let response = client.vpn_setting().await.context(error::Api)?;
    ctx.sync_from_client(&client);
    ctx.save()?;
    Ok(response)
}

pub async fn vpn_locations(ctx: &mut AppContext) -> Result<GetVpnLocationsResponse> {
    let client = ctx.api_client()?;
    let response = client.vpn_locations().await.context(error::Api)?;
    ctx.sync_from_client(&client);
    ctx.save()?;
    Ok(response)
}

pub async fn vpn_conn(
    ctx: &mut AppContext, base_url_override: Option<&str>, request: &VpnConnRequest,
) -> Result<VpnConnEnvelope> {
    let client = ctx.api_client()?;
    let response = client
        .vpn_conn(base_url_override, request)
        .await
        .context(error::Api)?;
    ctx.sync_from_client(&client);
    ctx.save()?;
    Ok(response)
}

pub async fn vpn_config_from_dot_list(
    ctx: &mut AppContext, request: &VpnConfigRequest,
) -> Result<VpnConfigResult> {
    let client = ctx.api_client()?;
    let locations = client.vpn_locations().await.context(error::Api)?;
    ctx.sync_from_client(&client);
    let dots = locations.data.clone();
    if dots.is_empty() {
        return error::NoVpnDots.fail();
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
        return error::NoSupportedVpnDot {
            mode: request.mode.android_name().to_string(),
        }
        .fail();
    }

    candidates.truncate(MAX_DOT_ATTEMPTS);
    let mut last_error = None;
    for dot in candidates {
        let use_vpn_ip_for_api = dot.should_use_vpn_ip_for_config_api(!request.not_auto);
        let servers = VpnDotServers::from_dot(&dot, use_vpn_ip_for_api).context(error::Api)?;
        let body = VpnConnRequest {
            mode: Some(request.mode.android_name().to_string()),
            public_key: request.public_key.clone(),
            otp: request.otp.clone(),
            export_id: request.export_id,
            sign_token: request.sign_token.clone(),
            not_auto: Some(request.not_auto),
        };
        for attempt in 1..=MAX_CONFIG_ATTEMPTS_PER_DOT {
            tracing::info!(
                dot_id = dot.id,
                api_base_url = %servers.api_base_url,
                attempt,
                "requesting VPN config from dot"
            );
            match client
                .vpn_conn_for_dot(&dot, use_vpn_ip_for_api, &body)
                .await
            {
                Ok(response) => {
                    ctx.sync_from_client(&client);
                    ctx.save()?;
                    if response.data.is_none() {
                        return error::MissingVpnConfigData.fail();
                    }
                    return Ok(VpnConfigResult {
                        dot,
                        servers,
                        response,
                    });
                }
                Err(source) => {
                    tracing::warn!(
                        dot_id = dot.id,
                        api_base_url = %servers.api_base_url,
                        attempt,
                        error = %source,
                        "VPN config request failed"
                    );
                    last_error = Some(source);
                }
            }
        }
    }

    ctx.sync_from_client(&client);
    ctx.save()?;
    if let Some(source) = last_error {
        return Err(error::Error::Api {
            source: Box::new(source),
        });
    }
    error::NoSupportedVpnDot {
        mode: request.mode.android_name().to_string(),
    }
    .fail()
}

pub async fn report_vpn(
    ctx: &mut AppContext, dot: &VpnDot, request: &VpnReportRequest,
) -> Result<ReportVpnResponse> {
    let client = ctx.api_client()?;
    let response = client
        .report_vpn_for_dot(dot, request)
        .await
        .context(error::Api)?;
    ctx.sync_from_client(&client);
    ctx.save()?;
    Ok(response)
}
