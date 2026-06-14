use rustylink_api::{
    BaseResponse, LoginSetting, TenantConfig, UserInfo, VpnConnRequest, VpnConnResponse,
    VpnLocation, VpnSetting,
};
use snafu::prelude::*;

use crate::{AppContext, error, error::Result};

pub async fn user_info(ctx: &mut AppContext) -> Result<BaseResponse<UserInfo>> {
    let client = ctx.api_client()?;
    let response = client.user_info().await.context(error::Api)?;
    ctx.sync_from_client(&client);
    ctx.save()?;
    Ok(response)
}

pub async fn tenant_config(ctx: &mut AppContext) -> Result<BaseResponse<TenantConfig>> {
    let client = ctx.api_client()?;
    let response = client.tenant_config().await.context(error::Api)?;
    ctx.sync_from_client(&client);
    if let Some(data) = &response.data {
        merge_signing_config(ctx, data);
    }
    ctx.save()?;
    Ok(response)
}

pub async fn login_setting(ctx: &mut AppContext) -> Result<BaseResponse<LoginSetting>> {
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

pub async fn vpn_setting(ctx: &mut AppContext) -> Result<BaseResponse<VpnSetting>> {
    let client = ctx.api_client()?;
    let response = client.vpn_setting().await.context(error::Api)?;
    ctx.sync_from_client(&client);
    ctx.save()?;
    Ok(response)
}

pub async fn vpn_locations(ctx: &mut AppContext) -> Result<BaseResponse<Vec<VpnLocation>>> {
    let client = ctx.api_client()?;
    let response = client.vpn_locations().await.context(error::Api)?;
    ctx.sync_from_client(&client);
    ctx.save()?;
    Ok(response)
}

pub async fn vpn_conn(
    ctx: &mut AppContext, base_url_override: Option<&str>, request: &VpnConnRequest,
) -> Result<BaseResponse<VpnConnResponse>> {
    let client = ctx.api_client()?;
    let response = client
        .vpn_conn(base_url_override, request)
        .await
        .context(error::Api)?;
    ctx.sync_from_client(&client);
    ctx.save()?;
    Ok(response)
}
