use std::str::FromStr;

use rustylink_api::{VpnConnRequest, VpnReportRequest};
use rustylink_core::{
    AppContext,
    vpn::{self, VpnConfigRequest, VpnConnectMode},
};
use rustylink_tunnel::{LocalTunnelParams, OutboundInterface, TunnelConfig, TunnelSession};
use serde_json::json;
use snafu::prelude::*;
use strum::IntoEnumIterator;

use crate::{
    args::{VpnConnArgs, VpnSubcommand},
    error::{Result, cli_error},
    output::print_json,
};

pub async fn handle(ctx: &mut AppContext, command: VpnSubcommand) -> Result<()> {
    match command {
        VpnSubcommand::Setting => {
            let response = vpn::vpn_setting(ctx).await.context(cli_error::VpnSnafu)?;
            print_json(&response)?;
        }
        VpnSubcommand::Locations => {
            let response = vpn::vpn_locations(ctx).await.context(cli_error::VpnSnafu)?;
            print_json(&response)?;
        }
        VpnSubcommand::Conn(args) => {
            let request = vpn_conn_request(ctx, args).await?;
            let response = vpn::vpn_conn(ctx, request.1.as_deref(), &request.0)
                .await
                .context(cli_error::VpnSnafu)?;
            print_json(&response)?;
        }
        VpnSubcommand::Connect(args) => {
            let outbound_interface = ensure_outbound_interface(ctx)?;
            let mode = parse_vpn_mode(args.mode.as_deref())?;
            let export_id = resolve_export_id(ctx, args.export_id).await?;
            let local_params = local_params_for_connect(&args)?;
            let config_request = VpnConfigRequest {
                mode,
                public_key: local_params.local_public_key.clone(),
                export_id,
                otp: args.otp,
                sign_token: args.sign_token,
                not_auto: args.not_auto.unwrap_or(true),
                reconnect: args.reconnect,
                preferred_dot_id: args.dot_id,
            };
            let config_result = vpn::vpn_config_from_dot_list(ctx, &config_request)
                .await
                .context(cli_error::VpnSnafu)?;
            let data = config_result
                .response
                .data
                .clone()
                .expect("core checked config data exists");
            let mut config = TunnelConfig::from_vpn_conn(
                &data,
                local_params.clone(),
                config_result.endpoint.wireguard_endpoint.clone(),
                config_result.dot.protocol_mode,
                config_result.dot.protocol_detect_enabled(),
            )
            .context(cli_error::TunnelSnafu)?;
            config.outbound_interface = outbound_interface.map(|interface| interface.name);
            let mut session = TunnelSession::new(config);
            session.start().await.context(cli_error::TunnelSnafu)?;
            let connect_report =
                vpn_report_request(100, &data.ip, &local_params.local_public_key, mode);
            let connect_report_response =
                match vpn::report_vpn(ctx, &config_result.dot, &connect_report).await {
                    Ok(response) => Some(response),
                    Err(error) => {
                        tracing::warn!(%error, "failed to report VPN connection");
                        None
                    }
                };
            print_json(&json!({
                "response": &config_result.response,
                "dot": &config_result.dot,
                "endpoint": &config_result.endpoint,
                "local_public_key": &local_params.local_public_key,
                "outbound_interface": ctx.outbound_interface(),
                "connect_report": connect_report_response,
                "tunnel_status": session.status,
            }))?;
            tokio::signal::ctrl_c()
                .await
                .context(cli_error::WaitForSignalSnafu)?;
            let disconnect_report =
                vpn_report_request(101, &data.ip, &local_params.local_public_key, mode);
            if let Err(error) = vpn::report_vpn(ctx, &config_result.dot, &disconnect_report).await {
                tracing::warn!(%error, "failed to report VPN disconnection");
            }
            session.stop().await.context(cli_error::TunnelSnafu)?;
        }
    }
    Ok(())
}

fn ensure_outbound_interface(ctx: &mut AppContext) -> Result<Option<OutboundInterface>> {
    let outbound_interface = OutboundInterface::resolve(ctx.outbound_interface(), None)
        .context(cli_error::OutboundInterfaceSnafu)?;
    if let Some(outbound_interface) = &outbound_interface {
        ctx.set_outbound_interface(Some(outbound_interface.name.clone()));
    }
    Ok(outbound_interface)
}

async fn vpn_conn_request(
    ctx: &mut AppContext, args: VpnConnArgs,
) -> Result<(VpnConnRequest, Option<String>)> {
    let mode = parse_vpn_mode(args.mode.as_deref())?;
    let export_id = resolve_export_id(ctx, args.export_id).await?;
    let public_key = args
        .public_key
        .unwrap_or_else(|| LocalTunnelParams::generate().local_public_key);
    Ok((
        VpnConnRequest {
            mode: Some(mode.android_name()),
            public_key,
            otp: args.otp,
            export_id,
            sign_token: args.sign_token,
            not_auto: args.not_auto,
        },
        args.api_base_url,
    ))
}

async fn resolve_export_id(ctx: &mut AppContext, export_id: Option<i32>) -> Result<i32> {
    if let Some(export_id) = export_id {
        return Ok(export_id);
    }
    let setting = vpn::vpn_setting(ctx).await.context(cli_error::VpnSnafu)?;
    setting
        .data
        .and_then(|data| data.export_id)
        .context(cli_error::MissingExportIdSnafu)
}

fn local_params_for_connect(args: &VpnConnArgs) -> Result<LocalTunnelParams> {
    if let Some(private_key) = &args.local_private_key {
        return LocalTunnelParams::from_private_key(private_key).context(cli_error::TunnelSnafu);
    }
    Ok(LocalTunnelParams::generate())
}

fn parse_vpn_mode(value: Option<&str>) -> Result<VpnConnectMode> {
    let Some(value) = value else {
        return Ok(VpnConnectMode::Full);
    };
    VpnConnectMode::from_str(value).map_err(|_| {
        cli_error::InvalidVpnModeSnafu {
            value: value.to_string(),
            expected: vpn_mode_names(),
        }
        .build()
    })
}

fn vpn_mode_names() -> String {
    VpnConnectMode::iter()
        .map(VpnConnectMode::android_name)
        .collect::<Vec<_>>()
        .join(", ")
}

fn vpn_report_request(
    report_type: i32, ip: &str, public_key: &str, mode: VpnConnectMode,
) -> VpnReportRequest {
    VpnReportRequest {
        ip: ip.to_string(),
        mode: mode.android_name(),
        public_key: public_key.to_string(),
        r#type: report_type.to_string(),
    }
}
