//! macOS route bypass: scoped default route.
//!
//! Installs `route add -ifscope <iface> default <gateway>` so that sockets
//! bound via `IP_BOUND_IF` have a valid route even when `/1` full-tunnel
//! routes point all traffic to the TUN.
//!
//! This is the industry-standard approach used by clash-rs, mihomo/sing-tun,
//! and `NetBird`.

use std::net::IpAddr;

use snafu::prelude::*;

use crate::OutboundInterface;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed to add scoped default route on `{interface}`: {stderr}"))]
    AddScopedDefault { interface: String, stderr: String },

    #[snafu(display("failed to run `route` command: {source}"))]
    RouteCommand { source: std::io::Error },
}

// ---------------------------------------------------------------------------
// RouteBypass
// ---------------------------------------------------------------------------

pub struct RouteBypass {
    interface_name: String,
    gateway_v4: Option<IpAddr>,
    gateway_v6: Option<IpAddr>,
}

#[async_trait::async_trait]
impl super::RouteBypassT for RouteBypass {
    type Error = Error;

    async fn setup(interface: &OutboundInterface, full_tunnel: bool) -> Result<Self, Error> {
        if !full_tunnel {
            return Ok(Self {
                interface_name: interface.name.clone(),
                gateway_v4: None,
                gateway_v6: None,
            });
        }

        let gw_v4 = interface.gateway_v4;
        let gw_v6 = interface.gateway_v6;

        if let Some(gw) = gw_v4 {
            add_scoped_default(&interface.name, gw, false).await?;
        }
        if let Some(gw) = gw_v6 {
            add_scoped_default(&interface.name, gw, true).await?;
        }

        if gw_v4.is_none() && gw_v6.is_none() {
            tracing::warn!(
                interface = %interface.name,
                "no gateway available for scoped default route; \
                 IP_BOUND_IF may fail with ENETUNREACH in full-tunnel mode"
            );
        } else {
            tracing::info!(
                interface = %interface.name,
                ?gw_v4,
                ?gw_v6,
                "route bypass installed (macOS scoped defaults)"
            );
        }

        Ok(Self {
            interface_name: interface.name.clone(),
            gateway_v4: gw_v4,
            gateway_v6: gw_v6,
        })
    }

    async fn teardown(self) -> Result<(), Error> {
        if let Some(gw) = self.gateway_v4 {
            remove_scoped_default(&self.interface_name, gw, false).await;
        }
        if let Some(gw) = self.gateway_v6 {
            remove_scoped_default(&self.interface_name, gw, true).await;
        }
        tracing::info!(
            interface = %self.interface_name,
            "route bypass removed"
        );
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Shell helpers
// ---------------------------------------------------------------------------

async fn add_scoped_default(iface: &str, gateway: IpAddr, ipv6: bool) -> Result<(), Error> {
    use tokio::process::Command;

    let gw = gateway.to_string();
    let mut args = vec!["add"];
    if ipv6 {
        args.push("-inet6");
    }
    args.extend(["-ifscope", iface, "default", &gw]);

    tracing::debug!(
        %iface, %gateway, ipv6,
        cmd = %format!("route {}", args.join(" ")),
        "adding scoped default route"
    );

    let output = Command::new("route")
        .args(&args)
        .output()
        .await
        .context(RouteCommandSnafu)?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        // "File exists" is harmless — the scoped route is already present.
        if !stderr.contains("File exists") {
            return AddScopedDefaultSnafu {
                interface: iface.to_string(),
                stderr,
            }
            .fail();
        }
        tracing::debug!(
            %iface, %gateway, ipv6,
            "scoped default route already exists"
        );
    }

    Ok(())
}

async fn remove_scoped_default(iface: &str, gateway: IpAddr, ipv6: bool) {
    use tokio::process::Command;

    let gw = gateway.to_string();
    let mut args = vec!["delete"];
    if ipv6 {
        args.push("-inet6");
    }
    args.extend(["-ifscope", iface, "default", &gw]);

    tracing::debug!(
        %iface, %gateway, ipv6,
        cmd = %format!("route {}", args.join(" ")),
        "removing scoped default route"
    );

    match Command::new("route").args(&args).output().await {
        Ok(output) if !output.status.success() => {
            let stderr = String::from_utf8_lossy(&output.stderr);
            tracing::debug!(%iface, %gateway, %stderr, "scoped default route removal note");
        }
        Err(e) => {
            tracing::warn!(%iface, %gateway, %e, "failed to run route delete command");
        }
        _ => {}
    }
}
