use rustylink_api::VpnConnResponse;
use serde::{Deserialize, Serialize};

use crate::{DnsHijackPlan, RoutePlan, error, error::Result};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct TunnelConfig {
    pub interface_name: String,
    pub local_addr: String,
    pub local_addr_v6: Option<String>,
    pub local_prefix: Option<i32>,
    pub mtu: i32,
    pub server_public_key: String,
    pub server_preshared_key: Option<String>,
    pub protocol_version: Option<String>,
    pub route_plan: RoutePlan,
    pub dns_plan: DnsHijackPlan,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TunnelStatus {
    Created,
    RoutesApplied,
    Running,
    Stopped,
}

#[derive(Debug)]
pub struct TunnelSession {
    pub config: TunnelConfig,
    pub status: TunnelStatus,
}

impl TunnelConfig {
    pub fn from_vpn_conn(conn: &VpnConnResponse) -> Result<Self> {
        if conn.setting.vpn_mtu <= 0 {
            return error::InvalidConfig {
                reason: "vpn_mtu must be positive".to_string(),
            }
            .fail();
        }
        Ok(Self {
            interface_name: "wg0".to_string(),
            local_addr: conn.ip.clone(),
            local_addr_v6: conn.ipv6.clone(),
            local_prefix: conn.ip_mask,
            mtu: conn.setting.vpn_mtu,
            server_public_key: conn.public_key.clone(),
            server_preshared_key: conn.preshared_key.clone(),
            protocol_version: conn.protocol_version.clone(),
            route_plan: RoutePlan::from_vpn_conn(conn),
            dns_plan: DnsHijackPlan::from_vpn_conn(conn),
        })
    }
}

impl TunnelSession {
    #[must_use]
    pub const fn new(config: TunnelConfig) -> Self {
        Self {
            config,
            status: TunnelStatus::Created,
        }
    }

    #[allow(clippy::unused_async)]
    pub async fn start(&mut self) -> Result<()> {
        tracing::info!(
            interface = %self.config.interface_name,
            mtu = self.config.mtu,
            "starting tunnel session"
        );
        self.config.route_plan.apply()?;
        self.status = TunnelStatus::RoutesApplied;
        tracing::info!("gotatun/tun-rs startup point reached");
        self.status = TunnelStatus::Running;
        Ok(())
    }

    #[allow(clippy::unused_async)]
    pub async fn stop(&mut self) -> Result<()> {
        tracing::info!(interface = %self.config.interface_name, "stopping tunnel session");
        self.status = TunnelStatus::Stopped;
        Ok(())
    }
}
