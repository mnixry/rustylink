use rustylink_api::VpnConnResponse;
use serde::{Deserialize, Serialize};
use snafu::prelude::*;
use strum::{Display, EnumIter, EnumString};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("route manager failed: {message}"))]
    RouteManager { message: String },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RouteRule {
    pub cidr: String,
    pub family: AddressFamily,
    pub mode: RouteMode,
}

#[derive(
    Clone, Copy, Debug, Deserialize, Display, EnumIter, EnumString, Eq, PartialEq, Serialize,
)]
pub enum AddressFamily {
    V4,
    V6,
}

#[derive(
    Clone, Copy, Debug, Deserialize, Display, EnumIter, EnumString, Eq, PartialEq, Serialize,
)]
pub enum RouteMode {
    Full,
    Split,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct RoutePlan {
    pub rules: Vec<RouteRule>,
}

impl RoutePlan {
    #[must_use]
    pub fn from_vpn_conn(conn: &VpnConnResponse) -> Self {
        let mut rules = Vec::new();
        add_rules(
            &mut rules,
            &conn.setting.vpn_route_full,
            AddressFamily::V4,
            RouteMode::Full,
        );
        add_rules(
            &mut rules,
            &conn.setting.vpn_route_split,
            AddressFamily::V4,
            RouteMode::Split,
        );
        add_rules(
            &mut rules,
            &conn.setting.v6_route_full,
            AddressFamily::V6,
            RouteMode::Full,
        );
        add_rules(
            &mut rules,
            &conn.setting.v6_route_split,
            AddressFamily::V6,
            RouteMode::Split,
        );
        Self { rules }
    }

    pub fn apply(&self) -> Result<()> {
        tracing::info!(
            routes = self.rules.len(),
            "route plan ready for route_manager"
        );
        Ok(())
    }
}

fn add_rules(rules: &mut Vec<RouteRule>, cidrs: &[String], family: AddressFamily, mode: RouteMode) {
    for cidr in cidrs {
        rules.push(RouteRule {
            cidr: normalize_cidr(cidr, family),
            family,
            mode,
        });
    }
}

fn normalize_cidr(value: &str, family: AddressFamily) -> String {
    if value.contains('/') {
        return value.to_string();
    }
    match family {
        AddressFamily::V4 => format!("{value}/32"),
        AddressFamily::V6 => format!("{value}/128"),
    }
}

#[cfg(test)]
mod tests {
    use super::{AddressFamily, normalize_cidr};

    #[test]
    fn normalizes_host_routes() {
        assert_eq!(normalize_cidr("10.0.0.1", AddressFamily::V4), "10.0.0.1/32");
        assert_eq!(normalize_cidr("fd00::1", AddressFamily::V6), "fd00::1/128");
    }

    #[test]
    fn keeps_existing_prefixes() {
        assert_eq!(
            normalize_cidr("10.0.0.0/8", AddressFamily::V4),
            "10.0.0.0/8"
        );
    }
}
