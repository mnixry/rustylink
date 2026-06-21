use rustylink_api::VpnConnResponse;
use serde::{Deserialize, Serialize};
use snafu::prelude::*;
use strum::{Display, EnumIter, EnumString};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("route manager setup failed: {source}"))]
    RouteManager { source: std::io::Error },

    #[snafu(display("invalid route CIDR `{cidr}`: {source}"))]
    InvalidRoute {
        cidr: String,
        source: ipnetwork::IpNetworkError,
    },

    #[snafu(display("failed to add route `{route}`: {source}"))]
    AddRoute {
        route: String,
        source: std::io::Error,
    },

    #[snafu(display("failed to delete route `{route}`: {source}"))]
    DeleteRoute {
        route: String,
        source: std::io::Error,
    },
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

#[derive(Debug)]
pub struct AppliedRoutes {
    interface_name: String,
    routes: Vec<route_manager::Route>,
}

impl RoutePlan {
    #[must_use]
    pub fn from_vpn_conn(conn: &VpnConnResponse) -> Self {
        let mut rules = Vec::new();
        add_rules(
            &mut rules,
            conn.setting.vpn_route_full.as_deref().unwrap_or_default(),
            AddressFamily::V4,
            RouteMode::Full,
        );
        add_rules(
            &mut rules,
            conn.setting.vpn_route_split.as_deref().unwrap_or_default(),
            AddressFamily::V4,
            RouteMode::Split,
        );
        add_rules(
            &mut rules,
            conn.setting.v6_route_full.as_deref().unwrap_or_default(),
            AddressFamily::V6,
            RouteMode::Full,
        );
        add_rules(
            &mut rules,
            conn.setting.v6_route_split.as_deref().unwrap_or_default(),
            AddressFamily::V6,
            RouteMode::Split,
        );
        Self { rules }
    }

    pub async fn apply(&self, interface_name: &str) -> Result<AppliedRoutes> {
        let routes = self.system_routes(interface_name)?;
        let mut manager = route_manager::AsyncRouteManager::new().context(RouteManagerSnafu)?;
        for route in &routes {
            tracing::debug!(%interface_name, %route, "adding VPN route");
            manager.add(route).await.context(AddRouteSnafu {
                route: route.to_string(),
            })?;
        }
        tracing::info!(
            %interface_name,
            routes = routes.len(),
            "applied VPN routes"
        );
        Ok(AppliedRoutes {
            interface_name: interface_name.to_string(),
            routes,
        })
    }

    fn system_routes(&self, interface_name: &str) -> Result<Vec<route_manager::Route>> {
        self.rules
            .iter()
            .map(|rule| system_route(rule, interface_name))
            .collect()
    }
}

impl AppliedRoutes {
    pub async fn remove(self) -> Result<()> {
        let mut manager = route_manager::AsyncRouteManager::new().context(RouteManagerSnafu)?;
        for route in self.routes.iter().rev() {
            tracing::debug!(interface_name = %self.interface_name, %route, "deleting VPN route");
            manager.delete(route).await.context(DeleteRouteSnafu {
                route: route.to_string(),
            })?;
        }
        tracing::info!(
            interface_name = %self.interface_name,
            routes = self.routes.len(),
            "deleted VPN routes"
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

fn system_route(rule: &RouteRule, interface_name: &str) -> Result<route_manager::Route> {
    let network = rule
        .cidr
        .parse::<ipnetwork::IpNetwork>()
        .context(InvalidRouteSnafu {
            cidr: rule.cidr.clone(),
        })?;
    Ok(route_manager::Route::new(network.ip(), network.prefix())
        .with_if_name(interface_name.to_string()))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::{AddressFamily, RouteMode, RouteRule, normalize_cidr, system_route};

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

    #[test]
    fn converts_plan_rule_to_system_route() {
        let route = system_route(
            &RouteRule {
                cidr: "10.0.0.0/8".to_string(),
                family: AddressFamily::V4,
                mode: RouteMode::Split,
            },
            "utun7",
        )
        .expect("route");
        assert_eq!(route.destination(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)));
        assert_eq!(route.prefix(), 8);
        assert_eq!(route.if_name().map(String::as_str), Some("utun7"));
    }
}
