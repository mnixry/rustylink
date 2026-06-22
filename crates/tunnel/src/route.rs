use ipnetwork::IpNetwork;
use rustylink_api::VpnConnResponse;
use serde::{Deserialize, Serialize};
use snafu::prelude::*;
use strum::{Display, EnumIter, EnumString};

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("route manager setup failed: {source}"))]
    RouteManager { source: std::io::Error },

    #[snafu(display("invalid route `{cidr}`: {source}"))]
    InvalidRoute {
        cidr: String,
        source: ipnetwork::IpNetworkError,
    },

    #[snafu(display("invalid route `{cidr}`: expected {family} route"))]
    InvalidRouteFamily { cidr: String, family: AddressFamily },

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
    pub network: IpNetwork,
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
    pub fn from_vpn_conn(conn: &VpnConnResponse) -> Result<Self> {
        let mut rules = Vec::new();
        add_rules(
            &mut rules,
            conn.setting.vpn_route_full.as_deref().unwrap_or_default(),
            AddressFamily::V4,
            RouteMode::Full,
        )?;
        add_rules(
            &mut rules,
            conn.setting.vpn_route_split.as_deref().unwrap_or_default(),
            AddressFamily::V4,
            RouteMode::Split,
        )?;
        add_rules(
            &mut rules,
            conn.setting.v6_route_full.as_deref().unwrap_or_default(),
            AddressFamily::V6,
            RouteMode::Full,
        )?;
        add_rules(
            &mut rules,
            conn.setting.v6_route_split.as_deref().unwrap_or_default(),
            AddressFamily::V6,
            RouteMode::Split,
        )?;
        Ok(Self { rules })
    }

    pub async fn apply(&self, interface_name: &str) -> Result<AppliedRoutes> {
        let routes = self.system_routes(interface_name);
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

    fn system_routes(&self, interface_name: &str) -> Vec<route_manager::Route> {
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

fn add_rules(
    rules: &mut Vec<RouteRule>, cidrs: &[String], family: AddressFamily, mode: RouteMode,
) -> Result<()> {
    for cidr in cidrs {
        let network = parse_network(cidr, family)?;
        rules.push(RouteRule {
            network,
            family,
            mode,
        });
    }
    Ok(())
}

fn parse_network(value: &str, family: AddressFamily) -> Result<IpNetwork> {
    let network = value.parse::<IpNetwork>().context(InvalidRouteSnafu {
        cidr: value.to_string(),
    })?;
    ensure!(
        (network.is_ipv4() && family == AddressFamily::V4)
            || (network.is_ipv6() && family == AddressFamily::V6),
        InvalidRouteFamilySnafu {
            cidr: value.to_string(),
            family,
        }
    );
    Ok(network)
}

fn system_route(rule: &RouteRule, interface_name: &str) -> route_manager::Route {
    route_manager::Route::new(rule.network.network(), rule.network.prefix())
        .with_if_name(interface_name.to_string())
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::{AddressFamily, RouteMode, RouteRule, parse_network, system_route};

    #[test]
    fn normalizes_host_routes() {
        assert_eq!(
            parse_network("10.0.0.1", AddressFamily::V4).expect("network"),
            "10.0.0.1/32".parse().expect("static CIDR")
        );
        assert_eq!(
            parse_network("fd00::1", AddressFamily::V6).expect("network"),
            "fd00::1/128".parse().expect("static CIDR")
        );
    }

    #[test]
    fn keeps_existing_prefixes() {
        assert_eq!(
            parse_network("10.0.0.0/8", AddressFamily::V4).expect("network"),
            "10.0.0.0/8".parse().expect("static CIDR")
        );
    }

    #[test]
    fn converts_plan_rule_to_system_route() {
        let route = system_route(
            &RouteRule {
                network: "10.0.0.0/8".parse().expect("static CIDR"),
                family: AddressFamily::V4,
                mode: RouteMode::Split,
            },
            "utun7",
        );
        assert_eq!(route.destination(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)));
        assert_eq!(route.prefix(), 8);
        assert_eq!(route.if_name().map(String::as_str), Some("utun7"));
    }
}
