use std::{io, net::IpAddr};

use ipnetwork::IpNetwork;
use rustylink_api::VpnConnResponse;
use snafu::prelude::*;
use strum::Display;

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
    InvalidRouteFamily { cidr: String, family: &'static str },

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

#[derive(Clone, Copy, Debug, Display, Eq, PartialEq)]
pub enum VpnRouteMode {
    Full,
    Split,
}

#[derive(Clone, Copy, Debug, Display, Eq, PartialEq)]
enum AddressFamily {
    V4,
    V6,
}

impl AddressFamily {
    const fn name(self) -> &'static str {
        match self {
            Self::V4 => "V4",
            Self::V6 => "V6",
        }
    }
}

#[derive(Debug)]
pub struct AppliedRoutes {
    interface_name: String,
    routes: Vec<route_manager::Route>,
}

pub fn networks_from_vpn_conn(
    conn: &VpnConnResponse, route_mode: VpnRouteMode, ipv6_enabled: bool,
) -> Result<Vec<IpNetwork>> {
    let mut routes = Vec::new();
    let (v4_cidrs, v6_cidrs) = match route_mode {
        VpnRouteMode::Full => (
            conn.setting.vpn_route_full.as_deref().unwrap_or_default(),
            conn.setting.v6_route_full.as_deref().unwrap_or_default(),
        ),
        VpnRouteMode::Split => (
            conn.setting.vpn_route_split.as_deref().unwrap_or_default(),
            conn.setting.v6_route_split.as_deref().unwrap_or_default(),
        ),
    };
    add_networks(&mut routes, v4_cidrs, AddressFamily::V4)?;
    if ipv6_enabled {
        add_networks(&mut routes, v6_cidrs, AddressFamily::V6)?;
    }
    Ok(routes)
}

/// Build host routes (`/32` or `/128`) for the given system DNS server IPs so
/// their traffic enters the TUN and can be intercepted by the DNS hijacker.
/// IPv6 servers are included only when `ipv6_enabled`.
#[must_use]
pub fn dns_host_routes(servers: &[IpAddr], ipv6_enabled: bool) -> Vec<IpNetwork> {
    servers
        .iter()
        .filter(|ip| ipv6_enabled || ip.is_ipv4())
        .copied()
        .map(IpNetwork::from)
        .collect()
}

pub async fn apply(interface_name: &str, networks: &[IpNetwork]) -> Result<AppliedRoutes> {
    let routes = system_routes(interface_name, networks);
    let planned_routes = routes.iter().map(ToString::to_string).collect::<Vec<_>>();
    tracing::info!(
        %interface_name,
        routes = planned_routes.len(),
        planned_routes = ?planned_routes,
        "planned VPN routes to add"
    );

    let mut manager = route_manager::AsyncRouteManager::new().context(RouteManagerSnafu)?;
    let mut added_routes = Vec::new();
    for route in routes {
        tracing::debug!(%interface_name, %route, "adding VPN route");
        match manager.add(&route).await {
            Ok(()) => added_routes.push(route),
            Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {
                tracing::warn!(
                    %interface_name,
                    %route,
                    "VPN route already installed; skipping"
                );
            }
            Err(source) => {
                let route = route.to_string();
                rollback_added_routes(&mut manager, interface_name, &added_routes).await;
                return Err(Error::AddRoute { route, source });
            }
        }
    }
    tracing::info!(
        %interface_name,
        routes = added_routes.len(),
        "applied VPN routes"
    );
    Ok(AppliedRoutes {
        interface_name: interface_name.to_string(),
        routes: added_routes,
    })
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

// NIT: garbage
fn add_networks(
    routes: &mut Vec<IpNetwork>, cidrs: &[String], family: AddressFamily,
) -> Result<()> {
    for cidr in cidrs {
        routes.push(parse_network(cidr, family)?);
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
            family: family.name(),
        }
    );
    Ok(network)
}

fn system_routes(interface_name: &str, networks: &[IpNetwork]) -> Vec<route_manager::Route> {
    networks
        .iter()
        .map(|network| system_route(*network, interface_name))
        .collect()
}

fn system_route(network: IpNetwork, interface_name: &str) -> route_manager::Route {
    route_manager::Route::new(network.network(), network.prefix())
        .with_if_name(interface_name.to_string())
}

async fn rollback_added_routes(
    manager: &mut route_manager::AsyncRouteManager, interface_name: &str,
    routes: &[route_manager::Route],
) {
    for route in routes.iter().rev() {
        tracing::debug!(%interface_name, %route, "rolling back VPN route");
        if let Err(error) = manager.delete(route).await {
            tracing::warn!(%interface_name, %route, %error, "failed to roll back VPN route");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use rustylink_api::VpnConnResponse;

    use super::{
        AddressFamily, VpnRouteMode, dns_host_routes, networks_from_vpn_conn, parse_network,
        system_route,
    };

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
    fn converts_network_to_system_route() {
        let route = system_route("10.0.0.0/8".parse().expect("static CIDR"), "utun7");

        assert_eq!(route.destination(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0)));
        assert_eq!(route.prefix(), 8);
        assert_eq!(route.if_name().map(String::as_str), Some("utun7"));
    }

    #[test]
    fn selects_only_full_routes_from_vpn_config() {
        let routes = networks_from_vpn_conn(&vpn_conn(), VpnRouteMode::Full, true).expect("routes");

        assert_eq!(
            routes,
            vec![
                "0.0.0.0/1".parse().expect("static CIDR"),
                "::/1".parse().expect("static CIDR"),
            ]
        );
    }

    #[test]
    fn selects_only_split_routes_from_vpn_config() {
        let routes =
            networks_from_vpn_conn(&vpn_conn(), VpnRouteMode::Split, true).expect("routes");

        assert_eq!(
            routes,
            vec![
                "10.0.0.0/8".parse().expect("static CIDR"),
                "fd00::/8".parse().expect("static CIDR"),
            ]
        );
    }

    #[test]
    fn omits_ipv6_routes_when_tunnel_has_no_v6_address() {
        let routes =
            networks_from_vpn_conn(&vpn_conn(), VpnRouteMode::Full, false).expect("routes");

        assert_eq!(routes, vec!["0.0.0.0/1".parse().expect("static CIDR")]);
    }

    #[test]
    fn builds_dns_host_routes_gated_by_ipv6() {
        let servers = [
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            "2001:4860:4860::8888".parse().expect("static IP"),
        ];

        assert_eq!(
            dns_host_routes(&servers, false),
            vec!["192.168.1.1/32".parse().expect("static CIDR")]
        );
        assert_eq!(
            dns_host_routes(&servers, true),
            vec![
                "192.168.1.1/32".parse().expect("static CIDR"),
                "2001:4860:4860::8888/128".parse().expect("static CIDR"),
            ]
        );
    }

    fn vpn_conn() -> VpnConnResponse {
        serde_json::from_value(serde_json::json!({
            "ip": "10.0.0.2",
            "public_key": "server",
            "setting": {
                "vpn_mtu": 1360,
                "vpn_route_full": ["0.0.0.0/1"],
                "vpn_route_split": ["10.0.0.0/8"],
                "v6_route_full": ["::/1"],
                "v6_route_split": ["fd00::/8"]
            }
        }))
        .expect("VPN conn response")
    }
}
