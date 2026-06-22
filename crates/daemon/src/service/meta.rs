//! `MetaService` — RPC handlers for daemon metadata, user info, and
//! configuration.
//!
//! Wraps [`Daemon`] and implements the generated `MetaService` trait.  These
//! are simple request/response handlers — no state machine interaction beyond
//! reading the current config or auth state for API calls.

use connectrpc::{RequestContext, Response, ServiceRequest, ServiceResult};
use rustylink_proto::proto::rustylink::daemon::{v1 as pb, v1::MetaService};

use crate::{
    daemon::{Daemon, project_user_info},
    error::{DaemonError, RpcFault},
};

/// Wrapper around [`Daemon`] implementing the `MetaService` trait.
#[derive(Clone)]
pub struct MetaServiceImpl {
    daemon: Daemon,
}

impl MetaServiceImpl {
    #[must_use]
    pub fn new(daemon: Daemon) -> Self {
        Self { daemon }
    }
}

#[allow(refining_impl_trait_reachable)]
impl MetaService for MetaServiceImpl {
    async fn ping(
        &self, _ctx: RequestContext, _request: ServiceRequest<'_, pb::PingRequest>,
    ) -> ServiceResult<pb::PingResponse> {
        Response::ok(pb::PingResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_seconds: self.daemon.uptime_seconds(),
            ..Default::default()
        })
    }

    async fn get_user_info(
        &self, _ctx: RequestContext, _request: ServiceRequest<'_, pb::GetUserInfoRequest>,
    ) -> ServiceResult<pb::GetUserInfoResponse> {
        self.daemon.require_authenticated().await?;
        let client = {
            let inner = self.daemon.inner.lock().await;
            inner
                .auth
                .build_tenant_client()
                .ok_or_else(|| DaemonError::from(RpcFault::NotAuthenticated))?
        };
        let resp = rustylink_core::vpn::user_info(&client)
            .await
            .map_err(DaemonError::from)?;
        Response::ok(pb::GetUserInfoResponse {
            user_info: project_user_info(resp.data).into(),
            ..Default::default()
        })
    }

    async fn get_configuration(
        &self, _ctx: RequestContext, _request: ServiceRequest<'_, pb::GetConfigurationRequest>,
    ) -> ServiceResult<pb::GetConfigurationResponse> {
        let configuration = {
            let inner = self.daemon.inner.lock().await;
            inner.config.to_configuration_proto()
        };
        Response::ok(pb::GetConfigurationResponse {
            configuration: configuration.into(),
            ..Default::default()
        })
    }

    async fn update_configuration(
        &self, _ctx: RequestContext, request: ServiceRequest<'_, pb::UpdateConfigurationRequest>,
    ) -> ServiceResult<pb::UpdateConfigurationResponse> {
        let owned = request.to_owned_message();
        let config = owned.configuration;

        // Extract outbound interface selector.
        let outbound_name =
            config
                .outbound_interface
                .selector
                .as_ref()
                .map(|selector| match selector {
                    pb::outbound_interface::Selector::Name(name) if !name.is_empty() => {
                        Some(name.clone())
                    }
                    _ => None,
                });

        // Extract dns interface selector.
        let dns_name = config
            .dns_interface
            .selector
            .as_ref()
            .map(|selector| match selector {
                pb::outbound_interface::Selector::Name(name) if !name.is_empty() => {
                    Some(name.clone())
                }
                _ => None,
            });

        {
            let mut inner = self.daemon.inner.lock().await;
            inner.config.auto_reconnect = config.auto_reconnect_on_start;
            if let Some(name) = outbound_name {
                inner.config.outbound_interface = name;
            }
            if let Some(name) = dns_name {
                inner.config.dns_interface = name;
            }
            // Only touch `tun_interface` when the field is present in the
            // (partial) update; an empty string clears it to the platform
            // default.
            if let Some(tun) = config.tun_interface.as_deref() {
                let tun = tun.trim();
                inner.config.tun_interface = (!tun.is_empty()).then(|| tun.to_owned());
            }
        }

        self.daemon.persist_config().await;

        let configuration = {
            let inner = self.daemon.inner.lock().await;
            inner.config.to_configuration_proto()
        };
        Response::ok(pb::UpdateConfigurationResponse {
            configuration: configuration.into(),
            ..Default::default()
        })
    }

    async fn list_network_interfaces(
        &self, _ctx: RequestContext, _request: ServiceRequest<'_, pb::ListNetworkInterfacesRequest>,
    ) -> ServiceResult<pb::ListNetworkInterfacesResponse> {
        let interfaces = default_net::get_interfaces();
        let default_iface = default_net::get_default_interface().ok();
        let auto_selected = default_iface
            .as_ref()
            .map(|iface| iface.name.clone())
            .unwrap_or_default();

        let proto_interfaces = interfaces
            .into_iter()
            .map(|iface| {
                let is_default = default_iface
                    .as_ref()
                    .is_some_and(|d| d.index == iface.index);
                let ipv4_addrs = iface.ipv4.iter().map(|net| net.addr.to_string()).collect();
                let ipv6_addrs = iface.ipv6.iter().map(|net| net.addr.to_string()).collect();
                pb::NetworkInterface {
                    name: iface.name,
                    index: iface.index,
                    is_up: iface.if_type != default_net::interface::InterfaceType::Unknown,
                    is_loopback: iface.if_type == default_net::interface::InterfaceType::Loopback,
                    has_gateway: iface.gateway.is_some(),
                    is_default,
                    ipv4_addrs,
                    ipv6_addrs,
                    ..Default::default()
                }
            })
            .collect();

        Response::ok(pb::ListNetworkInterfacesResponse {
            interfaces: proto_interfaces,
            auto_selected,
            ..Default::default()
        })
    }
}
