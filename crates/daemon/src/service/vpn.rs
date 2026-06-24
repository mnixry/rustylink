//! `VpnService` — RPC handlers for VPN tunnel operations.
//!
//! Wraps [`Daemon`] and implements the generated `VpnService` trait.  Tunnel
//! connect/disconnect is delegated to `Daemon::connect_tunnel` /
//! `Daemon::disconnect_tunnel`; the RPC handlers add proto framing.

use std::time::Duration;

use connectrpc::{RequestContext, Response, ServiceRequest, ServiceResult, ServiceStream};
use rustylink_api::{GetVpnLocationsRequest, GetVpnSettingRequest, SendableRequest};
use rustylink_proto::proto::rustylink::daemon::{v1 as pb, v1::VpnService};
use tokio_stream::{StreamExt as _, wrappers::WatchStream};

use crate::{
    daemon::{Daemon, build_dot_api_client, project_vpn_location},
    error::{DaemonError, RpcFault},
    latency,
    state::{VpnMachine, vpn_request_from_proto},
};

/// Wrapper around [`Daemon`] implementing the `VpnService` trait.
#[derive(Clone)]
pub struct VpnServiceImpl {
    daemon: Daemon,
}

impl VpnServiceImpl {
    #[must_use]
    pub fn new(daemon: Daemon) -> Self {
        Self { daemon }
    }
}

#[allow(refining_impl_trait_reachable)]
impl VpnService for VpnServiceImpl {
    async fn get_tunnel(
        &self, _ctx: RequestContext, _request: ServiceRequest<'_, pb::GetTunnelRequest>,
    ) -> ServiceResult<pb::GetTunnelResponse> {
        let tunnel = {
            let inner = self.daemon.inner.lock().await;
            inner
                .vpn
                .as_ref()
                .map_or_else(pb::Tunnel::default, VpnMachine::to_tunnel_proto)
        };
        Response::ok(pb::GetTunnelResponse {
            tunnel: tunnel.into(),
            ..Default::default()
        })
    }

    async fn connect_tunnel(
        &self, _ctx: RequestContext, request: ServiceRequest<'_, pb::ConnectTunnelRequest>,
    ) -> ServiceResult<pb::ConnectTunnelResponse> {
        let vpn_request = vpn_request_from_proto(
            request.mode.as_known(),
            request.protocol_mode.as_known(),
            request.export_id,
            request.preferred_dot_id,
            request.otp,
            request.reconnect,
        );
        let tunnel = self.daemon.connect_tunnel(vpn_request).await?;
        Response::ok(pb::ConnectTunnelResponse {
            tunnel: tunnel.into(),
            ..Default::default()
        })
    }

    async fn disconnect_tunnel(
        &self, _ctx: RequestContext, _request: ServiceRequest<'_, pb::DisconnectTunnelRequest>,
    ) -> ServiceResult<pb::DisconnectTunnelResponse> {
        let tunnel = self.daemon.disconnect_tunnel().await?;
        Response::ok(pb::DisconnectTunnelResponse {
            tunnel: tunnel.into(),
            ..Default::default()
        })
    }

    async fn list_vpn_locations(
        &self, _ctx: RequestContext, _request: ServiceRequest<'_, pb::ListVpnLocationsRequest>,
    ) -> ServiceResult<pb::ListVpnLocationsResponse> {
        self.daemon.require_authenticated().await?;
        let client = {
            let inner = self.daemon.inner.lock().await;
            inner
                .auth
                .build_tenant_client()
                .ok_or_else(|| DaemonError::from(RpcFault::NotAuthenticated))?
        };
        let resp = GetVpnLocationsRequest.send(&client).await.map_err(|e| {
            DaemonError::from(rustylink_core::vpn::Error::Api {
                source: Box::new(e),
            })
        })?;
        let locations = resp
            .data
            .unwrap_or_default()
            .into_iter()
            .map(project_vpn_location)
            .collect();
        Response::ok(pb::ListVpnLocationsResponse {
            locations,
            ..Default::default()
        })
    }

    async fn probe_dot_latency(
        &self, _ctx: RequestContext, _request: ServiceRequest<'_, pb::ProbeDotLatencyRequest>,
    ) -> ServiceResult<pb::ProbeDotLatencyResponse> {
        self.daemon.require_authenticated().await?;
        let client = {
            let inner = self.daemon.inner.lock().await;
            inner
                .auth
                .build_tenant_client()
                .ok_or_else(|| DaemonError::from(RpcFault::NotAuthenticated))?
        };
        let resp = GetVpnLocationsRequest.send(&client).await.map_err(|e| {
            DaemonError::from(rustylink_core::vpn::Error::Api {
                source: Box::new(e),
            })
        })?;
        let dots = resp.data.unwrap_or_default();

        // Reach each dot's API host with the tenant TLS name (matching the dot
        // config call) and time `GET /vpn/ping` to measure latency.
        let vpn_domain = GetVpnSettingRequest
            .send(&client)
            .await
            .ok()
            .and_then(|resp| resp.data)
            .and_then(|setting| setting.vpn_domain)
            .filter(|domain| !domain.trim().is_empty());
        let (pool, hooks, outbound_interface) = {
            let inner = self.daemon.inner.lock().await;
            (
                inner.auth.http_pool.clone(),
                inner.auth.build_hooks(),
                inner.config.outbound_interface.clone(),
            )
        };

        // Probe each dot in parallel using a JoinSet.
        let mut join_set = tokio::task::JoinSet::new();
        for dot in &dots {
            let dot_id = dot.id.unwrap_or_default();
            let dot_name = dot.name.clone().unwrap_or_default();
            let client = match rustylink_api::DotEndpoint::from_dot(dot, false).ok() {
                Some(endpoint) => Some(
                    build_dot_api_client(
                        &endpoint,
                        &pool,
                        &hooks,
                        vpn_domain.as_deref(),
                        outbound_interface.as_deref(),
                    )
                    .await,
                ),
                None => None,
            };
            join_set.spawn(async move {
                let rtt = match client {
                    Some(client) => {
                        latency::probe_latency(&client, latency::DEFAULT_PROBE_TIMEOUT).await
                    }
                    None => None,
                };
                pb::DotLatency {
                    dot_id,
                    dot_name,
                    latency_ms: duration_ms(rtt, 0),
                    reachable: rtt.is_some(),
                    ..Default::default()
                }
            });
        }

        let mut results = Vec::with_capacity(dots.len());
        while let Some(Ok(result)) = join_set.join_next().await {
            results.push(result);
        }
        // Sort by latency: reachable first (ascending), unreachable last.
        results.sort_by(|a, b| match (a.reachable, b.reachable) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => a.latency_ms.cmp(&b.latency_ms),
        });

        Response::ok(pb::ProbeDotLatencyResponse {
            results,
            ..Default::default()
        })
    }

    async fn watch_tunnel(
        &self, _ctx: RequestContext, _request: ServiceRequest<'_, pb::WatchTunnelRequest>,
    ) -> ServiceResult<ServiceStream<pb::WatchTunnelResponse>> {
        let stream = WatchStream::new(self.daemon.subscribe_tunnel()).map(|tunnel| {
            Ok(pb::WatchTunnelResponse {
                tunnel: tunnel.into(),
                ..Default::default()
            })
        });
        Response::stream_ok(stream)
    }
}

// ---------------------------------------------------------------------------
// Proto → domain conversion
// ---------------------------------------------------------------------------

/// Convert an optional probe duration to whole milliseconds for the wire,
/// using `fallback` when absent (`0` for the effective latency, `-1` for a
/// component probe that got no response).
fn duration_ms(value: Option<Duration>, fallback: i32) -> i32 {
    value.map_or(fallback, |d| {
        i32::try_from(d.as_millis()).unwrap_or(i32::MAX)
    })
}
