//! `VpnService` — RPC handlers for VPN tunnel operations.
//!
//! Wraps [`Daemon`] and implements the generated `VpnService` trait.  Tunnel
//! connect/disconnect is delegated to `Daemon::connect_tunnel` /
//! `Daemon::disconnect_tunnel`; the RPC handlers add proto framing.

use connectrpc::{RequestContext, Response, ServiceRequest, ServiceResult, ServiceStream};
use rustylink_core::vpn::VpnConnectMode;
use rustylink_proto::proto::rustylink::daemon::{v1 as pb, v1::VpnService};
use tokio_stream::{StreamExt as _, wrappers::WatchStream};

use crate::{
    daemon::{Daemon, project_vpn_location},
    error::{DaemonError, RpcFault},
    latency,
    state::{AuthEvent, VpnMachine, VpnRequest},
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
        let vpn_request = vpn_request_from_proto(&request);
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
        let (resp, meta) = rustylink_core::vpn::vpn_locations(&client)
            .await
            .map_err(DaemonError::from)?;
        {
            let mut inner = self.daemon.inner.lock().await;
            let event = AuthEvent::MergeResponseMeta {
                cookies: meta
                    .cookies
                    .as_ref()
                    .map(|c| c.values.clone())
                    .unwrap_or_default(),
                csrf_token: meta.csrf_token.clone(),
            };
            inner.auth.handle(&event).await;
            drop(inner);
        }
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
        let (resp, meta) = rustylink_core::vpn::vpn_locations(&client)
            .await
            .map_err(DaemonError::from)?;
        {
            let mut inner = self.daemon.inner.lock().await;
            let event = AuthEvent::MergeResponseMeta {
                cookies: meta
                    .cookies
                    .as_ref()
                    .map(|c| c.values.clone())
                    .unwrap_or_default(),
                csrf_token: meta.csrf_token.clone(),
            };
            inner.auth.handle(&event).await;
            drop(inner);
        }
        let dots = resp.data.unwrap_or_default();

        // Probe each dot in parallel using a JoinSet.
        let mut join_set = tokio::task::JoinSet::new();
        for dot in &dots {
            let dot_id = dot.id.unwrap_or_default();
            let dot_name = dot.name.clone().unwrap_or_default();
            let host = dot.api_host().unwrap_or_default().to_owned();
            let port = dot
                .api_port
                .and_then(|p| u16::try_from(p).ok())
                .unwrap_or(latency::DEFAULT_API_PORT);
            join_set.spawn(async move {
                let rtt =
                    latency::probe_tcp_latency(&host, port, latency::DEFAULT_PROBE_TIMEOUT).await;
                pb::DotLatency {
                    dot_id,
                    dot_name,
                    latency_ms: rtt.map_or(0, |d| i32::try_from(d.as_millis()).unwrap_or(i32::MAX)),
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

fn vpn_request_from_proto(request: &ServiceRequest<'_, pb::ConnectTunnelRequest>) -> VpnRequest {
    let mode = match request.mode.as_known() {
        Some(pb::VpnMode::Split) => VpnConnectMode::Split,
        Some(pb::VpnMode::Relay) => VpnConnectMode::Relay,
        _ => VpnConnectMode::Full,
    };
    let otp = request.otp.filter(|s| !s.is_empty()).map(ToOwned::to_owned);
    VpnRequest {
        mode,
        export_id: request.export_id,
        preferred_dot_id: request.preferred_dot_id,
        otp,
        reconnect: request.reconnect,
    }
}
