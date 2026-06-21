//! Latency probing for dot (access-point) selection.
//!
//! Each dot's API server already exposes an HTTP endpoint (`/vpn/ping`), so a
//! plain TCP connect to that host:port gives us the round-trip latency to the
//! tenant server directly — no separate ICMP or `WireGuard` ping mechanism is
//! needed.
//!
//! **The probe is routed through the picked outbound interface** (the same
//! configured-or-default interface the tunnel binds to), via
//! [`rustylink_tunnel::outbound::connect_tcp`]. Measuring through any other
//! path would not reflect the latency the tunnel will actually experience.

use std::{
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

use rustylink_api::VpnDot;
use rustylink_tunnel::{OutboundInterface, outbound::connect_tcp};

/// Default timeout for a single probe attempt.
pub const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Default API port when the dot does not advertise one.
pub const DEFAULT_API_PORT: u16 = 443;

/// Probe latency to a dot's API server by timing a TCP connect, bound to the
/// given outbound interface.
///
/// Returns `Some(rtt)` on a successful connect within `timeout`, or `None` if
/// the host cannot be resolved or the connect fails/times out.
pub async fn probe_latency(
    host: &str, port: u16, outbound: Option<&OutboundInterface>, timeout: Duration,
) -> Option<Duration> {
    let destination = resolve_addr(host, port).await?;
    let start = Instant::now();
    connect_tcp(destination, outbound, timeout)
        .await
        .ok()
        .map(|_stream| start.elapsed())
}

/// Rank dots by measured latency, best (lowest RTT) first.
///
/// All dots are probed concurrently through `outbound`. Reachable dots are
/// ordered ahead of unreachable ones; ties and unreachable dots keep their
/// original order. This mirrors the "auto" outbound-interface behaviour: when
/// the caller has not pinned a specific node, pick the one that responds
/// fastest over the egress path the tunnel will use.
#[must_use = "the returned, latency-ordered list is the selection result"]
pub async fn rank_dots_by_latency(
    dots: Vec<VpnDot>, outbound: Option<OutboundInterface>,
) -> Vec<VpnDot> {
    if dots.len() <= 1 {
        return dots;
    }

    let mut join_set = tokio::task::JoinSet::new();
    for (index, dot) in dots.iter().enumerate() {
        let host = dot.api_host().map(ToOwned::to_owned);
        let port = dot
            .api_port
            .and_then(|p| u16::try_from(p).ok())
            .unwrap_or(DEFAULT_API_PORT);
        let outbound = outbound.clone();
        join_set.spawn(async move {
            let rtt = match host {
                Some(host) => {
                    probe_latency(&host, port, outbound.as_ref(), DEFAULT_PROBE_TIMEOUT).await
                }
                None => None,
            };
            (index, rtt)
        });
    }

    let mut latencies: Vec<Option<Duration>> = vec![None; dots.len()];
    while let Some(Ok((index, rtt))) = join_set.join_next().await {
        if let Some(slot) = latencies.get_mut(index) {
            *slot = rtt;
        }
    }

    let mut indexed: Vec<(usize, VpnDot)> = dots.into_iter().enumerate().collect();
    indexed.sort_by(|(a, _), (b, _)| cmp_latency(latencies[*a], latencies[*b]).then(a.cmp(b)));
    indexed.into_iter().map(|(_, dot)| dot).collect()
}

/// Order two probe results: reachable (`Some`) before unreachable (`None`),
/// then ascending round-trip time.
pub fn cmp_latency(a: Option<Duration>, b: Option<Duration>) -> std::cmp::Ordering {
    match (a, b) {
        (Some(a), Some(b)) => a.cmp(&b),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => std::cmp::Ordering::Equal,
    }
}

/// Resolve `host:port` (an IP literal or DNS name) to a single [`SocketAddr`].
async fn resolve_addr(host: &str, port: u16) -> Option<SocketAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(SocketAddr::new(ip, port));
    }
    tokio::net::lookup_host((host, port)).await.ok()?.next()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmp_latency_orders_reachable_first_then_ascending() {
        let mut probes = vec![
            None,
            Some(Duration::from_millis(50)),
            Some(Duration::from_millis(10)),
        ];
        probes.sort_by(|a, b| cmp_latency(*a, *b));
        assert_eq!(
            probes,
            vec![
                Some(Duration::from_millis(10)),
                Some(Duration::from_millis(50)),
                None,
            ]
        );
    }
}
