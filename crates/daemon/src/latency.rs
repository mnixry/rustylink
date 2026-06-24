//! Latency probing for dot (access-point) selection.
//!
//! Each dot's API server exposes `GET /vpn/ping`, so timing that request
//! against the dot's API host gives the application-level round-trip latency to
//! the tenant server. The probe reuses the shared API client (cookies, request
//! signing and the tenant `vpn_domain` TLS host), so it measures the same path
//! the dot config call will take.

use std::time::{Duration, Instant};

use rustylink_api::{ApiClient, VpnDot};

/// Default timeout for a single probe attempt.
pub const DEFAULT_PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Probe latency to a dot by timing a `GET /vpn/ping` against its API server.
///
/// Returns `Some(rtt)` on a successful reply within `timeout`, or `None` if the
/// request fails or times out.
pub async fn probe_latency(client: &ApiClient, timeout: Duration) -> Option<Duration> {
    let start = Instant::now();
    match tokio::time::timeout(timeout, rustylink_core::vpn::vpn_ping(client)).await {
        Ok(Ok(())) => Some(start.elapsed()),
        Ok(Err(error)) => {
            tracing::debug!(%error, "vpn ping probe failed");
            None
        }
        Err(_) => {
            tracing::debug!("vpn ping probe timed out");
            None
        }
    }
}

/// Rank dots by measured latency, best (lowest RTT) first.
///
/// All dots are probed concurrently; `build_client` yields the per-dot API
/// client (or `None` when its endpoint can't be built). Reachable dots are
/// ordered ahead of unreachable ones; ties and unreachable dots keep their
/// original order.
#[must_use = "the returned, latency-ordered list is the selection result"]
pub async fn rank_dots_by_latency(
    dots: Vec<VpnDot>, build_client: impl Fn(&VpnDot) -> Option<ApiClient>,
) -> Vec<VpnDot> {
    if dots.len() <= 1 {
        return dots;
    }

    let mut join_set = tokio::task::JoinSet::new();
    for (index, dot) in dots.iter().enumerate() {
        let Some(client) = build_client(dot) else {
            continue;
        };
        join_set.spawn(async move { (index, probe_latency(&client, DEFAULT_PROBE_TIMEOUT).await) });
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
