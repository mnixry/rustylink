//! Tunnel supervisor: a single `tokio::select!` loop that watches a running
//! tunnel for reconnect triggers (S1), spawned on connect and cancelled on
//! disconnect (S2).
//!
//! Triggers detected here (per D9):
//!   - `TransportFailed`   — `TunnelSession::wait()` resolves (device error)
//!   - `HandshakeTimeout`  — liveness probe stops getting replies (initial
//!     connect window: no probe reply within [`CONNECT_TIMEOUT`]; steady-state:
//!     gap between replies exceeds [`LIVENESS_TIMEOUT`])
//!   - `NetworkChanged`    — default route / pinned interface changes (S3)
//!   - `ServerKickOut`     — periodic `/vpn/report` returns force-logout
//!
//! `IdleTimeout` is deferred (not reverse-engineered).
//!
//! gotatun is lazy: `WireGuard` performs the initial handshake only when an
//! outbound TUN packet asks for the first transport (there is no force-
//! handshake API). The `LivenessProbe` owned by the session sends a constant
//! routed DNS query every ~3 s, which both triggers the initial handshake and
//! provides the steady-state liveness signal we read here.

use std::time::Duration;

use rustylink_tunnel::{ReconnectEvent, TunnelSession};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

/// How often to inspect probe + network + report state.
const LIVENESS_POLL: Duration = Duration::from_secs(3);
const NETWORK_POLL: Duration = Duration::from_secs(5);
const REPORT_INTERVAL: Duration = Duration::from_mins(1);

/// Maximum time we wait for the first liveness-probe reply after connect.
/// Exceeding it without any reply is treated as `HandshakeTimeout`.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

/// Maximum gap between successive liveness-probe replies on a healthy tunnel.
/// Exceeding it is treated as `HandshakeTimeout` (likely peer death, network
/// stall, or roaming).
const LIVENESS_TIMEOUT: Duration = Duration::from_secs(30);

/// The reason a supervised tunnel stopped.
#[derive(Clone, Debug)]
pub enum SupervisorOutcome {
    /// A reconnect trigger fired; the actor should run the reconnect policy.
    Trigger(ReconnectEvent),
    /// The server forced a logout via a `/vpn/report` response.
    ServerKickOut,
    /// Disconnect was requested (cancellation).
    Cancelled,
}

/// Network-state snapshot used to detect changes.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct NetSnapshot {
    default_iface: Option<String>,
}

fn current_net() -> NetSnapshot {
    NetSnapshot {
        default_iface: default_net::get_default_interface().ok().map(|i| i.name),
    }
}

/// Returns true if the pinned interface is present in the system interface
/// list.
fn interface_present(name: &str) -> bool {
    default_net::get_interfaces().iter().any(|i| i.name == name)
}

/// Liveness verdict from the probe state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LivenessStatus {
    /// At least one probe reply within bounds.
    Healthy,
    /// No probe reply yet and the initial-connect window expired.
    ConnectTimeout,
    /// Probe replied at least once, but the gap to the last reply exceeded
    /// [`LIVENESS_TIMEOUT`].
    Stalled,
}

fn liveness_status(probe_age: Option<Duration>, session_age: Duration) -> LivenessStatus {
    match probe_age {
        None if session_age > CONNECT_TIMEOUT => LivenessStatus::ConnectTimeout,
        Some(age) if age > LIVENESS_TIMEOUT => LivenessStatus::Stalled,
        _ => LivenessStatus::Healthy,
    }
}

/// Run the supervisor loop until a trigger fires or disconnect is requested.
///
/// `report` is invoked on the report interval; it returns `Ok(true)` if the
/// server signalled a force-logout/kickout.
pub async fn run<F, Fut>(
    session: &mut TunnelSession, outbound: Option<String>, cancel: CancellationToken, mut report: F,
) -> SupervisorOutcome
where
    F: FnMut() -> Fut + Send,
    Fut: std::future::Future<Output = bool> + Send, {
    let mut liveness_tick = tokio::time::interval(LIVENESS_POLL);
    let mut network_tick = tokio::time::interval(NETWORK_POLL);
    let mut report_tick = tokio::time::interval(REPORT_INTERVAL);
    // Skip the immediate first tick on the report timer.
    report_tick.tick().await;

    let last_net = current_net();
    let started = Instant::now();

    loop {
        tokio::select! {
            () = cancel.cancelled() => return SupervisorOutcome::Cancelled,

            () = session.wait() => {
                tracing::warn!("tunnel transport failed (device stopped)");
                return SupervisorOutcome::Trigger(ReconnectEvent::TransportFailed);
            }

            _ = liveness_tick.tick() => {
                // Per-peer tx/rx + handshake age are debug-only diagnostic
                // signals now: the supervisor's verdict comes from the routed
                // probe, not the `WireGuard` handshake age (the Android client
                // does the same — see `mLastRxBytes`/`mIdleCount`).
                for peer in session.peer_stats().await {
                    tracing::debug!(
                        tx_bytes = peer.stats.tx_bytes,
                        rx_bytes = peer.stats.rx_bytes,
                        last_handshake_secs = peer.stats.last_handshake.map(|age| age.as_secs()),
                        session_age_secs = started.elapsed().as_secs(),
                        "tunnel peer stats"
                    );
                }
                let probe_age = session.last_probe_rx_elapsed();
                let status = liveness_status(probe_age, started.elapsed());
                if status != LivenessStatus::Healthy {
                    tracing::warn!(
                        ?status,
                        probe_age_secs = probe_age.map(|d| d.as_secs()),
                        session_age_secs = started.elapsed().as_secs(),
                        "tunnel liveness probe stalled"
                    );
                    return SupervisorOutcome::Trigger(ReconnectEvent::HandshakeTimeout);
                }
            }

            _ = network_tick.tick() => {
                if let Some(name) = &outbound {
                    if !interface_present(name) {
                        tracing::warn!(interface = %name, "pinned outbound interface lost");
                        return SupervisorOutcome::Trigger(ReconnectEvent::NetworkChanged);
                    }
                } else {
                    let now = current_net();
                    if now != last_net {
                        tracing::info!(?last_net, ?now, "default network changed");
                        return SupervisorOutcome::Trigger(ReconnectEvent::NetworkChanged);
                    }
                }
            }

            _ = report_tick.tick() => {
                if report().await {
                    tracing::warn!("server kickout detected from /vpn/report");
                    return SupervisorOutcome::ServerKickOut;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{CONNECT_TIMEOUT, LIVENESS_TIMEOUT, LivenessStatus, liveness_status};

    #[test]
    fn initial_connect_window_tolerates_silence_then_fails() {
        // Before the connect timeout, silence is acceptable (handshake still
        // pending lazy-trigger via the first probe).
        assert_eq!(
            liveness_status(None, CONNECT_TIMEOUT.saturating_sub(Duration::from_secs(1))),
            LivenessStatus::Healthy
        );
        // Past the connect timeout, silence is a hard failure.
        assert_eq!(
            liveness_status(None, CONNECT_TIMEOUT + Duration::from_secs(1)),
            LivenessStatus::ConnectTimeout
        );
    }

    #[test]
    fn steady_state_stalls_when_probe_gap_exceeds_threshold() {
        let healthy = LIVENESS_TIMEOUT.saturating_sub(Duration::from_secs(1));
        let stalled = LIVENESS_TIMEOUT + Duration::from_secs(1);
        assert_eq!(
            liveness_status(Some(healthy), Duration::from_mins(2)),
            LivenessStatus::Healthy
        );
        assert_eq!(
            liveness_status(Some(stalled), Duration::from_mins(2)),
            LivenessStatus::Stalled
        );
    }
}
