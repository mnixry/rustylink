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

use rustylink_outbound::{NetworkSnapshot, pinned_present};
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
    /// `was_healthy` is true if the session received at least one liveness-
    /// probe reply before this trigger fired.
    Trigger {
        event: ReconnectEvent,
        was_healthy: bool,
    },
    /// The server forced a logout via a `/vpn/report` response.
    ServerKickOut { was_healthy: bool },
    /// Disconnect was requested (cancellation).
    Cancelled,
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

    let last_net = match NetworkSnapshot::capture().await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(%e, "initial network snapshot failed");
            NetworkSnapshot::default()
        }
    };
    let started = Instant::now();

    loop {
        tokio::select! {
            () = cancel.cancelled() => return SupervisorOutcome::Cancelled,

            () = session.wait() => {
                let was_healthy = session.last_probe_rx_elapsed().is_some();
                tracing::warn!("tunnel transport failed (device stopped)");
                return SupervisorOutcome::Trigger {
                    event: ReconnectEvent::TransportFailed,
                    was_healthy,
                };
            }

            _ = liveness_tick.tick() => {
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
                    let was_healthy = probe_age.is_some();
                    tracing::warn!(
                        ?status,
                        probe_age_secs = probe_age.map(|d| d.as_secs()),
                        session_age_secs = started.elapsed().as_secs(),
                        "tunnel liveness probe stalled"
                    );
                    return SupervisorOutcome::Trigger {
                        event: ReconnectEvent::HandshakeTimeout,
                        was_healthy,
                    };
                }
            }

            _ = network_tick.tick() => {
                let was_healthy = session.last_probe_rx_elapsed().is_some();
                if let Some(name) = &outbound {
                    if !pinned_present(name).await.unwrap_or(false) {
                        tracing::warn!(interface = %name, "pinned outbound interface lost");
                        return SupervisorOutcome::Trigger {
                            event: ReconnectEvent::NetworkChanged,
                            was_healthy,
                        };
                    }
                } else {
                    let now = match NetworkSnapshot::capture().await {
                        Ok(s) => s,
                        Err(e) => {
                            tracing::warn!(%e, "network snapshot failed");
                            continue;
                        }
                    };
                    if now != last_net {
                        tracing::info!(?last_net, ?now, "default network changed");
                        return SupervisorOutcome::Trigger {
                            event: ReconnectEvent::NetworkChanged,
                            was_healthy,
                        };
                    }
                }
            }

            _ = report_tick.tick() => {
                if report().await {
                    let was_healthy = session.last_probe_rx_elapsed().is_some();
                    tracing::warn!("server kickout detected from /vpn/report");
                    return SupervisorOutcome::ServerKickOut { was_healthy };
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
        assert_eq!(
            liveness_status(None, CONNECT_TIMEOUT.saturating_sub(Duration::from_secs(1))),
            LivenessStatus::Healthy
        );
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
