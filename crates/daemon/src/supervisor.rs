//! Tunnel supervisor: a single `tokio::select!` loop that watches a running
//! tunnel for reconnect triggers (S1), spawned on connect and cancelled on
//! disconnect (S2).
//!
//! Triggers detected here (per D9):
//!   - `TransportFailed`  — `TunnelSession::wait()` resolves (device error)
//!   - `HandshakeTimeout` — WG last-handshake age exceeds a protocol threshold
//!   - `NetworkChanged`   — default route / pinned interface changes (S3)
//!   - `ServerKickOut`    — periodic `/vpn/report` returns force-logout
//!
//! `IdleTimeout` is deferred (not reverse-engineered).

use std::time::Duration;

use rustylink_tunnel::{ReconnectEvent, TunnelSession};
use tokio_util::sync::CancellationToken;

/// How often to poll the WG handshake age and the network state.
const HANDSHAKE_POLL: Duration = Duration::from_secs(3);
const NETWORK_POLL: Duration = Duration::from_secs(5);
const REPORT_INTERVAL: Duration = Duration::from_mins(1);

/// Handshake-age thresholds by protocol mode (UDP / TCP / dual), in seconds.
const HANDSHAKE_TIMEOUT_UDP: u64 = 15;
const HANDSHAKE_TIMEOUT_TCP: u64 = 9;
const HANDSHAKE_TIMEOUT_DUAL: u64 = 6;

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

fn handshake_threshold(protocol_mode: Option<i32>) -> Duration {
    let secs = match protocol_mode {
        Some(1) => HANDSHAKE_TIMEOUT_TCP,
        Some(2) => HANDSHAKE_TIMEOUT_DUAL,
        _ => HANDSHAKE_TIMEOUT_UDP,
    };
    Duration::from_secs(secs)
}

/// Run the supervisor loop until a trigger fires or disconnect is requested.
///
/// `report` is invoked on the report interval; it returns `Ok(true)` if the
/// server signalled a force-logout/kickout.
pub async fn run<F, Fut>(
    session: &mut TunnelSession, protocol_mode: Option<i32>, outbound: Option<String>,
    cancel: CancellationToken, mut report: F,
) -> SupervisorOutcome
where
    F: FnMut() -> Fut + Send,
    Fut: std::future::Future<Output = bool> + Send, {
    let mut handshake_tick = tokio::time::interval(HANDSHAKE_POLL);
    let mut network_tick = tokio::time::interval(NETWORK_POLL);
    let mut report_tick = tokio::time::interval(REPORT_INTERVAL);
    // Skip the immediate first tick on the report timer.
    report_tick.tick().await;

    let threshold = handshake_threshold(protocol_mode);
    let last_net = current_net();

    loop {
        tokio::select! {
            () = cancel.cancelled() => return SupervisorOutcome::Cancelled,

            () = session.wait() => {
                tracing::warn!("tunnel transport failed (device stopped)");
                return SupervisorOutcome::Trigger(ReconnectEvent::TransportFailed);
            }

            _ = handshake_tick.tick() => {
                if let Some(age) = session.last_handshake().await
                    && age > threshold
                {
                    tracing::warn!(age_secs = age.as_secs(), "handshake timeout");
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
