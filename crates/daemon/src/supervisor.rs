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

use rustylink_api::VpnProtocolDetectConfig;
use rustylink_tunnel::{ProtocolMode, ReconnectEvent, TunnelSession};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

/// How often to poll the WG handshake age and the network state.
const HANDSHAKE_POLL: Duration = Duration::from_secs(3);
const NETWORK_POLL: Duration = Duration::from_secs(5);
const REPORT_INTERVAL: Duration = Duration::from_mins(1);

/// Handshake-age thresholds by protocol mode (UDP / TCP / dual), in seconds.
const HANDSHAKE_TIMEOUT_UDP: u64 = 15;
const HANDSHAKE_TIMEOUT_TCP: u64 = 9;
const HANDSHAKE_TIMEOUT_DUAL: u64 = 6;
const TCP_TO_UDP_AVOID_AFTER_UDP_TO_TCP: Duration = Duration::from_hours(1);

/// The reason a supervised tunnel stopped.
#[derive(Clone, Debug)]
pub enum SupervisorOutcome {
    /// A reconnect trigger fired; the actor should run the reconnect policy.
    Trigger(ReconnectEvent),
    /// The server forced a logout via a `/vpn/report` response.
    ServerKickOut,
    /// Protocol detection selected the other transport for a dual-capable dot.
    ProtocolSwitch(ProtocolMode),
    /// Disconnect was requested (cancellation).
    Cancelled,
}

#[derive(Clone, Debug, Default)]
pub struct ProtocolDetectOptions {
    pub config: Option<VpnProtocolDetectConfig>,
    pub dot_protocol_mode: Option<ProtocolMode>,
    pub last_udp_to_tcp: Option<Instant>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProtocolDetectAction {
    Continue,
    HandshakeTimeout,
    Switch(ProtocolMode),
}

#[derive(Clone, Debug)]
struct ProtocolDetectState {
    udp2tcp_timeout_count: Option<u32>,
    tcp2udp_available_count: Option<u32>,
    refresh_timeout_count: Option<u32>,
    bad_network_count: Option<u32>,
    udp_timeout_count: u32,
    tcp_timeout_count: u32,
    tcp_available_count: u32,
    bad_network_samples: u32,
    last_udp_to_tcp: Option<Instant>,
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

fn handshake_threshold(protocol_mode: Option<ProtocolMode>) -> Duration {
    let secs = match protocol_mode {
        Some(ProtocolMode::FeilianTcp) => HANDSHAKE_TIMEOUT_TCP,
        Some(ProtocolMode::Dual) => HANDSHAKE_TIMEOUT_DUAL,
        Some(ProtocolMode::Udp) | None => HANDSHAKE_TIMEOUT_UDP,
    };
    Duration::from_secs(secs)
}

impl ProtocolDetectState {
    fn new(options: ProtocolDetectOptions) -> Option<Self> {
        let config = options.config?;
        if config.enable != Some(true) || options.dot_protocol_mode != Some(ProtocolMode::Dual) {
            return None;
        }
        let positive_count =
            |value: Option<i32>| u32::try_from(value?).ok().filter(|value| *value > 0);
        Some(Self {
            udp2tcp_timeout_count: positive_count(config.udp2tcp_timeout_count),
            tcp2udp_available_count: positive_count(config.tcp2udp_available_count),
            refresh_timeout_count: positive_count(config.refresh_timeout_count),
            bad_network_count: positive_count(config.bad_network_count),
            udp_timeout_count: 0,
            tcp_timeout_count: 0,
            tcp_available_count: 0,
            bad_network_samples: 0,
            last_udp_to_tcp: options.last_udp_to_tcp,
        })
    }

    fn record_timeout(&mut self, protocol_mode: Option<ProtocolMode>) -> ProtocolDetectAction {
        self.tcp_available_count = 0;
        match protocol_mode {
            Some(ProtocolMode::FeilianTcp) => {
                self.tcp_timeout_count = self.tcp_timeout_count.saturating_add(1);
                if self
                    .refresh_timeout_count
                    .is_some_and(|threshold| self.tcp_timeout_count >= threshold)
                {
                    ProtocolDetectAction::HandshakeTimeout
                } else if self.refresh_timeout_count.is_some() {
                    tracing::warn!(
                        timeout_count = self.tcp_timeout_count,
                        threshold = ?self.refresh_timeout_count,
                        "TCP protocol-detect timeout below refresh threshold"
                    );
                    ProtocolDetectAction::Continue
                } else {
                    ProtocolDetectAction::HandshakeTimeout
                }
            }
            Some(ProtocolMode::Udp | ProtocolMode::Dual) | None => {
                self.udp_timeout_count = self.udp_timeout_count.saturating_add(1);
                self.bad_network_samples = self.bad_network_samples.saturating_add(1);
                if self
                    .udp2tcp_timeout_count
                    .is_some_and(|threshold| self.udp_timeout_count >= threshold)
                {
                    tracing::warn!(
                        timeout_count = self.udp_timeout_count,
                        threshold = ?self.udp2tcp_timeout_count,
                        "UDP protocol-detect threshold reached; switching to TCP"
                    );
                    ProtocolDetectAction::Switch(ProtocolMode::FeilianTcp)
                } else if self
                    .bad_network_count
                    .is_some_and(|threshold| self.bad_network_samples >= threshold)
                {
                    ProtocolDetectAction::HandshakeTimeout
                } else if self.udp2tcp_timeout_count.is_some() || self.bad_network_count.is_some() {
                    tracing::warn!(
                        timeout_count = self.udp_timeout_count,
                        udp2tcp_threshold = ?self.udp2tcp_timeout_count,
                        bad_network_samples = self.bad_network_samples,
                        bad_network_threshold = ?self.bad_network_count,
                        "UDP protocol-detect timeout below switch threshold"
                    );
                    ProtocolDetectAction::Continue
                } else {
                    ProtocolDetectAction::HandshakeTimeout
                }
            }
        }
    }

    fn record_success(&mut self, protocol_mode: Option<ProtocolMode>) -> ProtocolDetectAction {
        self.udp_timeout_count = 0;
        self.tcp_timeout_count = 0;
        self.bad_network_samples = 0;
        if protocol_mode != Some(ProtocolMode::FeilianTcp) {
            self.tcp_available_count = 0;
            return ProtocolDetectAction::Continue;
        }

        self.tcp_available_count = self.tcp_available_count.saturating_add(1);
        let Some(threshold) = self.tcp2udp_available_count else {
            return ProtocolDetectAction::Continue;
        };
        if self.tcp_available_count < threshold {
            return ProtocolDetectAction::Continue;
        }
        if self
            .last_udp_to_tcp
            .is_some_and(|instant| instant.elapsed() < TCP_TO_UDP_AVOID_AFTER_UDP_TO_TCP)
        {
            tracing::debug!(
                available_count = self.tcp_available_count,
                threshold,
                "TCP protocol-detect availability threshold reached inside TCP-to-UDP avoid window"
            );
            return ProtocolDetectAction::Continue;
        }
        tracing::info!(
            available_count = self.tcp_available_count,
            threshold,
            "TCP protocol-detect availability threshold reached; switching back to UDP"
        );
        ProtocolDetectAction::Switch(ProtocolMode::Udp)
    }
}

/// Run the supervisor loop until a trigger fires or disconnect is requested.
///
/// `report` is invoked on the report interval; it returns `Ok(true)` if the
/// server signalled a force-logout/kickout.
pub async fn run<F, Fut>(
    session: &mut TunnelSession, protocol_mode: Option<ProtocolMode>, outbound: Option<String>,
    protocol_detect_options: ProtocolDetectOptions, cancel: CancellationToken, mut report: F,
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
    let started = Instant::now();
    let mut protocol_detect = ProtocolDetectState::new(protocol_detect_options);

    loop {
        tokio::select! {
            () = cancel.cancelled() => return SupervisorOutcome::Cancelled,

            () = session.wait() => {
                tracing::warn!("tunnel transport failed (device stopped)");
                return SupervisorOutcome::Trigger(ReconnectEvent::TransportFailed);
            }

            _ = handshake_tick.tick() => {
                let handshake_age = session.last_handshake().await;
                if handshake_age.map_or_else(|| started.elapsed() > threshold, |age| age > threshold) {
                    if let Some(detect) = &mut protocol_detect {
                        match detect.record_timeout(protocol_mode) {
                            ProtocolDetectAction::Continue => continue,
                            ProtocolDetectAction::HandshakeTimeout => {}
                            ProtocolDetectAction::Switch(protocol_mode) => {
                                return SupervisorOutcome::ProtocolSwitch(protocol_mode);
                            }
                        }
                    }
                    tracing::warn!(
                        age_secs = handshake_age.map(|age| age.as_secs()),
                        session_age_secs = started.elapsed().as_secs(),
                        "handshake timeout"
                    );
                    return SupervisorOutcome::Trigger(ReconnectEvent::HandshakeTimeout);
                }
                if handshake_age.is_some()
                    && let Some(detect) = &mut protocol_detect
                    && let ProtocolDetectAction::Switch(protocol_mode) =
                        detect.record_success(protocol_mode)
                {
                    return SupervisorOutcome::ProtocolSwitch(protocol_mode);
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

    use rustylink_api::VpnProtocolDetectConfig;
    use rustylink_tunnel::ProtocolMode;
    use tokio::time::Instant;

    use super::{
        ProtocolDetectAction, ProtocolDetectOptions, ProtocolDetectState,
        TCP_TO_UDP_AVOID_AFTER_UDP_TO_TCP,
    };

    fn config(
        udp2tcp: i32, tcp2udp: i32, refresh: i32, bad_network: i32,
    ) -> VpnProtocolDetectConfig {
        VpnProtocolDetectConfig {
            enable: Some(true),
            udp2tcp_timeout_count: Some(udp2tcp),
            tcp2udp_available_count: Some(tcp2udp),
            refresh_timeout_count: Some(refresh),
            bad_network_count: Some(bad_network),
        }
    }

    #[test]
    fn udp_timeouts_switch_to_tcp_after_config_threshold() {
        let mut state = ProtocolDetectState::new(ProtocolDetectOptions {
            config: Some(config(2, 0, 0, 0)),
            dot_protocol_mode: Some(ProtocolMode::Dual),
            last_udp_to_tcp: None,
        })
        .expect("state");

        assert_eq!(
            state.record_timeout(Some(ProtocolMode::Udp)),
            ProtocolDetectAction::Continue
        );
        assert_eq!(
            state.record_timeout(Some(ProtocolMode::Udp)),
            ProtocolDetectAction::Switch(ProtocolMode::FeilianTcp)
        );
    }

    #[test]
    fn tcp_success_switches_back_to_udp_outside_avoid_window() {
        let mut state = ProtocolDetectState::new(ProtocolDetectOptions {
            config: Some(config(0, 2, 0, 0)),
            dot_protocol_mode: Some(ProtocolMode::Dual),
            last_udp_to_tcp: Some(
                Instant::now() - TCP_TO_UDP_AVOID_AFTER_UDP_TO_TCP - Duration::from_secs(1),
            ),
        })
        .expect("state");

        assert_eq!(
            state.record_success(Some(ProtocolMode::FeilianTcp)),
            ProtocolDetectAction::Continue
        );
        assert_eq!(
            state.record_success(Some(ProtocolMode::FeilianTcp)),
            ProtocolDetectAction::Switch(ProtocolMode::Udp)
        );
    }

    #[test]
    fn tcp_success_does_not_switch_inside_avoid_window() {
        let mut state = ProtocolDetectState::new(ProtocolDetectOptions {
            config: Some(config(0, 1, 0, 0)),
            dot_protocol_mode: Some(ProtocolMode::Dual),
            last_udp_to_tcp: Some(Instant::now()),
        })
        .expect("state");

        assert_eq!(
            state.record_success(Some(ProtocolMode::FeilianTcp)),
            ProtocolDetectAction::Continue
        );
    }
}
