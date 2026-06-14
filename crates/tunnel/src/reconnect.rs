use std::time::Duration;

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ReconnectEvent {
    HandshakeTimeout,
    IdleTimeout,
    ServerKickOut,
    NetworkChanged,
    TransportFailed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ReconnectDecision {
    Retry { after: Duration, attempt: u32 },
    SwitchNode { after: Duration, attempt: u32 },
    Stop,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ReconnectPolicy {
    pub max_attempts: u32,
    pub base_delay: Duration,
    pub max_delay: Duration,
    pub switch_node_after: u32,
}

#[derive(Clone, Debug)]
pub struct ReconnectController {
    policy: ReconnectPolicy,
    attempts: u32,
}

impl ReconnectPolicy {
    #[must_use]
    pub const fn android_compatible_default() -> Self {
        Self {
            max_attempts: 8,
            base_delay: Duration::from_secs(2),
            max_delay: Duration::from_mins(1),
            switch_node_after: 3,
        }
    }
}

impl Default for ReconnectPolicy {
    fn default() -> Self {
        Self::android_compatible_default()
    }
}

impl ReconnectController {
    #[must_use]
    pub const fn new(policy: ReconnectPolicy) -> Self {
        Self {
            policy,
            attempts: 0,
        }
    }

    pub fn record(&mut self, event: ReconnectEvent) -> ReconnectDecision {
        self.attempts = self.attempts.saturating_add(1);
        if self.attempts > self.policy.max_attempts {
            return ReconnectDecision::Stop;
        }
        let delay = self.delay_for_attempt(self.attempts);
        if matches!(event, ReconnectEvent::ServerKickOut)
            || self.attempts >= self.policy.switch_node_after
        {
            ReconnectDecision::SwitchNode {
                after: delay,
                attempt: self.attempts,
            }
        } else {
            ReconnectDecision::Retry {
                after: delay,
                attempt: self.attempts,
            }
        }
    }

    pub const fn reset(&mut self) {
        self.attempts = 0;
    }

    fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let exponent = attempt.saturating_sub(1).min(5);
        let factor = 2_u32.saturating_pow(exponent);
        self.policy
            .base_delay
            .saturating_mul(factor)
            .min(self.policy.max_delay)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{ReconnectController, ReconnectDecision, ReconnectEvent, ReconnectPolicy};

    #[test]
    fn retries_then_switches_node() {
        let policy = ReconnectPolicy {
            max_attempts: 4,
            base_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(10),
            switch_node_after: 3,
        };
        let mut controller = ReconnectController::new(policy);
        assert_eq!(
            controller.record(ReconnectEvent::HandshakeTimeout),
            ReconnectDecision::Retry {
                after: Duration::from_secs(1),
                attempt: 1
            }
        );
        assert_eq!(
            controller.record(ReconnectEvent::TransportFailed),
            ReconnectDecision::Retry {
                after: Duration::from_secs(2),
                attempt: 2
            }
        );
        assert_eq!(
            controller.record(ReconnectEvent::IdleTimeout),
            ReconnectDecision::SwitchNode {
                after: Duration::from_secs(4),
                attempt: 3
            }
        );
    }
}
