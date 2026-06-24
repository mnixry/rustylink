//! Network snapshot for change detection.
//!
//! The supervisor polls [`NetworkSnapshot::capture()`] every 5 s and compares
//! against the connect-time baseline.  A change in the fingerprint (interface
//! name, index, gateway, or addresses) fires `NetworkChanged`.

use std::net::IpAddr;

use snafu::prelude::*;

// ---------------------------------------------------------------------------
// Error
// ---------------------------------------------------------------------------

/// Error returned when capturing a network snapshot fails.
#[derive(Debug, Snafu)]
pub enum Error {
    #[snafu(display("failed to capture network snapshot: {source}"))]
    Capture {
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

// ---------------------------------------------------------------------------
// NetworkSnapshot
// ---------------------------------------------------------------------------

/// A point-in-time snapshot of the default network interface state.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NetworkSnapshot {
    default_interface: Option<InterfaceFingerprint>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct InterfaceFingerprint {
    name: String,
    index: u32,
    gateway: Option<IpAddr>,
    addrs: Vec<IpAddr>,
}

impl NetworkSnapshot {
    /// Capture the current default-interface fingerprint.
    ///
    /// Returns `Ok(snapshot)` with `default_interface = None` if no default
    /// interface exists.  Returns `Err` if the blocking task panics or
    /// is cancelled.
    pub async fn capture() -> Result<Self> {
        tokio::task::spawn_blocking(Self::capture_blocking)
            .await
            .map_err(|e| Error::Capture {
                source: Box::new(e),
            })
    }

    fn capture_blocking() -> Self {
        let Ok(interface) = default_net::get_default_interface() else {
            return Self::default();
        };
        let mut addrs: Vec<IpAddr> = Vec::new();
        for net in &interface.ipv4 {
            addrs.push(IpAddr::V4(net.addr));
        }
        for net in &interface.ipv6 {
            addrs.push(IpAddr::V6(net.addr));
        }
        addrs.sort();
        Self {
            default_interface: Some(InterfaceFingerprint {
                name: interface.name,
                index: interface.index,
                gateway: interface.gateway.map(|g| g.ip_addr),
                addrs,
            }),
        }
    }
}

/// Returns whether the named interface is present in the system interface list.
/// Used to detect whether a pinned outbound interface has disappeared.
pub async fn pinned_present(name: &str) -> Result<bool> {
    let name = name.to_owned();
    tokio::task::spawn_blocking(move || {
        default_net::get_interfaces().iter().any(|i| i.name == name)
    })
    .await
    .map_err(|e| Error::Capture {
        source: Box::new(e),
    })
}

// ---------------------------------------------------------------------------
// Unit tests (pure logic only — no networking)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_snapshots_compare_equal() {
        let a = NetworkSnapshot {
            default_interface: Some(InterfaceFingerprint {
                name: "en0".to_string(),
                index: 4,
                gateway: Some("192.168.1.1".parse().unwrap()),
                addrs: vec!["192.168.1.100".parse().unwrap()],
            }),
        };
        let b = a.clone();
        assert_eq!(a, b);
    }

    #[test]
    fn differing_gateway_is_a_change() {
        let a = NetworkSnapshot {
            default_interface: Some(InterfaceFingerprint {
                name: "en0".to_string(),
                index: 4,
                gateway: Some("192.168.1.1".parse().unwrap()),
                addrs: vec!["192.168.1.100".parse().unwrap()],
            }),
        };
        let b = NetworkSnapshot {
            default_interface: Some(InterfaceFingerprint {
                name: "en0".to_string(),
                index: 4,
                gateway: Some("10.0.0.1".parse().unwrap()),
                addrs: vec!["192.168.1.100".parse().unwrap()],
            }),
        };
        assert_ne!(a, b);
    }

    #[test]
    fn differing_index_is_a_change() {
        let a = NetworkSnapshot {
            default_interface: Some(InterfaceFingerprint {
                name: "en0".to_string(),
                index: 4,
                gateway: None,
                addrs: vec![],
            }),
        };
        let b = NetworkSnapshot {
            default_interface: Some(InterfaceFingerprint {
                name: "en0".to_string(),
                index: 7,
                gateway: None,
                addrs: vec![],
            }),
        };
        assert_ne!(a, b);
    }

    #[test]
    fn differing_addrs_is_a_change() {
        let a = NetworkSnapshot {
            default_interface: Some(InterfaceFingerprint {
                name: "en0".to_string(),
                index: 4,
                gateway: None,
                addrs: vec!["192.168.1.100".parse().unwrap()],
            }),
        };
        let b = NetworkSnapshot {
            default_interface: Some(InterfaceFingerprint {
                name: "en0".to_string(),
                index: 4,
                gateway: None,
                addrs: vec!["10.0.0.50".parse().unwrap()],
            }),
        };
        assert_ne!(a, b);
    }

    #[test]
    fn none_vs_some_is_a_change() {
        let a = NetworkSnapshot::default();
        let b = NetworkSnapshot {
            default_interface: Some(InterfaceFingerprint {
                name: "en0".to_string(),
                index: 4,
                gateway: None,
                addrs: vec![],
            }),
        };
        assert_ne!(a, b);
    }
}
