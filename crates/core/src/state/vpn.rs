//! Pure VPN connection state and transitions.
//!
//! [`VpnState`] is the runtime-agnostic state of the tunnel: the daemon owns the
//! live OS resources (the `WireGuard` session, cancellation token) separately
//! and drives this state through the pure transition methods below. Each
//! transition consumes the current state and returns the next one, so the only
//! place state is *assigned* is the daemon's single transition helper.

use crate::vpn::VpnConnectMode;

/// A VPN connect request — the working form that drives the connect loop.
#[derive(Clone, Debug)]
pub struct VpnRequest {
    pub mode: VpnConnectMode,
    pub export_id: i32,
    pub preferred_dot_id: Option<i32>,
    pub otp: Option<String>,
    pub reconnect: bool,
}

impl Default for VpnRequest {
    fn default() -> Self {
        Self {
            mode: VpnConnectMode::Full,
            export_id: 0,
            preferred_dot_id: None,
            otp: None,
            reconnect: true,
        }
    }
}

/// A live, connected tunnel — recorded while the tunnel is up.
#[derive(Clone, Debug, Default)]
pub struct ActiveTunnel {
    pub dot_id: i32,
    pub dot_name: String,
    pub endpoint: String,
    pub assigned_ip: String,
}

/// VPN connection state.
#[derive(Clone, Debug)]
pub enum VpnState {
    Disconnected,
    Connecting {
        request: VpnRequest,
    },
    Configuring {
        request: VpnRequest,
    },
    Connected {
        request: VpnRequest,
        tunnel_info: ActiveTunnel,
    },
    Reconnecting {
        request: VpnRequest,
        attempts: u32,
    },
    Failed {
        request: VpnRequest,
        error: String,
        attempts: u32,
    },
    Disconnecting {
        request: VpnRequest,
    },
}

impl VpnState {
    // ------- queries -------

    /// True when a connect may start (no active or in-flight tunnel).
    #[must_use]
    pub const fn can_connect(&self) -> bool {
        matches!(self, Self::Disconnected | Self::Failed { .. })
    }

    /// Current reconnect attempt count.
    #[must_use]
    pub const fn attempts(&self) -> u32 {
        match self {
            Self::Reconnecting { attempts, .. } | Self::Failed { attempts, .. } => *attempts,
            _ => 0,
        }
    }

    /// Borrow the in-flight request, if any.
    #[must_use]
    pub const fn current_request(&self) -> Option<&VpnRequest> {
        match self {
            Self::Connecting { request }
            | Self::Configuring { request }
            | Self::Connected { request, .. }
            | Self::Reconnecting { request, .. }
            | Self::Failed { request, .. }
            | Self::Disconnecting { request } => Some(request),
            Self::Disconnected => None,
        }
    }

    // ------- transitions (consume self, return the next state) -------

    /// Begin a fresh connection attempt with a new request.
    #[must_use]
    pub fn into_connecting(request: VpnRequest) -> Self {
        Self::Connecting { request }
    }

    /// Move to `Configuring`, preserving the current request.
    #[must_use]
    pub fn into_configuring(self) -> Self {
        Self::Configuring {
            request: self.into_request(),
        }
    }

    /// Move to `Connected` with the live tunnel info.
    #[must_use]
    pub fn into_connected(self, tunnel_info: ActiveTunnel) -> Self {
        Self::Connected {
            request: self.into_request(),
            tunnel_info,
        }
    }

    /// Move to `Reconnecting`, incrementing the attempt counter.
    #[must_use]
    pub fn into_reconnecting(self) -> Self {
        let attempts = self.attempts().saturating_add(1);
        Self::Reconnecting {
            request: self.into_request(),
            attempts,
        }
    }

    /// Move to `Failed` with an error message, preserving the attempt count.
    #[must_use]
    pub fn into_failed(self, error: String) -> Self {
        let attempts = self.attempts();
        Self::Failed {
            request: self.into_request(),
            error,
            attempts,
        }
    }

    /// Move to `Disconnecting`, preserving the current request.
    #[must_use]
    pub fn into_disconnecting(self) -> Self {
        Self::Disconnecting {
            request: self.into_request(),
        }
    }

    /// Extract the request from the current state, falling back to a default.
    fn into_request(self) -> VpnRequest {
        match self {
            Self::Disconnected => VpnRequest::default(),
            Self::Connecting { request }
            | Self::Configuring { request }
            | Self::Connected { request, .. }
            | Self::Reconnecting { request, .. }
            | Self::Failed { request, .. }
            | Self::Disconnecting { request } => request,
        }
    }
}
