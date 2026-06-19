//! Redacted projections from the persistence schema
//! (`rustylink.daemon.persist.v1`) to the wire/service types
//! (`rustylink.daemon.v1`).
//!
//! Both source and target types are defined in this crate, so the `From` impls
//! are legal under the orphan rule.  Secrets present in `PersistedState` are
//! never read — the projections are redacted by construction.

use crate::proto::rustylink::daemon::{persist::v1 as persist, v1 as pb};

/// Extract (`tenant_name`, `base_url`) from a `PersistedConfiguredBase`,
/// respecting the `use_backup` flag.
fn tenant_fields(base: Option<&persist::PersistedConfiguredBase>) -> (String, String) {
    let tenant = base.and_then(|b| b.tenant.as_option());
    let name = tenant.and_then(|t| t.name.clone()).unwrap_or_default();
    let url = tenant
        .and_then(|t| {
            if t.use_backup {
                t.backup_url.clone().or_else(|| t.base_url.clone())
            } else {
                t.base_url.clone()
            }
        })
        .unwrap_or_default();
    (name, url)
}

impl From<&persist::PersistedState> for pb::Session {
    fn from(state: &persist::PersistedState) -> Self {
        use persist::persisted_state::AuthState;
        match &state.auth_state {
            None | Some(AuthState::Unconfigured(_)) => Self {
                state: pb::session::State::Unconfigured.into(),
                ..Default::default()
            },
            Some(AuthState::Configured(d)) => {
                let (name, url) = tenant_fields(d.base.as_option());
                Self {
                    state: pb::session::State::Configured.into(),
                    tenant_name: name,
                    base_url: url,
                    ..Default::default()
                }
            }
            Some(AuthState::Authenticating(d)) => {
                let (name, url) = tenant_fields(d.base.as_option());
                Self {
                    state: pb::session::State::Authenticating.into(),
                    tenant_name: name,
                    base_url: url,
                    pending_challenge: d.pending_challenge.clone(),
                    ..Default::default()
                }
            }
            Some(AuthState::Authenticated(d)) => {
                let (name, url) = tenant_fields(d.base.as_option());
                Self {
                    state: pb::session::State::Authenticated.into(),
                    tenant_name: name,
                    base_url: url,
                    ..Default::default()
                }
            }
            Some(AuthState::Expired(d)) => {
                let (name, url) = tenant_fields(d.base.as_option());
                Self {
                    state: pb::session::State::Expired.into(),
                    tenant_name: name,
                    base_url: url,
                    ..Default::default()
                }
            }
        }
    }
}

impl From<&persist::PersistedState> for pb::Tunnel {
    fn from(state: &persist::PersistedState) -> Self {
        use persist::{persisted_authenticated::VpnState, persisted_state::AuthState};

        let auth = match &state.auth_state {
            Some(AuthState::Authenticated(d)) => d.as_ref(),
            _ => {
                return Self {
                    state: pb::tunnel::State::Disconnected.into(),
                    ..Default::default()
                };
            }
        };

        match &auth.vpn_state {
            None | Some(VpnState::VpnDisconnected(_)) => Self {
                state: pb::tunnel::State::Disconnected.into(),
                ..Default::default()
            },
            Some(VpnState::VpnConnecting(d)) => Self {
                state: pb::tunnel::State::Connecting.into(),
                mode: d.request.as_option().map(|r| r.mode).unwrap_or_default(),
                ..Default::default()
            },
            Some(VpnState::VpnConfiguring(d)) => Self {
                state: pb::tunnel::State::Configuring.into(),
                mode: d.request.as_option().map(|r| r.mode).unwrap_or_default(),
                ..Default::default()
            },
            Some(VpnState::VpnConnected(d)) => {
                let active = d.active.as_option();
                Self {
                    state: pb::tunnel::State::Connected.into(),
                    mode: d.request.as_option().map(|r| r.mode).unwrap_or_default(),
                    dot_id: active.map(|a| a.dot_id).unwrap_or_default(),
                    dot_name: active.map(|a| a.dot_name.clone()).unwrap_or_default(),
                    endpoint: active.map(|a| a.endpoint.clone()).unwrap_or_default(),
                    assigned_ip: active.map(|a| a.assigned_ip.clone()).unwrap_or_default(),
                    connected_at: active.map(|a| a.connected_at.clone()).unwrap_or_default(),
                    last_handshake_at: active
                        .map(|a| a.last_handshake_at.clone())
                        .unwrap_or_default(),
                    ..Default::default()
                }
            }
            Some(VpnState::VpnReconnecting(d)) => Self {
                state: pb::tunnel::State::Reconnecting.into(),
                mode: d.request.as_option().map(|r| r.mode).unwrap_or_default(),
                reconnect_attempts: d.reconnect_attempts,
                ..Default::default()
            },
            Some(VpnState::VpnFailed(d)) => Self {
                state: pb::tunnel::State::Failed.into(),
                mode: d.request.as_option().map(|r| r.mode).unwrap_or_default(),
                error: d.error.clone(),
                reconnect_attempts: d.reconnect_attempts,
                ..Default::default()
            },
            Some(VpnState::VpnDisconnecting(d)) => Self {
                state: pb::tunnel::State::Disconnecting.into(),
                mode: d.request.as_option().map(|r| r.mode).unwrap_or_default(),
                ..Default::default()
            },
        }
    }
}

impl From<&persist::PersistedState> for pb::Configuration {
    fn from(state: &persist::PersistedState) -> Self {
        Self {
            outbound_interface: state.outbound_interface.clone(),
            auto_reconnect_on_start: state.auto_reconnect_on_start,
            ..Default::default()
        }
    }
}

impl From<&persist::PersistedState> for pb::WatchStateResponse {
    fn from(state: &persist::PersistedState) -> Self {
        Self {
            session: pb::Session::from(state).into(),
            tunnel: pb::Tunnel::from(state).into(),
            configuration: pb::Configuration::from(state).into(),
            updated_at: state.updated_at.clone(),
            ..Default::default()
        }
    }
}
