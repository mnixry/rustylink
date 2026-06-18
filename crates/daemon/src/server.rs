//! `RustylinkService` implementation — thin handlers that validate input,
//! delegate to the [`Daemon`] core, and project results to the proto wire
//! types.  Tunnel connect/disconnect are wired in Phase 6; everything else is
//! functional here.

use buffa::EnumValue;
use connectrpc::{
    ConnectError, RequestContext, Response, ServiceRequest, ServiceResult, ServiceStream,
};
use rustylink_core::vpn::VpnConnectMode;
use rustylink_proto::proto::rustylink::daemon::v1::{self as pb, RustylinkService};
use tokio_stream::{StreamExt as _, wrappers::WatchStream};

use crate::daemon::Daemon;

#[derive(Clone)]
pub struct Svc {
    daemon: Daemon,
}

impl Svc {
    #[must_use]
    pub fn new(daemon: Daemon) -> Self {
        Self { daemon }
    }
}

/// Convert an empty wire string to `None`, else `Some(owned)`.
fn opt(value: &str) -> Option<String> {
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

// Handlers return concrete response types, which are more specific than the
// trait's `impl Encodable<...>` return bound — this is intentional refinement.
#[allow(refining_impl_trait_reachable)]
impl RustylinkService for Svc {
    // ----- meta -----

    async fn ping(
        &self, _ctx: RequestContext, _request: ServiceRequest<'_, pb::PingRequest>,
    ) -> ServiceResult<pb::PingResponse> {
        Response::ok(pb::PingResponse {
            version: env!("CARGO_PKG_VERSION").to_string(),
            uptime_seconds: self.daemon.uptime_seconds(),
            ..Default::default()
        })
    }

    async fn watch_state(
        &self, _ctx: RequestContext, _request: ServiceRequest<'_, pb::WatchStateRequest>,
    ) -> ServiceResult<ServiceStream<pb::WatchStateResponse>> {
        let rx = self.daemon.subscribe();
        let stream = WatchStream::new(rx).map(|state| Ok(state.to_watch_response()));
        Response::stream_ok(stream)
    }

    // ----- session -----

    async fn get_session(
        &self, _ctx: RequestContext, _request: ServiceRequest<'_, pb::GetSessionRequest>,
    ) -> ServiceResult<pb::GetSessionResponse> {
        let session = self.daemon.session().await;
        Response::ok(pb::GetSessionResponse {
            session: session.into(),
            ..Default::default()
        })
    }

    async fn activate(
        &self, _ctx: RequestContext, request: ServiceRequest<'_, pb::ActivateRequest>,
    ) -> ServiceResult<pb::ActivateResponse> {
        let session = self
            .daemon
            .activate(
                opt(request.code),
                opt(request.base_url),
                opt(request.backup_url),
                opt(request.match_base_url),
            )
            .await?;
        Response::ok(pb::ActivateResponse {
            session: session.into(),
            ..Default::default()
        })
    }

    async fn login(
        &self, _ctx: RequestContext, request: ServiceRequest<'_, pb::LoginRequest>,
    ) -> ServiceResult<pb::LoginResponse> {
        if request.account.is_empty() || request.password.is_empty() {
            return Err(ConnectError::invalid_argument(
                "account and password are required",
            ));
        }
        let login_scene = nonempty_or(request.login_scene, "login");
        let account_type = nonempty_or(request.account_type, "account");
        let session = self
            .daemon
            .login(
                login_scene,
                account_type,
                request.account.to_string(),
                request.password.to_string(),
            )
            .await?;
        Response::ok(pb::LoginResponse {
            session: session.into(),
            ..Default::default()
        })
    }

    async fn request_login_code(
        &self, _ctx: RequestContext, request: ServiceRequest<'_, pb::RequestLoginCodeRequest>,
    ) -> ServiceResult<pb::RequestLoginCodeResponse> {
        if request.account.is_empty() {
            return Err(ConnectError::invalid_argument("account is required"));
        }
        let code = self
            .daemon
            .request_login_code(
                nonempty_or(request.login_scene, "login"),
                nonempty_or(request.account_type, "account"),
                request.login_type.to_string(),
                request.account.to_string(),
            )
            .await?;
        Response::ok(pb::RequestLoginCodeResponse {
            code,
            ..Default::default()
        })
    }

    async fn verify_login_code(
        &self, _ctx: RequestContext, request: ServiceRequest<'_, pb::VerifyLoginCodeRequest>,
    ) -> ServiceResult<pb::VerifyLoginCodeResponse> {
        if request.account.is_empty() || request.code.is_empty() {
            return Err(ConnectError::invalid_argument(
                "account and code are required",
            ));
        }
        let session = self
            .daemon
            .verify_login_code(
                nonempty_or(request.login_scene, "login"),
                nonempty_or(request.account_type, "account"),
                request.login_type.to_string(),
                request.account.to_string(),
                request.code.to_string(),
            )
            .await?;
        Response::ok(pb::VerifyLoginCodeResponse {
            session: session.into(),
            ..Default::default()
        })
    }

    async fn request_mfa_code(
        &self, _ctx: RequestContext, request: ServiceRequest<'_, pb::RequestMfaCodeRequest>,
    ) -> ServiceResult<pb::RequestMfaCodeResponse> {
        if request.mfa_type.is_empty() || request.account.is_empty() {
            return Err(ConnectError::invalid_argument(
                "mfa_type and account are required",
            ));
        }
        let code = self
            .daemon
            .request_mfa_code(
                nonempty_or(request.login_scene, "login"),
                request.mfa_type.to_string(),
                request.account.to_string(),
            )
            .await?;
        Response::ok(pb::RequestMfaCodeResponse {
            code,
            ..Default::default()
        })
    }

    async fn verify_mfa(
        &self, _ctx: RequestContext, request: ServiceRequest<'_, pb::VerifyMfaRequest>,
    ) -> ServiceResult<pb::VerifyMfaResponse> {
        if request.mfa_type.is_empty() || request.account.is_empty() {
            return Err(ConnectError::invalid_argument(
                "mfa_type and account are required",
            ));
        }
        let session = self
            .daemon
            .verify_mfa(
                nonempty_or(request.login_scene, "login"),
                request.mfa_type.to_string(),
                request.account.to_string(),
                opt(request.code),
                opt(request.password),
            )
            .await?;
        Response::ok(pb::VerifyMfaResponse {
            session: session.into(),
            ..Default::default()
        })
    }

    async fn skip_pending_challenge(
        &self, _ctx: RequestContext, request: ServiceRequest<'_, pb::SkipPendingChallengeRequest>,
    ) -> ServiceResult<pb::SkipPendingChallengeResponse> {
        let session = self
            .daemon
            .skip_pending_challenge(nonempty_or(request.login_scene, "login"))
            .await?;
        Response::ok(pb::SkipPendingChallengeResponse {
            session: session.into(),
            ..Default::default()
        })
    }

    async fn list_third_party_providers(
        &self, _ctx: RequestContext,
        _request: ServiceRequest<'_, pb::ListThirdPartyProvidersRequest>,
    ) -> ServiceResult<pb::ListThirdPartyProvidersResponse> {
        let providers = self.daemon.list_third_party_providers().await?;
        Response::ok(pb::ListThirdPartyProvidersResponse {
            providers,
            ..Default::default()
        })
    }

    async fn start_third_party_login(
        &self, _ctx: RequestContext, request: ServiceRequest<'_, pb::StartThirdPartyLoginRequest>,
    ) -> ServiceResult<pb::StartThirdPartyLoginResponse> {
        if request.alias_key.is_empty() {
            return Err(ConnectError::invalid_argument("alias_key is required"));
        }
        let response = self
            .daemon
            .start_third_party_login(
                request.alias_key.to_string(),
                request.redirect_uri.to_string(),
            )
            .await?;
        Response::ok(response)
    }

    async fn complete_third_party_login(
        &self, _ctx: RequestContext,
        request: ServiceRequest<'_, pb::CompleteThirdPartyLoginRequest>,
    ) -> ServiceResult<pb::CompleteThirdPartyLoginResponse> {
        if request.alias_key.is_empty() || request.code.is_empty() || request.state.is_empty() {
            return Err(ConnectError::invalid_argument(
                "alias_key, code, and state are required",
            ));
        }
        let session = self
            .daemon
            .complete_third_party_login(
                request.alias_key.to_string(),
                request.code.to_string(),
                request.state.to_string(),
            )
            .await?;
        Response::ok(pb::CompleteThirdPartyLoginResponse {
            session: session.into(),
            ..Default::default()
        })
    }

    async fn logout(
        &self, _ctx: RequestContext, request: ServiceRequest<'_, pb::LogoutRequest>,
    ) -> ServiceResult<pb::LogoutResponse> {
        let session = self.daemon.logout(request.logout_all).await?;
        Response::ok(pb::LogoutResponse {
            session: session.into(),
            ..Default::default()
        })
    }

    // ----- tunnel -----

    async fn get_tunnel(
        &self, _ctx: RequestContext, _request: ServiceRequest<'_, pb::GetTunnelRequest>,
    ) -> ServiceResult<pb::GetTunnelResponse> {
        let tunnel = self.daemon.tunnel().await;
        Response::ok(pb::GetTunnelResponse {
            tunnel: tunnel.into(),
            ..Default::default()
        })
    }

    async fn connect_tunnel(
        &self, _ctx: RequestContext, request: ServiceRequest<'_, pb::ConnectTunnelRequest>,
    ) -> ServiceResult<pb::ConnectTunnelResponse> {
        let vpn_request = crate::state::VpnRequest {
            mode: vpn_mode_from_proto(request.mode),
            export_id: request.export_id,
            preferred_dot_id: (request.preferred_dot_id > 0).then_some(request.preferred_dot_id),
            otp: opt(request.otp),
            reconnect: request.reconnect,
            protocol_mode: protocol_mode_from_proto(request.protocol_mode),
        };
        let tunnel = self.daemon.connect_tunnel(vpn_request).await?;
        Response::ok(pb::ConnectTunnelResponse {
            tunnel: tunnel.into(),
            ..Default::default()
        })
    }

    async fn disconnect_tunnel(
        &self, _ctx: RequestContext, _request: ServiceRequest<'_, pb::DisconnectTunnelRequest>,
    ) -> ServiceResult<pb::DisconnectTunnelResponse> {
        let tunnel = self.daemon.disconnect_tunnel().await?;
        Response::ok(pb::DisconnectTunnelResponse {
            tunnel: tunnel.into(),
            ..Default::default()
        })
    }

    async fn list_vpn_locations(
        &self, _ctx: RequestContext, _request: ServiceRequest<'_, pb::ListVpnLocationsRequest>,
    ) -> ServiceResult<pb::ListVpnLocationsResponse> {
        let locations = self.daemon.list_vpn_locations().await?;
        Response::ok(pb::ListVpnLocationsResponse {
            locations,
            ..Default::default()
        })
    }

    // ----- profile + configuration -----

    async fn get_user_info(
        &self, _ctx: RequestContext, _request: ServiceRequest<'_, pb::GetUserInfoRequest>,
    ) -> ServiceResult<pb::GetUserInfoResponse> {
        let user_info = self.daemon.user_info().await?;
        Response::ok(pb::GetUserInfoResponse {
            user_info: user_info.into(),
            ..Default::default()
        })
    }

    async fn get_configuration(
        &self, _ctx: RequestContext, _request: ServiceRequest<'_, pb::GetConfigurationRequest>,
    ) -> ServiceResult<pb::GetConfigurationResponse> {
        let configuration = self.daemon.configuration().await;
        Response::ok(pb::GetConfigurationResponse {
            configuration: configuration.into(),
            ..Default::default()
        })
    }

    async fn update_configuration(
        &self, _ctx: RequestContext, request: ServiceRequest<'_, pb::UpdateConfigurationRequest>,
    ) -> ServiceResult<pb::UpdateConfigurationResponse> {
        // Without a field mask we treat each present field as authoritative.
        let owned = request.to_owned_message();
        let config = owned.configuration;
        let configuration = self
            .daemon
            .set_auto_reconnect(config.auto_reconnect_on_start)
            .await?;
        // Only update the outbound interface if the oneof was actually set.
        let configuration = if let Some(selector) = config.outbound_interface.selector.as_ref() {
            let name = match selector {
                pb::outbound_interface::Selector::Name(name) if !name.is_empty() => {
                    Some(name.clone())
                }
                _ => None,
            };
            self.daemon.set_outbound_interface(name).await?
        } else {
            configuration
        };
        Response::ok(pb::UpdateConfigurationResponse {
            configuration: configuration.into(),
            ..Default::default()
        })
    }
}

fn nonempty_or(value: &str, default: &str) -> String {
    if value.is_empty() {
        default.to_string()
    } else {
        value.to_string()
    }
}

/// Map a proto `VpnMode` to the core connect mode (defaults to Full).
fn vpn_mode_from_proto(mode: EnumValue<pb::VpnMode>) -> VpnConnectMode {
    match mode {
        EnumValue::Known(pb::VpnMode::Split) => VpnConnectMode::Split,
        EnumValue::Known(pb::VpnMode::Relay) => VpnConnectMode::Relay,
        _ => VpnConnectMode::Full,
    }
}

/// Map a proto `ProtocolMode` to the dot protocol convention
/// (0 = UDP, 1 = `FeiLian` TCP, 2 = dual/auto); `None` means "use the dot's".
fn protocol_mode_from_proto(mode: EnumValue<pb::ProtocolMode>) -> Option<i32> {
    match mode {
        EnumValue::Known(pb::ProtocolMode::Udp) => Some(0),
        EnumValue::Known(pb::ProtocolMode::Tcp) => Some(1),
        EnumValue::Known(pb::ProtocolMode::Auto) => Some(2),
        _ => None,
    }
}
