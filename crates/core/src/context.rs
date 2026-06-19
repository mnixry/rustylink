use std::collections::HashMap;

use rustylink_api::{
    ApiClient, ApiClientOptions, ApiEndpoint, ApiHooks, ClientIdentity, DotEndpoint, MatchEndpoint,
    SessionCookies, SigningConfig, SigningContext, TenantEndpoint, VpnDot, build_http_client,
};
use rustylink_proto::proto::rustylink::daemon::persist::v1 as persist;
use snafu::prelude::*;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("no tenant base URL configured; run activate with --base-url first"))]
    MissingBaseUrl,

    #[snafu(display("API client setup failed"))]
    Api {
        #[snafu(source(from(rustylink_api::Error, Box::new)))]
        source: Box<rustylink_api::Error>,
    },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

/// Application context holding a shared HTTP client pool, per-server API
/// clients, and a read-only proto state snapshot.
///
/// The daemon owns the canonical `PersistedState`; it refreshes this context
/// before each command.  Core functions take `&AppContext` and **never** mutate
/// state — they return `Vec<StateChange>` instead.
#[derive(Clone)]
pub struct AppContext {
    http: reqwest::Client,
    tenant_client: Option<ApiClient>,
    match_client: ApiClient,
    proto: persist::PersistedState,
    api_options: ApiClientOptions,
}

impl AppContext {
    /// Create a new `AppContext` from a proto state snapshot.
    pub fn new(proto: &persist::PersistedState, api_options: ApiClientOptions) -> Result<Self> {
        let http = build_http_client(&api_options).context(ApiSnafu)?;
        let proto = proto.clone();
        // The match client targets the infallible default match endpoint, so it
        // is always present (unlike the tenant client, which needs a base URL).
        let match_client = ApiClient::for_endpoint(
            &MatchEndpoint::default(),
            http.clone(),
            Self::hooks_for(&proto),
        );
        let mut ctx = Self {
            http,
            tenant_client: None,
            match_client,
            proto,
            api_options,
        };
        ctx.rebuild_clients();
        Ok(ctx)
    }

    /// Refresh with a new proto state snapshot.
    pub fn refresh(&mut self, proto: &persist::PersistedState) {
        self.proto = proto.clone();
        self.rebuild_clients();
    }

    /// Rebuild the HTTP client (when outbound interface changes).
    pub fn rebuild_http(&mut self, options: ApiClientOptions) -> Result<()> {
        self.http = build_http_client(&options).context(ApiSnafu)?;
        self.api_options = options;
        self.rebuild_clients();
        Ok(())
    }

    // ------- client accessors -------

    pub fn tenant_client(&self) -> Result<&ApiClient> {
        self.tenant_client.as_ref().context(MissingBaseUrlSnafu)
    }

    /// The always-present match-server API client.
    #[must_use]
    pub fn match_client(&self) -> &ApiClient {
        &self.match_client
    }

    pub fn match_client_with_url(&self, base_url: &str) -> Result<ApiClient> {
        let endpoint = MatchEndpoint::new(base_url).context(ApiSnafu)?;
        Ok(ApiClient::for_endpoint(
            &endpoint,
            self.http.clone(),
            self.build_hooks(),
        ))
    }

    #[must_use]
    pub fn dot_client(&self, endpoint: &DotEndpoint) -> ApiClient {
        ApiClient::for_endpoint(endpoint, self.http.clone(), self.build_hooks())
    }

    #[must_use]
    pub fn client_for_endpoint(&self, endpoint: &impl ApiEndpoint) -> ApiClient {
        ApiClient::for_endpoint(endpoint, self.http.clone(), self.build_hooks())
    }

    pub fn dot_endpoint(
        dot: &VpnDot, use_vpn_ip_for_api: bool,
    ) -> rustylink_api::Result<DotEndpoint> {
        DotEndpoint::from_dot(dot, use_vpn_ip_for_api)
    }

    #[must_use]
    pub fn outbound_interface(&self) -> Option<&str> {
        self.api_options.outbound_interface.as_deref()
    }

    // ------- proto-aware state accessors (core functions use these) -------

    /// The configured tenant, if any.
    #[must_use]
    pub fn tenant(&self) -> Option<&persist::PersistedTenant> {
        self.configured_base().and_then(|b| b.tenant.as_option())
    }

    /// The signing config, if configured.
    #[must_use]
    pub fn signing(&self) -> Option<SigningConfig> {
        self.configured_base()
            .and_then(|b| b.signing.as_option())
            .map(SigningConfig::from)
    }

    /// The signing config as proto (for producing `StateChange`s).
    #[must_use]
    pub fn signing_proto(&self) -> Option<&persist::PersistedSigning> {
        self.configured_base().and_then(|b| b.signing.as_option())
    }

    /// The client identity.
    #[must_use]
    pub fn identity(&self) -> ClientIdentity {
        self.proto
            .identity
            .as_option()
            .map(ClientIdentity::from)
            .unwrap_or_default()
    }

    /// The device ID from the (merged) identity.
    #[must_use]
    pub fn device_id(&self) -> String {
        self.identity().device_id
    }

    /// The OAuth state (only in Authenticating).
    #[must_use]
    pub fn oauth(&self) -> Option<&persist::PersistedOauth> {
        use persist::persisted_state::AuthState;
        match &self.proto.auth_state {
            Some(AuthState::Authenticating(d)) => d.oauth.as_option(),
            _ => None,
        }
    }

    /// The selected tenant base URL (respects `use_backup`).
    #[must_use]
    pub fn selected_base_url(&self) -> Option<String> {
        let tenant = self.tenant()?;
        if tenant.use_backup {
            tenant
                .backup_url
                .clone()
                .or_else(|| tenant.base_url.clone())
        } else {
            tenant.base_url.clone()
        }
    }

    /// The session cookies as a proto map.
    #[must_use]
    pub fn session_cookies(&self) -> Option<&HashMap<String, String>> {
        use persist::persisted_state::AuthState;
        match &self.proto.auth_state {
            Some(AuthState::Authenticating(d)) => Some(&d.cookies),
            Some(AuthState::Authenticated(d)) => Some(&d.cookies),
            _ => None,
        }
    }

    // ------- private helpers -------

    fn configured_base(&self) -> Option<&persist::PersistedConfiguredBase> {
        configured_base_of(&self.proto)
    }

    fn rebuild_clients(&mut self) {
        let hooks = self.build_hooks();
        self.match_client =
            ApiClient::for_endpoint(&MatchEndpoint::default(), self.http.clone(), hooks.clone());
        self.tenant_client = self.selected_base_url().and_then(|base_url| {
            if let Ok(endpoint) = TenantEndpoint::new(&base_url) {
                Some(ApiClient::for_endpoint(
                    &endpoint,
                    self.http.clone(),
                    hooks.clone(),
                ))
            } else {
                tracing::warn!(%base_url, "invalid tenant base URL");
                None
            }
        });
    }

    fn build_hooks(&self) -> ApiHooks {
        Self::hooks_for(&self.proto)
    }

    fn hooks_for(proto: &persist::PersistedState) -> ApiHooks {
        use persist::persisted_state::AuthState;
        let identity = proto
            .identity
            .as_option()
            .map(ClientIdentity::from)
            .unwrap_or_default();
        let signing = configured_base_of(proto)
            .and_then(|base| base.signing.as_option())
            .map(SigningConfig::from)
            .unwrap_or_default();
        let cookies = match &proto.auth_state {
            Some(AuthState::Authenticating(d)) => Some(&d.cookies),
            Some(AuthState::Authenticated(d)) => Some(&d.cookies),
            _ => None,
        }
        .map(SessionCookies::from_map)
        .unwrap_or_default();
        let csrf_token = match &proto.auth_state {
            Some(AuthState::Authenticating(d)) => d.csrf_token.clone(),
            Some(AuthState::Authenticated(d)) => d.csrf_token.clone(),
            _ => None,
        };
        let knock_token = match &proto.auth_state {
            Some(AuthState::Authenticating(d)) => d.knock_token.clone(),
            Some(AuthState::Authenticated(d)) => d.knock_token.clone(),
            _ => None,
        };
        ApiHooks {
            identity,
            cookies,
            csrf_token,
            knock_token,
            signer: SigningContext::new(signing),
        }
    }
}

/// The configured tenant/signing base shared by every non-Unconfigured state.
fn configured_base_of(
    proto: &persist::PersistedState,
) -> Option<&persist::PersistedConfiguredBase> {
    use persist::persisted_state::AuthState;
    match &proto.auth_state {
        Some(AuthState::Configured(d)) => d.base.as_option(),
        Some(AuthState::Authenticating(d)) => d.base.as_option(),
        Some(AuthState::Authenticated(d)) => d.base.as_option(),
        Some(AuthState::Expired(d)) => d.base.as_option(),
        _ => None,
    }
}
