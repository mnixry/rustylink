use rustylink_api::{
    ApiClient, ApiClientOptions, ApiEndpoint, ApiHooks, DotEndpoint, MatchEndpoint,
    SigningContext, TenantEndpoint, VpnDot, build_http_client,
};
use snafu::prelude::*;

use crate::state::RustylinkState;

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

/// Application context holding a shared HTTP client pool, per-server
/// `ApiClient` instances, and a read-only snapshot of the current state.
///
/// The daemon actor owns the canonical state; it builds/refreshes an
/// `AppContext` before each command so core functions can read the latest
/// cookies, signing config, etc.  Core functions take `&AppContext` and
/// **never** mutate state directly — they return `Vec<StateChange>` instead.
#[derive(Clone)]
pub struct AppContext {
    /// Shared `reqwest::Client` — reused for connection pooling and TLS
    /// session reuse.  Rebuilt only when the outbound interface changes.
    http: reqwest::Client,
    /// Long-lived tenant-server client (snapshot of auth hooks).
    tenant_client: Option<ApiClient>,
    /// Long-lived match-server client (snapshot of auth hooks).
    match_client: Option<ApiClient>,
    /// Read-only snapshot of the persisted state.  Core reads from here to
    /// build requests; it never writes back.
    pub state: RustylinkState,
    /// Client options (outbound interface binding).
    api_options: ApiClientOptions,
}

impl AppContext {
    /// Create a new `AppContext` from a state snapshot and client options.
    pub fn new(state: RustylinkState, api_options: ApiClientOptions) -> Result<Self> {
        let http = build_http_client(&api_options).context(ApiSnafu)?;
        let mut ctx = Self {
            http,
            tenant_client: None,
            match_client: None,
            state,
            api_options,
        };
        ctx.rebuild_clients();
        Ok(ctx)
    }

    /// Refresh the state snapshot and rebuild per-server client hooks.
    /// Called by the daemon actor before processing each command.
    pub fn refresh(&mut self, state: &RustylinkState) {
        self.state = state.clone();
        self.rebuild_clients();
    }

    /// Rebuild the shared HTTP client (only needed when outbound interface changes).
    pub fn rebuild_http(&mut self, options: ApiClientOptions) -> Result<()> {
        self.http = build_http_client(&options).context(ApiSnafu)?;
        self.api_options = options;
        self.rebuild_clients();
        Ok(())
    }

    /// Get the tenant API client.
    ///
    /// # Errors
    /// Returns `MissingBaseUrl` if no tenant URL is configured.
    pub fn tenant_client(&self) -> Result<&ApiClient> {
        self.tenant_client.as_ref().context(MissingBaseUrlSnafu)
    }

    /// Get the match-server API client.
    ///
    /// # Panics
    /// Panics if the match client was not built, which never happens — it is
    /// always constructed by `rebuild_clients`.
    #[must_use]
    pub fn match_client(&self) -> &ApiClient {
        self.match_client
            .as_ref()
            .expect("match client is always built")
    }

    /// Get a match-server client with a custom base URL override.
    pub fn match_client_with_url(&self, base_url: &str) -> Result<ApiClient> {
        let endpoint = MatchEndpoint::new(base_url).context(ApiSnafu)?;
        Ok(ApiClient::for_endpoint(
            &endpoint,
            self.http.clone(),
            self.build_hooks(),
        ))
    }

    /// Build an ephemeral dot-server API client that shares the HTTP pool.
    #[must_use]
    pub fn dot_client(&self, endpoint: &DotEndpoint) -> ApiClient {
        ApiClient::for_endpoint(endpoint, self.http.clone(), self.build_hooks())
    }

    /// Build an API client for an arbitrary endpoint (shares the HTTP pool).
    #[must_use]
    pub fn client_for_endpoint(&self, endpoint: &impl ApiEndpoint) -> ApiClient {
        ApiClient::for_endpoint(endpoint, self.http.clone(), self.build_hooks())
    }

    /// Create a dot endpoint from a `VpnDot`.
    pub fn dot_endpoint(dot: &VpnDot, use_vpn_ip_for_api: bool) -> rustylink_api::Result<DotEndpoint> {
        DotEndpoint::from_dot(dot, use_vpn_ip_for_api)
    }

    #[must_use]
    pub fn outbound_interface(&self) -> Option<&str> {
        self.api_options.outbound_interface.as_deref()
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    fn rebuild_clients(&mut self) {
        let hooks = self.build_hooks();

        // Always build a match client (default URL)
        let match_endpoint = MatchEndpoint::default();
        self.match_client = Some(ApiClient::for_endpoint(
            &match_endpoint,
            self.http.clone(),
            hooks.clone(),
        ));

        // Build tenant client only if a base URL is configured
        if let Some(base_url) = self.state.selected_base_url() {
            if let Ok(endpoint) = TenantEndpoint::new(base_url) {
                self.tenant_client = Some(ApiClient::for_endpoint(
                    &endpoint,
                    self.http.clone(),
                    hooks,
                ));
            } else {
                tracing::warn!(%base_url, "invalid tenant base URL; tenant client not built");
                self.tenant_client = None;
            }
        } else {
            self.tenant_client = None;
        }
    }

    fn build_hooks(&self) -> ApiHooks {
        ApiHooks {
            identity: self.state.identity.clone(),
            cookies: self.state.cookies.clone(),
            csrf_token: self.state.csrf_token.clone(),
            knock_token: self.state.knock_token.clone(),
            signer: SigningContext::new(self.state.signing.clone()),
        }
    }
}
