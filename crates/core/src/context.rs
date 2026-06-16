use std::path::PathBuf;

use rustylink_api::{ApiClient, ApiClientOptions, SigningContext};
use snafu::prelude::*;

use crate::state::RustylinkState;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)))]
pub enum Error {
    #[snafu(display("state operation failed"))]
    State { source: crate::state::Error },

    #[snafu(display("no tenant base URL configured; run activate with --base-url first"))]
    MissingBaseUrl,

    #[snafu(display("API client setup failed"))]
    Api {
        #[snafu(source(from(rustylink_api::Error, Box::new)))]
        source: Box<rustylink_api::Error>,
    },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Clone, Debug)]
pub struct AppContext {
    pub state_path: PathBuf,
    pub state: RustylinkState,
    api_options: ApiClientOptions,
}

impl AppContext {
    pub fn load(path: Option<PathBuf>) -> Result<Self> {
        Self::load_with_api_options(path, ApiClientOptions::from_env())
    }

    pub fn load_with_api_options(
        path: Option<PathBuf>, api_options: ApiClientOptions,
    ) -> Result<Self> {
        let state_path = path.unwrap_or_else(default_state_path);
        let state = RustylinkState::load_or_default(&state_path).context(StateSnafu)?;
        Ok(Self {
            state_path,
            state,
            api_options,
        })
    }

    pub fn save(&mut self) -> Result<()> {
        self.state.save(&self.state_path).context(StateSnafu)
    }

    pub fn api_client(&self) -> Result<ApiClient> {
        let base_url = self
            .state
            .selected_base_url()
            .context(MissingBaseUrlSnafu)?
            .to_string();
        self.api_client_for_base_url(base_url)
    }

    pub fn api_client_for_base_url(&self, base_url: impl AsRef<str>) -> Result<ApiClient> {
        let client = ApiClient::new_with_options(
            base_url.as_ref(),
            self.state.identity.clone(),
            SigningContext::new(self.state.signing.clone()),
            self.state.cookies.clone(),
            &self.api_options,
        )
        .context(ApiSnafu)?;
        client.set_csrf_token(self.state.csrf_token.clone());
        client.set_knock_token(self.state.knock_token.clone());
        Ok(client)
    }

    pub fn sync_from_client(&mut self, client: &ApiClient) {
        self.state.cookies = client.cookies();
    }

    #[must_use]
    pub fn outbound_interface(&self) -> Option<&str> {
        self.api_options.outbound_interface.as_deref()
    }

    pub fn set_outbound_interface(&mut self, outbound_interface: Option<String>) {
        self.api_options.outbound_interface = outbound_interface;
    }
}

fn default_state_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("rustylink")
        .join("state.json")
}
