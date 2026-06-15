use std::path::PathBuf;

use rustylink_api::{ApiClient, SigningContext};
use snafu::prelude::*;

use crate::{error, error::Result, state::RustylinkState};

#[derive(Clone, Debug)]
pub struct AppContext {
    pub state_path: PathBuf,
    pub state: RustylinkState,
}

impl AppContext {
    pub fn load(path: Option<PathBuf>) -> Result<Self> {
        let state_path = path.unwrap_or_else(default_state_path);
        let state = RustylinkState::load_or_default(&state_path)?;
        Ok(Self { state_path, state })
    }

    pub fn save(&mut self) -> Result<()> {
        self.state.save(&self.state_path)
    }

    pub fn api_client(&self) -> Result<ApiClient> {
        let base_url = self
            .state
            .selected_base_url()
            .context(error::MissingBaseUrl)?
            .to_string();
        let client = ApiClient::new(
            base_url,
            self.state.identity.clone(),
            SigningContext::new(self.state.signing.clone()),
            self.state.cookies.clone(),
        )
        .context(error::Api)?;
        client.set_csrf_token(self.state.csrf_token.clone());
        client.set_knock_token(self.state.knock_token.clone());
        Ok(client)
    }

    pub fn sync_from_client(&mut self, client: &ApiClient) {
        self.state.cookies = client.cookies();
    }
}

fn default_state_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("rustylink")
        .join("state.json")
}
