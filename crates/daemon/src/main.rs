//! `rustylinkd` — the Rustylink Connect RPC daemon.
//!
//! Owns auth state (statig), VPN state, and config; persists them as JSON.
//! Serves a Connect + gRPC + gRPC-Web endpoint under the `/api` path prefix,
//! guarded by a bearer token and a restrictive CORS layer. When built with
//! `--features embed-ui`, the built web UI is embedded and served at `/`.
//!
//! Three RPC services are registered:
//!   - `AuthService`  — authentication & session management
//!   - `VpnService`   — VPN tunnel connect/disconnect/watch
//!   - `MetaService`   — ping, user info, configuration

mod auth_layer;
mod daemon;
mod error;
mod latency;
mod persist;
mod service;
mod state;
#[cfg(feature = "embed-ui")]
mod static_assets;
mod supervisor;
mod token;

use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use clap::Parser;
use connectrpc::Router as ConnectRouter;
use rustylink_proto::proto::rustylink::daemon::v1::{
    AuthServiceExt as _, MetaServiceExt as _, VpnServiceExt as _,
};
use snafu::prelude::*;
use tower::ServiceBuilder;
use tower_http::{
    cors::CorsLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, SetRequestIdLayer},
    trace::TraceLayer,
    validate_request::ValidateRequestHeaderLayer,
};
use tracing_subscriber::{EnvFilter, fmt};

use crate::{
    auth_layer::AuthState,
    daemon::Daemon,
    persist::{DaemonConfig, PersistedCredentials},
    service::{auth::AuthServiceImpl, meta::MetaServiceImpl, vpn::VpnServiceImpl},
};

#[derive(Debug, Parser)]
#[command(name = "rustylinkd", version, about = "Rustylink Connect RPC daemon")]
struct Args {
    /// Path to the daemon configuration file.
    #[arg(long, env = "RUSTYLINKD_CONFIG_PATH")]
    config_path: Option<PathBuf>,

    /// Path to the credentials file.
    #[arg(long, env = "RUSTYLINKD_CREDENTIAL_PATH")]
    credential_path: Option<PathBuf>,

    /// Address to bind the Connect RPC server.
    #[arg(long, default_value = "127.0.0.1:7878")]
    listen: SocketAddr,

    /// Regenerate the bearer token (clears + reprints).
    #[arg(long)]
    rotate_token: bool,
}

#[snafu::report]
#[tokio::main]
async fn main() -> Result<(), InitError> {
    let args = Args::parse();

    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    let config_path = args.config_path.unwrap_or_else(default_config_path);
    let credential_path = args.credential_path.unwrap_or_else(default_credential_path);

    tracing::info!(path = %config_path.display(), "loading daemon config");
    let mut config = DaemonConfig::load_or_default(&config_path)
        .await
        .context(LoadConfigSnafu {
            path: config_path.clone(),
        })?;

    // Complete the persisted device identity: generate a full one (with a
    // device id) on first run, or merge missing fields into a partial one,
    // then overwrite the config below with the complete identity.
    if config.identity.ensure_full() {
        tracing::info!("completed device identity in daemon config");
    }

    // Ensure a bearer token exists (first run or rotation).
    let token_hash = ensure_token(&mut config, args.rotate_token)?;
    config.save(&config_path).await.context(SaveConfigSnafu {
        path: config_path.clone(),
    })?;

    tracing::info!(path = %credential_path.display(), "loading credentials");
    let credentials = PersistedCredentials::load(&credential_path)
        .await
        .context(LoadCredentialsSnafu {
            path: credential_path.clone(),
        })?;

    let daemon = Daemon::new(config, config_path, credential_path, credentials);

    // Recognise a restored, previously-authenticated session before anything
    // queries the auth state (otherwise it stays Unconfigured).
    daemon.restore_auth_state().await;

    // Auto-resume: if we were connected before shutdown and auto-reconnect
    // is enabled, re-establish the tunnel.
    daemon.maybe_auto_resume().await;

    // Build three service implementations.
    let auth_svc = AuthServiceImpl::new(daemon.clone());
    let vpn_svc = VpnServiceImpl::new(daemon.clone());
    let meta_svc = MetaServiceImpl::new(daemon);

    // Register all three services with the Connect router.
    let router = ConnectRouter::new();
    let router = Arc::new(auth_svc).register(router);
    let router = Arc::new(vpn_svc).register(router);
    let router = Arc::new(meta_svc).register(router);

    let auth = AuthState::new(token_hash);

    // The Connect RPC surface, guarded by CORS + bearer auth, mounted under
    // `/api` (the prefix is stripped before the Connect service, so wire paths
    // stay `/rustylink.daemon.v1.<Service>/<Method>`). Auth applies ONLY here —
    // static UI assets must load without a token so the user can enter it.
    let api = router.into_axum_router().layer(
        ServiceBuilder::new()
            .layer(CorsLayer::new())
            .layer(ValidateRequestHeaderLayer::custom(auth)),
    );

    let app = axum::Router::new().nest("/api", api);

    // Serve the embedded SPA at `/` (with SPA-fallback) when built with the
    // `embed-ui` feature. Without it, the daemon serves `/api` only and the UI
    // is served by the Vite dev server (which proxies `/api`).
    #[cfg(feature = "embed-ui")]
    let app = app.fallback(static_assets::handler);

    // Outer layers wrap everything: stamp a request id, open a tracing span
    // carrying it, then echo the id on the way out.
    let app = app.layer(
        ServiceBuilder::new()
            .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
            .layer(
                TraceLayer::new_for_http().make_span_with(|request: &axum::extract::Request| {
                    let request_id = request
                        .headers()
                        .get("x-request-id")
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or_default();
                    tracing::info_span!(
                        "request",
                        method = %request.method(),
                        uri = %request.uri(),
                        request_id,
                    )
                }),
            )
            .layer(PropagateRequestIdLayer::x_request_id()),
    );

    let listener = tokio::net::TcpListener::bind(args.listen)
        .await
        .context(BindListenerSnafu { listen: args.listen })?;
    tracing::info!(addr = %args.listen, "rustylinkd listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context(ServeSnafu)?;

    tracing::info!("rustylinkd shut down cleanly");
    Ok(())
}

/// Ensure a bearer token exists, returning its argon2 hash.  On first run or
/// `--rotate-token` a fresh token is generated, printed once to stderr, and its
/// hash stored in `config`; otherwise the existing hash is returned unchanged.
fn ensure_token(config: &mut DaemonConfig, rotate: bool) -> Result<String, InitError> {
    if !config.token_hash.is_empty() && !rotate {
        return Ok(config.token_hash.clone());
    }
    let plain_token = token::generate_token();
    let hash = token::hash_token(&plain_token).context(HashTokenSnafu)?;
    config.token_hash.clone_from(&hash);
    eprintln!("─────────────────────────────────────────────────────────────");
    eprintln!("  rustylinkd bearer token (shown once — store it securely):");
    eprintln!("    {plain_token}");
    eprintln!("─────────────────────────────────────────────────────────────");
    Ok(hash)
}

fn default_config_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("rustylink")
        .join("config.json")
}

fn default_credential_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("rustylink")
        .join("credentials.json")
}

/// Resolve when SIGINT or SIGTERM is received.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };

    #[cfg(unix)]
    let terminate = async {
        if let Ok(mut sig) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            sig.recv().await;
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        () = ctrl_c => tracing::info!("received SIGINT"),
        () = terminate => tracing::info!("received SIGTERM"),
    }
}

/// Fatal errors raised while starting the daemon, before the RPC server begins
/// serving. Surfaced from `main` via [`snafu::Report`] (`#[snafu::report]`) for
/// a clean, fully-sourced error stack instead of a `Box<dyn Error>` debug dump.
#[derive(Debug, Snafu)]
enum InitError {
    #[snafu(display("failed to load daemon config from {}: {source}", path.display()))]
    LoadConfig {
        path: PathBuf,
        source: persist::Error,
    },

    #[snafu(display("failed to save daemon config to {}: {source}", path.display()))]
    SaveConfig {
        path: PathBuf,
        source: persist::Error,
    },

    #[snafu(display("failed to load credentials from {}: {source}", path.display()))]
    LoadCredentials {
        path: PathBuf,
        source: persist::Error,
    },

    #[snafu(display("failed to hash the generated bearer token"))]
    HashToken,

    #[snafu(display("failed to bind the RPC listener to {listen}: {source}"))]
    BindListener {
        listen: SocketAddr,
        source: std::io::Error,
    },

    #[snafu(display("the RPC server terminated unexpectedly: {source}"))]
    Serve { source: std::io::Error },
}
