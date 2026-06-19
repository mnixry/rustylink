//! `rustylinkd` — the Rustylink Connect RPC daemon.
//!
//! Owns auth state (statig), VPN state, and config; persists them as JSON.
//! Binds a Connect + gRPC + gRPC-Web endpoint on loopback (enforced at bind
//! time), guarded by a bearer token and a restrictive CORS layer.
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
mod supervisor;
mod token;

use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use clap::Parser;
use connectrpc::Router as ConnectRouter;
use rustylink_proto::proto::rustylink::daemon::v1::{
    AuthServiceExt as _, MetaServiceExt as _, VpnServiceExt as _,
};
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

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_writer(std::io::stderr)
        .init();

    // Network isolation: only ever bind loopback.
    if !args.listen.ip().is_loopback() {
        return Err(format!(
            "refusing to bind non-loopback address {}; rustylinkd only listens on loopback",
            args.listen
        )
        .into());
    }

    let config_path = args.config_path.unwrap_or_else(default_config_path);
    let credential_path = args.credential_path.unwrap_or_else(default_credential_path);

    tracing::info!(path = %config_path.display(), "loading daemon config");
    let mut config = DaemonConfig::load_or_default(&config_path).await?;

    // Ensure a bearer token exists (first run or rotation).
    let token_hash = ensure_token(&mut config, args.rotate_token)?;
    config.save(&config_path).await?;

    tracing::info!(path = %credential_path.display(), "loading credentials");
    let credentials = PersistedCredentials::load(&credential_path).await?;

    let daemon = Daemon::new(config, config_path, credential_path, credentials);

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

    // Layer stack (outermost first): stamp a request id, open a tracing span
    // carrying it, reject cross-origin browser requests (CORS), verify the
    // bearer token, then echo the id on the way out.
    let app = axum::Router::new()
        .fallback_service(router.into_axum_service())
        .layer(
            ServiceBuilder::new()
                .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
                .layer(TraceLayer::new_for_http().make_span_with(
                    |request: &axum::extract::Request| {
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
                    },
                ))
                .layer(CorsLayer::new())
                .layer(ValidateRequestHeaderLayer::custom(auth))
                .layer(PropagateRequestIdLayer::x_request_id()),
        );

    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    tracing::info!(addr = %args.listen, "rustylinkd listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("rustylinkd shut down cleanly");
    Ok(())
}

/// Ensure a bearer token exists, returning its argon2 hash.  On first run or
/// `--rotate-token` a fresh token is generated, printed once to stderr, and its
/// hash stored in `config`; otherwise the existing hash is returned unchanged.
fn ensure_token(
    config: &mut DaemonConfig, rotate: bool,
) -> Result<String, Box<dyn std::error::Error>> {
    if !config.token_hash.is_empty() && !rotate {
        return Ok(config.token_hash.clone());
    }
    let plain_token = token::generate_token();
    let hash = token::hash_token(&plain_token).ok_or("failed to hash bearer token")?;
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
