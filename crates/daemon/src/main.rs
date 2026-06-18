//! `rustylinkd` — the Rustylink Connect RPC daemon.
//!
//! Owns HTTP/signing/cookies/tunnel and persists its whole state as a JSON
//! state machine.  Binds a Connect + gRPC + gRPC-Web endpoint on loopback,
//! guarded by a bearer token + loopback Host/Origin checks.

mod auth_layer;
mod daemon;
mod error;
mod server;
mod state;
mod supervisor;
mod token;

use std::{net::SocketAddr, path::PathBuf};

use axum::middleware::from_fn_with_state;
use clap::Parser;
use connectrpc::Router as ConnectRouter;
use rustylink_proto::proto::rustylink::daemon::v1::RustylinkServiceExt as _;
use tracing_subscriber::{EnvFilter, fmt};

use crate::{auth_layer::AuthState, daemon::Daemon, server::Svc, state::DaemonState};

#[derive(Debug, Parser)]
#[command(name = "rustylinkd", version, about = "Rustylink Connect RPC daemon")]
struct Args {
    /// Path to the persisted state file.
    #[arg(long, env = "RUSTYLINKD_STATE_PATH")]
    state_path: Option<PathBuf>,

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

    let state_path = args.state_path.unwrap_or_else(default_state_path);
    tracing::info!(path = %state_path.display(), "loading daemon state");
    let mut state = DaemonState::load_or_default(&state_path)?;

    // Ensure a bearer token exists (first run or rotation).
    ensure_token(&mut state, args.rotate_token);
    state.save(&state_path)?;

    let token_hash = state
        .token_hash
        .clone()
        .expect("token hash is set by ensure_token");

    let daemon = Daemon::new(state, state_path)?;

    // Auto-resume (F2): if we were connected before shutdown and auto-reconnect
    // is enabled, re-establish the tunnel (fresh /vpn/conn, keypair, TOTP).
    daemon.maybe_auto_resume().await;

    let svc = std::sync::Arc::new(Svc::new(daemon));

    let connect = svc.register(ConnectRouter::new());
    let auth_state = AuthState::new(token_hash);
    let app = axum::Router::new()
        .fallback_service(connect.into_axum_service())
        .layer(from_fn_with_state(auth_state, auth_layer::require_auth));

    let listener = tokio::net::TcpListener::bind(args.listen).await?;
    tracing::info!(addr = %args.listen, "rustylinkd listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("rustylinkd shut down cleanly");
    Ok(())
}

/// Generate + print + hash a token on first run or `--rotate-token`.
fn ensure_token(state: &mut DaemonState, rotate: bool) {
    if !rotate && state.token_hash.is_some() {
        return;
    }
    let token = token::generate_token();
    let Some(hash) = token::hash_token(&token) else {
        tracing::error!("failed to hash bearer token");
        return;
    };
    state.token_hash = Some(hash);
    eprintln!("─────────────────────────────────────────────────────────────");
    eprintln!("  rustylinkd bearer token (shown once — store it securely):");
    eprintln!("    {token}");
    eprintln!("─────────────────────────────────────────────────────────────");
}

fn default_state_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("rustylink")
        .join("rustylinkd.state.json")
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
