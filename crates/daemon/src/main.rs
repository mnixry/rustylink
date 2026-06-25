//! The `rustylinkd` Connect RPC daemon.
//!
//! Owns auth state, VPN state, and config; persists them as JSON.
//! Serves a Connect + gRPC + gRPC-Web endpoint under the `/api` path prefix,
//! guarded by a bearer token and a restrictive CORS layer. When built with
//! `--features embed-ui`, the built web UI is embedded and served at `/`.
//!
//! Three RPC services are registered:
//!   - `AuthService`  — authentication & session management
//!   - `VpnService`   — VPN tunnel connect/disconnect/watch
//!   - `MetaService`   — ping, user info, configuration

mod daemon;
mod error;
mod latency;
mod persist;
mod service;
mod state;
mod supervisor;
mod token;
mod ui;

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

use clap::Parser;
use connectrpc::Router as ConnectRouter;
use rustylink_proto::proto::rustylink::daemon::v1::{
    AuthServiceExt as _, MetaServiceExt as _, VpnServiceExt as _,
};
use snafu::prelude::*;
use tower::ServiceBuilder;
use tower_http::{
    cors::CorsLayer,
    request_id::{MakeRequestUuid, PropagateRequestIdLayer, RequestId, SetRequestIdLayer},
    trace::TraceLayer,
    validate_request::ValidateRequestHeaderLayer,
};
use tracing_subscriber::{EnvFilter, fmt};

use crate::{
    daemon::Daemon,
    persist::{DaemonConfig, PersistedCredentials},
    service::{auth::AuthServiceImpl, meta::MetaServiceImpl, vpn::VpnServiceImpl},
};

#[derive(Debug, Parser)]
#[command(version, about = "CorpLink VPN daemon")]
struct Args {
    /// Directory holding `config.json` and `credentials.json`.
    #[arg(long, env = "RUSTYLINKD_CONFIG_DIR")]
    config_dir: Option<PathBuf>,

    /// Address to bind the Connect RPC server.
    #[arg(long, default_value = "127.0.0.1:7878")]
    listen: SocketAddr,

    /// Log filter in `tracing` `EnvFilter` syntax, e.g.
    /// `info,rustylink_tunnel=trace,gotatun=debug`. Reads `RUST_LOG` when the
    /// flag is omitted; defaults to `debug` in debug builds, `info` in release.
    #[arg(long, env = "RUST_LOG", default_value = default_log_level())]
    log_level: String,
}

/// Default log filter: verbose in debug builds, quiet in release. Overridden by
/// `--log-level` or `RUST_LOG`.
fn default_log_level() -> &'static str {
    if cfg!(debug_assertions) {
        "debug"
    } else {
        "info"
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

    #[snafu(display("failed to parse log level {log_level:?}: {source}"))]
    LogLevelParse {
        log_level: String,
        source: tracing_subscriber::filter::ParseError,
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

    #[snafu(display("failed to bind the RPC listener to {listen}: {source}"))]
    BindListener {
        listen: SocketAddr,
        source: std::io::Error,
    },

    #[snafu(display("the RPC server terminated unexpectedly: {source}"))]
    Serve { source: std::io::Error },
}

#[snafu::report]
#[tokio::main]
async fn main() -> Result<(), InitError> {
    let args = Args::parse();

    fmt()
        .with_env_filter(
            EnvFilter::try_new(&args.log_level).context(LogLevelParseSnafu {
                log_level: args.log_level.clone(),
            })?,
        )
        .with_writer(std::io::stderr)
        .init();

    let config_dir = args.config_dir.unwrap_or_else(default_config_dir);
    let config_path = config_dir.join("config.json");
    let credential_path = config_dir.join("credentials.json");

    tracing::info!(path = %config_path.display(), "loading daemon config");
    let mut config =
        DaemonConfig::load_or_default(&config_path)
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
    config.save(&config_path).await.context(SaveConfigSnafu {
        path: config_path.clone(),
    })?;

    // A fresh access token is generated each run and never persisted; the
    // access URLs below carry it as a `?token=` query the UI captures.
    let token = token::generate_token();

    tracing::info!(path = %credential_path.display(), "loading credentials");
    let credentials =
        PersistedCredentials::load(&credential_path)
            .await
            .context(LoadCredentialsSnafu {
                path: credential_path.clone(),
            })?;

    let daemon = Daemon::new(config, config_path, credential_path, credentials).await;

    // Persist refreshed session cookies as the shared jar absorbs them.
    daemon.install_cookie_persist_listener().await;

    // Recognise a restored, previously-authenticated session before anything
    // queries the auth state (otherwise it stays Unconfigured).
    daemon.restore_auth_state().await;

    // Auto-resume: if we were connected before shutdown and auto-reconnect
    // is enabled, re-establish the tunnel.
    daemon.maybe_auto_resume().await;

    // Build three service implementations.
    let auth_svc = AuthServiceImpl::new(daemon.clone());
    let vpn_svc = VpnServiceImpl::new(daemon.clone());
    let meta_svc = MetaServiceImpl::new(daemon.clone());

    // Register all three services with the Connect router.
    let router = ConnectRouter::new();
    let router = Arc::new(auth_svc).register(router);
    let router = Arc::new(vpn_svc).register(router);
    let router = Arc::new(meta_svc).register(router);

    // The Connect RPC surface, guarded by CORS + bearer auth, mounted under
    // `/api` (the prefix is stripped before the Connect service, so wire paths
    // stay `/rustylink.daemon.v1.<Service>/<Method>`). Auth applies ONLY here —
    // static UI assets must load without a token so the `?token=` capture works.
    //
    // tower-http deprecates `bearer` as "too basic" for general web apps, but a
    // static, per-run token compared against one `Authorization: Bearer` header
    // is exactly what this local daemon needs.
    #[allow(deprecated)]
    let api = router.into_axum_router().layer(
        ServiceBuilder::new()
            .layer(CorsLayer::new())
            .layer(ValidateRequestHeaderLayer::bearer(&token)),
    );

    let app = axum::Router::new()
        .nest("/api", api)
        .fallback(ui::handler)
        .layer(
            ServiceBuilder::new()
                .layer(SetRequestIdLayer::x_request_id(MakeRequestUuid))
                .layer(TraceLayer::new_for_http().make_span_with(
                    |request: &axum::extract::Request| {
                        let request_id = request
                            .extensions()
                            .get::<RequestId>()
                            .and_then(|value| value.header_value().to_str().ok())
                            .unwrap_or_default();
                        tracing::info_span!(
                            "request",
                            method = %request.method(),
                            uri = %request.uri(),
                            request_id,
                        )
                    },
                ))
                .layer(PropagateRequestIdLayer::x_request_id()),
        );

    let listener = tokio::net::TcpListener::bind(args.listen)
        .await
        .context(BindListenerSnafu {
            listen: args.listen,
        })?;
    tracing::info!(addr = %args.listen, "daemon listening");
    for url in access_urls(args.listen, &token) {
        tracing::info!("open the web UI at {url}");
    }
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context(ServeSnafu)?;

    // Graceful tunnel teardown: cancel the supervise task, await it, and
    // clean up OS state (routes, route-bypass rules, WireGuard device).
    // Without this, a signal-initiated shutdown leaks /1 routes and scoped
    // default routes in the OS routing table.
    tracing::info!("shutting down tunnel...");
    match daemon.disconnect_tunnel().await {
        Ok(_) => tracing::info!("tunnel teardown complete"),
        Err(e) => tracing::warn!(%e, "tunnel teardown failed"),
    }

    tracing::info!("shutdown complete");
    Ok(())
}

/// Build the `http://<host>:<port>/?token=<token>` URLs the UI can be opened
/// with. When the listen address is unspecified (e.g. `0.0.0.0`), every
/// non-loopback interface address is listed alongside localhost; otherwise only
/// the configured address is shown.
fn access_urls(listen: SocketAddr, token: &str) -> Vec<String> {
    let port = listen.port();
    let mut hosts: Vec<IpAddr> = Vec::new();
    if listen.ip().is_unspecified() {
        hosts.push(IpAddr::V4(Ipv4Addr::LOCALHOST));
        for interface in default_net::get_interfaces() {
            if interface.is_loopback() {
                continue;
            }
            hosts.extend(interface.ipv4.into_iter().map(|net| IpAddr::V4(net.addr)));
        }
    } else {
        hosts.push(listen.ip());
    }
    hosts
        .into_iter()
        .map(|host| format!("http://{}/?token={token}", SocketAddr::new(host, port)))
        .collect()
}

fn default_config_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("rustylink")
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
