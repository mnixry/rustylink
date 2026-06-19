//! Embedded web UI assets, served from axum when built with `--features
//! embed-ui`.
//!
//! The built SPA (`ui/dist`) is baked into the binary via `rust-embed`. Any
//! request that does not match an embedded asset falls back to `index.html`
//! so client-side (React Router) routes resolve on a hard refresh.

use axum::{
    extract::Request,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "../../ui/dist"]
struct Assets;

/// Serve an embedded asset for `req`, or fall back to `index.html`.
pub async fn handler(req: Request) -> Response {
    serve(req.uri().path().trim_start_matches('/'))
}

fn serve(path: &str) -> Response {
    let candidate = if path.is_empty() { "index.html" } else { path };

    if let Some(asset) = Assets::get(candidate) {
        let mime = mime_guess::from_path(candidate).first_or_octet_stream();
        return (
            [(header::CONTENT_TYPE, mime.as_ref())],
            asset.data.into_owned(),
        )
            .into_response();
    }

    // SPA fallback: unknown path -> serve index.html for client-side routing.
    Assets::get("index.html").map_or_else(
        || StatusCode::NOT_FOUND.into_response(),
        |index| {
            (
                [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
                index.data.into_owned(),
            )
                .into_response()
        },
    )
}
