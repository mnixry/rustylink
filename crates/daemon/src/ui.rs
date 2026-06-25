use axum::{
    extract::Request,
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use rust_embed::RustEmbed;

#[derive(RustEmbed)]
#[folder = "../../ui/dist"]
#[allow_missing = true]
struct Assets;

impl Assets {
    const INDEX_HTML: &str = "index.html";

    fn serve(path: &str) -> Response {
        let Some(asset) = Self::get(path).or_else(|| Self::get(Self::INDEX_HTML)) else {
            return StatusCode::NOT_FOUND.into_response();
        };
        (
            [(header::CONTENT_TYPE, asset.metadata.mimetype())],
            asset.data.into_owned(),
        )
            .into_response()
    }
}

/// Serve an embedded asset for `req`, or fall back to `index.html`.
pub async fn handler(req: Request) -> Response {
    Assets::serve(req.uri().path().trim_start_matches('/'))
}
