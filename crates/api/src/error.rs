use snafu::prelude::*;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub(crate)), context(suffix(false)))]
pub enum Error {
    #[snafu(display("invalid base URL `{value}`"))]
    InvalidBaseUrl {
        value: String,
        source: url::ParseError,
    },

    #[snafu(display("failed to build HTTP client"))]
    BuildHttpClient { source: reqwest::Error },

    #[snafu(display("HTTP request failed: {method} {url}"))]
    HttpRequest {
        method: String,
        url: String,
        source: reqwest::Error,
    },

    #[snafu(display("failed to decode response body from {url}"))]
    DecodeResponse { url: String, source: reqwest::Error },

    #[snafu(display("failed to serialize request body"))]
    EncodeRequest { source: serde_json::Error },

    #[snafu(display("failed to build header `{name}`"))]
    HeaderValue {
        name: String,
        source: reqwest::header::InvalidHeaderValue,
    },

    #[snafu(display("failed to build header name `{name}`"))]
    HeaderName {
        name: String,
        source: reqwest::header::InvalidHeaderName,
    },

    #[snafu(display("failed to sign request"))]
    SignRequest {
        source: crate::signing::SigningError,
    },

    #[snafu(display("failed to encrypt password"))]
    EncryptPassword {
        source: crate::signing::PasswordCipherError,
    },

    #[snafu(display("API returned code {code}: {message}"))]
    ApiStatus { code: i32, message: String },
}

pub type Result<T, E = Error> = std::result::Result<T, E>;
