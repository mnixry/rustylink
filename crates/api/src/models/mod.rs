macro_rules! impl_json_request {
    ($ty:ty, $method:ident, $path:literal, $response:ty) => {
        #[async_trait::async_trait]
        impl $crate::models::SendableRequest for $ty {
            type Response = $response;

            const METHOD: reqwest::Method = reqwest::Method::$method;

            fn path(&self) -> std::borrow::Cow<'static, str> {
                std::borrow::Cow::Borrowed($path)
            }

            fn body(&self) -> std::result::Result<Option<Vec<u8>>, serde_json::Error> {
                serde_json::to_vec(self).map(Some)
            }
        }
    };
}

macro_rules! impl_empty_request {
    ($ty:ty, $method:ident, $path:literal, $response:ty) => {
        #[async_trait::async_trait]
        impl $crate::models::SendableRequest for $ty {
            type Response = $response;

            const METHOD: reqwest::Method = reqwest::Method::$method;

            fn path(&self) -> std::borrow::Cow<'static, str> {
                std::borrow::Cow::Borrowed($path)
            }
        }
    };
}

pub mod auth;
pub mod common;
pub mod profile;
pub mod security;
pub mod vpn;

pub use auth::*;
pub use common::{ApiResponse, BaseResponse, JsonObject, LogoutReason, SendableRequest};
pub use profile::*;
pub use security::*;
pub use vpn::*;
