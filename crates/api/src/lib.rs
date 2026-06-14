#![allow(clippy::missing_errors_doc, clippy::missing_const_for_fn)]

pub mod client;
pub mod error;
pub mod identity;
pub mod models;
pub mod signing;

#[allow(clippy::all, clippy::cargo, clippy::nursery, clippy::pedantic)]
pub mod codegen {
    include!(concat!(env!("OUT_DIR"), "/progenitor.rs"));
}

pub use client::{ApiClient, EndpointPaths, SessionCookies};
pub use error::{Error, Result};
pub use identity::ClientIdentity;
pub use models::*;
pub use signing::{PasswordCipher, SigningConfig, SigningContext, SigningRuleConfig};
