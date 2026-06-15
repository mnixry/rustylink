#![allow(clippy::missing_errors_doc, clippy::missing_const_for_fn)]

pub mod client;
pub mod error;
pub mod identity;
pub mod signing;

#[allow(clippy::all, clippy::cargo, clippy::nursery, clippy::pedantic)]
pub mod codegen {
    include!(concat!(env!("OUT_DIR"), "/progenitor.rs"));
}

pub type JsonObject = serde_json::Map<String, serde_json::Value>;

pub use client::{ApiClient, SessionCookies};
pub use codegen::types::{
    ActivateInfo, ActivateRequest, ActivateResponse, GetLoginSettingResponse,
    GetTenantConfigResponse, GetUserInfoResponse, GetVpnLocationsResponse, GetVpnSettingResponse,
    LoginByPasswordResponse, LoginResult, LoginSetting, OAuthCallbackRequest,
    OauthCallbackResponse, PasswordLoginRequest, ReportSecurityResponse, SecurityReportItem,
    SecurityReportRequest, SendCodeRequest, SendLoginCodeResponse,
    SigningConfig as TenantSigningConfig, SigningRule, TenantConfig, UserInfo, VerifyCodeRequest,
    VerifyLoginCodeResponse, VerifyMfaRequest, VerifyMfaResponse, VpnConnEnvelope, VpnConnRequest,
    VpnConnResponse, VpnConnSetting, VpnDot, VpnLocation, VpnSetting,
};
pub use error::{Error, Result};
pub use identity::ClientIdentity;
pub use signing::{PasswordCipher, SigningConfig, SigningContext, SigningRuleConfig};
