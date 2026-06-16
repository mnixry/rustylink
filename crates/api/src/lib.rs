#![allow(clippy::module_name_repetitions)]

include!(concat!(env!("OUT_DIR"), "/openapi_modules.rs"));

pub mod api;
pub mod client;
pub mod error;
pub mod identity;
pub mod signing;

pub mod codegen {
    pub use crate::{apis, models};
}

pub type JsonObject = std::collections::HashMap<String, serde_json::Value>;
pub type VpnExportInfo = JsonObject;

pub use client::{
    ApiClient, ApiClientOptions, DEFAULT_MATCH_BASE_URL, RawApiError, SessionCookies, VpnDotServers,
};
pub use error::{Error, Result};
pub use identity::ClientIdentity;
pub use models::{
    ActivateInfo, ActivateRequest, ActivateResponse, GetLoginSettingResponse,
    GetTenantConfigResponse, GetThirdPartyLoginLinksResponse, GetUserInfoResponse,
    GetVpnExportsResponse, GetVpnLocationsResponse, GetVpnSettingResponse, LoginByPasswordResponse,
    LoginResult, LoginSetting, OAuthCallbackRequest, OauthCallbackResponse, PasswordLoginRequest,
    ReportSecurityResponse, ReportVpnResponse, SecurityReportItem, SecurityReportRequest,
    SendCodeRequest, SendLoginCodeResponse, SigningConfig as TenantSigningConfig, SigningRule,
    TenantConfig, ThirdPartyLoginInfo, ThirdPartyTokenCheckRequest, ThirdPartyTokenCheckResponse,
    ThirdPartyTokenCheckResult, UserInfo, VerifyCodeRequest, VerifyLoginCodeResponse,
    VerifyMfaRequest, VerifyMfaResponse, VpnConnEnvelope, VpnConnRequest, VpnConnResponse,
    VpnConnSetting, VpnDot, VpnExportListInfo, VpnLocation, VpnPingResponse, VpnReportRequest,
    VpnSetting,
};
pub use signing::{PasswordCipher, SigningConfig, SigningContext, SigningRuleConfig};
