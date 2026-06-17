#![allow(clippy::module_name_repetitions)]

pub mod client;
pub mod error;
pub mod identity;
pub mod models;
pub mod signing;

pub use client::{
    ApiClient, ApiClientOptions, ApiEndpoint, DEFAULT_MATCH_BASE_URL, DotEndpoint, MatchEndpoint,
    SessionCookies, TenantEndpoint,
};
pub use error::{Error, Result};
pub use identity::ClientIdentity;
pub use models::{
    ActivateInfo, ActivateRequest, ApiResponse, BaseResponse, CommonStringResult,
    GetLoginSettingRequest, GetTenantConfigRequest, GetThirdPartyLoginLinksRequest,
    GetUserInfoRequest, GetVpnExportsRequest, GetVpnLocationsRequest, GetVpnSettingRequest,
    IpDelayRoutingPolicy, JsonObject, LoginResult, LoginSetting, LoginV2Next, LoginV2Result,
    OAuthCallbackRequest, OAuthQueryCallbackRequest, PasswordLoginRequest, SecurityReportItem,
    SecurityReportRequest, SendCodeRequest, SendableRequest, SigningRule, TenantConfig,
    TenantSigningConfig, ThirdPartyLoginInfo, ThirdPartyTokenCheckRequest, UserInfo,
    VerifyCodeRequest, VerifyMfaRequest, VpnConnRequest, VpnConnResponse, VpnConnSetting, VpnDot,
    VpnExportInfo, VpnExportListInfo, VpnLocation, VpnPingRequest, VpnProtocolDetectConfig,
    VpnReportRequest, VpnSetting,
};
pub use signing::{PasswordCipher, SigningConfig, SigningContext, SigningRuleConfig};
