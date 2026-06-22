use std::borrow::Cow;

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;
use snafu::ResultExt as _;

use super::{BaseResponse, JsonObject, SendableRequest};
use crate::signing::PasswordCipher;

/// RFC 3986 *unreserved* set (`ALPHA / DIGIT / "-" / "." / "_" / "~"`). Every
/// other byte in a path segment is percent-encoded (uppercase hex), so a value
/// containing `/` cannot break out of its path segment.
const PATH_SEGMENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

// ---------------------------------------------------------------------------
// Activate
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivateRequest {
    pub code: String,
}

impl_json_request!(
    ActivateRequest,
    POST,
    "/api/match",
    BaseResponse<ActivateInfo>
);

#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ActivateInfo {
    pub activate_host: Option<String>,
    pub activate_backup_domain: Option<String>,
    pub activate_enable_backup_domain: Option<bool>,
    pub tenant_name: Option<String>,
    pub name: Option<String>,
    pub zh_name: Option<String>,
    pub en_name: Option<String>,
    pub domain: Option<String>,
    pub enable_self_signed: Option<bool>,
    pub self_signed_cert: Option<String>,
    pub enable_public_key: Option<bool>,
    pub public_key: Option<String>,
    pub raw: Option<JsonObject>,
}

// ---------------------------------------------------------------------------
// Legacy login (pre-v1)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordLoginRequest {
    pub login_scene: String,
    pub account_type: String,
    pub account: String,
    pub password: String,
}

impl PasswordLoginRequest {
    pub fn encrypted(
        login_scene: String, account_type: String, account: String, password: &str,
    ) -> crate::client::Result<Self> {
        let password = PasswordCipher::generated()
            .encrypt_aes_cbc(password)
            .context(crate::client::EncryptPasswordSnafu)?;
        Ok(Self {
            login_scene,
            account_type,
            account,
            password,
        })
    }
}

impl_json_request!(
    PasswordLoginRequest,
    POST,
    "/api/login",
    BaseResponse<LoginV2Result>
);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SendCodeRequest {
    pub login_scene: String,
    pub account_type: String,
    pub login_type: String,
    pub account: String,
}

impl_json_request!(
    SendCodeRequest,
    POST,
    "/api/login/code/send",
    BaseResponse<CommonStringResult>
);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyCodeRequest {
    pub login_scene: String,
    pub account_type: String,
    pub login_type: String,
    pub account: String,
    pub code: String,
}

impl_json_request!(
    VerifyCodeRequest,
    POST,
    "/api/login/code/verify",
    BaseResponse<LoginV2Result>
);

#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyMfaRequest {
    pub login_scene: String,
    pub mfa_type: String,
    pub account: String,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

impl VerifyMfaRequest {
    pub fn encrypted(
        login_scene: String, mfa_type: String, account: String, code: Option<String>,
        password: Option<String>,
    ) -> crate::client::Result<Self> {
        let password = password
            .map(|value| {
                PasswordCipher::generated()
                    .encrypt_aes_cbc(&value)
                    .context(crate::client::EncryptPasswordSnafu)
            })
            .transpose()?;
        Ok(Self {
            login_scene,
            mfa_type,
            account,
            code,
            password,
        })
    }
}

impl_json_request!(
    VerifyMfaRequest,
    POST,
    "/api/mfa/code/verify",
    BaseResponse<LoginV2Result>
);

// ---------------------------------------------------------------------------
// V1 login (newer flow)
// ---------------------------------------------------------------------------

/// `POST /api/v1/login`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct V1LoginRequest {
    pub login_scene: String,
    pub account_type: String,
    pub account: String,
    pub password: String,
}

impl V1LoginRequest {
    pub fn encrypted(
        login_scene: String, account_type: String, account: String, password: &str,
    ) -> crate::client::Result<Self> {
        let password = PasswordCipher::generated()
            .encrypt_aes_cbc(password)
            .context(crate::client::EncryptPasswordSnafu)?;
        Ok(Self {
            login_scene,
            account_type,
            account,
            password,
        })
    }
}

impl_json_request!(
    V1LoginRequest,
    POST,
    "/api/v1/login",
    BaseResponse<LoginV2Result>
);

/// `POST /api/v1/login/send`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct V1SendCodeRequest {
    pub login_scene: String,
    pub account_type: String,
    pub login_type: String,
    pub account: String,
}

impl_json_request!(
    V1SendCodeRequest,
    POST,
    "/api/v1/login/send",
    BaseResponse<CommonStringResult>
);

/// `POST /api/v1/login/verify`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct V1VerifyCodeRequest {
    pub login_scene: String,
    pub account_type: String,
    pub login_type: String,
    pub account: String,
    pub code: String,
}

impl_json_request!(
    V1VerifyCodeRequest,
    POST,
    "/api/v1/login/verify",
    BaseResponse<LoginV2Result>
);

/// `POST /api/v1/login/mfa/send`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct V1MfaSendRequest {
    pub login_scene: String,
    pub mfa_type: String,
    pub account: String,
}

impl_json_request!(
    V1MfaSendRequest,
    POST,
    "/api/v1/login/mfa/send",
    BaseResponse<CommonStringResult>
);

/// `POST /api/v1/login/mfa/verify`
#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct V1MfaVerifyRequest {
    pub login_scene: String,
    pub mfa_type: String,
    pub account: String,
    #[serde(default)]
    pub code: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

impl V1MfaVerifyRequest {
    pub fn encrypted(
        login_scene: String, mfa_type: String, account: String, code: Option<String>,
        password: Option<String>,
    ) -> crate::client::Result<Self> {
        let password = password
            .map(|value| {
                PasswordCipher::generated()
                    .encrypt_aes_cbc(&value)
                    .context(crate::client::EncryptPasswordSnafu)
            })
            .transpose()?;
        Ok(Self {
            login_scene,
            mfa_type,
            account,
            code,
            password,
        })
    }
}

impl_json_request!(
    V1MfaVerifyRequest,
    POST,
    "/api/v1/login/mfa/verify",
    BaseResponse<LoginV2Result>
);

/// `POST /api/v1/login/skip`
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct V1LoginSkipRequest {
    pub login_scene: String,
    pub account: String,
}

impl_json_request!(
    V1LoginSkipRequest,
    POST,
    "/api/v1/login/skip",
    BaseResponse<LoginV2Result>
);

// ---------------------------------------------------------------------------
// Logout
// ---------------------------------------------------------------------------

/// `GET /api/logout`
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LogoutRequest {
    pub logout_all: bool,
}

#[async_trait::async_trait]
impl SendableRequest for LogoutRequest {
    type Response = BaseResponse<serde_json::Value>;

    const METHOD: reqwest::Method = reqwest::Method::GET;

    fn path(&self) -> Cow<'static, str> {
        Cow::Borrowed("/api/logout")
    }

    fn query_pairs(&self) -> Vec<(&'static str, String)> {
        vec![("logout_all", self.logout_all.to_string())]
    }
}

// ---------------------------------------------------------------------------
// Third-party / OAuth login
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthCallbackRequest {
    pub alias_key: String,
    pub code: String,
    pub state: String,
    pub code_verifier: String,
}

impl_json_request!(
    OAuthCallbackRequest,
    POST,
    "/api/tpslogin/callback",
    BaseResponse<LoginResult>
);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthQueryCallbackRequest {
    pub alias: String,
    pub code: String,
    pub state: String,
}

#[async_trait::async_trait]
impl SendableRequest for OAuthQueryCallbackRequest {
    type Response = BaseResponse<LoginResult>;

    const METHOD: reqwest::Method = reqwest::Method::GET;

    fn path(&self) -> Cow<'static, str> {
        Cow::Owned(format!(
            "/api/tpslogin/callback/{}",
            utf8_percent_encode(&self.alias, PATH_SEGMENT)
        ))
    }

    fn query_pairs(&self) -> Vec<(&'static str, String)> {
        vec![("code", self.code.clone()), ("state", self.state.clone())]
    }
}

/// `POST /api/tpslogin/device/callback`
#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceOAuthCallbackRequest {
    pub alias_key: String,
    pub code: String,
    pub state: String,
    #[serde(default)]
    pub code_verifier: Option<String>,
}

impl_json_request!(
    DeviceOAuthCallbackRequest,
    POST,
    "/api/tpslogin/device/callback",
    BaseResponse<LoginV2Result>
);

#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetThirdPartyLoginLinksRequest {
    pub code_challenge: Option<String>,
}

#[async_trait::async_trait]
impl SendableRequest for GetThirdPartyLoginLinksRequest {
    type Response = BaseResponse<Vec<ThirdPartyLoginInfo>>;

    const METHOD: reqwest::Method = reqwest::Method::GET;

    fn path(&self) -> Cow<'static, str> {
        Cow::Borrowed("/api/tpslogin/link")
    }

    fn query_pairs(&self) -> Vec<(&'static str, String)> {
        // With a code_challenge the server returns a PKCE OAuth login_url (no
        // poll token); without it, the server returns a poll `token` for the
        // device/QR flow. We rely on this distinction.
        match &self.code_challenge {
            Some(challenge) if !challenge.is_empty() => {
                vec![("code_challenge", challenge.clone())]
            }
            _ => Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThirdPartyTokenCheckRequest {
    pub token: String,
}

impl_json_request!(
    ThirdPartyTokenCheckRequest,
    POST,
    "/api/tpslogin/token/check",
    BaseResponse<LoginResult>
);

// ---------------------------------------------------------------------------
// Response / result types
// ---------------------------------------------------------------------------

#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CommonStringResult {
    pub result: Option<String>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LoginV2Result {
    pub result: Option<String>,
    pub next: Option<LoginV2Next>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LoginV2Next {
    pub action: Option<String>,
    #[serde(rename = "canSkip", alias = "can_skip")]
    pub can_skip: Option<bool>,
    #[serde(rename = "authList", alias = "auth_list")]
    pub auth_list: Option<Vec<String>>,
    pub mobile: Option<String>,
    pub email: Option<String>,
    #[serde(rename = "passwordRule", alias = "password_rule")]
    pub password_rule: Option<JsonObject>,
    pub link: Option<String>,
    #[serde(rename = "passkeyUid", alias = "passkey_uid")]
    pub passkey_uid: Option<String>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LoginResult {
    #[serde(rename = "loginResult", alias = "login_result")]
    pub login_result: Option<String>,
    pub url: Option<String>,
    pub auth: Option<serde_json::Value>,
    pub timestamp: Option<i64>,
    #[serde(rename = "needVerify", alias = "need_verify")]
    pub need_verify: Option<bool>,
    pub token: Option<String>,
    pub vpn_token: Option<String>,
    #[serde(rename = "csrf-token", alias = "csrf_token")]
    pub csrf_token: Option<String>,
    pub uid: Option<String>,
    pub need_mfa: Option<bool>,
    pub mfa_token: Option<String>,
    pub raw: Option<JsonObject>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ThirdPartyLoginInfo {
    pub alias: Option<String>,
    #[serde(rename = "aliasKey", alias = "alias_key")]
    pub alias_key: Option<String>,
    pub name: Option<String>,
    pub link: Option<String>,
    pub url: Option<String>,
    #[serde(rename = "loginUrl", alias = "login_url")]
    pub login_url: Option<String>,
    pub token: Option<String>,
    pub state: Option<String>,
    pub schema: Option<String>,
    pub appid: Option<String>,
    pub agentid: Option<String>,
    pub scope: Option<String>,
    pub notice: Option<String>,
    #[serde(rename = "isCustom", alias = "is_custom")]
    pub is_custom: Option<bool>,
    #[serde(rename = "fullTitle", alias = "full_title")]
    pub full_title: Option<String>,
    pub icon: Option<String>,
    pub abbreviation: Option<String>,
    pub raw: Option<JsonObject>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oauth_query_callback_alias_is_path_segment_encoded() {
        let request = OAuthQueryCallbackRequest {
            alias: "foo/bar".to_string(),
            code: "code".to_string(),
            state: "state".to_string(),
        };

        assert_eq!(request.path(), "/api/tpslogin/callback/foo%2Fbar");
    }

    #[test]
    fn send_code_response_accepts_android_common_string_result() {
        let response = serde_json::from_str::<BaseResponse<CommonStringResult>>(
            r#"{"code":0,"data":{"result":"ok"}}"#,
        )
        .expect("decode");

        assert_eq!(
            response.data.and_then(|data| data.result),
            Some("ok".to_string())
        );
    }

    #[test]
    fn logout_response_accepts_android_token_or_result_payload() {
        type LogoutResponse = <LogoutRequest as SendableRequest>::Response;

        serde_json::from_str::<LogoutResponse>(r#"{"code":0,"data":{"token":"next"}}"#)
            .expect("decode token payload");
        serde_json::from_str::<LogoutResponse>(r#"{"code":0,"data":{"result":"success"}}"#)
            .expect("decode result payload");
    }

    #[test]
    fn login_v2_result_accepts_android_next_bean_keys() {
        let response = serde_json::from_str::<BaseResponse<LoginV2Result>>(
            r#"{
                "code": 0,
                "data": {
                    "result": "next",
                    "next": {
                        "action": "verify_code",
                        "canSkip": true,
                        "authList": ["otp", "mobile"],
                        "mobile": "+1******1234",
                        "email": "user@example.com",
                        "passwordRule": {"min": 8},
                        "link": "https://example.invalid/reset",
                        "passkeyUid": "passkey-user"
                    }
                }
            }"#,
        )
        .expect("decode");

        let next = response.data.and_then(|data| data.next).expect("next");
        assert_eq!(next.can_skip, Some(true));
        assert_eq!(
            next.auth_list,
            Some(vec!["otp".to_string(), "mobile".to_string()])
        );
        assert_eq!(next.passkey_uid, Some("passkey-user".to_string()));
        assert!(next.password_rule.is_some());
    }

    #[test]
    fn third_party_login_info_accepts_android_camel_case_keys() {
        let provider = serde_json::from_str::<ThirdPartyLoginInfo>(
            r#"{
                "alias": "lark",
                "aliasKey": "lark_default",
                "loginUrl": "https://example.invalid/qr",
                "isCustom": false,
                "fullTitle": "Lark",
                "token": "poll-token"
            }"#,
        )
        .expect("decode");

        assert_eq!(provider.alias_key, Some("lark_default".to_string()));
        assert_eq!(
            provider.login_url,
            Some("https://example.invalid/qr".to_string())
        );
        assert_eq!(provider.is_custom, Some(false));
        assert_eq!(provider.full_title, Some("Lark".to_string()));
    }

    #[test]
    fn login_result_accepts_android_third_party_result_keys() {
        let response = serde_json::from_str::<BaseResponse<LoginResult>>(
            r#"{
                "code": 0,
                "data": {
                    "loginResult": "success",
                    "url": "corplink://callback",
                    "auth": {"method": "lark"},
                    "timestamp": 1710000000,
                    "needVerify": false
                }
            }"#,
        )
        .expect("decode");

        let data = response.data.expect("data");
        assert_eq!(data.login_result, Some("success".to_string()));
        assert_eq!(data.need_verify, Some(false));
        assert!(data.auth.is_some());
    }
}
