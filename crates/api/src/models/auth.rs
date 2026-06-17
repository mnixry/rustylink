use std::borrow::Cow;

use serde::{Deserialize, Serialize};
use snafu::ResultExt as _;

use super::{BaseResponse, JsonObject, SendableRequest};
use crate::signing::PasswordCipher;

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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActivateInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activate_host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activate_backup_domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub activate_enable_backup_domain: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub zh_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub en_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_self_signed: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_signed_cert: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enable_public_key: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<JsonObject>,
}

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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifyMfaRequest {
    pub login_scene: String,
    pub mfa_type: String,
    pub account: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
            encode_path_segment(&self.alias)
        ))
    }

    fn query_pairs(&self) -> Vec<(&'static str, String)> {
        vec![("code", self.code.clone()), ("state", self.state.clone())]
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetThirdPartyLoginLinksRequest {
    pub code_challenge: String,
}

#[async_trait::async_trait]
impl SendableRequest for GetThirdPartyLoginLinksRequest {
    type Response = BaseResponse<Vec<ThirdPartyLoginInfo>>;

    const METHOD: reqwest::Method = reqwest::Method::GET;

    fn path(&self) -> Cow<'static, str> {
        Cow::Borrowed("/api/tpslogin/link")
    }

    fn query_pairs(&self) -> Vec<(&'static str, String)> {
        vec![("code_challenge", self.code_challenge.clone())]
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommonStringResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginV2Result {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next: Option<LoginV2Next>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginV2Next {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(
        default,
        rename = "canSkip",
        alias = "can_skip",
        skip_serializing_if = "Option::is_none"
    )]
    pub can_skip: Option<bool>,
    #[serde(
        default,
        rename = "authList",
        alias = "auth_list",
        skip_serializing_if = "Option::is_none"
    )]
    pub auth_list: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mobile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(
        default,
        rename = "passwordRule",
        alias = "password_rule",
        skip_serializing_if = "Option::is_none"
    )]
    pub password_rule: Option<JsonObject>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
    #[serde(
        default,
        rename = "passkeyUid",
        alias = "passkey_uid",
        skip_serializing_if = "Option::is_none"
    )]
    pub passkey_uid: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginResult {
    #[serde(
        default,
        rename = "loginResult",
        alias = "login_result",
        skip_serializing_if = "Option::is_none"
    )]
    pub login_result: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<i64>,
    #[serde(
        default,
        rename = "needVerify",
        alias = "need_verify",
        skip_serializing_if = "Option::is_none"
    )]
    pub need_verify: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpn_token: Option<String>,
    #[serde(
        default,
        rename = "csrf-token",
        alias = "csrf_token",
        skip_serializing_if = "Option::is_none"
    )]
    pub csrf_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub need_mfa: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mfa_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<JsonObject>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThirdPartyLoginInfo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    #[serde(
        default,
        rename = "aliasKey",
        alias = "alias_key",
        skip_serializing_if = "Option::is_none"
    )]
    pub alias_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(
        default,
        rename = "loginUrl",
        alias = "login_url",
        skip_serializing_if = "Option::is_none"
    )]
    pub login_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub appid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agentid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notice: Option<String>,
    #[serde(
        default,
        rename = "isCustom",
        alias = "is_custom",
        skip_serializing_if = "Option::is_none"
    )]
    pub is_custom: Option<bool>,
    #[serde(
        default,
        rename = "fullTitle",
        alias = "full_title",
        skip_serializing_if = "Option::is_none"
    )]
    pub full_title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abbreviation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<JsonObject>,
}

fn encode_path_segment(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if is_unreserved_path_byte(byte) {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(hex_char(byte >> 4));
            encoded.push(hex_char(byte & 0x0F));
        }
    }
    encoded
}

const fn is_unreserved_path_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~')
}

const fn hex_char(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        _ => (b'A' + value - 10) as char,
    }
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
