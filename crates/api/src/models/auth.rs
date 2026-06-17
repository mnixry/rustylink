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
    BaseResponse<LoginResult>
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
    BaseResponse<String>
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
    BaseResponse<LoginResult>
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
    BaseResponse<LoginResult>
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
    BaseResponse<ThirdPartyTokenCheckResult>
);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginResult {
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_custom: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full_title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub abbreviation: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<JsonObject>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ThirdPartyTokenCheckResult {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
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
}
