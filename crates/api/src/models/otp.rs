use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use super::BaseResponse;

/// `POST /api/v2/p/otp` — provisions the tenant's TOTP account(s).
///
/// The exact response envelope is tenant-dependent and was not fully pinned
/// from static analysis (the Android decompile typed it `BaseResponse<LoginResult>`,
/// which is likely an artifact). We decode the payload as a free-form JSON value
/// and extract the default `OtpAccount` (`OTPBean`) defensively in core.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FetchOtpRequest;

impl_empty_request!(
    FetchOtpRequest,
    POST,
    "/api/v2/p/otp",
    BaseResponse<serde_json::Value>
);

/// A single OTP account (`OTPBean` in the Android app).
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct OtpAccount {
    pub secret: Option<String>,
    pub issuer: Option<String>,
    pub email: Option<String>,
    pub algorithm: Option<String>,
    pub digits: Option<String>,
    pub period: Option<i64>,
    #[serde(rename = "isDefault", alias = "is_default")]
    pub is_default: Option<bool>,
}
