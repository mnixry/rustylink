use serde::{Deserialize, Serialize};
use serde_with::skip_serializing_none;

use super::BaseResponse;

/// `POST /api/v2/p/otp` — provisions the tenant's TOTP.
///
/// Gated on the Android `User-Agent` we send: the server then embeds the TOTP
/// secret in an `otpauth://` provisioning URI in `url`, and the server
/// wall-clock (seconds) in `timestamp` (used to time-correct generated codes).
/// The Android client types this `BaseResponse<LoginResult>`; we model only the
/// fields we consume.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FetchOtpRequest;

impl_empty_request!(
    FetchOtpRequest,
    POST,
    "/api/v2/p/otp",
    BaseResponse<OtpProvision>
);

/// The TOTP provisioning payload (`LoginResult`-shaped on the wire).
#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct OtpProvision {
    /// `otpauth://totp/...` URI carrying secret/algorithm/digits/period.
    /// Empty when the tenant has no OTP requirement.
    pub url: String,
    /// Server wall-clock in seconds, for TOTP time correction.
    pub timestamp: i64,
}
