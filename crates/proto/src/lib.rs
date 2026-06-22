pub use buffa;

#[allow(clippy::all, clippy::pedantic, clippy::nursery, clippy::cargo)]
pub mod proto {
    connectrpc::include_generated!();
}

use proto::rustylink::daemon::v1::LoginCodeType;

impl LoginCodeType {
    /// The corplink wire value for this delivery channel: `"mobile"` for SMS,
    /// `"email"` for email. [`Unspecified`](Self::Unspecified) maps to
    /// `"mobile"`, the default channel.
    #[must_use]
    pub const fn wire(self) -> &'static str {
        match self {
            Self::LOGIN_CODE_TYPE_EMAIL => "email",
            _ => "mobile",
        }
    }
}

impl From<&str> for LoginCodeType {
    /// Classify a corplink wire channel string; anything other than `"email"`
    /// is treated as [`Mobile`](Self::Mobile) (the default).
    fn from(value: &str) -> Self {
        match value {
            "email" => Self::LOGIN_CODE_TYPE_EMAIL,
            _ => Self::LOGIN_CODE_TYPE_MOBILE,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::proto::rustylink::daemon::v1::LoginCodeType;

    #[test]
    fn login_code_type_wire_round_trips() {
        assert_eq!(LoginCodeType::Mobile.wire(), "mobile");
        assert_eq!(LoginCodeType::Email.wire(), "email");
        // Unspecified defaults to the SMS channel.
        assert_eq!(LoginCodeType::Unspecified.wire(), "mobile");

        assert_eq!(LoginCodeType::from("mobile"), LoginCodeType::Mobile);
        assert_eq!(LoginCodeType::from("email"), LoginCodeType::Email);
        // Unrecognised values fall back to mobile.
        assert_eq!(LoginCodeType::from("sms"), LoginCodeType::Mobile);
    }
}
