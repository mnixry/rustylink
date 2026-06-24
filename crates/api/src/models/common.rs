use std::{borrow::Cow, collections::HashMap};

use http::Method;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_with::skip_serializing_none;

pub type JsonObject = HashMap<String, serde_json::Value>;

#[skip_serializing_none]
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaseResponse<T> {
    pub code: i32,
    pub message: Option<String>,
    pub data: Option<T>,
    #[serde(default)]
    pub action: Option<String>,
    #[serde(default)]
    pub logout_reason: Option<LogoutReason>,
    pub extra: Option<JsonObject>,
}

#[skip_serializing_none]
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LogoutReason {
    pub reason: Option<String>,
    pub message: Option<String>,
}

impl<T> Default for BaseResponse<T> {
    fn default() -> Self {
        Self {
            code: 0,
            message: None,
            data: None,
            action: None,
            logout_reason: None,
            extra: None,
        }
    }
}

impl<T> BaseResponse<T> {
    /// Returns `true` if the server signalled a forced logout via `action`.
    #[must_use]
    pub fn is_force_logout(&self) -> bool {
        self.action.as_deref() == Some("logout")
    }
}

pub trait ApiResponse {
    fn code(&self) -> i32;
    fn message(&self) -> Option<&str>;

    fn is_force_logout(&self) -> bool {
        false
    }
}

impl<T> ApiResponse for BaseResponse<T> {
    fn code(&self) -> i32 {
        self.code
    }

    fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    fn is_force_logout(&self) -> bool {
        self.action.as_deref() == Some("logout")
    }
}

#[async_trait::async_trait]
pub trait SendableRequest: Sized + Send + Sync {
    type Response: ApiResponse + DeserializeOwned + Send + 'static;

    const METHOD: Method;

    fn path(&self) -> Cow<'static, str>;

    fn query_pairs(&self) -> Vec<(&'static str, String)> {
        Vec::new()
    }

    fn body(&self) -> std::result::Result<Option<Vec<u8>>, serde_json::Error> {
        Ok(None)
    }

    async fn send(
        self, client: &crate::client::ApiClient,
    ) -> crate::client::Result<Self::Response> {
        client.send(self).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_response_accepts_missing_optional_payload() {
        let response = serde_json::from_str::<BaseResponse<serde_json::Value>>(r#"{"code":0}"#)
            .expect("decode");

        assert_eq!(response.code, 0);
        assert_eq!(response.message, None);
        assert_eq!(response.data, None);
    }
}
