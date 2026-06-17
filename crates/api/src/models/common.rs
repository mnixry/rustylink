use std::{borrow::Cow, collections::HashMap};

use reqwest::Method;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

pub type JsonObject = HashMap<String, serde_json::Value>;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaseResponse<T> {
    pub code: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra: Option<JsonObject>,
}

impl<T> Default for BaseResponse<T> {
    fn default() -> Self {
        Self {
            code: 0,
            message: None,
            data: None,
            extra: None,
        }
    }
}

pub trait ApiResponse {
    fn code(&self) -> i32;
    fn message(&self) -> Option<&str>;
}

impl<T> ApiResponse for BaseResponse<T> {
    fn code(&self) -> i32 {
        self.code
    }

    fn message(&self) -> Option<&str> {
        self.message.as_deref()
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
