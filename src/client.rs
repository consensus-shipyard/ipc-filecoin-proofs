// Copyright 2022-2024 Protocol Labs
// SPDX-License-Identifier: MIT

use anyhow::Result;
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use tokio::time::Duration;
use url::Url;

/// Request timeout of the RPC client
const DEFAULT_REQ_TIMEOUT: Duration = Duration::from_secs(250);

/// A simple Lotus RPC client
#[derive(Clone)]
pub struct LotusClient {
    http_client: reqwest::Client,
    url: Url,
    bearer_token: Option<String>,
}

impl LotusClient {
    /// Creates a new Lotus client that sends requests to `url`
    pub fn new(url: Url, bearer_token: Option<&str>) -> Self {
        Self {
            http_client: reqwest::Client::default(),
            url,
            bearer_token: bearer_token.map(String::from),
        }
    }

    /// Make a generic RPC request
    pub async fn request<T: DeserializeOwned>(&self, method: &str, params: Value) -> Result<T> {
        let request_body = json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
            "id": 1
        });

        tracing::debug!(
            "{} request: {}",
            method,
            serde_json::to_string_pretty(&request_body).unwrap()
        );

        let mut builder = self.http_client.post(self.url.as_str()).json(&request_body);
        builder = builder.timeout(DEFAULT_REQ_TIMEOUT);

        if self.bearer_token.is_some() {
            builder = builder.bearer_auth(self.bearer_token.as_ref().unwrap());
        }

        let response = builder.send().await?;
        let response_body = response.text().await?;
        tracing::debug!("{} raw response: {}", method, response_body);

        // Parse the JSON-RPC response
        let value: serde_json::Value = serde_json::from_str(&response_body)?;

        if let Some(result) = value.get("result") {
            let data: T = serde_json::from_value(result.clone())?;
            Ok(data)
        } else if let Some(error) = value.get("error") {
            let error_msg = error
                .get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown error");
            anyhow::bail!("{} RPC error: {}", method, error_msg);
        } else {
            anyhow::bail!("{} response has neither result nor error", method);
        }
    }
}
