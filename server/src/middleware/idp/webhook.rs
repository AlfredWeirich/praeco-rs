use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, StatusCode};
use hyper_util::client::legacy::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

use crate::configuration::IdpParams;

#[derive(Debug, Error)]
pub enum WebhookError {
    #[error("HTTP request failed: {0}")]
    Request(#[from] hyper_util::client::legacy::Error),
    #[error("HTTP request building failed: {0}")]
    Http(#[from] hyper::http::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Webhook returned non-success status: {0}")]
    Status(StatusCode),
    #[error("Timeout fetching claims")]
    Timeout,
    #[error("Body read error: {0}")]
    Body(String),
}

#[derive(Debug, Serialize)]
struct WebhookRequest<'a> {
    sub: &'a str,
    cert_oids: &'a [String],
}

#[derive(Debug, Deserialize)]
struct WebhookResponse {
    oids: Vec<String>,
}

#[derive(Clone)]
pub struct WebhookClient {
    client: Client<common::client::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>, Full<Bytes>>,
    url: String,
    timeout: Duration,
}

impl WebhookClient {
    pub fn new(params: &IdpParams) -> Result<Option<Self>, anyhow::Error> {
        let url = match &params.claims_webhook_url {
            Some(u) => u.clone(),
            None => return Ok(None),
        };

        // If webhook uses HTTPS, load mTLS configs if provided
        let root_store = common::build_root_store(&params.claims_webhook_ca_cert);
        let tls_config = common::build_tls_client_config(
            root_store,
            params.claims_webhook_client_cert.as_deref(),
            params.claims_webhook_client_key.as_deref(),
        );

        let pool_config = common::client::ClientPoolConfig {
            idle_timeout: Some(Duration::from_secs(60)),
            max_idle_per_host: Some(16),
            http2_only: false,
        };

        let client = common::client::build_hyper_client(tls_config, pool_config);

        Ok(Some(Self {
            client,
            url,
            timeout: Duration::from_millis(params.claims_webhook_timeout_ms),
        }))
    }

    pub async fn fetch_claims(
        &self,
        sub: &str,
        cert_oids: &[String],
    ) -> Result<Vec<String>, WebhookError> {
        let req_payload = WebhookRequest { sub, cert_oids };
        let body_bytes = serde_json::to_vec(&req_payload)?;

        let req = Request::builder()
            .method(Method::POST)
            .uri(&self.url)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(body_bytes)))?;

        let fetch_fut = self.client.request(req);
        
        let res = match tokio::time::timeout(self.timeout, fetch_fut).await {
            Ok(Ok(response)) => response,
            Ok(Err(e)) => return Err(WebhookError::Request(e)),
            Err(_) => return Err(WebhookError::Timeout),
        };

        if !res.status().is_success() {
            return Err(WebhookError::Status(res.status()));
        }

        let body_bytes = res
            .into_body()
            .collect()
            .await
            .map_err(|e| WebhookError::Body(e.to_string()))?
            .to_bytes();

        let resp_payload: WebhookResponse = serde_json::from_slice(&body_bytes)?;

        Ok(resp_payload.oids)
    }
}
