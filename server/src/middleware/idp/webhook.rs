use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, StatusCode};
use hyper_util::client::legacy::Client;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use thiserror::Error;

use crate::configuration::IdpParams;

/// Maximum allowed response body size from the claims webhook (64 KB).
const MAX_WEBHOOK_BODY_SIZE: usize = 65_536;

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

pub struct WebhookFetchFuture {
    inner: Pin<Box<dyn Future<Output = Result<Vec<String>, WebhookError>> + Send>>,
}

impl Future for WebhookFetchFuture {
    type Output = Result<Vec<String>, WebhookError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        self.inner.as_mut().poll(cx)
    }
}

impl WebhookClient {
    pub fn new(params: &IdpParams) -> Result<Option<Self>, anyhow::Error> {
        let url = match &params.claims_webhook_url {
            Some(u) => u.clone(),
            None => return Ok(None),
        };

        // Enforce HTTPS for non-localhost endpoints to prevent token/claims interception
        if !url.starts_with("https://") && !url.starts_with("http://127.0.0.1") && !url.starts_with("http://localhost") {
            return Err(anyhow::anyhow!(
                "claims_webhook_url must use HTTPS for secure claims transport (plain HTTP is only allowed for localhost / 127.0.0.1)"
            ));
        }

        // If webhook uses HTTPS, load mTLS configs if provided
        let root_store = common::build_root_store(&params.claims_webhook_ca_cert)?;
        let tls_config = common::build_tls_client_config(
            root_store,
            params.claims_webhook_client_cert.as_deref(),
            params.claims_webhook_client_key.as_deref(),
        )?;

        let pool_config = common::client::ClientPoolConfig {
            idle_timeout: Some(Duration::from_secs(60)),
            max_idle_per_host: Some(16),
            http2_only: false,
            ..Default::default()
        };

        let client = common::client::build_hyper_client(tls_config, pool_config);

        Ok(Some(Self {
            client,
            url,
            timeout: Duration::from_millis(params.claims_webhook_timeout_ms),
        }))
    }

    pub fn fetch_claims(
        &self,
        sub: &str,
        cert_oids: &[String],
    ) -> Result<WebhookFetchFuture, WebhookError> {
        let req_payload = WebhookRequest { sub, cert_oids };
        let body_bytes = serde_json::to_vec(&req_payload)?;

        let req = Request::builder()
            .method(Method::POST)
            .uri(&self.url)
            .header("Content-Type", "application/json")
            .body(Full::new(Bytes::from(body_bytes)))?;

        let client = self.client.clone();
        let timeout = self.timeout;

        let work_fut = async move {
            let response = client.request(req).await.map_err(WebhookError::Request)?;
            if !response.status().is_success() {
                return Err(WebhookError::Status(response.status()));
            }

            // Enforce maximum body size to protect against memory exhaustion / slowloris
            let limited = http_body_util::Limited::new(response.into_body(), MAX_WEBHOOK_BODY_SIZE);
            let collected = limited.collect().await.map_err(|e| WebhookError::Body(e.to_string()))?;
            let body_bytes = collected.to_bytes();
            let resp: WebhookResponse = serde_json::from_slice(&body_bytes)?;
            Ok(resp.oids)
        };

        let timed_fut = async move {
            match tokio::time::timeout(timeout, work_fut).await {
                Ok(res) => res,
                Err(_) => Err(WebhookError::Timeout),
            }
        };

        Ok(WebhookFetchFuture {
            inner: Box::pin(timed_fut),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_idp_params(url: Option<String>) -> IdpParams {
        let _ = rustls::crypto::ring::default_provider().install_default();
        IdpParams {
            jwt_private_key: "".to_string(),
            jwt_public_key: None,
            token_expiry_seconds: 3600,
            session_ttl_seconds: 120,
            cookie_name: "jwt".to_string(),
            cookie_domain: None,
            redirect_after_login: "/".to_string(),
            allowed_audiences: vec![],
            issuer: "praeco-idp".to_string(),
            claims_webhook_url: url,
            claims_webhook_timeout_ms: 1000,
            on_webhook_failure: "reject".to_string(),
            debug_show_session_id: Some(false),
            claims_webhook_client_cert: None,
            claims_webhook_client_key: None,
            claims_webhook_ca_cert: None,
        }
    }

    #[test]
    fn test_webhook_insecure_http_rejected() {
        let params = dummy_idp_params(Some("http://evil-server.com/claims".to_string()));
        let client = WebhookClient::new(&params);
        match client {
            Err(e) => assert!(e.to_string().contains("must use HTTPS")),
            Ok(_) => panic!("Expected error for non-HTTPS URL"),
        }
    }

    #[test]
    fn test_webhook_localhost_http_allowed() {
        let params = dummy_idp_params(Some("http://127.0.0.1:50053/claims".to_string()));
        let client = WebhookClient::new(&params);
        assert!(client.is_ok());

        let params_lh = dummy_idp_params(Some("http://localhost:50053/claims".to_string()));
        let client_lh = WebhookClient::new(&params_lh);
        assert!(client_lh.is_ok());
    }

    #[test]
    fn test_webhook_https_allowed() {
        let params = dummy_idp_params(Some("https://secure.example.com/claims".to_string()));
        let client = WebhookClient::new(&params);
        assert!(client.is_ok());
    }
}
