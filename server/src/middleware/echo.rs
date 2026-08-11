//! # Echo Service Middleware
//!
//! This module provides a simple `EchoService` used primarily for testing,
//! debugging, and load testing. **The proxy itself is not an application web server**,
//! but this endpoint layer allows developers to verify routing, headers,
//! and load balancing mechanisms without needing external backend services.

// === Standard Library ===
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

// === External Crates ===
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode, header};
use tower::Service;

// === Internal Modules ===
use crate::{ServiceRespBody, SrvBody, SrvError};

/// A Tower [`Service`] that echoes back HTTP requests for debugging purposes.
/// It responds to a few hardcoded routes like `/`, `/name`, `/health`, and `/help`.
#[derive(Clone, Debug)]
pub struct EchoService {
    server_name: &'static str,
    cached_root_msg: Bytes,
    cached_name_msg: Bytes,
}

impl EchoService {
    /// Creates a new `EchoService` with pre-allocated cached response messages.
    ///
    /// # Arguments
    /// * `server_name` - The identifier of the server, included in echo responses.
    pub fn new(server_name: &'static str) -> Self {
        let cached_root_msg =
            Bytes::from(format!("Echo /! Query: none from Server: {server_name}"));
        let cached_name_msg = Bytes::from(format!(
            "Echo /name! Query: none from Server: {server_name}"
        ));
        Self {
            server_name,
            cached_root_msg,
            cached_name_msg,
        }
    }
}

impl Service<Request<SrvBody>> for EchoService {
    type Response = Response<ServiceRespBody>;
    type Error = SrvError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<SrvBody>) -> Self::Future {
        let server_name = self.server_name;
        // Cheaply clone the cached Bytes since Bytes::clone is just an atomic refcount bump
        let cached_root = self.cached_root_msg.clone();
        let cached_name = self.cached_name_msg.clone();

        Box::pin(async move {
            match (req.method(), req.uri().path()) {
                // ── GET / ────────────────────────────────────────────
                (&hyper::Method::GET, "/") => {
                    let msg_bytes = if let Some(query) = req.uri().query() {
                        Bytes::from(format!(
                            "Echo /! Query: {} from Server: {}",
                            query, server_name
                        ))
                    } else {
                        cached_root
                    };

                    let body: ServiceRespBody =
                        Full::new(msg_bytes).map_err(SrvError::from).boxed();

                    let response = Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "text/plain")
                        .body(body)
                        .unwrap();

                    Ok(response)
                }

                // ── GET /name ────────────────────────────────────────────
                (&hyper::Method::GET, "/name") => {
                    let msg_bytes = if let Some(query) = req.uri().query() {
                        Bytes::from(format!(
                            "Echo /name! Query: {} from Server: {}",
                            query, server_name
                        ))
                    } else {
                        cached_name
                    };

                    let body: ServiceRespBody =
                        Full::new(msg_bytes).map_err(SrvError::from).boxed();

                    let response = Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "text/plain")
                        .body(body)
                        .unwrap();

                    Ok(response)
                }

                // ── GET /health ──────────────────────────────────────
                (&hyper::Method::GET, "/health") => {
                    let msg = r#"{"score": 100, "message": "echo service is alive"}"#;
                    let body = Full::new(Bytes::from_static(msg.as_bytes()))
                        .map_err(SrvError::from)
                        .boxed();
                    let response = Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(body)
                        .unwrap();
                    Ok(response)
                }

                // ── GET /help ────────────────────────────────────────
                (&hyper::Method::GET, "/help") => {
                    let msg = format!("=====> This is the help page from {server_name}\n");
                    let body = Full::new(Bytes::from(msg)).map_err(SrvError::from).boxed();
                    Ok(Response::new(body))
                }

                // ── POST / ──────────────────────────────────────────
                (&hyper::Method::POST, "/") => {
                    let content_type =
                        req.headers().get(header::CONTENT_TYPE).cloned().unwrap_or(
                            header::HeaderValue::from_static("application/octet-stream"),
                        );

                    let body_bytes = req.collect().await?.to_bytes();
                    let body = Full::new(body_bytes).map_err(SrvError::from).boxed();

                    let response = Response::builder()
                        .header(header::CONTENT_TYPE, content_type)
                        .body(body)
                        .unwrap();
                    Ok(response)
                }

                // ── PUT / ───────────────────────────────────────────
                (&hyper::Method::PUT, "/") => {
                    let body_bytes = req.collect().await?.to_bytes();
                    let body_str = String::from_utf8_lossy(&body_bytes);
                    let trimmed = body_str.trim();

                    let final_bytes = if let Some(pos) = trimmed.rfind('}') {
                        let mut new_body = trimmed[..pos].to_string();
                        let msg = format!(", \"note\": \"from echo name: {}\" }}", server_name);
                        new_body.push_str(&msg);
                        Bytes::from(new_body)
                    } else {
                        body_bytes
                    };

                    let response = Response::builder()
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Full::new(final_bytes).map_err(SrvError::from).boxed())
                        .unwrap();

                    Ok(response)
                }

                // ── Catch-all ───────────────────────────────────────
                (other, other_path) => {
                    tracing::warn!("{}: {} {} -> 404", server_name, other, other_path);
                    let body = Full::new(Bytes::from_static(b"Not Found"))
                        .map_err(SrvError::from)
                        .boxed();

                    let response = Response::builder()
                        .status(StatusCode::NOT_FOUND)
                        .body(body)
                        .unwrap();
                    Ok(response)
                }
            }
        })
    }
}

/// CPU-intensive workload.
/// Since we are in a 'sync' function on a blocking thread, we don't need .await or sleep.
#[allow(dead_code)]
fn load_test_echo_sync() -> String {
    let mut data = vec![1.0f64; 32_000_000]; // 256MB
    for i in 0..1 {
        for val in data.iter_mut() {
            *val += (i as f64).sin().cos();
        }
    }
    let checksum: f64 = data.iter().sum();
    format!("Result checksum: {:.6}", checksum)
}
