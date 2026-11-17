//! # Embedded HTTPS (HTTP/1.1 + HTTP/2 + HTTP/3 QUIC) Web Server Example
//!
//! Demonstrates how an external Rust binary can embed `praeco-rs` with
//! `default-features = false` and **without any `Config.toml`**:
//!
//! 1. Programmatic `ServerConfig` with `Protocol::Https` (dual-stack TCP + UDP/QUIC).
//! 2. Hardened security middleware stack (`TraceId`, `SecurityHeaders`, `AltSvc`,
//!    `IpFilter`, `RateLimiter:TokenBucket`, `ConcurrencyLimit`, `MaxPayload`,
//!    `Decompression`, and `Inspection` with `AllowedPathes`).
//! 3. Composable endpoint handlers defined as standalone `async fn`s outside `main()`
//!    and wired via [`WebRouter`].

mod router;

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;
use http_body_util::BodyExt;
use hyper::{Method, Request, Response, StatusCode};
use praeco_rs::{
    ServiceRespBody, SrvBody, SrvError, build_service_stack_with_base,
    configuration::{
        AllowedPathes, ConcurrencyLimitConfig, ConnectionLimitsConfig, DecompressionConfig,
        IpFilterConfig, Layers, MaxPayloadConfig, Protocol, RateLimitKeyStrategy, ServerCertConfig,
        ServerConfig, TokenBucketRateLimiterConfig,
    },
    start_single_server,
};
use serde::Serialize;
use tokio_util::sync::CancellationToken;
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::router::{PathParams, WebRouter, json_response, text_response};

// ============================================================================
//  Endpoint Handlers (defined outside main)
// ============================================================================

#[derive(Serialize)]
struct HealthPayload {
    status: &'static str,
    protocol_hint: &'static str,
}

#[derive(Serialize)]
struct UserPayload {
    id: String,
    name: String,
    trace_id: Option<String>,
}

#[derive(Serialize)]
struct EchoPayload {
    received_bytes: usize,
    body: serde_json::Value,
    trace_id: Option<String>,
}

/// `GET /` — Minimal welcome response showing HTTP version and Trace ID.
async fn index(req: Request<SrvBody>) -> Result<Response<ServiceRespBody>, SrvError> {
    let version = req.version();
    let trace_id = req
        .headers()
        .get("x-trace-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("<none>");

    text_response(
        StatusCode::OK,
        format!("Hallo von praeco-rs ({version:?}, x-trace-id={trace_id})!\n"),
    )
}

/// `GET /healthz` — Liveness probe returning JSON.
async fn healthz(_req: Request<SrvBody>) -> Result<Response<ServiceRespBody>, SrvError> {
    json_response(
        StatusCode::OK,
        &HealthPayload {
            status: "ok",
            protocol_hint: "HTTP/1.1 + HTTP/2 + HTTP/3 (QUIC)",
        },
    )
}

/// `GET /users/{id}` — Demonstrates `matchit` path parameters + TraceId propagation.
async fn get_user(req: Request<SrvBody>) -> Result<Response<ServiceRespBody>, SrvError> {
    let user_id = req
        .extensions()
        .get::<PathParams>()
        .and_then(|p| p.get("id"))
        .unwrap_or("unknown")
        .to_owned();

    let trace_id = req
        .headers()
        .get("x-trace-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    json_response(
        StatusCode::OK,
        &UserPayload {
            name: format!("User {user_id}"),
            id: user_id,
            trace_id,
        },
    )
}

/// `POST /api/echo` — Reads JSON body (bounded by `MaxPayload` & `Decompression` layers).
async fn echo_json(req: Request<SrvBody>) -> Result<Response<ServiceRespBody>, SrvError> {
    let trace_id = req
        .headers()
        .get("x-trace-id")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    let body_bytes = req.collect().await?.to_bytes();
    let received_bytes = body_bytes.len();
    let parsed: serde_json::Value = serde_json::from_slice(&body_bytes)
        .map_err(|e| SrvError::Other(format!("Invalid JSON payload: {e}")))?;

    json_response(
        StatusCode::OK,
        &EchoPayload {
            received_bytes,
            body: parsed,
            trace_id,
        },
    )
}

// ============================================================================
//  Programmatic Server & Security Configuration
// ============================================================================

/// Resolves a path relative to the workspace root regardless of whether `cargo run`
/// was invoked from the repository root or from `examples/https_web_server/`.
fn resolve_workspace_path(env_key: &str, relative_from_root: &str) -> String {
    if let Ok(override_path) = std::env::var(env_key) {
        return override_path;
    }
    if Path::new(relative_from_root).exists() {
        return relative_from_root.to_owned();
    }
    let from_crate_dir = format!("../../{relative_from_root}");
    if Path::new(&from_crate_dir).exists() {
        return from_crate_dir;
    }
    relative_from_root.to_owned()
}

/// Builds a hardened HTTPS + HTTP/3 [`ServerConfig`] purely in Rust.
fn build_server_config(port: u16) -> anyhow::Result<Arc<ServerConfig>> {
    let cert_path = resolve_workspace_path(
        "PRAECO_TLS_CERT",
        "server_certs/self_signed/praeco_public.pem",
    );
    let key_path = resolve_workspace_path(
        "PRAECO_TLS_KEY",
        "server_certs/self_signed/praeco_public.key",
    );

    // WAF allowlist for the `Inspection` layer: only defined routes/methods are permitted.
    let get_rules = HashMap::from([
        ("/".into(), vec!["^/$".into()]),
        ("/healthz".into(), vec!["^/healthz$".into()]),
        ("/users/*".into(), vec!["^/users/[A-Za-z0-9_-]+$".into()]),
    ]);
    let post_rules = HashMap::from([("/api/echo".into(), vec!["^/api/echo$".into()])]);

    let mut cfg = ServerConfig {
        name: "https_web_example".into(),
        ip: Some("127.0.0.1".into()),
        port: Some(port),
        protocol: Protocol::Https,
        server_certs: Some(ServerCertConfig {
            ssl_certificate: cert_path,
            ssl_certificate_key: key_path,
        }),
        connection_limits: ConnectionLimitsConfig {
            max_connections: 1024,
            max_connections_per_ip: 64,
        },
        layers: Layers {
            // Note: `TraceId` must be first; `Inspection` must come after `Decompression`.
            enabled: vec![
                "TraceId".into(),
                "SecurityHeaders".into(),
                "AltSvc".into(),
                "IpFilter".into(),
                "RateLimiter:TokenBucket".into(),
                "ConcurrencyLimit".into(),
                "MaxPayload".into(),
                "Decompression".into(),
                "Inspection".into(),
            ],
            security_headers_config: Some(Default::default()),
            ip_filter_config: Some(IpFilterConfig {
                allow_cidrs: vec!["127.0.0.1/32".into(), "::1/128".into()],
                deny_cidrs: vec![],
                trust_forwarded_headers: false,
            }),
            token_bucket_config: Some(TokenBucketRateLimiterConfig {
                max_capacity: 20,
                refill: 10,
                duration_micros: 1_000_000,
                key_by: RateLimitKeyStrategy::Ip,
                max_entries: 10_000,
                ttl_seconds: 300,
                trust_forwarded_headers: false,
            }),
            concurrency_limit_config: Some(ConcurrencyLimitConfig {
                max_concurrent_requests: 128,
                load_shed: true,
                queue_timeout_ms: None,
            }),
            max_payload_config: Some(MaxPayloadConfig {
                max_bytes: 1024 * 1024, // 1 MiB
            }),
            decompression_config: Some(DecompressionConfig {
                max_decompressed_bytes: 2 * 1024 * 1024, // 2 MiB
            }),
            ..Default::default()
        },
        allowed_pathes: Some(AllowedPathes {
            get: Some(get_rules),
            post: Some(post_rules),
            put: None,
            delete: None,
            patch: None,
            head: None,
        }),
        ..Default::default()
    };

    cfg.finalize()?;
    Ok(Arc::new(cfg))
}

/// Builds the composable endpoint router from standalone handler functions.
fn build_app_router() -> anyhow::Result<praeco_rs::BoxedCloneService> {
    Ok(WebRouter::new()
        .route(Method::GET, "/", index)?
        .route(Method::GET, "/healthz", healthz)?
        .route(Method::GET, "/users/{id}", get_user)?
        .route(Method::POST, "/api/echo", echo_json)?
        .into_service())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing in the embedding binary (since `default-features = false` omits CLI logging).
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,praeco_rs=info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    // Required once per process for rustls / Quinn TLS 1.3.
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("Failed to install rustls ring crypto provider"))?;

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8443);

    let server_cfg = build_server_config(port)?;
    let app = build_app_router()?;

    let hardened_stack = build_service_stack_with_base(&server_cfg, app)?;
    let dynamic_stack = Arc::new(ArcSwap::from_pointee(hardened_stack));

    let cancel = CancellationToken::new();
    let server_task = tokio::spawn(start_single_server(
        Arc::clone(&server_cfg),
        cancel.clone(),
        dynamic_stack,
    ));

    info!(
        "HTTPS + HTTP/3 Web Server listening on https://127.0.0.1:{} (Ctrl+C to stop)",
        port
    );

    tokio::signal::ctrl_c().await?;
    info!("Shutdown requested, draining connections...");
    cancel.cancel();
    let _ = server_task.await;
    info!("Server stopped cleanly.");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::{Empty, Full};
    use praeco_rs::build_rustls_config;
    use std::net::SocketAddr;
    use tower::ServiceExt;

    fn make_req(method: Method, uri: &str, body: Option<&'static [u8]>) -> Request<SrvBody> {
        let srv_body = match body {
            Some(bytes) => Full::new(Bytes::from_static(bytes))
                .map_err(SrvError::from)
                .boxed(),
            None => Empty::<Bytes>::new().map_err(SrvError::from).boxed(),
        };
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .body(srv_body)
            .expect("valid test request");
        let peer: SocketAddr = "127.0.0.1:50000".parse().expect("valid SocketAddr");
        req.extensions_mut().insert(peer);
        req
    }

    #[tokio::test]
    async fn test_hardened_https_stack_and_endpoints() -> anyhow::Result<()> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let cfg = build_server_config(8443)?;

        // Verify TLS/QUIC rustls ServerConfig builds cleanly from the self-signed certs.
        let _tls = build_rustls_config(&cfg)?;

        let stack = build_service_stack_with_base(&cfg, build_app_router()?)?;

        // 1. GET / -> 200 OK + Alt-Svc + SecurityHeaders + TraceId in handler
        let res = stack.clone().oneshot(make_req(Method::GET, "/", None)).await?;
        assert_eq!(res.status(), StatusCode::OK);
        assert!(res.headers().contains_key("alt-svc"));
        assert!(res.headers().contains_key("strict-transport-security"));
        let root_body = res.collect().await?.to_bytes();
        let root_text = std::str::from_utf8(&root_body)?;
        assert!(root_text.contains("x-trace-id=00-"));

        // 2. GET /users/42 -> 200 OK + JSON path param + TraceId
        let res = stack
            .clone()
            .oneshot(make_req(Method::GET, "/users/42", None))
            .await?;
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.collect().await?.to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(json["id"], "42");
        assert!(
            json["trace_id"]
                .as_str()
                .is_some_and(|s| s.starts_with("00-"))
        );

        // 3. POST /api/echo -> 200 OK
        let res = stack
            .clone()
            .oneshot(make_req(Method::POST, "/api/echo", Some(br#"{"ok":true}"#)))
            .await?;
        assert_eq!(res.status(), StatusCode::OK);

        // 4. GET /admin -> 403 Forbidden from Inspection WAF layer
        let res = stack
            .clone()
            .oneshot(make_req(Method::GET, "/admin", None))
            .await?;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        // 5. Router 405 Method Not Allowed (tested directly on WebRouter)
        let router = build_app_router()?;
        let res = router.oneshot(make_req(Method::DELETE, "/healthz", None)).await?;
        assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(res.headers().get("allow").and_then(|v| v.to_str().ok()), Some("GET"));

        Ok(())
    }
}
