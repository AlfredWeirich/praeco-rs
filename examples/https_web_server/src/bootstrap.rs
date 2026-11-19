//! App-specific HTTPS + HTTP/3 server configuration and lifecycle bootstrap.
//!
//! Keeps [`crate::main`] focused purely on endpoint definitions and routing while
//! encapsulating tracing setup, TLS certificate paths, hardened middleware
//! defaults, and graceful `Ctrl+C` shutdown.

use std::path::Path;
use std::sync::Arc;

use arc_swap::ArcSwap;
use praeco_rs::{
    build_service_stack_with_base,
    configuration::{
        AllowedPathes, ConcurrencyLimitConfig, ConnectionLimitsConfig, DecompressionConfig,
        IpFilterConfig, Layers, MaxPayloadConfig, Protocol, RateLimitKeyStrategy, ServerCertConfig,
        ServerConfig, TokenBucketRateLimiterConfig,
    },
    start_single_server,
    web::WebRouter,
};
use tokio_util::sync::CancellationToken;
use tracing::info;
use tracing_subscriber::EnvFilter;

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

/// Builds a hardened HTTPS + HTTP/3 [`ServerConfig`] purely in Rust, deriving the
/// `Inspection` WAF allowlist directly from `allowed_pathes` and loading certificates
/// from `PRAECO_TLS_CERT`/`PRAECO_TLS_KEY` or the default workspace paths.
pub fn build_server_config(
    port: u16,
    allowed_pathes: AllowedPathes,
) -> anyhow::Result<Arc<ServerConfig>> {
    let cert_path = resolve_workspace_path(
        "PRAECO_TLS_CERT",
        "server_certs/self_signed/praeco_public.pem",
    );
    let key_path = resolve_workspace_path(
        "PRAECO_TLS_KEY",
        "server_certs/self_signed/praeco_public.key",
    );
    build_server_config_with_certs(port, allowed_pathes, cert_path, key_path)
}

/// Builds a hardened HTTPS + HTTP/3 [`ServerConfig`] with explicit TLS certificate
/// and private-key paths.
pub fn build_server_config_with_certs(
    port: u16,
    allowed_pathes: AllowedPathes,
    cert_path: String,
    key_path: String,
) -> anyhow::Result<Arc<ServerConfig>> {

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
        allowed_pathes: Some(allowed_pathes),
        ..Default::default()
    };

    cfg.finalize()?;
    Ok(Arc::new(cfg))
}

/// Initializes tracing & `rustls`, wires the hardened Praeco service stack around
/// `router`, and runs the dual-stack HTTPS + HTTP/3 server until `Ctrl+C`.
pub async fn run_https_server(router: WebRouter) -> anyhow::Result<()> {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,praeco_rs=info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    // Required once per process for rustls / Quinn TLS 1.3.
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("Failed to install rustls aws-lc-rs crypto provider"))?;

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(8443);

    let server_cfg = build_server_config(port, router.allowed_pathes())?;
    let hardened_stack = build_service_stack_with_base(&server_cfg, router.into_service())?;
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
