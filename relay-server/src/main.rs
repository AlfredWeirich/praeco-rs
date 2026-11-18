//! # Praeco Relay Server Binary
//!
//! Entry point for the Zero-Trust, SNI-based TCP Relay Server.
//!
//! Loads [`RelayConfig`], initializes observability (OpenTelemetry + non-blocking rolling file logs),
//! binds the Control Plane and Data Plane TCP listeners, and manages graceful shutdown.

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use anyhow::{Context, Result};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::Resource;
use praeco_relay_server::{
    RelayConfig, RelayConnectionTracker, SessionMap, new_session_map, run_control_plane,
    run_data_plane_with_stream_timeout, setup_mtls_acceptor,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};
use tracing_appender::{non_blocking::WorkerGuard, rolling::RollingFileAppender};
use tracing_subscriber::{EnvFilter, Layer, Registry, layer::SubscriberExt};

#[cfg(unix)]
async fn wait_for_shutdown() -> Result<()> {
    use tokio::signal::unix::{SignalKind, signal};
    let mut sigterm =
        signal(SignalKind::terminate()).context("Failed to register SIGTERM handler")?;
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Received SIGINT (Ctrl+C). Shutting down Relay Server...");
        }
        _ = sigterm.recv() => {
            info!("Received SIGTERM. Shutting down Relay Server...");
        }
    }
    Ok(())
}

#[cfg(not(unix))]
async fn wait_for_shutdown() -> Result<()> {
    let _ = tokio::signal::ctrl_c().await;
    info!("Shutdown signal received. Shutting down Relay Server...");
    Ok(())
}

/// Configures tracing, daily rolling file logging (if `log_dir` is configured),
/// and OpenTelemetry (OTLP) based on the provided configuration.
///
/// Returns a tuple containing:
/// - An optional [`WorkerGuard`] that ensures buffered file logs are flushed on shutdown.
/// - An optional [`opentelemetry_sdk::trace::SdkTracerProvider`] so background telemetry batch export is kept alive.
fn setup_tracing(
    config: &RelayConfig,
) -> Result<(
    Option<WorkerGuard>,
    Option<opentelemetry_sdk::trace::SdkTracerProvider>,
)> {
    let log_dir = config.log_dir.as_deref();
    let enable_otlp = config.enable_opentelemetry.unwrap_or(false);
    let jaeger_endpoint = config
        .jaeger_endpoint
        .as_deref()
        .unwrap_or("http://localhost:4317");
    let otel_log_level = config.otel_log_level.as_deref().unwrap_or("info");
    let otel_sample_ratio = config.otel_sample_ratio.unwrap_or(1.0);

    let console_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let stdout_layer = tracing_subscriber::fmt::layer()
        .with_ansi(true)
        .with_filter(console_filter);

    let (telemetry_layer, tracer_provider) = if enable_otlp {
        let sampler = if (otel_sample_ratio - 1.0).abs() < f64::EPSILON {
            opentelemetry_sdk::trace::Sampler::AlwaysOn
        } else {
            opentelemetry_sdk::trace::Sampler::ParentBased(Box::new(
                opentelemetry_sdk::trace::Sampler::TraceIdRatioBased(otel_sample_ratio),
            ))
        };

        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(jaeger_endpoint)
            .build()
            .context("Failed to initialize OTLP exporter")?;

        let resource = Resource::builder()
            .with_service_name("praeco-relay")
            .build();

        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_sampler(sampler)
            .with_resource(resource)
            .build();

        opentelemetry::global::set_tracer_provider(provider.clone());

        let tracer = provider.tracer("praeco-relay");
        let telemetry_filter = EnvFilter::new(otel_log_level);

        let telemetry_layer = tracing_opentelemetry::layer()
            .with_tracer(tracer)
            .with_filter(telemetry_filter);

        (Some(telemetry_layer), Some(provider))
    } else {
        (None, None)
    };

    if let Some(dir) = log_dir {
        let file_appender = RollingFileAppender::builder()
            .rotation(tracing_appender::rolling::Rotation::DAILY)
            .filename_prefix("relay")
            .filename_suffix("log")
            .build(dir)
            .with_context(|| {
                format!(
                    "Failed to initialize RollingFileAppender in directory: '{}'",
                    dir
                )
            })?;

        let (non_blocking_appender, guard) = tracing_appender::non_blocking(file_appender);

        let file_layer = tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(non_blocking_appender)
            .with_filter(
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
            );

        let subscriber = Registry::default()
            .with(telemetry_layer)
            .with(stdout_layer)
            .with(file_layer);

        tracing::subscriber::set_global_default(subscriber)
            .context("Failed to set global tracing subscriber with file layer")?;

        Ok((Some(guard), tracer_provider))
    } else {
        let subscriber = Registry::default().with(telemetry_layer).with(stdout_layer);

        tracing::subscriber::set_global_default(subscriber)
            .context("Failed to set global tracing subscriber")?;

        Ok((None, tracer_provider))
    }
}

/// Entry point for the Relay Server.
///
/// Loads the configuration, sets up observability, initializes the mTLS acceptor,
/// and spawns the Data Plane (HTTPS traffic) and Control Plane (internal mTLS registration).
#[tokio::main]
async fn main() -> Result<()> {
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "RelayConfig.toml".to_string());
    let config = RelayConfig::load(&config_path)?;
    let (_tracing_guard, tracer_provider) = setup_tracing(&config)?;

    // Install default crypto provider for rustls
    let _ = rustls::crypto::ring::default_provider().install_default();

    info!("Starting Praeco Relay Server...");

    let active_tunnels: SessionMap = new_session_map();
    let cancel_token = CancellationToken::new();

    let tls_acceptor = setup_mtls_acceptor(
        &config.ca_cert_path,
        &config.server_cert_path,
        &config.server_key_path,
        config.crl_path.as_ref(),
    )
    .context("Failed to setup mTLS acceptor")?;

    // --- Bind & Spawn Control Plane ---
    let control_listener = TcpListener::bind(&config.control_plane_addr)
        .await
        .with_context(|| {
            format!(
                "Failed to bind control plane on {}",
                config.control_plane_addr
            )
        })?;
    let control_tunnels = active_tunnels.clone();
    let control_handshake_timeout =
        Duration::from_secs(config.control_plane_handshake_timeout_secs.unwrap_or(10));
    let max_yamux_streams = config.max_yamux_streams.unwrap_or(4096);
    let enable_proxy_protocol = config.enable_proxy_protocol.unwrap_or(true);
    let control_cancel = cancel_token.clone();

    let mut control_handle = tokio::spawn(async move {
        if let Err(e) = run_control_plane(
            control_listener,
            tls_acceptor,
            control_tunnels,
            control_handshake_timeout,
            max_yamux_streams,
            enable_proxy_protocol,
            control_cancel,
        )
        .await
        {
            error!("Control plane failed: {}", e);
        }
    });

    // --- Bind & Spawn Data Plane ---
    let data_listener = TcpListener::bind(&config.data_plane_addr)
        .await
        .with_context(|| format!("Failed to bind data plane on {}", config.data_plane_addr))?;
    let rate_rate = config.rate_limit_connections_per_sec.unwrap_or(50) as f32;
    let rate_burst = config.rate_limit_burst.unwrap_or(100) as f32;
    let idle_timeout = match config.data_plane_idle_timeout_secs.unwrap_or(1800) {
        0 => None,
        secs => Some(Duration::from_secs(secs)),
    };
    let tcp_keepalive = match config.tcp_keepalive_secs.unwrap_or(60) {
        0 => None,
        secs => Some(Duration::from_secs(secs)),
    };
    let max_global_conn = config.max_concurrent_connections.unwrap_or(10000);
    let max_ip_conn = config.max_concurrent_connections_per_ip.unwrap_or(100);
    let connection_tracker = Arc::new(RelayConnectionTracker::new(max_global_conn, max_ip_conn));
    let client_hello_timeout = Duration::from_secs(config.client_hello_timeout_secs.unwrap_or(10));
    let tunnel_stream_open_timeout =
        Duration::from_secs(config.tunnel_stream_open_timeout_secs.unwrap_or(5).max(1));
    let data_cancel = cancel_token.clone();

    let mut data_handle = tokio::spawn(async move {
        if let Err(e) = run_data_plane_with_stream_timeout(
            data_listener,
            active_tunnels,
            rate_rate,
            rate_burst,
            idle_timeout,
            tcp_keepalive,
            connection_tracker,
            client_hello_timeout,
            tunnel_stream_open_timeout,
            data_cancel,
        )
        .await
        {
            error!("Data plane failed: {}", e);
        }
    });

    tokio::select! {
        res = wait_for_shutdown() => {
            res?;
            info!("Shutdown signal received. Shutting down Relay Server...");
            cancel_token.cancel();
            let _ = tokio::join!(control_handle, data_handle);
        }
        res = &mut control_handle => {
            error!("Control plane exited unexpectedly ({:?}); shutting down Relay Server", res);
            cancel_token.cancel();
            if let Err(e) = data_handle.await {
                error!("Data plane task panicked during shutdown: {:?}", e);
            }
        }
        res = &mut data_handle => {
            error!("Data plane exited unexpectedly ({:?}); shutting down Relay Server", res);
            cancel_token.cancel();
            if let Err(e) = control_handle.await {
                error!("Control plane task panicked during shutdown: {:?}", e);
            }
        }
    }

    if let Some(provider) = tracer_provider {
        let _ = provider.shutdown();
    }
    Ok(())
}
