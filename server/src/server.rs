//! # Server Binary — Entry Point & Lifecycle
//!
//! This is the main executable for the server application. It orchestrates:
//! `RUST_LOG=warn,praeco_rs=trace,praeco_rs::middleware::logger=trace cargo run -p praeco-rs --release`
//!
//! 1. **Configuration loading** via [`Config::init`].
//! 2. **Tokio runtime creation** with a configurable number of worker threads.
//! 3. **Tracing / logging setup** (stdout + optional rolling-file appender + OTLP).
//! 4. **Per-server task spawning** — each enabled `[[Server]]` block in `Config.toml`
//!    runs via [`praeco_rs::start_single_server`].
//! 5. **Hot-reload on `SIGHUP`** with dry-run validation and lock-free `ArcSwap` updates.
//! 6. **Graceful shutdown** on `Ctrl-C` using a shared [`CancellationToken`].
//!
//! ## Example `curl` Invocations
//!
//! ```bash
//! # HTTP/2 + mTLS + help endpoint
//! curl -v --http2 \
//!   --cert client_certs/client.cert.pem \
//!   --key  client_certs/client.key.pem \
//!   --cacert server_certs/self_signed/myca.pem \
//!   https://192.168.178.175:1337/help
//!
//! # HTTP/3 + JWT + JSON PUT
//! echo '{"status": "updated"}' | curl -v --http3 -X PUT \
//!   --cert client_certs/client.cert.pem \
//!   --key  client_certs/client.key.pem \
//!   --cacert server_certs/self_signed/myca.pem \
//!   -H "Authorization: Bearer $(cat ./jwt/token1.jwt)" \
//!   -H "Content-Type: application/json" \
//!   --data-binary @- https://192.168.178.175:1337/
//! ```

/// Use mimalloc as the global allocator for reduced contention
/// under heavy multi-threaded workloads (5–15% throughput gain).
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

// === Standard Library ===
use std::collections::HashMap;
use std::sync::Arc;

// === External Crates ===
use anyhow::{Context, Error};
use arc_swap::ArcSwap;
use tokio::runtime::Builder;
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};
use tracing_appender::{non_blocking::WorkerGuard, rolling::RollingFileAppender};
use tracing_subscriber::{EnvFilter, Registry, fmt, layer::SubscriberExt};

// === Internal Modules ===
use praeco_rs::{
    BoxedCloneService,
    configuration::{Config, Protocol, ServerConfig},
    runner::start_single_server_with_socket_signal,
    stack::{build_rustls_config, build_service_stack},
};

/// Main entry point for the server application.
///
/// 1. **Parse Arguments**: Looks for a configuration file path (default: `Config.toml`).
/// 2. **Load Configuration**: Reads and parses the global settings via [`Config::init`].
/// 3. **Build Runtime**: Starts the multi-threaded Tokio runtime.
/// 4. **Setup Logging**: Initializes stdout, rolling file logging, and optional OTLP export.
/// 5. **Start Server**: Launches [`main_async`] and flushes telemetry on exit.
fn main() -> Result<(), Error> {
    praeco_rs::middleware::admin::init_process_start_time();
    let arg = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "Config.toml".to_string());

    // Install 'ring' as the default crypto provider for the process.
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let config = Config::init(&arg)?;

    let tokio_threads = config
        .tokio_threads
        .filter(|&n| n > 0)
        .unwrap_or_else(num_cpus::get);

    let runtime = Builder::new_multi_thread()
        .worker_threads(tokio_threads)
        .enable_all()
        .build()
        .context("Failed to build Tokio runtime")?;

    // Enter the runtime context so OTLP can spawn its background export task.
    let _rt_guard = runtime.enter();

    let (_tracing_guard, _tracer_provider) = setup_tracing(&config)?;

    info!("Configuration loaded from: {} ({} servers)", arg, config.servers.len());

    let res = runtime.block_on(main_async(config, arg));
    if let Some(provider) = _tracer_provider {
        let _ = provider.shutdown();
    }
    res
}

/// A running server instance managed by the hot-reload loop.
struct ActiveServer {
    /// Cancels the server (stops accepting and drains connections).
    cancel_token: CancellationToken,
    /// Configuration the instance was started with.
    config: Arc<ServerConfig>,
    /// Hot-swappable service stack.
    stack: Arc<ArcSwap<BoxedCloneService>>,
    /// Resolves as soon as the server's listening sockets (or tunnel session)
    /// are released, even while slow connections are still draining.
    sockets_released: oneshot::Receiver<()>,
}

/// Spawns `start_single_server_with_socket_signal` into `join_set` and returns a
/// receiver that resolves as soon as the server releases its listening sockets.
///
/// If `wait_for` is given (a predecessor that still holds the same socket address or
/// tunnel), the new instance waits for that signal before binding, avoiding `EADDRINUSE`
/// without stalling behind slow connection drains.
fn spawn_server(
    join_set: &mut tokio::task::JoinSet<()>,
    config: Arc<ServerConfig>,
    cancel_token: CancellationToken,
    stack: Arc<ArcSwap<BoxedCloneService>>,
    wait_for: Option<oneshot::Receiver<()>>,
) -> oneshot::Receiver<()> {
    let (released_tx, released_rx) = oneshot::channel();
    join_set.spawn(async move {
        if let Some(previous) = wait_for {
            // An `Err` only means the predecessor task dropped the sender on exit.
            let _ = previous.await;
        }
        start_single_server_with_socket_signal(config, cancel_token, stack, Some(released_tx))
            .await;
    });
    released_rx
}

/// Asynchronous mission-control loop managing server tasks, `SIGHUP` hot-reloads,
/// and `Ctrl-C` graceful shutdown.
async fn main_async(config: Arc<Config>, config_path: String) -> Result<(), Error> {
    let mut server_join_set = tokio::task::JoinSet::new();

    // Map: server name -> running instance
    let mut active_servers: HashMap<String, ActiveServer> = HashMap::new();

    for server_config in &config.servers {
        if !server_config.enabled {
            continue;
        }

        let cancel_token = CancellationToken::new();
        let server_config_arc = Arc::new(server_config.clone());

        let service_stack = match build_service_stack(&server_config_arc) {
            Ok(svc) => svc,
            Err(e) => {
                error!(
                    "{}: Failed to build initial service stack: {:?}",
                    server_config.name, e
                );
                continue;
            }
        };
        let dynamic_stack = Arc::new(ArcSwap::from_pointee(service_stack));

        let sockets_released = spawn_server(
            &mut server_join_set,
            server_config_arc.clone(),
            cancel_token.clone(),
            dynamic_stack.clone(),
            None,
        );
        active_servers.insert(
            server_config.name.clone(),
            ActiveServer {
                cancel_token,
                config: server_config_arc,
                stack: dynamic_stack,
                sockets_released,
            },
        );
    }

    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Shutdown signal received (Ctrl+C). Starting graceful shutdown...");
                break;
            }
            _ = sigterm.recv() => {
                info!("Shutdown signal received (SIGTERM). Starting graceful shutdown...");
                break;
            }
            _ = sighup.recv() => {
                info!("Received SIGHUP, initiating hot-reload from '{}'...", config_path);

                // 1. Reload configuration from disk without modifying global CONFIG yet.
                let new_config = match Config::load(&config_path) {
                    Ok(c) => c,
                    Err(e) => {
                        error!("Failed to reload config on SIGHUP, ignoring: {:?}", e);
                        continue;
                    }
                };

                info!("Successfully parsed and validated new config from '{}'", config_path);

                // 2. DRY-RUN PASS: Build all service stacks and TLS configurations first.
                let mut reload_errors = Vec::new();
                let mut built_stacks = HashMap::new();

                for new_server in &new_config.servers {
                    if !new_server.enabled {
                        continue;
                    }
                    let server_config_arc = Arc::new(new_server.clone());

                    if (new_server.protocol == Protocol::Https || new_server.tunnel.is_some())
                        && let Err(e) = build_rustls_config(new_server)
                    {
                        error!("{}: FAILED to build TLS config (dry-run): {:?}", new_server.name, e);
                        reload_errors.push((new_server.name.clone(), format!("TLS config error: {e}")));
                        continue;
                    }

                    match build_service_stack(&server_config_arc) {
                        Ok(svc) => {
                            built_stacks.insert(new_server.name.clone(), (server_config_arc, svc));
                        }
                        Err(e) => {
                            error!("{}: FAILED to build service stack (dry-run): {:?}", new_server.name, e);
                            reload_errors.push((new_server.name.clone(), e.to_string()));
                        }
                    }
                }

                if !reload_errors.is_empty() {
                    error!(
                        "Hot-reload aborted! {} server(s) failed to build their service stacks:",
                        reload_errors.len()
                    );
                    for (name, err) in &reload_errors {
                        error!(" - {}: {}", name, err);
                    }
                    error!("Keeping previous configuration completely intact.");
                    continue;
                }

                // 3. APPLY PASS: Atomic config swap and diff/manage listeners.
                info!("Dry-run passed. Applying new configuration...");
                Config::update_global(new_config.clone());
                let mut next_active_servers = HashMap::new();

                for (name, (server_config_arc, service_stack)) in built_stacks {
                    let new_server = &server_config_arc;
                    let needs_restart = match active_servers.get(&name) {
                        None => true,
                        Some(old) => {
                            old.config.ip != new_server.ip
                                || old.config.port != new_server.port
                                || old.config.protocol != new_server.protocol
                                || old.config.tunnel != new_server.tunnel
                        }
                    };

                    if needs_restart {
                        // Retire the previous instance first. If it holds the same socket
                        // address (or tunnel SNI), the successor waits until it released it,
                        // otherwise the new bind would fail with EADDRINUSE.
                        let wait_for = active_servers.remove(&name).and_then(|old| {
                            info!("Stopping previous instance of '{}' for restart", old.config.name);
                            old.cancel_token.cancel();
                            let same_bind = (old.config.ip == new_server.ip
                                && old.config.port == new_server.port)
                                || (old.config.tunnel.is_some() && new_server.tunnel.is_some());
                            same_bind.then_some(old.sockets_released)
                        });

                        info!("Starting server '{}'...", new_server.name);
                        let cancel_token = CancellationToken::new();
                        let dynamic_stack = Arc::new(ArcSwap::from_pointee(service_stack));

                        let sockets_released = spawn_server(
                            &mut server_join_set,
                            server_config_arc.clone(),
                            cancel_token.clone(),
                            dynamic_stack.clone(),
                            wait_for,
                        );
                        next_active_servers.insert(
                            name,
                            ActiveServer {
                                cancel_token,
                                config: server_config_arc.clone(),
                                stack: dynamic_stack,
                                sockets_released,
                            },
                        );
                    } else if let Some(mut active) = active_servers.remove(&name) {
                        active.stack.store(Arc::new(service_stack));
                        info!("Hot-swapped service stack for '{}'", new_server.name);

                        active.config = server_config_arc.clone();
                        next_active_servers.insert(name, active);
                    }
                }

                // 4. Stop drained/removed listeners.
                for (_name, active) in active_servers.drain() {
                    info!("Stopping server '{}'", active.config.name);
                    active.cancel_token.cancel();
                }

                active_servers = next_active_servers;
                info!("Hot-reload complete.");
            }
        }
    }

    for (_, active) in active_servers {
        active.cancel_token.cancel();
    }

    while let Some(res) = server_join_set.join_next().await {
        if let Err(e) = res {
            error!("Server task panicked or failed prematurely: {:?}", e);
        }
    }

    info!("All servers shut down cleanly.");
    Ok(())
}

/// Distinct `FormatFields` newtype for the file `fmt::Layer` so its `FormattedFields<N>`
/// span extension does not collide with `stdout_layer`'s `FormattedFields<DefaultFields>`
/// (which otherwise causes `on_record` to append recorded fields like `traceparent` twice
/// and leaks ANSI escapes into the file log).
#[derive(Default)]
struct FileFormatFields(fmt::format::DefaultFields);

impl<'writer> fmt::FormatFields<'writer> for FileFormatFields {
    fn format_fields<R: tracing_subscriber::field::RecordFields>(
        &self,
        writer: fmt::format::Writer<'writer>,
        fields: R,
    ) -> std::fmt::Result {
        self.0.format_fields(writer, fields)
    }
}

/// Configures the global tracing subscriber for logging and OpenTelemetry tracing.
///
/// Returns a tuple containing an optional `WorkerGuard` (for non-blocking file logging)
/// and an optional `SdkTracerProvider` (for OpenTelemetry tracing).
fn setup_tracing(
    config: &Config,
) -> Result<(Option<WorkerGuard>, Option<opentelemetry_sdk::trace::SdkTracerProvider>), Error> {
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_otlp::WithExportConfig;
    use opentelemetry_sdk::Resource;
    use opentelemetry_sdk::trace::SdkTracerProvider;
    use tracing_subscriber::Layer as _;

    let log_dir = config.log_dir.as_deref();
    let enable_otlp = config.enable_opentelemetry.unwrap_or(false);
    let jaeger_endpoint = config.jaeger_endpoint.as_deref().unwrap_or("http://localhost:4317");
    let otel_log_level = config.otel_log_level.as_deref().unwrap_or("info");
    let otel_sample_ratio = config.otel_sample_ratio.unwrap_or(1.0);

    let console_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let telemetry_filter = EnvFilter::new(otel_log_level);

    let stdout_layer = fmt::layer().with_ansi(true).with_filter(console_filter);

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
            .with_service_name("praeco-rs")
            .build();

        let provider = SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_sampler(sampler)
            .with_resource(resource)
            .build();

        opentelemetry::global::set_tracer_provider(provider.clone());
        opentelemetry::global::set_text_map_propagator(
            opentelemetry_sdk::propagation::TraceContextPropagator::new(),
        );

        let tracer = provider.tracer("praeco-rs");
        let layer = tracing_opentelemetry::layer()
            .with_tracer(tracer)
            .with_filter(telemetry_filter);
        (Some(layer), Some(provider))
    } else {
        (None, None)
    };

    if let Some(dir) = log_dir {
        let file_appender = RollingFileAppender::builder()
            .rotation(tracing_appender::rolling::Rotation::DAILY)
            .filename_prefix("praeco")
            .filename_suffix("log")
            .build(dir)?;

        let (non_blocking_appender, _guard) = tracing_appender::non_blocking(file_appender);

        let file_layer = fmt::layer()
            .fmt_fields(FileFormatFields::default())
            .with_ansi(false)
            .with_writer(non_blocking_appender)
            .with_filter(
                EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
            );

        let subscriber = Registry::default()
            .with(telemetry_layer)
            .with(stdout_layer)
            .with(file_layer);

        tracing::subscriber::set_global_default(subscriber)?;

        Ok((Some(_guard), tracer_provider))
    } else {
        let subscriber = Registry::default().with(telemetry_layer).with(stdout_layer);
        tracing::subscriber::set_global_default(subscriber)?;
        Ok((None, tracer_provider))
    }
}

#[cfg(test)]
mod tests {
    use super::FileFormatFields;
    use std::io;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::{Registry, fmt, layer::SubscriberExt};

    #[derive(Clone, Default)]
    struct SharedWriter(Arc<Mutex<Vec<u8>>>);

    impl SharedWriter {
        fn into_string(self) -> String {
            String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
        }
    }

    impl io::Write for SharedWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> fmt::MakeWriter<'a> for SharedWriter {
        type Writer = SharedWriter;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    #[test]
    fn test_dual_fmt_layers_do_not_duplicate_recorded_traceparent() {
        let stdout_buf = SharedWriter::default();
        let file_buf = SharedWriter::default();

        let stdout_layer = fmt::layer().with_ansi(true).with_writer(stdout_buf.clone());
        let file_layer = fmt::layer()
            .fmt_fields(FileFormatFields::default())
            .with_ansi(false)
            .with_writer(file_buf.clone());

        let subscriber = Registry::default().with(stdout_layer).with(file_layer);

        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!(
                "request",
                http.method = "GET",
                traceparent = tracing::field::Empty
            );
            let _enter = span.enter();
            tracing::Span::current().record(
                "traceparent",
                "00-ac4746a75cdeaa2ef4f0be9bfa7bee9a-03fe4ad60e39c2cb-01",
            );
            tracing::info!("handled request");
        });

        let stdout_out = stdout_buf.into_string();
        let file_out = file_buf.into_string();

        let tp = "00-ac4746a75cdeaa2ef4f0be9bfa7bee9a-03fe4ad60e39c2cb-01";
        assert_eq!(stdout_out.matches(tp).count(), 1, "stdout: {stdout_out}");
        assert_eq!(file_out.matches("traceparent=").count(), 1, "file: {file_out}");
        assert_eq!(file_out.matches(tp).count(), 1, "file: {file_out}");
        assert!(
            !file_out.contains('\x1b'),
            "file log must not contain ANSI escapes: {file_out}"
        );
    }
}
