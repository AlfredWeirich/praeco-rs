//! # Server Binary — Entry Point & Lifecycle
//!
//! This is the main executable for the server application. It orchestrates:
//! RUST_LOG=warn,praeco_rs=trace,praeco_rs::middleware::logger=trace cargo run -p praeco-rs --release
//!
//! 1. **Configuration loading** via [`Config::init`].
//! 2. **Tokio runtime creation** with a configurable number of worker threads.
//! 3. **Tracing / logging setup** (stdout + optional rolling-file appender).
//! 4. **Per-server task spawning** — each `[[Server]]` block in `Config.toml`
//!    becomes an independent Tokio task.
//! 5. **Dual-stack listeners** — HTTPS servers accept both TCP (HTTP/1.1 + H2)
//!    and UDP (HTTP/3 via QUIC) on the **same port**.
//! 6. **Graceful shutdown** on `Ctrl-C` using a shared [`CancellationToken`].
//!
//! ## Architecture Overview
//!
//! ```text
//! main()
//!   └─ main_async()                       (tokio runtime)
//!       ├─ start_single_server(server_A)  (spawned task)
//!       │   ├─ build_service_stack()
//!       │   └─ run_dual_stack()
//!       │       ├─ run_tcp_listener()     (HTTP/1.1, H2)
//!       │       └─ run_udp_listener()     (H3/QUIC)
//!       ├─ start_single_server(server_B)
//!       │   └─ …
//!       └─ Ctrl-C handler → CancellationToken
//! ```
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

// tokio console: https://tokio.rs/tokio/topics/tracing-next-steps

/// Optimization 1
/// Use mimalloc as the global allocator for reduced contention
/// under heavy multi-threaded workloads (5–15% throughput gain).
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

// === Standard Library ===
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

// === External Crates ===
use anyhow::{Context, Error};
use hyper::Request;
use hyper_util::rt::TokioIo;
use tokio::{net::TcpListener, runtime::Builder};

use tokio_util::sync::CancellationToken;
use tower::{Layer, limit::ConcurrencyLimit};
use praeco_rs::BoxCloneSyncServiceExt;
use arc_swap::ArcSwap;
#[allow(unused_imports)]
use tracing::{debug, error, info, trace, warn, Instrument};
use tracing_appender::{non_blocking::WorkerGuard, rolling::RollingFileAppender};
use tracing_subscriber::{EnvFilter, Registry, fmt, layer::SubscriberExt};

// === Internal Modules ===

use praeco_rs::{
    BoxedCloneService, ConnectionHandler,
    configuration::{
        AuthenticationMethod, CompiledAllowedPathes, Config, MiddlewareLayer, Protocol,
        ServerConfig, ServiceType,
    },
    middleware::{
        CountingLayer, DelayLayer, EchoService, InspectionLayer, JwtAuthLayer, LoggerLayer,
        MaxPayloadLayer, RouterService, SecurityHeadersLayer, SimpleRateLimiterLayer, TimingLayer,
        TokenBucketRateLimiterLayer,
        alt_svc::AltSvcLayer,
        compression::{SrvCompressionLayer, SrvDecompressionLayer},
    },
    tls_conf::{extract_cert_san_and_pem, extract_oids_from_cert, tls_config},
};

use http_body_util::BodyExt;
use hyper::{Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioTimer};
use hyper_util::server::conn::auto;
use praeco_rs::H3Body;
use rustls::ServerConfig as RustlsServerConfig;


///    Main entry point for the server application.
///
/// This function is the "synchronous" wrapper that starts the program.
/// It performs the following steps:
/// 1. **Parse Arguments**: Looks for a configuration file path (default: `Config.toml`).
/// 2. **Load Configuration**: Reads and parses the global settings.
/// 3. **Setup Logging**: Initializes the tracing system to see what the server is doing.
/// 4. **Build Runtime**: Starts the Tokio runtime, which is the engine that drives all asynchronous tasks.
/// 5. **Start Server**: Launches the main asynchronous loop.
fn main() -> Result<(), Error> {
    let arg = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "Config.toml".to_string());

    // This installs 'ring' as the default provider for the entire process.
    // Ensure you have the 'ring' feature enabled in rustls (usually default).
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Initialize the global configuration from the provided file.
    // This uses a OnceLock pattern for safe, global read access.
    let config = Config::init(&arg)?;

    // Determine the number of Tokio worker threads. Defaults to 2x logical CPUs if not specified.
    let tokio_threads = config.tokio_threads.unwrap_or_else(num_cpus::get);

    // Build the high-performance multi-threaded Tokio runtime.
    let runtime = Builder::new_multi_thread()
        .worker_threads(tokio_threads)
        .enable_all()
        .build()
        .context("Failed to build Tokio runtime")?;

    // Enter the runtime context so that OTLP can spawn its background export task.
    let _rt_guard = runtime.enter();

    // Setup the tracing/logging system (stdout and optional file appender).
    // Use _guard to keep the non-blocking appender alive until the end of main.
    let _tracing_guard = setup_tracing(&config)?;

    info!("Configuration loaded from: {}", arg);
    trace!("Full Config: {:#?}", config);

    // Block the main thread on the execution of the asynchronous server loop.
    runtime.block_on(main_async(config))
}

/// The asynchronous main loop that manages multiple server instances.
///
/// Think of this as the "Mission Control" center.
/// - It reads the list of servers from the config.
/// - For each enabled server, it launches a separate, independent task (green thread).
/// - It listens for a "Shutdown Signal" (like pressing Ctrl+C).
/// - It ensures all servers stop gracefully before the program exits.
async fn main_async(config: Arc<Config>) -> Result<(), Error> {
    let mut server_join_set = tokio::task::JoinSet::new();

    // Map: port -> (CancellationToken, Arc<ServerConfig>, Arc<ArcSwap<BoxedCloneService>>)
    let mut active_servers: HashMap<
        u16,
        (
            CancellationToken,
            Arc<ServerConfig>,
            Arc<ArcSwap<BoxedCloneService>>,
        ),
    > = HashMap::new();

    // Iterate through all configured servers and spawn tasks for those that are enabled.
    // Each enabled server gets its own cancellation token, configuration snapshot, and
    // dynamic service stack (wrapped in a Mutex so we can hot-swap it upon reload).
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

        active_servers.insert(
            server_config.port,
            (
                cancel_token.clone(),
                server_config_arc.clone(),
                dynamic_stack.clone(),
            ),
        );

        server_join_set.spawn(async move {
            start_single_server(server_config_arc, cancel_token, dynamic_stack).await;
        });
    }

    let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup())?;

    // Wait for a shutdown signal or handle configuration reloads
    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                info!("Shutdown signal received (Ctrl+C). Starting graceful shutdown...");
                break;
            }
            _ = sighup.recv() => {
                info!("Received SIGHUP, initiating hot-reload...");

                // 1. Reload configuration from disk
                // Config::init reads the file and returns the new Arc<Config>.
                // It also updates the globally available rustls CertifiedKeys (via ArcSwap)
                // so that DynamicCertResolver instantly gets the new certificates.
                let new_config = match Config::init("Config.toml") {
                    Ok(c) => c,
                    Err(e) => {
                        error!("Failed to reload config on SIGHUP, ignoring: {:?}", e);
                        continue;
                    }
                };

                info!("Successfully parsed new Config.toml");

                // 2. DRY-RUN PASS: Build all service stacks first
                let mut reload_errors = Vec::new();
                let mut built_stacks = std::collections::HashMap::new();

                for new_server in &new_config.servers {
                    if !new_server.enabled { continue; }
                    let server_config_arc = Arc::new(new_server.clone());
                    match build_service_stack(&server_config_arc) {
                        Ok(svc) => {
                            built_stacks.insert(new_server.port, (server_config_arc, svc));
                        }
                        Err(e) => {
                            error!("{}: FAILED to build service stack (dry-run): {:?}", new_server.name, e);
                            reload_errors.push((new_server.name.clone(), e.to_string()));
                        }
                    }
                }

                if !reload_errors.is_empty() {
                    error!("Hot-reload aborted! {} server(s) failed to build their service stacks:", reload_errors.len());
                    for (name, err) in &reload_errors {
                        error!(" - {}: {}", name, err);
                    }
                    error!("Keeping previous configuration completely intact.");
                    continue; // Abort SIGHUP handling, leave `active_servers` unmodified
                }

                // 3. APPLY PASS: Diff and manage listeners
                info!("Dry-run passed. Applying new configuration...");
                let mut next_active_servers = std::collections::HashMap::new();

                for (port, (server_config_arc, service_stack)) in built_stacks {
                    let new_server = &server_config_arc;
                    let needs_restart = match active_servers.get(&port) {
                        None => true, // New listener on this port
                        Some((_, old_server, _)) => {
                            // Restart listener if fundamental binding parameters changed
                            old_server.ip != new_server.ip || old_server.protocol != new_server.protocol
                        }
                    };

                    if needs_restart {
                        info!("Starting new listener for '{}' on port {}", new_server.name, port);
                        let cancel_token = CancellationToken::new();
                        let dynamic_stack = Arc::new(ArcSwap::from_pointee(service_stack));

                        next_active_servers.insert(
                            port,
                            (cancel_token.clone(), server_config_arc.clone(), dynamic_stack.clone()),
                        );

                        let cloned_config = server_config_arc.clone();
                        server_join_set.spawn(async move {
                            start_single_server(cloned_config, cancel_token, dynamic_stack).await;
                        });
                    } else {
                        // Keep listener alive!
                        // Removing from active_servers so we know which ones to drop later
                        let (old_token, _, dynamic_stack) = active_servers.remove(&port).unwrap();
                        
                        // Hot-swap service stack for new config
                        dynamic_stack.store(Arc::new(service_stack));
                        info!("Hot-swapped service stack for '{}' on port {}", new_server.name, port);

                        next_active_servers.insert(port, (old_token, server_config_arc.clone(), dynamic_stack));
                    }
                }

                // 4. Stop drained/removed listeners
                for (port, (token, old_server, _)) in active_servers.drain() {
                    info!("Stopping listener for '{}' on port {}", old_server.name, port);
                    token.cancel();
                }

                active_servers = next_active_servers;
                info!("Hot-reload complete.");
            }
        }
    }

    // Cancel all running listeners on graceful shutdown
    for (_, (token, _, _)) in active_servers {
        token.cancel();
    }

    // Await the completion of all spawned server tasks.
    while let Some(res) = server_join_set.join_next().await {
        if let Err(e) = res {
            error!("Server task panicked or failed prematurely: {:?}", e);
        }
    }

    info!("All servers shut down cleanly.");
    opentelemetry::global::shutdown_tracer_provider();
    Ok(())
}

/// Starts a single server instance (HTTP or HTTPS/H3) based on the provided configuration.
///
/// This is where the specific instructions for one server (one port) are executed.
///
/// # Architecture & Lifecycle:
/// 1. **Active Health Checks**: If defining a router, it establishes dedicated
///    background loops (`tokio::spawn`) to ping upstreams.
///    - For HTTP/REST backends, it issues `GET /health` requests.
///    - For gRPC backends, it dynamically evaluates the endpoint using **gRPC Reflection Layer**,
///      locating a `health` RPC method and invoking it with a 5-byte uncompressed empty payload.
/// 2. **Resolve IP**: Evaluates the `SocketAddr` to bind based on `0.0.0.0` or hostname.
/// 3. **Protocol Dispatch**:
///    - **HTTPS (Dual Stack)**: Starts *two* concurrent listeners: a standard TCP listener
///      (for HTTP/1.1 and HTTP/2 connections over TLS) and a UDP QUIC endpoint (for HTTP/3).
///    - **HTTP (Plaintext)**: Starts a single basic TCP listener using Hyper's legacy
///      auto-connection builder, injecting timeouts to mitigate Slowloris attacks.
async fn start_single_server(
    server_config: Arc<ServerConfig>,
    cancel_token: CancellationToken,
    dynamic_stack: Arc<ArcSwap<BoxedCloneService>>,
) {
    if server_config.service == ServiceType::Router {
        spawn_router_health_checks(&server_config, cancel_token.clone());
    }

    let server_addr = match server_config.get_server_ip() {
        Ok(addr) => addr,
        Err(e) => {
            error!("{}: Failed to resolve IP: {:?}", server_config.name, e);
            return;
        }
    };

    info!(
        "{}: Listening on {} ({:?})",
        server_config.name, server_addr, server_config.protocol
    );

    // === HTTPS / DUAL STACK PATH ===
    let oid_mapping = Arc::new(server_config.oid_mapping.clone());

    if let Some(tunnel) = &server_config.tunnel {
        info!("{}: Connecting to Zero-Trust Tunnel at {}", server_config.name, tunnel.target_url);
        let tls_config: Arc<RustlsServerConfig> = match build_rustls_config(server_config.as_ref()) {
            Ok(cfg) => Arc::new(cfg),
            Err(e) => {
                error!("{}: TLS Setup Error: {:?}", server_config.name, e);
                return;
            }
        };

        let mut retry_count = 0;
        let initial_delay = Duration::from_secs(1);

        loop {
            if cancel_token.is_cancelled() {
                break;
            }

            if let Err(e) = run_tunnel(
                tunnel.clone(),
                tls_config.clone(),
                dynamic_stack.clone(),
                cancel_token.clone(),
                server_config.static_name.expect("missing static_name"),
                oid_mapping.clone(),
            ).await {
                error!("{}: Tunnel crashed: {:?}", server_config.name, e);
            } else {
                info!("{}: Tunnel connection ended cleanly", server_config.name);
            }

            retry_count += 1;
            let delay = initial_delay * 2u32.pow(retry_count.min(6));
            warn!("{}: Reconnecting tunnel in {:?}", server_config.name, delay);
            
            tokio::select! {
                _ = tokio::time::sleep(delay) => {},
                _ = cancel_token.cancelled() => {
                    break;
                }
            }
        }
        return;
    }

    if server_config.protocol == Protocol::Https {
        let tls_config: RustlsServerConfig = match build_rustls_config(server_config.as_ref()) {
            Ok(cfg) => cfg,
            Err(e) => {
                error!("{}: TLS Setup Error: {:?}", server_config.name, e);
                return;
            }
        };

        if let Err(e) = run_dual_stack(
            server_addr,
            tls_config,
            dynamic_stack,
            cancel_token,
            server_config.static_name.expect("missing static_name"),
            oid_mapping,
        )
        .await
        {
            error!(
                "{}: HTTPS/Dual Stack Server crashed: {:?}",
                server_config.name, e
            );
        }
    } else {
        // === HTTP (PLAINTEXT) FALLBACK ===
        // Your original logic for plaintext HTTP only
        let listener = match TcpListener::bind(server_addr).await {
            Ok(l) => l,
            Err(e) => {
                error!("{}: HTTP Bind failed: {}", server_config.name, e);
                return;
            }
        };

        loop {
            tokio::select! {
                _ = cancel_token.cancelled() => break,
                res = listener.accept() => {
                    match res {
                        Ok((stream, peer_addr)) => {
                            let svc = (**dynamic_stack.load()).clone(); // fresh stack per connection
                            let conn_token = cancel_token.clone();
                            let oid_mapping = oid_mapping.clone();
                            tokio::spawn(async move {
                                let handler = ConnectionHandler::new(svc, peer_addr, Vec::new(), None, None, oid_mapping);
                                let mut builder = auto::Builder::new(TokioExecutor::new());
                                // Timeout: drop clients that take too long to send HTTP/1 headers
                                builder.http1()
                                    .timer(TokioTimer::new())
                                    .header_read_timeout(Duration::from_secs(10));
                                // Timeout: detect dead HTTP/2 connections via keep-alive pings
                                builder
                                    .http2()
                                    .timer(TokioTimer::new())
                                    .initial_stream_window_size(1024 * 1024)
                                    .max_concurrent_streams(1024)
                                    .max_pending_accept_reset_streams(Some(16384))
                                    .keep_alive_interval(Some(Duration::from_secs(30)))
                                    .keep_alive_timeout(Duration::from_secs(10));
                                let conn = builder
                                    .serve_connection(TokioIo::new(stream), handler);
                                let mut conn = std::pin::pin!(conn);
                                tokio::select! {
                                    res = conn.as_mut() => { let _ = res; },
                                    _ = conn_token.cancelled() => {
                                        conn.as_mut().graceful_shutdown();
                                        let _ = conn.await;
                                    }
                                }
                            });
                        }
                        Err(e) => error!("{}: HTTP Accept error: {}", server_config.name, e),
                    }
                }
            }
        }
    }
}

/// Spawns the background active health checker loops for upstream router targets.
///
/// This evaluates all `parsed_routes` in the given `ServerConfig`. For any backend marked
/// with a non-zero health check interval, this method provisions dedicated keep-alive
/// hyper clients (either HTTP/2 exclusively for gRPC, or generic for REST) and spawns a repeating
/// `tokio::select!` loop to heartbeat the instance.
fn spawn_router_health_checks(server_config: &Arc<ServerConfig>, cancel_token: CancellationToken) {
    // Check if router parameters are configured for this server instance
    if let Some(router_params) = &server_config.router_params {
        // --- 1. TLS Context Initialization for Upstreams ---
        // If the router needs to speak HTTPS/mTLS to its backends, we build a trusted root store.
        let root_store = common::build_root_store(&router_params.ssl_root_certificate);

        // Check if mutual TLS (mTLS) is required (i.e., the proxy must present its own certificate)
        let is_mtls = router_params.authentication == AuthenticationMethod::ClientCert;

        // Build the exact TLS handshake instructions this proxy will use when calling upstream nodes.
        let tls_client_config = if is_mtls {
            common::build_tls_client_config(
                root_store,
                router_params.ssl_client_certificate.as_deref(), // The proxy's own client cert
                router_params.ssl_client_key.as_deref(),         // The proxy's private key
            )
        } else {
            // Standard TLS (only verifying the server, no client certificate provided)
            common::build_tls_client_config(root_store, None, None)
        };

        // --- 2. Connection Pool Setup ---
        // To maximize throughput, the proxy maintains keep-alive connection pools.
        // This avoids the overhead of establishing a new TCP/TLS connection for every health check.

        // gRPC-specific pool: gRPC strictly requires HTTP/2 multiplexing.
        // We enforce `http2_only: true` so it strictly negotiates H2 during the TLS ALPN handshake.
        let grpc_pool_config = common::client::ClientPoolConfig {
            idle_timeout: Some(Duration::from_secs(30)),
            max_idle_per_host: Some(16),
            http2_only: true, // Force HTTP/2 for gRPC
        };
        // Build the client specifically for gRPC health checks
        let grpc_client =
            common::client::build_hyper_client(tls_client_config.clone(), grpc_pool_config);

        // Standard REST/HTTP pool: Allows HTTP/1.1 or H2 depending on what the upstream server supports.
        let pool_config = common::client::ClientPoolConfig {
            idle_timeout: Some(Duration::from_secs(30)),
            max_idle_per_host: Some(16),
            http2_only: false, // Default negotiation for standard web traffic
        };

        // Build the client for standard REST health checks
        let client = common::client::build_hyper_client(tls_client_config, pool_config);

        // --- Authentication Setup ---
        // Process a pre-configured static JWT Bearer token if this proxy needs to authenticate
        // to upstreams via Authorization header.
        let jwt_token = router_params
            .jwt
            .as_ref()
            .and_then(|t| hyper::header::HeaderValue::from_str(&format!("Bearer {}", t)).ok());

        // Determine the default protocol string (http or https) to use if a target URI doesn't specify one
        let proto_str = match router_params.protocol {
            Protocol::Https => "https",
            Protocol::Http => "http",
        };

        // --- 3. Active Health Check Initialization ---
        // Iterate over all routing rules to find upstreams that require active health monitoring.
        for route in &server_config.parsed_routes {
            // The interval (in seconds) between health checks. 0 means disabled.
            let interval = route.target.active_health_check_interval;
            let is_grpc = route.backend_type
                == praeco_rs::configuration::RouteBackendType::GrpcTranscoding
                || route.backend_type
                    == praeco_rs::configuration::RouteBackendType::GrpcPassthrough;

            // If interval > 0, the user wants the proxy to automatically ping the servers in the background
            // to evict them from the load-balancer if they die, and re-add them when they recover.
            if interval > 0 {
                // Iterate through all individual backend nodes (upstreams) for this route
                for (idx, node) in route.target.upstreams.iter().enumerate() {
                    // Select the appropriate hyper connection pool based on the backend type
                    let client = if is_grpc {
                        grpc_client.clone()
                    } else {
                        client.clone()
                    };

                    // Clone the cancellation token so the spawned task can stop cleanly upon shutdown/reload
                    let token = cancel_token.clone();

                    // Parse target URIs stringly. Use `proto_str` as a fallback boundary
                    // if the user omitted `http://` or `https://` in the config.
                    let base_uri_str = format!(
                        "{}://{}",
                        node.uri.scheme_str().unwrap_or(proto_str),
                        node.uri.authority().unwrap().as_str()
                    );
                    let base_uri = base_uri_str.parse::<hyper::Uri>().unwrap();

                    // By default, REST active health checks use the `/health` convention relative to the root.
                    // This creates the full URI for REST pinging.
                    let rest_uri = format!("{}/health", base_uri_str)
                        .parse::<hyper::Uri>()
                        .unwrap();

                    // Prepare captured variables for the background task
                    let server_name = server_config.static_name.unwrap_or("unknown");
                    let interval_dur = Duration::from_secs(interval);
                    let target_arc = route.target.clone(); // Access to the shared upstream health state
                    let auth_header = jwt_token.clone();
                    let router_params = router_params.clone();

                    // Spawn a dedicated Tokio task (green thread) for this specific upstream node
                    tokio::spawn(async move {
                        // Create a timer to fire repeatedly according to the configured interval
                        let mut ticker = tokio::time::interval(interval_dur);
                        // Set tick behavior so it doesn't burst/spam if delayed (e.g., due to CPU starvation)
                        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

                        // For gRPC, we resolve the health path structurally using Server Reflection (lazily)
                        let mut grpc_health_path: Option<String> = None;
                        // Flag to ensure we only try reflection resolution once to avoid overhead
                        let mut checked_grpc_reflection = false;

                        // The infinite loop for periodic health checking
                        loop {
                            // Select between cancellation signal and the next tick timer
                            tokio::select! {
                                _ = token.cancelled() => break, // Graceful exit condition
                                _ = ticker.tick() => {
                                    let final_uri;
                                    let mut req_builder = Request::builder();

                                    if is_grpc {
                                        // --- gRPC Health Check Resolution ---
                                        // On the first run, try to dynamically fetch the server's protobuf schema
                                        // using gRPC reflection, and search it for a method named "health".
                                        if !checked_grpc_reflection {
                                            checked_grpc_reflection = true;

                                            // Acquire write lock to initialize the grpc reflection pool if empty
                                            let mut pool_guard = target_arc.grpc_pool.write().await;
                                            if pool_guard.is_none() {
                                                match praeco_rs::middleware::router::build_grpc_pool(&base_uri, Some(&router_params)).await {
                                                    Ok(p) => *pool_guard = Some(p),
                                                    Err(e) => tracing::warn!("{}: Failed to load gRPC reflection schema for active health check: {:?}", server_name, e)
                                                }
                                            }

                                            // Search the loaded schema specifically for a health check endpoint
                                            if let Some(pool) = pool_guard.as_ref() {
                                                for service in pool.services() {
                                                    for method in service.methods() {
                                                        // Commonly, gRPC services implement an endpoint containing 'health'
                                                        if method.name() == "health" {
                                                            grpc_health_path = Some(format!("/{}/health", service.full_name()));
                                                            break;
                                                        }
                                                    }
                                                    if grpc_health_path.is_some() { break; }
                                                }
                                            }

                                            if grpc_health_path.is_none() {
                                                tracing::warn!("{}: No 'health' method found in gRPC reflection schema for {}; skipping active health check", server_name, base_uri);
                                            }
                                        }

                                        // Formulate the gRPC request using the discovered route
                                        if let Some(path) = &grpc_health_path {
                                            final_uri = format!("{}{}", base_uri_str, path).parse::<hyper::Uri>().unwrap();
                                            req_builder = req_builder.method(hyper::Method::POST).uri(final_uri.clone());
                                            req_builder = req_builder.header("content-type", "application/grpc");
                                            req_builder = req_builder.header("te", "trailers"); // required for gRPC trailer blocks
                                        } else {
                                            // Skip this cycle if we couldn't resolve a gRPC endpoint
                                            continue;
                                        }
                                    } else {
                                        // --- REST Health Check ---
                                        // For REST, just use the statically defined GET /health endpoint
                                        final_uri = rest_uri.clone();
                                        req_builder = req_builder.method(hyper::Method::GET).uri(final_uri.clone());
                                    }

                                    // Append authorization token if configured
                                    if let Some(ref header_val) = auth_header {
                                        req_builder = req_builder.header(hyper::header::AUTHORIZATION, header_val.clone());
                                    }

                                    // Build the appropriate HTTP request body
                                    let req_body = if is_grpc && grpc_health_path.is_some() {
                                        // gRPC Payload Structure for an empty request message:
                                        // 1 byte compressed flag (0 = false), 4 bytes length (0) -> 0x00000000
                                        let payload = bytes::Bytes::from(vec![0u8, 0, 0, 0, 0]);
                                        http_body_util::Full::new(payload).map_err(|e| match e {}).boxed()
                                    } else {
                                        // REST usually sends an empty body for GET /health checks
                                        http_body_util::Empty::<bytes::Bytes>::new().map_err(|e| match e {}).boxed()
                                    };

                                    // Dispatch the request asynchronously over the connection pool
                                    let req = req_builder.body(req_body).unwrap();
                                    // TODO: Move this hardcoded 5s timeout to Config.toml in the future
                                    match tokio::time::timeout(Duration::from_secs(5), client.request(req)).await {
                                        Ok(Ok(mut resp)) => {

                                            // We consider any 200 OK status as a healthy indication
                                            let is_ok = resp.status() == StatusCode::OK;
                                            let mut health_score_ok = true;

                                            // If it's a gRPC health check, parse the HealthScore
                                            if is_ok && is_grpc && grpc_health_path.is_some() {
                                                use http_body_util::BodyExt;
                                                if let Ok(bytes) = resp.body_mut().collect().await.map(|b| b.to_bytes()) {
                                                    // Frame format: 1 byte compressed flag, 4 bytes length, then protobuf payload
                                                    if bytes.len() >= 5 {
                                                        let payload_len = u32::from_be_bytes(bytes[1..5].try_into().unwrap()) as usize;
                                                        if bytes.len() >= 5 + payload_len {
                                                            let raw_payload = &bytes[5..5 + payload_len];

                                                            // HealthScore is { uint32 score = 1; }
                                                            // For small varints like <= 127 in field 1, it's just `0x08 <val>`
                                                            // We can decode the varint manually, or use a dynamic message.
                                                            // Since we don't have statically compiled prost bindings in `server`,
                                                            // let's do a simple manual decode of the protobuf payload.
                                                            let mut healthy = false;
                                                            if raw_payload.len() >= 2 && raw_payload[0] == 0x08 { // field 1, varint
                                                                // Decode varint (simplified assuming score is 0-100, so it fits in 1 byte)
                                                                let score = raw_payload[1];
                                                                target_arc.upstreams[idx].current_score.store(score as usize, std::sync::atomic::Ordering::Relaxed);
                                                                if score > 0 {
                                                                    healthy = true;
                                                                }
                                                            }

                                                            if !healthy {
                                                                health_score_ok = false;
                                                            }
                                                        } else {
                                                            health_score_ok = false; // Truncated
                                                        }
                                                    } else {
                                                        health_score_ok = false; // Too short to be a valid frame
                                                    }
                                                } else {
                                                    health_score_ok = false; // Failed to read body
                                                }
                                            } else if is_ok && !is_grpc {
                                                // For REST, parse the JSON {"score": 100} response
                                                use http_body_util::BodyExt;
                                                if let Ok(bytes) = resp.body_mut().collect().await.map(|b| b.to_bytes()) {
                                                    if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                                                        if let Some(score) = json.get("score").and_then(|s| s.as_u64()) {
                                                            target_arc.upstreams[idx].current_score.store(score as usize, std::sync::atomic::Ordering::Relaxed);
                                                            if score == 0 {
                                                                health_score_ok = false;
                                                            }
                                                        } else {
                                                            // if no score field exists, we should probably consider it unhealthy based on the new convention
                                                            health_score_ok = false;
                                                        }
                                                    } else {
                                                        health_score_ok = false; // Invalid JSON
                                                    }
                                                } else {
                                                    health_score_ok = false; // Failed to read body
                                                }
                                            }

                                            if is_ok && health_score_ok {
                                                let current_score = target_arc.upstreams[idx].current_score.load(std::sync::atomic::Ordering::Relaxed);
                                                tracing::trace!("{}: Health check successful for '{}', score: {}", server_name, final_uri, current_score);
                                                // If the node was previously considered dead, revive it in the LB
                                                if !target_arc.upstreams[idx].is_alive.load(std::sync::atomic::Ordering::Relaxed) {
                                                    info!("{}: Health check recovered '{}'", server_name, final_uri);
                                                    target_arc.upstreams[idx].is_alive.store(true, std::sync::atomic::Ordering::Relaxed);
                                                }
                                            } else {
                                                target_arc.upstreams[idx].current_score.store(0, std::sync::atomic::Ordering::Relaxed);
                                                // If it returns non-200 and was marked alive, consider it dead
                                                if target_arc.upstreams[idx].is_alive.load(std::sync::atomic::Ordering::Relaxed) {
                                                    tracing::warn!("{}: Health check failed status {} for '{}' (Score OK: {})", server_name, resp.status(), final_uri, health_score_ok);
                                                    target_arc.upstreams[idx].is_alive.store(false, std::sync::atomic::Ordering::Relaxed);
                                                }
                                            }
                                        }
                                        Ok(Err(e)) => {
                                            target_arc.upstreams[idx].current_score.store(0, std::sync::atomic::Ordering::Relaxed);
                                            // Network errors means the node is dead/unresponsive
                                            if target_arc.upstreams[idx].is_alive.load(std::sync::atomic::Ordering::Relaxed) {
                                                tracing::warn!("{}: Health check network error for '{}': {}", server_name, final_uri, e);
                                                target_arc.upstreams[idx].is_alive.store(false, std::sync::atomic::Ordering::Relaxed);
                                            }
                                        }
                                        Err(_) => {
                                            target_arc.upstreams[idx].current_score.store(0, std::sync::atomic::Ordering::Relaxed);
                                            // Timeout means the node is dead/unresponsive
                                            if target_arc.upstreams[idx].is_alive.load(std::sync::atomic::Ordering::Relaxed) {
                                                tracing::warn!("{}: Health check timed out after 5s for '{}'", server_name, final_uri);
                                                target_arc.upstreams[idx].is_alive.store(false, std::sync::atomic::Ordering::Relaxed);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    });
                }
            }
        }
    }
}

/// Builds the service stack for a given server configuration.
///
/// This function takes a `ServerConfig` and constructs a `BoxedCloneService`
/// by applying a series of middleware layers defined in the configuration.
/// It also ensures that if an `InspectionLayer` is used, the `compiled_allowed_pathes`
/// are correctly provided.
///
/// # Arguments
/// * `config` - A static reference to the `ServerConfig` for which to build the service stack.
///
/// # Returns
/// A `Result` which is `Ok` containing a `BoxedCloneService` if successful,
/// or an `Error` if the service stack cannot be built (e.g., missing compiled paths).
fn build_service_stack(server_config: &Arc<ServerConfig>) -> Result<BoxedCloneService, Error> {
    let layers = server_config.layers.build_middleware_layers(&server_config.name)?;

    // Ensure compiled paths are available.
    // While the InspectionLayer will also validate this, checking here provides
    // an early configuration error if the paths are missing when needed.
    let compiled_allowed_pathes =
        server_config
            .compiled_allowed_pathes
            .as_ref()
            .context(format!(
                "Server '{}': Compiled paths missing",
                server_config.name
            ))?;

    let base_service = match server_config.service {
        ServiceType::Echo => {
            EchoService::new(server_config.static_name.expect("static_name missing")).boxed_clone_sync()
        }
        ServiceType::Router => RouterService::new(server_config.clone()).boxed_clone_sync(),
        ServiceType::Idp => {
            let params = server_config.idp_params.as_ref().expect("IdpParams missing").clone();
            let idp_service = praeco_rs::middleware::idp::IdpService::new(params, server_config.static_name.expect("static_name missing")).expect("Failed to init IdP Service");
            praeco_rs::BoxCloneSyncService::new(idp_service)
        }
    };

    let applied = apply_layers(
        base_service, // The core service (Echo or Router) handling the request
        layers,
        server_config.static_name.expect("static_name missing"),
        compiled_allowed_pathes.clone(),
        server_config.port,
        Arc::new(server_config.oid_mapping.clone()),
    );

    use tower_http::trace::{DefaultOnResponse, TraceLayer};
    use tracing::{Level, info_span};

    let traced = tower::ServiceBuilder::new()
        .map_response(|res: hyper::Response<_>| {
            res.map(|b| {
                // Box the body to match SrvBody (BoxBody<Bytes, SrvError>)
                http_body_util::BodyExt::map_err(b, praeco_rs::SrvError::from).boxed()
            })
        })
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(|request: &hyper::Request<_>| {
                    let path = request.uri().path();
                    let method = request.method();
                    let otel_name = format!("{} {}", method, path);
                    info_span!(
                        "request",
                        otel.name = otel_name.as_str(),
                        http.method = %method,
                        http.uri = %request.uri()
                    )
                })
                .on_response(DefaultOnResponse::new().level(Level::INFO)),
        )
        .service(applied);

    Ok(traced.boxed_clone_sync())
}

/// Applies the configured middleware layers to the base service.
///
/// This function builds the final service stack by wrapping the base service with each middleware layer
/// defined in the configuration. The layers are applied in reverse order (outside-in execution flow),
/// so the first layer in the list is the outermost wrapper.
///
/// # Arguments
///
/// * `service` - The base service (e.g., Echo or Router) to wrap.
/// * `layers` - A list of middleware layers to apply.
/// * `server_name` - The name of the server, used for logging and metrics.
/// * `compiled_allowed_pathes` - Pre-compiled regex paths for the inspection layer (if used).
/// * `server_port` - The port the server listens on, used for `Alt-Svc` headers.
///
/// # Returns
///
/// A `BoxedCloneService` representing the full middleware stack ready to handle requests.
fn apply_layers(
    service: BoxedCloneService,
    layers: Vec<MiddlewareLayer>,
    server_name: &'static str,
    compiled_allowed_pathes: Arc<CompiledAllowedPathes>,
    server_port: u16, // <--- Add this argument
    oid_mapping: Arc<std::collections::HashMap<String, praeco_rs::configuration::UserRole>>,
) -> BoxedCloneService {
    layers
        .into_iter()
        .rev()
        .fold(service, |svc, layer| match layer {
            MiddlewareLayer::TraceId => praeco_rs::middleware::TraceIdLayer::new().layer(svc).boxed_clone_sync(),
            MiddlewareLayer::Timing => TimingLayer::new(server_name).layer(svc).boxed_clone_sync(),
            MiddlewareLayer::Counter => CountingLayer::new(server_name).layer(svc).boxed_clone_sync(),
            MiddlewareLayer::Logger => LoggerLayer::new(server_name).layer(svc).boxed_clone_sync(),
            MiddlewareLayer::Inspection => {
                InspectionLayer::new(compiled_allowed_pathes.clone(), server_name)
                    .layer(svc)
                    .boxed_clone_sync()
            }
            MiddlewareLayer::Delay(micros) => {
                DelayLayer::new(Duration::from_micros(micros), server_name)
                    .layer(svc)
                    .boxed_clone_sync()
            }
            MiddlewareLayer::JwtAuth(cfg) => {
                JwtAuthLayer::new(
                    cfg.jwt_public_keys.clone(),
                    server_name,
                    oid_mapping.clone(),
                    cfg.cookie_fallback.clone(),
                    cfg.redirect_on_failure.clone(),
                    cfg.expected_issuer.clone(),
                    cfg.expected_audience.clone(),
                )
                .layer(svc)
                .boxed_clone_sync()
            }
            MiddlewareLayer::RateLimiter(praeco_rs::configuration::RateLimiter::Simple(cfg)) => {
                let dur = Duration::from_secs_f32(1.0 / cfg.requests_per_second as f32);
                SimpleRateLimiterLayer::new(dur, server_name)
                    .layer(svc)
                    .boxed_clone_sync()
            }
            MiddlewareLayer::RateLimiter(
                praeco_rs::configuration::RateLimiter::TokenBucket(cfg),
            ) => TokenBucketRateLimiterLayer::new(
                cfg.max_capacity,
                cfg.refill,
                Duration::from_micros(cfg.duration_micros),
                server_name,
            )
            .layer(svc)
            .boxed_clone_sync(),
            MiddlewareLayer::ConcurrencyLimit(max_requests) => {
                // Here we directly use the extracted usize value
                ConcurrencyLimit::new(svc, max_requests).boxed_clone_sync()
            }
            MiddlewareLayer::Compression => SrvCompressionLayer::new(server_name)
                .layer(svc)
                .boxed_clone_sync(),
            MiddlewareLayer::Decompression(max_bytes) => {
                SrvDecompressionLayer::new(server_name, max_bytes)
                    .layer(svc)
                    .boxed_clone_sync()
            }
            MiddlewareLayer::MaxPayload(max_bytes) => MaxPayloadLayer::new(max_bytes, server_name)
                .layer(svc)
                .boxed_clone_sync(),
            MiddlewareLayer::AltSvc => {
                // We use the actual running port of the server
                AltSvcLayer::new(server_port).layer(svc).boxed_clone_sync()
            }
            MiddlewareLayer::Cors(cfg) => {
                let origins: Vec<hyper::http::HeaderValue> = cfg
                    .allowed_origins
                    .iter()
                    .filter_map(|o| o.parse().ok())
                    .collect();
                let methods: Vec<hyper::http::Method> = cfg
                    .allowed_methods
                    .iter()
                    .filter_map(|m| m.parse().ok())
                    .collect();
                let headers: Vec<hyper::http::header::HeaderName> = cfg
                    .allowed_headers
                    .iter()
                    .filter_map(|h| h.parse().ok())
                    .collect();

                let is_any_origin = cfg.allowed_origins.iter().any(|o| o == "*");
                let is_any_method = cfg.allowed_methods.iter().any(|m| m == "*");
                let is_any_header = cfg.allowed_headers.iter().any(|h| h == "*");

                macro_rules! apply_cors {
                    ($cors:expr) => {
                        $cors
                            .allow_credentials(cfg.allow_credentials)
                            .layer(svc)
                            .boxed_clone_sync()
                    };
                }

                match (is_any_origin, is_any_method, is_any_header) {
                    (true, true, true) => apply_cors!(
                        tower_http::cors::CorsLayer::new()
                            .allow_origin(tower_http::cors::Any)
                            .allow_methods(tower_http::cors::Any)
                            .allow_headers(tower_http::cors::Any)
                    ),
                    (true, true, false) => apply_cors!(
                        tower_http::cors::CorsLayer::new()
                            .allow_origin(tower_http::cors::Any)
                            .allow_methods(tower_http::cors::Any)
                            .allow_headers(headers)
                    ),
                    (true, false, true) => apply_cors!(
                        tower_http::cors::CorsLayer::new()
                            .allow_origin(tower_http::cors::Any)
                            .allow_methods(methods)
                            .allow_headers(tower_http::cors::Any)
                    ),
                    (true, false, false) => apply_cors!(
                        tower_http::cors::CorsLayer::new()
                            .allow_origin(tower_http::cors::Any)
                            .allow_methods(methods)
                            .allow_headers(headers)
                    ),
                    (false, true, true) => apply_cors!(
                        tower_http::cors::CorsLayer::new()
                            .allow_origin(origins)
                            .allow_methods(tower_http::cors::Any)
                            .allow_headers(tower_http::cors::Any)
                    ),
                    (false, true, false) => apply_cors!(
                        tower_http::cors::CorsLayer::new()
                            .allow_origin(origins)
                            .allow_methods(tower_http::cors::Any)
                            .allow_headers(headers)
                    ),
                    (false, false, true) => apply_cors!(
                        tower_http::cors::CorsLayer::new()
                            .allow_origin(origins)
                            .allow_methods(methods)
                            .allow_headers(tower_http::cors::Any)
                    ),
                    (false, false, false) => apply_cors!(
                        tower_http::cors::CorsLayer::new()
                            .allow_origin(origins)
                            .allow_methods(methods)
                            .allow_headers(headers)
                    ),
                }
            }
            MiddlewareLayer::SecurityHeaders(cfg) => {
                SecurityHeadersLayer::new(cfg).layer(svc).boxed_clone_sync()
            }
        })
}

// === Refactored run_dual_stack ===

/// Runs a dual-stack server supporting both TCP (HTTP/1.1, HTTP/2) and UDP (HTTP/3).
///
/// # What is "Dual Stack"?
/// Modern web servers often need to speak two different "languages" on the transport layer:
/// 1. **TCP (Transmission Control Protocol)**: The traditional, reliable way to send data. Used for HTTP/1.1 and HTTP/2.
/// 2. **UDP (User Datagram Protocol)**: A faster, but less strict way to send data. Used for HTTP/3 (QUIC).
///
/// This function starts TWO listeners on the same port: one for TCP and one for UDP.
pub async fn run_dual_stack(
    server_addr: SocketAddr,
    tls_config: RustlsServerConfig,
    dynamic_stack: Arc<ArcSwap<BoxedCloneService>>,
    cancel_token: CancellationToken,
    server_name: &'static str,
    oid_mapping: Arc<std::collections::HashMap<String, praeco_rs::configuration::UserRole>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let arc_tls_config = Arc::new(tls_config);

    // We need two tokens for the two listeners
    let tcp_cancel_token = cancel_token.clone();
    let udp_cancel_token = cancel_token; // move the original

    // 1. TCP Listener (HTTP/1.1 & HTTP/2)
    let tcp_handle = run_tcp_listener(
        server_addr,
        arc_tls_config.clone(),
        dynamic_stack.clone(),
        tcp_cancel_token,
        server_name,
        oid_mapping.clone(),
    );

    // 2. UDP Listener (HTTP/3)
    let udp_handle = run_udp_listener(
        server_addr,
        arc_tls_config,
        dynamic_stack,
        udp_cancel_token,
        server_name,
        oid_mapping,
    );

    // Wait for both listeners to finish (shutdown signal)
    let _ = tokio::join!(tcp_handle, udp_handle);
    Ok(())
}

/// Runs the TCP listener for HTTPS traffic (supporting HTTP/1.1 and HTTP/2).
///
/// # How it works:
/// 1. **Bind**: Reserves the port for TCP connections.
/// 2. **Accept**: Waits for a client (like a browser) to connect.
/// 3. **Handshake**: Performs the TLS "secret handshake" to encrypt the connection.
/// 4. **Identify**: Checks the client's certificate for special IDs (OIDs) to know who they are.
/// 5. **Serve**: Starts a task to handle the requests using `hyper` (the HTTP engine).
async fn run_tcp_listener(
    server_addr: SocketAddr,
    tls_config: Arc<RustlsServerConfig>,
    dynamic_stack: Arc<ArcSwap<BoxedCloneService>>,
    cancel_token: CancellationToken,
    server_name: &'static str,
    oid_mapping: Arc<std::collections::HashMap<String, praeco_rs::configuration::UserRole>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let tcp_listener = TcpListener::bind(server_addr).await?;
    let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel_token.cancelled() => break,
                res = tcp_listener.accept() => {
                    if let Ok((stream, peer_addr)) = res {
                        // Optimization 2
                        // Disable Nagle's algorithm — send small responses immediately
                        // instead of waiting to batch them. Critical for low-latency APIs.
                        let _ = stream.set_nodelay(true);
                        let acceptor = acceptor.clone();
                        let dynamic_stack = dynamic_stack.clone();
                        let oid_mapping = oid_mapping.clone();
                        tokio::spawn(async move {
                            trace!("{}: TCP Connection accepted", server_name);
                            // Timeout: abort TLS handshakes that stall (Slowloris protection)
                            let tls_result = tokio::time::timeout(
                                Duration::from_secs(10),
                                acceptor.accept(stream),
                            ).await;
                            match tls_result {
                                Ok(Ok(tls_stream)) => {
                                    // --- TCP OID EXTRACTION ---
                                    let (_, session) = tls_stream.get_ref();
                                    let certs = session.peer_certificates();

                                    let mut client_cert_pem = None;
                                    let mut client_cert_san = None;

                                    let client_oids = if let Some(c) = certs.and_then(|c| c.first()) {
                                        let (pem, san) = extract_cert_san_and_pem(c.as_ref());
                                        client_cert_pem = pem;
                                        client_cert_san = san;
                                        extract_oids_from_cert(c.as_ref())
                                    } else {
                                        Vec::new()
                                    };

                                    let svc = (**dynamic_stack.load()).clone(); // fresh stack
                                    // Use the standard constructor which wraps Vec in Arc
                                    let handler = ConnectionHandler::new(svc, peer_addr, client_oids, client_cert_pem, client_cert_san, oid_mapping.clone());

                                    let mut builder = auto::Builder::new(TokioExecutor::new());
                                    // Timeout: drop clients that take too long to send HTTP/1 headers
                                    builder.http1()
                                    .timer(TokioTimer::new())
                                    .header_read_timeout(Duration::from_secs(10));
                                    // Timeout: detect dead HTTP/2 connections via keep-alive pings
                                    builder
                                        .http2()
                                        .timer(TokioTimer::new())
                                        .initial_stream_window_size(1024 * 1024)
                                        .max_concurrent_streams(1024)
                                        .max_pending_accept_reset_streams(Some(16384))
                                        .keep_alive_interval(Some(Duration::from_secs(30)))
                                        .keep_alive_timeout(Duration::from_secs(10));
                                    let _ = builder
                                        .serve_connection(TokioIo::new(tls_stream), handler)
                                        .await;
                                }
                                Ok(Err(e)) => {
                                    error!("{}: TLS Handshake failed: {}", server_name, e);
                                }
                                Err(_) => {
                                    trace!("{}: TLS Handshake timed out for {}", server_name, peer_addr);
                                }
                            }
                        });
                    }
                }
            }
        }
    });

    Ok(())
}

/// Runs the UDP listener for HTTP/3 traffic using QUIC (via `quinn` and `h3`).
///
/// # What is QUIC?
/// QUIC is a new transport protocol that runs on top of UDP. It's designed to be faster and more secure than TCP+TLS.
///
/// # Key Steps:
/// 1. **Config**: Sets up specific settings for QUIC (like telling clients "I speak h3").
/// 2. **Bind**: Reserves the port for UDP packets.
/// 3. **Listen**: Waits for QUIC packets to arrive.
/// 4. **Handle**: When a connection forms, it hands it off to `handle_h3_connection`.
async fn run_udp_listener(
    server_addr: SocketAddr,
    tls_config: Arc<RustlsServerConfig>,
    dynamic_stack: Arc<ArcSwap<BoxedCloneService>>,
    cancel_token: CancellationToken,
    server_name: &'static str,
    oid_mapping: Arc<std::collections::HashMap<String, praeco_rs::configuration::UserRole>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Determine if we need to modify the TLS config for QUIC (ALPN)
    // Quinn expects explicit "h3" ALPN
    let mut quic_tls_models = rustls::ServerConfig::clone(&tls_config);
    quic_tls_models.alpn_protocols = vec![b"h3".to_vec()];

    let quic_config = quinn::crypto::rustls::QuicServerConfig::try_from(quic_tls_models)
        .map_err(|e| format!("TLS Config Error for QUIC: {e}"))?;

    let mut quinn_server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_config));

    // Optimization 3
    // Tune QUIC transport for higher throughput (defaults are conservative)
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_uni_streams(1024u32.into());
    transport.max_concurrent_bidi_streams(1024u32.into());
    // Aggressively tune flow control windows to prevent stream resets under high load
    transport.receive_window(128_000_000u32.into());
    transport.send_window(128_000_000u64);
    transport.stream_receive_window(16_000_000u32.into());
    // Timeout: close idle QUIC connections after 30 seconds
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_secs(30)).unwrap(),
    ));
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    quinn_server_config.transport_config(Arc::new(transport));

    // Bind UDP socket
    let endpoint = quinn::Endpoint::server(quinn_server_config, server_addr)?;

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel_token.cancelled() => break,
                res = endpoint.accept() => {
                    if let Some(conn) = res {
                        trace!("{}: UDP Connection accepted", server_name);
                        let dynamic_stack = dynamic_stack.clone();
                        let oid_mapping = oid_mapping.clone();

                        tokio::spawn(async move {
                            if let Err(e) = handle_h3_connection(conn, dynamic_stack, server_name, oid_mapping).await {
                                error!("{}: H3 Connection Error: {:?}", server_name, e);
                            }
                        });
                    } else {
                        break; // Endpoint closed
                    }
                }
            }
        }
    });

    Ok(())
}

/// Handles a single HTTP/3 (QUIC) connection.
///
/// Unlike TCP where the OS handles the connection mostly, here we have to do a bit more work.
///
/// # Work Flow:
/// 1. **Connect**: Finishes establishing the QUIC connection.
/// 2. **Verify**: Checks who the client is (using their certificate) - **Just once** for the whole connection!
/// 3. **Loop**: Enters a loop where it waits for individual "Streams" (Requests).
///    - In HTTP/3, one connection can carry MANY requests at the same time.
/// 4. **Serve**: Passes each request to our `ConnectionHandler`.
async fn handle_h3_connection(
    connecting: quinn::Incoming,
    dynamic_stack: Arc<ArcSwap<BoxedCloneService>>,
    #[allow(unused_variables)] server_name: &str,
    oid_mapping: Arc<std::collections::HashMap<String, praeco_rs::configuration::UserRole>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 1. Establish QUIC connection
    let connection = connecting.await?;
    let peer_addr = connection.remote_address();

    // 2. Extract OIDs (Strings)
    let mut oids = Vec::new();
    let mut client_cert_pem = None;
    let mut client_cert_san = None;
    if let Some(identity) = connection.peer_identity()
        && let Some(certs) =
            identity.downcast_ref::<Vec<rustls_pki_types::CertificateDer<'static>>>()
    {
        if let Some(first_cert) = certs.first() {
            let (pem, san) = extract_cert_san_and_pem(first_cert.as_ref());
            client_cert_pem = pem;
            client_cert_san = san;
        }
        for c in certs {
            oids.extend(extract_oids_from_cert(c.as_ref()));
        }
    }

    // --- OPTIMIZATION START ---
    // Convert OIDs (Strings) to Roles (Enums) ONCE for the whole connection.
    let mut roles: Vec<praeco_rs::configuration::UserRole> = oids
        .iter()
        .map(|oid| {
            oid_mapping
                .get(oid)
                .cloned()
                .unwrap_or_else(praeco_rs::configuration::UserRole::guest)
        })
        .filter(|role| *role != praeco_rs::configuration::UserRole::guest())
        .collect();

    if roles.is_empty() {
        roles.push(praeco_rs::configuration::UserRole::guest());
    }

    // Wrap the ROLES in Arc, not the OIDs.
    let shared_roles = Arc::new(roles);
    // Preserve raw OIDs for IdP to embed in JWTs
    let shared_oids = Arc::new(oids);
    // --- OPTIMIZATION END ---

    // 3. HTTP/3 Connection Setup
    let h3_conn = h3_quinn::Connection::new(connection);
    let mut h3_server: h3::server::Connection<h3_quinn::Connection, bytes::Bytes> =
        h3::server::Connection::new(h3_conn).await?;

    // --- MUTEX OPTIMIZATION ---
    // Lock the Mutex ONCE per QUIC connection, not per HTTP/3 request stream!
    // The underlying Tower service handles its own cheap lock-free cloning.
    let base_svc = (**dynamic_stack.load()).clone();

    // 4. Request Loop
    loop {
        match h3_server.accept().await {
            Ok(Some(resolver)) => {
                // Cheap lock-free clone per QUIC stream
                let svc = base_svc.clone();
                // Cheap clone of the already calculated roles
                let roles_for_req = shared_roles.clone();
                let shared_oids_for_req = shared_oids.clone();

                let req_cert_pem = client_cert_pem.clone();
                let req_cert_san = client_cert_san.clone();

                tokio::spawn(async move {
                    match resolver.resolve_request().await {
                        Ok((req, stream)) => {
                            let (mut sender, receiver) = stream.split();

                            // Pass the ROLES to new_shared
                            let handler = ConnectionHandler::new_shared(
                                svc,
                                peer_addr,
                                roles_for_req,
                                req_cert_pem,
                                req_cert_san,
                                shared_oids_for_req,
                            );

                            let (parts, _) = req.into_parts();
                            let body = H3Body::new(receiver);
                            let hyper_req = Request::from_parts(parts, body.boxed());

                            if let Ok(res) = handler.handle(hyper_req).await {
                                let (res_parts, mut res_body) = res.into_parts();

                                if sender
                                    .send_response(Response::from_parts(res_parts, ()))
                                    .await
                                    .is_ok()
                                {
                                    while let Some(frame_res) = res_body.frame().await {
                                        match frame_res {
                                            Ok(frame) => {
                                                let frame = match frame.into_data() {
                                                    Ok(data) => {
                                                        if sender.send_data(data).await.is_err() {
                                                            break;
                                                        }
                                                        continue;
                                                    }
                                                    Err(f) => f,
                                                };

                                                if let Ok(trailers) = frame.into_trailers() {
                                                    if sender.send_trailers(trailers).await.is_err()
                                                    {
                                                        break;
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                tracing::error!(
                                                    "H3 Response body stream error: {:?}",
                                                    e
                                                );
                                                break;
                                            }
                                        }
                                    }
                                    let _ = sender.finish().await;
                                }
                            }
                        }
                        Err(e) => error!("H3 Request Error: {e}"),
                    }
                });
            }
            Ok(None) => break,
            Err(_e) => break,
        }
    }
    Ok(())
}
// async fn handle_h3_connection(
//     connecting: quinn::Incoming,
//     service_stack: BoxedCloneService,
//     server_name: &str,
// ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
//     // 1. Establish QUIC connection
//     let connection = connecting.await?;
//     let peer_addr = connection.remote_address();

//     // 2. Extract OIDs ONCE per connection
//     let mut oids = Vec::new();
//     if let Some(identity) = connection.peer_identity() {
//         if let Some(certs) =
//             identity.downcast_ref::<Vec<rustls_pki_types::CertificateDer<'static>>>()
//         {
//             for c in certs {
//                 oids.extend(extract_oids_from_cert(c.as_ref()));
//             }
//         } else {
//             error!(
//                 "{}: QUIC Identity present but downcast failed.",
//                 server_name
//             );
//         }
//     }

//     // Wrap OIDs in Arc for cheap sharing across requests on this connection
//     let shared_oids = Arc::new(oids);

//     // 3. HTTP/3 Connection Setup
//     let h3_conn = h3_quinn::Connection::new(connection);
//     let mut h3_server = h3::server::Connection::new(h3_conn).await?;

//     // 4. Request Loop
//     loop {
//         match h3_server.accept().await {
//             Ok(Some(resolver)) => {
//                 let svc = service_stack.clone();
//                 let oids = shared_oids.clone(); // Cheap Arcc clone

//                 tokio::spawn(async move {
//                     match resolver.resolve_request().await {
//                         Ok((req, stream)) => {
//                             let (mut sender, receiver) = stream.split();

//                             // Use the new_shared constructor for existing Arc
//                             let handler = ConnectionHandler::new_shared(svc, peer_addr, oids);

//                             let (parts, _) = req.into_parts();
//                             let body = H3Body::new(receiver);
//                             let hyper_req = Request::from_parts(parts, body.boxed());

//                             if let Ok(res) = handler.handle(hyper_req).await {
//                                 let (res_parts, mut res_body) = res.into_parts();

//                                 if sender
//                                     .send_response(Response::from_parts(res_parts, ()))
//                                     .await
//                                     .is_ok()
//                                 {
//                                     while let Some(frame) = res_body.frame().await {
//                                         if let Ok(data) = frame.unwrap().into_data() {
//                                             if sender.send_data(data).await.is_err() {
//                                                 break;
//                                             }
//                                         }
//                                     }
//                                     let _ = sender.finish().await;
//                                 }
//                             }
//                         }
//                         Err(e) => error!("H3 Request Error: {e}"),
//                     }
//                 });
//             }
//             Ok(None) => break, // Connection closed by client
//             Err(e) => {
//                 trace!("H3 Connection closed: {e}");
//                 break;
//             }
//         }
//     }
//     Ok(())
// }

/// Helper function to build the Rustls server configuration.
///
/// It loads the server's certificate chain and private key.
/// If client certificate authentication (mTLS) is enabled, it also loads the client CA roots.
fn build_rustls_config(config: &ServerConfig) -> Result<RustlsServerConfig, Error> {
    let server_certs = config.server_certs.as_ref().context(format!(
        "{}: HTTPS enabled but no server_certs",
        config.name
    ))?;

    let client_certs = if config.authentication == AuthenticationMethod::ClientCert
        || config.authentication == AuthenticationMethod::OptionalClientCert
    {
        Some(
            config
                .client_certs
                .as_deref()
                .context("mTLS enabled but no client_certs")?,
        )
    } else {
        None
    };

    // Use your existing tls_config function
    let tls_config = tls_config(
        config.static_name.expect("static_name missing"),
        server_certs,
        client_certs,
        config.authentication,
    )?;

    Ok(tls_config)
}

// --- Logging Setup ---

/// Configures the global tracing subscriber for logging.
///
/// # Arguments
///
/// * `log_dir` - An optional directory path. If provided, logs will also be written to rolling files
///   in this directory (rotated daily). If `None`, logs are written only to stdout.
///
/// By default, it uses the `RUST_LOG` environment variable filter (defaulting to "info").
fn setup_tracing(config: &praeco_rs::configuration::Config) -> Result<Option<WorkerGuard>, Error> {
    use opentelemetry::KeyValue;
    use opentelemetry::trace::TracerProvider as _;
    use opentelemetry_sdk::Resource;
    use tracing_subscriber::Layer as _;
    use opentelemetry_otlp::WithExportConfig;

    let log_dir = config.log_dir.as_deref();
    let enable_otlp = config.enable_opentelemetry.unwrap_or(false);
    let jaeger_endpoint = config.jaeger_endpoint.as_deref().unwrap_or("http://localhost:4317");
    let otel_log_level = config.otel_log_level.as_deref().unwrap_or("info");

    let otel_sample_ratio = config.otel_sample_ratio.unwrap_or(1.0);

    // Per-layer filters
    let console_filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let telemetry_filter = EnvFilter::new(otel_log_level);

    let stdout_layer = fmt::layer().with_ansi(true).with_filter(console_filter);

    let telemetry_layer = if enable_otlp {
        let sampler = if (otel_sample_ratio - 1.0).abs() < f64::EPSILON {
            opentelemetry_sdk::trace::Sampler::AlwaysOn
        } else {
            opentelemetry_sdk::trace::Sampler::ParentBased(Box::new(opentelemetry_sdk::trace::Sampler::TraceIdRatioBased(otel_sample_ratio)))
        };

        let provider = opentelemetry_otlp::new_pipeline()
            .tracing()
            .with_exporter(opentelemetry_otlp::new_exporter().tonic().with_endpoint(jaeger_endpoint))
            .with_trace_config(
                opentelemetry_sdk::trace::Config::default()
                    .with_sampler(sampler)
                    .with_resource(Resource::new(vec![
                        KeyValue::new("service.name", "praeco-rs")
                    ])),
            )
            .install_batch(opentelemetry_sdk::runtime::Tokio)
            .expect("Failed to initialize OTLP tracer");

        // We MUST set the provider globally, otherwise it gets dropped at the end of this function
        opentelemetry::global::set_tracer_provider(provider.clone());
        
        let _ = opentelemetry::global::set_error_handler(|err| {
            tracing::error!("OpenTelemetry Export Error: {:?}", err);
        });

        // Also set the global TextMapPropagator so we can inject traceparent headers into outgoing requests!
        opentelemetry::global::set_text_map_propagator(
            opentelemetry_sdk::propagation::TraceContextPropagator::new(),
        );

        let tracer = provider.tracer("praeco-rs");
        Some(
            tracing_opentelemetry::layer()
                .with_tracer(tracer)
                .with_filter(telemetry_filter),
        )
    } else {
        None
    };

    if let Some(dir) = log_dir {
        let file_appender = RollingFileAppender::builder()
            .rotation(tracing_appender::rolling::Rotation::DAILY)
            .filename_prefix("app")
            .filename_suffix("log")
            .build(dir)?;

        // PERFORMANCE FIX: Use non_blocking wrapper
        let (non_blocking_appender, _guard) = tracing_appender::non_blocking(file_appender);

        let file_layer = fmt::layer()
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

        // Return the guard so it's not dropped
        Ok(Some(_guard))
    } else {
        let subscriber = Registry::default().with(telemetry_layer).with(stdout_layer);
        tracing::subscriber::set_global_default(subscriber)?;
        Ok(None)
    }
}
use tokio_util::compat::{TokioAsyncReadCompatExt, FuturesAsyncReadCompatExt};
use tokio::net::TcpStream;
use tokio::io::AsyncWriteExt;

#[tracing::instrument(skip_all, fields(server = %server_name, sni = %tunnel.sni_domain))]
async fn run_tunnel(
    tunnel: praeco_rs::configuration::TunnelConfig,
    tls_config: Arc<RustlsServerConfig>,
    dynamic_stack: Arc<ArcSwap<BoxedCloneService>>,
    cancel_token: CancellationToken,
    server_name: &'static str,
    oid_mapping: Arc<std::collections::HashMap<String, praeco_rs::configuration::UserRole>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);

    // 1. Prepare Outbound mTLS
    let mut root_store = rustls::RootCertStore::empty();
    let ca_file = std::fs::File::open(&tunnel.ca_cert_path)?;
    for cert in rustls_pemfile::certs(&mut std::io::BufReader::new(ca_file)) {
        root_store.add(cert?)?;
    }
    
    let cert_file = std::fs::File::open(&tunnel.client_cert_path)?;
    let certs: Vec<rustls::pki_types::CertificateDer> = rustls_pemfile::certs(&mut std::io::BufReader::new(cert_file))
        .collect::<Result<Vec<_>, _>>()?;
        
    let key_file = std::fs::File::open(&tunnel.client_key_path)?;
    let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(key_file))?
        .ok_or("No private key found")?;

    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(certs, key)?;

    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

    // 2. Connect to Relay
    let parsed_url = url::Url::parse(&tunnel.target_url).context("Invalid tunnel target URL")?;
    let relay_host = parsed_url.host_str().unwrap_or("localhost");
    let relay_port = parsed_url.port().unwrap_or(7001);
    
    let tcp_stream = TcpStream::connect((relay_host, relay_port)).await?;
    let domain = rustls::pki_types::ServerName::try_from(relay_host.to_string())?;
    
    let mut tls_stream = connector.connect(domain, tcp_stream).await?;

    // 3. Register SNI
    let reg_cmd = format!("REGISTER {}\n", tunnel.sni_domain);
    tls_stream.write_all(reg_cmd.as_bytes()).await?;

    // 4. Setup Yamux
    let cfg = yamux::Config::default();
    let mut connection = yamux::Connection::new(tls_stream.compat(), cfg, yamux::Mode::Client);

    info!("{}: Tunnel connected successfully to {}", server_name, tunnel.target_url);

    // 5. Accept Streams loop
    loop {
        tokio::select! {
                _ = cancel_token.cancelled() => break,
                inbound = std::future::poll_fn(|cx| connection.poll_next_inbound(cx)) => {
                    match inbound {
                        Some(Ok(yamux_stream)) => {
                            trace!("{}: Tunneled connection accepted", server_name);
                            let acceptor = acceptor.clone();
                            let dynamic_stack = dynamic_stack.clone();
                            let oid_mapping = oid_mapping.clone();
                            
                            // We must create a dummy SocketAddr since tunnels don't have real remote IPs (unless we proxy protocol it)
                            let peer_addr = std::net::SocketAddr::from(([0, 0, 0, 0], 0));

                            tokio::spawn(async move {
                                // Provide AsyncRead/Write compat for hyper
                                let compat_stream = yamux_stream.compat();

                                let tls_result = tokio::time::timeout(
                                    Duration::from_secs(10),
                                    acceptor.accept(compat_stream),
                                ).await;

                                match tls_result {
                                    Ok(Ok(tls_stream)) => {
                                        let (_, session) = tls_stream.get_ref();
                                        let certs = session.peer_certificates();
                                        let mut client_cert_pem = None;
                                        let mut client_cert_san = None;
                                        let client_oids = if let Some(c) = certs.and_then(|c| c.first()) {
                                            let (pem, san) = extract_cert_san_and_pem(c.as_ref());
                                            client_cert_pem = pem;
                                            client_cert_san = san;
                                            extract_oids_from_cert(c.as_ref())
                                        } else {
                                            Vec::new()
                                        };

                                        let svc = (**dynamic_stack.load()).clone();
                                        let handler = ConnectionHandler::new(svc, peer_addr, client_oids, client_cert_pem, client_cert_san, oid_mapping.clone());

                                        let mut builder = auto::Builder::new(TokioExecutor::new());
                                        builder.http1().timer(TokioTimer::new()).header_read_timeout(Duration::from_secs(10));
                                        builder.http2().timer(TokioTimer::new())
                                            .initial_stream_window_size(1024 * 1024)
                                            .max_concurrent_streams(1024);
                                        
                                        let _ = builder.serve_connection(TokioIo::new(tls_stream), handler).await;
                                    }
                                    _ => {
                                        warn!("{}: TLS handshake via tunnel failed", server_name);
                                    }
                                }
                            }.instrument(tracing::info_span!("tunneled_connection", server = %server_name, sni = %tunnel.sni_domain)));
                        }
                        Some(Err(e)) => {
                            error!("{}: Tunnel error: {:?}", server_name, e);
                            break;
                        }
                        None => {
                            info!("{}: Tunnel closed by Relay", server_name);
                            break;
                        }
                    }
                }
            }
        }

    Ok(())
}

