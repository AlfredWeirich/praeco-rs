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
use anyhow::{Context, Error, anyhow};
use hyper::Request;
use tokio::{net::TcpListener, runtime::Builder};

use tokio_util::sync::CancellationToken;
use arc_swap::ArcSwap;
#[allow(unused_imports)]
use tracing::{debug, error, info, trace, warn, Instrument};
use tracing_appender::{non_blocking::WorkerGuard, rolling::RollingFileAppender};
use tracing_subscriber::{EnvFilter, Registry, fmt, layer::SubscriberExt};

// === Internal Modules ===

use praeco_rs::{
    BoxedCloneService, ConnectionHandler,
    configuration::{
        AuthenticationMethod, Config, Protocol,
        ServerConfig, ServiceType,
    },
    tls_conf::extract_client_metadata,
    connection_tracker::{AcquireError, ConnectionTracker},
    stack::{
        build_rustls_config, build_service_stack, build_tunnel_tls_connector,
        run_tunnel_over_stream, serve_http_connection, serve_tls_connection,
    },
};

use http_body_util::BodyExt;
use hyper::{Response, StatusCode};
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
    praeco_rs::middleware::admin::init_process_start_time();
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
    // Use _tracing_guard and _tracer_provider to keep the appender and OTLP exporter alive until main exits.
    let (_tracing_guard, _tracer_provider) = setup_tracing(&config)?;

    info!("Configuration loaded from: {}", arg);
    trace!("Full Config: {:#?}", config);

    // Block the main thread on the execution of the asynchronous server loop.
    let res = runtime.block_on(main_async(config, arg));
    if let Some(provider) = _tracer_provider {
        let _ = provider.shutdown();
    }
    res
}

/// The asynchronous main loop that manages multiple server instances.
///
/// Think of this as the "Mission Control" center.
/// - It reads the list of servers from the config.
/// - For each enabled server, it launches a separate, independent task (green thread).
/// - It listens for a "Shutdown Signal" (like pressing Ctrl+C).
/// - It ensures all servers stop gracefully before the program exits.
async fn main_async(config: Arc<Config>, config_path: String) -> Result<(), Error> {
    let mut server_join_set = tokio::task::JoinSet::new();

    // Map: name -> (CancellationToken, Arc<ServerConfig>, Arc<ArcSwap<BoxedCloneService>>)
    let mut active_servers: HashMap<
        String,
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
            server_config.name.clone(),
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
                info!("Received SIGHUP, initiating hot-reload from '{}'...", config_path);

                // 1. Reload configuration from disk into a fresh Config instance
                // We use Config::load instead of Config::init so that the global CONFIG
                // is NOT updated if validation or dry-run fails.
                let new_config = match Config::load(&config_path) {
                    Ok(c) => c,
                    Err(e) => {
                        error!("Failed to reload config on SIGHUP, ignoring: {:?}", e);
                        continue;
                    }
                };

                info!("Successfully parsed and validated new config from '{}'", config_path);

                // 2. DRY-RUN PASS: Build all service stacks and TLS configurations first
                let mut reload_errors = Vec::new();
                let mut built_stacks = std::collections::HashMap::new();

                for new_server in &new_config.servers {
                    if !new_server.enabled { continue; }
                    let server_config_arc = Arc::new(new_server.clone());

                    // Validate TLS configuration if https or tunnel
                    if new_server.protocol == Protocol::Https || new_server.tunnel.is_some() {
                        if let Err(e) = build_rustls_config(new_server) {
                            error!("{}: FAILED to build TLS config (dry-run): {:?}", new_server.name, e);
                            reload_errors.push((new_server.name.clone(), format!("TLS config error: {e}")));
                            continue;
                        }
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
                    error!("Hot-reload aborted! {} server(s) failed to build their service stacks:", reload_errors.len());
                    for (name, err) in &reload_errors {
                        error!(" - {}: {}", name, err);
                    }
                    error!("Keeping previous configuration completely intact.");
                    continue; // Abort SIGHUP handling, leave `active_servers` and `CONFIG` unmodified
                }

                // 3. APPLY PASS: Atomic config swap and diff/manage listeners
                info!("Dry-run passed. Applying new configuration...");
                Config::update_global(new_config.clone());
                let mut next_active_servers = std::collections::HashMap::new();

                for (name, (server_config_arc, service_stack)) in built_stacks {
                    let new_server = &server_config_arc;
                    let needs_restart = match active_servers.get(&name) {
                        None => true, // New server with this name
                        Some((_, old_server, _)) => {
                            // Restart listener if fundamental binding parameters or tunnel changed
                            old_server.ip != new_server.ip
                                || old_server.port != new_server.port
                                || old_server.protocol != new_server.protocol
                                || old_server.tunnel != new_server.tunnel
                        }
                    };

                    if needs_restart {
                        info!("Starting server '{}'...", new_server.name);
                        let cancel_token = CancellationToken::new();
                        let dynamic_stack = Arc::new(ArcSwap::from_pointee(service_stack));

                        next_active_servers.insert(
                            name,
                            (cancel_token.clone(), server_config_arc.clone(), dynamic_stack.clone()),
                        );

                        let cloned_config = server_config_arc.clone();
                        server_join_set.spawn(async move {
                            start_single_server(cloned_config, cancel_token, dynamic_stack).await;
                        });
                    } else {
                        // Keep listener alive!
                        // Removing from active_servers so we know which ones to drop later
                        let (old_token, _, dynamic_stack) = active_servers.remove(&name).unwrap();
                        
                        // Hot-swap service stack for new config
                        dynamic_stack.store(Arc::new(service_stack));
                        info!("Hot-swapped service stack for '{}'", new_server.name);

                        next_active_servers.insert(name, (old_token, server_config_arc.clone(), dynamic_stack));
                    }
                }

                // 4. Stop drained/removed listeners
                for (_name, (token, old_server, _)) in active_servers.drain() {
                    info!("Stopping server '{}'", old_server.name);
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

    let oid_mapping = Arc::new(server_config.oid_mapping.clone());
    let connection_tracker = Arc::new(ConnectionTracker::new(
        server_config.connection_limits.max_connections,
        server_config.connection_limits.max_connections_per_ip,
    ));

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

            let start_time = std::time::Instant::now();
            if let Err(e) = run_tunnel(
                tunnel.clone(),
                tls_config.clone(),
                dynamic_stack.clone(),
                cancel_token.clone(),
                server_config.static_name.expect("missing static_name"),
                oid_mapping.clone(),
                connection_tracker.clone(),
            ).await {
                error!("{}: Tunnel crashed: {:?}", server_config.name, e);
            } else {
                info!("{}: Tunnel connection ended cleanly", server_config.name);
            }

            // If the tunnel ran stably for >= 30 seconds, reset retry_count so future reconnects don't wait 64s
            if start_time.elapsed() >= Duration::from_secs(30) {
                retry_count = 0;
            } else {
                retry_count += 1;
            }

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

    if server_config.protocol == Protocol::Https {
        let tls_config: RustlsServerConfig = match build_rustls_config(server_config.as_ref()) {
            Ok(cfg) => cfg,
            Err(e) => {
                error!("{}: TLS Setup Error: {:?}", server_config.name, e);
                return;
            }
        };

        let static_name = server_config.static_name.expect("missing static_name");

        if let Err(e) = run_dual_stack(
            server_addr,
            tls_config,
            dynamic_stack,
            cancel_token,
            static_name,
            oid_mapping,
            connection_tracker.clone(),
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

        let static_name = server_config.static_name.expect("missing static_name");

        loop {
            tokio::select! {
                _ = cancel_token.cancelled() => break,
                res = listener.accept() => {
                    match res {
                        Ok((stream, peer_addr)) => {
                            let peer_ip = peer_addr.ip();
                            let conn_guard = match connection_tracker.acquire(Some(peer_ip)) {
                                Ok(guard) => guard,
                                Err(AcquireError::GlobalLimitReached { current, max }) => {
                                    warn!("{}: Global connection limit reached ({} >= {}), dropping HTTP connection from {}", static_name, current, max, peer_addr);
                                    drop(stream);
                                    continue;
                                }
                                Err(AcquireError::IpLimitReached { ip, current, max }) => {
                                    warn!("{}: Per-IP connection limit reached for {} ({} >= {}), dropping HTTP connection", static_name, ip, current, max);
                                    drop(stream);
                                    continue;
                                }
                            };
                            let svc = (**dynamic_stack.load()).clone(); // fresh stack per connection
                            let conn_token = cancel_token.clone();
                            let oid_mapping = oid_mapping.clone();
                            tokio::spawn(async move {
                                let _guard = conn_guard;
                                let handler = ConnectionHandler::new(
                                    svc,
                                    peer_addr,
                                    Vec::new(),
                                    None,
                                    None,
                                    oid_mapping,
                                );
                                serve_http_connection(stream, handler, conn_token).await;
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
        let root_store = match common::build_root_store(&router_params.ssl_root_certificate) {
            Ok(store) => store,
            Err(e) => {
                error!("{}: Failed to build root store for health checks: {}", server_config.name, e);
                return;
            }
        };

        // Check if mutual TLS (mTLS) is required (i.e., the proxy must present its own certificate)
        let is_mtls = router_params.authentication == AuthenticationMethod::ClientCert;

        // Build the exact TLS handshake instructions this proxy will use when calling upstream nodes.
        let tls_client_config = match if is_mtls {
            common::build_tls_client_config(
                root_store,
                router_params.ssl_client_certificate.as_deref(), // The proxy's own client cert
                router_params.ssl_client_key.as_deref(),         // The proxy's private key
            )
        } else {
            // Standard TLS (only verifying the server, no client certificate provided)
            common::build_tls_client_config(root_store, None, None)
        } {
            Ok(cfg) => cfg,
            Err(e) => {
                error!("{}: Failed to build TLS client config for health checks: {}", server_config.name, e);
                return;
            }
        };

        // --- 2. Connection Pool Setup ---
        // To maximize throughput, the proxy maintains keep-alive connection pools.
        // This avoids the overhead of establishing a new TCP/TLS connection for every health check.

        // gRPC-specific pool: gRPC strictly requires HTTP/2 multiplexing.
        // We enforce `http2_only: true` so it strictly negotiates H2 during the TLS ALPN handshake.
        let grpc_pool_config = common::client::ClientPoolConfig {
            idle_timeout: Some(Duration::from_secs(router_params.idle_timeout_seconds)),
            max_idle_per_host: Some(16),
            http2_only: true, // Force HTTP/2 for gRPC
            connect_timeout: (router_params.connect_timeout_seconds > 0)
                .then(|| Duration::from_secs(router_params.connect_timeout_seconds)),
            ..Default::default()
        };
        // Build the client specifically for gRPC health checks
        let grpc_client =
            common::client::build_hyper_client(tls_client_config.clone(), grpc_pool_config);

        // Standard REST/HTTP pool: Allows HTTP/1.1 or H2 depending on what the upstream server supports.
        let pool_config = common::client::ClientPoolConfig {
            idle_timeout: Some(Duration::from_secs(router_params.idle_timeout_seconds)),
            max_idle_per_host: Some(16),
            http2_only: false, // Default negotiation for standard web traffic
            connect_timeout: (router_params.connect_timeout_seconds > 0)
                .then(|| Duration::from_secs(router_params.connect_timeout_seconds)),
            ..Default::default()
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
                        // Startup grace period (10 seconds): allow co-started or manually launched
                        // backend services (which may first fetch JWKS from Praeco's IdP) to bind
                        // their listening ports before running the first active health check.
                        tokio::select! {
                            _ = token.cancelled() => return,
                            _ = tokio::time::sleep(Duration::from_secs(10)) => {}
                        }

                        // Create a timer to fire repeatedly according to the configured interval
                        let mut ticker = tokio::time::interval(interval_dur);
                        // Set tick behavior so it doesn't burst/spam if delayed (e.g., due to CPU starvation)
                        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

                        // For gRPC, we resolve the health path structurally using Server Reflection (lazily)
                        let mut grpc_health_path: Option<String> = None;
                        let mut reflection_attempts: usize = 0;

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
                                        // Probe this specific node's gRPC reflection endpoint (`base_uri`).
                                        // If reflection fails (e.g. ConnectionRefused on a dead port),
                                        // immediately trip this node's circuit breaker to OPEN (`mark_dead`).
                                        if grpc_health_path.is_none() {
                                            reflection_attempts += 1;

                                            match praeco_rs::middleware::router::build_grpc_pool(&base_uri, Some(&router_params)).await {
                                                Ok(p) => {
                                                    // Search the node's schema for a dedicated "health" method
                                                    for service in p.services() {
                                                        for method in service.methods() {
                                                            if method.name() == "health" {
                                                                grpc_health_path = Some(format!("/{}/health", service.full_name()));
                                                                break;
                                                            }
                                                        }
                                                        if grpc_health_path.is_some() { break; }
                                                    }

                                                    // Populate shared descriptor pool if still empty
                                                    let mut pool_guard = target_arc.grpc_pool.write().await;
                                                    if pool_guard.is_none() {
                                                        *pool_guard = Some(praeco_rs::configuration::CachedDescriptorPool {
                                                            pool: p,
                                                            created_at: std::time::Instant::now(),
                                                        });
                                                    }
                                                    drop(pool_guard);

                                                    // If the backend does not define a custom `health` RPC method,
                                                    // a successful gRPC reflection handshake itself proves the node is alive!
                                                    if grpc_health_path.is_none() {
                                                        if !target_arc.upstreams[idx].is_alive.load(std::sync::atomic::Ordering::Relaxed) {
                                                            info!("{}: gRPC reflection health check recovered '{}'", server_name, base_uri);
                                                            target_arc.upstreams[idx].mark_alive();
                                                        }
                                                        continue;
                                                    }
                                                }
                                                Err(e) => {
                                                    if target_arc.upstreams[idx].is_alive.load(std::sync::atomic::Ordering::Relaxed)
                                                        || reflection_attempts <= 3
                                                        || reflection_attempts % 10 == 0
                                                    {
                                                        tracing::warn!(
                                                            "{}: Active health check failed to connect to gRPC upstream '{}': {:?} — marking node DEAD (Circuit OPEN)",
                                                            server_name,
                                                            base_uri,
                                                            e
                                                        );
                                                    }
                                                    target_arc.upstreams[idx].mark_dead();
                                                    continue;
                                                }
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
                                    match tokio::time::timeout(Duration::from_secs(5), client.request(req)).await {
                                        Ok(Ok(resp)) => {
                                            let resp_status = resp.status();
                                            let is_ok = resp_status == StatusCode::OK;
                                            let mut health_score_ok = true;

                                            // If it's a gRPC health check, parse the HealthScore with a 64KB body limit
                                            if is_ok && is_grpc && grpc_health_path.is_some() {
                                                use http_body_util::{BodyExt, Limited};
                                                let limited_body = Limited::new(resp.into_body(), 64 * 1024);
                                                if let Ok(collected) = limited_body.collect().await {
                                                    let bytes = collected.to_bytes();
                                                    // Frame format: 1 byte compressed flag, 4 bytes length, then protobuf payload
                                                    if bytes.len() >= 5 {
                                                        let payload_len = u32::from_be_bytes(bytes[1..5].try_into().unwrap()) as usize;
                                                        if bytes.len() >= 5 + payload_len {
                                                            let raw_payload = &bytes[5..5 + payload_len];
                                                            let mut healthy = false;
                                                            if raw_payload.len() >= 2 && raw_payload[0] == 0x08 { // field 1, varint
                                                                // Decode standard protobuf varint (supports scores > 127)
                                                                let mut score = 0usize;
                                                                let mut shift = 0;
                                                                for &b in &raw_payload[1..] {
                                                                    score |= ((b & 0x7F) as usize) << shift;
                                                                    if (b & 0x80) == 0 {
                                                                        break;
                                                                    }
                                                                    shift += 7;
                                                                    if shift >= 32 { break; }
                                                                }
                                                                target_arc.upstreams[idx].current_score.store(score, std::sync::atomic::Ordering::Relaxed);
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
                                                    health_score_ok = false; // Failed to read body or exceeded limit
                                                }
                                            } else if is_ok && !is_grpc {
                                                // For REST, parse the JSON {"score": 100} response with a 64KB body limit
                                                use http_body_util::{BodyExt, Limited};
                                                let limited_body = Limited::new(resp.into_body(), 64 * 1024);
                                                if let Ok(collected) = limited_body.collect().await {
                                                    let bytes = collected.to_bytes();
                                                    if let Ok(json) = serde_json::from_slice::<serde_json::Value>(&bytes) {
                                                        if let Some(score) = json.get("score").and_then(|s| s.as_u64()) {
                                                            target_arc.upstreams[idx].current_score.store(score as usize, std::sync::atomic::Ordering::Relaxed);
                                                            if score == 0 {
                                                                health_score_ok = false;
                                                            }
                                                        } else {
                                                            health_score_ok = false;
                                                        }
                                                    } else {
                                                        health_score_ok = false; // Invalid JSON
                                                    }
                                                } else {
                                                    health_score_ok = false; // Failed to read body or exceeded limit
                                                }
                                            }

                                            if is_ok && health_score_ok {
                                                let current_score = target_arc.upstreams[idx].current_score.load(std::sync::atomic::Ordering::Relaxed);
                                                tracing::trace!("{}: Health check successful for '{}', score: {}", server_name, final_uri, current_score);
                                                // If the node was previously considered dead, revive it in the LB
                                                if !target_arc.upstreams[idx].is_alive.load(std::sync::atomic::Ordering::Relaxed) {
                                                    info!("{}: Health check recovered '{}'", server_name, final_uri);
                                                    target_arc.upstreams[idx].mark_alive();
                                                }
                                            } else {
                                                target_arc.upstreams[idx].current_score.store(0, std::sync::atomic::Ordering::Relaxed);
                                                if target_arc.upstreams[idx].is_alive.load(std::sync::atomic::Ordering::Relaxed) {
                                                    tracing::warn!("{}: Health check failed status {} for '{}' (Score OK: {})", server_name, resp_status, final_uri, health_score_ok);
                                                    target_arc.upstreams[idx].mark_dead();
                                                } else {
                                                    // Keep failure timestamp fresh so cooldown doesn't prematurely revive dead node
                                                    let now = std::time::SystemTime::now()
                                                        .duration_since(std::time::UNIX_EPOCH)
                                                        .unwrap_or_default()
                                                        .as_secs();
                                                    target_arc.upstreams[idx].last_failure_time.store(now, std::sync::atomic::Ordering::Relaxed);
                                                }
                                            }
                                        }
                                        Ok(Err(e)) => {
                                            target_arc.upstreams[idx].current_score.store(0, std::sync::atomic::Ordering::Relaxed);
                                            if target_arc.upstreams[idx].is_alive.load(std::sync::atomic::Ordering::Relaxed) {
                                                tracing::warn!("{}: Health check network error for '{}': {}", server_name, final_uri, e);
                                                target_arc.upstreams[idx].mark_dead();
                                            } else {
                                                let now = std::time::SystemTime::now()
                                                    .duration_since(std::time::UNIX_EPOCH)
                                                    .unwrap_or_default()
                                                    .as_secs();
                                                target_arc.upstreams[idx].last_failure_time.store(now, std::sync::atomic::Ordering::Relaxed);
                                            }
                                        }
                                        Err(_) => {
                                            target_arc.upstreams[idx].current_score.store(0, std::sync::atomic::Ordering::Relaxed);
                                            if target_arc.upstreams[idx].is_alive.load(std::sync::atomic::Ordering::Relaxed) {
                                                tracing::warn!("{}: Health check timed out after 5s for '{}'", server_name, final_uri);
                                                target_arc.upstreams[idx].mark_dead();
                                            } else {
                                                let now = std::time::SystemTime::now()
                                                    .duration_since(std::time::UNIX_EPOCH)
                                                    .unwrap_or_default()
                                                    .as_secs();
                                                target_arc.upstreams[idx].last_failure_time.store(now, std::sync::atomic::Ordering::Relaxed);
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
    connection_tracker: Arc<ConnectionTracker>,
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
        connection_tracker.clone(),
    );

    // 2. UDP Listener (HTTP/3)
    let udp_handle = run_udp_listener(
        server_addr,
        arc_tls_config,
        dynamic_stack,
        udp_cancel_token,
        server_name,
        oid_mapping,
        connection_tracker,
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
    connection_tracker: Arc<ConnectionTracker>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let tcp_listener = TcpListener::bind(server_addr).await?;
    let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel_token.cancelled() => break,
                res = tcp_listener.accept() => {
                    if let Ok((stream, peer_addr)) = res {
                        let peer_ip = peer_addr.ip();
                        let conn_guard = match connection_tracker.acquire(Some(peer_ip)) {
                            Ok(guard) => guard,
                            Err(AcquireError::GlobalLimitReached { current, max }) => {
                                warn!("{}: Global connection limit reached ({} >= {}), dropping TCP connection from {}", server_name, current, max, peer_addr);
                                drop(stream);
                                continue;
                            }
                            Err(AcquireError::IpLimitReached { ip, current, max }) => {
                                warn!("{}: Per-IP connection limit reached for {} ({} >= {}), dropping TCP connection", server_name, ip, current, max);
                                drop(stream);
                                continue;
                            }
                        };
                        // Optimization 2
                        // Disable Nagle's algorithm — send small responses immediately
                        // instead of waiting to batch them. Critical for low-latency APIs.
                        let _ = stream.set_nodelay(true);
                        let acceptor = acceptor.clone();
                        let dynamic_stack = dynamic_stack.clone();
                        let oid_mapping = oid_mapping.clone();
                        let conn_token = cancel_token.clone();
                        tokio::spawn(async move {
                            let _guard = conn_guard;
                            trace!("{}: TCP Connection accepted", server_name);
                            let _ = serve_tls_connection(
                                stream,
                                peer_addr,
                                &acceptor,
                                &dynamic_stack,
                                &oid_mapping,
                                conn_token,
                                server_name,
                            )
                            .await;
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
    connection_tracker: Arc<ConnectionTracker>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Determine if we need to modify the TLS config for QUIC (ALPN)
    // Quinn expects explicit "h3" ALPN
    let mut quic_tls_models = rustls::ServerConfig::clone(&tls_config);
    quic_tls_models.alpn_protocols = vec![b"h3".to_vec()];

    let quic_config = quinn::crypto::rustls::QuicServerConfig::try_from(quic_tls_models)
        .map_err(|e| format!("TLS Config Error for QUIC: {e}"))?;

    let mut quinn_server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_config));

    // Hardened QUIC transport parameters
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_uni_streams(128u32.into());
    transport.max_concurrent_bidi_streams(128u32.into());
    // Safe flow control windows to prevent memory exhaustion (8MB conn, 1MB stream)
    transport.receive_window(8_388_608u32.into());
    transport.send_window(8_388_608u64);
    transport.stream_receive_window(1_048_576u32.into());
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
                        // Anti-amplification / address validation check (RFC 9000 §8)
                        if !conn.remote_address_validated() && conn.may_retry() {
                            if let Err(e) = conn.retry() {
                                trace!("{}: Failed to send QUIC retry packet: {:?}", server_name, e);
                            }
                            continue;
                        }

                        let peer_ip = conn.remote_address().ip();
                        let conn_guard = match connection_tracker.acquire(Some(peer_ip)) {
                            Ok(guard) => guard,
                            Err(AcquireError::GlobalLimitReached { current, max }) => {
                                warn!("{}: Global connection limit reached ({} >= {}), dropping QUIC connection from {}", server_name, current, max, conn.remote_address());
                                conn.refuse();
                                continue;
                            }
                            Err(AcquireError::IpLimitReached { ip, current, max }) => {
                                warn!("{}: Per-IP connection limit reached for {} ({} >= {}), dropping QUIC connection", server_name, ip, current, max);
                                conn.refuse();
                                continue;
                            }
                        };
                        trace!("{}: UDP Connection accepted", server_name);
                        let dynamic_stack = dynamic_stack.clone();
                        let oid_mapping = oid_mapping.clone();

                        tokio::spawn(async move {
                            let _guard = conn_guard;
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

    // 2. Extract client identity metadata strictly from leaf certificate
    let client_meta = {
        let peer_identity = connection.peer_identity();
        let client_certs = peer_identity.as_ref().and_then(|identity| {
            identity
                .downcast_ref::<Vec<rustls_pki_types::CertificateDer<'static>>>()
                .map(|v| v.as_slice())
        });
        extract_client_metadata(client_certs)
    };
    let oids = client_meta.oids;
    let client_cert_pem = client_meta.pem;
    let client_cert_san = client_meta.san;

    // --- OPTIMIZATION START ---
    // Convert OIDs (Strings) to Roles (Enums) ONCE for the whole connection.
    let mut roles: praeco_rs::configuration::RoleVec<6> = oids
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

    // Bound concurrent request stream tasks per QUIC connection
    let stream_semaphore = Arc::new(tokio::sync::Semaphore::new(128));

    // 4. Request Loop
    loop {
        match h3_server.accept().await {
            Ok(Some(resolver)) => {
                let permit = match stream_semaphore.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        warn!("{}: Max concurrent H3 streams reached (128), shedding request", server_name);
                        continue;
                    }
                };
                // Cheap lock-free clone per QUIC stream
                let svc = base_svc.clone();
                // Cheap clone of the already calculated roles
                let roles_for_req = shared_roles.clone();
                let shared_oids_for_req = shared_oids.clone();

                let req_cert_pem = client_cert_pem.clone();
                let req_cert_san = client_cert_san.clone();

                tokio::spawn(async move {
                    let _permit = permit;
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

// --- Logging Setup ---

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
/// # Arguments
///
/// * `config` - Reference to the application configuration.
///
/// Returns a tuple containing an optional `WorkerGuard` (for non-blocking file logging)
/// and an optional `SdkTracerProvider` (for OpenTelemetry tracing).
fn setup_tracing(
    config: &praeco_rs::configuration::Config,
) -> Result<(Option<WorkerGuard>, Option<opentelemetry_sdk::trace::SdkTracerProvider>), Error> {
    use opentelemetry_otlp::WithExportConfig;
    use opentelemetry_sdk::Resource;
    use opentelemetry_sdk::trace::SdkTracerProvider;
    use opentelemetry::trace::TracerProvider as _;
    use tracing_subscriber::Layer as _;

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

    let (telemetry_layer, tracer_provider) = if enable_otlp {
        let sampler = if (otel_sample_ratio - 1.0).abs() < f64::EPSILON {
            opentelemetry_sdk::trace::Sampler::AlwaysOn
        } else {
            opentelemetry_sdk::trace::Sampler::ParentBased(Box::new(opentelemetry_sdk::trace::Sampler::TraceIdRatioBased(otel_sample_ratio)))
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

        // We MUST set the provider globally, otherwise it gets dropped at the end of this function
        opentelemetry::global::set_tracer_provider(provider.clone());

        // Also set the global TextMapPropagator so we can inject traceparent headers into outgoing requests!
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

        // PERFORMANCE FIX: Use non_blocking wrapper
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

        // Return the guard and provider so they are not dropped
        Ok((Some(_guard), tracer_provider))
    } else {
        let subscriber = Registry::default().with(telemetry_layer).with(stdout_layer);
        tracing::subscriber::set_global_default(subscriber)?;
        Ok((None, tracer_provider))
    }
}

use tokio::net::TcpStream;

#[tracing::instrument(skip_all, fields(server = %server_name, sni = %tunnel.sni_domain))]
async fn run_tunnel(
    tunnel: praeco_rs::configuration::TunnelConfig,
    tls_config: Arc<RustlsServerConfig>,
    dynamic_stack: Arc<ArcSwap<BoxedCloneService>>,
    cancel_token: CancellationToken,
    server_name: &'static str,
    oid_mapping: Arc<std::collections::HashMap<String, praeco_rs::configuration::UserRole>>,
    connection_tracker: Arc<ConnectionTracker>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 1. Prepare Outbound mTLS
    let connector = build_tunnel_tls_connector(&tunnel)?;

    // 2. Connect to Relay
    let parsed_url = url::Url::parse(&tunnel.target_url).context("Invalid tunnel target URL")?;
    let relay_host = parsed_url.host_str().unwrap_or("localhost");
    let relay_port = parsed_url.port().unwrap_or(7001);

    let connect_timeout = Duration::from_secs(10);
    let tcp_stream = match tokio::time::timeout(
        connect_timeout,
        TcpStream::connect((relay_host, relay_port)),
    )
    .await
    {
        Ok(res) => res?,
        Err(_) => {
            return Err(anyhow!(
                "Connection to relay server at {}:{} timed out after 10s",
                relay_host,
                relay_port
            )
            .into())
        }
    };
    let sock_ref = socket2::SockRef::from(&tcp_stream);
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(30))
        .with_interval(Duration::from_secs(10));
    let _ = sock_ref.set_tcp_keepalive(&keepalive);
    let _ = sock_ref.set_nodelay(true);

    let domain = rustls::pki_types::ServerName::try_from(relay_host.to_string())?;

    let tls_stream = match tokio::time::timeout(connect_timeout, connector.connect(domain, tcp_stream)).await {
        Ok(res) => res?,
        Err(_) => {
            return Err(anyhow!(
                "TLS handshake with relay server at {}:{} timed out after 10s",
                relay_host,
                relay_port
            )
            .into())
        }
    };

    // 3. Register SNI, initialize Yamux, and serve tunneled connections
    run_tunnel_over_stream(
        tls_stream,
        &tunnel,
        tls_config,
        dynamic_stack,
        cancel_token,
        server_name,
        oid_mapping,
        connection_tracker,
    )
    .await?;

    Ok(())
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
        fn into_string(&self) -> String {
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
