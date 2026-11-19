//! # Server Runtime & Listener Orchestration
//!
//! This module provides the transport listeners, active upstream health-check
//! loops, and outbound relay tunnel runner used to execute configured Praeco
//! gateway servers.
//!
//! Moving this orchestration into the library crate allows external Rust
//! applications to embed full HTTP/1.1, HTTP/2, HTTP/3 (QUIC), and Zero-Trust
//! tunnel servers programmatically without pulling in CLI-only dependencies
//! (global allocator, tracing subscriber, OTLP exporter, or signal handlers).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use http_body_util::BodyExt;
use hyper::{Request, Response, StatusCode};
use rustls::ServerConfig as RustlsServerConfig;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio::task::{JoinError, JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, trace, warn};

use crate::{
    BoxedCloneService, ConnectionHandler, H3Body, SrvError,
    configuration::{
        AuthenticationMethod, CachedDescriptorPool, Config, Protocol, RoleVec, RouteBackendType,
        ServerConfig, ServiceType, TunnelConfig, UserRole,
    },
    connection_tracker::{AcquireError, ConnectionTracker},
    middleware::router::build_grpc_pool,
    stack::{
        build_rustls_config, build_service_stack, build_tunnel_tls_connector, serve_http_connection,
    },
    tls_conf::extract_client_metadata_with_base,
};

/// Spawns and drives all enabled [`ServerConfig`] instances in `config` until
/// `cancel_token` is cancelled, then waits for graceful shutdown.
pub async fn run_servers(config: Arc<Config>, cancel_token: CancellationToken) {
    let mut server_join_set = JoinSet::new();

    for server_config in &config.servers {
        if !server_config.enabled {
            continue;
        }

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
        let token = cancel_token.clone();

        server_join_set.spawn(async move {
            start_single_server(server_config_arc, token, dynamic_stack).await;
        });
    }

    cancel_token.cancelled().await;

    while let Some(res) = server_join_set.join_next().await {
        if let Err(e) = res {
            error!("Server task panicked or failed prematurely: {:?}", e);
        }
    }
}

/// Default maximum time in-flight connections (and HTTP/3 streams) get to finish
/// after a shutdown was requested. Can be overridden per server via
/// `ServerConfig::graceful_shutdown_timeout_seconds`.
pub const CONNECTION_DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

/// Maximum time the QUIC endpoint gets to flush `CONNECTION_CLOSE` frames after
/// all HTTP/3 connections have been drained.
const QUIC_IDLE_TIMEOUT: Duration = Duration::from_secs(2);

/// Maximum time background tasks (active health checks) get to stop after the
/// server's cancellation token fired.
const BACKGROUND_STOP_TIMEOUT: Duration = Duration::from_secs(5);

/// Backoff after a transient `accept()` error (e.g. `EMFILE`) to avoid a busy loop.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);

/// Signals a `oneshot::Sender<()>` once `expected` socket-release events have occurred
/// (or on `Drop` as a safety net if a task exits early).
struct SocketReleaseBarrier {
    remaining: std::sync::atomic::AtomicU8,
    tx: std::sync::Mutex<Option<oneshot::Sender<()>>>,
}

impl SocketReleaseBarrier {
    fn new(expected: u8, tx: Option<oneshot::Sender<()>>) -> Arc<Self> {
        let barrier = Arc::new(Self {
            remaining: std::sync::atomic::AtomicU8::new(expected),
            tx: std::sync::Mutex::new(tx),
        });
        if expected == 0 {
            barrier.fire();
        }
        barrier
    }

    fn release(&self) {
        if self
            .remaining
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel)
            == 1
        {
            self.fire();
        }
    }

    fn fire(&self) {
        if let Ok(mut guard) = self.tx.lock()
            && let Some(tx) = guard.take()
        {
            let _ = tx.send(());
        }
    }
}

impl Drop for SocketReleaseBarrier {
    fn drop(&mut self) {
        self.fire();
    }
}

/// Logs panics and unexpected failures of a finished task; cancelled (aborted)
/// tasks are silent because aborting is a deliberate action of the runner.
fn log_task_result(server_name: &str, what: &str, res: Result<(), JoinError>) {
    if let Err(e) = res {
        if e.is_panic() {
            error!("{}: {} task panicked: {:?}", server_name, what, e);
        } else if !e.is_cancelled() {
            error!("{}: {} task failed: {:?}", server_name, what, e);
        }
    }
}

/// Waits for all tasks in `tasks` to finish within `timeout`, then aborts the rest.
///
/// Panics of finished tasks are logged via [`log_task_result`].
async fn drain_tasks(tasks: &mut JoinSet<()>, server_name: &str, what: &str, timeout: Duration) {
    let drain = async {
        while let Some(res) = tasks.join_next().await {
            log_task_result(server_name, what, res);
        }
    };
    if tokio::time::timeout(timeout, drain).await.is_err() {
        warn!(
            "{}: {} did not finish within {:?}; aborting {} remaining task(s)",
            server_name,
            what,
            timeout,
            tasks.len()
        );
        tasks.abort_all();
        while let Some(res) = tasks.join_next().await {
            log_task_result(server_name, what, res);
        }
    }
}

/// Starts a single server instance (HTTP, HTTPS/H3 dual-stack, or outbound Relay tunnel)
/// based on the provided configuration and returns once it has fully stopped.
///
/// # Architecture & Lifecycle
///
/// 1. **Active Health Checks**: For [`ServiceType::Router`], spawns background loops
///    for every upstream with `active_health_check_interval > 0`. They are supervised:
///    panics are logged and the loops are awaited on shutdown.
/// 2. **Tunnel or Listener Dispatch**:
///    - If `server_config.tunnel` is set, connects outbound via mTLS + Yamux with
///      exponential backoff on disconnects.
///    - For [`Protocol::Https`], starts dual-stack TCP (HTTP/1.1 + HTTP/2) and UDP
///      (HTTP/3 over QUIC) listeners via [`spawn_dual_stack`]. If one listener dies
///      unexpectedly, the whole server is shut down instead of running half-dead.
///    - For [`Protocol::Http`], starts a plaintext TCP listener.
/// 3. **Graceful shutdown**: When `cancel_token` fires, listeners stop accepting,
///    in-flight connections get up to `server_config.drain_timeout()` to finish and
///    this function returns only after everything has been drained.
pub async fn start_single_server(
    server_config: Arc<ServerConfig>,
    cancel_token: CancellationToken,
    dynamic_stack: Arc<ArcSwap<BoxedCloneService>>,
) {
    start_single_server_with_socket_signal(server_config, cancel_token, dynamic_stack, None).await;
}

/// Hot-reload payload delivered on `SIGHUP` to a running server instance
/// whose listening socket or tunnel target did not change.
#[derive(Clone)]
pub struct ServerReloadUpdate {
    /// Updated server configuration (contains new `parsed_routes` / `UpstreamNode`s,
    /// `oid_mapping`, `parsed_pki_base_oid`, and `connection_limits`).
    pub config: Arc<ServerConfig>,
    /// Pre-validated TLS configuration (when `protocol == Https` or `tunnel.is_some()`).
    pub tls_config: Option<Arc<RustlsServerConfig>>,
}

/// Like [`start_single_server`], but notifies `sockets_released` as soon as the
/// server's listening sockets are closed (before waiting for slow HTTP connection
/// draining to finish), allowing hot-reload restarts on the same port to bind promptly.
pub async fn start_single_server_with_socket_signal(
    server_config: Arc<ServerConfig>,
    cancel_token: CancellationToken,
    dynamic_stack: Arc<ArcSwap<BoxedCloneService>>,
    sockets_released: Option<oneshot::Sender<()>>,
) {
    let (_reload_tx, reload_rx) = tokio::sync::watch::channel(ServerReloadUpdate {
        config: server_config.clone(),
        tls_config: None,
    });
    start_single_server_reloadable(
        server_config,
        cancel_token,
        dynamic_stack,
        sockets_released,
        reload_rx,
    )
    .await;
}

/// Like [`start_single_server_with_socket_signal`], but also listens on `reload_rx`
/// to hot-reload TLS/mTLS/CRL configurations, OID mappings, connection limits, and
/// active router health-check loops in place on `SIGHUP`.
pub async fn start_single_server_reloadable(
    server_config: Arc<ServerConfig>,
    cancel_token: CancellationToken,
    dynamic_stack: Arc<ArcSwap<BoxedCloneService>>,
    sockets_released: Option<oneshot::Sender<()>>,
    reload_rx: tokio::sync::watch::Receiver<ServerReloadUpdate>,
) {
    // Per-server token: cancelled by the caller or if a listener dies unexpectedly.
    let server_token = cancel_token.child_token();
    let health_shutdown_token = CancellationToken::new();
    let health_handle = tokio::spawn(supervise_reloadable_health_checks(
        server_config.clone(),
        health_shutdown_token.clone(),
        reload_rx.clone(),
    ));

    serve_listeners(
        &server_config,
        &server_token,
        dynamic_stack,
        sockets_released,
        reload_rx,
    )
    .await;

    if !cancel_token.is_cancelled() {
        error!(
            "{}: Server stopped before a shutdown was requested",
            server_config.name
        );
    }

    server_token.cancel();
    health_shutdown_token.cancel();
    let _ = health_handle.await;
}

/// Supervises active router health-check tasks and restarts them against the new
/// [`UpstreamNode`] instances whenever a `SIGHUP` reload arrives on `reload_rx`.
async fn supervise_reloadable_health_checks(
    initial_config: Arc<ServerConfig>,
    server_token: CancellationToken,
    mut reload_rx: tokio::sync::watch::Receiver<ServerReloadUpdate>,
) {
    let server_name = initial_config.name.clone();
    let mut health_token = server_token.child_token();
    let mut background_tasks: JoinSet<()> = JoinSet::new();

    if initial_config.service == ServiceType::Router {
        spawn_router_health_checks_in(&initial_config, health_token.clone(), &mut background_tasks);
    }

    loop {
        tokio::select! {
            _ = server_token.cancelled() => break,
            Some(res) = background_tasks.join_next(), if !background_tasks.is_empty() => {
                log_task_result(&server_name, "background", res);
            }
            changed = reload_rx.changed() => {
                if changed.is_err() {
                    std::future::pending::<()>().await;
                }
                let next_cfg = reload_rx.borrow_and_update().config.clone();
                health_token.cancel();
                drain_tasks(
                    &mut background_tasks,
                    &server_name,
                    "background",
                    BACKGROUND_STOP_TIMEOUT,
                )
                .await;

                health_token = server_token.child_token();
                if next_cfg.service == ServiceType::Router {
                    spawn_router_health_checks_in(
                        &next_cfg,
                        health_token.clone(),
                        &mut background_tasks,
                    );
                    info!("{}: Reloaded active health checks for updated upstream targets", server_name);
                }
            }
        }
    }

    health_token.cancel();
    drain_tasks(
        &mut background_tasks,
        &server_name,
        "background",
        BACKGROUND_STOP_TIMEOUT,
    )
    .await;
}

/// Runs the tunnel or listener part of a server until `server_token` is cancelled
/// (or the listeners cannot be started) and drains all in-flight connections.
async fn serve_listeners(
    server_config: &Arc<ServerConfig>,
    server_token: &CancellationToken,
    dynamic_stack: Arc<ArcSwap<BoxedCloneService>>,
    sockets_released: Option<oneshot::Sender<()>>,
    mut reload_rx: tokio::sync::watch::Receiver<ServerReloadUpdate>,
) {
    let drain_timeout = server_config.drain_timeout();
    let Some(static_name) = server_config.static_name else {
        error!(
            "{}: Missing static_name (ensure ServerConfig::finalize was called)",
            server_config.name
        );
        return;
    };

    let live_oid_mapping = Arc::new(ArcSwap::from_pointee(server_config.oid_mapping.clone()));
    let live_pki_base_oid: Arc<ArcSwap<Option<Arc<[u64]>>>> = Arc::new(ArcSwap::from_pointee(
        server_config.parsed_pki_base_oid.as_deref().map(Arc::from),
    ));
    let connection_tracker = Arc::new(ConnectionTracker::with_server_name(
        server_config.connection_limits.max_connections,
        server_config.connection_limits.max_connections_per_ip,
        &server_config.name,
    ));

    if let Some(tunnel) = &server_config.tunnel {
        let _release_guard = SocketReleaseBarrier::new(1, sockets_released);
        info!(
            "{}: Connecting to Zero-Trust Tunnel at {}",
            server_config.name, tunnel.target_url
        );
        let initial_tls = reload_rx.borrow().tls_config.clone();
        let tls_config: Arc<RustlsServerConfig> = match initial_tls {
            Some(cfg) => cfg,
            None => match build_rustls_config(server_config.as_ref()) {
                Ok(cfg) => Arc::new(cfg),
                Err(e) => {
                    error!("{}: TLS Setup Error: {:?}", server_config.name, e);
                    return;
                }
            },
        };
        let live_acceptor = Arc::new(ArcSwap::from_pointee(tokio_rustls::TlsAcceptor::from(
            tls_config,
        )));

        let watcher_token = server_token.child_token();
        let watcher_tracker = connection_tracker.clone();
        let watcher_oids = live_oid_mapping.clone();
        let watcher_base_oid = live_pki_base_oid.clone();
        let watcher_acceptor = live_acceptor.clone();
        let _reload_watcher = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = watcher_token.cancelled() => break,
                    res = reload_rx.changed() => {
                        if res.is_err() {
                            break;
                        }
                        let snap = reload_rx.borrow_and_update().clone();
                        watcher_tracker.update_limits(
                            snap.config.connection_limits.max_connections,
                            snap.config.connection_limits.max_connections_per_ip,
                        );
                        watcher_oids.store(Arc::new(snap.config.oid_mapping.clone()));
                        watcher_base_oid.store(Arc::new(
                            snap.config.parsed_pki_base_oid.as_deref().map(Arc::from),
                        ));
                        let new_tls = snap.tls_config.or_else(|| {
                            build_rustls_config(snap.config.as_ref()).ok().map(Arc::new)
                        });
                        if let Some(tls_cfg) = new_tls {
                            watcher_acceptor.store(Arc::new(tokio_rustls::TlsAcceptor::from(tls_cfg)));
                        }
                    }
                }
            }
        });

        let mut retry_count = 0;
        let initial_delay = Duration::from_secs(1);

        loop {
            if server_token.is_cancelled() {
                break;
            }

            let start_time = std::time::Instant::now();
            if let Err(e) = run_tunnel_with_dynamic_state(
                tunnel.clone(),
                live_acceptor.clone(),
                dynamic_stack.clone(),
                server_token.clone(),
                static_name,
                live_oid_mapping.clone(),
                connection_tracker.clone(),
                drain_timeout,
                live_pki_base_oid.clone(),
            )
            .await
            {
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
                _ = server_token.cancelled() => {
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
        let initial_tls = reload_rx.borrow().tls_config.clone();
        let tls_config: Arc<RustlsServerConfig> = match initial_tls {
            Some(cfg) => cfg,
            None => match build_rustls_config(server_config.as_ref()) {
                Ok(cfg) => Arc::new(cfg),
                Err(e) => {
                    error!("{}: TLS Setup Error: {:?}", server_config.name, e);
                    return;
                }
            },
        };

        let barrier = SocketReleaseBarrier::new(2, sockets_released);
        match spawn_dual_stack_reloadable(
            server_addr,
            tls_config,
            dynamic_stack,
            server_token.clone(),
            static_name,
            live_oid_mapping,
            connection_tracker.clone(),
            drain_timeout,
            Some(barrier),
            live_pki_base_oid,
            Some(reload_rx),
        )
        .await
        {
            Ok(handles) => supervise_dual_stack(handles, server_token, &server_config.name).await,
            Err(e) => error!(
                "{}: HTTPS/Dual Stack Server crashed: {:?}",
                server_config.name, e
            ),
        }
    } else {
        // === HTTP (PLAINTEXT) FALLBACK ===
        let listener = match TcpListener::bind(server_addr).await {
            Ok(l) => l,
            Err(e) => {
                error!("{}: HTTP Bind failed: {}", server_config.name, e);
                return;
            }
        };

        let watcher_token = server_token.child_token();
        let watcher_tracker = connection_tracker.clone();
        let watcher_oids = live_oid_mapping.clone();
        let _reload_watcher = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = watcher_token.cancelled() => break,
                    res = reload_rx.changed() => {
                        if res.is_err() {
                            break;
                        }
                        let snap = reload_rx.borrow_and_update().clone();
                        watcher_tracker.update_limits(
                            snap.config.connection_limits.max_connections,
                            snap.config.connection_limits.max_connections_per_ip,
                        );
                        watcher_oids.store(Arc::new(snap.config.oid_mapping.clone()));
                    }
                }
            }
        });

        let barrier = SocketReleaseBarrier::new(1, sockets_released);
        let mut conn_tasks: JoinSet<()> = JoinSet::new();
        loop {
            tokio::select! {
                _ = server_token.cancelled() => break,
                Some(res) = conn_tasks.join_next(), if !conn_tasks.is_empty() => {
                    log_task_result(static_name, "connection", res);
                }
                res = listener.accept() => {
                    match res {
                        Ok((stream, peer_addr)) => {
                            let peer_ip = peer_addr.ip();
                            let conn_guard = match connection_tracker.acquire(Some(peer_ip)) {
                                Ok(guard) => guard,
                                Err(AcquireError::GlobalLimitReached { current, max }) => {
                                    warn!(
                                        "{}: Global connection limit reached ({} >= {}), dropping HTTP connection from {}",
                                        static_name, current, max, peer_addr
                                    );
                                    drop(stream);
                                    continue;
                                }
                                Err(AcquireError::IpLimitReached { ip, current, max }) => {
                                    warn!(
                                        "{}: Per-IP connection limit reached for {} ({} >= {}), dropping HTTP connection",
                                        static_name, ip, current, max
                                    );
                                    drop(stream);
                                    continue;
                                }
                            };
                            let dynamic_stack = dynamic_stack.clone();
                            let conn_token = server_token.clone();
                            let oid_mapping = live_oid_mapping.clone();
                            conn_tasks.spawn(async move {
                                let _guard = conn_guard;
                                let handler = ConnectionHandler::with_dynamic_stack_and_oids(
                                    dynamic_stack,
                                    peer_addr,
                                    Vec::new(),
                                    None,
                                    None,
                                    oid_mapping,
                                );
                                serve_http_connection(stream, handler, conn_token).await;
                            });
                        }
                        Err(e) => {
                            error!("{}: HTTP Accept error: {}", server_config.name, e);
                            tokio::select! {
                                _ = server_token.cancelled() => break,
                                _ = tokio::time::sleep(ACCEPT_ERROR_BACKOFF) => {}
                            }
                        }
                    }
                }
            }
        }

        // Release the listening socket first so a successor can bind immediately.
        drop(listener);
        barrier.release();
        drain_tasks(&mut conn_tasks, static_name, "connection", drain_timeout).await;
    }
}

/// Waits for both dual-stack listeners.
///
/// If one listener ends before a shutdown was requested (panic or unexpected exit),
/// the server token is cancelled so the sibling listener and the health checks do
/// not keep running half-dead, and both listeners are awaited.
async fn supervise_dual_stack(
    handles: DualStackHandles,
    server_token: &CancellationToken,
    server_name: &str,
) {
    let DualStackHandles {
        mut tcp_task,
        mut udp_task,
    } = handles;

    let (tcp_res, udp_res) = tokio::select! {
        res = &mut tcp_task => {
            if !server_token.is_cancelled() {
                error!("{}: TCP listener exited unexpectedly; shutting down server", server_name);
            }
            server_token.cancel();
            (res, udp_task.await)
        }
        res = &mut udp_task => {
            if !server_token.is_cancelled() {
                error!("{}: UDP/QUIC listener exited unexpectedly; shutting down server", server_name);
            }
            server_token.cancel();
            (tcp_task.await, res)
        }
    };

    log_task_result(server_name, "TCP listener", tcp_res);
    log_task_result(server_name, "UDP/QUIC listener", udp_res);
}

/// Spawns background active health-checker loops for upstream router targets.
///
/// Evaluates all `parsed_routes` in `server_config`. For any backend marked with a
/// non-zero `active_health_check_interval`, this provisions keep-alive Hyper clients
/// (HTTP/2-only for gRPC, standard for REST) and spawns periodic probes.
///
/// The probes run detached; a small reaper task logs panics. Use
/// [`spawn_router_health_checks_in`] to supervise them in your own [`JoinSet`].
pub fn spawn_router_health_checks(
    server_config: &Arc<ServerConfig>,
    cancel_token: CancellationToken,
) {
    let mut tasks: JoinSet<()> = JoinSet::new();
    spawn_router_health_checks_in(server_config, cancel_token, &mut tasks);
    if tasks.is_empty() {
        return;
    }

    let server_name = server_config.name.clone();
    tokio::spawn(async move {
        while let Some(res) = tasks.join_next().await {
            log_task_result(&server_name, "health-check", res);
        }
    });
}

/// Like [`spawn_router_health_checks`], but spawns the probe loops into the caller's
/// `tasks` set so they can be supervised, awaited and aborted together with the server.
pub fn spawn_router_health_checks_in(
    server_config: &Arc<ServerConfig>,
    cancel_token: CancellationToken,
    tasks: &mut JoinSet<()>,
) {
    let Some(router_params) = &server_config.router_params else {
        return;
    };

    // --- 1. TLS Context Initialization for Upstreams ---
    let root_store = match common::build_root_store(&router_params.ssl_root_certificate) {
        Ok(store) => store,
        Err(e) => {
            error!(
                "{}: Failed to build root store for health checks: {}",
                server_config.name, e
            );
            return;
        }
    };

    let is_mtls = router_params.authentication == AuthenticationMethod::ClientCert;

    let tls_client_config = match if is_mtls {
        common::build_tls_client_config(
            root_store,
            router_params.ssl_client_certificate.as_deref(),
            router_params.ssl_client_key.as_deref(),
        )
    } else {
        common::build_tls_client_config(root_store, None, None)
    } {
        Ok(cfg) => cfg,
        Err(e) => {
            error!(
                "{}: Failed to build TLS client config for health checks: {}",
                server_config.name, e
            );
            return;
        }
    };

    // --- 2. Connection Pool Setup ---
    let grpc_pool_config = common::client::ClientPoolConfig {
        idle_timeout: Some(Duration::from_secs(router_params.idle_timeout_seconds)),
        max_idle_per_host: Some(16),
        http2_only: true,
        connect_timeout: (router_params.connect_timeout_seconds > 0)
            .then(|| Duration::from_secs(router_params.connect_timeout_seconds)),
        ..Default::default()
    };
    let grpc_client = common::client::build_hyper_client(tls_client_config.clone(), grpc_pool_config);

    let pool_config = common::client::ClientPoolConfig {
        idle_timeout: Some(Duration::from_secs(router_params.idle_timeout_seconds)),
        max_idle_per_host: Some(16),
        http2_only: false,
        connect_timeout: (router_params.connect_timeout_seconds > 0)
            .then(|| Duration::from_secs(router_params.connect_timeout_seconds)),
        ..Default::default()
    };
    let client = common::client::build_hyper_client(tls_client_config, pool_config);

    let jwt_token = router_params
        .jwt
        .as_ref()
        .and_then(|t| hyper::header::HeaderValue::from_str(&format!("Bearer {}", t)).ok());

    let proto_str = match router_params.protocol {
        Protocol::Https => "https",
        Protocol::Http => "http",
    };

    // --- 3. Active Health Check Initialization ---
    for (_, backend_type, target_ref) in server_config
        .parsed_routes
        .iter()
        .flat_map(|route| route.iter_targets())
    {
        let interval = target_ref.active_health_check_interval;
        if interval == 0 {
            continue;
        }

        let is_grpc = *backend_type == RouteBackendType::GrpcTranscoding
            || *backend_type == RouteBackendType::GrpcPassthrough;

        for (idx, node) in target_ref.upstreams.iter().enumerate() {
            let client = if is_grpc {
                grpc_client.clone()
            } else {
                client.clone()
            };

            let token = cancel_token.clone();
            let Some(authority) = node.uri.authority() else {
                error!(
                    "{}: Skipping health check for upstream '{}' without authority",
                    server_config.name, node.uri
                );
                continue;
            };

            let base_uri_str = format!(
                "{}://{}",
                node.uri.scheme_str().unwrap_or(proto_str),
                authority.as_str()
            );
            let Ok(base_uri) = base_uri_str.parse::<hyper::Uri>() else {
                error!(
                    "{}: Invalid upstream base URI for health check: '{}'",
                    server_config.name, base_uri_str
                );
                continue;
            };
            let Ok(rest_uri) = format!("{}/health", base_uri_str).parse::<hyper::Uri>() else {
                error!(
                    "{}: Invalid REST health check URI for '{}'",
                    server_config.name, base_uri_str
                );
                continue;
            };

            let server_name = server_config.static_name.unwrap_or("unknown");
            let interval_dur = Duration::from_secs(interval);
            let target_arc = target_ref.clone();
            let auth_header = jwt_token.clone();
            let router_params = router_params.clone();

            tasks.spawn(async move {
                // Startup grace period (10 seconds): allow co-started or manually launched
                // backend services (which may first fetch JWKS from Praeco's IdP) to bind
                // their listening ports before running the first active health check.
                tokio::select! {
                    _ = token.cancelled() => return,
                    _ = tokio::time::sleep(Duration::from_secs(10)) => {}
                }

                let mut ticker = tokio::time::interval(interval_dur);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

                let mut grpc_health_path: Option<String> = None;
                let mut reflection_attempts: usize = 0;

                loop {
                    tokio::select! {
                        _ = token.cancelled() => break,
                        _ = ticker.tick() => {
                            let final_uri;
                            let mut req_builder = Request::builder();

                            if is_grpc {
                                if grpc_health_path.is_none() {
                                    reflection_attempts += 1;

                                    match build_grpc_pool(&base_uri, Some(&router_params)).await {
                                        Ok(p) => {
                                            for service in p.services() {
                                                for method in service.methods() {
                                                    if method.name() == "health" {
                                                        grpc_health_path = Some(format!("/{}/health", service.full_name()));
                                                        break;
                                                    }
                                                }
                                                if grpc_health_path.is_some() { break; }
                                            }

                                            let mut pool_guard = target_arc.grpc_pool.write().await;
                                            if pool_guard.is_none() {
                                                *pool_guard = Some(CachedDescriptorPool {
                                                    pool: p,
                                                    created_at: std::time::Instant::now(),
                                                });
                                            }
                                            drop(pool_guard);

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
                                                || reflection_attempts.is_multiple_of(10)
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

                                if let Some(path) = &grpc_health_path {
                                    let Ok(uri) = format!("{}{}", base_uri_str, path).parse::<hyper::Uri>() else {
                                        continue;
                                    };
                                    final_uri = uri;
                                    req_builder = req_builder
                                        .method(hyper::Method::POST)
                                        .uri(final_uri.clone())
                                        .header("content-type", "application/grpc")
                                        .header("te", "trailers");
                                } else {
                                    continue;
                                }
                            } else {
                                final_uri = rest_uri.clone();
                                req_builder = req_builder.method(hyper::Method::GET).uri(final_uri.clone());
                            }

                            if let Some(ref header_val) = auth_header {
                                req_builder = req_builder.header(hyper::header::AUTHORIZATION, header_val.clone());
                            }

                            let req_body = if is_grpc && grpc_health_path.is_some() {
                                let payload = bytes::Bytes::from(vec![0u8, 0, 0, 0, 0]);
                                http_body_util::Full::new(payload).map_err(|e| match e {}).boxed()
                            } else {
                                http_body_util::Empty::<bytes::Bytes>::new().map_err(|e| match e {}).boxed()
                            };

                            let Ok(req) = req_builder.body(req_body) else {
                                continue;
                            };

                            match tokio::time::timeout(Duration::from_secs(5), client.request(req)).await {
                                Ok(Ok(resp)) => {
                                    let resp_status = resp.status();
                                    let is_ok = resp_status == StatusCode::OK;
                                    let mut health_score_ok = true;

                                    if is_ok && is_grpc && grpc_health_path.is_some() {
                                        use http_body_util::Limited;
                                        let limited_body = Limited::new(resp.into_body(), 64 * 1024);
                                        if let Ok(collected) = limited_body.collect().await
                                            && let Some(score) = parse_grpc_health_score(&collected.to_bytes())
                                        {
                                            target_arc.upstreams[idx]
                                                .current_score
                                                .store(score, std::sync::atomic::Ordering::Relaxed);
                                            if score == 0 {
                                                health_score_ok = false;
                                            }
                                        } else {
                                            health_score_ok = false;
                                        }
                                    } else if is_ok && !is_grpc {
                                        use http_body_util::Limited;
                                        let limited_body = Limited::new(resp.into_body(), 64 * 1024);
                                        if let Ok(collected) = limited_body.collect().await
                                            && let Some(score) = parse_rest_health_score(&collected.to_bytes())
                                        {
                                            target_arc.upstreams[idx]
                                                .current_score
                                                .store(score, std::sync::atomic::Ordering::Relaxed);
                                            if score == 0 {
                                                health_score_ok = false;
                                            }
                                        } else {
                                            health_score_ok = false;
                                        }
                                    }

                                    if is_ok && health_score_ok {
                                        let current_score = target_arc.upstreams[idx].current_score.load(std::sync::atomic::Ordering::Relaxed);
                                        tracing::trace!("{}: Health check successful for '{}', score: {}", server_name, final_uri, current_score);
                                        if !target_arc.upstreams[idx].is_alive.load(std::sync::atomic::Ordering::Relaxed) {
                                            info!("{}: Health check recovered '{}'", server_name, final_uri);
                                            target_arc.upstreams[idx].mark_alive();
                                        }
                                    } else {
                                        record_health_check_failure(&target_arc.upstreams[idx], || {
                                            tracing::warn!(
                                                "{}: Health check failed status {} for '{}' (Score OK: {})",
                                                server_name,
                                                resp_status,
                                                final_uri,
                                                health_score_ok
                                            );
                                        });
                                    }
                                }
                                Ok(Err(e)) => {
                                    record_health_check_failure(&target_arc.upstreams[idx], || {
                                        tracing::warn!(
                                            "{}: Health check network error for '{}': {}",
                                            server_name,
                                            final_uri,
                                            e
                                        );
                                    });
                                }
                                Err(_) => {
                                    record_health_check_failure(&target_arc.upstreams[idx], || {
                                        tracing::warn!(
                                            "{}: Health check timed out after 5s for '{}'",
                                            server_name,
                                            final_uri
                                        );
                                    });
                                }
                            }
                        }
                    }
                }
            });
        }
    }
}

/// Decodes a gRPC health-check response frame (`[compressed: u8][len: u32 BE][protobuf]`)
/// and extracts field 1 (`score` varint) if well-formed.
fn parse_grpc_health_score(bytes: &[u8]) -> Option<usize> {
    if bytes.len() < 5 {
        return None;
    }
    let len_bytes: [u8; 4] = [bytes[1], bytes[2], bytes[3], bytes[4]];
    let payload_len = u32::from_be_bytes(len_bytes) as usize;
    if bytes.len() < 5 + payload_len {
        return None;
    }
    let raw_payload = &bytes[5..5 + payload_len];
    if raw_payload.len() < 2 || raw_payload[0] != 0x08 {
        return None;
    }
    let mut score = 0usize;
    let mut shift = 0;
    for &b in &raw_payload[1..] {
        score |= ((b & 0x7F) as usize) << shift;
        if (b & 0x80) == 0 {
            return Some(score);
        }
        shift += 7;
        if shift >= 32 {
            return None;
        }
    }
    None
}

/// Extracts the numeric `"score"` field from a REST `/health` JSON payload.
fn parse_rest_health_score(bytes: &[u8]) -> Option<usize> {
    let json: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let score = json.get("score")?.as_u64()?;
    usize::try_from(score).ok()
}

/// Resets an upstream node's health score, trips its circuit breaker on transition,
/// or refreshes `last_failure_time` while already dead.
fn record_health_check_failure(
    node: &crate::configuration::UpstreamNode,
    log_transition: impl FnOnce(),
) {
    node.current_score
        .store(0, std::sync::atomic::Ordering::Relaxed);
    if node.is_alive.load(std::sync::atomic::Ordering::Relaxed) {
        log_transition();
        node.mark_dead();
    } else {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        node.last_failure_time
            .store(now, std::sync::atomic::Ordering::Relaxed);
    }
}

/// Join handles of the two accept loops started by [`spawn_dual_stack`].
///
/// Dropping the handles detaches the loops (they keep running until the
/// cancellation token fires); awaiting them waits for the graceful drain.
#[derive(Debug)]
pub struct DualStackHandles {
    /// TCP accept loop (HTTP/1.1 + HTTP/2 over TLS).
    pub tcp_task: JoinHandle<()>,
    /// UDP accept loop (HTTP/3 over QUIC).
    pub udp_task: JoinHandle<()>,
}

/// Runs a dual-stack HTTPS server supporting both TCP (HTTP/1.1, HTTP/2) and UDP (HTTP/3 over QUIC)
/// on the same socket address.
///
/// Returns as soon as both sockets are bound and the accept loops are running; the loops
/// stay detached. Use [`spawn_dual_stack`] to obtain their [`JoinHandle`]s and supervise them.
///
/// # Errors
///
/// Returns [`SrvError`] if the TCP or UDP socket cannot be bound or the QUIC TLS
/// configuration is invalid. In that case no task is left running.
pub async fn run_dual_stack(
    server_addr: SocketAddr,
    tls_config: RustlsServerConfig,
    dynamic_stack: Arc<ArcSwap<BoxedCloneService>>,
    cancel_token: CancellationToken,
    server_name: &'static str,
    oid_mapping: Arc<HashMap<String, UserRole>>,
    connection_tracker: Arc<ConnectionTracker>,
) -> Result<(), SrvError> {
    spawn_dual_stack(
        server_addr,
        tls_config,
        dynamic_stack,
        cancel_token,
        server_name,
        oid_mapping,
        connection_tracker,
    )
    .await
    .map(|_| ())
}

/// Binds the TCP and UDP sockets and spawns the HTTPS (TCP) and HTTP/3 (QUIC) accept loops.
///
/// Both sockets are bound **before** any task is spawned, so a failing second bind never
/// leaves the first accept loop running. When `cancel_token` fires, both loops stop
/// accepting, release their sockets, drain in-flight connections for up to
/// [`CONNECTION_DRAIN_TIMEOUT`] and then finish; awaiting the returned handles waits for that.
///
/// # Errors
///
/// Returns [`SrvError`] if the TCP/UDP bind fails or the QUIC TLS configuration is invalid.
pub async fn spawn_dual_stack(
    server_addr: SocketAddr,
    tls_config: RustlsServerConfig,
    dynamic_stack: Arc<ArcSwap<BoxedCloneService>>,
    cancel_token: CancellationToken,
    server_name: &'static str,
    oid_mapping: Arc<HashMap<String, UserRole>>,
    connection_tracker: Arc<ConnectionTracker>,
) -> Result<DualStackHandles, SrvError> {
    spawn_dual_stack_inner(
        server_addr,
        tls_config,
        dynamic_stack,
        cancel_token,
        server_name,
        oid_mapping,
        connection_tracker,
        CONNECTION_DRAIN_TIMEOUT,
        None,
        Config::try_global().and_then(|c| c.parsed_pki_base_oid.as_deref().map(Arc::from)),
    )
    .await
}

/// Like [`spawn_dual_stack`], with explicit `drain_timeout`, optional `release_barrier`,
/// and optional per-server `pki_base_oid`.
#[allow(clippy::too_many_arguments)]
async fn spawn_dual_stack_inner(
    server_addr: SocketAddr,
    tls_config: RustlsServerConfig,
    dynamic_stack: Arc<ArcSwap<BoxedCloneService>>,
    cancel_token: CancellationToken,
    server_name: &'static str,
    oid_mapping: Arc<HashMap<String, UserRole>>,
    connection_tracker: Arc<ConnectionTracker>,
    drain_timeout: Duration,
    release_barrier: Option<Arc<SocketReleaseBarrier>>,
    pki_base_oid: Option<Arc<[u64]>>,
) -> Result<DualStackHandles, SrvError> {
    spawn_dual_stack_reloadable(
        server_addr,
        Arc::new(tls_config),
        dynamic_stack,
        cancel_token,
        server_name,
        Arc::new(ArcSwap::new(oid_mapping)),
        connection_tracker,
        drain_timeout,
        release_barrier,
        Arc::new(ArcSwap::from_pointee(pki_base_oid)),
        None,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn spawn_dual_stack_reloadable(
    server_addr: SocketAddr,
    arc_tls_config: Arc<RustlsServerConfig>,
    dynamic_stack: Arc<ArcSwap<BoxedCloneService>>,
    cancel_token: CancellationToken,
    server_name: &'static str,
    live_oid_mapping: Arc<ArcSwap<HashMap<String, UserRole>>>,
    connection_tracker: Arc<ConnectionTracker>,
    drain_timeout: Duration,
    release_barrier: Option<Arc<SocketReleaseBarrier>>,
    live_pki_base_oid: Arc<ArcSwap<Option<Arc<[u64]>>>>,
    reload_rx: Option<tokio::sync::watch::Receiver<ServerReloadUpdate>>,
) -> Result<DualStackHandles, SrvError> {
    // Bind everything first: on failure the already-bound socket is simply dropped.
    let tcp_listener = TcpListener::bind(server_addr)
        .await
        .map_err(|e| SrvError::Other(format!("TCP bind failed on {server_addr}: {e}")))?;
    let quic_endpoint = build_quic_endpoint(server_addr, &arc_tls_config)?;
    let live_acceptor = Arc::new(ArcSwap::from_pointee(tokio_rustls::TlsAcceptor::from(
        arc_tls_config,
    )));

    if let Some(mut rx) = reload_rx {
        let watcher_token = cancel_token.child_token();
        let watcher_tracker = connection_tracker.clone();
        let watcher_oids = live_oid_mapping.clone();
        let watcher_base_oid = live_pki_base_oid.clone();
        let watcher_acceptor = live_acceptor.clone();
        let watcher_endpoint = quic_endpoint.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = watcher_token.cancelled() => break,
                    res = rx.changed() => {
                        if res.is_err() {
                            break;
                        }
                        let snap = rx.borrow_and_update().clone();
                        watcher_tracker.update_limits(
                            snap.config.connection_limits.max_connections,
                            snap.config.connection_limits.max_connections_per_ip,
                        );
                        watcher_oids.store(Arc::new(snap.config.oid_mapping.clone()));
                        watcher_base_oid.store(Arc::new(
                            snap.config.parsed_pki_base_oid.as_deref().map(Arc::from),
                        ));
                        let new_tls = snap.tls_config.or_else(|| {
                            build_rustls_config(snap.config.as_ref()).ok().map(Arc::new)
                        });
                        if let Some(tls_cfg) = new_tls {
                            watcher_acceptor.store(Arc::new(tokio_rustls::TlsAcceptor::from(
                                tls_cfg.clone(),
                            )));
                            if let Ok(quinn_cfg) = build_quinn_server_config(&tls_cfg) {
                                watcher_endpoint.set_server_config(Some(quinn_cfg));
                            }
                        }
                    }
                }
            }
        });
    }

    let tcp_task = tokio::spawn(run_tcp_accept_loop(
        tcp_listener,
        live_acceptor,
        dynamic_stack.clone(),
        cancel_token.clone(),
        server_name,
        live_oid_mapping.clone(),
        connection_tracker.clone(),
        drain_timeout,
        release_barrier.clone(),
        live_pki_base_oid.clone(),
    ));
    let udp_task = tokio::spawn(run_udp_accept_loop(
        quic_endpoint,
        dynamic_stack,
        cancel_token,
        server_name,
        live_oid_mapping,
        connection_tracker,
        drain_timeout,
        release_barrier,
        live_pki_base_oid,
    ));

    Ok(DualStackHandles { tcp_task, udp_task })
}

/// Accept loop for HTTPS traffic (HTTP/1.1 and HTTP/2) on an already bound listener.
///
/// Connection tasks are tracked in a [`JoinSet`]: finished ones are reaped while running
/// (panics are logged) and the remaining ones are drained after `cancel_token` fired.
#[allow(clippy::too_many_arguments)]
async fn run_tcp_accept_loop(
    tcp_listener: TcpListener,
    live_acceptor: Arc<ArcSwap<tokio_rustls::TlsAcceptor>>,
    dynamic_stack: Arc<ArcSwap<BoxedCloneService>>,
    cancel_token: CancellationToken,
    server_name: &'static str,
    live_oid_mapping: Arc<ArcSwap<HashMap<String, UserRole>>>,
    connection_tracker: Arc<ConnectionTracker>,
    drain_timeout: Duration,
    release_barrier: Option<Arc<SocketReleaseBarrier>>,
    live_pki_base_oid: Arc<ArcSwap<Option<Arc<[u64]>>>>,
) {
    let mut conn_tasks: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => break,
            Some(res) = conn_tasks.join_next(), if !conn_tasks.is_empty() => {
                log_task_result(server_name, "connection", res);
            }
            res = tcp_listener.accept() => {
                match res {
                    Ok((stream, peer_addr)) => {
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
                        let _ = stream.set_nodelay(true);
                        let acceptor = (**live_acceptor.load()).clone();
                        let dynamic_stack = dynamic_stack.clone();
                        let oid_mapping = live_oid_mapping.clone();
                        let conn_token = cancel_token.clone();
                        let pki_base_oid = (**live_pki_base_oid.load()).clone();
                        conn_tasks.spawn(async move {
                            let _guard = conn_guard;
                            trace!("{}: TCP Connection accepted", server_name);
                            let _ = crate::stack::serve_tls_connection_with_dynamic_oids(
                                stream,
                                peer_addr,
                                &acceptor,
                                &dynamic_stack,
                                &oid_mapping,
                                conn_token,
                                server_name,
                                pki_base_oid.as_deref(),
                            )
                            .await;
                        });
                    }
                    Err(e) => {
                        error!("{}: TCP Accept error: {}", server_name, e);
                        tokio::select! {
                            _ = cancel_token.cancelled() => break,
                            _ = tokio::time::sleep(ACCEPT_ERROR_BACKOFF) => {}
                        }
                    }
                }
            }
        }
    }

    // Release the listening socket first so a successor can bind immediately.
    drop(tcp_listener);
    if let Some(barrier) = release_barrier {
        barrier.release();
    }
    drain_tasks(&mut conn_tasks, server_name, "connection", drain_timeout).await;
}

/// Builds a `quinn::ServerConfig` from a `RustlsServerConfig` with Praeco's HTTP/3 transport parameters.
fn build_quinn_server_config(
    tls_config: &Arc<RustlsServerConfig>,
) -> Result<quinn::ServerConfig, SrvError> {
    let mut quic_tls_models = rustls::ServerConfig::clone(tls_config);
    quic_tls_models.alpn_protocols = vec![b"h3".to_vec()];

    let quic_config = quinn::crypto::rustls::QuicServerConfig::try_from(quic_tls_models)
        .map_err(|e| SrvError::Other(format!("TLS Config Error for QUIC: {e}")))?;

    let mut quinn_server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_config));

    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_uni_streams(128u32.into());
    transport.max_concurrent_bidi_streams(128u32.into());
    transport.receive_window(8_388_608u32.into());
    transport.send_window(8_388_608u64);
    transport.stream_receive_window(1_048_576u32.into());
    let idle_timeout = quinn::IdleTimeout::try_from(Duration::from_secs(30))
        .map_err(|e| SrvError::Other(format!("Invalid QUIC idle timeout: {e}")))?;
    transport.max_idle_timeout(Some(idle_timeout));
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    quinn_server_config.transport_config(Arc::new(transport));

    Ok(quinn_server_config)
}

/// Builds the QUIC server endpoint (and binds its UDP socket) for HTTP/3.
fn build_quic_endpoint(
    server_addr: SocketAddr,
    tls_config: &Arc<RustlsServerConfig>,
) -> Result<quinn::Endpoint, SrvError> {
    let quinn_server_config = build_quinn_server_config(tls_config)?;
    quinn::Endpoint::server(quinn_server_config, server_addr)
        .map_err(|e| SrvError::Other(format!("QUIC UDP bind failed on {server_addr}: {e}")))
}

/// Accept loop for HTTP/3 traffic using QUIC (`quinn` and `h3`) on an already bound endpoint.
///
/// On shutdown it stops accepting new connections, lets the per-connection tasks finish their
/// in-flight streams (they send an HTTP/3 `GOAWAY`), and only then closes the endpoint.
#[allow(clippy::too_many_arguments)]
async fn run_udp_accept_loop(
    endpoint: quinn::Endpoint,
    dynamic_stack: Arc<ArcSwap<BoxedCloneService>>,
    cancel_token: CancellationToken,
    server_name: &'static str,
    live_oid_mapping: Arc<ArcSwap<HashMap<String, UserRole>>>,
    connection_tracker: Arc<ConnectionTracker>,
    drain_timeout: Duration,
    release_barrier: Option<Arc<SocketReleaseBarrier>>,
    live_pki_base_oid: Arc<ArcSwap<Option<Arc<[u64]>>>>,
) {
    let mut conn_tasks: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => break,
            Some(res) = conn_tasks.join_next(), if !conn_tasks.is_empty() => {
                log_task_result(server_name, "H3 connection", res);
            }
            res = endpoint.accept() => {
                let Some(conn) = res else { break };

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
                let oid_mapping = live_oid_mapping.clone();
                let conn_token = cancel_token.clone();
                let pki_base_oid = (**live_pki_base_oid.load()).clone();

                conn_tasks.spawn(async move {
                    let _guard = conn_guard;
                    if let Err(e) = handle_h3_connection(
                        conn,
                        dynamic_stack,
                        server_name,
                        oid_mapping,
                        conn_token,
                        drain_timeout,
                        pki_base_oid,
                    )
                    .await
                    {
                        error!("{}: H3 Connection Error: {:?}", server_name, e);
                    }
                });
            }
        }
    }

    // Refuse new handshakes while the existing connections finish their streams. The
    // per-connection drain is bounded by `drain_timeout`, so this outer bound
    // carries a small margin to avoid aborting a connection that is just about to finish.
    endpoint.set_server_config(None);
    drain_tasks(
        &mut conn_tasks,
        server_name,
        "H3 connection",
        drain_timeout + Duration::from_secs(1),
    )
    .await;

    endpoint.close(0u32.into(), b"shutdown");
    if tokio::time::timeout(QUIC_IDLE_TIMEOUT, endpoint.wait_idle())
        .await
        .is_err()
    {
        trace!("{}: QUIC endpoint did not become idle in time", server_name);
    }
    drop(endpoint);
    if let Some(barrier) = release_barrier {
        barrier.release();
    }
}

fn map_h3_oids_to_roles(
    oids: &[String],
    oid_mapping: &HashMap<String, UserRole>,
) -> RoleVec<6> {
    let mut roles: RoleVec<6> = oids
        .iter()
        .map(|oid| {
            oid_mapping
                .get(oid)
                .cloned()
                .unwrap_or_else(UserRole::guest)
        })
        .filter(|role| *role != UserRole::guest())
        .collect();

    if roles.is_empty() {
        roles.push(UserRole::guest());
    }
    roles
}

/// Handles a single HTTP/3 (QUIC) connection and dispatches its request streams through [`ConnectionHandler`].
///
/// When `cancel_token` fires, an HTTP/3 `GOAWAY` is sent, no new requests are accepted and the
/// in-flight request streams get up to `drain_timeout` to finish. The `h3`
/// connection object is kept alive until then because dropping it closes the QUIC connection.
async fn handle_h3_connection(
    connecting: quinn::Incoming,
    dynamic_stack: Arc<ArcSwap<BoxedCloneService>>,
    server_name: &str,
    live_oid_mapping: Arc<ArcSwap<HashMap<String, UserRole>>>,
    cancel_token: CancellationToken,
    drain_timeout: Duration,
    pki_base_oid: Option<Arc<[u64]>>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let connection = connecting.await?;
    let peer_addr = connection.remote_address();

    let client_meta = {
        let peer_identity = connection.peer_identity();
        let client_certs = peer_identity.as_ref().and_then(|identity| {
            identity
                .downcast_ref::<Vec<rustls_pki_types::CertificateDer<'static>>>()
                .map(|v| v.as_slice())
        });
        extract_client_metadata_with_base(client_certs, pki_base_oid.as_deref())
    };
    let oids = client_meta.oids;
    let client_cert_pem = client_meta.pem;
    let client_cert_san = client_meta.san;

    let mut cached_oid_map = live_oid_mapping.load_full();
    let mut shared_roles = Arc::new(map_h3_oids_to_roles(&oids, &cached_oid_map));
    let shared_oids = Arc::new(oids);

    let h3_conn = h3_quinn::Connection::new(connection);
    let mut h3_server: h3::server::Connection<h3_quinn::Connection, bytes::Bytes> =
        h3::server::Connection::new(h3_conn).await?;

    let stream_semaphore = Arc::new(tokio::sync::Semaphore::new(128));
    let mut stream_tasks: JoinSet<()> = JoinSet::new();

    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                // Tell the client to stop opening requests; in-flight ones are drained below.
                if let Err(e) = h3_server.shutdown(0).await {
                    trace!("{}: H3 GOAWAY failed: {:?}", server_name, e);
                }
                break;
            }
            Some(res) = stream_tasks.join_next(), if !stream_tasks.is_empty() => {
                log_task_result(server_name, "H3 stream", res);
            }
            accepted = h3_server.accept() => match accepted {
                Ok(Some(resolver)) => {
                    let permit = match stream_semaphore.clone().try_acquire_owned() {
                        Ok(p) => p,
                        Err(_) => {
                            warn!("{}: Max concurrent H3 streams reached (128), shedding request", server_name);
                            continue;
                        }
                    };
                    let current_oid_map = live_oid_mapping.load();
                    if !Arc::ptr_eq(&current_oid_map, &cached_oid_map) {
                        cached_oid_map = Arc::clone(&current_oid_map);
                        shared_roles = Arc::new(map_h3_oids_to_roles(&shared_oids, &cached_oid_map));
                    }

                    let dynamic_stack_for_req = dynamic_stack.clone();
                    let roles_for_req = shared_roles.clone();
                    let shared_oids_for_req = shared_oids.clone();
                    let req_cert_pem = client_cert_pem.clone();
                    let req_cert_san = client_cert_san.clone();

                    stream_tasks.spawn(async move {
                        let _permit = permit;
                        match resolver.resolve_request().await {
                            Ok((req, stream)) => {
                                let (mut sender, receiver) = stream.split();

                                let handler = ConnectionHandler::with_dynamic_stack_shared(
                                    dynamic_stack_for_req,
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
                                                    if let Ok(trailers) = frame.into_trailers()
                                                        && sender.send_trailers(trailers).await.is_err()
                                                    {
                                                        break;
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
                Ok(None) | Err(_) => break,
            }
        }
    }

    // Let in-flight request streams finish; `h3_server` stays alive until they are done
    // because dropping it closes the QUIC connection.
    drain_tasks(&mut stream_tasks, server_name, "H3 stream", drain_timeout).await;
    drop(h3_server);
    Ok(())
}

/// Connects outbound to the configured Relay Server via TCP + mTLS and drives
/// [`run_tunnel_over_stream`] until the control plane closes or `cancel_token` fires.
pub async fn run_tunnel(
    tunnel: TunnelConfig,
    tls_config: Arc<RustlsServerConfig>,
    dynamic_stack: Arc<ArcSwap<BoxedCloneService>>,
    cancel_token: CancellationToken,
    server_name: &'static str,
    oid_mapping: Arc<HashMap<String, UserRole>>,
    connection_tracker: Arc<ConnectionTracker>,
) -> Result<(), SrvError> {
    run_tunnel_with_timeout(
        tunnel,
        tls_config,
        dynamic_stack,
        cancel_token,
        server_name,
        oid_mapping,
        connection_tracker,
        CONNECTION_DRAIN_TIMEOUT,
    )
    .await
}

/// Like [`run_tunnel`], with an explicit `drain_timeout` for in-flight tunneled streams.
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip_all, fields(server = %server_name, sni = %tunnel.sni_domain), err)]
pub async fn run_tunnel_with_timeout(
    tunnel: TunnelConfig,
    tls_config: Arc<RustlsServerConfig>,
    dynamic_stack: Arc<ArcSwap<BoxedCloneService>>,
    cancel_token: CancellationToken,
    server_name: &'static str,
    oid_mapping: Arc<HashMap<String, UserRole>>,
    connection_tracker: Arc<ConnectionTracker>,
    drain_timeout: Duration,
) -> Result<(), SrvError> {
    let global_base: Option<Arc<[u64]>> = Config::try_global()
        .and_then(|c| c.parsed_pki_base_oid.as_deref().map(Arc::from));
    run_tunnel_with_timeout_and_base_oid(
        tunnel,
        tls_config,
        dynamic_stack,
        cancel_token,
        server_name,
        oid_mapping,
        connection_tracker,
        drain_timeout,
        global_base,
    )
    .await
}

/// Like [`run_tunnel_with_timeout`], but accepts an explicit `pki_base_oid`
/// instead of reading [`Config::try_global`].
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip_all, fields(server = %server_name, sni = %tunnel.sni_domain), err)]
pub async fn run_tunnel_with_timeout_and_base_oid(
    tunnel: TunnelConfig,
    tls_config: Arc<RustlsServerConfig>,
    dynamic_stack: Arc<ArcSwap<BoxedCloneService>>,
    cancel_token: CancellationToken,
    server_name: &'static str,
    oid_mapping: Arc<HashMap<String, UserRole>>,
    connection_tracker: Arc<ConnectionTracker>,
    drain_timeout: Duration,
    pki_base_oid: Option<Arc<[u64]>>,
) -> Result<(), SrvError> {
    let live_acceptor = Arc::new(ArcSwap::from_pointee(tokio_rustls::TlsAcceptor::from(
        tls_config,
    )));
    let live_oid_mapping = Arc::new(ArcSwap::new(oid_mapping));
    let live_pki_base_oid = Arc::new(ArcSwap::from_pointee(pki_base_oid));
    run_tunnel_with_dynamic_state(
        tunnel,
        live_acceptor,
        dynamic_stack,
        cancel_token,
        server_name,
        live_oid_mapping,
        connection_tracker,
        drain_timeout,
        live_pki_base_oid,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip_all, fields(server = %server_name, sni = %tunnel.sni_domain), err)]
async fn run_tunnel_with_dynamic_state(
    tunnel: TunnelConfig,
    live_acceptor: Arc<ArcSwap<tokio_rustls::TlsAcceptor>>,
    dynamic_stack: Arc<ArcSwap<BoxedCloneService>>,
    cancel_token: CancellationToken,
    server_name: &'static str,
    live_oid_mapping: Arc<ArcSwap<HashMap<String, UserRole>>>,
    connection_tracker: Arc<ConnectionTracker>,
    drain_timeout: Duration,
    live_pki_base_oid: Arc<ArcSwap<Option<Arc<[u64]>>>>,
) -> Result<(), SrvError> {
    let connector = build_tunnel_tls_connector(&tunnel)?;

    let parsed_url = url::Url::parse(&tunnel.target_url)
        .map_err(|e| SrvError::Other(format!("Invalid tunnel target URL: {e}")))?;
    let relay_host = parsed_url.host_str().unwrap_or("localhost");
    let relay_port = parsed_url.port().unwrap_or(7001);

    let connect_timeout = Duration::from_secs(10);
    let tcp_stream = match tokio::time::timeout(
        connect_timeout,
        TcpStream::connect((relay_host, relay_port)),
    )
    .await
    {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            return Err(SrvError::Other(format!(
                "Failed to connect to relay server at {relay_host}:{relay_port}: {e}"
            )));
        }
        Err(_) => {
            return Err(SrvError::Other(format!(
                "Connection to relay server at {relay_host}:{relay_port} timed out after 10s"
            )));
        }
    };

    let sock_ref = socket2::SockRef::from(&tcp_stream);
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(30))
        .with_interval(Duration::from_secs(10));
    let _ = sock_ref.set_tcp_keepalive(&keepalive);
    let _ = sock_ref.set_nodelay(true);

    let domain = rustls::pki_types::ServerName::try_from(relay_host.to_string())
        .map_err(|e| SrvError::Other(format!("Invalid relay server hostname '{relay_host}': {e}")))?;

    let tls_stream = match tokio::time::timeout(connect_timeout, connector.connect(domain, tcp_stream)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            return Err(SrvError::Other(format!(
                "TLS handshake with relay server at {relay_host}:{relay_port} failed: {e}"
            )));
        }
        Err(_) => {
            return Err(SrvError::Other(format!(
                "TLS handshake with relay server at {relay_host}:{relay_port} timed out after 10s"
            )));
        }
    };

    crate::stack::run_tunnel_over_stream_dynamic(
        tls_stream,
        &tunnel,
        live_acceptor,
        dynamic_stack,
        cancel_token,
        server_name,
        live_oid_mapping,
        connection_tracker,
        drain_timeout,
        live_pki_base_oid,
    )
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::UpstreamNode;
    use crate::middleware::EchoService;
    use crate::{BoxCloneSyncServiceExt, build_rustls_config};
    use std::sync::Once;

    static INIT_CRYPTO: Once = Once::new();

    fn ensure_crypto_provider() {
        INIT_CRYPTO.call_once(|| {
            let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        });
    }

    #[test]
    fn test_parse_grpc_health_score_valid_and_invalid_frames() {
        // Valid 1-byte varint score = 100 (0x64)
        assert_eq!(parse_grpc_health_score(&[0, 0, 0, 0, 2, 0x08, 100]), Some(100));
        // Valid 2-byte varint score = 300 (0xAC 0x02)
        assert_eq!(
            parse_grpc_health_score(&[0, 0, 0, 0, 3, 0x08, 0xAC, 0x02]),
            Some(300)
        );
        // Zero score parses cleanly (caller treats 0 as unhealthy)
        assert_eq!(parse_grpc_health_score(&[0, 0, 0, 0, 2, 0x08, 0]), Some(0));
        // Truncated header / payload / wrong field tag
        assert_eq!(parse_grpc_health_score(&[0, 0, 0, 0]), None);
        assert_eq!(parse_grpc_health_score(&[0, 0, 0, 0, 5, 0x08, 1]), None);
        assert_eq!(parse_grpc_health_score(&[0, 0, 0, 0, 2, 0x10, 100]), None);
        // Unterminated varint
        assert_eq!(parse_grpc_health_score(&[0, 0, 0, 0, 2, 0x08, 0x80]), None);
    }

    #[test]
    fn test_parse_rest_health_score_valid_and_invalid_json() {
        assert_eq!(parse_rest_health_score(br#"{"score": 85}"#), Some(85));
        assert_eq!(parse_rest_health_score(br#"{"score": 0}"#), Some(0));
        assert_eq!(parse_rest_health_score(br#"{"status": "ok"}"#), None);
        assert_eq!(parse_rest_health_score(br#"{"score": "100"}"#), None);
        assert_eq!(parse_rest_health_score(b"not-json"), None);
    }

    #[test]
    fn test_record_health_check_failure_transitions_and_refreshes_timestamp() {
        let node = UpstreamNode::new("http://127.0.0.1:9999".parse().unwrap());
        node.current_score
            .store(90, std::sync::atomic::Ordering::Relaxed);
        assert!(node.is_alive.load(std::sync::atomic::Ordering::Relaxed));

        let mut logged = false;
        record_health_check_failure(&node, || logged = true);
        assert!(logged);
        assert!(!node.is_alive.load(std::sync::atomic::Ordering::Relaxed));
        assert_eq!(
            node.current_score
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );

        let mut logged_second = false;
        record_health_check_failure(&node, || logged_second = true);
        assert!(!logged_second);
        assert!(
            node.last_failure_time
                .load(std::sync::atomic::Ordering::Relaxed)
                > 0
        );
    }

    #[tokio::test]
    async fn test_start_single_server_missing_static_name_exits_cleanly() {
        let mut cfg: Config = toml::from_str(
            r#"
            [[Server]]
            name = "unfinalized"
            ip = "127.0.0.1"
            port = 0
            protocol = "http"
            service = "Echo"
            enabled = true

            [Server.Layers]
            enabled = []
        "#,
        )
        .expect("valid TOML");
        let srv = Arc::new(cfg.servers.pop().unwrap());
        assert!(srv.static_name.is_none());

        let stack = Arc::new(ArcSwap::from_pointee(
            EchoService::new("unfinalized").boxed_clone_sync(),
        ));
        let token = CancellationToken::new();
        // Should return immediately without panicking.
        start_single_server(srv, token, stack).await;
    }

    #[tokio::test]
    async fn test_run_dual_stack_bind_conflict_returns_err() {
        ensure_crypto_provider();
        let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = occupied.local_addr().unwrap();

        let pki = common::test_pki::TestPki::new();
        let cert_pem = common::test_pki::TestPki::s(&pki.praeco_public_pem);
        let cert_key = common::test_pki::TestPki::s(&pki.praeco_public_key);

        let mut cfg: Config = toml::from_str(&format!(
            r#"
            [[Server]]
            name = "dual_conflict"
            ip = "127.0.0.1"
            port = 1337
            protocol = "https"
            service = "Echo"
            enabled = true

            [Server.server_certs]
            ssl_certificate = "{cert_pem}"
            ssl_certificate_key = "{cert_key}"

            [Server.Layers]
            enabled = []
        "#,
        ))
        .expect("valid TOML");
        cfg.servers[0].finalize().unwrap();

        let tls_cfg = build_rustls_config(&cfg.servers[0]).unwrap();
        let stack = Arc::new(ArcSwap::from_pointee(
            EchoService::new("dual_conflict").boxed_clone_sync(),
        ));
        let tracker = Arc::new(ConnectionTracker::new(16, 16));
        let token = CancellationToken::new();

        let res = run_dual_stack(
            addr,
            tls_cfg,
            stack,
            token.clone(),
            "dual_conflict",
            Arc::new(HashMap::new()),
            tracker,
        )
        .await;
        token.cancel();
        assert!(res.is_err(), "occupied TCP port must surface bind error");
    }

    #[tokio::test]
    async fn test_run_tunnel_invalid_url_and_unreachable_relay_return_srv_error() {
        ensure_crypto_provider();
        let pki = common::test_pki::TestPki::new();
        let pub_pem = common::test_pki::TestPki::s(&pki.praeco_public_pem);
        let pub_key = common::test_pki::TestPki::s(&pki.praeco_public_key);
        let cli_pem = common::test_pki::TestPki::s(&pki.praeco_client_pem);
        let cli_key = common::test_pki::TestPki::s(&pki.praeco_client_key);
        let ca_pem = common::test_pki::TestPki::s(&pki.public_ca_pem);
        let mut cfg: Config = toml::from_str(&format!(
            r#"
            [[Server]]
            name = "tunnel_err"
            protocol = "https"
            service = "Echo"
            enabled = true

            [Server.server_certs]
            ssl_certificate = "{pub_pem}"
            ssl_certificate_key = "{pub_key}"

            [Server.tunnel]
            target_url = "not a valid url"
            sni_domain = "wurzelwerk.api.aweirich.eu"
            client_cert_path = "{cli_pem}"
            client_key_path = "{cli_key}"
            ca_cert_path = "{ca_pem}"

            [Server.Layers]
            enabled = []
        "#,
        ))
        .expect("valid TOML");
        cfg.servers[0].finalize().unwrap();

        let tls_cfg = Arc::new(build_rustls_config(&cfg.servers[0]).unwrap());
        let stack = Arc::new(ArcSwap::from_pointee(
            EchoService::new("tunnel_err").boxed_clone_sync(),
        ));
        let tracker = Arc::new(ConnectionTracker::new(16, 16));

        // 1. Invalid URL
        let bad_tunnel = cfg.servers[0].tunnel.clone().unwrap();
        let err_url = run_tunnel(
            bad_tunnel,
            tls_cfg.clone(),
            stack.clone(),
            CancellationToken::new(),
            "tunnel_err",
            Arc::new(HashMap::new()),
            tracker.clone(),
        )
        .await
        .unwrap_err();
        assert!(err_url.to_string().contains("Invalid tunnel target URL"));

        // 2. Unreachable relay port
        let dead_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_port = dead_listener.local_addr().unwrap().port();
        drop(dead_listener);

        let mut unreachable_tunnel = cfg.servers[0].tunnel.clone().unwrap();
        unreachable_tunnel.target_url = format!("https://127.0.0.1:{dead_port}");
        let err_conn = run_tunnel(
            unreachable_tunnel,
            tls_cfg,
            stack,
            CancellationToken::new(),
            "tunnel_err",
            Arc::new(HashMap::new()),
            tracker,
        )
        .await
        .unwrap_err();
        assert!(
            err_conn
                .to_string()
                .contains("Failed to connect to relay server")
        );
    }

    #[tokio::test]
    async fn test_spawn_router_health_checks_no_router_params_is_noop() {
        let mut cfg: Config = toml::from_str(
            r#"
            [[Server]]
            name = "echo_only"
            ip = "127.0.0.1"
            port = 0
            protocol = "http"
            service = "Echo"
            enabled = true

            [Server.Layers]
            enabled = []
        "#,
        )
        .expect("valid TOML");
        cfg.servers[0].finalize().unwrap();
        let srv = Arc::new(cfg.servers.pop().unwrap());
        let token = CancellationToken::new();
        spawn_router_health_checks(&srv, token.clone());
        token.cancel();
    }

    /// Picks a loopback address whose port is currently free on TCP and UDP.
    async fn reserve_dual_stack_addr() -> SocketAddr {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = tcp.local_addr().unwrap();
        let udp = std::net::UdpSocket::bind(addr).unwrap();
        drop(udp);
        drop(tcp);
        addr
    }

    /// Builds a finalized HTTPS Echo server config bound to `127.0.0.1:{port}`.
    fn echo_https_server(
        pki: &common::test_pki::TestPki,
        name: &str,
        port: u16,
    ) -> Arc<ServerConfig> {
        let cert_pem = common::test_pki::TestPki::s(&pki.praeco_public_pem);
        let cert_key = common::test_pki::TestPki::s(&pki.praeco_public_key);
        let mut cfg: Config = toml::from_str(&format!(
            r#"
            [[Server]]
            name = "{name}"
            ip = "127.0.0.1"
            port = {port}
            protocol = "https"
            service = "Echo"
            enabled = true

            [Server.server_certs]
            ssl_certificate = "{cert_pem}"
            ssl_certificate_key = "{cert_key}"

            [Server.Layers]
            enabled = []
        "#
        ))
        .expect("valid TOML");
        cfg.servers[0].finalize().unwrap();
        Arc::new(cfg.servers.pop().unwrap())
    }

    /// Waits (briefly) until the UDP socket of a closed QUIC endpoint is released.
    ///
    /// The endpoint driver task releases the socket asynchronously after the endpoint
    /// was dropped, so a short poll avoids a flaky immediate re-bind.
    async fn assert_udp_released(addr: SocketAddr) {
        for _ in 0..40 {
            if std::net::UdpSocket::bind(addr).is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        panic!("UDP port {addr} was not released");
    }

    #[tokio::test]
    async fn test_spawn_dual_stack_partial_bind_failure_leaks_no_listener() {
        ensure_crypto_provider();
        let pki = common::test_pki::TestPki::new();
        let addr = reserve_dual_stack_addr().await;
        // Occupy only the UDP side: the TCP bind succeeds first, the QUIC bind then fails.
        let _udp_blocker = std::net::UdpSocket::bind(addr).unwrap();

        let srv = echo_https_server(&pki, "dual_partial", addr.port());
        let tls_cfg = build_rustls_config(&srv).unwrap();
        let stack = Arc::new(ArcSwap::from_pointee(
            EchoService::new("dual_partial").boxed_clone_sync(),
        ));
        let token = CancellationToken::new();

        let res = spawn_dual_stack(
            addr,
            tls_cfg,
            stack,
            token.clone(),
            "dual_partial",
            Arc::new(HashMap::new()),
            Arc::new(ConnectionTracker::new(16, 16)),
        )
        .await;
        assert!(res.is_err(), "occupied UDP port must surface a bind error");

        // The TCP listener must not be left behind in a detached accept loop.
        TcpListener::bind(addr)
            .await
            .expect("TCP port must be released after a failed dual-stack start");
        token.cancel();
    }

    #[tokio::test]
    async fn test_start_single_server_https_returns_only_after_sockets_released() {
        ensure_crypto_provider();
        let pki = common::test_pki::TestPki::new();
        let addr = reserve_dual_stack_addr().await;
        let srv = echo_https_server(&pki, "graceful_https", addr.port());
        let stack = Arc::new(ArcSwap::from_pointee(
            EchoService::new("graceful_https").boxed_clone_sync(),
        ));
        let token = CancellationToken::new();

        let server = tokio::spawn(start_single_server(srv, token.clone(), stack));
        tokio::time::sleep(Duration::from_millis(200)).await;
        token.cancel();

        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("start_single_server must return after cancellation")
            .expect("server task must not panic");

        // Returning means the listeners are gone: the addresses can be re-bound right away.
        TcpListener::bind(addr)
            .await
            .expect("TCP port must be free once start_single_server returned");
        assert_udp_released(addr).await;
    }

    #[test]
    fn test_graceful_shutdown_timeout_configuration_parses_and_defaults() {
        let mut cfg: Config = toml::from_str(
            r#"
            [[Server]]
            name = "default_drain"
            ip = "127.0.0.1"
            port = 8080
            protocol = "http"
            service = "Echo"

            [Server.Layers]
            enabled = []

            [[Server]]
            name = "custom_drain"
            ip = "127.0.0.1"
            port = 8081
            protocol = "http"
            service = "Echo"
            graceful_shutdown_timeout_seconds = 3

            [Server.Layers]
            enabled = []
        "#,
        )
        .expect("valid TOML");
        for srv in &mut cfg.servers {
            srv.finalize().unwrap();
        }
        assert_eq!(cfg.servers[0].graceful_shutdown_timeout_seconds, 10);
        assert_eq!(cfg.servers[0].drain_timeout(), Duration::from_secs(10));
        assert_eq!(cfg.servers[1].graceful_shutdown_timeout_seconds, 3);
        assert_eq!(cfg.servers[1].drain_timeout(), Duration::from_secs(3));
    }

    #[tokio::test]
    async fn test_http_server_drains_inflight_request_while_releasing_socket_early() {
        use bytes::Bytes;
        use http_body_util::{BodyExt, Empty, Full};
        use hyper_util::rt::TokioIo;
        use tower::Service;

        #[derive(Clone)]
        struct SlowEchoService;

        impl Service<Request<crate::SrvBody>> for SlowEchoService {
            type Response = Response<crate::ServiceRespBody>;
            type Error = SrvError;
            type Future = std::pin::Pin<
                Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
            >;

            fn poll_ready(
                &mut self,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Result<(), Self::Error>> {
                std::task::Poll::Ready(Ok(()))
            }

            fn call(&mut self, _req: Request<crate::SrvBody>) -> Self::Future {
                Box::pin(async move {
                    tokio::time::sleep(Duration::from_millis(300)).await;
                    Ok(Response::builder()
                        .status(StatusCode::OK)
                        .body(
                            Full::new(Bytes::from_static(b"slow-ok"))
                                .map_err(SrvError::from)
                                .boxed(),
                        )
                        .unwrap())
                })
            }
        }

        let probe = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = probe.local_addr().unwrap();
        drop(probe);

        let mut cfg: Config = toml::from_str(&format!(
            r#"
            [[Server]]
            name = "slow_drain"
            ip = "127.0.0.1"
            port = {}
            protocol = "http"
            service = "Echo"
            graceful_shutdown_timeout_seconds = 3

            [Server.Layers]
            enabled = []
        "#,
            addr.port()
        ))
        .expect("valid TOML");
        cfg.servers[0].finalize().unwrap();
        let srv = Arc::new(cfg.servers.pop().unwrap());
        let stack = Arc::new(ArcSwap::from_pointee(SlowEchoService.boxed_clone_sync()));
        let token = CancellationToken::new();
        let (released_tx, released_rx) = oneshot::channel();

        let server_handle = tokio::spawn(start_single_server_with_socket_signal(
            srv,
            token.clone(),
            stack,
            Some(released_tx),
        ));

        let stream = {
            let mut attempts = 0u32;
            loop {
                match TcpStream::connect(addr).await {
                    Ok(s) => break s,
                    Err(e) if attempts < 50 => {
                        attempts += 1;
                        tokio::time::sleep(Duration::from_millis(10)).await;
                        let _ = e;
                    }
                    Err(e) => panic!("failed to connect to test HTTP server at {addr}: {e}"),
                }
            }
        };

        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let req = Request::builder()
            .method(hyper::Method::GET)
            .uri("/slow")
            .header("host", addr.to_string())
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp_fut = tokio::spawn(async move { sender.send_request(req).await });

        // Give the server a moment to accept and enter the 300ms handler.
        tokio::time::sleep(Duration::from_millis(50)).await;
        token.cancel();

        // 1. Listening socket is released immediately (before the 300ms request finishes).
        tokio::time::timeout(Duration::from_millis(150), released_rx)
            .await
            .expect("listening socket should be released before slow request finishes")
            .expect("socket release signal must fire");
        let rebound = TcpListener::bind(addr)
            .await
            .expect("port must be re-bindable while old HTTP connections drain");
        drop(rebound);

        // 2. Server task must NOT have returned yet because the in-flight request is still draining.
        assert!(
            !server_handle.is_finished(),
            "server must wait for in-flight request drain before returning"
        );

        // 3. In-flight request completes with 200 OK and body.
        let resp = resp_fut.await.unwrap().expect("in-flight request must succeed");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], b"slow-ok");

        // 4. Server exits cleanly once drain completes.
        tokio::time::timeout(Duration::from_secs(2), server_handle)
            .await
            .expect("server must exit right after in-flight request completes")
            .expect("server task must not panic");
    }
}
