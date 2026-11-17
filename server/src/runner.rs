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
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, trace, warn};

use crate::{
    BoxedCloneService, ConnectionHandler, H3Body, SrvError,
    configuration::{
        AuthenticationMethod, CachedDescriptorPool, Config, Protocol, RouteBackendType,
        ServerConfig, ServiceType, TunnelConfig, UserRole, RoleVec,
    },
    connection_tracker::{AcquireError, ConnectionTracker},
    middleware::router::build_grpc_pool,
    stack::{
        build_rustls_config, build_service_stack, build_tunnel_tls_connector,
        run_tunnel_over_stream, serve_http_connection, serve_tls_connection,
    },
    tls_conf::extract_client_metadata,
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

/// Starts a single server instance (HTTP, HTTPS/H3 dual-stack, or outbound Relay tunnel)
/// based on the provided configuration.
///
/// # Architecture & Lifecycle
///
/// 1. **Active Health Checks**: For [`ServiceType::Router`], spawns background loops
///    for every upstream with `active_health_check_interval > 0`.
/// 2. **Tunnel or Listener Dispatch**:
///    - If `server_config.tunnel` is set, connects outbound via mTLS + Yamux with
///      exponential backoff on disconnects.
///    - For [`Protocol::Https`], starts dual-stack TCP (HTTP/1.1 + HTTP/2) and UDP
///      (HTTP/3 over QUIC) listeners via [`run_dual_stack`].
///    - For [`Protocol::Http`], starts a plaintext TCP listener.
pub async fn start_single_server(
    server_config: Arc<ServerConfig>,
    cancel_token: CancellationToken,
    dynamic_stack: Arc<ArcSwap<BoxedCloneService>>,
) {
    if server_config.service == ServiceType::Router {
        spawn_router_health_checks(&server_config, cancel_token.clone());
    }

    let Some(static_name) = server_config.static_name else {
        error!(
            "{}: Missing static_name (ensure ServerConfig::finalize was called)",
            server_config.name
        );
        return;
    };

    let oid_mapping = Arc::new(server_config.oid_mapping.clone());
    let connection_tracker = Arc::new(ConnectionTracker::with_server_name(
        server_config.connection_limits.max_connections,
        server_config.connection_limits.max_connections_per_ip,
        &server_config.name,
    ));

    if let Some(tunnel) = &server_config.tunnel {
        info!(
            "{}: Connecting to Zero-Trust Tunnel at {}",
            server_config.name, tunnel.target_url
        );
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
                static_name,
                oid_mapping.clone(),
                connection_tracker.clone(),
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
                            let svc = (**dynamic_stack.load()).clone();
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

/// Spawns background active health-checker loops for upstream router targets.
///
/// Evaluates all `parsed_routes` in `server_config`. For any backend marked with a
/// non-zero `active_health_check_interval`, this provisions keep-alive Hyper clients
/// (HTTP/2-only for gRPC, standard for REST) and spawns periodic probes.
pub fn spawn_router_health_checks(
    server_config: &Arc<ServerConfig>,
    cancel_token: CancellationToken,
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

            tokio::spawn(async move {
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

/// Runs a dual-stack HTTPS server supporting both TCP (HTTP/1.1, HTTP/2) and UDP (HTTP/3 over QUIC)
/// on the same socket address.
pub async fn run_dual_stack(
    server_addr: SocketAddr,
    tls_config: RustlsServerConfig,
    dynamic_stack: Arc<ArcSwap<BoxedCloneService>>,
    cancel_token: CancellationToken,
    server_name: &'static str,
    oid_mapping: Arc<HashMap<String, UserRole>>,
    connection_tracker: Arc<ConnectionTracker>,
) -> Result<(), SrvError> {
    let arc_tls_config = Arc::new(tls_config);

    let tcp_cancel_token = cancel_token.clone();
    let udp_cancel_token = cancel_token;

    let tcp_handle = run_tcp_listener(
        server_addr,
        arc_tls_config.clone(),
        dynamic_stack.clone(),
        tcp_cancel_token,
        server_name,
        oid_mapping.clone(),
        connection_tracker.clone(),
    );

    let udp_handle = run_udp_listener(
        server_addr,
        arc_tls_config,
        dynamic_stack,
        udp_cancel_token,
        server_name,
        oid_mapping,
        connection_tracker,
    );

    let (tcp_res, udp_res) = tokio::join!(tcp_handle, udp_handle);
    tcp_res?;
    udp_res?;
    Ok(())
}

/// Runs the TCP listener for HTTPS traffic (HTTP/1.1 and HTTP/2).
async fn run_tcp_listener(
    server_addr: SocketAddr,
    tls_config: Arc<RustlsServerConfig>,
    dynamic_stack: Arc<ArcSwap<BoxedCloneService>>,
    cancel_token: CancellationToken,
    server_name: &'static str,
    oid_mapping: Arc<HashMap<String, UserRole>>,
    connection_tracker: Arc<ConnectionTracker>,
) -> Result<(), SrvError> {
    let tcp_listener = TcpListener::bind(server_addr)
        .await
        .map_err(|e| SrvError::Other(format!("TCP bind failed on {server_addr}: {e}")))?;
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

/// Runs the UDP listener for HTTP/3 traffic using QUIC (`quinn` and `h3`).
async fn run_udp_listener(
    server_addr: SocketAddr,
    tls_config: Arc<RustlsServerConfig>,
    dynamic_stack: Arc<ArcSwap<BoxedCloneService>>,
    cancel_token: CancellationToken,
    server_name: &'static str,
    oid_mapping: Arc<HashMap<String, UserRole>>,
    connection_tracker: Arc<ConnectionTracker>,
) -> Result<(), SrvError> {
    let mut quic_tls_models = rustls::ServerConfig::clone(&tls_config);
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

    let endpoint = quinn::Endpoint::server(quinn_server_config, server_addr)
        .map_err(|e| SrvError::Other(format!("QUIC UDP bind failed on {server_addr}: {e}")))?;

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = cancel_token.cancelled() => break,
                res = endpoint.accept() => {
                    if let Some(conn) = res {
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
                        break;
                    }
                }
            }
        }
        endpoint.close(0u32.into(), b"shutdown");
    });

    Ok(())
}

/// Handles a single HTTP/3 (QUIC) connection and dispatches its request streams through [`ConnectionHandler`].
async fn handle_h3_connection(
    connecting: quinn::Incoming,
    dynamic_stack: Arc<ArcSwap<BoxedCloneService>>,
    #[allow(unused_variables)] server_name: &str,
    oid_mapping: Arc<HashMap<String, UserRole>>,
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
        extract_client_metadata(client_certs)
    };
    let oids = client_meta.oids;
    let client_cert_pem = client_meta.pem;
    let client_cert_san = client_meta.san;

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

    let shared_roles = Arc::new(roles);
    let shared_oids = Arc::new(oids);

    let h3_conn = h3_quinn::Connection::new(connection);
    let mut h3_server: h3::server::Connection<h3_quinn::Connection, bytes::Bytes> =
        h3::server::Connection::new(h3_conn).await?;

    let base_svc = (**dynamic_stack.load()).clone();
    let stream_semaphore = Arc::new(tokio::sync::Semaphore::new(128));

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
                let svc = base_svc.clone();
                let roles_for_req = shared_roles.clone();
                let shared_oids_for_req = shared_oids.clone();
                let req_cert_pem = client_cert_pem.clone();
                let req_cert_san = client_cert_san.clone();

                tokio::spawn(async move {
                    let _permit = permit;
                    match resolver.resolve_request().await {
                        Ok((req, stream)) => {
                            let (mut sender, receiver) = stream.split();

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
            Ok(None) => break,
            Err(_e) => break,
        }
    }
    Ok(())
}

/// Connects outbound to the configured Relay Server via TCP + mTLS and drives
/// [`run_tunnel_over_stream`] until the control plane closes or `cancel_token` fires.
#[tracing::instrument(skip_all, fields(server = %server_name, sni = %tunnel.sni_domain), err)]
pub async fn run_tunnel(
    tunnel: TunnelConfig,
    tls_config: Arc<RustlsServerConfig>,
    dynamic_stack: Arc<ArcSwap<BoxedCloneService>>,
    cancel_token: CancellationToken,
    server_name: &'static str,
    oid_mapping: Arc<HashMap<String, UserRole>>,
    connection_tracker: Arc<ConnectionTracker>,
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

        let mut cfg: Config = toml::from_str(
            r#"
            [[Server]]
            name = "dual_conflict"
            ip = "127.0.0.1"
            port = 1337
            protocol = "https"
            service = "Echo"
            enabled = true

            [Server.server_certs]
            ssl_certificate = "../server_certs/self_signed/praeco_public.pem"
            ssl_certificate_key = "../server_certs/self_signed/praeco_public.key"

            [Server.Layers]
            enabled = []
        "#,
        )
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
        let mut cfg: Config = toml::from_str(
            r#"
            [[Server]]
            name = "tunnel_err"
            protocol = "https"
            service = "Echo"
            enabled = true

            [Server.server_certs]
            ssl_certificate = "../server_certs/self_signed/praeco_public.pem"
            ssl_certificate_key = "../server_certs/self_signed/praeco_public.key"

            [Server.tunnel]
            target_url = "not a valid url"
            sni_domain = "wurzelwerk.api.aweirich.eu"
            client_cert_path = "../server_certs/self_signed/praeco_client.pem"
            client_key_path = "../server_certs/self_signed/praeco_client.key"
            ca_cert_path = "../server_certs/self_signed/public_ca.pem"

            [Server.Layers]
            enabled = []
        "#,
        )
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
}
