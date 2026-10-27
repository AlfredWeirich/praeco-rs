//! # Admin & Telemetry Service (`ServiceType::Admin` & `RouteBackendType::Admin`)
//!
//! Provides a generic, application-agnostic administrative and observability endpoint
//! for `praeco-rs` inspired by Traefik's `api@internal` and Envoy's admin interface.
//!
//! Can be mounted in two ways:
//! 1. **Standalone Server (`service = "Admin"`)**: Dedicated local/internal port (e.g. `127.0.0.1:9090`)
//!    for Prometheus scraping (`/metrics`), health probes (`/healthz`), and JSON status (`/status`).
//! 2. **Internal Router Backend (`backend_type = "admin"`)**: Mounted under any custom path prefix
//!    (e.g. `[Server.ReverseRoutes."/api/GetPraecoStatus"]`) inside an existing `ServiceType::Router`
//!    instance, inheriting that server's TLS/SNI tunnel, JWT/mTLS authentication, and RBAC rules.

use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, OnceLock},
    task::{Context, Poll},
    time::{Instant, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{HeaderMap, Method, Request, Response, StatusCode, Uri, header};
use serde::Serialize;
use tower::Service;

use crate::{
    ServiceRespBody, SrvBody, SrvError,
    configuration::{Config, RouteBackendType, ServerConfig},
    middleware::router::circuit_breaker::CircuitState,
};

static PROCESS_START: OnceLock<Instant> = OnceLock::new();

/// Initializes the process start timestamp for uptime reporting.
pub fn init_process_start_time() {
    let _ = PROCESS_START.set(Instant::now());
}

fn uptime_seconds() -> u64 {
    PROCESS_START
        .get_or_init(Instant::now)
        .elapsed()
        .as_secs()
}

/// Top-level JSON status response returned by the Admin endpoint.
#[derive(Debug, Clone, Serialize)]
pub struct AdminStatusResponse {
    pub status: &'static str,
    pub uptime_seconds: u64,
    pub timestamp_unix: u64,
    pub summary: AdminSummary,
    pub servers: Vec<AdminServerStatus>,
}

/// Aggregated health, traffic, security & circuit-breaker counters across all configured servers.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AdminSummary {
    pub total_servers: usize,
    pub total_routes: usize,
    pub total_upstreams: usize,
    pub healthy_upstreams: usize,
    pub open_circuits: usize,
    pub half_open_circuits: usize,
    pub active_connections: usize,
    pub total_requests: u64,
    pub total_upstream_requests: u64,
    pub total_upstream_failures: u64,
    pub total_circuit_trips: u64,
    pub total_failover_retries: u64,
    pub total_blocked_requests: u64,
    pub revoked_jwt_tokens: usize,
}

/// Per-server edge traffic & security/WAF block counters (Package 2).
#[derive(Debug, Clone, Default, Serialize)]
pub struct AdminServerTrafficSecurity {
    pub total_requests: u64,
    pub blocked_ip_filter: u64,
    pub blocked_inspection: u64,
    pub blocked_auth_rbac: u64,
    pub rate_limited: u64,
}

/// Per-server PKI, TLS leaf certificate & mTLS CRL expiration status (Package 3).
#[derive(Debug, Clone, Default, Serialize)]
pub struct AdminServerPkiStatus {
    pub server_cert_valid_until_unix: Option<i64>,
    pub server_cert_days_remaining: Option<i64>,
    pub crl_next_update_unix: Option<i64>,
    pub crl_expired: Option<bool>,
    pub crl_revoked_certs_count: usize,
}

/// Per-server configuration and runtime routing status.
#[derive(Debug, Clone, Serialize)]
pub struct AdminServerStatus {
    pub name: String,
    pub protocol: String,
    pub service: String,
    pub authentication: String,
    pub listen: String,
    pub enabled_layers: Vec<String>,
    pub traffic_and_security: AdminServerTrafficSecurity,
    pub pki: AdminServerPkiStatus,
    pub routes: Vec<AdminRouteStatus>,
}

/// Per-route load-balancing and circuit-breaker configuration + upstream states.
#[derive(Debug, Clone, Serialize)]
pub struct AdminRouteStatus {
    pub prefix: String,
    pub backend_type: String,
    pub strategy: String,
    pub cooldown_seconds: u64,
    pub max_retries: usize,
    pub failure_threshold: usize,
    pub max_retry_buffer_bytes: usize,
    pub active_health_check_interval: u64,
    pub failover_retries: u64,
    pub upstreams: Vec<AdminUpstreamStatus>,
}

/// Live atomic state and telemetry of a single upstream backend node (Package 1).
#[derive(Debug, Clone, Serialize)]
pub struct AdminUpstreamStatus {
    pub uri: String,
    pub circuit_state: &'static str,
    pub is_alive: bool,
    pub is_available: bool,
    pub active_connections: usize,
    pub total_requests: u64,
    pub total_failures: u64,
    pub circuit_trips: u64,
    pub failover_retries: u64,
    pub last_response_ms: u64,
    pub ema_response_ms: u64,
    pub consecutive_failures: usize,
    pub last_failure_time: u64,
    pub cooldown_remaining_secs: u64,
    pub half_open_probe_in_flight: bool,
    pub health_score: usize,
}

/// Collects a lock-free snapshot of all enabled servers, routes, and upstream circuit breakers.
pub fn collect_admin_status(fallback_server: Option<&ServerConfig>) -> AdminStatusResponse {
    let now_unix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let now_unix_i64 = now_unix as i64;

    let global_cfg = Config::try_global();
    let servers_slice: Vec<ServerConfig> = if let Some(ref cfg) = global_cfg {
        cfg.servers
            .iter()
            .filter(|s| s.enabled)
            .cloned()
            .collect()
    } else if let Some(srv) = fallback_server {
        vec![srv.clone()]
    } else {
        Vec::new()
    };

    let revoked_jwt_tokens = crate::middleware::jwt::get_jwt_revocation_store().len();

    let mut summary = AdminSummary {
        total_servers: servers_slice.len(),
        revoked_jwt_tokens,
        ..Default::default()
    };
    let mut servers = Vec::with_capacity(servers_slice.len());

    for srv in &servers_slice {
        let listen = if let Some(ref tunnel) = srv.tunnel {
            format!("tunnel://{} ({})", tunnel.sni_domain, tunnel.target_url)
        } else {
            format!(
                "{}:{}",
                srv.ip.as_deref().unwrap_or("0.0.0.0"),
                srv.port.unwrap_or(0)
            )
        };

        // Package 2: Per-server edge traffic & security counters
        let srv_metrics = crate::configuration::ServerMetrics::for_server(&srv.name);
        let srv_total_reqs = srv_metrics
            .total_requests
            .load(std::sync::atomic::Ordering::Relaxed);
        let srv_blocked_ip = srv_metrics
            .blocked_ip_filter
            .load(std::sync::atomic::Ordering::Relaxed);
        let srv_blocked_insp = srv_metrics
            .blocked_inspection
            .load(std::sync::atomic::Ordering::Relaxed);
        let srv_blocked_auth = srv_metrics
            .blocked_auth_rbac
            .load(std::sync::atomic::Ordering::Relaxed);
        let srv_rate_limited = srv_metrics
            .rate_limited
            .load(std::sync::atomic::Ordering::Relaxed);

        summary.total_requests += srv_total_reqs;
        summary.total_blocked_requests +=
            srv_blocked_ip + srv_blocked_insp + srv_blocked_auth + srv_rate_limited;

        let traffic_and_security = AdminServerTrafficSecurity {
            total_requests: srv_total_reqs,
            blocked_ip_filter: srv_blocked_ip,
            blocked_inspection: srv_blocked_insp,
            blocked_auth_rbac: srv_blocked_auth,
            rate_limited: srv_rate_limited,
        };

        // Package 3: PKI / Certificate & CRL expiration monitoring
        let server_cert_days_remaining = srv
            .pki_info
            .server_cert_valid_until_unix
            .map(|exp| (exp - now_unix_i64) / 86_400);
        let crl_expired = srv
            .pki_info
            .crl_next_update_unix
            .map(|next_upd| now_unix_i64 > next_upd);

        let pki = AdminServerPkiStatus {
            server_cert_valid_until_unix: srv.pki_info.server_cert_valid_until_unix,
            server_cert_days_remaining,
            crl_next_update_unix: srv.pki_info.crl_next_update_unix,
            crl_expired,
            crl_revoked_certs_count: srv.pki_info.crl_revoked_certs_count,
        };

        let mut routes = Vec::new();
        for route in &srv.parsed_routes {
            // Skip internal admin self-routes in upstream health counts
            if route.backend_type == RouteBackendType::Admin {
                continue;
            }
            summary.total_routes += 1;

            let cooldown = route.target.cooldown_seconds;
            let mut upstreams = Vec::with_capacity(route.target.upstreams.len());
            let mut route_failover_retries = 0u64;

            for node in &route.target.upstreams {
                summary.total_upstreams += 1;

                let state = node.circuit_state();
                let is_alive = node.is_alive.load(std::sync::atomic::Ordering::Acquire);
                let is_available = node.is_available(cooldown);
                let active_conn = node
                    .active_connections
                    .load(std::sync::atomic::Ordering::Relaxed);
                let total_reqs = node
                    .total_requests
                    .load(std::sync::atomic::Ordering::Relaxed);
                let total_fails = node
                    .total_failures
                    .load(std::sync::atomic::Ordering::Relaxed);
                let circuit_trips = node
                    .circuit_trips
                    .load(std::sync::atomic::Ordering::Relaxed);
                let node_failover_retries = node
                    .failover_retries
                    .load(std::sync::atomic::Ordering::Relaxed);
                let last_response_ms = node
                    .last_response_ms
                    .load(std::sync::atomic::Ordering::Relaxed);
                let ema_response_ms = node
                    .ema_response_ms
                    .load(std::sync::atomic::Ordering::Relaxed);
                let consecutive_failures = node
                    .consecutive_failures
                    .load(std::sync::atomic::Ordering::Relaxed);
                let last_failure_time = node
                    .last_failure_time
                    .load(std::sync::atomic::Ordering::Acquire);
                let half_open_probe = node
                    .half_open_probe_in_flight
                    .load(std::sync::atomic::Ordering::Acquire);
                let health_score = node
                    .current_score
                    .load(std::sync::atomic::Ordering::Relaxed);

                let cooldown_remaining_secs = if !is_alive && last_failure_time > 0 {
                    (last_failure_time + cooldown).saturating_sub(now_unix)
                } else {
                    0
                };

                let state_str = match state {
                    CircuitState::Closed => {
                        summary.healthy_upstreams += 1;
                        "Closed"
                    }
                    CircuitState::Open => {
                        summary.open_circuits += 1;
                        "Open"
                    }
                    CircuitState::HalfOpen => {
                        summary.half_open_circuits += 1;
                        "HalfOpen"
                    }
                };
                summary.active_connections += active_conn;
                summary.total_upstream_requests += total_reqs;
                summary.total_upstream_failures += total_fails;
                summary.total_circuit_trips += circuit_trips;
                summary.total_failover_retries += node_failover_retries;
                route_failover_retries += node_failover_retries;

                upstreams.push(AdminUpstreamStatus {
                    uri: node.uri.to_string(),
                    circuit_state: state_str,
                    is_alive,
                    is_available,
                    active_connections: active_conn,
                    total_requests: total_reqs,
                    total_failures: total_fails,
                    circuit_trips,
                    failover_retries: node_failover_retries,
                    last_response_ms,
                    ema_response_ms,
                    consecutive_failures,
                    last_failure_time,
                    cooldown_remaining_secs,
                    half_open_probe_in_flight: half_open_probe,
                    health_score,
                });
            }

            routes.push(AdminRouteStatus {
                prefix: route.prefix.clone(),
                backend_type: format!("{:?}", route.backend_type),
                strategy: format!("{:?}", route.target.strategy),
                cooldown_seconds: cooldown,
                max_retries: route.target.max_retries,
                failure_threshold: route.target.failure_threshold,
                max_retry_buffer_bytes: route.target.max_retry_buffer_bytes,
                active_health_check_interval: route.target.active_health_check_interval,
                failover_retries: route_failover_retries,
                upstreams,
            });
        }

        servers.push(AdminServerStatus {
            name: srv.name.clone(),
            protocol: format!("{:?}", srv.protocol),
            service: format!("{:?}", srv.service),
            authentication: format!("{:?}", srv.authentication),
            listen,
            enabled_layers: srv.layers.enabled.clone(),
            traffic_and_security,
            pki,
            routes,
        });
    }

    AdminStatusResponse {
        status: "ok",
        uptime_seconds: uptime_seconds(),
        timestamp_unix: now_unix,
        summary,
        servers,
    }
}

/// Formats the current [`AdminStatusResponse`] into Prometheus / OpenMetrics text exposition format.
pub fn format_prometheus_metrics(status: &AdminStatusResponse) -> String {
    let mut out = String::with_capacity(4096);
    out.push_str("# HELP praeco_uptime_seconds Process uptime in seconds.\n");
    out.push_str("# TYPE praeco_uptime_seconds gauge\n");
    out.push_str(&format!("praeco_uptime_seconds {}\n\n", status.uptime_seconds));

    out.push_str("# HELP praeco_revoked_jwt_tokens Number of active revoked JWT tokens in the denylist.\n");
    out.push_str("# TYPE praeco_revoked_jwt_tokens gauge\n");
    out.push_str(&format!(
        "praeco_revoked_jwt_tokens {}\n\n",
        status.summary.revoked_jwt_tokens
    ));

    out.push_str("# HELP praeco_server_requests_total Total incoming HTTP/gRPC requests per server.\n");
    out.push_str("# TYPE praeco_server_requests_total counter\n");
    for srv in &status.servers {
        out.push_str(&format!(
            "praeco_server_requests_total{{server=\"{}\"}} {}\n",
            srv.name, srv.traffic_and_security.total_requests
        ));
    }
    out.push('\n');

    out.push_str("# HELP praeco_server_blocked_requests_total Blocked requests per server by security layer.\n");
    out.push_str("# TYPE praeco_server_blocked_requests_total counter\n");
    for srv in &status.servers {
        out.push_str(&format!(
            "praeco_server_blocked_requests_total{{server=\"{}\",reason=\"ip_filter\"}} {}\n",
            srv.name, srv.traffic_and_security.blocked_ip_filter
        ));
        out.push_str(&format!(
            "praeco_server_blocked_requests_total{{server=\"{}\",reason=\"inspection\"}} {}\n",
            srv.name, srv.traffic_and_security.blocked_inspection
        ));
        out.push_str(&format!(
            "praeco_server_blocked_requests_total{{server=\"{}\",reason=\"auth_rbac\"}} {}\n",
            srv.name, srv.traffic_and_security.blocked_auth_rbac
        ));
        out.push_str(&format!(
            "praeco_server_blocked_requests_total{{server=\"{}\",reason=\"rate_limited\"}} {}\n",
            srv.name, srv.traffic_and_security.rate_limited
        ));
    }
    out.push('\n');

    out.push_str("# HELP praeco_server_cert_days_remaining Days remaining until the server TLS certificate expires.\n");
    out.push_str("# TYPE praeco_server_cert_days_remaining gauge\n");
    for srv in &status.servers {
        if let Some(days) = srv.pki.server_cert_days_remaining {
            out.push_str(&format!(
                "praeco_server_cert_days_remaining{{server=\"{}\"}} {}\n",
                srv.name, days
            ));
        }
    }
    out.push('\n');

    out.push_str("# HELP praeco_upstream_circuit_state Circuit breaker state per upstream (0=Closed, 1=Open, 2=HalfOpen).\n");
    out.push_str("# TYPE praeco_upstream_circuit_state gauge\n");
    for srv in &status.servers {
        for route in &srv.routes {
            for up in &route.upstreams {
                let state_num = match up.circuit_state {
                    "Closed" => 0,
                    "Open" => 1,
                    "HalfOpen" => 2,
                    _ => 0,
                };
                out.push_str(&format!(
                    "praeco_upstream_circuit_state{{server=\"{}\",route=\"{}\",upstream=\"{}\"}} {}\n",
                    srv.name, route.prefix, up.uri, state_num
                ));
            }
        }
    }
    out.push('\n');

    out.push_str("# HELP praeco_upstream_alive Whether the upstream node is marked alive (1=alive, 0=dead).\n");
    out.push_str("# TYPE praeco_upstream_alive gauge\n");
    for srv in &status.servers {
        for route in &srv.routes {
            for up in &route.upstreams {
                out.push_str(&format!(
                    "praeco_upstream_alive{{server=\"{}\",route=\"{}\",upstream=\"{}\"}} {}\n",
                    srv.name,
                    route.prefix,
                    up.uri,
                    if up.is_alive { 1 } else { 0 }
                ));
            }
        }
    }
    out.push('\n');

    out.push_str("# HELP praeco_upstream_active_connections Active in-flight requests to the upstream node.\n");
    out.push_str("# TYPE praeco_upstream_active_connections gauge\n");
    for srv in &status.servers {
        for route in &srv.routes {
            for up in &route.upstreams {
                out.push_str(&format!(
                    "praeco_upstream_active_connections{{server=\"{}\",route=\"{}\",upstream=\"{}\"}} {}\n",
                    srv.name, route.prefix, up.uri, up.active_connections
                ));
            }
        }
    }
    out.push('\n');

    out.push_str("# HELP praeco_upstream_requests_total Total requests dispatched to the upstream node.\n");
    out.push_str("# TYPE praeco_upstream_requests_total counter\n");
    for srv in &status.servers {
        for route in &srv.routes {
            for up in &route.upstreams {
                out.push_str(&format!(
                    "praeco_upstream_requests_total{{server=\"{}\",route=\"{}\",upstream=\"{}\"}} {}\n",
                    srv.name, route.prefix, up.uri, up.total_requests
                ));
            }
        }
    }
    out.push('\n');

    out.push_str("# HELP praeco_upstream_failures_total Total failures observed on the upstream node.\n");
    out.push_str("# TYPE praeco_upstream_failures_total counter\n");
    for srv in &status.servers {
        for route in &srv.routes {
            for up in &route.upstreams {
                out.push_str(&format!(
                    "praeco_upstream_failures_total{{server=\"{}\",route=\"{}\",upstream=\"{}\"}} {}\n",
                    srv.name, route.prefix, up.uri, up.total_failures
                ));
            }
        }
    }
    out.push('\n');

    out.push_str("# HELP praeco_upstream_circuit_trips_total Total times the upstream circuit breaker tripped to OPEN.\n");
    out.push_str("# TYPE praeco_upstream_circuit_trips_total counter\n");
    for srv in &status.servers {
        for route in &srv.routes {
            for up in &route.upstreams {
                out.push_str(&format!(
                    "praeco_upstream_circuit_trips_total{{server=\"{}\",route=\"{}\",upstream=\"{}\"}} {}\n",
                    srv.name, route.prefix, up.uri, up.circuit_trips
                ));
            }
        }
    }
    out.push('\n');

    out.push_str("# HELP praeco_upstream_ema_response_ms Exponential moving average response latency in milliseconds.\n");
    out.push_str("# TYPE praeco_upstream_ema_response_ms gauge\n");
    for srv in &status.servers {
        for route in &srv.routes {
            for up in &route.upstreams {
                out.push_str(&format!(
                    "praeco_upstream_ema_response_ms{{server=\"{}\",route=\"{}\",upstream=\"{}\"}} {}\n",
                    srv.name, route.prefix, up.uri, up.ema_response_ms
                ));
            }
        }
    }
    out.push('\n');

    out.push_str("# HELP praeco_upstream_consecutive_failures Consecutive outlier failures observed on the upstream node.\n");
    out.push_str("# TYPE praeco_upstream_consecutive_failures gauge\n");
    for srv in &status.servers {
        for route in &srv.routes {
            for up in &route.upstreams {
                out.push_str(&format!(
                    "praeco_upstream_consecutive_failures{{server=\"{}\",route=\"{}\",upstream=\"{}\"}} {}\n",
                    srv.name, route.prefix, up.uri, up.consecutive_failures
                ));
            }
        }
    }
    out
}

/// Applies an optional circuit-breaker control action (`action=mark_dead` or `action=mark_alive`
/// for a target `upstream=<uri>`) across all configured routes.
fn apply_optional_control_action(query: &str, fallback_server: Option<&ServerConfig>) {
    let mut action: Option<&str> = None;
    let mut target_upstream: Option<String> = None;

    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            match k {
                "action" => action = Some(v),
                "upstream" => target_upstream = Some(urlencoding_decode(v)),
                _ => {}
            }
        }
    }

    let (Some(act), Some(up_str)) = (action, target_upstream) else {
        return;
    };

    let global_cfg = Config::try_global();
    let servers_iter: Vec<ServerConfig> = if let Some(ref cfg) = global_cfg {
        cfg.servers.clone()
    } else if let Some(srv) = fallback_server {
        vec![srv.clone()]
    } else {
        return;
    };

    for srv in &servers_iter {
        for route in &srv.parsed_routes {
            for node in &route.target.upstreams {
                let node_uri_str = node.uri.to_string();
                if node_uri_str == up_str
                    || node_uri_str.trim_end_matches('/') == up_str.trim_end_matches('/')
                {
                    match act {
                        "mark_dead" | "open" => node.mark_dead(),
                        "mark_alive" | "close" | "reset" => node.mark_alive(),
                        _ => {}
                    }
                }
            }
        }
    }
}

fn urlencoding_decode(input: &str) -> String {
    let mut bytes = Vec::with_capacity(input.len());
    let mut chars = input.as_bytes().iter().copied();
    while let Some(b) = chars.next() {
        if b == b'%' {
            let hi = chars.next();
            let lo = chars.next();
            if let (Some(h), Some(l)) = (hi, lo) {
                let hex = [h, l];
                if let Ok(s) = std::str::from_utf8(&hex) {
                    if let Ok(val) = u8::from_str_radix(s, 16) {
                        bytes.push(val);
                        continue;
                    }
                }
            }
            bytes.push(b'%');
        } else if b == b'+' {
            bytes.push(b' ');
        } else {
            bytes.push(b);
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

/// Handles an incoming Admin / Telemetry HTTP request (from either `ServiceType::Admin`
/// or `RouteBackendType::Admin`).
pub fn handle_admin_request(
    uri: &Uri,
    method: &Method,
    headers: &HeaderMap,
    fallback_server: Option<&ServerConfig>,
) -> Response<ServiceRespBody> {
    if *method != Method::GET && *method != Method::POST && *method != Method::HEAD {
        let body = Full::new(Bytes::from_static(b"Method Not Allowed"))
            .map_err(SrvError::from)
            .boxed();
        return Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(body)
            .expect("Response builder failed");
    }

    let path = uri.path();
    let query = uri.query().unwrap_or("");

    // Fast liveness check endpoint
    if path.ends_with("/healthz") || path == "/health" {
        let payload = format!(
            r#"{{"status":"ok","uptime_seconds":{}}}"#,
            uptime_seconds()
        );
        let body = Full::new(Bytes::from(payload))
            .map_err(SrvError::from)
            .boxed();
        return Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::CACHE_CONTROL, "no-store")
            .body(body)
            .expect("Response builder failed");
    }

    // Optional circuit-breaker control action on POST requests (e.g. ?action=mark_dead&upstream=...)
    if *method == Method::POST && !query.is_empty() {
        apply_optional_control_action(query, fallback_server);
    }

    let status_snapshot = collect_admin_status(fallback_server);

    // Check if Prometheus text format was requested via path, query parameter, or Accept header
    let wants_prometheus = path.ends_with("/metrics")
        || query.contains("format=prometheus")
        || headers
            .get(header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|a| a.contains("application/openmetrics-text") || a.contains("version=0.0.4"));

    if wants_prometheus {
        let text = format_prometheus_metrics(&status_snapshot);
        let body = Full::new(Bytes::from(text))
            .map_err(SrvError::from)
            .boxed();
        Response::builder()
            .status(StatusCode::OK)
            .header(
                header::CONTENT_TYPE,
                "text/plain; version=0.0.4; charset=utf-8",
            )
            .header(header::CACHE_CONTROL, "no-store")
            .body(body)
            .expect("Response builder failed")
    } else {
        let json = serde_json::to_vec(&status_snapshot).unwrap_or_else(|_| b"{}".to_vec());
        let body = Full::new(Bytes::from(json))
            .map_err(SrvError::from)
            .boxed();
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::CACHE_CONTROL, "no-store")
            .body(body)
            .expect("Response builder failed")
    }
}

/// Standalone Tower [`Service`] for `ServiceType::Admin`.
#[derive(Clone)]
pub struct AdminService {
    server_config: Option<Arc<ServerConfig>>,
}

impl AdminService {
    pub fn new(server_config: Option<Arc<ServerConfig>>) -> Self {
        Self { server_config }
    }
}

impl Service<Request<SrvBody>> for AdminService {
    type Response = Response<ServiceRespBody>;
    type Error = SrvError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<SrvBody>) -> Self::Future {
        let (parts, _body) = req.into_parts();
        let fallback = self.server_config.clone();
        Box::pin(async move {
            Ok(handle_admin_request(
                &parts.uri,
                &parts.method,
                &parts.headers,
                fallback.as_deref(),
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::{LbStrategy, ParsedRoute, Protocol, RouteTarget, ServiceType, UpstreamNode};
    use http_body_util::BodyExt;
    use std::sync::atomic::AtomicUsize;

    fn build_mock_server_config() -> ServerConfig {
        let node_alive = UpstreamNode::new("https://127.0.0.1:50051".parse().unwrap());
        node_alive
            .total_requests
            .store(42, std::sync::atomic::Ordering::Relaxed);
        node_alive.record_latency_ms(12);

        let node_dead = UpstreamNode::new("https://127.0.0.1:59999".parse().unwrap());
        node_dead.mark_dead();
        node_dead
            .failover_retries
            .store(3, std::sync::atomic::Ordering::Relaxed);

        let target = Arc::new(RouteTarget {
            upstreams: vec![node_dead, node_alive],
            strategy: LbStrategy::RoundRobin,
            rr_counter: AtomicUsize::new(0),
            cooldown_seconds: 10,
            max_retries: 2,
            failure_threshold: 3,
            max_retry_buffer_bytes: 65536,
            active_health_check_interval: 60,
            grpc_pool: tokio::sync::RwLock::new(None),
            grpc_reflection_lock: tokio::sync::Mutex::new(()),
        });

        let route = ParsedRoute {
            prefix: "/".to_string(),
            target,
            allowed_roles: Vec::new(),
            backend_type: RouteBackendType::GrpcPassthrough,
        };

        let toml_str = r#"
            name = "test_gateway"
            ip = "127.0.0.1"
            port = 8080
            protocol = "https"
            service = "Router"
            [Layers]
            enabled = ["TraceId", "Logger"]
        "#;
        let mut srv: ServerConfig = toml::from_str(toml_str).unwrap();
        srv.protocol = Protocol::Https;
        srv.service = ServiceType::Router;
        srv.parsed_routes = vec![route];
        srv.pki_info.server_cert_valid_until_unix = Some(
            (SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                + 30 * 86_400) as i64,
        );
        crate::configuration::ServerMetrics::inc_total_requests("test_gateway");
        crate::configuration::ServerMetrics::inc_blocked_ip_filter("test_gateway");
        srv
    }

    #[tokio::test]
    async fn test_admin_json_status_reports_circuit_breaker_states() {
        let srv = build_mock_server_config();
        let uri: Uri = "https://wurzelwerk.admin.aweirich.eu/api/GetPraecoStatus"
            .parse()
            .unwrap();
        let headers = HeaderMap::new();

        let resp = handle_admin_request(&uri, &Method::POST, &headers, Some(&srv));
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );

        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

        assert_eq!(json["status"], "ok");
        assert_eq!(json["summary"]["total_upstreams"], 2);
        assert_eq!(json["summary"]["healthy_upstreams"], 1);
        assert_eq!(json["summary"]["open_circuits"], 1);
        assert_eq!(json["summary"]["total_upstream_requests"], 42);
        assert_eq!(json["summary"]["total_upstream_failures"], 1);
        assert_eq!(json["summary"]["total_circuit_trips"], 1);
        assert_eq!(json["summary"]["total_failover_retries"], 3);

        let srv_json = &json["servers"][0];
        assert!(srv_json["traffic_and_security"]["total_requests"].as_u64().unwrap() >= 1);
        assert!(srv_json["traffic_and_security"]["blocked_ip_filter"].as_u64().unwrap() >= 1);
        assert!(srv_json["pki"]["server_cert_days_remaining"].as_i64().unwrap() >= 29);

        let route_json = &srv_json["routes"][0];
        assert_eq!(route_json["failover_retries"], 3);

        let upstreams = route_json["upstreams"].as_array().unwrap();
        assert_eq!(upstreams[0]["uri"], "https://127.0.0.1:59999/");
        assert_eq!(upstreams[0]["circuit_state"], "Open");
        assert_eq!(upstreams[0]["is_alive"], false);
        assert_eq!(upstreams[0]["total_failures"], 1);
        assert_eq!(upstreams[0]["circuit_trips"], 1);
        assert_eq!(upstreams[0]["failover_retries"], 3);

        assert_eq!(upstreams[1]["uri"], "https://127.0.0.1:50051/");
        assert_eq!(upstreams[1]["circuit_state"], "Closed");
        assert_eq!(upstreams[1]["is_alive"], true);
        assert_eq!(upstreams[1]["total_requests"], 42);
        assert_eq!(upstreams[1]["last_response_ms"], 12);
        assert_eq!(upstreams[1]["ema_response_ms"], 12);
    }

    #[tokio::test]
    async fn test_admin_prometheus_metrics_output() {
        let srv = build_mock_server_config();
        let uri: Uri = "http://127.0.0.1:9090/metrics".parse().unwrap();
        let headers = HeaderMap::new();

        let resp = handle_admin_request(&uri, &Method::GET, &headers, Some(&srv));
        assert_eq!(resp.status(), StatusCode::OK);

        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8(body_bytes.to_vec()).unwrap();

        assert!(text.contains(
            r#"praeco_upstream_circuit_state{server="test_gateway",route="/",upstream="https://127.0.0.1:59999/"} 1"#
        ));
        assert!(text.contains(
            r#"praeco_upstream_circuit_state{server="test_gateway",route="/",upstream="https://127.0.0.1:50051/"} 0"#
        ));
    }
}
