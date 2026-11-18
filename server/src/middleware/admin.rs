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
    pub active_server_connections: usize,
    pub total_rejected_connections: u64,
    pub total_requests: u64,
    pub total_upstream_requests: u64,
    pub total_upstream_failures: u64,
    pub total_circuit_trips: u64,
    pub total_failover_retries: u64,
    pub total_blocked_requests: u64,
    pub total_responses_5xx: u64,
    pub revoked_jwt_tokens: usize,
}

/// Per-server edge traffic, connection, latency & security/WAF block counters (Package 2).
#[derive(Debug, Clone, Default, Serialize)]
pub struct AdminServerTrafficSecurity {
    pub total_requests: u64,
    pub active_connections: usize,
    pub connections_rejected_global: u64,
    pub connections_rejected_ip: u64,
    pub blocked_ip_filter: u64,
    pub blocked_inspection: u64,
    pub blocked_path_sanitizer: u64,
    pub blocked_jwt_auth: u64,
    pub blocked_auth_rbac: u64,
    pub rate_limited: u64,
    pub concurrency_limited: u64,
    pub payload_too_large: u64,
    pub decompression_limit_exceeded: u64,
    pub responses_2xx: u64,
    pub responses_3xx: u64,
    pub responses_4xx: u64,
    pub responses_5xx: u64,
    pub last_response_ms: u64,
    pub ema_response_ms: u64,
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
    let servers_refs: Vec<&ServerConfig> = if let Some(ref cfg) = global_cfg {
        cfg.servers.iter().filter(|s| s.enabled).collect()
    } else if let Some(srv) = fallback_server {
        vec![srv]
    } else {
        Vec::new()
    };

    let revoked_jwt_tokens = crate::middleware::jwt::get_jwt_revocation_store().len();

    let mut summary = AdminSummary {
        total_servers: servers_refs.len(),
        revoked_jwt_tokens,
        ..Default::default()
    };
    let mut servers = Vec::with_capacity(servers_refs.len());

    for srv in servers_refs {
        let listen = if let Some(ref tunnel) = srv.tunnel {
            format!("tunnel://{} ({})", tunnel.sni_domain, tunnel.target_url)
        } else {
            format!(
                "{}:{}",
                srv.ip.as_deref().unwrap_or("0.0.0.0"),
                srv.port.unwrap_or(0)
            )
        };

        // Package 2: Per-server edge traffic, connection, latency & security counters
        let srv_metrics = crate::configuration::ServerMetrics::for_server(&srv.name);
        let ord = std::sync::atomic::Ordering::Relaxed;
        let srv_total_reqs = srv_metrics.total_requests.load(ord);
        let srv_active_conns = srv_metrics.active_connections.load(ord);
        let srv_rej_global = srv_metrics.connections_rejected_global.load(ord);
        let srv_rej_ip = srv_metrics.connections_rejected_ip.load(ord);
        let srv_blocked_ip = srv_metrics.blocked_ip_filter.load(ord);
        let srv_blocked_insp = srv_metrics.blocked_inspection.load(ord);
        let srv_blocked_path = srv_metrics.blocked_path_sanitizer.load(ord);
        let srv_blocked_jwt = srv_metrics.blocked_jwt_auth.load(ord);
        let srv_blocked_rbac = srv_metrics.blocked_auth_rbac.load(ord);
        let srv_rate_limited = srv_metrics.rate_limited.load(ord);
        let srv_concurrency_limited = srv_metrics.concurrency_limited.load(ord);
        let srv_payload_too_large = srv_metrics.payload_too_large.load(ord);
        let srv_decompression_limit = srv_metrics.decompression_limit_exceeded.load(ord);
        let srv_resp_2xx = srv_metrics.responses_2xx.load(ord);
        let srv_resp_3xx = srv_metrics.responses_3xx.load(ord);
        let srv_resp_4xx = srv_metrics.responses_4xx.load(ord);
        let srv_resp_5xx = srv_metrics.responses_5xx.load(ord);
        let srv_last_ms = srv_metrics.last_response_ms.load(ord);
        let srv_ema_ms = srv_metrics.ema_response_ms.load(ord);

        summary.total_requests += srv_total_reqs;
        summary.active_server_connections += srv_active_conns;
        summary.total_rejected_connections += srv_rej_global + srv_rej_ip;
        summary.total_responses_5xx += srv_resp_5xx;
        summary.total_blocked_requests += srv_blocked_ip
            + srv_blocked_insp
            + srv_blocked_path
            + srv_blocked_jwt
            + srv_blocked_rbac
            + srv_rate_limited
            + srv_concurrency_limited
            + srv_payload_too_large
            + srv_decompression_limit;

        let traffic_and_security = AdminServerTrafficSecurity {
            total_requests: srv_total_reqs,
            active_connections: srv_active_conns,
            connections_rejected_global: srv_rej_global,
            connections_rejected_ip: srv_rej_ip,
            blocked_ip_filter: srv_blocked_ip,
            blocked_inspection: srv_blocked_insp,
            blocked_path_sanitizer: srv_blocked_path,
            blocked_jwt_auth: srv_blocked_jwt,
            blocked_auth_rbac: srv_blocked_rbac,
            rate_limited: srv_rate_limited,
            concurrency_limited: srv_concurrency_limited,
            payload_too_large: srv_payload_too_large,
            decompression_limit_exceeded: srv_decompression_limit,
            responses_2xx: srv_resp_2xx,
            responses_3xx: srv_resp_3xx,
            responses_4xx: srv_resp_4xx,
            responses_5xx: srv_resp_5xx,
            last_response_ms: srv_last_ms,
            ema_response_ms: srv_ema_ms,
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
            for (sub_key, backend_type, target) in route.iter_targets() {
                let display_prefix = match sub_key {
                    Some(k) => format!("{} [target:{}]", route.prefix, k),
                    None => route.prefix.clone(),
                };
                routes.push(collect_route_target_status(
                    display_prefix,
                    backend_type,
                    target,
                    now_unix,
                    &mut summary,
                ));
            }
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

    out.push_str("# HELP praeco_server_active_connections Active client connections per server.\n");
    out.push_str("# TYPE praeco_server_active_connections gauge\n");
    for srv in &status.servers {
        out.push_str(&format!(
            "praeco_server_active_connections{{server=\"{}\"}} {}\n",
            srv.name, srv.traffic_and_security.active_connections
        ));
    }
    out.push('\n');

    out.push_str("# HELP praeco_server_connections_rejected_total Connections rejected by connection limits.\n");
    out.push_str("# TYPE praeco_server_connections_rejected_total counter\n");
    for srv in &status.servers {
        out.push_str(&format!(
            "praeco_server_connections_rejected_total{{server=\"{}\",reason=\"global_limit\"}} {}\n",
            srv.name, srv.traffic_and_security.connections_rejected_global
        ));
        out.push_str(&format!(
            "praeco_server_connections_rejected_total{{server=\"{}\",reason=\"ip_limit\"}} {}\n",
            srv.name, srv.traffic_and_security.connections_rejected_ip
        ));
    }
    out.push('\n');

    out.push_str("# HELP praeco_server_blocked_requests_total Blocked requests per server by security or limit layer.\n");
    out.push_str("# TYPE praeco_server_blocked_requests_total counter\n");
    for srv in &status.servers {
        let ts = &srv.traffic_and_security;
        for (reason, count) in [
            ("ip_filter", ts.blocked_ip_filter),
            ("inspection", ts.blocked_inspection),
            ("path_sanitizer", ts.blocked_path_sanitizer),
            ("jwt_auth", ts.blocked_jwt_auth),
            ("auth_rbac", ts.blocked_auth_rbac),
            ("rate_limited", ts.rate_limited),
            ("concurrency_limit", ts.concurrency_limited),
            ("payload_too_large", ts.payload_too_large),
            ("decompression_limit", ts.decompression_limit_exceeded),
        ] {
            out.push_str(&format!(
                "praeco_server_blocked_requests_total{{server=\"{}\",reason=\"{}\"}} {}\n",
                srv.name, reason, count
            ));
        }
    }
    out.push('\n');

    out.push_str("# HELP praeco_server_responses_total Completed HTTP responses per server by status class.\n");
    out.push_str("# TYPE praeco_server_responses_total counter\n");
    for srv in &status.servers {
        let ts = &srv.traffic_and_security;
        for (status_class, count) in [
            ("2xx", ts.responses_2xx),
            ("3xx", ts.responses_3xx),
            ("4xx", ts.responses_4xx),
            ("5xx", ts.responses_5xx),
        ] {
            out.push_str(&format!(
                "praeco_server_responses_total{{server=\"{}\",status_class=\"{}\"}} {}\n",
                srv.name, status_class, count
            ));
        }
    }
    out.push('\n');

    out.push_str("# HELP praeco_server_last_response_ms Most recent observed request latency per server in milliseconds.\n");
    out.push_str("# TYPE praeco_server_last_response_ms gauge\n");
    for srv in &status.servers {
        out.push_str(&format!(
            "praeco_server_last_response_ms{{server=\"{}\"}} {}\n",
            srv.name, srv.traffic_and_security.last_response_ms
        ));
    }
    out.push('\n');

    out.push_str("# HELP praeco_server_ema_response_ms Exponential moving average request latency per server in milliseconds.\n");
    out.push_str("# TYPE praeco_server_ema_response_ms gauge\n");
    for srv in &status.servers {
        out.push_str(&format!(
            "praeco_server_ema_response_ms{{server=\"{}\"}} {}\n",
            srv.name, srv.traffic_and_security.ema_response_ms
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
    let servers_slice: &[ServerConfig] = if let Some(ref cfg) = global_cfg {
        &cfg.servers
    } else if let Some(srv) = fallback_server {
        std::slice::from_ref(srv)
    } else {
        return;
    };

    for srv in servers_slice {
        for route in &srv.parsed_routes {
            for (_, _, target) in route.iter_targets() {
                for node in &target.upstreams {
                    let node_uri_str = node.uri.to_string();
                    if node_uri_str == up_str
                        || node_uri_str.trim_end_matches('/') == up_str.trim_end_matches('/')
                    {
                        match act {
                            "mark_dead" | "open" => {
                                node.mark_dead();
                                tracing::warn!(
                                    target: "admin::audit",
                                    server = %srv.name,
                                    action = %act,
                                    upstream = %node_uri_str,
                                    "Admin circuit-breaker control action executed"
                                );
                            }
                            "mark_alive" | "close" | "reset" => {
                                node.mark_alive();
                                tracing::warn!(
                                    target: "admin::audit",
                                    server = %srv.name,
                                    action = %act,
                                    upstream = %node_uri_str,
                                    "Admin circuit-breaker control action executed"
                                );
                            }
                            _ => {}
                        }
                    }
                }
            }
        }
    }
}

/// Collects circuit-breaker and telemetry status for a single [`RouteTarget`].
fn collect_route_target_status(
    prefix: String,
    backend_type: &RouteBackendType,
    target: &crate::configuration::RouteTarget,
    now_unix: u64,
    summary: &mut AdminSummary,
) -> AdminRouteStatus {
    let cooldown = target.cooldown_seconds;
    let mut upstreams = Vec::with_capacity(target.upstreams.len());
    let mut route_failover_retries = 0u64;

    for node in &target.upstreams {
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

    AdminRouteStatus {
        prefix,
        backend_type: format!("{:?}", backend_type),
        strategy: format!("{:?}", target.strategy),
        cooldown_seconds: cooldown,
        max_retries: target.max_retries,
        failure_threshold: target.failure_threshold,
        max_retry_buffer_bytes: target.max_retry_buffer_bytes,
        active_health_check_interval: target.active_health_check_interval,
        failover_retries: route_failover_retries,
        upstreams,
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
                if let Ok(s) = std::str::from_utf8(&hex)
                    && let Ok(val) = u8::from_str_radix(s, 16) {
                        bytes.push(val);
                        continue;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdminEndpoint {
    Health,
    Status,
    Metrics,
}

/// Resolves an incoming Admin request path (optionally relative to a mounted router `mount_prefix`)
/// into a supported [`AdminEndpoint`], or `None` if the path is unknown.
fn resolve_admin_endpoint(path: &str, mount_prefix: Option<&str>) -> Option<AdminEndpoint> {
    let subpath = match mount_prefix {
        None => path,
        Some(prefix) => {
            let trimmed = prefix.trim_end_matches('/');
            if trimmed.is_empty() {
                if path == "/" {
                    return Some(AdminEndpoint::Status);
                }
                path
            } else {
                let rest = path.strip_prefix(trimmed)?;
                if rest.is_empty() || rest == "/" {
                    return Some(AdminEndpoint::Status);
                }
                rest
            }
        }
    };

    match subpath {
        "/healthz" | "/health" => Some(AdminEndpoint::Health),
        "/metrics" => Some(AdminEndpoint::Metrics),
        "/status" | "/upstreams" => Some(AdminEndpoint::Status),
        _ => None,
    }
}

fn build_admin_response(
    status: StatusCode,
    content_type: &'static str,
    payload: Bytes,
) -> Response<ServiceRespBody> {
    let body = Full::new(payload).map_err(SrvError::from).boxed();
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CACHE_CONTROL, "no-store")
        .body(body)
        .expect("Response builder failed")
}

/// Handles an incoming Admin / Telemetry HTTP request for a standalone `ServiceType::Admin`
/// listener.
pub fn handle_admin_request(
    uri: &Uri,
    method: &Method,
    headers: &HeaderMap,
    fallback_server: Option<&ServerConfig>,
) -> Response<ServiceRespBody> {
    handle_admin_request_with_prefix(uri, method, headers, fallback_server, None)
}

/// Handles an incoming Admin / Telemetry HTTP request (from either `ServiceType::Admin`
/// with `mount_prefix = None`, or `RouteBackendType::Admin` mounted under `mount_prefix`).
pub fn handle_admin_request_with_prefix(
    uri: &Uri,
    method: &Method,
    headers: &HeaderMap,
    fallback_server: Option<&ServerConfig>,
    mount_prefix: Option<&str>,
) -> Response<ServiceRespBody> {
    if *method != Method::GET && *method != Method::POST && *method != Method::HEAD {
        return build_admin_response(
            StatusCode::METHOD_NOT_ALLOWED,
            "text/plain; charset=utf-8",
            Bytes::from_static(b"Method Not Allowed"),
        );
    }

    let path = uri.path();
    let query = uri.query().unwrap_or("");

    let Some(endpoint) = resolve_admin_endpoint(path, mount_prefix) else {
        return build_admin_response(
            StatusCode::NOT_FOUND,
            "application/json",
            Bytes::from_static(br#"{"error":"Not Found"}"#),
        );
    };

    // Fast liveness check endpoint
    if endpoint == AdminEndpoint::Health {
        let payload = format!(
            r#"{{"status":"ok","uptime_seconds":{}}}"#,
            uptime_seconds()
        );
        return build_admin_response(StatusCode::OK, "application/json", Bytes::from(payload));
    }

    // Optional circuit-breaker control action on POST requests (e.g. ?action=mark_dead&upstream=...)
    if *method == Method::POST && !query.is_empty() {
        let is_unauthenticated_standalone = mount_prefix.is_none()
            && fallback_server.is_some_and(|srv| {
                srv.service == crate::configuration::ServiceType::Admin
                    && srv.authentication == crate::configuration::AuthenticationMethod::None
                    && !srv.layers.enabled.iter().any(|l| {
                        l.eq_ignore_ascii_case("JwtAuth") || l.eq_ignore_ascii_case("JWT")
                    })
            });

        if is_unauthenticated_standalone {
            tracing::warn!(
                target: "admin::audit",
                path = %path,
                "Rejected POST admin control action on unauthenticated Admin listener"
            );
            return build_admin_response(
                StatusCode::FORBIDDEN,
                "application/json",
                Bytes::from_static(br#"{"error":"Admin control actions require authentication"}"#),
            );
        }

        if let Some(sec_fetch_site) = headers
            .get("sec-fetch-site")
            .and_then(|v| v.to_str().ok())
            && !sec_fetch_site.eq_ignore_ascii_case("same-origin")
            && !sec_fetch_site.eq_ignore_ascii_case("none")
        {
            tracing::warn!(
                target: "admin::audit",
                sec_fetch_site = %sec_fetch_site,
                path = %path,
                "Blocked cross-site POST admin control action"
            );
            return build_admin_response(
                StatusCode::FORBIDDEN,
                "application/json",
                Bytes::from_static(br#"{"error":"Cross-site admin control action blocked"}"#),
            );
        }

        apply_optional_control_action(query, fallback_server);
    }

    let status_snapshot = collect_admin_status(fallback_server);

    // Check if Prometheus text format was requested via path, query parameter, or Accept header
    let wants_prometheus = endpoint == AdminEndpoint::Metrics
        || query.contains("format=prometheus")
        || headers
            .get(header::ACCEPT)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|a| a.contains("application/openmetrics-text") || a.contains("version=0.0.4"));

    if wants_prometheus {
        let text = format_prometheus_metrics(&status_snapshot);
        build_admin_response(
            StatusCode::OK,
            "text/plain; version=0.0.4; charset=utf-8",
            Bytes::from(text),
        )
    } else {
        let json = serde_json::to_vec(&status_snapshot).unwrap_or_else(|_| b"{}".to_vec());
        build_admin_response(StatusCode::OK, "application/json", Bytes::from(json))
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
            aggregate_targets: Vec::new(),
            aggregate_payload_mode: crate::configuration::AggregatePayloadMode::default(),
            expose_upstream_errors: false,
            aggregate_deadline_ms: None,
            max_request_bytes: crate::configuration::DEFAULT_MAX_BUFFERED_REQUEST_BYTES,
            max_response_bytes: crate::configuration::DEFAULT_MAX_AGGREGATE_RESPONSE_BYTES,
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

        let resp = handle_admin_request_with_prefix(
            &uri,
            &Method::POST,
            &headers,
            Some(&srv),
            Some("/api/GetPraecoStatus"),
        );
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

    #[tokio::test]
    async fn test_admin_unknown_paths_return_not_found() {
        let srv = build_mock_server_config();
        let headers = HeaderMap::new();

        for invalid_uri in [
            "http://127.0.0.1:9090/xstatusx",
            "http://127.0.0.1:9090/",
            "http://127.0.0.1:9090/status/extra",
            "http://127.0.0.1:9090/foo/metrics",
            "http://127.0.0.1:9090/foo/healthz",
        ] {
            let uri: Uri = invalid_uri.parse().unwrap();
            let resp = handle_admin_request(&uri, &Method::GET, &headers, Some(&srv));
            assert_eq!(
                resp.status(),
                StatusCode::NOT_FOUND,
                "expected 404 for {invalid_uri}"
            );
            let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
            let json: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
            assert_eq!(json["error"], "Not Found");
        }

        // Valid standalone endpoints must still return 200 OK
        for valid_uri in [
            "http://127.0.0.1:9090/status",
            "http://127.0.0.1:9090/upstreams",
            "http://127.0.0.1:9090/healthz",
            "http://127.0.0.1:9090/health",
            "http://127.0.0.1:9090/metrics",
        ] {
            let uri: Uri = valid_uri.parse().unwrap();
            let resp = handle_admin_request(&uri, &Method::GET, &headers, Some(&srv));
            assert_eq!(resp.status(), StatusCode::OK, "expected 200 for {valid_uri}");
        }

        // Mounted RouteBackendType::Admin sub-paths
        let bad_mounted: Uri = "https://example.com/api/GetPraecoStatus/xstatusx"
            .parse()
            .unwrap();
        let resp = handle_admin_request_with_prefix(
            &bad_mounted,
            &Method::GET,
            &headers,
            Some(&srv),
            Some("/api/GetPraecoStatus"),
        );
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);

        let good_mounted_metrics: Uri = "https://example.com/api/GetPraecoStatus/metrics"
            .parse()
            .unwrap();
        let resp = handle_admin_request_with_prefix(
            &good_mounted_metrics,
            &Method::GET,
            &headers,
            Some(&srv),
            Some("/api/GetPraecoStatus"),
        );
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_admin_reports_extended_server_metrics() {
        let srv = build_mock_server_config();
        let m = crate::configuration::ServerMetrics::for_server("test_gateway");
        m.active_connections
            .store(7, std::sync::atomic::Ordering::Relaxed);
        m.connections_rejected_global
            .fetch_add(2, std::sync::atomic::Ordering::Relaxed);
        m.connections_rejected_ip
            .fetch_add(3, std::sync::atomic::Ordering::Relaxed);
        crate::configuration::ServerMetrics::inc_blocked_path_sanitizer("test_gateway");
        crate::configuration::ServerMetrics::inc_blocked_jwt_auth("test_gateway");
        crate::configuration::ServerMetrics::inc_concurrency_limited("test_gateway");
        crate::configuration::ServerMetrics::inc_payload_too_large("test_gateway");
        crate::configuration::ServerMetrics::inc_decompression_limit_exceeded("test_gateway");
        crate::configuration::ServerMetrics::record_response("test_gateway", 200, 15);
        crate::configuration::ServerMetrics::record_response("test_gateway", 502, 35);

        let headers = HeaderMap::new();
        let status_uri: Uri = "http://127.0.0.1:9090/status".parse().unwrap();
        let status_resp = handle_admin_request(&status_uri, &Method::GET, &headers, Some(&srv));
        assert_eq!(status_resp.status(), StatusCode::OK);
        let status_bytes = status_resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&status_bytes).unwrap();

        let ts = &json["servers"][0]["traffic_and_security"];
        assert_eq!(ts["active_connections"], 7);
        assert!(ts["connections_rejected_global"].as_u64().unwrap() >= 2);
        assert!(ts["connections_rejected_ip"].as_u64().unwrap() >= 3);
        assert!(ts["blocked_path_sanitizer"].as_u64().unwrap() >= 1);
        assert!(ts["blocked_jwt_auth"].as_u64().unwrap() >= 1);
        assert!(ts["concurrency_limited"].as_u64().unwrap() >= 1);
        assert!(ts["payload_too_large"].as_u64().unwrap() >= 1);
        assert!(ts["decompression_limit_exceeded"].as_u64().unwrap() >= 1);
        assert!(ts["responses_2xx"].as_u64().unwrap() >= 1);
        assert!(ts["responses_5xx"].as_u64().unwrap() >= 1);
        assert!(ts["last_response_ms"].is_number());
        assert!(ts["ema_response_ms"].is_number());

        let metrics_uri: Uri = "http://127.0.0.1:9090/metrics".parse().unwrap();
        let metrics_resp = handle_admin_request(&metrics_uri, &Method::GET, &headers, Some(&srv));
        assert_eq!(metrics_resp.status(), StatusCode::OK);
        let metrics_bytes = metrics_resp.into_body().collect().await.unwrap().to_bytes();
        let text = String::from_utf8(metrics_bytes.to_vec()).unwrap();

        for expected in [
            r#"praeco_server_active_connections{server="test_gateway"} 7"#,
            r#"praeco_server_connections_rejected_total{server="test_gateway",reason="global_limit"}"#,
            r#"praeco_server_connections_rejected_total{server="test_gateway",reason="ip_limit"}"#,
            r#"praeco_server_blocked_requests_total{server="test_gateway",reason="path_sanitizer"}"#,
            r#"praeco_server_blocked_requests_total{server="test_gateway",reason="jwt_auth"}"#,
            r#"praeco_server_blocked_requests_total{server="test_gateway",reason="concurrency_limit"}"#,
            r#"praeco_server_blocked_requests_total{server="test_gateway",reason="payload_too_large"}"#,
            r#"praeco_server_blocked_requests_total{server="test_gateway",reason="decompression_limit"}"#,
            r#"praeco_server_responses_total{server="test_gateway",status_class="2xx"}"#,
            r#"praeco_server_responses_total{server="test_gateway",status_class="5xx"}"#,
            r#"praeco_server_last_response_ms{server="test_gateway"}"#,
            r#"praeco_server_ema_response_ms{server="test_gateway"}"#,
        ] {
            assert!(text.contains(expected), "missing metric line: {expected}");
        }
    }

    #[tokio::test]
    async fn test_admin_upstreams_reports_and_controls_aggregate_targets() {
        let toml_str = r#"
            name = "agg_admin_test"
            enabled = true
            protocol = "http"
            service = "Router"
            ip = "127.0.0.1"
            port = 8080

            [RouterParams]
            protocol = "http"

            [Layers]
            enabled = []

            [ReverseRoutes."/api/dashboard"]
            backend_type = "aggregate"

            [[ReverseRoutes."/api/dashboard".targets]]
            key = "user"
            backend_type = "grpc_transcoding"
            upstreams = ["http://127.0.0.1:50051"]
            path = "/user.UserService/GetUser"

            [[ReverseRoutes."/api/dashboard".targets]]
            key = "notifications"
            backend_type = "rest"
            upstreams = ["http://127.0.0.1:8081"]
            path = "/v1/notifications"
        "#;
        let mut srv: ServerConfig = toml::from_str(toml_str).unwrap();
        srv.finalize().unwrap();

        let status = collect_admin_status(Some(&srv));
        assert_eq!(status.summary.total_routes, 1);
        assert_eq!(status.summary.total_upstreams, 2);
        let routes = &status.servers[0].routes;
        assert_eq!(routes[0].prefix, "/api/dashboard [target:user]");
        assert_eq!(routes[1].prefix, "/api/dashboard [target:notifications]");

        // Mark gRPC sub-target dead via admin control endpoint
        let headers = HeaderMap::new();
        let mark_dead_uri: Uri =
            "http://127.0.0.1:9090/upstreams?action=mark_dead&upstream=http://127.0.0.1:50051/"
                .parse()
                .unwrap();
        let resp = handle_admin_request(&mark_dead_uri, &Method::POST, &headers, Some(&srv));
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            !srv.parsed_routes[0].aggregate_targets[0].target.upstreams[0]
                .is_alive
                .load(std::sync::atomic::Ordering::Acquire)
        );
    }

    #[tokio::test]
    async fn test_unauthenticated_standalone_admin_is_read_only_and_csrf_protected() {
        let toml_str = r#"
            name = "readonly_admin_test"
            enabled = true
            protocol = "http"
            service = "Admin"
            authentication = "None"
            ip = "127.0.0.1"
            port = 9090

            [Layers]
            enabled = []
        "#;
        let mut srv: ServerConfig = toml::from_str(toml_str).unwrap();
        srv.finalize().unwrap();

        let headers = HeaderMap::new();
        let status_uri: Uri = "http://127.0.0.1:9090/status".parse().unwrap();
        let get_resp = handle_admin_request(&status_uri, &Method::GET, &headers, Some(&srv));
        assert_eq!(get_resp.status(), StatusCode::OK);

        // POST control action on unauthenticated standalone AdminService must be forbidden
        let mark_dead_uri: Uri =
            "http://127.0.0.1:9090/status?action=mark_dead&upstream=http://127.0.0.1:50051/"
                .parse()
                .unwrap();
        let post_resp = handle_admin_request(&mark_dead_uri, &Method::POST, &headers, Some(&srv));
        assert_eq!(post_resp.status(), StatusCode::FORBIDDEN);

        // Cross-site Sec-Fetch-Site on mounted/authenticated admin POST must also be blocked
        let mut router_srv = ServerConfig {
            name: "mounted_admin".into(),
            ip: Some("127.0.0.1".into()),
            port: Some(8080),
            service: crate::configuration::ServiceType::Router,
            ..Default::default()
        };
        router_srv.finalize().unwrap();

        let mut csrf_headers = HeaderMap::new();
        csrf_headers.insert("sec-fetch-site", "cross-site".parse().unwrap());
        let csrf_resp = handle_admin_request_with_prefix(
            &"http://127.0.0.1:8080/api/GetPraecoStatus?action=mark_dead&upstream=http://127.0.0.1:50051/"
                .parse()
                .unwrap(),
            &Method::POST,
            &csrf_headers,
            Some(&router_srv),
            Some("/api/GetPraecoStatus"),
        );
        assert_eq!(csrf_resp.status(), StatusCode::FORBIDDEN);
    }
}
