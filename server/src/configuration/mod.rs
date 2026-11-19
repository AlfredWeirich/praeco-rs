//! # Server Configuration
//!
//! Defines the TOML-driven configuration model for the entire server
//! application. The [`Config`] struct is the root, containing global settings
//! and a list of [`ServerConfig`] instances — each describing one logical
//! server (listener + middleware stack + base service).
//!
//! ## Configuration Lifecycle
//!
//! 1. **Read** – [`Config::init`] reads a TOML file from disk.
//! 2. **Deserialize** – The file is parsed into the `Config` / `ServerConfig`
//!    struct hierarchy via `serde` + `toml`.
//! 3. **Finalize** – [`ServerConfig::finalize`] performs post-deserialization
//!    setup: route parsing, regex compilation, and validation.
//! 4. **Freeze** – The config is stored in a global [`OnceLock`] so that all
//!    server tasks can borrow it with `'static` lifetime.
//!
//! ## Global Access
//!
//! After [`Config::init`] succeeds, any code can call [`Config::global()`] to
//! obtain a `&'static Config` reference.

use anyhow::{Context, Error};
use arc_swap::ArcSwap;
use bytes::Bytes;
use hyper::{Method, Uri};
use regex::Regex;
use rustls::sign::CertifiedKey;
use serde::Deserialize;
use std::{
    collections::{HashMap, HashSet},
    fs,
    net::SocketAddr,
    sync::{Arc, OnceLock},
};

/// The global singleton holder for the parsed configuration.
///
/// Initialised once by [`Config::init`] and then immutably borrowed for the
/// lifetime of the process.
static CONFIG: OnceLock<ArcSwap<Config>> = OnceLock::new();

// ============================================================================
//  Core Enums
// ============================================================================

/// Represents the different authorization levels for a user based on their
/// mTLS certificate OIDs or JWT token claims.
///
/// The variant names match the TOML configuration (PascalCase) thanks to
/// `#[serde(rename_all = "PascalCase")]`.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq, Hash)]
#[serde(transparent)]
pub struct UserRole(pub String);

impl UserRole {
    /// Default role for unidentified or low-privileged clients.
    pub fn guest() -> Self {
        Self("Guest".to_string())
    }
}

/// Stack-allocated role vector: holds up to `N` (default 6) roles on the stack without heap allocation.
pub type RoleVec<const N: usize = 6> = smallvec::SmallVec<[UserRole; N]>;

/// The transport protocol for a server instance.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    /// Plain-text HTTP (no TLS). **Only for development / testing.**
    #[default]
    Http,
    /// TLS-encrypted HTTPS (HTTP/1.1 + HTTP/2 + HTTP/3).
    Https,
}

/// The base service type that sits at the bottom of the middleware stack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[non_exhaustive]
pub enum ServiceType {
    /// A diagnostic echo service for load testing.
    #[default]
    Echo,
    /// A reverse-proxy router with RBAC and URI rewriting.
    Router,
    /// An Identity Provider that issues JWTs (e.g. for mTLS to JWT or DeviceAuth).
    Idp,
    /// A static file server for serving SPAs and assets directly from disk.
    StaticFiles,
    /// An internal admin & telemetry service (`/status`, `/upstreams`, `/metrics`, `/healthz`).
    Admin,
}

/// How clients authenticate with this server instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
pub enum AuthenticationMethod {
    /// No authentication required.
    #[default]
    #[serde(alias = "", alias = "None")]
    None,
    /// JWT bearer-token authentication.
    #[serde(alias = "JWT")]
    Jwt,
    /// Mutual TLS (mTLS) — client must present a valid certificate.
    #[serde(alias = "ClientCert", alias = "mTLS")]
    ClientCert,
    /// Optional Mutual TLS (mTLS) — client may present a valid certificate, but connection succeeds without it.
    #[serde(alias = "OptionalClientCert")]
    OptionalClientCert,
}

// ============================================================================
//  Root Configuration
// ============================================================================

/// The root configuration structure for the server application.
///
/// Deserialized from a TOML file by [`Config::init`]. Holds global settings
/// (OID mappings, Tokio threads, log directory) and a list of
/// [`ServerConfig`] instances.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// List of file globs to include (e.g., ["conf.d/*.toml"]).
    #[serde(default)]
    pub includes: Vec<String>,
    
    /// List of server configurations to be spawned.
    #[serde(rename = "Server", default)]
    pub servers: Vec<ServerConfig>,
    /// Optional override for the number of Tokio worker threads.
    /// Defaults to the number of logical CPUs if `None`.
    pub tokio_threads: Option<usize>,
    /// Directory where log files will be stored (if file logging is enabled).
    pub log_dir: Option<String>,
    /// The base OID prefix for custom PKI extensions
    /// (e.g. `"2.25"` for UUID-based OIDs).
    pub pki_base_oid: Option<String>,
    /// Flag to enable or disable OpenTelemetry Tracing (Jaeger)
    pub enable_opentelemetry: Option<bool>,
    /// Jaeger OTLP gRPC endpoint (default: "http://localhost:4317")
    pub jaeger_endpoint: Option<String>,
    /// Log level for traces exported to Jaeger (default: "info")
    pub otel_log_level: Option<String>,
    /// Sampling ratio for OTLP traces (0.0 to 1.0, default: 1.0 = AlwaysOn)
    pub otel_sample_ratio: Option<f64>,

    /// Pre-parsed integer representation of [`pki_base_oid`](Config::pki_base_oid).
    /// Computed in [`Config::init`] for fast OID prefix matching in
    /// [`extract_oids_from_cert`](crate::tls_conf::extract_oids_from_cert).
    #[serde(skip)]
    pub parsed_pki_base_oid: Option<Vec<u64>>,
}

// ============================================================================
//  Per-Server Configuration
// ============================================================================

#[derive(Debug, Deserialize, Clone, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TunnelConfig {
    pub target_url: String,
    pub sni_domain: String,
    pub client_cert_path: String,
    pub client_key_path: String,
    pub ca_cert_path: String,
    /// Maximum concurrent Yamux multiplexed streams over the tunnel connection.
    /// Defaults to 4096 (replaces Yamux default of 512).
    #[serde(default)]
    pub max_yamux_streams: Option<usize>,
    /// Whether to enable PROXY-Protocol v2 negotiation for propagating real client IP addresses.
    /// Defaults to true.
    #[serde(default = "default_true")]
    pub proxy_protocol: bool,
}

/// Configuration for a single server instance (one listener address).
///
/// Each `ServerConfig` produces one TCP listener (and optionally one UDP
/// listener for HTTP/3). The middleware stack and base service are built from
/// the fields defined here.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    /// Human-readable name used in all log/trace output.
    pub name: String,

    /// Static reference to the name (populated in `finalize`) to avoid cloning in middleware.
    #[serde(skip)]
    pub static_name: Option<&'static str>,

    /// IP address to bind to. The special value `"local"` resolves to the
    /// machine's primary local IP at startup. Optional if a `tunnel` is configured.
    #[serde(default)]
    pub ip: Option<String>,
    /// TCP/UDP port to listen on. Optional if a `tunnel` is configured.
    #[serde(default)]
    pub port: Option<u16>,
    
    /// Optional Tunnel configuration for Outbound Zero-Trust connections (SNI Relay)
    #[serde(default)]
    pub tunnel: Option<TunnelConfig>,
    /// Whether this server instance should be started. Defaults to `true`.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// The base service type (Echo or Router).
    #[serde(default)]
    pub service: ServiceType,
    /// Transport protocol (HTTP or HTTPS).
    #[serde(default)]
    pub protocol: Protocol,
    /// Authentication method (None, JWT, or ClientCert/mTLS).
    #[serde(default)]
    pub authentication: AuthenticationMethod,

    /// Map of specific OID suffixes to [`UserRole`] variants for RBAC on this server.
    /// Example: `{"1" = "Admin", "2" = "Viewer"}`.
    #[serde(default)]
    pub oid_mapping: HashMap<String, UserRole>,

    /// Optional per-server PKI Base Object Identifier (OID) overriding the global
    /// `pki_base_oid` in `Config.toml` (e.g. `"1.3.6.1.4.1.65111"`).
    ///
    /// When omitted, the global [`Config::pki_base_oid`] is used as fallback.
    #[serde(default)]
    pub pki_base_oid: Option<String>,

    /// Server TLS certificate and key paths (required for HTTPS).
    pub server_certs: Option<ServerCertConfig>,
    /// Client CA certificates for mTLS verification.
    pub client_certs: Option<Vec<ClientCertConfig>>,

    /// Configuration for forwarding client certificate details to the backend.
    pub client_cert_forwarding: Option<ClientCertForwardingConfig>,

    /// Connection limits for TCP/QUIC listeners (default: 10,000 global, 100 per IP).
    #[serde(default, alias = "ConnectionLimits")]
    pub connection_limits: ConnectionLimitsConfig,

    /// Maximum time in seconds to drain in-flight connections on shutdown or
    /// hot-reload restart before remaining tasks are aborted (default: `10`).
    #[serde(default = "default_graceful_shutdown_timeout_seconds")]
    pub graceful_shutdown_timeout_seconds: u64,

    /// Middleware layer configuration (names + per-layer settings).
    #[serde(rename = "Layers")]
    pub layers: Layers,

    /// Optional regex-based allowed path rules for the Inspection layer.
    #[serde(rename = "AllowedPathes")]
    pub allowed_pathes: Option<AllowedPathes>,

    /// Mapping of path prefixes to backend targets (Reverse Proxy logic).
    #[serde(rename = "ReverseRoutes")]
    pub rev_routes: Option<HashMap<String, RouteConfig>>,

    /// Granular path-based Role-Based Access Control (RBAC) rules.
    ///
    /// Maps paths (exact or prefix wildcards ending with `*`) to required roles.
    /// An empty list `[]` acts as an explicit Deny-All rule.
    /// Wildcard `"*"` in the roles list permits any caller.
    #[serde(default, rename = "Rbac", alias = "rbac")]
    pub rbac: Option<HashMap<String, Vec<UserRole>>>,

    /// Additional parameters for the Router service (upstream protocol,
    /// auth settings, TLS for upstream connections).
    #[serde(rename = "RouterParams")]
    pub router_params: Option<RouterParams>,

    /// Additional parameters for the IdP service (JWT signing key, expiration, etc.).
    #[serde(rename = "IdpParams")]
    pub idp_params: Option<IdpParams>,

    /// Additional parameters for the StaticFiles service (root directory, fallback behavior).
    #[serde(rename = "StaticFilesParams")]
    pub static_files_params: Option<StaticFilesParams>,

    /// Pre-parsed and sorted reverse-proxy routes. Computed in [`ServerConfig::finalize`].
    #[serde(skip)]
    pub parsed_routes: Vec<ParsedRoute>,

    /// Pre-compiled regex patterns for the Inspection layer. Computed in
    /// [`ServerConfig::finalize`].
    #[serde(skip)]
    pub compiled_allowed_pathes: Option<Arc<CompiledAllowedPathes>>,

    /// Pre-compiled RBAC lookup structure computed in [`ServerConfig::finalize`].
    #[serde(skip)]
    pub compiled_rbac: Option<Arc<CompiledRbac>>,

    /// The loaded TLS private key + certificate chain. Computed in
    /// [`ServerConfig::finalize`] if HTTPS matches.
    #[serde(skip)]
    pub certified_key: Option<Arc<CertifiedKey>>,

    /// Per-server lock-free request and security block counters.
    #[serde(skip)]
    pub metrics: Arc<ServerMetrics>,

    /// Cached X.509 certificate and CRL expiration metadata extracted in [`ServerConfig::finalize`].
    #[serde(skip)]
    pub pki_info: ServerPkiInfo,

    /// Pre-parsed base OID components for this server (`server.pki_base_oid` or
    /// fallback to [`Config::parsed_pki_base_oid`]).
    #[serde(skip)]
    pub parsed_pki_base_oid: Option<Vec<u64>>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            static_name: None,
            ip: None,
            port: None,
            tunnel: None,
            enabled: true,
            service: ServiceType::default(),
            protocol: Protocol::default(),
            authentication: AuthenticationMethod::default(),
            oid_mapping: HashMap::new(),
            server_certs: None,
            client_certs: None,
            client_cert_forwarding: None,
            connection_limits: ConnectionLimitsConfig::default(),
            graceful_shutdown_timeout_seconds: default_graceful_shutdown_timeout_seconds(),
            layers: Layers::default(),
            allowed_pathes: None,
            rev_routes: None,
            rbac: None,
            router_params: None,
            idp_params: None,
            static_files_params: None,
            parsed_routes: Vec::new(),
            compiled_allowed_pathes: None,
            compiled_rbac: None,
            certified_key: None,
            metrics: Arc::new(ServerMetrics::default()),
            pki_info: ServerPkiInfo::default(),
            pki_base_oid: None,
            parsed_pki_base_oid: None,
        }
    }
}

static SERVER_METRICS_REGISTRY: OnceLock<dashmap::DashMap<String, Arc<ServerMetrics>>> =
    OnceLock::new();

fn metrics_registry() -> &'static dashmap::DashMap<String, Arc<ServerMetrics>> {
    SERVER_METRICS_REGISTRY.get_or_init(dashmap::DashMap::new)
}

mod resilience;
pub use resilience::{CachedDescriptorPool, LbStrategy, RouteTarget, UpstreamNode};
use resilience::update_ema_ms;

/// Lock-free per-server operational and security counters (`Ordering::Relaxed`).
#[derive(Debug, Default)]
pub struct ServerMetrics {
    /// Total HTTP/gRPC requests received by this server instance.
    pub total_requests: std::sync::atomic::AtomicU64,
    /// Active TCP/QUIC/Tunnel connections currently tracked by `ConnectionTracker`.
    pub active_connections: std::sync::atomic::AtomicUsize,
    /// Connections dropped because the global connection limit was reached.
    pub connections_rejected_global: std::sync::atomic::AtomicU64,
    /// Connections dropped because the per-IP connection limit was reached.
    pub connections_rejected_ip: std::sync::atomic::AtomicU64,
    /// Requests blocked by `IpFilterLayer` (`403 Forbidden`).
    pub blocked_ip_filter: std::sync::atomic::AtomicU64,
    /// Requests blocked by `InspectionLayer` (`403 Forbidden`).
    pub blocked_inspection: std::sync::atomic::AtomicU64,
    /// Requests blocked by `PathSanitizerLayer` or router URI canonicalization (`400 Bad Request`).
    pub blocked_path_sanitizer: std::sync::atomic::AtomicU64,
    /// Requests rejected by `JwtAuthLayer` (`401 Unauthorized` / `302 Redirect`).
    pub blocked_jwt_auth: std::sync::atomic::AtomicU64,
    /// Requests rejected by `CompiledRbac` or route-level RBAC (`403 Forbidden`).
    pub blocked_auth_rbac: std::sync::atomic::AtomicU64,
    /// Requests shed by `SimpleRateLimiter` or `TokenBucketRateLimiter` (`429`).
    pub rate_limited: std::sync::atomic::AtomicU64,
    /// Requests shed or timed out by `ConcurrencyLimitLayer` (`503`).
    pub concurrency_limited: std::sync::atomic::AtomicU64,
    /// Requests rejected by `MaxPayloadLayer` (`413`).
    pub payload_too_large: std::sync::atomic::AtomicU64,
    /// Compressed request streams aborted by `SrvDecompressionLayer` bomb protection.
    pub decompression_limit_exceeded: std::sync::atomic::AtomicU64,
    /// Completed responses with HTTP `2xx` status.
    pub responses_2xx: std::sync::atomic::AtomicU64,
    /// Completed responses with HTTP `3xx` status.
    pub responses_3xx: std::sync::atomic::AtomicU64,
    /// Completed responses with HTTP `4xx` status.
    pub responses_4xx: std::sync::atomic::AtomicU64,
    /// Completed responses with HTTP `5xx` status.
    pub responses_5xx: std::sync::atomic::AtomicU64,
    /// Most recent observed request latency in milliseconds.
    pub last_response_ms: std::sync::atomic::AtomicU64,
    /// Exponential moving average request latency in milliseconds.
    pub ema_response_ms: std::sync::atomic::AtomicU64,
}

impl ServerMetrics {
    /// Returns (or creates) the shared `Arc<ServerMetrics>` for `server_name`.
    pub fn for_server(server_name: &str) -> Arc<Self> {
        if let Some(existing) = metrics_registry().get(server_name) {
            return existing.value().clone();
        }
        metrics_registry()
            .entry(server_name.to_string())
            .or_insert_with(|| Arc::new(Self::default()))
            .value()
            .clone()
    }

    #[inline]
    pub fn inc_total_requests(server_name: &str) {
        Self::for_server(server_name)
            .total_requests
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_blocked_ip_filter(server_name: &str) {
        Self::for_server(server_name)
            .blocked_ip_filter
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_blocked_inspection(server_name: &str) {
        Self::for_server(server_name)
            .blocked_inspection
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_blocked_path_sanitizer(server_name: &str) {
        Self::for_server(server_name)
            .blocked_path_sanitizer
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_blocked_jwt_auth(server_name: &str) {
        Self::for_server(server_name)
            .blocked_jwt_auth
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_blocked_auth_rbac(server_name: &str) {
        Self::for_server(server_name)
            .blocked_auth_rbac
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_rate_limited(server_name: &str) {
        Self::for_server(server_name)
            .rate_limited
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_concurrency_limited(server_name: &str) {
        Self::for_server(server_name)
            .concurrency_limited
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_payload_too_large(server_name: &str) {
        Self::for_server(server_name)
            .payload_too_large
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[inline]
    pub fn inc_decompression_limit_exceeded(server_name: &str) {
        Self::for_server(server_name)
            .decompression_limit_exceeded
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Records the HTTP status class and end-to-end latency for a completed response.
    #[inline]
    pub fn record_response(server_name: &str, status_code: u16, latency_ms: u64) {
        let metrics = Self::for_server(server_name);
        match status_code {
            200..=299 => {
                metrics
                    .responses_2xx
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            300..=399 => {
                metrics
                    .responses_3xx
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            400..=499 => {
                metrics
                    .responses_4xx
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            500..=599 => {
                metrics
                    .responses_5xx
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            _ => {}
        }
        update_ema_ms(&metrics.last_response_ms, &metrics.ema_response_ms, latency_ms);
    }
}

/// Cached X.509 certificate and CRL expiration metadata extracted during [`ServerConfig::finalize`].
#[derive(Debug, Clone, Default)]
pub struct ServerPkiInfo {
    /// UNIX timestamp (seconds) when the server's leaf TLS certificate expires (`notAfter`).
    pub server_cert_valid_until_unix: Option<i64>,
    /// UNIX timestamp (seconds) of the earliest `nextUpdate` across configured client CRLs.
    pub crl_next_update_unix: Option<i64>,
    /// Total number of revoked certificate serials across configured client CRLs.
    pub crl_revoked_certs_count: usize,
}

// ============================================================================
//  Supporting Structures
// ============================================================================

/// Parameters for the StaticFiles service.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct StaticFilesParams {
    /// The root directory to serve files from.
    pub root: String,
    /// If true, requests to missing files will fallback to serving index.html (useful for SPAs).
    #[serde(default)]
    pub fallback_to_index: bool,
}

/// A single reverse-proxy route definition from the TOML config.
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    /// The upstream backend addresses (e.g. `["127.0.0.1:8080", "127.0.0.1:8081"]`).
    /// Can be omitted or empty (`[]`) when `backend_type = "admin"` or `"aggregate"`.
    #[serde(default)]
    pub upstreams: Vec<String>,
    /// The load balancing strategy to use for this route.
    #[serde(default)]
    pub strategy: LbStrategy,
    /// Roles permitted to access this route. Empty means unrestricted.
    #[serde(default)]
    pub allowed_roles: Vec<UserRole>,
    /// How many seconds a node stays dead after a connection failure. Defaults to 10.
    pub cooldown_seconds: Option<u64>,
    /// Maximum number of automatic retries on another node. Defaults to 2.
    pub max_retries: Option<usize>,
    /// Number of consecutive upstream 502/503/504 outlier responses before opening the circuit breaker. Defaults to 3.
    pub failure_threshold: Option<usize>,
    /// Maximum request body size (in bytes) buffered in RAM for automatic retries.
    /// Payloads exceeding this threshold stream directly without retry buffering. Defaults to 65536 (64 KiB).
    pub max_retry_buffer_bytes: Option<usize>,
    /// Interval in seconds for actively polling the /health endpoint of upstreams. Defaults to 0 (disabled).
    pub active_health_check_interval: Option<u64>,
    /// The type of backend this route proxies to (`rest`, `grpc_passthrough`, `grpc_transcoding`, `admin`, or `aggregate`). Defaults to `rest`.
    #[serde(default)]
    pub backend_type: RouteBackendType,
    /// Sub-requests for fan-out aggregation when `backend_type = "aggregate"`.
    #[serde(default)]
    pub targets: Vec<AggregateTargetConfig>,
    /// How incoming `POST` bodies are distributed across fan-out targets (`keyed` or `broadcast`).
    /// Defaults to `keyed` (fail-closed: each target only receives `body[target.key]`).
    #[serde(default)]
    pub payload_mode: AggregatePayloadMode,
    /// Whether raw upstream error response bodies may be reflected to clients on `aggregate` routes.
    /// Defaults to `false` (only sanitized HTTP reason phrases are returned; details go to server logs).
    #[serde(default)]
    pub expose_upstream_errors: bool,
    /// Optional overall deadline in milliseconds for completing an `aggregate` route fan-out.
    /// When exceeded, unfinished optional targets degrade to `504` in `_errors`; unfinished
    /// required targets abort the route with `504 Gateway Timeout`.
    pub deadline_ms: Option<u64>,
    /// Maximum incoming request body size in bytes buffered in RAM for buffered-only routes
    /// (`grpc_transcoding` and `aggregate`). Defaults to 4 MiB.
    pub max_request_bytes: Option<usize>,
    /// Maximum response bytes buffered in RAM for `grpc_transcoding` routes or cumulatively
    /// across all sub-targets of an `aggregate` route. Defaults to 4 MiB.
    pub max_response_bytes: Option<usize>,
    /// Strip client-supplied `Authorization` header before forwarding to upstream (default: `true`).
    /// Note that `[Server.RouterParams].jwt` always overrides `Authorization` if configured.
    pub strip_authorization: Option<bool>,
    /// Explicit opt-in to forward the client's `Authorization` header to upstream (default: `false`).
    pub forward_authorization: Option<bool>,
    /// Strip the entire client `Cookie` header before forwarding to upstream (default: `true` unless
    /// `strip_cookie_names` is non-empty or `"cookie"` is listed in `forward_headers`).
    pub strip_cookies: Option<bool>,
    /// Specific cookie names to strip from incoming `Cookie` headers while keeping other cookies
    /// (implies `strip_cookies = false` if `strip_cookies` is omitted).
    #[serde(default)]
    pub strip_cookie_names: Vec<String>,
    /// Optional explicit allowlist of client header names forwarded to sensitive upstreams
    /// (e.g. `["content-type", "accept", "x-request-id"]`). Case-insensitive.
    /// Hop-by-hop and identity-spoofing headers are always stripped; essential HTTP/gRPC wire
    /// framing headers and Praeco-injected headers remain preserved.
    #[serde(default)]
    pub forward_headers: Option<Vec<String>>,
}

/// Default maximum request body size buffered in RAM for `grpc_transcoding` and `aggregate` routes (4 MiB).
pub const DEFAULT_MAX_BUFFERED_REQUEST_BYTES: usize = 4 * 1024 * 1024;
/// Default maximum response size buffered in RAM for `grpc_transcoding` and `aggregate` routes (4 MiB).
pub const DEFAULT_MAX_AGGREGATE_RESPONSE_BYTES: usize = 4 * 1024 * 1024;

/// Controls how incoming `POST` request bodies are distributed across fan-out targets
/// on an `aggregate` route.
#[derive(Debug, Deserialize, Clone, Copy, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AggregatePayloadMode {
    /// Each target receives strictly `body[target.key]`. Targets whose key is absent
    /// receive `{}` (never sibling target payloads), and unknown top-level keys are
    /// rejected with `400 Bad Request`.
    #[default]
    Keyed,
    /// Every target receives the full incoming request body unchanged.
    Broadcast,
}

/// Configuration for a single fan-out target within an `aggregate` route.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AggregateTargetConfig {
    /// JSON key under which this target's response is placed in the aggregated object.
    pub key: String,
    /// Backend protocol for this sub-request (`rest` or `grpc_transcoding`). Defaults to `rest`.
    #[serde(default)]
    pub backend_type: RouteBackendType,
    /// Upstream backend addresses for this target.
    #[serde(default)]
    pub upstreams: Vec<String>,
    /// Target URI path (e.g. `"/v1/notifications"` for REST or `"/pkg.Service/Method"` for gRPC).
    pub path: String,
    /// Optional HTTP method override for REST sub-requests (gRPC transcoding always uses `POST`).
    pub method: Option<String>,
    /// Whether failure of this target aborts the entire aggregated request (default: `true`).
    /// When `false`, failures set `"<key>": null` and add an entry under `"_errors"`.
    #[serde(default = "default_true")]
    pub required: bool,
    /// Optional allowlist of client query parameter names forwarded to this target.
    /// When omitted (`None`), all client query params *not* already pinned in `path` are forwarded.
    /// When `Some([])`, no client query params are forwarded. Operator-pinned params in `path` always take precedence.
    #[serde(default)]
    pub forward_query: Option<Vec<String>>,
    /// Client credential header names explicitly permitted to be forwarded to this target
    /// (e.g. `["authorization"]` or `["cookie"]`). Case-insensitive. Defaults to `[]` (credentials stripped).
    #[serde(default)]
    pub forward_headers: Vec<String>,
    /// Optional per-target timeout in milliseconds (overrides router `request_timeout_seconds` for this target).
    pub timeout_ms: Option<u64>,
    /// Load balancing strategy for this target's upstreams.
    #[serde(default)]
    pub strategy: LbStrategy,
    /// How many seconds a node stays dead after a connection failure. Defaults to 10.
    pub cooldown_seconds: Option<u64>,
    /// Maximum number of automatic retries on another node. Defaults to 2.
    pub max_retries: Option<usize>,
    /// Number of consecutive upstream 502/503/504 outlier responses before opening the circuit breaker. Defaults to 3.
    pub failure_threshold: Option<usize>,
    /// Maximum request body size (in bytes) buffered in RAM for automatic retries. Defaults to 65536.
    pub max_retry_buffer_bytes: Option<usize>,
    /// Interval in seconds for actively polling the health endpoint of upstreams. Defaults to 0 (disabled).
    pub active_health_check_interval: Option<u64>,
}

/// The type of backend service being routed to.
#[derive(Debug, Deserialize, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RouteBackendType {
    /// Standard HTTP/REST backend (default).
    #[default]
    Rest,
    /// Native gRPC transparent proxying. HTTP/2 is forced to the backend.
    GrpcPassthrough,
    /// gRPC backend with automatic JSON-to-Protobuf transcoding.
    #[serde(alias = "grpc")]
    GrpcTranscoding,
    /// Internal Praeco Admin & Telemetry handler (`status`, `upstreams`, `metrics`, `healthz`).
    #[serde(alias = "praeco_admin")]
    Admin,
    /// Parallel fan-out aggregator across multiple REST and gRPC-transcoding backends.
    #[serde(alias = "fanout")]
    Aggregate,
}

/// A compiled fan-out sub-target within an aggregate [`ParsedRoute`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ParsedAggregateTarget {
    /// Output JSON field name (and optional input payload sub-key).
    pub key: String,
    /// Pre-serialized JSON object key prefix (`"\"<escaped_key>\":"`) for zero-copy response assembly.
    pub json_key_prefix: Bytes,
    /// Sub-request backend protocol (`Rest` or `GrpcTranscoding`).
    pub backend_type: RouteBackendType,
    /// Load-balanced upstream pool and circuit breaker for this sub-target.
    pub target: Arc<RouteTarget>,
    /// Parsed target path and optional query string (e.g. `"/pkg.Service/Method"` or `"/v1/items"`).
    pub target_uri: Uri,
    /// Pre-parsed query parameter names pinned in `target_uri` (operator precedence over client query).
    pub pinned_query_keys: HashSet<String>,
    /// Optional HTTP method override for REST sub-requests.
    pub method: Option<Method>,
    /// Whether failure of this sub-target aborts the whole aggregated response.
    pub required: bool,
    /// Optional allowlist of client query parameter names forwarded to this sub-target.
    pub forward_query: Option<HashSet<String>>,
    /// Lowercased client credential header names explicitly allowed to be forwarded to this sub-target.
    pub forward_headers: HashSet<String>,
    /// Optional per-target timeout in milliseconds.
    pub timeout_ms: Option<u64>,
}

/// Compiled per-route upstream header sanitization and credential policy (`S-05`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteHeaderPolicy {
    /// Strip client-supplied `Authorization` header unless `[Server.RouterParams].jwt` injects one.
    pub strip_authorization: bool,
    /// Strip the entire client `Cookie` header.
    pub strip_cookies: bool,
    /// Specific cookie names stripped from incoming `Cookie` headers when `strip_cookies` is `false`.
    /// Automatically includes `[Server.Layers.JWT].cookie_fallback` when configured.
    pub strip_cookie_names: HashSet<String>,
    /// Optional explicit allowlist of lowercased client header names permitted through to the upstream.
    pub forward_headers: Option<HashSet<String>>,
    /// For `aggregate` routes: whether any sub-target explicitly opted into forwarding `authorization`
    /// via `sub_target.forward_headers`.
    pub preserve_authorization_for_subtargets: bool,
    /// For `aggregate` routes: whether any sub-target explicitly opted into forwarding `cookie`
    /// via `sub_target.forward_headers`.
    pub preserve_cookies_for_subtargets: bool,
}

impl Default for RouteHeaderPolicy {
    fn default() -> Self {
        Self {
            strip_authorization: true,
            strip_cookies: true,
            strip_cookie_names: HashSet::new(),
            forward_headers: None,
            preserve_authorization_for_subtargets: false,
            preserve_cookies_for_subtargets: false,
        }
    }
}

/// A processed reverse-proxy route ready for use by the router.
///
/// Created from [`RouteConfig`] during [`ServerConfig::finalize`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ParsedRoute {
    /// The path prefix that triggers this route (e.g. `"/api"`).
    pub prefix: String,
    /// The load-balanced target composed of upstreams and a strategy.
    pub target: Arc<RouteTarget>,
    /// Roles permitted to access this route.
    pub allowed_roles: Vec<UserRole>,
    /// The type of backend (rest, grpc, admin, or aggregate).
    pub backend_type: RouteBackendType,
    /// Fan-out sub-targets populated when `backend_type == RouteBackendType::Aggregate`.
    pub aggregate_targets: Vec<Arc<ParsedAggregateTarget>>,
    /// Payload distribution mode for `aggregate` routes (`Keyed` or `Broadcast`).
    pub aggregate_payload_mode: AggregatePayloadMode,
    /// Whether raw upstream error texts may be exposed to clients on `aggregate` routes.
    pub expose_upstream_errors: bool,
    /// Optional overall deadline in milliseconds for `aggregate` routes.
    pub aggregate_deadline_ms: Option<u64>,
    /// Maximum incoming request body size buffered in RAM for buffered-only routes.
    pub max_request_bytes: usize,
    /// Maximum cumulative response bytes buffered across all sub-targets of an `aggregate` route.
    pub max_response_bytes: usize,
    /// Compiled header & credential sanitization policy for upstream forwarding (`S-05`).
    pub header_policy: RouteHeaderPolicy,
}

impl ParsedRoute {
    /// Iterates over all active backend targets owned by this route without allocating.
    ///
    /// For regular single-target routes this yields one entry `(None, &self.backend_type, &self.target)`;
    /// for [`RouteBackendType::Aggregate`] routes it yields one entry
    /// `(Some(sub.key.as_str()), &sub.backend_type, &sub.target)` per configured sub-target.
    pub fn iter_targets(
        &self,
    ) -> impl Iterator<Item = (Option<&str>, &RouteBackendType, &Arc<RouteTarget>)> {
        let is_aggregate = self.backend_type == RouteBackendType::Aggregate;
        let single = (!is_aggregate).then_some((None, &self.backend_type, &self.target));
        let aggregate = is_aggregate
            .then(|| {
                self.aggregate_targets
                    .iter()
                    .map(|sub| (Some(sub.key.as_str()), &sub.backend_type, &sub.target))
            })
            .into_iter()
            .flatten();
        single.into_iter().chain(aggregate)
    }
}

// --- Middleware Layer Structures ---

/// Represents the various middleware layers that can be applied to a service.
///
/// Each variant corresponds to a string in the `[Layers].enabled` TOML list
/// and may carry configuration data extracted from sibling TOML sections.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum MiddlewareLayer {
    /// Injects a Trace ID into requests for observability.
    TraceId,
    /// Tracks request/response timing.
    Timing,
    /// Counts the number of requests.
    Counter,
    /// Logs request and response details.
    Logger,
    /// Inspects request paths against allowed regex patterns.
    Inspection,
    /// Compresses response bodies.
    Compression,
    /// Decompresses request bodies (with max decompressed size limit in bytes).
    Decompression(usize),
    /// Limits the rate of incoming requests.
    RateLimiter(RateLimiter),
    /// Introduces a fixed delay (in microseconds) before processing requests.
    Delay(u64),
    /// Authenticates requests using JWT tokens (carries full config including public keys and cookie fallback).
    JwtAuth(JwtAuthConfig),
    /// Limits the number of concurrent requests.
    ConcurrencyLimit(ConcurrencyLimitConfig),
    /// Limits the maximum size of request payloads (in bytes).
    MaxPayload(usize),
    /// Adds an Alt-Svc header to the response.
    AltSvc,
    /// Adds CORS headers to responses and handles preflight requests.
    Cors(CorsConfig),
    /// Adds security headers to responses.
    SecurityHeaders(SecurityHeadersConfig),
    /// Enforces RFC 3986 path canonicalization and rejects traversal / illegal encodings.
    PathSanitizer,
    /// Enforces IPv4 / IPv6 CIDR allowlist and blocklist rules.
    IpFilter(IpFilterConfig),
}

/// Rate limiter algorithm selection.
#[derive(Debug, Clone)]
pub enum RateLimiter {
    /// Fixed-window rate limiter.
    Simple(SimpleRateLimiterConfig),
    /// Token-bucket rate limiter.
    TokenBucket(TokenBucketRateLimiterConfig),
}

/// Container for the ordered list of enabled layers and their per-layer
/// configuration sections.
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct Layers {
    /// Ordered list of layer names. The order defines the middleware
    /// wrapping order (first entry = outermost layer).
    pub enabled: Vec<String>,
    /// Configuration for the [`MaxPayload`](MiddlewareLayer::MaxPayload) layer.
    #[serde(rename = "MaxPayload")]
    pub max_payload_config: Option<MaxPayloadConfig>,
    /// Configuration for the [`Decompression`](MiddlewareLayer::Decompression) layer.
    #[serde(rename = "Decompression")]
    pub decompression_config: Option<DecompressionConfig>,
    /// Configuration for the simple fixed-window rate limiter.
    #[serde(rename = "RateLimiter")]
    pub rate_limiter_config: Option<SimpleRateLimiterConfig>,
    /// Configuration for the token-bucket rate limiter.
    #[serde(rename = "TokenBucketRateLimiter")]
    pub token_bucket_config: Option<TokenBucketRateLimiterConfig>,
    /// Configuration for the [`Delay`](MiddlewareLayer::Delay) layer.
    #[serde(rename = "Delay")]
    pub delay_config: Option<DelayConfig>,
    /// Configuration for the [`JwtAuth`](MiddlewareLayer::JwtAuth) layer.
    #[serde(rename = "JWT")]
    pub jwt_config: Option<JwtAuthConfig>,
    /// Configuration for the [`ConcurrencyLimit`](MiddlewareLayer::ConcurrencyLimit) layer.
    #[serde(rename = "ConcurrencyLimit")]
    pub concurrency_limit_config: Option<ConcurrencyLimitConfig>,
    /// Configuration for the [`Cors`](MiddlewareLayer::Cors) layer.
    #[serde(rename = "Cors")]
    pub cors_config: Option<CorsConfig>,
    /// Configuration for the [`SecurityHeaders`](MiddlewareLayer::SecurityHeaders) layer.
    #[serde(rename = "SecurityHeaders")]
    pub security_headers_config: Option<SecurityHeadersConfig>,
    /// Configuration for the [`IpFilter`](MiddlewareLayer::IpFilter) layer.
    #[serde(rename = "IpFilter")]
    pub ip_filter_config: Option<IpFilterConfig>,
}

// --- Helper Structures for Configuration ---

/// Configuration for the maximum payload size enforcement layer.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct MaxPayloadConfig {
    /// Maximum allowed request body size in bytes.
    pub max_bytes: usize,
}

/// Configuration for the decompression layer's bomb protection.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DecompressionConfig {
    /// Maximum allowed size of the decompressed request body in bytes.
    pub max_decompressed_bytes: usize,
}

fn default_connect_timeout_seconds() -> u64 {
    5
}

fn default_request_timeout_seconds() -> u64 {
    30
}

fn default_idle_timeout_seconds() -> u64 {
    90
}

fn default_grpc_reflection_timeout_seconds() -> u64 {
    10
}

fn default_grpc_reflection_ttl_seconds() -> u64 {
    600
}

/// Parameters for the reverse-proxy router's upstream connections.
///
/// Controls how the router communicates with backend services (protocol,
/// TLS settings, authentication).
#[derive(Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct RouterParams {
    /// Protocol for upstream connections (HTTP or HTTPS).
    #[serde(default)]
    pub protocol: Protocol,
    /// Authentication method for upstream connections.
    #[serde(default)]
    pub authentication: AuthenticationMethod,
    /// Path to the root CA certificate for verifying upstream TLS.
    pub ssl_root_certificate: Option<String>,
    /// Path to a JWT token file or bearer token for upstream authentication.
    pub jwt: Option<String>,
    /// Path to the client certificate for upstream mTLS.
    pub ssl_client_certificate: Option<String>,
    /// Path to the client private key for upstream mTLS.
    pub ssl_client_key: Option<String>,
    /// Connect timeout in seconds for upstream connections (default: 5).
    #[serde(default = "default_connect_timeout_seconds")]
    pub connect_timeout_seconds: u64,
    /// Request timeout in seconds for upstream response headers (default: 30).
    #[serde(default = "default_request_timeout_seconds")]
    pub request_timeout_seconds: u64,
    /// Pool idle connection timeout in seconds (default: 90).
    #[serde(default = "default_idle_timeout_seconds")]
    pub idle_timeout_seconds: u64,
    /// gRPC reflection schema fetch timeout in seconds (default: 10).
    #[serde(default = "default_grpc_reflection_timeout_seconds")]
    pub grpc_reflection_timeout_seconds: u64,
    /// gRPC reflection schema cache TTL in seconds (default: 600 / 10 mins).
    #[serde(default = "default_grpc_reflection_ttl_seconds")]
    pub grpc_reflection_ttl_seconds: u64,
}

impl std::fmt::Debug for RouterParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RouterParams")
            .field("protocol", &self.protocol)
            .field("authentication", &self.authentication)
            .field("ssl_root_certificate", &self.ssl_root_certificate)
            .field("jwt", &self.jwt.as_ref().map(|_| "<redacted>"))
            .field("ssl_client_certificate", &self.ssl_client_certificate)
            .field("ssl_client_key", &self.ssl_client_key)
            .field("connect_timeout_seconds", &self.connect_timeout_seconds)
            .field("request_timeout_seconds", &self.request_timeout_seconds)
            .field("idle_timeout_seconds", &self.idle_timeout_seconds)
            .field(
                "grpc_reflection_timeout_seconds",
                &self.grpc_reflection_timeout_seconds,
            )
            .field(
                "grpc_reflection_ttl_seconds",
                &self.grpc_reflection_ttl_seconds,
            )
            .finish()
    }
}

/// Parameters for the Identity Provider (IdP) service.
///
/// Controls how the IdP issues tokens and manages sessions.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct IdpParams {
    /// Path to the Ed25519 private key used to sign issued JWTs.
    pub jwt_private_key: String,
    /// Expiration time for issued tokens in seconds (default: 900 / 15 mins).
    #[serde(default = "default_token_expiry")]
    pub token_expiry_seconds: u64,
    /// Time-to-live for QR code login sessions in seconds (default: 120).
    #[serde(default = "default_session_ttl")]
    pub session_ttl_seconds: u64,
    /// Name of the cookie to set for the issued JWT (default: "__Host-jwt").
    #[serde(default = "default_cookie_name")]
    pub cookie_name: String,
    /// Optional domain for the cookie to allow sharing across subdomains (e.g. ".aweirich.eu").
    pub cookie_domain: Option<String>,
    /// Default redirect path after successful login if no `redirect` param is present.
    #[serde(default = "default_redirect")]
    pub redirect_after_login: String,
    /// If true, displays the session ID on the web UI for testing purposes.
    pub debug_show_session_id: Option<bool>,
    /// The issuer claim (`iss`) for generated JWTs. (default: "praeco-idp")
    #[serde(default = "default_issuer")]
    pub issuer: String,
    /// Optional allowed audiences (`aud`). If requested by client, it must be in this list.
    #[serde(default)]
    pub allowed_audiences: Vec<String>,
    /// Optional path to the Ed25519 public key. If provided, exposed at /.well-known/jwks.json.
    pub jwt_public_key: Option<String>,

    // --- Webhook Configuration ---

    /// Optional URL for dynamic claims resolution via HTTP webhook.
    /// If set, the IdP will POST to this URL to fetch current user roles.
    pub claims_webhook_url: Option<String>,
    /// Timeout for the webhook HTTP call in milliseconds (default: 3000).
    #[serde(default = "default_webhook_timeout")]
    pub claims_webhook_timeout_ms: u64,
    /// Behavior when the webhook call fails ("fallback_to_cert" or "reject").
    #[serde(default = "default_on_webhook_failure")]
    pub on_webhook_failure: String,
    /// Path to client certificate PEM for mTLS authentication to the webhook endpoint.
    pub claims_webhook_client_cert: Option<String>,
    /// Path to client private key for mTLS authentication to the webhook endpoint.
    pub claims_webhook_client_key: Option<String>,
    /// Path to CA certificate for verifying the webhook endpoint's server certificate.
    pub claims_webhook_ca_cert: Option<String>,
}

fn default_token_expiry() -> u64 { 900 }
fn default_session_ttl() -> u64 { 120 }
fn default_cookie_name() -> String { "__Host-jwt".to_string() }
fn default_redirect() -> String { "/".to_string() }
fn default_issuer() -> String { "praeco-idp".to_string() }
fn default_webhook_timeout() -> u64 { 3000 }
fn default_on_webhook_failure() -> String { "reject".to_string() }

/// Validates RFC 6265 cookie name token syntax (RFC 7230 `tchar`: no CTLs, whitespace, or separators).
fn is_valid_rfc6265_cookie_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// Validates RFC 6265 `Domain` attribute syntax (optional leading dot + DNS hostname or IP literal).
fn is_valid_cookie_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return false;
    }
    if domain.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    let host = domain.strip_prefix('.').unwrap_or(domain);
    if host.is_empty() || host.len() > 253 || host.ends_with('.') {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}

/// Validates `IdpParams.redirect_after_login`: must be a relative path starting with `/` (not `//`)
/// or an explicit `http://` / `https://` URL without control characters or backslashes (`S-07`).
fn is_valid_redirect_after_login(redirect: &str) -> bool {
    if redirect.is_empty() || redirect.chars().any(|c| c.is_control()) || redirect.contains('\\') {
        return false;
    }
    if redirect.starts_with('/') {
        return !redirect.starts_with("//");
    }
    let Ok(parsed) = url::Url::parse(redirect) else {
        return false;
    };
    matches!(parsed.scheme(), "http" | "https") && parsed.has_host()
}

/// Validates IdP cookie attributes and `redirect_after_login` at startup (`S-07`).
pub(crate) fn validate_idp_cookie_and_redirect(
    params: &IdpParams,
    server_name: &str,
) -> Result<(), Error> {
    if !is_valid_rfc6265_cookie_name(&params.cookie_name) {
        return Err(Error::msg(format!(
            "Configuration error in Server '{}': IdpParams.cookie_name '{}' is not a valid RFC 6265 cookie token.",
            server_name, params.cookie_name
        )));
    }
    if let Some(domain) = &params.cookie_domain
        && !is_valid_cookie_domain(domain)
    {
        return Err(Error::msg(format!(
            "Configuration error in Server '{}': IdpParams.cookie_domain '{}' is not a valid cookie domain or IP.",
            server_name, domain
        )));
    }
    if !is_valid_redirect_after_login(&params.redirect_after_login) {
        return Err(Error::msg(format!(
            "Configuration error in Server '{}': IdpParams.redirect_after_login '{}' must be a safe relative path starting with '/' (not '//') or an http(s) URL.",
            server_name, params.redirect_after_login
        )));
    }
    Ok(())
}


/// Server TLS certificate and key paths.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ServerCertConfig {
    /// Path to the PEM-encoded server certificate chain.
    pub ssl_certificate: String,
    /// Path to the PEM-encoded server private key.
    pub ssl_certificate_key: String,
}

fn default_strict_crl() -> bool {
    true
}

/// Client CA certificate configuration for mTLS.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ClientCertConfig {
    /// Path to the PEM-encoded client CA certificate.
    pub ssl_client_ca: String,
    /// Optional path to a PEM-encoded Certificate Revocation List.
    pub ssl_client_crl: Option<String>,
    /// Enforce strict CRL validation (reject expired/malformed/missing-nextUpdate CRLs
    /// and enforce `nextUpdate` expiration at TLS handshake time). Defaults to `true` (fail-closed).
    #[serde(default = "default_strict_crl")]
    pub strict_crl: bool,
}

/// Configuration for client certificate forwarding.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ClientCertForwardingConfig {
    /// The HTTP header name used to forward the full URL-encoded client certificate.
    pub header_cert: Option<String>,
    /// The HTTP header name used to forward the client certificate's SAN (Subject Alternative Name).
    pub header_san: Option<String>,
    /// The HTTP header name used to forward the mapped user roles (e.g., 'x-user-roles').
    pub header_roles: Option<String>,
    /// The HTTP header name used to forward the client's IP address (e.g., 'x-forwarded-for').
    pub header_client_ip: Option<String>,
}

/// Keying strategy for rate limiting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitKeyStrategy {
    /// Keys requests by authenticated identity (JWT sub or mTLS SAN), falling back to client IP.
    #[default]
    Identity,
    /// Keys requests strictly by client IP.
    Ip,
    /// Shared global rate limiter across the whole server route.
    Global,
}

fn default_max_entries() -> usize {
    10_000
}

fn default_ttl_seconds() -> u64 {
    300
}

fn default_trusted_proxy_hops() -> usize {
    1
}

fn default_load_shed() -> bool {
    true
}

/// Configuration for the simple fixed-window rate limiter.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct SimpleRateLimiterConfig {
    /// Maximum number of requests per second.
    pub requests_per_second: u64,
    /// Keying strategy: "identity", "ip", or "global" (default: "identity").
    #[serde(default)]
    pub key_by: RateLimitKeyStrategy,
    /// Maximum number of tracking entries in memory before pruning (default: 10,000).
    #[serde(default = "default_max_entries")]
    pub max_entries: usize,
    /// Entry idle TTL in seconds before pruning (default: 300).
    #[serde(default = "default_ttl_seconds")]
    pub ttl_seconds: u64,
    /// Whether to trust `X-Forwarded-For` / `X-Real-IP` headers when socket IP is unspecified (default: false).
    #[serde(default)]
    pub trust_forwarded_headers: bool,
    /// Number of trusted reverse-proxy hops counted from the right of `X-Forwarded-For` (default: 1).
    /// Set to `0` to ignore `X-Forwarded-For` completely.
    #[serde(default = "default_trusted_proxy_hops")]
    pub trusted_proxy_hops: usize,
}

/// Configuration for the token-bucket rate limiter.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct TokenBucketRateLimiterConfig {
    /// Maximum number of tokens the bucket can hold.
    pub max_capacity: usize,
    /// Number of tokens added per refill interval.
    pub refill: usize,
    /// Refill interval in microseconds.
    pub duration_micros: u64,
    /// Keying strategy: "identity", "ip", or "global" (default: "identity").
    #[serde(default)]
    pub key_by: RateLimitKeyStrategy,
    /// Maximum number of tracking entries in memory before pruning (default: 10,000).
    #[serde(default = "default_max_entries")]
    pub max_entries: usize,
    /// Entry idle TTL in seconds before pruning (default: 300).
    #[serde(default = "default_ttl_seconds")]
    pub ttl_seconds: u64,
    /// Whether to trust `X-Forwarded-For` / `X-Real-IP` headers when socket IP is unspecified (default: false).
    #[serde(default)]
    pub trust_forwarded_headers: bool,
    /// Number of trusted reverse-proxy hops counted from the right of `X-Forwarded-For` (default: 1).
    /// Set to `0` to ignore `X-Forwarded-For` completely.
    #[serde(default = "default_trusted_proxy_hops")]
    pub trusted_proxy_hops: usize,
}

/// Configuration for the artificial delay layer.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct DelayConfig {
    /// Delay duration in microseconds.
    pub delay_micros: u64,
}

fn default_require_jti() -> bool {
    true
}

fn default_max_token_lifetime_seconds() -> u64 {
    common::DEFAULT_MAX_JWT_LIFETIME_SECS
}

/// Configuration for the JWT authentication layer.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct JwtAuthConfig {
    /// List of file paths to PEM-encoded Ed25519 public keys.
    pub jwt_public_keys: Vec<String>,
    /// Optional cookie name to extract the JWT from if the Authorization header is missing.
    pub cookie_fallback: Option<String>,
    /// Optional redirect URL if authentication fails (useful for redirecting to the IdP).
    pub redirect_on_failure: Option<String>,
    /// The expected issuer (`iss`) to validate against. This is mandatory.
    pub expected_issuer: String,
    /// The expected audience (`aud`) to validate against. This is mandatory.
    pub expected_audience: String,
    /// Optional list of request paths (e.g. `["/api/Logout"]`) on which a valid JWT's `jti`
    /// is automatically added to the global [`JwtRevocationStore`](crate::middleware::JwtRevocationStore)
    /// while still forwarding the request to the upstream backend.
    #[serde(default)]
    pub revoke_on_paths: Vec<String>,
    /// Whether incoming JWTs must contain a non-empty `jti` claim (default: `true`).
    /// Enforcing `jti` ensures tokens can be revoked via the `jti` denylist.
    #[serde(default = "default_require_jti")]
    pub require_jti: bool,
    /// Maximum allowed remaining token lifetime (`exp - now`) in seconds (default: `2_592_000` / 30 days).
    /// Set to `0` to disable the upper lifetime bound.
    #[serde(default = "default_max_token_lifetime_seconds")]
    pub max_token_lifetime_seconds: u64,
}

fn default_max_connections() -> usize {
    10_000
}

fn default_max_connections_per_ip() -> usize {
    100
}

/// Configuration for server connection limits (global and per-IP).
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConnectionLimitsConfig {
    /// Maximum number of concurrent connections across the entire server instance (default: 10,000).
    #[serde(default = "default_max_connections")]
    pub max_connections: usize,

    /// Maximum number of concurrent connections from a single IP address (default: 100).
    #[serde(default = "default_max_connections_per_ip")]
    pub max_connections_per_ip: usize,
}

impl Default for ConnectionLimitsConfig {
    fn default() -> Self {
        Self {
            max_connections: default_max_connections(),
            max_connections_per_ip: default_max_connections_per_ip(),
        }
    }
}

/// Configuration for the concurrency limit layer.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ConcurrencyLimitConfig {
    /// Maximum number of in-flight requests.
    pub max_concurrent_requests: usize,
    /// Whether to fail fast (503 Service Unavailable) when at capacity (default: true).
    #[serde(default = "default_load_shed")]
    pub load_shed: bool,
    /// Optional queue timeout in milliseconds if load_shed is false.
    pub queue_timeout_ms: Option<u64>,
}

/// Configuration for the CORS layer.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct CorsConfig {
    /// List of allowed origins. Use `["*"]` to allow all.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// List of allowed HTTP methods.
    #[serde(default)]
    pub allowed_methods: Vec<String>,
    /// List of allowed HTTP headers.
    #[serde(default)]
    pub allowed_headers: Vec<String>,
    /// Whether credentials (cookies, auth headers) are allowed.
    #[serde(default)]
    pub allow_credentials: bool,
}

/// Configuration for the SecurityHeaders layer.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct SecurityHeadersConfig {
    pub content_security_policy: String,
    pub strict_transport_security: String,
    pub x_content_type_options: String,
    pub x_frame_options: String,
    #[serde(default = "default_referrer_policy")]
    pub referrer_policy: String,
}

/// Configuration for the IP allowlist / blocklist (`IpFilter`) middleware layer.
///
/// Evaluates `deny_cidrs` first (explicit blocklist) and `allow_cidrs` second
/// (when non-empty, only IPs matching at least one allowed CIDR are permitted).
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct IpFilterConfig {
    /// Optional list of allowed IPv4/IPv6 CIDR blocks or single IPs
    /// (e.g. `["10.0.0.0/8", "192.168.1.0/24", "127.0.0.1/32", "::1/128"]`).
    /// If empty, all IPs not matching `deny_cidrs` are permitted.
    #[serde(default)]
    pub allow_cidrs: Vec<String>,
    /// Optional list of blocked IPv4/IPv6 CIDR blocks or single IPs
    /// (e.g. `["10.99.0.0/16", "203.0.113.0/24"]`).
    /// Evaluated before `allow_cidrs` (`deny` takes precedence over `allow`).
    #[serde(default)]
    pub deny_cidrs: Vec<String>,
    /// Whether to trust `X-Forwarded-For` / `X-Real-IP` headers when the
    /// underlying socket IP is unspecified (`0.0.0.0` / `::`) (default: `false`).
    #[serde(default)]
    pub trust_forwarded_headers: bool,
    /// Number of trusted reverse-proxy hops counted from the right of `X-Forwarded-For` (default: 1).
    /// Set to `0` to ignore `X-Forwarded-For` completely.
    #[serde(default = "default_trusted_proxy_hops")]
    pub trusted_proxy_hops: usize,
}

impl Default for IpFilterConfig {
    fn default() -> Self {
        Self {
            allow_cidrs: Vec::new(),
            deny_cidrs: Vec::new(),
            trust_forwarded_headers: false,
            trusted_proxy_hops: default_trusted_proxy_hops(),
        }
    }
}

fn default_referrer_policy() -> String {
    "strict-origin-when-cross-origin".to_string()
}

impl Default for SecurityHeadersConfig {
    fn default() -> Self {
        Self {
            content_security_policy: "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:".to_string(),
            strict_transport_security: "max-age=63072000; includeSubDomains; preload".to_string(),
            x_content_type_options: "nosniff".to_string(),
            x_frame_options: "DENY".to_string(),
            referrer_policy: default_referrer_policy(),
        }
    }
}

/// Raw deserialized allowed-path rules (per HTTP method).
///
/// Each method maps a base path (e.g. `"/api"`) to a list of regex pattern
/// strings. These are compiled into [`CompiledAllowedPathes`] during
/// [`ServerConfig::finalize`].
#[derive(Debug, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct AllowedPathes {
    /// Allowed GET path patterns.
    #[serde(rename = "GET")]
    pub get: Option<HashMap<String, Vec<String>>>,
    /// Allowed POST path patterns.
    #[serde(rename = "POST")]
    pub post: Option<HashMap<String, Vec<String>>>,
    /// Allowed PUT path patterns.
    #[serde(rename = "PUT")]
    pub put: Option<HashMap<String, Vec<String>>>,
    /// Allowed DELETE path patterns.
    #[serde(rename = "DELETE")]
    pub delete: Option<HashMap<String, Vec<String>>>,
    /// Allowed PATCH path patterns.
    #[serde(rename = "PATCH")]
    pub patch: Option<HashMap<String, Vec<String>>>,
    /// Allowed HEAD path patterns.
    #[serde(rename = "HEAD")]
    pub head: Option<HashMap<String, Vec<String>>>,
}

/// Pre-compiled regex patterns for path inspection for a specific HTTP method.
///
/// Supports exact path matching (fast $O(1)$ HashMap lookup) and prefix matching
/// with longest-prefix-match-wins ordering.
#[derive(Debug, Clone, Default)]
pub struct MethodRules {
    /// Exact path matches: path -> regex list
    pub exact: HashMap<String, Vec<Regex>>,
    /// Prefix matches: (prefix, regex list) sorted by descending prefix length
    pub prefix: Vec<(String, Vec<Regex>)>,
}

impl MethodRules {
    pub fn is_empty(&self) -> bool {
        self.exact.is_empty() && self.prefix.is_empty()
    }

    /// Checks if `full_path` matches any rule registered for `path`.
    /// 1. Exact match fast-path.
    /// 2. If no exact match, tries prefix matches in descending prefix length order.
    pub fn is_allowed(&self, path: &str, full_path: &str) -> bool {
        // 1. Exact match
        if let Some(rules) = self.exact.get(path) {
            return rules.iter().any(|re| re.is_match(full_path));
        }
        // 2. Prefix matches (longest first)
        for (pfx, rules) in &self.prefix {
            if path.starts_with(pfx)
                && rules.iter().any(|re| re.is_match(full_path)) {
                    return true;
                }
        }
        false
    }
}

/// Pre-compiled regex patterns for path inspection.
///
/// Created from [`AllowedPathes`] during [`ServerConfig::finalize`].
/// Used by the [`InspectionService`](crate::middleware::inspection::InspectionService)
/// at runtime for zero-allocation path matching.
#[derive(Debug, Clone, Default)]
pub struct CompiledAllowedPathes {
    /// Compiled regex rules for GET requests.
    pub get: MethodRules,
    /// Compiled regex rules for POST requests.
    pub post: MethodRules,
    /// Compiled regex rules for PUT requests.
    pub put: MethodRules,
    /// Compiled regex rules for DELETE requests.
    pub delete: MethodRules,
    /// Compiled regex rules for PATCH requests.
    pub patch: MethodRules,
    /// Compiled regex rules for HEAD requests.
    pub head: MethodRules,
}

/// Helper to provide `true` as the default value for `serde`.
fn default_true() -> bool {
    true
}

/// Default graceful connection drain timeout in seconds (`10`).
fn default_graceful_shutdown_timeout_seconds() -> u64 {
    10
}

// ============================================================================
//  Implementations
// ============================================================================

impl Config {
    /// Initializes the global configuration from a TOML file.
    ///
    /// This is the primary entry point for configuration loading. It performs:
    ///
    /// 1. **Read** the TOML file from `config_file`.
    /// 2. **Deserialize** into the `Config` struct hierarchy.
    /// 3. **Pre-compute** the OID base vector for fast certificate matching.
    /// 4. **Finalize** each [`ServerConfig`] (route parsing, regex compilation,
    ///    validation).
    /// 5. **Freeze** the config into the global [`OnceLock`].
    ///
    /// # Errors
    ///
    /// Loads and parses the configuration from disk, merges includes, parses OID,
    /// and finalizes all servers (including eagerly loading certificates/keys and validating layers).
    ///
    /// This method does NOT modify the global configuration singleton.
    pub fn load(config_file: &str) -> Result<Arc<Config>, Error> {
        // 1. Read the raw TOML string
        let toml_str = fs::read_to_string(config_file)
            .with_context(|| format!("Failed to read config file: {}", config_file))?;

        // 2. Deserialize into our Config struct
        let mut config: Config =
            toml::from_str(&toml_str).context("Failed to parse TOML configuration")?;

        if config.tokio_threads == Some(0) {
            return Err(Error::msg(
                "Configuration error: 'tokio_threads' must be >= 1.",
            ));
        }

        // 2.5 Process Includes
        let base_dir = std::path::Path::new(config_file)
            .parent()
            .unwrap_or_else(|| std::path::Path::new(""));
        
        // Clone the list to avoid borrowing issues while mutating config
        let includes = config.includes.clone();
        for pattern in includes {
            let glob_pattern = if std::path::Path::new(&pattern).is_absolute() {
                pattern.clone()
            } else {
                base_dir.join(&pattern).to_string_lossy().to_string()
            };

            let paths = glob::glob(&glob_pattern)
                .with_context(|| format!("Invalid glob pattern: {}", glob_pattern))?;

            for path_res in paths {
                match path_res {
                    Ok(path) => {
                        let include_toml = fs::read_to_string(&path)
                            .with_context(|| format!("Failed to read included config file: {:?}", path))?;
                        
                        let value: toml::Value = toml::from_str(&include_toml)
                            .with_context(|| format!("Failed to parse included TOML configuration: {:?}", path))?;

                        if let toml::Value::Table(map) = &value {
                            for key in map.keys() {
                                if key != "Server" {
                                    tracing::warn!("Included file {:?} contains global key '{}' which will be ignored. Only [[Server]] blocks are merged.", path, key);
                                }
                            }
                        }

                        let fragment: Config = toml::from_str(&include_toml)
                            .with_context(|| format!("Failed to parse included TOML into Config struct: {:?}", path))?;
                        
                        config.servers.extend(fragment.servers);
                    }
                    Err(e) => {
                        tracing::error!("Error matching glob pattern: {:?}", e);
                    }
                }
            }
        }

        // 3. Pre-compute the OID Vector (Optimization for Hot Path)
        // We parse the dot-notation string (e.g. "1.2.840.113549") into u64 integers.
        // We use u64 to support UUID-based OIDs (arc 2.25).
        if let Some(ref oid_str) = config.pki_base_oid {
            config.parsed_pki_base_oid = Some(parse_pki_base_oid(oid_str)?);
        }

        // 4. Finalize individual server settings (e.g. compile regexes, load certs, validate layers)
        for server in config.servers.iter_mut() {
            server.finalize()?;
            if server.parsed_pki_base_oid.is_none() {
                server.parsed_pki_base_oid = config.parsed_pki_base_oid.clone();
            }
        }

        Ok(Arc::new(config))
    }

    /// Atomically updates the global configuration singleton.
    pub fn update_global(arc_config: Arc<Config>) {
        if let Some(existing) = CONFIG.get() {
            existing.store(arc_config);
        } else if CONFIG.set(ArcSwap::new(arc_config)).is_err() {
            tracing::warn!("Config::update_global called concurrently during init.");
        }
    }

    /// Initializes the global configuration singleton from disk.
    ///
    /// # Errors
    ///
    /// Returns an error if the file cannot be read, TOML parsing fails, or
    /// any server's [`finalize`](ServerConfig::finalize) step detects invalid
    /// configuration.
    pub fn init(config_file: &str) -> Result<Arc<Config>, Error> {
        let arc_config = Self::load(config_file)?;
        Self::update_global(arc_config.clone());
        Ok(arc_config)
    }

    /// Returns a cloned `Arc<Config>` from the global configuration singleton if initialized.
    pub fn try_global() -> Option<Arc<Config>> {
        CONFIG.get().map(|c| c.load_full())
    }

    /// Returns a cloned `Arc<Config>` from the global configuration singleton.
    ///
    /// # Panics
    ///
    /// Panics if [`Config::init`] has not been called yet.
    pub fn global() -> Arc<Config> {
        CONFIG
            .get()
            .expect("Configuration not initialized - check if Config::init was called in main")
            .load_full()
    }
}

/// Parses a dot-separated OID string (e.g. `"1.3.6.1.4.1.65111"`) into `u64` components.
///
/// Supports 64-bit arcs such as UUID-based OIDs (`2.25.<uuid-int>`).
///
/// # Errors
///
/// Returns an error if the string is empty or any dot-separated component is not a valid `u64`.
pub fn parse_pki_base_oid(oid_str: &str) -> Result<Vec<u64>, Error> {
    let trimmed = oid_str.trim();
    if trimmed.is_empty() {
        return Err(Error::msg("Invalid OID in config: must not be empty"));
    }
    trimmed
        .split('.')
        .map(|s| {
            s.parse::<u64>()
                .with_context(|| format!("Invalid OID component in config: '{}'", s))
        })
        .collect()
}

impl ServerConfig {
    /// Returns the configured graceful connection drain timeout.
    pub fn drain_timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.graceful_shutdown_timeout_seconds)
    }

    /// Finalizes the server configuration by preparing internal state.
    ///
    /// Performs the following steps:
    ///
    /// 1. Parses raw reverse-route strings into [`ParsedRoute`] objects.
    /// 2. Compiles allowed-path regex patterns.
    /// 3. **Validates** the middleware layer names (catches typos early).
    /// 4. **Validates** HTTPS requirements (certificate presence).
    /// 5. **Validates** authentication requirements (JWT keys, mTLS certs).
    ///
    /// # Errors
    ///
    /// Returns an error on any validation failure, with a message identifying
    /// the offending server by name.
    pub fn finalize(&mut self) -> Result<(), Error> {
        if self.name.trim().is_empty() {
            return Err(Error::msg(
                "Configuration error: Server 'name' must not be empty.",
            ));
        }
        self.static_name = Some(Box::leak(self.name.clone().into_boxed_str()));
        let server_name = self.name.clone();
        self.metrics = ServerMetrics::for_server(&server_name);

        if let Some(ref oid_str) = self.pki_base_oid {
            self.parsed_pki_base_oid = Some(
                parse_pki_base_oid(oid_str)
                    .with_context(|| format!("{server_name}: invalid pki_base_oid"))?,
            );
        }

        let mut pki_info = ServerPkiInfo::default();

        // Eagerly pre-load TLS CertifiedKey if HTTPS is enabled
        if self.protocol == Protocol::Https {
            if let Some(cert_config) = &self.server_certs {
                let static_name = self.static_name.expect("static_name initialized");
                let loaded_key = crate::tls_conf::load_certified_key(static_name, cert_config)?;
                if let Some(leaf_der) = loaded_key.cert.first()
                    && let Ok((_, parsed_cert)) =
                        x509_parser::parse_x509_certificate(leaf_der.as_ref())
                    {
                        pki_info.server_cert_valid_until_unix =
                            Some(parsed_cert.validity().not_after.timestamp());
                    }
                self.certified_key = Some(loaded_key);
            } else {
                return Err(Error::msg(format!(
                    "Configuration error in Server '{}': Protocol is 'https' but [Server.server_certs] (ssl_certificate/key) is missing.",
                    self.name
                )));
            }
        }

        // Extract CRL metadata if client_certs are configured
        if let Some(ref client_certs) = self.client_certs {
            use rustls_pki_types::{CertificateRevocationListDer, pem::PemObject};
            for cc in client_certs {
                if let Some(ref crl_path) = cc.ssl_client_crl
                    && let Ok(crl_der) = CertificateRevocationListDer::from_pem_file(crl_path)
                        && let Ok((_, parsed_crl)) = x509_parser::parse_x509_crl(crl_der.as_ref()) {
                            pki_info.crl_revoked_certs_count +=
                                parsed_crl.iter_revoked_certificates().count();
                            if let Some(next_up) = parsed_crl.next_update() {
                                let ts = next_up.timestamp();
                                pki_info.crl_next_update_unix = match pki_info.crl_next_update_unix {
                                    Some(existing) => Some(existing.min(ts)),
                                    None => Some(ts),
                                };
                            }
                        }
            }
        }
        self.pki_info = pki_info;

        // Validate network binding requirements: if no tunnel is configured, ip and port are mandatory
        if self.tunnel.is_none() {
            if self.ip.is_none() {
                return Err(Error::msg(format!(
                    "Configuration error in Server '{}': 'ip' is required when no [Server.tunnel] is configured.",
                    self.name
                )));
            }
            if self.port.is_none() {
                return Err(Error::msg(format!(
                    "Configuration error in Server '{}': 'port' is required when no [Server.tunnel] is configured.",
                    self.name
                )));
            }
        }

        if self.connection_limits.max_connections == 0 {
            return Err(Error::msg(format!(
                "Configuration error in Server '{}': connection_limits.max_connections must be strictly greater than 0.",
                self.name
            )));
        }
        if self.connection_limits.max_connections_per_ip == 0 {
            return Err(Error::msg(format!(
                "Configuration error in Server '{}': connection_limits.max_connections_per_ip must be strictly greater than 0.",
                self.name
            )));
        }

        self.init_parsed_routes()?;
        self.init_compiled_allowed_pathes()?;
        self.init_compiled_rbac()?;
        // === VALIDATION STEP ===
        // We attempt to build the layers here. If there is a typo (e.g. "Decompressionx")
        // or a missing config section, this will return an Error immediately.
        // We discard the result ('let _') because we only care if it fails.
        let _ = self
            .layers
            .build_middleware_layers(&server_name)
            .with_context(|| format!("Configuration error in Server '{}'", self.name))?;
        // 3. === VALIDATION: HTTPS Requirements ===
        if self.protocol == Protocol::Https {
            // If Protocol is HTTPS, server_certs MUST be present
            if self.server_certs.is_none() {
                return Err(Error::msg(format!(
                    "Configuration error in Server '{}': Protocol is 'https' but [Server.server_certs] (ssl_certificate/key) is missing.",
                    self.name
                )));
            }
        }
        // 4. Validate Authentication Requirements
        match self.authentication {
            AuthenticationMethod::ClientCert | AuthenticationMethod::OptionalClientCert => {
                if self.protocol != Protocol::Https {
                    return Err(Error::msg(format!(
                        "Configuration error in Server '{}': Authentication is '{:?}' (mTLS), but protocol is not 'https'.",
                        self.name, self.authentication
                    )));
                }
                if self.client_certs.as_ref().is_none_or(|c| c.is_empty()) {
                    return Err(Error::msg(format!(
                        "Configuration error in Server '{}': Authentication is '{:?}' (mTLS), but [[Server.client_certs]] is missing.",
                        self.name, self.authentication
                    )));
                }
            }
            AuthenticationMethod::Jwt => {
                // A. Check if the Config Block exists
                let jwt_cfg = self.layers.jwt_config.as_ref().ok_or_else(|| {
                    Error::msg(format!(
                        "Configuration error in Server '{}': Authentication is 'JWT', but [Server.Layers.JWT] config section is missing.",
                        self.name
                    ))
                })?;

                // B. Check if keys are actually provided
                if jwt_cfg.jwt_public_keys.is_empty() {
                    return Err(Error::msg(format!(
                        "Configuration error in Server '{}': Authentication is 'JWT', but 'jwt_public_keys' list is empty.",
                        self.name
                    )));
                }

                // C. Check if the Layer is actually enabled in the list
                // We accept both "JwtAuth" (Internal name) and "JWT" (Alias)
                let layer_enabled =
                    self.layers.enabled.iter().any(|l| {
                        l.eq_ignore_ascii_case("JwtAuth") || l.eq_ignore_ascii_case("JWT")
                    });

                if !layer_enabled {
                    return Err(Error::msg(format!(
                        "Configuration error in Server '{}': Authentication is 'JWT', but the 'JwtAuth' layer is NOT in [Server.Layers.enabled]. You must enable the layer to perform the check.",
                        self.name
                    )));
                }
            }

            AuthenticationMethod::None => {
                // No specific config required for None
            }
        }

        // 5. Validate Service Requirements
        if self.service == ServiceType::Idp {
            let idp_params = self.idp_params.as_ref().ok_or_else(|| {
                Error::msg(format!(
                    "Configuration error in Server '{}': Service is 'Idp', but [Server.IdpParams] section is missing.",
                    self.name
                ))
            })?;
            
            // Validate that IdP private key can be loaded
            common::load_encoding_key(&idp_params.jwt_private_key)
                .with_context(|| format!("{}: Failed to load IdP private key", self.name))?;

            validate_idp_cookie_and_redirect(idp_params, &self.name)?;

            if idp_params.cookie_name.starts_with("__Host-") {
                if self.protocol != Protocol::Https {
                    return Err(Error::msg(format!(
                        "Configuration error in Server '{}': Service is 'Idp' using '__Host-' cookie, but Protocol is not 'Https'. This will be rejected by browsers.",
                        self.name
                    )));
                }
                if idp_params
                    .cookie_domain
                    .as_deref()
                    .is_some_and(|d| !d.trim().is_empty())
                {
                    return Err(Error::msg(format!(
                        "Configuration error in Server '{}': Service is 'Idp' using '__Host-' cookie, which forbids setting 'cookie_domain' per RFC 6265bis.",
                        self.name
                    )));
                }
            }
        } else if self.service == ServiceType::StaticFiles {
            let params = self.static_files_params.as_ref().ok_or_else(|| {
                Error::msg(format!(
                    "Configuration error in Server '{}': Service is 'StaticFiles', but [Server.StaticFilesParams] section is missing.",
                    self.name
                ))
            })?;
            
            if !std::path::Path::new(&params.root).is_dir() {
                tracing::warn!(
                    "Server '{}': StaticFiles root '{}' does not exist (yet). Files will return 404.",
                    self.name, params.root
                );
            }
        } else if self.service == ServiceType::Admin
            && self.authentication == AuthenticationMethod::None
        {
            let has_jwt_layer = self.layers.enabled.iter().any(|l| {
                l.eq_ignore_ascii_case("JwtAuth") || l.eq_ignore_ascii_case("JWT")
            });
            if !has_jwt_layer {
                if self.tunnel.is_some() {
                    return Err(Error::msg(format!(
                        "Configuration error in Server '{}': Service 'Admin' without authentication cannot be exposed over a tunnel.",
                        self.name
                    )));
                }
                let is_loopback = self.ip.as_deref().is_some_and(|ip| {
                    ip.eq_ignore_ascii_case("localhost")
                        || ip.parse::<std::net::IpAddr>().is_ok_and(|a| a.is_loopback())
                });
                if !is_loopback {
                    return Err(Error::msg(format!(
                        "Configuration error in Server '{}': Service 'Admin' without authentication must bind to a loopback address (127.0.0.1 or ::1).",
                        self.name
                    )));
                }
            }
        }

        if self.service == ServiceType::Router {
            let has_jwt_layer = self.layers.enabled.iter().any(|l| {
                l.eq_ignore_ascii_case("JwtAuth") || l.eq_ignore_ascii_case("JWT")
            });
            for route in &self.parsed_routes {
                if route.backend_type == RouteBackendType::Admin
                    && self.authentication == AuthenticationMethod::None
                    && !has_jwt_layer
                    && route.allowed_roles.is_empty()
                    && self.rbac.is_none()
                {
                    return Err(Error::msg(format!(
                        "Configuration error in Server '{}': Route '{}' with backend_type 'admin' requires authentication, non-empty 'allowed_roles', or [Server.Rbac].",
                        self.name, route.prefix
                    )));
                }
            }
        }

        Ok(())
    }

    /// Returns the socket address computed from the IP and port configuration.
    ///
    /// The special IP value `"local"` resolves to the machine's primary
    /// local IP address at runtime.
    pub fn get_server_ip(&self) -> Result<SocketAddr, Error> {
        let ip = self.ip.as_deref().ok_or_else(|| {
            Error::msg(format!("Configuration error in Server '{}': 'ip' is not configured", self.name))
        })?;
        let port = self.port.ok_or_else(|| {
            Error::msg(format!("Configuration error in Server '{}': 'port' is not configured", self.name))
        })?;

        let ip_str = if ip == "local" {
            local_ip_address::local_ip()?.to_string()
        } else {
            ip.to_string()
        };
        format!("{}:{}", ip_str, port)
            .parse()
            .with_context(|| format!("Invalid address: {}:{}", ip_str, port))
    }

    /// Builds a [`RouteTarget`] from upstream strings and resilience parameters.
    #[allow(clippy::too_many_arguments)]
    fn build_route_target(
        upstreams: &[String],
        proto_str: &str,
        strategy: LbStrategy,
        cooldown_seconds: Option<u64>,
        max_retries: Option<usize>,
        failure_threshold: Option<usize>,
        max_retry_buffer_bytes: Option<usize>,
        active_health_check_interval: Option<u64>,
    ) -> Result<RouteTarget, Error> {
        let mut upstream_nodes = Vec::with_capacity(upstreams.len());
        for upstream in upstreams {
            let uri_str = if upstream.starts_with("http://") || upstream.starts_with("https://") {
                upstream.to_string()
            } else {
                format!("{proto_str}://{upstream}")
            };

            let uri = uri_str
                .parse::<Uri>()
                .with_context(|| format!("Invalid upstream URI: {uri_str}"))?;

            upstream_nodes.push(UpstreamNode::new(uri));
        }

        Ok(RouteTarget {
            upstreams: upstream_nodes,
            strategy,
            rr_counter: std::sync::atomic::AtomicUsize::new(0),
            cooldown_seconds: cooldown_seconds.unwrap_or(10),
            max_retries: max_retries.unwrap_or(2),
            failure_threshold: failure_threshold.unwrap_or(3).max(1),
            max_retry_buffer_bytes: max_retry_buffer_bytes.unwrap_or(65_536),
            active_health_check_interval: active_health_check_interval.unwrap_or(0),
            grpc_pool: tokio::sync::RwLock::new(None),
            grpc_reflection_lock: tokio::sync::Mutex::new(()),
        })
    }

    /// Validates and compiles fan-out sub-targets for an `aggregate` route.
    fn parse_aggregate_targets(
        prefix: &str,
        cfg: &RouteConfig,
        proto_str: &str,
    ) -> Result<Vec<Arc<ParsedAggregateTarget>>, Error> {
        if !cfg.upstreams.is_empty() {
            return Err(Error::msg(format!(
                "Configuration error: Aggregate route '{}' must define 'targets' instead of top-level 'upstreams'.",
                prefix
            )));
        }
        if cfg.targets.is_empty() {
            return Err(Error::msg(format!(
                "Configuration error: Aggregate route '{}' must define at least one target.",
                prefix
            )));
        }

        let mut seen_keys = HashSet::with_capacity(cfg.targets.len());
        let mut parsed = Vec::with_capacity(cfg.targets.len());

        for t in &cfg.targets {
            let key = t.key.trim();
            if key.is_empty() || key == "_errors" {
                return Err(Error::msg(format!(
                    "Configuration error: Aggregate route '{}' has invalid target key '{}'.",
                    prefix, t.key
                )));
            }
            if !seen_keys.insert(key.to_string()) {
                return Err(Error::msg(format!(
                    "Configuration error: Aggregate route '{}' has duplicate target key '{}'.",
                    prefix, key
                )));
            }
            if !matches!(
                t.backend_type,
                RouteBackendType::Rest | RouteBackendType::GrpcTranscoding
            ) {
                return Err(Error::msg(format!(
                    "Configuration error: Aggregate route '{}' target '{}' only supports backend_type 'rest' or 'grpc_transcoding'.",
                    prefix, key
                )));
            }
            if t.upstreams.is_empty() {
                return Err(Error::msg(format!(
                    "Configuration error: Aggregate route '{}' target '{}' has no upstreams defined.",
                    prefix, key
                )));
            }
            if !t.path.starts_with('/') {
                return Err(Error::msg(format!(
                    "Configuration error: Aggregate route '{}' target '{}' path '{}' must start with '/'.",
                    prefix, key, t.path
                )));
            }

            let target_uri: Uri = t.path.parse().with_context(|| {
                format!(
                    "Configuration error: Aggregate route '{}' target '{}' has invalid path '{}'",
                    prefix, key, t.path
                )
            })?;
            if target_uri.scheme().is_some() || target_uri.authority().is_some() {
                return Err(Error::msg(format!(
                    "Configuration error: Aggregate route '{}' target '{}' path '{}' must be a relative path without scheme or host.",
                    prefix, key, t.path
                )));
            }

            if t.backend_type == RouteBackendType::GrpcTranscoding {
                let segments: Vec<&str> = target_uri
                    .path()
                    .trim_start_matches('/')
                    .split('/')
                    .collect();
                if segments.len() != 2 || segments[0].is_empty() || segments[1].is_empty() {
                    return Err(Error::msg(format!(
                        "Configuration error: Aggregate route '{}' gRPC target '{}' path '{}' must match '/<Package.Service>/<Method>'.",
                        prefix, key, t.path
                    )));
                }
            }

            let method = match &t.method {
                Some(raw_method) => {
                    let trimmed = raw_method.trim().to_ascii_uppercase();
                    let parsed_method = Method::from_bytes(trimmed.as_bytes()).with_context(|| {
                        format!(
                            "Configuration error: Aggregate route '{}' target '{}' has invalid HTTP method '{}'",
                            prefix, key, raw_method
                        )
                    })?;
                    if t.backend_type == RouteBackendType::GrpcTranscoding
                        && parsed_method != Method::POST
                    {
                        return Err(Error::msg(format!(
                            "Configuration error: Aggregate route '{}' gRPC target '{}' only supports POST method (got '{}').",
                            prefix, key, parsed_method
                        )));
                    }
                    Some(parsed_method)
                }
                None => None,
            };

            let route_target = Self::build_route_target(
                &t.upstreams,
                proto_str,
                t.strategy.clone(),
                t.cooldown_seconds,
                t.max_retries,
                t.failure_threshold,
                t.max_retry_buffer_bytes,
                t.active_health_check_interval,
            )?;

            if t.timeout_ms == Some(0) {
                return Err(Error::msg(format!(
                    "Configuration error: Aggregate route '{}' target '{}' timeout_ms must be greater than 0.",
                    prefix, key
                )));
            }

            let forward_query = t
                .forward_query
                .as_ref()
                .map(|list| list.iter().map(|s| s.trim().to_string()).collect());
            let forward_headers = t
                .forward_headers
                .iter()
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| !s.is_empty())
                .collect();
            let escaped_key = serde_json::to_string(key).with_context(|| {
                format!(
                    "Configuration error: Aggregate route '{}' target '{}' key could not be JSON-encoded",
                    prefix, key
                )
            })?;
            let json_key_prefix = Bytes::from(format!("{escaped_key}:"));
            let pinned_query_keys: HashSet<String> = target_uri
                .query()
                .filter(|q| !q.is_empty())
                .map(|tq| {
                    url::form_urlencoded::parse(tq.as_bytes())
                        .map(|(k, _)| k.into_owned())
                        .collect()
                })
                .unwrap_or_default();

            parsed.push(Arc::new(ParsedAggregateTarget {
                key: key.to_string(),
                json_key_prefix,
                backend_type: t.backend_type.clone(),
                target: Arc::new(route_target),
                target_uri,
                pinned_query_keys,
                method,
                required: t.required,
                forward_query,
                forward_headers,
                timeout_ms: t.timeout_ms,
            }));
        }

        Ok(parsed)
    }

    /// Compiles and validates the per-route upstream header sanitization policy (`S-05`).
    fn build_route_header_policy(
        prefix: &str,
        cfg: &RouteConfig,
        cookie_fallback: Option<&str>,
        aggregate_targets: &[Arc<ParsedAggregateTarget>],
    ) -> Result<RouteHeaderPolicy, Error> {
        if cfg.strip_authorization == Some(true) && cfg.forward_authorization == Some(true) {
            return Err(Error::msg(format!(
                "Configuration error: Route '{}' sets both 'strip_authorization = true' and 'forward_authorization = true'.",
                prefix
            )));
        }

        let mut allowlist: Option<HashSet<String>> = None;
        let mut allowlist_has_auth = false;
        let mut allowlist_has_cookie = false;

        if let Some(raw_headers) = &cfg.forward_headers {
            let mut set = HashSet::with_capacity(raw_headers.len());
            for raw in raw_headers {
                let normalized = raw.trim().to_ascii_lowercase();
                if normalized.is_empty()
                    || hyper::header::HeaderName::from_bytes(normalized.as_bytes()).is_err()
                {
                    return Err(Error::msg(format!(
                        "Configuration error: Route '{}' forward_headers contains invalid HTTP header name '{}'.",
                        prefix, raw
                    )));
                }
                if normalized == "authorization" {
                    allowlist_has_auth = true;
                } else if normalized == "cookie" {
                    allowlist_has_cookie = true;
                }
                set.insert(normalized);
            }
            allowlist = Some(set);
        }

        if cfg.strip_authorization == Some(true) && allowlist_has_auth {
            return Err(Error::msg(format!(
                "Configuration error: Route '{}' sets 'strip_authorization = true' while also allowing 'authorization' in 'forward_headers'.",
                prefix
            )));
        }

        let mut strip_cookie_names = HashSet::new();
        for raw_name in &cfg.strip_cookie_names {
            let trimmed = raw_name.trim();
            if trimmed.is_empty() {
                return Err(Error::msg(format!(
                    "Configuration error: Route '{}' strip_cookie_names must not contain empty cookie names.",
                    prefix
                )));
            }
            strip_cookie_names.insert(trimmed.to_string());
        }

        if cfg.strip_cookies == Some(true) && !strip_cookie_names.is_empty() {
            return Err(Error::msg(format!(
                "Configuration error: Route '{}' sets 'strip_cookies = true' together with non-empty 'strip_cookie_names'.",
                prefix
            )));
        }
        if cfg.strip_cookies == Some(true) && allowlist_has_cookie {
            return Err(Error::msg(format!(
                "Configuration error: Route '{}' sets 'strip_cookies = true' while also allowing 'cookie' in 'forward_headers'.",
                prefix
            )));
        }

        if let Some(cb) = cookie_fallback.map(str::trim).filter(|s| !s.is_empty()) {
            strip_cookie_names.insert(cb.to_string());
        }

        let strip_authorization = match (cfg.strip_authorization, cfg.forward_authorization) {
            (Some(false), _) | (_, Some(true)) => false,
            (Some(true), _) => true,
            (None, _) => !allowlist_has_auth,
        };

        let strip_cookies = match cfg.strip_cookies {
            Some(v) => v,
            None => cfg.strip_cookie_names.is_empty() && !allowlist_has_cookie,
        };

        let preserve_authorization_for_subtargets = aggregate_targets
            .iter()
            .any(|t| t.forward_headers.contains("authorization"));
        let preserve_cookies_for_subtargets = aggregate_targets
            .iter()
            .any(|t| t.forward_headers.contains("cookie"));

        Ok(RouteHeaderPolicy {
            strip_authorization,
            strip_cookies,
            strip_cookie_names,
            forward_headers: allowlist,
            preserve_authorization_for_subtargets,
            preserve_cookies_for_subtargets,
        })
    }

    /// Parses the raw reverse route configuration into structured [`ParsedRoute`] objects.
    ///
    /// Routes are sorted by prefix length (longest first) so that the most
    /// specific prefix wins during matching.
    pub fn init_parsed_routes(&mut self) -> Result<(), Error> {
        let mut rules = Vec::new();
        if let Some(map) = &self.rev_routes {
            // Determine the upstream protocol from RouterParams (defaults to HTTP).
            let proto = self
                .router_params
                .as_ref()
                .map(|p| p.protocol)
                .unwrap_or_default();
            let proto_str = match proto {
                Protocol::Https => "https",
                Protocol::Http => "http",
            };
            let cookie_fallback = self
                .layers
                .jwt_config
                .as_ref()
                .and_then(|j| j.cookie_fallback.as_deref());

            for (prefix, cfg) in map {
                if cfg.deadline_ms == Some(0) {
                    return Err(Error::msg(format!(
                        "Configuration error: Route '{}' deadline_ms must be greater than 0.",
                        prefix
                    )));
                }
                if cfg.max_request_bytes == Some(0) {
                    return Err(Error::msg(format!(
                        "Configuration error: Route '{}' max_request_bytes must be greater than 0.",
                        prefix
                    )));
                }
                if cfg.max_response_bytes == Some(0) {
                    return Err(Error::msg(format!(
                        "Configuration error: Route '{}' max_response_bytes must be greater than 0.",
                        prefix
                    )));
                }
                let max_request_bytes = cfg
                    .max_request_bytes
                    .unwrap_or(DEFAULT_MAX_BUFFERED_REQUEST_BYTES);
                let max_response_bytes = cfg
                    .max_response_bytes
                    .unwrap_or(DEFAULT_MAX_AGGREGATE_RESPONSE_BYTES);

                if cfg.backend_type == RouteBackendType::Aggregate {
                    let aggregate_targets =
                        Self::parse_aggregate_targets(prefix, cfg, proto_str)?;
                    let header_policy = Self::build_route_header_policy(
                        prefix,
                        cfg,
                        cookie_fallback,
                        &aggregate_targets,
                    )?;
                    let empty_target = Self::build_route_target(
                        &[],
                        proto_str,
                        cfg.strategy.clone(),
                        cfg.cooldown_seconds,
                        cfg.max_retries,
                        cfg.failure_threshold,
                        cfg.max_retry_buffer_bytes,
                        cfg.active_health_check_interval,
                    )?;
                    rules.push(ParsedRoute {
                        prefix: prefix.clone(),
                        target: Arc::new(empty_target),
                        allowed_roles: cfg.allowed_roles.clone(),
                        backend_type: cfg.backend_type.clone(),
                        aggregate_targets,
                        aggregate_payload_mode: cfg.payload_mode,
                        expose_upstream_errors: cfg.expose_upstream_errors,
                        aggregate_deadline_ms: cfg.deadline_ms,
                        max_request_bytes,
                        max_response_bytes,
                        header_policy,
                    });
                    continue;
                }

                if !cfg.targets.is_empty() {
                    return Err(Error::msg(format!(
                        "Configuration error: Route '{}' defines 'targets', which is only valid for backend_type = \"aggregate\".",
                        prefix
                    )));
                }
                if cfg.upstreams.is_empty() && cfg.backend_type != RouteBackendType::Admin {
                    return Err(Error::msg(format!(
                        "Configuration error: Route '{}' has no upstreams defined.",
                        prefix
                    )));
                }

                let header_policy =
                    Self::build_route_header_policy(prefix, cfg, cookie_fallback, &[])?;

                let target = Self::build_route_target(
                    &cfg.upstreams,
                    proto_str,
                    cfg.strategy.clone(),
                    cfg.cooldown_seconds,
                    cfg.max_retries,
                    cfg.failure_threshold,
                    cfg.max_retry_buffer_bytes,
                    cfg.active_health_check_interval,
                )?;

                rules.push(ParsedRoute {
                    prefix: prefix.clone(),
                    target: Arc::new(target),
                    allowed_roles: cfg.allowed_roles.clone(),
                    backend_type: cfg.backend_type.clone(),
                    aggregate_targets: Vec::new(),
                    aggregate_payload_mode: AggregatePayloadMode::default(),
                    expose_upstream_errors: false,
                    aggregate_deadline_ms: None,
                    max_request_bytes,
                    max_response_bytes,
                    header_policy,
                });
            }
        }
        // Sort by descending prefix length for longest-prefix-first matching.
        rules.sort_by_key(|a| std::cmp::Reverse(a.prefix.len()));
        self.parsed_routes = rules;
        Ok(())
    }

    /// Compiles the raw allowed path patterns into [`CompiledAllowedPathes`].
    ///
    /// If no allowed paths are configured, creates an empty default (which
    /// means the Inspection layer will block everything).
    pub fn init_compiled_allowed_pathes(&mut self) -> Result<(), Error> {
        let raw = self.allowed_pathes.clone().unwrap_or_default();
        self.compiled_allowed_pathes = Some(Arc::new(CompiledAllowedPathes::from_raw(&raw)?));
        Ok(())
    }

    /// Compiles fine-grained RBAC rules into [`CompiledRbac`].
    pub fn init_compiled_rbac(&mut self) -> Result<(), Error> {
        self.compiled_rbac = self.rbac.as_ref().map(|raw| Arc::new(CompiledRbac::from_raw(raw)));
        Ok(())
    }
}

impl CompiledAllowedPathes {
    /// Compiles raw string patterns from [`AllowedPathes`] into [`Regex`] objects.
    ///
    /// # Errors
    ///
    /// Returns an error if any regex pattern is invalid.
    pub fn from_raw(raw: &AllowedPathes) -> Result<Self, Error> {
        let compile_method_rules =
            |opt_map: &Option<HashMap<String, Vec<String>>>| -> Result<MethodRules, Error> {
                let mut exact = HashMap::new();
                let mut prefix = Vec::new();

                if let Some(map) = opt_map {
                    for (pattern, patterns) in map {
                        let regexes: Result<Vec<_>, _> =
                            patterns.iter().map(|p| Regex::new(p)).collect();
                        let regexes = regexes
                            .map_err(|e| Error::msg(format!("Regex error for '{pattern}': {e}")))?;

                        if pattern.ends_with('*') {
                            // Strip trailing `*`: keeps trailing `/` for `"/api/*"`, or prefix `"/api"` for `"/api*"`
                            let pfx = &pattern[..pattern.len() - 1];
                            prefix.push((pfx.to_string(), regexes));
                        } else {
                            exact.insert(pattern.clone(), regexes);
                        }
                    }
                }

                // Deterministic longest-prefix match: sort descending by prefix length
                prefix.sort_by_key(|a| std::cmp::Reverse(a.0.len()));

                Ok(MethodRules { exact, prefix })
            };

        Ok(Self {
            get: compile_method_rules(&raw.get)?,
            post: compile_method_rules(&raw.post)?,
            put: compile_method_rules(&raw.put)?,
            delete: compile_method_rules(&raw.delete)?,
            patch: compile_method_rules(&raw.patch)?,
            head: compile_method_rules(&raw.head)?,
        })
    }

    /// Checks whether a `(method, path, query)` triple matches the allowed rules.
    ///
    /// The full path (including query string if present) is tested against every
    /// regex pattern registered for the given method and base path.
    ///
    /// Returns `false` for unrecognised HTTP methods or for paths that have no
    /// matching regex rules.
    pub fn is_allowed(&self, method: &str, path: &str, query: &str) -> bool {
        let full_path = if query.is_empty() {
            path.to_string()
        } else {
            format!("{}?{}", path, query)
        };

        match method {
            "GET" => self.get.is_allowed(path, &full_path),
            "POST" => self.post.is_allowed(path, &full_path),
            "PUT" => self.put.is_allowed(path, &full_path),
            "DELETE" => self.delete.is_allowed(path, &full_path),
            "PATCH" => self.patch.is_allowed(path, &full_path),
            "HEAD" => {
                self.head.is_allowed(path, &full_path) || self.get.is_allowed(path, &full_path)
            }
            "OPTIONS" => {
                self.get.is_allowed(path, &full_path)
                    || self.post.is_allowed(path, &full_path)
                    || self.put.is_allowed(path, &full_path)
                    || self.delete.is_allowed(path, &full_path)
                    || self.patch.is_allowed(path, &full_path)
                    || self.head.is_allowed(path, &full_path)
            }
            _ => false,
        }
    }
}

/// Pre-compiled granular Role-Based Access Control lookup structure.
///
/// Supports exact path matching (O(1) lookup) and wildcard prefix matching
/// (longest prefix first).
#[derive(Debug, Clone, Default)]
pub struct CompiledRbac {
    /// Exact path matches: path -> required_roles
    pub exact: HashMap<String, Vec<UserRole>>,
    /// Wildcard / prefix matches: (prefix, required_roles) sorted by descending prefix length
    pub prefix: Vec<(String, Vec<UserRole>)>,
}

impl CompiledRbac {
    /// Normalizes a path for exact RBAC matching by stripping trailing slashes
    /// (preserving `"/"`).
    #[inline]
    fn normalize_exact_key(path: &str) -> &str {
        if path.len() > 1 {
            let trimmed = path.trim_end_matches('/');
            if trimmed.is_empty() { "/" } else { trimmed }
        } else {
            path
        }
    }

    /// Compiles raw string patterns from the `[Server.rbac]` table.
    ///
    /// Keys ending with `*` are treated as prefix matches (e.g. `"/api/Admin*"` or `"/api/admin/*"`).
    /// Other keys are treated as exact path matches (normalized without trailing slashes).
    pub fn from_raw(raw: &HashMap<String, Vec<UserRole>>) -> Self {
        let mut exact = HashMap::new();
        let mut prefix = Vec::new();

        for (pattern, roles) in raw {
            if pattern.ends_with('*') {
                let pfx = &pattern[..pattern.len() - 1];
                prefix.push((pfx.to_string(), roles.clone()));
            } else {
                let normalized = Self::normalize_exact_key(pattern).to_string();
                exact.insert(normalized, roles.clone());
            }
        }

        // Sort descending by prefix length: most specific prefix wins
        prefix.sort_by_key(|a| std::cmp::Reverse(a.0.len()));

        Self { exact, prefix }
    }

    /// Matches a request path against exact and prefix RBAC rules.
    ///
    /// Exact matches take precedence over prefix matches. Trailing slashes on
    /// exact paths are normalized (so `/api/Admin/` matches `/api/Admin`).
    /// Returns `Some(&[UserRole])` if a rule matched, or `None` if no rule matched.
    pub fn match_path<'a>(&'a self, path: &str) -> Option<&'a [UserRole]> {
        let exact_key = Self::normalize_exact_key(path);
        if let Some(roles) = self.exact.get(exact_key) {
            return Some(roles.as_slice());
        }
        for (pfx, roles) in &self.prefix {
            if path.starts_with(pfx) {
                return Some(roles.as_slice());
            }
        }
        None
    }
}

impl Layers {
    /// Validates the order of middleware layers in `enabled`.
    fn validate_middleware_order(&self) -> Result<(), Error> {
        // Rule 1: TraceId (if present) must be first
        if let Some(idx) = self.enabled.iter().position(|l| l == "TraceId")
            && idx != 0 {
                return Err(Error::msg(
                    "TraceId layer must be FIRST (outermost) in [Server.Layers].enabled to capture all requests."
                ));
            }

        // Rule 2: Inspection must come AFTER Decompression
        if let Some(insp_idx) = self.enabled.iter().position(|l| l == "Inspection")
            && let Some(decomp_idx) = self.enabled.iter().position(|l| l == "Decompression")
                && insp_idx < decomp_idx {
                    return Err(Error::msg(
                        format!(
                            "Inspection (at index {}) must come AFTER Decompression (at index {}). Otherwise the WAF inspects compressed bytes!",
                            insp_idx, decomp_idx
                        )
                    ));
                }

        Ok(())
    }

    /// Maps the enabled layer names to their corresponding [`MiddlewareLayer`] variants.
    ///
    /// Each string in [`Layers::enabled`] is matched against known layer names.
    /// Layers that require configuration (e.g. `"MaxPayload"`, `"Delay"`) look up
    /// their sibling TOML section and fail with a descriptive error if it is missing.
    ///
    /// # Errors
    ///
    /// Returns an error if an unknown layer name is encountered or if a required
    /// configuration section is absent, or if the layer order is invalid.
    pub fn build_middleware_layers(&self, server_name: &str) -> Result<Vec<MiddlewareLayer>, Error> {
        self.validate_middleware_order()?;

        let mut layers: Vec<MiddlewareLayer> = self
            .enabled
            .iter()
            .map(|name| match name.as_str() {
                // New case for MaxPayload
                "MaxPayload" => self
                    .max_payload_config
                    .as_ref()
                    .map(|c| MiddlewareLayer::MaxPayload(c.max_bytes))
                    .context("Layer 'MaxPayload' enabled but [Server.Layers.MaxPayload] section is missing"),
                "TraceId" => Ok(MiddlewareLayer::TraceId),
                "Timing" => Ok(MiddlewareLayer::Timing),
                "Counter" => Ok(MiddlewareLayer::Counter),
                "Logger" => Ok(MiddlewareLayer::Logger),
                "PathSanitizer" | "NormalizePath" => Ok(MiddlewareLayer::PathSanitizer),
                "Inspection" => Ok(MiddlewareLayer::Inspection),
                "Compression" => Ok(MiddlewareLayer::Compression),
                "Decompression" => self
                    .decompression_config
                    .as_ref()
                    .map(|c| MiddlewareLayer::Decompression(c.max_decompressed_bytes))
                    .context("Layer 'Decompression' enabled but [Server.Layers.Decompression] section is missing"),
                "Delay" => self
                    .delay_config
                    .as_ref()
                    .map(|c| MiddlewareLayer::Delay(c.delay_micros))
                    .context("Missing [Layers.Delay]"),
                "JwtAuth" | "JWT" => {
                    let c = self
                        .jwt_config
                        .as_ref()
                        .ok_or_else(|| {
                            Error::msg(format!(
                                "{}: Missing [Server.Layers.JWT] section for JwtAuth layer",
                                server_name
                            ))
                        })?;
                    if c.jwt_public_keys.is_empty() {
                        return Err(Error::msg(format!(
                            "{}: Layer 'JwtAuth': jwt_public_keys must not be empty",
                            server_name
                        )));
                    }
                    if c.expected_issuer.split(',').all(|s| s.trim().is_empty()) {
                        return Err(Error::msg(format!(
                            "{}: Layer 'JwtAuth': expected_issuer must not be empty",
                            server_name
                        )));
                    }
                    if c.expected_audience.split(',').all(|s| s.trim().is_empty()) {
                        return Err(Error::msg(format!(
                            "{}: Layer 'JwtAuth': expected_audience must not be empty",
                            server_name
                        )));
                    }
                    // Validate decoding keys can actually be loaded
                    common::load_decoding_keys(&c.jwt_public_keys)?;
                    Ok(MiddlewareLayer::JwtAuth(c.clone()))
                }
                "ConcurrencyLimit" => {
                    let c = self
                        .concurrency_limit_config
                        .as_ref()
                        .context("Missing [Layers.ConcurrencyLimit]")?;
                    if c.max_concurrent_requests == 0 {
                        return Err(Error::msg(format!(
                            "{}: Layer 'ConcurrencyLimit': max_concurrent_requests must be greater than 0",
                            server_name
                        )));
                    }
                    Ok(MiddlewareLayer::ConcurrencyLimit(c.clone()))
                }
                "Cors" => {
                    let c = self
                        .cors_config
                        .as_ref()
                        .context("Missing [Layers.Cors]")?;
                    let has_wildcard = c.allowed_origins.iter().any(|o| o == "*")
                        || c.allowed_methods.iter().any(|m| m == "*")
                        || c.allowed_headers.iter().any(|h| h == "*");
                    if c.allow_credentials && has_wildcard {
                        return Err(Error::msg(format!(
                            "{}: Layer 'Cors': allow_credentials cannot be true when allowed_origins, allowed_methods, or allowed_headers contains wildcard '*' (violates CORS specification and causes panic in tower-http)",
                            server_name
                        )));
                    }
                    Ok(MiddlewareLayer::Cors(c.clone()))
                }
                "SecurityHeaders" => self
                    .security_headers_config
                    .as_ref()
                    .map(|c| MiddlewareLayer::SecurityHeaders(c.clone()))
                    .context("Layer 'SecurityHeaders' enabled but [Server.Layers.SecurityHeaders] section is missing"),
                "RateLimiter:Simple" => {
                    let c = self
                        .rate_limiter_config
                        .as_ref()
                        .context("Missing [Layers.RateLimiter]")?;
                    if c.requests_per_second == 0 {
                        return Err(Error::msg(format!(
                            "{}: Layer 'RateLimiter:Simple': requests_per_second must be greater than 0",
                            server_name
                        )));
                    }
                    Ok(MiddlewareLayer::RateLimiter(RateLimiter::Simple(c.clone())))
                }
                "RateLimiter:TokenBucket" => {
                    let c = self
                        .token_bucket_config
                        .as_ref()
                        .context("Missing [Layers.TokenBucketRateLimiter]")?;
                    if c.max_capacity == 0 || c.refill == 0 || c.duration_micros == 0 {
                        return Err(Error::msg(format!(
                            "{}: Layer 'RateLimiter:TokenBucket': max_capacity, refill, and duration_micros must all be greater than 0",
                            server_name
                        )));
                    }
                    Ok(MiddlewareLayer::RateLimiter(RateLimiter::TokenBucket(c.clone())))
                }
                "AltSvc" => Ok(MiddlewareLayer::AltSvc),
                "IpFilter" => {
                    let c = self
                        .ip_filter_config
                        .as_ref()
                        .context("Layer 'IpFilter' enabled but [Server.Layers.IpFilter] section is missing")?;
                    // Eagerly validate all CIDR entries during startup / SIGHUP reload
                    for cidr_str in &c.allow_cidrs {
                        crate::middleware::IpCidr::parse(cidr_str).map_err(|e| {
                            Error::msg(format!(
                                "{}: Layer 'IpFilter' invalid allow_cidrs entry '{}': {}",
                                server_name, cidr_str, e
                            ))
                        })?;
                    }
                    for cidr_str in &c.deny_cidrs {
                        crate::middleware::IpCidr::parse(cidr_str).map_err(|e| {
                            Error::msg(format!(
                                "{}: Layer 'IpFilter' invalid deny_cidrs entry '{}': {}",
                                server_name, cidr_str, e
                            ))
                        })?;
                    }
                    Ok(MiddlewareLayer::IpFilter(c.clone()))
                }
                other => Err(Error::msg(format!("Unknown layer type: {}", other))),
            })
            .collect::<Result<_, _>>()?;

        // Position SecurityHeaders: If SecurityHeaders was not explicitly enabled in the list,
        // we insert it near the top (outermost layer) so that all short-circuit responses
        // (401, 403, 429, 503, etc.) carry standard security headers.
        if !self.enabled.iter().any(|n| n == "SecurityHeaders") {
            let insert_idx = layers
                .iter()
                .position(|l| !matches!(l, MiddlewareLayer::TraceId | MiddlewareLayer::Logger | MiddlewareLayer::Timing | MiddlewareLayer::Counter))
                .unwrap_or(0);
            layers.insert(
                insert_idx,
                MiddlewareLayer::SecurityHeaders(
                    self.security_headers_config.clone().unwrap_or_default(),
                ),
            );
        }

        Ok(layers)
    }
}

// --- ServerConfig Methods ---

impl ServerConfig {
    /// Maps a client-provided OID suffix to an internal [`UserRole`].
    ///
    /// Falls back to `UserRole::guest()` if the suffix is not in the
    /// [`oid_mapping`](ServerConfig::oid_mapping) table.
    pub fn map_oid_to_role(&self, suffix: &str) -> UserRole {
        self.oid_mapping
            .get(suffix)
            .cloned()
            .unwrap_or_else(UserRole::guest)
    }
}

// --- Helper function for Main (Backward Compatibility) ---

/// Convenience wrapper around [`Config::init`].
///
/// Provided for backward compatibility with older calling code in `main()`.
pub fn get_configuration(config_file: &str) -> Result<Arc<Config>, Error> {
    Config::init(config_file)
}


#[cfg(test)]
mod tests;
