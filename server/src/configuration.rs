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
use hyper::Uri;
use regex::Regex;
use rustls::sign::CertifiedKey;
use serde::Deserialize;
use std::{collections::HashMap, fs, net::SocketAddr, sync::Arc, sync::OnceLock};

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

    /// Server TLS certificate and key paths (required for HTTPS).
    pub server_certs: Option<ServerCertConfig>,
    /// Client CA certificates for mTLS verification.
    pub client_certs: Option<Vec<ClientCertConfig>>,

    /// Configuration for forwarding client certificate details to the backend.
    pub client_cert_forwarding: Option<ClientCertForwardingConfig>,

    /// Connection limits for TCP/QUIC listeners (default: 10,000 global, 100 per IP).
    #[serde(default, alias = "ConnectionLimits")]
    pub connection_limits: ConnectionLimitsConfig,

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
}

// ============================================================================
//  Supporting Structures
// ============================================================================

/// Parameters for the StaticFiles service.
#[derive(Debug, Deserialize, Clone)]
pub struct StaticFilesParams {
    /// The root directory to serve files from.
    pub root: String,
    /// If true, requests to missing files will fallback to serving index.html (useful for SPAs).
    #[serde(default)]
    pub fallback_to_index: bool,
}

/// A single reverse-proxy route definition from the TOML config.
#[derive(Debug, Deserialize, Clone)]
pub struct RouteConfig {
    /// The upstream backend addresses (e.g. `["127.0.0.1:8080", "127.0.0.1:8081"]`).
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
    /// Interval in seconds for actively polling the /health endpoint of upstreams. Defaults to 0 (disabled).
    pub active_health_check_interval: Option<u64>,
    /// The type of backend this route proxies to (rest or grpc). Defaults to rest.
    #[serde(default)]
    pub backend_type: RouteBackendType,
}

/// The type of backend service being routed to.
#[derive(Debug, Deserialize, Clone, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RouteBackendType {
    /// Standard HTTP/REST backend (default).
    #[default]
    Rest,
    /// Native gRPC transparent proxying. HTTP/2 is forced to the backend.
    GrpcPassthrough,
    /// gRPC backend with automatic JSON-to-Protobuf transcoding.
    #[serde(alias = "grpc")]
    GrpcTranscoding,
}

/// A load balancing strategy for downstream forwarding.
#[derive(Debug, Deserialize, Clone, Default, PartialEq, Eq)]
pub enum LbStrategy {
    #[default]
    RoundRobin,
    Random,
    LeastConnections,
    Sticky,
    HighestScore,
}

/// A single upstream node within a load-balanced route target.
#[derive(Debug)]
pub struct UpstreamNode {
    /// The parsed URI for this upstream node.
    pub uri: Uri,
    /// Number of active connections to this upstream (used for LeastConnections).
    pub active_connections: std::sync::atomic::AtomicUsize,
    /// Whether the node is currently considered alive.
    pub is_alive: std::sync::atomic::AtomicBool,
    /// Timestamp of the last connection failure (seconds since UNIX epoch).
    pub last_failure_time: std::sync::atomic::AtomicU64,
    /// The health score of this node (0-100) reported by active health checks.
    pub current_score: std::sync::atomic::AtomicUsize,
}

impl UpstreamNode {
    /// Marks the node as dead and records the current failure timestamp.
    pub fn mark_dead(&self) {
        self.is_alive
            .store(false, std::sync::atomic::Ordering::Relaxed);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_failure_time
            .store(now, std::sync::atomic::Ordering::Relaxed);
    }

    /// Marks the node as alive and clears the failure timestamp.
    pub fn mark_alive(&self) {
        self.is_alive
            .store(true, std::sync::atomic::Ordering::Relaxed);
        self.last_failure_time
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    /// Checks if the node is considered available for routing.
    /// A node is available if it is marked alive, or if the cooldown period has elapsed.
    pub fn is_available(&self, cooldown_seconds: u64) -> bool {
        if self.is_alive.load(std::sync::atomic::Ordering::Relaxed) {
            return true;
        }

        let last_fail = self
            .last_failure_time
            .load(std::sync::atomic::Ordering::Relaxed);
        if last_fail == 0 {
            // Node is explicitly marked dead but has no failure timestamp: not available
            return false;
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        now > last_fail + cooldown_seconds
    }
}

/// Cached gRPC DescriptorPool with creation timestamp for TTL-based cache expiration.
#[derive(Debug, Clone)]
pub struct CachedDescriptorPool {
    /// The loaded descriptor pool containing protobuf definitions.
    pub pool: std::sync::Arc<prost_reflect::DescriptorPool>,
    /// Instant when this pool was retrieved via gRPC reflection.
    pub created_at: std::time::Instant,
}

/// The load-balanced target configuration for a parsed route.
#[derive(Debug)]
pub struct RouteTarget {
    /// The available upstream nodes.
    pub upstreams: Vec<UpstreamNode>,
    /// The strategy to distribute requests among `upstreams`.
    pub strategy: LbStrategy,
    /// Atomic counter used for RoundRobin selection.
    pub rr_counter: std::sync::atomic::AtomicUsize,
    /// Cooldown time for dead nodes before they can be retried.
    pub cooldown_seconds: u64,
    /// Maximum amount of automatic retry attempts.
    pub max_retries: usize,
    /// Interval in seconds for actively polling the /health endpoint of upstreams. 0 means disabled.
    pub active_health_check_interval: u64,
    /// Cached gRPC DescriptorPool from reflection, lazily loaded by the router with TTL.
    /// Only used if backend_type is Grpc.
    pub grpc_pool: tokio::sync::RwLock<Option<CachedDescriptorPool>>,
    /// Mutex to synchronize reflection fetches without holding the read/write lock across network I/O.
    pub grpc_reflection_lock: tokio::sync::Mutex<()>,
}

impl RouteTarget {
    /// Marks an upstream node as dead due to a connection failure.
    pub fn mark_dead(&self, uri: &Uri) {
        for node in &self.upstreams {
            if &node.uri == uri {
                node.mark_dead();
                break;
            }
        }
    }

    /// Marks an upstream node as alive after a successful request or health check.
    pub fn mark_alive(&self, uri: &Uri) {
        for node in &self.upstreams {
            if &node.uri == uri {
                node.mark_alive();
                break;
            }
        }
    }

    /// Selects the next upstream node based on the configured load-balancing strategy.
    pub fn next_upstream(
        &self,
        client_ip: Option<&std::net::SocketAddr>,
        failed_uris: &[Uri],
    ) -> &UpstreamNode {
        // Filter available nodes first
        let available: Vec<&UpstreamNode> = self
            .upstreams
            .iter()
            .filter(|n| n.is_available(self.cooldown_seconds) && !failed_uris.contains(&n.uri))
            .collect();

        let slice = if !available.is_empty() {
            available
        } else {
            // Fallback 1: try nodes not explicitly failed this request
            let f1: Vec<&UpstreamNode> = self
                .upstreams
                .iter()
                .filter(|n| !failed_uris.contains(&n.uri))
                .collect();
            if f1.is_empty() {
                // Fallback 2: return all upstreams
                self.upstreams.iter().collect()
            } else {
                f1
            }
        };

        if slice.len() == 1 {
            return slice[0];
        }

        match self.strategy {
            LbStrategy::RoundRobin => {
                let count = self
                    .rr_counter
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                slice[count % slice.len()]
            }
            LbStrategy::Random => {
                use rand::Rng;
                let index = rand::thread_rng().gen_range(0..slice.len());
                slice[index]
            }
            LbStrategy::LeastConnections => slice
                .into_iter()
                .min_by_key(|node| {
                    node.active_connections
                        .load(std::sync::atomic::Ordering::Relaxed)
                })
                .unwrap(),
            LbStrategy::Sticky => {
                let hash = if let Some(addr) = client_ip {
                    use std::hash::{Hash, Hasher};
                    let mut hasher = std::collections::hash_map::DefaultHasher::new();
                    addr.ip().hash(&mut hasher);
                    hasher.finish() as usize
                } else {
                    // Fallback to random if no IP is provided
                    rand::random::<usize>()
                };
                slice[hash % slice.len()]
            }
            LbStrategy::HighestScore => slice
                .into_iter()
                .max_by_key(|node| {
                    node.current_score
                        .load(std::sync::atomic::Ordering::Relaxed)
                })
                .unwrap(),
        }
    }
}

/// A processed reverse-proxy route ready for use by the router.
///
/// Created from [`RouteConfig`] during [`ServerConfig::finalize`].
#[derive(Debug, Clone)]
pub struct ParsedRoute {
    /// The path prefix that triggers this route (e.g. `"/api"`).
    pub prefix: String,
    /// The load-balanced target composed of upstreams and a strategy.
    pub target: Arc<RouteTarget>,
    /// Roles permitted to access this route.
    pub allowed_roles: Vec<UserRole>,
    /// The type of backend (rest or grpc).
    pub backend_type: RouteBackendType,
}

// --- Middleware Layer Structures ---

/// Represents the various middleware layers that can be applied to a service.
///
/// Each variant corresponds to a string in the `[Layers].enabled` TOML list
/// and may carry configuration data extracted from sibling TOML sections.
#[derive(Debug, Clone)]
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
pub struct MaxPayloadConfig {
    /// Maximum allowed request body size in bytes.
    pub max_bytes: usize,
}

/// Configuration for the decompression layer's bomb protection.
#[derive(Debug, Deserialize, Clone)]
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
#[derive(Debug, Deserialize, Clone)]
pub struct RouterParams {
    /// Protocol for upstream connections (HTTP or HTTPS).
    #[serde(default)]
    pub protocol: Protocol,
    /// Authentication method for upstream connections.
    #[serde(default)]
    pub authentication: AuthenticationMethod,
    /// Path to the root CA certificate for verifying upstream TLS.
    pub ssl_root_certificate: Option<String>,
    /// Path to a JWT token file for upstream authentication.
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

/// Parameters for the Identity Provider (IdP) service.
///
/// Controls how the IdP issues tokens and manages sessions.
#[derive(Debug, Deserialize, Clone)]
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


/// Server TLS certificate and key paths.
#[derive(Debug, Deserialize, Clone)]
pub struct ServerCertConfig {
    /// Path to the PEM-encoded server certificate chain.
    pub ssl_certificate: String,
    /// Path to the PEM-encoded server private key.
    pub ssl_certificate_key: String,
}

/// Client CA certificate configuration for mTLS.
#[derive(Debug, Deserialize, Clone)]
pub struct ClientCertConfig {
    /// Path to the PEM-encoded client CA certificate.
    pub ssl_client_ca: String,
    /// Optional path to a PEM-encoded Certificate Revocation List.
    pub ssl_client_crl: Option<String>,
}

/// Configuration for client certificate forwarding.
#[derive(Debug, Deserialize, Clone)]
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

fn default_load_shed() -> bool {
    true
}

/// Configuration for the simple fixed-window rate limiter.
#[derive(Debug, Deserialize, Clone)]
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
}

/// Configuration for the token-bucket rate limiter.
#[derive(Debug, Deserialize, Clone)]
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
}

/// Configuration for the artificial delay layer.
#[derive(Debug, Deserialize, Clone)]
pub struct DelayConfig {
    /// Delay duration in microseconds.
    pub delay_micros: u64,
}

/// Configuration for the JWT authentication layer.
#[derive(Debug, Deserialize, Clone)]
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
}

fn default_max_connections() -> usize {
    10_000
}

fn default_max_connections_per_ip() -> usize {
    100
}

/// Configuration for server connection limits (global and per-IP).
#[derive(Debug, Deserialize, Clone, Copy, PartialEq, Eq)]
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
#[derive(Debug, Deserialize, Clone, Default)]
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
            if path.starts_with(pfx) {
                if rules.iter().any(|re| re.is_match(full_path)) {
                    return true;
                }
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
            let parsed: Vec<u64> = oid_str
                .split('.')
                .map(|s| {
                    s.parse::<u64>()
                        .with_context(|| format!("Invalid OID component in config: '{}'", s))
                })
                .collect::<Result<Vec<u64>, Error>>()?;

            // Store the optimized vector
            config.parsed_pki_base_oid = Some(parsed);
        }

        // 4. Finalize individual server settings (e.g. compile regexes, load certs, validate layers)
        for server in config.servers.iter_mut() {
            server.finalize()?;
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

impl ServerConfig {
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
        self.static_name = Some(Box::leak(self.name.clone().into_boxed_str()));
        let server_name = self.name.clone();

        // Eagerly pre-load TLS CertifiedKey if HTTPS is enabled
        if self.protocol == Protocol::Https {
            if let Some(cert_config) = &self.server_certs {
                let static_name = self.static_name.expect("static_name initialized");
                let loaded_key = crate::tls_conf::load_certified_key(static_name, cert_config)?;
                self.certified_key = Some(loaded_key);
            } else {
                return Err(Error::msg(format!(
                    "Configuration error in Server '{}': Protocol is 'https' but [Server.server_certs] (ssl_certificate/key) is missing.",
                    self.name
                )));
            }
        }

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
            AuthenticationMethod::ClientCert => {
                if self.client_certs.is_none() {
                    return Err(Error::msg(format!(
                        "Configuration error in Server '{}': Authentication is 'ClientCert' (mTLS), but [[Server.client_certs]] is missing.",
                        self.name
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

            AuthenticationMethod::OptionalClientCert => {
                if self.client_certs.is_none() {
                    return Err(Error::msg(format!(
                        "Configuration error in Server '{}': Authentication is 'OptionalClientCert' (mTLS), but [[Server.client_certs]] is missing.",
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

            if idp_params.cookie_name.starts_with("__Host-") && self.protocol != Protocol::Https {
                return Err(Error::msg(format!(
                    "Configuration error in Server '{}': Service is 'Idp' using '__Host-' cookie, but Protocol is not 'Https'. This will be rejected by browsers.",
                    self.name
                )));
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

            for (prefix, cfg) in map {
                if cfg.upstreams.is_empty() {
                    return Err(Error::msg(format!(
                        "Configuration error: Route '{}' has no upstreams defined.",
                        prefix
                    )));
                }

                let mut upstream_nodes = Vec::with_capacity(cfg.upstreams.len());
                for upstream in &cfg.upstreams {
                    let uri_str =
                        if upstream.starts_with("http://") || upstream.starts_with("https://") {
                            upstream.to_string()
                        } else {
                            format!("{proto_str}://{upstream}")
                        };

                    let uri = uri_str
                        .parse::<Uri>()
                        .with_context(|| format!("Invalid upstream URI: {uri_str}"))?;

                    upstream_nodes.push(UpstreamNode {
                        uri,
                        active_connections: std::sync::atomic::AtomicUsize::new(0),
                        is_alive: std::sync::atomic::AtomicBool::new(true),
                        last_failure_time: std::sync::atomic::AtomicU64::new(0),
                        current_score: std::sync::atomic::AtomicUsize::new(0),
                    });
                }

                let target = RouteTarget {
                    upstreams: upstream_nodes,
                    strategy: cfg.strategy.clone(),
                    rr_counter: std::sync::atomic::AtomicUsize::new(0),
                    cooldown_seconds: cfg.cooldown_seconds.unwrap_or(10),
                    max_retries: cfg.max_retries.unwrap_or(2),
                    active_health_check_interval: cfg.active_health_check_interval.unwrap_or(0),
                    grpc_pool: tokio::sync::RwLock::new(None),
                    grpc_reflection_lock: tokio::sync::Mutex::new(()),
                };

                rules.push(ParsedRoute {
                    prefix: prefix.clone(),
                    target: std::sync::Arc::new(target),
                    allowed_roles: cfg.allowed_roles.clone(),
                    backend_type: cfg.backend_type.clone(),
                });
            }
        }
        // Sort by descending prefix length for longest-prefix-first matching.
        rules.sort_by(|a, b| b.prefix.len().cmp(&a.prefix.len()));
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
                            let pfx = if pattern.ends_with("/*") {
                                &pattern[..pattern.len() - 1] // Keep trailing slash: "/api/"
                            } else {
                                &pattern[..pattern.len() - 1] // e.g. "/api"
                            };
                            prefix.push((pfx.to_string(), regexes));
                        } else {
                            exact.insert(pattern.clone(), regexes);
                        }
                    }
                }

                // Deterministic longest-prefix match: sort descending by prefix length
                prefix.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

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
    /// Compiles raw string patterns from the `[Server.rbac]` table.
    ///
    /// Keys ending with `*` are treated as prefix matches (e.g. `"/api/Admin*"` or `"/api/admin/*"`).
    /// Other keys are treated as exact path matches.
    pub fn from_raw(raw: &HashMap<String, Vec<UserRole>>) -> Self {
        let mut exact = HashMap::new();
        let mut prefix = Vec::new();

        for (pattern, roles) in raw {
            if pattern.ends_with('*') {
                let pfx = &pattern[..pattern.len() - 1];
                prefix.push((pfx.to_string(), roles.clone()));
            } else {
                exact.insert(pattern.clone(), roles.clone());
            }
        }

        // Sort descending by prefix length: most specific prefix wins
        prefix.sort_by(|a, b| b.0.len().cmp(&a.0.len()));

        Self { exact, prefix }
    }

    /// Matches a request path against exact and prefix RBAC rules.
    ///
    /// Exact matches take precedence over prefix matches.
    /// Returns `Some(&[UserRole])` if a rule matched, or `None` if no rule matched.
    pub fn match_path<'a>(&'a self, path: &str) -> Option<&'a [UserRole]> {
        if let Some(roles) = self.exact.get(path) {
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
        if let Some(idx) = self.enabled.iter().position(|l| l == "TraceId") {
            if idx != 0 {
                return Err(Error::msg(
                    "TraceId layer must be FIRST (outermost) in [Server.Layers].enabled to capture all requests."
                ));
            }
        }

        // Rule 2: Inspection must come AFTER Decompression
        if let Some(insp_idx) = self.enabled.iter().position(|l| l == "Inspection") {
            if let Some(decomp_idx) = self.enabled.iter().position(|l| l == "Decompression") {
                if insp_idx < decomp_idx {
                    return Err(Error::msg(
                        format!(
                            "Inspection (at index {}) must come AFTER Decompression (at index {}). Otherwise the WAF inspects compressed bytes!",
                            insp_idx, decomp_idx
                        )
                    ));
                }
            }
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
                    if c.allow_credentials && c.allowed_origins.iter().any(|o| o == "*") {
                        return Err(Error::msg(format!(
                            "{}: Layer 'Cors': allow_credentials cannot be true when allowed_origins contains wildcard '*' (violates CORS specification and causes panic in tower-http)",
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
mod tests {
    use super::*;

    #[test]
    fn test_server_with_tunnel_optional_ip_port() {
        let toml_str = r#"
            name = "tunnel_server"
            enabled = true
            protocol = "http"
            service = "Echo"

            [tunnel]
            target_url = "tls://localhost:7001"
            sni_domain = "example.com"
            client_cert_path = "dummy.pem"
            client_key_path = "dummy.key"
            ca_cert_path = "dummy_ca.pem"

            [Layers]
            enabled = []
        "#;
        let mut server: ServerConfig = toml::from_str(toml_str).unwrap();
        assert!(server.ip.is_none());
        assert!(server.port.is_none());
        assert!(server.finalize().is_ok());
        assert_eq!(server.tunnel.as_ref().unwrap().max_yamux_streams, None);
        assert!(server.tunnel.as_ref().unwrap().proxy_protocol);
    }

    #[test]
    fn test_tunnel_config_custom_max_yamux_streams() {
        let toml_str = r#"
            name = "custom_tunnel_server"
            enabled = true
            protocol = "http"
            service = "Echo"

            [tunnel]
            target_url = "tls://localhost:7001"
            sni_domain = "example.com"
            client_cert_path = "dummy.pem"
            client_key_path = "dummy.key"
            ca_cert_path = "dummy_ca.pem"
            max_yamux_streams = 8192

            [Layers]
            enabled = []
        "#;
        let mut server: ServerConfig = toml::from_str(toml_str).unwrap();
        assert!(server.finalize().is_ok());
        assert_eq!(server.tunnel.as_ref().unwrap().max_yamux_streams, Some(8192));
    }

    #[test]
    fn test_server_without_tunnel_requires_ip_and_port() {
        let toml_str = r#"
            name = "listen_server"
            enabled = true
            protocol = "http"
            service = "Echo"

            [Layers]
            enabled = []
        "#;
        let mut server: ServerConfig = toml::from_str(toml_str).unwrap();
        assert!(server.ip.is_none());
        assert!(server.port.is_none());
        let res = server.finalize();
        assert!(res.is_err());
        let err_msg = res.unwrap_err().to_string();
        assert!(err_msg.contains("'ip' is required"));
    }

    #[test]
    fn test_cors_wildcard_with_credentials_rejected() {
        let toml_str = r#"
            name = "cors_test"
            enabled = true
            protocol = "http"
            service = "Echo"
            ip = "127.0.0.1"
            port = 8080

            [Layers]
            enabled = ["Cors"]

            [Layers.Cors]
            allowed_origins = ["*"]
            allow_credentials = true
            allowed_methods = ["GET"]
            allowed_headers = ["*"]
        "#;
        let mut server: ServerConfig = toml::from_str(toml_str).unwrap();
        let res = server.finalize();
        assert!(res.is_err());
        let err_msg = format!("{:#}", res.unwrap_err());
        assert!(err_msg.contains("Cors") && err_msg.contains("allow_credentials"));
    }

    #[test]
    fn test_rate_limiter_zero_rps_rejected() {
        let toml_str = r#"
            name = "rate_limit_test"
            enabled = true
            protocol = "http"
            service = "Echo"
            ip = "127.0.0.1"
            port = 8080

            [Layers]
            enabled = ["RateLimiter:Simple"]

            [Layers.RateLimiter]
            requests_per_second = 0
        "#;
        let mut server: ServerConfig = toml::from_str(toml_str).unwrap();
        let res = server.finalize();
        assert!(res.is_err());
        let err_msg = format!("{:#}", res.unwrap_err());
        assert!(err_msg.contains("requests_per_second must be greater than 0"));
    }

    #[test]
    fn test_concurrency_limit_zero_rejected() {
        let toml_str = r#"
            name = "concurrency_test"
            enabled = true
            protocol = "http"
            service = "Echo"
            ip = "127.0.0.1"
            port = 8080

            [Layers]
            enabled = ["ConcurrencyLimit"]

            [Layers.ConcurrencyLimit]
            max_concurrent_requests = 0
        "#;
        let mut server: ServerConfig = toml::from_str(toml_str).unwrap();
        let res = server.finalize();
        assert!(res.is_err());
        let err_msg = format!("{:#}", res.unwrap_err());
        assert!(err_msg.contains("max_concurrent_requests must be greater than 0"));
    }

    #[test]
    fn test_router_params_defaults() {
        let toml_str = r#"
            protocol = "http"
        "#;
        let params: RouterParams = toml::from_str(toml_str).unwrap();
        assert_eq!(params.connect_timeout_seconds, 5);
        assert_eq!(params.request_timeout_seconds, 30);
        assert_eq!(params.idle_timeout_seconds, 90);
        assert_eq!(params.grpc_reflection_timeout_seconds, 10);
        assert_eq!(params.grpc_reflection_ttl_seconds, 600);
    }

    #[test]
    fn test_router_params_custom_timeouts() {
        let toml_str = r#"
            protocol = "https"
            connect_timeout_seconds = 2
            request_timeout_seconds = 15
            idle_timeout_seconds = 45
            grpc_reflection_timeout_seconds = 8
            grpc_reflection_ttl_seconds = 300
        "#;
        let params: RouterParams = toml::from_str(toml_str).unwrap();
        assert_eq!(params.connect_timeout_seconds, 2);
        assert_eq!(params.request_timeout_seconds, 15);
        assert_eq!(params.idle_timeout_seconds, 45);
        assert_eq!(params.grpc_reflection_timeout_seconds, 8);
        assert_eq!(params.grpc_reflection_ttl_seconds, 300);
    }

    #[test]
    fn test_connection_limits_defaults() {
        let toml_str = r#"
            name = "conn_limits_default"
            enabled = true
            protocol = "http"
            service = "Echo"
            ip = "127.0.0.1"
            port = 8080

            [Layers]
            enabled = []
        "#;
        let mut server: ServerConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(server.connection_limits.max_connections, 10_000);
        assert_eq!(server.connection_limits.max_connections_per_ip, 100);
        assert!(server.finalize().is_ok());
    }

    #[test]
    fn test_connection_limits_custom() {
        let toml_str = r#"
            name = "conn_limits_custom"
            enabled = true
            protocol = "http"
            service = "Echo"
            ip = "127.0.0.1"
            port = 8080

            [Layers]
            enabled = []

            [connection_limits]
            max_connections = 500
            max_connections_per_ip = 25
        "#;
        let mut server: ServerConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(server.connection_limits.max_connections, 500);
        assert_eq!(server.connection_limits.max_connections_per_ip, 25);
        assert!(server.finalize().is_ok());
    }

    #[test]
    fn test_connection_limits_zero_rejected() {
        let toml_str = r#"
            name = "conn_limits_zero"
            enabled = true
            protocol = "http"
            service = "Echo"
            ip = "127.0.0.1"
            port = 8080

            [Layers]
            enabled = []

            [connection_limits]
            max_connections = 0
            max_connections_per_ip = 25
        "#;
        let mut server: ServerConfig = toml::from_str(toml_str).unwrap();
        let res = server.finalize();
        assert!(res.is_err());
        assert!(format!("{:#}", res.unwrap_err()).contains("max_connections must be strictly greater than 0"));

        let toml_str_ip_zero = r#"
            name = "conn_limits_ip_zero"
            enabled = true
            protocol = "http"
            service = "Echo"
            ip = "127.0.0.1"
            port = 8080

            [Layers]
            enabled = []

            [connection_limits]
            max_connections = 100
            max_connections_per_ip = 0
        "#;
        let mut server_ip_zero: ServerConfig = toml::from_str(toml_str_ip_zero).unwrap();
        let res_ip = server_ip_zero.finalize();
        assert!(res_ip.is_err());
        assert!(format!("{:#}", res_ip.unwrap_err()).contains("max_connections_per_ip must be strictly greater than 0"));
    }

    #[test]
    fn test_compiled_rbac_matching() {
        let toml_str = r#"
            name = "rbac_test_server"
            enabled = true
            protocol = "http"
            service = "Echo"
            ip = "127.0.0.1"
            port = 8080

            [Layers]
            enabled = []

            [rbac]
            "/api/Admin*" = ["Admin"]
            "/api/AdminGetProducts" = ["Admin", "Seller"]
            "/api/GetDatabaseTables" = ["Admin"]
            "/api/Public*" = ["*"]
            "/api/Blocked" = []
        "#;
        let mut server: ServerConfig = toml::from_str(toml_str).unwrap();
        assert!(server.finalize().is_ok());

        let compiled = server.compiled_rbac.as_ref().expect("compiled_rbac should be populated");

        // Exact match
        let tables_roles = compiled.match_path("/api/GetDatabaseTables").unwrap();
        assert_eq!(tables_roles, &[UserRole("Admin".to_string())]);

        // Exact match overrides prefix
        let products_roles = compiled.match_path("/api/AdminGetProducts").unwrap();
        assert_eq!(products_roles, &[UserRole("Admin".to_string()), UserRole("Seller".to_string())]);

        // Prefix match
        let delete_user_roles = compiled.match_path("/api/AdminDeleteUser").unwrap();
        assert_eq!(delete_user_roles, &[UserRole("Admin".to_string())]);

        // Wildcard role prefix
        let public_roles = compiled.match_path("/api/Public/hello").unwrap();
        assert_eq!(public_roles, &[UserRole("*".to_string())]);

        // Empty role list (blocked)
        let blocked_roles = compiled.match_path("/api/Blocked").unwrap();
        assert!(blocked_roles.is_empty());

        // Unmatched path
        assert!(compiled.match_path("/other/path").is_none());
    }

    #[test]
    fn test_upstream_node_mark_dead_and_is_available() {
        let node = UpstreamNode {
            uri: "http://127.0.0.1:8080".parse().unwrap(),
            active_connections: std::sync::atomic::AtomicUsize::new(0),
            is_alive: std::sync::atomic::AtomicBool::new(true),
            last_failure_time: std::sync::atomic::AtomicU64::new(0),
            current_score: std::sync::atomic::AtomicUsize::new(100),
        };

        // 1. Initially alive
        assert!(node.is_available(10));

        // 2. Mark dead -> unavailable immediately
        node.mark_dead();
        assert!(!node.is_available(10));

        // 3. Manually reset last_failure_time to 0 while is_alive=false -> must still be unavailable!
        node.last_failure_time.store(0, std::sync::atomic::Ordering::Relaxed);
        assert!(!node.is_available(10));

        // 4. Simulate cooldown elapsed
        let past = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() - 15;
        node.last_failure_time.store(past, std::sync::atomic::Ordering::Relaxed);
        assert!(node.is_available(10)); // 15s > 10s cooldown -> now available for retry

        // 5. Recover node
        node.mark_alive();
        assert!(node.is_available(10));
        assert_eq!(node.last_failure_time.load(std::sync::atomic::Ordering::Relaxed), 0);
    }

    #[test]
    fn test_security_headers_outermost_positioning() {
        let custom_csp = "default-src 'self'; img-src 'self' data:".to_string();
        let layers_cfg = Layers {
            enabled: vec![
                "Logger".to_string(),
                "Inspection".to_string(),
                "ConcurrencyLimit".to_string(),
            ],
            security_headers_config: Some(SecurityHeadersConfig {
                content_security_policy: custom_csp.clone(),
                ..Default::default()
            }),
            concurrency_limit_config: Some(ConcurrencyLimitConfig {
                max_concurrent_requests: 100,
                load_shed: true,
                queue_timeout_ms: None,
            }),
            ..Default::default()
        };

        let layers = layers_cfg.build_middleware_layers("test_server").unwrap();
        // SecurityHeaders must be placed near the top (outermost) so it intercepts short-circuit responses
        // and must preserve custom [Server.Layers.SecurityHeaders] settings even if not in `enabled`.
        assert!(matches!(layers[0], MiddlewareLayer::Logger));
        match &layers[1] {
            MiddlewareLayer::SecurityHeaders(cfg) => {
                assert_eq!(cfg.content_security_policy, custom_csp);
            }
            other => panic!("Expected SecurityHeaders at index 1, got {:?}", other),
        }
        assert!(matches!(layers[2], MiddlewareLayer::Inspection));
        assert!(matches!(layers[3], MiddlewareLayer::ConcurrencyLimit(_)));
    }

    #[test]
    fn test_compiled_allowed_pathes_longest_prefix_and_methods() {
        let mut post_rules = HashMap::new();
        // Exact rule
        post_rules.insert(
            "/api/v2/special".to_string(),
            vec!["^/api/v2/special$".to_string()],
        );
        // More specific prefix rule
        post_rules.insert(
            "/api/v2/*".to_string(),
            vec!["^/api/v2/items/[0-9]+$".to_string()],
        );
        // Broader prefix rule
        post_rules.insert(
            "/api/*".to_string(),
            vec!["^/api/.*$".to_string()],
        );

        let mut get_rules = HashMap::new();
        get_rules.insert("/status".to_string(), vec!["^/status$".to_string()]);

        let mut patch_rules = HashMap::new();
        patch_rules.insert("/update".to_string(), vec!["^/update$".to_string()]);

        let mut head_rules = HashMap::new();
        head_rules.insert("/ping".to_string(), vec!["^/ping$".to_string()]);

        let raw = AllowedPathes {
            post: Some(post_rules),
            get: Some(get_rules),
            patch: Some(patch_rules),
            head: Some(head_rules),
            ..Default::default()
        };

        let compiled = CompiledAllowedPathes::from_raw(&raw).unwrap();

        // 1. Exact match
        assert!(compiled.is_allowed("POST", "/api/v2/special", ""));

        // 2. Longest prefix: /api/v2/items/123 matches /api/v2/*
        assert!(compiled.is_allowed("POST", "/api/v2/items/123", ""));

        // 3. /api/v1/other matches broader /api/*
        assert!(compiled.is_allowed("POST", "/api/v1/other", ""));

        // 4. /api/v2/letters doesn't match /api/v2/* pattern, but falls through to broader /api/*
        assert!(compiled.is_allowed("POST", "/api/v2/letters", ""));

        // 5. Unmatched path
        assert!(!compiled.is_allowed("POST", "/other", ""));

        // 6. PATCH support
        assert!(compiled.is_allowed("PATCH", "/update", ""));
        assert!(!compiled.is_allowed("PATCH", "/status", ""));

        // 7. Explicit HEAD support
        assert!(compiled.is_allowed("HEAD", "/ping", ""));

        // 8. HEAD fallback to GET (/status is in GET)
        assert!(compiled.is_allowed("HEAD", "/status", ""));

        // 9. OPTIONS matches if any method allows the path
        assert!(compiled.is_allowed("OPTIONS", "/status", ""));
        assert!(compiled.is_allowed("OPTIONS", "/update", ""));
        assert!(!compiled.is_allowed("OPTIONS", "/unregistered", ""));

        // 10. Unsupported method
        assert!(!compiled.is_allowed("TRACE", "/status", ""));
    }

    #[test]
    fn test_chatapp_admin_rbac_and_idp_allowed_pathes() {
        for config_path in [
            "../conf.d/01_chatapp.toml.template",
            "../conf.d/01_chatapp.toml.local.template",
            "../conf.d/01_chatapp.toml",
        ] {
            let toml_str = std::fs::read_to_string(config_path)
                .unwrap_or_else(|e| panic!("Failed to read {}: {}", config_path, e));
            let value: toml::Value = toml::from_str(&toml_str).unwrap();
            let servers_arr = value
                .get("Server")
                .and_then(|v| v.as_array())
                .expect("Expected [[Server]] array in config");

            let servers: Vec<ServerConfig> = servers_arr
                .iter()
                .map(|v| v.clone().try_into().expect("Failed to deserialize ServerConfig"))
                .collect();

            // 1. Verify wurzelwerk_admin RBAC rules
            let admin_srv = servers
                .iter()
                .find(|s| s.name == "wurzelwerk_admin")
                .expect("wurzelwerk_admin missing");
            let rbac = CompiledRbac::from_raw(admin_srv.rbac.as_ref().unwrap());

            let seller_allowed = [
                "/api/Logout",
                "/api/WhoAmI",
                "/api/GetAdminConversations",
                "/api/AdminGetMembers",
                "/api/GetAdminOrders",
                "/api/AdminUpdateOrderStatus",
                "/api/AdminGetProducts",
                "/api/AdminAddProduct",
                "/api/AdminDeleteProduct",
                "/api/AdminGetRides",
                "/api/AdminGetRideRequests",
                "/api/AdminGetRideBookings",
                "/api/AdminDeleteRide",
                "/api/AdminDeleteRideReq",
            ];
            for path in &seller_allowed {
                let roles = rbac.match_path(path).expect(path);
                assert!(
                    roles.contains(&UserRole("Seller".to_string())),
                    "Expected Seller to be allowed on {} in {}",
                    path,
                    config_path
                );
            }

            // Every other POST path in AllowedPathes must strictly require Admin only
            let admin_post_paths = admin_srv
                .allowed_pathes
                .as_ref()
                .unwrap()
                .post
                .as_ref()
                .unwrap();
            for path in admin_post_paths.keys() {
                if !seller_allowed.contains(&path.as_str()) {
                    let roles = rbac
                        .match_path(path)
                        .unwrap_or_else(|| panic!("Missing RBAC rule for {} in {}", path, config_path));
                    assert_eq!(
                        roles,
                        &[UserRole("Admin".to_string())],
                        "Endpoint {} must be restricted to Admin only in {}",
                        path,
                        config_path
                    );
                }
            }

            // 2. Verify wurzelwerk_idp AllowedPathes & Layers
            let idp_srv = servers
                .iter()
                .find(|s| s.name == "wurzelwerk_idp")
                .expect("wurzelwerk_idp missing");
            let idp_paths = CompiledAllowedPathes::from_raw(idp_srv.allowed_pathes.as_ref().unwrap()).unwrap();
            assert!(idp_paths.is_allowed("GET", "/.well-known/jwks.json", ""));
            assert!(idp_paths.is_allowed("GET", "/auth/login_page", "aud=admin-dashboard"));
            assert!(idp_paths.is_allowed("GET", "/auth/status", "session=abc_123&poll_secret=xyz-456"));
            assert!(idp_paths.is_allowed("POST", "/auth/login", "aud=admin-dashboard"));
            assert!(idp_paths.is_allowed("POST", "/auth/confirm", "session=abc_123&code=234-567"));
            assert!(idp_paths.is_allowed("POST", "/auth/revoke", ""));
            assert!(!idp_paths.is_allowed("GET", "/admin", ""));
        }
    }

    #[test]
    fn test_ip_filter_config_validation() {
        let valid_toml = r#"
            name = "ip_filter_valid"
            enabled = true
            protocol = "http"
            service = "Echo"
            ip = "127.0.0.1"
            port = 8080

            [Layers]
            enabled = ["IpFilter"]

            [Layers.IpFilter]
            allow_cidrs = ["10.0.0.0/8", "127.0.0.1/32", "::1/128"]
            deny_cidrs = ["10.99.0.0/16"]
        "#;
        let mut srv_ok: ServerConfig = toml::from_str(valid_toml).unwrap();
        assert!(srv_ok.finalize().is_ok());

        let invalid_cidr_toml = r#"
            name = "ip_filter_invalid"
            enabled = true
            protocol = "http"
            service = "Echo"
            ip = "127.0.0.1"
            port = 8080

            [Layers]
            enabled = ["IpFilter"]

            [Layers.IpFilter]
            allow_cidrs = ["10.0.0.0/99"]
        "#;
        let mut srv_bad: ServerConfig = toml::from_str(invalid_cidr_toml).unwrap();
        let res = srv_bad.finalize();
        assert!(res.is_err());
        assert!(format!("{:#}", res.unwrap_err()).contains("invalid allow_cidrs entry"));
    }
}

