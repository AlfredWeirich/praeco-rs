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

    /// Pre-parsed integer representation of [`pki_base_oid`](Config::pki_base_oid).
    /// Computed in [`Config::init`] for fast OID prefix matching in
    /// [`extract_oids_from_cert`](crate::tls_conf::extract_oids_from_cert).
    #[serde(skip)]
    pub parsed_pki_base_oid: Option<Vec<u64>>,
}

// ============================================================================
//  Per-Server Configuration
// ============================================================================

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
    /// machine's primary local IP at startup.
    pub ip: String,
    /// TCP/UDP port to listen on.
    pub port: u16,
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

    /// Middleware layer configuration (names + per-layer settings).
    #[serde(rename = "Layers")]
    pub layers: Layers,

    /// Optional regex-based allowed path rules for the Inspection layer.
    #[serde(rename = "AllowedPathes")]
    pub allowed_pathes: Option<AllowedPathes>,

    /// Mapping of path prefixes to backend targets (Reverse Proxy logic).
    #[serde(rename = "ReverseRoutes")]
    pub rev_routes: Option<HashMap<String, RouteConfig>>,

    /// Additional parameters for the Router service (upstream protocol,
    /// auth settings, TLS for upstream connections).
    #[serde(rename = "RouterParams")]
    pub router_params: Option<RouterParams>,

    /// Additional parameters for the IdP service (JWT signing key, expiration, etc.).
    #[serde(rename = "IdpParams")]
    pub idp_params: Option<IdpParams>,

    /// Pre-parsed and sorted reverse-proxy routes. Computed in [`ServerConfig::finalize`].
    #[serde(skip)]
    pub parsed_routes: Vec<ParsedRoute>,

    /// Pre-compiled regex patterns for the Inspection layer. Computed in
    /// [`ServerConfig::finalize`].
    #[serde(skip)]
    pub compiled_allowed_pathes: Option<Arc<CompiledAllowedPathes>>,

    /// The loaded TLS private key + certificate chain. Computed in
    /// [`ServerConfig::finalize`] if HTTPS matches.
    #[serde(skip)]
    pub certified_key: Option<Arc<CertifiedKey>>,
}

// ============================================================================
//  Supporting Structures
// ============================================================================

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
            return true;
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        now > last_fail + cooldown_seconds
    }
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
    /// Cached gRPC DescriptorPool from reflection, lazily loaded by the router.
    /// Only used if backend_type is Grpc.
    pub grpc_pool: tokio::sync::RwLock<Option<std::sync::Arc<prost_reflect::DescriptorPool>>>,
}

impl RouteTarget {
    /// Marks an upstream node as dead due to a connection failure.
    pub fn mark_dead(&self, uri: &Uri) {
        for node in &self.upstreams {
            if &node.uri == uri {
                node.is_alive
                    .store(false, std::sync::atomic::Ordering::Relaxed);
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                node.last_failure_time
                    .store(now, std::sync::atomic::Ordering::Relaxed);
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
                let index = fastrand::usize(..slice.len());
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
                    fastrand::usize(..)
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
    ConcurrencyLimit(usize),
    /// Limits the maximum size of request payloads (in bytes).
    MaxPayload(usize),
    /// Adds an Alt-Svc header to the response.
    AltSvc,
    /// Adds CORS headers to responses and handles preflight requests.
    Cors(CorsConfig),
    /// Adds security headers to responses.
    SecurityHeaders(SecurityHeadersConfig),
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
#[derive(Debug, Deserialize, Clone)]
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
    /// Default redirect path after successful login if no `redirect` param is present.
    #[serde(default = "default_redirect")]
    pub redirect_after_login: String,
    /// If true, displays the session ID on the web UI for testing purposes.
    pub debug_show_session_id: Option<bool>,
}

fn default_token_expiry() -> u64 { 900 }
fn default_session_ttl() -> u64 { 120 }
fn default_cookie_name() -> String { "__Host-jwt".to_string() }
fn default_redirect() -> String { "/".to_string() }


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

/// Configuration for the simple fixed-window rate limiter.
#[derive(Debug, Deserialize, Clone)]
pub struct SimpleRateLimiterConfig {
    /// Maximum number of requests per second.
    pub requests_per_second: u64,
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
}

/// Configuration for the concurrency limit layer.
#[derive(Debug, Deserialize, Clone)]
pub struct ConcurrencyLimitConfig {
    /// Maximum number of in-flight requests.
    pub max_concurrent_requests: usize,
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
}

impl Default for SecurityHeadersConfig {
    fn default() -> Self {
        Self {
            content_security_policy: "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:".to_string(),
            strict_transport_security: "max-age=63072000; includeSubDomains; preload".to_string(),
            x_content_type_options: "nosniff".to_string(),
            x_frame_options: "DENY".to_string(),
        }
    }
}

/// Raw deserialized allowed-path rules (per HTTP method).
///
/// Each method maps a base path (e.g. `"/api"`) to a list of regex pattern
/// strings. These are compiled into [`CompiledAllowedPathes`] during
/// [`ServerConfig::finalize`].
#[derive(Debug, Deserialize, Clone)]
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
}

/// Pre-compiled regex patterns for path inspection.
///
/// Created from [`AllowedPathes`] during [`ServerConfig::finalize`].
/// Used by the [`InspectionService`](crate::middleware::inspection::InspectionService)
/// at runtime for zero-allocation path matching.
#[derive(Debug, Clone)]
pub struct CompiledAllowedPathes {
    /// Compiled regex rules for GET requests.
    pub get: HashMap<String, Vec<Regex>>,
    /// Compiled regex rules for POST requests.
    pub post: HashMap<String, Vec<Regex>>,
    /// Compiled regex rules for PUT requests.
    pub put: HashMap<String, Vec<Regex>>,
    /// Compiled regex rules for DELETE requests.
    pub delete: HashMap<String, Vec<Regex>>,
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
    /// Returns an error if the file cannot be read, TOML parsing fails, or
    /// any server's [`finalize`](ServerConfig::finalize) step detects invalid
    /// configuration.
    pub fn init(config_file: &str) -> Result<Arc<Config>, Error> {
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

        // 4. Finalize individual server settings (e.g. compile regexes)
        for server in config.servers.iter_mut() {
            server.finalize()?;
        }

        let arc_config = Arc::new(config);

        // 5. Store in global OnceLock or update ArcSwap
        if let Some(existing) = CONFIG.get() {
            existing.store(arc_config);
        } else if CONFIG.set(ArcSwap::new(arc_config.clone())).is_err() {
            tracing::warn!("Config::init called multiple times concurrently.");
        }

        // 6. Return reference to the global singleton
        Ok(Self::global())
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

        self.init_parsed_routes()?;
        self.init_compiled_allowed_pathes()?;
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
            
            if idp_params.cookie_name.starts_with("__Host-") && self.protocol != Protocol::Https {
                return Err(Error::msg(format!(
                    "Configuration error in Server '{}': Service is 'Idp' using '__Host-' cookie, but Protocol is not 'Https'. This will be rejected by browsers.",
                    self.name
                )));
            }
        }

        Ok(())
    }

    /// Returns the socket address computed from the IP and port configuration.
    ///
    /// The special IP value `"local"` resolves to the machine's primary
    /// local IP address at runtime.
    pub fn get_server_ip(&self) -> Result<SocketAddr, Error> {
        let ip_str = if self.ip == "local" {
            local_ip_address::local_ip()?.to_string()
        } else {
            self.ip.clone()
        };
        format!("{}:{}", ip_str, self.port)
            .parse()
            .with_context(|| format!("Invalid address: {}:{}", ip_str, self.port))
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
        // If allowed_pathes is missing in TOML, we create an empty default object
        let raw = self.allowed_pathes.clone().unwrap_or(AllowedPathes {
            get: None,
            post: None,
            put: None,
            delete: None,
        });

        // Compile (creates empty HashMaps if None)
        self.compiled_allowed_pathes = Some(Arc::new(CompiledAllowedPathes::from_raw(&raw)?));
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
        let compile_map = |opt_map: &Option<HashMap<String, Vec<String>>>| -> Result<HashMap<String, Vec<Regex>>, Error> {
            let mut compiled = HashMap::new();
            if let Some(map) = opt_map {
                for (path, patterns) in map {
                    let regexes: Result<Vec<_>, _> = patterns.iter().map(|p| Regex::new(p)).collect();
                    compiled.insert(path.clone(), regexes.map_err(|e| Error::msg(format!("Regex error: {e}")))?);
                }
            }
            Ok(compiled)
        };

        Ok(Self {
            get: compile_map(&raw.get)?,
            post: compile_map(&raw.post)?,
            put: compile_map(&raw.put)?,
            delete: compile_map(&raw.delete)?,
        })
    }

    /// Helper to find matching regex rules for a path, supporting wildcard suffixes (e.g. `/*`).
    fn find_rules<'a>(map: &'a HashMap<String, Vec<Regex>>, path: &str) -> Option<&'a Vec<Regex>> {
        // 1. Exact match (fast path)
        if let Some(rules) = map.get(path) {
            return Some(rules);
        }
        // 2. Prefix match for wildcards (e.g. "/chat.ChatService/*")
        for (key, rules) in map {
            if key.ends_with("/*") {
                let prefix = &key[..key.len() - 1]; // e.g. "/chat.ChatService/"
                if path.starts_with(prefix) {
                    return Some(rules);
                }
            }
        }
        None
    }

    /// Checks whether a `(method, path, query)` triple matches the allowed rules.
    ///
    /// The full path (including query string if present) is tested against every
    /// regex pattern registered for the given method and base path.
    ///
    /// Returns `false` for unrecognised HTTP methods or for paths that have no
    /// matching regex rules.
    pub fn is_allowed(&self, method: &str, path: &str, query: &str) -> bool {
        // We assemble the full path for check,
        // if a query string exists (matching your regex definitions).
        let full_path = if query.is_empty() {
            path.to_string()
        } else {
            format!("{}?{}", path, query)
        };

        // Selection of the correct map based on the HTTP method
        let map = match method {
            "GET" => &self.get,
            "POST" => &self.post,
            "PUT" => &self.put,
            "DELETE" => &self.delete,
            "OPTIONS" => {
                if let Some(regex_list) = Self::find_rules(&self.post, path)
                    .or_else(|| Self::find_rules(&self.get, path))
                    .or_else(|| Self::find_rules(&self.put, path))
                    .or_else(|| Self::find_rules(&self.delete, path))
                {
                    return regex_list.iter().any(|re| re.is_match(&full_path));
                }
                return false;
            }
            _ => return false,
        };

        // Check: are there regex rules for this base path (e.g. "/help")?
        if let Some(regex_list) = Self::find_rules(map, path) {
            // If so: does at least one of the rules match the full_path?
            regex_list.iter().any(|re| re.is_match(&full_path))
        } else {
            false
        }
    }
}

impl Layers {
    /// Maps the enabled layer names to their corresponding [`MiddlewareLayer`] variants.
    ///
    /// Each string in [`Layers::enabled`] is matched against known layer names.
    /// Layers that require configuration (e.g. `"MaxPayload"`, `"Delay"`) look up
    /// their sibling TOML section and fail with a descriptive error if it is missing.
    ///
    /// # Errors
    ///
    /// Returns an error if an unknown layer name is encountered or if a required
    /// configuration section is absent.
    pub fn build_middleware_layers(&self, server_name: &str) -> Result<Vec<MiddlewareLayer>, Error> {
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
                "Timing" => Ok(MiddlewareLayer::Timing),
                "Counter" => Ok(MiddlewareLayer::Counter),
                "Logger" => Ok(MiddlewareLayer::Logger),
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
                "JwtAuth" | "JWT" => self
                    .jwt_config
                    .as_ref()
                    .map(|c| MiddlewareLayer::JwtAuth(c.clone()))
                    .ok_or_else(|| {
                        Error::msg(format!(
                            "{}: Missing [Server.Layers.JWT] section for JwtAuth layer",
                            server_name
                        ))
                    }),
                "ConcurrencyLimit" => self
                    .concurrency_limit_config
                    .as_ref()
                    .map(|c| MiddlewareLayer::ConcurrencyLimit(c.max_concurrent_requests))
                    .context("Missing [Layers.ConcurrencyLimit]"),
                "Cors" => self
                    .cors_config
                    .as_ref()
                    .map(|c| MiddlewareLayer::Cors(c.clone()))
                    .context("Missing [Layers.Cors]"),
                "SecurityHeaders" => self
                    .security_headers_config
                    .as_ref()
                    .map(|c| MiddlewareLayer::SecurityHeaders(c.clone()))
                    .context("Layer 'SecurityHeaders' enabled but [Server.Layers.SecurityHeaders] section is missing"),
                "RateLimiter:Simple" => self
                    .rate_limiter_config
                    .as_ref()
                    .map(|c| MiddlewareLayer::RateLimiter(RateLimiter::Simple(c.clone())))
                    .context("Missing [Layers.RateLimiter]"),
                "RateLimiter:TokenBucket" => self
                    .token_bucket_config
                    .as_ref()
                    .map(|c| MiddlewareLayer::RateLimiter(RateLimiter::TokenBucket(c.clone())))
                    .context("Missing [Layers.TokenBucketRateLimiter]"),
                "AltSvc" => Ok(MiddlewareLayer::AltSvc),
                other => Err(Error::msg(format!("Unknown layer type: {}", other))),
            })
            .collect::<Result<_, _>>()?;

        // Fallback: If SecurityHeaders was not explicitly enabled in the list,
        // we add it with standard strict defaults to protect the server.
        if !self.enabled.iter().any(|n| n == "SecurityHeaders") {
            layers.push(MiddlewareLayer::SecurityHeaders(
                SecurityHeadersConfig::default(),
            ));
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
