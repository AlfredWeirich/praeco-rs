//! # Middleware Layer Catalogue
//!
//! This module re-exports every Tower middleware layer and service used by the
//! server. Each sub-module follows the **Layer + Service** pattern defined by
//! the [`tower`] crate:
//!
//! - A **`Layer`** is a factory: it wraps an inner service to produce a new,
//!   decorated service.
//! - A **`Service`** is the runtime component that intercepts requests and/or
//!   responses.
//!
//! ## Available Middleware
//!
//! | Module | Layer | Purpose |
//! |--------|-------|---------|
//! | [`alt_svc`] | [`AltSvcLayer`] | Injects the `Alt-Svc` header to advertise HTTP/3. |
//! | [`cache`] | [`CacheLayer`] | Process-wide W-TinyLFU HTTP response cache with cancellation-safe [`Singleflight`]. |
//! | [`cache_l2`] | [`L2CacheBackend`] | Optional L2 wire codec (`PRC2`), bounded write budget, circuit breaker & in-memory test cluster. |
//! | [`compression`] | [`SrvCompressionLayer`] / [`SrvDecompressionLayer`] | Gzip/Brotli response compression and request decompression with bomb protection. |
//! | [`counter`] | [`CountingLayer`] | Atomic request counter with periodic logging. |
//! | [`delay`] | [`DelayLayer`] | Artificial latency injection (testing / simulation). |
//! | [`echo`] | — | Simple echo service (no layer; used as a base service). |
//! | [`inspection`] | [`InspectionLayer`] | Regex-based path allow-listing (WAF-lite). |
//! | [`ip_filter`] | [`IpFilterLayer`] | IPv4/IPv6 CIDR allowlist and blocklist enforcement. |
//! | [`jwt`] | [`JwtAuthLayer`] | JWT bearer-token authentication and role mapping. |
//! | [`limit`] | [`MaxPayloadLayer`] | Request body size enforcement (header + streaming). |
//! | [`logger`] | [`LoggerLayer`] | Request/response logging with client IP and role info. |
//! | [`path_sanitizer`] | [`PathSanitizerLayer`] | RFC 3986 path canonicalization and directory traversal protection. |
//! | [`rate_limiter`] | [`SimpleRateLimiterLayer`] / [`TokenBucketRateLimiterLayer`] | Fixed-window and token-bucket rate limiting. |
//! | [`rbac`] | [`RbacLayer`] | Fail-closed path- and method-based Role-Based Access Control. |
//! | [`router`] | — | Reverse-proxy routing service (no layer; used as a base service). |
//! | [`timing`] | [`TimingLayer`] | Request duration measurement and logging. |

// ── Sub-module declarations ──────────────────────────────────────────────────

/// Internal admin & telemetry status and Prometheus metrics service.
pub mod admin;
/// Injects the `Alt-Svc` HTTP header to advertise HTTP/3 support.
pub mod alt_svc;
/// Process-wide W-TinyLFU HTTP response cache and cancellation-safe Singleflight.
pub mod cache;
/// Optional L2 response cache backend abstractions, `PRC2` wire codec, and test cluster.
#[cfg(feature = "cache-l2-dragonfly")]
pub mod cache_l2;
/// Gzip / Brotli response compression and request decompression.
pub mod compression;
/// Atomic request counter with periodic log output.
pub mod counter;
/// Artificial request delay for testing / latency simulation.
pub mod delay;
/// Simple echo service used for diagnostics and load testing.
pub mod echo;
/// Identity Provider end-service.
pub mod idp;

/// Regex-based request path inspection (allow-list enforcement).
pub mod inspection;
/// IPv4 and IPv6 CIDR allowlist / blocklist middleware.
pub mod ip_filter;
/// JWT bearer-token authentication middleware.
pub mod jwt;
/// Maximum request payload size enforcement.
pub mod limit;
/// Request/response logging with client metadata.
pub mod logger;
/// Rate limiting (simple fixed-window and token-bucket algorithms).
pub mod rate_limiter;
/// Fail-closed path- and method-based Role-Based Access Control middleware.
pub mod rbac;
/// Reverse-proxy routing service with URI rewriting and upstream pooling.
pub mod router;
/// Security Headers injection layer.
pub mod security_headers;
/// Request timing / duration measurement.
pub mod timing;
/// Trace ID injection for observability.
pub mod trace_id;
/// Strict path sanitization and canonicalization (RFC 3986).
pub mod path_sanitizer;

// ── Convenience re-exports ───────────────────────────────────────────────────

pub use admin::AdminService;
pub use alt_svc::AltSvcLayer;
pub use cache::{
    CacheBypass, CacheLayer, CacheService, CachedResponse, FlightAborted, SharedResponseCache,
    Singleflight, configure_global_response_cache, global_response_cache,
};
#[cfg(feature = "cache-l2-dragonfly")]
pub use cache_l2::{
    InMemoryL2Backend, InMemoryL2Cluster, L2CacheBackend, L2CircuitBreaker, L2CircuitState,
    L2InvalidationEvent, L2LookupOutcome, L2StatusSnapshot, L2WireError, L2WriteBudget,
    L2WritePermit,
};
pub use counter::CountingLayer;
pub use delay::DelayLayer;
pub use echo::EchoService;
pub use inspection::InspectionLayer;
pub use ip_filter::{IpCidr, IpFilterLayer, IpFilterService};
pub use jwt::{JwtAuthLayer, JwtRevocationStore, get_jwt_revocation_store};
pub use limit::{ConcurrencyLimitLayer, MaxPayloadLayer};
pub use logger::LoggerLayer;
pub use path_sanitizer::PathSanitizerLayer;
pub use rate_limiter::{RateLimitKey, RateLimitKeyStrategy, SimpleRateLimiterLayer, TokenBucketRateLimiterLayer};
pub use rbac::RbacLayer;
pub use router::RouterService;
pub use security_headers::SecurityHeadersLayer;
pub use timing::TimingLayer;
pub use trace_id::TraceIdLayer;
