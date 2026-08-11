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
//! | [`compression`] | [`SrvCompressionLayer`] / [`SrvDecompressionLayer`] | Gzip/Brotli response compression and request decompression with bomb protection. |
//! | [`counter`] | [`CountingLayer`] | Atomic request counter with periodic logging. |
//! | [`delay`] | [`DelayLayer`] | Artificial latency injection (testing / simulation). |
//! | [`echo`] | — | Simple echo service (no layer; used as a base service). |
//! | [`inspection`] | [`InspectionLayer`] | Regex-based path allow-listing (WAF-lite). |
//! | [`jwt`] | [`JwtAuthLayer`] | JWT bearer-token authentication and role mapping. |
//! | [`limit`] | [`MaxPayloadLayer`] | Request body size enforcement (header + streaming). |
//! | [`logger`] | [`LoggerLayer`] | Request/response logging with client IP and role info. |
//! | [`rate_limiter`] | [`SimpleRateLimiterLayer`] / [`TokenBucketRateLimiterLayer`] | Fixed-window and token-bucket rate limiting. |
//! | [`router`] | — | Reverse-proxy routing service (no layer; used as a base service). |
//! | [`timing`] | [`TimingLayer`] | Request duration measurement and logging. |

// ── Sub-module declarations ──────────────────────────────────────────────────

/// Injects the `Alt-Svc` HTTP header to advertise HTTP/3 support.
pub mod alt_svc;
/// Gzip / Brotli response compression and request decompression.
pub mod compression;
/// Atomic request counter with periodic log output.
pub mod counter;
/// Artificial request delay for testing / latency simulation.
pub mod delay;
/// Simple echo service used for diagnostics and load testing.
pub mod echo;
/// Regex-based request path inspection (allow-list enforcement).
pub mod inspection;
/// JWT bearer-token authentication middleware.
pub mod jwt;
/// Maximum request payload size enforcement.
pub mod limit;
/// Request/response logging with client metadata.
pub mod logger;
/// Rate limiting (simple fixed-window and token-bucket algorithms).
pub mod rate_limiter;
/// Reverse-proxy routing service with RBAC and URI rewriting.
pub mod router;
/// Security Headers injection layer.
pub mod security_headers;
/// Request timing / duration measurement.
pub mod timing;

// ── Convenience re-exports ───────────────────────────────────────────────────

pub use alt_svc::AltSvcLayer;
pub use counter::CountingLayer;
pub use delay::DelayLayer;
pub use echo::EchoService;
pub use inspection::InspectionLayer;
pub use jwt::JwtAuthLayer;
pub use limit::MaxPayloadLayer;
pub use logger::LoggerLayer;
pub use rate_limiter::{SimpleRateLimiterLayer, TokenBucketRateLimiterLayer};
pub use router::RouterService;
pub use security_headers::SecurityHeadersLayer;
pub use timing::TimingLayer;
