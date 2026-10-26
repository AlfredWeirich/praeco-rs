//! # IP Allowlist / Blocklist (CIDR) Middleware
//!
//! This module provides [`IpFilterLayer`] and [`IpFilterService`], a Tower middleware
//! that enforces network-level access control using IPv4 and IPv6 CIDR ranges
//! (`allow_cidrs` and `deny_cidrs`) before expensive authentication (JWT, mTLS)
//! or upstream routing takes place.
//!
//! ## Evaluation Order & Security Invariants
//!
//! 1. **Deny Precedence (`deny_cidrs` first)**:
//!    If the client IP matches **any** CIDR block in `deny_cidrs`, the request is
//!    immediately rejected with `403 Forbidden`. This allows carving out blocked
//!    sub-ranges inside a broader allowed network (e.g., allowing `10.0.0.0/8`
//!    while denying `10.99.0.0/16`).
//! 2. **Allowlist Enforcement (`allow_cidrs` second)**:
//!    If `allow_cidrs` is non-empty, the client IP **must** match at least one
//!    entry in `allow_cidrs`. Otherwise, the request is rejected with `403 Forbidden`.
//!    If `allow_cidrs` is empty, all IPs not matching `deny_cidrs` are permitted.
//! 3. **Dual-Stack Canonicalization**:
//!    IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are automatically unwrapped to
//!    their canonical IPv4 representation (`a.b.c.d`) prior to matching so that a
//!    dual-stack socket can never bypass an IPv4 `deny_cidrs` rule.
//! 4. **Fail-Closed on Missing IP**:
//!    When `allow_cidrs` is non-empty and the peer IP is missing or unspecified
//!    (`0.0.0.0` / `::`), the request is rejected with `403 Forbidden`.
//! 5. **Relay Server & PROXY Protocol v2 Compatibility**:
//!    Reads the verified peer [`SocketAddr`](std::net::SocketAddr) from request
//!    extensions (populated by `ConnectionHandler` from direct TCP/QUIC sockets or
//!    via the Relay Server's `PROXY v2` tunnel header). Optionally falls back to
//!    `X-Forwarded-For` / `X-Real-IP` only when `trust_forwarded_headers = true`
//!    and the socket address is unspecified.
//! 6. **Zero-Allocation Hot Path**:
//!    CIDR matching uses pre-compiled bitwise masks (`u32` for IPv4, `u128` for IPv6)
//!    and a `#[pin_project]` enum future ([`IpFilterFuture`]) to avoid heap boxing
//!    (`Box::pin`) on every request.

use std::{
    fmt,
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    pin::Pin,
    str::FromStr,
    sync::Arc,
    task::{Context, Poll},
};

use anyhow::{ Error, anyhow };
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode};
use pin_project::pin_project;
use tower::{Layer, Service};

use crate::{ServiceRespBody, SrvError};

// ============================================================================
//  CIDR Representation & Bitwise Matching
// ============================================================================

/// A pre-compiled IPv4 or IPv6 CIDR network range for $O(1)$ bitwise matching.
///
/// Supports both explicit prefix notation (e.g. `"10.0.0.0/8"`, `"2001:db8::/32"`)
/// and single-host notation without a slash (e.g. `"127.0.0.1"` $\rightarrow$ `/32`,
/// `"::1"` $\rightarrow$ `/128`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpCidr {
    /// IPv4 network prefix and bitmask.
    V4 {
        /// Pre-masked network address (`addr & mask`).
        network: u32,
        /// Bitmask with the leading `prefix_len` bits set to `1`.
        mask: u32,
        /// Prefix length in bits (`0..=32`).
        prefix_len: u8,
    },
    /// IPv6 network prefix and bitmask.
    V6 {
        /// Pre-masked network address (`addr & mask`).
        network: u128,
        /// Bitmask with the leading `prefix_len` bits set to `1`.
        mask: u128,
        /// Prefix length in bits (`0..=128`).
        prefix_len: u8,
    },
}

impl IpCidr {
    /// Parses a CIDR string or single IP address into an [`IpCidr`].
    ///
    /// # Examples
    ///
    /// - `"10.0.0.0/8"` $\rightarrow$ IPv4 `/8` network
    /// - `"192.168.1.50"` $\rightarrow$ IPv4 `/32` single host
    /// - `"2001:db8::/32"` $\rightarrow$ IPv6 `/32` network
    /// - `"::1"` $\rightarrow$ IPv6 `/128` single host
    ///
    /// # Errors
    ///
    /// Returns a descriptive error string if the IP address is malformed, contains
    /// multiple `'/'` delimiters, or specifies an out-of-range prefix length
    /// (`> 32` for IPv4, `> 128` for IPv6).
    pub fn parse(input: &str) -> Result<Self, String> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Err("CIDR string cannot be empty".to_string());
        }

        let (ip_part, prefix_part) = match trimmed.split_once('/') {
            Some((ip_s, pfx_s)) => {
                if pfx_s.contains('/') {
                    return Err(format!("Invalid CIDR '{}': multiple '/' delimiters", trimmed));
                }
                (ip_s.trim(), Some(pfx_s.trim()))
            }
            None => (trimmed, None),
        };

        let raw_ip = ip_part
            .parse::<IpAddr>()
            .map_err(|e| format!("Invalid IP address in CIDR '{}': {}", trimmed, e))?;

        // Canonicalize IPv4-mapped IPv6 addresses (e.g. "::ffff:10.0.0.1") when no IPv6-only
        // prefix (> 32) is specified, so rules written in mapped form still match IPv4 clients.
        let ip = match raw_ip {
            IpAddr::V4(v4) => IpAddr::V4(v4),
            IpAddr::V6(v6) => {
                if let Some(mapped_v4) = v6.to_ipv4_mapped() {
                    match prefix_part {
                        None => IpAddr::V4(mapped_v4),
                        Some(pfx_str) => {
                            let pfx = pfx_str.parse::<u8>().map_err(|_| {
                                format!("Invalid prefix length '{}' in CIDR '{}'", pfx_str, trimmed)
                            })?;
                            if pfx <= 32 {
                                IpAddr::V4(mapped_v4)
                            } else if pfx >= 96 && pfx <= 128 {
                                // Convert /96..=/128 on ::ffff:a.b.c.d to the equivalent IPv4 /0..=/32 prefix
                                let v4_pfx = pfx - 96;
                                let mask = if v4_pfx == 0 {
                                    0u32
                                } else {
                                    !0u32 << (32 - v4_pfx)
                                };
                                let network = u32::from(mapped_v4) & mask;
                                return Ok(Self::V4 {
                                    network,
                                    mask,
                                    prefix_len: v4_pfx,
                                });
                            } else {
                                IpAddr::V6(v6)
                            }
                        }
                    }
                } else {
                    IpAddr::V6(v6)
                }
            }
        };

        match ip {
            IpAddr::V4(v4) => {
                let prefix_len = match prefix_part {
                    Some(s) => s.parse::<u8>().map_err(|_| {
                        format!("Invalid IPv4 prefix length '{}' in CIDR '{}'", s, trimmed)
                    })?,
                    None => 32,
                };
                if prefix_len > 32 {
                    return Err(format!(
                        "IPv4 prefix length {} out of range (0..=32) in CIDR '{}'",
                        prefix_len, trimmed
                    ));
                }
                let mask = if prefix_len == 0 {
                    0u32
                } else {
                    !0u32 << (32 - prefix_len)
                };
                let network = u32::from(v4) & mask;
                Ok(Self::V4 {
                    network,
                    mask,
                    prefix_len,
                })
            }
            IpAddr::V6(v6) => {
                let prefix_len = match prefix_part {
                    Some(s) => s.parse::<u8>().map_err(|_| {
                        format!("Invalid IPv6 prefix length '{}' in CIDR '{}'", s, trimmed)
                    })?,
                    None => 128,
                };
                if prefix_len > 128 {
                    return Err(format!(
                        "IPv6 prefix length {} out of range (0..=128) in CIDR '{}'",
                        prefix_len, trimmed
                    ));
                }
                let mask = if prefix_len == 0 {
                    0u128
                } else {
                    !0u128 << (128 - prefix_len)
                };
                let network = u128::from(v6) & mask;
                Ok(Self::V6 {
                    network,
                    mask,
                    prefix_len,
                })
            }
        }
    }

    /// Checks whether `ip` falls within this CIDR range.
    ///
    /// Automatically unwraps IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) to
    /// `IpAddr::V4(a.b.c.d)` before testing membership.
    #[inline]
    pub fn contains(&self, ip: IpAddr) -> bool {
        let canonical = unwrap_ipv4_mapped(ip);
        match (self, canonical) {
            (Self::V4 { network, mask, .. }, IpAddr::V4(v4)) => {
                (u32::from(v4) & *mask) == *network
            }
            (Self::V6 { network, mask, .. }, IpAddr::V6(v6)) => {
                (u128::from(v6) & *mask) == *network
            }
            _ => false,
        }
    }
}

impl FromStr for IpCidr {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl fmt::Display for IpCidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V4 {
                network,
                prefix_len,
                ..
            } => write!(f, "{}/{}", Ipv4Addr::from(*network), prefix_len),
            Self::V6 {
                network,
                prefix_len,
                ..
            } => write!(f, "{}/{}", Ipv6Addr::from(*network), prefix_len),
        }
    }
}

/// Unwraps IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) to their canonical
/// `IpAddr::V4` representation while preserving all 128 bits of native IPv6 addresses.
#[inline]
pub fn unwrap_ipv4_mapped(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped_v4) = v6.to_ipv4_mapped() {
                IpAddr::V4(mapped_v4)
            } else {
                IpAddr::V6(v6)
            }
        }
    }
}

// ============================================================================
//  Client IP Extraction & Decision Logic
// ============================================================================

/// Reason why a request was denied by [`IpFilterService`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpFilterRejection {
    /// The client IP matched an explicit entry in `deny_cidrs`.
    DeniedByBlocklist { client_ip: IpAddr, matched_cidr: IpCidr },
    /// `allow_cidrs` is non-empty and the client IP did not match any allowed CIDR.
    NotInAllowlist { client_ip: IpAddr },
    /// `allow_cidrs` is non-empty, but the client IP could not be determined (Fail-Closed).
    MissingClientIp,
}

impl fmt::Display for IpFilterRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DeniedByBlocklist {
                client_ip,
                matched_cidr,
            } => write!(
                f,
                "Client IP {} matched deny_cidrs rule {}",
                client_ip, matched_cidr
            ),
            Self::NotInAllowlist { client_ip } => {
                write!(f, "Client IP {} is not in allow_cidrs", client_ip)
            }
            Self::MissingClientIp => write!(
                f,
                "Client IP could not be determined while allow_cidrs is active (fail-closed)"
            ),
        }
    }
}

/// Extracts the client [`IpAddr`] from the request.
///
/// 1. Checks the peer [`SocketAddr`] extension injected by `ConnectionHandler`
///    (from a direct TCP/QUIC socket or a Relay Server `PROXY v2` tunnel stream).
/// 2. If the socket address is absent or unspecified (`0.0.0.0` / `::`) **and**
///    `trust_forwarded_headers` is `true`, inspects `X-Forwarded-For` (leftmost IP)
///    and `X-Real-IP`.
pub fn extract_client_ip<ReqBody>(
    req: &Request<ReqBody>,
    trust_forwarded_headers: bool,
) -> Option<IpAddr> {
    if let Some(addr) = req.extensions().get::<SocketAddr>() {
        let ip = addr.ip();
        if !ip.is_unspecified() {
            return Some(unwrap_ipv4_mapped(ip));
        }
    }

    if trust_forwarded_headers {
        if let Some(xff) = req.headers().get("x-forwarded-for") {
            if let Ok(s) = xff.to_str() {
                if let Some(first_ip) = s.split(',').next() {
                    if let Ok(ip) = first_ip.trim().parse::<IpAddr>() {
                        if !ip.is_unspecified() {
                            return Some(unwrap_ipv4_mapped(ip));
                        }
                    }
                }
            }
        }

        if let Some(xrip) = req.headers().get("x-real-ip") {
            if let Ok(s) = xrip.to_str() {
                if let Ok(ip) = s.trim().parse::<IpAddr>() {
                    if !ip.is_unspecified() {
                        return Some(unwrap_ipv4_mapped(ip));
                    }
                }
            }
        }
    }

    None
}

// ============================================================================
//  Tower Layer & Service Implementation
// ============================================================================

/// A Tower [`Layer`] that filters incoming HTTP requests by client IP against
/// pre-compiled `allow_cidrs` and `deny_cidrs` lists.
#[derive(Debug, Clone)]
pub struct IpFilterLayer {
    allow_cidrs: Arc<Vec<IpCidr>>,
    deny_cidrs: Arc<Vec<IpCidr>>,
    trust_forwarded_headers: bool,
    server_name: &'static str,
}

impl IpFilterLayer {
    /// Creates a new [`IpFilterLayer`] from pre-compiled [`IpCidr`] vectors.
    pub fn new(
        allow_cidrs: Vec<IpCidr>,
        deny_cidrs: Vec<IpCidr>,
        server_name: &'static str,
    ) -> Self {
        Self {
            allow_cidrs: Arc::new(allow_cidrs),
            deny_cidrs: Arc::new(deny_cidrs),
            trust_forwarded_headers: false,
            server_name,
        }
    }

    /// Parses string slices of `allow_cidrs` and `deny_cidrs` into an [`IpFilterLayer`].
    ///
    /// # Errors
    ///
    /// Returns an error if any CIDR string in `allow` or `deny` is invalid.
    pub fn from_cidr_strings(
        allow: &[String],
        deny: &[String],
        trust_forwarded_headers: bool,
        server_name: &'static str,
    ) -> Result<Self, Error> {
        let mut allow_cidrs = Vec::with_capacity(allow.len());
        for raw in allow {
            let cidr = IpCidr::parse(raw).map_err(|e| {
                anyhow!(
                    "{}: Invalid CIDR in [Server.Layers.IpFilter].allow_cidrs: {}",
                    server_name,
                    e
                )
            })?;
            allow_cidrs.push(cidr);
        }

        let mut deny_cidrs = Vec::with_capacity(deny.len());
        for raw in deny {
            let cidr = IpCidr::parse(raw).map_err(|e| {
                anyhow!(
                    "{}: Invalid CIDR in [Server.Layers.IpFilter].deny_cidrs: {}",
                    server_name,
                    e
                )
            })?;
            deny_cidrs.push(cidr);
        }

        Ok(Self {
            allow_cidrs: Arc::new(allow_cidrs),
            deny_cidrs: Arc::new(deny_cidrs),
            trust_forwarded_headers,
            server_name,
        })
    }

    /// Configures whether `X-Forwarded-For` and `X-Real-IP` headers should be
    /// trusted when the underlying socket IP is unspecified (`0.0.0.0` / `::`).
    pub fn with_trust_forwarded_headers(mut self, trust: bool) -> Self {
        self.trust_forwarded_headers = trust;
        self
    }
}

impl<S> Layer<S> for IpFilterLayer {
    type Service = IpFilterService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        IpFilterService {
            inner,
            allow_cidrs: self.allow_cidrs.clone(),
            deny_cidrs: self.deny_cidrs.clone(),
            trust_forwarded_headers: self.trust_forwarded_headers,
            server_name: self.server_name,
        }
    }
}

/// Tower [`Service`] that enforces IP allowlist and blocklist rules.
#[derive(Debug, Clone)]
pub struct IpFilterService<S> {
    inner: S,
    allow_cidrs: Arc<Vec<IpCidr>>,
    deny_cidrs: Arc<Vec<IpCidr>>,
    trust_forwarded_headers: bool,
    server_name: &'static str,
}

impl<S> IpFilterService<S> {
    /// Evaluates the extracted client IP against `deny_cidrs` (first) and
    /// `allow_cidrs` (second).
    pub fn evaluate_ip(&self, client_ip: Option<IpAddr>) -> Result<(), IpFilterRejection> {
        match client_ip {
            Some(ip) => {
                let ip = unwrap_ipv4_mapped(ip);

                // 1. Deny takes precedence over Allow
                for cidr in self.deny_cidrs.iter() {
                    if cidr.contains(ip) {
                        return Err(IpFilterRejection::DeniedByBlocklist {
                            client_ip: ip,
                            matched_cidr: *cidr,
                        });
                    }
                }

                // 2. If an allowlist is configured, the IP must match at least one entry
                if !self.allow_cidrs.is_empty()
                    && !self.allow_cidrs.iter().any(|cidr| cidr.contains(ip))
                {
                    return Err(IpFilterRejection::NotInAllowlist { client_ip: ip });
                }

                Ok(())
            }
            None => {
                // Fail-closed if an allowlist is active but no client IP could be resolved
                if !self.allow_cidrs.is_empty() {
                    Err(IpFilterRejection::MissingClientIp)
                } else {
                    Ok(())
                }
            }
        }
    }

    fn build_forbidden_response() -> Response<ServiceRespBody> {
        let body: ServiceRespBody = Full::new(Bytes::from_static(b"Forbidden\n"))
            .map_err(SrvError::from)
            .boxed();

        Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(body)
            .unwrap()
    }
}

/// Zero-allocation future returned by [`IpFilterService`].
///
/// Avoids heap-allocating (`Box::pin`) on either the allowed hot path or the
/// short-circuit `403 Forbidden` path.
#[pin_project(project = IpFilterFutureProj)]
pub enum IpFilterFuture<F> {
    /// Request passed IP filtering and is delegated to the inner service.
    Allowed {
        #[pin]
        inner: F,
    },
    /// Request was rejected by IP filtering with an immediate `403 Forbidden` response.
    Blocked {
        response: Option<Response<ServiceRespBody>>,
    },
}

impl<F, E> Future for IpFilterFuture<F>
where
    F: Future<Output = Result<Response<ServiceRespBody>, E>>,
{
    type Output = Result<Response<ServiceRespBody>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            IpFilterFutureProj::Allowed { inner } => inner.poll(cx),
            IpFilterFutureProj::Blocked { response } => {
                let res = response
                    .take()
                    .expect("IpFilterFuture polled after completion");
                Poll::Ready(Ok(res))
            }
        }
    }
}

impl<S, ReqBody> Service<Request<ReqBody>> for IpFilterService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ServiceRespBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ReqBody: Send + 'static,
{
    type Response = Response<ServiceRespBody>;
    type Error = S::Error;
    type Future = IpFilterFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let client_ip = extract_client_ip(&req, self.trust_forwarded_headers);

        match self.evaluate_ip(client_ip) {
            Ok(()) => IpFilterFuture::Allowed {
                inner: self.inner.call(req),
            },
            Err(rejection) => {
                tracing::warn!(
                    target: "security",
                    "{}: Blocked request with 403 Forbidden due to IP filter: {} (method: {}, uri: '{}')",
                    self.server_name,
                    rejection,
                    req.method(),
                    req.uri()
                );
                IpFilterFuture::Blocked {
                    response: Some(Self::build_forbidden_response()),
                }
            }
        }
    }
}

// ============================================================================
//  Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::convert::Infallible;
    use tower::ServiceExt;

    #[test]
    fn test_ip_cidr_parse_and_contains_ipv4() {
        let cidr = IpCidr::parse("10.0.0.0/8").unwrap();
        assert!(cidr.contains("10.0.0.1".parse().unwrap()));
        assert!(cidr.contains("10.255.255.254".parse().unwrap()));
        assert!(!cidr.contains("11.0.0.1".parse().unwrap()));

        // Single host without /32
        let host = IpCidr::parse("192.168.1.42").unwrap();
        assert_eq!(host.to_string(), "192.168.1.42/32");
        assert!(host.contains("192.168.1.42".parse().unwrap()));
        assert!(!host.contains("192.168.1.43".parse().unwrap()));

        // /0 matches all IPv4 addresses
        let all_v4 = IpCidr::parse("0.0.0.0/0").unwrap();
        assert!(all_v4.contains("1.2.3.4".parse().unwrap()));
        assert!(all_v4.contains("255.255.255.255".parse().unwrap()));
        assert!(!all_v4.contains("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn test_ip_cidr_parse_and_contains_ipv6() {
        let cidr = IpCidr::parse("2001:db8:abcd::/48").unwrap();
        assert!(cidr.contains("2001:db8:abcd:0001::1".parse().unwrap()));
        assert!(cidr.contains("2001:db8:abcd:ffff:ffff:ffff:ffff:ffff".parse().unwrap()));
        assert!(!cidr.contains("2001:db8:abce::1".parse().unwrap()));

        // Single IPv6 host without /128
        let loopback = IpCidr::parse("::1").unwrap();
        assert_eq!(loopback.to_string(), "::1/128");
        assert!(loopback.contains("::1".parse().unwrap()));
        assert!(!loopback.contains("::2".parse().unwrap()));
    }

    #[test]
    fn test_ipv4_mapped_ipv6_canonicalization() {
        let deny_v4 = IpCidr::parse("10.99.0.0/16").unwrap();
        // Dual-stack socket address ::ffff:10.99.1.25 must match the IPv4 CIDR 10.99.0.0/16
        let mapped_ip: IpAddr = "::ffff:10.99.1.25".parse().unwrap();
        assert!(deny_v4.contains(mapped_ip));

        let safe_mapped: IpAddr = "::ffff:10.1.1.25".parse().unwrap();
        assert!(!deny_v4.contains(safe_mapped));
    }

    #[test]
    fn test_invalid_cidr_rejected() {
        assert!(IpCidr::parse("").is_err());
        assert!(IpCidr::parse("10.0.0.0/33").is_err());
        assert!(IpCidr::parse("2001:db8::/129").is_err());
        assert!(IpCidr::parse("10.0.0.0/8/16").is_err());
        assert!(IpCidr::parse("not-an-ip/24").is_err());
        assert!(IpCidr::parse("10.0.0.1/abc").is_err());
    }

    #[tokio::test]
    async fn test_deny_takes_precedence_over_allow() {
        let layer = IpFilterLayer::from_cidr_strings(
            &["10.0.0.0/8".to_string(), "127.0.0.1/32".to_string()],
            &["10.99.0.0/16".to_string()],
            false,
            "test_srv",
        )
        .unwrap();

        let inner = tower::service_fn(|_req: Request<Full<Bytes>>| async move {
            let body: ServiceRespBody = Full::new(Bytes::from_static(b"OK"))
                .map_err(SrvError::from)
                .boxed();
            Ok::<_, Infallible>(Response::new(body))
        });

        let svc = layer.layer(inner);

        // 1. Allowed IP inside 10.0.0.0/8 (10.1.2.3) -> 200 OK
        let mut req_ok = Request::builder().uri("/admin").body(Full::new(Bytes::new())).unwrap();
        req_ok
            .extensions_mut()
            .insert("10.1.2.3:54321".parse::<SocketAddr>().unwrap());
        let resp_ok = svc.clone().oneshot(req_ok).await.unwrap();
        assert_eq!(resp_ok.status(), StatusCode::OK);

        // 2. Denied IP inside carved-out 10.99.0.0/16 (10.99.5.10) -> 403 Forbidden
        let mut req_denied = Request::builder().uri("/admin").body(Full::new(Bytes::new())).unwrap();
        req_denied
            .extensions_mut()
            .insert("10.99.5.10:54321".parse::<SocketAddr>().unwrap());
        let resp_denied = svc.clone().oneshot(req_denied).await.unwrap();
        assert_eq!(resp_denied.status(), StatusCode::FORBIDDEN);

        // 3. IP outside 10.0.0.0/8 and 127.0.0.1/32 (192.168.1.10) -> 403 Forbidden
        let mut req_outside = Request::builder().uri("/admin").body(Full::new(Bytes::new())).unwrap();
        req_outside
            .extensions_mut()
            .insert("192.168.1.10:54321".parse::<SocketAddr>().unwrap());
        let resp_outside = svc.clone().oneshot(req_outside).await.unwrap();
        assert_eq!(resp_outside.status(), StatusCode::FORBIDDEN);

        // 4. Missing SocketAddr when allow_cidrs is non-empty -> Fail-Closed (403 Forbidden)
        let req_no_ip = Request::builder().uri("/admin").body(Full::new(Bytes::new())).unwrap();
        let resp_no_ip = svc.oneshot(req_no_ip).await.unwrap();
        assert_eq!(resp_no_ip.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn test_trust_forwarded_headers_when_socket_unspecified() {
        let layer = IpFilterLayer::from_cidr_strings(
            &["198.51.100.0/24".to_string()],
            &["198.51.100.99/32".to_string()],
            true,
            "test_srv",
        )
        .unwrap();

        let inner = tower::service_fn(|_req: Request<Full<Bytes>>| async move {
            let body: ServiceRespBody = Full::new(Bytes::from_static(b"OK"))
                .map_err(SrvError::from)
                .boxed();
            Ok::<_, Infallible>(Response::new(body))
        });

        let svc = layer.layer(inner);

        // Unspecified socket IP + allowed X-Forwarded-For -> 200 OK
        let mut req_allowed = Request::builder()
            .uri("/api")
            .header("x-forwarded-for", "198.51.100.42, 10.0.0.1")
            .body(Full::new(Bytes::new()))
            .unwrap();
        req_allowed
            .extensions_mut()
            .insert("0.0.0.0:0".parse::<SocketAddr>().unwrap());
        let resp_allowed = svc.clone().oneshot(req_allowed).await.unwrap();
        assert_eq!(resp_allowed.status(), StatusCode::OK);

        // Unspecified socket IP + denied X-Forwarded-For -> 403 Forbidden
        let mut req_denied = Request::builder()
            .uri("/api")
            .header("x-forwarded-for", "198.51.100.99")
            .body(Full::new(Bytes::new()))
            .unwrap();
        req_denied
            .extensions_mut()
            .insert("0.0.0.0:0".parse::<SocketAddr>().unwrap());
        let resp_denied = svc.oneshot(req_denied).await.unwrap();
        assert_eq!(resp_denied.status(), StatusCode::FORBIDDEN);
    }
}
