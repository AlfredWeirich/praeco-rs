//! # Rate Limiting Middleware
//!
//! This module provides two rate-limiting strategies, each implemented as a
//! Tower Layer + Service pair:
//!
//! 1. **[`SimpleRateLimiterLayer`]** – A fixed-window limiter that enforces a
//!    minimum duration between consecutive requests. Simple and deterministic.
//! 2. **[`TokenBucketRateLimiterLayer`]** – A token-bucket limiter that allows
//!    bursts up to a configured capacity while enforcing an average rate over
//!    time. More flexible for real-world traffic patterns.
//!
//! Both limiters support:
//! - **Keyed rate limiting**: Requests can be partitioned by Client IP (`RateLimitKeyStrategy::Ip`),
//!   authenticated identity (JWT `sub` or mTLS SAN, falling back to IP, `RateLimitKeyStrategy::Identity`),
//!   or server-wide (`RateLimitKeyStrategy::Global`).
//! - **Bounded state & TTL pruning**: Keyed states are tracked in thread-safe [`DashMap`] with a maximum
//!   entry cap and idle TTL cleanup to prevent unbounded memory consumption from IP spoofing / scanning.
//! - **Floating-point token precision**: Refills track fractional tokens without truncating elapsed intervals,
//!   preventing token drift.
//! - **RFC 6585 compliance**: All 429 Too Many Requests responses include a standardized `Retry-After` header.

// === Standard Library ===
use std::{
    fmt::Debug,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant},
};

// === External Crates ===
use bytes::Bytes;
use dashmap::DashMap;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode};
use pin_project::pin_project;
use tower::{Layer, Service};
#[allow(unused_imports)]
use tracing::{debug, info, trace, warn};

// === Internal Modules ===
use crate::{ServiceRespBody, SrvError};
pub use crate::configuration::RateLimitKeyStrategy;

// ============================================================================
//  RATE LIMIT KEY & EXTRACTOR
// ============================================================================

/// Identifies the client or principal being rate limited.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RateLimitKey {
    /// Authenticated user ID (e.g. from JWT `sub`).
    User(String),
    /// Authenticated client certificate Subject Alternative Name (SAN).
    ClientCert(String),
    /// Remote client IP address.
    Ip(std::net::IpAddr),
    /// Server-wide global bucket.
    Global,
}

impl std::fmt::Display for RateLimitKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::User(u) => write!(f, "user:{}", u),
            Self::ClientCert(c) => write!(f, "cert:{}", c),
            Self::Ip(ip) => write!(f, "ip:{}", ip),
            Self::Global => write!(f, "global"),
        }
    }
}

/// Extracts a [`RateLimitKey`] from a request based on the selected [`RateLimitKeyStrategy`].
pub fn extract_rate_limit_key<ReqBody>(
    req: &Request<ReqBody>,
    strategy: RateLimitKeyStrategy,
) -> RateLimitKey {
    match strategy {
        RateLimitKeyStrategy::Global => RateLimitKey::Global,
        RateLimitKeyStrategy::Ip => extract_ip_key(req),
        RateLimitKeyStrategy::Identity => {
            // 1. Try JWT Claims `sub`
            if let Some(claims) = req.extensions().get::<common::Claims>() {
                if !claims.sub.is_empty() {
                    return RateLimitKey::User(claims.sub.clone());
                }
            }
            // 2. Try mTLS client certificate SAN
            if let Some(san) = req.extensions().get::<crate::SanCertExtension>() {
                if !san.0.is_empty() {
                    return RateLimitKey::ClientCert(san.0.clone());
                }
            }
            // 3. Fallback to client IP
            extract_ip_key(req)
        }
    }
}

fn extract_ip_key<ReqBody>(req: &Request<ReqBody>) -> RateLimitKey {
    // 1. Direct TCP connection socket address
    if let Some(addr) = req.extensions().get::<std::net::SocketAddr>() {
        let ip = addr.ip();
        if !ip.is_unspecified() {
            return RateLimitKey::Ip(ip);
        }
    }

    // 2. Check X-Forwarded-For if socket address was unspecified (e.g. 0.0.0.0 through tunnel)
    if let Some(xff) = req.headers().get("x-forwarded-for") {
        if let Ok(s) = xff.to_str() {
            if let Some(first_ip) = s.split(',').next() {
                if let Ok(ip) = first_ip.trim().parse::<std::net::IpAddr>() {
                    return RateLimitKey::Ip(ip);
                }
            }
        }
    }

    // 3. Check X-Real-IP
    if let Some(xrip) = req.headers().get("x-real-ip") {
        if let Ok(s) = xrip.to_str() {
            if let Ok(ip) = s.trim().parse::<std::net::IpAddr>() {
                return RateLimitKey::Ip(ip);
            }
        }
    }

    RateLimitKey::Global
}

// ============================================================================
//  SIMPLE RATE LIMITER
// ============================================================================

#[derive(Debug)]
struct KeyedSimpleEntry {
    next_allowed: Instant,
    last_seen: Instant,
}

/// Thread-safe storage for keyed fixed-window rate limiter state.
#[derive(Clone)]
pub struct KeyedSimpleRateLimitStore {
    entries: Arc<DashMap<RateLimitKey, KeyedSimpleEntry>>,
    max_entries: usize,
    ttl: Duration,
    last_cleanup: Arc<std::sync::Mutex<Instant>>,
}

impl KeyedSimpleRateLimitStore {
    pub fn new(max_entries: usize, ttl: Duration) -> Self {
        Self {
            entries: Arc::new(DashMap::new()),
            max_entries,
            ttl,
            last_cleanup: Arc::new(std::sync::Mutex::new(Instant::now())),
        }
    }

    pub fn check_and_record(&self, key: &RateLimitKey, limit_duration: Duration) -> Result<(), u64> {
        let now = Instant::now();
        self.maybe_cleanup(now);

        let mut entry = self.entries.entry(key.clone()).or_insert_with(|| {
            KeyedSimpleEntry {
                next_allowed: now,
                last_seen: now,
            }
        });

        entry.last_seen = now;

        if now < entry.next_allowed {
            let wait_secs = (entry.next_allowed.duration_since(now).as_secs_f64()).ceil().max(1.0) as u64;
            Err(wait_secs)
        } else {
            entry.next_allowed = now + limit_duration;
            Ok(())
        }
    }

    /// Explicitly purges entries that have been inactive longer than `ttl`.
    pub fn cleanup(&self, now: Instant) {
        let ttl = self.ttl;
        self.entries.retain(|_, entry| {
            now.duration_since(entry.last_seen) < ttl
        });
    }

    fn maybe_cleanup(&self, now: Instant) {
        if let Ok(mut last_cleanup) = self.last_cleanup.try_lock() {
            if self.entries.len() >= self.max_entries || now.duration_since(*last_cleanup) > Duration::from_secs(10) {
                *last_cleanup = now;
                self.cleanup(now);
            }
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// A fixed-window rate limiter layer.
#[derive(Clone)]
pub struct SimpleRateLimiterLayer {
    limit_duration: Duration,
    key_by: RateLimitKeyStrategy,
    max_entries: usize,
    ttl: Duration,
    server_name: &'static str,
}

impl SimpleRateLimiterLayer {
    /// Creates a new `SimpleRateLimiterLayer` with default `Identity` keying.
    pub fn new(per: Duration, server_name: &'static str) -> Self {
        Self::with_config(
            per,
            RateLimitKeyStrategy::Identity,
            10_000,
            Duration::from_secs(300),
            server_name,
        )
    }

    /// Creates a `SimpleRateLimiterLayer` with custom keying, capacity, and TTL settings.
    pub fn with_config(
        per: Duration,
        key_by: RateLimitKeyStrategy,
        max_entries: usize,
        ttl: Duration,
        server_name: &'static str,
    ) -> Self {
        Self {
            limit_duration: per,
            key_by,
            max_entries,
            ttl,
            server_name,
        }
    }
}

impl<S> Layer<S> for SimpleRateLimiterLayer {
    type Service = SimpleRateLimiterService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        SimpleRateLimiterService::with_config(
            inner,
            self.limit_duration,
            self.key_by,
            self.max_entries,
            self.ttl,
            self.server_name,
        )
    }
}

/// Service that enforces the simple fixed-window rate limit.
#[derive(Clone)]
pub struct SimpleRateLimiterService<S> {
    inner: S,
    store: KeyedSimpleRateLimitStore,
    limit_duration: Duration,
    key_by: RateLimitKeyStrategy,
    server_name: &'static str,
}

impl<S> SimpleRateLimiterService<S> {
    pub fn new(inner: S, per: Duration, server_name: &'static str) -> Self {
        Self::with_config(
            inner,
            per,
            RateLimitKeyStrategy::Identity,
            10_000,
            Duration::from_secs(300),
            server_name,
        )
    }

    pub fn with_config(
        inner: S,
        per: Duration,
        key_by: RateLimitKeyStrategy,
        max_entries: usize,
        ttl: Duration,
        server_name: &'static str,
    ) -> Self {
        Self {
            inner,
            store: KeyedSimpleRateLimitStore::new(max_entries, ttl),
            limit_duration: per,
            key_by,
            server_name,
        }
    }
}

#[pin_project(project = SimpleRateLimitFutureProj)]
pub enum SimpleRateLimitFuture<F> {
    Allowed {
        #[pin]
        inner: F,
    },
    Blocked {
        response: Option<Response<ServiceRespBody>>,
    },
}

impl<F, E> Future for SimpleRateLimitFuture<F>
where
    F: Future<Output = Result<Response<ServiceRespBody>, E>>,
{
    type Output = Result<Response<ServiceRespBody>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            SimpleRateLimitFutureProj::Allowed { inner } => inner.poll(cx),
            SimpleRateLimitFutureProj::Blocked { response } => {
                let res = response.take().expect("polled after completion");
                Poll::Ready(Ok(res))
            }
        }
    }
}

impl<S, ReqBody> Service<Request<ReqBody>> for SimpleRateLimiterService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ServiceRespBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
{
    type Response = Response<ServiceRespBody>;
    type Error = S::Error;
    type Future = SimpleRateLimitFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let key = extract_rate_limit_key(&req, self.key_by);
        let server_name = self.server_name;

        match self.store.check_and_record(&key, self.limit_duration) {
            Ok(()) => {
                trace!("{}: Allowed request for key {}", server_name, key);
                let fut = self.inner.call(req);
                SimpleRateLimitFuture::Allowed { inner: fut }
            }
            Err(retry_after_secs) => {
                warn!("{}: Too Many Requests for key {} (simple limiter)", server_name, key);
                let body: ServiceRespBody = Full::new(Bytes::from_static(b"Too Many Requests"))
                    .map_err(SrvError::from)
                    .boxed();

                let mut response = Response::new(body);
                *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
                response.headers_mut().insert(
                    hyper::header::RETRY_AFTER,
                    hyper::header::HeaderValue::from(retry_after_secs),
                );
                SimpleRateLimitFuture::Blocked {
                    response: Some(response),
                }
            }
        }
    }
}

// ============================================================================
//  TOKEN BUCKET RATE LIMITER
// ============================================================================

#[derive(Debug)]
struct KeyedBucketEntry {
    tokens: f64,
    last_refill: Instant,
    last_seen: Instant,
}

/// Thread-safe storage for keyed token-bucket rate limiter states.
#[derive(Clone)]
pub struct KeyedTokenBucketStore {
    entries: Arc<DashMap<RateLimitKey, KeyedBucketEntry>>,
    max_entries: usize,
    ttl: Duration,
    last_cleanup: Arc<std::sync::Mutex<Instant>>,
}

impl KeyedTokenBucketStore {
    pub fn new(max_entries: usize, ttl: Duration) -> Self {
        Self {
            entries: Arc::new(DashMap::new()),
            max_entries,
            ttl,
            last_cleanup: Arc::new(std::sync::Mutex::new(Instant::now())),
        }
    }

    pub fn try_consume(
        &self,
        key: &RateLimitKey,
        capacity: usize,
        refill_tokens: usize,
        interval: Duration,
    ) -> Result<(), u64> {
        let now = Instant::now();
        let cap_f64 = capacity as f64;
        let rate = refill_tokens as f64 / interval.as_secs_f64();

        self.maybe_cleanup(now);

        let mut entry = self.entries.entry(key.clone()).or_insert_with(|| {
            KeyedBucketEntry {
                tokens: cap_f64,
                last_refill: now,
                last_seen: now,
            }
        });

        // 1. Refill tokens using floating-point math to preserve fractional intervals
        let elapsed = now.duration_since(entry.last_refill);
        let added = elapsed.as_secs_f64() * rate;
        entry.tokens = (entry.tokens + added).min(cap_f64);
        entry.last_refill = now;
        entry.last_seen = now;

        // 2. Consume 1.0 token if available
        if entry.tokens >= 1.0 {
            entry.tokens -= 1.0;
            Ok(())
        } else {
            // Calculate delay in whole seconds until at least 1.0 token is available
            let needed = 1.0 - entry.tokens;
            let retry_after_secs = (needed / rate).ceil().max(1.0) as u64;
            Err(retry_after_secs)
        }
    }

    /// Explicitly purges entries that have been inactive longer than `ttl`.
    pub fn cleanup(&self, now: Instant) {
        let ttl = self.ttl;
        self.entries.retain(|_, entry| {
            now.duration_since(entry.last_seen) < ttl
        });
    }

    fn maybe_cleanup(&self, now: Instant) {
        if let Ok(mut last_cleanup) = self.last_cleanup.try_lock() {
            if self.entries.len() >= self.max_entries || now.duration_since(*last_cleanup) > Duration::from_secs(10) {
                *last_cleanup = now;
                self.cleanup(now);
            }
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// A token bucket rate limiter layer.
#[derive(Clone)]
pub struct TokenBucketRateLimiterLayer {
    capacity: usize,
    refill_tokens: usize,
    interval: Duration,
    key_by: RateLimitKeyStrategy,
    max_entries: usize,
    ttl: Duration,
    server_name: &'static str,
}

impl TokenBucketRateLimiterLayer {
    /// Creates a new `TokenBucketRateLimiterLayer` with default `Identity` keying.
    pub fn new(
        capacity: usize,
        refill_tokens: usize,
        interval: Duration,
        server_name: &'static str,
    ) -> Self {
        Self::with_config(
            capacity,
            refill_tokens,
            interval,
            RateLimitKeyStrategy::Identity,
            10_000,
            Duration::from_secs(300),
            server_name,
        )
    }

    /// Creates a `TokenBucketRateLimiterLayer` with custom keying, capacity, and TTL settings.
    pub fn with_config(
        capacity: usize,
        refill_tokens: usize,
        interval: Duration,
        key_by: RateLimitKeyStrategy,
        max_entries: usize,
        ttl: Duration,
        server_name: &'static str,
    ) -> Self {
        Self {
            capacity,
            refill_tokens,
            interval,
            key_by,
            max_entries,
            ttl,
            server_name,
        }
    }
}

impl<S> Layer<S> for TokenBucketRateLimiterLayer {
    type Service = TokenBucketRateLimiterService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        TokenBucketRateLimiterService::with_config(
            inner,
            self.capacity,
            self.refill_tokens,
            self.interval,
            self.key_by,
            self.max_entries,
            self.ttl,
            self.server_name,
        )
    }
}

/// Service that enforces the token-bucket rate limit.
#[derive(Clone)]
pub struct TokenBucketRateLimiterService<S> {
    inner: S,
    store: KeyedTokenBucketStore,
    capacity: usize,
    refill_tokens: usize,
    interval: Duration,
    key_by: RateLimitKeyStrategy,
    server_name: &'static str,
}

impl<S> TokenBucketRateLimiterService<S> {
    pub fn new(
        inner: S,
        capacity: usize,
        refill_tokens: usize,
        interval: Duration,
        server_name: &'static str,
    ) -> Self {
        Self::with_config(
            inner,
            capacity,
            refill_tokens,
            interval,
            RateLimitKeyStrategy::Identity,
            10_000,
            Duration::from_secs(300),
            server_name,
        )
    }

    pub fn with_config(
        inner: S,
        capacity: usize,
        refill_tokens: usize,
        interval: Duration,
        key_by: RateLimitKeyStrategy,
        max_entries: usize,
        ttl: Duration,
        server_name: &'static str,
    ) -> Self {
        Self {
            inner,
            store: KeyedTokenBucketStore::new(max_entries, ttl),
            capacity,
            refill_tokens,
            interval,
            key_by,
            server_name,
        }
    }
}

#[pin_project(project = TokenBucketRateLimitFutureProj)]
pub enum TokenBucketRateLimitFuture<F> {
    Allowed {
        #[pin]
        inner: F,
    },
    Blocked {
        response: Option<Response<ServiceRespBody>>,
    },
}

impl<F, E> Future for TokenBucketRateLimitFuture<F>
where
    F: Future<Output = Result<Response<ServiceRespBody>, E>>,
{
    type Output = Result<Response<ServiceRespBody>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            TokenBucketRateLimitFutureProj::Allowed { inner } => inner.poll(cx),
            TokenBucketRateLimitFutureProj::Blocked { response } => {
                let res = response.take().expect("polled after completion");
                Poll::Ready(Ok(res))
            }
        }
    }
}

impl<S, ReqBody> Service<Request<ReqBody>> for TokenBucketRateLimiterService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ServiceRespBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
{
    type Response = Response<ServiceRespBody>;
    type Error = S::Error;
    type Future = TokenBucketRateLimitFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let key = extract_rate_limit_key(&req, self.key_by);
        let server_name = self.server_name;

        match self.store.try_consume(&key, self.capacity, self.refill_tokens, self.interval) {
            Ok(()) => {
                debug!(
                    "{}: Token consumed for key {} (bucket limiter)",
                    server_name, key
                );
                let fut = self.inner.call(req);
                TokenBucketRateLimitFuture::Allowed { inner: fut }
            }
            Err(retry_after_secs) => {
                warn!(
                    "{}: Too Many Requests for key {} – bucket exhausted (bucket limiter)",
                    server_name, key
                );
                let body: ServiceRespBody = Full::new(Bytes::from_static(b"Too Many Requests"))
                    .map_err(SrvError::from)
                    .boxed();

                let mut response = Response::new(body);
                *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
                response.headers_mut().insert(
                    hyper::header::RETRY_AFTER,
                    hyper::header::HeaderValue::from(retry_after_secs),
                );
                TokenBucketRateLimitFuture::Blocked {
                    response: Some(response),
                }
            }
        }
    }
}

// ============================================================================
//  UNIT TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    #[derive(Clone)]
    struct DummyOkService;

    impl Service<Request<Full<Bytes>>> for DummyOkService {
        type Response = Response<ServiceRespBody>;
        type Error = std::convert::Infallible;
        type Future = std::future::Ready<Result<Self::Response, Self::Error>>;

        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&mut self, _req: Request<Full<Bytes>>) -> Self::Future {
            let body: ServiceRespBody = Full::new(Bytes::from("OK")).map_err(SrvError::from).boxed();
            std::future::ready(Ok(Response::new(body)))
        }
    }

    #[tokio::test]
    async fn test_token_bucket_per_ip_isolation() {
        let svc = DummyOkService;
        let mut limiter = TokenBucketRateLimiterService::with_config(
            svc,
            2, // capacity = 2
            1, // refill = 1
            Duration::from_secs(60), // interval = 60s
            RateLimitKeyStrategy::Ip,
            100,
            Duration::from_secs(300),
            "test_server",
        );

        let ip_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)), 12345);
        let ip_b = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 54321);

        // Client A consumes token 1
        let mut req_a1 = Request::builder().uri("/").body(Full::new(Bytes::new())).unwrap();
        req_a1.extensions_mut().insert(ip_a);
        let resp = limiter.call(req_a1).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Client A consumes token 2
        let mut req_a2 = Request::builder().uri("/").body(Full::new(Bytes::new())).unwrap();
        req_a2.extensions_mut().insert(ip_a);
        let resp = limiter.call(req_a2).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Client A is out of tokens -> 429 Too Many Requests with Retry-After
        let mut req_a3 = Request::builder().uri("/").body(Full::new(Bytes::new())).unwrap();
        req_a3.extensions_mut().insert(ip_a);
        let resp = limiter.call(req_a3).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(resp.headers().contains_key(hyper::header::RETRY_AFTER));

        // Client B was NOT blocked because rate limiting is keyed per IP!
        let mut req_b1 = Request::builder().uri("/").body(Full::new(Bytes::new())).unwrap();
        req_b1.extensions_mut().insert(ip_b);
        let resp = limiter.call(req_b1).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_token_bucket_per_identity_isolation() {

        let svc = DummyOkService;
        let mut limiter = TokenBucketRateLimiterService::with_config(
            svc,
            1, // capacity = 1
            1,
            Duration::from_secs(60),
            RateLimitKeyStrategy::Identity,
            100,
            Duration::from_secs(300),
            "test_server",
        );

        let claims_user1 = common::Claims {
            sub: "user-uuid-1".to_string(),
            iss: "praeco-idp".to_string(),
            aud: Some("admin-dashboard".to_string()),
            exp: 9999999999,
            oids: vec!["1".to_string()],
            jti: None,
        };

        let claims_user2 = common::Claims {
            sub: "user-uuid-2".to_string(),
            iss: "praeco-idp".to_string(),
            aud: Some("admin-dashboard".to_string()),
            exp: 9999999999,
            oids: vec!["1".to_string()],
            jti: None,
        };

        // User 1 consumes their single token
        let mut req1 = Request::builder().uri("/").body(Full::new(Bytes::new())).unwrap();
        req1.extensions_mut().insert(claims_user1.clone());
        let resp = limiter.call(req1).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // User 1 is blocked on second request
        let mut req2 = Request::builder().uri("/").body(Full::new(Bytes::new())).unwrap();
        req2.extensions_mut().insert(claims_user1);
        let resp = limiter.call(req2).await.unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

        // User 2 has their own bucket and succeeds
        let mut req3 = Request::builder().uri("/").body(Full::new(Bytes::new())).unwrap();
        req3.extensions_mut().insert(claims_user2);
        let resp = limiter.call(req3).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_simple_rate_limiter_retry_after() {

        let svc = DummyOkService;
        let mut limiter = SimpleRateLimiterService::with_config(
            svc,
            Duration::from_secs(5),
            RateLimitKeyStrategy::Global,
            100,
            Duration::from_secs(300),
            "test_server",
        );

        let req1 = Request::builder().uri("/").body(Full::new(Bytes::new())).unwrap();
        let resp1 = limiter.call(req1).await.unwrap();
        assert_eq!(resp1.status(), StatusCode::OK);

        let req2 = Request::builder().uri("/").body(Full::new(Bytes::new())).unwrap();
        let resp2 = limiter.call(req2).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::TOO_MANY_REQUESTS);

        let retry_header = resp2.headers().get(hyper::header::RETRY_AFTER).unwrap().to_str().unwrap();
        let wait_secs: u64 = retry_header.parse().unwrap();
        assert!(wait_secs >= 1 && wait_secs <= 5);
    }

    #[test]
    fn test_token_bucket_float_refill_precision() {
        let store = KeyedTokenBucketStore::new(100, Duration::from_secs(300));
        let key = RateLimitKey::User("alice".to_string());

        // Capacity 1, refill 10 tokens per 1 second (1 token per 100ms)
        assert!(store.try_consume(&key, 1, 10, Duration::from_secs(1)).is_ok());

        // Immediately exhausted
        assert!(store.try_consume(&key, 1, 10, Duration::from_secs(1)).is_err());

        // Wait 120ms (enough for 1.2 tokens)
        std::thread::sleep(Duration::from_millis(120));

        // Must succeed without discarding fractional time!
        assert!(store.try_consume(&key, 1, 10, Duration::from_secs(1)).is_ok());
    }

    #[test]
    fn test_store_pruning_lifecycle() {
        let store = KeyedTokenBucketStore::new(5, Duration::from_millis(50));
        let key1 = RateLimitKey::Ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        let key2 = RateLimitKey::Ip(IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)));

        assert!(store.try_consume(&key1, 10, 1, Duration::from_secs(1)).is_ok());
        assert!(store.try_consume(&key2, 10, 1, Duration::from_secs(1)).is_ok());
        assert_eq!(store.len(), 2);

        // Sleep to exceed 50ms TTL
        std::thread::sleep(Duration::from_millis(60));

        // Running cleanup prunes stale entries
        store.cleanup(Instant::now());
        assert_eq!(store.len(), 0);
    }
}
