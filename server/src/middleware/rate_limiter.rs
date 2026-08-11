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
//! Both limiters share state across all service clones via `Arc<Mutex<…>>`,
//! so the limit is enforced server-wide (not per-connection).
//!
//! When a request is rate-limited, the service returns a **429 Too Many
//! Requests** response immediately.

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
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode};
use std::sync::Mutex;
use tower::{Layer, Service};
#[allow(unused_imports)]
use tracing::{debug, info, trace, warn};

// === Internal Modules ===
use crate::{ServiceRespBody, SrvError};

// ============================================================================
//  SIMPLE RATE LIMITER
// ============================================================================

/// A simple fixed-window rate limiter layer.
///
/// This middleware enforces a minimum duration between consecutive requests.
/// If a request arrives too soon after the previous one, it is rejected with a
/// 429 Too Many Requests response.
///
/// ## Trade-offs
///
/// * **Pros**: Simple, deterministic, very low overhead.
/// * **Cons**: Does not handle bursts well — even a brief spike will trigger
///   rejections.
#[derive(Clone)]
pub struct SimpleRateLimiterLayer {
    /// The minimum allowed interval between consecutive requests.
    limit_duration: Duration,
    /// Server name label for tracing output.
    server_name: &'static str,
}

impl SimpleRateLimiterLayer {
    /// Creates a new `SimpleRateLimiterLayer`.
    ///
    /// # Arguments
    ///
    /// * `per`         – The minimum interval between requests.
    /// * `server_name` – A `'static` label for log output.
    pub fn new(per: Duration, server_name: &'static str) -> Self {
        Self {
            limit_duration: per,
            server_name,
        }
    }
}

impl<S> Layer<S> for SimpleRateLimiterLayer {
    type Service = SimpleRateLimiterService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        SimpleRateLimiterService::new(inner, self.limit_duration, self.server_name)
    }
}

/// Service that enforces the simple fixed-window rate limit.
///
/// Shared state is protected by a standard [`std::sync::Mutex`] because the
/// critical section (updating the timestamp) is extremely short and does not
/// involve any `.await` points. This is much faster than an async mutex.
#[derive(Clone)]
pub struct SimpleRateLimiterService<S> {
    /// The inner (downstream) service.
    inner: S,
    /// Shared mutable state tracking the next allowed request instant.
    state: Arc<Mutex<RateLimitState>>,
    /// The minimum interval between requests.
    limit_duration: Duration,
    /// Server name label for tracing.
    server_name: &'static str,
}

/// Internal state for the simple rate limiter.
#[derive(Debug)]
struct RateLimitState {
    /// The earliest point in time at which the next request will be accepted.
    next_allowed: Instant,
}

impl<S> SimpleRateLimiterService<S> {
    /// Creates a new `SimpleRateLimiterService` wrapping `inner`.
    pub fn new(inner: S, per: Duration, server_name: &'static str) -> Self {
        trace!(
            "{}: Creating SimpleRateLimiterService with limit duration: {:?}",
            server_name, per
        );
        Self {
            inner,
            state: Arc::new(Mutex::new(RateLimitState {
                next_allowed: Instant::now(),
            })),
            limit_duration: per,
            server_name,
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
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    /// Checks the shared state to determine if the request is within the
    /// allowed interval. If not, returns 429 immediately.
    ///
    /// The lock is held only long enough to read/update `next_allowed` and
    /// is explicitly dropped before calling the inner service, preventing
    /// lock contention during downstream processing.
    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let rate_limited = {
            let mut state = self.state.lock().unwrap();
            let now = Instant::now();
            let rate_limited = now < state.next_allowed;
            if !rate_limited {
                // Update the next allowed instant since we allow this request
                state.next_allowed = now + self.limit_duration;
            }
            rate_limited
        };

        let server_name = self.server_name;

        if rate_limited {
            warn!("{}: Too Many Requests (simple limiter)", server_name);
            let body: ServiceRespBody = Full::new(Bytes::from_static(b"Too Many Requests"))
                .map_err(SrvError::from)
                .boxed();

            let mut response = Response::new(body);
            *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
            return Box::pin(async move { Ok(response) });
        }

        trace!("{}: Allowed request", server_name);
        let fut = self.inner.call(req);
        Box::pin(async move { fut.await })
    }
}

// ============================================================================
//  TOKEN BUCKET RATE LIMITER
// ============================================================================

/// A token bucket rate limiter layer.
///
/// This algorithm allows a certain number of "tokens" to be available for requests.
/// Tokens are refilled at a fixed rate (`refill_tokens` every `interval`) up to a maximum `capacity`.
/// Each incoming request consumes one token. If no tokens are available, the request is rejected.
///
/// This provides a more flexible rate limiting strategy than the simple fixed-window approach,
/// as it can handle bursts of traffic up to the bucket's capacity, while still enforcing
/// an average rate limit.
///
/// ## Example
///
/// With `capacity = 100`, `refill_tokens = 10`, and `interval = 1s`:
/// * A burst of 100 requests will be accepted immediately.
/// * After the burst, 10 new tokens become available every second.
/// * Sustained throughput is capped at ~10 requests/second.
#[derive(Clone)]
pub struct TokenBucketRateLimiterLayer {
    /// The maximum number of tokens the bucket can hold.
    capacity: usize,
    /// The number of tokens to add to the bucket at each interval.
    refill_tokens: usize,
    /// The duration after which `refill_tokens` are added.
    interval: Duration,
    /// Server name label for tracing output.
    server_name: &'static str,
}

impl TokenBucketRateLimiterLayer {
    /// Creates a new `TokenBucketRateLimiterLayer`.
    ///
    /// # Arguments
    ///
    /// * `capacity` - The maximum number of tokens the bucket can hold.
    /// * `refill_tokens` - The number of tokens to add to the bucket at each interval.
    /// * `interval` - The duration after which `refill_tokens` are added to the bucket.
    /// * `server_name` - A static string identifier for the server, used in logging.
    pub fn new(
        capacity: usize,
        refill_tokens: usize,
        interval: Duration,
        server_name: &'static str,
    ) -> Self {
        Self {
            capacity,
            refill_tokens,
            interval,
            server_name,
        }
    }
}

impl<S> Layer<S> for TokenBucketRateLimiterLayer {
    type Service = TokenBucketRateLimiterService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        TokenBucketRateLimiterService::new(
            inner,
            self.capacity,
            self.refill_tokens,
            self.interval,
            self.server_name,
        )
    }
}

/// Internal state for the token bucket.
///
/// Tracks the current token count and the last time tokens were refilled.
#[derive(Debug)]
struct TokenBucket {
    /// Current number of available tokens (0 ≤ tokens ≤ capacity).
    tokens: usize,
    /// Timestamp of the last refill. Used to calculate how many tokens
    /// should be added since the last check.
    last_refill: Instant,
}

impl TokenBucket {
    /// Refills the bucket based on elapsed time.
    ///
    /// Calculates the number of full intervals that have passed since
    /// `last_refill` and adds the corresponding tokens, capped at `capacity`.
    fn refill(&mut self, capacity: usize, refill_tokens: usize, interval: Duration) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);

        if elapsed >= interval {
            // Use floating-point to handle partial intervals correctly.
            let intervals_passed = elapsed.as_secs_f64() / interval.as_secs_f64();
            let added_tokens = (intervals_passed * refill_tokens as f64).floor() as usize;

            self.tokens = (self.tokens + added_tokens).min(capacity);
            self.last_refill = now;
        }
    }

    /// Attempts to consume a single token.
    ///
    /// Returns `true` if a token was available (and consumed), `false` if the
    /// bucket is empty.
    fn try_consume(&mut self) -> bool {
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }
}

/// Service that enforces the token-bucket rate limit.
///
/// All clones share the same [`TokenBucket`] via `Arc<Mutex<…>>`, ensuring
/// the token count is consistent across connections.
#[derive(Clone)]
pub struct TokenBucketRateLimiterService<S> {
    /// The inner (downstream) service.
    inner: S,
    /// Shared mutable token bucket state.
    state: Arc<Mutex<TokenBucket>>,
    /// Maximum token capacity (for refill capping).
    capacity: usize,
    /// Tokens added per refill interval.
    refill_tokens: usize,
    /// Duration between refills.
    interval: Duration,
    /// Server name label for tracing.
    server_name: &'static str,
}

impl<S> TokenBucketRateLimiterService<S> {
    /// Creates a new `TokenBucketRateLimiterService`.
    ///
    /// The bucket starts at full capacity.
    pub fn new(
        inner: S,
        capacity: usize,
        refill_tokens: usize,
        interval: Duration,
        server_name: &'static str,
    ) -> Self {
        let state = Arc::new(Mutex::new(TokenBucket {
            tokens: capacity,
            last_refill: Instant::now(),
        }));

        Self {
            inner,
            state,
            capacity,
            refill_tokens,
            interval,
            server_name,
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
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    /// Refills the bucket, then attempts to consume a token.
    ///
    /// * **Token available** → drops the lock and forwards the request.
    /// * **Bucket empty** → returns 429 immediately.
    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let (try_consume, current_tokens) = {
            let mut bucket = self.state.lock().unwrap();
            bucket.refill(self.capacity, self.refill_tokens, self.interval);
            let consumed = bucket.try_consume();
            (consumed, bucket.tokens)
        };

        let server_name = self.server_name;

        if try_consume {
            debug!(
                "{}: Token consumed (bucket limiter). Remaining: {}",
                server_name, current_tokens
            );
            let fut = self.inner.call(req);
            Box::pin(async move { fut.await })
        } else {
            warn!(
                "{}: Too Many Requests – no tokens available (bucket limiter).",
                server_name
            );
            let body: ServiceRespBody = Full::new(Bytes::from_static(b"Too Many Requests"))
                .map_err(SrvError::from)
                .boxed();

            let mut response = Response::new(body);
            *response.status_mut() = StatusCode::TOO_MANY_REQUESTS;
            Box::pin(async move { Ok(response) })
        }
    }
}
