//! # Request and Concurrency Limiting Middleware
//!
//! This module provides two resource protection mechanisms:
//!
//! 1. **[`MaxPayloadLayer`]** – Enforces an upper bound on incoming request body size
//!    using a two-stage strategy (Header check and streaming body frame check).
//! 2. **[`ConcurrencyLimitLayer`]** – Limits the number of concurrent in-flight requests
//!    per server route using a semaphore. Supports:
//!    - **Load-Shedding**: Fails fast with **503 Service Unavailable** and `Retry-After: 1`
//!      instead of queuing indefinitely into RAM.
//!    - **Body-Aware Permits**: Retains the concurrency permit across the entire lifecycle
//!      of response body streaming, preventing slow/streaming clients from bypassing concurrency quotas.

// === Standard Library ===
use std::{
    future::Future,
    pin::Pin,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};

// === External Crates ===
use bytes::Bytes;
use http_body::Body;
use http_body_util::{BodyExt, Full};
use hyper::{header::CONTENT_LENGTH, Request, Response, StatusCode};
use pin_project::pin_project;
use tower::{Layer, Service};

// === Internal Modules ===
use crate::{SrvBody, SrvError};

// ============================================================================
//  MAX PAYLOAD LAYER & SERVICE
// ============================================================================

/// Returns `true` if `err` or any error in its `.source()` chain is a payload-size
/// limit violation (`SrvError::PayloadTooLarge` or `http_body_util::LengthLimitError`).
pub(crate) fn is_payload_too_large_error(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut current: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = current {
        if let Some(SrvError::PayloadTooLarge { .. }) = e.downcast_ref::<SrvError>() {
            return true;
        }
        if e.downcast_ref::<http_body_util::LengthLimitError>().is_some() {
            return true;
        }
        current = e.source();
    }
    false
}

/// Default multiplier applied to `max_bytes` for cumulative `application/grpc`
/// stream body limits when no explicit stream cap is configured.
const DEFAULT_GRPC_STREAM_MULTIPLIER: usize = 64;

/// Controls when `MaxPayloadLayer` allows `Content-Type: application/grpc` requests
/// to use per-message gRPC framing and the cumulative `max_stream_bytes` cap instead
/// of the strict single-body `max_bytes` cap (`S2-04`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum GrpcStreamPolicy {
    /// Never allow gRPC framing / `max_stream_bytes` expansion; every request is
    /// strictly bounded by `max_bytes` regardless of its `Content-Type` header.
    Disabled,
    /// Allow gRPC framing only when the sanitized request URI path matches one of
    /// the configured `grpc_passthrough` route prefixes.
    AllowPrefixes(Arc<[String]>),
    /// Allow gRPC framing for any request advertising `Content-Type: application/grpc*`
    /// (default for [`MaxPayloadLayer::new`] and embedded custom gRPC bases).
    #[default]
    AllowAnyGrpcContentType,
}

/// Checks if a normalized request path matches a configured route prefix on a segment boundary.
fn matches_route_prefix(normalized_path: &str, prefix: &str) -> bool {
    let normalized_prefix = prefix.trim_end_matches('/');
    if normalized_prefix.is_empty() {
        return prefix == "/";
    }
    normalized_path == normalized_prefix
        || normalized_path
            .strip_prefix(normalized_prefix)
            .is_some_and(|rest| rest.starts_with('/'))
}

/// A Tower [`Layer`] that wraps a service with payload size enforcement.
#[derive(Clone)]
pub struct MaxPayloadLayer {
    /// Maximum allowed request body size in bytes (or per-message cap for gRPC).
    max_bytes: usize,
    /// Optional cumulative maximum stream body size in bytes for `application/grpc` requests.
    max_stream_bytes: Option<usize>,
    /// Policy governing which routes/services may opt into gRPC framing (`S2-04`).
    grpc_stream_policy: GrpcStreamPolicy,
    /// Server name label for tracing output.
    server_name: &'static str,
}

impl MaxPayloadLayer {
    /// Creates a new `MaxPayloadLayer`.
    ///
    /// For `application/grpc` streams allowed by [`GrpcStreamPolicy`], enforces
    /// `max_bytes` per gRPC message frame and a cumulative stream cap of
    /// `max_bytes.saturating_mul(64)` by default
    /// (override via [`MaxPayloadLayer::with_max_stream_bytes`] and restrict routes
    /// via [`MaxPayloadLayer::with_grpc_stream_policy`]).
    pub fn new(max_bytes: usize, server_name: &'static str) -> Self {
        Self {
            max_bytes,
            max_stream_bytes: Some(max_bytes.saturating_mul(DEFAULT_GRPC_STREAM_MULTIPLIER)),
            grpc_stream_policy: GrpcStreamPolicy::AllowAnyGrpcContentType,
            server_name,
        }
    }

    /// Configures the cumulative stream body byte limit for `application/grpc` requests.
    pub fn with_max_stream_bytes(mut self, max_stream_bytes: Option<usize>) -> Self {
        self.max_stream_bytes = max_stream_bytes;
        self
    }

    /// Restricts when `Content-Type: application/grpc` may activate gRPC framing
    /// and `max_stream_bytes` (e.g., only on `RouteBackendType::GrpcPassthrough` routes).
    pub fn with_grpc_stream_policy(mut self, grpc_stream_policy: GrpcStreamPolicy) -> Self {
        self.grpc_stream_policy = grpc_stream_policy;
        self
    }
}

impl<S> Layer<S> for MaxPayloadLayer {
    type Service = MaxPayloadService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        MaxPayloadService {
            inner,
            max_bytes: self.max_bytes,
            max_stream_bytes: self.max_stream_bytes,
            grpc_stream_policy: self.grpc_stream_policy.clone(),
            server_name: self.server_name,
        }
    }
}

/// Service that enforces the maximum payload size.
#[derive(Clone)]
pub struct MaxPayloadService<S> {
    inner: S,
    max_bytes: usize,
    max_stream_bytes: Option<usize>,
    grpc_stream_policy: GrpcStreamPolicy,
    server_name: &'static str,
}

impl<S> MaxPayloadService<S> {
    fn allows_grpc_streaming(&self, raw_uri_path: &str) -> bool {
        match &self.grpc_stream_policy {
            GrpcStreamPolicy::Disabled => false,
            GrpcStreamPolicy::AllowAnyGrpcContentType => true,
            GrpcStreamPolicy::AllowPrefixes(prefixes) => {
                // Fail-closed: if the URI path contains traversal or illegal escapes,
                // never grant the expanded gRPC stream budget.
                let Ok(normalized) =
                    crate::middleware::path_sanitizer::sanitize_and_normalize_path_cow(raw_uri_path)
                else {
                    return false;
                };
                prefixes
                    .iter()
                    .any(|prefix| matches_route_prefix(&normalized, prefix))
            }
        }
    }
}

#[pin_project(project = MaxPayloadFutureProj)]
pub enum MaxPayloadFuture<F> {
    HeaderRejected {
        response: Option<Response<SrvBody>>,
    },
    Streaming {
        #[pin]
        inner: F,
        server_name: &'static str,
        max_bytes: usize,
    },
}

impl<F, E> Future for MaxPayloadFuture<F>
where
    F: Future<Output = Result<Response<SrvBody>, E>>,
    SrvError: From<E>,
{
    type Output = Result<Response<SrvBody>, SrvError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            MaxPayloadFutureProj::HeaderRejected { response } => {
                crate::poll_ready_response(response)
            }
            MaxPayloadFutureProj::Streaming {
                inner,
                server_name,
                max_bytes,
            } => {
                let result = std::task::ready!(inner.poll(cx));
                tracing::debug!("{}: End Max Payload: {}", server_name, max_bytes);

                match result {
                    Ok(resp) => Poll::Ready(Ok(resp)),
                    Err(e) => {
                        let srv_err: SrvError = e.into();
                        if is_payload_too_large_error(&srv_err) {
                            crate::configuration::ServerMetrics::inc_payload_too_large(server_name);
                            let msg = "Payload too large (Streaming check)";
                            tracing::warn!("{}: {}", server_name, msg);
                            Poll::Ready(Ok(build_413_response(msg)))
                        } else {
                            Poll::Ready(Err(srv_err))
                        }
                    }
                }
            }
        }
    }
}

impl<S> Service<Request<SrvBody>> for MaxPayloadService<S>
where
    S: Service<Request<SrvBody>, Response = Response<SrvBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    SrvError: From<<S as tower::Service<hyper::Request<SrvBody>>>::Error>,
{
    type Response = Response<SrvBody>;
    type Error = SrvError;
    type Future = MaxPayloadFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: Request<SrvBody>) -> Self::Future {
        let max_bytes = self.max_bytes;
        let server_name = self.server_name;

        // Stage 1: Content-Length header fast path (fail-closed on overflowing or malformed values)
        for content_length_val in req.headers().get_all(CONTENT_LENGTH) {
            let invalid_or_exceeds = match content_length_val.to_str() {
                Ok(s) => match s.trim().parse::<usize>() {
                    Ok(len) => len > max_bytes,
                    Err(_) => true,
                },
                Err(_) => true,
            };
            if invalid_or_exceeds {
                crate::configuration::ServerMetrics::inc_payload_too_large(server_name);
                let msg = "Payload too large (Header check)";
                tracing::warn!("{}: {}", server_name, msg);
                return MaxPayloadFuture::HeaderRejected {
                    response: Some(build_413_response(msg)),
                };
            }
        }

        // Stage 2: Streaming byte counter (zero-alloc check excluding base64 grpc-web-text)
        let has_grpc_content_type = req
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|s| {
                let b = s.trim().as_bytes();
                b.len() >= 16
                    && b[..16].eq_ignore_ascii_case(b"application/grpc")
                    && !(b.len() >= 25
                        && b[..25].eq_ignore_ascii_case(b"application/grpc-web-text"))
            });
        let is_grpc = has_grpc_content_type && self.allows_grpc_streaming(req.uri().path());

        let grpc_state = if is_grpc {
            Some(GrpcFramingState::Header {
                buf: [0u8; 5],
                pos: 0,
            })
        } else {
            None
        };

        let (parts, body) = req.into_parts();
        let limited_body = LimitedBody {
            inner: body,
            max_bytes,
            max_stream_bytes: self.max_stream_bytes,
            current_bytes: 0,
            grpc_state,
        };

        let req = Request::from_parts(parts, limited_body.boxed());
        let fut = self.inner.call(req);

        MaxPayloadFuture::Streaming {
            inner: fut,
            server_name,
            max_bytes,
        }
    }
}

/// Internal state machine for tracking gRPC message framing.
///
/// In gRPC (HTTP/2 or HTTP/3), every message starts with a 5-byte prefix:
/// - 1 byte: compression flag (`0x00` = uncompressed, `0x01` = compressed)
/// - 4 bytes: message length in big-endian (`u32`)
///
/// By parsing this framing, the max-payload limiter enforces `max_bytes`
/// on each individual message in a gRPC stream (preventing giant-payload attacks)
/// while allowing long-lived streaming RPCs (like chat or pub/sub) to run indefinitely.
#[derive(Debug, Clone)]
enum GrpcFramingState {
    Header { buf: [u8; 5], pos: usize },
    Payload { remaining: usize },
}

/// A body wrapper that counts the bytes passing through and aborts with an
/// error when the configured limit is exceeded.
#[pin_project]
pub struct LimitedBody<B> {
    #[pin]
    inner: B,
    max_bytes: usize,
    max_stream_bytes: Option<usize>,
    current_bytes: usize,
    grpc_state: Option<GrpcFramingState>,
}

impl<B> Body for LimitedBody<B>
where
    B: Body<Data = Bytes, Error = SrvError>,
{
    type Data = Bytes;
    type Error = SrvError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let this = self.project();

        match this.inner.poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    if let Some(state) = this.grpc_state {
                        *this.current_bytes = this.current_bytes.saturating_add(data.len());
                        if let Some(max_stream) = *this.max_stream_bytes
                            && *this.current_bytes > max_stream
                        {
                            return Poll::Ready(Some(Err(SrvError::PayloadTooLarge {
                                current: *this.current_bytes,
                                max: max_stream,
                            })));
                        }

                        let mut offset = 0;
                        while offset < data.len() {
                            match state {
                                GrpcFramingState::Header { buf, pos } => {
                                    let needed = 5 - *pos;
                                    let available = data.len() - offset;
                                    let to_copy = needed.min(available);
                                    buf[*pos..*pos + to_copy]
                                        .copy_from_slice(&data[offset..offset + to_copy]);
                                    *pos += to_copy;
                                    offset += to_copy;

                                    if *pos == 5 {
                                        if buf[0] > 1 {
                                            return Poll::Ready(Some(Err(
                                                SrvError::PayloadTooLarge {
                                                    current: *this.current_bytes,
                                                    max: *this.max_bytes,
                                                },
                                            )));
                                        }
                                        let msg_len = u32::from_be_bytes([
                                            buf[1], buf[2], buf[3], buf[4],
                                        ]) as usize;
                                        if msg_len > *this.max_bytes {
                                            return Poll::Ready(Some(Err(
                                                SrvError::PayloadTooLarge {
                                                    current: msg_len,
                                                    max: *this.max_bytes,
                                                },
                                            )));
                                        }
                                        *state = GrpcFramingState::Payload {
                                            remaining: msg_len,
                                        };
                                    }
                                }
                                GrpcFramingState::Payload { remaining } => {
                                    let available = data.len() - offset;
                                    let consumed = available.min(*remaining);
                                    *remaining -= consumed;
                                    offset += consumed;

                                    if *remaining == 0 {
                                        *state = GrpcFramingState::Header {
                                            buf: [0u8; 5],
                                            pos: 0,
                                        };
                                    }
                                }
                            }
                        }
                    } else {
                        *this.current_bytes = this.current_bytes.saturating_add(data.len());

                        if *this.current_bytes > *this.max_bytes {
                            return Poll::Ready(Some(Err(SrvError::PayloadTooLarge {
                                current: *this.current_bytes,
                                max: *this.max_bytes,
                            })));
                        }
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            res => res,
        }
    }
}

/// Builds a **413 Payload Too Large** response with a short message body.
fn build_413_response(msg: &'static str) -> Response<SrvBody> {
    let body = Full::new(Bytes::from(msg))
        .map_err(|e| match e {})
        .boxed();

    crate::build_infallible_response(StatusCode::PAYLOAD_TOO_LARGE, None, body)
}

// ============================================================================
//  CONCURRENCY LIMIT LAYER & SERVICE
// ============================================================================

/// A body wrapper that retains an [`tokio::sync::OwnedSemaphorePermit`] until the
/// response body stream finishes or is dropped.
#[pin_project]
pub struct PermittedBody<B> {
    #[pin]
    inner: B,
    permit: Option<tokio::sync::OwnedSemaphorePermit>,
}

impl<B> Body for PermittedBody<B>
where
    B: Body<Data = Bytes, Error = SrvError>,
{
    type Data = Bytes;
    type Error = SrvError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let this = self.project();
        let res = this.inner.poll_frame(cx);
        match &res {
            Poll::Ready(None) | Poll::Ready(Some(Err(_))) => {
                this.permit.take();
            }
            _ => {}
        }
        res
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

/// Default maximum queue capacity when `load_shed = false` and no explicit queue limit is set.
/// Setting `with_queue_limit(None)` allows unbounded waiting for backward compatibility unless
/// overridden via `ConcurrencyLimitConfig::max_queue_size`.
#[derive(Debug)]
struct QueueSlotGuard {
    queued: Arc<AtomicUsize>,
}

impl Drop for QueueSlotGuard {
    fn drop(&mut self) {
        self.queued.fetch_sub(1, Ordering::Release);
    }
}

/// A Tower [`Layer`] that limits concurrent in-flight requests.
#[derive(Clone)]
pub struct ConcurrencyLimitLayer {
    semaphore: Arc<tokio::sync::Semaphore>,
    server_name: &'static str,
    load_shed: bool,
    queue_timeout: Option<Duration>,
    max_queue_size: Option<usize>,
    queued_requests: Arc<AtomicUsize>,
}

impl ConcurrencyLimitLayer {
    pub fn new(max_requests: usize, server_name: &'static str) -> Self {
        Self::with_config(max_requests, true, None, server_name)
    }

    pub fn with_config(
        max_requests: usize,
        load_shed: bool,
        queue_timeout: Option<Duration>,
        server_name: &'static str,
    ) -> Self {
        // Bound the waiting queue by default to prevent unbounded RAM growth under load.
        let default_queue_cap = max_requests.saturating_mul(4).clamp(64, 4096);
        Self {
            semaphore: Arc::new(tokio::sync::Semaphore::new(max_requests)),
            server_name,
            load_shed,
            queue_timeout,
            max_queue_size: Some(default_queue_cap),
            queued_requests: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Sets an upper bound on the number of requests waiting in the queue when
    /// `load_shed` is `false`. Excess requests fail fast with `503 Service Unavailable`.
    pub fn with_queue_limit(mut self, max_queue_size: Option<usize>) -> Self {
        self.max_queue_size = max_queue_size;
        self
    }
}

impl<S> Layer<S> for ConcurrencyLimitLayer {
    type Service = ConcurrencyLimitService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        ConcurrencyLimitService {
            inner,
            semaphore: self.semaphore.clone(),
            server_name: self.server_name,
            load_shed: self.load_shed,
            queue_timeout: self.queue_timeout,
            max_queue_size: self.max_queue_size,
            queued_requests: self.queued_requests.clone(),
        }
    }
}

/// Service that enforces concurrent request quotas.
#[derive(Clone)]
pub struct ConcurrencyLimitService<S> {
    inner: S,
    semaphore: Arc<tokio::sync::Semaphore>,
    server_name: &'static str,
    load_shed: bool,
    queue_timeout: Option<Duration>,
    max_queue_size: Option<usize>,
    queued_requests: Arc<AtomicUsize>,
}

#[pin_project(project = ConcurrencyLimitFutureProj)]
pub enum ConcurrencyLimitFuture<F, S, ReqBody> {
    Processing {
        #[pin]
        inner: F,
        permit: Option<tokio::sync::OwnedSemaphorePermit>,
    },
    Waiting {
        #[pin]
        acquire_task: Pin<Box<dyn Future<Output = Result<tokio::sync::OwnedSemaphorePermit, ()>> + Send>>,
        req: Option<Request<ReqBody>>,
        inner: S,
        server_name: &'static str,
    },
    Immediate {
        response: Option<Response<SrvBody>>,
    },
}

impl<S, ReqBody> Service<Request<ReqBody>> for ConcurrencyLimitService<S>
where
    S: Service<Request<ReqBody>, Response = Response<SrvBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<SrvError> + 'static,
    ReqBody: Send + 'static,
{
    type Response = Response<SrvBody>;
    type Error = SrvError;
    type Future = ConcurrencyLimitFuture<S::Future, S, ReqBody>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        if self.load_shed {
            match self.semaphore.clone().try_acquire_owned() {
                Ok(permit) => {
                    let fut = self.inner.call(req);
                    ConcurrencyLimitFuture::Processing {
                        inner: fut,
                        permit: Some(permit),
                    }
                }
                Err(_) => {
                    crate::configuration::ServerMetrics::inc_concurrency_limited(self.server_name);
                    tracing::warn!("{}: Concurrency limit reached (load-shedding)", self.server_name);
                    ConcurrencyLimitFuture::Immediate {
                        response: Some(build_503_response()),
                    }
                }
            }
        } else {
            // Fast path: if a permit is immediately available, avoid queuing overhead.
            if let Ok(permit) = self.semaphore.clone().try_acquire_owned() {
                let fut = self.inner.call(req);
                return ConcurrencyLimitFuture::Processing {
                    inner: fut,
                    permit: Some(permit),
                };
            }

            // Enforce optional bounded queue capacity before allocating a waiting future.
            let queue_guard = if let Some(max_q) = self.max_queue_size {
                let mut cur = self.queued_requests.load(Ordering::Acquire);
                loop {
                    if cur >= max_q {
                        crate::configuration::ServerMetrics::inc_concurrency_limited(
                            self.server_name,
                        );
                        tracing::warn!(
                            "{}: Concurrency queue full (max_queue_size = {}), rejecting request",
                            self.server_name,
                            max_q
                        );
                        return ConcurrencyLimitFuture::Immediate {
                            response: Some(build_503_response()),
                        };
                    }
                    match self.queued_requests.compare_exchange_weak(
                        cur,
                        cur + 1,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    ) {
                        Ok(_) => break,
                        Err(actual) => cur = actual,
                    }
                }
                Some(QueueSlotGuard {
                    queued: self.queued_requests.clone(),
                })
            } else {
                None
            };

            let sem = self.semaphore.clone();
            let acquire_task: Pin<
                Box<dyn Future<Output = Result<tokio::sync::OwnedSemaphorePermit, ()>> + Send>,
            > = if let Some(timeout_dur) = self.queue_timeout {
                Box::pin(async move {
                    let _guard = queue_guard;
                    match tokio::time::timeout(timeout_dur, sem.acquire_owned()).await {
                        Ok(Ok(p)) => Ok(p),
                        _ => Err(()),
                    }
                })
            } else {
                Box::pin(async move {
                    let _guard = queue_guard;
                    sem.acquire_owned().await.map_err(|_| ())
                })
            };

            ConcurrencyLimitFuture::Waiting {
                acquire_task,
                req: Some(req),
                inner: self.inner.clone(),
                server_name: self.server_name,
            }
        }
    }
}

impl<F, S, ReqBody, E> Future for ConcurrencyLimitFuture<F, S, ReqBody>
where
    F: Future<Output = Result<Response<SrvBody>, E>>,
    E: Into<SrvError>,
    S: Service<Request<ReqBody>, Response = Response<SrvBody>, Future = F> + Clone,
{
    type Output = Result<Response<SrvBody>, SrvError>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        loop {
            let this = self.as_mut().project();
            match this {
                ConcurrencyLimitFutureProj::Immediate { response } => {
                    return crate::poll_ready_response(response);
                }
                ConcurrencyLimitFutureProj::Waiting {
                    acquire_task,
                    req,
                    inner,
                    server_name,
                } => match acquire_task.poll(cx) {
                    Poll::Ready(Ok(permit)) => {
                        let Some(request) = req.take() else {
                            return Poll::Ready(Err(SrvError::from(
                                "ConcurrencyLimitFuture polled after completion".to_string(),
                            )));
                        };
                        let fut = inner.call(request);
                        self.set(ConcurrencyLimitFuture::Processing {
                            inner: fut,
                            permit: Some(permit),
                        });
                        continue;
                    }
                    Poll::Ready(Err(())) => {
                        crate::configuration::ServerMetrics::inc_concurrency_limited(server_name);
                        return Poll::Ready(Ok(build_503_response()));
                    }
                    Poll::Pending => return Poll::Pending,
                },
                ConcurrencyLimitFutureProj::Processing { inner, permit } => {
                    match inner.poll(cx) {
                        Poll::Ready(Ok(resp)) => {
                            let Some(p) = permit.take() else {
                                return Poll::Ready(Err(SrvError::from(
                                    "ConcurrencyLimitFuture permit missing in Processing".to_string(),
                                )));
                            };
                            let (parts, body) = resp.into_parts();
                            let permitted = PermittedBody {
                                inner: body,
                                permit: Some(p),
                            };
                            return Poll::Ready(Ok(Response::from_parts(parts, permitted.boxed())));
                        }
                        Poll::Ready(Err(e)) => {
                            return Poll::Ready(Err(e.into()));
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }
    }
}

/// Builds a **503 Service Unavailable** response with `Retry-After: 1` header.
pub fn build_503_response() -> Response<SrvBody> {
    let body = Full::new(Bytes::from_static(b"Service Overloaded (Concurrency Limit Exceeded)"))
        .map_err(|e| match e {})
        .boxed();

    let mut resp = crate::build_infallible_response(StatusCode::SERVICE_UNAVAILABLE, None, body);
    resp.headers_mut().insert(
        hyper::header::RETRY_AFTER,
        hyper::header::HeaderValue::from_static("1"),
    );
    resp
}

// ============================================================================
//  UNIT TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use tower::{service_fn, ServiceExt};
    use tokio::sync::oneshot;

    #[tokio::test]
    async fn test_concurrency_limit_load_shedding_rejects_immediately() {
        let (tx, rx) = oneshot::channel::<()>();
        let shared_rx = Arc::new(tokio::sync::Mutex::new(Some(rx)));

        let inner_svc = service_fn(move |_req: Request<Full<Bytes>>| {
            let rx = shared_rx.clone();
            async move {
                if let Some(r) = rx.lock().await.take() {
                    let _ = r.await;
                }
                let body: SrvBody = Full::new(Bytes::from("OK")).map_err(SrvError::from).boxed();
                Ok::<Response<SrvBody>, std::convert::Infallible>(Response::new(body))
            }
        });

        let mut svc = ConcurrencyLimitService {
            inner: inner_svc,
            semaphore: Arc::new(tokio::sync::Semaphore::new(1)),
            server_name: "test_concurrency",
            load_shed: true,
            queue_timeout: None,
            max_queue_size: None,
            queued_requests: Arc::new(AtomicUsize::new(0)),
        };

        // First request acquires the single permit and waits on the channel
        let req1 = Request::builder().uri("/test1").body(Full::new(Bytes::new())).unwrap();
        let fut1 = svc.ready().await.unwrap().call(req1);
        tokio::pin!(fut1);

        // Drive fut1 once so it acquires the permit and blocks inside inner service
        let waker = futures::task::noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(fut1.as_mut().poll(&mut cx).is_pending());

        // Second request arrives while permit 1 is in-flight -> rejected immediately with 503
        let req2 = Request::builder().uri("/test2").body(Full::new(Bytes::new())).unwrap();
        let resp2 = svc.ready().await.unwrap().call(req2).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(resp2.headers().get(hyper::header::RETRY_AFTER).unwrap(), "1");

        // Complete request 1
        tx.send(()).unwrap();
        let resp1 = fut1.await.unwrap();
        assert_eq!(resp1.status(), StatusCode::OK);

        // Drop response 1 to release its body and the associated concurrency permit
        drop(resp1);

        // Third request can now succeed since permit was released
        let req3 = Request::builder().uri("/test3").body(Full::new(Bytes::new())).unwrap();
        let resp3 = svc.ready().await.unwrap().call(req3).await.unwrap();
        assert_eq!(resp3.status(), StatusCode::OK);

        let metrics = crate::configuration::ServerMetrics::for_server("test_concurrency");
        assert_eq!(
            metrics
                .concurrency_limited
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn test_concurrency_limit_retains_permit_during_body_streaming() {
        let (body_tx, body_rx) = tokio::sync::mpsc::channel::<Result<http_body::Frame<Bytes>, SrvError>>(2);

        struct ChannelBody {
            rx: tokio::sync::mpsc::Receiver<Result<http_body::Frame<Bytes>, SrvError>>,
        }

        impl Body for ChannelBody {
            type Data = Bytes;
            type Error = SrvError;

            fn poll_frame(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
                self.rx.poll_recv(cx)
            }
        }

        let shared_rx = Arc::new(tokio::sync::Mutex::new(Some(body_rx)));

        let inner_svc = service_fn(move |_req: Request<Full<Bytes>>| {
            let rx = shared_rx.clone();
            async move {
                let rx_taken = rx.lock().await.take().unwrap();
                let body: SrvBody = ChannelBody { rx: rx_taken }.boxed();
                Ok::<Response<SrvBody>, std::convert::Infallible>(Response::new(body))
            }
        });

        let mut svc = ConcurrencyLimitService {
            inner: inner_svc,
            semaphore: Arc::new(tokio::sync::Semaphore::new(1)),
            server_name: "test_streaming",
            load_shed: true,
            queue_timeout: None,
            max_queue_size: None,
            queued_requests: Arc::new(AtomicUsize::new(0)),
        };

        // Request 1 arrives and gets headers response, but body stream is still active
        let req1 = Request::builder().uri("/stream").body(Full::new(Bytes::new())).unwrap();
        let mut resp1 = svc.ready().await.unwrap().call(req1).await.unwrap();
        assert_eq!(resp1.status(), StatusCode::OK);

        // Request 2 arrives while Request 1's body has NOT finished -> must be rejected (503)!
        let req2 = Request::builder().uri("/other").body(Full::new(Bytes::new())).unwrap();
        let resp2 = svc.ready().await.unwrap().call(req2).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::SERVICE_UNAVAILABLE);

        // Stream frame 1 of request 1
        body_tx.send(Ok(http_body::Frame::data(Bytes::from("chunk1")))).await.unwrap();
        let frame1 = resp1.body_mut().frame().await.unwrap().unwrap();
        assert_eq!(frame1.into_data().unwrap(), Bytes::from("chunk1"));

        // Still active -> Request 2 still rejected
        let req2b = Request::builder().uri("/other").body(Full::new(Bytes::new())).unwrap();
        let resp2b = svc.ready().await.unwrap().call(req2b).await.unwrap();
        assert_eq!(resp2b.status(), StatusCode::SERVICE_UNAVAILABLE);

        // Drop body_tx to end stream of request 1
        drop(body_tx);
        assert!(resp1.body_mut().frame().await.is_none());

        // Now Request 3 can acquire the permit!
        let _req3 = Request::builder().uri("/other").body(Full::new(Bytes::new())).unwrap();
        // Since inner_svc can't take rx again, let's test that the semaphore itself has capacity
        assert_eq!(svc.semaphore.available_permits(), 1);
    }

    #[tokio::test]
    async fn test_max_payload_grpc_streaming_multiple_messages_exceeding_cumulative_limit_succeeds() {
        // max_bytes = 25.
        // We will send 3 gRPC messages, each with 10 bytes payload (15 bytes total per message).
        // Total bytes = 45 bytes > 25. In the old cumulative implementation, this failed.
        // In the new framing implementation, each message is 10 <= 25, so it must succeed!
        let inner_svc = service_fn(|mut req: Request<SrvBody>| async move {
            let mut total_received = 0;
            while let Some(frame) = req.body_mut().frame().await {
                let frame = frame.unwrap();
                if let Some(data) = frame.data_ref() {
                    total_received += data.len();
                }
            }
            let body: SrvBody = Full::new(Bytes::from(format!("Received {}", total_received)))
                .map_err(SrvError::from)
                .boxed();
            Ok::<Response<SrvBody>, SrvError>(Response::new(body))
        });

        let layer = MaxPayloadLayer::new(25, "test_grpc_streaming");
        let mut svc = layer.layer(inner_svc);

        // Helper to encode a gRPC frame: [0x00][u32 len][payload]
        let make_grpc_msg = |payload: &[u8]| -> Vec<u8> {
            let mut buf = Vec::with_capacity(5 + payload.len());
            buf.push(0x00); // uncompressed
            buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            buf.extend_from_slice(payload);
            buf
        };

        let msg1 = make_grpc_msg(&[b'A'; 10]);
        let msg2 = make_grpc_msg(&[b'B'; 10]);
        let msg3 = make_grpc_msg(&[b'C'; 10]);

        let (body_tx, body_rx) = tokio::sync::mpsc::channel::<Result<http_body::Frame<Bytes>, SrvError>>(5);

        struct ChannelReqBody {
            rx: tokio::sync::mpsc::Receiver<Result<http_body::Frame<Bytes>, SrvError>>,
        }
        impl Body for ChannelReqBody {
            type Data = Bytes;
            type Error = SrvError;
            fn poll_frame(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
                self.rx.poll_recv(cx)
            }
        }

        let req = Request::builder()
            .uri("/chat.ChatService/StreamMessages")
            .header(hyper::header::CONTENT_TYPE, "application/grpc")
            .body(ChannelReqBody { rx: body_rx }.boxed())
            .unwrap();

        let fut = svc.ready().await.unwrap().call(req);

        // Stream the 3 messages
        body_tx.send(Ok(http_body::Frame::data(Bytes::from(msg1)))).await.unwrap();
        body_tx.send(Ok(http_body::Frame::data(Bytes::from(msg2)))).await.unwrap();
        body_tx.send(Ok(http_body::Frame::data(Bytes::from(msg3)))).await.unwrap();
        drop(body_tx); // EOF

        let mut resp = fut.await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let resp_data = resp.body_mut().frame().await.unwrap().unwrap().into_data().unwrap();
        assert_eq!(resp_data, Bytes::from("Received 45"));
    }

    #[tokio::test]
    async fn test_max_payload_grpc_single_message_exceeds_limit_fails() {
        let inner_svc = service_fn(|mut req: Request<SrvBody>| async move {
            while let Some(frame) = req.body_mut().frame().await {
                let _ = frame?;
            }
            Ok::<Response<SrvBody>, SrvError>(Response::new(Full::new(Bytes::from("OK")).map_err(SrvError::from).boxed()))
        });

        let layer = MaxPayloadLayer::new(25, "test_grpc_single_oversized");
        let mut svc = layer.layer(inner_svc);

        // gRPC frame declaring 30 bytes payload (30 > 25 limit)
        let mut oversized_header = vec![0x00];
        oversized_header.extend_from_slice(&(30u32).to_be_bytes());
        oversized_header.extend_from_slice(&[b'X'; 10]); // send partial data

        let req = Request::builder()
            .uri("/chat.ChatService/SendMessage")
            .header(hyper::header::CONTENT_TYPE, "application/grpc")
            .body(Full::new(Bytes::from(oversized_header)).map_err(SrvError::from).boxed())
            .unwrap();

        let resp = svc.ready().await.unwrap().call(req).await.unwrap();
        // Since inner body polling fails with PayloadTooLarge, MaxPayloadFuture maps it to 413 Payload Too Large!
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn test_max_payload_http_cumulative_stream_fails() {
        let inner_svc = service_fn(|mut req: Request<SrvBody>| async move {
            while let Some(frame) = req.body_mut().frame().await {
                let _ = frame?;
            }
            Ok::<Response<SrvBody>, SrvError>(Response::new(Full::new(Bytes::from("OK")).map_err(SrvError::from).boxed()))
        });

        let layer = MaxPayloadLayer::new(25, "test_http_cumulative");
        let mut svc = layer.layer(inner_svc);

        // Standard HTTP (no application/grpc): 30 bytes total > 25 limit
        let req = Request::builder()
            .uri("/upload")
            .header(hyper::header::CONTENT_TYPE, "application/octet-stream")
            .body(Full::new(Bytes::from(vec![b'Z'; 30])).map_err(SrvError::from).boxed())
            .unwrap();

        let resp = svc.ready().await.unwrap().call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let metrics = crate::configuration::ServerMetrics::for_server("test_http_cumulative");
        assert_eq!(
            metrics
                .payload_too_large
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn test_max_payload_header_reject_records_metric() {
        let inner_svc = service_fn(|_req: Request<SrvBody>| async move {
            Ok::<Response<SrvBody>, SrvError>(Response::new(
                Full::new(Bytes::from("OK")).map_err(SrvError::from).boxed(),
            ))
        });

        let layer = MaxPayloadLayer::new(16, "test_max_payload_header_metrics");
        let mut svc = layer.layer(inner_svc);

        let req = Request::builder()
            .uri("/upload")
            .header(CONTENT_LENGTH, "100")
            .body(Full::new(Bytes::new()).map_err(SrvError::from).boxed())
            .unwrap();

        let resp = svc.ready().await.unwrap().call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);

        let metrics =
            crate::configuration::ServerMetrics::for_server("test_max_payload_header_metrics");
        assert_eq!(
            metrics
                .payload_too_large
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn test_max_payload_grpc_streaming_cumulative_cap_rejects_excess() {
        let inner_svc = service_fn(|mut req: Request<SrvBody>| async move {
            while let Some(frame) = req.body_mut().frame().await {
                frame?;
            }
            let body: SrvBody = Full::new(Bytes::from("OK")).map_err(SrvError::from).boxed();
            Ok::<Response<SrvBody>, SrvError>(Response::new(body))
        });

        // Per-message limit = 25, cumulative stream cap = 35
        let layer = MaxPayloadLayer::new(25, "test_grpc_stream_cap").with_max_stream_bytes(Some(35));
        let mut svc = layer.layer(inner_svc);

        let make_grpc_msg = |payload: &[u8]| -> Vec<u8> {
            let mut buf = Vec::with_capacity(5 + payload.len());
            buf.push(0x00);
            buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            buf.extend_from_slice(payload);
            buf
        };

        // 3 messages of 10 B payload => 15 B each => 45 B total > 35 B cumulative cap
        let combined = [
            make_grpc_msg(&[b'A'; 10]),
            make_grpc_msg(&[b'B'; 10]),
            make_grpc_msg(&[b'C'; 10]),
        ]
        .concat();

        let req = Request::builder()
            .uri("/chat.ChatService/StreamMessages")
            .header(hyper::header::CONTENT_TYPE, "application/grpc")
            .body(Full::new(Bytes::from(combined)).map_err(SrvError::from).boxed())
            .unwrap();

        let resp = svc.ready().await.unwrap().call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn test_concurrency_limit_bounded_queue_rejects_excess() {
        let notify = Arc::new(tokio::sync::Notify::new());
        let notify_clone = notify.clone();
        let inner_svc = service_fn(move |_req: Request<SrvBody>| {
            let notify = notify_clone.clone();
            async move {
                notify.notified().await;
                Ok::<Response<SrvBody>, SrvError>(Response::new(
                    Full::new(Bytes::from("OK")).map_err(SrvError::from).boxed(),
                ))
            }
        });

        let layer = ConcurrencyLimitLayer::with_config(
            1,
            false,
            Some(Duration::from_secs(5)),
            "test_bounded_queue",
        )
        .with_queue_limit(Some(1));
        let mut svc = layer.layer(inner_svc);

        let make_req = || {
            Request::builder()
                .uri("/work")
                .body(Full::new(Bytes::new()).map_err(SrvError::from).boxed())
                .unwrap()
        };

        // 1st request acquires the single active permit and blocks on notify.
        let fut1 = tokio::spawn(svc.ready().await.unwrap().call(make_req()));
        tokio::task::yield_now().await;

        // 2nd request waits in the queue (occupies queue slot 1/1).
        let fut2 = tokio::spawn(svc.ready().await.unwrap().call(make_req()));
        tokio::task::yield_now().await;

        // 3rd request exceeds max_queue_size=1 and must fail fast with 503.
        let resp3 = svc.ready().await.unwrap().call(make_req()).await.unwrap();
        assert_eq!(resp3.status(), StatusCode::SERVICE_UNAVAILABLE);

        // Release 1st request's execution, then drop `resp1` so its `PermittedBody`
        // releases the semaphore permit for the queued 2nd request (`fut2`).
        notify.notify_one();
        let resp1 = fut1.await.unwrap().unwrap();
        assert_eq!(resp1.status(), StatusCode::OK);
        drop(resp1);

        notify.notify_one();
        let resp2 = fut2.await.unwrap().unwrap();
        assert_eq!(resp2.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_max_payload_rejects_malformed_content_length_and_invalid_grpc_flag() -> Result<(), Box<dyn std::error::Error>> {
        let inner_svc = service_fn(|mut req: Request<SrvBody>| async move {
            while let Some(frame) = req.body_mut().frame().await {
                frame?;
            }
            let body: SrvBody = Full::new(Bytes::from("OK")).map_err(SrvError::from).boxed();
            Ok::<Response<SrvBody>, SrvError>(Response::new(body))
        });

        let layer = MaxPayloadLayer::new(64, "test_malformed_cl");
        let mut svc = layer.layer(inner_svc);

        // 1. Overflowing Content-Length (> usize::MAX) must fail-closed in Stage 1 with 413
        let req_overflow = Request::builder()
            .uri("/upload")
            .header(CONTENT_LENGTH, "999999999999999999999999999999999999999")
            .body(Full::new(Bytes::from_static(b"hi")).map_err(SrvError::from).boxed())?;
        let resp_overflow = svc.ready().await?.call(req_overflow).await?;
        assert_eq!(resp_overflow.status(), StatusCode::PAYLOAD_TOO_LARGE);

        // 2. Invalid gRPC compression flag (0x02 > 1) must be rejected with 413
        let bad_grpc_frame = vec![0x02, 0x00, 0x00, 0x00, 0x01, 0xAA];
        let req_bad_grpc = Request::builder()
            .uri("/chat.Service/Call")
            .header(hyper::header::CONTENT_TYPE, "application/grpc")
            .body(Full::new(Bytes::from(bad_grpc_frame)).map_err(SrvError::from).boxed())?;
        let resp_bad_grpc = svc.ready().await?.call(req_bad_grpc).await?;
        assert_eq!(resp_bad_grpc.status(), StatusCode::PAYLOAD_TOO_LARGE);
        Ok(())
    }

    #[tokio::test]
    async fn test_max_payload_grpc_stream_policy_blocks_non_grpc_route_bypass()
    -> Result<(), Box<dyn std::error::Error>> {
        let make_inner = || {
            service_fn(|mut req: Request<SrvBody>| async move {
                let mut total = 0usize;
                while let Some(frame) = req.body_mut().frame().await {
                    let frame = frame?;
                    if let Some(data) = frame.data_ref() {
                        total += data.len();
                    }
                }
                let body: SrvBody = Full::new(Bytes::from(format!("{total}")))
                    .map_err(SrvError::from)
                    .boxed();
                Ok::<Response<SrvBody>, SrvError>(Response::new(body))
            })
        };

        // Construct a 40-byte payload disguised as two 15-byte gRPC frames (each <= max_bytes=25,
        // total 40 bytes > max_bytes=25, <= 64*25).
        let mut disguised_body = Vec::new();
        for byte in *b"AB" {
            disguised_body.push(0x00);
            disguised_body.extend_from_slice(&(15u32).to_be_bytes());
            disguised_body.extend_from_slice(&[byte; 15]);
        }
        assert_eq!(disguised_body.len(), 40);

        let send_chunked_grpc_header = |mut svc: MaxPayloadService<_>, uri: &str| {
            let body_bytes = disguised_body.clone();
            let uri = uri.to_string();
            async move {
                let (tx, rx) =
                    tokio::sync::mpsc::channel::<Result<http_body::Frame<Bytes>, SrvError>>(2);
                struct StreamBody {
                    rx: tokio::sync::mpsc::Receiver<Result<http_body::Frame<Bytes>, SrvError>>,
                }
                impl Body for StreamBody {
                    type Data = Bytes;
                    type Error = SrvError;
                    fn poll_frame(
                        mut self: Pin<&mut Self>,
                        cx: &mut Context<'_>,
                    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>>
                    {
                        self.rx.poll_recv(cx)
                    }
                }
                tx.send(Ok(http_body::Frame::data(Bytes::from(body_bytes))))
                    .await?;
                drop(tx);
                let req = Request::builder()
                    .uri(uri)
                    .header(hyper::header::CONTENT_TYPE, "application/grpc")
                    .body(StreamBody { rx }.boxed())?;
                let resp = svc.ready().await?.call(req).await?;
                Ok::<_, Box<dyn std::error::Error>>(resp)
            }
        };

        // 1. GrpcStreamPolicy::Disabled rejects disguised >25-byte body with 413
        let disabled_svc = MaxPayloadLayer::new(25, "test_disabled")
            .with_grpc_stream_policy(GrpcStreamPolicy::Disabled)
            .layer(make_inner());
        let resp_disabled = send_chunked_grpc_header(disabled_svc, "/api/upload").await?;
        assert_eq!(resp_disabled.status(), StatusCode::PAYLOAD_TOO_LARGE);

        // 2. AllowPrefixes(["/grpc.Chat"]) allows matching gRPC route (/grpc.Chat/Stream),
        //    but strictly caps REST (/api/upload), prefix-similar (/grpc.ChatEvil/Stream),
        //    and traversal (/grpc.Chat/../api/upload) at max_bytes=25 (413).
        let prefix_layer = MaxPayloadLayer::new(25, "test_prefix_policy")
            .with_grpc_stream_policy(GrpcStreamPolicy::AllowPrefixes(Arc::from([
                "/grpc.Chat".to_string()
            ])));

        let resp_allowed =
            send_chunked_grpc_header(prefix_layer.clone().layer(make_inner()), "/grpc.Chat/Stream")
                .await?;
        assert_eq!(resp_allowed.status(), StatusCode::OK);

        for blocked_uri in [
            "/api/upload",
            "/grpc.ChatEvil/Stream",
            "/grpc.Chat/../api/upload",
            "/grpc.Chat/%2e%2e/api/upload",
            "/grpc.Chat/%2E%2E/api/upload",
        ] {
            let resp_blocked =
                send_chunked_grpc_header(prefix_layer.clone().layer(make_inner()), blocked_uri)
                    .await?;
            assert_eq!(
                resp_blocked.status(),
                StatusCode::PAYLOAD_TOO_LARGE,
                "expected 413 for non-gRPC or traversal URI '{blocked_uri}'"
            );
        }

        // 3. Trailing-slash prefix matches exact base path (/grpc.Chat) and subpaths (/grpc.Chat/Call)
        let trailing_layer = MaxPayloadLayer::new(25, "test_trailing_slash_prefix")
            .with_grpc_stream_policy(GrpcStreamPolicy::AllowPrefixes(Arc::from([
                "/grpc.Chat/".to_string()
            ])));
        for allowed_uri in ["/grpc.Chat", "/grpc.Chat/Call"] {
            let resp =
                send_chunked_grpc_header(trailing_layer.clone().layer(make_inner()), allowed_uri)
                    .await?;
            assert_eq!(resp.status(), StatusCode::OK);
        }
        let resp_trailing_evil = send_chunked_grpc_header(
            trailing_layer.layer(make_inner()),
            "/grpc.ChatEvil/Call",
        )
        .await?;
        assert_eq!(resp_trailing_evil.status(), StatusCode::PAYLOAD_TOO_LARGE);

        // 4. Root prefix ("/") matches any normalized path
        let root_layer = MaxPayloadLayer::new(25, "test_root_prefix")
            .with_grpc_stream_policy(GrpcStreamPolicy::AllowPrefixes(Arc::from(["/".to_string()])));
        let resp_root =
            send_chunked_grpc_header(root_layer.layer(make_inner()), "/any.Service/Call").await?;
        assert_eq!(resp_root.status(), StatusCode::OK);

        Ok(())
    }
}
