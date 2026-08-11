//! # Request Counter Middleware
//!
//! Maintains a global [`AtomicU64`](std::sync::atomic::AtomicU64) counter that
//! is incremented for every completed request. A log line is emitted at `INFO`
//! level every **500** requests (and the very first request) to keep the output manageable
//! while still providing periodic throughput feedback.
//!
//! ## Design Details
//!
//! * The counter is wrapped in an [`Arc`] so that all clones of the service
//!   share the same counter — useful when Hyper spawns one service clone per
//!   connection.
//! * Instead of boxing the future, this middleware uses a custom
//!   [`CountingFuture`] with `pin_project` to avoid a heap allocation per
//!   request.

// === Standard Library ===
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    sync::atomic::{AtomicU64, Ordering},
    task::{Context, Poll},
};

// === External Crates ===
use hyper::{Request, Response};
use pin_project::pin_project;
use tower::{Layer, Service};

/// A Tower Layer that wraps services to count the number of handled requests,
/// with a server name label for all tracing.
///
/// This layer maintains a global atomic counter (`Arc<AtomicU64>`) that is shared
/// across all services created by this layer. Each time a request is processed
/// by a service, this counter is incremented. This allows for tracking the total
/// number of requests handled by a group of services (e.g., all services for a
/// particular server).
//#[derive(Clone)]
pub struct CountingLayer {
    /// Server name label included in every log line.
    server_name: &'static str,
    /// The shared atomic counter. Initialised to `0` in [`CountingLayer::new`].
    counter: Arc<AtomicU64>,
}

impl CountingLayer {
    /// Create a new `CountingLayer` with a name for this server/service.
    ///
    /// The `counter` is an `Arc<AtomicU64>` that will be shared across all
    /// services created by this layer. It is initialized to `0`.
    pub fn new(server_name: &'static str) -> Self {
        Self {
            server_name,
            counter: Arc::new(AtomicU64::new(0)),
        }
    }
}

impl<S> Layer<S> for CountingLayer {
    type Service = CountingService<S>;
    fn layer(&self, inner: S) -> Self::Service {
        CountingService::new(inner, self.counter.clone(), self.server_name)
    }
}

/// Middleware service that wraps another service and counts handled requests,
/// tagging all traces with a server name.
#[derive(Clone)]
pub struct CountingService<S> {
    /// The inner (downstream) service.
    inner: S,
    /// Shared atomic counter across all service clones.
    count: Arc<AtomicU64>,
    /// Server name label for log output.
    server_name: &'static str,
}

impl<S> CountingService<S> {
    /// Create a new CountingService wrapping `inner` with `server_name`.
    pub fn new(inner: S, counter: Arc<AtomicU64>, server_name: &'static str) -> Self {
        Self {
            inner,
            count: counter,
            server_name,
        }
    }
}

/// A custom future that awaits the inner service's future and increments the
/// request counter upon completion.
///
/// Using a concrete future type (via `pin_project`) avoids the overhead of
/// `Box::pin` for every request.
#[pin_project]
pub struct CountingFuture<F, ResBody, Error>
where
    F: Future<Output = Result<Response<ResBody>, Error>>,
{
    /// The pinned inner future from the wrapped service.
    #[pin]
    inner_fut: F,
    /// Shared counter; incremented when the inner future resolves.
    count: Arc<AtomicU64>,
    /// Server name for the periodic log line.
    server_name: &'static str,
}

impl<F, ResBody, Error> Future for CountingFuture<F, ResBody, Error>
where
    F: Future<Output = Result<Response<ResBody>, Error>>,
{
    type Output = Result<Response<ResBody>, Error>;

    /// Polls the inner future; when it is ready, atomically increments the
    /// counter and emits a log line every 500 requests.
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        match this.inner_fut.poll(cx) {
            Poll::Ready(result) => {
                // `fetch_add` returns the *previous* value; add 1 to get the new total.
                let old = this.count.fetch_add(1, Ordering::Relaxed) + 1;
                // Log the first request, then every 500 requests to save CPU/IO
                if old == 1 || old.is_multiple_of(500) {
                    tracing::info!("{}: Processed {} requests", this.server_name, old);
                }
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for CountingService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    S::Future: Future<Output = Result<Response<ResBody>, S::Error>> + Send + 'static,
{
    type Response = Response<ResBody>;
    type Error = S::Error;
    /// Uses the concrete [`CountingFuture`] instead of a boxed future.
    type Future = CountingFuture<S::Future, ResBody, S::Error>;

    /// Delegates back-pressure to the inner service.
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    /// Forwards the request to the inner service and wraps the resulting
    /// future in a [`CountingFuture`] that increments the counter on
    /// completion.
    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let inner_fut = self.inner.call(req);
        CountingFuture {
            inner_fut,
            count: Arc::clone(&self.count),
            server_name: self.server_name,
        }
    }
}
