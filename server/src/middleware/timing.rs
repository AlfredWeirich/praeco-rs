//! # Request Timing Middleware
//!
//! Measures the wall-clock duration of each request and logs it via
//! [`tracing`]. Useful for identifying slow endpoints and tracking latency
//! trends across the service stack.

// === Standard Library ===
use std::{
    fmt::Debug,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    time::Instant,
};

// === External Crates ===
use hyper::{Request, Response};
use tower::{Layer, Service};

// === Internal Modules ===
use crate::ServiceRespBody;

/// A Tower [`Layer`] that wraps a service with request-duration measurement.
///
/// When applied, every request is timed from the moment [`Service::call`]
/// is invoked until the inner future resolves. The elapsed time is logged
/// at `INFO` level, tagged with the `server_name`.
#[derive(Clone)]
pub struct TimingLayer {
    /// Identifier used to tag all timing log lines, making it easy to
    /// correlate measurements with a specific server instance.
    server_name: &'static str,
}

impl TimingLayer {
    /// Creates a new `TimingLayer`.
    ///
    /// # Arguments
    ///
    /// * `server_name` – A `'static` label included in every log line
    ///   (e.g. `"api-server"`).
    pub fn new(server_name: &'static str) -> Self {
        Self { server_name }
    }
}

impl<S> Layer<S> for TimingLayer {
    type Service = TimingMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TimingMiddleware {
            inner,
            server_name: self.server_name,
        }
    }
}

/// Middleware service that records and logs the duration of each request.
///
/// The timer starts when [`Service::call`] is invoked and stops once the
/// inner service's future resolves. This means the measurement covers the
/// full downstream processing time, including all inner middleware layers
/// and the base service.
#[derive(Clone)]
pub struct TimingMiddleware<S> {
    /// The next service in the middleware chain.
    inner: S,
    /// Server name label for log output.
    server_name: &'static str,
}

// impl<S> TimingMiddleware<S> {
//     pub fn get_s<ReqBody>(self) -> impl Service<Request<ReqBody>, Response = Response<ServiceRespBody>>+ Clone + Send + 'static
//     where
//         S: Service<Request<ReqBody>, Response = Response<ServiceRespBody>> + Clone + Send + 'static,
//         S::Future: Send + 'static,
//         S::Error: Debug + Send + 'static,
//         ReqBody: Send + 'static,
//     {
//         self
//     }
// }

impl<S, ReqBody> Service<Request<ReqBody>> for TimingMiddleware<S>
where
    S: Service<Request<ReqBody>, Response = Response<ServiceRespBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Debug + Send + 'static,
    ReqBody: Send + 'static,
{
    type Response = Response<ServiceRespBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    /// Delegates back-pressure to the wrapped inner service.
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    /// Starts a high-resolution timer, forwards the request to the inner
    /// service, and logs the elapsed time once the response is ready.
    ///
    /// The log line uses `INFO` level and includes the server name and
    /// the duration formatted to two decimal places (e.g. `"42.17ms"`).
    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let server_name = self.server_name;
        let start = Instant::now();

        let fut = self.inner.call(req);

        Box::pin(async move {
            let result = fut.await;
            let duration = start.elapsed();
            tracing::info!("{}: == Took {:.2?}", server_name, duration);
            result
        })
    }
}
