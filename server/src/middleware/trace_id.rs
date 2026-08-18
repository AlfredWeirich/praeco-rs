use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

use hyper::{Request, Response};
use tower::{Layer, Service};
use uuid::Uuid;

use crate::{SrvBody, ServiceRespBody};

#[derive(Clone, Default)]
pub struct TraceIdLayer;

impl TraceIdLayer {
    pub fn new() -> Self {
        TraceIdLayer
    }
}

impl<S> Layer<S> for TraceIdLayer {
    type Service = TraceIdMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        TraceIdMiddleware { inner }
    }
}

#[derive(Clone)]
pub struct TraceIdMiddleware<S> {
    inner: S,
}

impl<S> Service<Request<SrvBody>> for TraceIdMiddleware<S>
where
    S: Service<Request<SrvBody>, Response = Response<ServiceRespBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
{
    type Response = Response<ServiceRespBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<SrvBody>) -> Self::Future {
        // Clone the inner service for 'static lifetime in the Future
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);

        // Extract or generate trace ID
        let trace_id = req
            .headers()
            .get("traceparent")
            .and_then(|h| h.to_str().ok())
            .map(|s| s.to_string())
            .or_else(|| {
                req.headers()
                    .get("x-trace-id")
                    .and_then(|h| h.to_str().ok())
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| {
                // Generate new trace ID matching W3C traceparent format: 00-{trace-id}-{span-id}-01
                let trace = Uuid::new_v4().simple().to_string();
                let span = &Uuid::new_v4().simple().to_string()[0..16];
                format!("00-{}-{}-01", trace, span)
            });

        // Store in extensions for downstream middleware (e.g., Logger, gRPC transcoding)
        req.extensions_mut().insert(trace_id.clone());

        // Inject into request headers (idempotent)
        if !req.headers().contains_key("traceparent") {
            if let Ok(value) = hyper::header::HeaderValue::from_str(&trace_id) {
                req.headers_mut().insert("traceparent", value);
            }
        }

        Box::pin(async move {
            inner.call(req).await
        })
    }
}
