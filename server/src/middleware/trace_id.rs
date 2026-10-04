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
    // TraceIdMiddleware only modifies the request, not the response.
    // Therefore, we can directly return the inner future without any wrapping!
    type Future = S::Future;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<SrvBody>) -> Self::Future {
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

        // We avoid Box::pin entirely by simply passing the request down 
        // and returning the inner future as is.
        self.inner.call(req)
    }
}
