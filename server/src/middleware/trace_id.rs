//! # W3C Trace-ID & OpenTelemetry Context Propagation Middleware
//!
//! This module implements the [`TraceIdLayer`] and [`TraceIdMiddleware`] Tower components,
//! which ensure every incoming HTTP request carries a unique, W3C-compliant `traceparent`
//! identifier and that the active [`tracing::Span`] is linked to the incoming distributed
//! trace context.
//!
//! ## Processing Pipeline
//!
//! 1. **Header Extraction / Fallback Generation**:
//!    - Checks for an incoming W3C `traceparent` header (`00-<32-hex-trace-id>-<16-hex-span-id>-<2-hex-flags>`).
//!    - Falls back to a legacy `x-trace-id` header if `traceparent` is absent.
//!    - If neither header is present, generates a new W3C-compliant `traceparent` string
//!      using cryptographically random UUID v4 values (`00-{trace_id}-{span_id}-01`).
//! 2. **Extension & Header Injection**:
//!    - Inserts the resolved trace ID `String` into [`Request::extensions_mut`] so downstream
//!      layers (such as logging, auditing, or error handlers) can access it without header lookups.
//!    - Ensures the `traceparent` header is present on the [`Request`] itself so downstream
//!      proxy handlers always have a valid header even when OpenTelemetry export is disabled.
//! 3. **OpenTelemetry Parent Context Attachment**:
//!    - Extracts the W3C `TraceContext` from the request headers via the global
//!      [`TextMapPropagator`](opentelemetry::propagation::TextMapPropagator) and
//!      [`HeaderExtractor`](opentelemetry_http::HeaderExtractor).
//!    - Creates a dedicated [`tracing::Span`] and attaches the extracted context as its parent
//!      via [`OpenTelemetrySpanExt::set_parent`](tracing_opentelemetry::OpenTelemetrySpanExt::set_parent)
//!      **before** entering the span (as required by `tracing-opentelemetry`, which rejects
//!      `set_parent` with `SetParentError::AlreadyStarted` once a span has been entered).
//!    - Instruments the inner service future with this span (`Instrumented<S::Future>`, zero
//!      heap boxing overhead) so that all synchronous and asynchronous downstream work
//!      (including [`HeaderInjector`](opentelemetry_http::HeaderInjector) in `http_proxy`,
//!      `grpc_passthrough`, and `grpc_web`) preserves the exact 32-hex-character `trace-id`.

use std::task::{Context, Poll};

use hyper::{Request, Response};
use opentelemetry::trace::TraceContextExt;
use opentelemetry_http::HeaderExtractor;
use tower::{Layer, Service};
use tracing::{Instrument, info_span};
use tracing_opentelemetry::OpenTelemetrySpanExt;
use uuid::Uuid;

use crate::{ServiceRespBody, SrvBody};

/// Tower [`Layer`] factory that wraps an inner service with [`TraceIdMiddleware`].
///
/// When enabled in `[Server.layers]`, this layer must be placed first (outermost)
/// in the declarative layer list so that all subsequent middleware layers and terminal
/// services operate within the same trace context.
#[derive(Clone, Default)]
pub struct TraceIdLayer;

impl TraceIdLayer {
    /// Creates a new [`TraceIdLayer`].
    pub fn new() -> Self {
        TraceIdLayer
    }
}

impl<S> Layer<S> for TraceIdLayer {
    type Service = TraceIdMiddleware<S>;

    /// Wraps the inner service `S` with [`TraceIdMiddleware`].
    fn layer(&self, inner: S) -> Self::Service {
        TraceIdMiddleware { inner }
    }
}

/// Middleware [`Service`] that extracts or generates a W3C `traceparent` header
/// and instruments the request pipeline with an OpenTelemetry-linked [`tracing::Span`].
#[derive(Clone)]
pub struct TraceIdMiddleware<S> {
    /// The wrapped inner Tower service.
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
    // `Instrumented<S::Future>` wraps the inner future inline without heap allocation (`Box::pin`),
    // ensuring the OpenTelemetry-parented span stays active across all async `.await` points.
    type Future = tracing::instrument::Instrumented<S::Future>;

    /// Checks whether the inner service is ready to accept a request.
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    /// Extracts or synthesizes the W3C `traceparent` header, stores it in request
    /// extensions, attaches the extracted OpenTelemetry context to a fresh [`tracing::Span`]
    /// prior to first entry, and instruments the inner service future with that span.
    fn call(&mut self, mut req: Request<SrvBody>) -> Self::Future {
        // Inspect the active OpenTelemetry span context (e.g. from the outer `TraceLayer`
        // `"request"` span in `server.rs`) so that when no incoming `traceparent` header is
        // present, we reuse the outer span's Trace ID instead of splitting the trace.
        let current_otel_cx = tracing::Span::current().context();
        let current_sc = current_otel_cx.span().span_context().clone();

        // 1. Extract an existing trace identifier (`traceparent` or `x-trace-id`),
        //    reuse the active OpenTelemetry root span context if valid, or synthesize
        //    a fresh W3C TraceContext `traceparent` header via UUID v4 fallback.
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
                if current_sc.is_valid() {
                    format!(
                        "00-{}-{}-{:02x}",
                        current_sc.trace_id(),
                        current_sc.span_id(),
                        current_sc.trace_flags().to_u8()
                    )
                } else {
                    // Generate new trace ID matching W3C traceparent format: 00-{trace-id}-{span-id}-01
                    let trace = Uuid::new_v4().simple().to_string();
                    let span = &Uuid::new_v4().simple().to_string()[0..16];
                    format!("00-{}-{}-01", trace, span)
                }
            });

        // 2. Store in request extensions for downstream middleware (e.g., Logger, auditing).
        req.extensions_mut().insert(trace_id.clone());

        // 3. Inject `traceparent` and `x-trace-id` into request headers if not already present
        //    so that both the OpenTelemetry HeaderExtractor below and non-OTel handlers see them.
        if !req.headers().contains_key("traceparent") {
            if let Ok(value) = hyper::header::HeaderValue::from_str(&trace_id) {
                req.headers_mut().insert("traceparent", value);
            }
        }
        if !req.headers().contains_key("x-trace-id") {
            if let Ok(value) = hyper::header::HeaderValue::from_str(&trace_id) {
                req.headers_mut().insert("x-trace-id", value);
            }
        }

        // 4. Create a span for this request's trace context and attach the extracted W3C
        //    OpenTelemetry context BEFORE entering the span (`tracing-opentelemetry` requires
        //    `set_parent` to be called prior to the first `on_enter` event).
        //    If the outer `TraceLayer` span already shares the same Trace ID, `trace_span`
        //    naturally inherits it as a child span without overriding its parent Span ID.
        let trace_span = info_span!("trace_id", traceparent = %trace_id);
        opentelemetry::global::get_text_map_propagator(|propagator| {
            let parent_cx = propagator.extract(&HeaderExtractor(req.headers()));
            let parent_sc = parent_cx.span().span_context().clone();
            if parent_sc.is_valid()
                && (!current_sc.is_valid() || current_sc.trace_id() != parent_sc.trace_id())
            {
                let _ = trace_span.set_parent(parent_cx);
            }
        });

        // 5. Enter the span during synchronous `call` construction and instrument the returned
        //    future so `Span::current()` carries the extracted Trace ID across all async polls.
        let fut = {
            let _guard = trace_span.enter();
            self.inner.call(req)
        };
        fut.instrument(trace_span)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::{BodyExt, Empty};
    use hyper::StatusCode;
    use tower::ServiceExt;

    fn empty_body() -> SrvBody {
        Empty::<Bytes>::new().map_err(crate::SrvError::from).boxed()
    }

    #[tokio::test]
    async fn test_trace_id_preserves_existing_traceparent() {
        let incoming_tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let svc = TraceIdLayer::new().layer(tower::service_fn(
            move |req: Request<SrvBody>| async move {
                let ext_tp = req.extensions().get::<String>().cloned().unwrap();
                let hdr_tp = req
                    .headers()
                    .get("traceparent")
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string();
                assert_eq!(ext_tp, incoming_tp);
                assert_eq!(hdr_tp, incoming_tp);
                Ok::<_, crate::SrvError>(
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(empty_body())
                        .unwrap(),
                )
            },
        ));

        let req = Request::builder()
            .uri("/test")
            .header("traceparent", incoming_tp)
            .body(empty_body())
            .unwrap();

        let res = svc.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_trace_id_generates_valid_w3c_traceparent_when_missing() {
        let svc = TraceIdLayer::new().layer(tower::service_fn(|req: Request<SrvBody>| async move {
            let ext_tp = req.extensions().get::<String>().cloned().unwrap();
            let hdr_tp = req
                .headers()
                .get("traceparent")
                .unwrap()
                .to_str()
                .unwrap()
                .to_string();
            assert_eq!(ext_tp, hdr_tp);
            let parts: Vec<&str> = hdr_tp.split('-').collect();
            assert_eq!(parts.len(), 4, "W3C traceparent must have 4 dash-separated parts");
            assert_eq!(parts[0], "00");
            assert_eq!(parts[1].len(), 32);
            assert_eq!(parts[2].len(), 16);
            assert_eq!(parts[3], "01");
            Ok::<_, crate::SrvError>(
                Response::builder()
                    .status(StatusCode::OK)
                    .body(empty_body())
                    .unwrap(),
            )
        }));

        let req = Request::builder().uri("/test").body(empty_body()).unwrap();
        let res = svc.oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_trace_id_sets_opentelemetry_parent_context_on_current_span() {
        use opentelemetry::trace::TracerProvider as _;
        use tracing_subscriber::layer::SubscriberExt;

        opentelemetry::global::set_text_map_propagator(
            opentelemetry_sdk::propagation::TraceContextPropagator::new(),
        );
        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder().build();
        let tracer = provider.tracer("test-trace-id");
        let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);
        let subscriber = tracing_subscriber::Registry::default().with(otel_layer);

        let incoming_trace_id = "4bf92f3577b34da6a3ce929d0e0e4736";
        let incoming_tp = format!("00-{}-00f067aa0ba902b7-01", incoming_trace_id);

        let req = Request::builder()
            .uri("/test")
            .header("traceparent", incoming_tp)
            .body(empty_body())
            .unwrap();

        let injected_headers = std::sync::Arc::new(std::sync::Mutex::new(hyper::HeaderMap::new()));
        let injected_clone = injected_headers.clone();

        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("request");
            let _enter = span.enter();

            let mut svc = TraceIdLayer::new().layer(tower::service_fn(
                move |inner_req: Request<SrvBody>| {
                    // Simulate downstream HeaderInjector inside the inner service (as used in
                    // http_proxy, grpc_passthrough, and grpc_web)
                    opentelemetry::global::get_text_map_propagator(|propagator| {
                        propagator.inject_context(
                            &tracing::Span::current().context(),
                            &mut opentelemetry_http::HeaderInjector(
                                &mut injected_clone.lock().unwrap(),
                            ),
                        );
                    });
                    async move {
                        Ok::<_, crate::SrvError>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .body(inner_req.into_body())
                                .unwrap(),
                        )
                    }
                },
            ));

            let _fut = svc.call(req);
        });

        let headers_guard = injected_headers.lock().unwrap();
        let propagated_tp = headers_guard
            .get("traceparent")
            .expect("HeaderInjector must inject traceparent")
            .to_str()
            .unwrap();

        assert!(
            propagated_tp.starts_with(&format!("00-{}-", incoming_trace_id)),
            "Propagated traceparent '{}' must preserve incoming trace-id '{}'",
            propagated_tp,
            incoming_trace_id
        );
    }
}
