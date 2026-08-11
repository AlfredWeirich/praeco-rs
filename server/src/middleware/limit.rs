//! # Maximum Payload Size Middleware
//!
//! Enforces an upper bound on the size of incoming request bodies using a
//! **two-stage** strategy:
//!
//! 1. **Header check** – If the `Content-Length` header is present and exceeds
//!    the limit, the request is rejected immediately with **413 Payload Too
//!    Large** (no body data is ever read).
//! 2. **Streaming check** – The body is wrapped in a [`LimitedBody`] that
//!    counts bytes as they arrive. If the running total exceeds the limit,
//!    the body emits a [`SrvError`] which Hyper propagates as a connection
//!    error. The service catches this specific error and converts it into a
//!    413 response.
//!
//! The two-stage approach handles both well-behaved clients (that send
//! `Content-Length` accurately) and adversarial / chunked clients (that omit
//! or lie about the content length).

// === Standard Library ===
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

// === External Crates ===
use bytes::Bytes;
use http_body::Body;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode, header::CONTENT_LENGTH};
use pin_project::pin_project;
use tower::{Layer, Service};

// === Internal Modules ===
use crate::{SrvBody, SrvError};

/// A Tower [`Layer`] that wraps a service with payload size enforcement.
#[derive(Clone)]
pub struct MaxPayloadLayer {
    /// Maximum allowed request body size in bytes.
    max_bytes: usize,
    /// Server name label for tracing output.
    server_name: &'static str,
}

impl MaxPayloadLayer {
    /// Creates a new `MaxPayloadLayer`.
    ///
    /// # Arguments
    ///
    /// * `max_bytes`   – The maximum number of body bytes allowed.
    /// * `server_name` – A `'static` label for log/trace output.
    pub fn new(max_bytes: usize, server_name: &'static str) -> Self {
        Self {
            max_bytes,
            server_name,
        }
    }
}

impl<S> Layer<S> for MaxPayloadLayer {
    type Service = MaxPayloadService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        MaxPayloadService {
            inner,
            max_bytes: self.max_bytes,
            server_name: self.server_name,
        }
    }
}

/// Service that enforces the maximum payload size.
///
/// See the [module-level documentation](self) for the two-stage enforcement
/// strategy.
#[derive(Clone)]
pub struct MaxPayloadService<S> {
    /// The inner (downstream) service.
    inner: S,
    /// Maximum allowed request body size in bytes.
    max_bytes: usize,
    /// Server name label for tracing.
    server_name: &'static str,
}

impl<S> Service<Request<SrvBody>> for MaxPayloadService<S>
where
    S: Service<Request<SrvBody>, Response = Response<SrvBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    SrvError: From<<S as tower::Service<hyper::Request<SrvBody>>>::Error>,
{
    type Response = Response<SrvBody>;
    type Error = SrvError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    /// Enforces the payload limit and forwards the request.
    ///
    /// ## Stage 1 – Header Check
    ///
    /// Parses `Content-Length`; if it exceeds `max_bytes`, returns 413
    /// immediately without reading the body.
    ///
    /// ## Stage 2 – Streaming Check
    ///
    /// Wraps the body in [`LimitedBody`]. If the inner service encounters a
    /// "Payload Limit Exceeded" error during streaming, it is caught here and
    /// converted into a 413 response.
    fn call(&mut self, req: Request<SrvBody>) -> Self::Future {
        let max_bytes = self.max_bytes;
        // Since server_name is &'static str, this copy is cheap and 'static-safe.
        let server_name = self.server_name;

        tracing::debug!("{}: Max Payload: {}", server_name, max_bytes);

        // ── Stage 1: Header Check ────────────────────────────────────────
        if let Some(content_length) = req
            .headers()
            .get(CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<usize>().ok())
            && content_length > max_bytes
        {
            let msg = "Payload too large (Header check)";
            tracing::warn!("{}: {}", server_name, msg);
            return Box::pin(async move { Ok(build_413_response(msg)) });
        }

        // ── Stage 2: Wrap body in LimitedBody for streaming enforcement ──
        let (parts, body) = req.into_parts();
        let limited_body = LimitedBody {
            inner: body,
            max_bytes,
            current_bytes: 0,
        };

        let req = Request::from_parts(parts, limited_body.boxed());
        let fut = self.inner.call(req);

        Box::pin(async move {
            let result = fut.await;
            tracing::debug!("{}: End Max Payload: {}", server_name, max_bytes);

            match result {
                Ok(resp) => Ok(resp),
                Err(e) => {
                    let srv_err: SrvError = e.into();

                    // Check if the error was caused by our LimitedBody.
                    if srv_err.to_string().contains("Payload Limit Exceeded") {
                        let msg = "Payload too large (Streaming check)";
                        tracing::warn!("{}: {}", server_name, msg);
                        Ok(build_413_response(msg))
                    } else {
                        Err(srv_err)
                    }
                }
            }
        })
    }
}

// ============================================================================
//  LIMITED BODY — Streaming Byte Counter
// ============================================================================

/// A body wrapper that counts the bytes passing through and aborts with an
/// error when the configured limit is exceeded.
///
/// Unlike the decompression [`LimitedReader`](super::compression), this
/// operates at the `http_body::Body` level (frame-by-frame) rather than the
/// `AsyncRead` level.
#[pin_project]
pub struct LimitedBody<B> {
    /// The original request body.
    #[pin]
    inner: B,
    /// Maximum number of bytes allowed.
    max_bytes: usize,
    /// Running total of bytes seen so far.
    current_bytes: usize,
}

impl<B> Body for LimitedBody<B>
where
    B: Body<Data = Bytes, Error = SrvError>,
{
    type Data = Bytes;
    type Error = SrvError;

    /// Polls the inner body for the next frame and enforces the byte limit.
    ///
    /// If the cumulative data bytes exceed `max_bytes`, returns a
    /// `SrvError::Other("Payload Limit Exceeded: …")` which the outer
    /// service catches and maps to a 413 response.
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let this = self.project();

        match this.inner.poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    *this.current_bytes += data.len();

                    if *this.current_bytes > *this.max_bytes {
                        // Trigger an error that will be caught by MaxPayloadService.
                        return Poll::Ready(Some(Err(SrvError::Other(format!(
                            "Payload Limit Exceeded: {} > {}",
                            this.current_bytes, this.max_bytes
                        )))));
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            // Network errors or end-of-stream (None) are passed through unchanged.
            res => res,
        }
    }
}

/// Builds a **413 Payload Too Large** response with a short message body.
fn build_413_response(msg: &'static str) -> Response<SrvBody> {
    let body = Full::new(Bytes::from(msg))
        .map_err(|e| match e {}) // Infallible
        .boxed();

    Response::builder()
        .status(StatusCode::PAYLOAD_TOO_LARGE)
        .body(body)
        .unwrap()
}
