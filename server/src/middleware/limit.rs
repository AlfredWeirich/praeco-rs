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
    sync::Arc,
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
#[derive(Clone)]
pub struct MaxPayloadService<S> {
    inner: S,
    max_bytes: usize,
    server_name: &'static str,
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
                let res = response.take().expect("MaxPayloadFuture polled after completion");
                Poll::Ready(Ok(res))
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
                        if srv_err.to_string().contains("Payload Limit Exceeded") {
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

        // Stage 1: Content-Length header fast path
        if let Some(content_length_str) = req.headers().get(CONTENT_LENGTH) {
            if let Ok(content_length) = content_length_str.to_str().unwrap_or("").parse::<usize>() {
                if content_length > max_bytes {
                    let msg = "Payload too large (Header check)";
                    tracing::warn!("{}: {}", server_name, msg);
                    return MaxPayloadFuture::HeaderRejected {
                        response: Some(build_413_response(msg)),
                    };
                }
            }
        }

        // Stage 2: Streaming byte counter
        let (parts, body) = req.into_parts();
        let limited_body = LimitedBody {
            inner: body,
            max_bytes,
            current_bytes: 0,
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

/// A body wrapper that counts the bytes passing through and aborts with an
/// error when the configured limit is exceeded.
#[pin_project]
pub struct LimitedBody<B> {
    #[pin]
    inner: B,
    max_bytes: usize,
    current_bytes: usize,
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
                    *this.current_bytes += data.len();

                    if *this.current_bytes > *this.max_bytes {
                        return Poll::Ready(Some(Err(SrvError::Other(format!(
                            "Payload Limit Exceeded: {} > {}",
                            this.current_bytes, this.max_bytes
                        )))));
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

    Response::builder()
        .status(StatusCode::PAYLOAD_TOO_LARGE)
        .body(body)
        .unwrap()
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

/// A Tower [`Layer`] that limits concurrent in-flight requests.
#[derive(Clone)]
pub struct ConcurrencyLimitLayer {
    semaphore: Arc<tokio::sync::Semaphore>,
    server_name: &'static str,
    load_shed: bool,
    queue_timeout: Option<Duration>,
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
        Self {
            semaphore: Arc::new(tokio::sync::Semaphore::new(max_requests)),
            server_name,
            load_shed,
            queue_timeout,
        }
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
                    tracing::warn!("{}: Concurrency limit reached (load-shedding)", self.server_name);
                    ConcurrencyLimitFuture::Immediate {
                        response: Some(build_503_response()),
                    }
                }
            }
        } else if let Some(timeout_dur) = self.queue_timeout {
            let sem = self.semaphore.clone();
            let acquire_task = Box::pin(async move {
                match tokio::time::timeout(timeout_dur, sem.acquire_owned()).await {
                    Ok(Ok(p)) => Ok(p),
                    _ => Err(()),
                }
            });
            ConcurrencyLimitFuture::Waiting {
                acquire_task,
                req: Some(req),
                inner: self.inner.clone(),
            }
        } else {
            let sem = self.semaphore.clone();
            let acquire_task = Box::pin(async move {
                sem.acquire_owned().await.map_err(|_| ())
            });
            ConcurrencyLimitFuture::Waiting {
                acquire_task,
                req: Some(req),
                inner: self.inner.clone(),
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
                    let res = response.take().expect("polled after completion");
                    return Poll::Ready(Ok(res));
                }
                ConcurrencyLimitFutureProj::Waiting { acquire_task, req, inner } => {
                    match acquire_task.poll(cx) {
                        Poll::Ready(Ok(permit)) => {
                            let request = req.take().expect("polled after completion");
                            let fut = inner.call(request);
                            self.set(ConcurrencyLimitFuture::Processing {
                                inner: fut,
                                permit: Some(permit),
                            });
                            continue;
                        }
                        Poll::Ready(Err(())) => {
                            return Poll::Ready(Ok(build_503_response()));
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
                ConcurrencyLimitFutureProj::Processing { inner, permit } => {
                    match inner.poll(cx) {
                        Poll::Ready(Ok(resp)) => {
                            let p = permit.take().expect("permit missing in Processing");
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

    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header(hyper::header::RETRY_AFTER, "1")
        .body(body)
        .unwrap()
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
}
