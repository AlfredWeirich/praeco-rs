use hyper::header::{
    CONTENT_SECURITY_POLICY, HeaderValue, STRICT_TRANSPORT_SECURITY, X_CONTENT_TYPE_OPTIONS,
};
use hyper::{Request, Response};
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use pin_project::pin_project;
use tower::{Layer, Service};

use crate::configuration::SecurityHeadersConfig;

/// A Tower layer that applies security headers to all responses.
#[derive(Clone)]
pub struct SecurityHeadersLayer {
    config: SecurityHeadersConfig,
}

impl SecurityHeadersLayer {
    pub fn new(config: SecurityHeadersConfig) -> Self {
        Self { config }
    }
}

impl<S> Layer<S> for SecurityHeadersLayer {
    type Service = SecurityHeadersMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SecurityHeadersMiddleware {
            inner,
            config: self.config.clone(),
        }
    }
}

/// The actual Tower middleware service that injects security headers into responses.
#[derive(Clone)]
pub struct SecurityHeadersMiddleware<S> {
    inner: S,
    config: SecurityHeadersConfig,
}

#[pin_project]
pub struct SecurityHeadersFuture<F> {
    #[pin]
    inner: F,
    config: SecurityHeadersConfig,
}

impl<F, B, E> Future for SecurityHeadersFuture<F>
where
    F: Future<Output = Result<Response<B>, E>>,
{
    type Output = Result<Response<B>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let mut response = std::task::ready!(this.inner.poll(cx))?;

        let headers = response.headers_mut();

        if let Ok(csp) = HeaderValue::from_str(&this.config.content_security_policy) {
            headers.insert(CONTENT_SECURITY_POLICY, csp);
        }
        if let Ok(hsts) = HeaderValue::from_str(&this.config.strict_transport_security) {
            headers.insert(STRICT_TRANSPORT_SECURITY, hsts);
        }
        if let Ok(nosniff) = HeaderValue::from_str(&this.config.x_content_type_options) {
            headers.insert(X_CONTENT_TYPE_OPTIONS, nosniff);
        }
        if let Ok(xframe) = HeaderValue::from_str(&this.config.x_frame_options) {
            headers.insert(
                hyper::header::HeaderName::from_static("x-frame-options"),
                xframe,
            );
        }

        Poll::Ready(Ok(response))
    }
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for SecurityHeadersMiddleware<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = SecurityHeadersFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        // Evaluate the inner future directly to avoid cloning `self.inner`
        let fut = self.inner.call(req);
        SecurityHeadersFuture {
            inner: fut,
            config: self.config.clone(),
        }
    }
}
