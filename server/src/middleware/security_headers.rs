use hyper::header::{
    CONTENT_SECURITY_POLICY, HeaderValue, STRICT_TRANSPORT_SECURITY, X_CONTENT_TYPE_OPTIONS,
};
use hyper::{Request, Response};
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
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

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for SecurityHeadersMiddleware<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    ReqBody: Send + 'static,
    ResBody: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let clone = self.inner.clone();
        let mut inner = std::mem::replace(&mut self.inner, clone);
        let config = self.config.clone();

        Box::pin(async move {
            let mut response = inner.call(req).await?;
            let headers = response.headers_mut();

            if let Ok(csp) = HeaderValue::from_str(&config.content_security_policy) {
                headers.insert(CONTENT_SECURITY_POLICY, csp);
            }
            if let Ok(hsts) = HeaderValue::from_str(&config.strict_transport_security) {
                headers.insert(STRICT_TRANSPORT_SECURITY, hsts);
            }
            if let Ok(nosniff) = HeaderValue::from_str(&config.x_content_type_options) {
                headers.insert(X_CONTENT_TYPE_OPTIONS, nosniff);
            }
            if let Ok(xframe) = HeaderValue::from_str(&config.x_frame_options) {
                headers.insert(
                    hyper::header::HeaderName::from_static("x-frame-options"),
                    xframe,
                );
            }

            Ok(response)
        })
    }
}
