use hyper::header::{
    CONTENT_SECURITY_POLICY, HeaderName, HeaderValue, REFERRER_POLICY, STRICT_TRANSPORT_SECURITY,
    X_CONTENT_TYPE_OPTIONS, X_FRAME_OPTIONS,
};
use hyper::{Request, Response};
use pin_project::pin_project;
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tower::{Layer, Service};

use crate::configuration::SecurityHeadersConfig;

/// Pre-parsed [`HeaderValue`]s built once at [`SecurityHeadersLayer::new`] time so
/// the request hot path performs a single `Arc::clone` instead of cloning 5 `String`s
/// and re-parsing 5 headers on every response (`P2-04`).
#[derive(Debug)]
struct PrecomputedSecurityHeaders {
    csp: Option<HeaderValue>,
    hsts: Option<HeaderValue>,
    x_content_type_options: Option<HeaderValue>,
    x_frame_options: Option<HeaderValue>,
    referrer_policy: Option<HeaderValue>,
}

fn parse_header_value(name: &'static str, raw: &str) -> Option<HeaderValue> {
    match HeaderValue::from_str(raw) {
        Ok(val) => Some(val),
        Err(e) => {
            tracing::warn!(
                header = name,
                error = %e,
                "Ignoring invalid SecurityHeaders value"
            );
            None
        }
    }
}

impl PrecomputedSecurityHeaders {
    fn from_config(config: &SecurityHeadersConfig) -> Self {
        Self {
            csp: parse_header_value("content-security-policy", &config.content_security_policy),
            hsts: parse_header_value(
                "strict-transport-security",
                &config.strict_transport_security,
            ),
            x_content_type_options: parse_header_value(
                "x-content-type-options",
                &config.x_content_type_options,
            ),
            x_frame_options: parse_header_value("x-frame-options", &config.x_frame_options),
            referrer_policy: parse_header_value("referrer-policy", &config.referrer_policy),
        }
    }

    fn apply(&self, headers: &mut hyper::HeaderMap) {
        let pairs: [(HeaderName, &Option<HeaderValue>); 5] = [
            (CONTENT_SECURITY_POLICY, &self.csp),
            (STRICT_TRANSPORT_SECURITY, &self.hsts),
            (X_CONTENT_TYPE_OPTIONS, &self.x_content_type_options),
            (X_FRAME_OPTIONS, &self.x_frame_options),
            (REFERRER_POLICY, &self.referrer_policy),
        ];
        for (name, val) in pairs {
            if let Some(hv) = val {
                headers.insert(name, hv.clone());
            }
        }
    }
}

/// A Tower layer that applies security headers to all responses.
#[derive(Clone)]
pub struct SecurityHeadersLayer {
    headers: Arc<PrecomputedSecurityHeaders>,
}

impl SecurityHeadersLayer {
    /// Creates a new [`SecurityHeadersLayer`], pre-parsing all header values once.
    pub fn new(config: SecurityHeadersConfig) -> Self {
        Self {
            headers: Arc::new(PrecomputedSecurityHeaders::from_config(&config)),
        }
    }
}

impl<S> Layer<S> for SecurityHeadersLayer {
    type Service = SecurityHeadersMiddleware<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SecurityHeadersMiddleware {
            inner,
            headers: Arc::clone(&self.headers),
        }
    }
}

/// The actual Tower middleware service that injects security headers into responses.
#[derive(Clone)]
pub struct SecurityHeadersMiddleware<S> {
    inner: S,
    headers: Arc<PrecomputedSecurityHeaders>,
}

#[pin_project]
pub struct SecurityHeadersFuture<F> {
    #[pin]
    inner: F,
    headers: Arc<PrecomputedSecurityHeaders>,
}

impl<F, B, E> Future for SecurityHeadersFuture<F>
where
    F: Future<Output = Result<Response<B>, E>>,
{
    type Output = Result<Response<B>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let mut response = std::task::ready!(this.inner.poll(cx))?;
        this.headers.apply(response.headers_mut());
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
            headers: Arc::clone(&self.headers),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::Full;
    use tower::{ServiceExt, service_fn};

    #[tokio::test]
    async fn test_security_headers_preparses_and_shares_header_values()
    -> Result<(), Box<dyn std::error::Error>> {
        let cfg = SecurityHeadersConfig {
            content_security_policy: "default-src 'self'".to_string(),
            // Invalid header value (contains newline) must be ignored cleanly at construction
            x_frame_options: "DENY\r\ninjected: 1".to_string(),
            ..Default::default()
        };

        let layer = SecurityHeadersLayer::new(cfg);
        let svc1 = layer.layer(service_fn(|_req: Request<Full<Bytes>>| async {
            Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
        }));
        let svc2 = svc1.clone();
        assert!(Arc::ptr_eq(&svc1.headers, &svc2.headers));

        let resp = svc1
            .oneshot(Request::new(Full::new(Bytes::new())))
            .await?;
        let headers = resp.headers();
        assert_eq!(
            headers
                .get(CONTENT_SECURITY_POLICY)
                .and_then(|v| v.to_str().ok()),
            Some("default-src 'self'")
        );
        assert!(headers.get(STRICT_TRANSPORT_SECURITY).is_some());
        assert!(headers.get(X_CONTENT_TYPE_OPTIONS).is_some());
        assert!(headers.get(REFERRER_POLICY).is_some());
        assert!(
            headers.get(X_FRAME_OPTIONS).is_none(),
            "invalid X-Frame-Options must not be inserted"
        );
        Ok(())
    }
}
