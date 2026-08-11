//! # Alt-Svc Header Middleware
//!
//! Injects the [`Alt-Svc`](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Alt-Svc)
//! HTTP header into every response, advertising that this server also supports
//! **HTTP/3** on the same port. Browsers that see this header may upgrade
//! future requests to HTTP/3 over QUIC automatically.
//!
//! The header is pre-formatted once at construction time and then cheaply
//! cloned (via `Bytes`/`Arc` backing) per response.

use hyper::header::{ALT_SVC, HeaderValue};
use hyper::{Request, Response};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tower::{Layer, Service};

/// Layer to apply the `Alt-Svc` header to all responses.
///
/// The `Alt-Svc` (Alternative Services) header allows a server to indicate that
/// its resources can be accessed at a different network location or using a
/// different protocol (e.g., HTTP/3).
#[derive(Clone)]
pub struct AltSvcLayer {
    /// The pre-formatted header value to be served.
    header_value: HeaderValue,
}

impl AltSvcLayer {
    /// Creates a new `AltSvcLayer` that advertises HTTP/3 on the specified port.
    ///
    /// # Arguments
    ///
    /// * `port` - The port number where HTTP/3 is available.
    ///
    /// # Internal Details
    ///
    /// This constructs a header value like `h3=":443"; ma=86400`.
    /// - `h3`: Indicates HTTP/3 support.
    /// - `ma`: Max-age in seconds (86400 seconds = 24 hours), telling the client
    ///         how long to cache this alternative service association.
    pub fn new(port: u16) -> Self {
        tracing::trace!("AltSvcLayer::new(port: {})", port);
        // Construct the Alt-Svc header value.
        // "h3" advertises HTTP/3 support on the given port.
        // "ma" (max-age) indicates how long the client should remember this advertisement (86400s = 24h).
        let val = format!("h3=\":{}\" ; ma=86400", port);

        Self {
            header_value: HeaderValue::from_str(&val)
                .expect("Failed to create valid Alt-Svc header value"),
        }
    }
}

impl<S> Layer<S> for AltSvcLayer {
    type Service = AltSvcService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        AltSvcService {
            inner,
            header_value: self.header_value.clone(),
        }
    }
}

/// Service that wraps an inner service and injects the `Alt-Svc` header into its responses.
///
/// This service is generic over the inner service `S` and its request/response
/// body types, making it composable with any position in the middleware stack.
#[derive(Clone)]
pub struct AltSvcService<S> {
    /// The next service in the middleware chain.
    inner: S,
    /// The pre-formatted `Alt-Svc` header value to inject.
    header_value: HeaderValue,
}

impl<S, ReqBody, ResBody> Service<Request<ReqBody>> for AltSvcService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ResBody>>,
    S::Future: Send + 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    // We box the future because we need to await the response to modify its headers,
    // and we want to keep the type signature clean (and `S::Future` might not be `Unpin`).
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    /// Delegates back-pressure to the inner service.
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    /// Forwards the request to the inner service, then injects the `Alt-Svc`
    /// header into the response.
    ///
    /// This informs the client that they can upgrade to HTTP/3 for future
    /// requests to this origin.
    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        // Clone the header value to move it into the future.
        // Performance Note: `HeaderValue` is backed by `Bytes` (Arc-like), so cloning is cheap (O(1)).
        let val = self.header_value.clone();
        // Call the inner service to get the pending future.
        let fut = self.inner.call(req);

        Box::pin(async move {
            // Await the response from the inner service.
            let mut response = fut.await?;

            // Inject the `Alt-Svc` header into the response headers.
            // This informs the client that they can upgrade to HTTP/3 for future requests.
            response.headers_mut().insert(ALT_SVC, val);

            Ok(response)
        })
    }
}
