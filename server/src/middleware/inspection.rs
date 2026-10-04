//! # Path Inspection Middleware (Allow-List)
//!
//! This middleware acts as a lightweight WAF (Web Application Firewall) by
//! checking every incoming request's `(method, path, query)` triple against a
//! set of compiled regular expressions. If the request does **not** match any
//! allowed pattern, it is rejected immediately with a **403 Forbidden**
//! response, and a warning is logged.
//!
//! ## Performance Notes
//!
//! * On the **happy path** (request allowed), no heap allocations are
//!   performed — the method, path, and query are borrowed as `&str` directly
//!   from the request.
//! * On the **reject path**, strings are only allocated for the warning log
//!   line.
//! * A blocked request never reaches the inner service, saving downstream
//!   compute.

// === Standard Library ===
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

// === External Crates ===
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode};
use pin_project::pin_project;
use tower::{Layer, Service};

// === Internal Modules ===
use crate::{configuration::CompiledAllowedPathes, ServiceRespBody, SrvError};

/// A Tower [`Layer`] that inspects request paths against a set of regex rules.
///
/// If a path does not match any allowed prefix, a 403 Forbidden response is returned.
///
/// The compiled regex set is stored with `'static` lifetime because it is
/// owned by the global configuration and outlives all connections.
#[derive(Clone)]
pub struct InspectionLayer {
    /// Pre-compiled regex rules. Borrowed from the global configuration with
    /// a `'static` lifetime.
    rules: Arc<CompiledAllowedPathes>,
    /// Server name label for logging.
    server_name: &'static str,
}

impl InspectionLayer {
    /// Create a new InspectionLayer with rules and a server name.
    pub fn new(rules: Arc<CompiledAllowedPathes>, server_name: &'static str) -> Self {
        Self { rules, server_name }
    }
}

impl<S> Layer<S> for InspectionLayer {
    type Service = InspectionService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        InspectionService {
            inner,
            allowed_pathes: self.rules.clone(),
            server_name: self.server_name,
        }
    }
}

/// Middleware service that enforces the path allow-list.
///
/// On each request it calls
/// [`CompiledAllowedPathes::is_allowed`](crate::configuration::CompiledAllowedPathes::is_allowed)
/// to check the `(method, path, query)` triple. Allowed requests are forwarded
/// to the inner service; rejected requests receive an immediate 403.
#[derive(Clone)]
pub struct InspectionService<S> {
    /// The next service in the middleware chain.
    inner: S,
    /// The compiled regex set for allow-list matching.
    allowed_pathes: Arc<CompiledAllowedPathes>,
    /// Server name label for logging.
    server_name: &'static str,
}

/// A custom future that either polls the inner service (if the request is allowed)
/// or immediately resolves with a 403 Forbidden response (if blocked).
#[pin_project(project = InspectionFutureProj)]
pub enum InspectionFuture<F> {
    /// The request was allowed, so we poll the inner future.
    Allowed {
        #[pin]
        inner: F,
    },
    /// The request was blocked, returning the pre-built 403 response.
    Blocked {
        response: Option<Response<ServiceRespBody>>,
    },
}

impl<F, E> Future for InspectionFuture<F>
where
    F: Future<Output = Result<Response<ServiceRespBody>, E>>,
{
    type Output = Result<Response<ServiceRespBody>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            InspectionFutureProj::Allowed { inner } => inner.poll(cx),
            InspectionFutureProj::Blocked { response } => {
                let res = response.take().expect("InspectionFuture polled after completion");
                Poll::Ready(Ok(res))
            }
        }
    }
}

impl<S, ReqBody> Service<Request<ReqBody>> for InspectionService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ServiceRespBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ReqBody: Send + 'static,
{
    type Response = Response<ServiceRespBody>;
    type Error = S::Error;
    type Future = InspectionFuture<S::Future>;

    /// Delegates back-pressure to the inner service.
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    /// Checks the request against the allow-list, forwarding or rejecting it.
    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        // --- OPTIMIZATION: Avoid .to_string() and .clone() ---
        // We use &str directly from the request to avoid heap allocations.
        let server_name = self.server_name;
        let method = req.method().as_str();
        let path = req.uri().path();
        let query = req.uri().query().unwrap_or("");

        let allow = self.allowed_pathes.is_allowed(method, path, query);

        if allow {
            // Request allowed: Return the 'Allowed' variant containing the inner future.
            let fut = self.inner.call(req);
            InspectionFuture::Allowed { inner: fut }
        } else {
            // Log the failure
            let method_owned = method.to_string(); // Only allocate if we actually block
            let path_owned = path.to_string();
            let query_owned = query.to_string();

            tracing::warn!(
                target: "inspection",
                "{}: Blocked request: {} {}?{}",
                server_name, method_owned, path_owned, query_owned
            );

            // Return the 'Blocked' variant containing the immediate response.
            InspectionFuture::Blocked {
                response: Some(self.build_forbidden_response()),
            }
        }
    }
}

impl<S> InspectionService<S> {
    /// Constructs a **403 Forbidden** response with a short explanatory body.
    fn build_forbidden_response(&self) -> Response<ServiceRespBody> {
        let body: ServiceRespBody = Full::new(Bytes::from_static(
            b"Request does not match allowed patterns",
        ))
        .map_err(SrvError::from)
        .boxed();

        Response::builder()
            .status(StatusCode::FORBIDDEN)
            .body(body)
            .expect("Builder is infallible with these inputs")
    }
}
