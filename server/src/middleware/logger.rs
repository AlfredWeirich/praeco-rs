//! # Request/Response Logger Middleware
//!
//! Logs every incoming request (method, URI, client IP, user roles) and the
//! outgoing response (status code, headers) through [`tracing`]. This
//! middleware operates at `INFO` level and is typically placed near the outer
//! edge of the service stack so it captures the full picture after
//! authentication and role mapping have run.

// === Standard Library ===
use std::{
    fmt::Debug,
    future::Future,
    pin::Pin,
    sync::Arc, // <--- Added
    task::{Context, Poll},
};

// === External Crates ===
use hyper::{Request, Response};
use tower::{Layer, Service};

// === Internal Modules ===
use crate::ServiceRespBody;
// Import UserRole to know what type to look for in the extensions map
use crate::configuration::UserRole;

/// A Tower Layer that wraps a service with logging functionality.
///
/// Every request is logged on entry (method, URI, client IP, roles) and
/// again on exit (response status and headers).
#[derive(Clone)]
pub struct LoggerLayer {
    /// Server name label included in every log line.
    server_name: &'static str,
}

impl LoggerLayer {
    /// Creates a new `LoggerLayer`.
    ///
    /// # Arguments
    ///
    /// * `server_name` – A `'static` label for log output.
    pub fn new(server_name: &'static str) -> Self {
        Self { server_name }
    }
}

impl<S> Layer<S> for LoggerLayer {
    type Service = LoggerService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        LoggerService {
            inner,
            server_name: self.server_name,
        }
    }
}

/// Middleware service that logs requests/responses and inspects extensions.
///
/// On the request side it reads:
/// * **`SocketAddr`** – The client's IP address (inserted by
///   [`ConnectionHandler`](crate::ConnectionHandler)).
/// * **`Arc<Vec<UserRole>>`** – The mapped user roles (inserted by the JWT or
///   mTLS authentication layers via `ConnectionHandler`).
///
/// On the response side it logs the status code and all response headers.
#[derive(Clone)]
pub struct LoggerService<S> {
    /// The next service in the middleware chain.
    inner: S,
    /// Server name label for log output.
    server_name: &'static str,
}

impl<S, ReqBody> Service<Request<ReqBody>> for LoggerService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ServiceRespBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Debug + Send + 'static,
    ReqBody: Send + 'static,
{
    type Response = Response<ServiceRespBody>;
    type Error = S::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    /// Delegates back-pressure to the inner service.
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    /// Logs the request details, forwards the request, and logs the response.
    ///
    /// ## Request Logging
    ///
    /// Extracts the client IP and user roles from the request's
    /// [extensions](hyper::Request::extensions) map. Both are injected by
    /// earlier layers (`ConnectionHandler` for the IP and either JWT or mTLS
    /// middleware for the roles).
    ///
    /// ## Response Logging
    ///
    /// Logs the HTTP status code and all response headers, or an error
    /// message if the inner service failed.
    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let server_name = self.server_name;

        // === EXTENSION TRACING START ===
        let ext = req.extensions();

        // 1. Extract SocketAddr (IP)
        let client_ip = ext
            .get::<std::net::SocketAddr>()
            .map(|addr| addr.to_string())
            .unwrap_or_else(|| "Unknown IP".to_string());

        // 2. Extract User Roles
        // Note: We must match the EXACT type inserted by ConnectionHandler: Arc<Vec<UserRole>>
        let roles_str = if let Some(roles) = ext.get::<Arc<Vec<UserRole>>>() {
            format!("{:?}", roles)
        } else {
            "No Roles".to_string()
        };

        let req_method = req.method().clone();
        let req_origin = req.headers().get(hyper::header::ORIGIN).cloned();

        tracing::info!(
            "{}: --> {} {} | IP: {} | Roles: {} ",
            server_name,
            req.method(),
            req.uri(),
            client_ip,
            roles_str,
        );
        // === EXTENSION TRACING END ===

        // Note: 'req' is moved into 'inner.call' here, so we had to inspect extensions BEFORE this line.
        let fut = self.inner.call(req);

        Box::pin(async move {
            let response = fut.await;
            match &response {
                Ok(res) => {
                    let status = res.status();

                    let is_cors_preflight_failed = req_method == hyper::Method::OPTIONS
                        && req_origin.is_some()
                        && status == hyper::StatusCode::OK
                        && res
                            .headers()
                            .get(hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN)
                            .is_none();

                    if is_cors_preflight_failed {
                        let origin_str = req_origin
                            .as_ref()
                            .and_then(|h| h.to_str().ok())
                            .unwrap_or("unknown");
                        tracing::warn!(
                            "{}: !! CORS Preflight Blocked: Origin '{}' is not allowed",
                            server_name,
                            origin_str
                        );
                    }

                    if status.is_server_error() {
                        tracing::error!(
                            "{}: <-- Response: Status {} | Headers: {:?}",
                            server_name,
                            status,
                            res.headers()
                        );
                    } else if status.is_client_error() || is_cors_preflight_failed {
                        tracing::warn!(
                            "{}: <-- Response: Status {} | Headers: {:?}",
                            server_name,
                            status,
                            res.headers()
                        );
                    } else {
                        tracing::info!(
                            "{}: <-- Response: Status {} | Headers: {:?}",
                            server_name,
                            status,
                            res.headers()
                        );
                    }
                }
                Err(err) => {
                    tracing::error!("{}: !! Error: {:?}", server_name, err);
                }
            }
            response
        })
    }
}
