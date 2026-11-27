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
use hyper::{header::HeaderValue, Method, Request, Response};
use pin_project::pin_project;
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

/// A custom future that awaits the inner service's future and logs the response.
///
/// Using a concrete future type (via `pin_project`) avoids the overhead of
/// pinning and boxing for every request.
#[pin_project]
pub struct LoggerFuture<F> {
    #[pin]
    inner: F,
    server_name: &'static str,
    req_method: Method,
    req_origin: Option<HeaderValue>,
}

impl<F, E> Future for LoggerFuture<F>
where
    F: Future<Output = Result<Response<ServiceRespBody>, E>>,
    E: Debug,
{
    type Output = Result<Response<ServiceRespBody>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();

        let response = std::task::ready!(this.inner.poll(cx));

        match &response {
            Ok(res) => {
                let status = res.status();
                let is_cors_preflight_failed = *this.req_method == hyper::Method::OPTIONS
                    && this.req_origin.is_some()
                    && status == hyper::StatusCode::OK
                    && res
                        .headers()
                        .get(hyper::header::ACCESS_CONTROL_ALLOW_ORIGIN)
                        .is_none();

                if is_cors_preflight_failed {
                    let origin_str = this
                        .req_origin
                        .as_ref()
                        .and_then(|h| h.to_str().ok())
                        .unwrap_or("unknown");
                    tracing::warn!(
                        "{}: !! CORS Preflight Blocked: Origin '{}' is not allowed",
                        this.server_name,
                        origin_str
                    );
                }

                if status.is_server_error() {
                    if tracing::enabled!(tracing::Level::ERROR) {
                        let safe_headers = sanitize_headers(res.headers());
                        tracing::error!(
                            "{}: <-- Response: Status {} | Headers: {:?}",
                            this.server_name,
                            status,
                            safe_headers
                        );
                    }
                } else if status.is_client_error() || is_cors_preflight_failed {
                    if tracing::enabled!(tracing::Level::WARN) {
                        let safe_headers = sanitize_headers(res.headers());
                        tracing::warn!(
                            "{}: <-- Response: Status {} | Headers: {:?}",
                            this.server_name,
                            status,
                            safe_headers
                        );
                    }
                } else if tracing::enabled!(tracing::Level::INFO) {
                    let safe_headers = sanitize_headers(res.headers());
                    tracing::info!(
                        "{}: <-- Response: Status {} | Headers: {:?}",
                        this.server_name,
                        status,
                        safe_headers
                    );
                }
            }
            Err(err) => {
                tracing::error!("{}: !! Error: {:?}", this.server_name, err);
            }
        }

        Poll::Ready(response)
    }
}

/// Substrings identifying sensitive credential/session parameter and header names redacted from logs (`S-09`).
const SENSITIVE_KEY_SUBSTRINGS: &[&str] = &[
    "token",
    "secret",
    "session",
    "jwt",
    "key",
    "pass",
    "sig",
    "auth",
    "credential",
];

/// Returns `true` if a header or query-parameter name matches any sensitive credential substring.
fn is_sensitive_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    SENSITIVE_KEY_SUBSTRINGS
        .iter()
        .any(|needle| lower.contains(needle))
}

/// Redacts sensitive response headers (`Set-Cookie`, `Cookie`, `Authorization`, API keys, tokens) from logs.
fn sanitize_headers(headers: &hyper::HeaderMap) -> hyper::HeaderMap {
    let mut sanitized = headers.clone();
    let sensitive_names: Vec<hyper::header::HeaderName> = sanitized
        .keys()
        .filter(|name| {
            *name == hyper::header::SET_COOKIE
                || *name == hyper::header::COOKIE
                || is_sensitive_key(name.as_str())
        })
        .cloned()
        .collect();
    for name in sensitive_names {
        sanitized.insert(name, hyper::header::HeaderValue::from_static("[REDACTED]"));
    }
    sanitized
}

/// Redacts sensitive query parameters from logs via case-insensitive substring matching (`S-09`).
///
/// Returns [`std::borrow::Cow::Borrowed`] when no query parameters require redaction and the
/// URI has no scheme/authority prefix, avoiding per-request heap allocation on clean paths.
///
/// Note: `code` is kept visible strictly on `/auth/confirm` for device onboarding pairing codes,
/// and redacted on all other paths (e.g. OAuth authorization-code callbacks).
pub(crate) fn sanitize_uri(uri: &hyper::Uri) -> std::borrow::Cow<'_, str> {
    let path = uri.path();
    if let Some(query) = uri.query() {
        let needs_redaction = query.split('&').any(|pair| {
            pair.split_once('=').is_some_and(|(k, _)| {
                is_sensitive_key(k) || (k.eq_ignore_ascii_case("code") && path != "/auth/confirm")
            })
        });
        if !needs_redaction && let Some(pq) = uri.path_and_query() {
            return std::borrow::Cow::Borrowed(pq.as_str());
        }

        let mut out = String::with_capacity(path.len() + 1 + query.len());
        out.push_str(path);
        out.push('?');
        for (idx, pair) in query.split('&').enumerate() {
            if idx > 0 {
                out.push('&');
            }
            if let Some((k, _)) = pair.split_once('=') {
                let is_oauth_code =
                    k.eq_ignore_ascii_case("code") && path != "/auth/confirm";
                if is_sensitive_key(k) || is_oauth_code {
                    out.push_str(k);
                    out.push_str("=[REDACTED]");
                } else {
                    out.push_str(pair);
                }
            } else {
                out.push_str(pair);
            }
        }
        std::borrow::Cow::Owned(out)
    } else if uri.scheme().is_none()
        && uri.authority().is_none()
        && let Some(pq) = uri.path_and_query()
    {
        std::borrow::Cow::Borrowed(pq.as_str())
    } else {
        std::borrow::Cow::Owned(uri.to_string())
    }
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
    type Future = LoggerFuture<S::Future>;

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

        let req_method = req.method().clone();
        let req_origin = req.headers().get(hyper::header::ORIGIN).cloned();

        if tracing::enabled!(tracing::Level::INFO) {
            let ext = req.extensions();

            let client_ip = ext
                .get::<std::net::SocketAddr>()
                .map(|addr| addr.to_string())
                .unwrap_or_else(|| "Unknown IP".to_string());

            let roles_str = if let Some(roles) = ext.get::<Arc<crate::configuration::RoleVec<6>>>()
            {
                format!("{:?}", roles)
            } else if let Some(roles) = ext.get::<Arc<Vec<UserRole>>>() {
                format!("{:?}", roles)
            } else {
                "No Roles".to_string()
            };

            tracing::info!(
                "{}: --> {} {} | IP: {} | Roles: {} ",
                server_name,
                req.method(),
                sanitize_uri(req.uri()),
                client_ip,
                roles_str,
            );
        }

        let fut = self.inner.call(req);

        LoggerFuture {
            inner: fut,
            server_name,
            req_method,
            req_origin,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_headers_redacts_sensitive_tokens() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(hyper::header::CONTENT_TYPE, "application/json".parse().unwrap());
        headers.insert(hyper::header::SET_COOKIE, "admin-jwt=secret123; Path=/; HttpOnly".parse().unwrap());
        headers.insert(hyper::header::AUTHORIZATION, "Bearer topsecret456".parse().unwrap());
        headers.insert(hyper::header::COOKIE, "session_id=789".parse().unwrap());
        headers.insert("x-api-key", "secret-key-xyz".parse().unwrap());
        headers.insert("x-auth-token", "tok-999".parse().unwrap());

        let sanitized = sanitize_headers(&headers);
        assert_eq!(sanitized.get(hyper::header::CONTENT_TYPE).unwrap(), "application/json");
        assert_eq!(sanitized.get(hyper::header::SET_COOKIE).unwrap(), "[REDACTED]");
        assert_eq!(sanitized.get(hyper::header::AUTHORIZATION).unwrap(), "[REDACTED]");
        assert_eq!(sanitized.get(hyper::header::COOKIE).unwrap(), "[REDACTED]");
        assert_eq!(sanitized.get("x-api-key").unwrap(), "[REDACTED]");
        assert_eq!(sanitized.get("x-auth-token").unwrap(), "[REDACTED]");
    }

    #[test]
    fn test_sanitize_uri_redacts_sensitive_query_parameters() {
        let uri: hyper::Uri = "/auth/status?session=abc123456&poll_secret=def789&foo=bar".parse().unwrap();
        let sanitized = sanitize_uri(&uri);
        assert_eq!(sanitized, "/auth/status?session=[REDACTED]&poll_secret=[REDACTED]&foo=bar");

        let plain_uri: hyper::Uri = "/api/products?category=food".parse().unwrap();
        let plain_sanitized = sanitize_uri(&plain_uri);
        assert!(matches!(plain_sanitized, std::borrow::Cow::Borrowed(_)));
        assert_eq!(plain_sanitized, "/api/products?category=food");

        let code_uri: hyper::Uri = "/auth/confirm?session=abc123456&code=891023".parse().unwrap();
        assert_eq!(sanitize_uri(&code_uri), "/auth/confirm?session=[REDACTED]&code=891023");

        let oauth_uri: hyper::Uri = "/oauth/callback?access_token=a1&id_token=b2&refresh_token=c3&API_Key=d4&apikey=e5&key=f6&password=g7&passwd=h8&sig=i9&signature=j0&credentials=k1&code=l2&state=ok".parse().unwrap();
        assert_eq!(
            sanitize_uri(&oauth_uri),
            "/oauth/callback?access_token=[REDACTED]&id_token=[REDACTED]&refresh_token=[REDACTED]&API_Key=[REDACTED]&apikey=[REDACTED]&key=[REDACTED]&password=[REDACTED]&passwd=[REDACTED]&sig=[REDACTED]&signature=[REDACTED]&credentials=[REDACTED]&code=[REDACTED]&state=ok"
        );
    }
}
