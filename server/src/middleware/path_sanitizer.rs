//! # Path Sanitizer & Normalization Middleware (RFC 3986)
//!
//! This middleware protects against Path Traversal, WAF/Inspection Bypasses,
//! Route Confusion, and RBAC Bypasses by enforcing strict path canonicalization.
//!
//! ## Security Invariants Enforced
//!
//! 1. **No Raw or Encoded Null Bytes**: Rejects `\0` and `%00` immediately with **400 Bad Request**.
//! 2. **No Encoded Slashes (`%2f` / `%2F`)**: Rejects encoded slashes in URI paths to prevent
//!    semantic desync between proxy routing and downstream frameworks.
//! 3. **No Backslashes (`\` / `%5c`)**: Rejects backslashes to prevent Windows/UNC path confusion.
//! 4. **Strict Traversal Rejection**: Rejects any path segment that resolves to `..` (including
//!    percent-encoded variations like `%2e%2e`, `.%2e`, `%2e.`) with **400 Bad Request**.
//! 5. **Slash Normalization**: Collapses multiple consecutive slashes (e.g. `//`, `///`) into a single `/`.
//! 6. **Current-Directory Normalization**: Strips `/./` and trailing `/.` segments.
//! 7. **Unreserved Percent-Decoding**: Canonicalizes unreserved ASCII characters (`ALPHA`, `DIGIT`,
//!    `-`, `.`, `_`, `~`) per RFC 3986 §2.3 while preserving percent-encoding for reserved/special characters.
//! 8. **Uniform Upstream Dispatch**: Writes the canonical path back into the request URI so that
//!    Tracing, Inspection, Routing, RBAC, and Upstreams all observe the exact same path.

use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode, Uri};
use pin_project::pin_project;
use tower::{Layer, Service};

use crate::{ServiceRespBody, SrvError};

/// Specific errors that can occur during path sanitization and canonicalization.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PathSanitizeError {
    /// Path contains a raw or percent-encoded null byte.
    #[error("Path contains illegal null byte")]
    IllegalNullByte,

    /// Path contains an encoded forward slash (%2f or %2F).
    #[error("Path contains illegal encoded slash (%2f)")]
    IllegalEncodedSlash,

    /// Path contains a raw or encoded backslash.
    #[error("Path contains illegal backslash")]
    IllegalBackslash,

    /// Path contains a directory traversal attempt (`..` segment).
    #[error("Path traversal attempt detected (..)")]
    PathTraversal,

    /// Path contains invalid percent-encoding (e.g., malformed `%` sequence).
    #[error("Path contains invalid percent-encoding")]
    InvalidEncoding,

    /// Path contains suspicious nested or double percent-encoding.
    #[error("Path contains suspicious double-encoding")]
    DoubleEncoding,

    /// Path does not start with `/`.
    #[error("Path must start with '/'")]
    InvalidPath,

    /// Internal error constructing the canonical URI.
    #[error("Internal URI formatting error: {0}")]
    UriFormatError(String),
}

/// Sanitizes and canonicalizes a raw URI path according to RFC 3986 and strict gateway rules.
///
/// # Errors
///
/// Returns a [`PathSanitizeError`] if traversal, illegal characters, or invalid encodings are detected.
pub fn sanitize_and_normalize_path(raw_path: &str) -> Result<String, PathSanitizeError> {
    if raw_path.is_empty() {
        return Ok("/".to_string());
    }

    if !raw_path.starts_with('/') {
        return Err(PathSanitizeError::InvalidPath);
    }

    // 1. Fast checks for raw illegal characters
    if raw_path.contains('\0') {
        return Err(PathSanitizeError::IllegalNullByte);
    }
    if raw_path.contains('\\') {
        return Err(PathSanitizeError::IllegalBackslash);
    }

    // 2. Case-insensitive checks for forbidden encodings
    let lower = raw_path.to_ascii_lowercase();
    if lower.contains("%00") {
        return Err(PathSanitizeError::IllegalNullByte);
    }
    if lower.contains("%2f") {
        return Err(PathSanitizeError::IllegalEncodedSlash);
    }
    if lower.contains("%5c") {
        return Err(PathSanitizeError::IllegalBackslash);
    }

    // Double-encoding checks (%25 followed by 2e, 2f, 00, 5c)
    if lower.contains("%252e")
        || lower.contains("%252f")
        || lower.contains("%2500")
        || lower.contains("%255c")
    {
        return Err(PathSanitizeError::DoubleEncoding);
    }

    // 3. Verify that all '%' signs are valid two-digit hex sequences
    let bytes = raw_path.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            if i + 2 >= bytes.len()
                || !bytes[i + 1].is_ascii_hexdigit()
                || !bytes[i + 2].is_ascii_hexdigit()
            {
                return Err(PathSanitizeError::InvalidEncoding);
            }
            i += 3;
        } else {
            i += 1;
        }
    }

    // 4. Determine trailing slash intent
    let has_trailing_slash =
        raw_path.len() > 1 && (raw_path.ends_with('/') || raw_path.ends_with("/."));

    // 5. Split by '/' and normalize each segment
    let mut normalized_segments: Vec<String> = Vec::new();

    for raw_segment in raw_path.split('/') {
        if raw_segment.is_empty() {
            continue;
        }

        let normalized_seg = normalize_segment(raw_segment)?;

        if normalized_seg.is_empty() || normalized_seg == "." {
            continue;
        }

        if normalized_seg == ".." {
            return Err(PathSanitizeError::PathTraversal);
        }

        normalized_segments.push(normalized_seg);
    }

    if normalized_segments.is_empty() {
        return Ok("/".to_string());
    }

    let mut result = String::with_capacity(raw_path.len());
    for seg in &normalized_segments {
        result.push('/');
        result.push_str(seg);
    }
    if has_trailing_slash {
        result.push('/');
    }

    Ok(result)
}

/// Normalizes a single path segment by decoding unreserved ASCII characters
/// per RFC 3986 §2.3 and normalizing uppercase hex escapes for remaining percent-encodings.
fn normalize_segment(seg: &str) -> Result<String, PathSanitizeError> {
    let bytes = seg.as_bytes();
    let mut res = String::with_capacity(seg.len());
    let mut i = 0;

    while i < bytes.len() {
        if bytes[i] == b'%' {
            let h1 = bytes[i + 1];
            let h2 = bytes[i + 2];
            let hex_val = (hex_digit_to_val(h1)? << 4) | hex_digit_to_val(h2)?;

            // Decode unreserved characters: ALPHA / DIGIT / "-" / "." / "_" / "~"
            if is_unreserved(hex_val) {
                res.push(hex_val as char);
            } else {
                // Keep reserved or non-ASCII characters percent-encoded with uppercase hex
                res.push('%');
                res.push((h1 as char).to_ascii_uppercase());
                res.push((h2 as char).to_ascii_uppercase());
            }
            i += 3;
        } else {
            res.push(bytes[i] as char);
            i += 1;
        }
    }

    Ok(res)
}

#[inline]
fn hex_digit_to_val(b: u8) -> Result<u8, PathSanitizeError> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(PathSanitizeError::InvalidEncoding),
    }
}

#[inline]
fn is_unreserved(b: u8) -> bool {
    matches!(b, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~')
}

/// Sanitizes the path component of a [`hyper::Uri`], preserving query parameters.
///
/// # Errors
///
/// Returns [`PathSanitizeError`] if the path is invalid or cannot be reformatted into a valid URI.
pub fn sanitize_and_normalize_uri(uri: &Uri) -> Result<Uri, PathSanitizeError> {
    let raw_path = uri.path();
    let canonical_path = sanitize_and_normalize_path(raw_path)?;

    let query = uri.query();
    let new_pq_str = match query {
        Some(q) => format!("{}?{}", canonical_path, q),
        None => canonical_path,
    };

    let pq = new_pq_str
        .parse::<hyper::http::uri::PathAndQuery>()
        .map_err(|e| PathSanitizeError::UriFormatError(e.to_string()))?;

    let mut parts = uri.clone().into_parts();
    parts.path_and_query = Some(pq);

    Uri::from_parts(parts).map_err(|e| PathSanitizeError::UriFormatError(e.to_string()))
}

/// A Tower [`Layer`] that validates and canonicalizes request paths.
#[derive(Clone)]
pub struct PathSanitizerLayer {
    server_name: &'static str,
}

impl PathSanitizerLayer {
    /// Creates a new `PathSanitizerLayer` with the associated server label.
    pub fn new(server_name: &'static str) -> Self {
        Self { server_name }
    }
}

impl<S> Layer<S> for PathSanitizerLayer {
    type Service = PathSanitizerService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        PathSanitizerService {
            inner,
            server_name: self.server_name,
        }
    }
}

/// Service that enforces path sanitization and canonicalization.
#[derive(Clone)]
pub struct PathSanitizerService<S> {
    inner: S,
    server_name: &'static str,
}

#[pin_project(project = PathSanitizerFutureProj)]
pub enum PathSanitizerFuture<F> {
    Allowed {
        #[pin]
        inner: F,
    },
    Blocked {
        response: Option<Response<ServiceRespBody>>,
    },
}

impl<F, E> Future for PathSanitizerFuture<F>
where
    F: Future<Output = Result<Response<ServiceRespBody>, E>>,
{
    type Output = Result<Response<ServiceRespBody>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            PathSanitizerFutureProj::Allowed { inner } => inner.poll(cx),
            PathSanitizerFutureProj::Blocked { response } => {
                let res = response
                    .take()
                    .expect("PathSanitizerFuture polled after completion");
                Poll::Ready(Ok(res))
            }
        }
    }
}

impl<S, ReqBody> Service<Request<ReqBody>> for PathSanitizerService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ServiceRespBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ReqBody: Send + 'static,
{
    type Response = Response<ServiceRespBody>;
    type Error = S::Error;
    type Future = PathSanitizerFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        match sanitize_and_normalize_uri(req.uri()) {
            Ok(clean_uri) => {
                *req.uri_mut() = clean_uri;
                let fut = self.inner.call(req);
                PathSanitizerFuture::Allowed { inner: fut }
            }
            Err(e) => {
                crate::configuration::ServerMetrics::inc_blocked_inspection(self.server_name);
                tracing::warn!(
                    target: "security",
                    "{}: Blocked request with 400 Bad Request due to path sanitization: {} (URI: '{}')",
                    self.server_name, e, req.uri()
                );
                let resp = self.build_bad_request_response(&e.to_string());
                PathSanitizerFuture::Blocked {
                    response: Some(resp),
                }
            }
        }
    }
}

impl<S> PathSanitizerService<S> {
    fn build_bad_request_response(&self, msg: &str) -> Response<ServiceRespBody> {
        let body_text = format!("Bad Request: {}\n", msg);
        let body: ServiceRespBody = Full::new(Bytes::from(body_text))
            .map_err(SrvError::from)
            .boxed();

        Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header(hyper::header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(body)
            .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_paths_preserved() {
        assert_eq!(sanitize_and_normalize_path("/").unwrap(), "/");
        assert_eq!(sanitize_and_normalize_path("/api/v1/users").unwrap(), "/api/v1/users");
        assert_eq!(sanitize_and_normalize_path("/api/v1/users/").unwrap(), "/api/v1/users/");
    }

    #[test]
    fn test_multiple_slashes_collapsed() {
        assert_eq!(sanitize_and_normalize_path("//").unwrap(), "/");
        assert_eq!(sanitize_and_normalize_path("///").unwrap(), "/");
        assert_eq!(sanitize_and_normalize_path("/api//users").unwrap(), "/api/users");
        assert_eq!(sanitize_and_normalize_path("//api///v1////users//").unwrap(), "/api/v1/users/");
    }

    #[test]
    fn test_current_directory_segments_removed() {
        assert_eq!(sanitize_and_normalize_path("/.").unwrap(), "/");
        assert_eq!(sanitize_and_normalize_path("/./").unwrap(), "/");
        assert_eq!(sanitize_and_normalize_path("/api/./v1/./users").unwrap(), "/api/v1/users");
        assert_eq!(sanitize_and_normalize_path("/api/v1/.").unwrap(), "/api/v1/");
        assert_eq!(sanitize_and_normalize_path("/api/v1/./").unwrap(), "/api/v1/");
    }

    #[test]
    fn test_unreserved_characters_percent_decoded() {
        // %41 -> 'A', %42 -> 'B'
        assert_eq!(sanitize_and_normalize_path("/%41%42/users").unwrap(), "/AB/users");
        // %2e -> '.'
        assert_eq!(sanitize_and_normalize_path("/api/%2e/users").unwrap(), "/api/users");
    }

    #[test]
    fn test_reserved_characters_remain_percent_encoded() {
        // Space (%20) remains percent encoded
        assert_eq!(
            sanitize_and_normalize_path("/api/search/hello%20world").unwrap(),
            "/api/search/hello%20world"
        );
    }

    #[test]
    fn test_path_traversal_rejected() {
        assert_eq!(
            sanitize_and_normalize_path("/..").unwrap_err(),
            PathSanitizeError::PathTraversal
        );
        assert_eq!(
            sanitize_and_normalize_path("/../admin").unwrap_err(),
            PathSanitizeError::PathTraversal
        );
        assert_eq!(
            sanitize_and_normalize_path("/public/../admin").unwrap_err(),
            PathSanitizeError::PathTraversal
        );
        assert_eq!(
            sanitize_and_normalize_path("/public/..").unwrap_err(),
            PathSanitizeError::PathTraversal
        );
        assert_eq!(
            sanitize_and_normalize_path("/public/../").unwrap_err(),
            PathSanitizeError::PathTraversal
        );
    }

    #[test]
    fn test_percent_encoded_traversal_rejected() {
        assert_eq!(
            sanitize_and_normalize_path("/%2e%2e").unwrap_err(),
            PathSanitizeError::PathTraversal
        );
        assert_eq!(
            sanitize_and_normalize_path("/%2E%2E").unwrap_err(),
            PathSanitizeError::PathTraversal
        );
        assert_eq!(
            sanitize_and_normalize_path("/public/%2e%2e/admin").unwrap_err(),
            PathSanitizeError::PathTraversal
        );
        assert_eq!(
            sanitize_and_normalize_path("/public/.%2e/admin").unwrap_err(),
            PathSanitizeError::PathTraversal
        );
        assert_eq!(
            sanitize_and_normalize_path("/public/%2e./admin").unwrap_err(),
            PathSanitizeError::PathTraversal
        );
    }

    #[test]
    fn test_encoded_slash_rejected() {
        assert_eq!(
            sanitize_and_normalize_path("/public%2fadmin").unwrap_err(),
            PathSanitizeError::IllegalEncodedSlash
        );
        assert_eq!(
            sanitize_and_normalize_path("/public%2Fadmin").unwrap_err(),
            PathSanitizeError::IllegalEncodedSlash
        );
        assert_eq!(
            sanitize_and_normalize_path("/public/..%2fadmin").unwrap_err(),
            PathSanitizeError::IllegalEncodedSlash
        );
    }

    #[test]
    fn test_null_bytes_rejected() {
        assert_eq!(
            sanitize_and_normalize_path("/public%00admin").unwrap_err(),
            PathSanitizeError::IllegalNullByte
        );
        assert_eq!(
            sanitize_and_normalize_path("/public\0admin").unwrap_err(),
            PathSanitizeError::IllegalNullByte
        );
    }

    #[test]
    fn test_backslashes_rejected() {
        assert_eq!(
            sanitize_and_normalize_path("/public\\admin").unwrap_err(),
            PathSanitizeError::IllegalBackslash
        );
        assert_eq!(
            sanitize_and_normalize_path("/public%5cadmin").unwrap_err(),
            PathSanitizeError::IllegalBackslash
        );
        assert_eq!(
            sanitize_and_normalize_path("/public%5Cadmin").unwrap_err(),
            PathSanitizeError::IllegalBackslash
        );
    }

    #[test]
    fn test_double_encoding_rejected() {
        assert_eq!(
            sanitize_and_normalize_path("/public/%252e%252e/admin").unwrap_err(),
            PathSanitizeError::DoubleEncoding
        );
        assert_eq!(
            sanitize_and_normalize_path("/public/%252fadmin").unwrap_err(),
            PathSanitizeError::DoubleEncoding
        );
    }

    #[test]
    fn test_malformed_percent_encoding_rejected() {
        assert_eq!(
            sanitize_and_normalize_path("/api%").unwrap_err(),
            PathSanitizeError::InvalidEncoding
        );
        assert_eq!(
            sanitize_and_normalize_path("/api%2").unwrap_err(),
            PathSanitizeError::InvalidEncoding
        );
        assert_eq!(
            sanitize_and_normalize_path("/api%zz").unwrap_err(),
            PathSanitizeError::InvalidEncoding
        );
    }

    #[test]
    fn test_sanitize_and_normalize_uri_preserves_query() {
        let uri: Uri = "/api//users?sort=desc&limit=10".parse().unwrap();
        let cleaned = sanitize_and_normalize_uri(&uri).unwrap();
        assert_eq!(cleaned.to_string(), "/api/users?sort=desc&limit=10");

        let bad_uri: Uri = "/api/../admin?token=secret".parse().unwrap();
        assert_eq!(
            sanitize_and_normalize_uri(&bad_uri).unwrap_err(),
            PathSanitizeError::PathTraversal
        );
    }

    #[tokio::test]
    async fn test_path_sanitizer_layer_service() {
        use tower::ServiceExt;

        // Inner service echoes back the URI path it received
        let inner = tower::service_fn(|req: Request<Full<Bytes>>| async move {
            let path = req.uri().path().to_string();
            let body: ServiceRespBody = Full::new(Bytes::from(path)).map_err(SrvError::from).boxed();
            Ok::<_, SrvError>(Response::builder().status(StatusCode::OK).body(body).unwrap())
        });

        let mut svc = PathSanitizerLayer::new("test_server").layer(inner);

        // 1. Valid path with double slashes collapsed
        let req = Request::builder().uri("//api///users").body(Full::new(Bytes::new())).unwrap();
        let resp = svc.ready().await.unwrap().call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(body, "/api/users");

        // 2. Traversal rejected with 400 Bad Request
        let req = Request::builder().uri("/public/../admin").body(Full::new(Bytes::new())).unwrap();
        let resp = svc.ready().await.unwrap().call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // 3. Encoded traversal rejected with 400 Bad Request
        let req = Request::builder().uri("/public/%2e%2e/admin").body(Full::new(Bytes::new())).unwrap();
        let resp = svc.ready().await.unwrap().call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // 4. Encoded slash rejected with 400 Bad Request
        let req = Request::builder().uri("/public%2fadmin").body(Full::new(Bytes::new())).unwrap();
        let resp = svc.ready().await.unwrap().call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // 5. Encoded null byte rejected with 400 Bad Request
        let req = Request::builder().uri("/public%00admin").body(Full::new(Bytes::new())).unwrap();
        let resp = svc.ready().await.unwrap().call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        // 6. Backslash rejected with 400 Bad Request
        let req = Request::builder().uri("/public\\admin").body(Full::new(Bytes::new())).unwrap();
        let resp = svc.ready().await.unwrap().call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }
}
