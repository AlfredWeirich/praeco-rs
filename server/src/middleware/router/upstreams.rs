use crate::SrvError;
use hyper::http::uri::{PathAndQuery, Uri};
use pin_project::pin_project;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

/// RAII guard that increments an upstream node's `active_connections` counter on creation
/// and decrements it on drop.
///
/// When attached to a streaming response via [`TrackedBody`], the guard remains alive
/// for the entire duration of the HTTP/2, gRPC, or SSE response stream rather than
/// dropping prematurely as soon as the initial response headers arrive.
pub struct ConnectionGuard {
    target: Arc<crate::configuration::RouteTarget>,
    uri: Uri,
}

impl ConnectionGuard {
    pub fn new(target: Arc<crate::configuration::RouteTarget>, uri: Uri) -> Self {
        if let Some(node) = target.upstreams.iter().find(|n| n.uri == uri) {
            node.active_connections
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            node.total_requests
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        Self { target, uri }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        if let Some(node) = self.target.upstreams.iter().find(|n| n.uri == self.uri) {
            node.active_connections
                .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        }
    }
}

/// A response body wrapper that ties the lifetime of a [`ConnectionGuard`] to the
/// underlying HTTP/gRPC response stream.
///
/// Ensures `active_connections` stays accurate for long-lived gRPC server streams
/// (e.g. `StreamGlobalEvents`, `StreamMessages`) until the stream closes or the
/// client disconnects.
#[pin_project]
pub struct TrackedBody<B> {
    #[pin]
    inner: B,
    _guard: ConnectionGuard,
}

impl<B> TrackedBody<B> {
    pub fn new(inner: B, guard: ConnectionGuard) -> Self {
        Self {
            inner,
            _guard: guard,
        }
    }
}

impl<B> http_body::Body for TrackedBody<B>
where
    B: http_body::Body,
{
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        self.project().inner.poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

/// Reconstructs the Request URI for the upstream server.
///
/// Combines the backend's base URI with the matched sub-path (`*rest`) and
/// preserves any original query parameters.
pub fn build_upstream_uri(
    backend_base_uri: &Uri,
    matched_params: &matchit::Params,
    original_uri: &Uri,
) -> Result<Uri, SrvError> {
    let mut pq_string = String::with_capacity(64);
    pq_string.push_str(backend_base_uri.path().trim_end_matches('/'));

    if let Some(rest) = matched_params.get("rest") {
        // Defense-in-depth: Reject any sub-path containing traversal or illegal characters
        if rest.split('/').any(|seg| seg == "..")
            || rest.contains("%2f")
            || rest.contains("%2F")
            || rest.contains('\0')
            || rest.contains("%00")
            || rest.contains('\\')
            || rest.contains("%5c")
            || rest.contains("%5C")
        {
            return Err(SrvError::from("Suspicious path traversal or illegal characters detected in upstream URI".to_string()));
        }
        if !rest.starts_with('/') {
            pq_string.push('/');
        }
        pq_string.push_str(rest);
    } else if pq_string.is_empty() {
        pq_string.push('/');
    }

    if let Some(query) = original_uri.query() {
        pq_string.push('?');
        pq_string.push_str(query);
    }

    let mut uri_parts = backend_base_uri.clone().into_parts();
    uri_parts.path_and_query = Some(
        pq_string
            .parse::<PathAndQuery>()
            .map_err(|e| SrvError::from(format!("Invalid PathAndQuery: {e}")))?,
    );

    Uri::from_parts(uri_parts).map_err(|e| SrvError::from(format!("URI Build Error: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_upstream_uri_normal() {
        let base: Uri = "https://backend.local:8080/api".parse().unwrap();
        let orig: Uri = "/api/v1/users?page=1".parse().unwrap();
        let mut router = matchit::Router::new();
        router.insert("/api/{*rest}", ()).unwrap();
        let matched = router.at("/api/v1/users").unwrap();

        let upstream = build_upstream_uri(&base, &matched.params, &orig).unwrap();
        assert_eq!(upstream.to_string(), "https://backend.local:8080/api/v1/users?page=1");
    }

    #[test]
    fn test_build_upstream_uri_traversal_rejected() {
        let base: Uri = "https://backend.local:8080/api".parse().unwrap();
        let orig: Uri = "/public/../admin".parse().unwrap();
        let mut router = matchit::Router::new();
        router.insert("/public/{*rest}", ()).unwrap();
        let matched = router.at("/public/../admin").unwrap();

        let err = build_upstream_uri(&base, &matched.params, &orig).unwrap_err();
        assert!(err.to_string().contains("Suspicious path traversal"));
    }

    #[test]
    fn test_tracked_body_holds_active_connection_until_dropped() {
        use crate::configuration::{LbStrategy, RouteTarget, UpstreamNode};
        use std::sync::atomic::{AtomicUsize, Ordering};

        let uri: Uri = "https://127.0.0.1:50051".parse().unwrap();
        let node = UpstreamNode::new(uri.clone());
        let target = Arc::new(RouteTarget {
            upstreams: vec![node],
            strategy: LbStrategy::RoundRobin,
            rr_counter: AtomicUsize::new(0),
            cooldown_seconds: 10,
            max_retries: 2,
            failure_threshold: 3,
            max_retry_buffer_bytes: 65536,
            active_health_check_interval: 0,
            grpc_pool: tokio::sync::RwLock::new(None),
            grpc_reflection_lock: tokio::sync::Mutex::new(()),
        });

        assert_eq!(target.upstreams[0].active_connections.load(Ordering::Relaxed), 0);

        let guard = ConnectionGuard::new(target.clone(), uri);
        assert_eq!(target.upstreams[0].active_connections.load(Ordering::Relaxed), 1);

        let tracked = TrackedBody::new(http_body_util::Empty::<bytes::Bytes>::new(), guard);
        // Guard moved into TrackedBody -> active_connections must remain 1 while stream is open
        assert_eq!(target.upstreams[0].active_connections.load(Ordering::Relaxed), 1);

        drop(tracked);
        // Once stream body is dropped -> active_connections drops back to 0
        assert_eq!(target.upstreams[0].active_connections.load(Ordering::Relaxed), 0);
    }
}
