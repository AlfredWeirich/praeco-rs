use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Response, StatusCode, Uri, Version, header};
use hyper_util::client::legacy::Client;
use pin_project::pin_project;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tracing::{error, warn};

use super::upstreams::build_upstream_uri;
use super::{RequestBody, build_error_response};
use crate::{ServiceRespBody, SrvError, configuration::ParsedRoute};

pub async fn handle_http_proxy(
    route_info: &ParsedRoute,
    mut request_body: RequestBody,
    original_method: Method,
    original_version: Version,
    mut prepared_headers: hyper::HeaderMap,
    original_uri: &Uri,
    matched_params: &matchit::Params<'_, '_>,
    client_addr: Option<std::net::SocketAddr>,
    server_name: &str,
    client: &Client<
        common::client::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        ServiceRespBody,
    >,
    request_timeout: Option<std::time::Duration>,
) -> Result<Response<ServiceRespBody>, SrvError> {
    let mut failed_nodes = Vec::new();
    let max_retries = route_info.target.max_retries;
    let mut attempts = 0;
    let is_stream = matches!(request_body, RequestBody::Stream(_));
    let is_idempotent = matches!(
        original_method,
        hyper::Method::GET
            | hyper::Method::HEAD
            | hyper::Method::PUT
            | hyper::Method::DELETE
            | hyper::Method::OPTIONS
    );

    loop {
        let mut current_headers = if attempts == max_retries {
            std::mem::take(&mut prepared_headers)
        } else {
            prepared_headers.clone()
        };
        attempts += 1;

        let upstream_node = route_info
            .target
            .next_upstream(client_addr.as_ref(), &failed_nodes);
        let backend_base_uri = &upstream_node.uri;
        upstream_node
            .active_connections
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        struct ConnectionGuard {
            target: Arc<crate::configuration::RouteTarget>,
            uri: Uri,
        }
        impl Drop for ConnectionGuard {
            fn drop(&mut self) {
                if let Some(node) = self.target.upstreams.iter().find(|n| n.uri == self.uri) {
                    let current = node
                        .active_connections
                        .load(std::sync::atomic::Ordering::Relaxed);
                    if current > 0 {
                        node.active_connections
                            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }
        }

        let _conn_guard = ConnectionGuard {
            target: route_info.target.clone(),
            uri: backend_base_uri.clone(),
        };

        let target_uri = build_upstream_uri(backend_base_uri, matched_params, original_uri)?;

        if let Some(auth) = target_uri.authority() {
            if let Ok(host_val) = header::HeaderValue::from_str(auth.as_str()) {
                current_headers.insert(header::HOST, host_val);
            }
        }

        let body_error = Arc::new(std::sync::Mutex::new(None));
        let boxed_body: ServiceRespBody = match &mut request_body {
            RequestBody::Stream(_b) => {
                let mut temp_body = RequestBody::Buffered(bytes::Bytes::new());
                std::mem::swap(&mut temp_body, &mut request_body);
                if let RequestBody::Stream(taken_body) = temp_body {
                    BodyErrorTracker {
                        inner: taken_body,
                        last_error: body_error.clone(),
                    }
                    .boxed()
                } else {
                    unreachable!()
                }
            }
            RequestBody::Buffered(bytes) => {
                Full::new(bytes.clone()).map_err(SrvError::from).boxed()
            }
        };

        let mut proxy_req = Request::new(boxed_body);
        *proxy_req.method_mut() = original_method.clone();
        *proxy_req.uri_mut() = target_uri;
        *proxy_req.version_mut() = original_version;
        *proxy_req.headers_mut() = current_headers;

        // Inject OpenTelemetry context (e.g., traceparent) into the outgoing request headers.
        opentelemetry::global::get_text_map_propagator(|propagator| {
            use tracing_opentelemetry::OpenTelemetrySpanExt;
            propagator.inject_context(
                &tracing::Span::current().context(),
                &mut opentelemetry_http::HeaderInjector(proxy_req.headers_mut()),
            );
        });

        let req_fut = client.request(proxy_req);
        let resp_result = if let Some(timeout_dur) = request_timeout {
            match tokio::time::timeout(timeout_dur, req_fut).await {
                Ok(res) => res,
                Err(_elapsed) => {
                    error!(
                        "{}: Upstream request timed out after {:?} for {}",
                        server_name, timeout_dur, backend_base_uri
                    );
                    route_info.target.mark_dead(backend_base_uri);
                    failed_nodes.push(backend_base_uri.clone());

                    if !is_stream && is_idempotent && attempts <= max_retries {
                        warn!(
                            "{}: Retrying timed-out idempotent request... (Attempt {}/{})",
                            server_name, attempts, max_retries
                        );
                        continue;
                    } else {
                        if !is_idempotent && attempts <= max_retries {
                            warn!(
                                "{}: Non-idempotent {} request timed out on {}; skipping retry to prevent side-effects",
                                server_name, original_method, backend_base_uri
                            );
                        } else if is_stream && attempts <= max_retries {
                            warn!(
                                "{}: Streaming request timed out on {}; cannot retry consumed stream",
                                server_name, backend_base_uri
                            );
                        }
                        return Ok(build_error_response("Gateway Timeout", StatusCode::GATEWAY_TIMEOUT));
                    }
                }
            }
        } else {
            req_fut.await
        };

        match resp_result {
            Ok(res) => {
                if !upstream_node.is_alive.load(std::sync::atomic::Ordering::Relaxed) {
                    upstream_node.mark_alive();
                }
                let (mut res_parts, res_body) = res.into_parts();
                super::headers::clean_response_headers(&mut res_parts.headers);
                return Ok(Response::from_parts(
                    res_parts,
                    res_body.map_err(SrvError::from).boxed(),
                ));
            }
            Err(e) => {
                let client_error = body_error.lock().ok().and_then(|mut g| g.take());
                let error_kind = if let Some(srv_err) = client_error {
                    match srv_err {
                        SrvError::PayloadTooLarge { .. } => ProxyErrorKind::PayloadTooLarge,
                        SrvError::DecompressionLimitExceeded { .. } => ProxyErrorKind::DecompressionLimitExceeded,
                        SrvError::ClientAborted(reason) => ProxyErrorKind::ClientAborted(reason),
                        _ => ProxyErrorKind::ClientAborted("Client stream error".to_string()),
                    }
                } else {
                    classify_proxy_error(&e)
                };
                match error_kind {
                    ProxyErrorKind::PayloadTooLarge => {
                        warn!(
                            "{}: Client request payload exceeded limit during proxying to {}",
                            server_name, backend_base_uri
                        );
                        return Ok(build_error_response(
                            "Payload Too Large",
                            StatusCode::PAYLOAD_TOO_LARGE,
                        ));
                    }
                    ProxyErrorKind::DecompressionLimitExceeded => {
                        warn!(
                            "{}: Client request decompressed payload exceeded limit during proxying to {}",
                            server_name, backend_base_uri
                        );
                        return Ok(build_error_response(
                            "Payload Too Large",
                            StatusCode::PAYLOAD_TOO_LARGE,
                        ));
                    }
                    ProxyErrorKind::ClientAborted(ref reason) => {
                        warn!(
                            "{}: Client aborted request stream during proxying to {}: {}",
                            server_name, backend_base_uri, reason
                        );
                        return Ok(build_error_response(
                            "Client Closed Request",
                            StatusCode::BAD_REQUEST,
                        ));
                    }
                    ProxyErrorKind::UpstreamFailure => {
                        error!(
                            "{}: Backend connection failed to {}: {}",
                            server_name, backend_base_uri, e
                        );
                        route_info.target.mark_dead(backend_base_uri);
                        failed_nodes.push(backend_base_uri.clone());

                        if !is_stream && is_idempotent && attempts <= max_retries {
                            warn!(
                                "{}: Retrying request... (Attempt {}/{})",
                                server_name, attempts, max_retries
                            );
                            continue;
                        } else {
                            if !is_idempotent && attempts <= max_retries {
                                warn!(
                                    "{}: Non-idempotent {} request failed on {}; skipping retry to prevent duplicate side-effects",
                                    server_name, original_method, backend_base_uri
                                );
                            } else if is_stream && attempts <= max_retries {
                                warn!(
                                    "{}: Streaming request failed on {}; cannot retry consumed stream",
                                    server_name, backend_base_uri
                                );
                            }
                            error!(
                                "{}: Max retries reached or request not retryable (stream={}, idempotent={}). Returning 502 Bad Gateway.",
                                server_name, is_stream, is_idempotent
                            );
                            return Ok(build_error_response("Bad Gateway", StatusCode::BAD_GATEWAY));
                        }
                    }
                }
            }
        }
    }
}

/// A transparent body wrapper that captures any client-side error (such as payload limit or client abort)
/// so it can be distinguished from upstream backend failures.
#[pin_project]
pub struct BodyErrorTracker<B> {
    #[pin]
    pub inner: B,
    pub last_error: Arc<std::sync::Mutex<Option<SrvError>>>,
}

impl<B> http_body::Body for BodyErrorTracker<B>
where
    B: http_body::Body<Data = bytes::Bytes, Error = SrvError>,
{
    type Data = bytes::Bytes;
    type Error = SrvError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let this = self.project();
        match this.inner.poll_frame(cx) {
            Poll::Ready(Some(Err(e))) => {
                let recorded = match &e {
                    SrvError::PayloadTooLarge { current, max } => {
                        SrvError::PayloadTooLarge {
                            current: *current,
                            max: *max,
                        }
                    }
                    SrvError::DecompressionLimitExceeded { max } => {
                        SrvError::DecompressionLimitExceeded { max: *max }
                    }
                    SrvError::ClientAborted(msg) => SrvError::ClientAborted(msg.clone()),
                    other => {
                        let msg = other.to_string();
                        if msg.contains("Payload Limit Exceeded") {
                            SrvError::PayloadTooLarge { current: 0, max: 0 }
                        } else if msg.contains("Decompressed payload") {
                            SrvError::DecompressionLimitExceeded { max: 0 }
                        } else {
                            SrvError::ClientAborted(msg)
                        }
                    }
                };
                if let Ok(mut lock) = this.last_error.lock() {
                    *lock = Some(recorded);
                }
                Poll::Ready(Some(Err(e)))
            }
            res => res,
        }
    }
}

/// Categorizes errors that occur while sending a request to an upstream proxy backend.
#[derive(Debug, PartialEq, Eq)]
pub enum ProxyErrorKind {
    /// Client request payload exceeded the configured max_bytes limit
    PayloadTooLarge,
    /// Client decompressed body exceeded decompression bomb protection limit
    DecompressionLimitExceeded,
    /// Client aborted the stream or connection was severed by the client
    ClientAborted(String),
    /// Genuine upstream failure (connect failure, reset by upstream, protocol violation)
    UpstreamFailure,
}

/// Inspects the nested error chain from Hyper and Tower middleware to determine whether
/// a proxy request failure was caused by the upstream server (dead/unavailable) or by the client
/// (aborted, payload limit exceeded, decompression bomb).
pub fn classify_proxy_error(err: &hyper_util::client::legacy::Error) -> ProxyErrorKind {
    // 1. Upstream connection errors (refused, DNS, network unreachable) are genuine upstream failures
    if err.is_connect() {
        return ProxyErrorKind::UpstreamFailure;
    }

    let mut curr: Option<&(dyn std::error::Error + 'static)> = Some(err);
    let mut is_user_body = false;

    while let Some(e) = curr {
        if let Some(srv_err) = e.downcast_ref::<SrvError>() {
            match srv_err {
                SrvError::PayloadTooLarge { .. } => return ProxyErrorKind::PayloadTooLarge,
                SrvError::DecompressionLimitExceeded { .. } => {
                    return ProxyErrorKind::DecompressionLimitExceeded;
                }
                SrvError::ClientAborted(msg) => {
                    return ProxyErrorKind::ClientAborted(msg.clone());
                }
                _ => {}
            }
        }

        if let Some(hyper_err) = e.downcast_ref::<hyper::Error>() {
            if hyper_err.is_user() || hyper_err.is_body_write_aborted() {
                is_user_body = true;
            }
        }

        if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
            match io_err.kind() {
                std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::UnexpectedEof => {
                    return ProxyErrorKind::ClientAborted(io_err.to_string());
                }
                _ => {}
            }
        }

        let msg = e.to_string();
        if msg.contains("Payload Limit Exceeded") {
            return ProxyErrorKind::PayloadTooLarge;
        }
        if msg.contains("Decompressed payload exceeds maximum allowed size") {
            return ProxyErrorKind::DecompressionLimitExceeded;
        }
        if msg.contains("sent by user") || msg.contains("user body write aborted") {
            return ProxyErrorKind::ClientAborted(msg);
        }

        curr = e.source();
    }

    if is_user_body {
        return ProxyErrorKind::ClientAborted("Client body write aborted".to_string());
    }

    ProxyErrorKind::UpstreamFailure
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::time::Duration;
    use crate::configuration::{LbStrategy, RouteBackendType, RouteTarget, UpstreamNode};

    #[tokio::test]
    async fn test_http_proxy_request_timeout_returns_504() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // Spawn a slow upstream that accepts but delays sending any HTTP response
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                // Sleep longer than the request timeout
                tokio::time::sleep(Duration::from_millis(300)).await;
                use tokio::io::AsyncWriteExt;
                let _ = socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK").await;
            }
        });

        let upstream_uri: Uri = format!("http://127.0.0.1:{}", port).parse().unwrap();
        let node = UpstreamNode {
            uri: upstream_uri.clone(),
            active_connections: AtomicUsize::new(0),
            is_alive: AtomicBool::new(true),
            last_failure_time: AtomicU64::new(0),
            current_score: AtomicUsize::new(0),
        };

        let target = Arc::new(RouteTarget {
            upstreams: vec![node],
            strategy: LbStrategy::RoundRobin,
            rr_counter: AtomicUsize::new(0),
            cooldown_seconds: 10,
            max_retries: 0,
            active_health_check_interval: 0,
            grpc_pool: tokio::sync::RwLock::new(None),
            grpc_reflection_lock: tokio::sync::Mutex::new(()),
        });

        let route_info = ParsedRoute {
            prefix: "/api".to_string(),
            target: target.clone(),
            allowed_roles: Vec::new(),
            backend_type: RouteBackendType::Rest,
        };

        let root_store = rustls::RootCertStore::empty();
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let client = common::client::build_hyper_client(tls_config, common::client::ClientPoolConfig::default());

        let matched_params = matchit::Params::new();

        let req_uri: Uri = "http://localhost/api/slow".parse().unwrap();
        let prepared_headers = hyper::HeaderMap::new();

        // Send with a short timeout of 50ms (mock server sleeps 300ms)
        let response = handle_http_proxy(
            &route_info,
            RequestBody::Buffered(bytes::Bytes::new()),
            Method::GET,
            Version::HTTP_11,
            prepared_headers,
            &req_uri,
            &matched_params,
            None,
            "test_server",
            &client,
            Some(Duration::from_millis(50)),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        assert!(!target.upstreams[0].is_alive.load(Ordering::Relaxed), "Timed out node must be marked dead");
    }

    #[tokio::test]
    async fn test_http_proxy_streaming_payload_too_large_returns_413_and_node_remains_alive() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // Spawn mock upstream that accepts connection and starts reading request
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                use tokio::io::AsyncReadExt;
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
            }
        });

        let upstream_uri: Uri = format!("http://127.0.0.1:{}", port).parse().unwrap();
        let node = UpstreamNode {
            uri: upstream_uri.clone(),
            active_connections: AtomicUsize::new(0),
            is_alive: AtomicBool::new(true),
            last_failure_time: AtomicU64::new(0),
            current_score: AtomicUsize::new(0),
        };

        let target = Arc::new(RouteTarget {
            upstreams: vec![node],
            strategy: LbStrategy::RoundRobin,
            rr_counter: AtomicUsize::new(0),
            cooldown_seconds: 60,
            max_retries: 0,
            active_health_check_interval: 0,
            grpc_pool: tokio::sync::RwLock::new(None),
            grpc_reflection_lock: tokio::sync::Mutex::new(()),
        });

        let route_info = ParsedRoute {
            prefix: "/api".to_string(),
            target: target.clone(),
            allowed_roles: Vec::new(),
            backend_type: RouteBackendType::Rest,
        };

        let root_store = rustls::RootCertStore::empty();
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let client = common::client::build_hyper_client(tls_config, common::client::ClientPoolConfig::default());

        let matched_params = matchit::Params::new();
        let req_uri: Uri = "http://localhost/api/upload".parse().unwrap();
        let prepared_headers = hyper::HeaderMap::new();

        // Create a streaming body that errors out with PayloadTooLarge
        let err_stream = futures_util::stream::iter(vec![
            Ok(http_body::Frame::data(bytes::Bytes::from("initial chunk"))),
            Err(SrvError::PayloadTooLarge { current: 15, max: 10 }),
        ]);
        let body: ServiceRespBody = http_body_util::StreamBody::new(err_stream).boxed();

        let response = handle_http_proxy(
            &route_info,
            RequestBody::Stream(body),
            Method::POST,
            Version::HTTP_11,
            prepared_headers,
            &req_uri,
            &matched_params,
            None,
            "test_server",
            &client,
            Some(Duration::from_secs(5)),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(
            target.upstreams[0].is_alive.load(Ordering::Relaxed),
            "Upstream node must NOT be marked dead on client payload limit error"
        );
    }

    #[tokio::test]
    async fn test_http_proxy_streaming_client_aborted_returns_400_and_node_remains_alive() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                use tokio::io::AsyncReadExt;
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
            }
        });

        let upstream_uri: Uri = format!("http://127.0.0.1:{}", port).parse().unwrap();
        let node = UpstreamNode {
            uri: upstream_uri.clone(),
            active_connections: AtomicUsize::new(0),
            is_alive: AtomicBool::new(true),
            last_failure_time: AtomicU64::new(0),
            current_score: AtomicUsize::new(0),
        };

        let target = Arc::new(RouteTarget {
            upstreams: vec![node],
            strategy: LbStrategy::RoundRobin,
            rr_counter: AtomicUsize::new(0),
            cooldown_seconds: 60,
            max_retries: 0,
            active_health_check_interval: 0,
            grpc_pool: tokio::sync::RwLock::new(None),
            grpc_reflection_lock: tokio::sync::Mutex::new(()),
        });

        let route_info = ParsedRoute {
            prefix: "/api".to_string(),
            target: target.clone(),
            allowed_roles: Vec::new(),
            backend_type: RouteBackendType::Rest,
        };

        let root_store = rustls::RootCertStore::empty();
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let client = common::client::build_hyper_client(tls_config, common::client::ClientPoolConfig::default());

        let matched_params = matchit::Params::new();
        let req_uri: Uri = "http://localhost/api/upload".parse().unwrap();
        let prepared_headers = hyper::HeaderMap::new();

        // Create a streaming body that errors out with ClientAborted
        let err_stream = futures_util::stream::iter(vec![
            Ok(http_body::Frame::data(bytes::Bytes::from("some chunk"))),
            Err(SrvError::ClientAborted("Client disconnected prematurely".to_string())),
        ]);
        let body: ServiceRespBody = http_body_util::StreamBody::new(err_stream).boxed();

        let response = handle_http_proxy(
            &route_info,
            RequestBody::Stream(body),
            Method::POST,
            Version::HTTP_11,
            prepared_headers,
            &req_uri,
            &matched_params,
            None,
            "test_server",
            &client,
            Some(Duration::from_secs(5)),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(
            target.upstreams[0].is_alive.load(Ordering::Relaxed),
            "Upstream node must NOT be marked dead on client abort"
        );
    }

    #[tokio::test]
    async fn test_http_proxy_real_connect_failure_marks_node_dead_and_returns_502() {
        // Pick an unused port without starting a server
        let port = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap().port()
        };

        let upstream_uri: Uri = format!("http://127.0.0.1:{}", port).parse().unwrap();
        let node = UpstreamNode {
            uri: upstream_uri.clone(),
            active_connections: AtomicUsize::new(0),
            is_alive: AtomicBool::new(true),
            last_failure_time: AtomicU64::new(0),
            current_score: AtomicUsize::new(0),
        };

        let target = Arc::new(RouteTarget {
            upstreams: vec![node],
            strategy: LbStrategy::RoundRobin,
            rr_counter: AtomicUsize::new(0),
            cooldown_seconds: 60,
            max_retries: 0,
            active_health_check_interval: 0,
            grpc_pool: tokio::sync::RwLock::new(None),
            grpc_reflection_lock: tokio::sync::Mutex::new(()),
        });

        let route_info = ParsedRoute {
            prefix: "/api".to_string(),
            target: target.clone(),
            allowed_roles: Vec::new(),
            backend_type: RouteBackendType::Rest,
        };

        let root_store = rustls::RootCertStore::empty();
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let client = common::client::build_hyper_client(tls_config, common::client::ClientPoolConfig::default());

        let matched_params = matchit::Params::new();
        let req_uri: Uri = "http://localhost/api/test".parse().unwrap();
        let prepared_headers = hyper::HeaderMap::new();

        let response = handle_http_proxy(
            &route_info,
            RequestBody::Buffered(bytes::Bytes::new()),
            Method::GET,
            Version::HTTP_11,
            prepared_headers,
            &req_uri,
            &matched_params,
            None,
            "test_server",
            &client,
            Some(Duration::from_secs(5)),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert!(
            !target.upstreams[0].is_alive.load(Ordering::Relaxed),
            "Upstream node MUST be marked dead on connection failure"
        );
    }

    #[tokio::test]
    async fn test_http_proxy_streaming_decompression_bomb_returns_413_and_node_remains_alive() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                use tokio::io::AsyncReadExt;
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
            }
        });

        let upstream_uri: Uri = format!("http://127.0.0.1:{}", port).parse().unwrap();
        let node = UpstreamNode {
            uri: upstream_uri.clone(),
            active_connections: AtomicUsize::new(0),
            is_alive: AtomicBool::new(true),
            last_failure_time: AtomicU64::new(0),
            current_score: AtomicUsize::new(0),
        };

        let target = Arc::new(RouteTarget {
            upstreams: vec![node],
            strategy: LbStrategy::RoundRobin,
            rr_counter: AtomicUsize::new(0),
            cooldown_seconds: 60,
            max_retries: 0,
            active_health_check_interval: 0,
            grpc_pool: tokio::sync::RwLock::new(None),
            grpc_reflection_lock: tokio::sync::Mutex::new(()),
        });

        let route_info = ParsedRoute {
            prefix: "/api".to_string(),
            target: target.clone(),
            allowed_roles: Vec::new(),
            backend_type: RouteBackendType::Rest,
        };

        let root_store = rustls::RootCertStore::empty();
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let client = common::client::build_hyper_client(tls_config, common::client::ClientPoolConfig::default());

        let matched_params = matchit::Params::new();
        let req_uri: Uri = "http://localhost/api/upload".parse().unwrap();
        let prepared_headers = hyper::HeaderMap::new();

        let err_stream = futures_util::stream::iter(vec![
            Ok(http_body::Frame::data(bytes::Bytes::from("decompressed chunk"))),
            Err(SrvError::DecompressionLimitExceeded { max: 10485760 }),
        ]);
        let body: ServiceRespBody = http_body_util::StreamBody::new(err_stream).boxed();

        let response = handle_http_proxy(
            &route_info,
            RequestBody::Stream(body),
            Method::POST,
            Version::HTTP_11,
            prepared_headers,
            &req_uri,
            &matched_params,
            None,
            "test_server",
            &client,
            Some(Duration::from_secs(5)),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(
            target.upstreams[0].is_alive.load(Ordering::Relaxed),
            "Upstream node must NOT be marked dead on decompression bomb limit"
        );
    }
}

