use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Response, StatusCode, Uri, Version, header};
use hyper_util::client::legacy::Client;
use pin_project::pin_project;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tracing::{error, warn};

use super::upstreams::{ConnectionGuard, TrackedBody, build_upstream_uri};
use super::{RequestBody, build_error_response};
use crate::{ServiceRespBody, SrvError, configuration::RouteTarget};

/// Reason a failed upstream attempt is evaluated for failover retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetryReason {
    /// TCP/TLS connection could not be established (`err.is_connect()`).
    ConnectError,
    /// Upstream connection/protocol error after connect (request may have been sent).
    PostSendFailure,
    /// Upstream request timed out after connect.
    Timeout,
    /// Upstream returned an outlier HTTP/gRPC response status.
    Outlier,
}

/// Protocol-specific behavior differences between HTTP/REST proxying and raw HTTP/2 gRPC passthrough.
#[derive(Debug, Clone, Copy)]
pub(super) enum ProxyMode {
    /// Standard HTTP/REST reverse proxying preserving the negotiated HTTP version.
    Http(Version),
    /// Binary HTTP/2 gRPC passthrough enforcing `HTTP/2`, `TE: trailers`, and gRPC Trailers-Only error frames.
    GrpcPassthrough,
}

impl ProxyMode {
    #[inline]
    fn label(self) -> &'static str {
        match self {
            Self::Http(_) => "HTTP",
            Self::GrpcPassthrough => "gRPC",
        }
    }

    #[inline]
    fn can_retry(
        self,
        is_stream: bool,
        is_idempotent: bool,
        attempts: usize,
        max_retries: usize,
        reason: RetryReason,
    ) -> bool {
        if is_stream || attempts > max_retries {
            return false;
        }
        match self {
            Self::Http(_) => is_idempotent,
            // gRPC passthrough calls are always POST and may be non-idempotent mutations;
            // only retry on connect failures where the upstream never received the request.
            Self::GrpcPassthrough => reason == RetryReason::ConnectError,
        }
    }

    #[inline]
    fn is_outlier(self, status: StatusCode, headers: &hyper::HeaderMap) -> bool {
        match self {
            Self::Http(_) => super::circuit_breaker::is_outlier_status(status),
            Self::GrpcPassthrough => super::circuit_breaker::is_grpc_outlier_response(status, headers),
        }
    }

    fn apply_protocol_headers(self, req: &mut Request<ServiceRespBody>) {
        match self {
            Self::Http(version) => {
                *req.version_mut() = version;
            }
            Self::GrpcPassthrough => {
                *req.version_mut() = Version::HTTP_2;
                let headers = req.headers_mut();
                // Strip hop-by-hop headers that hyper's HTTP/2 client strictly rejects
                headers.remove(header::CONNECTION);
                headers.remove(header::TRANSFER_ENCODING);
                headers.remove(header::UPGRADE);
                headers.remove(header::TE);
                headers.insert(header::TE, header::HeaderValue::from_static("trailers"));
            }
        }
    }

    fn build_error(
        self,
        msg: &str,
        http_status: StatusCode,
        grpc_status_code: &'static str,
    ) -> Response<ServiceRespBody> {
        match self {
            Self::Http(_) => build_error_response(msg, http_status),
            Self::GrpcPassthrough => build_grpc_error_response(msg, http_status, grpc_status_code),
        }
    }
}

/// Builds a gRPC-compliant Trailers-Only error response (`content-type: application/grpc`,
/// `grpc-status`, `grpc-message`, and an empty body) so native gRPC clients (e.g. Tonic)
/// never attempt to parse a plain-text error string as a 5-byte length-prefixed Protobuf frame.
fn build_grpc_error_response(
    msg: &str,
    http_status: StatusCode,
    grpc_status_code: &'static str,
) -> Response<ServiceRespBody> {
    let body = http_body_util::Empty::<bytes::Bytes>::new()
        .map_err(SrvError::from)
        .boxed();
    let mut res = Response::new(body);
    *res.status_mut() = http_status;
    let headers = res.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/grpc"),
    );
    if let Ok(code_val) = header::HeaderValue::from_str(grpc_status_code) {
        headers.insert("grpc-status", code_val);
    }
    if let Ok(msg_val) = header::HeaderValue::from_str(msg) {
        headers.insert("grpc-message", msg_val);
    }
    res
}

/// Forwards an HTTP/REST request to a load-balanced upstream pool with 3-state circuit breaking,
/// passive outlier detection, idempotent failover retries, and client-error isolation.
#[allow(clippy::too_many_arguments)]
pub async fn handle_http_proxy(
    target: &Arc<RouteTarget>,
    request_body: RequestBody,
    original_method: Method,
    original_version: Version,
    prepared_headers: hyper::HeaderMap,
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
    forward_with_failover(
        ProxyMode::Http(original_version),
        target,
        request_body,
        original_method,
        prepared_headers,
        original_uri,
        matched_params,
        client_addr,
        server_name,
        client,
        request_timeout,
    )
    .await
}

/// Shared upstream forwarding engine used by both HTTP/REST proxying (`handle_http_proxy`)
/// and binary HTTP/2 gRPC passthrough (`handle_grpc_passthrough`).
#[allow(clippy::too_many_arguments)]
pub(super) async fn forward_with_failover(
    mode: ProxyMode,
    target: &Arc<RouteTarget>,
    mut request_body: RequestBody,
    original_method: Method,
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
    let is_multi_node = target.upstreams.len() > 1;
    // Fast-path: if only 1 backend is configured, disable failover retries (no alternate node exists)
    let max_retries = if is_multi_node {
        target.max_retries.min(target.upstreams.len() - 1)
    } else {
        0
    };
    let mut attempts = 0;
    let is_stream = matches!(request_body, RequestBody::Stream(_));
    let is_idempotent = matches!(
        original_method,
        Method::GET | Method::HEAD | Method::PUT | Method::DELETE | Method::OPTIONS
    );
    let proto_label = mode.label();

    loop {
        let mut current_headers = if attempts == max_retries {
            std::mem::take(&mut prepared_headers)
        } else {
            prepared_headers.clone()
        };
        attempts += 1;

        let upstream_node = target.next_upstream(client_addr.as_ref(), &failed_nodes);
        let backend_base_uri = &upstream_node.uri;
        let mut probe_guard = is_multi_node.then(|| {
            super::circuit_breaker::ProbeGuard::new(upstream_node, target.cooldown_seconds)
        });
        let conn_guard = ConnectionGuard::new(target.clone(), backend_base_uri.clone());

        let target_uri = build_upstream_uri(backend_base_uri, matched_params, original_uri)?;

        if let Some(auth) = target_uri.authority()
            && let Ok(host_val) = header::HeaderValue::from_str(auth.as_str())
        {
            current_headers.insert(header::HOST, host_val);
        }

        let body_error = Arc::new(std::sync::Mutex::new(None));
        let boxed_body: ServiceRespBody = match std::mem::replace(
            &mut request_body,
            RequestBody::Buffered(bytes::Bytes::new()),
        ) {
            RequestBody::Stream(taken_body) => BodyErrorTracker {
                inner: taken_body,
                last_error: body_error.clone(),
            }
            .boxed(),
            RequestBody::Buffered(bytes) => {
                let boxed = Full::new(bytes.clone()).map_err(SrvError::from).boxed();
                request_body = RequestBody::Buffered(bytes);
                boxed
            }
        };

        let mut proxy_req = Request::new(boxed_body);
        *proxy_req.method_mut() = original_method.clone();
        *proxy_req.uri_mut() = target_uri;
        *proxy_req.headers_mut() = current_headers;
        mode.apply_protocol_headers(&mut proxy_req);

        // Inject OpenTelemetry context (e.g., traceparent) into the outgoing request headers.
        opentelemetry::global::get_text_map_propagator(|propagator| {
            use tracing_opentelemetry::OpenTelemetrySpanExt;
            propagator.inject_context(
                &tracing::Span::current().context(),
                &mut opentelemetry_http::HeaderInjector(proxy_req.headers_mut()),
            );
        });

        let req_start = std::time::Instant::now();
        let req_fut = client.request(proxy_req);
        let resp_result = if let Some(timeout_dur) = request_timeout {
            match tokio::time::timeout(timeout_dur, req_fut).await {
                Ok(res) => res,
                Err(_elapsed) => {
                    error!(
                        "{}: Upstream {} request timed out after {:?} for {}",
                        server_name, proto_label, timeout_dur, backend_base_uri
                    );
                    if let Some(ref mut pg) = probe_guard {
                        pg.complete();
                    }
                    target.mark_dead(backend_base_uri);
                    failed_nodes.push(backend_base_uri.clone());

                    if mode.can_retry(
                        is_stream,
                        is_idempotent,
                        attempts,
                        max_retries,
                        RetryReason::Timeout,
                    ) {
                        upstream_node
                            .failover_retries
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        warn!(
                            "{}: [CIRCUIT BREAKER] Failover retry ({}/{}) after timed-out {} request on {}...",
                            server_name, attempts, max_retries, proto_label, backend_base_uri
                        );
                        continue;
                    } else {
                        if ((matches!(mode, ProxyMode::Http(_)) && !is_idempotent)
                            || matches!(mode, ProxyMode::GrpcPassthrough))
                            && !is_stream
                            && attempts <= max_retries
                        {
                            warn!(
                                "{}: Non-idempotent {} request timed out on {}; skipping retry to prevent side-effects",
                                server_name, original_method, backend_base_uri
                            );
                        } else if is_stream && attempts <= max_retries {
                            warn!(
                                "{}: Streaming {} request timed out on {}; cannot retry consumed stream",
                                server_name, proto_label, backend_base_uri
                            );
                        }
                        return Ok(mode.build_error(
                            "Gateway Timeout",
                            StatusCode::GATEWAY_TIMEOUT,
                            "4", // DEADLINE_EXCEEDED
                        ));
                    }
                }
            }
        } else {
            req_fut.await
        };

        match resp_result {
            Ok(res) => {
                upstream_node.record_latency_ms(req_start.elapsed().as_millis() as u64);
                if let Some(ref mut pg) = probe_guard {
                    pg.complete();
                }
                if mode.is_outlier(res.status(), res.headers()) {
                    let status = res.status();
                    let tripped = target.record_failure(backend_base_uri);
                    if is_multi_node {
                        failed_nodes.push(backend_base_uri.clone());
                    }

                    if tripped {
                        warn!(
                            "{}: Upstream {} {} returned outlier status (HTTP {}, grpc-status {:?}) — circuit breaker tripped to OPEN",
                            server_name,
                            proto_label,
                            backend_base_uri,
                            status,
                            res.headers().get("grpc-status")
                        );
                    } else {
                        warn!(
                            "{}: Upstream {} {} returned outlier status {} (consecutive failures: {}/{})",
                            server_name,
                            proto_label,
                            backend_base_uri,
                            status,
                            upstream_node
                                .consecutive_failures
                                .load(std::sync::atomic::Ordering::Relaxed),
                            target.failure_threshold
                        );
                    }

                    if mode.can_retry(
                        is_stream,
                        is_idempotent,
                        attempts,
                        max_retries,
                        RetryReason::Outlier,
                    ) {
                        upstream_node
                            .failover_retries
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        warn!(
                            "{}: [CIRCUIT BREAKER] Failover retry ({}/{}) after upstream {} outlier from {}...",
                            server_name, attempts, max_retries, status, backend_base_uri
                        );
                        continue;
                    }

                    let (mut res_parts, res_body) = res.into_parts();
                    super::headers::clean_response_headers(&mut res_parts.headers);
                    return Ok(Response::from_parts(
                        res_parts,
                        TrackedBody::new(res_body.map_err(SrvError::from), conn_guard).boxed(),
                    ));
                }

                upstream_node.record_success();
                let (mut res_parts, res_body) = res.into_parts();
                super::headers::clean_response_headers(&mut res_parts.headers);
                return Ok(Response::from_parts(
                    res_parts,
                    TrackedBody::new(res_body.map_err(SrvError::from), conn_guard).boxed(),
                ));
            }
            Err(e) => {
                let client_error = body_error.lock().ok().and_then(|mut g| g.take());
                let error_kind = if let Some(srv_err) = client_error {
                    match srv_err {
                        SrvError::PayloadTooLarge { .. } => ProxyErrorKind::PayloadTooLarge,
                        SrvError::DecompressionLimitExceeded { .. } => {
                            ProxyErrorKind::DecompressionLimitExceeded
                        }
                        SrvError::ClientAborted(reason) => ProxyErrorKind::ClientAborted(reason),
                        _ => ProxyErrorKind::ClientAborted("Client stream error".to_string()),
                    }
                } else {
                    classify_proxy_error(&e)
                };
                match error_kind {
                    ProxyErrorKind::PayloadTooLarge => {
                        warn!(
                            "{}: Client {} request payload exceeded limit during proxying to {}",
                            server_name, proto_label, backend_base_uri
                        );
                        return Ok(mode.build_error(
                            "Payload Too Large",
                            StatusCode::PAYLOAD_TOO_LARGE,
                            "8", // RESOURCE_EXHAUSTED
                        ));
                    }
                    ProxyErrorKind::DecompressionLimitExceeded => {
                        warn!(
                            "{}: Client {} request decompressed payload exceeded limit during proxying to {}",
                            server_name, proto_label, backend_base_uri
                        );
                        return Ok(mode.build_error(
                            "Payload Too Large",
                            StatusCode::PAYLOAD_TOO_LARGE,
                            "8", // RESOURCE_EXHAUSTED
                        ));
                    }
                    ProxyErrorKind::ClientAborted(ref reason) => {
                        warn!(
                            "{}: Client aborted {} request stream during proxying to {}: {}",
                            server_name, proto_label, backend_base_uri, reason
                        );
                        return Ok(mode.build_error(
                            "Client Closed Request",
                            StatusCode::BAD_REQUEST,
                            "1", // CANCELLED
                        ));
                    }
                    ProxyErrorKind::UpstreamFailure => {
                        error!(
                            "{}: Backend connection failed to {}: {}",
                            server_name, backend_base_uri, e
                        );
                        if let Some(ref mut pg) = probe_guard {
                            pg.complete();
                        }
                        target.mark_dead(backend_base_uri);
                        failed_nodes.push(backend_base_uri.clone());

                        let retry_reason = if e.is_connect() {
                            RetryReason::ConnectError
                        } else {
                            RetryReason::PostSendFailure
                        };
                        if mode.can_retry(
                            is_stream,
                            is_idempotent,
                            attempts,
                            max_retries,
                            retry_reason,
                        ) {
                            upstream_node
                                .failover_retries
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            warn!(
                                "{}: [CIRCUIT BREAKER] Failover retry ({}/{}) switching away from {}...",
                                server_name, attempts, max_retries, backend_base_uri
                            );
                            continue;
                        } else {
                            if ((matches!(mode, ProxyMode::Http(_)) && !is_idempotent)
                                || matches!(mode, ProxyMode::GrpcPassthrough))
                                && !is_stream
                                && attempts <= max_retries
                            {
                                warn!(
                                    "{}: Non-idempotent {} request failed on {}; skipping retry to prevent duplicate side-effects",
                                    server_name, original_method, backend_base_uri
                                );
                            } else if is_stream && attempts <= max_retries {
                                warn!(
                                    "{}: Streaming {} request failed on {}; cannot retry consumed stream",
                                    server_name, proto_label, backend_base_uri
                                );
                            }
                            error!(
                                "{}: Max retries reached or request not retryable (proto={}, stream={}, idempotent={}). Returning 502 Bad Gateway.",
                                server_name, proto_label, is_stream, is_idempotent
                            );
                            return Ok(mode.build_error(
                                "Bad Gateway",
                                StatusCode::BAD_GATEWAY,
                                "14", // UNAVAILABLE
                            ));
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

        if let Some(hyper_err) = e.downcast_ref::<hyper::Error>()
            && (hyper_err.is_user() || hyper_err.is_body_write_aborted()) {
                is_user_body = true;
            }

        if is_user_body
            && let Some(io_err) = e.downcast_ref::<std::io::Error>() {
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
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use crate::configuration::{LbStrategy, RouteTarget, UpstreamNode};

    #[tokio::test]
    async fn test_http_proxy_request_timeout_returns_504() {
        let _ = rustls::crypto::ring::default_provider().install_default();
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
        let node = UpstreamNode::new(upstream_uri.clone());

        let target = Arc::new(RouteTarget {
            upstreams: vec![node],
            strategy: LbStrategy::RoundRobin,
            rr_counter: AtomicUsize::new(0),
            cooldown_seconds: 10,
            max_retries: 0,
            failure_threshold: 3,
            max_retry_buffer_bytes: 65536,
            active_health_check_interval: 0,
            grpc_pool: tokio::sync::RwLock::new(None),
            grpc_reflection_lock: tokio::sync::Mutex::new(()),
        });


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
            &target,
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
        let node = UpstreamNode::new(upstream_uri.clone());

        let target = Arc::new(RouteTarget {
            upstreams: vec![node],
            strategy: LbStrategy::RoundRobin,
            rr_counter: AtomicUsize::new(0),
            cooldown_seconds: 60,
            max_retries: 0,
            failure_threshold: 3,
            max_retry_buffer_bytes: 65536,
            active_health_check_interval: 0,
            grpc_pool: tokio::sync::RwLock::new(None),
            grpc_reflection_lock: tokio::sync::Mutex::new(()),
        });


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
            &target,
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
        let node = UpstreamNode::new(upstream_uri.clone());

        let target = Arc::new(RouteTarget {
            upstreams: vec![node],
            strategy: LbStrategy::RoundRobin,
            rr_counter: AtomicUsize::new(0),
            cooldown_seconds: 60,
            max_retries: 0,
            failure_threshold: 3,
            max_retry_buffer_bytes: 65536,
            active_health_check_interval: 0,
            grpc_pool: tokio::sync::RwLock::new(None),
            grpc_reflection_lock: tokio::sync::Mutex::new(()),
        });


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
            &target,
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
        let _ = rustls::crypto::ring::default_provider().install_default();
        // Pick an unused port without starting a server
        let port = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            listener.local_addr().unwrap().port()
        };

        let upstream_uri: Uri = format!("http://127.0.0.1:{}", port).parse().unwrap();
        let node = UpstreamNode::new(upstream_uri.clone());

        let target = Arc::new(RouteTarget {
            upstreams: vec![node],
            strategy: LbStrategy::RoundRobin,
            rr_counter: AtomicUsize::new(0),
            cooldown_seconds: 60,
            max_retries: 0,
            failure_threshold: 3,
            max_retry_buffer_bytes: 65536,
            active_health_check_interval: 0,
            grpc_pool: tokio::sync::RwLock::new(None),
            grpc_reflection_lock: tokio::sync::Mutex::new(()),
        });


        let root_store = rustls::RootCertStore::empty();
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let client = common::client::build_hyper_client(tls_config, common::client::ClientPoolConfig::default());

        let matched_params = matchit::Params::new();
        let req_uri: Uri = "http://localhost/api/test".parse().unwrap();
        let prepared_headers = hyper::HeaderMap::new();

        let response = handle_http_proxy(
            &target,
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
        let node = UpstreamNode::new(upstream_uri.clone());

        let target = Arc::new(RouteTarget {
            upstreams: vec![node],
            strategy: LbStrategy::RoundRobin,
            rr_counter: AtomicUsize::new(0),
            cooldown_seconds: 60,
            max_retries: 0,
            failure_threshold: 3,
            max_retry_buffer_bytes: 65536,
            active_health_check_interval: 0,
            grpc_pool: tokio::sync::RwLock::new(None),
            grpc_reflection_lock: tokio::sync::Mutex::new(()),
        });


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
            &target,
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

    /// Regression test for [F-10]: a raw `std::io::Error` (e.g. `ConnectionReset`) caused by the
    /// *upstream* socket must be classified as an upstream failure (502 + node marked dead),
    /// not as a client abort (400).
    #[tokio::test]
    async fn test_http_proxy_upstream_tcp_reset_returns_502_and_marks_node_dead() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                use tokio::io::AsyncReadExt;
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                // SO_LINGER=0 turns the close into a TCP RST (ConnectionReset on the proxy side).
                #[allow(deprecated)]
                let _ = socket.set_linger(Some(Duration::ZERO));
                drop(socket);
            }
        });

        let upstream_uri: Uri = format!("http://127.0.0.1:{}", port).parse().unwrap();
        let node = UpstreamNode::new(upstream_uri.clone());

        let target = Arc::new(RouteTarget {
            upstreams: vec![node],
            strategy: LbStrategy::RoundRobin,
            rr_counter: AtomicUsize::new(0),
            cooldown_seconds: 60,
            max_retries: 0,
            failure_threshold: 3,
            max_retry_buffer_bytes: 65536,
            active_health_check_interval: 0,
            grpc_pool: tokio::sync::RwLock::new(None),
            grpc_reflection_lock: tokio::sync::Mutex::new(()),
        });


        let root_store = rustls::RootCertStore::empty();
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let client = common::client::build_hyper_client(tls_config, common::client::ClientPoolConfig::default());

        let matched_params = matchit::Params::new();
        let req_uri: Uri = "http://localhost/api/reset".parse().unwrap();

        let response = handle_http_proxy(
            &target,
            RequestBody::Buffered(bytes::Bytes::new()),
            Method::GET,
            Version::HTTP_11,
            hyper::HeaderMap::new(),
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
            "Upstream node MUST be marked dead when the upstream socket resets"
        );
    }

    #[tokio::test]
    async fn test_http_proxy_outlier_503_retries_on_healthy_node_and_trips_circuit_breaker() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Node 1 returns 503 Service Unavailable
        let listener1 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port1 = listener1.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener1.accept().await {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let _ = socket
                    .write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 11\r\n\r\nOverloaded!")
                    .await;
            }
        });

        // Node 2 returns 200 OK
        let listener2 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port2 = listener2.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener2.accept().await {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let _ = socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nrecovered")
                    .await;
            }
        });

        let node1 = UpstreamNode::new(format!("http://127.0.0.1:{}", port1).parse().unwrap());
        let node2 = UpstreamNode::new(format!("http://127.0.0.1:{}", port2).parse().unwrap());

        let target = Arc::new(RouteTarget {
            upstreams: vec![node1, node2],
            strategy: LbStrategy::RoundRobin,
            rr_counter: AtomicUsize::new(0),
            cooldown_seconds: 60,
            max_retries: 1,
            failure_threshold: 2,
            max_retry_buffer_bytes: 65536,
            active_health_check_interval: 0,
            grpc_pool: tokio::sync::RwLock::new(None),
            grpc_reflection_lock: tokio::sync::Mutex::new(()),
        });


        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let client = common::client::build_hyper_client(
            tls_config,
            common::client::ClientPoolConfig::default(),
        );
        let matched_params = matchit::Params::new();
        let req_uri: Uri = "http://localhost/api/items".parse().unwrap();

        // Request 1: hits node 1 (503) -> automatically retries on node 2 (200 OK)
        let resp1 = handle_http_proxy(
            &target,
            RequestBody::Buffered(bytes::Bytes::new()),
            Method::GET,
            Version::HTTP_11,
            hyper::HeaderMap::new(),
            &req_uri,
            &matched_params,
            None,
            "test_server",
            &client,
            Some(Duration::from_secs(5)),
        )
        .await
        .unwrap();

        assert_eq!(resp1.status(), StatusCode::OK);
        assert_eq!(target.upstreams[0].consecutive_failures.load(Ordering::Relaxed), 1);
        // Threshold is 2, so node 1 is still Closed after 1st 503
        assert!(target.upstreams[0].is_alive.load(Ordering::Relaxed));

        // Reset rr_counter to 0 so Request 2 hits node 1 again
        target.rr_counter.store(0, Ordering::Relaxed);

        // Request 2: hits node 1 (503 #2 -> trips circuit breaker to Open!) and retries on node 2 (200 OK)
        let resp2 = handle_http_proxy(
            &target,
            RequestBody::Buffered(bytes::Bytes::new()),
            Method::GET,
            Version::HTTP_11,
            hyper::HeaderMap::new(),
            &req_uri,
            &matched_params,
            None,
            "test_server",
            &client,
            Some(Duration::from_secs(5)),
        )
        .await
        .unwrap();

        assert_eq!(resp2.status(), StatusCode::OK);
        assert!(!target.upstreams[0].is_alive.load(Ordering::Relaxed), "Node 1 circuit must be Open after reaching failure_threshold=2");
        assert_eq!(
            target.upstreams[0].circuit_state(),
            super::super::circuit_breaker::CircuitState::Open
        );
    }

    /// Retry policy matrix of the shared proxy engine: HTTP retries only idempotent, buffered
    /// requests; gRPC passthrough retries only connect-time failures (where the request was never
    /// sent to the upstream); neither retries consumed streams nor exceeds `max_retries`.
    #[test]
    fn test_proxy_mode_retry_policy_matrix() {
        let http = ProxyMode::Http(Version::HTTP_11);
        let grpc = ProxyMode::GrpcPassthrough;

        // (is_stream, is_idempotent, attempts, max_retries, reason)
        assert!(http.can_retry(false, true, 1, 2, RetryReason::Timeout), "HTTP idempotent buffered => retry");
        assert!(!http.can_retry(false, false, 1, 2, RetryReason::ConnectError), "HTTP non-idempotent => never retry");
        assert!(!http.can_retry(true, true, 1, 2, RetryReason::ConnectError), "HTTP stream => never retry");
        assert!(!http.can_retry(false, true, 3, 2, RetryReason::ConnectError), "HTTP retries exhausted");

        assert!(grpc.can_retry(false, false, 1, 2, RetryReason::ConnectError), "gRPC buffered connect error => retry");
        assert!(grpc.can_retry(false, true, 2, 2, RetryReason::ConnectError), "gRPC last permitted connect retry");
        assert!(!grpc.can_retry(false, false, 1, 2, RetryReason::Timeout), "gRPC timeout after connect => never retry");
        assert!(!grpc.can_retry(false, false, 1, 2, RetryReason::PostSendFailure), "gRPC post-send failure => never retry");
        assert!(!grpc.can_retry(false, false, 1, 2, RetryReason::Outlier), "gRPC outlier => never retry");
        assert!(!grpc.can_retry(true, false, 1, 2, RetryReason::ConnectError), "gRPC stream => never retry");
        assert!(!grpc.can_retry(false, false, 3, 2, RetryReason::ConnectError), "gRPC retries exhausted");
    }

    /// Protocol header rules: HTTP preserves the negotiated version and headers untouched;
    /// gRPC passthrough enforces HTTP/2, strips hop-by-hop headers and sets `TE: trailers`.
    #[test]
    fn test_proxy_mode_protocol_headers_and_error_format() {
        let make_req = || {
            let body: ServiceRespBody = Full::new(bytes::Bytes::new()).map_err(SrvError::from).boxed();
            let mut req = Request::new(body);
            *req.version_mut() = Version::HTTP_11;
            for (k, v) in [("connection", "keep-alive"), ("upgrade", "h2c"), ("te", "gzip")] {
                req.headers_mut().insert(
                    header::HeaderName::from_static(k),
                    header::HeaderValue::from_static(v),
                );
            }
            req
        };

        let mut http_req = make_req();
        ProxyMode::Http(Version::HTTP_11).apply_protocol_headers(&mut http_req);
        assert_eq!(http_req.version(), Version::HTTP_11);
        assert!(http_req.headers().contains_key(header::CONNECTION));

        let mut grpc_req = make_req();
        ProxyMode::GrpcPassthrough.apply_protocol_headers(&mut grpc_req);
        assert_eq!(grpc_req.version(), Version::HTTP_2);
        assert!(!grpc_req.headers().contains_key(header::CONNECTION));
        assert!(!grpc_req.headers().contains_key(header::UPGRADE));
        assert_eq!(grpc_req.headers().get(header::TE).unwrap(), "trailers");

        // Error format: plain HTTP vs. gRPC Trailers-Only.
        let http_err = ProxyMode::Http(Version::HTTP_11).build_error("Bad Gateway", StatusCode::BAD_GATEWAY, "14");
        assert_eq!(http_err.status(), StatusCode::BAD_GATEWAY);
        assert!(!http_err.headers().contains_key("grpc-status"));

        let grpc_err = ProxyMode::GrpcPassthrough.build_error("Bad Gateway", StatusCode::BAD_GATEWAY, "14");
        assert_eq!(grpc_err.headers().get("grpc-status").unwrap(), "14");
        assert_eq!(grpc_err.headers().get(header::CONTENT_TYPE).unwrap(), "application/grpc");
    }
}

