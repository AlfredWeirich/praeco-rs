use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Response, StatusCode, Uri, header};
use hyper_util::client::legacy::Client;
use std::sync::Arc;
use tracing::{error, warn};

use super::upstreams::{ConnectionGuard, TrackedBody, build_upstream_uri};
use super::RequestBody;
use crate::{ServiceRespBody, SrvError, configuration::ParsedRoute};

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
    Response::builder()
        .status(http_status)
        .header(header::CONTENT_TYPE, "application/grpc")
        .header("grpc-status", grpc_status_code)
        .header("grpc-message", msg)
        .body(body)
        .expect("gRPC error response builder failed")
}

pub async fn handle_grpc_passthrough(
    route_info: &ParsedRoute,
    mut request_body: RequestBody,
    original_method: Method,
    mut prepared_headers: hyper::HeaderMap,
    original_uri: &Uri,
    matched_params: &matchit::Params<'_, '_>,
    client_addr: Option<std::net::SocketAddr>,
    server_name: &str,
    grpc_client: &Client<
        common::client::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        ServiceRespBody,
    >,
    request_timeout: Option<std::time::Duration>,
) -> Result<Response<ServiceRespBody>, SrvError> {
    let mut failed_nodes = Vec::new();
    let is_multi_node = route_info.target.upstreams.len() > 1;
    let max_retries = if is_multi_node {
        route_info
            .target
            .max_retries
            .min(route_info.target.upstreams.len() - 1)
    } else {
        0
    };
    let mut attempts = 0;
    let is_stream = matches!(request_body, RequestBody::Stream(_));

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
        let mut probe_guard = is_multi_node.then(|| {
            super::circuit_breaker::ProbeGuard::new(
                upstream_node,
                route_info.target.cooldown_seconds,
            )
        });
        let conn_guard = ConnectionGuard::new(route_info.target.clone(), backend_base_uri.clone());

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
                    super::http_proxy::BodyErrorTracker {
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

        *proxy_req.version_mut() = hyper::Version::HTTP_2;
        // Strip hop-by-hop headers that hyper's HTTP/2 client strictly rejects
        current_headers.remove(hyper::header::CONNECTION);
        current_headers.remove(hyper::header::TRANSFER_ENCODING);
        current_headers.remove(hyper::header::UPGRADE);
        current_headers.remove(hyper::header::TE); // TE is allowed in HTTP/2 only if it is "trailers"
        current_headers.insert(
            hyper::header::TE,
            hyper::header::HeaderValue::from_static("trailers"),
        );

        *proxy_req.headers_mut() = current_headers;

        // Inject OpenTelemetry context (e.g., traceparent) into the outgoing request headers.
        opentelemetry::global::get_text_map_propagator(|propagator| {
            use tracing_opentelemetry::OpenTelemetrySpanExt;
            propagator.inject_context(
                &tracing::Span::current().context(),
                &mut opentelemetry_http::HeaderInjector(proxy_req.headers_mut()),
            );
        });

        let req_start = std::time::Instant::now();
        let req_fut = grpc_client.request(proxy_req);
        let resp_result = if let Some(timeout_dur) = request_timeout {
            match tokio::time::timeout(timeout_dur, req_fut).await {
                Ok(res) => res,
                Err(_elapsed) => {
                    error!(
                        "{}: Upstream gRPC request timed out after {:?} for {}",
                        server_name, timeout_dur, backend_base_uri
                    );
                    if let Some(ref mut pg) = probe_guard {
                        pg.complete();
                    }
                    route_info.target.mark_dead(backend_base_uri);
                    failed_nodes.push(backend_base_uri.clone());

                    if !is_stream && attempts <= max_retries {
                        upstream_node
                            .failover_retries
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        warn!(
                            "{}: [CIRCUIT BREAKER] Failover retry ({}/{}) after timed-out gRPC request on {}...",
                            server_name, attempts, max_retries, backend_base_uri
                        );
                        continue;
                    } else {
                        if is_stream && attempts <= max_retries {
                            warn!(
                                "{}: Streaming gRPC request timed out on {}; cannot retry consumed stream",
                                server_name, backend_base_uri
                            );
                        }
                        return Ok(build_grpc_error_response(
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
                if super::circuit_breaker::is_grpc_outlier_response(res.status(), res.headers()) {
                    let status = res.status();
                    let tripped = route_info.target.record_failure(backend_base_uri);
                    if is_multi_node {
                        failed_nodes.push(backend_base_uri.clone());
                    }

                    if tripped {
                        warn!(
                            "{}: Upstream gRPC {} returned outlier status (HTTP {}, grpc-status {:?}) — circuit breaker tripped to OPEN",
                            server_name,
                            backend_base_uri,
                            status,
                            res.headers().get("grpc-status")
                        );
                    } else {
                        warn!(
                            "{}: Upstream gRPC {} returned outlier status (HTTP {}, grpc-status {:?})",
                            server_name,
                            backend_base_uri,
                            status,
                            res.headers().get("grpc-status")
                        );
                    }

                    if !is_stream && attempts <= max_retries {
                        upstream_node
                            .failover_retries
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        warn!(
                            "{}: [CIRCUIT BREAKER] Failover retry ({}/{}) after upstream outlier from {}...",
                            server_name, attempts, max_retries, backend_base_uri
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
                        SrvError::PayloadTooLarge { .. } => super::http_proxy::ProxyErrorKind::PayloadTooLarge,
                        SrvError::DecompressionLimitExceeded { .. } => {
                            super::http_proxy::ProxyErrorKind::DecompressionLimitExceeded
                        }
                        SrvError::ClientAborted(reason) => super::http_proxy::ProxyErrorKind::ClientAborted(reason),
                        _ => super::http_proxy::ProxyErrorKind::ClientAborted("Client stream error".to_string()),
                    }
                } else {
                    super::http_proxy::classify_proxy_error(&e)
                };
                match error_kind {
                    super::http_proxy::ProxyErrorKind::PayloadTooLarge => {
                        warn!(
                            "{}: Client gRPC request payload exceeded limit during proxying to {}",
                            server_name, backend_base_uri
                        );
                        return Ok(build_grpc_error_response(
                            "Payload Too Large",
                            StatusCode::PAYLOAD_TOO_LARGE,
                            "8", // RESOURCE_EXHAUSTED
                        ));
                    }
                    super::http_proxy::ProxyErrorKind::DecompressionLimitExceeded => {
                        warn!(
                            "{}: Client gRPC request decompressed payload exceeded limit during proxying to {}",
                            server_name, backend_base_uri
                        );
                        return Ok(build_grpc_error_response(
                            "Payload Too Large",
                            StatusCode::PAYLOAD_TOO_LARGE,
                            "8", // RESOURCE_EXHAUSTED
                        ));
                    }
                    super::http_proxy::ProxyErrorKind::ClientAborted(ref reason) => {
                        warn!(
                            "{}: Client aborted gRPC request stream during proxying to {}: {}",
                            server_name, backend_base_uri, reason
                        );
                        return Ok(build_grpc_error_response(
                            "Client Closed Request",
                            StatusCode::BAD_REQUEST,
                            "1", // CANCELLED
                        ));
                    }
                    super::http_proxy::ProxyErrorKind::UpstreamFailure => {
                        error!(
                            "{}: Backend connection failed to {}: {}",
                            server_name, backend_base_uri, e
                        );
                        if let Some(ref mut pg) = probe_guard {
                            pg.complete();
                        }
                        route_info.target.mark_dead(backend_base_uri);
                        failed_nodes.push(backend_base_uri.clone());

                        if !is_stream && attempts <= max_retries {
                            upstream_node
                                .failover_retries
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            warn!(
                                "{}: [CIRCUIT BREAKER] Failover retry ({}/{}) switching away from {}...",
                                server_name, attempts, max_retries, backend_base_uri
                            );
                            continue;
                        } else {
                            if is_stream && attempts <= max_retries {
                                warn!(
                                    "{}: Streaming gRPC request failed on {}; cannot retry consumed stream",
                                    server_name, backend_base_uri
                                );
                            }
                            error!(
                                "{}: Max retries reached or stream not retryable. Returning 502 Bad Gateway.",
                                server_name
                            );
                            return Ok(build_grpc_error_response(
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use crate::configuration::{LbStrategy, RouteBackendType, RouteTarget, UpstreamNode};

    #[tokio::test]
    async fn test_grpc_passthrough_request_timeout_returns_504() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // Spawn a slow upstream that delays responding
        tokio::spawn(async move {
            if let Ok((_socket, _)) = listener.accept().await {
                tokio::time::sleep(Duration::from_millis(300)).await;
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

        let route_info = ParsedRoute {
            prefix: "/chat.ChatService".to_string(),
            target: target.clone(),
            allowed_roles: Vec::new(),
            backend_type: RouteBackendType::GrpcPassthrough,
        };

        let root_store = rustls::RootCertStore::empty();
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let pool_config = common::client::ClientPoolConfig {
            http2_only: true,
            ..Default::default()
        };
        let client = common::client::build_hyper_client(tls_config, pool_config);

        let req_uri: Uri = "http://localhost/chat.ChatService/SendMessage".parse().unwrap();
        let prepared_headers = hyper::HeaderMap::new();
        let matched_params = matchit::Params::new();

        let response = handle_grpc_passthrough(
            &route_info,
            RequestBody::Buffered(bytes::Bytes::new()),
            Method::POST,
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
        assert_eq!(
            response.headers().get("grpc-status").and_then(|v| v.to_str().ok()),
            Some("4"),
            "504 timeout must return gRPC Trailers-Only DEADLINE_EXCEEDED (4)"
        );
        assert_eq!(
            response.headers().get(hyper::header::CONTENT_TYPE).and_then(|v| v.to_str().ok()),
            Some("application/grpc")
        );
        assert!(!target.upstreams[0].is_alive.load(Ordering::Relaxed), "Timed out gRPC node must be marked dead");
    }

    #[tokio::test]
    async fn test_grpc_passthrough_failover_from_dead_node_to_healthy_node() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();

        // Node 1: Dead port (bind and immediately drop so TCP connect refuses)
        let dead_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead_port = dead_listener.local_addr().unwrap().port();
        drop(dead_listener);

        // Node 2: Healthy HTTP/2 gRPC server
        let healthy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let healthy_port = healthy_listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((socket, _)) = healthy_listener.accept().await {
                let io = hyper_util::rt::TokioIo::new(socket);
                let _ = hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection(
                        io,
                        hyper::service::service_fn(|_req: hyper::Request<hyper::body::Incoming>| async move {
                            let res = hyper::Response::builder()
                                .status(StatusCode::OK)
                                .header("content-type", "application/grpc")
                                .header("grpc-status", "0")
                                .body(http_body_util::Empty::<bytes::Bytes>::new())
                                .unwrap();
                            Ok::<_, std::convert::Infallible>(res)
                        }),
                    )
                    .await;
            }
        });

        let dead_uri: Uri = format!("http://127.0.0.1:{}", dead_port).parse().unwrap();
        let healthy_uri: Uri = format!("http://127.0.0.1:{}", healthy_port).parse().unwrap();

        let target = Arc::new(RouteTarget {
            upstreams: vec![
                UpstreamNode::new(dead_uri),
                UpstreamNode::new(healthy_uri),
            ],
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

        let route_info = ParsedRoute {
            prefix: "/chat.ChatService".to_string(),
            target: target.clone(),
            allowed_roles: Vec::new(),
            backend_type: RouteBackendType::GrpcPassthrough,
        };

        let root_store = rustls::RootCertStore::empty();
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let pool_config = common::client::ClientPoolConfig {
            http2_only: true,
            ..Default::default()
        };
        let client = common::client::build_hyper_client(tls_config, pool_config);

        let req_uri: Uri = "http://localhost/chat.ChatService/StreamGlobalEvents".parse().unwrap();
        let prepared_headers = hyper::HeaderMap::new();
        let matched_params = matchit::Params::new();

        // Simulate bounded-buffered gRPC request frame (5-byte empty gRPC header)
        let grpc_frame = bytes::Bytes::from_static(&[0, 0, 0, 0, 0]);

        let response = handle_grpc_passthrough(
            &route_info,
            RequestBody::Buffered(grpc_frame),
            Method::POST,
            prepared_headers,
            &req_uri,
            &matched_params,
            None,
            "test_server",
            &client,
            Some(Duration::from_secs(2)),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), StatusCode::OK, "First request must transparently fail over from dead node to healthy node");
        assert!(!target.upstreams[0].is_alive.load(Ordering::Relaxed), "Dead node must be marked dead in Circuit Breaker");
        assert!(target.upstreams[1].is_alive.load(Ordering::Relaxed), "Healthy node must remain alive");
    }

    #[tokio::test]
    async fn test_grpc_passthrough_streaming_payload_too_large_returns_413_and_node_remains_alive() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // Spawn mock HTTP/2 upstream that accepts connection and reads body
        tokio::spawn(async move {
            if let Ok((socket, _)) = listener.accept().await {
                let io = hyper_util::rt::TokioIo::new(socket);
                let _ = hyper::server::conn::http2::Builder::new(hyper_util::rt::TokioExecutor::new())
                    .serve_connection(
                        io,
                        hyper::service::service_fn(|mut req: hyper::Request<hyper::body::Incoming>| async move {
                            use http_body_util::BodyExt;
                            while let Some(_) = req.frame().await {}
                            Ok::<_, std::convert::Infallible>(hyper::Response::new(http_body_util::Empty::<bytes::Bytes>::new()))
                        }),
                    )
                    .await;
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

        let route_info = ParsedRoute {
            prefix: "/chat.ChatService".to_string(),
            target: target.clone(),
            allowed_roles: Vec::new(),
            backend_type: RouteBackendType::GrpcPassthrough,
        };

        let root_store = rustls::RootCertStore::empty();
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let pool_config = common::client::ClientPoolConfig {
            http2_only: true,
            ..Default::default()
        };
        let client = common::client::build_hyper_client(tls_config, pool_config);

        let req_uri: Uri = "http://localhost/chat.ChatService/SendMessage".parse().unwrap();
        let prepared_headers = hyper::HeaderMap::new();
        let matched_params = matchit::Params::new();

        // Create a streaming body that errors out with PayloadTooLarge
        let err_stream = futures_util::stream::iter(vec![
            Ok(http_body::Frame::data(bytes::Bytes::from("grpc message chunk"))),
            Err(SrvError::PayloadTooLarge { current: 15, max: 10 }),
        ]);
        let body: ServiceRespBody = http_body_util::StreamBody::new(err_stream).boxed();

        let response = handle_grpc_passthrough(
            &route_info,
            RequestBody::Stream(body),
            Method::POST,
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
            "Upstream gRPC node must NOT be marked dead on client payload limit error"
        );
    }
}


