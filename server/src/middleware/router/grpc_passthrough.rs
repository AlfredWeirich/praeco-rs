use hyper::{Method, Response, Uri};
use hyper_util::client::legacy::Client;
use std::sync::Arc;

use super::RequestBody;
use super::http_proxy::{ProxyMode, forward_with_failover};
use crate::{ServiceRespBody, SrvError, configuration::RouteTarget};

/// Forwards a binary HTTP/2 gRPC request (`backend_type = "grpc_passthrough"`) through the
/// shared failover/circuit-breaker proxy engine with `HTTP/2` enforcement, `TE: trailers`,
/// gRPC outlier detection, and gRPC Trailers-Only error responses.
#[allow(clippy::too_many_arguments)]
pub async fn handle_grpc_passthrough(
    target: &Arc<RouteTarget>,
    request_body: RequestBody,
    original_method: Method,
    prepared_headers: hyper::HeaderMap,
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
    forward_with_failover(
        ProxyMode::GrpcPassthrough,
        target,
        request_body,
        original_method,
        prepared_headers,
        original_uri,
        matched_params,
        client_addr,
        server_name,
        grpc_client,
        request_timeout,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::{LbStrategy, RouteTarget, UpstreamNode};
    use http_body_util::BodyExt;
    use hyper::StatusCode;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

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
            &target,
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
            &target,
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
            &target,
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


