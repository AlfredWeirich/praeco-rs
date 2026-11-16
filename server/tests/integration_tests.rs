//! Integration Tests for `praeco-rs` (`server`).
//!
//! These tests verify the end-to-end assembly and execution of the Praeco Gateway
//! service stack (`build_service_stack`, `apply_layers`, `ConnectionHandler`,
//! `serve_http_connection`, `serve_tls_connection`, and `run_tunnel_over_stream`)
//! using realistic TOML configurations over in-memory `tokio::io::duplex` streams.

use std::net::SocketAddr;
use std::sync::{Arc, Once};

use arc_swap::ArcSwap;
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tokio_util::sync::CancellationToken;

use praeco_rs::{
    ConnectionHandler, build_rustls_config, build_service_stack,
    configuration::{Config, ServerConfig, TunnelConfig},
    connection_tracker::ConnectionTracker,
    run_tunnel_over_stream, serve_http_connection, serve_tls_connection,
};

static INIT_CRYPTO: Once = Once::new();

fn ensure_crypto_provider() {
    INIT_CRYPTO.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        praeco_rs::middleware::admin::init_process_start_time();
    });
}

/// Helper to parse a TOML configuration string and return the first finalized `ServerConfig`.
fn parse_server_config(toml_str: &str) -> Arc<ServerConfig> {
    ensure_crypto_provider();
    let mut config: Config = toml::from_str(toml_str).expect("valid test TOML config");
    for srv in config.servers.iter_mut() {
        srv.finalize().expect("ServerConfig::finalize must succeed");
    }
    Arc::new(config.servers.into_iter().next().expect("at least one [[Server]]"))
}

/// Helper to build a TLS client connector trusting `../server_certs/self_signed/public_ca.pem`.
fn build_public_tls_connector(alpn_protocols: Vec<Vec<u8>>) -> tokio_rustls::TlsConnector {
    ensure_crypto_provider();
    let mut root_store = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter("../server_certs/self_signed/public_ca.pem")
        .expect("read public_ca.pem")
    {
        root_store
            .add(cert.expect("parse public_ca.pem"))
            .expect("add public_ca.pem");
    }
    let mut client_cfg = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    client_cfg.alpn_protocols = alpn_protocols;
    tokio_rustls::TlsConnector::from(Arc::new(client_cfg))
}

/// 1. Full Pipeline Integration Test (EchoService + Middleware Stack over HTTP/1.1).
///
/// Verifies:
/// - `TraceId`, `Timing`, `Counter`, `PathSanitizer`, `Inspection`, `Compression`,
///   `MaxPayload`, `SecurityHeaders`, and `AltSvc` layers assembled via `build_service_stack`.
/// - Universal response headers (`cache-control: no-store`, `x-trace-id`, `alt-svc`,
///   and configured `SecurityHeaders`).
/// - Automatic gzip response compression when `Accept-Encoding: gzip` is sent.
/// - RFC 3986 path traversal rejection (`400 Bad Request` on `/api/../secret`).
/// - `InspectionLayer` path/method enforcement (`403 Forbidden` / `405 Method Not Allowed`).
/// - `MaxPayloadLayer` enforcement (`413 Payload Too Large` when payload exceeds limit).
#[tokio::test]
async fn test_full_pipeline_echo_and_middleware_stack_over_http_stream() {
    let toml_cfg = r#"
        [[Server]]
        name = "IntegrationEchoServer"
        ip = "127.0.0.1"
        port = 8443
        protocol = "http"
        service = "Echo"
        authentication = "None"

        [Server.AllowedPathes.GET]
        "/name" = ["^/name$"]
        "/health" = ["^/health$"]

        [Server.AllowedPathes.POST]
        "/" = ["^/$"]

        [Server.Layers]
        enabled = [
            "TraceId",
            "Timing",
            "Counter",
            "PathSanitizer",
            "SecurityHeaders",
            "AltSvc",
            "Inspection",
            "MaxPayload",
            "Compression",
        ]

        [Server.Layers.MaxPayload]
        max_bytes = 64

        [Server.Layers.SecurityHeaders]
        content_security_policy = "default-src 'self'"
        strict_transport_security = "max-age=63072000; includeSubDomains"
        x_content_type_options = "nosniff"
        x_frame_options = "DENY"
    "#;

    let server_config = parse_server_config(toml_cfg);
    let stack = build_service_stack(&server_config).expect("build_service_stack must succeed");

    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let cancel_token = CancellationToken::new();
    let srv_token = cancel_token.clone();
    let peer_addr: SocketAddr = "198.51.100.42:50000".parse().unwrap();
    let oid_mapping = Arc::new(server_config.oid_mapping.clone());

    let server_task = tokio::spawn(async move {
        let handler =
            ConnectionHandler::new(stack, peer_addr, Vec::new(), None, None, oid_mapping);
        serve_http_connection(server_io, handler, srv_token).await;
    });

    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(client_io))
        .await
        .expect("HTTP/1.1 handshake");
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });

    // (A) Valid GET request with Accept-Encoding: gzip
    let req = Request::builder()
        .method(Method::GET)
        .uri("/name")
        .header("host", "localhost:8443")
        .header("accept-encoding", "gzip")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = sender.send_request(req).await.expect("GET /name");
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok()),
        Some("no-store")
    );
    assert_eq!(
        resp.headers()
            .get("strict-transport-security")
            .and_then(|v| v.to_str().ok()),
        Some("max-age=63072000; includeSubDomains")
    );
    assert_eq!(
        resp.headers()
            .get("x-content-type-options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff")
    );
    assert_eq!(
        resp.headers()
            .get("x-frame-options")
            .and_then(|v| v.to_str().ok()),
        Some("DENY")
    );
    assert!(resp.headers().contains_key("alt-svc"));
    assert_eq!(
        resp.headers()
            .get("content-encoding")
            .and_then(|v| v.to_str().ok()),
        Some("gzip")
    );
    let _ = resp.into_body().collect().await.unwrap();

    // (B) Path traversal attempt must be rejected with 400 Bad Request by PathSanitizerLayer
    let traversal_req = Request::builder()
        .method(Method::GET)
        .uri("/name/../etc/passwd")
        .header("host", "localhost:8443")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let traversal_resp = sender
        .send_request(traversal_req)
        .await
        .expect("GET traversal");
    assert_eq!(traversal_resp.status(), StatusCode::BAD_REQUEST);
    let _ = traversal_resp.into_body().collect().await.unwrap();

    // (C) Disallowed path must be rejected by InspectionLayer with 403 Forbidden
    let forbidden_req = Request::builder()
        .method(Method::GET)
        .uri("/admin/secret")
        .header("host", "localhost:8443")
        .body(Full::new(Bytes::new()))
        .unwrap();
    let forbidden_resp = sender
        .send_request(forbidden_req)
        .await
        .expect("GET forbidden");
    assert_eq!(forbidden_resp.status(), StatusCode::FORBIDDEN);
    let _ = forbidden_resp.into_body().collect().await.unwrap();

    // (D) Oversized POST payload (> 64 bytes) must be rejected with 413 Payload Too Large
    let large_body = Bytes::from(vec![b'A'; 128]);
    let large_req = Request::builder()
        .method(Method::POST)
        .uri("/")
        .header("host", "localhost:8443")
        .body(Full::new(large_body))
        .unwrap();
    let large_resp = sender.send_request(large_req).await.expect("POST large");
    assert_eq!(large_resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let _ = large_resp.into_body().collect().await.unwrap();

    cancel_token.cancel();
    drop(sender);
    let _ = conn_task.await;
    let _ = server_task.await;
}

/// 2. Admin & Telemetry Service Integration Test.
///
/// Verifies `/healthz`, `/status` (JSON), and `/metrics` (Prometheus exposition format)
/// served through the full `build_service_stack` + `ConnectionHandler` pipeline.
#[tokio::test]
async fn test_admin_and_telemetry_endpoints_integration() {
    let toml_cfg = r#"
        [[Server]]
        name = "IntegrationAdminServer"
        ip = "127.0.0.1"
        port = 9090
        protocol = "http"
        service = "Admin"
        authentication = "None"

        [Server.AllowedPathes.GET]
        "/*" = ["^/.*$"]

        [Server.Layers]
        enabled = ["TraceId", "Counter", "Inspection"]
    "#;

    let server_config = parse_server_config(toml_cfg);
    let stack = build_service_stack(&server_config).expect("build Admin stack");

    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let cancel_token = CancellationToken::new();
    let srv_token = cancel_token.clone();
    let peer_addr: SocketAddr = "127.0.0.1:40000".parse().unwrap();
    let oid_mapping = Arc::new(server_config.oid_mapping.clone());

    let server_task = tokio::spawn(async move {
        let handler =
            ConnectionHandler::new(stack, peer_addr, Vec::new(), None, None, oid_mapping);
        serve_http_connection(server_io, handler, srv_token).await;
    });

    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(client_io))
        .await
        .expect("HTTP/1.1 handshake");
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });

    // 1. GET /healthz
    let req = Request::builder()
        .method(Method::GET)
        .uri("/healthz")
        .header("host", "localhost:9090")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let health_json: serde_json::Value =
        serde_json::from_slice(&body_bytes).expect("valid JSON from /healthz");
    assert_eq!(health_json["status"], "ok");

    // 2. GET /status
    let req = Request::builder()
        .method(Method::GET)
        .uri("/status")
        .header("host", "localhost:9090")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let status_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let status_json: serde_json::Value =
        serde_json::from_slice(&status_bytes).expect("valid JSON from /status");
    assert_eq!(status_json["status"], "ok");
    assert!(status_json["uptime_seconds"].is_number());

    // 3. GET /metrics
    let req = Request::builder()
        .method(Method::GET)
        .uri("/metrics")
        .header("host", "localhost:9090")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let metrics_text = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(metrics_text.contains("praeco_uptime_seconds"));
    assert!(metrics_text.contains("praeco_server_requests_total"));

    // 4. GET /upstreams -> 200 OK
    let req = Request::builder()
        .method(Method::GET)
        .uri("/upstreams")
        .header("host", "localhost:9090")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // 5. GET /xstatusx -> 404 Not Found
    let req = Request::builder()
        .method(Method::GET)
        .uri("/xstatusx")
        .header("host", "localhost:9090")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let not_found_bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let not_found_json: serde_json::Value =
        serde_json::from_slice(&not_found_bytes).expect("valid JSON error from /xstatusx");
    assert_eq!(not_found_json["error"], "Not Found");

    // 6. Verify TraceLayer recorded response status classes (2xx and 4xx) in /metrics
    let req = Request::builder()
        .method(Method::GET)
        .uri("/metrics")
        .header("host", "localhost:9090")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let metrics_text = String::from_utf8(
        resp.into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap();
    assert!(metrics_text.contains(
        r#"praeco_server_responses_total{server="IntegrationAdminServer",status_class="2xx"} 4"#
    ));
    assert!(metrics_text.contains(
        r#"praeco_server_responses_total{server="IntegrationAdminServer",status_class="4xx"} 1"#
    ));
    assert!(metrics_text.contains(
        r#"praeco_server_last_response_ms{server="IntegrationAdminServer"}"#
    ));
    assert!(metrics_text.contains(
        r#"praeco_server_ema_response_ms{server="IntegrationAdminServer"}"#
    ));

    cancel_token.cancel();
    drop(sender);
    let _ = conn_task.await;
    let _ = server_task.await;
}

/// 3. Rate Limiter & IP Filter Enforcement Integration Test.
///
/// Verifies:
/// - `IpFilter` CIDR allow/deny rules based on the connection's `peer_addr`.
/// - `TokenBucketRateLimiter` returning `429 Too Many Requests` with `retry-after`
///   when the bucket is exhausted.
#[tokio::test]
async fn test_rate_limiter_and_ip_filter_integration() {
    let toml_cfg = r#"
        [[Server]]
        name = "IntegrationRateLimitIpServer"
        ip = "127.0.0.1"
        port = 8080
        protocol = "http"
        service = "Echo"
        authentication = "None"

        [Server.AllowedPathes.GET]
        "/*" = ["^/.*$"]

        [Server.Layers]
        enabled = ["TraceId", "IpFilter", "RateLimiter:TokenBucket", "Inspection"]

        [Server.Layers.IpFilter]
        allow_cidrs = ["10.20.0.0/16"]
        deny_cidrs = ["10.20.99.0/24"]
        trust_forwarded_headers = false

        [Server.Layers.TokenBucketRateLimiter]
        max_capacity = 2
        refill = 1
        duration_micros = 5000000
        key_by = "ip"
    "#;

    let server_config = parse_server_config(toml_cfg);
    let stack = build_service_stack(&server_config).expect("build RateLimit+IpFilter stack");
    let oid_mapping = Arc::new(server_config.oid_mapping.clone());

    // (A) Connection from denied subnet 10.20.99.5 -> 403 Forbidden
    {
        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let token = CancellationToken::new();
        let denied_peer: SocketAddr = "10.20.99.5:12345".parse().unwrap();
        let handler = ConnectionHandler::new(
            stack.clone(),
            denied_peer,
            Vec::new(),
            None,
            None,
            oid_mapping.clone(),
        );
        tokio::spawn(serve_http_connection(server_io, handler, token.clone()));

        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(client_io))
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });

        let req = Request::builder()
            .method(Method::GET)
            .uri("/name")
            .header("host", "localhost")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = sender.send_request(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        token.cancel();
    }

    // (B) Connection from allowed subnet 10.20.1.10 -> first 2 requests 200 OK, 3rd -> 429 Too Many Requests
    {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let token = CancellationToken::new();
        let allowed_peer: SocketAddr = "10.20.1.10:12345".parse().unwrap();
        let handler = ConnectionHandler::new(
            stack,
            allowed_peer,
            Vec::new(),
            None,
            None,
            oid_mapping,
        );
        tokio::spawn(serve_http_connection(server_io, handler, token.clone()));

        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(client_io))
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });

        for i in 1..=2 {
            let req = Request::builder()
                .method(Method::GET)
                .uri("/name")
                .header("host", "localhost")
                .body(Empty::<Bytes>::new())
                .unwrap();
            let resp = sender.send_request(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "request #{i} must pass");
            let _ = resp.into_body().collect().await.unwrap();
        }

        // 3rd request exceeds MaxCapacity = 2
        let req3 = Request::builder()
            .method(Method::GET)
            .uri("/name")
            .header("host", "localhost")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp3 = sender.send_request(req3).await.unwrap();
        assert_eq!(resp3.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(resp3.headers().contains_key("retry-after"));
        token.cancel();
    }
}

/// 4. TLS + HTTP/2 Multiplexing + ArcSwap Hot-Reload Integration Test.
///
/// Verifies:
/// - `build_rustls_config` + `serve_tls_connection` over `tokio::io::duplex`.
/// - ALPN `h2` negotiation and concurrent multiplexed HTTP/2 streams on a single TLS session.
/// - Zero-downtime hot-reload via `ArcSwap<BoxedCloneService>`.
#[tokio::test]
async fn test_tls_http2_multiplexing_and_arcswap_hot_reload() {
    let echo_toml = r#"
        [[Server]]
        name = "IntegrationTlsH2Server"
        ip = "127.0.0.1"
        port = 8443
        protocol = "https"
        service = "Echo"
        authentication = "None"

        [Server.server_certs]
        ssl_certificate = "../server_certs/self_signed/praeco_public.pem"
        ssl_certificate_key = "../server_certs/self_signed/praeco_public.key"

        [Server.AllowedPathes.GET]
        "/*" = ["^/.*$"]

        [Server.Layers]
        enabled = ["TraceId", "Inspection"]
    "#;

    let echo_config = parse_server_config(echo_toml);
    let rustls_cfg = Arc::new(build_rustls_config(&echo_config).expect("build_rustls_config"));
    let acceptor = tokio_rustls::TlsAcceptor::from(rustls_cfg);

    let initial_stack = build_service_stack(&echo_config).expect("build initial Echo stack");
    let dynamic_stack = Arc::new(ArcSwap::from_pointee(initial_stack));
    let oid_mapping = Arc::new(echo_config.oid_mapping.clone());
    let static_name = echo_config.static_name.unwrap();

    // --- Part A: Concurrent HTTP/2 streams over TLS ---
    let (client_io, server_io) = tokio::io::duplex(128 * 1024);
    let token = CancellationToken::new();
    let srv_token = token.clone();
    let srv_acceptor = acceptor.clone();
    let srv_stack = dynamic_stack.clone();
    let srv_oids = oid_mapping.clone();

    tokio::spawn(async move {
        let peer: SocketAddr = "198.51.100.10:55555".parse().unwrap();
        serve_tls_connection(
            server_io,
            peer,
            &srv_acceptor,
            &srv_stack,
            &srv_oids,
            srv_token,
            static_name,
        )
        .await
        .expect("serve_tls_connection");
    });

    let connector = build_public_tls_connector(vec![b"h2".to_vec()]);
    let sni = ServerName::try_from("wurzelwerk.api.aweirich.eu".to_string()).unwrap();
    let tls_client = connector
        .connect(sni, client_io)
        .await
        .expect("TLS H2 connect");
    assert_eq!(tls_client.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));

    let (sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(tls_client))
            .await
            .expect("H2 handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });

    // Fire 5 concurrent HTTP/2 requests over the single TLS connection
    let mut handles = Vec::new();
    for i in 0..5 {
        let mut s = sender.clone();
        handles.push(tokio::spawn(async move {
            let req = Request::builder()
                .method(Method::GET)
                .uri(format!("https://wurzelwerk.api.aweirich.eu/name?id={i}"))
                .body(Empty::<Bytes>::new())
                .unwrap();
            let resp = s.send_request(req).await.expect("H2 send_request");
            assert_eq!(resp.status(), StatusCode::OK);
            let body = resp.into_body().collect().await.unwrap().to_bytes();
            assert!(!body.is_empty());
        }));
    }
    for h in handles {
        h.await.unwrap();
    }
    token.cancel();

    // --- Part B: Hot-Reload the service stack via ArcSwap to AdminService ---
    let admin_toml = echo_toml.replace("service = \"Echo\"", "service = \"Admin\"");
    let admin_config = parse_server_config(&admin_toml);
    let admin_stack = build_service_stack(&admin_config).expect("build Admin stack");
    dynamic_stack.store(Arc::new(admin_stack));

    let (client_io2, server_io2) = tokio::io::duplex(64 * 1024);
    let token2 = CancellationToken::new();
    let srv_token2 = token2.clone();
    tokio::spawn(async move {
        let peer: SocketAddr = "198.51.100.11:55556".parse().unwrap();
        serve_tls_connection(
            server_io2,
            peer,
            &acceptor,
            &dynamic_stack,
            &oid_mapping,
            srv_token2,
            static_name,
        )
        .await
        .expect("serve_tls_connection after hot-reload");
    });

    let connector1 = build_public_tls_connector(vec![b"http/1.1".to_vec()]);
    let sni2 = ServerName::try_from("wurzelwerk.api.aweirich.eu".to_string()).unwrap();
    let tls_client2 = connector1.connect(sni2, client_io2).await.unwrap();
    let (mut sender2, conn2) = hyper::client::conn::http1::handshake(TokioIo::new(tls_client2))
        .await
        .unwrap();
    tokio::spawn(async move {
        let _ = conn2.await;
    });

    let health_req = Request::builder()
        .method(Method::GET)
        .uri("/healthz")
        .header("host", "wurzelwerk.api.aweirich.eu")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let health_resp = sender2.send_request(health_req).await.unwrap();
    assert_eq!(health_resp.status(), StatusCode::OK);
    let health_body = health_resp.into_body().collect().await.unwrap().to_bytes();
    let health_json: serde_json::Value = serde_json::from_slice(&health_body).unwrap();
    assert_eq!(health_json["status"], "ok");
    token2.cancel();
}

/// 5. Yamux Tunnel & PROXY Protocol v2 Integration Test (`run_tunnel_over_stream`).
///
/// Verifies that `run_tunnel_over_stream`:
/// 1. Sends `REGISTER <sni> PROXY_V2\n` on the control stream.
/// 2. Multiplexes inbound Yamux streams in `Mode::Client`.
/// 3. Parses the mandatory PROXY v2 header to extract the real client IP (`203.0.113.88:44321`)
///    and enforces `IpFilter` against that real client IP.
/// 4. Terminates end-to-end TLS and serves the full Praeco HTTP stack.
#[tokio::test]
async fn test_run_tunnel_over_stream_with_proxy_protocol_v2() {
    use tokio::io::AsyncBufReadExt;

    let toml_cfg = r#"
        [[Server]]
        name = "IntegrationTunneledServer"
        ip = "127.0.0.1"
        port = 8443
        protocol = "https"
        service = "Admin"
        authentication = "None"

        [Server.server_certs]
        ssl_certificate = "../server_certs/self_signed/praeco_public.pem"
        ssl_certificate_key = "../server_certs/self_signed/praeco_public.key"

        [Server.AllowedPathes.GET]
        "/*" = ["^/.*$"]

        [Server.Layers]
        enabled = ["TraceId", "IpFilter", "Inspection"]

        [Server.Layers.IpFilter]
        allow_cidrs = ["203.0.113.0/24"]
        deny_cidrs = []
        trust_forwarded_headers = false
    "#;

    let server_config = parse_server_config(toml_cfg);
    let rustls_cfg = Arc::new(build_rustls_config(&server_config).expect("build_rustls_config"));
    let stack = build_service_stack(&server_config).expect("build_service_stack");
    let dynamic_stack = Arc::new(ArcSwap::from_pointee(stack));
    let oid_mapping = Arc::new(server_config.oid_mapping.clone());
    let static_name = server_config.static_name.unwrap();
    let tracker = Arc::new(ConnectionTracker::new(1000, 100));

    let tunnel_cfg = TunnelConfig {
        target_url: "tls://localhost:7001".to_string(),
        sni_domain: "wurzelwerk.api.aweirich.eu".to_string(),
        ca_cert_path: "../server_certs/self_signed/relay_ca.pem".to_string(),
        client_cert_path: "../server_certs/self_signed/praeco_client.pem".to_string(),
        client_key_path: "../server_certs/self_signed/praeco_client.key".to_string(),
        proxy_protocol: true,
        max_yamux_streams: Some(256),
    };

    let (relay_side, praeco_side) = tokio::io::duplex(128 * 1024);
    let cancel_token = CancellationToken::new();
    let tunnel_token = cancel_token.clone();

    let tunnel_handle = tokio::spawn(async move {
        run_tunnel_over_stream(
            praeco_side,
            &tunnel_cfg,
            rustls_cfg,
            dynamic_stack,
            tunnel_token,
            static_name,
            oid_mapping,
            tracker,
        )
        .await
        .expect("run_tunnel_over_stream");
    });

    // Simulate Relay Server reading `REGISTER wurzelwerk.api.aweirich.eu PROXY_V2\n`
    let mut reader = tokio::io::BufReader::new(relay_side);
    let mut reg_line = String::new();
    reader
        .read_line(&mut reg_line)
        .await
        .expect("read REGISTER line");
    assert_eq!(reg_line, "REGISTER wurzelwerk.api.aweirich.eu PROXY_V2\n");

    let relay_stream = reader.into_inner();
    let mut yamux_server =
        yamux::Connection::new(relay_stream.compat(), yamux::Config::default(), yamux::Mode::Server);

    // Open an outbound Yamux stream to Praeco before moving `yamux_server` into the background driver
    let yamux_stream = std::future::poll_fn(|cx| yamux_server.poll_new_outbound(cx))
        .await
        .expect("open yamux stream to Praeco");

    let yamux_driver = tokio::spawn(async move {
        while let Some(Ok(_)) = std::future::poll_fn(|cx| yamux_server.poll_next_inbound(cx)).await
        {}
    });

    let mut compat_stream = yamux_stream.compat();

    let real_client_addr: SocketAddr = "203.0.113.88:44321".parse().unwrap();
    let relay_addr: SocketAddr = "198.51.100.1:443".parse().unwrap();
    let pp_header = common::proxy_protocol::encode_proxy_v2(real_client_addr, relay_addr);
    tokio::io::AsyncWriteExt::write_all(&mut compat_stream, &pp_header)
        .await
        .expect("write PROXY v2 header");

    // Perform end-to-end TLS handshake over the Yamux stream
    let connector = build_public_tls_connector(vec![b"http/1.1".to_vec()]);
    let sni = ServerName::try_from("wurzelwerk.api.aweirich.eu".to_string()).unwrap();
    let tls_stream = connector
        .connect(sni, compat_stream)
        .await
        .expect("E2E TLS handshake over Yamux stream");

    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls_stream))
        .await
        .expect("HTTP/1.1 handshake over tunnel");
    tokio::spawn(async move {
        let _ = conn.await;
    });

    // Send GET /healthz through the tunnel (allowed by IpFilter because 203.0.113.88 is in 203.0.113.0/24!)
    let req = Request::builder()
        .method(Method::GET)
        .uri("/healthz")
        .header("host", "wurzelwerk.api.aweirich.eu")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let resp = sender
        .send_request(req)
        .await
        .expect("GET /healthz over tunnel");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.into_body().collect().await.unwrap().to_bytes();
    let body_json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(body_json["status"], "ok");

    cancel_token.cancel();
    drop(sender);
    yamux_driver.abort();
    let _ = tunnel_handle.await;
}

/// 6. mTLS Client Certificate Enforcement & StaticFiles SPA Fallback Integration Test.
///
/// Verifies:
/// - `AuthenticationMethod::ClientCert` (mTLS) rejects unauthenticated TLS clients.
/// - Authenticated mTLS clients (presenting `praeco_client.pem` signed by `relay_ca.pem`)
///   can access the `StaticFiles` service (`wrap_serve_dir`).
/// - Both direct static asset serving and SPA `fallback_to_index = true` work end-to-end.
#[tokio::test]
async fn test_mtls_client_cert_and_static_files_integration() {
    use rustls::pki_types::PrivateKeyDer;

    let tmp_dir = std::env::temp_dir().join(format!(
        "praeco_static_test_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&tmp_dir);
    std::fs::create_dir_all(&tmp_dir).expect("create temp static dir");
    std::fs::write(tmp_dir.join("index.html"), b"<html>SPA Index</html>").unwrap();
    std::fs::write(tmp_dir.join("hello.txt"), b"Hello Static Asset").unwrap();

    let toml_cfg = format!(
        r#"
        [[Server]]
        name = "IntegrationMtlsStaticServer"
        ip = "127.0.0.1"
        port = 8444
        protocol = "https"
        service = "StaticFiles"
        authentication = "ClientCert"

        [Server.server_certs]
        ssl_certificate = "../server_certs/self_signed/praeco_public.pem"
        ssl_certificate_key = "../server_certs/self_signed/praeco_public.key"

        [[Server.client_certs]]
        ssl_client_ca = "../server_certs/self_signed/relay_ca.pem"

        [Server.StaticFilesParams]
        root = "{}"
        fallback_to_index = true

        [Server.AllowedPathes.GET]
        "/*" = ["^/.*$"]

        [Server.Layers]
        enabled = ["TraceId", "Inspection"]
    "#,
        tmp_dir.display()
    );

    let server_config = parse_server_config(&toml_cfg);
    let rustls_cfg = Arc::new(build_rustls_config(&server_config).expect("build mTLS config"));
    let acceptor = tokio_rustls::TlsAcceptor::from(rustls_cfg);
    let stack = build_service_stack(&server_config).expect("build StaticFiles stack");
    let dynamic_stack = Arc::new(ArcSwap::from_pointee(stack));
    let oid_mapping = Arc::new(server_config.oid_mapping.clone());
    let static_name = server_config.static_name.unwrap();

    // (A) Client WITHOUT client certificate must fail mTLS handshake
    {
        let (client_io, server_io) = tokio::io::duplex(32 * 1024);
        let srv_acceptor = acceptor.clone();
        let srv_stack = dynamic_stack.clone();
        let srv_oids = oid_mapping.clone();
        let token = CancellationToken::new();

        let srv_handle = tokio::spawn(async move {
            let peer: SocketAddr = "198.51.100.50:50001".parse().unwrap();
            serve_tls_connection(
                server_io,
                peer,
                &srv_acceptor,
                &srv_stack,
                &srv_oids,
                token,
                static_name,
            )
            .await
        });

        let no_cert_connector = build_public_tls_connector(vec![b"http/1.1".to_vec()]);
        let sni = ServerName::try_from("wurzelwerk.api.aweirich.eu".to_string()).unwrap();
        if let Ok(mut tls_stream) = no_cert_connector.connect(sni, client_io).await {
            // In TLS 1.3, client cert rejection is surfaced on the first read/write after ClientHello
            let mut buf = [0u8; 16];
            let read_res = tokio::io::AsyncReadExt::read(&mut tls_stream, &mut buf).await;
            assert!(
                read_res.is_err() || matches!(read_res, Ok(0)),
                "unauthenticated client must be rejected by mTLS server"
            );
        }
        assert!(
            srv_handle.await.unwrap().is_err(),
            "server must return Err for unauthenticated mTLS handshake"
        );
    }

    // (B) Client WITH valid client certificate (`praeco_client.pem`) succeeds
    {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let token = CancellationToken::new();
        let srv_token = token.clone();
        let srv_acceptor = acceptor.clone();
        let srv_stack = dynamic_stack.clone();
        let srv_oids = oid_mapping.clone();

        tokio::spawn(async move {
            let peer: SocketAddr = "198.51.100.51:50002".parse().unwrap();
            serve_tls_connection(
                server_io,
                peer,
                &srv_acceptor,
                &srv_stack,
                &srv_oids,
                srv_token,
                static_name,
            )
            .await
            .expect("authenticated mTLS handshake must succeed");
        });

        // Build mTLS client config presenting `praeco_client.pem`
        let mut root_store = rustls::RootCertStore::empty();
        for cert in CertificateDer::pem_file_iter("../server_certs/self_signed/public_ca.pem")
            .unwrap()
        {
            root_store.add(cert.unwrap()).unwrap();
        }
        let client_certs: Vec<CertificateDer<'static>> =
            CertificateDer::pem_file_iter("../server_certs/self_signed/praeco_client.pem")
                .unwrap()
                .map(|c| c.unwrap())
                .collect();
        let client_key =
            PrivateKeyDer::from_pem_file("../server_certs/self_signed/praeco_client.key").unwrap();

        let mut mtls_client_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(client_certs, client_key)
            .unwrap();
        mtls_client_cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let mtls_connector = tokio_rustls::TlsConnector::from(Arc::new(mtls_client_cfg));

        let sni = ServerName::try_from("wurzelwerk.api.aweirich.eu".to_string()).unwrap();
        let tls_stream = mtls_connector.connect(sni, client_io).await.unwrap();
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(tls_stream))
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = conn.await;
        });

        // 1. Fetch existing static file `/hello.txt`
        let req1 = Request::builder()
            .method(Method::GET)
            .uri("/hello.txt")
            .header("host", "wurzelwerk.api.aweirich.eu")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp1 = sender.send_request(req1).await.unwrap();
        assert_eq!(resp1.status(), StatusCode::OK);
        let bytes1 = resp1.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&bytes1[..], b"Hello Static Asset");

        // 2. Fetch non-existent SPA route `/app/profile` -> falls back to `index.html`
        let req2 = Request::builder()
            .method(Method::GET)
            .uri("/app/profile")
            .header("host", "wurzelwerk.api.aweirich.eu")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp2 = sender.send_request(req2).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::OK);
        let bytes2 = resp2.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&bytes2[..], b"<html>SPA Index</html>");

        token.cancel();
    }

    let _ = std::fs::remove_dir_all(&tmp_dir);
}
