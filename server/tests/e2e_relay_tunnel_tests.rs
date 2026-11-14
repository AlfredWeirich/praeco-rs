//! Cross-Crate End-to-End System Tests (`praeco-rs` <-> `praeco-relay-server`).
//!
//! These tests connect a real `praeco-rs` Gateway instance (`build_tunnel_tls_connector`,
//! `run_tunnel_over_stream`, `build_rustls_config`, `build_service_stack`) with a real
//! `praeco-relay-server` instance (`setup_mtls_acceptor`, `handle_control_connection`,
//! `handle_data_connection`, `SessionMap`) over in-memory `tokio::io::duplex` streams.
//!
//! No mocks are used for protocol framing:
//! 1. Control Plane: Real mTLS 1.3 handshake (`praeco_client.pem` <-> `relay_server.pem`
//!    verified against `relay_ca.pem`) + X.509 SAN authorization + `REGISTER <sni> PROXY_V2`
//!    + Yamux multiplexing.
//! 2. Data Plane: External HTTPS client sends a real TLS 1.3 `ClientHello` -> Relay Server
//!    peeks SNI without terminating TLS -> Relay opens a Yamux stream and prepends a binary
//!    HAProxy `PROXY v2` header with the external client's socket address -> Praeco parses
//!    the `PROXY v2` header, enforces per-IP limits & `IpFilter` rules against the external
//!    client IP, terminates TLS 1.3 (ALPN `h2` / `http/1.1`), and processes requests through
//!    the full Tower middleware stack.

use std::net::SocketAddr;
use std::sync::{Arc, Once};
use std::time::Duration;

use arc_swap::ArcSwap;
use bytes::Bytes;
use http_body_util::{BodyExt, Empty};
use hyper::{Method, Request, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::pki_types::{CertificateDer, ServerName, pem::PemObject};
use tokio_util::sync::CancellationToken;

use praeco_relay_server::{
    handle_control_connection, handle_data_connection, new_session_map, setup_mtls_acceptor,
};
use praeco_rs::{
    build_rustls_config, build_service_stack, build_tunnel_tls_connector,
    configuration::{Config, ServerConfig, TunnelConfig},
    connection_tracker::ConnectionTracker,
    run_tunnel_over_stream,
};

static INIT_CRYPTO: Once = Once::new();

fn ensure_crypto_provider() {
    INIT_CRYPTO.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        praeco_rs::middleware::admin::init_process_start_time();
    });
}

fn parse_server_config(toml_str: &str) -> Arc<ServerConfig> {
    ensure_crypto_provider();
    let mut config: Config = toml::from_str(toml_str).expect("valid TOML config");
    for srv in config.servers.iter_mut() {
        srv.finalize().expect("ServerConfig::finalize must succeed");
    }
    Arc::new(config.servers.into_iter().next().expect("at least one [[Server]]"))
}

fn build_external_client_tls_connector(alpn: Vec<Vec<u8>>) -> tokio_rustls::TlsConnector {
    ensure_crypto_provider();
    let mut root_store = rustls::RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter("../server_certs/self_signed/public_ca.pem")
        .expect("read public_ca.pem")
    {
        root_store
            .add(cert.expect("parse public_ca.pem"))
            .expect("add public_ca.pem");
    }
    let mut cfg = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    cfg.alpn_protocols = alpn;
    tokio_rustls::TlsConnector::from(Arc::new(cfg))
}

/// Full Cross-Crate End-to-End Test:
/// External Client (HTTPS/H2) -> Relay Data Plane -> Yamux + PROXY v2 -> Praeco Gateway.
///
/// Verifies:
/// 1. Mutual TLS Control Plane authentication and SAN verification between Praeco and Relay.
/// 2. `REGISTER wurzelwerk.api.aweirich.eu PROXY_V2` negotiation and `SessionMap` registration.
/// 3. External client connecting from allowed IP `198.51.100.42:54321` negotiates end-to-end
///    TLS 1.3 + HTTP/2 (`h2`) with Praeco through the zero-knowledge Relay Server.
/// 4. Praeco's `IpFilter` receives the real external client IP (`198.51.100.42`) via `PROXY v2`
///    and permits the request, while blocking a second external client from denied IP
///    `198.51.100.99:54321` with `403 Forbidden`.
/// 5. Unregistered SNI (`wurzelwerk.admin.aweirich.eu`) is rejected at the Relay Data Plane.
#[tokio::test]
async fn test_e2e_praeco_gateway_and_relay_server_full_tunnel_pipeline() {
    ensure_crypto_provider();

    // ── 1. Configure & Prepare Praeco Gateway (`praeco-rs`) ──────────────────
    let praeco_toml = r#"
        [[Server]]
        name = "E2ETunneledPraecoGateway"
        protocol = "https"
        service = "Echo"
        authentication = "None"

        [Server.tunnel]
        target_url = "tls://localhost:7001"
        sni_domain = "wurzelwerk.api.aweirich.eu"
        ca_cert_path = "../server_certs/self_signed/relay_ca.pem"
        client_cert_path = "../server_certs/self_signed/praeco_client.pem"
        client_key_path = "../server_certs/self_signed/praeco_client.key"
        proxy_protocol = true
        max_yamux_streams = 256

        [Server.server_certs]
        ssl_certificate = "../server_certs/self_signed/praeco_public.pem"
        ssl_certificate_key = "../server_certs/self_signed/praeco_public.key"

        [Server.AllowedPathes.GET]
        "/name" = ["^/name(\\?.*)?$"]
        "/health" = ["^/health$"]

        [Server.Layers]
        enabled = [
            "TraceId",
            "SecurityHeaders",
            "IpFilter",
            "Inspection",
            "Compression",
        ]

        [Server.Layers.SecurityHeaders]
        content_security_policy = "default-src 'self'"
        strict_transport_security = "max-age=63072000; includeSubDomains"
        x_content_type_options = "nosniff"
        x_frame_options = "DENY"

        [Server.Layers.IpFilter]
        allow_cidrs = ["198.51.100.0/24"]
        deny_cidrs = ["198.51.100.99/32"]
        trust_forwarded_headers = false
    "#;

    let server_config = parse_server_config(praeco_toml);
    let tunnel_cfg: TunnelConfig = server_config
        .tunnel
        .clone()
        .expect("tunnel config must be present");
    let praeco_public_tls =
        Arc::new(build_rustls_config(&server_config).expect("build Praeco public TLS"));
    let stack = build_service_stack(&server_config).expect("build Praeco service stack");
    let dynamic_stack = Arc::new(ArcSwap::from_pointee(stack));
    let oid_mapping = Arc::new(server_config.oid_mapping.clone());
    let static_name = server_config.static_name.unwrap();
    let praeco_tracker = Arc::new(ConnectionTracker::new(1000, 50));

    // ── 2. Configure & Prepare Relay Server (`praeco-relay-server`) ──────────
    let session_map = new_session_map();
    let relay_mtls_acceptor = setup_mtls_acceptor(
        "../server_certs/self_signed/relay_ca.pem",
        "../server_certs/self_signed/relay_server.pem",
        "../server_certs/self_signed/relay_server.key",
        None,
    )
    .expect("setup Relay Control Plane mTLS acceptor");

    // ── 3. Establish Real mTLS Control Plane Connection (`duplex`) ───────────
    let (praeco_ctrl_raw, relay_ctrl_raw) = tokio::io::duplex(256 * 1024);
    let relay_sessions_ctrl = session_map.clone();

    let relay_ctrl_task = tokio::spawn(async move {
        let praeco_addr: SocketAddr = "10.0.0.50:49152".parse().unwrap();
        handle_control_connection(
            relay_ctrl_raw,
            praeco_addr,
            relay_mtls_acceptor,
            relay_sessions_ctrl,
            Duration::from_secs(5),
            256,
            true, // enable_proxy_protocol = true
        )
        .await;
    });

    // Praeco performs outbound mTLS handshake to Relay Control Plane
    let praeco_ctrl_connector =
        build_tunnel_tls_connector(&tunnel_cfg).expect("build Praeco mTLS connector");
    let relay_sni = ServerName::try_from("localhost".to_string()).unwrap();
    let praeco_ctrl_tls = praeco_ctrl_connector
        .connect(relay_sni, praeco_ctrl_raw)
        .await
        .expect("Praeco -> Relay Control Plane mTLS handshake must succeed");

    let cancel_token = CancellationToken::new();
    let praeco_tunnel_token = cancel_token.clone();
    let praeco_tunnel_task = tokio::spawn(async move {
        run_tunnel_over_stream(
            praeco_ctrl_tls,
            &tunnel_cfg,
            praeco_public_tls,
            dynamic_stack,
            praeco_tunnel_token,
            static_name,
            oid_mapping,
            praeco_tracker,
        )
        .await
        .expect("run_tunnel_over_stream");
    });

    // Wait until Relay Server has registered `wurzelwerk.api.aweirich.eu` in `session_map`
    tokio::time::timeout(Duration::from_secs(2), async {
        while !session_map.contains_key("wurzelwerk.api.aweirich.eu") {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("Relay Server must register wurzelwerk.api.aweirich.eu");

    let route_entry = session_map
        .get("wurzelwerk.api.aweirich.eu")
        .expect("tunnel route entry");
    assert!(
        route_entry.supports_proxy_v2,
        "PROXY_V2 capability must be negotiated on the registered route"
    );
    drop(route_entry);

    // ── 4. Scenario A: Allowed External Client over HTTP/2 + Gzip ────────────
    {
        let (ext_client_io, relay_data_io) = tokio::io::duplex(128 * 1024);
        let relay_sessions = session_map.clone();
        let allowed_external_ip: SocketAddr = "198.51.100.42:54321".parse().unwrap();
        let relay_public_listen: SocketAddr = "203.0.113.10:443".parse().unwrap();

        tokio::spawn(async move {
            handle_data_connection(
                relay_data_io,
                allowed_external_ip,
                relay_public_listen,
                relay_sessions,
                Some(Duration::from_secs(10)),
                Duration::from_secs(5),
            )
            .await;
        });

        // External client performs end-to-end TLS 1.3 handshake with ALPN `h2`
        let ext_connector = build_external_client_tls_connector(vec![b"h2".to_vec()]);
        let target_sni = ServerName::try_from("wurzelwerk.api.aweirich.eu".to_string()).unwrap();
        let ext_tls = ext_connector
            .connect(target_sni, ext_client_io)
            .await
            .expect("End-to-end TLS handshake through Relay Data Plane must succeed");
        assert_eq!(ext_tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));

        let (mut h2_sender, h2_conn) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(ext_tls))
                .await
                .expect("HTTP/2 handshake through Relay tunnel");
        tokio::spawn(async move {
            let _ = h2_conn.await;
        });

        let req = Request::builder()
            .method(Method::GET)
            .uri("https://wurzelwerk.api.aweirich.eu/name?client=external")
            .header("accept-encoding", "gzip")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = h2_sender
            .send_request(req)
            .await
            .expect("GET /name over H2 tunnel");
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("cache-control")
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
        assert_eq!(
            resp.headers()
                .get("x-frame-options")
                .and_then(|v| v.to_str().ok()),
            Some("DENY")
        );
        assert_eq!(
            resp.headers()
                .get("content-encoding")
                .and_then(|v| v.to_str().ok()),
            Some("gzip")
        );
        let _ = resp.into_body().collect().await.unwrap();
    }

    // ── 5. Scenario B: Blocked External Client IP via PROXY v2 -> 403 ────────
    {
        let (ext_client_io, relay_data_io) = tokio::io::duplex(128 * 1024);
        let relay_sessions = session_map.clone();
        // 198.51.100.99 is in Praeco's `deny_cidrs = ["198.51.100.99/32"]`
        let denied_external_ip: SocketAddr = "198.51.100.99:54322".parse().unwrap();
        let relay_public_listen: SocketAddr = "203.0.113.10:443".parse().unwrap();

        tokio::spawn(async move {
            handle_data_connection(
                relay_data_io,
                denied_external_ip,
                relay_public_listen,
                relay_sessions,
                Some(Duration::from_secs(10)),
                Duration::from_secs(5),
            )
            .await;
        });

        let ext_connector = build_external_client_tls_connector(vec![b"http/1.1".to_vec()]);
        let target_sni = ServerName::try_from("wurzelwerk.api.aweirich.eu".to_string()).unwrap();
        let ext_tls = ext_connector
            .connect(target_sni, ext_client_io)
            .await
            .expect("TLS handshake succeeds before HTTP IpFilter layer runs");

        let (mut h1_sender, h1_conn) = hyper::client::conn::http1::handshake(TokioIo::new(ext_tls))
            .await
            .expect("HTTP/1.1 handshake");
        tokio::spawn(async move {
            let _ = h1_conn.await;
        });

        let req = Request::builder()
            .method(Method::GET)
            .uri("/name")
            .header("host", "wurzelwerk.api.aweirich.eu")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let resp = h1_sender
            .send_request(req)
            .await
            .expect("GET /name from denied IP");
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "Praeco IpFilter must block 198.51.100.99 propagated via Relay PROXY v2 header"
        );
    }

    // ── 6. Scenario C: Unregistered SNI Rejected at Relay Data Plane ─────────
    {
        let (ext_client_io, relay_data_io) = tokio::io::duplex(64 * 1024);
        let relay_sessions = session_map.clone();
        let client_ip: SocketAddr = "198.51.100.42:54323".parse().unwrap();
        let relay_public_listen: SocketAddr = "203.0.113.10:443".parse().unwrap();

        tokio::spawn(async move {
            handle_data_connection(
                relay_data_io,
                client_ip,
                relay_public_listen,
                relay_sessions,
                Some(Duration::from_secs(10)),
                Duration::from_secs(5),
            )
            .await;
        });

        let ext_connector = build_external_client_tls_connector(vec![b"http/1.1".to_vec()]);
        let unregistered_sni =
            ServerName::try_from("wurzelwerk.admin.aweirich.eu".to_string()).unwrap();
        let res = ext_connector.connect(unregistered_sni, ext_client_io).await;
        assert!(
            res.is_err(),
            "Unregistered SNI must be dropped by Relay Data Plane before TLS handshake completes"
        );
    }

    // Graceful teardown
    cancel_token.cancel();
    let _ = praeco_tunnel_task.await;
    relay_ctrl_task.abort();
}

/// Cross-Crate E2E Test: Per-IP Connection Tracking via PROXY v2 & Session Failover.
///
/// Verifies:
/// 1. `ConnectionTracker` on Praeco enforces `max_connections_per_ip = 1` against the real
///    external client IP extracted from the Relay's binary `PROXY v2` header (rather than
///    lumping all tunneled connections under the Relay's IP).
/// 2. While `198.51.100.77` holds its 1 allowed connection open, a second simultaneous
///    connection from `198.51.100.77` is rejected before TLS handshake, whereas a connection
///    from a different external IP (`198.51.100.88`) succeeds concurrently over the same
///    Yamux session.
/// 3. When Praeco establishes a new Control Plane session for the same SNI (`wurzelwerk.api.aweirich.eu`),
///    Relay atomically replaces the route with an incremented generation and routes new traffic
///    to the new Praeco tunnel instance.
#[tokio::test]
async fn test_e2e_per_ip_connection_limit_via_proxy_v2_and_session_failover() {
    ensure_crypto_provider();

    let praeco_toml = r#"
        [[Server]]
        name = "E2EAuthTunnelGateway"
        protocol = "https"
        service = "Echo"
        authentication = "None"

        [Server.tunnel]
        target_url = "tls://localhost:7001"
        sni_domain = "wurzelwerk.api.aweirich.eu"
        ca_cert_path = "../server_certs/self_signed/relay_ca.pem"
        client_cert_path = "../server_certs/self_signed/praeco_client.pem"
        client_key_path = "../server_certs/self_signed/praeco_client.key"
        proxy_protocol = true
        max_yamux_streams = 128

        [Server.server_certs]
        ssl_certificate = "../server_certs/self_signed/praeco_public.pem"
        ssl_certificate_key = "../server_certs/self_signed/praeco_public.key"

        [Server.AllowedPathes.GET]
        "/health" = ["^/health$"]

        [Server.Layers]
        enabled = ["TraceId"]
    "#;

    let server_config = parse_server_config(praeco_toml);
    let tunnel_cfg: TunnelConfig = server_config.tunnel.clone().unwrap();
    let praeco_public_tls = Arc::new(build_rustls_config(&server_config).unwrap());
    let stack = build_service_stack(&server_config).unwrap();
    let dynamic_stack = Arc::new(ArcSwap::from_pointee(stack));
    let oid_mapping = Arc::new(server_config.oid_mapping.clone());
    let static_name = server_config.static_name.unwrap();

    // Allow max 10 total connections, but strictly 1 concurrent connection per external IP!
    let praeco_tracker = Arc::new(ConnectionTracker::new(10, 1));

    let session_map = new_session_map();
    let relay_mtls_acceptor = setup_mtls_acceptor(
        "../server_certs/self_signed/relay_ca.pem",
        "../server_certs/self_signed/relay_server.pem",
        "../server_certs/self_signed/relay_server.key",
        None,
    )
    .unwrap();

    // ── Establish Control Plane Session #1 ───────────────────────────────────
    let (praeco_ctrl_1, relay_ctrl_1) = tokio::io::duplex(256 * 1024);
    let relay_sessions_1 = session_map.clone();
    let acceptor_1 = relay_mtls_acceptor.clone();
    tokio::spawn(async move {
        handle_control_connection(
            relay_ctrl_1,
            "10.0.0.51:40001".parse().unwrap(),
            acceptor_1,
            relay_sessions_1,
            Duration::from_secs(5),
            128,
            true,
        )
        .await;
    });

    let praeco_ctrl_connector = build_tunnel_tls_connector(&tunnel_cfg).unwrap();
    let praeco_tls_1 = praeco_ctrl_connector
        .connect(
            ServerName::try_from("localhost".to_string()).unwrap(),
            praeco_ctrl_1,
        )
        .await
        .unwrap();

    let cancel_1 = CancellationToken::new();
    let cancel_1_clone = cancel_1.clone();
    let tunnel_cfg_1 = tunnel_cfg.clone();
    let tls_1 = praeco_public_tls.clone();
    let stack_1 = dynamic_stack.clone();
    let oid_1 = oid_mapping.clone();
    let tracker_1 = praeco_tracker.clone();

    let tunnel_task_1 = tokio::spawn(async move {
        let _ = run_tunnel_over_stream(
            praeco_tls_1,
            &tunnel_cfg_1,
            tls_1,
            stack_1,
            cancel_1_clone,
            static_name,
            oid_1,
            tracker_1,
        )
        .await;
    });

    tokio::time::timeout(Duration::from_secs(2), async {
        while !session_map.contains_key("wurzelwerk.api.aweirich.eu") {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("wurzelwerk.api.aweirich.eu registered");

    let gen_1 = session_map
        .get("wurzelwerk.api.aweirich.eu")
        .unwrap()
        .generation;

    // ── Client 1 from 198.51.100.77 opens and HOLDS an active HTTP/2 connection
    let (c1_io, r1_io) = tokio::io::duplex(128 * 1024);
    let sessions_c1 = session_map.clone();
    tokio::spawn(async move {
        handle_data_connection(
            r1_io,
            "198.51.100.77:50001".parse().unwrap(),
            "203.0.113.10:443".parse().unwrap(),
            sessions_c1,
            Some(Duration::from_secs(10)),
            Duration::from_secs(5),
        )
        .await;
    });

    let ext_connector = build_external_client_tls_connector(vec![b"h2".to_vec()]);
    let c1_tls = ext_connector
        .connect(
            ServerName::try_from("wurzelwerk.api.aweirich.eu".to_string()).unwrap(),
            c1_io,
        )
        .await
        .expect("Client 1 (198.51.100.77) first connection must succeed");
    let (mut c1_sender, c1_conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(c1_tls))
            .await
            .unwrap();
    let c1_conn_task = tokio::spawn(async move {
        let _ = c1_conn.await;
    });

    let resp = c1_sender
        .send_request(
            Request::builder()
                .method(Method::GET)
                .uri("https://wurzelwerk.api.aweirich.eu/health")
                .body(Empty::<Bytes>::new())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // ── Client 2 from SAME IP (198.51.100.77) must be rejected by Praeco's ConnectionTracker
    {
        let (c2_io, r2_io) = tokio::io::duplex(64 * 1024);
        let sessions_c2 = session_map.clone();
        tokio::spawn(async move {
            handle_data_connection(
                r2_io,
                "198.51.100.77:50002".parse().unwrap(),
                "203.0.113.10:443".parse().unwrap(),
                sessions_c2,
                Some(Duration::from_secs(5)),
                Duration::from_secs(5),
            )
            .await;
        });

        let c2_res = ext_connector
            .connect(
                ServerName::try_from("wurzelwerk.api.aweirich.eu".to_string()).unwrap(),
                c2_io,
            )
            .await;
        assert!(
            c2_res.is_err(),
            "Second concurrent connection from 198.51.100.77 must be rejected by ConnectionTracker via PROXY v2 IP"
        );
    }

    // ── Client 3 from DIFFERENT IP (198.51.100.88) must succeed concurrently!
    {
        let (c3_io, r3_io) = tokio::io::duplex(128 * 1024);
        let sessions_c3 = session_map.clone();
        tokio::spawn(async move {
            handle_data_connection(
                r3_io,
                "198.51.100.88:50003".parse().unwrap(),
                "203.0.113.10:443".parse().unwrap(),
                sessions_c3,
                Some(Duration::from_secs(10)),
                Duration::from_secs(5),
            )
            .await;
        });

        let c3_tls = ext_connector
            .connect(
                ServerName::try_from("wurzelwerk.api.aweirich.eu".to_string()).unwrap(),
                c3_io,
            )
            .await
            .expect("Concurrent connection from different IP 198.51.100.88 must succeed");
        let (mut c3_sender, c3_conn) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(c3_tls))
                .await
                .unwrap();
        tokio::spawn(async move {
            let _ = c3_conn.await;
        });

        let resp3 = c3_sender
            .send_request(
                Request::builder()
                    .method(Method::GET)
                    .uri("https://wurzelwerk.api.aweirich.eu/health")
                    .body(Empty::<Bytes>::new())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp3.status(), StatusCode::OK);
    }

    // Drop Client 1 connection
    drop(c1_sender);
    c1_conn_task.abort();

    // ── Session Failover: Shutdown Session #1, then Reconnect Session #2 ──────
    // Relay enforces P0.3 Overwrite Protection while Session #1 is active; once
    // Session #1 disconnects, Session #2 can register with a higher generation.
    cancel_1.cancel();
    let _ = tunnel_task_1.await;

    // Wait for Relay Control Plane to detect EOF on Session #1 and remove the old route
    tokio::time::timeout(Duration::from_secs(2), async {
        while session_map.contains_key("wurzelwerk.api.aweirich.eu") {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("Relay must clean up closed Session #1");

    let (praeco_ctrl_2, relay_ctrl_2) = tokio::io::duplex(256 * 1024);
    let relay_sessions_2 = session_map.clone();
    tokio::spawn(async move {
        handle_control_connection(
            relay_ctrl_2,
            "10.0.0.51:40002".parse().unwrap(),
            relay_mtls_acceptor,
            relay_sessions_2,
            Duration::from_secs(5),
            128,
            true,
        )
        .await;
    });

    let praeco_tls_2 = praeco_ctrl_connector
        .connect(
            ServerName::try_from("localhost".to_string()).unwrap(),
            praeco_ctrl_2,
        )
        .await
        .unwrap();

    let cancel_2 = CancellationToken::new();
    let cancel_2_clone = cancel_2.clone();
    let tunnel_task_2 = tokio::spawn(async move {
        let _ = run_tunnel_over_stream(
            praeco_tls_2,
            &tunnel_cfg,
            praeco_public_tls,
            dynamic_stack,
            cancel_2_clone,
            static_name,
            oid_mapping,
            praeco_tracker,
        )
        .await;
    });

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if let Some(entry) = session_map.get("wurzelwerk.api.aweirich.eu")
                && entry.generation > gen_1
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("Session #2 must register with higher generation after Session #1 teardown");

    cancel_2.cancel();
    let _ = tunnel_task_2.await;
}
