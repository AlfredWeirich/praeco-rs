//! # Praeco Relay Server Integration & E2E Tests
//!
//! End-to-End integration tests verifying the full Zero-Trust Reverse Tunneling
//! pipeline between the Data Plane, Control Plane (mTLS + SAN authorization),
//! Yamux stream multiplexing, and HAProxy PROXY Protocol v2 propagation.

use common::proxy_protocol::read_proxy_v2;
use common::test_pki::TestPki;
use praeco_relay_server::{
    Control, RelayConnectionTracker, SessionMap, TunnelRoute, handle_control_connection,
    handle_data_connection, new_session_map, run_control_plane, run_data_plane,
    setup_mtls_acceptor,
};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tokio_util::sync::CancellationToken;
use yamux::{Config as YamuxConfig, Connection, Mode};

fn ensure_crypto_provider() {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// Builds the Relay Control Plane `TlsAcceptor` using the ephemeral `TestPki`.
fn build_control_mtls_acceptor(pki: &TestPki, crl_path: Option<&std::path::Path>) -> TlsAcceptor {
    let crl = crl_path.map(|p| p.to_string_lossy().into_owned());
    setup_mtls_acceptor(
        TestPki::s(&pki.relay_ca_pem),
        TestPki::s(&pki.relay_server_pem),
        TestPki::s(&pki.relay_server_key),
        crl.as_ref(),
    )
    .expect("Failed to setup Relay mTLS acceptor")
}

/// Builds a `TlsConnector` for the simulated Praeco Gateway to authenticate
/// against the Relay Server's Control Plane via mTLS.
fn build_control_plane_client_connector(pki: &TestPki) -> TlsConnector {
    let mut root_store = RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(&pki.relay_ca_pem)
        .expect("Failed to open relay_ca.pem")
    {
        root_store
            .add(cert.expect("Invalid CA cert"))
            .expect("Failed to add CA cert");
    }

    let certs: Vec<CertificateDer> = CertificateDer::pem_file_iter(&pki.praeco_client_pem)
        .expect("Failed to open praeco_client.pem")
        .collect::<Result<Vec<_>, _>>()
        .expect("Failed to parse client certs");

    let key = PrivateKeyDer::from_pem_file(&pki.praeco_client_key)
        .expect("Failed to read praeco_client.key");

    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(certs, key)
        .expect("Failed to build mTLS client config");

    TlsConnector::from(Arc::new(client_config))
}

/// Builds an end-to-end `TlsAcceptor` representing the backend Praeco Gateway
/// that terminates the end-user's HTTPS connection.
fn build_backend_e2e_acceptor(pki: &TestPki) -> TlsAcceptor {
    let certs: Vec<CertificateDer> = CertificateDer::pem_file_iter(&pki.praeco_public_pem)
        .expect("Failed to open praeco_public.pem")
        .collect::<Result<Vec<_>, _>>()
        .expect("Failed to parse backend certs");

    let key = PrivateKeyDer::from_pem_file(&pki.praeco_public_key)
        .expect("Failed to read praeco_public.key");

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("Failed to build backend server config");

    TlsAcceptor::from(Arc::new(server_config))
}

/// Builds an end-to-end `TlsConnector` representing an external client (browser/API client)
/// connecting to the Relay Data Plane and verifying the backend's `praeco_public.pem` against `public_ca.pem`.
fn build_external_client_connector(pki: &TestPki) -> TlsConnector {
    let mut root_store = RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(&pki.public_ca_pem)
        .expect("Failed to open public_ca.pem")
    {
        root_store
            .add(cert.expect("Invalid backend CA"))
            .expect("Failed to add backend CA");
    }

    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    TlsConnector::from(Arc::new(client_config))
}

/// Waits until the specified `sni` is registered in `tunnels`.
async fn wait_for_tunnel_registration(tunnels: &SessionMap, sni: &str) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if tunnels.contains_key(sni) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("Timed out waiting for tunnel registration in SessionMap");
}

#[tokio::test]
async fn test_e2e_relay_tunnel_routing_with_tls_termination() {
    ensure_crypto_provider();
    let pki = TestPki::new();

    let tunnels = new_session_map();
    let control_acceptor = build_control_mtls_acceptor(&pki, None);

    let sni_domain = "wurzelwerk.api.aweirich.eu";

    // 1. Connect simulated Praeco Gateway to Relay Control Plane
    let (praeco_ctrl_io, relay_ctrl_io) = tokio::io::duplex(65536);
    let tunnels_ctrl = tunnels.clone();
    let ctrl_server_task = tokio::spawn(async move {
        handle_control_connection(
            relay_ctrl_io,
            "127.0.0.1:50001".parse().unwrap(),
            control_acceptor,
            tunnels_ctrl,
            Duration::from_secs(5),
            4096,
            true,
        )
        .await;
    });

    // Spawn Praeco side of the tunnel (mTLS + REGISTER + Yamux Client + E2E TLS Termination)
    let connector = build_control_plane_client_connector(&pki);
    let e2e_acceptor = build_backend_e2e_acceptor(&pki);
    let praeco_task = tokio::spawn(async move {
        let domain = ServerName::try_from("localhost".to_string()).unwrap();
        let mut tls_stream = connector
            .connect(domain, praeco_ctrl_io)
            .await
            .expect("Praeco mTLS handshake failed");

        // Legacy registration without PROXY_V2
        let cmd = format!("REGISTER {}\n", sni_domain);
        tls_stream.write_all(cmd.as_bytes()).await.unwrap();
        tls_stream.flush().await.unwrap();

        let mut yamux_conn =
            Connection::new(tls_stream.compat(), YamuxConfig::default(), Mode::Client);

        // Wait for one inbound stream from the Relay
        let inbound_stream = std::future::poll_fn(|cx| yamux_conn.poll_next_inbound(cx))
            .await
            .expect("Expected inbound Yamux stream")
            .expect("Yamux stream error");

        // Keep driving the Yamux connection in the background while handling the stream
        let driver_handle = tokio::spawn(async move {
            while let Some(Ok(_)) =
                std::future::poll_fn(|cx| yamux_conn.poll_next_inbound(cx)).await
            {}
        });

        let mut e2e_tls = e2e_acceptor
            .accept(inbound_stream.compat())
            .await
            .expect("End-to-end TLS handshake at Praeco failed");
        let mut reader = TokioBufReader::new(&mut e2e_tls);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        assert_eq!(line, "PING E2E OVER YAMUX\n");

        e2e_tls
            .write_all(b"PONG FROM PRAECO GATEWAY\n")
            .await
            .unwrap();
        e2e_tls.flush().await.unwrap();
        let _ = e2e_tls.shutdown().await;

        // Wait for client to finish reading and close its side before tearing down the Yamux tunnel
        let mut eof = [0u8; 1];
        let _ = e2e_tls.read(&mut eof).await;

        driver_handle.abort();
    });

    // Wait until the tunnel is active in Relay's routing table
    wait_for_tunnel_registration(&tunnels, sni_domain).await;

    // 2. Connect External Client to Relay Data Plane
    let (client_data_io, relay_data_io) = tokio::io::duplex(65536);
    let tunnels_data = tunnels.clone();
    let data_server_task = tokio::spawn(async move {
        handle_data_connection(
            relay_data_io,
            "198.51.100.77:60123".parse().unwrap(),
            "127.0.0.1:443".parse().unwrap(),
            tunnels_data,
            Some(Duration::from_secs(30)),
            Duration::from_secs(5),
        )
        .await;
    });

    let client_connector = build_external_client_connector(&pki);
    let target_sni = ServerName::try_from(sni_domain.to_string()).unwrap();
    let mut client_tls = client_connector
        .connect(target_sni, client_data_io)
        .await
        .expect("External client E2E TLS handshake failed");

    client_tls
        .write_all(b"PING E2E OVER YAMUX\n")
        .await
        .unwrap();
    client_tls.flush().await.unwrap();

    let mut client_reader = TokioBufReader::new(&mut client_tls);
    let mut response = String::new();
    client_reader.read_line(&mut response).await.unwrap();
    assert_eq!(response, "PONG FROM PRAECO GATEWAY\n");

    let _ = client_tls.shutdown().await;
    praeco_task.await.unwrap();
    data_server_task.await.unwrap();
    ctrl_server_task.await.unwrap();
}

#[tokio::test]
async fn test_e2e_relay_tunnel_with_proxy_protocol_v2_propagation() {
    ensure_crypto_provider();
    let pki = TestPki::new();

    let tunnels = new_session_map();
    let control_acceptor = build_control_mtls_acceptor(&pki, None);

    let sni_domain = "wurzelwerk.onboarding.aweirich.eu";
    let expected_client_addr: SocketAddr = "203.0.113.42:54321".parse().unwrap();
    let relay_local_addr: SocketAddr = "198.51.100.1:443".parse().unwrap();

    // 1. Connect Praeco Gateway with PROXY_V2 capability negotiation
    let (praeco_ctrl_io, relay_ctrl_io) = tokio::io::duplex(65536);
    let tunnels_ctrl = tunnels.clone();
    let ctrl_server_task = tokio::spawn(async move {
        handle_control_connection(
            relay_ctrl_io,
            "127.0.0.1:50002".parse().unwrap(),
            control_acceptor,
            tunnels_ctrl,
            Duration::from_secs(5),
            4096,
            true,
        )
        .await;
    });

    let connector = build_control_plane_client_connector(&pki);
    let e2e_acceptor = build_backend_e2e_acceptor(&pki);
    let praeco_task = tokio::spawn(async move {
        let domain = ServerName::try_from("localhost".to_string()).unwrap();
        let mut tls_stream = connector
            .connect(domain, praeco_ctrl_io)
            .await
            .expect("Praeco mTLS handshake failed");

        let cmd = format!("REGISTER {} PROXY_V2\n", sni_domain);
        tls_stream.write_all(cmd.as_bytes()).await.unwrap();
        tls_stream.flush().await.unwrap();

        let mut yamux_conn =
            Connection::new(tls_stream.compat(), YamuxConfig::default(), Mode::Client);

        let inbound_stream = std::future::poll_fn(|cx| yamux_conn.poll_next_inbound(cx))
            .await
            .expect("Expected inbound Yamux stream")
            .expect("Yamux stream error");

        let driver_handle = tokio::spawn(async move {
            while let Some(Ok(_)) =
                std::future::poll_fn(|cx| yamux_conn.poll_next_inbound(cx)).await
            {}
        });

        // Praeco reads & validates the binary HAProxy PROXY Protocol v2 header first
        let mut compat_stream = inbound_stream.compat();
        let resolved_client_ip = read_proxy_v2(&mut compat_stream)
            .await
            .expect("Failed to read PROXY v2 header")
            .expect("Expected valid PROXY v2 client SocketAddr");

        assert_eq!(resolved_client_ip, expected_client_addr);

        let mut e2e_tls = e2e_acceptor
            .accept(compat_stream)
            .await
            .expect("End-to-end TLS handshake after PROXY v2 header failed");

        let mut reader = TokioBufReader::new(&mut e2e_tls);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        assert_eq!(line, "WHO AM I?\n");

        let reply = format!("CLIENT_IP={}\n", resolved_client_ip);
        e2e_tls.write_all(reply.as_bytes()).await.unwrap();
        e2e_tls.flush().await.unwrap();
        let _ = e2e_tls.shutdown().await;

        // Wait for client to finish reading and close its side before tearing down the Yamux tunnel
        let mut eof = [0u8; 1];
        let _ = e2e_tls.read(&mut eof).await;

        driver_handle.abort();
    });

    wait_for_tunnel_registration(&tunnels, sni_domain).await;

    // Verify that `supports_proxy_v2` was recorded in the routing table
    assert!(
        tunnels
            .get(sni_domain)
            .expect("Route must exist")
            .supports_proxy_v2
    );

    // 2. External Client connects to Data Plane
    let (client_data_io, relay_data_io) = tokio::io::duplex(65536);
    let tunnels_data = tunnels.clone();
    let data_server_task = tokio::spawn(async move {
        handle_data_connection(
            relay_data_io,
            expected_client_addr,
            relay_local_addr,
            tunnels_data,
            Some(Duration::from_secs(30)),
            Duration::from_secs(5),
        )
        .await;
    });

    let client_connector = build_external_client_connector(&pki);
    let target_sni = ServerName::try_from(sni_domain.to_string()).unwrap();
    let mut client_tls = client_connector
        .connect(target_sni, client_data_io)
        .await
        .expect("External client TLS handshake failed");

    client_tls.write_all(b"WHO AM I?\n").await.unwrap();
    client_tls.flush().await.unwrap();

    let mut client_reader = TokioBufReader::new(&mut client_tls);
    let mut response = String::new();
    client_reader.read_line(&mut response).await.unwrap();
    assert_eq!(response, "CLIENT_IP=203.0.113.42:54321\n");

    let _ = client_tls.shutdown().await;
    praeco_task.await.unwrap();
    data_server_task.await.unwrap();
    ctrl_server_task.await.unwrap();
}

#[tokio::test]
async fn test_e2e_relay_multiplexes_concurrent_streams_over_single_tunnel() {
    ensure_crypto_provider();
    let pki = TestPki::new();

    let tunnels = new_session_map();
    let control_acceptor = build_control_mtls_acceptor(&pki, None);

    let sni_domain = "wurzelwerk.admin.aweirich.eu";
    let num_concurrent_clients = 5usize;

    let (praeco_ctrl_io, relay_ctrl_io) = tokio::io::duplex(131072);
    let tunnels_ctrl = tunnels.clone();
    tokio::spawn(async move {
        handle_control_connection(
            relay_ctrl_io,
            "127.0.0.1:50003".parse().unwrap(),
            control_acceptor,
            tunnels_ctrl,
            Duration::from_secs(5),
            4096,
            false,
        )
        .await;
    });

    // Spawn Praeco backend handling multiple concurrent Yamux streams
    let connector = build_control_plane_client_connector(&pki);
    let e2e_acceptor = build_backend_e2e_acceptor(&pki);
    let praeco_task = tokio::spawn(async move {
        let domain = ServerName::try_from("localhost".to_string()).unwrap();
        let mut tls_stream = connector.connect(domain, praeco_ctrl_io).await.unwrap();

        let cmd = format!("REGISTER {}\n", sni_domain);
        tls_stream.write_all(cmd.as_bytes()).await.unwrap();
        tls_stream.flush().await.unwrap();

        let mut yamux_conn =
            Connection::new(tls_stream.compat(), YamuxConfig::default(), Mode::Client);

        let mut stream_tasks = Vec::new();
        let mut accepted = 0;

        std::future::poll_fn(|cx| {
            while accepted < num_concurrent_clients {
                match yamux_conn.poll_next_inbound(cx) {
                    std::task::Poll::Ready(Some(Ok(stream))) => {
                        accepted += 1;
                        let acceptor = e2e_acceptor.clone();
                        stream_tasks.push(tokio::spawn(async move {
                            let mut tls = acceptor.accept(stream.compat()).await.unwrap();
                            let mut reader = TokioBufReader::new(&mut tls);
                            let mut line = String::new();
                            reader.read_line(&mut line).await.unwrap();
                            let response = format!("ECHO:{}", line);
                            tls.write_all(response.as_bytes()).await.unwrap();
                            tls.flush().await.unwrap();
                            let _ = tls.shutdown().await;
                            let mut eof = [0u8; 1];
                            let _ = tls.read(&mut eof).await;
                        }));
                    }
                    std::task::Poll::Ready(Some(Err(e))) => panic!("Yamux error: {:?}", e),
                    std::task::Poll::Ready(None) => break,
                    std::task::Poll::Pending => break,
                }
            }

            // Keep polling connection to drive active stream frames until all stream tasks finish
            if accepted == num_concurrent_clients && stream_tasks.iter().all(|t| t.is_finished()) {
                return std::task::Poll::Ready(());
            }

            let _ = yamux_conn.poll_next_inbound(cx);
            cx.waker().wake_by_ref();
            std::task::Poll::Pending
        })
        .await;

        for t in stream_tasks {
            t.await.unwrap();
        }
    });

    wait_for_tunnel_registration(&tunnels, sni_domain).await;

    // Launch 5 concurrent external clients
    let ext_connector = build_external_client_connector(&pki);
    let mut client_handles = Vec::new();
    for i in 0..num_concurrent_clients {
        let tunnels_data = tunnels.clone();
        let connector = ext_connector.clone();
        client_handles.push(tokio::spawn(async move {
            let (client_io, relay_io) = tokio::io::duplex(65536);
            tokio::spawn(async move {
                handle_data_connection(
                    relay_io,
                    format!("10.0.0.{}:4000{}", i + 1, i).parse().unwrap(),
                    "127.0.0.1:443".parse().unwrap(),
                    tunnels_data,
                    None,
                    Duration::from_secs(5),
                )
                .await;
            });

            let target_sni = ServerName::try_from(sni_domain.to_string()).unwrap();
            let mut tls = connector.connect(target_sni, client_io).await.unwrap();

            let msg = format!("HELLO_FROM_CLIENT_{}\n", i);
            tls.write_all(msg.as_bytes()).await.unwrap();
            tls.flush().await.unwrap();

            let mut reader = TokioBufReader::new(&mut tls);
            let mut reply = String::new();
            reader.read_line(&mut reply).await.unwrap();
            assert_eq!(reply, format!("ECHO:HELLO_FROM_CLIENT_{}\n", i));
            let _ = tls.shutdown().await;
        }));
    }

    for h in client_handles {
        h.await.unwrap();
    }
    praeco_task.await.unwrap();
}

#[tokio::test]
async fn test_e2e_unauthorized_sni_registration_rejected() {
    ensure_crypto_provider();
    let pki = TestPki::new();

    let tunnels = new_session_map();
    let control_acceptor = build_control_mtls_acceptor(&pki, None);

    let unauthorized_sni = "unauthorized.other-domain.eu";

    let (praeco_ctrl_io, relay_ctrl_io) = tokio::io::duplex(65536);
    let tunnels_ctrl = tunnels.clone();
    let ctrl_server_task = tokio::spawn(async move {
        handle_control_connection(
            relay_ctrl_io,
            "127.0.0.1:50004".parse().unwrap(),
            control_acceptor,
            tunnels_ctrl,
            Duration::from_secs(5),
            4096,
            true,
        )
        .await;
    });

    let connector = build_control_plane_client_connector(&pki);
    let domain = ServerName::try_from("localhost".to_string()).unwrap();
    let mut tls_stream = connector.connect(domain, praeco_ctrl_io).await.unwrap();

    let cmd = format!("REGISTER {}\n", unauthorized_sni);
    tls_stream.write_all(cmd.as_bytes()).await.unwrap();
    tls_stream.flush().await.unwrap();

    // Relay should reject and exit `handle_control_connection` immediately
    ctrl_server_task.await.unwrap();
    assert!(
        !tunnels.contains_key(unauthorized_sni),
        "Unauthorized SNI must not be added to SessionMap"
    );
}

#[tokio::test]
async fn test_e2e_active_tunnel_overwrite_rejected_and_reconnect_succeeds() {
    ensure_crypto_provider();
    let pki = TestPki::new();

    let tunnels = new_session_map();
    let control_acceptor = build_control_mtls_acceptor(&pki, None);

    let sni_domain = "wurzelwerk.idp.aweirich.eu";

    // 1. First tunnel registers `wurzelwerk.idp.aweirich.eu`
    let (praeco1_io, relay1_io) = tokio::io::duplex(65536);
    let tunnels1 = tunnels.clone();
    let acceptor1 = control_acceptor.clone();
    let server1_task = tokio::spawn(async move {
        handle_control_connection(
            relay1_io,
            "127.0.0.1:50010".parse().unwrap(),
            acceptor1,
            tunnels1,
            Duration::from_secs(5),
            4096,
            true,
        )
        .await;
    });

    let connector = build_control_plane_client_connector(&pki);
    let domain = ServerName::try_from("localhost".to_string()).unwrap();
    let mut tls1 = connector.connect(domain.clone(), praeco1_io).await.unwrap();
    tls1.write_all(format!("REGISTER {}\n", sni_domain).as_bytes())
        .await
        .unwrap();
    tls1.flush().await.unwrap();
    let mut yamux1 = Connection::new(tls1.compat(), YamuxConfig::default(), Mode::Client);

    wait_for_tunnel_registration(&tunnels, sni_domain).await;
    let first_gen = tunnels.get(sni_domain).unwrap().generation;

    // 2. Second tunnel attempts to hijack the same active SNI -> must be rejected
    let (praeco2_io, relay2_io) = tokio::io::duplex(65536);
    let tunnels2 = tunnels.clone();
    let acceptor2 = control_acceptor.clone();
    let server2_task = tokio::spawn(async move {
        handle_control_connection(
            relay2_io,
            "127.0.0.1:50011".parse().unwrap(),
            acceptor2,
            tunnels2,
            Duration::from_secs(5),
            4096,
            true,
        )
        .await;
    });

    let mut tls2 = connector.connect(domain.clone(), praeco2_io).await.unwrap();
    tls2.write_all(format!("REGISTER {}\n", sni_domain).as_bytes())
        .await
        .unwrap();
    tls2.flush().await.unwrap();

    // Server 2 task must exit quickly while keeping the first tunnel intact
    server2_task.await.unwrap();
    assert_eq!(
        tunnels.get(sni_domain).unwrap().generation,
        first_gen,
        "First tunnel generation must remain untouched after overwrite attempt"
    );

    // 3. Disconnect first tunnel cleanly -> route is removed -> reconnect succeeds with new generation
    let _ = std::future::poll_fn(|cx| yamux1.poll_close(cx)).await;
    drop(yamux1);
    server1_task.await.unwrap();
    assert!(
        !tunnels.contains_key(sni_domain),
        "Route should be cleaned up after disconnect"
    );

    let (praeco3_io, relay3_io) = tokio::io::duplex(65536);
    let tunnels3 = tunnels.clone();
    let server3_task = tokio::spawn(async move {
        handle_control_connection(
            relay3_io,
            "127.0.0.1:50012".parse().unwrap(),
            control_acceptor,
            tunnels3,
            Duration::from_secs(5),
            4096,
            true,
        )
        .await;
    });

    let mut tls3 = connector.connect(domain, praeco3_io).await.unwrap();
    tls3.write_all(format!("REGISTER {}\n", sni_domain).as_bytes())
        .await
        .unwrap();
    tls3.flush().await.unwrap();
    let mut yamux3 = Connection::new(tls3.compat(), YamuxConfig::default(), Mode::Client);

    wait_for_tunnel_registration(&tunnels, sni_domain).await;
    let third_gen = tunnels.get(sni_domain).unwrap().generation;
    assert!(
        third_gen > first_gen,
        "Re-registered tunnel must receive a newer generation ID"
    );

    let _ = std::future::poll_fn(|cx| yamux3.poll_close(cx)).await;
    drop(yamux3);
    server3_task.await.unwrap();
}

#[tokio::test]
async fn test_e2e_unregistered_sni_on_data_plane_dropped_cleanly() {
    ensure_crypto_provider();
    let pki = TestPki::new();

    // Empty routing table: no tunnels registered
    let tunnels = new_session_map();
    let (client_data_io, relay_data_io) = tokio::io::duplex(65536);

    let data_server_task = tokio::spawn(async move {
        handle_data_connection(
            relay_data_io,
            "198.51.100.99:55555".parse().unwrap(),
            "127.0.0.1:443".parse().unwrap(),
            tunnels,
            None,
            Duration::from_secs(5),
        )
        .await;
    });

    let client_connector = build_external_client_connector(&pki);
    let target_sni = ServerName::try_from("wurzelwerk.api.aweirich.eu".to_string()).unwrap();

    // Handshake must fail cleanly because Relay closes the stream when no route exists
    let res = client_connector.connect(target_sni, client_data_io).await;
    assert!(
        res.is_err(),
        "Connection to unregistered SNI must fail cleanly"
    );

    data_server_task.await.unwrap();
}

#[tokio::test]
async fn test_e2e_tcp_control_and_data_plane_with_graceful_shutdown() {
    ensure_crypto_provider();
    let pki = TestPki::new();

    let tunnels = new_session_map();
    let control_acceptor = build_control_mtls_acceptor(&pki, None);

    let ctrl_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let ctrl_addr = ctrl_listener.local_addr().unwrap();

    let data_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let data_addr = data_listener.local_addr().unwrap();

    let cancel_token = CancellationToken::new();
    let tracker = Arc::new(RelayConnectionTracker::new(100, 50));

    let ctrl_task = tokio::spawn(run_control_plane(
        ctrl_listener,
        control_acceptor,
        tunnels.clone(),
        Duration::from_secs(5),
        4096,
        true,
        cancel_token.clone(),
    ));

    let data_task = tokio::spawn(run_data_plane(
        data_listener,
        tunnels.clone(),
        50.0,
        100.0,
        Some(Duration::from_secs(30)),
        Some(Duration::from_secs(30)),
        tracker.clone(),
        Duration::from_secs(5),
        cancel_token.clone(),
    ));

    let sni_domain = "wurzelwerk.api.aweirich.eu";

    // Connect simulated Praeco Gateway over real TCP
    let praeco_tcp = TcpStream::connect(ctrl_addr).await.unwrap();
    let connector = build_control_plane_client_connector(&pki);
    let domain = ServerName::try_from("localhost".to_string()).unwrap();
    let mut ctrl_tls = connector.connect(domain, praeco_tcp).await.unwrap();
    ctrl_tls
        .write_all(format!("REGISTER {} PROXY_V2\n", sni_domain).as_bytes())
        .await
        .unwrap();
    ctrl_tls.flush().await.unwrap();

    let mut yamux_conn = Connection::new(ctrl_tls.compat(), YamuxConfig::default(), Mode::Client);
    let (stream_done_tx, stream_done_rx) = tokio::sync::oneshot::channel::<()>();
    let e2e_acceptor = build_backend_e2e_acceptor(&pki);
    let backend_task = tokio::spawn(async move {
        let inbound = std::future::poll_fn(|cx| yamux_conn.poll_next_inbound(cx))
            .await
            .expect("Expected inbound Yamux stream")
            .expect("Yamux stream error");

        let driver = tokio::spawn(async move {
            while let Some(Ok(_)) =
                std::future::poll_fn(|cx| yamux_conn.poll_next_inbound(cx)).await
            {}
        });

        let mut compat = inbound.compat();
        let client_ip = read_proxy_v2(&mut compat)
            .await
            .unwrap()
            .expect("Expected PROXY v2 header over TCP");
        assert_eq!(client_ip.ip(), "127.0.0.1".parse::<std::net::IpAddr>().unwrap());

        let mut e2e_tls = e2e_acceptor.accept(compat).await.unwrap();
        let mut reader = TokioBufReader::new(&mut e2e_tls);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        assert_eq!(line, "HELLO OVER TCP\n");

        e2e_tls.write_all(b"ACK OVER TCP\n").await.unwrap();
        e2e_tls.flush().await.unwrap();
        let _ = e2e_tls.shutdown().await;
        let mut eof = [0u8; 1];
        let _ = e2e_tls.read(&mut eof).await;

        let _ = stream_done_tx.send(());
        let _ = driver.await;
    });

    wait_for_tunnel_registration(&tunnels, sni_domain).await;

    // External client connects over real TCP to Data Plane
    let ext_tcp = TcpStream::connect(data_addr).await.unwrap();
    let ext_connector = build_external_client_connector(&pki);
    let mut ext_tls = ext_connector
        .connect(ServerName::try_from(sni_domain.to_string()).unwrap(), ext_tcp)
        .await
        .unwrap();
    ext_tls.write_all(b"HELLO OVER TCP\n").await.unwrap();
    ext_tls.flush().await.unwrap();

    let mut ext_reader = TokioBufReader::new(&mut ext_tls);
    let mut resp = String::new();
    ext_reader.read_line(&mut resp).await.unwrap();
    assert_eq!(resp, "ACK OVER TCP\n");
    let _ = ext_tls.shutdown().await;

    stream_done_rx.await.unwrap();

    // Trigger graceful shutdown via CancellationToken while tunnel driver is still alive
    cancel_token.cancel();

    let (ctrl_res, data_res) = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::join!(ctrl_task, data_task)
    })
    .await
    .expect("Control and Data planes must shut down gracefully within timeout");

    ctrl_res.unwrap().expect("run_control_plane must return Ok");
    data_res.unwrap().expect("run_data_plane must return Ok");
    tokio::time::timeout(Duration::from_secs(2), backend_task)
        .await
        .expect("Backend Yamux driver must terminate cleanly on relay shutdown")
        .unwrap();
    assert_eq!(tracker.current_global(), 0);
}

#[tokio::test]
async fn test_run_data_plane_rate_limit_drops_excess_connections() {
    ensure_crypto_provider();
    let pki = TestPki::new();

    let tunnels = new_session_map();
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    tunnels.insert(
        "wurzelwerk.api.aweirich.eu".to_string(),
        TunnelRoute {
            control: Control::new(tx),
            generation: 1,
            supports_proxy_v2: false,
        },
    );

    let data_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let data_addr = data_listener.local_addr().unwrap();
    let cancel_token = CancellationToken::new();
    let tracker = Arc::new(RelayConnectionTracker::new(100, 100));

    // Allow burst of 2, virtually zero refill during test
    let data_task = tokio::spawn(run_data_plane(
        data_listener,
        tunnels,
        0.01,
        2.0,
        None,
        None,
        tracker,
        Duration::from_secs(2),
        cancel_token.clone(),
    ));

    let client_connector = build_external_client_connector(&pki);
    let target_sni = ServerName::try_from("wurzelwerk.api.aweirich.eu".to_string()).unwrap();

    // First 2 connections consume the burst and reach `control.open_stream()`
    for _ in 0..2 {
        let tcp = TcpStream::connect(data_addr).await.unwrap();
        let conn = client_connector.clone();
        let sni = target_sni.clone();
        tokio::spawn(async move {
            let _ = conn.connect(sni, tcp).await;
        });
        let req = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("Expected stream open request for allowed burst connection");
        // Drop oneshot sender immediately so handle_data_connection exits
        drop(req);
    }

    // 3rd connection exceeds burst=2 -> must be dropped immediately by rate limiter
    let mut dropped_tcp = TcpStream::connect(data_addr).await.unwrap();
    let mut buf = [0u8; 16];
    let read_res = tokio::time::timeout(Duration::from_secs(2), dropped_tcp.read(&mut buf)).await;
    assert!(
        matches!(read_res, Ok(Ok(0)) | Ok(Err(_))),
        "Rate-limited TCP connection must be closed immediately, got {:?}",
        read_res
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .is_err(),
        "Rate-limited connection must not reach tunnel open_stream"
    );

    cancel_token.cancel();
    data_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn test_run_data_plane_concurrency_limit_enforced_over_tcp() {
    ensure_crypto_provider();
    let pki = TestPki::new();

    let tunnels = new_session_map();
    let (tx, mut rx) = tokio::sync::mpsc::channel(16);
    tunnels.insert(
        "wurzelwerk.api.aweirich.eu".to_string(),
        TunnelRoute {
            control: Control::new(tx),
            generation: 1,
            supports_proxy_v2: false,
        },
    );

    let data_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let data_addr = data_listener.local_addr().unwrap();
    let cancel_token = CancellationToken::new();
    // Max 1 concurrent connection per IP
    let tracker = Arc::new(RelayConnectionTracker::new(10, 1));

    let data_task = tokio::spawn(run_data_plane(
        data_listener,
        tunnels,
        100.0,
        100.0,
        None,
        None,
        tracker.clone(),
        Duration::from_secs(5),
        cancel_token.clone(),
    ));

    // 1st connection stays open waiting in read_client_hello_record, holding the single slot
    let mut first_tcp = TcpStream::connect(data_addr).await.unwrap();
    first_tcp.write_all(&[0x16, 0x03]).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), async {
        while tracker.current_global() < 1 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("First connection must acquire concurrency slot");

    // 2nd concurrent connection from 127.0.0.1 must be dropped immediately
    let mut second_tcp = TcpStream::connect(data_addr).await.unwrap();
    let mut buf = [0u8; 8];
    let second_read = tokio::time::timeout(Duration::from_secs(2), second_tcp.read(&mut buf)).await;
    assert!(
        matches!(second_read, Ok(Ok(0)) | Ok(Err(_))),
        "2nd concurrent connection exceeding max_per_ip=1 must be dropped, got {:?}",
        second_read
    );
    assert_eq!(tracker.current_global(), 1);

    // Close 1st connection and wait for guard release
    drop(first_tcp);
    tokio::time::timeout(Duration::from_secs(2), async {
        while tracker.current_global() > 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("Tracker must drop to 0 after first connection closes");

    // 3rd connection now succeeds and reaches tunnel open_stream()
    let third_tcp = TcpStream::connect(data_addr).await.unwrap();
    let conn = build_external_client_connector(&pki);
    let sni = ServerName::try_from("wurzelwerk.api.aweirich.eu".to_string()).unwrap();
    tokio::spawn(async move {
        let _ = conn.connect(sni, third_tcp).await;
    });
    let req = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("3rd connection should succeed after slot is freed");
    drop(req);

    cancel_token.cancel();
    data_task.await.unwrap().unwrap();
}

#[tokio::test]
async fn test_control_plane_mtls_handshake_timeout_and_untrusted_client_rejected() {
    ensure_crypto_provider();
    let pki = TestPki::new();

    let tunnels = new_session_map();
    let control_acceptor = build_control_mtls_acceptor(&pki, None);

    // 1. Handshake timeout when client sends nothing
    let (client_io, server_io) = tokio::io::duplex(4096);
    let tunnels1 = tunnels.clone();
    let acc1 = control_acceptor.clone();
    let task1 = tokio::spawn(async move {
        handle_control_connection(
            server_io,
            "127.0.0.1:51001".parse().unwrap(),
            acc1,
            tunnels1,
            Duration::from_millis(50),
            4096,
            true,
        )
        .await;
    });
    tokio::time::timeout(Duration::from_secs(2), task1)
        .await
        .expect("Control connection must time out mTLS handshake")
        .unwrap();
    drop(client_io);

    // 2. Client without client certificate is rejected by mTLS WebPkiClientVerifier
    let mut root_store = RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(&pki.relay_ca_pem).unwrap() {
        root_store.add(cert.unwrap()).unwrap();
    }
    let no_auth_connector = TlsConnector::from(Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    ));

    let (client_io2, server_io2) = tokio::io::duplex(65536);
    let tunnels2 = tunnels.clone();
    let task2 = tokio::spawn(async move {
        handle_control_connection(
            server_io2,
            "127.0.0.1:51002".parse().unwrap(),
            control_acceptor,
            tunnels2,
            Duration::from_secs(5),
            4096,
            true,
        )
        .await;
    });

    let domain = ServerName::try_from("localhost".to_string()).unwrap();
    let res = no_auth_connector.connect(domain, client_io2).await;
    if let Ok(mut tls_stream) = res {
        // TLS 1.3 server sends CertificateRequest/alert after client Finished; reading/writing observes rejection
        let _ = tls_stream.write_all(b"REGISTER wurzelwerk.api.aweirich.eu\n").await;
        let _ = tls_stream.flush().await;
        let mut buf = [0u8; 16];
        let _ = tls_stream.read(&mut buf).await;
    }
    task2.await.unwrap();
    assert!(tunnels.is_empty());
}

#[tokio::test]
async fn test_control_plane_crl_revocation_rejects_revoked_client_cert() {
    ensure_crypto_provider();
    let pki = TestPki::new();

    let control_acceptor = build_control_mtls_acceptor(&pki, Some(&pki.relay_crl_revoking_client_pem));

    let tunnels = new_session_map();
    let (client_io, server_io) = tokio::io::duplex(65536);
    let tunnels_ctrl = tunnels.clone();
    let server_task = tokio::spawn(async move {
        handle_control_connection(
            server_io,
            "127.0.0.1:51003".parse().unwrap(),
            control_acceptor,
            tunnels_ctrl,
            Duration::from_secs(5),
            4096,
            true,
        )
        .await;
    });

    let connector = build_control_plane_client_connector(&pki);
    let domain = ServerName::try_from("localhost".to_string()).unwrap();
    if let Ok(mut tls_stream) = connector.connect(domain, client_io).await {
        let _ = tls_stream
            .write_all(b"REGISTER wurzelwerk.api.aweirich.eu\n")
            .await;
        let _ = tls_stream.flush().await;
        let mut buf = [0u8; 16];
        let _ = tls_stream.read(&mut buf).await;
    }

    server_task.await.unwrap();
    assert!(
        tunnels.is_empty(),
        "Revoked client certificate must be rejected by CRL check and never register a tunnel"
    );
}

#[tokio::test]
async fn test_control_plane_malformed_and_oversized_register_commands_rejected() {
    ensure_crypto_provider();
    let pki = TestPki::new();

    let control_acceptor = build_control_mtls_acceptor(&pki, None);
    let connector = build_control_plane_client_connector(&pki);
    let domain = ServerName::try_from("localhost".to_string()).unwrap();

    let oversized_payload = vec![b'a'; 1030];
    let bad_payloads: Vec<&[u8]> = vec![
        b"INVALID wurzelwerk.api.aweirich.eu\n",
        b"REGISTER ../etc/passwd\n",
        b"\xff\xfe\xfd\n",
        &oversized_payload,
    ];

    for payload in bad_payloads {
        let tunnels = new_session_map();
        let (client_io, server_io) = tokio::io::duplex(65536);
        let tunnels_ctrl = tunnels.clone();
        let acc = control_acceptor.clone();
        let server_task = tokio::spawn(async move {
            handle_control_connection(
                server_io,
                "127.0.0.1:51004".parse().unwrap(),
                acc,
                tunnels_ctrl,
                Duration::from_secs(5),
                4096,
                true,
            )
            .await;
        });

        let mut tls_stream = connector.connect(domain.clone(), client_io).await.unwrap();
        let _ = tls_stream.write_all(payload).await;
        let _ = tls_stream.flush().await;

        tokio::time::timeout(Duration::from_secs(2), server_task)
            .await
            .expect("Malformed REGISTER must cause control handler to exit promptly")
            .unwrap();
        assert!(tunnels.is_empty());
    }
}

#[tokio::test]
async fn test_data_plane_scanner_slowloris_and_dead_tunnel_handled_cleanly() {
    ensure_crypto_provider();
    let pki = TestPki::new();

    let tunnels = new_session_map();

    // 1. Plaintext HTTP scanner probe -> handled cleanly without panic or hang
    let (mut scanner_client, scanner_server) = tokio::io::duplex(4096);
    let tunnels1 = tunnels.clone();
    let scanner_task = tokio::spawn(async move {
        handle_data_connection(
            scanner_server,
            "198.51.100.10:12345".parse().unwrap(),
            "127.0.0.1:443".parse().unwrap(),
            tunnels1,
            None,
            Duration::from_secs(2),
        )
        .await;
    });
    scanner_client
        .write_all(b"GET /wp-login.php HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    drop(scanner_client);
    tokio::time::timeout(Duration::from_secs(2), scanner_task)
        .await
        .unwrap()
        .unwrap();

    // 2. Slowloris partial TLS header -> timed out by client_hello_timeout
    let (mut slow_client, slow_server) = tokio::io::duplex(4096);
    let tunnels2 = tunnels.clone();
    let slow_task = tokio::spawn(async move {
        handle_data_connection(
            slow_server,
            "198.51.100.11:12346".parse().unwrap(),
            "127.0.0.1:443".parse().unwrap(),
            tunnels2,
            None,
            Duration::from_millis(50),
        )
        .await;
    });
    slow_client.write_all(&[0x16, 0x03, 0x01]).await.unwrap();
    tokio::time::timeout(Duration::from_secs(2), slow_task)
        .await
        .unwrap()
        .unwrap();
    drop(slow_client);

    // 3. Registered route whose Control receiver was dropped (dead tunnel) -> exits cleanly
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    drop(rx);
    tunnels.insert(
        "wurzelwerk.api.aweirich.eu".to_string(),
        TunnelRoute {
            control: Control::new(tx),
            generation: 1,
            supports_proxy_v2: false,
        },
    );
    let (client_io, server_io) = tokio::io::duplex(65536);
    let dead_task = tokio::spawn(async move {
        handle_data_connection(
            server_io,
            "198.51.100.12:12347".parse().unwrap(),
            "127.0.0.1:443".parse().unwrap(),
            tunnels,
            None,
            Duration::from_secs(2),
        )
        .await;
    });
    let connector = build_external_client_connector(&pki);
    let res = connector
        .connect(
            ServerName::try_from("wurzelwerk.api.aweirich.eu".to_string()).unwrap(),
            client_io,
        )
        .await;
    assert!(res.is_err());
    tokio::time::timeout(Duration::from_secs(2), dead_task)
        .await
        .unwrap()
        .unwrap();
}

#[tokio::test]
async fn test_control_plane_generation_guard_preserves_newer_route_on_stale_cleanup() {
    ensure_crypto_provider();
    let pki = TestPki::new();

    let tunnels = new_session_map();
    let control_acceptor = build_control_mtls_acceptor(&pki, None);

    let sni_domain = "wurzelwerk.idp.aweirich.eu";
    let (praeco_io, relay_io) = tokio::io::duplex(65536);
    let tunnels_ctrl = tunnels.clone();
    let server_task = tokio::spawn(async move {
        handle_control_connection(
            relay_io,
            "127.0.0.1:51005".parse().unwrap(),
            control_acceptor,
            tunnels_ctrl,
            Duration::from_secs(5),
            4096,
            true,
        )
        .await;
    });

    let connector = build_control_plane_client_connector(&pki);
    let mut tls = connector
        .connect(ServerName::try_from("localhost".to_string()).unwrap(), praeco_io)
        .await
        .unwrap();
    tls.write_all(format!("REGISTER {}\n", sni_domain).as_bytes())
        .await
        .unwrap();
    tls.flush().await.unwrap();
    let mut yamux = Connection::new(tls.compat(), YamuxConfig::default(), Mode::Client);

    wait_for_tunnel_registration(&tunnels, sni_domain).await;
    let old_gen = tunnels.get(sni_domain).unwrap().generation;

    // Simulate a newer tunnel generation taking over the route entry before old cleanup runs
    let newer_gen = old_gen + 100;
    let (tx_new, _rx_new) = tokio::sync::mpsc::channel(4);
    tunnels.insert(
        sni_domain.to_string(),
        TunnelRoute {
            control: Control::new(tx_new),
            generation: newer_gen,
            supports_proxy_v2: true,
        },
    );

    // Close the old tunnel; its remove_if must NOT remove newer_gen
    let _ = std::future::poll_fn(|cx| yamux.poll_close(cx)).await;
    drop(yamux);
    server_task.await.unwrap();

    let current = tunnels
        .get(sni_domain)
        .expect("Newer generation route must not be removed by stale tunnel cleanup");
    assert_eq!(current.generation, newer_gen);
}

#[tokio::test]
async fn test_control_plane_client_cert_without_dns_sans_rejected() {
    ensure_crypto_provider();
    let pki = TestPki::new();

    let mut root_store = RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(&pki.relay_ca_pem).unwrap() {
        root_store.add(cert.unwrap()).unwrap();
    }
    let client_certs: Vec<CertificateDer> = CertificateDer::pem_file_iter(&pki.nosan_client_pem)
        .unwrap()
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let client_key = PrivateKeyDer::from_pem_file(&pki.nosan_client_key).unwrap();
    let no_san_connector = TlsConnector::from(Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(client_certs, client_key)
            .unwrap(),
    ));

    let control_acceptor = build_control_mtls_acceptor(&pki, None);

    let tunnels = new_session_map();
    let (client_io, server_io) = tokio::io::duplex(65536);
    let tunnels_ctrl = tunnels.clone();
    let server_task = tokio::spawn(async move {
        handle_control_connection(
            server_io,
            "127.0.0.1:51006".parse().unwrap(),
            control_acceptor,
            tunnels_ctrl,
            Duration::from_secs(5),
            4096,
            true,
        )
        .await;
    });

    let mut tls = no_san_connector
        .connect(ServerName::try_from("localhost".to_string()).unwrap(), client_io)
        .await
        .expect("mTLS handshake with CA-signed cert must succeed before SAN check");
    let _ = tls
        .write_all(b"REGISTER wurzelwerk.api.aweirich.eu\n")
        .await;
    let _ = tls.flush().await;

    tokio::time::timeout(Duration::from_secs(2), server_task)
        .await
        .expect("Control handler must reject cert without DNS SANs promptly")
        .unwrap();
    assert!(tunnels.is_empty());
}

#[tokio::test]
async fn test_data_plane_case_insensitive_sni_routing() {
    ensure_crypto_provider();
    let pki = TestPki::new();

    let tunnels = new_session_map();
    let control_acceptor = build_control_mtls_acceptor(&pki, None);

    let lower_sni = "wurzelwerk.api.aweirich.eu";
    let upper_sni = "WURZELWERK.API.AWEIRICH.EU";

    // 1. Register tunnel using uppercase SNI in REGISTER (normalized to lowercase in SessionMap)
    let (praeco_ctrl_io, relay_ctrl_io) = tokio::io::duplex(65536);
    let tunnels_ctrl = tunnels.clone();
    let ctrl_task = tokio::spawn(async move {
        handle_control_connection(
            relay_ctrl_io,
            "127.0.0.1:51007".parse().unwrap(),
            control_acceptor,
            tunnels_ctrl,
            Duration::from_secs(5),
            4096,
            false,
        )
        .await;
    });

    let connector = build_control_plane_client_connector(&pki);
    let praeco_task = tokio::spawn(async move {
        let mut tls = connector
            .connect(
                ServerName::try_from("localhost".to_string()).unwrap(),
                praeco_ctrl_io,
            )
            .await
            .unwrap();
        tls.write_all(format!("REGISTER {}\n", upper_sni).as_bytes())
            .await
            .unwrap();
        tls.flush().await.unwrap();

        let mut yamux_conn = Connection::new(tls.compat(), YamuxConfig::default(), Mode::Client);
        let inbound = std::future::poll_fn(|cx| yamux_conn.poll_next_inbound(cx))
            .await
            .expect("Expected inbound Yamux stream for uppercase ClientHello SNI")
            .expect("Yamux stream error");

        let driver = tokio::spawn(async move {
            while let Some(Ok(_)) =
                std::future::poll_fn(|cx| yamux_conn.poll_next_inbound(cx)).await
            {}
        });

        // Verify the forwarded ClientHello contains our patched uppercase SNI
        // (post-quantum ClientHellos with ML-KEM768 exceed 512 bytes, so read the full record).
        let mut compat = inbound.compat();
        let mut received = Vec::with_capacity(2048);
        let mut chunk = [0u8; 1024];
        loop {
            let n = compat.read(&mut chunk).await.unwrap();
            if n == 0 {
                break;
            }
            received.extend_from_slice(&chunk[..n]);
            if received
                .windows(upper_sni.len())
                .any(|w| w == upper_sni.as_bytes())
            {
                break;
            }
        }
        assert!(
            received
                .windows(upper_sni.len())
                .any(|w| w == upper_sni.as_bytes()),
            "Forwarded ClientHello must arrive at the matching lowercase tunnel"
        );
        compat.write_all(b"ROUTED_OK").await.unwrap();
        compat.flush().await.unwrap();
        let _ = compat.shutdown().await;
        // Drain any trailing ClientHello bytes and wait until the external client reads ROUTED_OK
        // and closes its half (EOF == 0) before aborting the Yamux driver.
        let mut drain_buf = [0u8; 256];
        while matches!(compat.read(&mut drain_buf).await, Ok(n) if n > 0) {}
        driver.abort();
    });

    wait_for_tunnel_registration(&tunnels, lower_sni).await;

    // 2. Build a real ClientHello for lower_sni and patch the SNI bytes in-place to uppercase
    let client_cfg = Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(RootCertStore::empty())
            .with_no_client_auth(),
    );
    let mut rustls_conn = rustls::ClientConnection::new(
        client_cfg,
        ServerName::try_from(lower_sni.to_string()).unwrap(),
    )
    .unwrap();
    let mut hello_bytes = Vec::new();
    rustls_conn.write_tls(&mut hello_bytes).unwrap();
    let pos = hello_bytes
        .windows(lower_sni.len())
        .position(|w| w == lower_sni.as_bytes())
        .expect("ClientHello must contain lowercase SNI bytes");
    hello_bytes[pos..pos + lower_sni.len()].copy_from_slice(upper_sni.as_bytes());

    let (mut client_data_io, relay_data_io) = tokio::io::duplex(65536);
    let tunnels_data = tunnels.clone();
    let data_task = tokio::spawn(async move {
        handle_data_connection(
            relay_data_io,
            "198.51.100.55:44444".parse().unwrap(),
            "127.0.0.1:443".parse().unwrap(),
            tunnels_data,
            None,
            Duration::from_secs(5),
        )
        .await;
    });

    client_data_io.write_all(&hello_bytes).await.unwrap();
    client_data_io.flush().await.unwrap();

    let mut ack = [0u8; 9];
    client_data_io.read_exact(&mut ack).await.unwrap();
    assert_eq!(&ack, b"ROUTED_OK");
    drop(client_data_io);

    praeco_task.await.unwrap();
    data_task.await.unwrap();
    ctrl_task.await.unwrap();
}

#[tokio::test]
async fn test_control_plane_unexpected_inbound_yamux_stream_keeps_tunnel_healthy() {
    ensure_crypto_provider();
    let pki = TestPki::new();

    let tunnels = new_session_map();
    let control_acceptor = build_control_mtls_acceptor(&pki, None);

    let sni_domain = "wurzelwerk.api.aweirich.eu";
    let (praeco_ctrl_io, relay_ctrl_io) = tokio::io::duplex(65536);
    let tunnels_ctrl = tunnels.clone();
    let ctrl_task = tokio::spawn(async move {
        handle_control_connection(
            relay_ctrl_io,
            "127.0.0.1:51008".parse().unwrap(),
            control_acceptor,
            tunnels_ctrl,
            Duration::from_secs(5),
            4096,
            false,
        )
        .await;
    });

    let (unexpected_sent_tx, unexpected_sent_rx) = tokio::sync::oneshot::channel::<()>();
    let connector = build_control_plane_client_connector(&pki);
    let e2e_acceptor = build_backend_e2e_acceptor(&pki);
    let praeco_task = tokio::spawn(async move {
        let mut tls = connector
            .connect(
                ServerName::try_from("localhost".to_string()).unwrap(),
                praeco_ctrl_io,
            )
            .await
            .unwrap();
        tls.write_all(format!("REGISTER {}\n", sni_domain).as_bytes())
            .await
            .unwrap();
        tls.flush().await.unwrap();

        let mut yamux_conn = Connection::new(tls.compat(), YamuxConfig::default(), Mode::Client);

        // Client unexpectedly opens an outbound stream toward Relay (Relay expects only server->client streams)
        let unexpected_stream = std::future::poll_fn(|cx| yamux_conn.poll_new_outbound(cx))
            .await
            .expect("Yamux client outbound open should succeed");
        drop(unexpected_stream);
        let _ = unexpected_sent_tx.send(());

        // Tunnel must still receive legitimate Data Plane inbound streams afterwards
        let inbound = std::future::poll_fn(|cx| yamux_conn.poll_next_inbound(cx))
            .await
            .expect("Tunnel must remain healthy after unexpected inbound stream")
            .expect("Yamux stream error");

        let driver = tokio::spawn(async move {
            while let Some(Ok(_)) =
                std::future::poll_fn(|cx| yamux_conn.poll_next_inbound(cx)).await
            {}
        });

        let mut e2e_tls = e2e_acceptor.accept(inbound.compat()).await.unwrap();
        let mut reader = TokioBufReader::new(&mut e2e_tls);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        assert_eq!(line, "STILL ALIVE\n");

        e2e_tls.write_all(b"YES\n").await.unwrap();
        e2e_tls.flush().await.unwrap();
        let _ = e2e_tls.shutdown().await;
        let mut eof = [0u8; 1];
        let _ = e2e_tls.read(&mut eof).await;
        driver.abort();
    });

    wait_for_tunnel_registration(&tunnels, sni_domain).await;
    unexpected_sent_rx.await.unwrap();
    // Give the Relay driver loop a moment to process & drop the unexpected inbound stream
    tokio::time::sleep(Duration::from_millis(20)).await;
    assert!(
        tunnels.contains_key(sni_domain),
        "Tunnel must stay registered after unexpected client-initiated Yamux stream"
    );

    let (client_data_io, relay_data_io) = tokio::io::duplex(65536);
    let tunnels_data = tunnels.clone();
    let data_task = tokio::spawn(async move {
        handle_data_connection(
            relay_data_io,
            "198.51.100.66:33333".parse().unwrap(),
            "127.0.0.1:443".parse().unwrap(),
            tunnels_data,
            None,
            Duration::from_secs(5),
        )
        .await;
    });

    let ext_connector = build_external_client_connector(&pki);
    let mut ext_tls = ext_connector
        .connect(
            ServerName::try_from(sni_domain.to_string()).unwrap(),
            client_data_io,
        )
        .await
        .unwrap();
    ext_tls.write_all(b"STILL ALIVE\n").await.unwrap();
    ext_tls.flush().await.unwrap();

    let mut ext_reader = TokioBufReader::new(&mut ext_tls);
    let mut resp = String::new();
    ext_reader.read_line(&mut resp).await.unwrap();
    assert_eq!(resp, "YES\n");
    let _ = ext_tls.shutdown().await;

    praeco_task.await.unwrap();
    data_task.await.unwrap();
    ctrl_task.await.unwrap();
}



