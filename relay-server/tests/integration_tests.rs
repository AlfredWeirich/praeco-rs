//! # Praeco Relay Server Integration & E2E Tests
//!
//! End-to-End integration tests verifying the full Zero-Trust Reverse Tunneling
//! pipeline between the Data Plane, Control Plane (mTLS + SAN authorization),
//! Yamux stream multiplexing, and HAProxy PROXY Protocol v2 propagation.

use common::proxy_protocol::read_proxy_v2;
use praeco_relay_server::{
    SessionMap, handle_control_connection, handle_data_connection, new_session_map,
    setup_mtls_acceptor,
};
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader as TokioBufReader};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use yamux::{Config as YamuxConfig, Connection, Mode};

fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// Builds a `TlsConnector` for the simulated Praeco Gateway to authenticate
/// against the Relay Server's Control Plane via mTLS.
fn build_control_plane_client_connector() -> TlsConnector {
    let mut root_store = RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter("../server_certs/self_signed/relay_ca.pem")
        .expect("Failed to open relay_ca.pem")
    {
        root_store
            .add(cert.expect("Invalid CA cert"))
            .expect("Failed to add CA cert");
    }

    let certs: Vec<CertificateDer> =
        CertificateDer::pem_file_iter("../server_certs/self_signed/praeco_client.pem")
            .expect("Failed to open praeco_client.pem")
            .collect::<Result<Vec<_>, _>>()
            .expect("Failed to parse client certs");

    let key = PrivateKeyDer::from_pem_file("../server_certs/self_signed/praeco_client.key")
        .expect("Failed to read praeco_client.key");

    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(certs, key)
        .expect("Failed to build mTLS client config");

    TlsConnector::from(Arc::new(client_config))
}

/// Builds an end-to-end `TlsAcceptor` representing the backend Praeco Gateway
/// that terminates the end-user's HTTPS connection.
fn build_backend_e2e_acceptor() -> TlsAcceptor {
    let certs: Vec<CertificateDer> =
        CertificateDer::pem_file_iter("../server_certs/self_signed/praeco_public.pem")
            .expect("Failed to open praeco_public.pem")
            .collect::<Result<Vec<_>, _>>()
            .expect("Failed to parse backend certs");

    let key = PrivateKeyDer::from_pem_file("../server_certs/self_signed/praeco_public.key")
        .expect("Failed to read praeco_public.key");

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("Failed to build backend server config");

    TlsAcceptor::from(Arc::new(server_config))
}

/// Builds an end-to-end `TlsConnector` representing an external client (browser/API client)
/// connecting to the Relay Data Plane and verifying the backend's `praeco_public.pem` against `public_ca.pem`.
fn build_external_client_connector() -> TlsConnector {
    let mut root_store = RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter("../server_certs/self_signed/public_ca.pem")
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

    let tunnels = new_session_map();
    let control_acceptor = setup_mtls_acceptor(
        "../server_certs/self_signed/relay_ca.pem",
        "../server_certs/self_signed/relay_server.pem",
        "../server_certs/self_signed/relay_server.key",
        None,
    )
    .expect("Failed to setup Relay mTLS acceptor");

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
    let praeco_task = tokio::spawn(async move {
        let connector = build_control_plane_client_connector();
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

        let e2e_acceptor = build_backend_e2e_acceptor();
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

    let client_connector = build_external_client_connector();
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

    let tunnels = new_session_map();
    let control_acceptor = setup_mtls_acceptor(
        "../server_certs/self_signed/relay_ca.pem",
        "../server_certs/self_signed/relay_server.pem",
        "../server_certs/self_signed/relay_server.key",
        None,
    )
    .expect("Failed to setup Relay mTLS acceptor");

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

    let praeco_task = tokio::spawn(async move {
        let connector = build_control_plane_client_connector();
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

        let e2e_acceptor = build_backend_e2e_acceptor();
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

    let client_connector = build_external_client_connector();
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

    let tunnels = new_session_map();
    let control_acceptor = setup_mtls_acceptor(
        "../server_certs/self_signed/relay_ca.pem",
        "../server_certs/self_signed/relay_server.pem",
        "../server_certs/self_signed/relay_server.key",
        None,
    )
    .unwrap();

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
    let praeco_task = tokio::spawn(async move {
        let connector = build_control_plane_client_connector();
        let domain = ServerName::try_from("localhost".to_string()).unwrap();
        let mut tls_stream = connector.connect(domain, praeco_ctrl_io).await.unwrap();

        let cmd = format!("REGISTER {}\n", sni_domain);
        tls_stream.write_all(cmd.as_bytes()).await.unwrap();
        tls_stream.flush().await.unwrap();

        let mut yamux_conn =
            Connection::new(tls_stream.compat(), YamuxConfig::default(), Mode::Client);
        let e2e_acceptor = build_backend_e2e_acceptor();

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
    let mut client_handles = Vec::new();
    for i in 0..num_concurrent_clients {
        let tunnels_data = tunnels.clone();
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

            let connector = build_external_client_connector();
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

    let tunnels = new_session_map();
    let control_acceptor = setup_mtls_acceptor(
        "../server_certs/self_signed/relay_ca.pem",
        "../server_certs/self_signed/relay_server.pem",
        "../server_certs/self_signed/relay_server.key",
        None,
    )
    .unwrap();

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

    let connector = build_control_plane_client_connector();
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

    let tunnels = new_session_map();
    let control_acceptor = setup_mtls_acceptor(
        "../server_certs/self_signed/relay_ca.pem",
        "../server_certs/self_signed/relay_server.pem",
        "../server_certs/self_signed/relay_server.key",
        None,
    )
    .unwrap();

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

    let connector = build_control_plane_client_connector();
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

    let client_connector = build_external_client_connector();
    let target_sni = ServerName::try_from("wurzelwerk.api.aweirich.eu".to_string()).unwrap();

    // Handshake must fail cleanly because Relay closes the stream when no route exists
    let res = client_connector.connect(target_sni, client_data_io).await;
    assert!(
        res.is_err(),
        "Connection to unregistered SNI must fail cleanly"
    );

    data_server_task.await.unwrap();
}

