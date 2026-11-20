use super::*;
use crate::limits::RateLimitTable;
use rustls::RootCertStore;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::net::IpAddr;

    #[test]
    fn test_praeco_client_cert_snis() {
        let pki = common::test_pki::TestPki::new();
        let certs: Vec<CertificateDer> = CertificateDer::pem_file_iter(&pki.praeco_client_pem)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let cert_der = certs.first().unwrap();
        let allowed_snis = extract_allowed_snis(cert_der);
        assert!(allowed_snis.contains(&"wurzelwerk.api.aweirich.eu".to_string()));
        assert!(allowed_snis.contains(&"wurzelwerk.onboarding.aweirich.eu".to_string()));
        assert!(allowed_snis.contains(&"wurzelwerk.admin.aweirich.eu".to_string()));
        assert!(allowed_snis.contains(&"wurzelwerk.idp.aweirich.eu".to_string()));
    }

    #[tokio::test]
    async fn test_full_control_plane_registration() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let pki = common::test_pki::TestPki::new();
        // 1. Setup Acceptor
        let acceptor = setup_mtls_acceptor(
            common::test_pki::TestPki::s(&pki.relay_ca_pem),
            common::test_pki::TestPki::s(&pki.relay_server_pem),
            common::test_pki::TestPki::s(&pki.relay_server_key),
            None,
        )
        .unwrap();

        let (client_io, server_io) = tokio::io::duplex(65536);

        let listener_task = tokio::spawn(async move {
            let mut tls_stream = acceptor.accept(server_io).await.unwrap();
            let allowed_snis = tls_stream
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|certs| certs.first())
                .map(|cert_der| extract_allowed_snis(cert_der))
                .unwrap_or_default();

            let mut line_bytes = Vec::new();
            let mut byte = [0u8; 1];
            while tls_stream.read_exact(&mut byte).await.is_ok() {
                if byte[0] == b'\n' {
                    break;
                }
                line_bytes.push(byte[0]);
            }
            let line = String::from_utf8(line_bytes).unwrap();
            let (sni, _) = parse_register_command(&line, true).expect("Invalid REGISTER");
            assert!(
                allowed_snis.contains(&sni),
                "SNI not authorized! allowed_snis: {:?}, requested: {:?}",
                allowed_snis,
                sni
            );
        });

        // 2. Client side (Praeco run_tunnel)
        let mut root_store = rustls::RootCertStore::empty();
        for cert in CertificateDer::pem_file_iter(&pki.relay_ca_pem).unwrap() {
            root_store.add(cert.unwrap()).unwrap();
        }
        let certs: Vec<CertificateDer> = CertificateDer::pem_file_iter(&pki.praeco_client_pem)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let key = PrivateKeyDer::from_pem_file(&pki.praeco_client_key).unwrap();

        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(certs, key)
            .unwrap();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

        let domain = rustls::pki_types::ServerName::try_from("localhost".to_string()).unwrap();
        let mut tls_stream = connector.connect(domain, client_io).await.unwrap();

        let reg_cmd = "REGISTER wurzelwerk.onboarding.aweirich.eu\n";
        tls_stream.write_all(reg_cmd.as_bytes()).await.unwrap();
        tls_stream.flush().await.unwrap();

        // Simulate Praeco immediately wrapping the stream in Yamux
        let _client_conn =
            Connection::new(tls_stream.compat(), YamuxConfig::default(), Mode::Client);

        listener_task.await.unwrap();
    }

    #[test]
    fn test_canonicalize_ip() {
        // IPv4
        let ip4: IpAddr = "192.168.1.50".parse().unwrap();
        assert_eq!(canonicalize_ip(ip4), ip4);

        // IPv4-mapped IPv6
        let ip4_mapped: IpAddr = "::ffff:192.168.1.50".parse().unwrap();
        assert_eq!(canonicalize_ip(ip4_mapped), ip4);

        // IPv6 loopback preserved
        let loopback6: IpAddr = "::1".parse().unwrap();
        assert_eq!(canonicalize_ip(loopback6), loopback6);

        // IPv6 /64 aggregation
        let ip6_a: IpAddr = "2001:db8:abcd:0012:0000:0000:0000:0001".parse().unwrap();
        let ip6_b: IpAddr = "2001:db8:abcd:0012:ffff:ffff:ffff:ffff".parse().unwrap();
        let ip6_masked: IpAddr = "2001:db8:abcd:0012::".parse().unwrap();

        assert_eq!(canonicalize_ip(ip6_a), ip6_masked);
        assert_eq!(canonicalize_ip(ip6_b), ip6_masked);
        assert_eq!(canonicalize_ip(ip6_a), canonicalize_ip(ip6_b));
    }

    #[test]
    fn test_relay_connection_tracker_limits() {
        let tracker = Arc::new(RelayConnectionTracker::new(3, 2));

        let ip1: IpAddr = "10.0.0.1".parse().unwrap();
        let ip2: IpAddr = "10.0.0.2".parse().unwrap();

        // 1. Acquire 2 connections for ip1 (allowed)
        let g1 = tracker.acquire(ip1).expect("g1 should succeed");
        let g2 = tracker.acquire(ip1).expect("g2 should succeed");
        assert_eq!(tracker.current_global(), 2);
        assert_eq!(tracker.current_for_ip(ip1), 2);

        // 2. 3rd connection for ip1 exceeds per-IP limit (max 2)
        assert!(tracker.acquire(ip1).is_err());

        // 3. 3rd global connection for ip2 (allowed)
        let g3 = tracker.acquire(ip2).expect("g3 should succeed");
        assert_eq!(tracker.current_global(), 3);

        // 4. 4th connection exceeds global limit (max 3)
        assert!(tracker.acquire(ip2).is_err());

        // 5. Drop g1 -> global drops to 2, ip1 drops to 1
        drop(g1);
        assert_eq!(tracker.current_global(), 2);
        assert_eq!(tracker.current_for_ip(ip1), 1);

        // Now ip1 can acquire 1 more
        let g4 = tracker.acquire(ip1).expect("g4 should succeed");
        assert_eq!(tracker.current_global(), 3);
        assert_eq!(tracker.current_for_ip(ip1), 2);

        // Drop remaining
        drop(g2);
        drop(g3);
        drop(g4);
        assert_eq!(tracker.current_global(), 0);
        assert_eq!(tracker.current_for_ip(ip1), 0);
    }

    #[tokio::test]
    async fn test_read_client_hello_record_fragmented() {
        // Construct a synthetic valid TLS handshake record:
        // Header: [0x16, 0x03, 0x01, 0x00, 0x0A] (length 10)
        // Payload: 10 bytes of dummy handshake
        let mut full_record = vec![0x16, 0x03, 0x01, 0x00, 0x0A];
        full_record.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

        let (mut client_write, mut server_read) = tokio::io::duplex(64);
        let to_send = full_record.clone();

        // Send in 3 separate fragmented chunks:
        // Chunk 1: 3 bytes of header
        // Chunk 2: 2 bytes of header + 4 bytes of payload
        // Chunk 3: 6 bytes of payload
        tokio::spawn(async move {
            client_write.write_all(&to_send[..3]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
            client_write.write_all(&to_send[3..9]).await.unwrap();
            tokio::time::sleep(Duration::from_millis(10)).await;
            client_write.write_all(&to_send[9..]).await.unwrap();
        });

        let result = read_client_hello_record(&mut server_read, Duration::from_secs(2))
            .await
            .expect("Fragmented record reading should succeed");

        assert_eq!(result, full_record);
    }

    #[tokio::test]
    async fn test_read_client_hello_record_non_tls_scanner() {
        let http_probe = b"GET /admin/shell HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let (mut client_write, mut server_read) = tokio::io::duplex(64);

        tokio::spawn(async move {
            client_write.write_all(http_probe).await.unwrap();
        });

        let result = read_client_hello_record(&mut server_read, Duration::from_secs(2))
            .await
            .expect("Non-TLS scanner probe should return without error");

        assert!(result.starts_with(b"GET /"));
        // Passing non-TLS record to extract_sni will yield a clean error for the scanner preview logger
        assert!(extract_sni(&result).is_err());
    }

    #[tokio::test]
    async fn test_tunnel_overwrite_protection() {
        let active_tunnels: SessionMap = new_session_map();
        let (tx, _rx) = mpsc::channel(32);
        let control = Control::new(tx);

        // Register tunnel for api.test.com
        active_tunnels.insert(
            "api.test.com".to_string(),
            TunnelRoute {
                control: control.clone(),
                generation: 1,
                supports_proxy_v2: false,
            },
        );

        // When existing tunnel's tx is open (active & healthy), new registration must be rejected
        let existing = active_tunnels.get("api.test.com").unwrap();
        assert!(!existing.value().control.is_closed(), "Channel should be open");

        // If the old tunnel closes its receiver (drops connection), is_closed() becomes true
        drop(_rx);
        assert!(
            existing.value().control.is_closed(),
            "Channel should now be closed"
        );
    }

    #[test]
    fn test_register_command_parsing_capability_negotiation() {
        // 1. Legacy Praeco without PROXY_V2
        let (sni1, pp1) = parse_register_command("REGISTER api.example.com\n", true).unwrap();
        assert_eq!(sni1, "api.example.com");
        assert!(!pp1);

        // 2. Modern Praeco with PROXY_V2 and Relay enabled
        let (sni2, pp2) =
            parse_register_command("REGISTER chat.example.com PROXY_V2\n", true).unwrap();
        assert_eq!(sni2, "chat.example.com");
        assert!(pp2);

        // 3. Modern Praeco with PROXY_V2 but Relay config has enable_proxy_protocol = false
        let (sni3, pp3) =
            parse_register_command("REGISTER chat.example.com PROXY_V2\n", false).unwrap();
        assert_eq!(sni3, "chat.example.com");
        assert!(!pp3);

        // 4. Extensible capability flags
        let (sni4, pp4) =
            parse_register_command("REGISTER stream.example.com OTHER_FLAG PROXY_V2\n", true)
                .unwrap();
        assert_eq!(sni4, "stream.example.com");
        assert!(pp4);
    }

    #[test]
    fn test_relay_config_custom_max_yamux_streams() {
        let toml_content = r#"
            control_plane_addr = "127.0.0.1:7001"
            data_plane_addr = "127.0.0.1:443"
            ca_cert_path = "ca.pem"
            server_cert_path = "cert.pem"
            server_key_path = "key.pem"
            max_yamux_streams = 8192
            max_concurrent_connections = 50000
            max_concurrent_connections_per_ip = 500
            client_hello_timeout_secs = 15
            control_plane_handshake_timeout_secs = 12
        "#;
        let config: RelayConfig = toml::from_str(toml_content).unwrap();
        assert_eq!(config.max_yamux_streams, Some(8192));
        assert_eq!(config.max_concurrent_connections, Some(50000));
        assert_eq!(config.max_concurrent_connections_per_ip, Some(500));
        assert_eq!(config.client_hello_timeout_secs, Some(15));
        assert_eq!(config.control_plane_handshake_timeout_secs, Some(12));

        // Test bounded scaling calculation for Yamux config without tripping yamux invariants
        let max_streams = config.max_yamux_streams.unwrap_or(4096);
        let _ = build_yamux_config(4);
        let _ = build_yamux_config(512);
        let _ = build_yamux_config(max_streams);
    }

    #[test]
    fn test_token_bucket_burst_refill_and_cap() {
        let mut bucket = TokenBucket::new(2.0);
        // Initial burst of 2 tokens should succeed
        assert!(bucket.consume(100.0, 2.0));
        assert!(bucket.consume(100.0, 2.0));
        // Immediately consuming a 3rd token should fail
        assert!(!bucket.consume(100.0, 2.0));

        // Wait enough time to refill >= 2 tokens at 100/sec, verify capped at burst=2.0
        std::thread::sleep(Duration::from_millis(50));
        assert!(bucket.consume(100.0, 2.0));
        assert!(bucket.consume(100.0, 2.0));
        assert!(!bucket.consume(100.0, 2.0));
        let _ = bucket.last_update();
    }

    #[test]
    fn test_is_valid_sni() {
        assert!(is_valid_sni("example.com"));
        assert!(is_valid_sni("api-1.sub.example.eu"));
        assert!(is_valid_sni("localhost"));

        assert!(!is_valid_sni(""));
        assert!(!is_valid_sni(&"a".repeat(254)));
        assert!(!is_valid_sni(&format!("{}.com", "a".repeat(64))));
        assert!(!is_valid_sni("-bad.com"));
        assert!(!is_valid_sni("bad-.com"));
        assert!(!is_valid_sni("bad..com"));
        assert!(!is_valid_sni(".bad.com"));
        assert!(!is_valid_sni("bad.com."));
        assert!(!is_valid_sni("bad/path.com"));
        assert!(!is_valid_sni("bad_host.com"));
        assert!(!is_valid_sni("bad host.com"));
    }

    #[test]
    fn test_parse_register_command_invalid_and_case_normalization() {
        assert_eq!(
            parse_register_command("  REGISTER API.Example.COM PROXY_V2 \n", true),
            Some(("api.example.com".to_string(), true))
        );
        assert_eq!(parse_register_command("", true), None);
        assert_eq!(parse_register_command("   \n", true), None);
        assert_eq!(parse_register_command("REGISTER\n", true), None);
        assert_eq!(parse_register_command("HELLO api.example.com\n", true), None);
    }

    #[test]
    fn test_extract_allowed_snis_edge_cases() {
        let pki = common::test_pki::TestPki::new();
        // Garbage bytes return empty list
        assert!(extract_allowed_snis(b"not-a-der-cert").is_empty());

        // CA cert without DNS SAN extensions returns empty list
        let ca_certs: Vec<CertificateDer> = CertificateDer::pem_file_iter(&pki.relay_ca_pem)
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert!(extract_allowed_snis(ca_certs.first().unwrap()).is_empty());
    }

    #[test]
    fn test_setup_mtls_acceptor_errors_and_crl_loading() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let pki = common::test_pki::TestPki::new();
        let ca = common::test_pki::TestPki::s(&pki.relay_ca_pem);
        let srv_cert = common::test_pki::TestPki::s(&pki.relay_server_pem);
        let srv_key = common::test_pki::TestPki::s(&pki.relay_server_key);

        // Missing CA file
        assert!(matches!(
            setup_mtls_acceptor("nonexistent_ca.pem", srv_cert, srv_key, None),
            Err(RelayError::Pem(_) | RelayError::Io(_))
        ));

        // Missing CRL file
        let missing_crl = "nonexistent_crl.pem".to_string();
        assert!(matches!(
            setup_mtls_acceptor(ca, srv_cert, srv_key, Some(&missing_crl)),
            Err(RelayError::Pem(_) | RelayError::Io(_))
        ));

        // Valid certs + CRL file (exercises CRL parsing & expiration warning check)
        let crl_path = pki.relay_crl_pem.to_string_lossy().to_string();
        assert!(setup_mtls_acceptor(ca, srv_cert, srv_key, Some(&crl_path)).is_ok());
    }

    fn build_client_hello_bytes(server_name: rustls::pki_types::ServerName<'static>) -> Vec<u8> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let cfg = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(RootCertStore::empty())
                .with_no_client_auth(),
        );
        let mut conn = rustls::ClientConnection::new(cfg, server_name).unwrap();
        let mut out = Vec::new();
        conn.write_tls(&mut out).unwrap();
        out
    }

    #[test]
    fn test_extract_sni_valid_and_error_cases() {
        // 1. Valid TLS ClientHello with DNS SNI
        let hello_dns = build_client_hello_bytes(
            rustls::pki_types::ServerName::try_from("service.example.eu".to_string()).unwrap(),
        );
        assert_eq!(extract_sni(&hello_dns), Ok("service.example.eu".to_string()));

        // 2. Valid TLS ClientHello with IP literal (no SNI extension per RFC 6066)
        let ip_name = rustls::pki_types::ServerName::IpAddress(
            "127.0.0.1".parse::<IpAddr>().unwrap().into(),
        );
        let hello_ip = build_client_hello_bytes(ip_name);
        assert_eq!(extract_sni(&hello_ip), Err("ClientHello has no SNI extension"));

        // 3. Invalid TLS plaintext
        assert_eq!(
            extract_sni(b"GET / HTTP/1.1\r\n\r\n"),
            Err("Not a valid TLS plaintext message")
        );

        // 4. Valid TLS ChangeCipherSpec record (0x14) -> no handshake
        let ccs = [0x14, 0x03, 0x03, 0x00, 0x01, 0x01];
        assert_eq!(extract_sni(&ccs), Err("No TLS Handshake found"));
    }

    #[tokio::test]
    async fn test_read_client_hello_record_error_cases() {
        // 1. Empty EOF
        let (client_write, mut server_read) = tokio::io::duplex(64);
        drop(client_write);
        assert_eq!(
            read_client_hello_record(&mut server_read, Duration::from_secs(1)).await,
            Err("Connection closed before any data received")
        );

        // 2. Truncated 3-byte header EOF
        let (mut client_write, mut server_read) = tokio::io::duplex(64);
        client_write.write_all(&[0x16, 0x03, 0x01]).await.unwrap();
        drop(client_write);
        assert_eq!(
            read_client_hello_record(&mut server_read, Duration::from_secs(1)).await,
            Err("Unexpected EOF while reading TLS record header")
        );

        // 3. Truncated payload EOF (claims 10 bytes, sends 4)
        let (mut client_write, mut server_read) = tokio::io::duplex(64);
        client_write
            .write_all(&[0x16, 0x03, 0x01, 0x00, 0x0A, 1, 2, 3, 4])
            .await
            .unwrap();
        drop(client_write);
        assert_eq!(
            read_client_hello_record(&mut server_read, Duration::from_secs(1)).await,
            Err("Unexpected EOF while reading TLS record payload")
        );

        // 4. Oversized TLS record (> 16384 bytes)
        let (mut client_write, mut server_read) = tokio::io::duplex(64);
        client_write
            .write_all(&[0x16, 0x03, 0x01, 0x40, 0x01])
            .await
            .unwrap();
        assert_eq!(
            read_client_hello_record(&mut server_read, Duration::from_secs(1)).await,
            Err("TLS record payload exceeds maximum allowable length of 16384 bytes")
        );

        // 5. Slowloris timeout (partial header, stream stays open)
        let (mut client_write, mut server_read) = tokio::io::duplex(64);
        client_write.write_all(&[0x16, 0x03]).await.unwrap();
        let res = read_client_hello_record(&mut server_read, Duration::from_millis(40)).await;
        drop(client_write);
        assert_eq!(res, Err("Timed out while reading TLS ClientHello"));
    }

    #[tokio::test(start_paused = true)]
    async fn test_copy_bidirectional_clean_idle_timeout_and_activity_reset() {
        // 1. Clean bidirectional copy without idle timeout
        let (mut a_peer, a_relay) = tokio::io::duplex(1024);
        let (mut b_peer, b_relay) = tokio::io::duplex(1024);
        let copy_task = tokio::spawn(copy_bidirectional_with_idle_timeout(a_relay, b_relay, None));

        a_peer.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        b_peer.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");

        b_peer.write_all(b"world!").await.unwrap();
        let mut buf2 = [0u8; 6];
        a_peer.read_exact(&mut buf2).await.unwrap();
        assert_eq!(&buf2, b"world!");

        a_peer.shutdown().await.unwrap();
        b_peer.shutdown().await.unwrap();
        match copy_task.await.unwrap() {
            CopyResult::Clean(up, down) => {
                assert_eq!(up, 5);
                assert_eq!(down, 6);
            }
            other => panic!("Expected Clean copy result, got {:?}", other),
        }

        // 2. Idle timeout triggers when no data flows (virtual time auto-advances)
        let (_a_peer2, a_relay2) = tokio::io::duplex(1024);
        let (_b_peer2, b_relay2) = tokio::io::duplex(1024);
        let idle_res = copy_bidirectional_with_idle_timeout(
            a_relay2,
            b_relay2,
            Some(Duration::from_secs(20)),
        )
        .await;
        assert!(matches!(idle_res, CopyResult::IdleTimeout));

        // 3. Continuous periodic activity prevents idle timeout past the timeout window
        let (mut a_peer3, a_relay3) = tokio::io::duplex(1024);
        let (mut b_peer3, b_relay3) = tokio::io::duplex(1024);
        let active_task = tokio::spawn(copy_bidirectional_with_idle_timeout(
            a_relay3,
            b_relay3,
            Some(Duration::from_secs(10)),
        ));

        for _ in 0..5 {
            tokio::time::sleep(Duration::from_secs(6)).await;
            a_peer3.write_all(b"ping").await.unwrap();
            let mut r = [0u8; 4];
            b_peer3.read_exact(&mut r).await.unwrap();
            assert_eq!(&r, b"ping");
        }
        a_peer3.shutdown().await.unwrap();
        b_peer3.shutdown().await.unwrap();
        assert!(matches!(
            active_task.await.unwrap(),
            CopyResult::Clean(20, 0)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_relay_connection_tracker_concurrent_acquire_drop_no_drift() {
        let tracker = Arc::new(RelayConnectionTracker::new(1000, 16));
        let ip: IpAddr = "10.20.30.40".parse().unwrap();

        let mut handles = Vec::new();
        for _ in 0..16 {
            let t = tracker.clone();
            handles.push(tokio::spawn(async move {
                for _ in 0..250 {
                    if let Ok(guard) = t.acquire(ip) {
                        tokio::task::yield_now().await;
                        drop(guard);
                    }
                }
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        assert_eq!(tracker.current_global(), 0);
        assert_eq!(tracker.current_for_ip(ip), 0);
        assert!(tracker.ip_counts.is_empty(), "ip_counts must have no stale entries");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_try_register_tunnel_only_one_wins() {
        let tunnels: SessionMap = new_session_map();
        let barrier = Arc::new(tokio::sync::Barrier::new(8));
        let winners = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        let mut handles = Vec::new();
        let mut receivers = Vec::new();
        for gen_id in 1..=8u64 {
            let (tx, rx) = mpsc::channel(4);
            receivers.push(rx);
            let t = tunnels.clone();
            let b = barrier.clone();
            let w = winners.clone();
            handles.push(tokio::spawn(async move {
                let route = TunnelRoute {
                    control: Control::new(tx),
                    generation: gen_id,
                    supports_proxy_v2: true,
                };
                b.wait().await;
                if try_register_tunnel(&t, "race.example.com".to_string(), route) {
                    w.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }
        for h in handles {
            h.await.unwrap();
        }

        assert_eq!(
            winners.load(Ordering::SeqCst),
            1,
            "Exactly one concurrent REGISTER must win when channel stays open"
        );
        drop(receivers);
    }

    #[tokio::test]
    async fn test_data_connection_times_out_when_open_stream_stalls() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        // Build a real TLS ClientHello with SNI "stalled.example.com"
        let root_store = rustls::RootCertStore::empty();
        let tls_cfg = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth(),
        );
        let server_name = rustls::pki_types::ServerName::try_from("stalled.example.com").unwrap();
        let mut client_conn = rustls::ClientConnection::new(tls_cfg, server_name).unwrap();
        let mut client_hello = Vec::new();
        client_conn.write_tls(&mut client_hello).unwrap();

        // Register a tunnel whose driver rx never responds to open_stream()
        let tunnels: SessionMap = new_session_map();
        let (tx, _rx_stalled) = mpsc::channel(32);
        tunnels.insert(
            "stalled.example.com".to_string(),
            TunnelRoute {
                control: Control::new(tx),
                generation: 1,
                supports_proxy_v2: false,
            },
        );

        let (mut client_write, server_read) = tokio::io::duplex(client_hello.len() + 64);
        client_write.write_all(&client_hello).await.unwrap();

        let addr: SocketAddr = "127.0.0.1:44444".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:443".parse().unwrap();

        // Must return promptly after stream_open_timeout (50ms) rather than hanging
        let res = tokio::time::timeout(
            Duration::from_secs(2),
            handle_data_connection_with_stream_timeout(
                server_read,
                addr,
                local,
                tunnels,
                None,
                Duration::from_secs(2),
                Duration::from_millis(50),
            ),
        )
        .await;
        assert!(res.is_ok(), "handle_data_connection must time out when open_stream stalls");
    }

    #[test]
    fn test_parse_revoked_serials_and_extract_cert_expiry() {
        let pki = common::test_pki::TestPki::new();
        let client_certs: Vec<CertificateDer<'static>> =
            CertificateDer::pem_file_iter(&pki.praeco_client_pem)
                .unwrap()
                .map(|c| c.unwrap())
                .collect();
        let (not_after, client_serial) =
            extract_cert_expiry_and_serial(client_certs[0].as_ref()).expect("valid leaf cert");
        assert!(not_after > current_unix_timestamp());
        assert!(!client_serial.is_empty());

        let non_revoking = parse_revoked_serials_from_crl_pem(
            &pki.relay_crl_pem.to_string_lossy(),
        )
        .expect("parse non-revoking CRL");
        assert!(!non_revoking.contains(&client_serial));

        let revoking = parse_revoked_serials_from_crl_pem(
            &pki.relay_crl_revoking_client_pem.to_string_lossy(),
        )
        .expect("parse revoking CRL");
        assert!(revoking.contains(&client_serial));
    }

    #[tokio::test]
    async fn test_active_control_tunnel_terminated_on_live_crl_revocation() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let pki = common::test_pki::TestPki::new();

        let ca_str = pki.relay_ca_pem.to_string_lossy().to_string();
        let srv_cert_str = pki.relay_server_pem.to_string_lossy().to_string();
        let srv_key_str = pki.relay_server_key.to_string_lossy().to_string();
        let non_revoking_crl = pki.relay_crl_pem.to_string_lossy().to_string();
        let revoking_crl = pki.relay_crl_revoking_client_pem.to_string_lossy().to_string();

        let initial_acceptor = setup_mtls_acceptor(
            &ca_str,
            &srv_cert_str,
            &srv_key_str,
            Some(&non_revoking_crl),
        )
        .expect("initial acceptor");
        let initial_serials =
            parse_revoked_serials_from_crl_pem(&non_revoking_crl).expect("initial serials");
        let (reload_tx, reload_rx) = tokio::sync::watch::channel(ControlPlaneReloadState {
            acceptor: initial_acceptor.clone(),
            revoked_serials: Arc::new(initial_serials),
        });

        let tunnels: SessionMap = new_session_map();
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let peer_addr: SocketAddr = "127.0.0.1:55555".parse().unwrap();

        let tunnels_srv = tunnels.clone();
        let server_task = tokio::spawn(async move {
            handle_control_connection_with_reload(
                server_io,
                peer_addr,
                initial_acceptor,
                tunnels_srv,
                Duration::from_secs(5),
                128,
                true,
                CancellationToken::new(),
                Some(reload_rx),
                Duration::from_millis(DEFAULT_SAME_CERT_TAKEOVER_PROBE_TIMEOUT_MS),
            )
            .await;
        });

        // Build mTLS client connector using praeco_client_pem
        let mut root_store = RootCertStore::empty();
        for cert in CertificateDer::pem_file_iter(&pki.relay_ca_pem).unwrap() {
            root_store.add(cert.unwrap()).unwrap();
        }
        let client_certs: Vec<CertificateDer<'static>> =
            CertificateDer::pem_file_iter(&pki.praeco_client_pem)
                .unwrap()
                .map(|c| c.unwrap())
                .collect();
        let client_key = PrivateKeyDer::from_pem_file(&pki.praeco_client_key).unwrap();
        let client_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(client_certs, client_key)
            .unwrap();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_cfg));
        let domain = rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut tls_client = connector.connect(domain, client_io).await.unwrap();

        // Register SNI allowed by praeco_client_pem
        tls_client
            .write_all(b"REGISTER wurzelwerk.api.aweirich.eu PROXY_V2\n")
            .await
            .unwrap();
        tls_client.flush().await.unwrap();

        let mut client_yamux =
            Connection::new(tls_client.compat(), YamuxConfig::default(), Mode::Client);
        let _client_driver = tokio::spawn(async move {
            let _ = std::future::poll_fn(|cx| client_yamux.poll_next_inbound(cx)).await;
        });

        // Wait until the tunnel is registered in SessionMap
        for _ in 0..50 {
            if tunnels.contains_key("wurzelwerk.api.aweirich.eu") {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            tunnels.contains_key("wurzelwerk.api.aweirich.eu"),
            "Tunnel must be registered before CRL update"
        );

        // Broadcast CRL reload that revokes praeco_client_pem
        let revoked_acceptor =
            setup_mtls_acceptor(&ca_str, &srv_cert_str, &srv_key_str, Some(&revoking_crl))
                .expect("revoked acceptor");
        let revoked_serials =
            parse_revoked_serials_from_crl_pem(&revoking_crl).expect("revoked serials");
        reload_tx
            .send(ControlPlaneReloadState {
                acceptor: revoked_acceptor,
                revoked_serials: Arc::new(revoked_serials),
            })
            .unwrap();

        // Active control tunnel task must exit promptly and evict the route from SessionMap
        tokio::time::timeout(Duration::from_secs(2), server_task)
            .await
            .expect("active tunnel must close promptly upon CRL revocation")
            .unwrap();
        assert!(
            !tunnels.contains_key("wurzelwerk.api.aweirich.eu"),
            "Revoked tunnel must be removed from SessionMap"
        );
    }

    #[test]
    fn test_sanitize_log_str_escapes_control_chars_and_borrows_clean_sni() {
        let clean = sanitize_log_str("api.example.com");
        assert!(matches!(clean, std::borrow::Cow::Borrowed("api.example.com")));

        let injected = sanitize_log_str("evil.com\r\nFAKE_LOG=true\t\x1b[31m");
        assert_eq!(injected, "evil.com\\r\\nFAKE_LOG=true\\t\\u{1b}[31m");
    }

    #[test]
    fn test_rate_limit_table_uses_overflow_bucket_on_saturation_without_eviction() {
        let table = RateLimitTable::with_capacity(2);
        let ip1: IpAddr = "198.51.100.1".parse().unwrap();
        let ip2: IpAddr = "198.51.100.2".parse().unwrap();
        let ip3: IpAddr = "198.51.100.3".parse().unwrap();
        let ip4: IpAddr = "198.51.100.4".parse().unwrap();

        assert!(table.check_and_consume(ip1, 0.0, 2.0));
        assert!(table.check_and_consume(ip2, 0.0, 2.0));
        assert_eq!(table.buckets.len(), 2);

        // At capacity: unknown IPs share the O(1) overflow bucket (burst = 2.0)
        assert!(table.check_and_consume(ip3, 0.0, 2.0));
        assert!(table.check_and_consume(ip4, 0.0, 2.0));
        assert!(
            !table.check_and_consume("198.51.100.5".parse().unwrap(), 0.0, 2.0),
            "overflow bucket must rate-limit saturated unknown IP floods"
        );
        assert_eq!(table.buckets.len(), 2);

        // Tracked IPs were NOT evicted by the unknown-IP flood and retain their remaining token
        assert!(table.buckets.contains_key(&ip1));
        assert!(table.buckets.contains_key(&ip2));
        assert!(table.check_and_consume(ip1, 0.0, 2.0));
        assert!(!table.check_and_consume(ip1, 0.0, 2.0));

        // After idle entries are swept, capacity recovers and ip3 gets its own tracked bucket
        table.sweep_expired(Duration::ZERO);
        assert!(table.buckets.is_empty());
        assert!(table.check_and_consume(ip3, 0.0, 2.0));
        assert!(table.buckets.contains_key(&ip3));
    }

    #[tokio::test]
    async fn test_same_cert_takeover_replaces_unresponsive_peer_and_blocks_foreign_cert() {
        let tunnels = new_session_map();
        let fp_a = [0xAAu8; 32];
        let fp_b = [0xBBu8; 32];
        let probe_timeout = Duration::from_millis(200);
        let takeovers_before = same_cert_takeover_count();

        // Simulated dead/unresponsive driver where probe ack receiver stays dropped/unacked
        let (tx1, _rx1) = mpsc::channel(4);
        let probe_notify1 = Arc::new(tokio::sync::Notify::new());
        let (_probe_ack_tx1, probe_ack_rx1) = tokio::sync::watch::channel(0u64);
        let token1 = CancellationToken::new();
        let ctrl1 = Control::with_identity(
            tx1,
            Some(fp_a),
            probe_notify1,
            probe_ack_rx1,
            token1.clone(),
        );
        tunnels.insert(
            "svc.example.com".to_string(),
            TunnelRoute {
                control: ctrl1,
                generation: 1,
                supports_proxy_v2: false,
            },
        );

        // Foreign certificate must be rejected even if old peer looks dead via probe
        let (tx_foreign, _rx_f) = mpsc::channel(4);
        let probe_notify_f = Arc::new(tokio::sync::Notify::new());
        let (_probe_ack_tx_f, probe_ack_rx_f) = tokio::sync::watch::channel(0u64);
        let ctrl_foreign = Control::with_identity(
            tx_foreign,
            Some(fp_b),
            probe_notify_f,
            probe_ack_rx_f,
            CancellationToken::new(),
        );
        assert!(
            !try_register_tunnel_with_takeover(
                &tunnels,
                "svc.example.com".to_string(),
                TunnelRoute {
                    control: ctrl_foreign,
                    generation: 2,
                    supports_proxy_v2: false,
                },
                probe_timeout,
            )
            .await
        );
        assert_eq!(tunnels.get("svc.example.com").unwrap().generation, 1);
        assert_eq!(same_cert_takeover_count(), takeovers_before);

        // Same certificate takes over unresponsive route cleanly and cancels old driver
        let (tx2, _rx2) = mpsc::channel(4);
        let probe_notify2 = Arc::new(tokio::sync::Notify::new());
        let (probe_ack_tx2, probe_ack_rx2) = tokio::sync::watch::channel(0u64);
        let probe_notify2_task = Arc::clone(&probe_notify2);
        let token2 = CancellationToken::new();
        let token2_task = token2.clone();
        tokio::spawn(async move {
            let mut seq = 0u64;
            loop {
                tokio::select! {
                    _ = token2_task.cancelled() => break,
                    _ = probe_notify2_task.notified() => {
                        seq = seq.saturating_add(1);
                        let _ = probe_ack_tx2.send(seq);
                    }
                }
            }
        });
        let ctrl2 = Control::with_identity(
            tx2,
            Some(fp_a),
            probe_notify2,
            probe_ack_rx2,
            token2.clone(),
        );
        assert!(
            try_register_tunnel_with_takeover(
                &tunnels,
                "svc.example.com".to_string(),
                TunnelRoute {
                    control: ctrl2,
                    generation: 3,
                    supports_proxy_v2: false,
                },
                probe_timeout,
            )
            .await
        );
        assert_eq!(tunnels.get("svc.example.com").unwrap().generation, 3);
        assert!(token1.is_cancelled());
        assert!(same_cert_takeover_count() > takeovers_before);

        // Live responsive same-cert peer must NOT be displaced, even under concurrent probes
        let takeovers_after_first = same_cert_takeover_count();
        let route_live = tunnels.get("svc.example.com").unwrap().clone();
        let (probe_res_1, probe_res_2, probe_res_3) = tokio::join!(
            route_live.control.probe_liveness(probe_timeout),
            route_live.control.probe_liveness(probe_timeout),
            route_live.control.probe_liveness(probe_timeout),
        );
        assert!(probe_res_1 && probe_res_2 && probe_res_3);

        let (tx3, _rx3) = mpsc::channel(4);
        let probe_notify3 = Arc::new(tokio::sync::Notify::new());
        let (_probe_ack_tx3, probe_ack_rx3) = tokio::sync::watch::channel(0u64);
        let ctrl3 = Control::with_identity(
            tx3,
            Some(fp_a),
            probe_notify3,
            probe_ack_rx3,
            CancellationToken::new(),
        );
        assert!(
            !try_register_tunnel_with_takeover(
                &tunnels,
                "svc.example.com".to_string(),
                TunnelRoute {
                    control: ctrl3,
                    generation: 4,
                    supports_proxy_v2: false,
                },
                probe_timeout,
            )
            .await
        );
        assert_eq!(tunnels.get("svc.example.com").unwrap().generation, 3);
        assert!(!token2.is_cancelled());
        assert_eq!(same_cert_takeover_count(), takeovers_after_first);

        token2.cancel();
    }

    #[test]
    fn test_parse_revoked_serials_rejects_empty_and_corrupt_pem() {
        let base = std::env::temp_dir();
        let pid = std::process::id();

        let empty_path = base.join(format!("praeco_empty_crl_{pid}.pem"));
        std::fs::write(&empty_path, "").unwrap();
        let empty_res = parse_revoked_serials_from_crl_pem(&empty_path.to_string_lossy());
        let _ = std::fs::remove_file(&empty_path);
        assert!(empty_res.is_err(), "empty CRL PEM must fail closed");

        let corrupt_path = base.join(format!("praeco_corrupt_crl_{pid}.pem"));
        std::fs::write(
            &corrupt_path,
            "-----BEGIN X509 CRL-----\nbm90LWEtY3Js\n-----END X509 CRL-----\n",
        )
        .unwrap();
        let corrupt_res = parse_revoked_serials_from_crl_pem(&corrupt_path.to_string_lossy());
        let _ = std::fs::remove_file(&corrupt_path);
        assert!(corrupt_res.is_err(), "corrupt CRL DER must fail closed");
    }

    #[tokio::test]
    async fn test_crl_reload_watcher_fails_closed_on_init_and_preserves_state_on_corrupt_reload() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let pki = common::test_pki::TestPki::new();
        let ca = common::test_pki::TestPki::s(&pki.relay_ca_pem).to_string();
        let srv_cert = common::test_pki::TestPki::s(&pki.relay_server_pem).to_string();
        let srv_key = common::test_pki::TestPki::s(&pki.relay_server_key).to_string();

        let working_crl = std::env::temp_dir().join(format!(
            "praeco_watcher_crl_{}.pem",
            std::process::id()
        ));
        // 1. Corrupt initial CRL must fail spawn_crl_reload_watcher
        std::fs::write(
            &working_crl,
            "-----BEGIN X509 CRL-----\nbm90LWEtY3Js\n-----END X509 CRL-----\n",
        )
        .unwrap();
        let valid_acceptor = setup_mtls_acceptor(&ca, &srv_cert, &srv_key, None).unwrap();
        let cancel_bad = CancellationToken::new();
        let init_err = spawn_crl_reload_watcher(
            ca.clone(),
            srv_cert.clone(),
            srv_key.clone(),
            Some(working_crl.to_string_lossy().to_string()),
            valid_acceptor,
            Duration::from_secs(60),
            cancel_bad.clone(),
        );
        cancel_bad.cancel();
        assert!(init_err.is_err(), "corrupt initial CRL must fail startup");

        // 2. Copy valid revoking CRL, start watcher, then corrupt the file on disk
        let valid_bytes = std::fs::read(&pki.relay_crl_revoking_client_pem).unwrap();
        std::fs::write(&working_crl, &valid_bytes).unwrap();
        let crl_str = working_crl.to_string_lossy().to_string();
        let acceptor = setup_mtls_acceptor(&ca, &srv_cert, &srv_key, Some(&crl_str)).unwrap();

        let cancel = CancellationToken::new();
        let rx = spawn_crl_reload_watcher(
            ca,
            srv_cert,
            srv_key,
            Some(crl_str),
            acceptor,
            Duration::from_millis(25),
            cancel.clone(),
        )
        .expect("valid CRL must initialize watcher");

        let initial_count = rx.borrow().revoked_serials.len();
        assert_eq!(initial_count, 1);

        // Overwrite CRL with corrupt content and wait past reload interval
        std::fs::write(&working_crl, "").unwrap();
        tokio::time::sleep(Duration::from_millis(80)).await;

        assert_eq!(
            rx.borrow().revoked_serials.len(),
            initial_count,
            "corrupt CRL reload must keep previous revoked serials"
        );

        cancel.cancel();
        let _ = std::fs::remove_file(&working_crl);
    }

    #[test]
    fn test_token_bucket_rejected_consume_does_not_refresh_last_update() {
        let mut bucket = TokenBucket::new(1.0);
        assert!(bucket.consume(0.0, 1.0));
        let ts_after_consume = bucket.last_update();

        std::thread::sleep(Duration::from_millis(15));
        assert!(!bucket.consume(0.0, 1.0));
        assert_eq!(
            bucket.last_update(),
            ts_after_consume,
            "rejected consume must not advance last_update and pin exhausted entries"
        );
    }
