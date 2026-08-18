use anyhow::{Context, Result};
use dashmap::DashMap;
use rustls::pki_types::CertificateDer;
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use std::fs::File;
use std::io::BufReader;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio_rustls::TlsAcceptor;
use tokio_util::compat::{TokioAsyncReadCompatExt, FuturesAsyncWriteCompatExt};
use tracing::{error, info, warn};
use yamux::{Config as YamuxConfig, Connection, Mode, Stream as YamuxStream};
use tls_parser::{parse_tls_plaintext, TlsExtension, TlsMessageHandshake};

#[derive(Clone)]
struct Control {
    tx: mpsc::Sender<oneshot::Sender<Result<YamuxStream, yamux::ConnectionError>>>,
}

impl Control {
    async fn open_stream(&mut self) -> Result<YamuxStream, yamux::ConnectionError> {
        let (tx, rx) = oneshot::channel();
        self.tx.send(tx).await.map_err(|_| yamux::ConnectionError::Closed)?;
        rx.await.map_err(|_| yamux::ConnectionError::Closed)?
    }
}

type SessionMap = Arc<DashMap<String, Control>>;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    
    // Install default crypto provider for rustls
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    info!("Starting Praeco Relay Server...");

    let active_tunnels: SessionMap = Arc::new(DashMap::new());

    // --- mTLS Configuration for Control Plane ---
    let ca_cert_path = std::env::var("RELAY_CA_CERT").unwrap_or_else(|_| "server_certs/self_signed/myca.pem".to_string());
    let server_cert_path = std::env::var("RELAY_SERVER_CERT").unwrap_or_else(|_| "server_certs/self_signed/fullchain_self.pem".to_string());
    let server_key_path = std::env::var("RELAY_SERVER_KEY").unwrap_or_else(|_| "server_certs/self_signed/privkey_self.pem".to_string());

    let tls_acceptor = setup_mtls_acceptor(&ca_cert_path, &server_cert_path, &server_key_path)
        .context("Failed to setup mTLS acceptor")?;

    // --- Spawn Control Plane ---
    let control_tunnels = active_tunnels.clone();
    tokio::spawn(async move {
        if let Err(e) = run_control_plane(tls_acceptor, control_tunnels).await {
            error!("Control plane failed: {}", e);
        }
    });

    // --- Spawn Data Plane ---
    run_data_plane(active_tunnels).await?;

    Ok(())
}

fn setup_mtls_acceptor(ca_path: &str, cert_path: &str, key_path: &str) -> Result<TlsAcceptor> {
    let ca_file = File::open(ca_path)?;
    let mut ca_reader = BufReader::new(ca_file);
    let mut root_store = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut ca_reader) {
        root_store.add(cert?).unwrap();
    }
    
    let verifier = WebPkiClientVerifier::builder(Arc::new(root_store)).build()?;

    let cert_file = File::open(cert_path)?;
    let mut cert_reader = BufReader::new(cert_file);
    let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;

    let key_file = File::open(key_path)?;
    let mut key_reader = BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_reader)?.context("No private key found")?;

    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

async fn run_control_plane(tls_acceptor: TlsAcceptor, tunnels: SessionMap) -> Result<()> {
    let addr = "0.0.0.0:7001";
    let listener = TcpListener::bind(addr).await.context("Failed to bind control plane")?;
    info!("Control plane listening on mTLS {}", addr);

    loop {
        let (stream, addr) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to accept control connection: {}", e);
                continue;
            }
        };

        let acceptor = tls_acceptor.clone();
        let tunnels = tunnels.clone();

        tokio::spawn(async move {
            info!("New control connection from {}", addr);
            let mut tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    warn!("mTLS handshake failed from {}: {}", addr, e);
                    return;
                }
            };

            let mut buf = [0u8; 1024];
            let mut line = String::new();
            loop {
                let n = match tls_stream.read(&mut buf).await {
                    Ok(0) => return,
                    Ok(n) => n,
                    Err(_) => return,
                };
                line.push_str(&String::from_utf8_lossy(&buf[..n]));
                if line.contains('\n') {
                    break;
                }
            }

            let parts: Vec<&str> = line.trim().split_whitespace().collect();
            if parts.is_empty() || parts[0] != "REGISTER" {
                warn!("Invalid register command from {}", addr);
                return;
            }

            let sni = parts[1].to_string();
            info!("Praeco tunnel registered for SNI: {}", sni);

            let cfg = YamuxConfig::default();
            let mut connection = Connection::new(tls_stream.compat(), cfg, Mode::Server);

            let (tx, mut rx) = mpsc::channel(32);
            let control = Control { tx };

            tunnels.insert(sni.clone(), control);

            // Connection Driver Loop
            loop {
                tokio::select! {
                    Some(resp_tx) = rx.recv() => {
                        let stream_res = std::future::poll_fn(|cx| connection.poll_new_outbound(cx)).await;
                        let _ = resp_tx.send(stream_res);
                    }
                    inbound = std::future::poll_fn(|cx| connection.poll_next_inbound(cx)) => {
                        match inbound {
                            Some(Ok(_stream)) => {
                                // We don't expect Praeco to open streams TO the Relay. Just drop them.
                            }
                            Some(Err(e)) => {
                                warn!("Tunnel connection for {} failed: {:?}", sni, e);
                                break;
                            }
                            None => {
                                info!("Tunnel for {} closed cleanly", sni);
                                break;
                            }
                        }
                    }
                }
            }

            tunnels.remove(&sni);
        });
    }
}

async fn run_data_plane(tunnels: SessionMap) -> Result<()> {
    let listener = TcpListener::bind("0.0.0.0:443").await?;
    info!("Data plane listening on 0.0.0.0:443 (SNI-Routing)");

    loop {
        let (mut client_stream, addr) = match listener.accept().await {
            Ok(s) => s,
            Err(_) => continue,
        };

        let tunnels = tunnels.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            let n = match client_stream.read(&mut buf).await {
                Ok(0) => return,
                Ok(n) => n,
                Err(_) => return,
            };

            let sni = match extract_sni(&buf[..n]) {
                Some(s) => s,
                None => {
                    warn!("Failed to parse SNI or not a TLS ClientHello from {}", addr);
                    return;
                }
            };
            
            if sni.is_empty() {
                warn!("Empty SNI from {}", addr);
                return;
            }

            let mut control = match tunnels.get_mut(&sni) {
                Some(c) => c.clone(),
                None => {
                    warn!("No active tunnel for SNI: {}", sni);
                    return;
                }
            };

            let tunnel_stream = match control.open_stream().await {
                Ok(s) => s,
                Err(e) => {
                    warn!("Failed to open stream in tunnel {}: {}", sni, e);
                    return;
                }
            };
            
            let mut tokio_tunnel = tunnel_stream.compat_write();

            if tokio_tunnel.write_all(&buf[..n]).await.is_err() {
                return;
            }

            let _ = tokio::io::copy_bidirectional(&mut client_stream, &mut tokio_tunnel).await;
        });
    }
}

fn extract_sni(buf: &[u8]) -> Option<String> {
    match parse_tls_plaintext(buf) {
        Ok((_, pt)) => {
            for msg in pt.msg {
                if let tls_parser::TlsMessage::Handshake(TlsMessageHandshake::ClientHello(client_hello)) = msg {
                    if let Some(ext_bytes) = client_hello.ext {
                        if let Ok((_, exts)) = tls_parser::parse_tls_extensions(ext_bytes) {
                            for ext in exts {
                                if let TlsExtension::SNI(sni_ext) = ext {
                                    if let Some((_, name)) = sni_ext.first() {
                                        if let Ok(name_str) = std::str::from_utf8(name) {
                                            return Some(name_str.to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            None
        }
        Err(_) => None,
    }
}
