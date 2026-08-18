mod config;

use anyhow::{Context, Result};
use config::RelayConfig;
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
use tokio_util::compat::{FuturesAsyncWriteCompatExt, TokioAsyncReadCompatExt};
use tracing::{error, info, info_span, warn, Instrument};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::Resource;
use opentelemetry::KeyValue;
use opentelemetry::trace::TracerProvider as _;
use std::time::Duration;
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

fn setup_tracing(config: &RelayConfig) {
    let enable_otlp = config.enable_opentelemetry.unwrap_or(false);
    let jaeger_endpoint = config.jaeger_endpoint.as_deref().unwrap_or("http://localhost:4317");
    let otel_log_level = config.otel_log_level.as_deref().unwrap_or("info");

    let console_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let stdout_layer = tracing_subscriber::fmt::layer().with_ansi(true).with_filter(console_filter);

    let telemetry_layer = if enable_otlp {
        let provider = opentelemetry_otlp::new_pipeline()
            .tracing()
            .with_exporter(opentelemetry_otlp::new_exporter().tonic().with_endpoint(jaeger_endpoint))
            .with_trace_config(
                opentelemetry_sdk::trace::Config::default()
                    .with_resource(Resource::new(vec![KeyValue::new("service.name", "praeco-relay")])),
            )
            .install_batch(opentelemetry_sdk::runtime::Tokio)
            .expect("Failed to initialize OTLP tracer");

        opentelemetry::global::set_tracer_provider(provider.clone());
        
        let _ = opentelemetry::global::set_error_handler(|err| {
            tracing::error!("OpenTelemetry Export Error: {:?}", err);
        });

        let tracer = provider.tracer("praeco-relay");
        let telemetry_filter = EnvFilter::new(otel_log_level);
        
        Some(tracing_opentelemetry::layer().with_tracer(tracer).with_filter(telemetry_filter))
    } else {
        None
    };

    tracing_subscriber::registry()
        .with(stdout_layer)
        .with(telemetry_layer)
        .init();
}

#[tokio::main]
async fn main() -> Result<()> {
    let config = RelayConfig::load("RelayConfig.toml")?;
    setup_tracing(&config);
    
    // Install default crypto provider for rustls
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    info!("Starting Praeco Relay Server...");

    let active_tunnels: SessionMap = Arc::new(DashMap::new());

    let tls_acceptor = setup_mtls_acceptor(&config.ca_cert_path, &config.server_cert_path, &config.server_key_path)
        .context("Failed to setup mTLS acceptor")?;

    // --- Spawn Control Plane ---
    let control_tunnels = active_tunnels.clone();
    let control_addr = config.control_plane_addr.clone();
    tokio::spawn(async move {
        if let Err(e) = run_control_plane(tls_acceptor, control_tunnels, &control_addr).await {
            error!("Control plane failed: {}", e);
        }
    });

    // --- Spawn Data Plane ---
    let data_addr = config.data_plane_addr.clone();
    tokio::spawn(async move {
        if let Err(e) = run_data_plane(active_tunnels, &data_addr).await {
            error!("Data plane failed: {}", e);
        }
    });

    let _ = tokio::signal::ctrl_c().await;
    info!("Shutdown signal received. Shutting down Relay Server...");
    opentelemetry::global::shutdown_tracer_provider();
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

async fn run_control_plane(tls_acceptor: TlsAcceptor, tunnels: SessionMap, addr: &str) -> Result<()> {
    let listener = TcpListener::bind(addr).await.context("Failed to bind control plane")?;
    info!("Control plane listening on mTLS {}", addr);

    loop {
        let (stream, client_addr) = match listener.accept().await {
            Ok(s) => s,
            Err(e) => {
                warn!("Failed to accept control connection: {}", e);
                continue;
            }
        };

        let acceptor = tls_acceptor.clone();
        let tunnels = tunnels.clone();

        tokio::spawn(async move {
            info!(target: "relay::control_plane", "New control connection");
            let mut tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    warn!(target: "relay::control_plane", client_ip = %client_addr, error = %e, "mTLS handshake failed");
                    return;
                }
            };

            let mut buf = [0u8; 1024];
            let mut line = String::new();
            let timeout_res = tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    let n = match tls_stream.read(&mut buf).await {
                        Ok(0) => return false,
                        Ok(n) => n,
                        Err(_) => return false,
                    };
                    line.push_str(&String::from_utf8_lossy(&buf[..n]));
                    if line.contains('\n') {
                        return true;
                    }
                }
            }).await;

            if !timeout_res.unwrap_or(false) {
                warn!(target: "relay::control_plane", client_ip = %client_addr, "REGISTER command failed or timed out");
                return;
            }

            let parts: Vec<&str> = line.trim().split_whitespace().collect();
            if parts.is_empty() || parts[0] != "REGISTER" {
                warn!(target: "relay::control_plane", client_ip = %client_addr, "Invalid register command");
                return;
            }

            let sni = parts[1].to_string();
            info!(target: "relay::control_plane", sni = %sni, "Praeco tunnel registered");

            let cfg = YamuxConfig::default();
            let mut connection = Connection::new(tls_stream.compat(), cfg, Mode::Server);

            let (tx, mut rx) = mpsc::channel(32);
            let control = Control { tx };

            tunnels.insert(sni.clone(), control.clone());

            // Health check keepalive ping task
            let ping_sni = sni.clone();
            let ping_tunnels = tunnels.clone();
            let mut ping_control = control.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(30));
                // Tick first to wait 30s before first ping
                interval.tick().await; 
                loop {
                    interval.tick().await;
                    if !ping_tunnels.contains_key(&ping_sni) {
                        break;
                    }
                    match ping_control.open_stream().await {
                        Ok(s) => drop(s), // Ping OK
                        Err(_) => {
                            warn!(target: "relay::control_plane", sni = %ping_sni, "Heartbeat failed, removing tunnel");
                            ping_tunnels.remove(&ping_sni);
                            break;
                        }
                    }
                }
            });

            // Connection Driver Loop
            let mut pending_outbound: Option<oneshot::Sender<Result<yamux::Stream, yamux::ConnectionError>>> = None;

            std::future::poll_fn(|cx| {
                // 1. Check for new outbound requests if we don't have one pending
                if pending_outbound.is_none() {
                    if let std::task::Poll::Ready(Some(resp_tx)) = rx.poll_recv(cx) {
                        pending_outbound = Some(resp_tx);
                    }
                }

                // 2. Drive outbound stream opening if pending
                if pending_outbound.is_some() {
                    if let std::task::Poll::Ready(stream_res) = connection.poll_new_outbound(cx) {
                        let resp_tx = pending_outbound.take().unwrap();
                        let _ = resp_tx.send(stream_res);
                    }
                }

                // 3. Drive inbound streams and connection progress
                match connection.poll_next_inbound(cx) {
                    std::task::Poll::Ready(Some(Ok(unexpected_stream))) => {
                        warn!(target: "relay::control_plane", sni = %sni, "Unexpected inbound stream from client");
                        drop(unexpected_stream);
                        // Wake up immediately to continue processing
                        cx.waker().wake_by_ref();
                    }
                    std::task::Poll::Ready(Some(Err(e))) => {
                        warn!(target: "relay::control_plane", sni = %sni, error = ?e, "Tunnel connection failed");
                        return std::task::Poll::Ready(());
                    }
                    std::task::Poll::Ready(None) => {
                        info!(target: "relay::control_plane", sni = %sni, "Tunnel closed cleanly");
                        return std::task::Poll::Ready(());
                    }
                    std::task::Poll::Pending => {}
                }

                std::task::Poll::Pending
            }).await;

            tunnels.remove(&sni);
        }.instrument(info_span!("control_connection", client_ip = %client_addr)));
    }
}

async fn run_data_plane(tunnels: SessionMap, addr: &str) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!("Data plane listening on {} (SNI-Routing)", addr);

    loop {
        let (mut client_stream, client_addr) = match listener.accept().await {
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
                    warn!(target: "relay::data_plane", client_ip = %client_addr, "Failed to parse SNI or not a TLS ClientHello");
                    return;
                }
            };
            
            if !is_valid_sni(&sni) {
                warn!(target: "relay::data_plane", client_ip = %client_addr, sni = %sni, "Invalid or empty SNI");
                return;
            }

            let mut control = match tunnels.get_mut(&sni) {
                Some(c) => c.clone(),
                None => {
                    warn!(target: "relay::data_plane", sni = %sni, client_ip = %client_addr, "No active tunnel for SNI");
                    return;
                }
            };

            let tunnel_stream = match control.open_stream().await {
                Ok(s) => s,
                Err(e) => {
                    warn!(target: "relay::data_plane", sni = %sni, error = %e, "Failed to open stream in tunnel");
                    return;
                }
            };
            
            let mut tokio_tunnel = tunnel_stream.compat_write();

            if let Err(e) = tokio_tunnel.write_all(&buf[..n]).await {
                warn!(target: "relay::data_plane", sni = %sni, error = %e, "Failed to write ClientHello to tunnel");
                return;
            }

            let _ = tokio::time::timeout(
                Duration::from_secs(300),
                tokio::io::copy_bidirectional(&mut client_stream, &mut tokio_tunnel)
            ).await;
        }.instrument(info_span!("data_connection", client_ip = %client_addr)));
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

fn is_valid_sni(sni: &str) -> bool {
    if sni.is_empty() || sni.len() > 253 {
        return false;
    }
    for label in sni.split('.') {
        if label.is_empty() || label.len() > 63 {
            return false;
        }
        if !label.chars().all(|c| c.is_alphanumeric() || c == '-') {
            return false;
        }
        if label.starts_with('-') || label.ends_with('-') {
            return false;
        }
    }
    true
}
