//! # Praeco Relay Server
//!
//! The relay server provides a Zero-Trust, SNI-based TCP proxy. It acts as an
//! intermediary between the public internet (Data Plane) and the internal Praeco
//! gateway instances (Control Plane) which may be behind a NAT or firewall.
//!
//! Internal gateways register via an mTLS connection and establish a Yamux multiplexed
//! tunnel. The data plane parses the SNI from incoming TLS ClientHellos and routes
//! the raw TCP streams over the Yamux tunnel to the corresponding backend server.
//!
//! This preserves end-to-end encryption, as TLS is terminated at the backend Praeco
//! server, not at the relay.

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
use std::net::IpAddr;
use std::time::{Duration, Instant};
use yamux::{Config as YamuxConfig, Connection, Mode, Stream as YamuxStream};
use tls_parser::{parse_tls_plaintext, TlsExtension, TlsMessageHandshake};

/// Basic token bucket rate limiter tracking capacity per IP.
struct TokenBucket {
    tokens: f32,
    last_update: Instant,
}

impl TokenBucket {
    fn new(burst: f32) -> Self {
        Self {
            tokens: burst,
            last_update: Instant::now(),
        }
    }

    fn consume(&mut self, rate: f32, burst: f32) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f32();
        
        // Refill tokens based on elapsed time and rate
        self.tokens += elapsed * rate;
        if self.tokens > burst {
            self.tokens = burst;
        }
        self.last_update = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Represents a control handle to an active Yamux multiplexed connection.
/// Used to request new outbound streams from the Relay to the Praeco backend.
#[derive(Clone)]
struct Control {
    tx: mpsc::Sender<oneshot::Sender<Result<YamuxStream, yamux::ConnectionError>>>,
}

impl Control {
    /// Opens a new stream over the multiplexed Yamux connection.
    ///
    /// This method sends a request to the connection driver task to open a new stream.
    /// It returns a `YamuxStream` which implements `AsyncRead` and `AsyncWrite`.
    async fn open_stream(&mut self) -> Result<YamuxStream, yamux::ConnectionError> {
        let (tx, rx) = oneshot::channel();
        self.tx.send(tx).await.map_err(|_| yamux::ConnectionError::Closed)?;
        rx.await.map_err(|_| yamux::ConnectionError::Closed)?
    }
}

/// Thread-safe map storing the active SNI-to-Control routing table.
type SessionMap = Arc<DashMap<String, (Control, u64)>>;

/// Configures tracing and OpenTelemetry (OTLP) based on the provided configuration.
fn setup_tracing(config: &RelayConfig) {
    let enable_otlp = config.enable_opentelemetry.unwrap_or(false);
    let jaeger_endpoint = config.jaeger_endpoint.as_deref().unwrap_or("http://localhost:4317");
    let otel_log_level = config.otel_log_level.as_deref().unwrap_or("info");

    let otel_sample_ratio = config.otel_sample_ratio.unwrap_or(1.0);

    let console_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let stdout_layer = tracing_subscriber::fmt::layer().with_ansi(true).with_filter(console_filter);

    let telemetry_layer = if enable_otlp {
        let sampler = if (otel_sample_ratio - 1.0).abs() < f64::EPSILON {
            opentelemetry_sdk::trace::Sampler::AlwaysOn
        } else {
            opentelemetry_sdk::trace::Sampler::ParentBased(Box::new(opentelemetry_sdk::trace::Sampler::TraceIdRatioBased(otel_sample_ratio)))
        };

        let provider = opentelemetry_otlp::new_pipeline()
            .tracing()
            .with_exporter(opentelemetry_otlp::new_exporter().tonic().with_endpoint(jaeger_endpoint))
            .with_trace_config(
                opentelemetry_sdk::trace::Config::default()
                    .with_sampler(sampler)
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

/// Entry point for the Relay Server.
///
/// Loads the configuration, sets up observability, initializes the mTLS acceptor,
/// and spawns the Data Plane (HTTPS traffic) and Control Plane (internal mTLS registration).
#[tokio::main]
async fn main() -> Result<()> {
    let config_path = std::env::args().nth(1).unwrap_or_else(|| "RelayConfig.toml".to_string());
    let config = RelayConfig::load(&config_path)?;
    setup_tracing(&config);
    
    // Install default crypto provider for rustls
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    info!("Starting Praeco Relay Server...");

    let active_tunnels: SessionMap = Arc::new(DashMap::new());

    let tls_acceptor = setup_mtls_acceptor(
        &config.ca_cert_path, 
        &config.server_cert_path, 
        &config.server_key_path,
        config.crl_path.as_ref(),
    ).context("Failed to setup mTLS acceptor")?;

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
    let rate_rate = config.rate_limit_connections_per_sec.unwrap_or(50) as f32;
    let rate_burst = config.rate_limit_burst.unwrap_or(100) as f32;
    
    tokio::spawn(async move {
        if let Err(e) = run_data_plane(active_tunnels, &data_addr, rate_rate, rate_burst).await {
            error!("Data plane failed: {}", e);
        }
    });

    let _ = tokio::signal::ctrl_c().await;
    info!("Shutdown signal received. Shutting down Relay Server...");
    opentelemetry::global::shutdown_tracer_provider();
    Ok(())
}

/// Loads certificates and constructs a `TlsAcceptor` configured for strict mTLS.
fn setup_mtls_acceptor(ca_path: &str, cert_path: &str, key_path: &str, crl_path: Option<&String>) -> Result<TlsAcceptor> {
    let ca_file = File::open(ca_path)?;
    let mut ca_reader = BufReader::new(ca_file);
    let mut root_store = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut ca_reader) {
        root_store.add(cert?).unwrap();
    }
    
    let mut verifier_builder = WebPkiClientVerifier::builder(Arc::new(root_store));
    
    if let Some(path) = crl_path {
        let crl_file = File::open(path)?;
        let mut crl_reader = BufReader::new(crl_file);
        let crls = rustls_pemfile::crls(&mut crl_reader).collect::<Result<Vec<_>, _>>()?;
        verifier_builder = verifier_builder.with_crls(crls);
    }
    
    let verifier = verifier_builder.build()?;

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

/// Runs the Control Plane, accepting incoming mTLS registrations from Praeco servers.
///
/// When a Praeco instance connects, it sends a `REGISTER <sni>` command.
/// The relay creates a Yamux session, stores the control handle in the `tunnels` map,
/// and spawns a connection driver loop to multiplex incoming data plane requests.
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

            // --- Extract Client Certificate SANs (P0.2) ---
            let mut allowed_snis = Vec::new();
            if let Some(certs) = tls_stream.get_ref().1.peer_certificates() {
                if let Some(cert_der) = certs.first() {
                    if let Ok((_, cert)) = x509_parser::parse_x509_certificate(cert_der) {
                        for ext in cert.iter_extensions() {
                            if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
                                for name in &san.general_names {
                                    if let x509_parser::extensions::GeneralName::DNSName(dns) = name {
                                        allowed_snis.push(dns.to_string());
                                    }
                                }
                            }
                        }
                    }
                }
            }
            if allowed_snis.is_empty() {
                warn!(target: "relay::control_plane", client_ip = %client_addr, "No DNS SANs found in client certificate");
                return;
            }

            let mut buf = [0u8; 1024];
            let mut line = String::new();
            let mut total_read = 0;
            let timeout_res = tokio::time::timeout(Duration::from_secs(10), async {
                loop {
                    let n = match tls_stream.read(&mut buf).await {
                        Ok(0) => return false,
                        Ok(n) => n,
                        Err(_) => return false,
                    };
                    total_read += n;
                    line.push_str(&String::from_utf8_lossy(&buf[..n]));
                    if line.contains('\n') {
                        return true;
                    }
                    // Prevent memory exhaustion (P0.4)
                    if total_read > 1024 {
                        return false;
                    }
                }
            }).await;

            if !timeout_res.unwrap_or(false) {
                warn!(target: "relay::control_plane", client_ip = %client_addr, "REGISTER command failed, timed out or too long");
                return;
            }

            // --- Safe Parsing (P0.4) ---
            let line_trimmed = line.trim();
            let Some(("REGISTER", sni_raw)) = line_trimmed.split_once(' ') else {
                warn!(target: "relay::control_plane", client_ip = %client_addr, "Invalid register command format");
                return;
            };
            let sni = sni_raw.trim().to_string();

            // --- Verify SNI against Certificate SANs (P0.2) ---
            if !allowed_snis.contains(&sni) {
                warn!(target: "relay::control_plane", client_ip = %client_addr, requested_sni = %sni, "SNI not authorized by client certificate");
                return;
            }

            info!(target: "relay::control_plane", sni = %sni, "Praeco tunnel registered");

            let cfg = YamuxConfig::default();
            let mut connection = Connection::new(tls_stream.compat(), cfg, Mode::Server);

            let (tx, mut rx) = mpsc::channel(32);
            let control = Control { tx };

            // --- Store with Generation ID (P0.5) ---
            use std::sync::atomic::{AtomicU64, Ordering};
            static GENERATION: AtomicU64 = AtomicU64::new(1);
            let my_generation = GENERATION.fetch_add(1, Ordering::SeqCst);

            tunnels.insert(sni.clone(), (control.clone(), my_generation));

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
                    // Check if we are still the active generation (P0.5)
                    let still_active = if let Some(entry) = ping_tunnels.get(&ping_sni) {
                        entry.value().1 == my_generation
                    } else {
                        false
                    };
                    if !still_active {
                        break; // Another tunnel took over or it was deleted
                    }
                    
                    match ping_control.open_stream().await {
                        Ok(s) => drop(s), // Ping OK
                        Err(_) => {
                            warn!(target: "relay::control_plane", sni = %ping_sni, "Heartbeat failed, removing tunnel");
                            // Remove only if generation matches (P0.5)
                            ping_tunnels.remove_if(&ping_sni, |_, (_, g)| *g == my_generation);
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

            // Remove only if generation matches (P0.5)
            tunnels.remove_if(&sni, |_, (_, g)| *g == my_generation);
        }.instrument(info_span!("control_connection", client_ip = %client_addr)));
    }
}

/// Runs the Data Plane, accepting public TCP connections and routing them via SNI.
///
/// Extracts the Server Name Indication (SNI) from the initial TLS ClientHello.
/// Looks up the SNI in the `tunnels` map, opens a new stream over the corresponding
/// Yamux connection, and blindly copies the bidirectional TCP traffic.
/// Applies a Token-Bucket rate limit per client IP to mitigate L4 connection floods.
async fn run_data_plane(tunnels: SessionMap, addr: &str, rate: f32, burst: f32) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!("Data plane listening on {} (SNI-Routing)", addr);

    let rate_limits: Arc<DashMap<IpAddr, TokenBucket>> = Arc::new(DashMap::new());
    
    // Spawn a cleanup task to prevent DashMap from growing indefinitely
    let cleanup_limits = rate_limits.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            // Remove buckets that haven't been used in 2 minutes
            cleanup_limits.retain(|_, bucket| bucket.last_update.elapsed() < Duration::from_secs(120));
        }
    });

    loop {
        let (mut client_stream, client_addr) = match listener.accept().await {
            Ok(s) => s,
            Err(_) => continue,
        };

        // --- Rate Limiting Check ---
        let mut bucket = rate_limits.entry(client_addr.ip()).or_insert_with(|| TokenBucket::new(burst));
        if !bucket.consume(rate, burst) {
            warn!(target: "relay::data_plane", client_ip = %client_addr, "Rate limit exceeded, dropping connection");
            continue; // Drop instantly
        }
        drop(bucket); // Explicitly release the lock before spawning

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

            let mut control = match tunnels.get(&sni) {
                Some(entry) => entry.value().0.clone(),
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

/// Best-effort extraction of the SNI domain name from a raw TLS ClientHello packet.
/// 
/// Relies on `tls_parser` to interpret the raw bytes without completing a handshake.
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

/// Validates the structure of an SNI hostname against basic RFC 1035 constraints.
/// Prevents path traversal or code injection if the SNI is logged or used in a DashMap.
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
