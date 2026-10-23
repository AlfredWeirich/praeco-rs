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
use tracing::{debug, error, info, info_span, warn, Instrument};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Layer};
use opentelemetry_otlp::WithExportConfig;
use opentelemetry_sdk::Resource;
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
    /// Creates a new `TokenBucket` initialized with the maximum burst capacity.
    ///
    /// # Arguments
    ///
    /// * `burst` - The maximum number of tokens this bucket can hold.
    fn new(burst: f32) -> Self {
        Self {
            tokens: burst,
            last_update: Instant::now(),
        }
    }

    /// Attempts to consume a single token from the bucket.
    ///
    /// The bucket is refilled based on the elapsed time since the last update
    /// multiplied by the refill `rate`.
    ///
    /// # Arguments
    ///
    /// * `rate` - The number of tokens added per second.
    /// * `burst` - The maximum capacity of the bucket.
    ///
    /// # Returns
    ///
    /// Returns `true` if a token was successfully consumed, or `false` if the bucket is empty
    /// (indicating the rate limit has been exceeded).
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

/// Canonicalizes an IP address:
/// - IPv4 addresses remain unchanged.
/// - IPv4-mapped IPv6 addresses (::ffff:a.b.c.d) are unwrapped to IPv4.
/// - Standard IPv6 addresses are masked to a /64 subnet prefix to prevent rate-limit and connection-limit evasion.
pub fn canonicalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(v4) => IpAddr::V4(v4),
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                IpAddr::V4(v4)
            } else {
                let segs = v6.segments();
                IpAddr::V6(std::net::Ipv6Addr::new(
                    segs[0], segs[1], segs[2], segs[3], 0, 0, 0, 0,
                ))
            }
        }
    }
}

use std::sync::atomic::AtomicUsize;

/// Central connection tracker for the Relay Server.
/// Enforces global and per-canonical-IP concurrency limits using RAII guards.
pub struct RelayConnectionTracker {
    max_global: usize,
    max_per_ip: usize,
    global_count: AtomicUsize,
    ip_counts: DashMap<IpAddr, usize>,
}

/// RAII guard that decrements the connection count when dropped.
pub struct RelayConnectionGuard {
    tracker: Arc<RelayConnectionTracker>,
    ip: IpAddr,
}

impl Drop for RelayConnectionGuard {
    fn drop(&mut self) {
        self.tracker.global_count.fetch_sub(1, Ordering::SeqCst);
        let mut remove = false;
        if let Some(mut count) = self.tracker.ip_counts.get_mut(&self.ip) {
            if *count > 0 {
                *count -= 1;
            }
            if *count == 0 {
                remove = true;
            }
        }
        if remove {
            self.tracker.ip_counts.remove(&self.ip);
        }
    }
}

impl RelayConnectionTracker {
    pub fn new(max_global: usize, max_per_ip: usize) -> Self {
        Self {
            max_global,
            max_per_ip,
            global_count: AtomicUsize::new(0),
            ip_counts: DashMap::new(),
        }
    }

    pub fn acquire(self: &Arc<Self>, raw_ip: IpAddr) -> Result<RelayConnectionGuard, &'static str> {
        let ip = canonicalize_ip(raw_ip);

        // 1. Check global limit
        let prev_global = self.global_count.fetch_add(1, Ordering::SeqCst);
        if prev_global >= self.max_global {
            self.global_count.fetch_sub(1, Ordering::SeqCst);
            return Err("Global connection limit reached");
        }

        // 2. Check per-IP limit
        let mut entry = self.ip_counts.entry(ip).or_insert(0);
        if *entry >= self.max_per_ip {
            self.global_count.fetch_sub(1, Ordering::SeqCst);
            return Err("Per-IP connection limit reached");
        }
        *entry += 1;
        drop(entry);

        Ok(RelayConnectionGuard {
            tracker: self.clone(),
            ip,
        })
    }

    pub fn current_global(&self) -> usize {
        self.global_count.load(Ordering::Relaxed)
    }

    pub fn current_for_ip(&self, raw_ip: IpAddr) -> usize {
        let ip = canonicalize_ip(raw_ip);
        self.ip_counts.get(&ip).map(|v| *v).unwrap_or(0)
    }
}

/// Reads a full TLS ClientHello record from the incoming stream with a timeout and protection against Slowloris.
///
/// Handles TLS record fragmentation across multiple TCP segments. If the initial bytes indicate a non-TLS
/// request (e.g. plain HTTP GET or port scanner), reads an initial chunk and returns it so the caller
/// can log the diagnostic preview.
pub async fn read_client_hello_record<S: AsyncReadExt + Unpin>(
    stream: &mut S,
    timeout: Duration,
) -> Result<Vec<u8>, &'static str> {
    tokio::time::timeout(timeout, async {
        let mut buf = Vec::with_capacity(4096);

        // 1. Read the 5-byte TLS record header
        while buf.len() < 5 {
            let mut chunk = [0u8; 5];
            let needed = 5 - buf.len();
            let n = stream
                .read(&mut chunk[..needed])
                .await
                .map_err(|_| "I/O error reading TLS header")?;
            if n == 0 {
                if buf.is_empty() {
                    return Err("Connection closed before any data received");
                } else {
                    return Err("Unexpected EOF while reading TLS record header");
                }
            }
            buf.extend_from_slice(&chunk[..n]);
        }

        // 2. Check if this is a TLS Handshake record (ContentType == 0x16)
        if buf[0] != 0x16 {
            // Not TLS handshake: might be plain HTTP (GET, POST), scanner probe, or garbage.
            // Read any readily available additional data up to 512 bytes for scanner logging.
            let mut extra = [0u8; 512];
            if let Ok(Ok(n)) = tokio::time::timeout(Duration::from_millis(50), stream.read(&mut extra)).await {
                buf.extend_from_slice(&extra[..n]);
            }
            return Ok(buf);
        }

        // 3. Extract the 16-bit record payload length
        let record_len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
        // Max allowed TLS record payload is 16384 bytes (RFC 8446 §5.1), plus 5-byte header = 16389 bytes.
        if record_len > 16384 {
            return Err("TLS record payload exceeds maximum allowable length of 16384 bytes");
        }

        let target_len = 5 + record_len;

        // 4. Read the remainder of the full TLS record (handling any fragmentation)
        let mut temp = [0u8; 4096];
        while buf.len() < target_len {
            let needed = target_len - buf.len();
            let to_read = std::cmp::min(needed, temp.len());
            let n = stream
                .read(&mut temp[..to_read])
                .await
                .map_err(|_| "I/O error reading TLS record payload")?;
            if n == 0 {
                return Err("Unexpected EOF while reading TLS record payload");
            }
            buf.extend_from_slice(&temp[..n]);
        }

        Ok(buf)
    })
    .await
    .map_err(|_| "Timed out while reading TLS ClientHello")?
}

#[cfg(unix)]
async fn wait_for_shutdown() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut sigterm = signal(SignalKind::terminate()).expect("Failed to register SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {
            info!("Received SIGINT (Ctrl+C). Shutting down Relay Server...");
        }
        _ = sigterm.recv() => {
            info!("Received SIGTERM. Shutting down Relay Server...");
        }
    }
}

#[cfg(not(unix))]
async fn wait_for_shutdown() {
    let _ = tokio::signal::ctrl_c().await;
    info!("Shutdown signal received. Shutting down Relay Server...");
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

/// Represents an active tunnel route registered by a Praeco Gateway.
#[derive(Clone)]
struct TunnelRoute {
    control: Control,
    generation: u64,
    supports_proxy_v2: bool,
}

/// Thread-safe map storing the active SNI-to-Control routing table.
type SessionMap = Arc<DashMap<String, TunnelRoute>>;

/// Configures tracing and OpenTelemetry (OTLP) based on the provided configuration.
/// Returns the `SdkTracerProvider` so it isn't dropped prematurely.
fn setup_tracing(config: &RelayConfig) -> Option<opentelemetry_sdk::trace::SdkTracerProvider> {
    let enable_otlp = config.enable_opentelemetry.unwrap_or(false);
    let jaeger_endpoint = config.jaeger_endpoint.as_deref().unwrap_or("http://localhost:4317");
    let otel_log_level = config.otel_log_level.as_deref().unwrap_or("info");

    let otel_sample_ratio = config.otel_sample_ratio.unwrap_or(1.0);

    let console_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let stdout_layer = tracing_subscriber::fmt::layer().with_ansi(true).with_filter(console_filter);

    if enable_otlp {
        let sampler = if (otel_sample_ratio - 1.0).abs() < f64::EPSILON {
            opentelemetry_sdk::trace::Sampler::AlwaysOn
        } else {
            opentelemetry_sdk::trace::Sampler::ParentBased(Box::new(opentelemetry_sdk::trace::Sampler::TraceIdRatioBased(otel_sample_ratio)))
        };

        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_tonic()
            .with_endpoint(jaeger_endpoint)
            .build()
            .expect("Failed to initialize OTLP exporter");

        let resource = Resource::builder()
            .with_service_name("praeco-relay")
            .build();

        let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_sampler(sampler)
            .with_resource(resource)
            .build();

        opentelemetry::global::set_tracer_provider(provider.clone());

        let tracer = provider.tracer("praeco-relay");
        let telemetry_filter = EnvFilter::new(otel_log_level);

        let telemetry_layer = tracing_opentelemetry::layer().with_tracer(tracer).with_filter(telemetry_filter);

        tracing_subscriber::registry()
            .with(stdout_layer)
            .with(telemetry_layer)
            .init();

        Some(provider)
    } else {
        tracing_subscriber::registry()
            .with(stdout_layer)
            .init();

        None
    }
}

/// Entry point for the Relay Server.
///
/// Loads the configuration, sets up observability, initializes the mTLS acceptor,
/// and spawns the Data Plane (HTTPS traffic) and Control Plane (internal mTLS registration).
#[tokio::main]
async fn main() -> Result<()> {
    let config_path = std::env::args().nth(1).unwrap_or_else(|| "RelayConfig.toml".to_string());
    let config = RelayConfig::load(&config_path)?;
    let _tracer_provider = setup_tracing(&config);
    
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
    let control_handshake_timeout = Duration::from_secs(config.control_plane_handshake_timeout_secs.unwrap_or(10));
    let max_yamux_streams = config.max_yamux_streams.unwrap_or(4096);
    let enable_proxy_protocol = config.enable_proxy_protocol.unwrap_or(true);
    tokio::spawn(async move {
        if let Err(e) = run_control_plane(
            tls_acceptor,
            control_tunnels,
            &control_addr,
            control_handshake_timeout,
            max_yamux_streams,
            enable_proxy_protocol,
        )
        .await
        {
            error!("Control plane failed: {}", e);
        }
    });

    // --- Spawn Data Plane ---
    let data_addr = config.data_plane_addr.clone();
    let rate_rate = config.rate_limit_connections_per_sec.unwrap_or(50) as f32;
    let rate_burst = config.rate_limit_burst.unwrap_or(100) as f32;
    let idle_timeout = match config.data_plane_idle_timeout_secs.unwrap_or(1800) {
        0 => None,
        secs => Some(Duration::from_secs(secs)),
    };
    let tcp_keepalive = match config.tcp_keepalive_secs.unwrap_or(60) {
        0 => None,
        secs => Some(Duration::from_secs(secs)),
    };
    let max_global_conn = config.max_concurrent_connections.unwrap_or(10000);
    let max_ip_conn = config.max_concurrent_connections_per_ip.unwrap_or(100);
    let connection_tracker = Arc::new(RelayConnectionTracker::new(max_global_conn, max_ip_conn));
    let client_hello_timeout = Duration::from_secs(config.client_hello_timeout_secs.unwrap_or(10));
    
    tokio::spawn(async move {
        if let Err(e) = run_data_plane(
            active_tunnels,
            &data_addr,
            rate_rate,
            rate_burst,
            idle_timeout,
            tcp_keepalive,
            connection_tracker,
            client_hello_timeout,
        )
        .await
        {
            error!("Data plane failed: {}", e);
        }
    });

    wait_for_shutdown().await;
    info!("Shutdown signal received. Shutting down Relay Server...");
    if let Some(provider) = _tracer_provider {
        let _ = provider.shutdown();
    }
    Ok(())
}

/// Loads certificates and constructs a `TlsAcceptor` configured for strict mTLS.
fn setup_mtls_acceptor(ca_path: &str, cert_path: &str, key_path: &str, crl_path: Option<&String>) -> Result<TlsAcceptor> {
    let ca_file = File::open(ca_path)?;
    let mut ca_reader = BufReader::new(ca_file);
    let mut root_store = RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut ca_reader) {
        let cert = cert.context("Failed to parse CA certificate")?;
        root_store.add(cert).context("Failed to add CA certificate to root store")?;
    }
    
    let mut verifier_builder = WebPkiClientVerifier::builder(Arc::new(root_store));
    
    if let Some(path) = crl_path {
        let crl_file = File::open(path)?;
        let mut crl_reader = BufReader::new(crl_file);
        let crls = rustls_pemfile::crls(&mut crl_reader).collect::<Result<Vec<_>, _>>()?;
        for crl_der in &crls {
            match x509_parser::parse_x509_crl(crl_der.as_ref()) {
                Ok((_, parsed_crl)) => {
                    if let Some(next_update) = parsed_crl.next_update() {
                        let now_ts = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs() as i64)
                            .unwrap_or(0);
                        if next_update.timestamp() < now_ts {
                            warn!(
                                crl_path = %path,
                                next_update = %next_update,
                                "Loaded CRL has expired (nextUpdate is in the past)! Revocation checks may use stale data."
                            );
                        }
                    } else {
                        warn!(crl_path = %path, "Loaded CRL does not contain a nextUpdate field.");
                    }
                }
                Err(e) => {
                    warn!(crl_path = %path, error = %e, "Failed to parse CRL with x509-parser for expiration check");
                }
            }
        }
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
async fn run_control_plane(
    tls_acceptor: TlsAcceptor,
    tunnels: SessionMap,
    addr: &str,
    handshake_timeout: Duration,
    max_yamux_streams: usize,
    enable_proxy_protocol: bool,
) -> Result<()> {
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

        // Socket-level TCP Keepalive on Control Plane to detect dead connections without dummy streams
        let sock_ref = socket2::SockRef::from(&stream);
        let keepalive = socket2::TcpKeepalive::new()
            .with_time(Duration::from_secs(30))
            .with_interval(Duration::from_secs(10));
        let _ = sock_ref.set_tcp_keepalive(&keepalive);
        let _ = sock_ref.set_nodelay(true);

        let acceptor = tls_acceptor.clone();
        let tunnels = tunnels.clone();

        tokio::spawn(async move {
            info!(target: "relay::control_plane", "New control connection");
            
            // 1. Perform strict mTLS Handshake with timeout (S-27 Hardening).
            let mut tls_stream = match tokio::time::timeout(handshake_timeout, acceptor.accept(stream)).await {
                Ok(Ok(s)) => s,
                Ok(Err(e)) => {
                    warn!(target: "relay::control_plane", client_ip = %client_addr, error = %e, "mTLS handshake failed");
                    return;
                }
                Err(_) => {
                    warn!(target: "relay::control_plane", client_ip = %client_addr, "mTLS handshake timed out");
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

            // --- Read REGISTER command byte-by-byte (up to '\n') ---
            // We must NOT over-read into a multi-byte buffer, because Praeco immediately
            // sends Yamux binary frames (e.g. ping/SYN) after the newline. Any over-read
            // bytes would corrupt both the SNI extraction and the subsequent Yamux stream.
            let mut line_bytes = Vec::with_capacity(128);
            let timeout_res = tokio::time::timeout(Duration::from_secs(10), async {
                let mut byte = [0u8; 1];
                while line_bytes.len() < 1024 {
                    match tls_stream.read_exact(&mut byte).await {
                        Ok(_) => {
                            if byte[0] == b'\n' {
                                return true;
                            }
                            line_bytes.push(byte[0]);
                        }
                        Err(_) => return false,
                    }
                }
                false
            }).await;

            if !timeout_res.unwrap_or(false) {
                warn!(target: "relay::control_plane", client_ip = %client_addr, "REGISTER command failed, timed out or too long");
                return;
            }

            let line = match String::from_utf8(line_bytes) {
                Ok(l) => l,
                Err(_) => {
                    warn!(target: "relay::control_plane", client_ip = %client_addr, "REGISTER command is not valid UTF-8");
                    return;
                }
            };

            // --- Safe Parsing with Capability Negotiation (P0.4 / Phase 4) ---
            let line_trimmed = line.trim();
            let parts: Vec<&str> = line_trimmed.split_whitespace().collect();
            if parts.is_empty() || parts[0] != "REGISTER" || parts.len() < 2 {
                warn!(target: "relay::control_plane", client_ip = %client_addr, "Invalid register command format");
                return;
            }
            let sni = parts[1].to_ascii_lowercase();
            let supports_proxy_v2 = parts[2..].contains(&"PROXY_V2") && enable_proxy_protocol;

            if !is_valid_sni(&sni) {
                warn!(target: "relay::control_plane", client_ip = %client_addr, requested_sni = %sni, "Invalid SNI hostname in REGISTER command");
                return;
            }

            // --- Verify SNI against Certificate SANs (P0.2) ---
            if !allowed_snis.iter().any(|allowed| allowed.eq_ignore_ascii_case(&sni)) {
                warn!(target: "relay::control_plane", client_ip = %client_addr, requested_sni = %sni, allowed_snis = ?allowed_snis, "SNI not authorized by client certificate");
                return;
            }

            // --- Overwrite Protection (P0.3 / S-27) ---
            // Prevent hijacking/blackholing of an active healthy tunnel
            if let Some(existing) = tunnels.get(&sni) {
                if !existing.value().control.tx.is_closed() {
                    warn!(
                        target: "relay::control_plane",
                        sni = %sni,
                        client_ip = %client_addr,
                        "Registration rejected: active healthy tunnel already registered for this SNI"
                    );
                    return;
                }
            }

            info!(target: "relay::control_plane", sni = %sni, proxy_v2 = supports_proxy_v2, "Praeco tunnel registered");

            let mut cfg = YamuxConfig::default();
            let min_window = max_yamux_streams * 256 * 1024;
            cfg.set_max_connection_receive_window(Some(std::cmp::max(min_window, 1024 * 1024 * 1024)));
            cfg.set_max_num_streams(max_yamux_streams);
            let mut connection = Connection::new(tls_stream.compat(), cfg, Mode::Server);

            let (tx, mut rx) = mpsc::channel(32);
            let control = Control { tx };

            // --- Store with Generation ID (P0.5) ---
            // To handle reconnects gracefully without race conditions (where an old dying connection
            // might delete the newly established connection's map entry), we use an atomic Generation ID.
            use std::sync::atomic::{AtomicU64, Ordering};
            static GENERATION: AtomicU64 = AtomicU64::new(1);
            let my_generation = GENERATION.fetch_add(1, Ordering::SeqCst);

            tunnels.insert(
                sni.clone(),
                TunnelRoute {
                    control: control.clone(),
                    generation: my_generation,
                    supports_proxy_v2,
                },
            );

            // --- Connection Driver Loop ---
            // This loop polls the Yamux multiplexer. It constantly checks for new outbound
            // stream requests (originating from the Data Plane) and pushes them down the tunnel,
            // whilst simultaneously driving all active streams to completion.
            // When the underlying TCP/mTLS socket drops (detected via TCP keepalive or EOF),
            // this loop exits cleanly and removes the tunnel without spurious TLS warnings.
            let mut pending_outbound: Option<oneshot::Sender<Result<yamux::Stream, yamux::ConnectionError>>> = None;

            std::future::poll_fn(|cx| {
                // 1. Check for new outbound requests (from Data Plane) if we don't have one pending
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

                // 3. Drive inbound streams and connection progress (keeping multiplexing alive)
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
            tunnels.remove_if(&sni, |_, route| route.generation == my_generation);
        }.instrument(info_span!("control_connection", client_ip = %client_addr)));
    }
}

/// Result outcome for copying bidirectional traffic.
#[derive(Debug)]
enum CopyResult {
    /// Both directions finished gracefully with transferred bytes (up, down).
    Clean(u64, u64),
    /// The connection was closed after being idle for longer than the configured timeout.
    IdleTimeout,
    /// An I/O error occurred during transfer.
    Error(std::io::Error),
}

use std::sync::atomic::{AtomicBool, Ordering};
use std::pin::Pin;
use std::task::Poll;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// A wrapper around any AsyncRead + AsyncWrite that sets an atomic boolean flag on every I/O operation.
struct ActivityTracker<S> {
    inner: S,
    had_activity: Arc<AtomicBool>,
}

impl<S> ActivityTracker<S> {
    fn new(inner: S, had_activity: Arc<AtomicBool>) -> Self {
        Self { inner, had_activity }
    }
    
    #[inline(always)]
    fn mark_active(&self) {
        // Absolute Zero-Overhead: A single CPU instruction, no syscalls, no time calculations.
        self.had_activity.store(true, Ordering::Relaxed);
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ActivityTracker<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(_)) = &res {
            self.mark_active();
        }
        res
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ActivityTracker<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let res = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(_)) = &res {
            self.mark_active();
        }
        res
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Bidirectionally forwards traffic between two async streams with an optional idle timeout.
///
/// Unlike a hard lifetime timeout, this watchdog only triggers if NO data is transferred
/// in either direction for the specified `idle_timeout` duration.
///
/// # Arguments
///
/// * `a` - The client stream (or first endpoint).
/// * `b` - The tunnel stream (or second endpoint).
/// * `idle_timeout` - Optional maximum idle duration before terminating inactive connections.
///
/// # Returns
///
/// * `CopyResult::Clean(up, down)` if the connection closed normally.
/// * `CopyResult::IdleTimeout` if no data was transferred in either direction for `idle_timeout`.
/// * `CopyResult::Error(err)` if an I/O error occurred.
async fn copy_bidirectional_with_idle_timeout<A, B>(
    a: A,
    b: B,
    idle_timeout: Option<Duration>,
) -> CopyResult
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static,
{
    let Some(timeout) = idle_timeout else {
        // If no idle timeout is configured, rely purely on OS-level TCP keepalive
        let mut a = a;
        let mut b = b;
        return match tokio::io::copy_bidirectional(&mut a, &mut b).await {
            Ok((up, down)) => CopyResult::Clean(up, down),
            Err(e) => CopyResult::Error(e),
        };
    };

    let had_activity = Arc::new(AtomicBool::new(true));

    let mut a_tracker = ActivityTracker::new(a, had_activity.clone());
    let mut b_tracker = ActivityTracker::new(b, had_activity.clone());

    tokio::select! {
        res = tokio::io::copy_bidirectional(&mut a_tracker, &mut b_tracker) => {
            match res {
                Ok((up, down)) => CopyResult::Clean(up, down),
                Err(e) => CopyResult::Error(e),
            }
        }
        _ = async {
            let tick_interval_secs = 10;
            let max_idle_ticks = timeout.as_secs() / tick_interval_secs;
            let mut idle_ticks = 0;
            
            let mut interval = tokio::time::interval(Duration::from_secs(tick_interval_secs));
            loop {
                interval.tick().await;
                // Swap the flag to false. If it was true, we had activity.
                if had_activity.swap(false, Ordering::Relaxed) {
                    idle_ticks = 0;
                } else {
                    idle_ticks += 1;
                    if idle_ticks >= max_idle_ticks {
                        break;
                    }
                }
            }
        } => {
            CopyResult::IdleTimeout
        }
    }
}

/// Runs the Data Plane, accepting public TCP connections and routing them via SNI.
///
/// Extracts the Server Name Indication (SNI) from the initial TLS ClientHello.
/// Looks up the SNI in the `tunnels` map, opens a new stream over the corresponding
/// Yamux connection, and forwards bidirectional TCP traffic with an activity-based idle timeout.
/// Applies a Token-Bucket rate limit per client IP to mitigate L4 connection floods.
async fn run_data_plane(
    tunnels: SessionMap,
    addr: &str,
    rate: f32,
    burst: f32,
    idle_timeout: Option<Duration>,
    tcp_keepalive: Option<Duration>,
    connection_tracker: Arc<RelayConnectionTracker>,
    client_hello_timeout: Duration,
) -> Result<()> {
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

        // --- Socket-level TCP Keepalive ---
        if let Some(keepalive_dur) = tcp_keepalive {
            let sock_ref = socket2::SockRef::from(&client_stream);
            let keepalive = socket2::TcpKeepalive::new()
                .with_time(keepalive_dur)
                .with_interval(Duration::from_secs(10));
            let _ = sock_ref.set_tcp_keepalive(&keepalive);
            let _ = sock_ref.set_nodelay(true);
        }

        // --- Rate Limiting Check (Aggregated IPv6 on /64 to prevent evasion) ---
        let canonical_ip = canonicalize_ip(client_addr.ip());
        const MAX_RATE_LIMIT_ENTRIES: usize = 100_000;
        if !rate_limits.contains_key(&canonical_ip) && rate_limits.len() >= MAX_RATE_LIMIT_ENTRIES {
            warn!(target: "relay::data_plane", client_ip = %client_addr, "Rate limit table at capacity, dropping new IP connection");
            continue;
        }
        let mut bucket = rate_limits.entry(canonical_ip).or_insert_with(|| TokenBucket::new(burst));
        if !bucket.consume(rate, burst) {
            warn!(target: "relay::data_plane", client_ip = %client_addr, "Rate limit exceeded, dropping connection");
            continue; // Drop instantly
        }
        drop(bucket); // Explicitly release the lock before spawning

        // --- Concurrency Limit Check (Global & Per-IP /64 Cap) ---
        let connection_guard = match connection_tracker.acquire(client_addr.ip()) {
            Ok(guard) => guard,
            Err(e) => {
                warn!(target: "relay::data_plane", client_ip = %client_addr, error = %e, "Connection rejected: concurrency limit reached");
                continue;
            }
        };

        let tunnels = tunnels.clone();
        tokio::spawn(async move {
            let _guard = connection_guard;

            // --- Read TLS ClientHello Record (Protected against Slowloris & TCP Fragmentation) ---
            let buf = match read_client_hello_record(&mut client_stream, client_hello_timeout).await {
                Ok(b) => b,
                Err(err_msg) => {
                    warn!(target: "relay::data_plane", client_ip = %client_addr, error = %err_msg, "Failed to read ClientHello");
                    return;
                }
            };

            let sni = match extract_sni(&buf) {
                Ok(s) => s.to_ascii_lowercase(),
                Err(reason) => {
                    let preview_len = std::cmp::min(buf.len(), 64);
                    let preview = &buf[..preview_len];
                    
                    let is_ascii = preview.iter().all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace());
                    let preview_str = if is_ascii {
                        String::from_utf8_lossy(preview).replace('\r', "\\r").replace('\n', "\\n")
                    } else {
                        preview.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join(" ")
                    };

                    warn!(
                        target: "relay::data_plane", 
                        client_ip = %client_addr, 
                        reason = %reason, 
                        payload_preview = %preview_str,
                        "Failed to extract SNI (possible port scanner or plaintext HTTP)"
                    );
                    return;
                }
            };
            
            if !is_valid_sni(&sni) {
                warn!(target: "relay::data_plane", client_ip = %client_addr, sni = %sni, "Invalid or empty SNI");
                return;
            }

            let (mut control, supports_proxy_v2) = match tunnels.get(&sni) {
                Some(entry) => (entry.value().control.clone(), entry.value().supports_proxy_v2),
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

            if supports_proxy_v2 {
                let local_addr = client_stream.local_addr().unwrap_or(client_addr);
                let ppv2_header = common::proxy_protocol::encode_proxy_v2(client_addr, local_addr);
                if let Err(e) = tokio_tunnel.write_all(&ppv2_header).await {
                    warn!(target: "relay::data_plane", sni = %sni, error = %e, "Failed to write PROXY-Protocol v2 header to tunnel");
                    return;
                }
            }

            if let Err(e) = tokio_tunnel.write_all(&buf).await {
                warn!(target: "relay::data_plane", sni = %sni, error = %e, "Failed to write ClientHello to tunnel");
                return;
            }

            info!(target: "relay::data_plane", sni = %sni, client_ip = %client_addr, "Routing connection via tunnel");

            let res = copy_bidirectional_with_idle_timeout(client_stream, tokio_tunnel, idle_timeout).await;

            match res {
                CopyResult::Clean(up, down) => {
                    info!(target: "relay::data_plane", sni = %sni, client_ip = %client_addr, up_bytes = up, down_bytes = down, "Connection closed cleanly");
                }
                CopyResult::Error(e) => {
                    debug!(target: "relay::data_plane", sni = %sni, client_ip = %client_addr, error = %e, "Connection closed with I/O error");
                }
                CopyResult::IdleTimeout => {
                    debug!(target: "relay::data_plane", sni = %sni, client_ip = %client_addr, "Connection closed after idle timeout");
                }
            }
        }.instrument(info_span!("data_connection", client_ip = %client_addr)));
    }
}

/// Best-effort extraction of the SNI domain name from a raw TLS ClientHello packet.
/// 
/// Relies on `tls_parser` to interpret the raw bytes without completing a handshake.
fn extract_sni(buf: &[u8]) -> Result<String, &'static str> {
    match parse_tls_plaintext(buf) {
        Ok((_, pt)) => {
            let mut found_handshake = false;
            for msg in pt.msg {
                if let tls_parser::TlsMessage::Handshake(handshake_msg) = msg {
                    found_handshake = true;
                    if let TlsMessageHandshake::ClientHello(client_hello) = handshake_msg {
                        if let Some(ext_bytes) = client_hello.ext {
                            if let Ok((_, exts)) = tls_parser::parse_tls_extensions(ext_bytes) {
                                for ext in exts {
                                    if let TlsExtension::SNI(sni_ext) = ext {
                                        if let Some((_, name)) = sni_ext.first() {
                                            if let Ok(name_str) = std::str::from_utf8(name) {
                                                return Ok(name_str.to_string());
                                            } else {
                                                return Err("Invalid UTF-8 in SNI hostname");
                                            }
                                        } else {
                                            return Err("SNI extension present but empty");
                                        }
                                    }
                                }
                                return Err("ClientHello has no SNI extension");
                            } else {
                                return Err("Failed to parse ClientHello extensions");
                            }
                        } else {
                            return Err("ClientHello has no extensions");
                        }
                    }
                }
            }
            if found_handshake {
                Err("No ClientHello found in TLS Handshake")
            } else {
                Err("No TLS Handshake found")
            }
        }
        Err(_) => Err("Not a valid TLS plaintext message"),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_praeco_client_cert_snis() {
        let cert_file = File::open("../server_certs/self_signed/praeco_client.pem").unwrap();
        let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut BufReader::new(cert_file)).collect::<Result<Vec<_>, _>>().unwrap();
        let cert_der = certs.first().unwrap();
        let (_, cert) = x509_parser::parse_x509_certificate(cert_der).unwrap();
        let mut allowed_snis = Vec::new();
        for ext in cert.iter_extensions() {
            if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) = ext.parsed_extension() {
                for name in &san.general_names {
                    if let x509_parser::extensions::GeneralName::DNSName(dns) = name {
                        allowed_snis.push(dns.to_string());
                    }
                }
            }
        }
        println!("ALLOWED SNIS: {:?}", allowed_snis);
        assert!(allowed_snis.contains(&"wurzelwerk.api.aweirich.eu".to_string()));
        assert!(allowed_snis.contains(&"wurzelwerk.onboarding.aweirich.eu".to_string()));
        assert!(allowed_snis.contains(&"wurzelwerk.admin.aweirich.eu".to_string()));
        assert!(allowed_snis.contains(&"wurzelwerk.idp.aweirich.eu".to_string()));
    }

    #[tokio::test]
    async fn test_full_control_plane_registration() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        use tokio::io::AsyncWriteExt;
        // 1. Setup Acceptor
        let acceptor = setup_mtls_acceptor(
            "../server_certs/self_signed/relay_ca.pem",
            "../server_certs/self_signed/relay_server.pem",
            "../server_certs/self_signed/relay_server.key",
            None,
        ).unwrap();

        let (client_io, server_io) = tokio::io::duplex(65536);

        let listener_task = tokio::spawn(async move {
            let mut tls_stream = acceptor.accept(server_io).await.unwrap();
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

            let mut line_bytes = Vec::new();
            let mut byte = [0u8; 1];
            while tls_stream.read_exact(&mut byte).await.is_ok() {
                if byte[0] == b'\n' {
                    break;
                }
                line_bytes.push(byte[0]);
            }
            let line = String::from_utf8(line_bytes).unwrap();
            let line_trimmed = line.trim();
            let Some(("REGISTER", sni_raw)) = line_trimmed.split_once(' ') else {
                panic!("Invalid REGISTER");
            };
            let sni = sni_raw.trim().to_string();
            assert!(allowed_snis.contains(&sni), "SNI not authorized! allowed_snis: {:?}, requested: {:?}", allowed_snis, sni);

        });

        // 2. Client side (Praeco run_tunnel)
        let mut root_store = rustls::RootCertStore::empty();
        let ca_file = File::open("../server_certs/self_signed/relay_ca.pem").unwrap();
        for cert in rustls_pemfile::certs(&mut BufReader::new(ca_file)) {
            root_store.add(cert.unwrap()).unwrap();
        }
        let cert_file = File::open("../server_certs/self_signed/praeco_client.pem").unwrap();
        let certs: Vec<CertificateDer> = rustls_pemfile::certs(&mut BufReader::new(cert_file)).collect::<Result<Vec<_>, _>>().unwrap();
        let key_file = File::open("../server_certs/self_signed/praeco_client.key").unwrap();
        let key = rustls_pemfile::private_key(&mut BufReader::new(key_file)).unwrap().unwrap();

        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(certs, key).unwrap();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

        let domain = rustls::pki_types::ServerName::try_from("localhost".to_string()).unwrap();
        let mut tls_stream = connector.connect(domain, client_io).await.unwrap();

        let reg_cmd = "REGISTER wurzelwerk.onboarding.aweirich.eu\n";
        tls_stream.write_all(reg_cmd.as_bytes()).await.unwrap();
        tls_stream.flush().await.unwrap();

        // Simulate Praeco immediately wrapping the stream in Yamux
        let _client_conn = Connection::new(tls_stream.compat(), YamuxConfig::default(), Mode::Client);

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
        let active_tunnels: SessionMap = Arc::new(DashMap::new());
        let (tx, _rx) = mpsc::channel(32);
        let control = Control { tx };

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
        assert!(!existing.value().control.tx.is_closed(), "Channel should be open");

        // If the old tunnel closes its receiver (drops connection), tx.is_closed() becomes true
        drop(_rx);
        assert!(existing.value().control.tx.is_closed(), "Channel should now be closed");
    }

    #[test]
    fn test_register_command_parsing_capability_negotiation() {
        let parse_register = |line: &str, enable_pp: bool| -> Option<(String, bool)> {
            let line_trimmed = line.trim();
            let parts: Vec<&str> = line_trimmed.split_whitespace().collect();
            if parts.is_empty() || parts[0] != "REGISTER" || parts.len() < 2 {
                return None;
            }
            let sni = parts[1].to_string();
            let ppv2 = parts[2..].contains(&"PROXY_V2") && enable_pp;
            Some((sni, ppv2))
        };

        // 1. Legacy Praeco without PROXY_V2
        let (sni1, pp1) = parse_register("REGISTER api.example.com\n", true).unwrap();
        assert_eq!(sni1, "api.example.com");
        assert!(!pp1);

        // 2. Modern Praeco with PROXY_V2 and Relay enabled
        let (sni2, pp2) = parse_register("REGISTER chat.example.com PROXY_V2\n", true).unwrap();
        assert_eq!(sni2, "chat.example.com");
        assert!(pp2);

        // 3. Modern Praeco with PROXY_V2 but Relay config has enable_proxy_protocol = false
        let (sni3, pp3) = parse_register("REGISTER chat.example.com PROXY_V2\n", false).unwrap();
        assert_eq!(sni3, "chat.example.com");
        assert!(!pp3);

        // 4. Extensible capability flags
        let (sni4, pp4) = parse_register("REGISTER stream.example.com OTHER_FLAG PROXY_V2\n", true).unwrap();
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

        // Test scaling calculation for Yamux config
        let max_streams = config.max_yamux_streams.unwrap_or(4096);
        let mut yamux_cfg = YamuxConfig::default();
        let min_window = max_streams * 256 * 1024;
        yamux_cfg.set_max_connection_receive_window(Some(std::cmp::max(min_window, 1024 * 1024 * 1024)));
        yamux_cfg.set_max_num_streams(max_streams);
    }
}
