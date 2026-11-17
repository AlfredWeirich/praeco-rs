//! # Praeco Relay Server Library
//!
//! Core library for the Zero-Trust, SNI-based TCP Relay Server.
//!
//! Internal Praeco gateway instances register via an outbound mTLS connection on the
//! **Control Plane** and establish a Yamux multiplexed tunnel. The **Data Plane**
//! parses the Server Name Indication (SNI) from incoming TLS `ClientHello` records
//! and forwards the raw TCP stream over the corresponding Yamux tunnel to the
//! backend Praeco server (optionally prefixed with a binary HAProxy PROXY Protocol v2 header).

pub mod config;

pub use config::RelayConfig;

use dashmap::DashMap;
use rustls::RootCertStore;
use rustls::pki_types::{
    CertificateDer, CertificateRevocationListDer, PrivateKeyDer, pem::PemObject,
};
use rustls::server::WebPkiClientVerifier;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::task::Poll;
use std::time::{Duration, Instant};
use tls_parser::{TlsExtension, TlsMessageHandshake, parse_tls_plaintext};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::{mpsc, oneshot};
use tokio::task::{JoinError, JoinSet};
use tokio_rustls::TlsAcceptor;
use tokio_util::compat::{FuturesAsyncWriteCompatExt, TokioAsyncReadCompatExt};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use yamux::{Config as YamuxConfig, Connection, Mode, Stream as YamuxStream};

/// Maximum time active control/data tasks get to finish on relay shutdown.
const RELAY_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Backoff after a transient `accept()` error (e.g. `EMFILE`) to avoid a busy loop.
const ACCEPT_ERROR_BACKOFF: Duration = Duration::from_millis(50);

fn log_relay_task_result(what: &str, res: Result<(), JoinError>) {
    if let Err(e) = res {
        if e.is_panic() {
            error!("Relay {} task panicked: {:?}", what, e);
        } else if !e.is_cancelled() {
            error!("Relay {} task failed: {:?}", what, e);
        }
    }
}

async fn drain_relay_tasks(tasks: &mut JoinSet<()>, what: &str, timeout: Duration) {
    let drain = async {
        while let Some(res) = tasks.join_next().await {
            log_relay_task_result(what, res);
        }
    };
    if tokio::time::timeout(timeout, drain).await.is_err() {
        warn!(
            "Relay {} drain timed out after {:?}; aborting {} remaining task(s)",
            what,
            timeout,
            tasks.len()
        );
        tasks.abort_all();
        while let Some(res) = tasks.join_next().await {
            log_relay_task_result(what, res);
        }
    }
}

/// Domain-specific error type for the Praeco Relay Server library.
#[derive(Debug, thiserror::Error)]
pub enum RelayError {
    /// Configuration file does not exist at the specified path.
    #[error(
        "Configuration file not found at path: {0}. A valid configuration is strictly required for secure Relay operation."
    )]
    ConfigNotFound(String),

    /// Failed to read the configuration file from disk.
    #[error("Failed to read configuration file '{path}': {source}")]
    ConfigRead {
        /// Path to the configuration file.
        path: String,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Failed to parse the TOML configuration content.
    #[error("Failed to parse TOML configuration: {0}")]
    ConfigParse(#[from] toml::de::Error),

    /// Standard I/O error (file reading, socket binding, etc.).
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Rustls TLS configuration or runtime error.
    #[error("TLS error: {0}")]
    Rustls(#[from] rustls::Error),

    /// Failed to build the WebPKI client certificate verifier.
    #[error("Client certificate verifier builder error: {0}")]
    VerifierBuilder(#[from] rustls::server::VerifierBuilderError),

    /// PEM parsing error for certificates, CRLs, or private keys.
    #[error("PEM error: {0}")]
    Pem(#[from] rustls::pki_types::pem::Error),
}

/// Basic token bucket rate limiter tracking connection capacity per canonical IP.
pub struct TokenBucket {
    tokens: f32,
    last_update: Instant,
}

impl TokenBucket {
    /// Creates a new `TokenBucket` initialized with the maximum burst capacity.
    ///
    /// # Arguments
    ///
    /// * `burst` - The maximum number of tokens this bucket can hold.
    pub fn new(burst: f32) -> Self {
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
    pub fn consume(&mut self, rate: f32, burst: f32) -> bool {
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

    /// Returns the timestamp of the last bucket update.
    pub fn last_update(&self) -> Instant {
        self.last_update
    }
}

/// Canonicalizes an IP address:
/// - IPv4 addresses remain unchanged.
/// - IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are unwrapped to IPv4.
/// - Standard IPv6 addresses are masked to a `/64` subnet prefix to prevent rate-limit and connection-limit evasion.
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
    /// Creates a new [`RelayConnectionTracker`] with the given global and per-IP connection limits.
    pub fn new(max_global: usize, max_per_ip: usize) -> Self {
        Self {
            max_global,
            max_per_ip,
            global_count: AtomicUsize::new(0),
            ip_counts: DashMap::new(),
        }
    }

    /// Attempts to acquire a connection slot for `raw_ip`.
    ///
    /// # Errors
    ///
    /// Returns an error message if either the global or per-IP limit is reached.
    pub fn acquire(
        self: &Arc<Self>,
        raw_ip: IpAddr,
    ) -> Result<RelayConnectionGuard, &'static str> {
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

    /// Returns the current number of active connections across all IPs.
    pub fn current_global(&self) -> usize {
        self.global_count.load(Ordering::Relaxed)
    }

    /// Returns the current number of active connections for the canonicalized `raw_ip`.
    pub fn current_for_ip(&self, raw_ip: IpAddr) -> usize {
        let ip = canonicalize_ip(raw_ip);
        self.ip_counts.get(&ip).map(|v| *v).unwrap_or(0)
    }
}

/// Reads a full TLS `ClientHello` record from the incoming stream with a timeout and protection against Slowloris.
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
            if let Ok(Ok(n)) =
                tokio::time::timeout(Duration::from_millis(50), stream.read(&mut extra)).await
            {
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

/// Represents a control handle to an active Yamux multiplexed connection.
/// Used to request new outbound streams from the Relay to the Praeco backend.
#[derive(Clone)]
pub struct Control {
    tx: mpsc::Sender<oneshot::Sender<Result<YamuxStream, yamux::ConnectionError>>>,
}

impl Control {
    /// Creates a new [`Control`] handle wrapping the given bounded channel sender.
    pub fn new(
        tx: mpsc::Sender<oneshot::Sender<Result<YamuxStream, yamux::ConnectionError>>>,
    ) -> Self {
        Self { tx }
    }

    /// Opens a new stream over the multiplexed Yamux connection.
    ///
    /// This method sends a request to the connection driver task to open a new stream.
    /// It returns a `YamuxStream` which implements `AsyncRead` and `AsyncWrite`.
    pub async fn open_stream(&mut self) -> Result<YamuxStream, yamux::ConnectionError> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(tx)
            .await
            .map_err(|_| yamux::ConnectionError::Closed)?;
        rx.await.map_err(|_| yamux::ConnectionError::Closed)?
    }

    /// Returns `true` if the underlying control channel is closed (i.e. the tunnel driver task has exited).
    pub fn is_closed(&self) -> bool {
        self.tx.is_closed()
    }
}

/// Represents an active tunnel route registered by a Praeco Gateway.
#[derive(Clone)]
pub struct TunnelRoute {
    /// Control handle for opening new outbound Yamux streams on this tunnel.
    pub control: Control,
    /// Monotonically increasing generation ID to prevent stale disconnect cleanups from removing newer routes.
    pub generation: u64,
    /// Whether this tunnel negotiated binary HAProxy PROXY Protocol v2 headers.
    pub supports_proxy_v2: bool,
}

/// Thread-safe map storing the active SNI-to-Control routing table.
pub type SessionMap = Arc<DashMap<String, TunnelRoute>>;

/// Creates a new empty [`SessionMap`].
pub fn new_session_map() -> SessionMap {
    Arc::new(DashMap::new())
}

/// Loads certificates and constructs a [`TlsAcceptor`] configured for strict mTLS.
///
/// # Errors
///
/// Returns a [`RelayError`] if any certificate, CRL, or private key file cannot be read or parsed,
/// or if the `rustls` verifier or server config fails to build.
pub fn setup_mtls_acceptor(
    ca_path: &str,
    cert_path: &str,
    key_path: &str,
    crl_path: Option<&String>,
) -> Result<TlsAcceptor, RelayError> {
    let mut root_store = RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(ca_path)? {
        root_store.add(cert?)?;
    }

    let mut verifier_builder = WebPkiClientVerifier::builder(Arc::new(root_store));

    if let Some(path) = crl_path {
        let crls =
            CertificateRevocationListDer::pem_file_iter(path)?.collect::<Result<Vec<_>, _>>()?;
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

    let certs: Vec<CertificateDer> =
        CertificateDer::pem_file_iter(cert_path)?.collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(key_path)?;

    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Extracts all DNS Subject Alternative Names (SANs) from a DER-encoded X.509 certificate.
pub fn extract_allowed_snis(cert_der: &[u8]) -> Vec<String> {
    let mut allowed_snis = Vec::new();
    if let Ok((_, cert)) = x509_parser::parse_x509_certificate(cert_der) {
        for ext in cert.iter_extensions() {
            if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) =
                ext.parsed_extension()
            {
                for name in &san.general_names {
                    if let x509_parser::extensions::GeneralName::DNSName(dns) = name {
                        allowed_snis.push(dns.to_string());
                    }
                }
            }
        }
    }
    allowed_snis
}

/// Parses a `REGISTER <sni> [PROXY_V2 ...]` control-plane command line.
///
/// Returns `Some((lowercased_sni, supports_proxy_v2))` if the command format is valid.
pub fn parse_register_command(line: &str, enable_proxy_protocol: bool) -> Option<(String, bool)> {
    let line_trimmed = line.trim();
    let parts: Vec<&str> = line_trimmed.split_whitespace().collect();
    if parts.is_empty() || parts[0] != "REGISTER" || parts.len() < 2 {
        return None;
    }
    let sni = parts[1].to_ascii_lowercase();
    let supports_proxy_v2 = parts[2..].contains(&"PROXY_V2") && enable_proxy_protocol;
    Some((sni, supports_proxy_v2))
}

/// Handles a single Control Plane connection from a Praeco Gateway.
///
/// Performs the mTLS handshake, validates the client certificate's SANs against the
/// requested SNI in the `REGISTER` command, enforces active-tunnel overwrite protection,
/// registers the tunnel in `tunnels`, and drives the Yamux multiplexer until disconnection.
#[allow(clippy::too_many_arguments)]
pub async fn handle_control_connection<S>(
    stream: S,
    client_addr: SocketAddr,
    acceptor: TlsAcceptor,
    tunnels: SessionMap,
    handshake_timeout: Duration,
    max_yamux_streams: usize,
    enable_proxy_protocol: bool,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    handle_control_connection_with_cancel(
        stream,
        client_addr,
        acceptor,
        tunnels,
        handshake_timeout,
        max_yamux_streams,
        enable_proxy_protocol,
        CancellationToken::new(),
    )
    .await;
}

#[allow(clippy::too_many_arguments)]
#[tracing::instrument(
    name = "control_connection",
    skip(
        stream,
        acceptor,
        tunnels,
        handshake_timeout,
        max_yamux_streams,
        enable_proxy_protocol,
        cancel_token
    ),
    fields(client_ip = %client_addr)
)]
async fn handle_control_connection_with_cancel<S>(
    stream: S,
    client_addr: SocketAddr,
    acceptor: TlsAcceptor,
    tunnels: SessionMap,
    handshake_timeout: Duration,
    max_yamux_streams: usize,
    enable_proxy_protocol: bool,
    cancel_token: CancellationToken,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    info!(target: "relay::control_plane", "New control connection");

    // 1. Perform strict mTLS Handshake with timeout (S-27 Hardening).
    let mut tls_stream = match tokio::time::timeout(handshake_timeout, acceptor.accept(stream)).await
    {
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
    let allowed_snis = tls_stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certs| certs.first())
        .map(|cert_der| extract_allowed_snis(cert_der))
        .unwrap_or_default();

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
    })
    .await;

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
    let Some((sni, supports_proxy_v2)) = parse_register_command(&line, enable_proxy_protocol) else {
        warn!(target: "relay::control_plane", client_ip = %client_addr, "Invalid register command format");
        return;
    };

    if !is_valid_sni(&sni) {
        warn!(target: "relay::control_plane", client_ip = %client_addr, requested_sni = %sni, "Invalid SNI hostname in REGISTER command");
        return;
    }

    // --- Verify SNI against Certificate SANs (P0.2) ---
    if !allowed_snis
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(&sni))
    {
        warn!(target: "relay::control_plane", client_ip = %client_addr, requested_sni = %sni, allowed_snis = ?allowed_snis, "SNI not authorized by client certificate");
        return;
    }

    // --- Overwrite Protection (P0.3 / S-27) ---
    // Prevent hijacking/blackholing of an active healthy tunnel
    if let Some(existing) = tunnels.get(&sni)
        && !existing.value().control.is_closed()
    {
        warn!(
            target: "relay::control_plane",
            sni = %sni,
            client_ip = %client_addr,
            "Registration rejected: active healthy tunnel already registered for this SNI"
        );
        return;
    }

    info!(target: "relay::control_plane", sni = %sni, proxy_v2 = supports_proxy_v2, "Praeco tunnel registered");

    let mut cfg = YamuxConfig::default();
    let min_window = max_yamux_streams * 256 * 1024;
    cfg.set_max_connection_receive_window(Some(std::cmp::max(min_window, 1024 * 1024 * 1024)));
    cfg.set_max_num_streams(max_yamux_streams);
    let mut connection = Connection::new(tls_stream.compat(), cfg, Mode::Server);

    let (tx, mut rx) = mpsc::channel(32);
    let control = Control::new(tx);

    // --- Store with Generation ID (P0.5) ---
    // To handle reconnects gracefully without race conditions (where an old dying connection
    // might delete the newly established connection's map entry), we use an atomic Generation ID.
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
    let mut pending_outbound: Option<
        oneshot::Sender<Result<yamux::Stream, yamux::ConnectionError>>,
    > = None;

    let driver = std::future::poll_fn(|cx| {
        // 1. Check for new outbound requests (from Data Plane) if we don't have one pending
        if pending_outbound.is_none()
            && let std::task::Poll::Ready(Some(resp_tx)) = rx.poll_recv(cx)
        {
            pending_outbound = Some(resp_tx);
        }

        // 2. Drive outbound stream opening if pending
        if pending_outbound.is_some()
            && let std::task::Poll::Ready(stream_res) = connection.poll_new_outbound(cx)
            && let Some(resp_tx) = pending_outbound.take()
        {
            let _ = resp_tx.send(stream_res);
        }

        // 3. Drive inbound streams and connection progress (keeping multiplexing alive)
        match connection.poll_next_inbound(cx) {
            std::task::Poll::Ready(Some(Ok(unexpected_stream))) => {
                warn!(target: "relay::control_plane", sni = %sni, "Unexpected inbound stream from client");
                drop(unexpected_stream);
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
    });

    tokio::select! {
        () = driver => {}
        () = cancel_token.cancelled() => {
            info!(target: "relay::control_plane", sni = %sni, "Closing control tunnel on shutdown");
            let _ = tokio::time::timeout(
                Duration::from_secs(1),
                std::future::poll_fn(|cx| connection.poll_close(cx)),
            )
            .await;
        }
    }

    // Remove only if generation matches (P0.5)
    tunnels.remove_if(&sni, |_, route| route.generation == my_generation);
}

/// Runs the Control Plane accept loop on a pre-bound [`TcpListener`], accepting incoming mTLS
/// registrations from Praeco servers until `cancel_token` is triggered.
#[tracing::instrument(skip(listener, tls_acceptor, tunnels, cancel_token), err)]
pub async fn run_control_plane(
    listener: TcpListener,
    tls_acceptor: TlsAcceptor,
    tunnels: SessionMap,
    handshake_timeout: Duration,
    max_yamux_streams: usize,
    enable_proxy_protocol: bool,
    cancel_token: CancellationToken,
) -> Result<(), RelayError> {
    if let Ok(local_addr) = listener.local_addr() {
        info!("Control plane listening on mTLS {}", local_addr);
    }

    let mut conn_tasks: JoinSet<()> = JoinSet::new();

    loop {
        let (stream, client_addr) = tokio::select! {
            _ = cancel_token.cancelled() => {
                info!("Control plane shutting down gracefully");
                break;
            }
            Some(res) = conn_tasks.join_next(), if !conn_tasks.is_empty() => {
                log_relay_task_result("control connection", res);
                continue;
            }
            accept_res = listener.accept() => {
                match accept_res {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("Failed to accept control connection: {}", e);
                        tokio::select! {
                            _ = cancel_token.cancelled() => break,
                            _ = tokio::time::sleep(ACCEPT_ERROR_BACKOFF) => {}
                        }
                        continue;
                    }
                }
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
        let conn_cancel = cancel_token.child_token();

        conn_tasks.spawn(handle_control_connection_with_cancel(
            stream,
            client_addr,
            acceptor,
            tunnels,
            handshake_timeout,
            max_yamux_streams,
            enable_proxy_protocol,
            conn_cancel,
        ));
    }

    drop(listener);
    drain_relay_tasks(&mut conn_tasks, "control connection", RELAY_DRAIN_TIMEOUT).await;
    Ok(())
}

/// Result outcome for copying bidirectional traffic.
#[derive(Debug)]
pub enum CopyResult {
    /// Both directions finished gracefully with transferred bytes (up, down).
    Clean(u64, u64),
    /// The connection was closed after being idle for longer than the configured timeout.
    IdleTimeout,
    /// An I/O error occurred during transfer.
    Error(std::io::Error),
}

/// A wrapper around any `AsyncRead + AsyncWrite` that sets an atomic boolean flag on every I/O operation.
struct ActivityTracker<S> {
    inner: S,
    had_activity: Arc<AtomicBool>,
}

impl<S> ActivityTracker<S> {
    fn new(inner: S, had_activity: Arc<AtomicBool>) -> Self {
        Self {
            inner,
            had_activity,
        }
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

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Bidirectionally forwards traffic between two async streams with an optional idle timeout.
///
/// Unlike a hard lifetime timeout, this watchdog only triggers if NO data is transferred
/// in either direction for the specified `idle_timeout` duration.
pub async fn copy_bidirectional_with_idle_timeout<A, B>(
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
            let max_idle_ticks = std::cmp::max(1, timeout.as_secs() / tick_interval_secs);
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

/// Handles a single Data Plane client connection: reads the initial `ClientHello`,
/// extracts the target SNI, opens a Yamux stream on the matching tunnel, optionally
/// writes the PROXY Protocol v2 header, and forwards bidirectional traffic.
#[tracing::instrument(
    name = "data_connection",
    skip(
        client_stream,
        local_addr,
        tunnels,
        idle_timeout,
        client_hello_timeout
    ),
    fields(client_ip = %client_addr)
)]
pub async fn handle_data_connection<S>(
    mut client_stream: S,
    client_addr: SocketAddr,
    local_addr: SocketAddr,
    tunnels: SessionMap,
    idle_timeout: Option<Duration>,
    client_hello_timeout: Duration,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
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

            let is_ascii = preview
                .iter()
                .all(|&b| b.is_ascii_graphic() || b.is_ascii_whitespace());
            let preview_str = if is_ascii {
                String::from_utf8_lossy(preview)
                    .replace('\r', "\\r")
                    .replace('\n', "\\n")
            } else {
                preview
                    .iter()
                    .map(|b| format!("{:02X}", b))
                    .collect::<Vec<_>>()
                    .join(" ")
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
        Some(entry) => (
            entry.value().control.clone(),
            entry.value().supports_proxy_v2,
        ),
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
}

/// Runs the Data Plane accept loop on a pre-bound [`TcpListener`], accepting public TCP
/// connections and routing them via SNI until `cancel_token` is triggered.
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip(listener, tunnels, connection_tracker, cancel_token), err)]
pub async fn run_data_plane(
    listener: TcpListener,
    tunnels: SessionMap,
    rate: f32,
    burst: f32,
    idle_timeout: Option<Duration>,
    tcp_keepalive: Option<Duration>,
    connection_tracker: Arc<RelayConnectionTracker>,
    client_hello_timeout: Duration,
    cancel_token: CancellationToken,
) -> Result<(), RelayError> {
    if let Ok(local_addr) = listener.local_addr() {
        info!("Data plane listening on {} (SNI-Routing)", local_addr);
    }

    let rate_limits: Arc<DashMap<IpAddr, TokenBucket>> = Arc::new(DashMap::new());

    // Spawn a cleanup task to prevent DashMap from growing indefinitely
    let cleanup_limits = rate_limits.clone();
    let cleanup_token = cancel_token.clone();
    let cleanup_handle = tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            tokio::select! {
                _ = cleanup_token.cancelled() => break,
                _ = interval.tick() => {
                    // Remove buckets that haven't been used in 2 minutes
                    cleanup_limits.retain(|_, bucket| bucket.last_update().elapsed() < Duration::from_secs(120));
                }
            }
        }
    });

    let mut conn_tasks: JoinSet<()> = JoinSet::new();

    loop {
        let (client_stream, client_addr) = tokio::select! {
            _ = cancel_token.cancelled() => {
                info!("Data plane shutting down gracefully");
                break;
            }
            Some(res) = conn_tasks.join_next(), if !conn_tasks.is_empty() => {
                log_relay_task_result("data connection", res);
                continue;
            }
            accept_res = listener.accept() => {
                match accept_res {
                    Ok(s) => s,
                    Err(e) => {
                        warn!("Data plane accept error: {}", e);
                        tokio::select! {
                            _ = cancel_token.cancelled() => break,
                            _ = tokio::time::sleep(ACCEPT_ERROR_BACKOFF) => {}
                        }
                        continue;
                    }
                }
            }
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
        let mut bucket = rate_limits
            .entry(canonical_ip)
            .or_insert_with(|| TokenBucket::new(burst));
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

        let local_addr = client_stream.local_addr().unwrap_or(client_addr);
        let tunnels = tunnels.clone();
        conn_tasks.spawn(async move {
            let _guard = connection_guard;
            handle_data_connection(
                client_stream,
                client_addr,
                local_addr,
                tunnels,
                idle_timeout,
                client_hello_timeout,
            )
            .await;
        });
    }

    drop(listener);
    let _ = cleanup_handle.await;
    drain_relay_tasks(&mut conn_tasks, "data connection", RELAY_DRAIN_TIMEOUT).await;
    Ok(())
}

/// Best-effort extraction of the SNI domain name from a raw TLS `ClientHello` packet.
///
/// Relies on `tls_parser` to interpret the raw bytes without completing a handshake.
pub fn extract_sni(buf: &[u8]) -> Result<String, &'static str> {
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
/// Prevents path traversal or code injection if the SNI is logged or used in a `DashMap`.
pub fn is_valid_sni(sni: &str) -> bool {
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
        let certs: Vec<CertificateDer> =
            CertificateDer::pem_file_iter("../server_certs/self_signed/praeco_client.pem")
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
        let _ = rustls::crypto::ring::default_provider().install_default();
        // 1. Setup Acceptor
        let acceptor = setup_mtls_acceptor(
            "../server_certs/self_signed/relay_ca.pem",
            "../server_certs/self_signed/relay_server.pem",
            "../server_certs/self_signed/relay_server.key",
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
        for cert in
            CertificateDer::pem_file_iter("../server_certs/self_signed/relay_ca.pem").unwrap()
        {
            root_store.add(cert.unwrap()).unwrap();
        }
        let certs: Vec<CertificateDer> =
            CertificateDer::pem_file_iter("../server_certs/self_signed/praeco_client.pem")
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        let key =
            PrivateKeyDer::from_pem_file("../server_certs/self_signed/praeco_client.key").unwrap();

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

        // Test scaling calculation for Yamux config
        let max_streams = config.max_yamux_streams.unwrap_or(4096);
        let mut yamux_cfg = YamuxConfig::default();
        let min_window = max_streams * 256 * 1024;
        yamux_cfg
            .set_max_connection_receive_window(Some(std::cmp::max(min_window, 1024 * 1024 * 1024)));
        yamux_cfg.set_max_num_streams(max_streams);
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
        // Garbage bytes return empty list
        assert!(extract_allowed_snis(b"not-a-der-cert").is_empty());

        // CA cert without DNS SAN extensions returns empty list
        let ca_certs: Vec<CertificateDer> =
            CertificateDer::pem_file_iter("../server_certs/self_signed/relay_ca.pem")
                .unwrap()
                .collect::<Result<Vec<_>, _>>()
                .unwrap();
        assert!(extract_allowed_snis(ca_certs.first().unwrap()).is_empty());
    }

    #[test]
    fn test_setup_mtls_acceptor_errors_and_crl_loading() {
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Missing CA file
        assert!(matches!(
            setup_mtls_acceptor(
                "nonexistent_ca.pem",
                "../server_certs/self_signed/relay_server.pem",
                "../server_certs/self_signed/relay_server.key",
                None,
            ),
            Err(RelayError::Pem(_) | RelayError::Io(_))
        ));

        // Missing CRL file
        let missing_crl = "nonexistent_crl.pem".to_string();
        assert!(matches!(
            setup_mtls_acceptor(
                "../server_certs/self_signed/relay_ca.pem",
                "../server_certs/self_signed/relay_server.pem",
                "../server_certs/self_signed/relay_server.key",
                Some(&missing_crl),
            ),
            Err(RelayError::Pem(_) | RelayError::Io(_))
        ));

        // Valid certs + CRL file (exercises CRL parsing & expiration warning check)
        let crl_path = "../client_certs/crl_experiments/test1_crl/ca.crl.pem".to_string();
        assert!(
            setup_mtls_acceptor(
                "../server_certs/self_signed/relay_ca.pem",
                "../server_certs/self_signed/relay_server.pem",
                "../server_certs/self_signed/relay_server.key",
                Some(&crl_path),
            )
            .is_ok()
        );
    }

    fn build_client_hello_bytes(server_name: rustls::pki_types::ServerName<'static>) -> Vec<u8> {
        let _ = rustls::crypto::ring::default_provider().install_default();
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
}
