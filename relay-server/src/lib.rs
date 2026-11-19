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
mod limits;
mod protocol;
mod tls;

pub use limits::{RelayConnectionGuard, RelayConnectionTracker, TokenBucket, canonicalize_ip};
pub use protocol::{
    CopyResult, copy_bidirectional_with_idle_timeout, extract_sni, is_valid_sni,
    parse_register_command, read_client_hello_record, sanitize_log_str,
};
pub use tls::{
    ControlPlaneReloadState, extract_allowed_snis, extract_cert_expiry_and_serial,
    parse_revoked_serials_from_crl_pem, setup_mtls_acceptor, spawn_crl_reload_watcher,
};

use limits::{MAX_RATE_LIMIT_ENTRIES, RateLimitTable};
use tls::{cert_sha256_fingerprint, current_unix_timestamp};

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
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

/// Default timeout for opening a Yamux tunnel stream and writing initial
/// PROXY-Protocol v2 / ClientHello bytes.
pub const DEFAULT_TUNNEL_STREAM_OPEN_TIMEOUT: Duration = Duration::from_secs(5);

/// Default maximum concurrent connections on the Control Plane (Port `7001`).
pub const DEFAULT_CONTROL_MAX_CONNECTIONS: usize = 256;

/// Default maximum concurrent connections per IP (/64) on the Control Plane (Port `7001`).
pub const DEFAULT_CONTROL_MAX_CONNECTIONS_PER_IP: usize = 16;

const MIN_YAMUX_CONNECTION_WINDOW: usize = 4 * 1024 * 1024;

pub(crate) fn build_yamux_config(max_streams: usize) -> YamuxConfig {
    let streams = max_streams.max(1);
    let mut cfg = YamuxConfig::default();
    // Temporarily lift the default 1 GiB ceiling before adjusting max_num_streams so
    // arbitrary stream counts never trip yamux's cross-field assertion, then pin the
    // connection receive window to the tightest valid bound (max(4 MiB, 256 KiB * streams)).
    cfg.set_max_connection_receive_window(None);
    cfg.set_max_num_streams(streams);
    let bounded_window = streams
        .saturating_mul(256 * 1024)
        .max(MIN_YAMUX_CONNECTION_WINDOW);
    cfg.set_max_connection_receive_window(Some(bounded_window));
    cfg
}

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

/// Represents a control handle to an active Yamux multiplexed connection.
/// Used to request new outbound streams from the Relay to the Praeco backend.
#[derive(Clone)]
pub struct Control {
    tx: mpsc::Sender<oneshot::Sender<Result<YamuxStream, yamux::ConnectionError>>>,
    cert_fingerprint: Option<[u8; 32]>,
    probe_tx: Option<mpsc::Sender<oneshot::Sender<bool>>>,
    takeover_token: Option<CancellationToken>,
}

impl Control {
    /// Creates a new [`Control`] handle wrapping the given bounded channel sender.
    pub fn new(
        tx: mpsc::Sender<oneshot::Sender<Result<YamuxStream, yamux::ConnectionError>>>,
    ) -> Self {
        Self {
            tx,
            cert_fingerprint: None,
            probe_tx: None,
            takeover_token: None,
        }
    }

    fn with_identity(
        tx: mpsc::Sender<oneshot::Sender<Result<YamuxStream, yamux::ConnectionError>>>,
        cert_fingerprint: Option<[u8; 32]>,
        probe_tx: mpsc::Sender<oneshot::Sender<bool>>,
        takeover_token: CancellationToken,
    ) -> Self {
        Self {
            tx,
            cert_fingerprint,
            probe_tx: Some(probe_tx),
            takeover_token: Some(takeover_token),
        }
    }

    /// Probes whether the existing tunnel driver is still alive when a reconnect
    /// with the same client certificate arrives.
    async fn probe_liveness(&self) -> bool {
        if self.is_closed() {
            return false;
        }
        let Some(ref probe_tx) = self.probe_tx else {
            return true;
        };
        let (ack_tx, ack_rx) = oneshot::channel();
        if probe_tx.send(ack_tx).await.is_err() {
            return false;
        }
        tokio::time::timeout(Duration::from_millis(250), ack_rx)
            .await
            .ok()
            .and_then(|res| res.ok())
            .unwrap_or(false)
    }

    fn trigger_takeover(&self) {
        if let Some(ref token) = self.takeover_token {
            token.cancel();
        }
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

/// Pre-handshake connection limits and live CRL reload state for [`run_control_plane_with_options`].
#[derive(Clone)]
pub struct ControlPlaneOptions {
    /// Enforces global and per-IP connection limits before starting the mTLS handshake.
    pub connection_tracker: Arc<RelayConnectionTracker>,
    /// Optional watch receiver delivering reloaded [`TlsAcceptor`] and CRL serial sets.
    pub reload_rx: Option<tokio::sync::watch::Receiver<ControlPlaneReloadState>>,
}

impl Default for ControlPlaneOptions {
    fn default() -> Self {
        Self {
            connection_tracker: Arc::new(RelayConnectionTracker::new(
                DEFAULT_CONTROL_MAX_CONNECTIONS,
                DEFAULT_CONTROL_MAX_CONNECTIONS_PER_IP,
            )),
            reload_rx: None,
        }
    }
}

/// Atomically registers `route` for `sni` using `DashMap::entry()` so concurrent
/// `REGISTER` attempts for the same SNI cannot race past overwrite protection.
#[cfg(test)]
fn try_register_tunnel(tunnels: &SessionMap, sni: String, route: TunnelRoute) -> bool {
    match tunnels.entry(sni) {
        dashmap::mapref::entry::Entry::Occupied(mut occupied) => {
            if !occupied.get().control.is_closed() {
                false
            } else {
                occupied.insert(route);
                true
            }
        }
        dashmap::mapref::entry::Entry::Vacant(vacant) => {
            vacant.insert(route);
            true
        }
    }
}

/// Async variant of [`try_register_tunnel`] that probes unresponsive peers holding an
/// identical client certificate fingerprint (`cert_fingerprint`) and allows safe takeover
/// when the existing peer is dead, while rejecting hijack attempts from different certs
/// or live tunnels. Never holds a `DashMap` shard lock across `.await`.
async fn try_register_tunnel_with_takeover(
    tunnels: &SessionMap,
    sni: String,
    route: TunnelRoute,
) -> bool {
    let probe_candidate = {
        match tunnels.entry(sni.clone()) {
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                vacant.insert(route);
                return true;
            }
            dashmap::mapref::entry::Entry::Occupied(mut occupied) => {
                if occupied.get().control.is_closed() {
                    occupied.insert(route);
                    return true;
                }
                let same_cert = route.control.cert_fingerprint.is_some()
                    && route.control.cert_fingerprint == occupied.get().control.cert_fingerprint;
                if same_cert {
                    Some((occupied.get().generation, occupied.get().control.clone()))
                } else {
                    return false;
                }
            }
        }
    };

    if let Some((stale_gen, stale_control)) = probe_candidate
        && !stale_control.probe_liveness().await
        && let dashmap::mapref::entry::Entry::Occupied(mut occupied) = tunnels.entry(sni)
        && occupied.get().generation == stale_gen
    {
        occupied.insert(route);
        stale_control.trigger_takeover();
        return true;
    }

    false
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
    handle_control_connection_with_reload(
        stream,
        client_addr,
        acceptor,
        tunnels,
        handshake_timeout,
        max_yamux_streams,
        enable_proxy_protocol,
        cancel_token,
        None,
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
        cancel_token,
        reload_rx
    ),
    fields(client_ip = %client_addr)
)]
async fn handle_control_connection_with_reload<S>(
    stream: S,
    client_addr: SocketAddr,
    acceptor: TlsAcceptor,
    tunnels: SessionMap,
    handshake_timeout: Duration,
    max_yamux_streams: usize,
    enable_proxy_protocol: bool,
    cancel_token: CancellationToken,
    mut reload_rx: Option<tokio::sync::watch::Receiver<ControlPlaneReloadState>>,
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

    // --- Extract Client Certificate SANs, Validity (notAfter), and Serial (P0.2 & R-05) ---
    let leaf_cert = tls_stream
        .get_ref()
        .1
        .peer_certificates()
        .and_then(|certs| certs.first());

    let allowed_snis = leaf_cert
        .map(|cert_der| extract_allowed_snis(cert_der))
        .unwrap_or_default();

    let Some((cert_not_after_ts, cert_serial)) =
        leaf_cert.and_then(|cert_der| extract_cert_expiry_and_serial(cert_der))
    else {
        warn!(target: "relay::control_plane", client_ip = %client_addr, "Failed to parse client certificate validity/serial");
        return;
    };
    let cert_fingerprint = leaf_cert.and_then(|cert_der| cert_sha256_fingerprint(cert_der.as_ref()));

    let now_ts = current_unix_timestamp();
    if cert_not_after_ts <= now_ts {
        warn!(
            target: "relay::control_plane",
            client_ip = %client_addr,
            not_after = cert_not_after_ts,
            "Rejecting control connection: client certificate has expired"
        );
        return;
    }

    if let Some(ref rx) = reload_rx
        && rx.borrow().revoked_serials.contains(&cert_serial)
    {
        warn!(
            target: "relay::control_plane",
            client_ip = %client_addr,
            "Rejecting control connection: client certificate serial is revoked by latest CRL"
        );
        return;
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
        let safe_sni = sanitize_log_str(&sni);
        warn!(target: "relay::control_plane", client_ip = %client_addr, requested_sni = %safe_sni, "Invalid SNI hostname in REGISTER command");
        return;
    }

    // --- Verify SNI against Certificate SANs (P0.2) ---
    if !allowed_snis
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(&sni))
    {
        let safe_sni = sanitize_log_str(&sni);
        warn!(target: "relay::control_plane", client_ip = %client_addr, requested_sni = %safe_sni, "SNI not authorized by client certificate");
        return;
    }

    let (tx, mut rx) = mpsc::channel(32);
    let (probe_tx, mut probe_rx) = mpsc::channel::<oneshot::Sender<bool>>(4);
    let takeover_token = CancellationToken::new();
    let control = Control::with_identity(tx, cert_fingerprint, probe_tx, takeover_token.clone());

    // --- Store with Generation ID (P0.5) & Atomic Overwrite Protection (P0.3 / S-27) ---
    static GENERATION: AtomicU64 = AtomicU64::new(1);
    let my_generation = GENERATION.fetch_add(1, Ordering::SeqCst);

    let route = TunnelRoute {
        control: control.clone(),
        generation: my_generation,
        supports_proxy_v2,
    };
    if !try_register_tunnel_with_takeover(&tunnels, sni.clone(), route).await {
        warn!(
            target: "relay::control_plane",
            sni = %sanitize_log_str(&sni),
            client_ip = %client_addr,
            "Registration rejected: active healthy tunnel already registered for this SNI"
        );
        return;
    }

    info!(target: "relay::control_plane", sni = %sanitize_log_str(&sni), proxy_v2 = supports_proxy_v2, "Praeco tunnel registered");

    let cfg = build_yamux_config(max_yamux_streams);
    let mut connection = Connection::new(tls_stream.compat(), cfg, Mode::Server);

    let mut pending_outbound: Option<
        oneshot::Sender<Result<yamux::Stream, yamux::ConnectionError>>,
    > = None;

    let remaining_lifetime_secs = (cert_not_after_ts - current_unix_timestamp()).max(0) as u64;
    let expiry_wait = Duration::from_secs(remaining_lifetime_secs.min(30 * 24 * 3600));
    let expiry_timer = tokio::time::sleep(expiry_wait);
    tokio::pin!(expiry_timer);

    loop {
        tokio::select! {
            () = std::future::poll_fn(|cx| {
                // Loop steps 1 & 2 so after every completed outbound stream we re-poll
                // `rx` until it returns `Poll::Pending` (preventing lost wakeups).
                loop {
                    while pending_outbound.is_none() {
                        match rx.poll_recv(cx) {
                            std::task::Poll::Ready(Some(resp_tx)) => {
                                pending_outbound = Some(resp_tx);
                            }
                            std::task::Poll::Ready(None) => return std::task::Poll::Ready(()),
                            std::task::Poll::Pending => break,
                        }
                    }

                    if pending_outbound.is_some()
                        && let std::task::Poll::Ready(stream_res) = connection.poll_new_outbound(cx)
                        && let Some(resp_tx) = pending_outbound.take()
                    {
                        let _ = resp_tx.send(stream_res);
                        continue;
                    }
                    break;
                }

                // 3. Drive inbound streams and connection progress continuously until Pending
                loop {
                    match connection.poll_next_inbound(cx) {
                        std::task::Poll::Ready(Some(Ok(unexpected_stream))) => {
                            warn!(target: "relay::control_plane", sni = %sanitize_log_str(&sni), "Unexpected inbound stream from client");
                            drop(unexpected_stream);
                        }
                        std::task::Poll::Ready(Some(Err(e))) => {
                            warn!(target: "relay::control_plane", sni = %sanitize_log_str(&sni), error = ?e, "Tunnel connection failed");
                            return std::task::Poll::Ready(());
                        }
                        std::task::Poll::Ready(None) => {
                            info!(target: "relay::control_plane", sni = %sanitize_log_str(&sni), "Tunnel closed cleanly");
                            return std::task::Poll::Ready(());
                        }
                        std::task::Poll::Pending => break,
                    }
                }

                std::task::Poll::Pending
            }) => break,
            Some(ack_tx) = probe_rx.recv() => {
                let mut noop_cx = std::task::Context::from_waker(std::task::Waker::noop());
                match connection.poll_next_inbound(&mut noop_cx) {
                    std::task::Poll::Ready(Some(Err(_))) | std::task::Poll::Ready(None) => {
                        let _ = ack_tx.send(false);
                        break;
                    }
                    std::task::Poll::Ready(Some(Ok(unexpected))) => {
                        drop(unexpected);
                        let _ = ack_tx.send(true);
                    }
                    std::task::Poll::Pending => {
                        let _ = ack_tx.send(true);
                    }
                }
            }
            () = takeover_token.cancelled() => {
                info!(target: "relay::control_plane", sni = %sanitize_log_str(&sni), "Closing stale tunnel after same-certificate takeover");
                break;
            }
            () = &mut expiry_timer => {
                if current_unix_timestamp() >= cert_not_after_ts {
                    warn!(
                        target: "relay::control_plane",
                        sni = %sni,
                        not_after = cert_not_after_ts,
                        "Closing active tunnel: client certificate reached notAfter expiration"
                    );
                    let _ = tokio::time::timeout(
                        Duration::from_secs(1),
                        std::future::poll_fn(|cx| connection.poll_close(cx)),
                    )
                    .await;
                    break;
                }
                let next_rem = (cert_not_after_ts - current_unix_timestamp()).max(0) as u64;
                expiry_timer
                    .as_mut()
                    .reset(tokio::time::Instant::now() + Duration::from_secs(next_rem.min(30 * 24 * 3600)));
            }
            changed = async {
                match reload_rx.as_mut() {
                    Some(rx) => rx.changed().await,
                    None => std::future::pending().await,
                }
            } => {
                if changed.is_err() {
                    reload_rx = None;
                    continue;
                }
                let revoked = reload_rx
                    .as_mut()
                    .is_some_and(|rx| rx.borrow_and_update().revoked_serials.contains(&cert_serial));
                let expired = current_unix_timestamp() >= cert_not_after_ts;
                if revoked || expired {
                    warn!(
                        target: "relay::control_plane",
                        sni = %sni,
                        revoked,
                        expired,
                        "Closing active tunnel: client certificate revoked by updated CRL or expired"
                    );
                    let _ = tokio::time::timeout(
                        Duration::from_secs(1),
                        std::future::poll_fn(|cx| connection.poll_close(cx)),
                    )
                    .await;
                    break;
                }
            }
            () = cancel_token.cancelled() => {
                info!(target: "relay::control_plane", sni = %sni, "Closing control tunnel on shutdown");
                let _ = tokio::time::timeout(
                    Duration::from_secs(1),
                    std::future::poll_fn(|cx| connection.poll_close(cx)),
                )
                .await;
                break;
            }
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
    run_control_plane_with_options(
        listener,
        tls_acceptor,
        tunnels,
        handshake_timeout,
        max_yamux_streams,
        enable_proxy_protocol,
        cancel_token,
        ControlPlaneOptions::default(),
    )
    .await
}

/// Like [`run_control_plane`], but accepts explicit [`ControlPlaneOptions`] for pre-mTLS
/// connection limiting and live CRL reload notifications.
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip(listener, tls_acceptor, tunnels, cancel_token, options), err)]
pub async fn run_control_plane_with_options(
    listener: TcpListener,
    tls_acceptor: TlsAcceptor,
    tunnels: SessionMap,
    handshake_timeout: Duration,
    max_yamux_streams: usize,
    enable_proxy_protocol: bool,
    cancel_token: CancellationToken,
    options: ControlPlaneOptions,
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

        let conn_guard = match options.connection_tracker.acquire(client_addr.ip()) {
            Ok(guard) => guard,
            Err(reason) => {
                warn!(
                    target: "relay::control_plane",
                    client_ip = %client_addr,
                    reason = %reason,
                    "Control-plane connection rejected before mTLS handshake"
                );
                drop(stream);
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

        let acceptor = options
            .reload_rx
            .as_ref()
            .map(|rx| rx.borrow().acceptor.clone())
            .unwrap_or_else(|| tls_acceptor.clone());
        let tunnels = tunnels.clone();
        let conn_cancel = cancel_token.child_token();
        let reload_rx = options.reload_rx.clone();

        conn_tasks.spawn(async move {
            let _guard = conn_guard;
            handle_control_connection_with_reload(
                stream,
                client_addr,
                acceptor,
                tunnels,
                handshake_timeout,
                max_yamux_streams,
                enable_proxy_protocol,
                conn_cancel,
                reload_rx,
            )
            .await;
        });
    }

    drop(listener);
    drain_relay_tasks(&mut conn_tasks, "control connection", RELAY_DRAIN_TIMEOUT).await;
    Ok(())
}

/// Handles a single Data Plane client connection: reads the initial `ClientHello`,
/// extracts the target SNI, opens a Yamux stream on the matching tunnel, optionally
/// writes the PROXY Protocol v2 header, and forwards bidirectional traffic.
pub async fn handle_data_connection<S>(
    client_stream: S,
    client_addr: SocketAddr,
    local_addr: SocketAddr,
    tunnels: SessionMap,
    idle_timeout: Option<Duration>,
    client_hello_timeout: Duration,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    handle_data_connection_with_stream_timeout(
        client_stream,
        client_addr,
        local_addr,
        tunnels,
        idle_timeout,
        client_hello_timeout,
        DEFAULT_TUNNEL_STREAM_OPEN_TIMEOUT,
    )
    .await;
}

/// Like [`handle_data_connection`], with an explicit `stream_open_timeout` covering
/// opening the Yamux tunnel stream and writing the initial PROXY-Protocol v2 header
/// and TLS `ClientHello` bytes.
#[tracing::instrument(
    name = "data_connection",
    skip(
        client_stream,
        local_addr,
        tunnels,
        idle_timeout,
        client_hello_timeout,
        stream_open_timeout
    ),
    fields(client_ip = %client_addr)
)]
pub async fn handle_data_connection_with_stream_timeout<S>(
    mut client_stream: S,
    client_addr: SocketAddr,
    local_addr: SocketAddr,
    tunnels: SessionMap,
    idle_timeout: Option<Duration>,
    client_hello_timeout: Duration,
    stream_open_timeout: Duration,
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
        let safe_sni = sanitize_log_str(&sni);
        warn!(target: "relay::data_plane", client_ip = %client_addr, sni = %safe_sni, "Invalid or empty SNI");
        return;
    }

    let safe_sni = sanitize_log_str(&sni);
    let (mut control, supports_proxy_v2) = match tunnels.get(&sni) {
        Some(entry) => (
            entry.value().control.clone(),
            entry.value().supports_proxy_v2,
        ),
        None => {
            warn!(target: "relay::data_plane", sni = %safe_sni, client_ip = %client_addr, "No active tunnel for SNI");
            return;
        }
    };

    let tunnel_stream = match tokio::time::timeout(stream_open_timeout, control.open_stream()).await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            warn!(target: "relay::data_plane", sni = %sni, error = %e, "Failed to open stream in tunnel");
            return;
        }
        Err(_) => {
            warn!(
                target: "relay::data_plane",
                sni = %sni,
                timeout_ms = stream_open_timeout.as_millis() as u64,
                "Timed out opening stream in tunnel"
            );
            return;
        }
    };

    let mut tokio_tunnel = tunnel_stream.compat_write();

    if supports_proxy_v2 {
        let ppv2_header = common::proxy_protocol::encode_proxy_v2(client_addr, local_addr);
        match tokio::time::timeout(stream_open_timeout, tokio_tunnel.write_all(&ppv2_header)).await
        {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                warn!(target: "relay::data_plane", sni = %sni, error = %e, "Failed to write PROXY-Protocol v2 header to tunnel");
                return;
            }
            Err(_) => {
                warn!(target: "relay::data_plane", sni = %sni, "Timed out writing PROXY-Protocol v2 header to tunnel");
                return;
            }
        }
    }

    match tokio::time::timeout(stream_open_timeout, tokio_tunnel.write_all(&buf)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            warn!(target: "relay::data_plane", sni = %sni, error = %e, "Failed to write ClientHello to tunnel");
            return;
        }
        Err(_) => {
            warn!(target: "relay::data_plane", sni = %sni, "Timed out writing ClientHello to tunnel");
            return;
        }
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
    run_data_plane_with_stream_timeout(
        listener,
        tunnels,
        rate,
        burst,
        idle_timeout,
        tcp_keepalive,
        connection_tracker,
        client_hello_timeout,
        DEFAULT_TUNNEL_STREAM_OPEN_TIMEOUT,
        cancel_token,
    )
    .await
}

/// Like [`run_data_plane`], with an explicit `stream_open_timeout` for opening
/// Yamux tunnel streams and writing initial PROXY-Protocol v2 / ClientHello bytes.
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip(listener, tunnels, connection_tracker, cancel_token), err)]
pub async fn run_data_plane_with_stream_timeout(
    listener: TcpListener,
    tunnels: SessionMap,
    rate: f32,
    burst: f32,
    idle_timeout: Option<Duration>,
    tcp_keepalive: Option<Duration>,
    connection_tracker: Arc<RelayConnectionTracker>,
    client_hello_timeout: Duration,
    stream_open_timeout: Duration,
    cancel_token: CancellationToken,
) -> Result<(), RelayError> {
    if let Ok(local_addr) = listener.local_addr() {
        info!("Data plane listening on {} (SNI-Routing)", local_addr);
    }

    let rate_limits = Arc::new(RateLimitTable::with_capacity(MAX_RATE_LIMIT_ENTRIES));

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
                    cleanup_limits.sweep_expired(Duration::from_secs(120));
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

        // --- Rate Limiting Check (Aggregated IPv6 on /64, bounded with LRU eviction) ---
        let canonical_ip = canonicalize_ip(client_addr.ip());
        if !rate_limits.check_and_consume(canonical_ip, rate, burst) {
            warn!(target: "relay::data_plane", client_ip = %client_addr, "Rate limit exceeded, dropping connection");
            continue; // Drop instantly
        }

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
            handle_data_connection_with_stream_timeout(
                client_stream,
                client_addr,
                local_addr,
                tunnels,
                idle_timeout,
                client_hello_timeout,
                stream_open_timeout,
            )
            .await;
        });
    }

    drop(listener);
    let _ = cleanup_handle.await;
    drain_relay_tasks(&mut conn_tasks, "data connection", RELAY_DRAIN_TIMEOUT).await;
    Ok(())
}


#[cfg(test)]
mod tests;
