//! # mTLS Stress-Test Client
//!
//! A command-line HTTP(S) client designed for **load and throughput testing**
//! against the server. It fires `N` total requests with a configurable
//! concurrency window, using [`FuturesUnordered`] to keep up to `M` requests
//! in flight simultaneously.
//!
//! ## Architecture Overview
//!
//! The client supports two fundamentally different network paths:
//!
//! - **HTTP/2 path** (`-v h2`, default): Uses `hyper::Client` with TCP + TLS.
//!   The `hyper` connection pool manages TCP connections and multiplexes
//!   HTTP/2 streams over them.
//!
//! - **HTTP/3 path** (`-v h3`): Uses `quinn` (QUIC transport) + `h3` (HTTP/3
//!   protocol layer). Opens a **single** QUIC connection and multiplexes all
//!   requests as independent QUIC streams — no head-of-line blocking, typically
//!   ~5× faster than HTTP/2 on local networks.
//!
//! ## Supported Authentication Modes
//!
//! | Flag | Mode | Notes |
//! |------|------|-------|
//! | `-s http` | Plain HTTP | No TLS |
//! | `-s https` | HTTPS | Server-only TLS |
//! | `-s jwt` | JWT bearer | Requires `-j <token file>` |
//! | `-s mtls` | Mutual TLS | Requires `-c <cert>` and `-k <key>` |
//!
//! ## HTTP Version
//!
//! | Flag | Protocol | Transport |
//! |------|----------|----------|
//! | `-v h2` | HTTP/2 (default) | TCP + TLS |
//! | `-v h3` | HTTP/3 | QUIC (UDP) |
//!
//! ## macOS Tuning
//!
//! For high-concurrency tests (> 10 000 requests), raise the file-descriptor
//! limits **before** running the client:
//!
//! ```bash
//! sudo sysctl -w kern.maxfiles=65536
//! sudo sysctl -w kern.maxfilesperproc=65536
//! ulimit -n 65536
//! ```
//!
//! ## Example
//!
//! ```bash
//! # HTTP/2 (default)
//! RUST_LOG=client=trace cargo run -p client --bin=client --release -- \
//!   --ca ./server_certs/self_signed/myca.pem \
//!   -c ./client_certs/test1_crl/client1.cert.pem \
//!   -k ./client_certs/test1_crl/client1.key.pem \
//!   -s mtls -i 65000 -p /
//!
//! # HTTP/3
//! RUST_LOG=client=trace cargo run -p client --bin=client --release -- \
//!   --ca ./server_certs/self_signed/myca.pem \
//!   -c ./client_certs/test1_crl/client1.cert.pem \
//!   -k ./client_certs/test1_crl/client1.key.pem \
//!   -s mtls -v h3 -i 65000 -p /
//! ```

// === Standard Library ===
use std::error::Error as StdError;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::Instant;

// === External Crates ===
use anyhow::{Context, Error};
use bytes::Bytes;
use clap::{Parser, ValueEnum};
use futures::{StreamExt, stream::FuturesUnordered};
use http_body_util::{BodyExt, Full};
use hyper::{Request, http::uri::Uri};
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use tracing::{error, trace};

// === Internal Modules ===

// =============================================================================
// Entrypoint
// =============================================================================

/// Program entrypoint.
///
/// 1. Initialises the `tracing` logging subscriber.
/// 2. Installs the `ring` cryptography provider for `rustls`
///    (required by both TLS and QUIC).
/// 3. Parses and validates command-line arguments.
/// 4. Dispatches to the HTTP/2 or HTTP/3 stress-test path based on
///    the `--http-version` flag.
#[tokio::main]
async fn main() -> Result<(), Error> {
    //console_subscriber::init();
    tracing_subscriber::fmt::init();

    // Install the `ring` crypto provider as the process-wide default.
    // This is required by both `rustls` (TCP+TLS path) and `quinn` (QUIC path).
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    let cli = Cli::parse();
    // Validate that required flags are present for the chosen protocol
    validate_cli(&cli);

    // Dispatch to the appropriate transport layer
    match cli.http_version {
        HttpVersion::H2 => run_h2(&cli).await,
        HttpVersion::H3 => run_h3(&cli).await,
    }
}

// =============================================================================
// HTTP/2 (TCP + TLS) Path
// =============================================================================

/// Runs the **HTTP/2** stress-test using TCP + TLS transport.
///
/// This is the original client behaviour. It uses `hyper::Client` which
/// internally manages a connection pool — multiple TCP connections may be
/// opened and HTTP/2 streams are multiplexed over them.
///
/// ## Concurrency Model
///
/// Uses a bounded "sliding window" of in-flight requests (via [`run_sliding_window`]):
///
/// 1. **Seed** — push `min(concurrency, total)` futures to start.
/// 2. **Slide** — whenever one future completes, push a new one (if any
///    remain), keeping the window full.
/// 3. **Drain** — once all requests have been launched, just drain remaining
///    completions.
///
/// This avoids spawning all futures at once (which would overwhelm the
/// connection pool) while maintaining maximum throughput.
async fn run_h2(cli: &Cli) -> Result<(), Error> {
    // Load JWT token from file (only used when `-s jwt`)
    let jwt_token = read_jwt(cli);

    // Construct the hyper HTTP client (with TLS connector) and target URI
    let client = build_h2_client(cli);
    let uri = build_uri(cli);

    let concurrency = cli.num_parallel as usize;
    let total_requests = cli.num_req as usize;

    // --- Sliding-window request loop ---
    run_sliding_window(total_requests, concurrency, "Request failed", || {
        let uri = uri.clone();
        let client_clone = client.clone();
        let jwt_token_clone = jwt_token.as_deref().map(|s| s.to_string());
        async move { do_request_h2(&client_clone, cli, jwt_token_clone.as_deref(), uri).await }
    })
    .await;

    Ok(())
}

// =============================================================================
// CLI Definitions
// =============================================================================

/// Command-line arguments for configuring the client.
///
/// All fields map directly to CLI flags. Defaults are chosen so that a
/// minimal invocation (`cargo run -p client`) performs 10 HTTPS GET requests
/// against the default server address.
#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Cli {
    /// Total number of requests to send.
    #[clap(short = 'i', long, default_value_t = 10)]
    num_req: u32,

    /// Maximum number of requests in flight at the same time.
    /// Higher values increase throughput but also resource usage.
    #[clap(long, default_value_t = 128)]
    num_parallel: u16,

    /// Authentication / security mode (determines TLS and auth setup).
    #[clap(short = 's', long, value_enum, default_value_t = Protocol::Https)]
    security: Protocol,

    /// HTTP version to use: `h2` (TCP + TLS, default) or `h3` (QUIC / UDP).
    #[clap(short = 'v', long = "http-version", value_enum, default_value_t = HttpVersion::H2)]
    http_version: HttpVersion,

    /// Path to the root CA certificate (PEM). Used to verify the server's
    /// identity. If omitted, only the system-wide WebPKI roots are trusted.
    #[clap(short = 'r', long, value_name = "Root ca")]
    ca: Option<String>,

    /// Path to a file containing a JWT token (for `-s jwt` mode).
    #[clap(long, short = 'j', value_name = "jwt file")]
    jwt: Option<String>,

    /// Path to the client certificate (PEM) for mTLS authentication.
    #[clap(short = 'c', long, value_name = "client cert")]
    cert: Option<String>,

    /// Path to the client private key (PEM) for mTLS authentication.
    #[clap(short = 'k', long, value_name = "client-key")]
    key: Option<String>,

    /// HTTP request method (GET, POST, PUT, DELETE, …).
    #[clap(
        short = 'm',
        long,
        default_value = "GET",
        value_name = "request method"
    )]
    method: String,

    /// Server address in `host:port` format (e.g. `192.168.178.31:1337`).
    #[clap(short = 'u', long, default_value = "192.168.178.31:1337")]
    uri: String,

    /// Request path appended to the URI (e.g. `/`, `/api/health`).
    #[clap(long, short = 'p', default_value = "/", value_name = "request path")]
    path: String,
}

/// Selects the HTTP protocol version (and underlying transport).
#[derive(Debug, Clone, ValueEnum, PartialEq)]
enum HttpVersion {
    /// HTTP/2 over TCP + TLS (traditional, connection-pooled)
    H2,
    /// HTTP/3 over QUIC (UDP, single-connection multiplexing)
    H3,
}

/// Authentication / security protocols supported by the client.
///
/// Each variant implies a different TLS and credential configuration:
///
/// - `Http`  — no TLS at all.
/// - `Https` — TLS with server verification only.
/// - `Jwt`   — TLS + an `Authorization: Bearer <token>` header.
/// - `Mtls`  — TLS with **mutual** certificate authentication.
#[derive(Debug, Clone, ValueEnum, PartialEq)]
enum Protocol {
    Http,
    Https,
    Jwt,
    Mtls,
}

// =============================================================================
// CLI Validation
// =============================================================================

/// Validates that all required CLI arguments are present for the chosen
/// [`Protocol`].
///
/// | Protocol | Required flags |
/// |----------|---------------|
/// | `Http` | *(none)* |
/// | `Https` | `--ca` (currently soft-warn) |
/// | `Jwt` | `--ca` (soft), `--jwt` |
/// | `Mtls` | `--ca` (soft), `--cert`, `--key` |
///
/// Missing **hard** requirements cause an immediate `exit(1)`.
fn validate_cli(cli: &Cli) {
    match cli.security {
        Protocol::Https => {
            if cli.ca.is_none() {
                // Soft warning — the system WebPKI roots may suffice for
                // public servers, so we do not hard-fail here.
                // error!("--ca <Root ca> must be set for HTTPS");
                // std::process::exit(1);
            }
        }
        Protocol::Jwt => {
            if cli.ca.is_none() {
                // error!("--ca <Root ca> must be set for JWT");
                // std::process::exit(1);
            }
            if cli.jwt.is_none() {
                error!("--jwt <jwt file> must be set for JWT");
                std::process::exit(1);
            }
        }
        Protocol::Mtls => {
            if cli.ca.is_none() {
                // error!("--ca <Root ca> must be set for mTLS");
                // std::process::exit(1);
            }
            // mTLS requires both the client certificate and its private key
            if cli.cert.is_none() || cli.key.is_none() {
                error!("--cert <client cert> and --key <client-key> must be set for mTLS");
                std::process::exit(1);
            }
        }
        Protocol::Http => {} // No TLS, nothing to validate
    }
}

// =============================================================================
// HTTP/2 Client Construction
// =============================================================================

/// Builds a `hyper::Client` with the appropriate TLS connector for the chosen
/// [`Protocol`].
///
/// The connector is created via `hyper-rustls`, which wraps a plain
/// [`HttpConnector`] with a TLS layer. Depending on the protocol:
///
/// - **Http**: TLS is configured but `https_or_http()` allows plain HTTP.
/// - **Https / Jwt**: Strict HTTPS, no client certificate.
/// - **Mtls**: Strict HTTPS **with** client certificate + key
///   (mutual TLS authentication).
///
/// HTTP/1.1 and HTTP/2 are both enabled so `hyper` can negotiate the
/// best version with the server via ALPN.
fn build_h2_client(
    cli: &Cli,
) -> Client<common::client::HttpsConnector<HttpConnector>, Full<Bytes>> {
    let root_store = common::build_root_store(&cli.ca);

    // Create the appropriate TLS config based on the security protocol.
    let tls_client_config = match cli.security {
        Protocol::Http | Protocol::Https | Protocol::Jwt => {
            common::build_tls_client_config(root_store, None, None)
        }
        Protocol::Mtls => {
            common::build_tls_client_config(root_store, cli.cert.as_deref(), cli.key.as_deref())
        }
    };

    // Configure the shared pool.
    let pool_config = common::client::ClientPoolConfig {
        idle_timeout: None,
        max_idle_per_host: Some(1024),
        http2_only: false,
    };

    common::client::build_hyper_client(tls_client_config, pool_config)
}

// =============================================================================
// Shared Helpers (used by both H2 and H3 paths)
// =============================================================================

/// Reads a JWT token from the file specified by `--jwt`, trimming whitespace.
///
/// Returns `None` if the current protocol is **not** `Jwt` (the token is
/// simply not needed).
///
/// # Panics
///
/// Panics if the file cannot be read (the path was already validated by
/// [`validate_cli`]).
fn read_jwt(cli: &Cli) -> Option<String> {
    if let Protocol::Jwt = cli.security {
        let path = cli.jwt.as_ref().unwrap();
        Some(
            std::fs::read_to_string(path)
                .expect("Failed to read JWT")
                .trim()
                .to_string(),
        )
    } else {
        None
    }
}

/// Constructs the full request URI from the CLI flags.
///
/// Combines `--security` (to pick `http://` or `https://`), `--uri`
/// (host:port), and `--path` into a single [`Uri`].
///
/// # Example
///
/// With `-s mtls -u 192.168.178.31:1337 -p /api/health`:
///
/// → `https://192.168.178.31:1337/api/health`
fn build_uri(cli: &Cli) -> Uri {
    let scheme = match cli.security {
        Protocol::Https | Protocol::Mtls | Protocol::Jwt => "https",
        Protocol::Http => "http",
    };
    let uri = format!("{}://{}{}", scheme, cli.uri, cli.path);
    let uri = uri.parse().expect("Invalid URI");
    trace!("Built URI: {}", uri);
    uri
}

// =============================================================================
// HTTP/2 Request Execution
// =============================================================================

/// Sends a **single HTTP/2** request through the `hyper::Client` and returns
/// the response body as a `String`.
///
/// # Request Construction
///
/// - Uses [`prepare_request_builder`] to configure the HTTP method, URI, and
///   authentication headers.
/// - Sends a static `"Hello, World!"` body (useful for POST/PUT tests).
///
/// # Error Handling
///
/// - Non-2xx status codes are converted into `Err(...)` with the response
///   body included for debugging.
/// - Network / TLS errors from `hyper` are propagated via `?`.
async fn do_request_h2(
    client: &Client<common::client::HttpsConnector<HttpConnector>, Full<Bytes>>,
    cli: &Cli,
    jwt_token: Option<&str>,
    uri: Uri,
) -> Result<String, Error> {
    // --- Build the HTTP request ---
    let body = match cli.method.to_uppercase().as_str() {
        "POST" | "PUT" | "PATCH" => Full::new(Bytes::from_static(b"Hello, World!")),
        _ => Full::new(Bytes::new()),
    };

    let request = prepare_request_builder(cli, jwt_token, &uri)
        .body(body)
        .expect("Failed to build request");

    // trace!("Request: {:#?}", request);

    // --- Send and await the response ---
    let response = match client.request(request).await {
        Ok(res) => res,
        Err(e) => {
            let mut err_msg = format!("client error: {}", e);
            let mut current_err: Option<&dyn StdError> = e.source();
            while let Some(source) = current_err {
                err_msg.push_str(&format!(" -> {}", source));
                current_err = source.source();
            }
            return Err(anyhow::anyhow!("Request failed: {}", err_msg));
        }
    };
    let status = response.status();

    // Treat non-2xx responses as errors (with body for diagnostics)
    if !status.is_success() {
        let (_parts, body) = response.into_parts();
        let body_bytes = body
            .collect()
            .await
            .context("Failed to read error response body")?
            .to_bytes();
        let body_str = String::from_utf8_lossy(&body_bytes);
        return Err(anyhow::anyhow!(
            "Request to {uri} failed with status {status}: {body_str}"
        ));
    }

    // --- Collect the successful response body ---
    let (_parts, body) = response.into_parts();
    let body_bytes = body
        .collect()
        .await
        .context("Failed to read response body")?
        .to_bytes();

    // Convert body bytes to a UTF-8 String (error if invalid encoding)
    let body_str =
        String::from_utf8(body_bytes.to_vec()).context("Response body was not valid UTF-8")?;
    trace!("Response body: {}", body_str);
    Ok(body_str)
}

// =============================================================================
// HTTP/3 (QUIC) Path
// =============================================================================

/// Runs the **HTTP/3** stress-test over a single QUIC connection.
///
/// Unlike the HTTP/2 path (which relies on `hyper`'s connection pool), the
/// HTTP/3 path opens **one** QUIC connection and multiplexes all request
/// streams over it. This is the native HTTP/3 model and avoids the overhead
/// of repeated TCP + TLS handshakes.
///
/// ## Setup Steps
///
/// 1. **TLS config** — Reuses `common::build_tls_client_config` with the
///    `h3` ALPN protocol (required by QUIC to advertise HTTP/3 support).
/// 2. **Quinn endpoint** — Creates a client-side QUIC endpoint bound to an
///    ephemeral UDP port (`0.0.0.0:0`).
/// 3. **QUIC connection** — Connects to the server using the resolved address
///    and SNI hostname extracted from `--uri`.
/// 4. **H3 layer** — Wraps the QUIC connection in `h3_quinn::Connection` and
///    creates an `h3::client::SendRequest` handle for issuing requests.
/// 5. **Connection driver** — The `h3` crate requires a background task that
///    continuously polls the connection state machine (`poll_close`).
///
/// ## Concurrency Model
///
/// Same sliding-window pattern as [`run_h2`] (via [`run_sliding_window`]), but each
/// future calls [`do_request_h3`] which clones the `SendRequest` handle
/// (cheap, reference-counted) and opens a new QUIC stream.
async fn run_h3(cli: &Cli) -> Result<(), Error> {
    // ---- Step 1: Build TLS config with "h3" ALPN ----
    let root_store = common::build_root_store(&cli.ca);
    let mut tls_config =
        common::build_tls_client_config(root_store, cli.cert.as_deref(), cli.key.as_deref());
    // QUIC mandates the "h3" ALPN to negotiate HTTP/3 during the handshake
    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    // Convert the rustls ClientConfig into a Quinn-compatible QUIC config
    let quic_client_config = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
        .map_err(|e| anyhow::anyhow!("Failed to build QUIC client config: {e}"))?;

    let mut client_config = quinn::ClientConfig::new(Arc::new(quic_client_config));
    // Optimization: Tune client QUIC transport for higher throughput
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_uni_streams(1024u32.into());
    transport.max_concurrent_bidi_streams(1024u32.into());
    transport.receive_window(128_000_000u32.into());
    transport.send_window(128_000_000u64);
    transport.stream_receive_window(16_000_000u32.into());
    client_config.transport_config(Arc::new(transport));

    // ---- Step 2: Create QUIC endpoint on an ephemeral UDP port ----
    let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())?;
    endpoint.set_default_client_config(client_config);

    // ---- Step 3: Resolve target address and connect ----
    // Resolve "host:port" to a SocketAddr (supports DNS names and raw IPs)
    let server_addr = cli
        .uri
        .to_socket_addrs()
        .context("Could not resolve server URI to a socket address")?
        .next()
        .context("No socket address resolved")?;

    // Extract the hostname part (before the colon) for TLS SNI verification.
    // For IP addresses this will be the IP itself; for DNS names, the hostname.
    let server_name = cli.uri.split(':').next().unwrap_or(&cli.uri);

    trace!("HTTP/3: Connecting to {} ({})", server_name, server_addr);

    // Perform the QUIC handshake (including TLS 1.3 inside QUIC)
    let quinn_conn = endpoint
        .connect(server_addr, server_name)?
        .await
        .context("QUIC connection failed")?;

    trace!("HTTP/3: QUIC connection established");

    // ---- Step 4: Create H3 client over the QUIC connection ----
    // Wrap the quinn Connection in an h3-quinn adapter
    let h3_conn = h3_quinn::Connection::new(quinn_conn);
    // `h3::client::new` returns:
    //   - `h3_driver`: the connection state machine (must be polled)
    //   - `send_request`: a clonable handle for issuing new requests
    let (mut h3_driver, send_request) = h3::client::new(h3_conn)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create h3 client connection: {e}"))?;

    // ---- Step 5: Spawn the connection driver as a background task ----
    // The h3 connection driver processes incoming frames, flow-control updates,
    // and QUIC events. It must run as long as the connection is alive.
    // When the connection closes normally (H3_NO_ERROR), poll_close returns
    // the close reason — this is expected, not a real error.
    tokio::spawn(async move {
        let e = futures::future::poll_fn(|cx| h3_driver.poll_close(cx)).await;
        trace!("HTTP/3 connection driver closed: {e}");
    });

    // ---- Step 6: Sliding-window request loop (same pattern as run_h2) ----
    let concurrency = cli.num_parallel as usize;
    let total_requests = cli.num_req as usize;

    // jwt_token and uri must be declared BEFORE the sliding window so they
    // live long enough for the async requests to borrow them.
    let jwt_token = read_jwt(cli);
    let uri = build_uri(cli);

    run_sliding_window(total_requests, concurrency, "H3 request failed", || {
        let uri = uri.clone();
        let send_request = send_request.clone();
        let jwt_token_clone = jwt_token.as_deref().map(|s| s.to_string());
        async move { do_request_h3(&send_request, cli, jwt_token_clone.as_deref(), uri).await }
    })
    .await;

    Ok(())
}

// =============================================================================
// HTTP/3 Request Execution
// =============================================================================

/// Sends a **single HTTP/3** request over an existing QUIC connection and
/// returns the response body as a `String`.
///
/// # How It Works
///
/// 1. **Clone** the [`SendRequest`](h3::client::SendRequest) handle — this is
///    cheap (reference-counted) and opens a new QUIC stream.
/// 2. **Build Request** using [`prepare_request_builder`] and an empty body `()`.
/// 3. **Send** the request headers via `send_request()`.
/// 4. **Finish** the send side of the stream (signals "no more data").
///    For GET requests there is no body; for POST this client sends no body
///    over H3 (unlike the H2 path which sends `"Hello, World!"`).
/// 5. **Receive** the response headers via `recv_response()`.
/// 6. **Read** the response body by looping over `recv_data()` until the
///    server closes the stream.
///
/// # Error Handling
///
/// All `h3` errors are wrapped in [`anyhow::Error`] for consistent error
/// propagation. Under high concurrency, the server may occasionally reset
/// a stream with `0x0` (H3_NO_ERROR) — this is normal QUIC back-pressure.
async fn do_request_h3(
    send_request: &h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    cli: &Cli,
    jwt_token: Option<&str>,
    uri: Uri,
) -> Result<String, Error> {
    // --- Build the HTTP request (headers only, no body for h3) ---
    // h3 requests have `()` body — data is sent separately via send_data()
    let request = prepare_request_builder(cli, jwt_token, &uri)
        .body(())
        .expect("Failed to build h3 request");

    // Clone the SendRequest handle to open a fresh QUIC bidirectional stream.
    // This is the h3 equivalent of opening a new HTTP/2 stream.
    let mut stream = send_request
        .clone()
        .send_request(request)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to send h3 request: {e}"))?;

    // If this is a method with a body, we would send `send_data` here.
    // For GET requests, the `h3` crate usually closes the send side automatically if there is no body,
    // but calling `finish()` guarantees the FIN bit is sent.
    // However, if the server replies instantly and closes its receive stream before our FIN arrives,
    // we get `Remote reset: 0x0` which is harmless.
    if matches!(cli.method.to_uppercase().as_str(), "POST" | "PUT" | "PATCH") {
        if let Err(e) = stream.finish().await {
            tracing::trace!("Hint: Failed to finish h3 stream (often benign): {e}");
        }
    } else {
        // For GET requests, we just signal FIN
        let _ = stream.finish().await;
    }

    // --- Receive the response ---
    // Wait for the server to send back the response headers (status, etc.)
    let response = stream
        .recv_response()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to receive h3 response: {e}"))?;

    let status = response.status();

    // Read the response body in chunks until the server signals EOF.
    // recv_data() returns `impl Buf`, so we use `Buf::chunk()` to get the
    // underlying byte slice for each frame.
    let mut body_bytes = Vec::new();
    while let Some(chunk) = stream
        .recv_data()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to read h3 response body: {e}"))?
    {
        body_bytes.extend_from_slice(bytes::Buf::chunk(&chunk));
    }

    // Convert the collected bytes to a UTF-8 string
    let body_str = String::from_utf8(body_bytes).context("Response body was not valid UTF-8")?;

    // Treat non-2xx responses as errors (same behaviour as the H2 path)
    if !status.is_success() {
        return Err(anyhow::anyhow!(
            "H3 Request to {uri} failed with status {status}: {body_str}"
        ));
    }

    Ok(body_str)
}

// =============================================================================
// Shared Helpers
// =============================================================================

/// Prepares a partially-constructed HTTP request builder with method, URI,
/// and configured authentication headers.
fn prepare_request_builder(
    cli: &Cli,
    jwt_token: Option<&str>,
    uri: &Uri,
) -> hyper::http::request::Builder {
    let mut builder = Request::builder()
        .method(cli.method.to_uppercase().as_str())
        .uri(uri);

    if cli.security == Protocol::Jwt
        && let Some(token) = jwt_token
    {
        builder = builder.header("Authorization", format!("Bearer {token}"));
    }

    builder
}

/// A sliding-window task executor.
/// Keeps up to `concurrency` tasks in flight, running `total_requests` tasks in total,
/// polling them as they complete, and refilling the window.
async fn run_sliding_window<F, Fut>(
    total_requests: usize,
    concurrency: usize,
    err_prefix: &str,
    mut make_future: F,
) where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<String, Error>>,
{
    let mut futs = FuturesUnordered::new();
    let start = Instant::now();
    let mut completed = 0;
    let mut launched = 0;

    // Seed the initial batch
    let first_batch = std::cmp::min(concurrency, total_requests);
    for _ in 0..first_batch {
        futs.push(make_future());
        launched += 1;
    }

    // Poll completions and refill until all are done
    while completed < total_requests {
        if let Some(res) = futs.next().await {
            completed += 1;
            match res {
                Ok(_) => {}
                Err(e) => error!("{err_prefix}: {e}"),
            }

            if launched < total_requests {
                futs.push(make_future());
                launched += 1;
            }
        }
    }

    print_stats(start, total_requests, concurrency);
}

/// Prints throughput statistics after all requests have completed.
///
/// Reports:
/// - Total wall-clock duration in milliseconds.
/// - Mean requests per second.
/// - Mean latency per request in microseconds.
fn print_stats(start: Instant, total_requests: usize, concurrency: usize) {
    let duration = start.elapsed();
    let mean = total_requests as f64 / duration.as_secs_f64();
    tracing::info!(
        "\nDuration: {}ms with {} total requests at concurrency {}\nMean requests per second: {mean:.0}  --> per request: {:.1}us",
        duration.as_millis(),
        total_requests,
        concurrency,
        1000000. / mean
    );
}
