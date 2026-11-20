//! Relay wire protocol parsing, TLS ClientHello inspection, SNI validation, and idle-aware stream copying.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::Poll;
use std::time::Duration;
use tls_parser::{TlsExtension, TlsMessageHandshake, parse_tls_plaintext};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

/// Sanitizes untrusted strings (such as network-supplied SNI values) before logging
/// to prevent log-injection via newlines, carriage returns, or terminal control characters.
/// Zero-copy on valid printable ASCII hostnames.
pub fn sanitize_log_str(raw: &str) -> std::borrow::Cow<'_, str> {
    if !raw.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return std::borrow::Cow::Borrowed(raw);
    }
    let mut sanitized = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '\n' => sanitized.push_str("\\n"),
            '\r' => sanitized.push_str("\\r"),
            '\t' => sanitized.push_str("\\t"),
            c if c.is_control() => {
                use std::fmt::Write;
                let _ = write!(&mut sanitized, "\\u{{{:x}}}", c as u32);
            }
            c => sanitized.push(c),
        }
    }
    std::borrow::Cow::Owned(sanitized)
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
            let tick_period = (timeout / 4).clamp(Duration::from_millis(20), Duration::from_secs(10));
            let mut last_activity = tokio::time::Instant::now();
            let mut interval = tokio::time::interval_at(last_activity + tick_period, tick_period);
            loop {
                interval.tick().await;
                // Swap the flag to false. If it was true, we had activity since the last tick.
                if had_activity.swap(false, Ordering::Relaxed) {
                    last_activity = tokio::time::Instant::now();
                } else if last_activity.elapsed() >= timeout {
                    break;
                }
            }
        } => {
            CopyResult::IdleTimeout
        }
    }
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

