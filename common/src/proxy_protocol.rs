//! PROXY-Protocol v2 (HAProxy) Encoder, Decoder & Stream Utilities.
//!
//! Provides zero-dependency encoding and decoding for PROXY-Protocol v2 headers
//! (IPv4 and IPv6 over TCP), used to propagate real client IP addresses through
//! the Praeco Relay tunnel to the Praeco Gateway.

use std::io::Cursor;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::pin::Pin;
use std::task::{Context, Poll};
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

/// The 12-byte fixed PROXY protocol v2 signature.
pub const PROXY_V2_MAGIC: [u8; 12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

#[derive(Debug, Error)]
pub enum ProxyProtocolError {
    #[error("I/O error reading PROXY-Protocol header: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid PROXY-Protocol v2 magic signature: {0:?}")]
    InvalidMagic(Vec<u8>),

    #[error("Unsupported PROXY-Protocol version: {0} (expected 2)")]
    UnsupportedVersion(u8),

    #[error("PROXY-Protocol payload too large: {0} bytes (max 1024)")]
    PayloadTooLarge(usize),

    #[error("Truncated address payload: expected at least {expected} bytes, got {got}")]
    TruncatedPayload { expected: usize, got: usize },
}

/// Encodes a PROXY-Protocol v2 binary header for the given source and destination socket addresses.
///
/// Returns a 28-byte payload for IPv4 or a 52-byte payload for IPv6 (or IPv4-mapped IPv6).
pub fn encode_proxy_v2(src: SocketAddr, dst: SocketAddr) -> Vec<u8> {
    let mut buf = Vec::with_capacity(52);
    buf.extend_from_slice(&PROXY_V2_MAGIC);

    match (src, dst) {
        (SocketAddr::V4(s), SocketAddr::V4(d)) => {
            buf.push(0x21); // Version 2, Command PROXY
            buf.push(0x11); // AF_INET (IPv4), STREAM (TCP)
            buf.extend_from_slice(&(12u16).to_be_bytes()); // Length: 12 bytes
            buf.extend_from_slice(&s.ip().octets());
            buf.extend_from_slice(&d.ip().octets());
            buf.extend_from_slice(&s.port().to_be_bytes());
            buf.extend_from_slice(&d.port().to_be_bytes());
        }
        (SocketAddr::V6(s), SocketAddr::V6(d)) => {
            buf.push(0x21); // Version 2, Command PROXY
            buf.push(0x21); // AF_INET6 (IPv6), STREAM (TCP)
            buf.extend_from_slice(&(36u16).to_be_bytes()); // Length: 36 bytes
            buf.extend_from_slice(&s.ip().octets());
            buf.extend_from_slice(&d.ip().octets());
            buf.extend_from_slice(&s.port().to_be_bytes());
            buf.extend_from_slice(&d.port().to_be_bytes());
        }
        (s, d) => {
            let s6_ip = match s.ip() {
                IpAddr::V4(v4) => v4.to_ipv6_mapped(),
                IpAddr::V6(v6) => v6,
            };
            let d6_ip = match d.ip() {
                IpAddr::V4(v4) => v4.to_ipv6_mapped(),
                IpAddr::V6(v6) => v6,
            };
            buf.push(0x21); // Version 2, Command PROXY
            buf.push(0x21); // AF_INET6, STREAM
            buf.extend_from_slice(&(36u16).to_be_bytes()); // Length: 36 bytes
            buf.extend_from_slice(&s6_ip.octets());
            buf.extend_from_slice(&d6_ip.octets());
            buf.extend_from_slice(&s.port().to_be_bytes());
            buf.extend_from_slice(&d.port().to_be_bytes());
        }
    }

    buf
}

/// Reads and parses a PROXY-Protocol v2 header from an asynchronous reader.
///
/// Returns `Ok(Some(client_addr))` if a valid PROXY v2 header is parsed.
/// Returns `Ok(None)` if the command was LOCAL or protocol was UNSPEC.
/// Returns `Err(ProxyProtocolError)` if the header is malformed, has invalid magic, or fails I/O.
pub async fn read_proxy_v2<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<SocketAddr>, ProxyProtocolError> {
    let mut header = [0u8; 16];
    reader.read_exact(&mut header).await?;

    if header[0..12] != PROXY_V2_MAGIC {
        return Err(ProxyProtocolError::InvalidMagic(header[0..12].to_vec()));
    }

    let version_cmd = header[12];
    let version = version_cmd >> 4;
    if version != 2 {
        return Err(ProxyProtocolError::UnsupportedVersion(version));
    }

    let cmd = version_cmd & 0x0F;
    let fam_proto = header[13];
    let fam = fam_proto >> 4;
    let payload_len = u16::from_be_bytes([header[14], header[15]]) as usize;

    if payload_len > 1024 {
        return Err(ProxyProtocolError::PayloadTooLarge(payload_len));
    }

    let mut payload = vec![0u8; payload_len];
    reader.read_exact(&mut payload).await?;

    // If LOCAL command (0x0), no client IP was proxied
    if cmd == 0x0 {
        return Ok(None);
    }

    match fam {
        0x1 => {
            // AF_INET (IPv4): 4B src + 4B dst + 2B sport + 2B dport = 12 bytes
            if payload_len < 12 {
                return Err(ProxyProtocolError::TruncatedPayload {
                    expected: 12,
                    got: payload_len,
                });
            }
            let src_ip = Ipv4Addr::new(payload[0], payload[1], payload[2], payload[3]);
            let src_port = u16::from_be_bytes([payload[8], payload[9]]);
            Ok(Some(SocketAddr::V4(SocketAddrV4::new(src_ip, src_port))))
        }
        0x2 => {
            // AF_INET6 (IPv6): 16B src + 16B dst + 2B sport + 2B dport = 36 bytes
            if payload_len < 36 {
                return Err(ProxyProtocolError::TruncatedPayload {
                    expected: 36,
                    got: payload_len,
                });
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&payload[0..16]);
            let src_ip = Ipv6Addr::from(octets);
            let src_port = u16::from_be_bytes([payload[32], payload[33]]);

            if let Some(v4) = src_ip.to_ipv4_mapped() {
                Ok(Some(SocketAddr::V4(SocketAddrV4::new(v4, src_port))))
            } else {
                Ok(Some(SocketAddr::V6(SocketAddrV6::new(src_ip, src_port, 0, 0))))
            }
        }
        _ => {
            // UNSPEC or other family
            Ok(None)
        }
    }
}

/// A stream wrapper that prepends a buffered byte prefix before reading from the underlying stream.
///
/// Implements both `AsyncRead` and `AsyncWrite` transparently.
pub struct PrefixedStream<S> {
    prefix: Cursor<Vec<u8>>,
    stream: S,
}

impl<S> PrefixedStream<S> {
    pub fn new(prefix: Vec<u8>, stream: S) -> Self {
        Self {
            prefix: Cursor::new(prefix),
            stream,
        }
    }

    pub fn into_inner(self) -> S {
        self.stream
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let prefix_len = self.prefix.get_ref().len() as u64;
        if self.prefix.position() < prefix_len {
            let before = buf.remaining();
            let unfilled = buf.initialize_unfilled();
            let to_read = std::cmp::min(before, unfilled.len());
            let n = std::io::Read::read(&mut self.prefix, &mut unfilled[..to_read])?;
            buf.advance(n);
            Poll::Ready(Ok(()))
        } else {
            Pin::new(&mut self.stream).poll_read(cx, buf)
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[tokio::test]
    async fn test_encode_and_read_proxy_v2_ipv4() {
        let client_addr: SocketAddr = "198.51.100.42:54321".parse().unwrap();
        let relay_addr: SocketAddr = "203.0.113.1:443".parse().unwrap();

        let encoded = encode_proxy_v2(client_addr, relay_addr);
        assert_eq!(encoded.len(), 28);
        assert_eq!(&encoded[0..12], &PROXY_V2_MAGIC);

        let mut cursor = Cursor::new(encoded);
        let parsed = read_proxy_v2(&mut cursor).await.unwrap();
        assert_eq!(parsed, Some(client_addr));
    }

    #[tokio::test]
    async fn test_encode_and_read_proxy_v2_ipv6() {
        let client_addr: SocketAddr = "[2001:db8::1234]:49152".parse().unwrap();
        let relay_addr: SocketAddr = "[2001:db8::1]:443".parse().unwrap();

        let encoded = encode_proxy_v2(client_addr, relay_addr);
        assert_eq!(encoded.len(), 52);
        assert_eq!(&encoded[0..12], &PROXY_V2_MAGIC);

        let mut cursor = Cursor::new(encoded);
        let parsed = read_proxy_v2(&mut cursor).await.unwrap();
        assert_eq!(parsed, Some(client_addr));
    }

    #[tokio::test]
    async fn test_read_proxy_v2_invalid_magic() {
        let raw_tls = vec![0x16, 0x03, 0x01, 0x00, 0xA0]; // TLS Handshake Record
        let mut cursor = Cursor::new(raw_tls);
        let err = read_proxy_v2(&mut cursor).await.unwrap_err();
        assert!(matches!(err, ProxyProtocolError::Io(_))); // EOF before 16 bytes

        let fake_bytes = vec![0x16; 16];
        let mut cursor2 = Cursor::new(fake_bytes);
        let err2 = read_proxy_v2(&mut cursor2).await.unwrap_err();
        assert!(matches!(err2, ProxyProtocolError::InvalidMagic(_)));
    }

    #[tokio::test]
    async fn test_prefixed_stream_reads_prefix_then_body() {
        let prefix = b"HELLO ".to_vec();
        let body = Cursor::new(b"WORLD".to_vec());
        let mut stream = PrefixedStream::new(prefix, body);

        let mut out = Vec::new();
        stream.read_to_end(&mut out).await.unwrap();
        assert_eq!(out, b"HELLO WORLD");
    }
}
