//! # L2 Response Cache Abstractions, Wire Codec & Test Cluster
//!
//! Provides the backend-agnostic building blocks for the optional Dragonfly/Redis L2 tier:
//!
//! 1. **Deterministic Hash-Tagged Key Encoding (`K-01`, `K-05`):** Generation-free slot keys
//!    using full 256-bit SHA-256 namespace tags (`{prefix}:v1:e:{ns_tag}:{entry_hex}`) so
//!    cross-node sharing works across cold starts without stale reads or orphaned zombie keys.
//! 2. **Binary `PRC2` Wire Codec (`async-compression` + Zip-Bomb Guard):** Compact frame format
//!    embedding canonical remote generations `(remote_global_gen, remote_ns_gen)`, `original_ttl_ms`,
//!    headers, optional HTTP/2 trailers, and optional `gzip`/`brotli` compression reusing existing
//!    `OnceCell` buffers zero-copy.
//! 3. **Bounded Write Budget & Fail-Open Circuit Breaker (`K-06`):** Atomic [`L2WriteBudget`] with
//!    RAII [`L2WritePermit`]s prevents mailbox OOM outside `moka`, while [`L2CircuitBreaker`]
//!    isolates L2 outages in nanoseconds.
//! 4. **[`L2CacheBackend`] Trait & [`InMemoryL2Backend`]:** Enables deterministic multi-node
//!    integration tests without requiring a running Dragonfly server.

use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use async_compression::{
    Level,
    tokio::bufread::{BrotliDecoder, GzipDecoder, GzipEncoder},
};
use bytes::{BufMut, Bytes, BytesMut};
use hyper::{
    HeaderMap, StatusCode,
    header::{HeaderName, HeaderValue},
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::io::AsyncReadExt as _;

use crate::{
    configuration::CacheScope,
    middleware::cache::{
        CacheKey, CachedResponse, entry_eligible_for_precompression,
        has_non_identity_content_encoding,
    },
};

/// Magic bytes identifying a `praeco-rs` L2 cache wire frame (`PRC2`).
pub const WIRE_MAGIC: [u8; 4] = *b"PRC2";

/// Supported `PRC2` wire frame format version.
pub const WIRE_VERSION: u8 = 1;

/// Fixed byte length of the `PRC2` frame header before variable-length sections.
const WIRE_FIXED_HEADER_LEN: usize = 32;

/// Maximum permitted wire metadata overhead beyond `max_entry_bytes` (`64 KiB`).
pub const MAX_WIRE_HEADER_OVERHEAD: usize = 64 * 1024;

/// Maximum permitted number of headers or trailers in a single wire frame.
pub const MAX_WIRE_HEADERS: usize = 512;

/// Minimum remaining L2 `PTTL` required to accept an L2 HIT and backfill L1 (`100 ms`, `K-09`).
pub const MIN_L2_HIT_REMAINING_TTL: Duration = Duration::from_millis(100);

/// Minimum TTL required before enqueueing an asynchronous L2 write (`500 ms`, `K-09`).
pub const MIN_L2_WRITE_TTL: Duration = Duration::from_millis(500);

/// Body encoding stored inside a `PRC2` wire frame (`Flags` bits `0..=1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum WireBodyEncoding {
    /// Raw uncompressed payload.
    Identity = 0,
    /// Gzip-compressed payload.
    Gzip = 1,
    /// Brotli-compressed payload.
    Brotli = 2,
}

impl WireBodyEncoding {
    fn from_flags(flags: u8) -> Result<Self, L2WireError> {
        match flags {
            0 => Ok(Self::Identity),
            1 => Ok(Self::Gzip),
            2 => Ok(Self::Brotli),
            other => Err(L2WireError::UnknownFlags(other)),
        }
    }
}

/// Errors produced when encoding or decoding `PRC2` wire frames.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum L2WireError {
    #[error("wire frame truncated: expected at least {expected} bytes, got {actual}")]
    TooShort { expected: usize, actual: usize },
    #[error("wire frame size {size} exceeds maximum permitted {max}")]
    FrameTooLarge { size: usize, max: usize },
    #[error("invalid PRC2 wire magic")]
    InvalidMagic,
    #[error("unsupported PRC2 wire version {0}")]
    UnsupportedVersion(u8),
    #[error("unknown PRC2 wire flags byte {0:#04x}")]
    UnknownFlags(u8),
    #[error("invalid HTTP status code {0} in wire frame")]
    InvalidStatusCode(u16),
    #[error("uncompressed body length {size} exceeds max_entry_bytes {max}")]
    UncompressedBodyTooLarge { size: usize, max: usize },
    #[error("wire header/trailer count {0} exceeds maximum {MAX_WIRE_HEADERS}")]
    TooManyHeaders(usize),
    #[error("invalid HTTP header/trailer in wire frame: {0}")]
    HeaderDecode(String),
    #[error("wire payload length mismatch (expected {expected}, got {actual})")]
    LengthMismatch { expected: usize, actual: usize },
    #[error("failed to decompress wire body: {0}")]
    DecompressionFailed(String),
    #[error("response metadata or body exceeds u32 wire length bounds")]
    EncodeOverflow,
}

// ============================================================================
//  Deterministic Key & Channel Encoding (K-01, K-05)
// ============================================================================

#[inline]
fn push_hex_digest(out: &mut String, digest: &[u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for &b in digest {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
}

#[inline]
fn update_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

/// Encodes a logical cache `namespace` into a collision-resistant 256-bit lowercase hex tag.
pub fn encode_namespace_tag(namespace: &str) -> String {
    let digest: [u8; 32] = Sha256::digest(namespace.as_bytes()).into();
    let mut hex = String::with_capacity(64);
    push_hex_digest(&mut hex, &digest);
    hex
}

/// Encodes [`CacheKey`] into a generation-free, Redis/Dragonfly hash-tagged entry key.
///
/// Omits `key.generation` intentionally (`K-01`): canonical remote generations are verified
/// inside the `PRC2` wire frame so cold-starting nodes share L2 entries immediately without
/// stale reads or orphaned zombie keys.
pub fn encode_l2_entry_key(key: &CacheKey, key_prefix: &str) -> String {
    let ns_tag = encode_namespace_tag(&key.namespace);

    let mut hasher = Sha256::new();
    hasher.update(b"praeco-l2-key-v1\0");
    let scope_byte: u8 = match key.scope {
        CacheScope::Public => 0,
        CacheScope::PerRole => 1,
        CacheScope::PerSubject => 2,
    };
    hasher.update([scope_byte]);
    update_len_prefixed(&mut hasher, key.method.as_bytes());
    update_len_prefixed(&mut hasher, key.path_and_query.as_bytes());

    let mut sorted_vary: Vec<(&str, &str)> = key
        .vary_values
        .iter()
        .map(|(k, v)| (k.as_ref(), v.as_str()))
        .collect();
    sorted_vary.sort_unstable();
    hasher.update((sorted_vary.len() as u64).to_le_bytes());
    for (name, val) in sorted_vary {
        update_len_prefixed(&mut hasher, name.as_bytes());
        update_len_prefixed(&mut hasher, val.as_bytes());
    }

    update_len_prefixed(&mut hasher, key.scope_key.as_bytes());

    match &key.body_hash {
        Some(h) => {
            hasher.update([1u8]);
            hasher.update(h);
        }
        None => hasher.update([0u8]),
    }

    match &key.post_encoding {
        Some((ct, ce, ge)) => {
            hasher.update([1u8]);
            update_len_prefixed(&mut hasher, ct.as_bytes());
            update_len_prefixed(&mut hasher, ce.as_bytes());
            update_len_prefixed(&mut hasher, ge.as_bytes());
        }
        None => hasher.update([0u8]),
    }

    let entry_digest: [u8; 32] = hasher.finalize().into();
    let mut out = String::with_capacity(key_prefix.len() + 6 + 66 + 1 + 64);
    out.push_str(key_prefix);
    out.push_str(":v1:e:{");
    out.push_str(&ns_tag);
    out.push_str("}:");
    push_hex_digest(&mut out, &entry_digest);
    out
}

/// Returns the Dragonfly key storing the canonical generation counter for `namespace`.
pub fn encode_l2_ns_gen_key(namespace: &str, key_prefix: &str) -> String {
    let ns_tag = encode_namespace_tag(namespace);
    format!("{key_prefix}:v1:gen:ns:{{{ns_tag}}}")
}

/// Returns the Dragonfly key storing the canonical global generation counter.
pub fn encode_l2_global_gen_key(key_prefix: &str) -> String {
    format!("{key_prefix}:v1:gen:global")
}

/// Returns the Dragonfly Pub/Sub channel carrying cluster-wide invalidation events.
pub fn encode_l2_inv_channel(key_prefix: &str) -> String {
    format!("{key_prefix}:v1:inv")
}

// ============================================================================
//  PRC2 Binary Wire Codec
// ============================================================================

fn encode_header_map(headers: &HeaderMap) -> Result<Vec<u8>, L2WireError> {
    let count = headers.len();
    if count > MAX_WIRE_HEADERS {
        return Err(L2WireError::TooManyHeaders(count));
    }
    let count_u16 = u16::try_from(count).map_err(|_| L2WireError::EncodeOverflow)?;
    let estimated_bytes: usize = 2 + headers
        .iter()
        .map(|(k, v)| 6 + k.as_str().len() + v.as_bytes().len())
        .sum::<usize>();
    let mut buf = Vec::with_capacity(estimated_bytes);
    buf.extend_from_slice(&count_u16.to_le_bytes());

    for (name, val) in headers {
        let name_bytes = name.as_str().as_bytes();
        let val_bytes = val.as_bytes();
        let name_len = u16::try_from(name_bytes.len()).map_err(|_| L2WireError::EncodeOverflow)?;
        let val_len = u32::try_from(val_bytes.len()).map_err(|_| L2WireError::EncodeOverflow)?;
        buf.extend_from_slice(&name_len.to_le_bytes());
        buf.extend_from_slice(name_bytes);
        buf.extend_from_slice(&val_len.to_le_bytes());
        buf.extend_from_slice(val_bytes);
    }
    Ok(buf)
}

fn decode_header_map(raw: &Bytes, start: usize, len: usize) -> Result<HeaderMap, L2WireError> {
    let end = start
        .checked_add(len)
        .ok_or_else(|| L2WireError::HeaderDecode("header blob offset overflow".to_string()))?;
    if end > raw.len() {
        return Err(L2WireError::TooShort {
            expected: end,
            actual: raw.len(),
        });
    }
    if len < 2 {
        return Err(L2WireError::HeaderDecode(
            "header blob shorter than 2-byte count".to_string(),
        ));
    }
    let count = u16::from_le_bytes([raw[start], raw[start + 1]]) as usize;
    if count > MAX_WIRE_HEADERS {
        return Err(L2WireError::TooManyHeaders(count));
    }

    let mut headers = HeaderMap::with_capacity(count);
    let mut pos = start + 2;

    for _ in 0..count {
        let name_len_end = pos + 2;
        if name_len_end > end {
            return Err(L2WireError::HeaderDecode(
                "truncated header name length".to_string(),
            ));
        }
        let name_len = u16::from_le_bytes([raw[pos], raw[pos + 1]]) as usize;
        pos = name_len_end;

        let name_end = pos
            .checked_add(name_len)
            .ok_or_else(|| L2WireError::HeaderDecode("header name overflow".to_string()))?;
        if name_end + 4 > end {
            return Err(L2WireError::HeaderDecode(
                "truncated header name or value length".to_string(),
            ));
        }
        let name = HeaderName::from_bytes(&raw[pos..name_end])
            .map_err(|e| L2WireError::HeaderDecode(e.to_string()))?;
        pos = name_end;

        let val_len = u32::from_le_bytes([raw[pos], raw[pos + 1], raw[pos + 2], raw[pos + 3]])
            as usize;
        pos += 4;

        let val_end = pos
            .checked_add(val_len)
            .ok_or_else(|| L2WireError::HeaderDecode("header value overflow".to_string()))?;
        if val_end > end {
            return Err(L2WireError::HeaderDecode(
                "truncated header value bytes".to_string(),
            ));
        }
        let val = HeaderValue::from_maybe_shared(raw.slice(pos..val_end))
            .map_err(|e| L2WireError::HeaderDecode(e.to_string()))?;
        headers.append(name, val);
        pos = val_end;
    }

    if pos != end {
        return Err(L2WireError::HeaderDecode(
            "trailing unparsed bytes inside header blob".to_string(),
        ));
    }
    Ok(headers)
}

/// Encodes a [`CachedResponse`] into a versioned `PRC2` binary wire frame.
///
/// Reuses existing `OnceCell` precompressed `gzip`/`brotli` variants zero-copy when present,
/// or compresses the body in the background with `GzipEncoder` (`Level::Fastest`) when
/// `compress_min_bytes > 0` and the payload is not already `Content-Encoding`-encoded.
pub async fn encode_wire_v1(
    entry: &CachedResponse,
    remote_gen: (u64, u64),
    compress_min_bytes: usize,
) -> Result<Bytes, L2WireError> {
    let uncompressed_len = entry.body.len();

    let (encoding, wire_body) = if let Some(gz) = entry
        .peek_precompressed_gzip()
        .filter(|b| !b.is_empty() && b.len() < uncompressed_len)
    {
        (WireBodyEncoding::Gzip, gz)
    } else if let Some(br) = entry
        .peek_precompressed_br()
        .filter(|b| !b.is_empty() && b.len() < uncompressed_len)
    {
        (WireBodyEncoding::Brotli, br)
    } else if compress_min_bytes > 0
        && uncompressed_len >= compress_min_bytes
        && !has_non_identity_content_encoding(&entry.headers)
        && entry_eligible_for_precompression(entry)
    {
        let cursor = std::io::Cursor::new(entry.body.clone());
        let mut out = Vec::with_capacity(uncompressed_len / 2);
        let res = GzipEncoder::with_quality(cursor, Level::Fastest)
            .read_to_end(&mut out)
            .await;
        if res.is_ok() && !out.is_empty() && out.len() < uncompressed_len {
            (WireBodyEncoding::Gzip, Bytes::from(out))
        } else {
            (WireBodyEncoding::Identity, entry.body.clone())
        }
    } else {
        (WireBodyEncoding::Identity, entry.body.clone())
    };

    let headers_blob = encode_header_map(&entry.headers)?;
    let trailers_blob = match &entry.trailers {
        Some(tr) => Some(encode_header_map(tr)?),
        None => None,
    };

    let headers_len = u32::try_from(headers_blob.len()).map_err(|_| L2WireError::EncodeOverflow)?;
    let trailers_len = trailers_blob
        .as_ref()
        .map_or(Ok(0u32), |b| u32::try_from(b.len()))
        .map_err(|_| L2WireError::EncodeOverflow)?;
    let uncompressed_body_len =
        u32::try_from(uncompressed_len).map_err(|_| L2WireError::EncodeOverflow)?;
    let wire_body_len = u32::try_from(wire_body.len()).map_err(|_| L2WireError::EncodeOverflow)?;
    let ttl_ms = u64::try_from(entry.ttl.as_millis()).unwrap_or(u64::MAX);

    let total_len = WIRE_FIXED_HEADER_LEN
        .checked_add(4)
        .and_then(|n| n.checked_add(headers_blob.len()))
        .and_then(|n| n.checked_add(4))
        .and_then(|n| n.checked_add(trailers_blob.as_ref().map_or(0, Vec::len)))
        .and_then(|n| n.checked_add(8))
        .and_then(|n| n.checked_add(wire_body.len()))
        .ok_or(L2WireError::EncodeOverflow)?;

    let mut out = BytesMut::with_capacity(total_len);
    out.put_slice(&WIRE_MAGIC);
    out.put_u8(WIRE_VERSION);
    out.put_u8(encoding as u8);
    out.put_u16_le(entry.status.as_u16());
    out.put_u64_le(remote_gen.0);
    out.put_u64_le(remote_gen.1);
    out.put_u64_le(ttl_ms);

    out.put_u32_le(headers_len);
    out.put_slice(&headers_blob);
    out.put_u32_le(trailers_len);
    if let Some(tr_blob) = trailers_blob {
        out.put_slice(&tr_blob);
    }
    out.put_u32_le(uncompressed_body_len);
    out.put_u32_le(wire_body_len);
    out.put_slice(&wire_body);

    Ok(out.freeze())
}

/// Decoded `PRC2` wire frame ready for generation/policy validation and [`CachedResponse`] construction.
#[derive(Debug, Clone)]
pub struct DecodedL2Wire {
    /// Canonical Dragonfly `(global_gen, ns_gen)` recorded when the entry was stored.
    pub remote_gen: (u64, u64),
    /// Original response TTL in milliseconds for accurate `Age` header calculation (`K-02`).
    pub original_ttl_ms: u64,
    /// HTTP status code.
    pub status: StatusCode,
    /// Sanitized HTTP response headers.
    pub headers: HeaderMap,
    /// Optional HTTP/2 trailers (e.g., `grpc-status: 0`).
    pub trailers: Option<HeaderMap>,
    /// Decompressed uncompressed response body.
    pub body: Bytes,
    /// Optional precompressed `gzip` slice reused zero-copy from the wire payload.
    pub precompressed_gzip: Option<Bytes>,
    /// Optional precompressed `brotli` slice reused zero-copy from the wire payload.
    pub precompressed_br: Option<Bytes>,
}

impl DecodedL2Wire {
    /// Converts this decoded wire frame into a local [`CachedResponse`] bounded by `l1_max_ttl`.
    pub fn into_cached_response(self, pttl_ms: u64, l1_max_ttl: Duration) -> CachedResponse {
        let remaining = Duration::from_millis(pttl_ms);
        let l1_ttl = remaining.min(l1_max_ttl);
        let initial_age = Duration::from_millis(self.original_ttl_ms.saturating_sub(pttl_ms));
        CachedResponse::from_l2_parts(
            self.status,
            self.headers,
            self.body,
            self.trailers,
            l1_ttl,
            initial_age,
            self.precompressed_gzip,
            self.precompressed_br,
        )
    }
}

#[inline]
fn read_u32_le(raw: &Bytes, pos: usize) -> Result<(u32, usize), L2WireError> {
    let end = pos
        .checked_add(4)
        .ok_or(L2WireError::TooShort {
            expected: usize::MAX,
            actual: raw.len(),
        })?;
    if end > raw.len() {
        return Err(L2WireError::TooShort {
            expected: end,
            actual: raw.len(),
        });
    }
    let val = u32::from_le_bytes([raw[pos], raw[pos + 1], raw[pos + 2], raw[pos + 3]]);
    Ok((val, end))
}

/// Validates and decodes a `PRC2` binary wire frame, enforcing strict `max_entry_bytes`
/// bounds and decompression bomb protection (`take(uncompressed_body_len + 1)`).
pub async fn decode_wire_v1(raw: Bytes, max_entry_bytes: usize) -> Result<DecodedL2Wire, L2WireError> {
    let max_wire_size = max_entry_bytes.saturating_add(MAX_WIRE_HEADER_OVERHEAD);
    if raw.len() > max_wire_size {
        return Err(L2WireError::FrameTooLarge {
            size: raw.len(),
            max: max_wire_size,
        });
    }
    if raw.len() < WIRE_FIXED_HEADER_LEN + 16 {
        return Err(L2WireError::TooShort {
            expected: WIRE_FIXED_HEADER_LEN + 16,
            actual: raw.len(),
        });
    }

    if raw[0..4] != WIRE_MAGIC {
        return Err(L2WireError::InvalidMagic);
    }
    let version = raw[4];
    if version != WIRE_VERSION {
        return Err(L2WireError::UnsupportedVersion(version));
    }
    let encoding = WireBodyEncoding::from_flags(raw[5])?;
    let status_u16 = u16::from_le_bytes([raw[6], raw[7]]);
    let status =
        StatusCode::from_u16(status_u16).map_err(|_| L2WireError::InvalidStatusCode(status_u16))?;
    let remote_global_gen = u64::from_le_bytes([
        raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
    ]);
    let remote_ns_gen = u64::from_le_bytes([
        raw[16], raw[17], raw[18], raw[19], raw[20], raw[21], raw[22], raw[23],
    ]);
    let original_ttl_ms = u64::from_le_bytes([
        raw[24], raw[25], raw[26], raw[27], raw[28], raw[29], raw[30], raw[31],
    ]);

    let mut pos = WIRE_FIXED_HEADER_LEN;

    let (headers_len_u32, next_pos) = read_u32_le(&raw, pos)?;
    let headers_len = headers_len_u32 as usize;
    let headers = decode_header_map(&raw, next_pos, headers_len)?;
    pos = next_pos
        .checked_add(headers_len)
        .ok_or_else(|| L2WireError::HeaderDecode("headers offset overflow".to_string()))?;

    let (trailers_len_u32, next_pos) = read_u32_le(&raw, pos)?;
    let trailers_len = trailers_len_u32 as usize;
    let trailers = if trailers_len == 0 {
        pos = next_pos;
        None
    } else {
        let tr = decode_header_map(&raw, next_pos, trailers_len)?;
        pos = next_pos
            .checked_add(trailers_len)
            .ok_or_else(|| L2WireError::HeaderDecode("trailers offset overflow".to_string()))?;
        Some(tr)
    };

    let (uncompressed_len_u32, next_pos) = read_u32_le(&raw, pos)?;
    let uncompressed_len = uncompressed_len_u32 as usize;
    if uncompressed_len > max_entry_bytes {
        return Err(L2WireError::UncompressedBodyTooLarge {
            size: uncompressed_len,
            max: max_entry_bytes,
        });
    }

    let (wire_body_len_u32, body_start) = read_u32_le(&raw, next_pos)?;
    let wire_body_len = wire_body_len_u32 as usize;
    let body_end = body_start
        .checked_add(wire_body_len)
        .ok_or(L2WireError::LengthMismatch {
            expected: usize::MAX,
            actual: raw.len(),
        })?;
    if body_end != raw.len() {
        return Err(L2WireError::LengthMismatch {
            expected: body_end,
            actual: raw.len(),
        });
    }

    let wire_body = raw.slice(body_start..body_end);

    let (body, precompressed_gzip, precompressed_br) = match encoding {
        WireBodyEncoding::Identity => {
            if wire_body_len != uncompressed_len {
                return Err(L2WireError::LengthMismatch {
                    expected: uncompressed_len,
                    actual: wire_body_len,
                });
            }
            (wire_body, None, None)
        }
        WireBodyEncoding::Gzip => {
            let decompressed =
                decompress_wire_body(wire_body.clone(), uncompressed_len, WireBodyEncoding::Gzip)
                    .await?;
            (decompressed, Some(wire_body), None)
        }
        WireBodyEncoding::Brotli => {
            let decompressed = decompress_wire_body(
                wire_body.clone(),
                uncompressed_len,
                WireBodyEncoding::Brotli,
            )
            .await?;
            (decompressed, None, Some(wire_body))
        }
    };

    Ok(DecodedL2Wire {
        remote_gen: (remote_global_gen, remote_ns_gen),
        original_ttl_ms,
        status,
        headers,
        trailers,
        body,
        precompressed_gzip,
        precompressed_br,
    })
}

async fn decompress_wire_body(
    wire_body: Bytes,
    expected_uncompressed_len: usize,
    encoding: WireBodyEncoding,
) -> Result<Bytes, L2WireError> {
    let limit = (expected_uncompressed_len as u64).saturating_add(1);
    let cursor = std::io::Cursor::new(wire_body);
    let mut out = Vec::with_capacity(expected_uncompressed_len);

    let read_res = match encoding {
        WireBodyEncoding::Gzip => GzipDecoder::new(cursor).take(limit).read_to_end(&mut out).await,
        WireBodyEncoding::Brotli => {
            BrotliDecoder::new(cursor)
                .take(limit)
                .read_to_end(&mut out)
                .await
        }
        WireBodyEncoding::Identity => return Err(L2WireError::UnknownFlags(0)),
    };
    read_res.map_err(|e| L2WireError::DecompressionFailed(e.to_string()))?;

    if out.len() != expected_uncompressed_len {
        return Err(L2WireError::LengthMismatch {
            expected: expected_uncompressed_len,
            actual: out.len(),
        });
    }
    Ok(Bytes::from(out))
}

// ============================================================================
//  Bounded Write Budget (K-06) & Fail-Open Circuit Breaker
// ============================================================================

/// Atomic byte budget capping queued payloads in `L2WriterActor` mailboxes (`K-06`).
#[derive(Debug)]
pub struct L2WriteBudget {
    max_bytes: usize,
    used_bytes: AtomicUsize,
}

/// RAII byte reservation released automatically when a queued write completes or is dropped.
#[derive(Debug)]
pub struct L2WritePermit {
    budget: Arc<L2WriteBudget>,
    bytes: usize,
}

impl L2WriteBudget {
    /// Creates a new write budget capped at `max_bytes`.
    pub fn new(max_bytes: usize) -> Arc<Self> {
        Arc::new(Self {
            max_bytes,
            used_bytes: AtomicUsize::new(0),
        })
    }

    /// Attempts to reserve `bytes` from the budget without blocking.
    pub fn try_reserve(self: &Arc<Self>, bytes: usize) -> Option<L2WritePermit> {
        if bytes == 0 {
            return Some(L2WritePermit {
                budget: Arc::clone(self),
                bytes: 0,
            });
        }
        let mut current = self.used_bytes.load(Ordering::Acquire);
        loop {
            let next = current.checked_add(bytes)?;
            if next > self.max_bytes {
                return None;
            }
            match self.used_bytes.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Some(L2WritePermit {
                        budget: Arc::clone(self),
                        bytes,
                    });
                }
                Err(actual) => current = actual,
            }
        }
    }

    /// Returns the number of bytes currently reserved by queued writes.
    #[inline]
    pub fn used_bytes(&self) -> usize {
        self.used_bytes.load(Ordering::Acquire)
    }

    /// Returns the configured maximum byte budget.
    #[inline]
    pub fn max_bytes(&self) -> usize {
        self.max_bytes
    }
}

impl Drop for L2WritePermit {
    fn drop(&mut self) {
        if self.bytes > 0 {
            self.budget.used_bytes.fetch_sub(self.bytes, Ordering::AcqRel);
        }
    }
}

/// Circuit breaker state exported to Prometheus and `/status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum L2CircuitState {
    Disabled = 0,
    Closed = 1,
    HalfOpen = 2,
    Open = 3,
}

impl L2CircuitState {
    fn from_u8(v: u8) -> Self {
        match v {
            0 => Self::Disabled,
            1 => Self::Closed,
            2 => Self::HalfOpen,
            _ => Self::Open,
        }
    }
}

#[inline]
fn now_epoch_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

/// Lock-free fail-open circuit breaker isolating Dragonfly outages from request latency.
#[derive(Debug)]
pub struct L2CircuitBreaker {
    state: AtomicU8,
    consecutive_failures: AtomicU32,
    open_until_epoch_ms: AtomicU64,
    half_open_probe_in_flight: AtomicBool,
    failure_threshold: u32,
    open_duration_ms: u64,
}

impl L2CircuitBreaker {
    /// Creates a new circuit breaker in [`L2CircuitState::Closed`].
    pub fn new(failure_threshold: u32, open_duration: Duration) -> Self {
        Self {
            state: AtomicU8::new(L2CircuitState::Closed as u8),
            consecutive_failures: AtomicU32::new(0),
            open_until_epoch_ms: AtomicU64::new(0),
            half_open_probe_in_flight: AtomicBool::new(false),
            failure_threshold: failure_threshold.max(1),
            open_duration_ms: u64::try_from(open_duration.as_millis())
                .unwrap_or(u64::MAX)
                .max(1),
        }
    }

    /// Returns the instantaneous circuit state (promoting expired `Open` windows to `HalfOpen`).
    pub fn state(&self) -> L2CircuitState {
        let raw = self.state.load(Ordering::Acquire);
        if raw == L2CircuitState::Open as u8 {
            let now = now_epoch_ms();
            let until = self.open_until_epoch_ms.load(Ordering::Acquire);
            if now >= until {
                return L2CircuitState::HalfOpen;
            }
        }
        L2CircuitState::from_u8(raw)
    }

    /// Returns whether an L2 operation is allowed to proceed right now.
    ///
    /// When `Open` expires, at most one concurrent caller wins the `HalfOpen` probe slot;
    /// concurrent callers fail open immediately without piling onto a recovering Dragonfly node.
    pub fn allow_request(&self) -> bool {
        match L2CircuitState::from_u8(self.state.load(Ordering::Acquire)) {
            L2CircuitState::Disabled => false,
            L2CircuitState::Closed => true,
            L2CircuitState::Open => {
                let now = now_epoch_ms();
                let until = self.open_until_epoch_ms.load(Ordering::Acquire);
                if now < until {
                    return false;
                }
                if self
                    .state
                    .compare_exchange(
                        L2CircuitState::Open as u8,
                        L2CircuitState::HalfOpen as u8,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    )
                    .is_ok()
                {
                    return self
                        .half_open_probe_in_flight
                        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                        .is_ok();
                }
                false
            }
            L2CircuitState::HalfOpen => self
                .half_open_probe_in_flight
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_ok(),
        }
    }

    /// Resets consecutive failures and closes the circuit on a successful L2 operation.
    pub fn record_success(&self) {
        self.consecutive_failures.store(0, Ordering::Release);
        self.half_open_probe_in_flight
            .store(false, Ordering::Release);
        self.state
            .store(L2CircuitState::Closed as u8, Ordering::Release);
    }

    /// Records an L2 failure and returns `true` if this call tripped the circuit into `Open`.
    pub fn record_failure(&self) -> bool {
        let prev_state = L2CircuitState::from_u8(self.state.load(Ordering::Acquire));
        if prev_state == L2CircuitState::HalfOpen {
            self.trip_open();
            return true;
        }
        let failures = self.consecutive_failures.fetch_add(1, Ordering::AcqRel) + 1;
        if failures >= self.failure_threshold {
            let was_open = prev_state == L2CircuitState::Open;
            self.trip_open();
            return !was_open;
        }
        false
    }

    fn trip_open(&self) {
        let until = now_epoch_ms().saturating_add(self.open_duration_ms);
        self.open_until_epoch_ms.store(until, Ordering::Release);
        self.half_open_probe_in_flight
            .store(false, Ordering::Release);
        self.state
            .store(L2CircuitState::Open as u8, Ordering::Release);
    }
}

// ============================================================================
//  L2CacheBackend Trait & In-Memory Reference Cluster for Tests
// ============================================================================

/// Result returned by [`L2CacheBackend::get`].
#[derive(Debug)]
pub enum L2LookupOutcome {
    /// Entry found, generation-matched, and decoded into a local [`CachedResponse`].
    Hit {
        entry: Arc<CachedResponse>,
        remote_gen: (u64, u64),
        pttl_ms: u64,
    },
    /// Key was absent, expired, corrupted, or stale-generation-mismatched.
    Miss {
        /// Canonical `(global_gen, ns_gen)` observed during the read pipeline, if available.
        observed_remote_gen: Option<(u64, u64)>,
    },
    /// L2 is unavailable, circuit-open, or timed out (caller must fail open to upstream).
    Unavailable,
}

/// Cluster-wide invalidation event broadcast over L2 Pub/Sub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum L2InvalidationEvent {
    Namespace(String),
    All,
}

/// Point-in-time status snapshot of an [`L2CacheBackend`] for `/status` and `/metrics`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L2StatusSnapshot {
    pub enabled: bool,
    pub endpoint_redacted: String,
    pub circuit_state: L2CircuitState,
    pub writer_queue_len: usize,
    pub writer_queue_capacity: usize,
    pub writer_queue_bytes: usize,
    pub writer_queue_max_bytes: usize,
    pub writes_dropped: u64,
    pub invalidation_connected: bool,
    pub actor_health: &'static str,
}

/// Object-safe async backend trait decoupling [`SharedResponseCache`] from Dragonfly transport.
pub trait L2CacheBackend: Send + Sync + 'static {
    /// Looks up `key` in L2, verifies canonical remote generations and size bounds, and
    /// decodes the `PRC2` frame into a local [`CachedResponse`].
    fn get<'a>(
        &'a self,
        key: &'a CacheKey,
        max_entry_bytes: usize,
    ) -> Pin<Box<dyn Future<Output = L2LookupOutcome> + Send + 'a>>;

    /// Enqueues a non-blocking write to L2 (`try_cast` + [`L2WriteBudget`]).
    fn enqueue_set(
        &self,
        key: CacheKey,
        entry: Arc<CachedResponse>,
        expected_remote_gen: Option<(u64, u64)>,
    );

    /// Asynchronously advances the remote generation for `namespace` and broadcasts invalidation.
    fn enqueue_invalidate_namespace(&self, namespace: &str);

    /// Asynchronously advances the global remote generation and broadcasts invalidation.
    fn enqueue_invalidate_all(&self);

    /// Returns a point-in-time health and queue snapshot.
    fn status_snapshot(&self) -> L2StatusSnapshot;

    /// Gracefully drains pending writes and shuts down background tasks.
    fn shutdown(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async {})
    }
}

#[derive(Clone)]
struct InMemorySlot {
    wire_bytes: Bytes,
    expires_at: Instant,
}

type InvalidationCallback = Arc<dyn Fn(L2InvalidationEvent) + Send + Sync>;

struct InMemoryClusterState {
    global_gen: u64,
    ns_gens: HashMap<String, u64>,
    entries: HashMap<String, InMemorySlot>,
    subscribers: Vec<(u64, InvalidationCallback)>,
}

/// Shared in-memory simulation of a Dragonfly cluster using the real `PRC2` codec
/// and multi-node Pub/Sub callbacks for deterministic integration tests.
pub struct InMemoryL2Cluster {
    state: Mutex<InMemoryClusterState>,
    next_node_id: AtomicU64,
    read_delay_ms: AtomicU64,
    fail_reads: AtomicBool,
    fail_writes: AtomicBool,
    get_calls: AtomicU64,
    set_calls: AtomicU64,
}

impl Default for InMemoryL2Cluster {
    fn default() -> Self {
        Self {
            state: Mutex::new(InMemoryClusterState {
                global_gen: 0,
                ns_gens: HashMap::new(),
                entries: HashMap::new(),
                subscribers: Vec::new(),
            }),
            next_node_id: AtomicU64::new(1),
            read_delay_ms: AtomicU64::new(0),
            fail_reads: AtomicBool::new(false),
            fail_writes: AtomicBool::new(false),
            get_calls: AtomicU64::new(0),
            set_calls: AtomicU64::new(0),
        }
    }
}

impl InMemoryL2Cluster {
    /// Creates an empty [`InMemoryL2Cluster`].
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Creates a node handle connected to this shared cluster.
    pub fn connect_node(
        self: &Arc<Self>,
        key_prefix: impl Into<String>,
        l1_max_ttl: Duration,
        read_timeout: Duration,
        compress_min_bytes: usize,
        max_write_queue_bytes: usize,
        on_invalidation: InvalidationCallback,
    ) -> Arc<InMemoryL2Backend> {
        let node_id = self.next_node_id.fetch_add(1, Ordering::Relaxed);
        {
            let mut guard = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.subscribers.push((node_id, on_invalidation));
        }
        Arc::new(InMemoryL2Backend {
            cluster: Arc::clone(self),
            node_id,
            key_prefix: key_prefix.into(),
            l1_max_ttl,
            read_timeout,
            compress_min_bytes,
            write_budget: L2WriteBudget::new(max_write_queue_bytes),
            circuit_breaker: L2CircuitBreaker::new(5, Duration::from_secs(10)),
            writes_dropped: AtomicU64::new(0),
            in_flight_writes: Arc::new(AtomicUsize::new(0)),
            write_notify: Arc::new(tokio::sync::Notify::new()),
        })
    }

    /// Injects artificial latency before cluster reads (for timeout / fail-open tests).
    pub fn set_read_delay(&self, delay: Duration) {
        let ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX);
        self.read_delay_ms.store(ms, Ordering::Release);
    }

    /// Forces all subsequent reads to fail as unavailable.
    pub fn set_fail_reads(&self, fail: bool) {
        self.fail_reads.store(fail, Ordering::Release);
    }

    /// Forces all subsequent writes to fail (tripping node circuit breakers).
    pub fn set_fail_writes(&self, fail: bool) {
        self.fail_writes.store(fail, Ordering::Release);
    }

    /// Simulates a full in-memory Dragonfly restart (`FLUSHALL` + generation reset to `0`, `K-07`).
    pub fn simulate_dragonfly_restart(&self) {
        let mut guard = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        guard.global_gen = 0;
        guard.ns_gens.clear();
        guard.entries.clear();
    }

    /// Returns total `get` operations executed against the cluster.
    pub fn get_calls(&self) -> u64 {
        self.get_calls.load(Ordering::Relaxed)
    }

    /// Returns total `set` operations persisted into the cluster.
    pub fn set_calls(&self) -> u64 {
        self.set_calls.load(Ordering::Relaxed)
    }
}

/// Per-node [`L2CacheBackend`] connected to an [`InMemoryL2Cluster`].
pub struct InMemoryL2Backend {
    cluster: Arc<InMemoryL2Cluster>,
    node_id: u64,
    key_prefix: String,
    l1_max_ttl: Duration,
    read_timeout: Duration,
    compress_min_bytes: usize,
    write_budget: Arc<L2WriteBudget>,
    circuit_breaker: L2CircuitBreaker,
    writes_dropped: AtomicU64,
    in_flight_writes: Arc<AtomicUsize>,
    write_notify: Arc<tokio::sync::Notify>,
}

impl InMemoryL2Backend {
    /// Waits until all background writes spawned via `enqueue_set` have finished.
    pub async fn flush_writes(&self) {
        while self.in_flight_writes.load(Ordering::Acquire) > 0 {
            let notified = self.write_notify.notified();
            if self.in_flight_writes.load(Ordering::Acquire) == 0 {
                break;
            }
            notified.await;
        }
    }

    /// Returns the number of writes rejected by [`L2WriteBudget`].
    pub fn writes_dropped(&self) -> u64 {
        self.writes_dropped.load(Ordering::Relaxed)
    }
}

impl L2CacheBackend for InMemoryL2Backend {
    fn get<'a>(
        &'a self,
        key: &'a CacheKey,
        max_entry_bytes: usize,
    ) -> Pin<Box<dyn Future<Output = L2LookupOutcome> + Send + 'a>> {
        Box::pin(async move {
            if !self.circuit_breaker.allow_request() {
                return L2LookupOutcome::Unavailable;
            }
            self.cluster.get_calls.fetch_add(1, Ordering::Relaxed);

            let delay_ms = self.cluster.read_delay_ms.load(Ordering::Acquire);
            if delay_ms > 0 {
                let delay = Duration::from_millis(delay_ms);
                if delay > self.read_timeout {
                    tokio::time::sleep(self.read_timeout).await;
                    self.circuit_breaker.record_failure();
                    return L2LookupOutcome::Unavailable;
                }
                tokio::time::sleep(delay).await;
            }

            if self.cluster.fail_reads.load(Ordering::Acquire) {
                self.circuit_breaker.record_failure();
                return L2LookupOutcome::Unavailable;
            }

            let entry_key = encode_l2_entry_key(key, &self.key_prefix);
            let ns_gen_key = encode_l2_ns_gen_key(&key.namespace, &self.key_prefix);

            let (remote_gen, slot_opt) = {
                let mut guard = self
                    .cluster
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let global_gen = guard.global_gen;
                let ns_gen = guard.ns_gens.get(&ns_gen_key).copied().unwrap_or(0);
                let slot = guard.entries.get(&entry_key).cloned();
                if let Some(ref s) = slot
                    && Instant::now() >= s.expires_at
                {
                    guard.entries.remove(&entry_key);
                    ((global_gen, ns_gen), None)
                } else {
                    ((global_gen, ns_gen), slot)
                }
            };

            self.circuit_breaker.record_success();

            let Some(slot) = slot_opt else {
                return L2LookupOutcome::Miss {
                    observed_remote_gen: Some(remote_gen),
                };
            };

            let remaining = slot.expires_at.saturating_duration_since(Instant::now());
            if remaining < MIN_L2_HIT_REMAINING_TTL {
                return L2LookupOutcome::Miss {
                    observed_remote_gen: Some(remote_gen),
                };
            }
            let pttl_ms = u64::try_from(remaining.as_millis()).unwrap_or(u64::MAX);

            let Ok(decoded) = decode_wire_v1(slot.wire_bytes, max_entry_bytes).await else {
                return L2LookupOutcome::Miss {
                    observed_remote_gen: Some(remote_gen),
                };
            };

            if decoded.remote_gen != remote_gen {
                return L2LookupOutcome::Miss {
                    observed_remote_gen: Some(remote_gen),
                };
            }

            let entry = Arc::new(decoded.into_cached_response(pttl_ms, self.l1_max_ttl));
            L2LookupOutcome::Hit {
                entry,
                remote_gen,
                pttl_ms,
            }
        })
    }

    fn enqueue_set(
        &self,
        key: CacheKey,
        entry: Arc<CachedResponse>,
        expected_remote_gen: Option<(u64, u64)>,
    ) {
        if entry.ttl < MIN_L2_WRITE_TTL {
            return;
        }
        let Some(permit) = self.write_budget.try_reserve(entry.byte_weight as usize) else {
            self.writes_dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };

        let cluster = Arc::clone(&self.cluster);
        let key_prefix = self.key_prefix.clone();
        let compress_min_bytes = self.compress_min_bytes;
        let in_flight = Arc::clone(&self.in_flight_writes);
        let notify = Arc::clone(&self.write_notify);
        let cb_open = self.circuit_breaker.state() == L2CircuitState::Open;
        if cb_open {
            drop(permit);
            return;
        }

        in_flight.fetch_add(1, Ordering::AcqRel);
        tokio::spawn(async move {
            let _permit = permit;
            if !cluster.fail_writes.load(Ordering::Acquire) {
                let entry_key = encode_l2_entry_key(&key, &key_prefix);
                let ns_gen_key = encode_l2_ns_gen_key(&key.namespace, &key_prefix);
                let remote_gen = match expected_remote_gen {
                    Some(g) => g,
                    None => {
                        let guard = cluster
                            .state
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        (
                            guard.global_gen,
                            guard.ns_gens.get(&ns_gen_key).copied().unwrap_or(0),
                        )
                    }
                };
                if let Ok(wire_bytes) =
                    encode_wire_v1(&entry, remote_gen, compress_min_bytes).await
                {
                    let expires_at = Instant::now() + entry.ttl;
                    let mut guard = cluster
                        .state
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    guard.entries.insert(
                        entry_key,
                        InMemorySlot {
                            wire_bytes,
                            expires_at,
                        },
                    );
                    cluster.set_calls.fetch_add(1, Ordering::Relaxed);
                }
            }
            if in_flight.fetch_sub(1, Ordering::AcqRel) == 1 {
                notify.notify_waiters();
            }
        });
    }

    fn enqueue_invalidate_namespace(&self, namespace: &str) {
        let ns_gen_key = encode_l2_ns_gen_key(namespace, &self.key_prefix);
        let callbacks: Vec<InvalidationCallback> = {
            let mut guard = self
                .cluster
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            let counter = guard.ns_gens.entry(ns_gen_key).or_insert(0);
            *counter += 1;
            guard
                .subscribers
                .iter()
                .filter(|(id, _)| *id != self.node_id)
                .map(|(_, cb)| Arc::clone(cb))
                .collect()
        };
        let event = L2InvalidationEvent::Namespace(namespace.to_string());
        for cb in callbacks {
            cb(event.clone());
        }
    }

    fn enqueue_invalidate_all(&self) {
        let callbacks: Vec<InvalidationCallback> = {
            let mut guard = self
                .cluster
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            guard.global_gen += 1;
            guard
                .subscribers
                .iter()
                .filter(|(id, _)| *id != self.node_id)
                .map(|(_, cb)| Arc::clone(cb))
                .collect()
        };
        for cb in callbacks {
            cb(L2InvalidationEvent::All);
        }
    }

    fn status_snapshot(&self) -> L2StatusSnapshot {
        L2StatusSnapshot {
            enabled: true,
            endpoint_redacted: format!("memory://node-{}", self.node_id),
            circuit_state: self.circuit_breaker.state(),
            writer_queue_len: self.in_flight_writes.load(Ordering::Acquire),
            writer_queue_capacity: 256,
            writer_queue_bytes: self.write_budget.used_bytes(),
            writer_queue_max_bytes: self.write_budget.max_bytes(),
            writes_dropped: self.writes_dropped.load(Ordering::Relaxed),
            invalidation_connected: true,
            actor_health: "Healthy",
        }
    }

    fn shutdown(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(self.flush_writes())
    }
}

// ============================================================================
//  Unit Tests (L2Cache.md Abschnitt 10.2)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use async_compression::tokio::bufread::GzipEncoder as TestGzipEncoder;
    use smallvec::SmallVec;

    fn sample_key() -> CacheKey {
        CacheKey {
            namespace: Arc::from("catalog"),
            generation: (12, 34),
            scope: CacheScope::Public,
            method: "GET",
            path_and_query: Arc::from("/api/items?page=1&sort=asc"),
            vary_values: SmallVec::from_buf([
                (Arc::from("x-tenant"), "acme".to_string()),
                (Arc::from("accept-language"), "de".to_string()),
            ]),
            scope_key: Arc::from(""),
            body_hash: None,
            post_encoding: None,
        }
    }

    #[test]
    fn test_l2_key_encoding_determinism_isolation_and_no_plaintext_leak() {
        let key_a = sample_key();
        let mut key_b = key_a.clone();
        // K-01: Local generation must NOT alter the L2 slot key
        key_b.generation = (0, 0);
        // Vary ordering differences must canonicalize identically
        key_b.vary_values.reverse();

        let encoded_a = encode_l2_entry_key(&key_a, "praeco");
        let encoded_b = encode_l2_entry_key(&key_b, "praeco");
        assert_eq!(encoded_a, encoded_b);

        let ns_tag = encode_namespace_tag("catalog");
        assert_eq!(ns_tag.len(), 64);
        assert!(ns_tag.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        assert!(encoded_a.starts_with(&format!("praeco:v1:e:{{{ns_tag}}}:")));
        assert!(!encoded_a.contains("catalog"));
        assert!(!encoded_a.contains("/api/items"));
        assert!(!encoded_a.contains("acme"));

        // Different scope, method, query, scope_key, body_hash, or post_encoding must produce distinct keys
        let mut diff_scope = key_a.clone();
        diff_scope.scope = CacheScope::PerRole;
        diff_scope.scope_key = Arc::from("admin");
        assert_ne!(encoded_a, encode_l2_entry_key(&diff_scope, "praeco"));

        let mut diff_post = key_a.clone();
        diff_post.method = "POST";
        diff_post.body_hash = Some([7u8; 32]);
        diff_post.post_encoding = Some((
            "application/json".to_string(),
            "identity".to_string(),
            "".to_string(),
        ));
        let post_key_1 = encode_l2_entry_key(&diff_post, "praeco");
        diff_post.body_hash = Some([8u8; 32]);
        let post_key_2 = encode_l2_entry_key(&diff_post, "praeco");
        assert_ne!(encoded_a, post_key_1);
        assert_ne!(post_key_1, post_key_2);
    }

    #[tokio::test]
    async fn test_prc2_wire_roundtrip_identity_gzip_brotli_and_grpc_trailers() {
        // 1. Multi-value HTTP headers + background GzipEncoder compression
        let mut headers = HeaderMap::new();
        headers.insert("content-type", HeaderValue::from_static("application/json"));
        headers.append("x-multi", HeaderValue::from_static("one"));
        headers.append("x-multi", HeaderValue::from_static("two"));
        let large_body = Bytes::from(vec![b'A'; 4096]);

        let entry = CachedResponse::new_for_test(
            StatusCode::OK,
            headers,
            large_body.clone(),
            None,
            Duration::from_secs(60),
        );
        let wire_gz = encode_wire_v1(&entry, (3, 9), 1024).await.unwrap();
        assert_eq!(wire_gz[5], WireBodyEncoding::Gzip as u8);
        assert!(wire_gz.len() < large_body.len());

        let decoded = decode_wire_v1(wire_gz, 64 * 1024).await.unwrap();
        assert_eq!(decoded.remote_gen, (3, 9));
        assert_eq!(decoded.original_ttl_ms, 60_000);
        assert_eq!(decoded.status, StatusCode::OK);
        assert_eq!(decoded.body, large_body);
        assert!(decoded.trailers.is_none());
        let multi: Vec<&str> = decoded
            .headers
            .get_all("x-multi")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(multi, vec!["one", "two"]);

        // 2. Identity when below compress_min_bytes or compression disabled
        let small_entry = CachedResponse::new_for_test(
            StatusCode::OK,
            HeaderMap::new(),
            Bytes::from_static(b"tiny"),
            None,
            Duration::from_secs(10),
        );
        let wire_id = encode_wire_v1(&small_entry, (1, 1), 1024).await.unwrap();
        assert_eq!(wire_id[5], WireBodyEncoding::Identity as u8);
        let dec_small = decode_wire_v1(wire_id, 64 * 1024).await.unwrap();
        assert_eq!(dec_small.body, Bytes::from_static(b"tiny"));

        // 3. OnceCell Brotli reuse + Unary gRPC with trailers
        let br_entry = CachedResponse::new_for_test(
            StatusCode::OK,
            HeaderMap::new(),
            Bytes::from("hello brotli cache world! ".repeat(64)),
            None,
            Duration::from_secs(30),
        );
        assert!(br_entry.ensure_br_for_test().await);
        let wire_br = encode_wire_v1(&br_entry, (2, 5), 0).await.unwrap();
        assert_eq!(wire_br[5], WireBodyEncoding::Brotli as u8);
        let dec_br = decode_wire_v1(wire_br, 64 * 1024).await.unwrap();
        assert_eq!(dec_br.body, br_entry.body);

        let mut grpc_headers = HeaderMap::new();
        grpc_headers.insert("content-type", HeaderValue::from_static("application/grpc"));
        let mut grpc_trailers = HeaderMap::new();
        grpc_trailers.insert("grpc-status", HeaderValue::from_static("0"));
        let grpc_payload = Bytes::from_static(b"\x00\x00\x00\x00\x03abc");
        let grpc_entry = CachedResponse::new_for_test(
            StatusCode::OK,
            grpc_headers,
            grpc_payload.clone(),
            Some(grpc_trailers),
            Duration::from_secs(20),
        );
        let wire_grpc = encode_wire_v1(&grpc_entry, (4, 7), 1).await.unwrap();
        assert_eq!(wire_grpc[5], WireBodyEncoding::Identity as u8);
        let dec_grpc = decode_wire_v1(wire_grpc, 64 * 1024).await.unwrap();
        assert_eq!(dec_grpc.body, grpc_payload);
        assert_eq!(
            dec_grpc
                .trailers
                .as_ref()
                .and_then(|t| t.get("grpc-status"))
                .and_then(|v| v.to_str().ok()),
            Some("0")
        );
    }

    #[tokio::test]
    async fn test_prc2_corrupt_frames_oversized_and_zip_bomb_rejected() {
        let entry = CachedResponse::new_for_test(
            StatusCode::OK,
            HeaderMap::new(),
            Bytes::from(vec![b'Z'; 4096]),
            None,
            Duration::from_secs(30),
        );
        let valid = encode_wire_v1(&entry, (1, 2), 64).await.unwrap();

        // Corrupt magic
        let mut bad_magic = valid.to_vec();
        bad_magic[0] = b'X';
        assert_eq!(
            decode_wire_v1(Bytes::from(bad_magic), 64 * 1024)
                .await
                .unwrap_err(),
            L2WireError::InvalidMagic
        );

        // Unsupported version
        let mut bad_ver = valid.to_vec();
        bad_ver[4] = 99;
        assert_eq!(
            decode_wire_v1(Bytes::from(bad_ver), 64 * 1024)
                .await
                .unwrap_err(),
            L2WireError::UnsupportedVersion(99)
        );

        // Unknown flags
        let mut bad_flags = valid.to_vec();
        bad_flags[5] = 0x7f;
        assert_eq!(
            decode_wire_v1(Bytes::from(bad_flags), 64 * 1024)
                .await
                .unwrap_err(),
            L2WireError::UnknownFlags(0x7f)
        );

        // Truncated frame
        assert!(matches!(
            decode_wire_v1(valid.slice(..valid.len() - 5), 64 * 1024).await,
            Err(L2WireError::LengthMismatch { .. }) | Err(L2WireError::TooShort { .. })
        ));

        // 0-ns uncompressed_body_len > max_entry_bytes rejection before allocation/decompression
        assert_eq!(
            decode_wire_v1(valid.clone(), 1024).await.unwrap_err(),
            L2WireError::UncompressedBodyTooLarge {
                size: 4096,
                max: 1024
            }
        );

        // FrameTooLarge rejection
        let huge = Bytes::from(vec![0u8; MAX_WIRE_HEADER_OVERHEAD + 2048]);
        assert!(matches!(
            decode_wire_v1(huge, 1024).await,
            Err(L2WireError::FrameTooLarge { .. })
        ));

        // Zip-bomb test: header claims uncompressed_len = 512, but gzip stream expands to 64 KiB
        let bomb_raw = vec![0u8; 64 * 1024];
        let mut bomb_gz = Vec::new();
        TestGzipEncoder::new(std::io::Cursor::new(bomb_raw))
            .read_to_end(&mut bomb_gz)
            .await
            .unwrap();
        let mut bomb_frame = BytesMut::new();
        bomb_frame.put_slice(&WIRE_MAGIC);
        bomb_frame.put_u8(WIRE_VERSION);
        bomb_frame.put_u8(WireBodyEncoding::Gzip as u8);
        bomb_frame.put_u16_le(200);
        bomb_frame.put_u64_le(1);
        bomb_frame.put_u64_le(1);
        bomb_frame.put_u64_le(60_000);
        bomb_frame.put_u32_le(2); // headers_len = 2 (count = 0)
        bomb_frame.put_u16_le(0);
        bomb_frame.put_u32_le(0); // trailers_len = 0
        bomb_frame.put_u32_le(512); // deceptive claimed uncompressed length
        bomb_frame.put_u32_le(bomb_gz.len() as u32);
        bomb_frame.put_slice(&bomb_gz);

        assert_eq!(
            decode_wire_v1(bomb_frame.freeze(), 1024 * 1024)
                .await
                .unwrap_err(),
            L2WireError::LengthMismatch {
                expected: 512,
                actual: 513
            }
        );
    }

    #[tokio::test]
    async fn test_prc2_zero_copy_precompression_warmup_and_grpc_exclusion_g02() {
        let mut http_headers = HeaderMap::new();
        http_headers.insert("content-type", HeaderValue::from_static("text/plain"));
        let entry = CachedResponse::new_for_test(
            StatusCode::OK,
            http_headers,
            Bytes::from("precompressed L2 warmup payload! ".repeat(64)),
            None,
            Duration::from_secs(60),
        );
        assert!(entry.ensure_gzip_for_test().await);
        let wire = encode_wire_v1(&entry, (1, 1), 64).await.unwrap();
        let decoded = decode_wire_v1(wire, 64 * 1024).await.unwrap();
        let l1_entry = decoded.into_cached_response(15_000, Duration::from_secs(10));

        assert_eq!(l1_entry.ttl, Duration::from_secs(10));
        assert_eq!(l1_entry.initial_age, Duration::from_secs(45));
        assert!(l1_entry.peek_precompressed_gzip().is_some());
        assert!(l1_entry.peek_precompressed_br().is_none());

        // G-02: Even if a compressed slice is passed to from_l2_parts, gRPC / trailers must never populate OnceCell
        let mut grpc_headers = HeaderMap::new();
        grpc_headers.insert("content-type", HeaderValue::from_static("application/grpc"));
        let mut grpc_trailers = HeaderMap::new();
        grpc_trailers.insert("grpc-status", HeaderValue::from_static("0"));
        let grpc_l1 = CachedResponse::from_l2_parts(
            StatusCode::OK,
            grpc_headers,
            Bytes::from(vec![0u8; 256]),
            Some(grpc_trailers),
            Duration::from_secs(10),
            Duration::from_secs(5),
            Some(Bytes::from_static(b"fake-gz")),
            Some(Bytes::from_static(b"fake-br")),
        );
        assert!(grpc_l1.peek_precompressed_gzip().is_none());
        assert!(grpc_l1.peek_precompressed_br().is_none());
    }

    #[tokio::test]
    async fn test_l2_write_budget_atomic_reservation_exhaustion_and_raii_drop() {
        let budget = L2WriteBudget::new(1024);
        let p1 = budget.try_reserve(600).expect("first permit");
        assert_eq!(budget.used_bytes(), 600);
        assert!(budget.try_reserve(500).is_none(), "exceeds 1024 cap");
        let p2 = budget.try_reserve(424).expect("exact remaining");
        assert_eq!(budget.used_bytes(), 1024);

        drop(p1);
        assert_eq!(budget.used_bytes(), 424);
        drop(p2);
        assert_eq!(budget.used_bytes(), 0);

        // Concurrent contention test
        let mut tasks = Vec::new();
        for _ in 0..32 {
            let b = Arc::clone(&budget);
            tasks.push(tokio::spawn(async move {
                if let Some(permit) = b.try_reserve(128) {
                    tokio::task::yield_now().await;
                    drop(permit);
                }
            }));
        }
        for t in tasks {
            t.await.unwrap();
        }
        assert_eq!(budget.used_bytes(), 0);
    }

    #[tokio::test]
    async fn test_l2_circuit_breaker_transitions_and_single_half_open_probe() {
        let cb = L2CircuitBreaker::new(3, Duration::from_millis(40));
        assert_eq!(cb.state(), L2CircuitState::Closed);
        assert!(cb.allow_request());

        assert!(!cb.record_failure());
        assert!(!cb.record_failure());
        assert!(cb.record_failure(), "3rd failure trips circuit open");
        assert_eq!(cb.state(), L2CircuitState::Open);
        assert!(!cb.allow_request());

        tokio::time::sleep(Duration::from_millis(55)).await;
        assert_eq!(cb.state(), L2CircuitState::HalfOpen);
        assert!(cb.allow_request(), "single HalfOpen probe allowed");
        assert!(!cb.allow_request(), "second concurrent probe must wait");

        // Probe failure re-opens immediately
        assert!(cb.record_failure());
        assert_eq!(cb.state(), L2CircuitState::Open);

        tokio::time::sleep(Duration::from_millis(55)).await;
        assert!(cb.allow_request());
        cb.record_success();
        assert_eq!(cb.state(), L2CircuitState::Closed);
        assert!(cb.allow_request());
    }

    #[tokio::test]
    async fn test_in_memory_l2_cluster_roundtrip_multi_node_invalidation_and_restart() {
        let cluster = InMemoryL2Cluster::new();
        let node_a_events = Arc::new(Mutex::new(Vec::new()));
        let node_b_events = Arc::new(Mutex::new(Vec::new()));

        let node_a_ev_ref = Arc::clone(&node_a_events);
        let node_a = cluster.connect_node(
            "praeco",
            Duration::from_secs(15),
            Duration::from_millis(50),
            512,
            1024 * 1024,
            Arc::new(move |ev| node_a_ev_ref.lock().unwrap().push(ev)),
        );

        let node_b_ev_ref = Arc::clone(&node_b_events);
        let node_b = cluster.connect_node(
            "praeco",
            Duration::from_secs(15),
            Duration::from_millis(50),
            512,
            1024 * 1024,
            Arc::new(move |ev| node_b_ev_ref.lock().unwrap().push(ev)),
        );

        let key = sample_key();
        assert!(matches!(
            node_a.get(&key, 64 * 1024).await,
            L2LookupOutcome::Miss {
                observed_remote_gen: Some((0, 0))
            }
        ));

        let entry = Arc::new(CachedResponse::new_for_test(
            StatusCode::OK,
            HeaderMap::new(),
            Bytes::from("shared cluster payload ".repeat(40)),
            None,
            Duration::from_secs(60),
        ));
        node_a.enqueue_set(key.clone(), entry, Some((0, 0)));
        node_a.flush_writes().await;

        // Node B reads with cold local generation (0, 0) and still gets HIT
        let mut node_b_key = key.clone();
        node_b_key.generation = (0, 0);
        match node_b.get(&node_b_key, 64 * 1024).await {
            L2LookupOutcome::Hit {
                entry: hit_entry,
                remote_gen,
                pttl_ms,
            } => {
                assert_eq!(remote_gen, (0, 0));
                assert!(pttl_ms >= 59_000);
                assert_eq!(hit_entry.ttl, Duration::from_secs(15));
                assert!(hit_entry.body.starts_with(b"shared cluster payload"));
            }
            other => panic!("expected L2 HIT on node_b, got {other:?}"),
        }

        // Invalidation on Node A notifies Node B (without self-echo) and invalidates slot
        node_a.enqueue_invalidate_namespace("catalog");
        assert!(node_a_events.lock().unwrap().is_empty());
        assert_eq!(
            *node_b_events.lock().unwrap(),
            vec![L2InvalidationEvent::Namespace("catalog".to_string())]
        );
        assert!(matches!(
            node_b.get(&node_b_key, 64 * 1024).await,
            L2LookupOutcome::Miss {
                observed_remote_gen: Some((0, 1))
            }
        ));

        // Simulate Dragonfly restart -> remote generations reset back to (0, 0)
        cluster.simulate_dragonfly_restart();
        assert!(matches!(
            node_b.get(&node_b_key, 64 * 1024).await,
            L2LookupOutcome::Miss {
                observed_remote_gen: Some((0, 0))
            }
        ));
    }
}
