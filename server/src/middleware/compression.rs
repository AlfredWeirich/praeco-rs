//! # Compression & Decompression Middleware
//!
//! This module provides two independent Tower middleware layers:
//!
//! 1. **[`SrvCompressionLayer`]** – Compresses **response** bodies using Gzip
//!    or Brotli, based on the client's `Accept-Encoding` header.
//! 2. **[`SrvDecompressionLayer`]** – Decompresses **request** bodies using
//!    Gzip or Brotli, based on the `Content-Encoding` header.
//!
//! ## Decompression Bomb Protection
//!
//! The decompression layer includes a [`LimitedReader`] wrapper that aborts
//! the decompression stream if the decompressed output exceeds
//! `max_decompressed_bytes`, defending against
//! [zip bomb attacks](https://en.wikipedia.org/wiki/Zip_bomb).
//!
//! ## Streaming Architecture
//!
//! Both layers operate in a streaming fashion:
//!
//! ```text
//! Body → BodyStream → filter_map(data frames) → StreamReader
//!      → Encoder/Decoder → ReaderStream → StreamBody → SrvBody
//! ```
//!
//! This avoids buffering the entire body in memory.

// Example curl commands for testing:
// echo '{"status": "updated", "id": 123}' | gzip | curl -v --http2 -X PUT --cert client_certs/client.cert.pem --key client_certs/client.key.pem --cacert server_certs/self_signed/myca.pem -H "Authorization: Bearer $(cat ./jwt/token1.jwt)" -H "Content-Type: application/json" -H "Content-Encoding: gzip" --data-binary @- https://192.168.178.175:1337/ -H "Accept-Encoding: gzip" --output ./out.gz
// cat out.gz | gunzip
// oder
// echo '{"status": "updated", "id": 123}' | gzip | curl -v --http2 -X PUT \
//   --cert client_certs/client.cert.pem \
//   --key client_certs/client.key.pem \
//   --cacert server_certs/self_signed/myca.pem \
//   -H "Authorization: Bearer $(cat ./jwt/token1.jwt)" \
//   -H "Content-Type: application/json" \
//   -H "Content-Encoding: gzip" \
//   --data-binary @- \
//   --compressed \
//   --output ./out.json \
//   https://192.168.178.175:1337/

// === Standard Library ===
use std::{
    future::Future,
    io,
    pin::Pin,
    task::{Context, Poll},
};

// === External Crates ===
use async_compression::tokio::bufread::{BrotliDecoder, BrotliEncoder, GzipDecoder, GzipEncoder};
use futures_util::StreamExt;
use http_body::Frame;
use http_body_util::{BodyExt, BodyStream, StreamBody};
use hyper::{
    Request, Response,
    header::{ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH},
};
use pin_project::pin_project;
use tokio::io::{AsyncRead, ReadBuf};
use tokio_util::io::{ReaderStream, StreamReader};
use tower::{Layer, Service};

// === Internal Modules ===
use crate::{SrvBody, SrvError};

// ============================================================================
//  COMPRESSION LAYER (Outgoing Responses)
// ============================================================================

/// A Tower [`Layer`] for **response** compression.
///
/// Supports **Gzip** and **Brotli** based on the client's `Accept-Encoding` header.
/// Gzip is preferred when both are present.
#[derive(Clone)]
pub struct SrvCompressionLayer {
    /// Server name label for tracing output.
    server_name: &'static str,
}
impl SrvCompressionLayer {
    /// Create a new `SrvCompressionLayer` with a server name for logging.
    pub fn new(server_name: &'static str) -> Self {
        Self { server_name }
    }
}

impl<S> Layer<S> for SrvCompressionLayer {
    type Service = SrvCompressionService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SrvCompressionService {
            inner,
            server_name: self.server_name,
        }
    }
}

/// Service that compresses response bodies based on `Accept-Encoding`.
///
/// When a supported encoding is found, this service:
/// 1. Removes the `Content-Length` header (the compressed size is unknown
///    ahead of time in a streaming context).
/// 2. Sets `Content-Encoding` to `gzip` or `br`.
/// 3. Pipes the response body through the appropriate encoder as a stream.
#[derive(Clone)]
pub struct SrvCompressionService<S> {
    /// The inner (downstream) service.
    inner: S,
    /// Server name label for tracing.
    server_name: &'static str,
}

impl<S> Service<Request<SrvBody>> for SrvCompressionService<S>
where
    S: Service<Request<SrvBody>, Response = Response<SrvBody>> + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<SrvError>,
{
    type Response = Response<SrvBody>;
    type Error = SrvError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    /// Compresses the response body if the client accepts Gzip or Brotli.
    ///
    /// ## Algorithm Selection
    ///
    /// Gzip is preferred over Brotli when both are present in the
    /// `Accept-Encoding` header, because Gzip is faster to compress at
    /// equivalent quality levels.
    ///
    /// ## Streaming Pipeline
    ///
    /// ```text
    /// Response body → BodyStream → data-only filter → StreamReader
    ///               → GzipEncoder/BrotliEncoder → ReaderStream
    ///               → StreamBody → boxed SrvBody
    /// ```
    fn call(&mut self, req: Request<SrvBody>) -> Self::Future {
        let server_name = self.server_name;

        // Capture the Accept-Encoding header before moving the request.
        let accept_header = req
            .headers()
            .get(ACCEPT_ENCODING)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();

        let fut = self.inner.call(req);

        Box::pin(async move {
            let mut resp = fut.await.map_err(Into::into)?;

            // Determine which compression algorithm to use (if any).
            let algo = if accept_header.contains("gzip") {
                Some("gzip")
            } else if accept_header.contains("br") {
                Some("br")
            } else {
                None
            };

            if let Some(encoding) = algo {
                tracing::trace!("{}: Compressing body with {}", server_name, encoding);
                // Content-Length is unknown for a streaming compressed body.
                resp.headers_mut().remove(CONTENT_LENGTH);
                resp.headers_mut().insert(
                    CONTENT_ENCODING,
                    hyper::header::HeaderValue::from_static(if encoding == "gzip" {
                        "gzip"
                    } else {
                        "br"
                    }),
                );

                let (parts, body) = resp.into_parts();

                // 1. Prepare Reader: convert the body into an AsyncRead stream.
                let body_stream = BodyStream::new(body);
                let data_stream = body_stream.filter_map(|r| async {
                    match r {
                        Ok(frame) => frame.into_data().ok().map(Ok),
                        Err(e) => Some(Err(io::Error::other(e))),
                    }
                });
                let body_reader = StreamReader::new(Box::pin(data_stream));

                // 2. Compress & Wrap in Frames
                let new_body: SrvBody = if encoding == "gzip" {
                    let encoder = GzipEncoder::new(body_reader);
                    let stream = ReaderStream::new(encoder).map(|res| res.map(Frame::data));
                    tracing::trace!("{}: Compress response with GZip", server_name);
                    StreamBody::new(stream)
                        // FIX: Explicit type annotation for 'e'
                        .map_err(|e: io::Error| SrvError::Other(e.to_string()))
                        .boxed()
                } else {
                    let encoder = BrotliEncoder::new(body_reader);
                    let stream = ReaderStream::new(encoder).map(|res| res.map(Frame::data));
                    tracing::trace!("{}: Compress response with Brotli", server_name);
                    StreamBody::new(stream)
                        // FIX: Explicit type annotation for 'e'
                        .map_err(|e: io::Error| SrvError::Other(e.to_string()))
                        .boxed()
                };

                Ok(Response::from_parts(parts, new_body))
            } else {
                // No compression requested — pass the response through unchanged.
                Ok(resp)
            }
        })
    }
}

// ============================================================================
//  DECOMPRESSION LAYER (Incoming Requests)
// ============================================================================

// echo '{"status": "updated", "id": 123}' | gzip | curl -v --http2 -X PUT --cert client_certs/client.cert.pem --key client_certs/client.key.pem --cacert server_certs/self_signed/myca.pem -H "Authorization: Bearer $(cat ./jwt/token1.jwt)" -H "Content-Type: application/json" -H "Content-Encoding: gzip" --data-binary @- https://192.168.178.175:1337/

/// A Tower [`Layer`] for **request** decompression.
///
/// Automatically decompresses Gzip and Brotli encoded request bodies.
/// Includes a bomb protection limit: if the decompressed output exceeds
/// `max_decompressed_bytes`, the stream is aborted with an error.
#[derive(Clone)]
pub struct SrvDecompressionLayer {
    /// Server name label for tracing output.
    server_name: &'static str,
    /// Maximum allowed size of the decompressed body (in bytes).
    /// Exceeding this limit aborts the decompression stream.
    max_decompressed_bytes: usize,
}
impl SrvDecompressionLayer {
    /// Create a new `SrvDecompressionLayer`.
    ///
    /// # Arguments
    ///
    /// * `server_name` – A `'static` label for tracing output.
    /// * `max_decompressed_bytes` – Upper bound on the decompressed body size.
    ///   If exceeded, the stream returns an I/O error (bomb protection).
    pub fn new(server_name: &'static str, max_decompressed_bytes: usize) -> Self {
        Self {
            server_name,
            max_decompressed_bytes,
        }
    }
}

impl<S> Layer<S> for SrvDecompressionLayer {
    type Service = SrvDecompressionService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        SrvDecompressionService {
            inner,
            server_name: self.server_name,
            max_decompressed_bytes: self.max_decompressed_bytes,
        }
    }
}

/// Service that decompresses incoming request bodies.
///
/// On each request it inspects the `Content-Encoding` header:
/// * `"gzip"` → pipes through [`GzipDecoder`] + [`LimitedReader`].
/// * `"br"`   → pipes through [`BrotliDecoder`] + [`LimitedReader`].
/// * Anything else → passes the request through unchanged.
///
/// After decompression, the `Content-Encoding` and `Content-Length` headers
/// are removed (they no longer reflect the actual body).
#[derive(Clone)]
pub struct SrvDecompressionService<S> {
    /// The inner (downstream) service.
    inner: S,
    /// Server name label for tracing.
    server_name: &'static str,
    /// Maximum allowed decompressed body size (bomb protection).
    max_decompressed_bytes: usize,
}

impl<S> Service<Request<SrvBody>> for SrvDecompressionService<S>
where
    S: Service<Request<SrvBody>, Response = Response<SrvBody>> + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<SrvError>,
{
    type Response = Response<SrvBody>;
    type Error = SrvError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx).map_err(Into::into)
    }

    /// Decompresses the request body (if applicable) and forwards the request.
    ///
    /// ## Streaming Pipeline
    ///
    /// ```text
    /// Request body → BodyStream → data-only filter → StreamReader
    ///              → GzipDecoder/BrotliDecoder → LimitedReader
    ///              → ReaderStream → StreamBody → boxed SrvBody
    /// ```
    ///
    /// The [`LimitedReader`] wrapper aborts with an `io::Error` if the
    /// decompressed output exceeds `max_decompressed_bytes`.
    fn call(&mut self, mut req: Request<SrvBody>) -> Self::Future {
        let server_name = self.server_name;
        let max_bytes = self.max_decompressed_bytes;

        // Inspect the Content-Encoding header to decide whether decompression
        // is needed.
        let encoding = req
            .headers()
            .get(CONTENT_ENCODING)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();

        if encoding == "gzip" || encoding == "br" {
            let (parts, body) = req.into_parts();
            tracing::trace!(
                "{}: Decompressing body: {} (max {} bytes)",
                server_name,
                encoding,
                max_bytes
            );

            // 1. Prepare Reader: convert body frames into an AsyncRead stream.
            let body_stream = BodyStream::new(body);
            let data_stream = body_stream.filter_map(|r| async {
                match r {
                    Ok(frame) => frame.into_data().ok().map(Ok),
                    Err(e) => Some(Err(io::Error::other(e))),
                }
            });
            let body_reader = StreamReader::new(Box::pin(data_stream));

            // 2. Decompress & Wrap in LimitedReader for bomb protection
            let new_body: SrvBody = if encoding == "gzip" {
                let decoder = GzipDecoder::new(body_reader);
                let limited = LimitedReader::new(decoder, max_bytes);
                let stream = ReaderStream::new(limited).map(|res| res.map(Frame::data));

                StreamBody::new(stream)
                    // FIX: Explicit type annotation for 'e'
                    .map_err(|e: io::Error| SrvError::Other(e.to_string()))
                    .boxed()
            } else {
                let decoder = BrotliDecoder::new(body_reader);
                let limited = LimitedReader::new(decoder, max_bytes);
                let stream = ReaderStream::new(limited).map(|res| res.map(Frame::data));

                StreamBody::new(stream)
                    // FIX: Explicit type annotation for 'e'
                    .map_err(|e: io::Error| SrvError::Other(e.to_string()))
                    .boxed()
            };

            // Rebuild the request with the decompressed body and remove
            // headers that no longer apply.
            let mut new_req = Request::from_parts(parts, new_body);
            new_req.headers_mut().remove(CONTENT_ENCODING);
            new_req.headers_mut().remove(CONTENT_LENGTH);

            req = new_req;
        }

        let fut = self.inner.call(req);
        Box::pin(async move { fut.await.map_err(Into::into) })
    }
}

// ============================================================================
//  LIMITED READER — Decompression Bomb Protection
// ============================================================================

/// A wrapper around an [`AsyncRead`] that enforces a maximum number of bytes.
///
/// If the inner reader produces more than `remaining` bytes in total,
/// subsequent reads return an [`io::Error`], aborting the decompression.
/// This prevents a malicious compressed payload from expanding into an
/// arbitrarily large buffer in memory.
#[pin_project]
struct LimitedReader<R> {
    /// The underlying async reader (decoder).
    #[pin]
    inner: R,
    /// Number of bytes still allowed before the limit is hit.
    remaining: usize,
}

impl<R> LimitedReader<R> {
    /// Creates a new `LimitedReader` that will allow at most `max_bytes`
    /// of decompressed output before returning an error.
    fn new(inner: R, max_bytes: usize) -> Self {
        Self {
            inner,
            remaining: max_bytes,
        }
    }
}

impl<R: AsyncRead> AsyncRead for LimitedReader<R> {
    /// Polls the inner reader and tracks the cumulative bytes produced.
    ///
    /// Returns `Err` if the total exceeds the configured limit.
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // If the limit has already been reached, reject immediately.
        if self.remaining == 0 {
            return Poll::Ready(Err(io::Error::other(
                "Decompressed payload exceeds maximum allowed size",
            )));
        }

        let this = self.project();
        let before = buf.filled().len();

        match this.inner.poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let bytes_read = buf.filled().len() - before;
                if bytes_read > *this.remaining {
                    // Limit exceeded — zero out remaining and return an error.
                    *this.remaining = 0;
                    Poll::Ready(Err(io::Error::other(
                        "Decompressed payload exceeds maximum allowed size",
                    )))
                } else {
                    *this.remaining -= bytes_read;
                    Poll::Ready(Ok(()))
                }
            }
            other => other,
        }
    }
}
