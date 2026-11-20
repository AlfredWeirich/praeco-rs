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
    header::{ACCEPT_ENCODING, CONTENT_ENCODING, CONTENT_LENGTH, VARY},
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

#[pin_project]
pub struct SrvCompressionFuture<F> {
    #[pin]
    inner: F,
    server_name: &'static str,
    accept_encoding: String,
    is_head_request: bool,
}

/// Checks whether `accept_encoding` permits `target_coding` with a quality value `q > 0`.
fn accepts_coding(accept_encoding: &str, target_coding: &str) -> bool {
    for item in accept_encoding.split(',') {
        let mut parts = item.trim().split(';');
        let Some(coding) = parts.next().map(str::trim) else {
            continue;
        };
        if !coding.eq_ignore_ascii_case(target_coding) {
            continue;
        }
        let mut allowed = true;
        for param in parts {
            if let Some((k, v)) = param.trim().split_once('=')
                && k.trim().eq_ignore_ascii_case("q")
                && let Ok(q) = v.trim().parse::<f32>()
                && q <= 0.0
            {
                allowed = false;
            }
        }
        if allowed {
            return true;
        }
    }
    false
}

impl<F, E> Future for SrvCompressionFuture<F>
where
    F: Future<Output = Result<Response<SrvBody>, E>>,
    E: Into<SrvError>,
{
    type Output = Result<Response<SrvBody>, SrvError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let result = std::task::ready!(this.inner.poll(cx));
        
        let mut resp = match result {
            Ok(r) => r,
            Err(e) => return Poll::Ready(Err(e.into())),
        };

        // Determine which compression algorithm to use (if any).
        let accept_header = this.accept_encoding;
        let server_name = *this.server_name;
        let status = resp.status();
        let is_bodiless_status = status.is_informational()
            || status == hyper::StatusCode::NO_CONTENT
            || status == hyper::StatusCode::NOT_MODIFIED;

        // Skip compression if the response is bodiless (HEAD / 1xx / 204 / 304),
        // already compressed, or is a gRPC stream (compressing a gRPC response body
        // strips HTTP/2 trailers like `grpc-status`).
        let already_encoded = resp.headers().contains_key(CONTENT_ENCODING);
        let is_grpc = resp
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|ct| ct.starts_with("application/grpc"));

        let algo = if *this.is_head_request || is_bodiless_status || already_encoded || is_grpc {
            None
        } else if accepts_coding(accept_header, "gzip") {
            Some("gzip")
        } else if accepts_coding(accept_header, "br") {
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
            append_vary_accept_encoding(resp.headers_mut());

            let (parts, body) = resp.into_parts();

            // 1. Prepare Reader: convert the body into an AsyncRead stream.
            let body_stream = BodyStream::new(body);
            let data_stream = body_stream.filter_map(|r| std::future::ready(
                match r {
                    Ok(frame) => frame.into_data().ok().map(Ok),
                    Err(e) => Some(Err(io::Error::other(e))),
                }
            ));
            let body_reader = StreamReader::new(data_stream);

            // 2. Compress & Wrap in Frames
            let new_body: SrvBody = if encoding == "gzip" {
                let encoder = GzipEncoder::new(body_reader);
                let stream = ReaderStream::new(encoder).map(|res| res.map(Frame::data));
                tracing::trace!("{}: Compress response with GZip", server_name);
                StreamBody::new(stream)
                    .map_err(|e: io::Error| SrvError::Other(e.to_string()))
                    .boxed()
            } else {
                let encoder = BrotliEncoder::new(body_reader);
                let stream = ReaderStream::new(encoder).map(|res| res.map(Frame::data));
                tracing::trace!("{}: Compress response with Brotli", server_name);
                StreamBody::new(stream)
                    .map_err(|e: io::Error| SrvError::Other(e.to_string()))
                    .boxed()
            };

            Poll::Ready(Ok(Response::from_parts(parts, new_body)))
        } else {
            Poll::Ready(Ok(resp))
        }
    }
}

impl<S> Service<Request<SrvBody>> for SrvCompressionService<S>
where
    S: Service<Request<SrvBody>, Response = Response<SrvBody>> + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<SrvError>,
{
    type Response = Response<SrvBody>;
    type Error = SrvError;
    type Future = SrvCompressionFuture<S::Future>;

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

        let is_head_request = req.method() == hyper::Method::HEAD;
        // Capture the Accept-Encoding header before moving the request.
        let accept_encoding = req
            .headers()
            .get(ACCEPT_ENCODING)
            .and_then(|h| h.to_str().ok())
            .unwrap_or("")
            .to_string();

        let fut = self.inner.call(req);

        SrvCompressionFuture {
            inner: fut,
            server_name,
            accept_encoding,
            is_head_request,
        }
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

#[pin_project]
pub struct SrvDecompressionFuture<F> {
    #[pin]
    inner: F,
}

impl<F, E> Future for SrvDecompressionFuture<F>
where
    F: Future<Output = Result<Response<SrvBody>, E>>,
    E: Into<SrvError>,
{
    type Output = Result<Response<SrvBody>, SrvError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let result = std::task::ready!(this.inner.poll(cx));
        Poll::Ready(result.map_err(Into::into))
    }
}

impl<S> Service<Request<SrvBody>> for SrvDecompressionService<S>
where
    S: Service<Request<SrvBody>, Response = Response<SrvBody>> + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Into<SrvError>,
{
    type Response = Response<SrvBody>;
    type Error = SrvError;
    type Future = SrvDecompressionFuture<S::Future>;

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
            .map(|s| s.trim().to_ascii_lowercase())
            .unwrap_or_default();

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
            let data_stream = body_stream.filter_map(|r| std::future::ready(
                match r {
                    Ok(frame) => frame.into_data().ok().map(Ok),
                    Err(e) => Some(Err(io::Error::other(e))),
                }
            ));
            let body_reader = StreamReader::new(data_stream);

            // 2. Decompress & Wrap in LimitedReader for bomb protection
            let new_body: SrvBody = if encoding == "gzip" {
                wrap_decompressed_reader(GzipDecoder::new(body_reader), max_bytes, server_name)
            } else {
                wrap_decompressed_reader(BrotliDecoder::new(body_reader), max_bytes, server_name)
            };

            // Rebuild the request with the decompressed body and remove
            // headers that no longer apply.
            let mut new_req = Request::from_parts(parts, new_body);
            new_req.headers_mut().remove(CONTENT_ENCODING);
            new_req.headers_mut().remove(CONTENT_LENGTH);

            req = new_req;
        }

        let fut = self.inner.call(req);
        SrvDecompressionFuture { inner: fut }
    }
}

/// Ensures `Vary` includes `Accept-Encoding` so caches do not serve compressed responses to plain clients.
fn append_vary_accept_encoding(headers: &mut hyper::HeaderMap) {
    let already_has_accept_encoding = headers.get_all(VARY).iter().any(|val| {
        val.to_str()
            .is_ok_and(|s| s.split(',').any(|tok| tok.trim().eq_ignore_ascii_case("accept-encoding")))
    });
    if !already_has_accept_encoding {
        headers.append(VARY, hyper::header::HeaderValue::from_static("Accept-Encoding"));
    }
}

/// Wraps a decompressor [`AsyncRead`] in [`LimitedReader`] and converts limit errors
/// into [`SrvError::DecompressionLimitExceeded`] while recording [`ServerMetrics`].
fn wrap_decompressed_reader<R: AsyncRead + Send + Sync + 'static>(
    decoder: R,
    max_bytes: usize,
    server_name: &'static str,
) -> SrvBody {
    let limited = LimitedReader::new(decoder, max_bytes);
    let stream = ReaderStream::new(limited).map(|res| res.map(Frame::data));

    StreamBody::new(stream)
        .map_err(move |e: io::Error| {
            let msg = e.to_string();
            if msg.contains("Decompressed payload exceeds maximum allowed size") {
                crate::configuration::ServerMetrics::inc_decompression_limit_exceeded(server_name);
                SrvError::DecompressionLimitExceeded { max: max_bytes }
            } else {
                SrvError::Other(msg)
            }
        })
        .boxed()
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


// ============================================================================
//  TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http_body_util::{BodyExt, Full};
    use hyper::header::{CONTENT_TYPE, HeaderMap, HeaderValue};
    use tower::{ServiceExt, service_fn};

    const PAYLOAD: &[u8] = b"hello hello hello hello hello hello hello hello";

    fn full_body(data: &'static [u8]) -> SrvBody {
        Full::new(Bytes::from_static(data))
            .map_err(|never| match never {})
            .boxed()
    }

    /// Runs the compression service against an inner service that answers with the
    /// given `Content-Type` / `Content-Encoding` headers and returns the final response.
    async fn run(
        content_type: Option<&'static str>,
        content_encoding: Option<&'static str>,
        accept_encoding: &str,
        body: SrvBody,
    ) -> Response<SrvBody> {
        let body = std::sync::Mutex::new(Some(body));
        let inner = service_fn(move |_req: Request<SrvBody>| {
            let body = body.lock().unwrap().take().unwrap();
            async move {
                let mut builder = Response::builder();
                if let Some(ct) = content_type {
                    builder = builder.header(CONTENT_TYPE, ct);
                }
                if let Some(ce) = content_encoding {
                    builder = builder.header(CONTENT_ENCODING, ce);
                }
                Ok::<_, SrvError>(builder.body(body).unwrap())
            }
        });
        let svc = SrvCompressionLayer::new("test").layer(inner);
        let req = Request::builder()
            .header(ACCEPT_ENCODING, accept_encoding)
            .body(full_body(b""))
            .unwrap();
        svc.oneshot(req).await.unwrap()
    }

    #[tokio::test]
    async fn test_plain_response_is_gzip_compressed() {
        let resp = run(Some("application/json"), None, "gzip", full_body(PAYLOAD)).await;
        assert_eq!(resp.headers().get(CONTENT_ENCODING).unwrap(), "gzip");
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&bytes[..2], &[0x1f, 0x8b], "body must carry the gzip magic header");
    }

    #[tokio::test]
    async fn test_grpc_response_is_not_compressed() {
        let resp = run(Some("application/grpc"), None, "gzip", full_body(PAYLOAD)).await;
        assert!(resp.headers().get(CONTENT_ENCODING).is_none());
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&bytes[..], PAYLOAD);
    }

    #[tokio::test]
    async fn test_grpc_proto_subtype_is_not_compressed() {
        let resp = run(Some("application/grpc+proto"), None, "br, gzip", full_body(PAYLOAD)).await;
        assert!(resp.headers().get(CONTENT_ENCODING).is_none());
    }

    #[tokio::test]
    async fn test_already_encoded_response_is_not_double_compressed() {
        let resp = run(Some("application/json"), Some("br"), "gzip", full_body(PAYLOAD)).await;
        assert_eq!(resp.headers().get(CONTENT_ENCODING).unwrap(), "br");
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&bytes[..], PAYLOAD, "backend-encoded body must pass through untouched");
    }

    #[tokio::test]
    async fn test_grpc_trailers_survive_compression_layer() {
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("0"));
        let frames: Vec<Result<Frame<Bytes>, SrvError>> = vec![
            Ok(Frame::data(Bytes::from_static(PAYLOAD))),
            Ok(Frame::trailers(trailers)),
        ];
        let body: SrvBody = BodyExt::boxed(StreamBody::new(futures_util::stream::iter(frames)));

        let resp = run(Some("application/grpc"), None, "gzip", body).await;
        let collected = resp.into_body().collect().await.unwrap();
        let trailers = collected.trailers().cloned().expect("grpc trailers must be preserved");
        assert_eq!(trailers.get("grpc-status").unwrap(), "0");
    }

    #[tokio::test]
    async fn test_no_accept_encoding_leaves_response_untouched() {
        let resp = run(Some("application/json"), None, "", full_body(PAYLOAD)).await;
        assert!(resp.headers().get(CONTENT_ENCODING).is_none());
    }

    #[tokio::test]
    async fn test_decompression_bomb_limit_records_metric() {
        use async_compression::tokio::write::GzipEncoder;
        use tokio::io::AsyncWriteExt;

        let mut encoder = GzipEncoder::new(Vec::new());
        encoder.write_all(&[b'A'; 512]).await.unwrap();
        encoder.shutdown().await.unwrap();
        let compressed = encoder.into_inner();

        let inner = service_fn(|mut req: Request<SrvBody>| async move {
            let _ = req.body_mut().collect().await?;
            Ok::<Response<SrvBody>, SrvError>(Response::new(full_body(b"OK")))
        });

        let srv_name = "test_decompression_bomb_metrics";
        let svc = SrvDecompressionLayer::new(srv_name, 64).layer(inner);
        let req = Request::builder()
            .header(CONTENT_ENCODING, "gzip")
            .body(
                Full::new(Bytes::from(compressed))
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap();

        let err = svc.oneshot(req).await.expect_err("must abort decompression bomb");
        assert!(matches!(err, SrvError::DecompressionLimitExceeded { max: 64 }));

        let metrics = crate::configuration::ServerMetrics::for_server(srv_name);
        assert_eq!(
            metrics
                .decompression_limit_exceeded
                .load(std::sync::atomic::Ordering::Relaxed),
            1
        );
    }

    #[tokio::test]
    async fn test_compressed_response_sets_vary_accept_encoding() {
        let resp = run(Some("application/json"), None, "gzip", full_body(PAYLOAD)).await;
        assert_eq!(resp.headers().get(CONTENT_ENCODING).unwrap(), "gzip");
        let has_vary = resp
            .headers()
            .get_all(VARY)
            .iter()
            .any(|v| v.to_str().is_ok_and(|s| s.eq_ignore_ascii_case("Accept-Encoding")));
        assert!(has_vary, "compressed response must carry Vary: Accept-Encoding");
    }

    #[tokio::test]
    async fn test_decompression_exact_limit_succeeds_and_uppercase_header() {
        use async_compression::tokio::write::GzipEncoder;
        use tokio::io::AsyncWriteExt;

        let exact_payload = vec![b'X'; 64];
        let mut encoder = GzipEncoder::new(Vec::new());
        encoder.write_all(&exact_payload).await.unwrap();
        encoder.shutdown().await.unwrap();
        let compressed = encoder.into_inner();

        let inner = service_fn(|mut req: Request<SrvBody>| async move {
            let collected = req.body_mut().collect().await?.to_bytes();
            assert_eq!(collected.len(), 64);
            Ok::<Response<SrvBody>, SrvError>(Response::new(full_body(b"OK")))
        });

        let svc = SrvDecompressionLayer::new("test_exact_limit", 64).layer(inner);
        let req = Request::builder()
            .header(CONTENT_ENCODING, "GZIP")
            .body(
                Full::new(Bytes::from(compressed))
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .unwrap();

        let resp = svc
            .oneshot(req)
            .await
            .expect("payload of exact max_bytes must succeed without off-by-one 413");
        assert_eq!(resp.status(), hyper::StatusCode::OK);
    }

    #[tokio::test]
    async fn test_compression_skips_head_204_and_q_zero() -> Result<(), Box<dyn std::error::Error>> {
        assert!(!accepts_coding("gzip;q=0", "gzip"));
        assert!(!accepts_coding("gzip; q=0.000", "gzip"));
        assert!(accepts_coding("gzip;q=0, br;q=1.0", "br"));
        assert!(!accepts_coding("deflate", "br"));

        // 1. q=0 must not compress
        let resp_q0 = run(Some("application/json"), None, "gzip;q=0", full_body(PAYLOAD)).await;
        assert!(resp_q0.headers().get(CONTENT_ENCODING).is_none());

        // 2. HEAD request must not compress or strip Content-Length
        let inner_head = service_fn(|_req: Request<SrvBody>| async move {
            let mut r = Response::new(full_body(b""));
            r.headers_mut().insert(CONTENT_LENGTH, HeaderValue::from_static("128"));
            Ok::<Response<SrvBody>, SrvError>(r)
        });
        let svc_head = SrvCompressionLayer::new("test_head").layer(inner_head);
        let req_head = Request::builder()
            .method(hyper::Method::HEAD)
            .header(ACCEPT_ENCODING, "gzip")
            .body(full_body(b""))?;
        let resp_head = svc_head.oneshot(req_head).await?;
        assert!(resp_head.headers().get(CONTENT_ENCODING).is_none());
        assert_eq!(
            resp_head.headers().get(CONTENT_LENGTH).and_then(|v| v.to_str().ok()),
            Some("128")
        );

        // 3. 204 No Content must not compress
        let inner_204 = service_fn(|_req: Request<SrvBody>| async move {
            let mut r = Response::new(full_body(b""));
            *r.status_mut() = hyper::StatusCode::NO_CONTENT;
            Ok::<Response<SrvBody>, SrvError>(r)
        });
        let svc_204 = SrvCompressionLayer::new("test_204").layer(inner_204);
        let req_204 = Request::builder()
            .header(ACCEPT_ENCODING, "gzip")
            .body(full_body(b""))?;
        let resp_204 = svc_204.oneshot(req_204).await?;
        assert!(resp_204.headers().get(CONTENT_ENCODING).is_none());
        Ok(())
    }
}
