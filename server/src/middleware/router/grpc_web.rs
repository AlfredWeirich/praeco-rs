//! # Dynamic JSON-to-gRPC Transcoding (`GrpcTranscoding`)
//!
//! This module implements Praeco's on-the-fly **REST/JSON-to-gRPC transcoding** engine.
//! It enables standard HTTP/1.1, HTTP/2, or HTTP/3 clients (such as web browsers or
//! REST services) to invoke backend gRPC methods using regular JSON payloads without
//! requiring pre-compiled `.proto` stubs at the gateway.
//!
//! ## Architecture & Workflow
//!
//! 1. **Dynamic Schema Discovery (`build_grpc_pool`)**:
//!    - Queries the upstream gRPC server via the standard **gRPC Server Reflection** protocol
//!      (`grpc.reflection.v1alpha.ServerReflection`) over HTTP/2 (supporting both plaintext `h2c`
//!      and End-to-End TLS/mTLS).
//!    - Compiles the returned `FileDescriptorProto` definitions into a cached
//!      [`prost_reflect::DescriptorPool`] with configurable TTL and *stale-while-revalidate*
//!      fallback resilience.
//! 2. **JSON-to-Protobuf Framing (`handle_grpc_web`)**:
//!    - Resolves the target gRPC service and method from the URI path (`/<package>.<Service>/<Method>`).
//!    - Deserializes the incoming JSON body directly into a [`prost_reflect::DynamicMessage`]
//!      seeded by the method's input descriptor, encodes it into binary Protobuf, and prefixes
//!      the 5-byte gRPC Length-Prefixed-Message header (`[compressed_flag: u8, length: u32]`).
//! 3. **W3C Trace Context & Wire Header Propagation**:
//!    - Replaces client JSON headers with authoritative gRPC wire headers
//!      (`content-type: application/grpc`, `te: trailers`).
//!    - Injects the active OpenTelemetry span context (`traceparent`, `tracestate`) into the
//!      outgoing HTTP/2 request via [`opentelemetry_http::HeaderInjector`] and mirrors the
//!      authoritative `traceparent` into `x-trace-id` for legacy gRPC metadata consumers.
//! 4. **Protobuf-to-JSON Response Translation**:
//!    - Reads the bounded (max 16 MiB) binary gRPC response frame, decodes the Protobuf payload
//!      using the method's output descriptor, and serializes it back to `application/json`.

use bytes::{BufMut, Bytes, BytesMut};
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Response, StatusCode, Uri, header};
use hyper_util::client::legacy::Client;
use prost::Message;
use prost_reflect::{DescriptorPool, DynamicMessage};
use serde::de::DeserializeSeed;
use std::sync::Arc;
use tokio_stream::wrappers::ReceiverStream;
use tonic_reflection::pb::v1alpha::{
    ServerReflectionRequest, server_reflection_client::ServerReflectionClient,
    server_reflection_request::MessageRequest,
};
use tracing::{error, warn};

use super::{RequestBody, build_error_response};
use crate::{
    ServiceRespBody, SrvError,
    configuration::{RouteTarget, ServerConfig},
};

/// Maps a canonical gRPC status code to an HTTP status code.
fn map_grpc_status_to_http(code: u32) -> StatusCode {
    match code {
        0 => StatusCode::OK,
        3 | 9 | 11 => StatusCode::BAD_REQUEST,       // INVALID_ARGUMENT, FAILED_PRECONDITION, OUT_OF_RANGE
        4 => StatusCode::GATEWAY_TIMEOUT,            // DEADLINE_EXCEEDED
        5 => StatusCode::NOT_FOUND,                  // NOT_FOUND
        6 | 10 => StatusCode::CONFLICT,              // ALREADY_EXISTS, ABORTED
        7 => StatusCode::FORBIDDEN,                  // PERMISSION_DENIED
        8 => StatusCode::TOO_MANY_REQUESTS,          // RESOURCE_EXHAUSTED
        12 => StatusCode::NOT_IMPLEMENTED,           // UNIMPLEMENTED
        14 => StatusCode::SERVICE_UNAVAILABLE,       // UNAVAILABLE
        16 => StatusCode::UNAUTHORIZED,              // UNAUTHENTICATED
        _ => StatusCode::BAD_GATEWAY,                // CANCELLED, UNKNOWN, INTERNAL, DATA_LOSS, etc.
    }
}

/// Extracts `(grpc-status, optional decoded grpc-message)` from an HTTP/2 header or trailer map.
fn extract_grpc_status(headers: &hyper::HeaderMap) -> Option<(u32, Option<String>)> {
    let code = headers
        .get("grpc-status")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u32>().ok())?;
    let message = headers
        .get("grpc-message")
        .and_then(|v| v.to_str().ok())
        .map(|raw| {
            urlencoding::decode(raw)
                .map(|c| c.into_owned())
                .unwrap_or_else(|_| raw.to_string())
        })
        .filter(|s| !s.is_empty());
    Some((code, message))
}

/// Builds a synthetic HTTP error response for a non-zero gRPC status code and preserves
/// the numeric `grpc-status` header for downstream inspection (e.g. `aggregator.rs`).
fn build_grpc_status_error(code: u32, message: Option<String>) -> Response<ServiceRespBody> {
    let http_status = map_grpc_status_to_http(code);
    let body_text = message.unwrap_or_else(|| {
        http_status
            .canonical_reason()
            .unwrap_or("gRPC Error")
            .to_string()
    });
    let mut resp = build_error_response(&body_text, http_status);
    if let Ok(hv) = header::HeaderValue::from_str(&code.to_string()) {
        resp.headers_mut().insert("grpc-status", hv);
    }
    resp
}

/// Fallback upper bound on a single gRPC response body when `handle_grpc_web` is called
/// in unit tests without an explicit per-route `max_response_bytes` limit (16 MiB).
#[cfg(test)]
pub const MAX_GRPC_WEB_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

/// Body wrapper enforcing both a per-route response size cap (`max_response_bytes`)
/// and the process-wide [`super::BufferBudget`] as HTTP/2 `DATA` frames arrive.
struct GrpcWebResponseBody<'a, B> {
    inner: &'a mut B,
    max_response_bytes: usize,
    read_bytes: usize,
    reservation: &'a mut super::BufferReservation,
    global_exhausted: &'a mut bool,
}

impl<B> http_body::Body for GrpcWebResponseBody<'_, B>
where
    B: http_body::Body<Data = Bytes> + Unpin,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Data = Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let this = &mut *self;
        match std::pin::Pin::new(&mut *this.inner).poll_frame(cx) {
            std::task::Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    let len = data.len();
                    let next_total = this.read_bytes.saturating_add(len);
                    if next_total > this.max_response_bytes {
                        return std::task::Poll::Ready(Some(Err(Box::new(
                            SrvError::PayloadTooLarge {
                                current: next_total,
                                max: this.max_response_bytes,
                            },
                        ))));
                    }
                    if !this.reservation.try_reserve(len) {
                        *this.global_exhausted = true;
                        return std::task::Poll::Ready(Some(Err(Box::new(SrvError::Other(
                            "Global response buffer budget exhausted".to_string(),
                        )))));
                    }
                    this.read_bytes = next_total;
                }
                std::task::Poll::Ready(Some(Ok(frame)))
            }
            std::task::Poll::Ready(Some(Err(e))) => {
                std::task::Poll::Ready(Some(Err(e.into())))
            }
            std::task::Poll::Ready(None) => std::task::Poll::Ready(None),
            std::task::Poll::Pending => std::task::Poll::Pending,
        }
    }
}

/// Handles a single JSON-to-gRPC transcoded request (`backend_type = "grpc_transcoding"`).
///
/// # Arguments
///
/// * `target` – Upstream pool (`RouteTarget`) with load balancer and cached reflection `DescriptorPool`.
/// * `request_body` – Buffered JSON payload from the client.
/// * `original_method` – Incoming HTTP method (must be `POST`).
/// * `prepared_headers` – Sanitized proxy headers including trace and identity headers.
/// * `original_uri` – Incoming URI encoding `/<Package.Service>/<Method>`.
/// * `client_addr` – Optional peer socket address used for sticky load-balancing.
/// * `server_name` – Static server identifier for structured logging and diagnostics.
/// * `grpc_client` – Shared HTTP/2-only Hyper client configured with upstream TLS/mTLS.
/// * `config` – Reference to the enclosing [`ServerConfig`] for timeout and reflection parameters.
/// * `timeout_override` – Optional per-call deadline overriding `config.router_params.request_timeout_seconds`.
///
/// # Returns
///
/// Returns an HTTP [`Response<ServiceRespBody>`] with `content-type: application/json` on success,
/// or an appropriate synthetic HTTP error status (`400`, `401`, `403`, `404`, `409`, `429`, `501`, `502`, `503`, `504`) on failure.
#[cfg(test)]
#[tracing::instrument(skip_all, fields(server = %server_name, method = %original_method), err)]
#[allow(clippy::too_many_arguments)]
pub async fn handle_grpc_web(
    target: &Arc<RouteTarget>,
    request_body: RequestBody,
    original_method: Method,
    prepared_headers: hyper::HeaderMap,
    original_uri: &Uri,
    client_addr: Option<std::net::SocketAddr>,
    server_name: &str,
    grpc_client: &Client<
        common::client::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        ServiceRespBody,
    >,
    config: &ServerConfig,
    timeout_override: Option<std::time::Duration>,
) -> Result<Response<ServiceRespBody>, SrvError> {
    handle_grpc_web_with_limit(
        target,
        request_body,
        original_method,
        prepared_headers,
        original_uri,
        client_addr,
        server_name,
        grpc_client,
        config,
        timeout_override,
        MAX_GRPC_WEB_RESPONSE_BYTES,
    )
    .await
}

/// Handles a single JSON-to-gRPC transcoded request with an explicit per-route
/// `max_response_bytes` cap and the global [`super::BufferBudget`].
#[tracing::instrument(skip_all, fields(server = %server_name, method = %original_method), err)]
#[allow(clippy::too_many_arguments)]
pub async fn handle_grpc_web_with_limit(
    target: &Arc<RouteTarget>,
    request_body: RequestBody,
    original_method: Method,
    prepared_headers: hyper::HeaderMap,
    original_uri: &Uri,
    client_addr: Option<std::net::SocketAddr>,
    server_name: &str,
    grpc_client: &Client<
        common::client::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        ServiceRespBody,
    >,
    config: &ServerConfig,
    timeout_override: Option<std::time::Duration>,
    max_response_bytes: usize,
) -> Result<Response<ServiceRespBody>, SrvError> {
    handle_grpc_web_with_budget(
        target,
        request_body,
        original_method,
        prepared_headers,
        original_uri,
        client_addr,
        server_name,
        grpc_client,
        config,
        timeout_override,
        max_response_bytes,
        super::global_response_buffer_budget(),
    )
    .await
}

/// Handles a single JSON-to-gRPC transcoded request with an explicit per-route
/// `max_response_bytes` cap and an explicit [`super::BufferBudget`].
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_grpc_web_with_budget(
    target: &Arc<RouteTarget>,
    request_body: RequestBody, // not mut since GrpcWeb buffers only
    original_method: Method,
    mut prepared_headers: hyper::HeaderMap,
    original_uri: &Uri,
    client_addr: Option<std::net::SocketAddr>,
    server_name: &str,
    grpc_client: &Client<
        common::client::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        ServiceRespBody,
    >,
    config: &ServerConfig,
    timeout_override: Option<std::time::Duration>,
    max_response_bytes: usize,
    global_budget: &Arc<super::BufferBudget>,
) -> Result<Response<ServiceRespBody>, SrvError> {
    let mut failed_nodes = Vec::new();
    let max_retries = target.max_retries;
    let mut attempts = 0;

    loop {
        let mut current_headers = if attempts == max_retries {
            std::mem::take(&mut prepared_headers)
        } else {
            prepared_headers.clone()
        };
        attempts += 1;

        let upstream_node = target.next_upstream(client_addr.as_ref(), &failed_nodes);
        let backend_base_uri = &upstream_node.uri;
        let is_multi_node = target.upstreams.len() > 1;
        let mut probe_guard = is_multi_node.then(|| {
            super::circuit_breaker::ProbeGuard::new(upstream_node, target.cooldown_seconds)
        });
        let request_epoch = probe_guard.as_ref().map_or_else(
            || {
                upstream_node
                    .circuit_epoch
                    .load(std::sync::atomic::Ordering::Acquire)
            },
            |pg| pg.epoch(),
        );
        let _conn_guard =
            super::upstreams::ConnectionGuard::new(target.clone(), backend_base_uri.clone());

        if let Some(auth) = backend_base_uri.authority()
            && let Ok(host_val) = header::HeaderValue::from_str(auth.as_str()) {
                current_headers.insert(header::HOST, host_val);
            }

        let reflection_ttl = config
            .router_params
            .as_ref()
            .map(|p| std::time::Duration::from_secs(p.grpc_reflection_ttl_seconds))
            .unwrap_or(std::time::Duration::from_secs(600));

        // 1. Fast path: check if cached pool is valid under read lock (also retain stale pool if expired)
        let (mut pool_opt, stale_pool) = {
            let read_guard = target.grpc_pool.read().await;
            if let Some(cached) = &*read_guard {
                if cached.created_at.elapsed() < reflection_ttl {
                    (Some(cached.pool.clone()), Some(cached.pool.clone()))
                } else {
                    (None, Some(cached.pool.clone()))
                }
            } else {
                (None, None)
            }
        };

        // 2. Slow path: if cache is expired AND we have a stale pool, avoid blocking callers
        //    behind `grpc_reflection_lock` while another task refreshes (stale-while-revalidate).
        if pool_opt.is_none() {
            let fetch_guard_opt = if stale_pool.is_some() {
                target.grpc_reflection_lock.try_lock().ok()
            } else {
                Some(target.grpc_reflection_lock.lock().await)
            };

            if let Some(_fetch_guard) = fetch_guard_opt {
                // Double check if another task refreshed it while we acquired the fetch lock
                let recheck = {
                    let read_guard = target.grpc_pool.read().await;
                    if let Some(cached) = &*read_guard {
                        if cached.created_at.elapsed() < reflection_ttl {
                            Some(cached.pool.clone())
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                };

                if let Some(p) = recheck {
                    pool_opt = Some(p);
                } else {
                    match build_grpc_pool(&upstream_node.uri, config.router_params.as_ref()).await {
                        Ok(new_pool) => {
                            let mut write_guard = target.grpc_pool.write().await;
                            *write_guard = Some(crate::configuration::CachedDescriptorPool {
                                pool: new_pool.clone(),
                                created_at: std::time::Instant::now(),
                            });
                            pool_opt = Some(new_pool);
                        }
                        Err(e) => {
                            error!(
                                "{}: Failed to fetch gRPC reflection schema from {}: {:?}",
                                server_name, backend_base_uri, e
                            );
                            if let Some(stale) = stale_pool {
                                warn!(
                                    "{}: Using stale gRPC reflection schema due to upstream fetch failure",
                                    server_name
                                );
                                pool_opt = Some(stale);
                            } else {
                                if let Some(ref mut pg) = probe_guard {
                                    pg.complete();
                                }
                                upstream_node.record_failure_with_epoch(
                                    target.failure_threshold,
                                    request_epoch,
                                );
                                return Ok(build_error_response(
                                    "Failed to fetch gRPC schema",
                                    StatusCode::BAD_GATEWAY,
                                ));
                            }
                        }
                    }
                }
            } else if let Some(stale) = stale_pool {
                pool_opt = Some(stale);
            }
        }

        let pool = pool_opt.expect("pool must be present");

        let uri_path = original_uri.path().trim_start_matches('/');
        let uri_parts: Vec<&str> = uri_path.split('/').collect();

        if original_method != Method::POST || uri_parts.len() < 2 {
            warn!(
                "{}: Invalid gRPC request method or path structure",
                server_name
            );
            return Ok(build_error_response(
                "Please use POST /Fully.Qualified.Service/Method for gRPC",
                StatusCode::BAD_REQUEST,
            ));
        }

        let service_name = uri_parts[uri_parts.len() - 2];
        let method_name = uri_parts[uri_parts.len() - 1];

        let method_desc = match pool.get_service_by_name(service_name) {
            Some(s) => match s.methods().find(|m| m.name() == method_name) {
                Some(m) => m,
                None => {
                    return Ok(build_error_response(
                        "gRPC Method Not Found",
                        StatusCode::NOT_FOUND,
                    ));
                }
            },
            None => {
                return Ok(build_error_response(
                    "gRPC Service Not Found",
                    StatusCode::NOT_FOUND,
                ));
            }
        };

        let RequestBody::Buffered(req_body_bytes) = &request_body else {
            return Ok(build_error_response(
                "Streaming not supported for gRPC transcoding yet",
                StatusCode::INTERNAL_SERVER_ERROR,
            ));
        };

        let mut deserializer = serde_json::Deserializer::from_slice(req_body_bytes);
        let dynamic_req_msg = match method_desc.input().deserialize(&mut deserializer) {
            Ok(msg) => msg,
            Err(e) => {
                warn!("{}: Invalid JSON payload for gRPC transcoding: {}", server_name, e);
                return Ok(build_error_response(
                    "Invalid JSON payload",
                    StatusCode::BAD_REQUEST,
                ));
            }
        };

        let encoded_len = dynamic_req_msg.encoded_len();
        let mut grpc_frame = BytesMut::with_capacity(5 + encoded_len);
        grpc_frame.put_u8(0);
        grpc_frame.put_u32(encoded_len as u32);
        if let Err(e) = dynamic_req_msg.encode(&mut grpc_frame) {
            error!("{}: Failed to encode gRPC protobuf request: {}", server_name, e);
            return Ok(build_error_response(
                "Internal Server Error",
                StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }

        let boxed_body: ServiceRespBody = Full::new(grpc_frame.freeze())
            .map_err(SrvError::from)
            .boxed();

        let grpc_target_path = format!("/{}/{}", service_name, method_name);
        let mut proxy_uri_parts = backend_base_uri.clone().into_parts();
        proxy_uri_parts.path_and_query =
            match hyper::http::uri::PathAndQuery::from_maybe_shared(grpc_target_path) {
                Ok(pq) => Some(pq),
                Err(e) => {
                    warn!("{}: Invalid gRPC target path: {}", server_name, e);
                    return Ok(build_error_response(
                        "Invalid Request URI",
                        StatusCode::BAD_REQUEST,
                    ));
                }
            };
        let final_target_uri = match Uri::from_parts(proxy_uri_parts) {
            Ok(u) => u,
            Err(e) => {
                warn!("{}: Invalid gRPC target URI: {}", server_name, e);
                return Ok(build_error_response(
                    "Invalid Request URI",
                    StatusCode::BAD_REQUEST,
                ));
            }
        };

        let builder = Request::builder()
            .method(Method::POST)
            .uri(final_target_uri)
            .version(hyper::Version::HTTP_2);

        let mut proxy_req = match builder.body(boxed_body) {
            Ok(req) => req,
            Err(e) => {
                error!("{}: Failed to build gRPC request: {}", server_name, e);
                return Ok(build_error_response(
                    "Internal Server Error",
                    StatusCode::INTERNAL_SERVER_ERROR,
                ));
            }
        };

        *proxy_req.version_mut() = hyper::Version::HTTP_2;

        // Replace client JSON headers with authoritative gRPC wire headers
        current_headers.remove(header::CONTENT_LENGTH);
        current_headers.remove(header::CONNECTION);
        current_headers.remove(header::TRANSFER_ENCODING);
        current_headers.remove(header::UPGRADE);
        current_headers.remove("grpc-encoding");
        current_headers.insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/grpc"),
        );
        current_headers.insert(
            header::TE,
            header::HeaderValue::from_static("trailers"),
        );
        current_headers.insert(
            header::HeaderName::from_static("grpc-accept-encoding"),
            header::HeaderValue::from_static("identity"),
        );

        *proxy_req.headers_mut() = current_headers;

        // Inject OpenTelemetry context (e.g., W3C `traceparent` and `tracestate`) into the
        // outgoing HTTP/2 gRPC request headers so distributed traces stay connected across
        // JSON-to-gRPC transcoding.
        opentelemetry::global::get_text_map_propagator(|propagator| {
            use tracing_opentelemetry::OpenTelemetrySpanExt;
            propagator.inject_context(
                &tracing::Span::current().context(),
                &mut opentelemetry_http::HeaderInjector(proxy_req.headers_mut()),
            );
        });

        // Ensure `x-trace-id` is populated for gRPC backends that expect it, using the
        // authoritative `traceparent` header (either freshly injected by OpenTelemetry above
        // or preserved from `TraceIdLayer` / incoming client headers).
        if let Some(trace_id) = proxy_req.headers().get("traceparent").cloned() {
            proxy_req.headers_mut().entry("x-trace-id").or_insert(trace_id);
        }

        let req_timeout = timeout_override.unwrap_or_else(|| {
            config
                .router_params
                .as_ref()
                .and_then(|p| {
                    (p.request_timeout_seconds > 0)
                        .then(|| std::time::Duration::from_secs(p.request_timeout_seconds))
                })
                .unwrap_or(std::time::Duration::from_secs(30))
        });

        let req_start = std::time::Instant::now();
        let req_result = match tokio::time::timeout(req_timeout, grpc_client.request(proxy_req)).await {
            Ok(res) => res,
            Err(_) => {
                error!(
                    "{}: gRPC transcoding request to {} timed out after {:?}",
                    server_name, backend_base_uri, req_timeout
                );
                if let Some(ref mut pg) = probe_guard {
                    pg.complete();
                }
                upstream_node.record_failure_with_epoch(target.failure_threshold, request_epoch);
                failed_nodes.push(backend_base_uri.clone());

                if attempts <= max_retries {
                    upstream_node
                        .failover_retries
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    warn!(
                        "{}: Retrying gRPC transcoding request after timeout... (Attempt {}/{})",
                        server_name, attempts, max_retries
                    );
                    continue;
                }
                return Ok(build_error_response(
                    "Gateway Timeout",
                    StatusCode::GATEWAY_TIMEOUT,
                ));
            }
        };

        match req_result {
            Ok(mut res) => {
                upstream_node.record_latency_ms(req_start.elapsed().as_millis() as u64);
                if let Some(ref mut pg) = probe_guard {
                    pg.complete();
                }
                if res.status() != StatusCode::OK {
                    let status = res.status();
                    warn!(
                        "{}: Upstream gRPC backend {} returned HTTP {}",
                        server_name, backend_base_uri, status
                    );
                    if super::circuit_breaker::is_outlier_status(status) {
                        upstream_node
                            .record_failure_with_epoch(target.failure_threshold, request_epoch);
                        failed_nodes.push(backend_base_uri.clone());
                        if attempts <= max_retries {
                            upstream_node
                                .failover_retries
                                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            warn!(
                                "{}: Retrying gRPC transcoding request after HTTP {}... (Attempt {}/{})",
                                server_name, status, attempts, max_retries
                            );
                            continue;
                        }
                    }
                    let msg = status.canonical_reason().unwrap_or("Bad Gateway");
                    return Ok(build_error_response(msg, status));
                }

                // Check Trailers-Only gRPC error status in initial HTTP/2 response headers
                if let Some((grpc_code, grpc_msg)) = extract_grpc_status(res.headers())
                    && grpc_code != 0
                {
                    if grpc_code == 14 {
                        upstream_node
                            .record_failure_with_epoch(target.failure_threshold, request_epoch);
                    } else {
                        upstream_node.record_success_with_epoch(request_epoch);
                    }
                    return Ok(build_grpc_status_error(grpc_code, grpc_msg));
                }

                let mut reservation = super::BufferReservation::new(Arc::clone(global_budget));
                let mut global_exhausted = false;
                let remaining_timeout = req_timeout.saturating_sub(req_start.elapsed());
                let collect_res = tokio::time::timeout(
                    remaining_timeout,
                    GrpcWebResponseBody {
                        inner: res.body_mut(),
                        max_response_bytes,
                        read_bytes: 0,
                        reservation: &mut reservation,
                        global_exhausted: &mut global_exhausted,
                    }
                    .collect(),
                )
                .await;

                let collected = match collect_res {
                    Ok(Ok(c)) => c,
                    Ok(Err(_)) if global_exhausted => {
                        warn!(
                            "{}: Global response buffer budget exhausted while reading gRPC response from {}",
                            server_name, backend_base_uri
                        );
                        return Ok(build_error_response(
                            "Service Unavailable",
                            StatusCode::SERVICE_UNAVAILABLE,
                        ));
                    }
                    Ok(Err(e)) => {
                        warn!(
                            "{}: Failed to read gRPC response body from {}: {}",
                            server_name, backend_base_uri, e
                        );
                        upstream_node
                            .record_failure_with_epoch(target.failure_threshold, request_epoch);
                        return Ok(build_error_response(
                            "Bad Gateway",
                            StatusCode::BAD_GATEWAY,
                        ));
                    }
                    Err(_) => {
                        warn!(
                            "{}: Gateway timeout reading gRPC response body from {}",
                            server_name, backend_base_uri
                        );
                        upstream_node
                            .record_failure_with_epoch(target.failure_threshold, request_epoch);
                        return Ok(build_error_response(
                            "Gateway Timeout",
                            StatusCode::GATEWAY_TIMEOUT,
                        ));
                    }
                };

                // Check gRPC status in HTTP/2 trailing headers BEFORE accepting body data frames
                if let Some(trailers) = collected.trailers()
                    && let Some((grpc_code, grpc_msg)) = extract_grpc_status(trailers)
                    && grpc_code != 0
                {
                    if grpc_code == 14 {
                        upstream_node
                            .record_failure_with_epoch(target.failure_threshold, request_epoch);
                    } else {
                        upstream_node.record_success_with_epoch(request_epoch);
                    }
                    return Ok(build_grpc_status_error(grpc_code, grpc_msg));
                }

                let res_body_bytes = collected.to_bytes();

                if res_body_bytes.len() < 5 {
                    upstream_node.record_success_with_epoch(request_epoch);
                    return Ok(build_error_response(
                        "Invalid gRPC Response",
                        StatusCode::BAD_GATEWAY,
                    ));
                }

                if res_body_bytes[0] != 0 {
                    warn!(
                        "{}: Upstream gRPC response used unsupported compression flag ({})",
                        server_name, res_body_bytes[0]
                    );
                    upstream_node.record_success_with_epoch(request_epoch);
                    return Ok(build_error_response(
                        "Unsupported gRPC Response Compression",
                        StatusCode::BAD_GATEWAY,
                    ));
                }

                let payload_len = u32::from_be_bytes([
                    res_body_bytes[1],
                    res_body_bytes[2],
                    res_body_bytes[3],
                    res_body_bytes[4],
                ]) as usize;
                let Some(frame_end) = 5usize.checked_add(payload_len) else {
                    return Ok(build_error_response(
                        "Invalid gRPC Response",
                        StatusCode::BAD_GATEWAY,
                    ));
                };
                if res_body_bytes.len() < frame_end {
                    upstream_node.record_success_with_epoch(request_epoch);
                    return Ok(build_error_response(
                        "Truncated gRPC Response",
                        StatusCode::BAD_GATEWAY,
                    ));
                }

                let raw_protobuf_res = &res_body_bytes[5..frame_end];

                let mut dynamic_res_msg = DynamicMessage::new(method_desc.output());
                if let Err(e) = dynamic_res_msg.merge(raw_protobuf_res) {
                    warn!(
                        "{}: Failed to decode protobuf response from {}: {}",
                        server_name, backend_base_uri, e
                    );
                    return Ok(build_error_response(
                        "Invalid Protobuf Response",
                        StatusCode::BAD_GATEWAY,
                    ));
                }

                let response_json = match serde_json::to_vec(&dynamic_res_msg) {
                    Ok(v) => v,
                    Err(e) => {
                        error!(
                            "{}: Failed to serialize decoded protobuf response to JSON: {}",
                            server_name, e
                        );
                        return Ok(build_error_response(
                            "Internal Server Error",
                            StatusCode::INTERNAL_SERVER_ERROR,
                        ));
                    }
                };

                // Release raw protobuf buffer and adjust global buffer reservation to the JSON size
                drop(res_body_bytes);
                if !reservation.adjust_to(response_json.len()) {
                    warn!(
                        "{}: Global response buffer budget exhausted after JSON transcoding ({} bytes)",
                        server_name,
                        response_json.len()
                    );
                    return Ok(build_error_response(
                        "Service Unavailable",
                        StatusCode::SERVICE_UNAVAILABLE,
                    ));
                }

                upstream_node.record_success_with_epoch(request_epoch);

                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(
                        super::BudgetedBytesBody::new(Bytes::from(response_json), reservation)
                            .boxed(),
                    )
                    .unwrap());
            }
            Err(e) => {
                if let Some(ref mut pg) = probe_guard {
                    pg.complete();
                }
                error!(
                    "{}: Backend connection failed to {}: {}",
                    server_name, backend_base_uri, e
                );
                target.mark_dead(backend_base_uri);
                failed_nodes.push(backend_base_uri.clone());

                if attempts <= max_retries {
                    upstream_node
                        .failover_retries
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    warn!(
                        "{}: Retrying gRPC request... (Attempt {}/{})",
                        server_name, attempts, max_retries
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                    continue;
                } else {
                    return Ok(build_error_response("Bad Gateway", StatusCode::BAD_GATEWAY));
                }
            }
        }
    }
}

/// Connects to an upstream gRPC server and builds a [`prost_reflect::DescriptorPool`]
/// by querying its `grpc.reflection.v1alpha.ServerReflection` service.
///
/// # Security & Fail-Closed Guarantees
///
/// * If `https` is used and `ssl_root_certificate` is configured, the CA file is read
///   and validated strictly (non-existent or empty files return an `Err`).
/// * If `AuthenticationMethod::ClientCert` (mTLS) is configured in `router_params`,
///   both `ssl_client_certificate` and `ssl_client_key` must be present and non-empty,
///   otherwise connection setup fails closed.
///
/// # Arguments
///
/// * `backend_base_uri` – Base URI (`http://` or `https://`) of the upstream gRPC node.
/// * `router_params` – Optional [`RouterParams`](crate::configuration::RouterParams) containing
///   TLS/mTLS certificate paths and connection/reflection timeouts.
///
/// # Returns
///
/// Returns an `Arc<DescriptorPool>` containing all non-reflection service and message descriptors
/// advertised by the upstream gRPC endpoint.
pub async fn build_grpc_pool(
    backend_base_uri: &Uri,
    router_params: Option<&crate::configuration::RouterParams>,
) -> Result<Arc<DescriptorPool>, Box<dyn std::error::Error + Send + Sync>> {
    let host = backend_base_uri.host().unwrap_or("localhost");
    let port = backend_base_uri.port_u16().unwrap_or(80);
    let scheme = backend_base_uri.scheme_str().unwrap_or("http");

    let connect_timeout = router_params
        .map(|p| std::time::Duration::from_secs(p.connect_timeout_seconds))
        .unwrap_or(std::time::Duration::from_secs(5));
    let request_timeout = router_params
        .map(|p| std::time::Duration::from_secs(p.grpc_reflection_timeout_seconds))
        .unwrap_or(std::time::Duration::from_secs(10));

    let target = format!("{}://{}:{}", scheme, host, port);
    let mut endpoint = tonic::transport::Channel::from_shared(target)?
        .connect_timeout(connect_timeout)
        .timeout(request_timeout)
        .tcp_keepalive(Some(std::time::Duration::from_secs(60)))
        .http2_keep_alive_interval(std::time::Duration::from_secs(30));

    if scheme == "https" {
        let mut tls = tonic::transport::ClientTlsConfig::new().domain_name(host);

        if let Some(params) = router_params {
            if let Some(ca_path) = &params.ssl_root_certificate {
                let pem = tokio::fs::read(ca_path).await.map_err(|e| {
                    std::io::Error::new(
                        e.kind(),
                        format!("Failed to read root CA certificate '{}': {}", ca_path, e),
                    )
                })?;
                if pem.is_empty() {
                    return Err(format!("Root CA certificate '{}' is empty", ca_path).into());
                }
                let ca = tonic::transport::Certificate::from_pem(pem);
                tls = tls.ca_certificate(ca);
            }

            if params.authentication == crate::configuration::AuthenticationMethod::ClientCert {
                let cert_path = params.ssl_client_certificate.as_ref().ok_or_else(|| {
                    format!("{}: ssl_client_certificate must be specified for ClientCert authentication", host)
                })?;
                let key_path = params.ssl_client_key.as_ref().ok_or_else(|| {
                    format!("{}: ssl_client_key must be specified for ClientCert authentication", host)
                })?;

                let cert_pem = tokio::fs::read(cert_path).await.map_err(|e| {
                    std::io::Error::new(
                        e.kind(),
                        format!("Failed to read client certificate '{}': {}", cert_path, e),
                    )
                })?;
                let key_pem = tokio::fs::read(key_path).await.map_err(|e| {
                    std::io::Error::new(
                        e.kind(),
                        format!("Failed to read client key '{}': {}", key_path, e),
                    )
                })?;

                if cert_pem.is_empty() || key_pem.is_empty() {
                    return Err(format!(
                        "Client certificate or key is empty ('{}', '{}')",
                        cert_path, key_path
                    ).into());
                }

                let identity = tonic::transport::Identity::from_pem(cert_pem, key_pem);
                tls = tls.identity(identity);
            }
        }
        endpoint = endpoint.tls_config(tls)?;
    }

    let channel = endpoint.connect().await?;
    let mut reflection_client = ServerReflectionClient::new(channel);

    let (tx, rx) = tokio::sync::mpsc::channel(1);
    tx.send(ServerReflectionRequest {
        host: String::new(),
        message_request: Some(MessageRequest::ListServices(String::new())),
    })
    .await?;

    let response: tonic::Response<
        tonic::Streaming<tonic_reflection::pb::v1alpha::ServerReflectionResponse>,
    > = reflection_client
        .server_reflection_info(tonic::Request::new(ReceiverStream::new(rx)))
        .await?;

    let mut response_stream = response.into_inner();
    let mut current_services = Vec::new();

    if let Some(res) = response_stream.message().await?
        && let Some(tonic_reflection::pb::v1alpha::server_reflection_response::MessageResponse::ListServicesResponse(list_res)) = res.message_response
    {
        for service in list_res.service {
            current_services.push(service.name);
        }
    }
    drop(tx);

    let mut pool = DescriptorPool::new();

    for service_name in current_services {
        if service_name.starts_with("grpc.reflection") {
            continue;
        }

        let (tx, rx) = tokio::sync::mpsc::channel(1);
        tx.send(ServerReflectionRequest {
            host: String::new(),
            message_request: Some(MessageRequest::FileContainingSymbol(service_name)),
        })
        .await?;

        let response: tonic::Response<
            tonic::Streaming<tonic_reflection::pb::v1alpha::ServerReflectionResponse>,
        > = reflection_client
            .server_reflection_info(tonic::Request::new(ReceiverStream::new(rx)))
            .await?;

        let mut response_stream = response.into_inner();

        if let Some(res) = response_stream.message().await?
            && let Some(tonic_reflection::pb::v1alpha::server_reflection_response::MessageResponse::FileDescriptorResponse(fd_res)) = res.message_response
        {
            for fd_bytes in fd_res.file_descriptor_proto {
                let fd_proto = prost::Message::decode(fd_bytes.as_ref())?;
                pool.add_file_descriptor_proto(fd_proto)?;
            }
        }
    }

    Ok(Arc::new(pool))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::{AuthenticationMethod, RouterParams};
    use hyper::Uri;

    #[tokio::test]
    async fn test_build_grpc_pool_fail_closed_nonexistent_ca() {
        let uri: Uri = "https://127.0.0.1:50051".parse().unwrap();
        let params = RouterParams {
            protocol: crate::configuration::Protocol::Https,
            authentication: AuthenticationMethod::None,
            ssl_root_certificate: Some("/path/to/nonexistent_ca_file_12345.pem".to_string()),
            jwt: None,
            ssl_client_certificate: None,
            ssl_client_key: None,
            connect_timeout_seconds: 1,
            request_timeout_seconds: 1,
            idle_timeout_seconds: 10,
            grpc_reflection_timeout_seconds: 1,
            grpc_reflection_ttl_seconds: 60,
        };

        let result = build_grpc_pool(&uri, Some(&params)).await;
        assert!(result.is_err(), "build_grpc_pool must fail-closed if configured CA cannot be read");
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("Failed to read root CA certificate"));
    }

    #[tokio::test]
    async fn test_build_grpc_pool_fail_closed_missing_client_cert_for_mtls() {
        let uri: Uri = "https://127.0.0.1:50051".parse().unwrap();
        let params = RouterParams {
            protocol: crate::configuration::Protocol::Https,
            authentication: AuthenticationMethod::ClientCert,
            ssl_root_certificate: None,
            jwt: None,
            ssl_client_certificate: None, // Missing cert!
            ssl_client_key: None,
            connect_timeout_seconds: 1,
            request_timeout_seconds: 1,
            idle_timeout_seconds: 10,
            grpc_reflection_timeout_seconds: 1,
            grpc_reflection_ttl_seconds: 60,
        };

        let result = build_grpc_pool(&uri, Some(&params)).await;
        assert!(result.is_err(), "build_grpc_pool must fail-closed if ClientCert auth is configured but cert path missing");
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("ssl_client_certificate must be specified"));
    }

    #[test]
    fn test_cached_descriptor_pool_ttl() {
        let pool = Arc::new(DescriptorPool::new());
        let cached = crate::configuration::CachedDescriptorPool {
            pool: pool.clone(),
            created_at: std::time::Instant::now() - std::time::Duration::from_secs(601),
        };
        let ttl = std::time::Duration::from_secs(600);
        assert!(cached.created_at.elapsed() >= ttl, "Pool older than 600s should be detected as expired");
    }

    // ------------------------------------------------------------------------
    //  End-to-end tests for the JSON -> gRPC transcoding path ([F-09])
    // ------------------------------------------------------------------------

    use crate::configuration::{CachedDescriptorPool, LbStrategy, RouteTarget, UpstreamNode};
    use prost_reflect::prost_types::{
        DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
        MethodDescriptorProto, ServiceDescriptorProto,
        field_descriptor_proto::{Label, Type},
    };
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    /// Builds a descriptor pool with `test.Echo/Say(test.Msg{text}) -> test.Msg`
    /// so that no live gRPC reflection server is required.
    fn test_descriptor_pool() -> Arc<DescriptorPool> {
        let file = FileDescriptorProto {
            name: Some("test.proto".into()),
            package: Some("test".into()),
            syntax: Some("proto3".into()),
            message_type: vec![DescriptorProto {
                name: Some("Msg".into()),
                field: vec![FieldDescriptorProto {
                    name: Some("text".into()),
                    json_name: Some("text".into()),
                    number: Some(1),
                    label: Some(Label::Optional as i32),
                    r#type: Some(Type::String as i32),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            service: vec![ServiceDescriptorProto {
                name: Some("Echo".into()),
                method: vec![MethodDescriptorProto {
                    name: Some("Say".into()),
                    input_type: Some(".test.Msg".into()),
                    output_type: Some(".test.Msg".into()),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        };
        Arc::new(
            DescriptorPool::from_file_descriptor_set(FileDescriptorSet { file: vec![file] })
                .expect("valid test descriptor set"),
        )
    }

    fn test_server_config(request_timeout_seconds: u64) -> ServerConfig {
        let toml_str = format!(
            r#"
            name = "grpc_web_test"
            enabled = true
            protocol = "http"
            service = "Echo"
            ip = "127.0.0.1"
            port = 8080

            [RouterParams]
            protocol = "http"
            request_timeout_seconds = {request_timeout_seconds}

            [Layers]
            enabled = []
        "#
        );
        toml::from_str(&toml_str).expect("valid test server config")
    }

    fn test_target(port: u16) -> Arc<RouteTarget> {
        let node = UpstreamNode::new(format!("http://127.0.0.1:{port}").parse().unwrap());
        Arc::new(RouteTarget {
            upstreams: vec![node],
            strategy: LbStrategy::RoundRobin,
            rr_counter: AtomicUsize::new(0),
            cooldown_seconds: 60,
            max_retries: 0,
            failure_threshold: 3,
            max_retry_buffer_bytes: 65536,
            active_health_check_interval: 0,
            // Pre-populated cache => handle_grpc_web never needs to perform reflection.
            grpc_pool: tokio::sync::RwLock::new(Some(CachedDescriptorPool {
                pool: test_descriptor_pool(),
                created_at: std::time::Instant::now(),
            })),
            grpc_reflection_lock: tokio::sync::Mutex::new(()),
        })
    }

    /// Spawns a one-shot HTTP/2 (h2c) mock upstream that serves the given handler.
    async fn spawn_h2_upstream<F, Fut>(handler: F) -> u16
    where
        F: Fn(hyper::Request<hyper::body::Incoming>) -> Fut + Send + 'static,
        Fut: std::future::Future<
                Output = Result<hyper::Response<Full<Bytes>>, std::convert::Infallible>,
            > + Send
            + 'static,
    {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((socket, _)) = listener.accept().await {
                let io = hyper_util::rt::TokioIo::new(socket);
                let _ = hyper::server::conn::http2::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                )
                .serve_connection(io, hyper::service::service_fn(handler))
                .await;
            }
        });
        port
    }

    async fn call_grpc_web(
        target: &Arc<RouteTarget>,
        config: &ServerConfig,
        headers: hyper::HeaderMap,
    ) -> Response<ServiceRespBody> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let client = common::client::build_hyper_client(
            tls_config,
            common::client::ClientPoolConfig {
                http2_only: true,
                ..Default::default()
            },
        );
        let uri: Uri = "http://localhost/test.Echo/Say".parse().unwrap();
        handle_grpc_web(
            target,
            RequestBody::Buffered(Bytes::from_static(br#"{"text":"hello"}"#)),
            Method::POST,
            headers,
            &uri,
            None,
            "test_server",
            &client,
            config,
            None,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn test_grpc_web_forwards_grpc_wire_headers_not_client_json_headers() {
        let captured = Arc::new(std::sync::Mutex::new(None::<hyper::HeaderMap>));
        let cap = captured.clone();
        let port = spawn_h2_upstream(move |req| {
            let cap = cap.clone();
            async move {
                *cap.lock().unwrap() = Some(req.headers().clone());
                let _ = req.into_body().collect().await;
                // gRPC frame: compressed-flag(0) + len(4) + protobuf Msg{text:"hi"}
                let frame = Bytes::from_static(&[0, 0, 0, 0, 4, 0x0a, 0x02, b'h', b'i']);
                Ok(hyper::Response::builder()
                    .status(200)
                    .body(Full::new(frame))
                    .unwrap())
            }
        })
        .await;

        let target = test_target(port);
        let config = test_server_config(5);

        let mut headers = hyper::HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        headers.insert(header::CONTENT_LENGTH, "9999".parse().unwrap());
        headers.insert(header::CONNECTION, "keep-alive".parse().unwrap());

        let resp = call_grpc_web(&target, &config, headers).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        assert!(String::from_utf8_lossy(&body).contains("hi"));

        let seen = captured.lock().unwrap().clone().expect("upstream must have been called");
        assert_eq!(seen.get(header::CONTENT_TYPE).unwrap(), "application/grpc");
        assert_eq!(seen.get(header::TE).unwrap(), "trailers");
        assert_ne!(
            seen.get(header::CONTENT_LENGTH).map(|v| v.to_str().unwrap()),
            Some("9999"),
            "stale client Content-Length must not be forwarded"
        );
        assert!(seen.get(header::CONNECTION).is_none(), "hop-by-hop headers must be stripped");
    }

    #[tokio::test]
    async fn test_grpc_web_request_timeout_returns_504() {
        let port = spawn_h2_upstream(|req| async move {
            let _ = req.into_body().collect().await;
            tokio::time::sleep(Duration::from_secs(5)).await;
            Ok(hyper::Response::new(Full::new(Bytes::new())))
        })
        .await;

        let target = test_target(port);
        let config = test_server_config(1);

        let started = std::time::Instant::now();
        let resp = call_grpc_web(&target, &config, hyper::HeaderMap::new()).await;
        assert_eq!(resp.status(), StatusCode::GATEWAY_TIMEOUT);
        assert!(
            started.elapsed() < Duration::from_secs(4),
            "request_timeout_seconds must bound the upstream call"
        );
    }

    #[tokio::test]
    async fn test_grpc_web_response_body_limit_returns_502() {
        let port = spawn_h2_upstream(|req| async move {
            let _ = req.into_body().collect().await;
            // 16 MiB + 1 byte exceeds MAX_GRPC_WEB_RESPONSE_BYTES.
            let oversized = Bytes::from(vec![0u8; 16 * 1024 * 1024 + 1]);
            Ok(hyper::Response::new(Full::new(oversized)))
        })
        .await;

        let target = test_target(port);
        let config = test_server_config(30);

        let resp = call_grpc_web(&target, &config, hyper::HeaderMap::new()).await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    #[tokio::test]
    async fn test_grpc_web_propagates_w3c_traceparent_and_x_trace_id() {
        let captured = Arc::new(std::sync::Mutex::new(None::<hyper::HeaderMap>));
        let cap = captured.clone();
        let port = spawn_h2_upstream(move |req| {
            let cap = cap.clone();
            async move {
                *cap.lock().unwrap() = Some(req.headers().clone());
                let _ = req.into_body().collect().await;
                let frame = Bytes::from_static(&[0, 0, 0, 0, 4, 0x0a, 0x02, b'o', b'k']);
                Ok(hyper::Response::builder()
                    .status(200)
                    .body(Full::new(frame))
                    .unwrap())
            }
        })
        .await;

        let target = test_target(port);
        let config = test_server_config(5);

        let expected_tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let mut headers = hyper::HeaderMap::new();
        headers.insert("traceparent", expected_tp.parse().unwrap());

        let resp = call_grpc_web(&target, &config, headers).await;
        assert_eq!(resp.status(), StatusCode::OK);

        let seen = captured
            .lock()
            .unwrap()
            .clone()
            .expect("upstream gRPC server must have been called");
        let seen_tp = seen
            .get("traceparent")
            .expect("traceparent header must be forwarded to gRPC upstream")
            .to_str()
            .unwrap();
        let seen_x_trace = seen
            .get("x-trace-id")
            .expect("x-trace-id header must be populated from traceparent")
            .to_str()
            .unwrap();

        assert!(
            seen_tp.starts_with("00-4bf92f3577b34da6a3ce929d0e0e4736-"),
            "traceparent '{}' must preserve the original 32-hex trace-id",
            seen_tp
        );
        assert_eq!(
            seen_x_trace, seen_tp,
            "x-trace-id must match the authoritative outgoing traceparent header"
        );
    }

    #[tokio::test]
    async fn test_grpc_web_rejects_compressed_frame_and_sends_identity_accept_encoding() {
        let captured = Arc::new(std::sync::Mutex::new(None::<hyper::HeaderMap>));
        let cap = captured.clone();
        let port = spawn_h2_upstream(move |req| {
            let cap = cap.clone();
            async move {
                *cap.lock().unwrap() = Some(req.headers().clone());
                let _ = req.into_body().collect().await;
                // Compressed flag = 1 (unsupported when identity requested)
                let frame = Bytes::from_static(&[1, 0, 0, 0, 4, 0x0a, 0x02, b'h', b'i']);
                Ok(hyper::Response::builder()
                    .status(200)
                    .body(Full::new(frame))
                    .unwrap())
            }
        })
        .await;

        let target = test_target(port);
        let config = test_server_config(5);

        let resp = call_grpc_web(&target, &config, hyper::HeaderMap::new()).await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);

        let seen = captured.lock().unwrap().clone().unwrap();
        assert_eq!(
            seen.get("grpc-accept-encoding").and_then(|v| v.to_str().ok()),
            Some("identity")
        );
    }

    #[tokio::test]
    async fn test_grpc_web_records_success_resets_consecutive_failures_and_timeout_records_failure() {
        // 1. Success resets consecutive_failures to 0
        let port = spawn_h2_upstream(|req| async move {
            let _ = req.into_body().collect().await;
            let frame = Bytes::from_static(&[0, 0, 0, 0, 4, 0x0a, 0x02, b'o', b'k']);
            Ok(hyper::Response::builder()
                .status(200)
                .body(Full::new(frame))
                .unwrap())
        })
        .await;
        let target = test_target(port);
        target.upstreams[0].consecutive_failures.store(2, std::sync::atomic::Ordering::Release);
        let config = test_server_config(5);

        let resp = call_grpc_web(&target, &config, hyper::HeaderMap::new()).await;
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            target.upstreams[0]
                .consecutive_failures
                .load(std::sync::atomic::Ordering::Acquire),
            0
        );

        // 2. Timeout increments failure counter instead of silently succeeding
        let slow_port = spawn_h2_upstream(|req| async move {
            let _ = req.into_body().collect().await;
            tokio::time::sleep(Duration::from_secs(3)).await;
            Ok(hyper::Response::new(Full::new(Bytes::new())))
        })
        .await;
        let slow_target = test_target(slow_port);
        let short_cfg = test_server_config(1);
        let resp = call_grpc_web(&slow_target, &short_cfg, hyper::HeaderMap::new()).await;
        assert_eq!(resp.status(), StatusCode::GATEWAY_TIMEOUT);
        assert!(
            slow_target.upstreams[0]
                .consecutive_failures
                .load(std::sync::atomic::Ordering::Acquire)
                >= 1
        );
    }

    #[tokio::test]
    async fn test_grpc_web_stale_while_revalidate_does_not_block_on_refresh_lock() {
        let port = spawn_h2_upstream(|req| async move {
            let _ = req.into_body().collect().await;
            let frame = Bytes::from_static(&[0, 0, 0, 0, 4, 0x0a, 0x02, b'o', b'k']);
            Ok(hyper::Response::builder()
                .status(200)
                .body(Full::new(frame))
                .unwrap())
        })
        .await;
        let target = test_target(port);
        // Mark cached pool as expired while another task holds grpc_reflection_lock
        {
            let mut w = target.grpc_pool.write().await;
            if let Some(ref mut cached) = *w {
                cached.created_at = std::time::Instant::now() - Duration::from_secs(3600);
            }
        }
        let held_lock = target.grpc_reflection_lock.lock().await;

        let config = test_server_config(5);
        let started = std::time::Instant::now();
        let resp = tokio::time::timeout(
            Duration::from_millis(500),
            call_grpc_web(&target, &config, hyper::HeaderMap::new()),
        )
        .await
        .expect("stale-while-revalidate must not deadlock or block waiting for reflection lock");
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(started.elapsed() < Duration::from_millis(500));
        drop(held_lock);
    }

    #[tokio::test]
    async fn test_grpc_web_response_body_distinguishes_route_cap_and_global_budget() {
        // 1. Per-route cap exceeded -> fails with global_exhausted == false
        let budget = super::super::BufferBudget::new(1024);
        let mut reservation = super::super::BufferReservation::new(Arc::clone(&budget));
        let mut global_exhausted = false;
        let mut inner_route_exceeded = Full::new(Bytes::from(vec![b'a'; 100]));
        let res_route = GrpcWebResponseBody {
            inner: &mut inner_route_exceeded,
            max_response_bytes: 50,
            read_bytes: 0,
            reservation: &mut reservation,
            global_exhausted: &mut global_exhausted,
        }
        .collect()
        .await;
        assert!(res_route.is_err());
        assert!(!global_exhausted);
        assert_eq!(budget.remaining(), 1024);

        // 2. Global budget exhausted -> fails with global_exhausted == true and restores on Drop
        let small_global = super::super::BufferBudget::new(40);
        {
            let mut res_global = super::super::BufferReservation::new(Arc::clone(&small_global));
            let mut global_flag = false;
            let mut inner_global_exceeded = Full::new(Bytes::from(vec![b'b'; 60]));
            let res = GrpcWebResponseBody {
                inner: &mut inner_global_exceeded,
                max_response_bytes: 1024,
                read_bytes: 0,
                reservation: &mut res_global,
                global_exhausted: &mut global_flag,
            }
            .collect()
            .await;
            assert!(res.is_err());
            assert!(global_flag);
        }
        assert_eq!(small_global.remaining(), 40);
    }
}
