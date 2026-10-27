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
    configuration::{ParsedRoute, ServerConfig},
};

/// Transcodes an incoming HTTP/JSON request into a binary HTTP/2 gRPC call,
/// dispatches it to a load-balanced upstream node, and translates the binary
/// Protobuf response back into `application/json`.
///
/// # Arguments
///
/// * `route_info` – The matched [`ParsedRoute`] containing upstream nodes, retry policy,
///   and the RwLock-protected gRPC reflection [`DescriptorPool`] cache.
/// * `request_body` – The buffered JSON request payload from the client.
/// * `original_method` – The HTTP method of the incoming request (must be `POST`).
/// * `prepared_headers` – Sanitized proxy headers (including forwarded identity and trace headers).
/// * `original_uri` – The original request URI whose path identifies `/<Service>/<Method>`.
/// * `client_addr` – Optional peer socket address used for sticky load-balancing.
/// * `server_name` – Static server identifier for structured logging and diagnostics.
/// * `grpc_client` – Shared HTTP/2-only Hyper client configured with upstream TLS/mTLS.
/// * `config` – Reference to the enclosing [`ServerConfig`] for timeout and reflection parameters.
///
/// # Returns
///
/// Returns an HTTP [`Response<ServiceRespBody>`] with `content-type: application/json` on success,
/// or an appropriate synthetic HTTP error status (`400`, `404`, `502`, `504`) on failure.
pub async fn handle_grpc_web(
    route_info: &ParsedRoute,
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
) -> Result<Response<ServiceRespBody>, SrvError> {
    let mut failed_nodes = Vec::new();
    let max_retries = route_info.target.max_retries;
    let mut attempts = 0;

    loop {
        let mut current_headers = if attempts == max_retries {
            std::mem::take(&mut prepared_headers)
        } else {
            prepared_headers.clone()
        };
        attempts += 1;

        let upstream_node = route_info
            .target
            .next_upstream(client_addr.as_ref(), &failed_nodes);
        let backend_base_uri = &upstream_node.uri;
        let _conn_guard = super::upstreams::ConnectionGuard::new(
            route_info.target.clone(),
            backend_base_uri.clone(),
        );

        if let Some(auth) = backend_base_uri.authority() {
            if let Ok(host_val) = header::HeaderValue::from_str(auth.as_str()) {
                current_headers.insert(header::HOST, host_val);
            }
        }

        let reflection_ttl = config
            .router_params
            .as_ref()
            .map(|p| std::time::Duration::from_secs(p.grpc_reflection_ttl_seconds))
            .unwrap_or(std::time::Duration::from_secs(600));

        // 1. Fast path: check if cached pool is valid under read lock
        let mut pool_opt = {
            let read_guard = route_info.target.grpc_pool.read().await;
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

        // 2. Slow path: fetch reflection without holding write lock across network I/O
        if pool_opt.is_none() {
            let _fetch_guard = route_info.target.grpc_reflection_lock.lock().await;

            // Double check if another task refreshed it while we waited for the fetch lock
            let recheck = {
                let read_guard = route_info.target.grpc_pool.read().await;
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
                        let mut write_guard = route_info.target.grpc_pool.write().await;
                        *write_guard = Some(crate::configuration::CachedDescriptorPool {
                            pool: new_pool.clone(),
                            created_at: std::time::Instant::now(),
                        });
                        pool_opt = Some(new_pool);
                    }
                    Err(e) => {
                        error!(
                            "{}: Failed to fetch gRPC reflection schema: {:?}",
                            server_name, e
                        );
                        // Stale-while-revalidate fallback: if we have an expired pool, use it rather than failing
                        let read_guard = route_info.target.grpc_pool.read().await;
                        if let Some(cached) = &*read_guard {
                            warn!(
                                "{}: Using stale gRPC reflection schema due to upstream fetch failure",
                                server_name
                            );
                            pool_opt = Some(cached.pool.clone());
                        } else {
                            return Ok(build_error_response(
                                "Failed to fetch gRPC schema",
                                StatusCode::BAD_GATEWAY,
                            ));
                        }
                    }
                }
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
                return Ok(build_error_response(
                    &format!("Invalid JSON payload: {}", e),
                    StatusCode::BAD_REQUEST,
                ));
            }
        };

        let mut protobuf_payload = BytesMut::new();
        if let Err(e) = dynamic_req_msg.encode(&mut protobuf_payload) {
            return Ok(build_error_response(
                &format!("Encode error: {}", e),
                StatusCode::INTERNAL_SERVER_ERROR,
            ));
        }

        let mut grpc_frame = BytesMut::with_capacity(5 + protobuf_payload.len());
        grpc_frame.put_u8(0);
        grpc_frame.put_u32(protobuf_payload.len() as u32);
        grpc_frame.put_slice(&protobuf_payload);

        let boxed_body: ServiceRespBody = Full::new(grpc_frame.freeze())
            .map_err(SrvError::from)
            .boxed();

        let grpc_target_path = format!("/{}/{}", service_name, method_name);
        let mut proxy_uri_parts = backend_base_uri.clone().into_parts();
        proxy_uri_parts.path_and_query =
            match hyper::http::uri::PathAndQuery::from_maybe_shared(grpc_target_path) {
                Ok(pq) => Some(pq),
                Err(e) => {
                    return Ok(build_error_response(
                        &format!("Invalid gRPC target path: {}", e),
                        StatusCode::BAD_REQUEST,
                    ));
                }
            };
        let final_target_uri = match Uri::from_parts(proxy_uri_parts) {
            Ok(u) => u,
            Err(e) => {
                return Ok(build_error_response(
                    &format!("Invalid gRPC target URI: {}", e),
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
                return Ok(build_error_response(
                    &format!("Failed to build gRPC request: {}", e),
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
        current_headers.insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/grpc"),
        );
        current_headers.insert(
            header::TE,
            header::HeaderValue::from_static("trailers"),
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

        let req_timeout = config
            .router_params
            .as_ref()
            .and_then(|p| {
                (p.request_timeout_seconds > 0)
                    .then(|| std::time::Duration::from_secs(p.request_timeout_seconds))
            })
            .unwrap_or(std::time::Duration::from_secs(30));

        let req_start = std::time::Instant::now();
        let req_result = match tokio::time::timeout(req_timeout, grpc_client.request(proxy_req)).await {
            Ok(res) => res,
            Err(_) => {
                error!(
                    "{}: gRPC transcoding request to {} timed out after {:?}",
                    server_name, backend_base_uri, req_timeout
                );
                return Ok(build_error_response(
                    "Gateway Timeout",
                    StatusCode::GATEWAY_TIMEOUT,
                ));
            }
        };

        match req_result {
            Ok(mut res) => {
                upstream_node.record_latency_ms(req_start.elapsed().as_millis() as u64);
                if res.status() != StatusCode::OK {
                    return Ok(build_error_response(
                        &format!("Backend Error: {}", res.status()),
                        res.status(),
                    ));
                }

                const MAX_GRPC_WEB_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
                let collect_res = tokio::time::timeout(
                    req_timeout,
                    http_body_util::Limited::new(res.body_mut(), MAX_GRPC_WEB_RESPONSE_BYTES).collect(),
                )
                .await;

                let res_body_bytes = match collect_res {
                    Ok(Ok(c)) => c.to_bytes(),
                    Ok(Err(e)) => {
                        return Ok(build_error_response(
                            &format!("Failed to read gRPC body: {}", e),
                            StatusCode::BAD_GATEWAY,
                        ));
                    }
                    Err(_) => {
                        return Ok(build_error_response(
                            "Gateway Timeout reading gRPC response body",
                            StatusCode::GATEWAY_TIMEOUT,
                        ));
                    }
                };

                if res_body_bytes.len() < 5 {
                    return Ok(build_error_response(
                        "Invalid gRPC Response",
                        StatusCode::BAD_GATEWAY,
                    ));
                }

                let payload_len = u32::from_be_bytes([
                    res_body_bytes[1],
                    res_body_bytes[2],
                    res_body_bytes[3],
                    res_body_bytes[4],
                ]) as usize;
                if res_body_bytes.len() < 5 + payload_len {
                    return Ok(build_error_response(
                        "Truncated gRPC Response",
                        StatusCode::BAD_GATEWAY,
                    ));
                }

                let raw_protobuf_res = &res_body_bytes[5..5 + payload_len];

                let mut dynamic_res_msg = DynamicMessage::new(method_desc.output());
                if let Err(e) = dynamic_res_msg.merge(raw_protobuf_res) {
                    return Ok(build_error_response(
                        &format!("Parse error: {}", e),
                        StatusCode::BAD_GATEWAY,
                    ));
                }

                let response_json = match serde_json::to_string(&dynamic_res_msg) {
                    Ok(s) => s,
                    Err(e) => {
                        return Ok(build_error_response(
                            &format!("JSON encode error: {}", e),
                            StatusCode::INTERNAL_SERVER_ERROR,
                        ));
                    }
                };

                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(
                        Full::new(Bytes::from(response_json))
                            .map_err(SrvError::from)
                            .boxed(),
                    )
                    .unwrap());
            }
            Err(e) => {
                error!(
                    "{}: Backend connection failed to {}: {}",
                    server_name, backend_base_uri, e
                );
                route_info.target.mark_dead(backend_base_uri);
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

    use crate::configuration::{
        CachedDescriptorPool, LbStrategy, RouteBackendType, RouteTarget, UpstreamNode,
    };
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

    fn test_route(port: u16) -> ParsedRoute {
        let node = UpstreamNode::new(format!("http://127.0.0.1:{port}").parse().unwrap());
        let target = Arc::new(RouteTarget {
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
        });
        ParsedRoute {
            prefix: "/".to_string(),
            target,
            allowed_roles: Vec::new(),
            backend_type: RouteBackendType::GrpcTranscoding,
        }
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
        route: &ParsedRoute,
        config: &ServerConfig,
        headers: hyper::HeaderMap,
    ) -> Response<ServiceRespBody> {
        let _ = rustls::crypto::ring::default_provider().install_default();
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
            route,
            RequestBody::Buffered(Bytes::from_static(br#"{"text":"hello"}"#)),
            Method::POST,
            headers,
            &uri,
            None,
            "test_server",
            &client,
            config,
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

        let route = test_route(port);
        let config = test_server_config(5);

        let mut headers = hyper::HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        headers.insert(header::CONTENT_LENGTH, "9999".parse().unwrap());
        headers.insert(header::CONNECTION, "keep-alive".parse().unwrap());

        let resp = call_grpc_web(&route, &config, headers).await;
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

        let route = test_route(port);
        let config = test_server_config(1);

        let started = std::time::Instant::now();
        let resp = call_grpc_web(&route, &config, hyper::HeaderMap::new()).await;
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

        let route = test_route(port);
        let config = test_server_config(30);

        let resp = call_grpc_web(&route, &config, hyper::HeaderMap::new()).await;
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

        let route = test_route(port);
        let config = test_server_config(5);

        let expected_tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let mut headers = hyper::HeaderMap::new();
        headers.insert("traceparent", expected_tp.parse().unwrap());

        let resp = call_grpc_web(&route, &config, headers).await;
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
}
