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
        upstream_node
            .active_connections
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        struct ConnectionGuard {
            target: Arc<crate::configuration::RouteTarget>,
            uri: Uri,
        }
        impl Drop for ConnectionGuard {
            fn drop(&mut self) {
                if let Some(node) = self.target.upstreams.iter().find(|n| n.uri == self.uri) {
                    let current = node
                        .active_connections
                        .load(std::sync::atomic::Ordering::Relaxed);
                    if current > 0 {
                        node.active_connections
                            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                    }
                }
            }
        }

        let _conn_guard = ConnectionGuard {
            target: route_info.target.clone(),
            uri: backend_base_uri.clone(),
        };

        if let Some(auth) = backend_base_uri.authority() {
            if let Ok(host_val) = header::HeaderValue::from_str(auth.as_str()) {
                current_headers.insert(header::HOST, host_val);
            }
        }

        // Double-Checked Locking Performance Fix!
        let pool = {
            let read_guard = route_info.target.grpc_pool.read().await;
            if let Some(p) = &*read_guard {
                p.clone()
            } else {
                drop(read_guard);
                let mut write_guard = route_info.target.grpc_pool.write().await;
                if let Some(p) = &*write_guard {
                    p.clone()
                } else {
                    match build_grpc_pool(&upstream_node.uri, config.router_params.as_ref()).await {
                        Ok(p) => {
                            *write_guard = Some(p.clone());
                            p
                        }
                        Err(e) => {
                            error!(
                                "{}: Failed to fetch gRPC reflection schema: {:?}",
                                server_name, e
                            );
                            return Ok(build_error_response(
                                "Failed to fetch gRPC schema",
                                StatusCode::BAD_GATEWAY,
                            ));
                        }
                    }
                }
            }
        };

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
            Some(hyper::http::uri::PathAndQuery::from_maybe_shared(grpc_target_path).unwrap());
        let final_target_uri = Uri::from_parts(proxy_uri_parts).unwrap();

        let mut builder = Request::builder()
            .method(Method::POST)
            .uri(final_target_uri)
            .version(hyper::Version::HTTP_2)
            .header(header::CONTENT_TYPE, "application/grpc")
            .header("te", "trailers");

        if let Some(auth) = current_headers.get(header::AUTHORIZATION) {
            builder = builder.header(header::AUTHORIZATION, auth.clone());
        }

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
        *proxy_req.headers_mut() = current_headers;

        // Inject OpenTelemetry context (e.g., traceparent) into the outgoing request headers.
        opentelemetry::global::get_text_map_propagator(|propagator| {
            use tracing_opentelemetry::OpenTelemetrySpanExt;
            propagator.inject_context(
                &tracing::Span::current().context(),
                &mut opentelemetry_http::HeaderInjector(proxy_req.headers_mut()),
            );
        });

        match grpc_client.request(proxy_req).await {
            Ok(mut res) => {
                if res.status() != StatusCode::OK {
                    return Ok(build_error_response(
                        &format!("Backend Error: {}", res.status()),
                        res.status(),
                    ));
                }

                let res_body_bytes = match res.body_mut().collect().await {
                    Ok(c) => c.to_bytes(),
                    Err(e) => {
                        return Ok(build_error_response(
                            &format!("Failed to read gRPC body: {}", e),
                            StatusCode::BAD_GATEWAY,
                        ));
                    }
                };

                if res_body_bytes.len() < 5 {
                    return Ok(build_error_response(
                        "Invalid gRPC Response",
                        StatusCode::BAD_GATEWAY,
                    ));
                }

                let payload_len =
                    u32::from_be_bytes(res_body_bytes[1..5].try_into().unwrap()) as usize;
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

pub async fn build_grpc_pool(
    backend_base_uri: &Uri,
    router_params: Option<&crate::configuration::RouterParams>,
) -> Result<Arc<DescriptorPool>, Box<dyn std::error::Error + Send + Sync>> {
    let host = backend_base_uri.host().unwrap_or("localhost");
    let port = backend_base_uri.port_u16().unwrap_or(80);
    let scheme = backend_base_uri.scheme_str().unwrap_or("http");

    let target = format!("{}://{}:{}", scheme, host, port);
    let mut endpoint = tonic::transport::Channel::from_shared(target)?;

    if scheme == "https" {
        let mut tls = tonic::transport::ClientTlsConfig::new().domain_name(host);

        if let Some(params) = router_params {
            if let Some(ca_path) = &params.ssl_root_certificate {
                let pem = std::fs::read(ca_path).unwrap_or_else(|_| Vec::new());
                if !pem.is_empty() {
                    let ca = tonic::transport::Certificate::from_pem(pem);
                    tls = tls.ca_certificate(ca);
                }
            }

            if params.authentication == crate::configuration::AuthenticationMethod::ClientCert
                && let (Some(cert_path), Some(key_path)) =
                    (&params.ssl_client_certificate, &params.ssl_client_key)
                && let (Ok(cert_pem), Ok(key_pem)) =
                    (std::fs::read(cert_path), std::fs::read(key_path))
            {
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
