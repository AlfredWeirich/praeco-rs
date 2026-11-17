use bytes::{BufMut, Bytes, BytesMut};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Method, Response, StatusCode, Uri, Version, header};
use hyper_util::client::legacy::Client;
use serde::Serialize;
use serde::de::IgnoredAny;
use std::collections::BTreeMap;
use std::sync::Arc;
use tokio::task::JoinSet;
use tracing::{Instrument, error, info_span, warn};

use super::{RequestBody, build_error_response, grpc_web, http_proxy};
use crate::{
    ServiceRespBody, SrvError,
    configuration::{ParsedAggregateTarget, ParsedRoute, RouteBackendType, ServerConfig},
};

/// Maximum size of a single sub-upstream response body buffered during aggregation (16 MiB).
const MAX_AGGREGATE_SUB_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
/// Maximum error snippet read from a failed sub-upstream response for `_errors` reporting.
const MAX_ERROR_SNIPPET_BYTES: usize = 1024;

#[derive(Debug, Serialize)]
struct AggregateErrorEntry {
    status: u16,
    message: String,
}

enum SubOutcome {
    Success(Bytes),
    Failed { status: StatusCode, message: String },
}

/// Converts URL query parameters into a compact JSON object `Bytes` for gRPC transcoding.
///
/// Repeated keys are encoded as JSON arrays of strings; single keys as JSON strings.
/// An empty query string produces `{}`.
fn query_to_json_bytes(query: Option<&str>) -> Bytes {
    let Some(q) = query.filter(|s| !s.is_empty()) else {
        return Bytes::from_static(b"{}");
    };

    let mut grouped: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (k, v) in url::form_urlencoded::parse(q.as_bytes()) {
        grouped
            .entry(k.into_owned())
            .or_default()
            .push(v.into_owned());
    }

    let mut obj = serde_json::Map::with_capacity(grouped.len());
    for (k, mut vals) in grouped {
        if vals.len() == 1 {
            obj.insert(k, serde_json::Value::String(vals.remove(0)));
        } else {
            obj.insert(
                k,
                serde_json::Value::Array(vals.into_iter().map(serde_json::Value::String).collect()),
            );
        }
    }

    match serde_json::to_vec(&serde_json::Value::Object(obj)) {
        Ok(vec) => Bytes::from(vec),
        Err(_) => Bytes::from_static(b"{}"),
    }
}

/// Combines an optional target-configured query string with the incoming client query string.
fn combine_queries(target_query: Option<&str>, client_query: Option<&str>) -> Option<String> {
    match (
        target_query.filter(|q| !q.is_empty()),
        client_query.filter(|q| !q.is_empty()),
    ) {
        (Some(tq), Some(cq)) => Some(format!("{tq}&{cq}")),
        (Some(tq), None) => Some(tq.to_string()),
        (None, Some(cq)) => Some(cq.to_string()),
        (None, None) => None,
    }
}

/// Builds the effective URI passed to a sub-request handler by merging any incoming query parameters.
fn build_effective_target_uri(target_uri: &Uri, client_query: Option<&str>) -> Uri {
    let Some(combined) = combine_queries(target_uri.query(), client_query) else {
        return target_uri.clone();
    };
    let pq = format!("{}?{}", target_uri.path(), combined);
    pq.parse::<Uri>().unwrap_or_else(|_| target_uri.clone())
}

/// Parses an incoming JSON body once into top-level object slices keyed by target key.
///
/// Returns `None` if the body is empty or not a JSON object (in which case each sub-target
/// receives the full buffered payload unchanged).
fn split_json_object_by_key(body: &Bytes) -> Option<serde_json::Map<String, serde_json::Value>> {
    if body.is_empty() {
        return None;
    }
    match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(serde_json::Value::Object(map)) => Some(map),
        _ => None,
    }
}

/// Selects the request payload for a specific sub-target.
fn select_sub_body(
    sub_target: &ParsedAggregateTarget,
    sub_method: &Method,
    raw_body: &Bytes,
    split_object: Option<&serde_json::Map<String, serde_json::Value>>,
    effective_query: Option<&str>,
) -> Bytes {
    if sub_target.backend_type == RouteBackendType::Rest
        && matches!(*sub_method, Method::GET | Method::HEAD)
    {
        return Bytes::new();
    }

    if let Some(map) = split_object
        && let Some(val) = map.get(&sub_target.key)
        && let Ok(serialized) = serde_json::to_vec(val)
    {
        return Bytes::from(serialized);
    }

    if raw_body.is_empty() && sub_target.backend_type == RouteBackendType::GrpcTranscoding {
        return query_to_json_bytes(effective_query);
    }

    raw_body.clone()
}

/// Sanitizes headers for a REST fan-out sub-call so length/compression match the sub-payload.
fn prepare_rest_sub_headers(
    base_headers: &hyper::HeaderMap,
    sub_method: &Method,
    sub_body: &Bytes,
) -> hyper::HeaderMap {
    let mut headers = base_headers.clone();
    headers.remove(header::CONTENT_LENGTH);
    headers.remove(header::TRANSFER_ENCODING);
    // Avoid receiving compressed JSON from REST upstreams so bytes can be spliced directly.
    headers.remove(header::ACCEPT_ENCODING);

    if matches!(*sub_method, Method::GET | Method::HEAD) {
        headers.remove(header::CONTENT_TYPE);
    } else if !sub_body.is_empty() {
        if let Ok(len_val) = header::HeaderValue::from_str(&sub_body.len().to_string()) {
            headers.insert(header::CONTENT_LENGTH, len_val);
        }
        headers
            .entry(header::CONTENT_TYPE)
            .or_insert_with(|| header::HeaderValue::from_static("application/json"));
    }

    headers
}

/// Reads and validates the response produced by a single sub-request handler.
async fn collect_sub_outcome(
    sub_target: &ParsedAggregateTarget,
    resp: Response<ServiceRespBody>,
    body_timeout: Option<std::time::Duration>,
) -> SubOutcome {
    let status = resp.status();
    let collect_fut = Limited::new(resp.into_body(), MAX_AGGREGATE_SUB_RESPONSE_BYTES).collect();
    let collected = match body_timeout {
        Some(dur) => match tokio::time::timeout(dur, collect_fut).await {
            Ok(res) => res,
            Err(_) => {
                return SubOutcome::Failed {
                    status: StatusCode::GATEWAY_TIMEOUT,
                    message: "Gateway Timeout reading sub-response".to_string(),
                };
            }
        },
        None => collect_fut.await,
    };

    let bytes = match collected {
        Ok(c) => c.to_bytes(),
        Err(e) => {
            return SubOutcome::Failed {
                status: StatusCode::BAD_GATEWAY,
                message: format!("Failed to read sub-response: {e}"),
            };
        }
    };

    if !status.is_success() {
        let snippet_len = bytes.len().min(MAX_ERROR_SNIPPET_BYTES);
        let msg = String::from_utf8_lossy(&bytes[..snippet_len])
            .trim()
            .to_string();
        let message = if msg.is_empty() {
            status
                .canonical_reason()
                .unwrap_or("Upstream Error")
                .to_string()
        } else {
            msg
        };
        return SubOutcome::Failed { status, message };
    }

    if bytes.is_empty() {
        return SubOutcome::Success(Bytes::from_static(b"null"));
    }

    // Validate REST upstream payloads are syntactically valid JSON without allocating a DOM tree.
    if sub_target.backend_type == RouteBackendType::Rest
        && let Err(e) = serde_json::from_slice::<IgnoredAny>(&bytes)
    {
        warn!(
            "Aggregate target '{}' returned non-JSON REST response: {}",
            sub_target.key, e
        );
        return SubOutcome::Failed {
            status: StatusCode::BAD_GATEWAY,
            message: format!("Upstream '{}' returned invalid JSON", sub_target.key),
        };
    }

    SubOutcome::Success(bytes)
}

/// Executes a single fan-out sub-request against either `grpc_web` or `http_proxy`.
#[allow(clippy::too_many_arguments)]
async fn execute_sub_target(
    sub_target: Arc<ParsedAggregateTarget>,
    sub_body: Bytes,
    sub_method: Method,
    effective_uri: Uri,
    original_version: Version,
    prepared_headers: hyper::HeaderMap,
    client_addr: Option<std::net::SocketAddr>,
    server_name: &'static str,
    client: Client<
        common::client::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        ServiceRespBody,
    >,
    grpc_client: Client<
        common::client::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        ServiceRespBody,
    >,
    config: Arc<ServerConfig>,
    request_timeout: Option<std::time::Duration>,
) -> SubOutcome {
    let synthetic_route = ParsedRoute {
        prefix: sub_target.target_uri.path().to_string(),
        target: sub_target.target.clone(),
        allowed_roles: Vec::new(),
        backend_type: sub_target.backend_type.clone(),
        aggregate_targets: Vec::new(),
    };

    let result = match sub_target.backend_type {
        RouteBackendType::GrpcTranscoding => {
            grpc_web::handle_grpc_web(
                &synthetic_route,
                RequestBody::Buffered(sub_body),
                Method::POST,
                prepared_headers,
                &effective_uri,
                client_addr,
                server_name,
                &grpc_client,
                &config,
            )
            .await
        }
        RouteBackendType::Rest => {
            let rest_headers = prepare_rest_sub_headers(&prepared_headers, &sub_method, &sub_body);
            let mut path_router = matchit::Router::new();
            let _ = path_router.insert("/", ());
            let _ = path_router.insert("/{*rest}", ());

            match path_router.at(effective_uri.path()) {
                Ok(matched) => {
                    http_proxy::handle_http_proxy(
                        &synthetic_route,
                        RequestBody::Buffered(sub_body),
                        sub_method,
                        original_version,
                        rest_headers,
                        &effective_uri,
                        &matched.params,
                        client_addr,
                        server_name,
                        &client,
                        request_timeout,
                    )
                    .await
                }
                Err(e) => {
                    return SubOutcome::Failed {
                        status: StatusCode::INTERNAL_SERVER_ERROR,
                        message: format!("Invalid target path '{}': {e}", effective_uri.path()),
                    };
                }
            }
        }
        _ => {
            return SubOutcome::Failed {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                message: "Unsupported aggregate target backend_type".to_string(),
            };
        }
    };

    match result {
        Ok(resp) => collect_sub_outcome(&sub_target, resp, request_timeout).await,
        Err(e) => SubOutcome::Failed {
            status: StatusCode::BAD_GATEWAY,
            message: format!("Sub-request failed: {e}"),
        },
    }
}

/// Assembles all sub-target outcomes into a single JSON object in `BytesMut` without parsing
/// successful JSON responses into an intermediate DOM.
fn assemble_aggregated_json(
    targets: &[ParsedAggregateTarget],
    outcomes: &[Option<SubOutcome>],
) -> Result<Bytes, SrvError> {
    let mut estimated_cap = 16usize;
    for (target, outcome_opt) in targets.iter().zip(outcomes.iter()) {
        estimated_cap += target.key.len() + 6;
        if let Some(SubOutcome::Success(b)) = outcome_opt {
            estimated_cap += b.len();
        } else {
            estimated_cap += 64;
        }
    }

    let mut out = BytesMut::with_capacity(estimated_cap);
    out.put_u8(b'{');

    let mut errors_map: BTreeMap<&str, AggregateErrorEntry> = BTreeMap::new();

    for (idx, (target, outcome_opt)) in targets.iter().zip(outcomes.iter()).enumerate() {
        if idx > 0 {
            out.put_u8(b',');
        }
        let escaped_key = serde_json::to_string(&target.key)
            .map_err(|e| SrvError::Other(format!("Failed to serialize aggregate key: {e}")))?;
        out.put_slice(escaped_key.as_bytes());
        out.put_u8(b':');

        match outcome_opt {
            Some(SubOutcome::Success(raw_json)) => {
                out.put_slice(raw_json);
            }
            Some(SubOutcome::Failed { status, message }) => {
                out.put_slice(b"null");
                errors_map.insert(
                    target.key.as_str(),
                    AggregateErrorEntry {
                        status: status.as_u16(),
                        message: message.clone(),
                    },
                );
            }
            None => {
                out.put_slice(b"null");
            }
        }
    }

    if !errors_map.is_empty() {
        out.put_slice(br#","_errors":"#);
        let errors_json = serde_json::to_vec(&errors_map)
            .map_err(|e| SrvError::Other(format!("Failed to serialize _errors map: {e}")))?;
        out.put_slice(&errors_json);
    }

    out.put_u8(b'}');
    Ok(out.freeze())
}

/// Handles a fan-out aggregation route (`backend_type = "aggregate"`).
///
/// Dispatches all configured `aggregate_targets` concurrently via a [`JoinSet`],
/// propagates OpenTelemetry span context and prepared identity headers, aborts
/// immediately when any `required = true` target fails, and degrades gracefully
/// with `"<key>": null` + `"_errors"` when `required = false` targets fail.
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip_all, fields(server = %server_name, route = %route_info.prefix, method = %original_method))]
pub async fn handle_aggregate(
    route_info: &ParsedRoute,
    request_body: RequestBody,
    original_method: Method,
    original_version: Version,
    prepared_headers: hyper::HeaderMap,
    original_uri: &Uri,
    client_addr: Option<std::net::SocketAddr>,
    server_name: &'static str,
    client: &Client<
        common::client::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        ServiceRespBody,
    >,
    grpc_client: &Client<
        common::client::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        ServiceRespBody,
    >,
    config: &Arc<ServerConfig>,
    request_timeout: Option<std::time::Duration>,
) -> Result<Response<ServiceRespBody>, SrvError> {
    if !matches!(original_method, Method::GET | Method::POST) {
        return Ok(build_error_response(
            "Method Not Allowed: Aggregate routes support GET and POST",
            StatusCode::METHOD_NOT_ALLOWED,
        ));
    }

    let RequestBody::Buffered(raw_body) = request_body else {
        return Ok(build_error_response(
            "Streaming request bodies are not supported for aggregate routes",
            StatusCode::INTERNAL_SERVER_ERROR,
        ));
    };

    if route_info.aggregate_targets.is_empty() {
        return Ok(build_error_response(
            "Aggregate route has no targets configured",
            StatusCode::INTERNAL_SERVER_ERROR,
        ));
    }

    let split_object = split_json_object_by_key(&raw_body);
    let client_query = original_uri.query();

    let mut join_set: JoinSet<(usize, SubOutcome)> = JoinSet::new();

    for (idx, target) in route_info.aggregate_targets.iter().enumerate() {
        let sub_target = Arc::new(target.clone());
        let effective_uri = build_effective_target_uri(&sub_target.target_uri, client_query);
        let sub_method = match sub_target.backend_type {
            RouteBackendType::GrpcTranscoding => Method::POST,
            _ => sub_target
                .method
                .clone()
                .unwrap_or_else(|| original_method.clone()),
        };

        let sub_body = select_sub_body(
            &sub_target,
            &sub_method,
            &raw_body,
            split_object.as_ref(),
            effective_uri.query(),
        );

        let sub_headers = prepared_headers.clone();
        let sub_client = client.clone();
        let sub_grpc_client = grpc_client.clone();
        let sub_config = Arc::clone(config);
        let span = info_span!(
            "aggregate_subrequest",
            target_key = %sub_target.key,
            backend_type = ?sub_target.backend_type
        );

        join_set.spawn(
            async move {
                let outcome = execute_sub_target(
                    sub_target,
                    sub_body,
                    sub_method,
                    effective_uri,
                    original_version,
                    sub_headers,
                    client_addr,
                    server_name,
                    sub_client,
                    sub_grpc_client,
                    sub_config,
                    request_timeout,
                )
                .await;
                (idx, outcome)
            }
            .instrument(span),
        );
    }

    let mut outcomes: Vec<Option<SubOutcome>> = (0..route_info.aggregate_targets.len())
        .map(|_| None)
        .collect();

    while let Some(join_res) = join_set.join_next().await {
        match join_res {
            Ok((idx, outcome)) => {
                if let SubOutcome::Failed {
                    ref status,
                    ref message,
                } = outcome
                {
                    let target = &route_info.aggregate_targets[idx];
                    if target.required {
                        error!(
                            "{}: Required aggregate target '{}' failed with {} ({}); aborting remaining sub-requests",
                            server_name, target.key, status, message
                        );
                        join_set.abort_all();
                        return Ok(build_error_response(message, *status));
                    }
                    warn!(
                        "{}: Optional aggregate target '{}' failed with {} ({}); degrading gracefully",
                        server_name, target.key, status, message
                    );
                }
                outcomes[idx] = Some(outcome);
            }
            Err(join_err) => {
                error!(
                    "{}: Aggregate sub-task failed unexpectedly: {}",
                    server_name, join_err
                );
                join_set.abort_all();
                return Ok(build_error_response(
                    "Internal Gateway Error",
                    StatusCode::INTERNAL_SERVER_ERROR,
                ));
            }
        }
    }

    let merged_json = assemble_aggregated_json(&route_info.aggregate_targets, &outcomes)?;

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Full::new(merged_json).map_err(SrvError::from).boxed())
        .map_err(|e| SrvError::Other(format!("Failed to build aggregate response: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::{
        CachedDescriptorPool, LbStrategy, RouteTarget, UpstreamNode,
    };
    use hyper::Request;
    use prost::Message;
    use prost_reflect::{
        DescriptorPool, DynamicMessage,
        prost_types::{
            DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
            MethodDescriptorProto, ServiceDescriptorProto,
            field_descriptor_proto::{Label, Type},
        },
    };
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    fn test_descriptor_pool() -> Arc<DescriptorPool> {
        let file = FileDescriptorProto {
            name: Some("user.proto".into()),
            package: Some("user".into()),
            syntax: Some("proto3".into()),
            message_type: vec![
                DescriptorProto {
                    name: Some("UserReq".into()),
                    field: vec![FieldDescriptorProto {
                        name: Some("user_id".into()),
                        json_name: Some("user_id".into()),
                        number: Some(1),
                        label: Some(Label::Optional as i32),
                        r#type: Some(Type::String as i32),
                        ..Default::default()
                    }],
                    ..Default::default()
                },
                DescriptorProto {
                    name: Some("UserRes".into()),
                    field: vec![
                        FieldDescriptorProto {
                            name: Some("id".into()),
                            json_name: Some("id".into()),
                            number: Some(1),
                            label: Some(Label::Optional as i32),
                            r#type: Some(Type::String as i32),
                            ..Default::default()
                        },
                        FieldDescriptorProto {
                            name: Some("name".into()),
                            json_name: Some("name".into()),
                            number: Some(2),
                            label: Some(Label::Optional as i32),
                            r#type: Some(Type::String as i32),
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                },
            ],
            service: vec![ServiceDescriptorProto {
                name: Some("UserService".into()),
                method: vec![MethodDescriptorProto {
                    name: Some("GetUser".into()),
                    input_type: Some(".user.UserReq".into()),
                    output_type: Some(".user.UserRes".into()),
                    ..Default::default()
                }],
                ..Default::default()
            }],
            ..Default::default()
        };
        Arc::new(
            DescriptorPool::from_file_descriptor_set(FileDescriptorSet { file: vec![file] })
                .expect("valid descriptor pool"),
        )
    }

    fn test_server_config(request_timeout_seconds: u64) -> Arc<ServerConfig> {
        let toml_str = format!(
            r#"
            name = "agg_test"
            enabled = true
            protocol = "http"
            service = "Router"
            ip = "127.0.0.1"
            port = 8080

            [RouterParams]
            protocol = "http"
            request_timeout_seconds = {request_timeout_seconds}

            [Layers]
            enabled = []
        "#
        );
        let mut cfg: ServerConfig = toml::from_str(&toml_str).unwrap();
        cfg.finalize().unwrap();
        Arc::new(cfg)
    }

    fn build_clients() -> (
        Client<
            common::client::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
            ServiceRespBody,
        >,
        Client<
            common::client::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
            ServiceRespBody,
        >,
    ) {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let http_client = common::client::build_hyper_client(
            tls.clone(),
            common::client::ClientPoolConfig::default(),
        );
        let grpc_client = common::client::build_hyper_client(
            tls,
            common::client::ClientPoolConfig {
                http2_only: true,
                ..Default::default()
            },
        );
        (http_client, grpc_client)
    }

    async fn spawn_grpc_user_mock(
        pool: Arc<DescriptorPool>,
        captured_trace: Option<Arc<tokio::sync::Mutex<Option<String>>>>,
    ) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    break;
                };
                let pool = pool.clone();
                let captured_trace = captured_trace.clone();
                tokio::spawn(async move {
                    let io = hyper_util::rt::TokioIo::new(socket);
                    let _ = hyper::server::conn::http2::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(
                        io,
                        hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                            let pool = pool.clone();
                            let captured_trace = captured_trace.clone();
                            async move {
                                if let Some(slot) = captured_trace {
                                    let val = req
                                        .headers()
                                        .get("traceparent")
                                        .and_then(|v| v.to_str().ok())
                                        .map(|s| s.to_string());
                                    *slot.lock().await = val;
                                }
                                let body_bytes = req.into_body().collect().await.unwrap().to_bytes();
                                let mut req_msg =
                                    DynamicMessage::new(pool.get_message_by_name("user.UserReq").unwrap());
                                if body_bytes.len() > 5 {
                                    let len = u32::from_be_bytes([
                                        body_bytes[1],
                                        body_bytes[2],
                                        body_bytes[3],
                                        body_bytes[4],
                                    ]) as usize;
                                    let payload = &body_bytes[5..5 + len];
                                    req_msg.merge(payload).unwrap();
                                }
                                let uid = req_msg
                                    .get_field_by_name("user_id")
                                    .map(|v| v.as_str().unwrap_or("").to_string())
                                    .unwrap_or_default();

                                let mut res_msg =
                                    DynamicMessage::new(pool.get_message_by_name("user.UserRes").unwrap());
                                res_msg.set_field_by_name(
                                    "id",
                                    prost_reflect::Value::String(uid.clone()),
                                );
                                res_msg.set_field_by_name(
                                    "name",
                                    prost_reflect::Value::String(format!("User-{uid}")),
                                );
                                let encoded = res_msg.encode_to_vec();
                                let mut frame = BytesMut::with_capacity(5 + encoded.len());
                                frame.put_u8(0);
                                frame.put_u32(encoded.len() as u32);
                                frame.put_slice(&encoded);

                                Ok::<_, std::convert::Infallible>(
                                    Response::builder()
                                        .status(StatusCode::OK)
                                        .header("content-type", "application/grpc")
                                        .header("grpc-status", "0")
                                        .body(Full::new(frame.freeze()))
                                        .unwrap(),
                                )
                            }
                        }),
                    )
                    .await;
                });
            }
        });
        port
    }

    async fn spawn_rest_mock(
        status: StatusCode,
        response_body: &'static str,
        delay: Duration,
        captured_uri: Option<Arc<tokio::sync::Mutex<Option<String>>>>,
        captured_trace: Option<Arc<tokio::sync::Mutex<Option<String>>>>,
    ) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    break;
                };
                let captured_uri = captured_uri.clone();
                let captured_trace = captured_trace.clone();
                tokio::spawn(async move {
                    let io = hyper_util::rt::TokioIo::new(socket);
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(
                            io,
                            hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                                let captured_uri = captured_uri.clone();
                                let captured_trace = captured_trace.clone();
                                async move {
                                    if let Some(slot) = captured_uri {
                                        *slot.lock().await = Some(req.uri().to_string());
                                    }
                                    if let Some(slot) = captured_trace {
                                        let val = req
                                            .headers()
                                            .get("traceparent")
                                            .and_then(|v| v.to_str().ok())
                                            .map(|s| s.to_string());
                                        *slot.lock().await = val;
                                    }
                                    if !delay.is_zero() {
                                        tokio::time::sleep(delay).await;
                                    }
                                    Ok::<_, std::convert::Infallible>(
                                        Response::builder()
                                            .status(status)
                                            .header("content-type", "application/json")
                                            .body(Full::new(Bytes::from_static(
                                                response_body.as_bytes(),
                                            )))
                                            .unwrap(),
                                    )
                                }
                            }),
                        )
                        .await;
                });
            }
        });
        port
    }

    fn make_sub_target(
        key: &str,
        backend_type: RouteBackendType,
        port: u16,
        path: &str,
        method: Option<Method>,
        required: bool,
        pool: Option<Arc<DescriptorPool>>,
    ) -> ParsedAggregateTarget {
        let node = UpstreamNode::new(format!("http://127.0.0.1:{port}").parse().unwrap());
        let grpc_pool = pool.map(|p| CachedDescriptorPool {
            pool: p,
            created_at: std::time::Instant::now(),
        });
        let target = Arc::new(RouteTarget {
            upstreams: vec![node],
            strategy: LbStrategy::RoundRobin,
            rr_counter: AtomicUsize::new(0),
            cooldown_seconds: 60,
            max_retries: 0,
            failure_threshold: 3,
            max_retry_buffer_bytes: 65536,
            active_health_check_interval: 0,
            grpc_pool: tokio::sync::RwLock::new(grpc_pool),
            grpc_reflection_lock: tokio::sync::Mutex::new(()),
        });
        ParsedAggregateTarget {
            key: key.to_string(),
            backend_type,
            target,
            target_uri: path.parse().unwrap(),
            method,
            required,
        }
    }

    fn make_aggregate_route(targets: Vec<ParsedAggregateTarget>) -> ParsedRoute {
        let empty_target = Arc::new(RouteTarget {
            upstreams: Vec::new(),
            strategy: LbStrategy::RoundRobin,
            rr_counter: AtomicUsize::new(0),
            cooldown_seconds: 10,
            max_retries: 0,
            failure_threshold: 3,
            max_retry_buffer_bytes: 65536,
            active_health_check_interval: 0,
            grpc_pool: tokio::sync::RwLock::new(None),
            grpc_reflection_lock: tokio::sync::Mutex::new(()),
        });
        ParsedRoute {
            prefix: "/api/dashboard".to_string(),
            target: empty_target,
            allowed_roles: Vec::new(),
            backend_type: RouteBackendType::Aggregate,
            aggregate_targets: targets,
        }
    }

    #[tokio::test]
    async fn test_aggregate_mixed_grpc_and_rest_post_split_payload() {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
        let pool = test_descriptor_pool();
        let grpc_port = spawn_grpc_user_mock(pool.clone(), None).await;
        let rest_uri_slot = Arc::new(tokio::sync::Mutex::new(None));
        let rest_port = spawn_rest_mock(
            StatusCode::OK,
            r#"[{"id":1,"msg":"hi"}]"#,
            Duration::ZERO,
            Some(rest_uri_slot.clone()),
            None,
        )
        .await;

        let route = make_aggregate_route(vec![
            make_sub_target(
                "user",
                RouteBackendType::GrpcTranscoding,
                grpc_port,
                "/user.UserService/GetUser",
                None,
                true,
                Some(pool),
            ),
            make_sub_target(
                "notifications",
                RouteBackendType::Rest,
                rest_port,
                "/v1/notifications",
                Some(Method::GET),
                false,
                None,
            ),
        ]);

        let (http_client, grpc_client) = build_clients();
        let cfg = test_server_config(5);
        let body = Bytes::from_static(br#"{"user":{"user_id":"42"}}"#);

        let resp = handle_aggregate(
            &route,
            RequestBody::Buffered(body),
            Method::POST,
            Version::HTTP_11,
            hyper::HeaderMap::new(),
            &"/api/dashboard".parse().unwrap(),
            None,
            "agg_test",
            &http_client,
            &grpc_client,
            &cfg,
            Some(Duration::from_secs(5)),
        )
        .await
        .unwrap();

        let status = resp.status();
        let json_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            status,
            StatusCode::OK,
            "Unexpected status {}: {}",
            status,
            String::from_utf8_lossy(&json_bytes)
        );
        let parsed: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();
        assert_eq!(parsed["user"]["id"], "42");
        assert_eq!(parsed["user"]["name"], "User-42");
        assert_eq!(parsed["notifications"][0]["msg"], "hi");
        assert!(parsed.get("_errors").is_none());
        assert_eq!(
            rest_uri_slot.lock().await.as_deref(),
            Some("/v1/notifications")
        );
    }

    #[tokio::test]
    async fn test_aggregate_get_query_params_to_grpc_and_rest() {
        let pool = test_descriptor_pool();
        let grpc_port = spawn_grpc_user_mock(pool.clone(), None).await;
        let rest_uri_slot = Arc::new(tokio::sync::Mutex::new(None));
        let rest_port = spawn_rest_mock(
            StatusCode::OK,
            r#"{"unread":3}"#,
            Duration::ZERO,
            Some(rest_uri_slot.clone()),
            None,
        )
        .await;

        let route = make_aggregate_route(vec![
            make_sub_target(
                "user",
                RouteBackendType::GrpcTranscoding,
                grpc_port,
                "/user.UserService/GetUser",
                None,
                true,
                Some(pool),
            ),
            make_sub_target(
                "notifications",
                RouteBackendType::Rest,
                rest_port,
                "/v1/notifications",
                None,
                true,
                None,
            ),
        ]);

        let (http_client, grpc_client) = build_clients();
        let cfg = test_server_config(5);

        let resp = handle_aggregate(
            &route,
            RequestBody::Buffered(Bytes::new()),
            Method::GET,
            Version::HTTP_11,
            hyper::HeaderMap::new(),
            &"/api/dashboard?user_id=99".parse().unwrap(),
            None,
            "agg_test",
            &http_client,
            &grpc_client,
            &cfg,
            Some(Duration::from_secs(5)),
        )
        .await
        .unwrap();

        let status = resp.status();
        let json_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            status,
            StatusCode::OK,
            "Unexpected status {}: {}",
            status,
            String::from_utf8_lossy(&json_bytes)
        );
        let parsed: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();
        assert_eq!(parsed["user"]["id"], "99");
        assert_eq!(parsed["user"]["name"], "User-99");
        assert_eq!(parsed["notifications"]["unread"], 3);
        assert_eq!(
            rest_uri_slot.lock().await.as_deref(),
            Some("/v1/notifications?user_id=99")
        );
    }

    #[tokio::test]
    async fn test_aggregate_optional_failure_returns_null_and_errors_map() {
        let pool = test_descriptor_pool();
        let grpc_port = spawn_grpc_user_mock(pool.clone(), None).await;
        let failing_rest_port = spawn_rest_mock(
            StatusCode::INTERNAL_SERVER_ERROR,
            "notification service down",
            Duration::ZERO,
            None,
            None,
        )
        .await;

        let route = make_aggregate_route(vec![
            make_sub_target(
                "user",
                RouteBackendType::GrpcTranscoding,
                grpc_port,
                "/user.UserService/GetUser",
                None,
                true,
                Some(pool),
            ),
            make_sub_target(
                "notifications",
                RouteBackendType::Rest,
                failing_rest_port,
                "/v1/notifications",
                Some(Method::GET),
                false,
                None,
            ),
        ]);

        let (http_client, grpc_client) = build_clients();
        let cfg = test_server_config(5);

        let resp = handle_aggregate(
            &route,
            RequestBody::Buffered(Bytes::from_static(br#"{"user_id":"7"}"#)),
            Method::POST,
            Version::HTTP_11,
            hyper::HeaderMap::new(),
            &"/api/dashboard".parse().unwrap(),
            None,
            "agg_test",
            &http_client,
            &grpc_client,
            &cfg,
            Some(Duration::from_secs(5)),
        )
        .await
        .unwrap();

        let status = resp.status();
        let json_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(
            status,
            StatusCode::OK,
            "Unexpected status {}: {}",
            status,
            String::from_utf8_lossy(&json_bytes)
        );
        let parsed: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();
        assert_eq!(parsed["user"]["id"], "7");
        assert!(parsed["notifications"].is_null());
        assert_eq!(parsed["_errors"]["notifications"]["status"], 500);
        assert_eq!(
            parsed["_errors"]["notifications"]["message"],
            "notification service down"
        );
    }

    #[tokio::test]
    async fn test_aggregate_required_failure_aborts_immediately() {
        let dead_port = {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            l.local_addr().unwrap().port()
        };
        let slow_rest_port = spawn_rest_mock(
            StatusCode::OK,
            r#"{"ok":true}"#,
            Duration::from_secs(5),
            None,
            None,
        )
        .await;

        let route = make_aggregate_route(vec![
            make_sub_target(
                "required_svc",
                RouteBackendType::Rest,
                dead_port,
                "/v1/req",
                Some(Method::GET),
                true,
                None,
            ),
            make_sub_target(
                "slow_svc",
                RouteBackendType::Rest,
                slow_rest_port,
                "/v1/slow",
                Some(Method::GET),
                false,
                None,
            ),
        ]);

        let (http_client, grpc_client) = build_clients();
        let cfg = test_server_config(10);

        let start = std::time::Instant::now();
        let resp = handle_aggregate(
            &route,
            RequestBody::Buffered(Bytes::new()),
            Method::GET,
            Version::HTTP_11,
            hyper::HeaderMap::new(),
            &"/api/dashboard".parse().unwrap(),
            None,
            "agg_test",
            &http_client,
            &grpc_client,
            &cfg,
            Some(Duration::from_secs(10)),
        )
        .await
        .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        assert!(
            start.elapsed() < Duration::from_secs(2),
            "Required failure must abort remaining slow sub-requests immediately"
        );
    }

    #[tokio::test]
    async fn test_aggregate_propagates_trace_headers_to_all_targets() {
        let pool = test_descriptor_pool();
        let grpc_trace = Arc::new(tokio::sync::Mutex::new(None));
        let rest_trace = Arc::new(tokio::sync::Mutex::new(None));

        let grpc_port = spawn_grpc_user_mock(pool.clone(), Some(grpc_trace.clone())).await;
        let rest_port = spawn_rest_mock(
            StatusCode::OK,
            r#"{"ok":true}"#,
            Duration::ZERO,
            None,
            Some(rest_trace.clone()),
        )
        .await;

        let route = make_aggregate_route(vec![
            make_sub_target(
                "user",
                RouteBackendType::GrpcTranscoding,
                grpc_port,
                "/user.UserService/GetUser",
                None,
                true,
                Some(pool),
            ),
            make_sub_target(
                "notifications",
                RouteBackendType::Rest,
                rest_port,
                "/v1/notifications",
                Some(Method::GET),
                true,
                None,
            ),
        ]);

        let (http_client, grpc_client) = build_clients();
        let cfg = test_server_config(5);
        let traceparent = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            "traceparent",
            hyper::header::HeaderValue::from_static(traceparent),
        );

        let resp = handle_aggregate(
            &route,
            RequestBody::Buffered(Bytes::from_static(br#"{"user_id":"1"}"#)),
            Method::POST,
            Version::HTTP_11,
            headers,
            &"/api/dashboard".parse().unwrap(),
            None,
            "agg_test",
            &http_client,
            &grpc_client,
            &cfg,
            Some(Duration::from_secs(5)),
        )
        .await
        .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(grpc_trace.lock().await.as_deref(), Some(traceparent));
        assert_eq!(rest_trace.lock().await.as_deref(), Some(traceparent));
    }

    #[tokio::test]
    async fn test_aggregate_invalid_json_from_rest_upstream_required_and_optional() {
        let bad_json_port = spawn_rest_mock(
            StatusCode::OK,
            "<html>not json</html>",
            Duration::ZERO,
            None,
            None,
        )
        .await;
        let ok_port = spawn_rest_mock(
            StatusCode::OK,
            r#"{"ok":true}"#,
            Duration::ZERO,
            None,
            None,
        )
        .await;

        let (http_client, grpc_client) = build_clients();
        let cfg = test_server_config(5);

        // Case A: required = true -> 502 Bad Gateway
        let route_req = make_aggregate_route(vec![make_sub_target(
            "bad",
            RouteBackendType::Rest,
            bad_json_port,
            "/v1/bad",
            Some(Method::GET),
            true,
            None,
        )]);
        let resp_req = handle_aggregate(
            &route_req,
            RequestBody::Buffered(Bytes::new()),
            Method::GET,
            Version::HTTP_11,
            hyper::HeaderMap::new(),
            &"/api/dashboard".parse().unwrap(),
            None,
            "agg_test",
            &http_client,
            &grpc_client,
            &cfg,
            Some(Duration::from_secs(5)),
        )
        .await
        .unwrap();
        assert_eq!(resp_req.status(), StatusCode::BAD_GATEWAY);

        // Case B: required = false -> 200 OK with null + _errors (502)
        let route_opt = make_aggregate_route(vec![
            make_sub_target(
                "good",
                RouteBackendType::Rest,
                ok_port,
                "/v1/ok",
                Some(Method::GET),
                true,
                None,
            ),
            make_sub_target(
                "bad",
                RouteBackendType::Rest,
                bad_json_port,
                "/v1/bad",
                Some(Method::GET),
                false,
                None,
            ),
        ]);
        let resp_opt = handle_aggregate(
            &route_opt,
            RequestBody::Buffered(Bytes::new()),
            Method::GET,
            Version::HTTP_11,
            hyper::HeaderMap::new(),
            &"/api/dashboard".parse().unwrap(),
            None,
            "agg_test",
            &http_client,
            &grpc_client,
            &cfg,
            Some(Duration::from_secs(5)),
        )
        .await
        .unwrap();
        assert_eq!(resp_opt.status(), StatusCode::OK);
        let json_bytes = resp_opt.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();
        assert_eq!(parsed["good"]["ok"], true);
        assert!(parsed["bad"].is_null());
        assert_eq!(parsed["_errors"]["bad"]["status"], 502);
        assert!(
            parsed["_errors"]["bad"]["message"]
                .as_str()
                .unwrap()
                .contains("invalid JSON")
        );
    }

    #[tokio::test]
    async fn test_aggregate_optional_timeout_returns_null_and_504_in_errors() {
        let ok_port = spawn_rest_mock(
            StatusCode::OK,
            r#"{"fast":1}"#,
            Duration::ZERO,
            None,
            None,
        )
        .await;
        let slow_port = spawn_rest_mock(
            StatusCode::OK,
            r#"{"slow":2}"#,
            Duration::from_millis(300),
            None,
            None,
        )
        .await;

        let route = make_aggregate_route(vec![
            make_sub_target(
                "fast",
                RouteBackendType::Rest,
                ok_port,
                "/v1/fast",
                Some(Method::GET),
                true,
                None,
            ),
            make_sub_target(
                "slow",
                RouteBackendType::Rest,
                slow_port,
                "/v1/slow",
                Some(Method::GET),
                false,
                None,
            ),
        ]);

        let (http_client, grpc_client) = build_clients();
        let cfg = test_server_config(5);

        let resp = handle_aggregate(
            &route,
            RequestBody::Buffered(Bytes::new()),
            Method::GET,
            Version::HTTP_11,
            hyper::HeaderMap::new(),
            &"/api/dashboard".parse().unwrap(),
            None,
            "agg_test",
            &http_client,
            &grpc_client,
            &cfg,
            Some(Duration::from_millis(60)),
        )
        .await
        .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let json_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();
        assert_eq!(parsed["fast"]["fast"], 1);
        assert!(parsed["slow"].is_null());
        assert_eq!(parsed["_errors"]["slow"]["status"], 504);
    }

    #[tokio::test]
    async fn test_aggregate_method_not_allowed_returns_405() {
        let route = make_aggregate_route(vec![]);
        let (http_client, grpc_client) = build_clients();
        let cfg = test_server_config(5);

        for method in [Method::PUT, Method::DELETE, Method::PATCH] {
            let resp = handle_aggregate(
                &route,
                RequestBody::Buffered(Bytes::new()),
                method,
                Version::HTTP_11,
                hyper::HeaderMap::new(),
                &"/api/dashboard".parse().unwrap(),
                None,
                "agg_test",
                &http_client,
                &grpc_client,
                &cfg,
                Some(Duration::from_secs(5)),
            )
            .await
            .unwrap();
            assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
        }
    }

    #[tokio::test]
    async fn test_aggregate_rest_post_flat_payload_forwarding_and_header_sanitizing() {
        let captured = Arc::new(tokio::sync::Mutex::new(None::<(
            Option<String>,
            Option<String>,
            Bytes,
        )>));
        let captured_srv = captured.clone();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            if let Ok((socket, _)) = listener.accept().await {
                let io = hyper_util::rt::TokioIo::new(socket);
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        io,
                        hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                            let captured_srv = captured_srv.clone();
                            async move {
                                let cl = req
                                    .headers()
                                    .get(header::CONTENT_LENGTH)
                                    .and_then(|v| v.to_str().ok())
                                    .map(|s| s.to_string());
                                let ae = req
                                    .headers()
                                    .get(header::ACCEPT_ENCODING)
                                    .and_then(|v| v.to_str().ok())
                                    .map(|s| s.to_string());
                                let body = req.into_body().collect().await.unwrap().to_bytes();
                                *captured_srv.lock().await = Some((cl, ae, body));
                                Ok::<_, std::convert::Infallible>(
                                    Response::builder()
                                        .status(StatusCode::OK)
                                        .header("content-type", "application/json")
                                        .body(Full::new(Bytes::from_static(br#"{"saved":true}"#)))
                                        .unwrap(),
                                )
                            }
                        }),
                    )
                    .await;
            }
        });

        let route = make_aggregate_route(vec![make_sub_target(
            "audit",
            RouteBackendType::Rest,
            port,
            "/v1/audit",
            Some(Method::POST),
            true,
            None,
        )]);

        let (http_client, grpc_client) = build_clients();
        let cfg = test_server_config(5);

        let flat_body = Bytes::from_static(br#"{"user_id":"42","action":"login"}"#);
        let mut headers = hyper::HeaderMap::new();
        headers.insert(header::ACCEPT_ENCODING, header::HeaderValue::from_static("gzip, br"));
        // Deliberately mismatched Content-Length to verify sanitizer recomputes it
        headers.insert(header::CONTENT_LENGTH, header::HeaderValue::from_static("9999"));

        let resp = handle_aggregate(
            &route,
            RequestBody::Buffered(flat_body.clone()),
            Method::POST,
            Version::HTTP_11,
            headers,
            &"/api/dashboard".parse().unwrap(),
            None,
            "agg_test",
            &http_client,
            &grpc_client,
            &cfg,
            Some(Duration::from_secs(5)),
        )
        .await
        .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let json_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&json_bytes).unwrap();
        assert_eq!(parsed["audit"]["saved"], true);

        let (got_cl, got_ae, got_body) = captured.lock().await.clone().unwrap();
        assert_eq!(got_cl.as_deref(), Some(flat_body.len().to_string().as_str()));
        assert_eq!(got_ae, None, "Accept-Encoding must be stripped for REST aggregate sub-calls");
        assert_eq!(got_body, flat_body);
    }
}
