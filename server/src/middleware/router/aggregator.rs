use bytes::Bytes;
use http_body_util::{BodyExt, Limited};
use hyper::{Method, Response, StatusCode, Uri, Version, header};
use hyper_util::client::legacy::Client;
use serde::Deserializer as _;
use serde::Serialize;
use serde::de::IgnoredAny;
use std::borrow::Cow;
use std::cell::Cell;
use std::collections::{BTreeMap, VecDeque};
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::task::{Context, Poll};
use tokio::task::JoinSet;
use tracing::{Instrument, error, info_span, warn};

use super::{RequestBody, build_error_response, grpc_web, http_proxy};
use crate::{
    ServiceRespBody, SrvError,
    configuration::{
        AggregatePayloadMode, ParsedAggregateTarget, ParsedRoute, RouteBackendType, ServerConfig,
    },
};

/// Maximum size of a single sub-upstream response body buffered during aggregation (16 MiB).
const MAX_AGGREGATE_SUB_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
/// Maximum error snippet read from a failed sub-upstream response for logs / optional `_errors` reporting.
const MAX_ERROR_SNIPPET_BYTES: usize = 1024;

/// Static catch-all `matchit::Router` shared across all REST aggregate sub-requests
/// so `execute_sub_target` avoids allocating and compiling a new router per call.
fn rest_path_router() -> &'static matchit::Router<()> {
    static ROUTER: OnceLock<matchit::Router<()>> = OnceLock::new();
    ROUTER.get_or_init(|| {
        let mut r = matchit::Router::new();
        let _ = r.insert("/", ());
        let _ = r.insert("/{*rest}", ());
        r
    })
}

#[derive(Debug, Serialize)]
struct AggregateErrorEntry {
    status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    grpc_status: Option<u32>,
    message: String,
}

enum SubOutcome {
    Success(Bytes),
    Failed {
        status: StatusCode,
        grpc_status: Option<u32>,
        client_message: String,
        internal_detail: String,
    },
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

/// Builds the effective URI passed to a sub-request handler while enforcing query precedence:
/// - Operator-pinned parameters in `sub_target.target_uri` always take precedence; client
///   parameters with the same name are dropped to prevent parameter pollution.
/// - If `sub_target.forward_query` is `Some(allowlist)`, only client parameters in `allowlist`
///   are forwarded.
fn build_effective_target_uri(
    sub_target: &ParsedAggregateTarget,
    client_query: Option<&str>,
) -> Uri {
    let target_uri = &sub_target.target_uri;
    let target_query = target_uri.query().filter(|q| !q.is_empty());
    let Some(cq) = client_query.filter(|q| !q.is_empty()) else {
        return target_uri.clone();
    };

    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in url::form_urlencoded::parse(cq.as_bytes()) {
        if sub_target.pinned_query_keys.contains(k.as_ref()) {
            continue;
        }
        if let Some(ref allowlist) = sub_target.forward_query
            && !allowlist.contains(k.as_ref())
        {
            continue;
        }
        serializer.append_pair(&k, &v);
    }
    let filtered_client_query = serializer.finish();

    let combined = match (target_query, filtered_client_query.is_empty()) {
        (Some(tq), false) => format!("{tq}&{filtered_client_query}"),
        (Some(tq), true) => tq.to_string(),
        (None, false) => filtered_client_query,
        (None, true) => return target_uri.clone(),
    };

    let pq = format!("{}?{}", target_uri.path(), combined);
    pq.parse::<Uri>().unwrap_or_else(|_| target_uri.clone())
}

/// Zero-copy [`serde::de::Visitor`] that extracts each top-level key's raw JSON value as a
/// reference-counted [`Bytes::slice_ref`] view into the incoming request buffer without
/// allocating an intermediate `serde_json::Value` DOM or re-serializing sub-payloads.
struct KeyedPayloadVisitor<'a> {
    raw_body: &'a Bytes,
    targets: &'a [Arc<ParsedAggregateTarget>],
    /// Set to `true` when a top-level key does not match any configured target key, so callers
    /// can distinguish that case from generic JSON/shape errors without parsing error strings.
    unknown_key: &'a Cell<bool>,
}

impl<'de, 'a> serde::de::Visitor<'de> for KeyedPayloadVisitor<'a>
where
    'a: 'de,
{
    type Value = Vec<Option<Bytes>>;

    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("a JSON object keyed by aggregate target keys")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::MapAccess<'de>,
    {
        let mut slots = vec![None; self.targets.len()];
        while let Some(key) = map.next_key::<Cow<'de, str>>()? {
            let Some(idx) = self.targets.iter().position(|t| t.key == key.as_ref()) else {
                self.unknown_key.set(true);
                return Err(serde::de::Error::custom("unknown aggregate target key"));
            };
            let raw_val = map.next_value::<&'de serde_json::value::RawValue>()?;
            slots[idx] = Some(self.raw_body.slice_ref(raw_val.get().as_bytes()));
        }
        Ok(slots)
    }
}

/// Validates and slices an incoming JSON body for `AggregatePayloadMode::Keyed` in zero-copy mode.
///
/// Rejects non-object bodies and unknown top-level keys (keys not matching any
/// configured `target.key`) with `400 Bad Request` before fanning out.
fn parse_keyed_payload(
    body: &Bytes,
    targets: &[Arc<ParsedAggregateTarget>],
) -> Result<Option<Vec<Option<Bytes>>>, &'static str> {
    const NOT_AN_OBJECT: &str = "Bad Request: Aggregate keyed payload must be a JSON object";

    if body.is_empty() {
        return Ok(None);
    }

    let unknown_key = Cell::new(false);
    let mut de = serde_json::Deserializer::from_slice(body);
    let parsed = de.deserialize_map(KeyedPayloadVisitor {
        raw_body: body,
        targets,
        unknown_key: &unknown_key,
    });
    let slots = match parsed {
        Ok(slots) => slots,
        Err(_) if unknown_key.get() => {
            return Err("Bad Request: Unknown target key in aggregate payload");
        }
        Err(_) => return Err(NOT_AN_OBJECT),
    };
    de.end().map_err(|_| NOT_AN_OBJECT)?;

    Ok(Some(slots))
}

/// Selects the request payload for a specific sub-target according to `payload_mode`.
///
/// In `Keyed` mode, a target whose key is absent from the request object receives `{}`
/// (or an empty body for REST `GET`/`HEAD`) and **never** receives sibling targets' payloads.
fn select_sub_body(
    target_idx: usize,
    sub_target: &ParsedAggregateTarget,
    sub_method: &Method,
    payload_mode: AggregatePayloadMode,
    raw_body: &Bytes,
    keyed_slices: Option<&[Option<Bytes>]>,
    effective_query: Option<&str>,
) -> Bytes {
    if sub_target.backend_type == RouteBackendType::Rest
        && matches!(*sub_method, Method::GET | Method::HEAD)
    {
        return Bytes::new();
    }

    match payload_mode {
        AggregatePayloadMode::Keyed => {
            if let Some(slices) = keyed_slices {
                if let Some(Some(sub_slice)) = slices.get(target_idx) {
                    return sub_slice.clone();
                }
                return Bytes::from_static(b"{}");
            }
            if sub_target.backend_type == RouteBackendType::GrpcTranscoding {
                query_to_json_bytes(effective_query)
            } else {
                Bytes::new()
            }
        }
        AggregatePayloadMode::Broadcast => {
            if raw_body.is_empty() && sub_target.backend_type == RouteBackendType::GrpcTranscoding {
                query_to_json_bytes(effective_query)
            } else {
                raw_body.clone()
            }
        }
    }
}

/// Strips conditional and range headers (`if-*`, `range`) once on the incoming request header map
/// before fan-out so no single sub-target can turn the aggregate into `304 Not Modified` or `206 Partial Content`.
fn strip_conditional_and_range_headers(headers: &mut hyper::HeaderMap) {
    for conditional in [
        header::IF_NONE_MATCH,
        header::IF_MODIFIED_SINCE,
        header::IF_MATCH,
        header::IF_UNMODIFIED_SINCE,
        header::IF_RANGE,
        header::RANGE,
    ] {
        headers.remove(conditional);
    }
}

/// Sanitizes per-target credential headers (`authorization`, `cookie`) in-place unless explicitly
/// opted in via `sub_target.forward_headers` (or `authorization` was authoritatively injected
/// by `[Server.RouterParams].jwt`).
fn sanitize_sub_headers(
    mut headers: hyper::HeaderMap,
    sub_target: &ParsedAggregateTarget,
    has_gateway_upstream_jwt: bool,
) -> hyper::HeaderMap {
    if !sub_target.forward_headers.contains("cookie") {
        headers.remove(header::COOKIE);
    }
    if !has_gateway_upstream_jwt && !sub_target.forward_headers.contains("authorization") {
        headers.remove(header::AUTHORIZATION);
    }

    headers
}

/// Sanitizes headers for a REST fan-out sub-call so length/compression match the sub-payload.
fn prepare_rest_sub_headers(
    mut headers: hyper::HeaderMap,
    sub_method: &Method,
    sub_body: &Bytes,
) -> hyper::HeaderMap {
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

/// Body adapter that enforces a shared cumulative byte budget atomically *while frames arrive*
/// across all concurrent fan-out sub-requests, aborting upstream reads immediately before peak
/// buffered memory can grow to `N * max_sub_bytes`.
struct SharedBudgetBody<B> {
    inner: B,
    remaining_budget: Arc<AtomicUsize>,
    exceeded: Arc<std::sync::atomic::AtomicBool>,
}

impl<B> http_body::Body for SharedBudgetBody<B>
where
    B: http_body::Body<Data = Bytes, Error = SrvError> + Unpin,
{
    type Data = Bytes;
    type Error = SrvError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    let len = data.len();
                    if self
                        .remaining_budget
                        .try_update(Ordering::Relaxed, Ordering::Relaxed, |rem| {
                            rem.checked_sub(len)
                        })
                        .is_err()
                    {
                        self.exceeded.store(true, Ordering::Relaxed);
                        return Poll::Ready(Some(Err(SrvError::PayloadTooLarge {
                            current: len,
                            max: 0,
                        })));
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

/// Reads up to `max_bytes` from an error response body without consuming the shared success budget
/// or buffering large upstream HTML/stacktrace error payloads.
async fn read_error_snippet(
    mut body: ServiceRespBody,
    max_bytes: usize,
    body_timeout: Option<std::time::Duration>,
) -> String {
    let mut buf = Vec::with_capacity(max_bytes.min(256));
    let read_fut = async {
        while buf.len() < max_bytes {
            match body.frame().await {
                Some(Ok(frame)) => {
                    if let Some(data) = frame.data_ref() {
                        let take = (max_bytes - buf.len()).min(data.len());
                        buf.extend_from_slice(&data[..take]);
                    }
                }
                Some(Err(_)) | None => break,
            }
        }
    };
    if let Some(dur) = body_timeout {
        let _ = tokio::time::timeout(dur, read_fut).await;
    } else {
        read_fut.await;
    }
    String::from_utf8_lossy(&buf).trim().to_string()
}

/// Reads and validates the response produced by a single sub-request handler.
async fn collect_sub_outcome(
    sub_target: &ParsedAggregateTarget,
    resp: Response<ServiceRespBody>,
    body_timeout: Option<std::time::Duration>,
    max_sub_bytes: usize,
    shared_budget: Arc<AtomicUsize>,
    expose_upstream_errors: bool,
) -> SubOutcome {
    let status = resp.status();
    let grpc_status = resp
        .headers()
        .get("grpc-status")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u32>().ok());

    if !status.is_success() {
        let canonical = status
            .canonical_reason()
            .unwrap_or("Upstream Error")
            .to_string();
        let snippet =
            read_error_snippet(resp.into_body(), MAX_ERROR_SNIPPET_BYTES, body_timeout).await;
        let internal_detail = if snippet.is_empty() {
            canonical.clone()
        } else {
            snippet
        };
        let client_message = if expose_upstream_errors {
            internal_detail.clone()
        } else {
            canonical
        };
        return SubOutcome::Failed {
            status,
            grpc_status,
            client_message,
            internal_detail,
        };
    }

    let budget_exceeded = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let budgeted_body = SharedBudgetBody {
        inner: resp.into_body(),
        remaining_budget: shared_budget,
        exceeded: budget_exceeded.clone(),
    };
    let collect_fut = Limited::new(budgeted_body, max_sub_bytes).collect();
    let collected = match body_timeout {
        Some(dur) => match tokio::time::timeout(dur, collect_fut).await {
            Ok(res) => res,
            Err(_) => {
                return SubOutcome::Failed {
                    status: StatusCode::GATEWAY_TIMEOUT,
                    grpc_status: None,
                    client_message: "Gateway Timeout".to_string(),
                    internal_detail: "Gateway Timeout reading sub-response".to_string(),
                };
            }
        },
        None => collect_fut.await,
    };

    let bytes = match collected {
        Ok(c) => c.to_bytes(),
        Err(e) => {
            let detail = if budget_exceeded.load(Ordering::Relaxed) {
                format!(
                    "Cumulative aggregate response budget exceeded while reading target '{}'",
                    sub_target.key
                )
            } else {
                format!("Failed to read sub-response: {e}")
            };
            return SubOutcome::Failed {
                status: StatusCode::BAD_GATEWAY,
                grpc_status: None,
                client_message: "Bad Gateway".to_string(),
                internal_detail: detail,
            };
        }
    };

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
            grpc_status: None,
            client_message: "Upstream returned invalid JSON".to_string(),
            internal_detail: format!("Upstream '{}' returned invalid JSON: {e}", sub_target.key),
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
    sub_timeout: Option<std::time::Duration>,
    max_sub_bytes: usize,
    shared_budget: Arc<AtomicUsize>,
    expose_upstream_errors: bool,
) -> SubOutcome {
    let start = std::time::Instant::now();

    let has_gateway_jwt = config
        .router_params
        .as_ref()
        .and_then(|p| p.jwt.as_ref())
        .is_some();
    let sanitized_headers = sanitize_sub_headers(prepared_headers, &sub_target, has_gateway_jwt);

    let result = match sub_target.backend_type {
        RouteBackendType::GrpcTranscoding => {
            grpc_web::handle_grpc_web(
                &sub_target.target,
                RequestBody::Buffered(sub_body),
                Method::POST,
                sanitized_headers,
                &effective_uri,
                client_addr,
                server_name,
                &grpc_client,
                &config,
                sub_timeout,
            )
            .await
        }
        RouteBackendType::Rest => {
            let rest_headers = prepare_rest_sub_headers(sanitized_headers, &sub_method, &sub_body);

            match rest_path_router().at(effective_uri.path()) {
                Ok(matched) => {
                    http_proxy::handle_http_proxy(
                        &sub_target.target,
                        RequestBody::Buffered(sub_body),
                        sub_method,
                        original_version,
                        rest_headers,
                        &effective_uri,
                        &matched.params,
                        client_addr,
                        server_name,
                        &client,
                        sub_timeout,
                    )
                    .await
                }
                Err(e) => {
                    return SubOutcome::Failed {
                        status: StatusCode::INTERNAL_SERVER_ERROR,
                        grpc_status: None,
                        client_message: "Internal Server Error".to_string(),
                        internal_detail: format!("Invalid target path '{}': {e}", effective_uri.path()),
                    };
                }
            }
        }
        _ => {
            return SubOutcome::Failed {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                grpc_status: None,
                client_message: "Internal Server Error".to_string(),
                internal_detail: "Unsupported aggregate target backend_type".to_string(),
            };
        }
    };

    let remaining_timeout = sub_timeout.map(|dur| dur.saturating_sub(start.elapsed()));
    match result {
        Ok(resp) => {
            collect_sub_outcome(
                &sub_target,
                resp,
                remaining_timeout,
                max_sub_bytes,
                shared_budget,
                expose_upstream_errors,
            )
            .await
        }
        Err(e) => SubOutcome::Failed {
            status: StatusCode::BAD_GATEWAY,
            grpc_status: None,
            client_message: "Bad Gateway".to_string(),
            internal_detail: format!("Sub-request failed: {e}"),
        },
    }
}

/// Zero-copy multi-chunk [`http_body::Body`] backed by a queue of reference-counted [`Bytes`]
/// frames so aggregated upstream JSON payloads are streamed directly to Hyper without copying
/// sub-response buffers into a single contiguous heap allocation.
struct ChunkedBytesBody {
    chunks: VecDeque<Bytes>,
    remaining_bytes: usize,
}

impl http_body::Body for ChunkedBytesBody {
    type Data = Bytes;
    type Error = SrvError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        while let Some(chunk) = self.chunks.pop_front() {
            if chunk.is_empty() {
                continue;
            }
            self.remaining_bytes = self.remaining_bytes.saturating_sub(chunk.len());
            return Poll::Ready(Some(Ok(http_body::Frame::data(chunk))));
        }
        Poll::Ready(None)
    }

    fn is_end_stream(&self) -> bool {
        self.remaining_bytes == 0
    }

    fn size_hint(&self) -> http_body::SizeHint {
        http_body::SizeHint::with_exact(self.remaining_bytes as u64)
    }
}

/// Assembles all sub-target outcomes into a zero-copy [`ChunkedBytesBody`] without parsing
/// or copying successful JSON responses into an intermediate buffer.
fn assemble_aggregated_body(
    targets: &[Arc<ParsedAggregateTarget>],
    outcomes: Vec<Option<SubOutcome>>,
) -> Result<ChunkedBytesBody, SrvError> {
    let mut chunks = VecDeque::with_capacity(targets.len() * 3 + 3);
    let mut total_bytes = 0usize;

    let mut push_chunk = |b: Bytes| {
        if !b.is_empty() {
            total_bytes += b.len();
            chunks.push_back(b);
        }
    };

    push_chunk(Bytes::from_static(b"{"));

    let mut errors_map: BTreeMap<&str, AggregateErrorEntry> = BTreeMap::new();

    for (idx, (target, outcome_opt)) in targets.iter().zip(outcomes).enumerate() {
        if idx > 0 {
            push_chunk(Bytes::from_static(b","));
        }
        push_chunk(target.json_key_prefix.clone());

        match outcome_opt {
            Some(SubOutcome::Success(raw_json)) => {
                // Zero-copy move of the validated upstream JSON buffer directly into the frame queue
                push_chunk(raw_json);
            }
            Some(SubOutcome::Failed {
                status,
                grpc_status,
                client_message,
                ..
            }) => {
                push_chunk(Bytes::from_static(b"null"));
                errors_map.insert(
                    target.key.as_str(),
                    AggregateErrorEntry {
                        status: status.as_u16(),
                        grpc_status,
                        message: client_message,
                    },
                );
            }
            None => {
                push_chunk(Bytes::from_static(b"null"));
            }
        }
    }

    if !errors_map.is_empty() {
        push_chunk(Bytes::from_static(br#","_errors":"#));
        let errors_json = serde_json::to_vec(&errors_map)
            .map_err(|e| SrvError::Other(format!("Failed to serialize _errors map: {e}")))?;
        push_chunk(Bytes::from(errors_json));
    }

    push_chunk(Bytes::from_static(b"}"));
    Ok(ChunkedBytesBody {
        chunks,
        remaining_bytes: total_bytes,
    })
}

/// Handles a fan-out aggregation route (`backend_type = "aggregate"`).
///
/// Dispatches all configured `aggregate_targets` concurrently via a [`JoinSet`],
/// enforces strict `Keyed` or `Broadcast` payload distribution, strips client
/// credentials and conditional headers by default, aborts immediately when any
/// `required = true` target fails, and degrades gracefully with `"<key>": null`
/// + sanitized `"_errors"` when `required = false` targets fail.
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip_all, fields(server = %server_name, route = %route_info.prefix, method = %original_method))]
pub async fn handle_aggregate(
    route_info: &ParsedRoute,
    request_body: RequestBody,
    original_method: Method,
    original_version: Version,
    mut prepared_headers: hyper::HeaderMap,
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

    let payload_mode = route_info.aggregate_payload_mode;
    let expose_upstream_errors = route_info.expose_upstream_errors;
    let max_response_bytes = route_info.max_response_bytes;
    let per_sub_max_bytes = max_response_bytes.min(MAX_AGGREGATE_SUB_RESPONSE_BYTES);
    let shared_budget = Arc::new(AtomicUsize::new(max_response_bytes));
    let overall_deadline = route_info
        .aggregate_deadline_ms
        .map(|ms| tokio::time::Instant::now() + std::time::Duration::from_millis(ms));

    let keyed_slices = if payload_mode == AggregatePayloadMode::Keyed {
        match parse_keyed_payload(&raw_body, &route_info.aggregate_targets) {
            Ok(s) => s,
            Err(msg) => return Ok(build_error_response(msg, StatusCode::BAD_REQUEST)),
        }
    } else {
        None
    };

    // Strip conditional & range headers once before fanning out across sub-targets
    strip_conditional_and_range_headers(&mut prepared_headers);

    let client_query = original_uri.query();
    let mut join_set: JoinSet<(usize, SubOutcome)> = JoinSet::new();

    for (idx, target) in route_info.aggregate_targets.iter().enumerate() {
        let sub_target = Arc::clone(target);
        let effective_uri = build_effective_target_uri(&sub_target, client_query);
        let sub_method = match sub_target.backend_type {
            RouteBackendType::GrpcTranscoding => Method::POST,
            _ => sub_target
                .method
                .clone()
                .unwrap_or_else(|| original_method.clone()),
        };

        let sub_body = select_sub_body(
            idx,
            &sub_target,
            &sub_method,
            payload_mode,
            &raw_body,
            keyed_slices.as_deref(),
            effective_uri.query(),
        );

        // Compute effective timeout: per-target `timeout_ms` overrides router default,
        // and both are bounded by the optional route-wide `deadline_ms`.
        let base_timeout = sub_target
            .timeout_ms
            .map(std::time::Duration::from_millis)
            .or(request_timeout);
        let effective_timeout = match (base_timeout, overall_deadline) {
            (Some(t), Some(dl)) => {
                let rem = dl.saturating_duration_since(tokio::time::Instant::now());
                Some(t.min(rem))
            }
            (Some(t), None) => Some(t),
            (None, Some(dl)) => Some(dl.saturating_duration_since(tokio::time::Instant::now())),
            (None, None) => None,
        };

        let sub_headers = prepared_headers.clone();
        let sub_client = client.clone();
        let sub_grpc_client = grpc_client.clone();
        let sub_config = Arc::clone(config);
        let sub_budget = Arc::clone(&shared_budget);
        let span = info_span!(
            "aggregate_subrequest",
            target_key = %sub_target.key,
            backend_type = ?sub_target.backend_type
        );

        join_set.spawn(
            async move {
                let fut = execute_sub_target(
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
                    effective_timeout,
                    per_sub_max_bytes,
                    sub_budget,
                    expose_upstream_errors,
                );
                let outcome = match effective_timeout {
                    Some(dur) => match tokio::time::timeout(dur, fut).await {
                        Ok(o) => o,
                        Err(_) => SubOutcome::Failed {
                            status: StatusCode::GATEWAY_TIMEOUT,
                            grpc_status: None,
                            client_message: "Gateway Timeout".to_string(),
                            internal_detail: format!("Sub-request timed out after {:?}", dur),
                        },
                    },
                    None => fut.await,
                };
                (idx, outcome)
            }
            .instrument(span),
        );
    }

    let mut outcomes: Vec<Option<SubOutcome>> = (0..route_info.aggregate_targets.len())
        .map(|_| None)
        .collect();
    let mut cumulative_response_bytes: usize = 0;

    loop {
        let next_res = match overall_deadline {
            Some(dl) => match tokio::time::timeout_at(dl, join_set.join_next()).await {
                Ok(Some(res)) => Some(res),
                Ok(None) => None,
                Err(_) => {
                    join_set.abort_all();
                    for (idx, target) in route_info.aggregate_targets.iter().enumerate() {
                        if outcomes[idx].is_none() {
                            if target.required {
                                error!(
                                    "{}: Aggregate route '{}' exceeded overall deadline while waiting for required target '{}'",
                                    server_name, route_info.prefix, target.key
                                );
                                return Ok(build_error_response(
                                    "Gateway Timeout",
                                    StatusCode::GATEWAY_TIMEOUT,
                                ));
                            }
                            warn!(
                                "{}: Aggregate route '{}' exceeded overall deadline; degrading optional target '{}' to 504",
                                server_name, route_info.prefix, target.key
                            );
                            outcomes[idx] = Some(SubOutcome::Failed {
                                status: StatusCode::GATEWAY_TIMEOUT,
                                grpc_status: None,
                                client_message: "Gateway Timeout".to_string(),
                                internal_detail: "Aggregate route deadline exceeded".to_string(),
                            });
                        }
                    }
                    break;
                }
            },
            None => join_set.join_next().await,
        };

        let Some(join_res) = next_res else {
            break;
        };

        match join_res {
            Ok((idx, mut outcome)) => {
                let target = &route_info.aggregate_targets[idx];

                // Enforce cumulative response memory cap across all sub-targets (M1)
                if let SubOutcome::Success(ref bytes) = outcome {
                    if cumulative_response_bytes.saturating_add(bytes.len()) > max_response_bytes {
                        let detail = format!(
                            "Cumulative aggregate response exceeded {} bytes on target '{}'",
                            max_response_bytes, target.key
                        );
                        outcome = SubOutcome::Failed {
                            status: StatusCode::BAD_GATEWAY,
                            grpc_status: None,
                            client_message: "Bad Gateway".to_string(),
                            internal_detail: detail,
                        };
                    } else {
                        cumulative_response_bytes += bytes.len();
                    }
                }

                if let SubOutcome::Failed {
                    ref status,
                    ref client_message,
                    ref internal_detail,
                    ..
                } = outcome
                {
                    if target.required {
                        error!(
                            "{}: Required aggregate target '{}' failed with {} ({}); aborting remaining sub-requests",
                            server_name, target.key, status, internal_detail
                        );
                        join_set.abort_all();
                        return Ok(build_error_response(client_message, *status));
                    }
                    warn!(
                        "{}: Optional aggregate target '{}' failed with {} ({}); degrading gracefully",
                        server_name, target.key, status, internal_detail
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

    let chunked_body = assemble_aggregated_body(&route_info.aggregate_targets, outcomes)?;
    let content_len = chunked_body.remaining_bytes;

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CONTENT_LENGTH, content_len)
        .body(chunked_body.boxed())
        .map_err(|e| SrvError::Other(format!("Failed to build aggregate response: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::{
        CachedDescriptorPool, LbStrategy, RouteTarget, UpstreamNode,
    };
    use bytes::{BufMut, BytesMut};
    use http_body_util::Full;
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
    use std::collections::HashSet;
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
        let target_uri: Uri = path.parse().unwrap();
        let pinned_query_keys: HashSet<String> = target_uri
            .query()
            .filter(|q| !q.is_empty())
            .map(|tq| {
                url::form_urlencoded::parse(tq.as_bytes())
                    .map(|(k, _)| k.into_owned())
                    .collect()
            })
            .unwrap_or_default();
        let json_key_prefix = Bytes::from(format!("{}:", serde_json::to_string(key).unwrap()));
        ParsedAggregateTarget {
            key: key.to_string(),
            json_key_prefix,
            backend_type,
            target,
            target_uri,
            pinned_query_keys,
            method,
            required,
            forward_query: None,
            forward_headers: HashSet::new(),
            timeout_ms: None,
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
            aggregate_targets: targets.into_iter().map(Arc::new).collect(),
            aggregate_payload_mode: AggregatePayloadMode::Keyed,
            expose_upstream_errors: false,
            aggregate_deadline_ms: None,
            max_request_bytes: crate::configuration::DEFAULT_MAX_BUFFERED_REQUEST_BYTES,
            max_response_bytes: crate::configuration::DEFAULT_MAX_AGGREGATE_RESPONSE_BYTES,
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
            RequestBody::Buffered(Bytes::from_static(br#"{"user":{"user_id":"7"}}"#)),
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
        // F4: raw upstream body ("notification service down") must NOT leak by default
        assert_eq!(
            parsed["_errors"]["notifications"]["message"],
            "Internal Server Error"
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
            RequestBody::Buffered(Bytes::from_static(br#"{"user":{"user_id":"1"}}"#)),
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
            Duration::from_millis(600),
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
            Some(Duration::from_millis(150)),
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

        let mut route = make_aggregate_route(vec![make_sub_target(
            "audit",
            RouteBackendType::Rest,
            port,
            "/v1/audit",
            Some(Method::POST),
            true,
            None,
        )]);
        route.aggregate_payload_mode = AggregatePayloadMode::Broadcast;

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

    /// Regression test for F1 (REST & gRPC): in default `Keyed` mode, a target whose key is
    /// absent from the request body must receive `{}` and NEVER sibling targets' payloads,
    /// and unknown top-level keys must be rejected with 400 Bad Request before fanning out.
    #[tokio::test]
    async fn test_aggregate_f1_keyed_mode_isolates_payloads_and_rejects_unknown_keys() {
        let body_a = Arc::new(tokio::sync::Mutex::new(None::<Bytes>));
        let body_b = Arc::new(tokio::sync::Mutex::new(None::<Bytes>));

        let spawn_capture = |slot: Arc<tokio::sync::Mutex<Option<Bytes>>>| async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            tokio::spawn(async move {
                loop {
                    let Ok((socket, _)) = listener.accept().await else {
                        break;
                    };
                    let slot = slot.clone();
                    tokio::spawn(async move {
                        let io = hyper_util::rt::TokioIo::new(socket);
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(
                                io,
                                hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                                    let slot = slot.clone();
                                    async move {
                                        let b = req.into_body().collect().await.unwrap().to_bytes();
                                        *slot.lock().await = Some(b);
                                        Ok::<_, std::convert::Infallible>(
                                            Response::builder()
                                                .status(StatusCode::OK)
                                                .header("content-type", "application/json")
                                                .body(Full::new(Bytes::from_static(br#"{"ok":true}"#)))
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
        };

        let port_a = spawn_capture(body_a.clone()).await;
        let port_b = spawn_capture(body_b.clone()).await;
        let pool = test_descriptor_pool();
        let grpc_port = spawn_grpc_user_mock(pool.clone(), None).await;

        let route = make_aggregate_route(vec![
            make_sub_target("a", RouteBackendType::Rest, port_a, "/in", Some(Method::POST), true, None),
            make_sub_target("b", RouteBackendType::Rest, port_b, "/in", Some(Method::POST), true, None),
            make_sub_target(
                "user",
                RouteBackendType::GrpcTranscoding,
                grpc_port,
                "/user.UserService/GetUser",
                None,
                true,
                Some(pool),
            ),
        ]);

        let (http_client, grpc_client) = build_clients();
        let cfg = test_server_config(5);

        // 1. Only key "a" present: "a" gets its sub-object, "b" and gRPC "user" get "{}" (no leak, no gRPC 400)
        let resp = handle_aggregate(
            &route,
            RequestBody::Buffered(Bytes::from_static(br#"{"a":{"secret_for_a":"s3cr3t"}}"#)),
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
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            body_a.lock().await.as_deref(),
            Some(&br#"{"secret_for_a":"s3cr3t"}"#[..])
        );
        assert_eq!(
            body_b.lock().await.as_deref(),
            Some(&b"{}"[..]),
            "Target without own key must receive '{{}}', never sibling payload"
        );

        // 2. Unknown top-level key in Keyed mode -> 400 Bad Request
        let bad_resp = handle_aggregate(
            &route,
            RequestBody::Buffered(Bytes::from_static(br#"{"unknown_key":{"x":1}}"#)),
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
        assert_eq!(bad_resp.status(), StatusCode::BAD_REQUEST);
    }

    /// Regression test for F4: raw upstream error bodies (stack traces, hostnames, credentials)
    /// must NOT leak to clients by default, and are only reflected when `expose_upstream_errors = true`.
    #[tokio::test]
    async fn test_aggregate_f4_sanitizes_upstream_error_bodies_by_default() {
        let leak_port = spawn_rest_mock(
            StatusCode::INTERNAL_SERVER_ERROR,
            "panic at db-prod-01.internal:5432 user=svc_orders pw=hunter2",
            Duration::ZERO,
            None,
            None,
        )
        .await;

        let (http_client, grpc_client) = build_clients();
        let cfg = test_server_config(5);

        // Required target with expose_upstream_errors = false (default)
        let route_req = make_aggregate_route(vec![make_sub_target(
            "t",
            RouteBackendType::Rest,
            leak_port,
            "/x",
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
        assert_eq!(resp_req.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let req_text = String::from_utf8(
            resp_req.into_body().collect().await.unwrap().to_bytes().to_vec(),
        )
        .unwrap();
        assert!(!req_text.contains("hunter2"));
        assert!(!req_text.contains("db-prod-01"));
        assert_eq!(req_text, "Internal Server Error");

        // Optional target with expose_upstream_errors = false (default)
        let mut route_opt = make_aggregate_route(vec![make_sub_target(
            "t",
            RouteBackendType::Rest,
            leak_port,
            "/x",
            Some(Method::GET),
            false,
            None,
        )]);
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
        let opt_bytes = resp_opt.into_body().collect().await.unwrap().to_bytes();
        let opt_text = String::from_utf8(opt_bytes.to_vec()).unwrap();
        assert!(!opt_text.contains("hunter2"));
        let parsed: serde_json::Value = serde_json::from_slice(&opt_bytes).unwrap();
        assert_eq!(parsed["_errors"]["t"]["message"], "Internal Server Error");

        // Explicit opt-in: expose_upstream_errors = true
        route_opt.expose_upstream_errors = true;
        let resp_exposed = handle_aggregate(
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
        let exposed_bytes = resp_exposed.into_body().collect().await.unwrap().to_bytes();
        let exposed_parsed: serde_json::Value = serde_json::from_slice(&exposed_bytes).unwrap();
        assert!(
            exposed_parsed["_errors"]["t"]["message"]
                .as_str()
                .unwrap()
                .contains("db-prod-01")
        );
    }

    /// Regression test for F2: operator-pinned query parameters in `target.path` take
    /// precedence over client query parameters (no parameter pollution), and `forward_query`
    /// allowlists restrict which client parameters reach a target.
    #[tokio::test]
    async fn test_aggregate_f2_query_precedence_and_allowlist() {
        let uri_pinned = Arc::new(tokio::sync::Mutex::new(None));
        let uri_filtered = Arc::new(tokio::sync::Mutex::new(None));

        let p1 = spawn_rest_mock(
            StatusCode::OK,
            r#"{"ok":1}"#,
            Duration::ZERO,
            Some(uri_pinned.clone()),
            None,
        )
        .await;
        let p2 = spawn_rest_mock(
            StatusCode::OK,
            r#"{"ok":2}"#,
            Duration::ZERO,
            Some(uri_filtered.clone()),
            None,
        )
        .await;

        let t1 = make_sub_target(
            "pinned",
            RouteBackendType::Rest,
            p1,
            "/v1/items?tenant=acme",
            Some(Method::GET),
            true,
            None,
        );
        let mut t2 = make_sub_target(
            "filtered",
            RouteBackendType::Rest,
            p2,
            "/v1/items",
            Some(Method::GET),
            true,
            None,
        );
        t2.forward_query = Some(HashSet::from(["allowed".to_string()]));

        let route = make_aggregate_route(vec![t1, t2]);
        let (http_client, grpc_client) = build_clients();
        let cfg = test_server_config(5);

        let resp = handle_aggregate(
            &route,
            RequestBody::Buffered(Bytes::new()),
            Method::GET,
            Version::HTTP_11,
            hyper::HeaderMap::new(),
            &"/api/dashboard?tenant=evil&allowed=yes&dropped=no"
                .parse()
                .unwrap(),
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

        let seen1 = uri_pinned.lock().await.clone().unwrap();
        assert!(seen1.contains("tenant=acme"), "pinned param preserved: {seen1}");
        assert!(
            !seen1.contains("tenant=evil"),
            "client must not pollute operator-pinned query param: {seen1}"
        );
        assert!(seen1.contains("allowed=yes"), "non-conflicting param forwarded: {seen1}");

        let seen2 = uri_filtered.lock().await.clone().unwrap();
        assert_eq!(seen2, "/v1/items?allowed=yes");
    }

    /// Regression test for F3: client `Authorization`/`Cookie` headers are stripped by default
    /// (unless opted in per target via `forward_headers`), and conditional headers (`If-None-Match`)
    /// are always stripped so no single target returns `304 Not Modified`.
    #[tokio::test]
    async fn test_aggregate_f3_strips_credentials_and_conditional_headers_by_default() {
        let capture = |slot: Arc<tokio::sync::Mutex<Option<hyper::HeaderMap>>>| async move {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            tokio::spawn(async move {
                if let Ok((socket, _)) = listener.accept().await {
                    let io = hyper_util::rt::TokioIo::new(socket);
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(
                            io,
                            hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                                let slot = slot.clone();
                                async move {
                                    let hdrs = req.headers().clone();
                                    let is_cond = hdrs.contains_key(header::IF_NONE_MATCH);
                                    *slot.lock().await = Some(hdrs);
                                    if is_cond {
                                        return Ok::<_, std::convert::Infallible>(
                                            Response::builder()
                                                .status(StatusCode::NOT_MODIFIED)
                                                .body(Full::new(Bytes::new()))
                                                .unwrap(),
                                        );
                                    }
                                    Ok::<_, std::convert::Infallible>(
                                        Response::builder()
                                            .status(StatusCode::OK)
                                            .header("content-type", "application/json")
                                            .body(Full::new(Bytes::from_static(br#"{"v":1}"#)))
                                            .unwrap(),
                                    )
                                }
                            }),
                        )
                        .await;
                }
            });
            port
        };

        let h_default = Arc::new(tokio::sync::Mutex::new(None));
        let h_optin = Arc::new(tokio::sync::Mutex::new(None));
        let p_default = capture(h_default.clone()).await;
        let p_optin = capture(h_optin.clone()).await;

        let t_default = make_sub_target(
            "untrusted",
            RouteBackendType::Rest,
            p_default,
            "/x",
            Some(Method::GET),
            true,
            None,
        );
        let mut t_optin = make_sub_target(
            "trusted",
            RouteBackendType::Rest,
            p_optin,
            "/y",
            Some(Method::GET),
            true,
            None,
        );
        t_optin.forward_headers.insert("authorization".to_string());

        let route = make_aggregate_route(vec![t_default, t_optin]);
        let (http_client, grpc_client) = build_clients();
        let cfg = test_server_config(5);

        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            header::HeaderValue::from_static("Bearer SECRET-TOKEN"),
        );
        headers.insert(
            header::COOKIE,
            header::HeaderValue::from_static("sid=SECRET-COOKIE"),
        );
        headers.insert(
            header::IF_NONE_MATCH,
            header::HeaderValue::from_static("\"etag-1\""),
        );

        let resp = handle_aggregate(
            &route,
            RequestBody::Buffered(Bytes::new()),
            Method::GET,
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

        assert_eq!(resp.status(), StatusCode::OK, "If-None-Match must be stripped");

        let got_default = h_default.lock().await.clone().unwrap();
        assert!(!got_default.contains_key(header::AUTHORIZATION));
        assert!(!got_default.contains_key(header::COOKIE));
        assert!(!got_default.contains_key(header::IF_NONE_MATCH));

        let got_optin = h_optin.lock().await.clone().unwrap();
        assert_eq!(
            got_optin.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()),
            Some("Bearer SECRET-TOKEN")
        );
        assert!(!got_optin.contains_key(header::COOKIE));
        assert!(!got_optin.contains_key(header::IF_NONE_MATCH));
    }

    /// Regression tests for F5: gRPC status codes in both Trailers-Only initial headers
    /// (`NOT_FOUND` -> 404 + `grpc_status: 5`) and trailing headers after a data frame
    /// (`INTERNAL` -> 502 + `grpc_status: 13`, never silent partial success) must be evaluated.
    #[tokio::test]
    async fn test_aggregate_f5_evaluates_grpc_status_trailers_only_and_trailing_errors() {
        use http_body::Frame;

        async fn spawn_grpc_status_mock(
            trailers_only: Option<&'static str>,
            trailing_after_data: Option<&'static str>,
        ) -> u16 {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            tokio::spawn(async move {
                loop {
                    let Ok((sock, _)) = listener.accept().await else {
                        break;
                    };
                    tokio::spawn(async move {
                        let io = hyper_util::rt::TokioIo::new(sock);
                        let _ = hyper::server::conn::http2::Builder::new(
                            hyper_util::rt::TokioExecutor::new(),
                        )
                        .serve_connection(
                            io,
                            hyper::service::service_fn(
                                move |req: Request<hyper::body::Incoming>| async move {
                                    let _ = req.into_body().collect().await;
                                    let mut frames: Vec<Result<Frame<Bytes>, std::convert::Infallible>> =
                                        Vec::new();
                                    let mut builder = Response::builder()
                                        .status(StatusCode::OK)
                                        .header("content-type", "application/grpc");
                                    if let Some(code) = trailers_only {
                                        builder = builder
                                            .header("grpc-status", code)
                                            .header("grpc-message", "user%20not%20found");
                                    } else {
                                        // Valid UserRes{ id: "x" } frame followed by error trailer
                                        frames.push(Ok(Frame::data(Bytes::from_static(&[
                                            0, 0, 0, 0, 3, 0x0a, 0x01, 0x78,
                                        ]))));
                                        let mut trailers = hyper::HeaderMap::new();
                                        trailers.insert(
                                            "grpc-status",
                                            trailing_after_data.unwrap_or("0").parse().unwrap(),
                                        );
                                        trailers.insert(
                                            "grpc-message",
                                            "internal%20failure".parse().unwrap(),
                                        );
                                        frames.push(Ok(Frame::trailers(trailers)));
                                    }
                                    let body = http_body_util::StreamBody::new(
                                        futures_util::stream::iter(frames),
                                    );
                                    Ok::<_, std::convert::Infallible>(builder.body(body).unwrap())
                                },
                            ),
                        )
                        .await;
                    });
                }
            });
            port
        }

        let pool = test_descriptor_pool();
        let not_found_port = spawn_grpc_status_mock(Some("5"), None).await;
        let trailing_err_port = spawn_grpc_status_mock(None, Some("13")).await;

        let route = make_aggregate_route(vec![
            make_sub_target(
                "missing",
                RouteBackendType::GrpcTranscoding,
                not_found_port,
                "/user.UserService/GetUser",
                None,
                false,
                Some(pool.clone()),
            ),
            make_sub_target(
                "broken",
                RouteBackendType::GrpcTranscoding,
                trailing_err_port,
                "/user.UserService/GetUser",
                None,
                false,
                Some(pool),
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
            &"/api/dashboard?user_id=42".parse().unwrap(),
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
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

        // Trailers-Only NOT_FOUND (5) -> HTTP 404 + grpc_status 5 (sanitized reason phrase by default)
        assert!(parsed["missing"].is_null());
        assert_eq!(parsed["_errors"]["missing"]["status"], 404);
        assert_eq!(parsed["_errors"]["missing"]["grpc_status"], 5);
        assert_eq!(parsed["_errors"]["missing"]["message"], "Not Found");

        // Trailing INTERNAL (13) after data frame -> must NOT be treated as success!
        assert!(parsed["broken"].is_null());
        assert_eq!(parsed["_errors"]["broken"]["status"], 502);
        assert_eq!(parsed["_errors"]["broken"]["grpc_status"], 13);
    }

    /// Regression test for P3: per-target `timeout_ms` and route-wide `aggregate_deadline_ms`
    /// prevent a slow optional target from blocking the entire aggregated response.
    #[tokio::test]
    async fn test_aggregate_p3_per_target_timeout_and_route_deadline_cap_optional_latency() {
        let fast_port = spawn_rest_mock(
            StatusCode::OK,
            r#"{"fast":true}"#,
            Duration::ZERO,
            None,
            None,
        )
        .await;
        let slow_port = spawn_rest_mock(
            StatusCode::OK,
            r#"{"slow":true}"#,
            Duration::from_secs(3),
            None,
            None,
        )
        .await;

        let t_fast = make_sub_target(
            "fast",
            RouteBackendType::Rest,
            fast_port,
            "/v1/fast",
            Some(Method::GET),
            true,
            None,
        );
        let mut t_slow = make_sub_target(
            "slow_opt",
            RouteBackendType::Rest,
            slow_port,
            "/v1/slow",
            Some(Method::GET),
            false,
            None,
        );
        t_slow.timeout_ms = Some(120);

        let mut route = make_aggregate_route(vec![t_fast, t_slow]);
        route.aggregate_deadline_ms = Some(250);

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

        let elapsed = start.elapsed();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            elapsed < Duration::from_millis(900),
            "Slow optional target must be bounded by timeout_ms/deadline_ms (took {elapsed:?})"
        );

        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed["fast"]["fast"], true);
        assert!(parsed["slow_opt"].is_null());
        assert_eq!(parsed["_errors"]["slow_opt"]["status"], 504);
    }

    /// Regression test for M1: cumulative `max_response_bytes` cap prevents RAM amplification
    /// across multiple sub-targets.
    #[tokio::test]
    async fn test_aggregate_m1_enforces_cumulative_max_response_bytes() {
        let p1 = spawn_rest_mock(
            StatusCode::OK,
            r#"{"data":"12345678901234567890"}"#, // 31 bytes
            Duration::ZERO,
            None,
            None,
        )
        .await;
        let p2 = spawn_rest_mock(
            StatusCode::OK,
            r#"{"data":"abcdefghijklmnopqrstuvwxyz"}"#, // 37 bytes
            Duration::ZERO,
            None,
            None,
        )
        .await;

        let mut route = make_aggregate_route(vec![
            make_sub_target("a", RouteBackendType::Rest, p1, "/a", Some(Method::GET), true, None),
            make_sub_target("b", RouteBackendType::Rest, p2, "/b", Some(Method::GET), true, None),
        ]);
        // Each individual response fits under 50 bytes, but their sum (68 bytes) exceeds the cap!
        route.max_response_bytes = 50;

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
            Some(Duration::from_secs(5)),
        )
        .await
        .unwrap();

        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }

    /// Verifies that both `parse_keyed_payload` (request splitting) and `assemble_aggregated_body`
    /// (response assembly) operate in true zero-copy mode by asserting pointer identity against
    /// the original `Bytes` buffers.
    #[test]
    fn test_aggregate_zero_copy_pointer_identity_for_request_slices_and_response_chunks() {
        let route = make_aggregate_route(vec![
            make_sub_target("alpha", RouteBackendType::Rest, 8081, "/a", Some(Method::POST), true, None),
            make_sub_target("beta", RouteBackendType::Rest, 8082, "/b", Some(Method::POST), true, None),
        ]);

        // 1. Request slicing: sub-slice pointers must lie strictly within `raw_req` buffer
        let raw_req = Bytes::from_static(br#"{"alpha":{"id":101},"beta":[1,2,3]}"#);
        let req_range = raw_req.as_ptr_range();
        let slices = parse_keyed_payload(&raw_req, &route.aggregate_targets)
            .expect("valid keyed payload")
            .expect("non-empty payload");

        let slice_alpha = slices[0].as_ref().expect("alpha slice");
        let slice_beta = slices[1].as_ref().expect("beta slice");
        assert_eq!(slice_alpha.as_ref(), br#"{"id":101}"#);
        assert_eq!(slice_beta.as_ref(), br#"[1,2,3]"#);
        assert!(
            req_range.contains(&slice_alpha.as_ptr()),
            "alpha request slice must point directly into raw_req (zero-copy)"
        );
        assert!(
            req_range.contains(&slice_beta.as_ptr()),
            "beta request slice must point directly into raw_req (zero-copy)"
        );

        // 2. Response assembly: upstream `Bytes` payloads must be moved into `ChunkedBytesBody`
        // without copying (`chunk.as_ptr() == upstream_bytes.as_ptr()`).
        let up_alpha = Bytes::from(vec![b'{', b'"', b'k', b'"', b':', b'1', b'}']);
        let up_beta = Bytes::from(vec![b'{', b'"', b'k', b'"', b':', b'2', b'}']);
        let ptr_alpha = up_alpha.as_ptr();
        let ptr_beta = up_beta.as_ptr();

        let body = assemble_aggregated_body(
            &route.aggregate_targets,
            vec![
                Some(SubOutcome::Success(up_alpha)),
                Some(SubOutcome::Success(up_beta)),
            ],
        )
        .expect("assemble_aggregated_body");

        assert!(
            body.chunks.iter().any(|c| c.as_ptr() == ptr_alpha),
            "alpha upstream response buffer must be preserved without copying"
        );
        assert!(
            body.chunks.iter().any(|c| c.as_ptr() == ptr_beta),
            "beta upstream response buffer must be preserved without copying"
        );
    }

    /// Edge cases of the zero-copy keyed request splitter: escaped keys, duplicate keys,
    /// non-object roots, trailing garbage, unknown keys, and error-classification robustness.
    #[test]
    fn test_parse_keyed_payload_edge_cases() {
        let route = make_aggregate_route(vec![
            make_sub_target("alpha", RouteBackendType::Rest, 1, "/a", Some(Method::POST), true, None),
            make_sub_target("beta", RouteBackendType::Rest, 2, "/b", Some(Method::POST), true, None),
        ]);
        let targets = &route.aggregate_targets;
        const NOT_OBJ: &str = "Bad Request: Aggregate keyed payload must be a JSON object";
        const UNKNOWN: &str = "Bad Request: Unknown target key in aggregate payload";
        let parse = |s: &'static str| parse_keyed_payload(&Bytes::from_static(s.as_bytes()), targets);

        // Empty body => no keyed payload at all.
        assert!(matches!(parse(""), Ok(None)));

        // Escaped key (`\u0061lpha` == "alpha") resolves to the right target; whitespace preserved.
        let slots = parse(r#"{ "\u0061lpha" : { "x" : 1 } }"#).unwrap().unwrap();
        assert_eq!(slots[0].as_deref(), Some(&br#"{ "x" : 1 }"#[..]));
        assert!(slots[1].is_none());

        // Duplicate keys: last occurrence wins (same as serde_json::Value semantics before).
        let slots = parse(r#"{"alpha":1,"alpha":2}"#).unwrap().unwrap();
        assert_eq!(slots[0].as_deref(), Some(&b"2"[..]));

        // Non-object roots and invalid JSON => "must be a JSON object".
        for bad in ["[1]", "null", "42", "\"str\"", "  ", "{", r#"{"alpha":}"#] {
            assert_eq!(parse(bad).unwrap_err(), NOT_OBJ, "input: {bad:?}");
        }
        // Trailing garbage after a valid object is rejected.
        assert_eq!(parse(r#"{"alpha":1} x"#).unwrap_err(), NOT_OBJ);

        // Unknown top-level key => dedicated message.
        assert_eq!(parse(r#"{"gamma":1}"#).unwrap_err(), UNKNOWN);
        // A string body that merely *contains* the old sentinel text must not be misclassified.
        assert_eq!(parse("\"unknown_target_key\"").unwrap_err(), NOT_OBJ);
        // A valid body whose *value* contains the sentinel is fine.
        assert!(parse(r#"{"alpha":"unknown_target_key"}"#).unwrap().is_some());
    }

    /// Verifies that `SharedBudgetBody` enforces the cumulative budget mid-stream as frames
    /// arrive (across concurrent readers), aborting before remaining chunks are buffered into RAM.
    #[tokio::test]
    async fn test_shared_budget_body_aborts_mid_stream_across_concurrent_readers() {
        let budget = Arc::new(AtomicUsize::new(35));
        let chunks_pulled_a = Arc::new(AtomicUsize::new(0));
        let chunks_pulled_b = Arc::new(AtomicUsize::new(0));

        let make_stream = |counter: Arc<AtomicUsize>| {
            let s = futures_util::stream::unfold(0usize, move |idx| {
                let counter = Arc::clone(&counter);
                async move {
                    if idx >= 10 {
                        return None;
                    }
                    counter.fetch_add(1, Ordering::Relaxed);
                    // Yield 20 bytes per chunk (10 chunks = 200 bytes total if unguarded)
                    let frame = http_body::Frame::data(Bytes::from(vec![b'x'; 20]));
                    Some((Ok::<_, SrvError>(frame), idx + 1))
                }
            });
            http_body_util::StreamBody::new(s).boxed()
        };

        let exceeded_a = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let exceeded_b = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let body_a = SharedBudgetBody {
            inner: make_stream(Arc::clone(&chunks_pulled_a)),
            remaining_budget: Arc::clone(&budget),
            exceeded: Arc::clone(&exceeded_a),
        };
        let body_b = SharedBudgetBody {
            inner: make_stream(Arc::clone(&chunks_pulled_b)),
            remaining_budget: Arc::clone(&budget),
            exceeded: Arc::clone(&exceeded_b),
        };

        let (res_a, res_b) = tokio::join!(body_a.collect(), body_b.collect());
        assert!(
            res_a.is_err() || res_b.is_err(),
            "Cumulative shared budget (35 B) must reject multi-chunk streams mid-flight"
        );
        assert!(
            exceeded_a.load(Ordering::Relaxed) || exceeded_b.load(Ordering::Relaxed),
            "At least one reader must flag budget exceeded"
        );
        // Combined pulled chunks must be at most 3 (1+1 within budget, plus the first overflowing chunk)
        let total_pulled =
            chunks_pulled_a.load(Ordering::Relaxed) + chunks_pulled_b.load(Ordering::Relaxed);
        assert!(
            total_pulled <= 3,
            "SharedBudgetBody must stop pulling before buffering remaining chunks (pulled {total_pulled}/20)"
        );
    }
}
