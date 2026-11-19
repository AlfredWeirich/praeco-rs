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

use super::{
    BufferBudget, BufferReservation, RequestBody, build_error_response,
    global_response_buffer_budget, grpc_web, http_proxy,
};
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
    Success(Bytes, BufferReservation),
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

/// Body adapter that enforces both the per-route cumulative byte budget and the
/// process-wide [`BufferBudget`] atomically *while frames arrive* across all concurrent
/// fan-out sub-requests, aborting upstream reads immediately before peak buffered memory
/// can grow unboundedly.
struct SharedBudgetBody<'a, B> {
    inner: B,
    remaining_budget: Arc<AtomicUsize>,
    exceeded: Arc<std::sync::atomic::AtomicBool>,
    reservation: &'a mut BufferReservation,
    global_exceeded: &'a mut bool,
}

impl<B> http_body::Body for SharedBudgetBody<'_, B>
where
    B: http_body::Body<Data = Bytes, Error = SrvError> + Unpin,
{
    type Data = Bytes;
    type Error = SrvError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let this = &mut *self;
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    let len = data.len();
                    let mut rem = this.remaining_budget.load(Ordering::Relaxed);
                    let within_budget = loop {
                        let Some(next) = rem.checked_sub(len) else {
                            break false;
                        };
                        match this.remaining_budget.compare_exchange_weak(
                            rem,
                            next,
                            Ordering::Relaxed,
                            Ordering::Relaxed,
                        ) {
                            Ok(_) => break true,
                            Err(actual) => rem = actual,
                        }
                    };
                    if !within_budget {
                        this.exceeded.store(true, Ordering::Relaxed);
                        return Poll::Ready(Some(Err(SrvError::PayloadTooLarge {
                            current: len,
                            max: 0,
                        })));
                    }
                    if !this.reservation.try_reserve(len) {
                        *this.global_exceeded = true;
                        return Poll::Ready(Some(Err(SrvError::Other(
                            "Global response buffer budget exhausted".to_string(),
                        ))));
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
    global_budget: Arc<BufferBudget>,
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

    let mut reservation = BufferReservation::new(global_budget);
    let mut global_exceeded = false;
    let budget_exceeded = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let budgeted_body = SharedBudgetBody {
        inner: resp.into_body(),
        remaining_budget: shared_budget,
        exceeded: budget_exceeded.clone(),
        reservation: &mut reservation,
        global_exceeded: &mut global_exceeded,
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
        Err(_) if global_exceeded => {
            return SubOutcome::Failed {
                status: StatusCode::SERVICE_UNAVAILABLE,
                grpc_status: None,
                client_message: "Service Unavailable".to_string(),
                internal_detail: format!(
                    "Global response buffer budget exhausted while reading target '{}'",
                    sub_target.key
                ),
            };
        }
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
        return SubOutcome::Success(Bytes::from_static(b"null"), reservation);
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

    SubOutcome::Success(bytes, reservation)
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
    global_budget: Arc<BufferBudget>,
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
            grpc_web::handle_grpc_web_with_budget(
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
                max_sub_bytes,
                &global_budget,
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
                global_budget,
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
///
/// Holds the consolidated [`BufferReservation`] and releases reserved bytes incrementally
/// as each chunk is yielded to Hyper (or all remaining bytes on `Drop`).
struct ChunkedBytesBody {
    chunks: VecDeque<Bytes>,
    remaining_bytes: usize,
    reservation: BufferReservation,
}

impl http_body::Body for ChunkedBytesBody {
    type Data = Bytes;
    type Error = SrvError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let this = &mut *self;
        while let Some(chunk) = this.chunks.pop_front() {
            if chunk.is_empty() {
                continue;
            }
            this.remaining_bytes = this.remaining_bytes.saturating_sub(chunk.len());
            this.reservation.release(chunk.len());
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
    global_budget: &Arc<BufferBudget>,
) -> Result<ChunkedBytesBody, SrvError> {
    let mut chunks = VecDeque::with_capacity(targets.len() * 3 + 3);
    let mut total_bytes = 0usize;
    let mut consolidated_reservation = BufferReservation::new(Arc::clone(global_budget));

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
            Some(SubOutcome::Success(raw_json, sub_reservation)) => {
                // Zero-copy move of the validated upstream JSON buffer and its reservation
                consolidated_reservation.absorb(sub_reservation);
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
        reservation: consolidated_reservation,
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
    handle_aggregate_with_budget(
        route_info,
        request_body,
        original_method,
        original_version,
        prepared_headers,
        original_uri,
        client_addr,
        server_name,
        client,
        grpc_client,
        config,
        request_timeout,
        global_response_buffer_budget(),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_aggregate_with_budget(
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
    global_budget: &Arc<BufferBudget>,
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
        let sub_global_budget = Arc::clone(global_budget);
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
                    sub_global_budget,
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
                if let SubOutcome::Success(ref bytes, _) = outcome {
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

    let chunked_body =
        assemble_aggregated_body(&route_info.aggregate_targets, outcomes, global_budget)?;
    let content_len = chunked_body.remaining_bytes;

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::CONTENT_LENGTH, content_len)
        .body(chunked_body.boxed())
        .map_err(|e| SrvError::Other(format!("Failed to build aggregate response: {e}")))
}


#[cfg(test)]
mod tests;
