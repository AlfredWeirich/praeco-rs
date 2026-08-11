use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Response, StatusCode, Uri, Version, header};
use hyper_util::client::legacy::Client;
use std::sync::Arc;
use tracing::{error, warn};

use super::upstreams::build_upstream_uri;
use super::{RequestBody, build_error_response};
use crate::{ServiceRespBody, SrvError, configuration::ParsedRoute};

pub async fn handle_http_proxy(
    route_info: &ParsedRoute,
    mut request_body: RequestBody,
    original_method: Method,
    original_version: Version,
    mut prepared_headers: hyper::HeaderMap,
    original_uri: &Uri,
    matched_params: &matchit::Params<'_, '_>,
    client_addr: Option<std::net::SocketAddr>,
    server_name: &str,
    client: &Client<
        common::client::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        ServiceRespBody,
    >,
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

        let target_uri = build_upstream_uri(backend_base_uri, matched_params, original_uri)?;

        if let Some(auth) = target_uri.authority() {
            if let Ok(host_val) = header::HeaderValue::from_str(auth.as_str()) {
                current_headers.insert(header::HOST, host_val);
            }
        }

        let boxed_body: ServiceRespBody = match &mut request_body {
            RequestBody::Stream(_b) => {
                let mut temp_body = RequestBody::Buffered(bytes::Bytes::new());
                std::mem::swap(&mut temp_body, &mut request_body);
                if let RequestBody::Stream(taken_body) = temp_body {
                    taken_body
                } else {
                    unreachable!()
                }
            }
            RequestBody::Buffered(bytes) => {
                Full::new(bytes.clone()).map_err(SrvError::from).boxed()
            }
        };

        let mut proxy_req = Request::new(boxed_body);
        *proxy_req.method_mut() = original_method.clone();
        *proxy_req.uri_mut() = target_uri;
        *proxy_req.version_mut() = original_version;
        *proxy_req.headers_mut() = current_headers;

        // Inject OpenTelemetry context (e.g., traceparent) into the outgoing request headers.
        opentelemetry::global::get_text_map_propagator(|propagator| {
            use tracing_opentelemetry::OpenTelemetrySpanExt;
            propagator.inject_context(
                &tracing::Span::current().context(),
                &mut opentelemetry_http::HeaderInjector(proxy_req.headers_mut()),
            );
        });

        match client.request(proxy_req).await {
            Ok(res) => {
                let (res_parts, res_body) = res.into_parts();
                return Ok(Response::from_parts(
                    res_parts,
                    res_body.map_err(SrvError::from).boxed(),
                ));
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
                        "{}: Retrying request... (Attempt {}/{})",
                        server_name, attempts, max_retries
                    );
                    continue;
                } else {
                    error!(
                        "{}: Max retries reached. Returning 502 Bad Gateway.",
                        server_name
                    );
                    return Ok(build_error_response("Bad Gateway", StatusCode::BAD_GATEWAY));
                }
            }
        }
    }
}
