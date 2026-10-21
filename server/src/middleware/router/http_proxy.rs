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
    request_timeout: Option<std::time::Duration>,
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

        let req_fut = client.request(proxy_req);
        let resp_result = if let Some(timeout_dur) = request_timeout {
            match tokio::time::timeout(timeout_dur, req_fut).await {
                Ok(res) => res,
                Err(_elapsed) => {
                    error!(
                        "{}: Upstream request timed out after {:?} for {}",
                        server_name, timeout_dur, backend_base_uri
                    );
                    route_info.target.mark_dead(backend_base_uri);
                    failed_nodes.push(backend_base_uri.clone());

                    if attempts <= max_retries {
                        warn!(
                            "{}: Retrying timed-out request... (Attempt {}/{})",
                            server_name, attempts, max_retries
                        );
                        continue;
                    } else {
                        return Ok(build_error_response("Gateway Timeout", StatusCode::GATEWAY_TIMEOUT));
                    }
                }
            }
        } else {
            req_fut.await
        };

        match resp_result {
            Ok(res) => {
                let (mut res_parts, res_body) = res.into_parts();
                super::headers::clean_response_headers(&mut res_parts.headers);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
    use std::time::Duration;
    use crate::configuration::{LbStrategy, RouteBackendType, RouteTarget, UpstreamNode};

    #[tokio::test]
    async fn test_http_proxy_request_timeout_returns_504() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // Spawn a slow upstream that accepts but delays sending any HTTP response
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                // Sleep longer than the request timeout
                tokio::time::sleep(Duration::from_millis(300)).await;
                use tokio::io::AsyncWriteExt;
                let _ = socket.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK").await;
            }
        });

        let upstream_uri: Uri = format!("http://127.0.0.1:{}", port).parse().unwrap();
        let node = UpstreamNode {
            uri: upstream_uri.clone(),
            active_connections: AtomicUsize::new(0),
            is_alive: AtomicBool::new(true),
            last_failure_time: AtomicU64::new(0),
            current_score: AtomicUsize::new(0),
        };

        let target = Arc::new(RouteTarget {
            upstreams: vec![node],
            strategy: LbStrategy::RoundRobin,
            rr_counter: AtomicUsize::new(0),
            cooldown_seconds: 10,
            max_retries: 0,
            active_health_check_interval: 0,
            grpc_pool: tokio::sync::RwLock::new(None),
            grpc_reflection_lock: tokio::sync::Mutex::new(()),
        });

        let route_info = ParsedRoute {
            prefix: "/api".to_string(),
            target: target.clone(),
            allowed_roles: Vec::new(),
            backend_type: RouteBackendType::Rest,
        };

        let root_store = rustls::RootCertStore::empty();
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let client = common::client::build_hyper_client(tls_config, common::client::ClientPoolConfig::default());

        let matched_params = matchit::Params::new();

        let req_uri: Uri = "http://localhost/api/slow".parse().unwrap();
        let prepared_headers = hyper::HeaderMap::new();

        // Send with a short timeout of 50ms (mock server sleeps 300ms)
        let response = handle_http_proxy(
            &route_info,
            RequestBody::Buffered(bytes::Bytes::new()),
            Method::GET,
            Version::HTTP_11,
            prepared_headers,
            &req_uri,
            &matched_params,
            None,
            "test_server",
            &client,
            Some(Duration::from_millis(50)),
        )
        .await
        .unwrap();

        assert_eq!(response.status(), StatusCode::GATEWAY_TIMEOUT);
        assert!(!target.upstreams[0].is_alive.load(Ordering::Relaxed), "Timed out node must be marked dead");
    }
}
