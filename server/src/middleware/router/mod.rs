//! # Reverse-Proxy Routing Service
//!
//! This module implements a Tower [`Service`] that acts as a **reverse proxy**.
//! Incoming HTTP requests are matched against a set of configured route prefixes,
//! then forwarded to the corresponding upstream (backend) server.

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode, header};
use hyper_util::client::legacy::Client;
use matchit::Router;
use tower::Service;
use tracing::{error, warn};

use crate::{
    ServiceRespBody, SrvBody, SrvError,
    configuration::{AuthenticationMethod, ParsedRoute, RouteBackendType, ServerConfig},
};
use common::{build_root_store, build_tls_client_config};

// Submodules
pub(crate) mod aggregator;
pub mod circuit_breaker;
pub(crate) mod grpc_passthrough;
pub(crate) mod grpc_web;
pub(crate) mod headers;
pub(crate) mod http_proxy;
pub(crate) mod rbac;
pub(crate) mod upstreams;

pub use grpc_web::build_grpc_pool;

/// Body handling for retries vs streaming
pub enum RequestBody {
    Stream(SrvBody),
    Buffered(bytes::Bytes),
}

/// Builds a minimal synthetic HTTP error response.
pub(crate) fn build_error_response(msg: &str, status: StatusCode) -> Response<ServiceRespBody> {
    let body = Full::new(Bytes::from(msg.to_string()))
        .map_err(SrvError::from)
        .boxed();
    Response::builder()
        .status(status)
        .body(body)
        .expect("Response builder failed")
}

#[derive(Clone)]
pub struct RouterService {
    client: Client<
        common::client::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        ServiceRespBody,
    >,
    grpc_client: Client<
        common::client::HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>,
        ServiceRespBody,
    >,
    router: Arc<Router<ParsedRoute>>,
    config: Arc<ServerConfig>,
    jwt_token: Option<header::HeaderValue>,
}

impl RouterService {
    pub fn new(config: Arc<ServerConfig>) -> Result<Self, anyhow::Error> {
        let router_params = config
            .router_params
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("{}: Router params missing", config.name))?;

        let mut router = Router::new();
        for route_data in &config.parsed_routes {
            let prefix = &route_data.prefix;
            router.insert(prefix, route_data.clone()).map_err(|e| {
                anyhow::anyhow!("{}: Failed to insert route '{}': {}", config.name, prefix, e)
            })?;

            let wildcard_path = if prefix.ends_with('/') {
                format!("{}{{*rest}}", prefix)
            } else {
                format!("{}/{{*rest}}", prefix)
            };

            if let Err(e) = router.insert(&wildcard_path, route_data.clone()) {
                warn!(
                    "{}: Failed to insert wildcard route {}: {}",
                    config.name, wildcard_path, e
                );
            } else {
                tracing::debug!(
                    "{}: Registered route: {} and {}",
                    config.name,
                    prefix,
                    wildcard_path
                );
            }
        }
        let router = Arc::new(router);

        let root_store = build_root_store(&router_params.ssl_root_certificate)?;
        let is_mtls = router_params.authentication == AuthenticationMethod::ClientCert;

        let tls_client_config = if is_mtls {
            build_tls_client_config(
                root_store,
                router_params.ssl_client_certificate.as_deref(),
                router_params.ssl_client_key.as_deref(),
            )?
        } else {
            build_tls_client_config(root_store, None, None)?
        };

        let client = {
            let pool_config = common::client::ClientPoolConfig {
                idle_timeout: Some(std::time::Duration::from_secs(router_params.idle_timeout_seconds)),
                max_idle_per_host: Some(1024),
                http2_only: false,
                connect_timeout: (router_params.connect_timeout_seconds > 0)
                    .then(|| std::time::Duration::from_secs(router_params.connect_timeout_seconds)),
                ..Default::default()
            };
            common::client::build_hyper_client(tls_client_config.clone(), pool_config)
        };

        let grpc_client = {
            let pool_config = common::client::ClientPoolConfig {
                idle_timeout: Some(std::time::Duration::from_secs(router_params.idle_timeout_seconds)),
                max_idle_per_host: Some(1024),
                http2_only: true,
                connect_timeout: (router_params.connect_timeout_seconds > 0)
                    .then(|| std::time::Duration::from_secs(router_params.connect_timeout_seconds)),
                ..Default::default()
            };
            common::client::build_hyper_client(tls_client_config.clone(), pool_config)
        };

        let jwt_token = match router_params.jwt.as_ref() {
            Some(t) => Some(
                header::HeaderValue::from_str(&format!("Bearer {}", t)).map_err(|e| {
                    anyhow::anyhow!(
                        "{}: Invalid [Server.RouterParams].jwt header value: {}",
                        config.name,
                        e
                    )
                })?,
            ),
            None => None,
        };

        Ok(RouterService {
            client,
            grpc_client,
            router,
            config,
            jwt_token,
        })
    }

    fn handle_health_check(&self) -> Result<Response<ServiceRespBody>, SrvError> {
        let config = &self.config;
        if config.parsed_routes.is_empty() {
            return Ok(build_error_response(
                r#"{"score": 100, "message": "no routes configured"}"#,
                StatusCode::OK,
            ));
        }

        let any_alive = config.parsed_routes.iter().any(is_route_healthy);

        if any_alive {
            Ok(build_error_response(
                r#"{"score": 100, "message": "nodes available"}"#,
                StatusCode::OK,
            ))
        } else {
            Ok(build_error_response(
                r#"{"score": 0, "message": "no upstream nodes available"}"#,
                StatusCode::SERVICE_UNAVAILABLE,
            ))
        }
    }
}

/// Evaluates whether a single configured route has enough healthy upstream capacity to serve
/// traffic: an `aggregate` route is healthy only when **every `required` sub-target** has at least
/// one available upstream (or, if all targets are optional, when at least one sub-target does).
fn is_route_healthy(route: &ParsedRoute) -> bool {
    if route.backend_type == RouteBackendType::Aggregate {
        let has_required = route.aggregate_targets.iter().any(|sub| sub.required);
        if has_required {
            route
                .aggregate_targets
                .iter()
                .filter(|sub| sub.required)
                .all(|sub| {
                    sub.target
                        .upstreams
                        .iter()
                        .any(|node| node.is_available(sub.target.cooldown_seconds))
                })
        } else {
            route.aggregate_targets.iter().any(|sub| {
                sub.target
                    .upstreams
                    .iter()
                    .any(|node| node.is_available(sub.target.cooldown_seconds))
            })
        }
    } else {
        route
            .target
            .upstreams
            .iter()
            .any(|node| node.is_available(route.target.cooldown_seconds))
    }
}

impl Service<Request<SrvBody>> for RouterService {
    type Response = Response<ServiceRespBody>;
    type Error = SrvError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<SrvBody>) -> Self::Future {
        let router = Arc::clone(&self.router);
        let client = self.client.clone();
        let grpc_client = self.grpc_client.clone();
        let server_name = self.config.static_name.unwrap_or("unknown");
        let jwt_token = self.jwt_token.clone();
        let self_clone = self.clone();

        Box::pin(async move {
            let (mut parts, body) = req.into_parts();

            if parts.uri.path() == "/health" && parts.method == hyper::Method::GET {
                return self_clone.handle_health_check();
            }

            let client_addr = parts.extensions.get::<std::net::SocketAddr>().copied();
            headers::inject_real_ip(&mut parts);

            // Defense-in-depth: Validate and canonicalize URI path
            match crate::middleware::path_sanitizer::sanitize_and_normalize_uri(&parts.uri) {
                Ok(clean_uri) => {
                    parts.uri = clean_uri;
                }
                Err(e) => {
                    crate::configuration::ServerMetrics::inc_blocked_path_sanitizer(server_name);
                    tracing::warn!(
                        target: "security",
                        "{}: RouterService rejected invalid path '{}': {}",
                        server_name,
                        parts.uri.path(),
                        e
                    );
                    return Ok(build_error_response(
                        &format!("Bad Request: {}", e),
                        StatusCode::BAD_REQUEST,
                    ));
                }
            }

            let path = parts.uri.path();
            let matched = match router.at(path) {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!(
                        "{}: Route not found for path '{}', error: {:?}",
                        server_name,
                        path,
                        e
                    );
                    return Ok(build_error_response("Not Found", StatusCode::NOT_FOUND));
                }
            };
            let route_info = matched.value;

            if let Err(forbidden_response) = rbac::enforce_rbac(
                &parts,
                route_info,
                self_clone.config.compiled_rbac.as_deref(),
                server_name,
            ) {
                return Ok(*forbidden_response);
            }

            // Internal Admin / Telemetry route (`backend_type = "admin"`) is answered directly in-memory
            if route_info.backend_type == RouteBackendType::Admin {
                return Ok(
                    crate::middleware::admin::handle_admin_request_with_prefix(
                        &parts.uri,
                        &parts.method,
                        &parts.headers,
                        Some(&self_clone.config),
                        Some(route_info.prefix.as_str()),
                    ),
                );
            }

            let original_method = parts.method;
            let mut prepared_headers = parts.headers;

            // For HTTP/2 and HTTP/3, populate Host from :authority if not explicitly present
            if !prepared_headers.contains_key(header::HOST)
                && let Some(auth) = parts.uri.authority()
                    && let Ok(hv) = header::HeaderValue::from_str(auth.as_str()) {
                        prepared_headers.insert(header::HOST, hv);
                    }

            if let Err(err_resp) = headers::prepare_proxy_headers(
                &mut prepared_headers,
                server_name,
                jwt_token.as_ref(),
                &parts.extensions,
                &self_clone.config,
            ) {
                return Ok(*err_resp);
            }

            let original_version = if parts.version == hyper::Version::HTTP_3 {
                hyper::Version::HTTP_2
            } else {
                parts.version
            };

            let is_buffered_only = matches!(
                route_info.backend_type,
                RouteBackendType::GrpcTranscoding | RouteBackendType::Aggregate
            );
            let is_passthrough = route_info.backend_type == RouteBackendType::GrpcPassthrough;
            let has_failover_nodes = route_info.target.upstreams.len() > 1;
            let is_idempotent = matches!(
                original_method,
                hyper::Method::GET
                    | hyper::Method::HEAD
                    | hyper::Method::PUT
                    | hyper::Method::DELETE
                    | hyper::Method::OPTIONS
            );

            let parsed_content_length = prepared_headers
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<usize>().ok());

            // Early Content-Length check before buffering body frames into RAM.
            if is_buffered_only
                && let Some(content_len) = parsed_content_length
                && content_len > route_info.max_request_bytes
            {
                tracing::warn!(
                    "{}: Request Content-Length ({} bytes) exceeded route buffered limit ({} bytes)",
                    server_name,
                    content_len,
                    route_info.max_request_bytes
                );
                return Ok(build_error_response(
                    "Payload Too Large",
                    StatusCode::PAYLOAD_TOO_LARGE,
                ));
            }

            // Check if Content-Length already exceeds max_retry_buffer_bytes
            let content_length_exceeds_retry_buf = parsed_content_length
                .is_some_and(|len| len > route_info.target.max_retry_buffer_bytes);

            // Fast-path:
            // - If there is only 1 upstream node (!has_failover_nodes) or max_retries == 0, always stream!
            // - For REST routes, only buffer idempotent methods.
            // - For gRPC passthrough routes (which always use HTTP POST), buffer up to max_retry_buffer_bytes
            //   when failover nodes exist so unary & server-streaming calls (e.g. StreamGlobalEvents) can
            //   seamlessly fail over to a healthy node on connection/outlier errors.
            let can_stream = (!has_failover_nodes
                || route_info.target.max_retries == 0
                || (!is_passthrough && !is_idempotent)
                || content_length_exceeds_retry_buf)
                && !is_buffered_only;

            let request_timeout = self_clone
                .config
                .router_params
                .as_ref()
                .and_then(|p| (p.request_timeout_seconds > 0).then(|| std::time::Duration::from_secs(p.request_timeout_seconds)));
            let buffer_timeout = request_timeout.unwrap_or(std::time::Duration::from_secs(10));

            let request_body = if can_stream {
                RequestBody::Stream(body)
            } else if is_buffered_only {
                let limited = http_body_util::Limited::new(body, route_info.max_request_bytes);
                match tokio::time::timeout(buffer_timeout, limited.collect()).await {
                    Ok(Ok(c)) => RequestBody::Buffered(c.to_bytes()),
                    Ok(Err(e)) => {
                        if matches!(
                            http_proxy::classify_error_chain(e.as_ref()),
                            http_proxy::ProxyErrorKind::PayloadTooLarge
                                | http_proxy::ProxyErrorKind::DecompressionLimitExceeded
                        ) {
                            tracing::warn!(
                                "{}: Request body exceeded buffered limit ({} bytes): {}",
                                server_name,
                                route_info.max_request_bytes,
                                e
                            );
                            return Ok(build_error_response(
                                "Payload Too Large",
                                StatusCode::PAYLOAD_TOO_LARGE,
                            ));
                        }
                        error!("{}: Failed to read request body: {}", server_name, e);
                        return Ok(build_error_response("Bad Request", StatusCode::BAD_REQUEST));
                    }
                    Err(_) => {
                        tracing::warn!(
                            "{}: Request body buffering timed out after {:?}",
                            server_name,
                            buffer_timeout
                        );
                        return Ok(build_error_response(
                            "Request Timeout",
                            StatusCode::REQUEST_TIMEOUT,
                        ));
                    }
                }
            } else {
                // Bounded retry buffering: for gRPC passthrough, stop after the first
                // complete frame unless EOF is already present (so bidi/client streams
                // start immediately without waiting for EOF).
                let buffer_fut = async {
                    if is_passthrough {
                        circuit_breaker::buffer_grpc_first_frame_or_stream(
                            body,
                            route_info.target.max_retry_buffer_bytes,
                        )
                        .await
                    } else {
                        circuit_breaker::buffer_body_up_to(
                            body,
                            route_info.target.max_retry_buffer_bytes,
                        )
                        .await
                    }
                };
                match tokio::time::timeout(buffer_timeout, buffer_fut).await {
                    Ok(Ok(req_body)) => req_body,
                    Ok(Err(e)) => {
                        if matches!(
                            http_proxy::classify_error_chain(&e),
                            http_proxy::ProxyErrorKind::PayloadTooLarge
                                | http_proxy::ProxyErrorKind::DecompressionLimitExceeded
                        ) {
                            tracing::warn!("{}: Request body exceeded payload limit: {}", server_name, e);
                            return Ok(build_error_response(
                                "Payload Too Large",
                                StatusCode::PAYLOAD_TOO_LARGE,
                            ));
                        }
                        error!("{}: Failed to read request body: {}", server_name, e);
                        return Ok(build_error_response("Bad Request", StatusCode::BAD_REQUEST));
                    }
                    Err(_) => {
                        tracing::warn!(
                            "{}: Retry body buffering timed out after {:?}",
                            server_name,
                            buffer_timeout
                        );
                        return Ok(build_error_response(
                            "Request Timeout",
                            StatusCode::REQUEST_TIMEOUT,
                        ));
                    }
                }
            };

            // Dispatch to the proper specialized terminal service
            match route_info.backend_type {
                RouteBackendType::GrpcTranscoding => {
                    grpc_web::handle_grpc_web(
                        &route_info.target,
                        request_body,
                        original_method,
                        prepared_headers,
                        &parts.uri,
                        client_addr,
                        server_name,
                        &grpc_client,
                        &self_clone.config,
                        request_timeout,
                    )
                    .await
                }
                RouteBackendType::GrpcPassthrough => {
                    grpc_passthrough::handle_grpc_passthrough(
                        &route_info.target,
                        request_body,
                        original_method,
                        prepared_headers,
                        &parts.uri,
                        &matched.params,
                        client_addr,
                        server_name,
                        &grpc_client,
                        request_timeout,
                    )
                    .await
                }
                RouteBackendType::Rest => {
                    http_proxy::handle_http_proxy(
                        &route_info.target,
                        request_body,
                        original_method,
                        original_version,
                        prepared_headers,
                        &parts.uri,
                        &matched.params,
                        client_addr,
                        server_name,
                        &client,
                        request_timeout,
                    )
                    .await
                }
                RouteBackendType::Admin => Ok(
                    crate::middleware::admin::handle_admin_request_with_prefix(
                        &parts.uri,
                        &original_method,
                        &prepared_headers,
                        Some(&self_clone.config),
                        Some(route_info.prefix.as_str()),
                    ),
                ),
                RouteBackendType::Aggregate => {
                    aggregator::handle_aggregate(
                        route_info,
                        request_body,
                        original_method,
                        original_version,
                        prepared_headers,
                        &parts.uri,
                        client_addr,
                        server_name,
                        &client,
                        &grpc_client,
                        &self_clone.config,
                        request_timeout,
                    )
                    .await
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::ServerConfig;

    #[test]
    fn test_aggregate_route_health_requires_all_required_targets() {
        let toml_cfg = r#"
            name = "health_agg"
            enabled = true
            protocol = "http"
            service = "Router"
            ip = "127.0.0.1"
            port = 8080

            [RouterParams]
            protocol = "http"

            [Layers]
            enabled = []

            [ReverseRoutes."/agg"]
            backend_type = "aggregate"

            [[ReverseRoutes."/agg".targets]]
            key = "req_a"
            backend_type = "rest"
            upstreams = ["http://127.0.0.1:9001"]
            path = "/a"
            required = true

            [[ReverseRoutes."/agg".targets]]
            key = "opt_b"
            backend_type = "rest"
            upstreams = ["http://127.0.0.1:9002"]
            path = "/b"
            required = false
        "#;
        let mut cfg: ServerConfig = toml::from_str(toml_cfg).unwrap();
        cfg.finalize().unwrap();
        let route = &cfg.parsed_routes[0];

        assert!(is_route_healthy(route), "All targets alive => healthy");

        // Optional target dead while required target alive => still healthy
        route.aggregate_targets[1].target.upstreams[0].mark_dead();
        assert!(
            is_route_healthy(route),
            "Aggregate route with dead optional target must stay healthy"
        );

        // Revive optional, kill required => must be UNHEALTHY even though optional is alive!
        route.aggregate_targets[1].target.upstreams[0].mark_alive();
        route.aggregate_targets[0].target.upstreams[0].mark_dead();
        assert!(
            !is_route_healthy(route),
            "Aggregate route with dead required target must report unhealthy even when optional targets are alive"
        );
    }

    #[test]
    fn test_aggregate_route_health_all_optional_is_healthy_if_any_alive() {
        let toml_cfg = r#"
            name = "health_opt_only"
            enabled = true
            protocol = "http"
            service = "Router"
            ip = "127.0.0.1"
            port = 8080

            [RouterParams]
            protocol = "http"

            [Layers]
            enabled = []

            [ReverseRoutes."/agg"]
            backend_type = "aggregate"

            [[ReverseRoutes."/agg".targets]]
            key = "opt_a"
            backend_type = "rest"
            upstreams = ["http://127.0.0.1:9001"]
            path = "/a"
            required = false

            [[ReverseRoutes."/agg".targets]]
            key = "opt_b"
            backend_type = "rest"
            upstreams = ["http://127.0.0.1:9002"]
            path = "/b"
            required = false
        "#;
        let mut cfg: ServerConfig = toml::from_str(toml_cfg).unwrap();
        cfg.finalize().unwrap();
        let route = &cfg.parsed_routes[0];

        route.aggregate_targets[0].target.upstreams[0].mark_dead();
        assert!(
            is_route_healthy(route),
            "Optional-only aggregate route remains healthy if another optional target is alive"
        );
        route.aggregate_targets[1].target.upstreams[0].mark_dead();
        assert!(
            !is_route_healthy(route),
            "Optional-only aggregate route is unhealthy when every target is dead"
        );
    }

    #[test]
    fn test_router_service_rejects_invalid_upstream_jwt_header() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let toml_cfg = r#"
            name = "bad_jwt_router"
            enabled = true
            protocol = "http"
            service = "Router"
            ip = "127.0.0.1"
            port = 8080

            [RouterParams]
            protocol = "http"
            jwt = "invalid\ntoken"

            [Layers]
            enabled = []
        "#;
        let mut cfg: ServerConfig = toml::from_str(toml_cfg).unwrap();
        cfg.finalize().unwrap();
        let err = RouterService::new(Arc::new(cfg))
            .err()
            .expect("invalid HeaderValue in RouterParams.jwt must return Err");
        assert!(err.to_string().contains("Invalid [Server.RouterParams].jwt"));
    }

    #[tokio::test]
    async fn test_router_early_content_length_rejects_buffered_route_before_reading_body() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use tower::Service;

        let _ = rustls::crypto::ring::default_provider().install_default();
        let toml_cfg = r#"
            name = "early_cl_router"
            enabled = true
            protocol = "http"
            service = "Router"
            ip = "127.0.0.1"
            port = 8080

            [RouterParams]
            protocol = "http"

            [Layers]
            enabled = []

            [ReverseRoutes."/agg"]
            strategy = "RoundRobin"
            backend_type = "aggregate"
            max_request_bytes = 64

            [[ReverseRoutes."/agg".targets]]
            key = "a"
            backend_type = "rest"
            upstreams = ["http://127.0.0.1:9001"]
            path = "/a"
        "#;
        let mut cfg: ServerConfig = toml::from_str(toml_cfg).unwrap();
        cfg.finalize().unwrap();
        let mut svc = RouterService::new(Arc::new(cfg)).unwrap();

        struct FlagBody {
            polled: Arc<AtomicBool>,
        }
        impl http_body::Body for FlagBody {
            type Data = bytes::Bytes;
            type Error = SrvError;
            fn poll_frame(
                self: std::pin::Pin<&mut Self>,
                _cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
                self.polled.store(true, Ordering::SeqCst);
                std::task::Poll::Ready(None)
            }
        }

        let polled = Arc::new(AtomicBool::new(false));
        let req = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri("/agg")
            .header(hyper::header::CONTENT_LENGTH, "1024")
            .body(FlagBody { polled: polled.clone() }.boxed())
            .unwrap();

        let resp = svc.call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(
            !polled.load(Ordering::SeqCst),
            "Early Content-Length check must reject before polling request body"
        );
    }

    #[test]
    fn test_typed_error_classification_via_source_chain() {
        let len_err: Box<dyn std::error::Error + Send + Sync> =
            Box::new(SrvError::PayloadTooLarge { current: 20, max: 10 });
        assert_eq!(
            http_proxy::classify_error_chain(len_err.as_ref()),
            http_proxy::ProxyErrorKind::PayloadTooLarge
        );

        let dec_err: Box<dyn std::error::Error + Send + Sync> =
            Box::new(SrvError::DecompressionLimitExceeded { max: 100 });
        assert_eq!(
            http_proxy::classify_error_chain(dec_err.as_ref()),
            http_proxy::ProxyErrorKind::DecompressionLimitExceeded
        );
    }
}
