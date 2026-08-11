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
    pub fn new(config: Arc<ServerConfig>) -> Self {
        let router_params = config
            .router_params
            .as_ref()
            .expect("Router params missing");

        let mut router = Router::new();
        for route_data in &config.parsed_routes {
            let prefix = &route_data.prefix;
            let _ = router.insert(prefix, route_data.clone());

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

        let root_store = build_root_store(&router_params.ssl_root_certificate);
        let is_mtls = router_params.authentication == AuthenticationMethod::ClientCert;

        let tls_client_config = if is_mtls {
            build_tls_client_config(
                root_store,
                router_params.ssl_client_certificate.as_deref(),
                router_params.ssl_client_key.as_deref(),
            )
        } else {
            build_tls_client_config(root_store, None, None)
        };

        let client = {
            let pool_config = common::client::ClientPoolConfig {
                idle_timeout: Some(std::time::Duration::from_secs(90)),
                max_idle_per_host: Some(1024),
                http2_only: false,
            };
            common::client::build_hyper_client(tls_client_config.clone(), pool_config)
        };

        let grpc_client = {
            let pool_config = common::client::ClientPoolConfig {
                idle_timeout: Some(std::time::Duration::from_secs(90)),
                max_idle_per_host: Some(1024),
                http2_only: true,
            };
            common::client::build_hyper_client(tls_client_config.clone(), pool_config)
        };

        let jwt_token = router_params
            .jwt
            .as_ref()
            .and_then(|t| header::HeaderValue::from_str(&format!("Bearer {}", t)).ok());

        RouterService {
            client,
            grpc_client,
            router,
            config,
            jwt_token,
        }
    }

    fn handle_health_check(&self) -> Result<Response<ServiceRespBody>, SrvError> {
        let config = &self.config;
        if config.parsed_routes.is_empty() {
            return Ok(build_error_response(
                r#"{"score": 100, "message": "no routes configured"}"#,
                StatusCode::OK,
            ));
        }

        let mut any_alive = false;
        for route in &config.parsed_routes {
            for node in &route.target.upstreams {
                if node.is_available(route.target.cooldown_seconds) {
                    any_alive = true;
                    break;
                }
            }
            if any_alive {
                break;
            }
        }

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

            if let Err(forbidden_response) = rbac::enforce_rbac(&parts, route_info, server_name) {
                return Ok(forbidden_response);
            }

            let original_method = parts.method;
            let mut prepared_headers = parts.headers;

            if let Err(err_resp) = headers::prepare_proxy_headers(
                &mut prepared_headers,
                server_name,
                jwt_token.as_ref(),
                &parts.extensions,
                &self_clone.config,
            ) {
                return Ok(err_resp);
            }

            let original_version = if parts.version == hyper::Version::HTTP_3 {
                hyper::Version::HTTP_2
            } else {
                parts.version
            };

            let is_transcoding = route_info.backend_type == RouteBackendType::GrpcTranscoding;
            let is_passthrough = route_info.backend_type == RouteBackendType::GrpcPassthrough;
            let can_stream =
                (route_info.target.max_retries == 0 || is_passthrough) && !is_transcoding;

            let request_body = if can_stream {
                RequestBody::Stream(body)
            } else {
                match body.collect().await {
                    Ok(c) => RequestBody::Buffered(c.to_bytes()),
                    Err(e) => {
                        error!("{}: Failed to read request body: {}", server_name, e);
                        return Ok(build_error_response("Bad Request", StatusCode::BAD_REQUEST));
                    }
                }
            };

            // Dispatch to the proper specialized terminal service
            match route_info.backend_type {
                RouteBackendType::GrpcTranscoding => {
                    grpc_web::handle_grpc_web(
                        route_info,
                        request_body,
                        original_method,
                        prepared_headers,
                        &parts.uri,
                        client_addr,
                        server_name,
                        &grpc_client,
                        &self_clone.config,
                    )
                    .await
                }
                RouteBackendType::GrpcPassthrough => {
                    grpc_passthrough::handle_grpc_passthrough(
                        route_info,
                        request_body,
                        original_method,
                        prepared_headers,
                        &parts.uri,
                        &matched.params,
                        client_addr,
                        server_name,
                        &grpc_client,
                    )
                    .await
                }
                RouteBackendType::Rest => {
                    http_proxy::handle_http_proxy(
                        route_info,
                        request_body,
                        original_method,
                        original_version,
                        prepared_headers,
                        &parts.uri,
                        &matched.params,
                        client_addr,
                        server_name,
                        &client,
                    )
                    .await
                }
            }
        })
    }
}
