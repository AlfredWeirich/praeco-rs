//! # Service Stack Assembly & Stream Runners
//!
//! This module provides the core building blocks for assembling a server's
//! Tower middleware pipeline ([`build_service_stack`], [`apply_layers`]),
//! configuring TLS ([`build_rustls_config`], [`build_tunnel_tls_connector`]),
//! and serving HTTP/1.1, HTTP/2, and Yamux-tunneled connections over arbitrary
//! asynchronous streams ([`serve_http_connection`], [`serve_tls_connection`],
//! [`run_tunnel_over_stream`]).
//!
//! Keeping these functions in the library crate decouples protocol and
//! middleware orchestration from listener/signal management (`src/runner.rs`,
//! `src/server.rs`), enabling deterministic in-memory integration and
//! end-to-end testing via `tokio::io::duplex`.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use http_body_util::BodyExt;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use hyper_util::server::conn::auto;
use rustls::ServerConfig as RustlsServerConfig;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::task::JoinSet;
use tokio_util::compat::{FuturesAsyncReadCompatExt, TokioAsyncReadCompatExt};
use tokio_util::sync::CancellationToken;
use tower::Layer;
use tracing::{ Instrument, Level, error, info, info_span, trace, warn};

use crate::{
    BoxCloneSyncService, BoxCloneSyncServiceExt, BoxedCloneService, ConnectionHandler, SrvBody,
    SrvError,
    configuration::{
        AuthenticationMethod, CompiledAllowedPathes, MiddlewareLayer, RateLimiter, ServerConfig,
        ServerMetrics, ServiceType, TunnelConfig, UserRole,
    },
    connection_tracker::{AcquireError, ConnectionTracker},
    middleware::{
        AdminService, ConcurrencyLimitLayer, CountingLayer, DelayLayer, EchoService,
        InspectionLayer, IpFilterLayer, JwtAuthLayer, LoggerLayer, MaxPayloadLayer,
        PathSanitizerLayer, RouterService, SecurityHeadersLayer, SimpleRateLimiterLayer,
        TimingLayer, TokenBucketRateLimiterLayer, TraceIdLayer,
        alt_svc::AltSvcLayer,
        compression::{SrvCompressionLayer, SrvDecompressionLayer},
        idp::IdpService,
    },
    tls_conf::{extract_client_metadata, tls_config},
};

/// Wraps a `tower_http::services::ServeDir` (with or without fallback) into
/// Praeco's [`BoxedCloneService`] requirement.
pub fn wrap_serve_dir<S>(serve: S) -> BoxedCloneService
where
    S: tower::Service<
            hyper::Request<SrvBody>,
            Response = hyper::Response<tower_http::services::fs::ServeFileSystemResponseBody>,
        > + Clone
        + Send
        + Sync
        + 'static,
    S::Future: Send + 'static,
    S::Error: std::fmt::Display + 'static,
{
    /// Wraps `tower_http::services::ServeFileSystemResponseBody` (which is
    /// `Send` but not `Sync`) to satisfy the `BoxBody<Bytes, SrvError>`
    /// (`Send + Sync`) requirement of Praeco's middleware pipeline.
    ///
    /// # Safety
    /// The inner body is only ever accessed from a single `async move` task
    /// context (by Hyper). No concurrent `&self` access occurs across threads,
    /// so the `Sync` bound is trivially satisfied.
    struct SyncWrapper<B>(B);
    unsafe impl<B: Send> Sync for SyncWrapper<B> {}
    impl<B: hyper::body::Body + Unpin> hyper::body::Body for SyncWrapper<B> {
        type Data = B::Data;
        type Error = B::Error;

        fn poll_frame(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
            std::pin::Pin::new(&mut self.0).poll_frame(cx)
        }

        fn is_end_stream(&self) -> bool {
            self.0.is_end_stream()
        }

        fn size_hint(&self) -> hyper::body::SizeHint {
            self.0.size_hint()
        }
    }

    let svc = tower::service_fn(move |req: hyper::Request<SrvBody>| {
        let s = serve.clone();
        async move {
            use tower::ServiceExt;
            match s.oneshot(req).await {
                Ok(response) => {
                    let mapped = response.map(|b| {
                        SyncWrapper(b)
                            .map_err(|e| SrvError::from(e.to_string()))
                            .boxed()
                    });
                    Ok(mapped)
                }
                Err(e) => Err(SrvError::from(e.to_string())),
            }
        }
    });
    BoxCloneSyncService::new(svc)
}

/// Zero-cost `Sync` adapter for `tonic::body::Body` (which wraps `UnsyncBoxBody`),
/// allowing streaming gRPC responses to fit [`ServiceRespBody`] (`Send + Sync`).
struct TonicSyncBody<B>(std::sync::Mutex<B>);

impl<B> http_body::Body for TonicSyncBody<B>
where
    B: http_body::Body + Unpin + Send,
    B::Error: std::fmt::Display,
{
    type Data = B::Data;
    type Error = SrvError;

    fn poll_frame(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let inner = self
            .get_mut()
            .0
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::pin::Pin::new(inner)
            .poll_frame(cx)
            .map_err(|e| SrvError::Other(e.to_string()))
    }

    fn is_end_stream(&self) -> bool {
        self.0
            .lock()
            .map(|b| b.is_end_stream())
            .unwrap_or(false)
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.0
            .lock()
            .map(|b| b.size_hint())
            .unwrap_or_default()
    }
}

/// Adapts a `tonic::service::Routes` router into a [`BoxedCloneService`] compatible
/// with [`build_service_stack_with_base`] and [`apply_layers`].
///
/// Maps Praeco's `PayloadTooLarge` and `DecompressionLimitExceeded` errors to gRPC
/// `RESOURCE_EXHAUSTED` (status code 8) and streams response bodies via an internal
/// `Sync` adapter without full-message buffering.
pub fn wrap_tonic_routes(routes: tonic::service::Routes) -> BoxedCloneService {
    use tower::Service;

    let svc = routes.prepare();
    tower::service_fn(move |req: hyper::Request<SrvBody>| {
        let mut svc = svc.clone();
        async move {
            let (parts, body) = req.into_parts();
            let tonic_body = tonic::body::Body::new(body.map_err(|e| match e {
                SrvError::PayloadTooLarge { .. } | SrvError::DecompressionLimitExceeded { .. } => {
                    tonic::Status::resource_exhausted(e.to_string())
                }
                SrvError::ClientAborted(msg) => tonic::Status::cancelled(msg),
                other => tonic::Status::internal(other.to_string()),
            }));
            let tonic_req = hyper::Request::from_parts(parts, tonic_body);

            let res = svc.call(tonic_req).await.unwrap_or_else(|e| match e {});
            let (res_parts, res_body) = res.into_parts();
            let boxed_resp: crate::ServiceRespBody =
                TonicSyncBody(std::sync::Mutex::new(res_body)).boxed();
            Ok::<_, SrvError>(hyper::Response::from_parts(res_parts, boxed_resp))
        }
    })
    .boxed_clone_sync()
}

/// Wraps an arbitrary custom `base_service` (e.g. a [`wrap_tonic_routes`]-adapted `tonic`
/// server) with Praeco's complete middleware pipeline: configured [`apply_layers`],
/// mandatory [`PathSanitizerLayer`], OpenTelemetry parent-context `TraceLayer`, and
/// [`ServerMetrics`] request/response telemetry.
///
/// # Errors
///
/// Returns [`SrvError::Other`] if the configuration is not finalized (e.g. missing
/// `compiled_allowed_pathes` or `static_name`) or if any middleware fails to initialize.
#[tracing::instrument(skip_all, fields(server = %server_config.name), err)]
pub fn build_service_stack_with_base(
    server_config: &Arc<ServerConfig>,
    base_service: BoxedCloneService,
) -> Result<BoxedCloneService, SrvError> {
    let layers = server_config
        .layers
        .build_middleware_layers(&server_config.name)
        .map_err(|e| SrvError::Other(e.to_string()))?;

    let compiled_allowed_pathes = server_config
        .compiled_allowed_pathes
        .as_ref()
        .ok_or_else(|| {
            SrvError::Other(format!(
                "Server '{}': Compiled paths missing (did you call ServerConfig::finalize?)",
                server_config.name
            ))
        })?;

    let static_name = server_config
        .static_name
        .ok_or_else(|| SrvError::Other(format!("{}: static_name missing", server_config.name)))?;

    let has_sanitizer = layers
        .iter()
        .any(|l| matches!(l, MiddlewareLayer::PathSanitizer));
    let applied = apply_layers(
        base_service,
        layers,
        static_name,
        compiled_allowed_pathes.clone(),
        server_config.port.unwrap_or(0),
        Arc::new(server_config.oid_mapping.clone()),
    )?;

    // Security: Enforce RFC 3986 path canonicalization and reject traversal/illegal encodings across all servers
    let sanitized = if has_sanitizer {
        applied
    } else {
        PathSanitizerLayer::new(static_name)
            .layer(applied)
            .boxed_clone_sync()
    };

    use tower_http::trace::{DefaultOnResponse, OnResponse, TraceLayer};

    let default_on_response = DefaultOnResponse::new().level(Level::INFO);
    let traced = tower::ServiceBuilder::new()
        .map_response(|res: hyper::Response<_>| {
            res.map(|b| http_body_util::BodyExt::map_err(b, SrvError::from).boxed())
        })
        .layer(
            TraceLayer::new_for_http()
                .make_span_with(move |request: &hyper::Request<_>| {
                    ServerMetrics::inc_total_requests(static_name);
                    let path = request.uri().path();
                    let method = request.method();
                    let otel_name = format!("{} {}", method, path);
                    let span = info_span!(
                        "request",
                        otel.name = otel_name.as_str(),
                        http.method = %method,
                        http.uri = %request.uri(),
                        traceparent = tracing::field::Empty
                    );
                    opentelemetry::global::get_text_map_propagator(|propagator| {
                        use opentelemetry::trace::TraceContextExt;
                        use tracing_opentelemetry::OpenTelemetrySpanExt;
                        let parent_cx = propagator.extract(
                            &opentelemetry_http::HeaderExtractor(request.headers()),
                        );
                        if parent_cx.span().span_context().is_valid() {
                            let _ = span.set_parent(parent_cx);
                        } else {
                            let _ = span.set_parent(opentelemetry::Context::new());
                        }
                    });
                    span
                })
                .on_response(
                    move |response: &hyper::Response<_>,
                          latency: Duration,
                          span: &tracing::Span| {
                        ServerMetrics::record_response(
                            static_name,
                            response.status().as_u16(),
                            latency.as_millis() as u64,
                        );
                        default_on_response.on_response(response, latency, span);
                    },
                ),
        )
        .service(sanitized);

    Ok(traced.boxed_clone_sync())
}

/// Builds the complete `tower::Service` stack for a single server instance.
///
/// This function takes a finalized [`ServerConfig`] and constructs a [`BoxedCloneService`]
/// by instantiating the built-in base service selected by `server_config.service`
/// (`Echo`, `Router`, `Admin`, `Idp`, or `StaticFiles`) and delegating to
/// [`build_service_stack_with_base`], which wraps it with all configured middleware layers
/// via [`apply_layers`], enforces RFC 3986 path canonicalization via [`PathSanitizerLayer`],
/// and attaches OpenTelemetry request tracing and [`ServerMetrics`] telemetry.
///
/// # Errors
///
/// Returns [`SrvError::Other`] if the configuration is not finalized (e.g. missing
/// `compiled_allowed_pathes` or `static_name`) or if any middleware/service fails to
/// initialize.
#[tracing::instrument(skip_all, fields(server = %server_config.name), err)]
pub fn build_service_stack(server_config: &Arc<ServerConfig>) -> Result<BoxedCloneService, SrvError> {
    let static_name = server_config
        .static_name
        .ok_or_else(|| SrvError::Other(format!("{}: static_name missing", server_config.name)))?;

    let base_service = match server_config.service {
        ServiceType::Echo => EchoService::new(static_name).boxed_clone_sync(),
        ServiceType::Router => RouterService::new(server_config.clone())
            .map_err(|e| SrvError::Other(e.to_string()))?
            .boxed_clone_sync(),
        ServiceType::Admin => AdminService::new(Some(server_config.clone())).boxed_clone_sync(),
        ServiceType::Idp => {
            let params = server_config
                .idp_params
                .as_ref()
                .ok_or_else(|| SrvError::Other(format!("{}: IdpParams missing", server_config.name)))?
                .clone();
            let idp_service = IdpService::new(params, static_name)
                .map_err(|e| SrvError::Other(e.to_string()))?;
            BoxCloneSyncService::new(idp_service)
        }
        ServiceType::StaticFiles => {
            let params = server_config
                .static_files_params
                .as_ref()
                .ok_or_else(|| {
                    SrvError::Other(format!("{}: StaticFilesParams missing", server_config.name))
                })?
                .clone();

            let abs_root = std::fs::canonicalize(&params.root)
                .unwrap_or_else(|_| std::path::PathBuf::from(&params.root));

            info!(
                "Static File Server '{}' serving from: {} (fallback_to_index: {})",
                server_config.name,
                abs_root.display(),
                params.fallback_to_index
            );

            let serve_dir = tower_http::services::ServeDir::new(&params.root);

            if params.fallback_to_index {
                let index_path = format!("{}/index.html", params.root.trim_end_matches('/'));
                let fallback =
                    serve_dir.fallback(tower_http::services::ServeFile::new(index_path));
                wrap_serve_dir(fallback)
            } else {
                wrap_serve_dir(serve_dir)
            }
        }
    };

    build_service_stack_with_base(server_config, base_service)
}

/// Applies the configured middleware layers to the base service.
///
/// Layers are applied in reverse order (outside-in execution flow), so the first
/// layer in `layers` becomes the outermost wrapper around `service`.
///
/// # Errors
///
/// Returns [`SrvError::Other`] if any layer has invalid parameters (such as zero
/// rate-limit rates or invalid CIDR blocks).
#[tracing::instrument(skip_all, fields(server = %server_name), err)]
pub fn apply_layers(
    service: BoxedCloneService,
    layers: Vec<MiddlewareLayer>,
    server_name: &'static str,
    compiled_allowed_pathes: Arc<CompiledAllowedPathes>,
    server_port: u16,
    oid_mapping: Arc<HashMap<String, UserRole>>,
) -> Result<BoxedCloneService, SrvError> {
    let mut svc = service;
    for layer in layers.into_iter().rev() {
        svc = match layer {
            MiddlewareLayer::TraceId => TraceIdLayer::new().layer(svc).boxed_clone_sync(),
            MiddlewareLayer::Timing => TimingLayer::new(server_name).layer(svc).boxed_clone_sync(),
            MiddlewareLayer::Counter => CountingLayer::new(server_name).layer(svc).boxed_clone_sync(),
            MiddlewareLayer::Logger => LoggerLayer::new(server_name).layer(svc).boxed_clone_sync(),
            MiddlewareLayer::PathSanitizer => PathSanitizerLayer::new(server_name)
                .layer(svc)
                .boxed_clone_sync(),
            MiddlewareLayer::Inspection => {
                InspectionLayer::new(compiled_allowed_pathes.clone(), server_name)
                    .layer(svc)
                    .boxed_clone_sync()
            }
            MiddlewareLayer::Delay(micros) => {
                DelayLayer::new(Duration::from_micros(micros), server_name)
                    .layer(svc)
                    .boxed_clone_sync()
            }
            MiddlewareLayer::JwtAuth(cfg) => {
                let layer = JwtAuthLayer::new(
                    cfg.jwt_public_keys.clone(),
                    server_name,
                    oid_mapping.clone(),
                    cfg.cookie_fallback.clone(),
                    cfg.redirect_on_failure.clone(),
                    cfg.expected_issuer.clone(),
                    cfg.expected_audience.clone(),
                )
                .map_err(|e| SrvError::Other(e.to_string()))?
                .with_revoke_on_paths(cfg.revoke_on_paths.clone());
                layer.layer(svc).boxed_clone_sync()
            }
            MiddlewareLayer::RateLimiter(RateLimiter::Simple(cfg)) => {
                if cfg.requests_per_second == 0 {
                    return Err(SrvError::Other(format!(
                        "{server_name}: RateLimiter requests_per_second must be > 0"
                    )));
                }
                let dur = Duration::from_secs_f32(1.0 / cfg.requests_per_second as f32);
                SimpleRateLimiterLayer::with_config(
                    dur,
                    cfg.key_by,
                    cfg.max_entries,
                    Duration::from_secs(cfg.ttl_seconds),
                    server_name,
                )
                .with_trust_forwarded_headers(cfg.trust_forwarded_headers)
                .layer(svc)
                .boxed_clone_sync()
            }
            MiddlewareLayer::RateLimiter(RateLimiter::TokenBucket(cfg)) => {
                if cfg.max_capacity == 0 || cfg.refill == 0 || cfg.duration_micros == 0 {
                    return Err(SrvError::Other(format!(
                        "{server_name}: TokenBucketRateLimiter parameters must all be > 0"
                    )));
                }
                TokenBucketRateLimiterLayer::with_config(
                    cfg.max_capacity,
                    cfg.refill,
                    Duration::from_micros(cfg.duration_micros),
                    cfg.key_by,
                    cfg.max_entries,
                    Duration::from_secs(cfg.ttl_seconds),
                    server_name,
                )
                .with_trust_forwarded_headers(cfg.trust_forwarded_headers)
                .layer(svc)
                .boxed_clone_sync()
            }
            MiddlewareLayer::ConcurrencyLimit(cfg) => {
                if cfg.max_concurrent_requests == 0 {
                    return Err(SrvError::Other(format!(
                        "{server_name}: ConcurrencyLimit max_concurrent_requests must be > 0"
                    )));
                }
                ConcurrencyLimitLayer::with_config(
                    cfg.max_concurrent_requests,
                    cfg.load_shed,
                    cfg.queue_timeout_ms.map(Duration::from_millis),
                    server_name,
                )
                .layer(svc)
                .boxed_clone_sync()
            }
            MiddlewareLayer::Compression => SrvCompressionLayer::new(server_name)
                .layer(svc)
                .boxed_clone_sync(),
            MiddlewareLayer::Decompression(max_bytes) => {
                SrvDecompressionLayer::new(server_name, max_bytes)
                    .layer(svc)
                    .boxed_clone_sync()
            }
            MiddlewareLayer::MaxPayload(max_bytes) => MaxPayloadLayer::new(max_bytes, server_name)
                .layer(svc)
                .boxed_clone_sync(),
            MiddlewareLayer::AltSvc => AltSvcLayer::new(server_port).layer(svc).boxed_clone_sync(),
            MiddlewareLayer::Cors(cfg) => {
                let origins: Vec<hyper::http::HeaderValue> = cfg
                    .allowed_origins
                    .iter()
                    .filter_map(|o| o.parse().ok())
                    .collect();
                let methods: Vec<hyper::http::Method> = cfg
                    .allowed_methods
                    .iter()
                    .filter_map(|m| m.parse().ok())
                    .collect();
                let headers: Vec<hyper::http::header::HeaderName> = cfg
                    .allowed_headers
                    .iter()
                    .filter_map(|h| h.parse().ok())
                    .collect();

                let is_any_origin = cfg.allowed_origins.iter().any(|o| o == "*");
                let is_any_method = cfg.allowed_methods.iter().any(|m| m == "*");
                let is_any_header = cfg.allowed_headers.iter().any(|h| h == "*");

                if cfg.allow_credentials && is_any_origin {
                    return Err(SrvError::Other(format!(
                        "{server_name}: CORS allow_credentials cannot be true when allowed_origins contains '*'"
                    )));
                }

                macro_rules! apply_cors {
                    ($cors:expr) => {
                        $cors
                            .allow_credentials(cfg.allow_credentials)
                            .layer(svc)
                            .boxed_clone_sync()
                    };
                }

                match (is_any_origin, is_any_method, is_any_header) {
                    (true, true, true) => apply_cors!(
                        tower_http::cors::CorsLayer::new()
                            .allow_origin(tower_http::cors::Any)
                            .allow_methods(tower_http::cors::Any)
                            .allow_headers(tower_http::cors::Any)
                    ),
                    (true, true, false) => apply_cors!(
                        tower_http::cors::CorsLayer::new()
                            .allow_origin(tower_http::cors::Any)
                            .allow_methods(tower_http::cors::Any)
                            .allow_headers(headers)
                    ),
                    (true, false, true) => apply_cors!(
                        tower_http::cors::CorsLayer::new()
                            .allow_origin(tower_http::cors::Any)
                            .allow_methods(methods)
                            .allow_headers(tower_http::cors::Any)
                    ),
                    (true, false, false) => apply_cors!(
                        tower_http::cors::CorsLayer::new()
                            .allow_origin(tower_http::cors::Any)
                            .allow_methods(methods)
                            .allow_headers(headers)
                    ),
                    (false, true, true) => apply_cors!(
                        tower_http::cors::CorsLayer::new()
                            .allow_origin(origins)
                            .allow_methods(tower_http::cors::Any)
                            .allow_headers(tower_http::cors::Any)
                    ),
                    (false, true, false) => apply_cors!(
                        tower_http::cors::CorsLayer::new()
                            .allow_origin(origins)
                            .allow_methods(tower_http::cors::Any)
                            .allow_headers(headers)
                    ),
                    (false, false, true) => apply_cors!(
                        tower_http::cors::CorsLayer::new()
                            .allow_origin(origins)
                            .allow_methods(methods)
                            .allow_headers(tower_http::cors::Any)
                    ),
                    (false, false, false) => apply_cors!(
                        tower_http::cors::CorsLayer::new()
                            .allow_origin(origins)
                            .allow_methods(methods)
                            .allow_headers(headers)
                    ),
                }
            }
            MiddlewareLayer::SecurityHeaders(cfg) => {
                SecurityHeadersLayer::new(cfg).layer(svc).boxed_clone_sync()
            }
            MiddlewareLayer::IpFilter(cfg) => {
                let layer = IpFilterLayer::from_cidr_strings(
                    &cfg.allow_cidrs,
                    &cfg.deny_cidrs,
                    cfg.trust_forwarded_headers,
                    server_name,
                )
                .map_err(|e| SrvError::Other(e.to_string()))?;
                layer.layer(svc).boxed_clone_sync()
            }
        };
    }
    Ok(svc)
}

/// Builds the [`RustlsServerConfig`] for a given [`ServerConfig`].
///
/// Loads the server certificate chain and private key, and—if client certificate
/// authentication (`ClientCert` or `OptionalClientCert`) is configured—also loads
/// the client CA root store and optional CRL.
///
/// # Errors
///
/// Returns [`SrvError::Other`] if required certificate paths are missing or invalid.
#[tracing::instrument(skip_all, fields(server = %config.name), err)]
pub fn build_rustls_config(config: &ServerConfig) -> Result<RustlsServerConfig, SrvError> {
    let server_certs = config.server_certs.as_ref().ok_or_else(|| {
        SrvError::Other(format!("{}: HTTPS enabled but no server_certs", config.name))
    })?;

    let client_certs = if config.authentication == AuthenticationMethod::ClientCert
        || config.authentication == AuthenticationMethod::OptionalClientCert
    {
        Some(config.client_certs.as_deref().ok_or_else(|| {
            SrvError::Other(format!("{}: mTLS enabled but no client_certs", config.name))
        })?)
    } else {
        None
    };

    let static_name = config
        .static_name
        .ok_or_else(|| SrvError::Other(format!("{}: static_name missing", config.name)))?;

    tls_config(static_name, server_certs, client_certs, config.authentication)
        .map_err(|e| SrvError::Other(e.to_string()))
}

/// Builds the outbound mTLS [`tokio_rustls::TlsConnector`] used by Praeco to
/// authenticate with the Relay Server's Control Plane.
///
/// # Errors
///
/// Returns [`SrvError::Other`] if the CA certificate, client certificate chain,
/// or client private key cannot be loaded.
#[tracing::instrument(skip_all, fields(sni = %tunnel.sni_domain), err)]
pub fn build_tunnel_tls_connector(
    tunnel: &TunnelConfig,
) -> Result<tokio_rustls::TlsConnector, SrvError> {
    use rustls::pki_types::pem::PemObject;

    let mut root_store = rustls::RootCertStore::empty();
    for cert in rustls::pki_types::CertificateDer::pem_file_iter(&tunnel.ca_cert_path)
        .map_err(|e| SrvError::Other(format!("Failed to open tunnel CA cert: {e}")))?
    {
        let cert =
            cert.map_err(|e| SrvError::Other(format!("Failed to parse tunnel CA cert: {e}")))?;
        root_store
            .add(cert)
            .map_err(|e| SrvError::Other(format!("Failed to add tunnel CA cert: {e}")))?;
    }

    let certs: Vec<rustls::pki_types::CertificateDer> =
        rustls::pki_types::CertificateDer::pem_file_iter(&tunnel.client_cert_path)
            .map_err(|e| SrvError::Other(format!("Failed to open tunnel client cert: {e}")))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| SrvError::Other(format!("Failed to parse tunnel client cert: {e}")))?;

    let key = rustls::pki_types::PrivateKeyDer::from_pem_file(&tunnel.client_key_path)
        .map_err(|e| SrvError::Other(format!("Failed to load tunnel client key: {e}")))?;

    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_client_auth_cert(certs, key)
        .map_err(|e| SrvError::Other(format!("Failed to build tunnel TLS client config: {e}")))?;

    Ok(tokio_rustls::TlsConnector::from(Arc::new(client_config)))
}

/// Resolves the client address of a freshly accepted tunneled (Yamux) stream.
///
/// * `use_proxy_protocol == false`: the peer is unknown and attributed to `0.0.0.0:0`.
/// * `use_proxy_protocol == true`: a valid HAProxy PROXY v2 header is **mandatory**. A
///   stream that does not start with one (wrong magic, truncated, I/O error or timeout)
///   yields `None` and must be dropped by the caller (fail-closed).
///
/// A PROXY v2 `LOCAL` command (no address) is accepted and attributed to `0.0.0.0:0`.
pub async fn resolve_tunnel_peer<S>(
    mut stream: S,
    use_proxy_protocol: bool,
    server_name: &str,
) -> Option<(SocketAddr, S)>
where
    S: AsyncRead + Unpin,
{
    let unspecified = SocketAddr::from(([0, 0, 0, 0], 0));
    if !use_proxy_protocol {
        return Some((unspecified, stream));
    }

    let pp_result = tokio::time::timeout(
        Duration::from_secs(5),
        common::proxy_protocol::read_proxy_v2(&mut stream),
    )
    .await;

    match pp_result {
        Ok(Ok(Some(addr))) => Some((addr, stream)),
        Ok(Ok(None)) => Some((unspecified, stream)),
        Ok(Err(common::proxy_protocol::ProxyProtocolError::InvalidMagic(_prefix))) => {
            warn!(
                "{}: Rejecting tunneled connection: proxy_protocol is enabled but stream did not start with a valid PROXY v2 header",
                server_name
            );
            None
        }
        Ok(Err(e)) => {
            warn!(
                "{}: Failed to read PROXY-Protocol header: {}",
                server_name, e
            );
            None
        }
        Err(_) => {
            warn!("{}: PROXY-Protocol read timed out", server_name);
            None
        }
    }
}

/// Serves an HTTP/1.1 or HTTP/2 connection over an arbitrary asynchronous stream
/// using Praeco's hardened connection settings and graceful shutdown handling.
pub async fn serve_http_connection<S>(
    stream: S,
    handler: ConnectionHandler,
    cancel_token: CancellationToken,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut builder = auto::Builder::new(TokioExecutor::new());
    // Timeout: drop clients that take too long to send HTTP/1 headers
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(10));
    // Timeout: detect dead HTTP/2 connections via keep-alive pings + hardened limits
    builder
        .http2()
        .timer(TokioTimer::new())
        .initial_stream_window_size(1024 * 1024)
        .max_concurrent_streams(128)
        .max_pending_accept_reset_streams(Some(20))
        .max_header_list_size(65536)
        .max_frame_size(16384)
        .keep_alive_interval(Some(Duration::from_secs(30)))
        .keep_alive_timeout(Duration::from_secs(10));

    let conn = builder.serve_connection(TokioIo::new(stream), handler);
    let mut conn = std::pin::pin!(conn);
    tokio::select! {
        res = conn.as_mut() => { let _ = res; },
        _ = cancel_token.cancelled() => {
            conn.as_mut().graceful_shutdown();
            let _ = conn.await;
        }
    }
}

/// Performs a bounded TLS handshake on `stream`, extracts client X.509 metadata
/// (OIDs, PEM, SAN), constructs a [`ConnectionHandler`] from the latest
/// [`ArcSwap`] service stack, and serves HTTP/1.1 or HTTP/2 traffic.
///
/// # Errors
///
/// Returns [`SrvError::Other`] if the TLS handshake fails or times out after 10 seconds.
pub async fn serve_tls_connection<S>(
    stream: S,
    peer_addr: SocketAddr,
    acceptor: &tokio_rustls::TlsAcceptor,
    dynamic_stack: &Arc<ArcSwap<BoxedCloneService>>,
    oid_mapping: &Arc<HashMap<String, UserRole>>,
    cancel_token: CancellationToken,
    server_name: &'static str,
) -> Result<(), SrvError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let tls_result = tokio::time::timeout(Duration::from_secs(10), acceptor.accept(stream)).await;

    match tls_result {
        Ok(Ok(tls_stream)) => {
            let (_, session) = tls_stream.get_ref();
            let client_meta = extract_client_metadata(session.peer_certificates());

            let svc = (**dynamic_stack.load()).clone();
            let handler = ConnectionHandler::new(
                svc,
                peer_addr,
                client_meta.oids,
                client_meta.pem,
                client_meta.san,
                oid_mapping.clone(),
            );

            serve_http_connection(tls_stream, handler, cancel_token).await;
            Ok(())
        }
        Ok(Err(e)) => {
            warn!("{}: TLS handshake failed: {}", server_name, e);
            Err(SrvError::Other(format!("TLS handshake failed: {e}")))
        }
        Err(_) => {
            trace!("{}: TLS handshake timed out for {}", server_name, peer_addr);
            Err(SrvError::Other("TLS handshake timed out".to_string()))
        }
    }
}

/// Runs the Praeco side of a Relay Server tunnel over an already-established
/// control-plane stream (e.g., an outbound mTLS stream to the Relay Control Plane),
/// using [`CONNECTION_DRAIN_TIMEOUT`](crate::runner::CONNECTION_DRAIN_TIMEOUT) for
/// graceful connection draining.
///
/// Performs:
/// 1. SNI registration (`REGISTER <sni_domain> [PROXY_V2]\n`).
/// 2. Yamux client multiplexer initialization with scaled receive windows.
/// 3. Inbound stream accept loop with [`ConnectionTracker`] enforcement,
///    fail-closed PROXY v2 resolution ([`resolve_tunnel_peer`]), end-to-end
///    TLS termination, and HTTP/1.1 + HTTP/2 serving ([`serve_tls_connection`]).
///
/// # Errors
///
/// Returns [`SrvError::Other`] if writing the registration command fails.
#[allow(clippy::too_many_arguments)]
pub async fn run_tunnel_over_stream<S>(
    control_stream: S,
    tunnel: &TunnelConfig,
    tls_config: Arc<RustlsServerConfig>,
    dynamic_stack: Arc<ArcSwap<BoxedCloneService>>,
    cancel_token: CancellationToken,
    server_name: &'static str,
    oid_mapping: Arc<HashMap<String, UserRole>>,
    connection_tracker: Arc<ConnectionTracker>,
) -> Result<(), SrvError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    run_tunnel_over_stream_with_drain_timeout(
        control_stream,
        tunnel,
        tls_config,
        dynamic_stack,
        cancel_token,
        server_name,
        oid_mapping,
        connection_tracker,
        crate::runner::CONNECTION_DRAIN_TIMEOUT,
    )
    .await
}

/// Like [`run_tunnel_over_stream`], but uses a caller-supplied `drain_timeout` when
/// waiting for in-flight tunneled connections to finish on shutdown.
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip_all, fields(server = %server_name, sni = %tunnel.sni_domain), err)]
pub async fn run_tunnel_over_stream_with_drain_timeout<S>(
    mut control_stream: S,
    tunnel: &TunnelConfig,
    tls_config: Arc<RustlsServerConfig>,
    dynamic_stack: Arc<ArcSwap<BoxedCloneService>>,
    cancel_token: CancellationToken,
    server_name: &'static str,
    oid_mapping: Arc<HashMap<String, UserRole>>,
    connection_tracker: Arc<ConnectionTracker>,
    drain_timeout: Duration,
) -> Result<(), SrvError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let acceptor = tokio_rustls::TlsAcceptor::from(tls_config);

    // 1. Register SNI with capability negotiation (Phase 4)
    let reg_cmd = if tunnel.proxy_protocol {
        format!("REGISTER {} PROXY_V2\n", tunnel.sni_domain)
    } else {
        format!("REGISTER {}\n", tunnel.sni_domain)
    };
    control_stream
        .write_all(reg_cmd.as_bytes())
        .await
        .map_err(|e| SrvError::Other(format!("Failed to write REGISTER command: {e}")))?;
    control_stream
        .flush()
        .await
        .map_err(|e| SrvError::Other(format!("Failed to flush REGISTER command: {e}")))?;

    // 2. Setup Yamux (S-27: configurable concurrent streams + scaled receive window)
    let max_streams = tunnel.max_yamux_streams.unwrap_or(4096);
    let mut cfg = yamux::Config::default();
    cfg.set_max_num_streams(max_streams);
    let min_window = max_streams * 256 * 1024;
    cfg.set_max_connection_receive_window(Some(std::cmp::max(min_window, 1024 * 1024 * 1024)));
    let mut connection = yamux::Connection::new(control_stream.compat(), cfg, yamux::Mode::Client);

    info!(
        "{}: Tunnel connected successfully to {}",
        server_name, tunnel.target_url
    );

    let use_proxy_protocol = tunnel.proxy_protocol;
    let sni_domain = tunnel.sni_domain.clone();
    let stream_token = cancel_token.child_token();
    let mut conn_tasks: JoinSet<()> = JoinSet::new();

    // 3. Accept Streams loop
    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => break,
            Some(res) = conn_tasks.join_next(), if !conn_tasks.is_empty() => {
                if let Err(e) = res {
                    if e.is_panic() {
                        error!("{}: Tunneled connection task panicked: {:?}", server_name, e);
                    } else if !e.is_cancelled() {
                        error!("{}: Tunneled connection task failed: {:?}", server_name, e);
                    }
                }
            }
            inbound = std::future::poll_fn(|cx| connection.poll_next_inbound(cx)) => {
                match inbound {
                    Some(Ok(yamux_stream)) => {
                        trace!("{}: Tunneled connection accepted", server_name);
                        let connection_guard = match connection_tracker.acquire(None) {
                            Ok(guard) => guard,
                            Err(AcquireError::GlobalLimitReached { current, max }) => {
                                warn!("{}: Tunneled connection rejected: global connection limit reached ({} >= {})", server_name, current, max);
                                continue;
                            }
                            Err(AcquireError::IpLimitReached { ip, current, max }) => {
                                warn!("{}: Tunneled connection rejected: IP connection limit reached for {} ({} >= {})", server_name, ip, current, max);
                                continue;
                            }
                        };
                        let acceptor = acceptor.clone();
                        let dynamic_stack = dynamic_stack.clone();
                        let oid_mapping = oid_mapping.clone();
                        let conn_token = stream_token.clone();
                        let span_sni = sni_domain.clone();

                        conn_tasks.spawn(async move {
                            let mut connection_guard = connection_guard;
                            let compat_stream = yamux_stream.compat();

                            // Fail-closed: with `proxy_protocol = true` a stream without a
                            // valid PROXY v2 header is dropped instead of being attributed
                            // to the unspecified address (which would bypass per-IP limits).
                            let Some((peer_addr, stream)) = resolve_tunnel_peer(
                                compat_stream,
                                use_proxy_protocol,
                                server_name,
                            )
                            .await
                            else {
                                return;
                            };

                            // Enforce per-IP concurrency limits now that real client IP is resolved
                            if !peer_addr.ip().is_unspecified()
                                && let Err(e) = connection_guard.bind_ip(peer_addr.ip())
                            {
                                warn!("{}: Tunneled connection rejected: {}", server_name, e);
                                return;
                            }

                            let _ = serve_tls_connection(
                                stream,
                                peer_addr,
                                &acceptor,
                                &dynamic_stack,
                                &oid_mapping,
                                conn_token,
                                server_name,
                            )
                            .await;
                        }.instrument(tracing::info_span!("tunneled_connection", server = %server_name, sni = %span_sni)));
                    }
                    Some(Err(e)) => {
                        error!("{}: Tunnel error: {:?}", server_name, e);
                        break;
                    }
                    None => {
                        info!("{}: Tunnel closed by Relay", server_name);
                        break;
                    }
                }
            }
        }
    }

    if cancel_token.is_cancelled() {
        // Keep polling `connection` during drain because active Yamux streams need the
        // multiplexer driver to exchange frames and complete HTTP/2 GOAWAY shutdowns.
        if !conn_tasks.is_empty() {
            let drain = async {
                while !conn_tasks.is_empty() {
                    tokio::select! {
                        Some(res) = conn_tasks.join_next() => {
                            if let Err(e) = res {
                                if e.is_panic() {
                                    error!("{}: Tunneled connection task panicked during drain: {:?}", server_name, e);
                                } else if !e.is_cancelled() {
                                    error!("{}: Tunneled connection task failed during drain: {:?}", server_name, e);
                                }
                            }
                        }
                        inbound = std::future::poll_fn(|cx| connection.poll_next_inbound(cx)) => {
                            match inbound {
                                Some(Ok(extra_stream)) => drop(extra_stream),
                                Some(Err(_)) | None => break,
                            }
                        }
                    }
                }
            };
            if tokio::time::timeout(drain_timeout, drain).await.is_err() {
                warn!(
                    "{}: Tunnel connection drain timed out after {:?}; aborting {} remaining task(s)",
                    server_name,
                    drain_timeout,
                    conn_tasks.len()
                );
                conn_tasks.abort_all();
                while let Some(res) = conn_tasks.join_next().await {
                    if let Err(e) = res && e.is_panic() {
                        error!("{}: Tunneled connection task panicked during abort: {:?}", server_name, e);
                    }
                }
            }
        }
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            std::future::poll_fn(|cx| connection.poll_close(cx)),
        )
        .await;
    } else {
        // Underlying Yamux connection closed or errored: cancel active stream handlers and reap.
        stream_token.cancel();
        let drain = async {
            while let Some(res) = conn_tasks.join_next().await {
                if let Err(e) = res && e.is_panic() {
                    error!("{}: Tunneled connection task panicked: {:?}", server_name, e);
                }
            }
        };
        if tokio::time::timeout(Duration::from_secs(2), drain).await.is_err() {
            conn_tasks.abort_all();
            while let Some(res) = conn_tasks.join_next().await {
                if let Err(e) = res && e.is_panic() {
                    error!("{}: Tunneled connection task panicked during abort: {:?}", server_name, e);
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tunnel_peer_tests {
    use super::resolve_tunnel_peer;
    use std::io::Cursor;
    use std::net::SocketAddr;

    #[tokio::test]
    async fn test_without_proxy_protocol_peer_is_unspecified() {
        let (addr, _stream) = resolve_tunnel_peer(Cursor::new(vec![0x16, 0x03, 0x01]), false, "t")
            .await
            .expect("stream without proxy_protocol must be accepted");
        assert!(addr.ip().is_unspecified());
    }

    #[tokio::test]
    async fn test_valid_proxy_v2_ipv4_header_yields_real_client_addr() {
        let src: SocketAddr = "203.0.113.7:54321".parse().unwrap();
        let dst: SocketAddr = "198.51.100.1:443".parse().unwrap();
        let mut bytes = common::proxy_protocol::encode_proxy_v2(src, dst);
        bytes.extend_from_slice(b"\x16\x03\x01tls-client-hello");

        let (addr, _stream) = resolve_tunnel_peer(Cursor::new(bytes), true, "t")
            .await
            .expect("valid PROXY v2 header must be accepted");
        assert_eq!(addr, src);
    }

    #[tokio::test]
    async fn test_valid_proxy_v2_ipv6_header_yields_real_client_addr() {
        let src: SocketAddr = "[2001:db8::1]:40000".parse().unwrap();
        let dst: SocketAddr = "[2001:db8::2]:443".parse().unwrap();
        let bytes = common::proxy_protocol::encode_proxy_v2(src, dst);

        let (addr, _stream) = resolve_tunnel_peer(Cursor::new(bytes), true, "t")
            .await
            .expect("valid IPv6 PROXY v2 header must be accepted");
        assert_eq!(addr, src);
    }

    /// [F-04] A raw TLS ClientHello (no PROXY header) must be rejected fail-closed
    /// when `proxy_protocol = true`, never attributed to `0.0.0.0:0`.
    #[tokio::test]
    async fn test_missing_proxy_header_is_rejected_fail_closed() {
        let tls_client_hello = vec![
            0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03, 0xde, 0xad, 0xbe,
            0xef, 0x00, 0x11, 0x22, 0x33, 0x44,
        ];
        assert!(
            resolve_tunnel_peer(Cursor::new(tls_client_hello), true, "t")
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_truncated_proxy_header_is_rejected() {
        // Fewer than the 16 bytes of a PROXY v2 fixed header, then EOF.
        assert!(
            resolve_tunnel_peer(Cursor::new(vec![0x0d, 0x0a, 0x0d, 0x0a]), true, "t")
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn test_empty_stream_is_rejected_when_proxy_protocol_required() {
        assert!(
            resolve_tunnel_peer(Cursor::new(Vec::<u8>::new()), true, "t")
                .await
                .is_none()
        );
    }
}
