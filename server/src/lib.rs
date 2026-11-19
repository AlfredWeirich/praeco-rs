//! # Server Library Crate Root
//!
//! This module defines the **core types** and the [`ConnectionHandler`] that
//! together form the backbone of the reverse-proxy server.
//!
//! ## Contents
//!
//! | Item | Purpose |
//! |------|---------|
//! | [`SrvBody`] / [`ServiceRespBody`] | Unified, boxed HTTP body type used throughout the service stack. |
//! | [`BoxedCloneService`] | A type-erased, cloneable Tower service – the fully assembled middleware pipeline. |
//! | [`H3Body`] | Adapter that bridges an HTTP/3 (QUIC) receive stream into a [`http_body::Body`]. |
//! | [`ConnectionHandler`] | Per-connection glue: injects client metadata (IP, roles) and security headers. |
//!
//! ## Module re-exports
//!
//! The crate publicly exposes its core building blocks:
//! - [`configuration`] – TOML-driven server configuration and route parsing.
//! - [`connection_tracker`] – Global and per-IP connection limits.
//! - [`error`] – The unified [`SrvError`] error type.
//! - [`middleware`] – Tower layers (logging, Alt-Svc, JWT, routing, …).
//! - [`runner`] – Transport listeners (HTTP/1.1, H2, H3/QUIC), health checks, and tunnel client.
//! - [`stack`] – Service stack assembly, TLS configuration builders, and stream runners.
//! - [`tls_conf`] – TLS acceptor construction for `rustls`.
//! - [`web`] *(feature `web`)* – Composable HTTP router, typed extractors, and WAF rule sync.

use bytes::Buf;
use core::net::SocketAddr;
use futures::Stream;
use http_body_util::{BodyExt, combinators::BoxBody};
use hyper::{
    Request, Response,
    body::{Bytes, Incoming},
};
// use pin_project::pin_project;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tower::Service;

// ── Public Modules ───────────────────────────────────────────────────────────

/// Server configuration, route parsing, and role definitions.
pub mod configuration;
/// Connection tracking and limits (global and per-IP).
pub mod connection_tracker;
/// Unified error type ([`SrvError`]) used across all layers.
pub mod error;
/// Tower middleware layers (logging, Alt-Svc header injection, routing, …).
pub mod middleware;
/// Transport listeners, active upstream health checks, and outbound relay tunnel runner.
pub mod runner;
/// Service stack assembly, TLS configuration builders, and stream runners.
pub mod stack;
/// TLS acceptor and `rustls` configuration helpers.
pub mod tls_conf;
/// Composable HTTP endpoint router and typed extractors (enabled via the `web` feature).
#[cfg(feature = "web")]
pub mod web;
pub use common::Claims;
pub use error::SrvError;
pub use runner::{
    CONNECTION_DRAIN_TIMEOUT, DualStackHandles, ServerReloadUpdate, run_dual_stack, run_servers,
    run_tunnel, run_tunnel_with_timeout, run_tunnel_with_timeout_and_base_oid, spawn_dual_stack,
    spawn_router_health_checks, spawn_router_health_checks_in, start_single_server,
    start_single_server_reloadable, start_single_server_with_socket_signal,
};
pub use stack::{
    apply_layers, build_rustls_config, build_service_stack, build_service_stack_with_base,
    build_tunnel_tls_connector, resolve_tunnel_peer, run_tunnel_over_stream,
    run_tunnel_over_stream_with_drain_timeout,
    run_tunnel_over_stream_with_drain_timeout_and_base_oid, serve_http_connection,
    serve_tls_connection, serve_tls_connection_with_base_oid, wrap_serve_dir, wrap_tonic_routes,
};

// ── Type Aliases ─────────────────────────────────────────────────────────────

/// The canonical body type flowing through the Tower service stack.
///
/// A boxed, dynamically-dispatched HTTP body whose data chunks are [`Bytes`]
/// and whose error type is [`SrvError`]. Using a single body type across all
/// middleware avoids generic-parameter explosion.
pub type SrvBody = BoxBody<Bytes, SrvError>;

/// Alias for response bodies – identical to [`SrvBody`] for symmetry.
///
/// Having a separate alias makes it easy to diverge later (e.g. if response
/// bodies need different constraints) without touching every signature.
pub type ServiceRespBody = SrvBody;

pub trait CloneSyncService<R, U, E>: Send + Sync {
    fn clone_box(&self) -> Box<dyn CloneSyncService<R, U, E>>;
    fn poll_ready_box(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), E>>;
    fn call_box(&mut self, request: R) -> Pin<Box<dyn Future<Output = Result<U, E>> + Send>>;
}

impl<R, U, E, S> CloneSyncService<R, U, E> for S
where
    S: Service<R, Response = U, Error = E> + Clone + Send + Sync + 'static,
    S::Future: Send + 'static,
{
    fn clone_box(&self) -> Box<dyn CloneSyncService<R, U, E>> {
        Box::new(self.clone())
    }

    fn poll_ready_box(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), E>> {
        self.poll_ready(cx)
    }

    fn call_box(&mut self, request: R) -> Pin<Box<dyn Future<Output = Result<U, E>> + Send>> {
        Box::pin(self.call(request))
    }
}

pub struct BoxCloneSyncService<T, U, E>(Box<dyn CloneSyncService<T, U, E>>);

impl<T, U, E> BoxCloneSyncService<T, U, E> {
    pub fn new<S>(inner: S) -> Self
    where
        S: Service<T, Response = U, Error = E> + Clone + Send + Sync + 'static,
        S::Future: Send + 'static,
    {
        BoxCloneSyncService(Box::new(inner))
    }
}

impl<T, U, E> Clone for BoxCloneSyncService<T, U, E> {
    fn clone(&self) -> Self {
        BoxCloneSyncService(self.0.clone_box())
    }
}

impl<T, U, E> Service<T> for BoxCloneSyncService<T, U, E> {
    type Response = U;
    type Error = E;
    type Future = Pin<Box<dyn Future<Output = Result<U, E>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), E>> {
        self.0.poll_ready_box(cx)
    }

    fn call(&mut self, request: T) -> Self::Future {
        self.0.call_box(request)
    }
}

pub trait BoxCloneSyncServiceExt<T>: Service<T> {
    fn boxed_clone_sync(self) -> BoxCloneSyncService<T, Self::Response, Self::Error>
    where
        Self: Sized + Clone + Send + Sync + 'static,
        Self::Future: Send + 'static;
}

impl<R, S: Service<R>> BoxCloneSyncServiceExt<R> for S {
    fn boxed_clone_sync(self) -> BoxCloneSyncService<R, Self::Response, Self::Error>
    where
        Self: Sized + Clone + Send + Sync + 'static,
        Self::Future: Send + 'static,
    {
        BoxCloneSyncService::new(self)
    }
}

/// A fully assembled, type-erased, **cloneable** Tower service.
///
/// This is the end product of stacking all middleware layers. It accepts a
/// `Request<SrvBody>` and produces a `Response<ServiceRespBody>`. Because it
/// is clone-able, it can be shared across connections via cheap `Arc`-based
/// cloning internally.
pub type BoxedCloneService = BoxCloneSyncService<Request<SrvBody>, Response<ServiceRespBody>, SrvError>;

// ── HTTP/3 Body Adapter ──────────────────────────────────────────────────────

/// The concrete receive-stream type from the `h3` + `h3_quinn` stack.
///
/// We use `RecvStream` (not `BidiStream`) because the request/response
/// halves are split: the server reads from `RecvStream` and writes to a
/// separate `SendStream`.
type H3RecvStream = h3::server::RequestStream<h3_quinn::RecvStream, bytes::Bytes>;

/// Adapter that presents an HTTP/3 QUIC receive stream as an [`http_body::Body`].
///
/// Hyper's service stack expects bodies to implement [`http_body::Body`], but
/// the `h3` crate exposes data through an async [`Stream`]. `H3Body` bridges
/// the two by wrapping the stream in a pinned, heap-allocated box and
/// delegating [`Body::poll_frame`] to [`Stream::poll_next`].
///
/// # Construction
///
/// Created via [`H3Body::new`], which takes ownership of an [`H3RecvStream`]
/// and internally builds a [`futures::stream::unfold`] that repeatedly calls
/// [`recv_data()`](h3::server::RequestStream::recv_data) until EOF or error.
pub struct H3Body {
    /// The underlying async stream of body frames, type-erased and pinned.
    ///
    /// Each item is a `Result<Frame<Bytes>, SrvError>`. The stream yields
    /// `None` on EOF and `Some(Err(…))` on transport errors.
    inner: Pin<Box<dyn Stream<Item = Result<http_body::Frame<Bytes>, SrvError>> + Send + Sync>>,
}

/// Default per-frame idle timeout enforced while reading an in-flight HTTP request body.
pub(crate) const DEFAULT_BODY_FRAME_TIMEOUT: Duration = Duration::from_secs(30);

/// Wraps an inbound HTTP/1.1 or HTTP/2 request body to abort stalled/Slowloris uploads
/// if no body frame arrives within [`Self::timeout`] while the body is actively polled.
///
/// Connections sitting idle between keep-alive requests are unaffected because the timer
/// only runs while awaiting a pending frame from the request body stream.
#[pin_project::pin_project]
pub(crate) struct IdleTimeoutBody<B> {
    #[pin]
    inner: B,
    #[pin]
    sleep: tokio::time::Sleep,
    deadline_armed: bool,
    timed_out: bool,
    timeout: Duration,
}

impl<B> IdleTimeoutBody<B> {
    pub(crate) fn new(inner: B, timeout: Duration) -> Self {
        Self {
            inner,
            sleep: tokio::time::sleep(timeout),
            deadline_armed: false,
            timed_out: false,
            timeout,
        }
    }
}

impl<B> http_body::Body for IdleTimeoutBody<B>
where
    B: http_body::Body<Data = Bytes>,
    B::Error: Into<SrvError>,
{
    type Data = Bytes;
    type Error = SrvError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let mut this = self.project();
        if *this.timed_out {
            return Poll::Ready(None);
        }

        match this.inner.poll_frame(cx) {
            Poll::Ready(res) => {
                *this.deadline_armed = false;
                Poll::Ready(res.map(|r| r.map_err(Into::into)))
            }
            Poll::Pending => {
                if !*this.deadline_armed {
                    this.sleep
                        .as_mut()
                        .reset(tokio::time::Instant::now() + *this.timeout);
                    *this.deadline_armed = true;
                }
                match this.sleep.poll(cx) {
                    Poll::Ready(()) => {
                        *this.timed_out = true;
                        Poll::Ready(Some(Err(SrvError::ClientAborted(format!(
                            "Request body idle timeout after {:?}",
                            *this.timeout
                        )))))
                    }
                    Poll::Pending => Poll::Pending,
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

impl H3Body {
    /// Creates a new `H3Body` by converting an HTTP/3 receive stream into
    /// an async [`Stream`] of body frames with a 30-second per-frame idle timeout.
    pub fn new(stream: H3RecvStream) -> Self {
        Self::with_timeout(stream, DEFAULT_BODY_FRAME_TIMEOUT)
    }

    /// Creates a new `H3Body` with an explicit per-frame receive idle timeout.
    pub fn with_timeout(stream: H3RecvStream, timeout: Duration) -> Self {
        let s = futures::stream::unfold((stream, false), move |(mut s, finished)| async move {
            if finished {
                return None;
            }
            match tokio::time::timeout(timeout, s.recv_data()).await {
                Ok(Ok(Some(mut bytes))) => {
                    let frame = http_body::Frame::data(bytes.copy_to_bytes(bytes.remaining()));
                    Some((Ok(frame), (s, false)))
                }
                Ok(Ok(None)) => None, // EOF
                Ok(Err(e)) => Some((Err(SrvError::from(e.to_string())), (s, true))),
                Err(_) => Some((
                    Err(SrvError::ClientAborted(format!(
                        "HTTP/3 request body idle timeout after {:?}",
                        timeout
                    ))),
                    (s, true),
                )),
            }
        });

        Self { inner: Box::pin(s) }
    }
}

/// [`http_body::Body`] implementation for [`H3Body`].
///
/// Delegates frame polling directly to the inner async stream. Because the
/// stream already yields `Result<Frame<Bytes>, SrvError>`, no additional
/// transformation is needed — this is a thin forwarding impl.
impl http_body::Body for H3Body {
    type Data = Bytes;
    type Error = SrvError;

    /// Polls the underlying QUIC receive stream for the next body frame.
    ///
    /// Returns:
    /// - `Poll::Ready(Some(Ok(frame)))` – a data frame is available.
    /// - `Poll::Ready(Some(Err(e)))` – a transport error occurred.
    /// - `Poll::Ready(None)` – the body has been fully received (EOF).
    /// - `Poll::Pending` – no data available yet; the waker is registered.
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        self.inner.as_mut().poll_next(cx)
    }
}

// Optimization 5
// ── Pre-Computed Security Headers ────────────────────────────────────────────
//
// Using `HeaderValue::from_static` avoids ANY allocations or atomic operations
// (like Arc cloning) on the hot path. It is entirely zero-cost.

use hyper::header::HeaderValue;

const CACHE_CTL_VALUE: HeaderValue = HeaderValue::from_static("no-store");

// ── Connection Handler ───────────────────────────────────────────────────────

use crate::configuration::UserRole;
use std::sync::Arc;

/// Per-connection bridge between the network transport and the application's
/// Tower service stack.
///
/// A `ConnectionHandler` is created once per accepted TLS connection and is
/// then cloned for every HTTP request that arrives on that connection (HTTP/2
/// multiplexes many requests over a single connection).
///
/// # Responsibilities
///
/// 1. **Client metadata injection** – Stores the peer's [`SocketAddr`] and
///    resolved [`UserRole`]s, and attaches them as request extensions so
///    downstream middleware (e.g. the router's RBAC check) can access them.
/// 2. **Security header enforcement** – Appends a set of hardened HTTP
///    response headers (HSTS, CSP, etc.) to **every** response, regardless
///    of what the upstream backend or middleware returns.
/// 3. **Body type bridging** – Converts Hyper's native [`Incoming`] body
///    into the unified [`SrvBody`] type expected by the service stack.
///
/// # Cloning
///
/// `ConnectionHandler` is cheaply cloneable: the inner service uses
/// [`BoxCloneService`] (internally `Arc`-based) and the role list is
/// wrapped in an [`Arc`].
#[derive(Clone, Debug)]
pub struct PemCertExtension(pub String);

#[derive(Clone, Debug)]
pub struct SanCertExtension(pub String);

/// Raw OID suffix strings extracted from the client certificate.
/// Preserved so that the IdP service can embed them in issued JWTs.
#[derive(Clone, Debug)]
pub struct OidCertExtension(pub Vec<String>);

#[derive(Clone)]
enum ServiceSource {
    Static(BoxedCloneService),
    Dynamic(Arc<arc_swap::ArcSwap<BoxedCloneService>>),
}

#[derive(Clone)]
struct DynamicOidMapping {
    live: Arc<arc_swap::ArcSwap<std::collections::HashMap<String, UserRole>>>,
    cached_map: Arc<std::collections::HashMap<String, UserRole>>,
}

fn resolve_roles_from_oids(
    oids: &[String],
    oid_mapping: &std::collections::HashMap<String, UserRole>,
) -> crate::configuration::RoleVec<6> {
    let roles: crate::configuration::RoleVec<6> = oids
        .iter()
        .map(|oid| {
            oid_mapping
                .get(oid)
                .cloned()
                .unwrap_or_else(UserRole::guest)
        })
        .filter(|role| *role != UserRole::guest())
        .collect();

    if roles.is_empty() {
        let mut r = crate::configuration::RoleVec::new();
        r.push(UserRole::guest());
        r
    } else {
        roles
    }
}

pub struct ConnectionHandler {
    /// The fully assembled middleware + routing pipeline (either a fixed
    /// [`BoxedCloneService`] or a live [`arc_swap::ArcSwap`] loaded per request).
    service_source: ServiceSource,

    /// The remote peer's socket address (IP + port), used to populate
    /// `X-Real-IP` and for logging/diagnostics.
    client_addr: SocketAddr,

    /// Pre-computed user roles derived from the client certificate's OIDs.
    ///
    /// Wrapped in [`Arc`] so that cloning the handler for each request on
    /// the same connection is a cheap pointer bump instead of a `Vec` copy.
    /// Defaults to `[UserRole::Guest]` when no recognized OID is found.
    client_roles: Arc<crate::configuration::RoleVec<6>>,

    /// Optional live `oid_mapping` reference used to detect `SIGHUP` role-table
    /// updates via a single `Arc::ptr_eq` check per request.
    dynamic_oid_mapping: Option<DynamicOidMapping>,

    /// The client's full certificate in PEM format, URL-encoded (shared across clones).
    client_cert_pem: Option<Arc<str>>,

    /// The client's Subject Alternative Name (SAN, shared across clones).
    client_cert_san: Option<Arc<str>>,

    /// The raw OID suffixes extracted from the client certificate.
    client_oids: Arc<Vec<String>>,
}

impl ConnectionHandler {
    /// Creates a new `ConnectionHandler`, performing the **OID → Role mapping**
    /// once at connection establishment time.
    ///
    /// The mapping is intentionally done here — not per-request — because it
    /// involves a global config lookup and allocation. Doing it once and
    /// sharing the result via [`Arc`] avoids repeated work for every request
    /// on the same connection.
    ///
    /// # Arguments
    ///
    /// * `service` – The boxed, cloneable Tower service stack.
    /// * `addr`    – The remote peer's socket address.
    /// * `oids`    – OID strings extracted from the client's X.509 certificate.
    ///
    /// Each OID is mapped to a [`UserRole`] via the global config.
    ///
    /// # Role resolution logic
    ///
    /// 1. Map every OID to a [`UserRole`] using [`Config::map_oid_to_role`].
    /// 2. Filter out [`UserRole::Guest`] (the default/fallback role).
    /// 3. If no meaningful roles remain, fall back to `[UserRole::Guest]`.
    pub fn new(
        service: BoxedCloneService,
        addr: SocketAddr,
        oids: Vec<String>,
        client_cert_pem: Option<String>,
        client_cert_san: Option<String>,
        oid_mapping: Arc<std::collections::HashMap<String, UserRole>>,
    ) -> Self {
        let final_roles = resolve_roles_from_oids(&oids, &oid_mapping);

        Self {
            service_source: ServiceSource::Static(service),
            client_addr: addr,
            client_roles: Arc::new(final_roles),
            dynamic_oid_mapping: None,
            client_cert_pem: client_cert_pem.map(Arc::<str>::from),
            client_cert_san: client_cert_san.map(Arc::<str>::from),
            client_oids: Arc::new(oids),
        }
    }

    /// Creates a `ConnectionHandler` backed by a live [`arc_swap::ArcSwap`] service
    /// stack so long-lived HTTP/1.1, HTTP/2, and tunneled connections automatically
    /// pick up hot-reloaded middleware and routing pipelines on every request.
    pub fn with_dynamic_stack(
        dynamic_stack: Arc<arc_swap::ArcSwap<BoxedCloneService>>,
        addr: SocketAddr,
        oids: Vec<String>,
        client_cert_pem: Option<String>,
        client_cert_san: Option<String>,
        oid_mapping: Arc<std::collections::HashMap<String, UserRole>>,
    ) -> Self {
        let final_roles = resolve_roles_from_oids(&oids, &oid_mapping);

        Self {
            service_source: ServiceSource::Dynamic(dynamic_stack),
            client_addr: addr,
            client_roles: Arc::new(final_roles),
            dynamic_oid_mapping: None,
            client_cert_pem: client_cert_pem.map(Arc::<str>::from),
            client_cert_san: client_cert_san.map(Arc::<str>::from),
            client_oids: Arc::new(oids),
        }
    }

    /// Like [`ConnectionHandler::with_dynamic_stack`], but also tracks a live
    /// [`arc_swap::ArcSwap`] OID-to-role map.
    ///
    /// On the hot path, each request performs a single `Arc::ptr_eq` check against
    /// the connection's cached map and only recomputes roles if a `SIGHUP` reload
    /// replaced the OID mapping table.
    pub fn with_dynamic_stack_and_oids(
        dynamic_stack: Arc<arc_swap::ArcSwap<BoxedCloneService>>,
        addr: SocketAddr,
        oids: Vec<String>,
        client_cert_pem: Option<String>,
        client_cert_san: Option<String>,
        oid_mapping: Arc<arc_swap::ArcSwap<std::collections::HashMap<String, UserRole>>>,
    ) -> Self {
        let cached_map = oid_mapping.load_full();
        let final_roles = resolve_roles_from_oids(&oids, &cached_map);

        Self {
            service_source: ServiceSource::Dynamic(dynamic_stack),
            client_addr: addr,
            client_roles: Arc::new(final_roles),
            dynamic_oid_mapping: Some(DynamicOidMapping {
                live: oid_mapping,
                cached_map,
            }),
            client_cert_pem: client_cert_pem.map(Arc::<str>::from),
            client_cert_san: client_cert_san.map(Arc::<str>::from),
            client_oids: Arc::new(oids),
        }
    }

    /// Creates a `ConnectionHandler` that **reuses** an already-resolved
    /// role list.
    ///
    /// This is the preferred constructor when handling a second (or Nth)
    /// request on the same connection, because the roles were already
    /// computed during the first [`ConnectionHandler::new`] call.
    ///
    /// # Arguments
    ///
    /// * `service` – The boxed, cloneable Tower service stack.
    /// * `addr`    – The remote peer's socket address.
    /// * `roles`   – A shared, pre-computed role vector (cheap `Arc` clone).
    pub fn new_shared(
        service: BoxedCloneService,
        addr: SocketAddr,
        roles: Arc<crate::configuration::RoleVec<6>>, // Pass roles, not OIDs
        client_cert_pem: Option<String>,
        client_cert_san: Option<String>,
        client_oids: Arc<Vec<String>>,
    ) -> Self {
        Self {
            service_source: ServiceSource::Static(service),
            client_addr: addr,
            client_roles: roles,
            dynamic_oid_mapping: None,
            client_cert_pem: client_cert_pem.map(Arc::<str>::from),
            client_cert_san: client_cert_san.map(Arc::<str>::from),
            client_oids,
        }
    }

    /// Like [`ConnectionHandler::new_shared`], but loads the current service stack
    /// from `dynamic_stack` on execution.
    pub fn with_dynamic_stack_shared(
        dynamic_stack: Arc<arc_swap::ArcSwap<BoxedCloneService>>,
        addr: SocketAddr,
        roles: Arc<crate::configuration::RoleVec<6>>,
        client_cert_pem: Option<String>,
        client_cert_san: Option<String>,
        client_oids: Arc<Vec<String>>,
    ) -> Self {
        Self::with_dynamic_stack_shared_arc(
            dynamic_stack,
            addr,
            roles,
            client_cert_pem.map(Arc::<str>::from),
            client_cert_san.map(Arc::<str>::from),
            client_oids,
        )
    }

    /// Internal zero-allocation variant sharing pre-allocated `Arc<str>` cert metadata
    /// across multiplexed HTTP/3 streams on the same connection.
    pub(crate) fn with_dynamic_stack_shared_arc(
        dynamic_stack: Arc<arc_swap::ArcSwap<BoxedCloneService>>,
        addr: SocketAddr,
        roles: Arc<crate::configuration::RoleVec<6>>,
        client_cert_pem: Option<Arc<str>>,
        client_cert_san: Option<Arc<str>>,
        client_oids: Arc<Vec<String>>,
    ) -> Self {
        Self {
            service_source: ServiceSource::Dynamic(dynamic_stack),
            client_addr: addr,
            client_roles: roles,
            dynamic_oid_mapping: None,
            client_cert_pem,
            client_cert_san,
            client_oids,
        }
    }

    /// Processes a single HTTP request through the full middleware pipeline.
    ///
    /// This method **consumes** `self`, which side-steps `Send` / `Sync`
    /// issues that would arise if we held a `&mut self` across `.await`
    /// points. Callers typically clone the handler first.
    ///
    /// # Processing steps
    ///
    /// 1. **Inject client IP** – Inserts the [`SocketAddr`] into the request
    ///    extensions so downstream layers (e.g. the router) can set
    ///    `X-Real-IP`.
    /// 2. **Inject user roles** – Clones the [`Arc<Vec<UserRole>>`] into the
    ///    request extensions (zero-cost pointer bump). The router's RBAC
    ///    check reads these roles later.
    /// 3. **Dispatch** – Forwards the enriched request to the inner service
    ///    stack and awaits its response.
    /// 4. **Caching headers** – Appends headers that must
    ///    apply universally, regardless of upstream or middleware behavior:
    ///    - `Cache-Control: no-store`
    ///
    /// # Arguments
    ///
    /// * `req` – The inbound request with a [`SrvBody`] (already box-erased).
    ///
    /// # Errors
    ///
    /// Returns `Err(SrvError)` if the inner service stack returns an error.
    #[tracing::instrument(skip(self, req), fields(client_addr = %self.client_addr), err)]
    pub async fn handle(
        self,
        mut req: Request<SrvBody>,
    ) -> Result<Response<ServiceRespBody>, SrvError> {
        req.extensions_mut().insert(self.client_addr);

        // 2. Zero-cost injection on the hot path (`Arc::ptr_eq` check when dynamic OIDs are used).
        let roles_to_inject = if let Some(ref dyn_oid) = self.dynamic_oid_mapping {
            let current_map = dyn_oid.live.load();
            if Arc::ptr_eq(&current_map, &dyn_oid.cached_map) {
                self.client_roles.clone()
            } else {
                Arc::new(resolve_roles_from_oids(&self.client_oids, &current_map))
            }
        } else {
            self.client_roles.clone()
        };
        req.extensions_mut().insert(roles_to_inject);

        // 3. Inject cert information if present
        if let Some(ref pem) = self.client_cert_pem {
            req.extensions_mut()
                .insert(PemCertExtension(pem.to_string()));
        }
        if let Some(ref san) = self.client_cert_san {
            req.extensions_mut()
                .insert(SanCertExtension(san.to_string()));
        }

        // 4. Inject raw OIDs for downstream services (e.g. IdP) to embed in JWTs
        if !self.client_oids.is_empty() {
            req.extensions_mut().insert(OidCertExtension((*self.client_oids).clone()));
        }

        // === gRPC Client Protocol Negotiation Check ===
        // Native gRPC requests (`content-type: application/grpc*`) cannot parse HTTP plain-text
        // short-circuit bodies from Tower middlewares (e.g. `403 Forbidden`, `429`, `401`, `413`).
        let is_grpc_request = req
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(is_grpc_content_type);

        let mut inner_service = match self.service_source {
            ServiceSource::Static(svc) => svc,
            ServiceSource::Dynamic(stack) => (**stack.load()).clone(),
        };

        // Tower service contract: poll_ready() MUST be called before call().
        // This is critical for layers like ConcurrencyLimit that acquire a
        // semaphore permit during poll_ready() and assert it exists in call().
        // Most layers silently accept skipping this, but ConcurrencyLimit panics.
        futures::future::poll_fn(|cx| inner_service.poll_ready(cx)).await?;

        let mut resp = inner_service.call(req).await?;

        if is_grpc_request && !resp.status().is_success() {
            let already_grpc = resp.headers().contains_key("grpc-status")
                || resp
                    .headers()
                    .get(hyper::header::CONTENT_TYPE)
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(is_grpc_content_type);
            if !already_grpc {
                resp = translate_http_error_to_grpc(resp).await;
            }
        }

        // === Universal Response Headers (pre-computed, zero-parse overhead) ===
        let headers = resp.headers_mut();
        headers.insert(hyper::header::CACHE_CONTROL, CACHE_CTL_VALUE);

        Ok(resp)
    }
}

/// Returns `true` if `content_type` designates a native gRPC-over-HTTP/2 stream
/// (`application/grpc` or `application/grpc+<subtype>`, ignoring optional `; params`).
#[inline]
fn is_grpc_content_type(content_type: &str) -> bool {
    let media_type = content_type
        .split(';')
        .next()
        .unwrap_or(content_type)
        .trim();
    const PREFIX_PLUS: &str = "application/grpc+";
    media_type.eq_ignore_ascii_case("application/grpc")
        || (media_type.len() > PREFIX_PLUS.len()
            && media_type[..PREFIX_PLUS.len()].eq_ignore_ascii_case(PREFIX_PLUS))
}

/// Maps HTTP error status codes from Tower middleware short-circuits to canonical gRPC status codes.
#[inline]
fn map_http_status_to_grpc_code(status: hyper::StatusCode) -> &'static str {
    match status {
        hyper::StatusCode::BAD_REQUEST => "3",            // INVALID_ARGUMENT
        hyper::StatusCode::UNAUTHORIZED => "16",          // UNAUTHENTICATED
        hyper::StatusCode::FORBIDDEN => "7",              // PERMISSION_DENIED
        hyper::StatusCode::NOT_FOUND
        | hyper::StatusCode::METHOD_NOT_ALLOWED
        | hyper::StatusCode::NOT_IMPLEMENTED => "12",     // UNIMPLEMENTED
        hyper::StatusCode::REQUEST_TIMEOUT
        | hyper::StatusCode::GATEWAY_TIMEOUT => "4",      // DEADLINE_EXCEEDED
        hyper::StatusCode::PAYLOAD_TOO_LARGE
        | hyper::StatusCode::TOO_MANY_REQUESTS => "8",    // RESOURCE_EXHAUSTED
        hyper::StatusCode::BAD_GATEWAY
        | hyper::StatusCode::SERVICE_UNAVAILABLE => "14", // UNAVAILABLE
        _ => "13",                                        // INTERNAL
    }
}

/// Converts a non-gRPC HTTP error response (e.g. `403 Forbidden` plain-text body from `IpFilterLayer`)
/// into a gRPC Trailers-Only error response (`content-type: application/grpc`, `grpc-status`,
/// `grpc-message`, and empty body) while preserving existing security/tracing headers.
async fn translate_http_error_to_grpc(resp: Response<ServiceRespBody>) -> Response<ServiceRespBody> {
    let (mut parts, mut body) = resp.into_parts();
    let status = parts.status;
    let grpc_code = map_http_status_to_grpc_code(status);

    // Read at most 512 bytes for a clean `grpc-message` instead of letting gRPC clients
    // try to frame the plain-text body as Protobuf.
    const MAX_MSG_BYTES: usize = 512;
    let mut msg_buf = Vec::with_capacity(64);
    while msg_buf.len() < MAX_MSG_BYTES {
        match body.frame().await {
            Some(Ok(frame)) => {
                if let Some(data) = frame.data_ref() {
                    let take = (MAX_MSG_BYTES - msg_buf.len()).min(data.len());
                    msg_buf.extend_from_slice(&data[..take]);
                }
            }
            Some(Err(_)) | None => break,
        }
    }

    let raw_msg = String::from_utf8_lossy(&msg_buf);
    let trimmed = raw_msg.trim();
    let msg_text = if trimmed.is_empty() {
        status.canonical_reason().unwrap_or("gRPC Error")
    } else {
        trimmed
    };

    parts.headers.remove(hyper::header::CONTENT_LENGTH);
    parts.headers.remove(hyper::header::CONTENT_ENCODING);
    parts.headers.insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/grpc"),
    );
    parts.headers.insert(
        "grpc-status",
        hyper::header::HeaderValue::from_static(grpc_code),
    );
    let encoded_msg = urlencoding::encode(msg_text);
    if let Ok(msg_val) = hyper::header::HeaderValue::from_str(encoded_msg.as_ref()) {
        parts.headers.insert("grpc-message", msg_val);
    }

    let empty_body: ServiceRespBody = http_body_util::Empty::<Bytes>::new()
        .map_err(SrvError::from)
        .boxed();
    Response::from_parts(parts, empty_body)
}

// ── Hyper Service Implementation ─────────────────────────────────────────────
//
// This is the entry point that Hyper's HTTP/1.1 and HTTP/2 connection drivers
// call for every incoming request. It adapts the native `Incoming` body type
// to our unified `SrvBody` and delegates to `ConnectionHandler::handle`.

impl hyper::service::Service<Request<Incoming>> for ConnectionHandler {
    type Response = Response<ServiceRespBody>;
    type Error = SrvError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    /// Called by Hyper's connection driver for each incoming HTTP request.
    ///
    /// Performs three steps:
    /// 1. **Decompose** the request into head (`parts`) and body.
    /// 2. **Box-erase** the [`Incoming`] body into a [`SrvBody`] so it is
    ///    compatible with the Tower service stack.
    /// 3. **Clone** `self` and spawn the actual processing inside a pinned
    ///    future, because `Service::call` takes `&self` but
    ///    [`ConnectionHandler::handle`] consumes `self` for `Send` safety.
    fn call(&self, req: Request<Incoming>) -> Self::Future {
        let (parts, body) = req.into_parts();
        let boxed_body = IdleTimeoutBody::new(body, DEFAULT_BODY_FRAME_TIMEOUT).boxed();
        let req = Request::from_parts(parts, boxed_body);
        let this = self.clone();
        Box::pin(async move { this.handle(req).await })
    }
}

/// Manual [`Clone`] implementation for [`ConnectionHandler`].
///
/// All fields are cheaply cloneable:
/// - `inner_service` – [`BoxCloneService`] clones via an internal `Arc`.
/// - `client_addr` – [`SocketAddr`] is `Copy`.
/// - `client_roles` – [`Arc<Vec<UserRole>>`] is a pointer bump.
impl Clone for ConnectionHandler {
    fn clone(&self) -> Self {
        Self {
            service_source: self.service_source.clone(),
            client_addr: self.client_addr,
            client_roles: self.client_roles.clone(),
            dynamic_oid_mapping: self.dynamic_oid_mapping.clone(),
            client_cert_pem: self.client_cert_pem.clone(),
            client_cert_san: self.client_cert_san.clone(),
            client_oids: self.client_oids.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::{RoleVec, UserRole};
    use arc_swap::ArcSwap;
    use http_body_util::Full;
    use std::collections::HashMap;
    use tower::service_fn;

    #[test]
    fn test_reexported_claims_matches_common_claims() {
        let claims: super::Claims = common::Claims {
            sub: "embedder".to_string(),
            iss: "praeco-idp".to_string(),
            aud: Some("api".to_string()),
            exp: 1_900_000_000,
            oids: vec!["1".to_string()],
            jti: None,
        };
        assert_eq!(claims.sub, "embedder");
    }

    #[tokio::test]
    async fn test_connection_handler_dynamic_stack_and_oids_updates_per_request() {
        let echo_role_svc = |tag: &'static str| {
            service_fn(move |req: Request<SrvBody>| async move {
                let roles = req
                    .extensions()
                    .get::<Arc<RoleVec<6>>>()
                    .expect("roles extension present");
                let role_name = roles
                    .first()
                    .map(|r| r.0.as_str())
                    .unwrap_or("none")
                    .to_string();
                let payload = format!("{tag}:{role_name}");
                let body = Full::new(Bytes::from(payload)).map_err(SrvError::from).boxed();
                Ok::<Response<ServiceRespBody>, SrvError>(Response::new(body))
            })
            .boxed_clone_sync()
        };

        let dynamic_stack = Arc::new(ArcSwap::from_pointee(echo_role_svc("v1")));
        let mut initial_oids = HashMap::new();
        initial_oids.insert("1".to_string(), UserRole("User".to_string()));
        let live_oid_map = Arc::new(ArcSwap::from_pointee(initial_oids));

        let peer: SocketAddr = "127.0.0.1:50000".parse().unwrap();
        let handler = ConnectionHandler::with_dynamic_stack_and_oids(
            dynamic_stack.clone(),
            peer,
            vec!["1".to_string()],
            None,
            None,
            live_oid_map.clone(),
        );

        // Request 1 on long-lived connection sees stack v1 and role "User"
        let req1 = Request::builder()
            .uri("/test")
            .body(Full::new(Bytes::new()).map_err(SrvError::from).boxed())
            .unwrap();
        let resp1 = handler.clone().handle(req1).await.unwrap();
        let body1 = resp1.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body1[..], b"v1:User");

        // Simulate SIGHUP hot-reload of both service stack and oid_mapping
        dynamic_stack.store(Arc::new(echo_role_svc("v2")));
        let mut updated_oids = HashMap::new();
        updated_oids.insert("1".to_string(), UserRole("Admin".to_string()));
        live_oid_map.store(Arc::new(updated_oids));

        // Request 2 on the SAME ConnectionHandler sees stack v2 and updated role "Admin"
        let req2 = Request::builder()
            .uri("/test")
            .body(Full::new(Bytes::new()).map_err(SrvError::from).boxed())
            .unwrap();
        let resp2 = handler.clone().handle(req2).await.unwrap();
        let body2 = resp2.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body2[..], b"v2:Admin");
    }

    #[tokio::test]
    async fn test_idle_timeout_body_aborts_stalled_upload_and_allows_timely_chunks() {
        use tokio::sync::mpsc;

        struct ChannelBody {
            rx: mpsc::Receiver<Result<http_body::Frame<Bytes>, SrvError>>,
        }
        impl http_body::Body for ChannelBody {
            type Data = Bytes;
            type Error = SrvError;
            fn poll_frame(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
                self.rx.poll_recv(cx)
            }
        }

        // 1. Chunk arrives within idle timeout -> succeeds, then stalls past timeout -> ClientAborted
        let (tx, rx) = mpsc::channel(2);
        tx.send(Ok(http_body::Frame::data(Bytes::from_static(b"chunk1"))))
            .await
            .unwrap();
        let timed = IdleTimeoutBody::new(ChannelBody { rx }, Duration::from_millis(60));
        tokio::pin!(timed);

        let first = timed.frame().await.unwrap().unwrap();
        assert_eq!(first.into_data().unwrap(), Bytes::from_static(b"chunk1"));

        // Keep sender alive without sending a second chunk -> idle timer fires
        let err = timed.frame().await.unwrap().unwrap_err();
        assert!(matches!(err, SrvError::ClientAborted(_)));
        drop(tx);
    }
}
