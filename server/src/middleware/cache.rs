//! # Process-Wide W-TinyLFU Response Cache & Cancellation-Safe Singleflight
//!
//! Provides two composable building blocks for `praeco-rs`:
//!
//! 1. [`Singleflight`] – A cancellation-safe async request coalescer. Concurrent callers
//!    for the same key share a single decoupled worker task; dropping a single caller's
//!    future does not cancel the work for remaining waiters, while dropping **all**
//!    waiters cancels the worker via a [`CancellationToken`].
//! 2. [`SharedResponseCache`] + [`CacheLayer`] / [`CacheService`] – A process-wide,
//!    byte-bounded W-TinyLFU HTTP response cache (`moka::sync::Cache`) shared across
//!    every `[[Server]]` instance in the running `praeco-rs` process.
//!
//! ## Zero-Trust Invariants
//!
//! - [`CacheLayer`] is validated at startup/reload to run **after** all security,
//!   authentication, RBAC, and compression layers (`IpFilter`, `PathSanitizer`,
//!   `Inspection`, `JwtAuth`, `Rbac`, `Compression`).
//! - Caching is opt-in per path rule under `[Server.Layers.Cache.rules]`.
//! - Cross-server sharing is controlled explicitly via `namespace` and isolated by
//!   `CacheScope` (`public`, `per_role`, `per_subject`).
//! - Responses marked with [`CacheBypass`] (e.g. partially degraded `aggregate` responses
//!   containing `_errors`), `Set-Cookie`, `Cache-Control: no-store`, or payloads larger
//!   than `max_entry_bytes` are never stored in the cache.

use std::{
    collections::{HashMap, VecDeque},
    future::Future,
    hash::Hash,
    pin::Pin,
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;
use bytes::Bytes;
use http_body::Frame;
use http_body_util::{BodyExt, Empty, Full};
use hyper::{
    HeaderMap, Method, Request, Response, StatusCode,
    header::{self, HeaderName, HeaderValue},
};
use moka::{Expiry, sync::Cache};
use pin_project::pin_project;
use tokio::sync::{oneshot, watch};
use tokio_util::sync::CancellationToken;
use tower::{Layer, Service};

use crate::{
    Claims, SanCertExtension, ServiceRespBody, SrvBody, SrvError,
    configuration::{
        CacheScope, CompiledCacheConfig, CompiledCacheRule, GlobalCacheConfig, ServerMetrics,
    },
    middleware::{path_sanitizer::sanitize_and_normalize_path_cow, rbac::extract_user_roles_from_extensions},
};

// ============================================================================
//  Cancellation-Safe Singleflight
// ============================================================================

/// Error returned when an in-flight [`Singleflight`] operation was aborted
/// unexpectedly (for example, due to a panic in the worker task).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FlightAborted;

impl std::fmt::Display for FlightAborted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "in-flight operation panicked or was unexpectedly dropped")
    }
}

impl std::error::Error for FlightAborted {}

/// Internal shared state of a single in-flight [`Singleflight`] execution.
struct Flight<T> {
    rx: watch::Receiver<Option<Result<T, FlightAborted>>>,
    waiters: AtomicUsize,
    cancel_token: CancellationToken,
}

/// Result of [`Singleflight::work_with_input`], returning unused input to followers.
enum CoalescedResult<T, I> {
    Leader(T),
    Follower(T, I),
}

/// Coordinates concurrent async computations for identical keys `K` so the
/// underlying operation executes only once across concurrent callers.
///
/// Cheaply cloneable (`Arc`-backed) and thread-safe.
pub struct Singleflight<K, T> {
    flights: Arc<Mutex<HashMap<K, Arc<Flight<T>>>>>,
}

impl<K, T> Clone for Singleflight<K, T> {
    fn clone(&self) -> Self {
        Self {
            flights: Arc::clone(&self.flights),
        }
    }
}

impl<K, T> Default for Singleflight<K, T>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    T: Clone + Send + Sync + 'static,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<K, T> Singleflight<K, T>
where
    K: Eq + Hash + Clone + Send + Sync + 'static,
    T: Clone + Send + Sync + 'static,
{
    /// Creates a new, empty [`Singleflight`] registry.
    pub fn new() -> Self {
        Self {
            flights: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Executes `make_fut()` once for `key` across concurrent callers and returns
    /// `(value, shared)` where `shared` is `false` for the leader caller that
    /// initiated the work and `true` for coalesced follower callers.
    ///
    /// # Cancellation Safety
    ///
    /// - Dropping one caller's future does not cancel the work while other callers
    ///   remain attached.
    /// - Dropping **all** callers triggers cancellation of the decoupled worker task
    ///   and cleans up the key.
    pub async fn work<F, Fut>(&self, key: K, make_fut: F) -> Result<(T, bool), FlightAborted>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = T> + Send + 'static,
    {
        match self.work_with_input(key, (), |()| make_fut()).await? {
            CoalescedResult::Leader(val) => Ok((val, false)),
            CoalescedResult::Follower(val, ()) => Ok((val, true)),
        }
    }

    /// Coalesces concurrent work while preserving `input` for followers that may
    /// need it as a fallback if the leader outcome cannot be shared.
    async fn work_with_input<I, F, Fut>(
        &self,
        key: K,
        input: I,
        make_fut: F,
    ) -> Result<CoalescedResult<T, I>, FlightAborted>
    where
        F: FnOnce(I) -> Fut,
        Fut: Future<Output = T> + Send + 'static,
    {
        // 1. Look up an active, non-cancelled flight or register a new leader flight.
        //    The mutex is never held across `.await` or user `make_fut()` execution.
        let (flight, leader_handle) = {
            let mut map = self
                .flights
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());

            if let Some(existing) = map.get(&key)
                && !existing.cancel_token.is_cancelled()
            {
                existing.waiters.fetch_add(1, Ordering::AcqRel);
                (Arc::clone(existing), None)
            } else {
                let (tx, rx) = watch::channel(None);
                let cancel_token = CancellationToken::new();

                let flight = Arc::new(Flight {
                    rx,
                    waiters: AtomicUsize::new(1),
                    cancel_token: cancel_token.clone(),
                });

                map.insert(key.clone(), Arc::clone(&flight));
                (flight, Some((tx, cancel_token)))
            }
        };

        let is_leader = leader_handle.is_some();
        let follower_input = if let Some((tx, cancel_token)) = leader_handle {
            let flights_ref = Arc::clone(&self.flights);
            let flight_ref = Arc::clone(&flight);
            let key_clone = key;
            let fut = make_fut(input);

            tokio::spawn(async move {
                let _cleanup = MapCleanupGuard {
                    flights: flights_ref,
                    key: key_clone,
                    flight: flight_ref,
                };

                let outcome = tokio::select! {
                    biased;
                    _ = cancel_token.cancelled() => Err(FlightAborted),
                    res = fut => Ok(res),
                };

                let _ = tx.send(Some(outcome));
            });
            None
        } else {
            Some(input)
        };

        // 2. Register this caller as an active waiter.
        let mut waiter_guard = WaiterGuard {
            flight: Arc::clone(&flight),
            completed: false,
        };

        // 3. Await the result from the watch channel without losing wakeups.
        let mut rx = flight.rx.clone();
        loop {
            if let Some(result) = rx.borrow_and_update().clone() {
                waiter_guard.completed = true;
                return match result {
                    Ok(val) => {
                        if is_leader {
                            Ok(CoalescedResult::Leader(val))
                        } else if let Some(inp) = follower_input {
                            Ok(CoalescedResult::Follower(val, inp))
                        } else {
                            Err(FlightAborted)
                        }
                    }
                    Err(e) => Err(e),
                };
            }

            if rx.changed().await.is_err() {
                waiter_guard.completed = true;
                return Err(FlightAborted);
            }
        }
    }
}

/// RAII guard decrementing the waiter count on cancellation and cancelling the
/// worker task if the last waiter is dropped before completion.
struct WaiterGuard<T> {
    flight: Arc<Flight<T>>,
    completed: bool,
}

impl<T> Drop for WaiterGuard<T> {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        if self.flight.waiters.fetch_sub(1, Ordering::AcqRel) == 1 {
            self.flight.cancel_token.cancel();
        }
    }
}

/// RAII guard ensuring the flight key is removed from the registry even if the
/// worker future panics, checking `Arc::ptr_eq` so an older cancelled flight
/// never evicts a newer replacement flight for the same key.
struct MapCleanupGuard<K: Eq + Hash, T> {
    flights: Arc<Mutex<HashMap<K, Arc<Flight<T>>>>>,
    key: K,
    flight: Arc<Flight<T>>,
}

impl<K: Eq + Hash, T> Drop for MapCleanupGuard<K, T> {
    fn drop(&mut self) {
        let mut map = self
            .flights
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(current) = map.get(&self.key)
            && Arc::ptr_eq(current, &self.flight)
        {
            map.remove(&self.key);
        }
    }
}

// ============================================================================
//  Cache Key, Stored Response & Process-Wide Moka Cache
// ============================================================================

/// Response extension marker inserted by handlers (such as partially degraded
/// `aggregate` routes with `_errors`) to prevent [`CacheLayer`] from storing the response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CacheBypass;

/// Canonical lookup key for [`SharedResponseCache`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct CacheKey {
    /// Logical cache namespace (defaults to the server name or an explicit shared namespace).
    pub namespace: String,
    /// Canonical HTTP method used as the stored slot (`"GET"` for both `GET` and `HEAD`).
    pub method: &'static str,
    /// Sanitized path plus lexicographically sorted query parameters.
    pub path_and_query: String,
    /// Lowercase header name/value pairs requested via `vary_headers`.
    pub vary_values: Vec<(String, String)>,
    /// Isolation scope key (`""` for `public`, sorted roles for `per_role`, subject for `per_subject`).
    pub scope_key: String,
}

/// Cached HTTP response stored inside [`SharedResponseCache`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CachedResponse {
    /// Cached HTTP status code.
    pub status: StatusCode,
    /// Cache-safe HTTP headers (stripped of hop-by-hop, `Set-Cookie`, and per-request headers).
    pub headers: HeaderMap,
    /// Buffered uncompressed response body payload.
    pub body: Bytes,
    /// Monotonic timestamp when the entry was inserted.
    pub stored_at: Instant,
    /// Effective time-to-live for this entry.
    pub ttl: Duration,
    /// Approximate memory footprint in bytes used by `moka`'s weigher.
    pub byte_weight: u32,
}

impl CachedResponse {
    fn new(status: StatusCode, headers: HeaderMap, body: Bytes, ttl: Duration) -> Self {
        let approx_header_bytes: usize = headers
            .iter()
            .map(|(k, v)| k.as_str().len() + v.as_bytes().len() + 16)
            .sum();
        let total = body
            .len()
            .saturating_add(approx_header_bytes)
            .saturating_add(64);
        let byte_weight = u32::try_from(total.max(1)).unwrap_or(u32::MAX);

        Self {
            status,
            headers,
            body,
            stored_at: Instant::now(),
            ttl,
            byte_weight,
        }
    }
}

/// Per-entry expiration policy reading `ttl` directly from each [`CachedResponse`].
struct PerEntryExpiry;

impl Expiry<CacheKey, Arc<CachedResponse>> for PerEntryExpiry {
    fn expire_after_create(
        &self,
        _key: &CacheKey,
        value: &Arc<CachedResponse>,
        _created_at: Instant,
    ) -> Option<Duration> {
        Some(value.ttl)
    }

    fn expire_after_update(
        &self,
        _key: &CacheKey,
        value: &Arc<CachedResponse>,
        _updated_at: Instant,
        _duration_until_expiry: Option<Duration>,
    ) -> Option<Duration> {
        Some(value.ttl)
    }
}

/// Outcome broadcast over [`Singleflight`] for a cacheable `GET` miss.
#[derive(Clone)]
enum SingleflightOutcome {
    Cached(Arc<CachedResponse>),
    Bypass,
    UpstreamError(String),
}

/// Process-wide W-TinyLFU HTTP response cache shared across all `[[Server]]` instances.
pub struct SharedResponseCache {
    store: Cache<CacheKey, Arc<CachedResponse>>,
    singleflight: Singleflight<CacheKey, SingleflightOutcome>,
    config: GlobalCacheConfig,
}

impl SharedResponseCache {
    /// Creates a new [`SharedResponseCache`] bounded by `config.max_bytes`.
    pub fn new(config: GlobalCacheConfig) -> Arc<Self> {
        let store = Self::build_store(config.max_bytes);
        Arc::new(Self {
            store,
            singleflight: Singleflight::new(),
            config,
        })
    }

    fn build_store(max_bytes: u64) -> Cache<CacheKey, Arc<CachedResponse>> {
        Cache::builder()
            .max_capacity(max_bytes.max(1))
            .weigher(|_k: &CacheKey, v: &Arc<CachedResponse>| v.byte_weight)
            .expire_after(PerEntryExpiry)
            .build()
    }

    /// Returns the active [`GlobalCacheConfig`] governing this cache instance.
    pub fn config(&self) -> &GlobalCacheConfig {
        &self.config
    }

    /// Looks up an unexpired [`CachedResponse`] by `key`.
    pub fn get(&self, key: &CacheKey) -> Option<Arc<CachedResponse>> {
        if !self.config.enabled {
            return None;
        }
        let entry = self.store.get(key)?;
        if entry.stored_at.elapsed() >= entry.ttl {
            return None;
        }
        Some(entry)
    }

    /// Inserts a [`CachedResponse`] into the W-TinyLFU cache if globally enabled.
    pub fn insert(&self, key: CacheKey, entry: Arc<CachedResponse>) {
        if self.config.enabled && !entry.ttl.is_zero() {
            self.store.insert(key, entry);
        }
    }

    /// Discards all cached entries across all namespaces.
    pub fn invalidate_all(&self) {
        self.store.invalidate_all();
    }

    /// Discards all cached entries belonging to `namespace`.
    pub fn invalidate_namespace(&self, namespace: &str) {
        let ns = namespace.to_string();
        let _ = self
            .store
            .invalidate_entries_if(move |k, _v| k.namespace == ns);
    }

    /// Flushes pending Moka maintenance tasks (primarily useful in deterministic tests).
    pub fn run_pending_tasks(&self) {
        self.store.run_pending_tasks();
    }

    /// Returns the approximate number of entries currently held in the cache.
    pub fn entry_count(&self) -> u64 {
        self.store.entry_count()
    }

    /// Returns the approximate total byte weight currently held in the cache.
    pub fn weighted_size(&self) -> u64 {
        self.store.weighted_size()
    }
}

static GLOBAL_RESPONSE_CACHE: OnceLock<ArcSwap<SharedResponseCache>> = OnceLock::new();

fn global_cache_holder() -> &'static ArcSwap<SharedResponseCache> {
    GLOBAL_RESPONSE_CACHE
        .get_or_init(|| ArcSwap::from(SharedResponseCache::new(GlobalCacheConfig::default())))
}

/// Returns the process-wide [`SharedResponseCache`] shared across all `[[Server]]` instances.
pub fn global_response_cache() -> Arc<SharedResponseCache> {
    global_cache_holder().load_full()
}

/// Updates the process-wide [`SharedResponseCache`] configuration (typically on startup or `SIGHUP`).
///
/// Preserves existing cached entries across `SIGHUP` reloads when `enabled` remains `true`
/// and `max_bytes` is unchanged.
pub fn configure_global_response_cache(cfg: Option<&GlobalCacheConfig>) {
    let next_cfg = cfg.cloned().unwrap_or_default();
    let holder = global_cache_holder();
    let current = holder.load_full();

    if !next_cfg.enabled {
        current.invalidate_all();
        holder.store(SharedResponseCache::new(next_cfg));
        return;
    }

    if current.config.enabled && current.config.max_bytes == next_cfg.max_bytes {
        let preserved = Arc::new(SharedResponseCache {
            store: current.store.clone(),
            singleflight: current.singleflight.clone(),
            config: next_cfg,
        });
        holder.store(preserved);
    } else {
        holder.store(SharedResponseCache::new(next_cfg));
    }
}

// ============================================================================
//  Tower CacheLayer & CacheService
// ============================================================================

/// Tower [`Layer`] enforcing [`CompiledCacheConfig`] rules backed by [`SharedResponseCache`].
#[derive(Clone)]
pub struct CacheLayer {
    rules: Arc<CompiledCacheConfig>,
    server_name: &'static str,
    cache: Option<Arc<SharedResponseCache>>,
}

impl CacheLayer {
    /// Creates a new [`CacheLayer`] bound to the process-wide [`global_response_cache`].
    pub fn new(rules: Arc<CompiledCacheConfig>, server_name: &'static str) -> Self {
        Self {
            rules,
            server_name,
            cache: None,
        }
    }

    /// Overrides the backing [`SharedResponseCache`] (useful for isolated tests or embedded setups).
    pub fn with_cache(mut self, cache: Arc<SharedResponseCache>) -> Self {
        self.cache = Some(cache);
        self
    }
}

impl<S> Layer<S> for CacheLayer {
    type Service = CacheService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        CacheService {
            inner,
            rules: Arc::clone(&self.rules),
            server_name: self.server_name,
            cache: self.cache.clone(),
        }
    }
}

/// Tower [`Service`] implementing L1 W-TinyLFU caching and cancellation-safe [`Singleflight`].
#[derive(Clone)]
pub struct CacheService<S> {
    inner: S,
    rules: Arc<CompiledCacheConfig>,
    server_name: &'static str,
    cache: Option<Arc<SharedResponseCache>>,
}

/// Future returned by [`CacheService`].
#[pin_project(project = CacheFutureProj)]
pub enum CacheFuture<F> {
    /// Synchronous L1 cache hit returned without boxing.
    Hit {
        response: Option<Response<ServiceRespBody>>,
    },
    /// Passthrough request (non-GET/HEAD, disabled cache, or unmatched path) polling `S::Future` inline.
    Passthrough {
        #[pin]
        inner: F,
    },
    /// Synchronous bypass decision (`Cache-Control: no-store`, unauthenticated `PerSubject`,
    /// or `HEAD` miss) polling `S::Future` inline with optional `x-praeco-cache: BYPASS` header.
    Bypass {
        #[pin]
        inner: F,
        expose_cache_header: bool,
    },
    /// Asynchronous L1 `GET` cache miss running Singleflight coalescing and body buffering.
    Coalesce {
        #[pin]
        fut: Pin<Box<dyn Future<Output = Result<Response<ServiceRespBody>, SrvError>> + Send>>,
    },
}

impl<F> Future for CacheFuture<F>
where
    F: Future<Output = Result<Response<ServiceRespBody>, SrvError>>,
{
    type Output = Result<Response<ServiceRespBody>, SrvError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            CacheFutureProj::Hit { response } => crate::poll_ready_response(response),
            CacheFutureProj::Passthrough { inner } => inner.poll(cx),
            CacheFutureProj::Bypass {
                inner,
                expose_cache_header,
            } => {
                let mut resp = std::task::ready!(inner.poll(cx))?;
                if *expose_cache_header {
                    attach_cache_status_header(&mut resp, "BYPASS");
                }
                Poll::Ready(Ok(resp))
            }
            CacheFutureProj::Coalesce { fut } => fut.poll(cx),
        }
    }
}

/// Streaming fallback body used when a response exceeds `max_entry_bytes` mid-stream,
/// seamlessly yielding already-buffered frames before polling the remaining upstream body.
#[pin_project]
struct ChainedStreamBody {
    buffered: VecDeque<Frame<Bytes>>,
    #[pin]
    rest: SrvBody,
    rest_done: bool,
}

impl http_body::Body for ChainedStreamBody {
    type Data = Bytes;
    type Error = SrvError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.project();
        if let Some(frame) = this.buffered.pop_front() {
            return Poll::Ready(Some(Ok(frame)));
        }
        if *this.rest_done {
            return Poll::Ready(None);
        }
        match this.rest.poll_frame(cx) {
            Poll::Ready(None) => {
                *this.rest_done = true;
                Poll::Ready(None)
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.buffered.is_empty() && (self.rest_done || self.rest.is_end_stream())
    }
}

/// Normalizes a URI path and query string (sorting query pairs lexicographically)
/// so `?a=1&b=2` and `?b=2&a=1` resolve to the same [`CacheKey`].
fn canonical_path_and_query(canonical_path: &str, query: Option<&str>) -> String {
    let Some(q) = query.filter(|s| !s.is_empty()) else {
        return canonical_path.to_string();
    };
    let mut pairs: Vec<(String, String)> = url::form_urlencoded::parse(q.as_bytes())
        .map(|(k, v)| (k.into_owned(), v.into_owned()))
        .collect();
    if pairs.is_empty() {
        return canonical_path.to_string();
    }
    pairs.sort();
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        serializer.append_pair(&k, &v);
    }
    let normalized_query = serializer.finish();
    if normalized_query.is_empty() {
        canonical_path.to_string()
    } else {
        format!("{canonical_path}?{normalized_query}")
    }
}

/// Computes the isolation key for the configured [`CacheScope`].
///
/// Returns `None` for [`CacheScope::PerSubject`] when no verified identity is present,
/// signalling callers to bypass the cache fail-safely.
fn build_scope_key(
    scope: CacheScope,
    extensions: &hyper::http::Extensions,
) -> Option<String> {
    match scope {
        CacheScope::Public => Some(String::new()),
        CacheScope::PerRole => {
            let mut roles: Vec<&str> = extract_user_roles_from_extensions(extensions)
                .map(|slice| slice.iter().map(|r| r.0.as_str()).collect())
                .unwrap_or_default();
            if roles.is_empty() {
                return Some("Guest".to_string());
            }
            roles.sort_unstable();
            roles.dedup();
            Some(roles.join(","))
        }
        CacheScope::PerSubject => {
            if let Some(claims) = extensions.get::<Claims>()
                && !claims.sub.trim().is_empty()
            {
                return Some(format!("jwt:{}", claims.sub));
            }
            if let Some(san) = extensions.get::<SanCertExtension>()
                && !san.0.trim().is_empty()
            {
                return Some(format!("san:{}", san.0));
            }
            None
        }
    }
}

fn collect_vary_values(headers: &HeaderMap, vary_headers: &[String]) -> Vec<(String, String)> {
    vary_headers
        .iter()
        .map(|name| {
            let joined = headers
                .get_all(name.as_str())
                .iter()
                .filter_map(|v| v.to_str().ok())
                .map(str::trim)
                .collect::<Vec<_>>()
                .join(",");
            (name.clone(), joined)
        })
        .collect()
}

fn contains_cache_directive(headers: &HeaderMap, header_name: HeaderName, target: &str) -> bool {
    headers.get_all(header_name).iter().any(|val| {
        val.to_str().is_ok_and(|s| {
            s.split(',')
                .map(str::trim)
                .any(|d| d.eq_ignore_ascii_case(target))
        })
    })
}

fn request_forbids_cache(headers: &HeaderMap) -> bool {
    contains_cache_directive(headers, header::CACHE_CONTROL, "no-store")
        || contains_cache_directive(headers, header::CACHE_CONTROL, "no-cache")
        || contains_cache_directive(headers, header::PRAGMA, "no-cache")
}

/// Parses `s-maxage` (preferred for shared caches) or `max-age` from `Cache-Control`.
fn parse_response_max_age(headers: &HeaderMap) -> Option<u64> {
    let mut s_maxage: Option<u64> = None;
    let mut max_age: Option<u64> = None;

    for val in headers.get_all(header::CACHE_CONTROL) {
        let Ok(raw) = val.to_str() else {
            continue;
        };
        for directive in raw.split(',').map(str::trim) {
            if let Some((name, raw_num)) = directive.split_once('=') {
                let key = name.trim();
                let num_str = raw_num.trim().trim_matches('"');
                if let Ok(secs) = num_str.parse::<u64>() {
                    if key.eq_ignore_ascii_case("s-maxage") {
                        s_maxage = Some(s_maxage.map_or(secs, |cur| cur.min(secs)));
                    } else if key.eq_ignore_ascii_case("max-age") {
                        max_age = Some(max_age.map_or(secs, |cur| cur.min(secs)));
                    }
                }
            }
        }
    }

    s_maxage.or(max_age)
}

fn is_hop_by_hop_or_excluded(name: &HeaderName, connection_tokens: &[String]) -> bool {
    let s = name.as_str();
    matches!(
        s,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
            | "set-cookie"
            | "x-trace-id"
            | "traceparent"
            | "date"
            | "age"
            | "x-praeco-cache"
            | "content-length"
    ) || connection_tokens
        .iter()
        .any(|tok| tok.eq_ignore_ascii_case(s))
}

fn sanitize_response_headers(src: &HeaderMap) -> HeaderMap {
    let connection_tokens: Vec<String> = src
        .get_all(header::CONNECTION)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(','))
        .map(|tok| tok.trim().to_ascii_lowercase())
        .filter(|tok| !tok.is_empty())
        .collect();

    let mut out = HeaderMap::with_capacity(src.len());
    for (name, val) in src.iter() {
        if !is_hop_by_hop_or_excluded(name, &connection_tokens) {
            out.append(name.clone(), val.clone());
        }
    }
    out
}

fn attach_cache_status_header(resp: &mut Response<ServiceRespBody>, status: &'static str) {
    resp.headers_mut().insert(
        HeaderName::from_static("x-praeco-cache"),
        HeaderValue::from_static(status),
    );
}

fn build_response_from_cached(
    entry: &CachedResponse,
    is_head: bool,
    expose_cache_header: bool,
    outcome_label: &'static str,
) -> Response<ServiceRespBody> {
    let body: ServiceRespBody = if is_head {
        Empty::<Bytes>::new().map_err(SrvError::from).boxed()
    } else {
        Full::new(entry.body.clone()).map_err(SrvError::from).boxed()
    };

    let mut resp = crate::build_infallible_response(entry.status, None, body);
    for (name, val) in entry.headers.iter() {
        resp.headers_mut().append(name.clone(), val.clone());
    }
    if let Ok(cl) = HeaderValue::from_str(&entry.body.len().to_string()) {
        resp.headers_mut().insert(header::CONTENT_LENGTH, cl);
    }
    if expose_cache_header {
        attach_cache_status_header(&mut resp, outcome_label);
        let age_secs = entry.stored_at.elapsed().as_secs();
        if let Ok(age_val) = HeaderValue::from_str(&age_secs.to_string()) {
            resp.headers_mut().insert(header::AGE, age_val);
        }
    }
    resp
}

/// Evaluates response status and headers to determine whether the response may be cached
/// and computes its effective TTL. Returns `None` if the response must bypass the cache.
fn evaluate_response_cacheability(
    resp: &Response<ServiceRespBody>,
    rule: &CompiledCacheRule,
    global_cfg: &GlobalCacheConfig,
    respect_cache_control: bool,
    max_entry_bytes: usize,
) -> Option<Duration> {
    if resp.status() != StatusCode::OK {
        return None;
    }
    if resp.extensions().get::<CacheBypass>().is_some() {
        return None;
    }
    let headers = resp.headers();
    if headers.contains_key(header::SET_COOKIE) {
        return None;
    }
    if headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| ct.to_ascii_lowercase().starts_with("application/grpc"))
    {
        return None;
    }
    if let Some(content_len) = headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
        && content_len > max_entry_bytes
    {
        return None;
    }

    let base_ttl = Duration::from_secs(rule.ttl_seconds.unwrap_or(global_cfg.default_ttl_seconds));
    if base_ttl.is_zero() {
        return None;
    }

    if respect_cache_control {
        if contains_cache_directive(headers, header::CACHE_CONTROL, "no-store")
            || contains_cache_directive(headers, header::CACHE_CONTROL, "no-cache")
        {
            return None;
        }
        if rule.scope == CacheScope::Public
            && contains_cache_directive(headers, header::CACHE_CONTROL, "private")
        {
            return None;
        }
        if let Some(max_age) = parse_response_max_age(headers) {
            if max_age == 0 {
                return None;
            }
            return Some(base_ttl.min(Duration::from_secs(max_age)));
        }
    }

    Some(base_ttl)
}

enum BufferedOrStream {
    Buffered(Bytes),
    Overflow {
        buffered: VecDeque<Frame<Bytes>>,
        rest: SrvBody,
    },
}

/// Reads up to `max_entry_bytes` of data frames from `body`. If the stream exceeds
/// `max_entry_bytes` or yields trailers/errors, returns [`BufferedOrStream::Overflow`]
/// without discarding any frames so the leader can keep streaming seamlessly.
async fn collect_up_to_limit(
    mut body: SrvBody,
    max_entry_bytes: usize,
) -> Result<BufferedOrStream, SrvError> {
    let mut frames: VecDeque<Frame<Bytes>> = VecDeque::new();
    let mut total_bytes: usize = 0;

    while let Some(frame_res) = body.frame().await {
        let frame = frame_res?;
        if let Some(data) = frame.data_ref() {
            let next_total = total_bytes.saturating_add(data.len());
            if next_total > max_entry_bytes {
                frames.push_back(frame);
                return Ok(BufferedOrStream::Overflow {
                    buffered: frames,
                    rest: body,
                });
            }
            total_bytes = next_total;
            frames.push_back(frame);
        } else {
            // Non-data frame (e.g. HTTP/2 trailers) -> bypass caching and stream directly.
            frames.push_back(frame);
            return Ok(BufferedOrStream::Overflow {
                buffered: frames,
                rest: body,
            });
        }
    }

    if frames.len() == 1
        && let Some(only) = frames.pop_front()
        && let Ok(bytes) = only.into_data()
    {
        return Ok(BufferedOrStream::Buffered(bytes));
    }

    let mut out = bytes::BytesMut::with_capacity(total_bytes);
    for frame in frames {
        if let Ok(chunk) = frame.into_data() {
            out.extend_from_slice(&chunk);
        }
    }
    Ok(BufferedOrStream::Buffered(out.freeze()))
}

impl<S> Service<Request<SrvBody>> for CacheService<S>
where
    S: Service<Request<SrvBody>, Response = Response<ServiceRespBody>, Error = SrvError>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    type Response = Response<ServiceRespBody>;
    type Error = SrvError;
    type Future = CacheFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<SrvBody>) -> Self::Future {
        let method = req.method();
        if *method != Method::GET && *method != Method::HEAD {
            return CacheFuture::Passthrough {
                inner: self.inner.call(req),
            };
        }

        let cache = self
            .cache
            .clone()
            .unwrap_or_else(global_response_cache);
        let global_cfg = cache.config().clone();
        if !global_cfg.enabled {
            return CacheFuture::Passthrough {
                inner: self.inner.call(req),
            };
        }

        let raw_path = req.uri().path();
        if raw_path.contains(';')
            || raw_path
                .as_bytes()
                .windows(3)
                .any(|w| w.eq_ignore_ascii_case(b"%3b"))
        {
            return CacheFuture::Passthrough {
                inner: self.inner.call(req),
            };
        }

        let canonical_path = match sanitize_and_normalize_path_cow(raw_path) {
            Ok(p) => p,
            Err(_) => {
                return CacheFuture::Passthrough {
                    inner: self.inner.call(req),
                };
            }
        };

        let matched_rule = self
            .rules
            .match_request(method.as_str(), &canonical_path)
            .or_else(|| {
                (*method == Method::HEAD)
                    .then(|| self.rules.match_request("GET", &canonical_path))
                    .flatten()
            });

        let Some(rule) = matched_rule.cloned() else {
            return CacheFuture::Passthrough {
                inner: self.inner.call(req),
            };
        };

        let server_name = self.server_name;
        let expose_cache_header = rule
            .expose_cache_header
            .unwrap_or(global_cfg.expose_cache_header);
        let respect_cache_control = rule
            .respect_cache_control
            .unwrap_or(global_cfg.respect_cache_control);
        let max_entry_bytes = rule
            .max_entry_bytes
            .unwrap_or(global_cfg.max_entry_bytes)
            .min(global_cfg.max_entry_bytes);

        if respect_cache_control && request_forbids_cache(req.headers()) {
            ServerMetrics::inc_cache_bypass(server_name);
            return CacheFuture::Bypass {
                inner: self.inner.call(req),
                expose_cache_header,
            };
        }

        let Some(scope_key) = build_scope_key(rule.scope, req.extensions()) else {
            ServerMetrics::inc_cache_bypass(server_name);
            return CacheFuture::Bypass {
                inner: self.inner.call(req),
                expose_cache_header,
            };
        };

        let namespace = rule
            .namespace
            .as_deref()
            .or(self.rules.default_namespace.as_deref())
            .unwrap_or(server_name)
            .to_string();

        let key = CacheKey {
            namespace,
            method: "GET",
            path_and_query: canonical_path_and_query(&canonical_path, req.uri().query()),
            vary_values: collect_vary_values(req.headers(), &rule.vary_headers),
            scope_key,
        };

        let is_head = *method == Method::HEAD;

        // Synchronous L1 hit fast-path
        if let Some(entry) = cache.get(&key) {
            ServerMetrics::inc_cache_hit(server_name);
            let resp = build_response_from_cached(&entry, is_head, expose_cache_header, "HIT");
            return CacheFuture::Hit {
                response: Some(resp),
            };
        }

        // HEAD misses bypass caching/singleflight so empty HEAD responses never populate GET slots.
        if is_head {
            ServerMetrics::inc_cache_bypass(server_name);
            return CacheFuture::Bypass {
                inner: self.inner.call(req),
                expose_cache_header,
            };
        }

        // GET miss (cold path): coalesce concurrent callers via cancellation-safe Singleflight.
        let mut inner = self.inner.clone();

        CacheFuture::Coalesce {
            fut: Box::pin(async move {
                let (direct_tx, mut direct_rx) = oneshot::channel::<Response<ServiceRespBody>>();
                let cache_for_worker = Arc::clone(&cache);
                let key_for_worker = key.clone();
                let rule_for_worker = rule.clone();
                let global_cfg_for_worker = global_cfg.clone();
                let mut inner_for_worker = inner.clone();

                let coalesced = cache
                    .singleflight
                    .work_with_input(key, req, move |leader_req| async move {
                        let resp = match inner_for_worker.call(leader_req).await {
                            Ok(r) => r,
                            Err(e) => return SingleflightOutcome::UpstreamError(e.to_string()),
                        };

                        let Some(ttl) = evaluate_response_cacheability(
                            &resp,
                            &rule_for_worker,
                            &global_cfg_for_worker,
                            respect_cache_control,
                            max_entry_bytes,
                        ) else {
                            let _ = direct_tx.send(resp);
                            return SingleflightOutcome::Bypass;
                        };

                        let (parts, body) = resp.into_parts();
                        match collect_up_to_limit(body, max_entry_bytes).await {
                            Ok(BufferedOrStream::Buffered(bytes)) => {
                                let clean_headers = sanitize_response_headers(&parts.headers);
                                let entry = Arc::new(CachedResponse::new(
                                    parts.status,
                                    clean_headers,
                                    bytes,
                                    ttl,
                                ));
                                cache_for_worker.insert(key_for_worker, Arc::clone(&entry));
                                SingleflightOutcome::Cached(entry)
                            }
                            Ok(BufferedOrStream::Overflow { buffered, rest }) => {
                                let chained = ChainedStreamBody {
                                    buffered,
                                    rest,
                                    rest_done: false,
                                }
                                .boxed();
                                let mut rebuilt = Response::from_parts(parts, chained);
                                rebuilt.headers_mut().remove(header::CONTENT_LENGTH);
                                let _ = direct_tx.send(rebuilt);
                                SingleflightOutcome::Bypass
                            }
                            Err(e) => SingleflightOutcome::UpstreamError(e.to_string()),
                        }
                    })
                    .await
                    .map_err(|_| SrvError::Other("Cache singleflight operation aborted".into()))?;

                match coalesced {
                    CoalescedResult::Leader(SingleflightOutcome::Cached(entry)) => {
                        ServerMetrics::inc_cache_miss(server_name);
                        Ok(build_response_from_cached(
                            &entry,
                            false,
                            expose_cache_header,
                            "MISS",
                        ))
                    }
                    CoalescedResult::Follower(SingleflightOutcome::Cached(entry), _unused_req) => {
                        ServerMetrics::inc_cache_coalesced(server_name);
                        Ok(build_response_from_cached(
                            &entry,
                            false,
                            expose_cache_header,
                            "COALESCED",
                        ))
                    }
                    CoalescedResult::Leader(SingleflightOutcome::Bypass) => {
                        ServerMetrics::inc_cache_bypass(server_name);
                        let mut resp = direct_rx.try_recv().map_err(|_| {
                            SrvError::Other("Cache leader bypass response channel closed".into())
                        })?;
                        if expose_cache_header {
                            attach_cache_status_header(&mut resp, "BYPASS");
                        }
                        Ok(resp)
                    }
                    CoalescedResult::Follower(SingleflightOutcome::Bypass, follower_req) => {
                        ServerMetrics::inc_cache_bypass(server_name);
                        let mut resp = inner.call(follower_req).await?;
                        if expose_cache_header {
                            attach_cache_status_header(&mut resp, "BYPASS");
                        }
                        Ok(resp)
                    }
                    CoalescedResult::Leader(SingleflightOutcome::UpstreamError(msg))
                    | CoalescedResult::Follower(SingleflightOutcome::UpstreamError(msg), _) => {
                        Err(SrvError::Other(msg))
                    }
                }
            }),
        }
    }
}

// ============================================================================
//  Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BoxCloneSyncServiceExt;
    use crate::configuration::{CacheLayerConfig, CacheRuleConfig, RoleVec, UserRole};
    use std::sync::atomic::AtomicU64;
    use tokio::sync::Notify;
    use tower::ServiceExt;

    fn empty_req(uri: &str) -> Request<SrvBody> {
        Request::builder()
            .method(Method::GET)
            .uri(uri)
            .body(Empty::<Bytes>::new().map_err(SrvError::from).boxed())
            .unwrap()
    }

    fn text_resp(body: &'static str) -> Response<ServiceRespBody> {
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/plain")
            .body(
                Full::new(Bytes::from_static(body.as_bytes()))
                    .map_err(SrvError::from)
                    .boxed(),
            )
            .unwrap()
    }

    #[tokio::test]
    async fn test_singleflight_coalesces_and_survives_leader_drop() {
        let sf: Singleflight<String, usize> = Singleflight::new();
        let executions = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());

        let sf1 = sf.clone();
        let exec1 = Arc::clone(&executions);
        let started1 = Arc::clone(&started);
        let release1 = Arc::clone(&release);

        let leader = tokio::spawn(async move {
            sf1.work("key1".to_string(), move || async move {
                exec1.fetch_add(1, Ordering::SeqCst);
                started1.notify_one();
                release1.notified().await;
                42
            })
            .await
        });

        started.notified().await;

        let sf2 = sf.clone();
        let exec2 = Arc::clone(&executions);
        let follower = tokio::spawn(async move {
            sf2.work("key1".to_string(), move || async move {
                exec2.fetch_add(1, Ordering::SeqCst);
                99
            })
            .await
        });

        // Yield so follower attaches before leader aborts.
        tokio::task::yield_now().await;
        leader.abort();
        let _ = leader.await;

        // Release worker; follower must still receive the leader's result.
        release.notify_waiters();
        let (val, shared) = follower.await.unwrap().unwrap();
        assert_eq!(val, 42);
        assert!(shared);
        assert_eq!(executions.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_singleflight_cancels_when_all_waiters_drop_and_allows_retry() {
        let sf: Singleflight<String, usize> = Singleflight::new();
        let cancelled = Arc::new(Notify::new());
        let cancelled_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let started = Arc::new(Notify::new());

        struct DropSignal {
            flag: Arc<std::sync::atomic::AtomicBool>,
            notify: Arc<Notify>,
        }
        impl Drop for DropSignal {
            fn drop(&mut self) {
                self.flag.store(true, Ordering::SeqCst);
                self.notify.notify_one();
            }
        }

        let sf1 = sf.clone();
        let started1 = Arc::clone(&started);
        let flag1 = Arc::clone(&cancelled_flag);
        let notify1 = Arc::clone(&cancelled);

        let caller = tokio::spawn(async move {
            sf1.work("key2".to_string(), move || async move {
                let _guard = DropSignal {
                    flag: flag1,
                    notify: notify1,
                };
                started1.notify_one();
                std::future::pending::<usize>().await
            })
            .await
        });

        started.notified().await;
        caller.abort();
        let _ = caller.await;

        tokio::time::timeout(Duration::from_secs(2), cancelled.notified())
            .await
            .expect("worker must be cancelled once all waiters drop");
        assert!(cancelled_flag.load(Ordering::SeqCst));

        // Immediately issuing a new call for the same key must start a fresh flight (no stale FlightAborted).
        let (val, shared) = sf
            .work("key2".to_string(), || async { 123 })
            .await
            .expect("fresh flight after cancellation must succeed");
        assert_eq!(val, 123);
        assert!(!shared);
    }

    #[tokio::test]
    async fn test_singleflight_cleans_up_on_worker_panic() {
        let sf: Singleflight<String, usize> = Singleflight::new();
        let res = sf
            .work("panic_key".to_string(), || async {
                panic!("simulated worker panic");
            })
            .await;
        assert_eq!(res, Err(FlightAborted));

        // Registry must have been cleaned up by MapCleanupGuard so subsequent calls succeed.
        let (val, shared) = sf
            .work("panic_key".to_string(), || async { 77 })
            .await
            .unwrap();
        assert_eq!(val, 77);
        assert!(!shared);
    }

    #[tokio::test]
    async fn test_cache_layer_hit_miss_ttl_and_query_normalization() {
        let cache = SharedResponseCache::new(GlobalCacheConfig {
            enabled: true,
            max_bytes: 1024 * 1024,
            default_ttl_seconds: 1,
            max_entry_bytes: 64 * 1024,
            respect_cache_control: true,
            expose_cache_header: true,
        });

        let layer_cfg = CacheLayerConfig {
            namespace: None,
            rules: HashMap::from([(
                "/catalog/*".to_string(),
                CacheRuleConfig {
                    ttl_seconds: Some(1),
                    scope: CacheScope::Public,
                    ..Default::default()
                },
            )]),
        };
        let compiled = Arc::new(CompiledCacheConfig::from_raw(&layer_cfg, "srv_a").unwrap());

        let hits = Arc::new(AtomicU64::new(0));
        let hits_clone = Arc::clone(&hits);
        let backend = tower::service_fn(move |_req: Request<SrvBody>| {
            let hits_inner = Arc::clone(&hits_clone);
            async move {
                let n = hits_inner.fetch_add(1, Ordering::SeqCst) + 1;
                let body = format!("resp-{n}");
                Ok::<_, SrvError>(
                    Response::builder()
                        .status(StatusCode::OK)
                        .body(Full::new(Bytes::from(body)).map_err(SrvError::from).boxed())
                        .unwrap(),
                )
            }
        })
        .boxed_clone_sync();

        let svc = CacheLayer::new(compiled, "srv_a")
            .with_cache(Arc::clone(&cache))
            .layer(backend);

        // 1. Miss
        let r1 = svc.clone().oneshot(empty_req("/catalog/items?b=2&a=1")).await.unwrap();
        assert_eq!(r1.headers().get("x-praeco-cache").unwrap(), "MISS");
        let b1 = r1.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&b1[..], b"resp-1");

        // 2. Hit with reordered query string
        let r2 = svc.clone().oneshot(empty_req("/catalog/items?a=1&b=2")).await.unwrap();
        assert_eq!(r2.headers().get("x-praeco-cache").unwrap(), "HIT");
        let b2 = r2.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&b2[..], b"resp-1");
        assert_eq!(hits.load(Ordering::SeqCst), 1);

        // 3. HEAD uses cached GET entry with empty body
        let head_req = Request::builder()
            .method(Method::HEAD)
            .uri("/catalog/items?a=1&b=2")
            .body(Empty::<Bytes>::new().map_err(SrvError::from).boxed())
            .unwrap();
        let r_head = svc.clone().oneshot(head_req).await.unwrap();
        assert_eq!(r_head.headers().get("x-praeco-cache").unwrap(), "HIT");
        assert_eq!(r_head.headers().get(header::CONTENT_LENGTH).unwrap(), "6");
        let b_head = r_head.into_body().collect().await.unwrap().to_bytes();
        assert!(b_head.is_empty());

        // 4. Wait past 1s TTL -> new MISS
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let r3 = svc.clone().oneshot(empty_req("/catalog/items?a=1&b=2")).await.unwrap();
        assert_eq!(r3.headers().get("x-praeco-cache").unwrap(), "MISS");
        let b3 = r3.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&b3[..], b"resp-2");
        assert_eq!(hits.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn test_cache_scopes_per_role_and_per_subject_and_cross_server_namespace() {
        let cache = SharedResponseCache::new(GlobalCacheConfig {
            enabled: true,
            max_bytes: 1024 * 1024,
            default_ttl_seconds: 60,
            max_entry_bytes: 64 * 1024,
            respect_cache_control: true,
            expose_cache_header: true,
        });

        let cfg = CacheLayerConfig {
            namespace: None,
            rules: HashMap::from([
                (
                    "/shared/*".to_string(),
                    CacheRuleConfig {
                        scope: CacheScope::Public,
                        namespace: Some("catalog_ns".to_string()),
                        ..Default::default()
                    },
                ),
                (
                    "/roles/*".to_string(),
                    CacheRuleConfig {
                        scope: CacheScope::PerRole,
                        ..Default::default()
                    },
                ),
                (
                    "/me/*".to_string(),
                    CacheRuleConfig {
                        scope: CacheScope::PerSubject,
                        ..Default::default()
                    },
                ),
            ]),
        };

        let comp_a = Arc::new(CompiledCacheConfig::from_raw(&cfg, "srv_a").unwrap());
        let comp_b = Arc::new(CompiledCacheConfig::from_raw(&cfg, "srv_b").unwrap());

        let count_a = Arc::new(AtomicU64::new(0));
        let count_a_ref = Arc::clone(&count_a);
        let svc_a = CacheLayer::new(comp_a, "srv_a")
            .with_cache(Arc::clone(&cache))
            .layer(
                tower::service_fn(move |req: Request<SrvBody>| {
                    let c = Arc::clone(&count_a_ref);
                    async move {
                        let n = c.fetch_add(1, Ordering::SeqCst) + 1;
                        let path = req.uri().path().to_string();
                        Ok::<_, SrvError>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .body(
                                    Full::new(Bytes::from(format!("A:{path}:{n}")))
                                        .map_err(SrvError::from)
                                        .boxed(),
                                )
                                .unwrap(),
                        )
                    }
                })
                .boxed_clone_sync(),
            );

        let count_b = Arc::new(AtomicU64::new(0));
        let count_b_ref = Arc::clone(&count_b);
        let svc_b = CacheLayer::new(comp_b, "srv_b")
            .with_cache(Arc::clone(&cache))
            .layer(
                tower::service_fn(move |_req: Request<SrvBody>| {
                    let c = Arc::clone(&count_b_ref);
                    async move {
                        c.fetch_add(1, Ordering::SeqCst);
                        Ok::<_, SrvError>(text_resp("from-B"))
                    }
                })
                .boxed_clone_sync(),
            );

        // Cross-server sharing via explicit namespace: populate on A, hit on B!
        let ra = svc_a.clone().oneshot(empty_req("/shared/books")).await.unwrap();
        assert_eq!(ra.headers().get("x-praeco-cache").unwrap(), "MISS");
        let rb = svc_b.clone().oneshot(empty_req("/shared/books")).await.unwrap();
        assert_eq!(rb.headers().get("x-praeco-cache").unwrap(), "HIT");
        let bb = rb.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&bb[..], b"A:/shared/books:1");
        assert_eq!(count_b.load(Ordering::SeqCst), 0);

        // PerRole isolation: Admin vs Seller
        let mut req_admin = empty_req("/roles/report");
        req_admin
            .extensions_mut()
            .insert(Arc::new(RoleVec::<6>::from_iter([UserRole("Admin".into())])));
        let r_adm = svc_a.clone().oneshot(req_admin).await.unwrap();
        assert_eq!(r_adm.headers().get("x-praeco-cache").unwrap(), "MISS");

        let mut req_seller = empty_req("/roles/report");
        req_seller
            .extensions_mut()
            .insert(Arc::new(RoleVec::<6>::from_iter([UserRole("Seller".into())])));
        let r_sel = svc_a.clone().oneshot(req_seller).await.unwrap();
        assert_eq!(r_sel.headers().get("x-praeco-cache").unwrap(), "MISS");

        // PerSubject isolation + fail-safe bypass when unauthenticated
        let r_unauth = svc_a.clone().oneshot(empty_req("/me/profile")).await.unwrap();
        assert_eq!(r_unauth.headers().get("x-praeco-cache").unwrap(), "BYPASS");

        let mut req_u1 = empty_req("/me/profile");
        req_u1.extensions_mut().insert(SanCertExtension::from("alice"));
        let r_u1_1 = svc_a.clone().oneshot(req_u1).await.unwrap();
        assert_eq!(r_u1_1.headers().get("x-praeco-cache").unwrap(), "MISS");

        let mut req_u1_again = empty_req("/me/profile");
        req_u1_again
            .extensions_mut()
            .insert(SanCertExtension::from("alice"));
        let r_u1_2 = svc_a.clone().oneshot(req_u1_again).await.unwrap();
        assert_eq!(r_u1_2.headers().get("x-praeco-cache").unwrap(), "HIT");

        let mut req_u2 = empty_req("/me/profile");
        req_u2.extensions_mut().insert(SanCertExtension::from("bob"));
        let r_u2 = svc_a.clone().oneshot(req_u2).await.unwrap();
        assert_eq!(r_u2.headers().get("x-praeco-cache").unwrap(), "MISS");
    }

    #[tokio::test]
    async fn test_cache_bypasses_large_streaming_responses_and_cache_bypass_marker() {
        let cache = SharedResponseCache::new(GlobalCacheConfig {
            enabled: true,
            max_bytes: 1024 * 1024,
            default_ttl_seconds: 60,
            max_entry_bytes: 10, // tiny limit
            respect_cache_control: true,
            expose_cache_header: true,
        });

        let cfg = CacheLayerConfig {
            namespace: None,
            rules: HashMap::from([("/*".to_string(), CacheRuleConfig::default())]),
        };
        let compiled = Arc::new(CompiledCacheConfig::from_raw(&cfg, "srv_stream").unwrap());

        let svc = CacheLayer::new(compiled, "srv_stream")
            .with_cache(Arc::clone(&cache))
            .layer(
                tower::service_fn(|req: Request<SrvBody>| async move {
                    if req.uri().path() == "/degraded" {
                        let mut resp = text_resp("ok");
                        resp.extensions_mut().insert(CacheBypass);
                        return Ok::<_, SrvError>(resp);
                    }
                    // Multi-frame response exceeding 10 bytes without Content-Length
                    let stream = futures_util::stream::iter(vec![
                        Ok::<_, SrvError>(Frame::data(Bytes::from_static(b"123456"))),
                        Ok::<_, SrvError>(Frame::data(Bytes::from_static(b"789012"))),
                    ]);
                    let body = http_body_util::StreamBody::new(stream).boxed();
                    Ok(Response::builder().status(StatusCode::OK).body(body).unwrap())
                })
                .boxed_clone_sync(),
            );

        let r_big = svc.clone().oneshot(empty_req("/large")).await.unwrap();
        assert_eq!(r_big.headers().get("x-praeco-cache").unwrap(), "BYPASS");
        let b_big = r_big.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&b_big[..], b"123456789012");

        let r_deg = svc.clone().oneshot(empty_req("/degraded")).await.unwrap();
        assert_eq!(r_deg.headers().get("x-praeco-cache").unwrap(), "BYPASS");
        cache.run_pending_tasks();
        assert_eq!(cache.entry_count(), 0);
    }

    #[tokio::test]
    async fn test_cache_control_set_cookie_private_and_max_age_directives() {
        let cache = SharedResponseCache::new(GlobalCacheConfig {
            enabled: true,
            max_bytes: 1024 * 1024,
            default_ttl_seconds: 60,
            max_entry_bytes: 64 * 1024,
            respect_cache_control: true,
            expose_cache_header: true,
        });

        let cfg = CacheLayerConfig {
            namespace: None,
            rules: HashMap::from([
                (
                    "/pub/*".to_string(),
                    CacheRuleConfig {
                        scope: CacheScope::Public,
                        ttl_seconds: Some(60),
                        ..Default::default()
                    },
                ),
                (
                    "/subj/*".to_string(),
                    CacheRuleConfig {
                        scope: CacheScope::PerSubject,
                        ttl_seconds: Some(60),
                        ..Default::default()
                    },
                ),
            ]),
        };
        let compiled = Arc::new(CompiledCacheConfig::from_raw(&cfg, "srv_cc").unwrap());
        let calls = Arc::new(AtomicU64::new(0));
        let calls_ref = Arc::clone(&calls);

        let svc = CacheLayer::new(compiled, "srv_cc")
            .with_cache(Arc::clone(&cache))
            .layer(
                tower::service_fn(move |req: Request<SrvBody>| {
                    let c = Arc::clone(&calls_ref);
                    async move {
                        let n = c.fetch_add(1, Ordering::SeqCst) + 1;
                        let mut builder = Response::builder().status(StatusCode::OK);
                        match req.uri().path() {
                            "/pub/cookie" => {
                                builder = builder.header(header::SET_COOKIE, "sid=secret; HttpOnly");
                            }
                            "/pub/private" => {
                                builder = builder.header(header::CACHE_CONTROL, "private, max-age=60");
                            }
                            "/subj/private" => {
                                builder = builder.header(header::CACHE_CONTROL, "private, max-age=60");
                            }
                            "/pub/zero" => {
                                builder = builder.header(header::CACHE_CONTROL, "max-age=0");
                            }
                            "/pub/short" => {
                                builder = builder.header(header::CACHE_CONTROL, "max-age=60, s-maxage=1");
                            }
                            _ => {}
                        }
                        Ok::<_, SrvError>(
                            builder
                                .body(
                                    Full::new(Bytes::from(format!("v-{n}")))
                                        .map_err(SrvError::from)
                                        .boxed(),
                                )
                                .unwrap(),
                        )
                    }
                })
                .boxed_clone_sync(),
            );

        // 1. Set-Cookie is never cached
        let rc1 = svc.clone().oneshot(empty_req("/pub/cookie")).await.unwrap();
        assert_eq!(rc1.headers().get("x-praeco-cache").unwrap(), "BYPASS");
        let rc2 = svc.clone().oneshot(empty_req("/pub/cookie")).await.unwrap();
        assert_eq!(rc2.headers().get("x-praeco-cache").unwrap(), "BYPASS");

        // 2. Cache-Control: private bypasses on Public scope
        let rp1 = svc.clone().oneshot(empty_req("/pub/private")).await.unwrap();
        assert_eq!(rp1.headers().get("x-praeco-cache").unwrap(), "BYPASS");

        // 3. Cache-Control: private is cached on PerSubject scope
        let mut req_subj1 = empty_req("/subj/private");
        req_subj1.extensions_mut().insert(SanCertExtension::from("alice"));
        let rs1 = svc.clone().oneshot(req_subj1).await.unwrap();
        assert_eq!(rs1.headers().get("x-praeco-cache").unwrap(), "MISS");

        let mut req_subj2 = empty_req("/subj/private");
        req_subj2.extensions_mut().insert(SanCertExtension::from("alice"));
        let rs2 = svc.clone().oneshot(req_subj2).await.unwrap();
        assert_eq!(rs2.headers().get("x-praeco-cache").unwrap(), "HIT");

        // 4. max-age=0 bypasses
        let rz = svc.clone().oneshot(empty_req("/pub/zero")).await.unwrap();
        assert_eq!(rz.headers().get("x-praeco-cache").unwrap(), "BYPASS");

        // 5. Request Cache-Control: no-cache forces BYPASS even when entry could be cached
        let mut req_nocache = empty_req("/pub/normal");
        req_nocache
            .headers_mut()
            .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-cache"));
        let rnc = svc.clone().oneshot(req_nocache).await.unwrap();
        assert_eq!(rnc.headers().get("x-praeco-cache").unwrap(), "BYPASS");

        // 6. s-maxage=1 clamps 60s rule TTL down to 1s
        let r_short1 = svc.clone().oneshot(empty_req("/pub/short")).await.unwrap();
        assert_eq!(r_short1.headers().get("x-praeco-cache").unwrap(), "MISS");
        let r_short2 = svc.clone().oneshot(empty_req("/pub/short")).await.unwrap();
        assert_eq!(r_short2.headers().get("x-praeco-cache").unwrap(), "HIT");
        tokio::time::sleep(Duration::from_millis(1100)).await;
        let r_short3 = svc.clone().oneshot(empty_req("/pub/short")).await.unwrap();
        assert_eq!(r_short3.headers().get("x-praeco-cache").unwrap(), "MISS");
    }

    #[tokio::test]
    async fn test_cache_vary_headers_partitioning() {
        let cache = SharedResponseCache::new(GlobalCacheConfig {
            enabled: true,
            max_bytes: 1024 * 1024,
            default_ttl_seconds: 60,
            max_entry_bytes: 64 * 1024,
            respect_cache_control: true,
            expose_cache_header: true,
        });

        let cfg = CacheLayerConfig {
            namespace: None,
            rules: HashMap::from([(
                "/i18n/*".to_string(),
                CacheRuleConfig {
                    vary_headers: vec!["Accept-Language".to_string()],
                    ..Default::default()
                },
            )]),
        };
        let compiled = Arc::new(CompiledCacheConfig::from_raw(&cfg, "srv_vary").unwrap());

        let svc = CacheLayer::new(compiled, "srv_vary")
            .with_cache(Arc::clone(&cache))
            .layer(
                tower::service_fn(|req: Request<SrvBody>| async move {
                    let lang = req
                        .headers()
                        .get(header::ACCEPT_LANGUAGE)
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("none")
                        .to_string();
                    Ok::<_, SrvError>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .body(Full::new(Bytes::from(lang)).map_err(SrvError::from).boxed())
                            .unwrap(),
                    )
                })
                .boxed_clone_sync(),
            );

        let mut req_de = empty_req("/i18n/hello");
        req_de
            .headers_mut()
            .insert(header::ACCEPT_LANGUAGE, HeaderValue::from_static("de"));
        let r_de1 = svc.clone().oneshot(req_de).await.unwrap();
        assert_eq!(r_de1.headers().get("x-praeco-cache").unwrap(), "MISS");
        assert_eq!(&r_de1.into_body().collect().await.unwrap().to_bytes()[..], b"de");

        let mut req_en = empty_req("/i18n/hello");
        req_en
            .headers_mut()
            .insert(header::ACCEPT_LANGUAGE, HeaderValue::from_static("en"));
        let r_en1 = svc.clone().oneshot(req_en).await.unwrap();
        assert_eq!(r_en1.headers().get("x-praeco-cache").unwrap(), "MISS");
        assert_eq!(&r_en1.into_body().collect().await.unwrap().to_bytes()[..], b"en");

        let mut req_de_hit = empty_req("/i18n/hello");
        req_de_hit
            .headers_mut()
            .insert(header::ACCEPT_LANGUAGE, HeaderValue::from_static("de"));
        let r_de2 = svc.clone().oneshot(req_de_hit).await.unwrap();
        assert_eq!(r_de2.headers().get("x-praeco-cache").unwrap(), "HIT");
        assert_eq!(&r_de2.into_body().collect().await.unwrap().to_bytes()[..], b"de");
    }

    #[tokio::test]
    async fn test_cache_layer_concurrent_coalescing_and_follower_bypass_fallback() {
        let cache = SharedResponseCache::new(GlobalCacheConfig {
            enabled: true,
            max_bytes: 1024 * 1024,
            default_ttl_seconds: 60,
            max_entry_bytes: 64 * 1024,
            respect_cache_control: true,
            expose_cache_header: true,
        });

        let cfg = CacheLayerConfig {
            namespace: None,
            rules: HashMap::from([("/*".to_string(), CacheRuleConfig::default())]),
        };
        let compiled = Arc::new(CompiledCacheConfig::from_raw(&cfg, "srv_coal").unwrap());

        // Part A: Concurrent cacheable GET -> 1 backend execution, leader MISS + follower COALESCED
        let started = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        let calls = Arc::new(AtomicU64::new(0));

        let started_ref = Arc::clone(&started);
        let release_ref = Arc::clone(&release);
        let calls_ref = Arc::clone(&calls);

        let svc = CacheLayer::new(Arc::clone(&compiled), "srv_coal")
            .with_cache(Arc::clone(&cache))
            .layer(
                tower::service_fn(move |req: Request<SrvBody>| {
                    let st = Arc::clone(&started_ref);
                    let rel = Arc::clone(&release_ref);
                    let cnt = Arc::clone(&calls_ref);
                    async move {
                        let n = cnt.fetch_add(1, Ordering::SeqCst) + 1;
                        if req.uri().path() == "/coalesce" {
                            if n == 1 {
                                st.notify_one();
                                rel.notified().await;
                            }
                            return Ok::<_, SrvError>(text_resp("shared-ok"));
                        }
                        if n == 1 {
                            st.notify_one();
                            rel.notified().await;
                        }
                        Ok(Response::builder()
                            .status(StatusCode::OK)
                            .header(header::CACHE_CONTROL, "no-store")
                            .body(
                                Full::new(Bytes::from(format!("nostore-{n}")))
                                    .map_err(SrvError::from)
                                    .boxed(),
                            )
                            .unwrap())
                    }
                })
                .boxed_clone_sync(),
            );

        let svc1 = svc.clone();
        let h1 = tokio::spawn(async move { svc1.oneshot(empty_req("/coalesce")).await.unwrap() });
        started.notified().await;

        let svc2 = svc.clone();
        let h2 = tokio::spawn(async move { svc2.oneshot(empty_req("/coalesce")).await.unwrap() });
        tokio::task::yield_now().await;
        release.notify_waiters();

        let (r1, r2) = tokio::join!(h1, h2);
        let r1 = r1.unwrap();
        let r2 = r2.unwrap();
        let statuses = [
            r1.headers().get("x-praeco-cache").unwrap().to_str().unwrap().to_string(),
            r2.headers().get("x-praeco-cache").unwrap().to_str().unwrap().to_string(),
        ];
        assert!(statuses.contains(&"MISS".to_string()));
        assert!(statuses.contains(&"COALESCED".to_string()));
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // Part B: Concurrent uncacheable GET (no-store) -> leader gets BYPASS, follower falls back cleanly
        calls.store(0, Ordering::SeqCst);
        let svc3 = svc.clone();
        let h3 = tokio::spawn(async move { svc3.oneshot(empty_req("/nostore")).await.unwrap() });
        started.notified().await;

        let svc4 = svc.clone();
        let h4 = tokio::spawn(async move { svc4.oneshot(empty_req("/nostore")).await.unwrap() });
        tokio::task::yield_now().await;
        release.notify_waiters();

        let (r3, r4) = tokio::join!(h3, h4);
        let r3 = r3.unwrap();
        let r4 = r4.unwrap();
        assert_eq!(r3.headers().get("x-praeco-cache").unwrap(), "BYPASS");
        assert_eq!(r4.headers().get("x-praeco-cache").unwrap(), "BYPASS");
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn test_configure_global_response_cache_preserves_entries_on_same_max_bytes_and_clears_on_change() {
        let key = CacheKey {
            namespace: "reload_test_ns".to_string(),
            method: "GET",
            path_and_query: "/item".to_string(),
            vary_values: vec![],
            scope_key: String::new(),
        };

        let initial_cfg = GlobalCacheConfig {
            enabled: true,
            max_bytes: 2 * 1024 * 1024,
            default_ttl_seconds: 60,
            max_entry_bytes: 64 * 1024,
            respect_cache_control: true,
            expose_cache_header: false,
        };
        configure_global_response_cache(Some(&initial_cfg));
        let c1 = global_response_cache();
        c1.insert(
            key.clone(),
            Arc::new(CachedResponse::new(
                StatusCode::OK,
                HeaderMap::new(),
                Bytes::from_static(b"cached"),
                Duration::from_secs(60),
            )),
        );
        assert!(c1.get(&key).is_some());

        // Reload with same max_bytes preserves cached entry while updating flags
        let same_size_cfg = GlobalCacheConfig {
            expose_cache_header: true,
            ..initial_cfg.clone()
        };
        configure_global_response_cache(Some(&same_size_cfg));
        let c2 = global_response_cache();
        assert!(c2.config().expose_cache_header);
        assert!(c2.get(&key).is_some(), "entries must survive reload with identical max_bytes");

        // Reload with changed max_bytes rebuilds and clears entries
        let resized_cfg = GlobalCacheConfig {
            max_bytes: 4 * 1024 * 1024,
            ..same_size_cfg
        };
        configure_global_response_cache(Some(&resized_cfg));
        let c3 = global_response_cache();
        assert!(c3.get(&key).is_none(), "changing max_bytes must reset cache");

        // Re-insert then disable globally -> clears entries
        c3.insert(
            key.clone(),
            Arc::new(CachedResponse::new(
                StatusCode::OK,
                HeaderMap::new(),
                Bytes::from_static(b"cached2"),
                Duration::from_secs(60),
            )),
        );
        configure_global_response_cache(Some(&GlobalCacheConfig {
            enabled: false,
            ..resized_cfg
        }));
        assert!(global_response_cache().get(&key).is_none());

        // Restore default global cache state for other tests in the process
        configure_global_response_cache(None);
    }
}
