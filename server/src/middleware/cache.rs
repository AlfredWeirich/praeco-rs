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
//!   authentication, RBAC, CORS, and compression layers (`IpFilter`, `PathSanitizer`,
//!   `Inspection`, `Cors`, `JwtAuth`, `Rbac`, `Compression`).
//! - Caching is opt-in per path rule under `[Server.Layers.Cache.rules]`.
//! - Cross-server sharing is controlled explicitly via `namespace` and isolated by
//!   `CacheScope` (`public`, `per_role`, `per_subject`), while RFC 9111 `Vary` response
//!   headers are enforced against `vary_headers`.
//! - Request/response buffering for caching uses bounded total deadlines (`timeout_at`)
//!   and the process-wide router `BufferBudget` (`BufferReservation`).
//! - Responses marked with [`CacheBypass`] (e.g. partially degraded `aggregate` responses
//!   containing `_errors`), `Set-Cookie`, `Cache-Control: no-store`, `Vary: *`, uncovered
//!   `Vary` headers, or payloads larger than `max_entry_bytes` are never stored in the cache.

use std::{
    borrow::Cow,
    collections::VecDeque,
    future::Future,
    hash::Hash,
    pin::Pin,
    sync::{
        Arc, OnceLock,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use arc_swap::ArcSwap;
use async_compression::tokio::bufread::{BrotliEncoder, GzipEncoder};
use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use http_body::{Body as _, Frame};
use http_body_util::{BodyExt, Empty, Full};
use hyper::{
    HeaderMap, Method, Request, Response, StatusCode,
    header::{self, HeaderName, HeaderValue},
};
use moka::{Expiry, sync::Cache};
use pin_project::pin_project;
use sha2::{Digest, Sha256};
use smallvec::SmallVec;
use tokio::{
    io::AsyncReadExt as _,
    sync::{OnceCell, oneshot, watch},
};
use tokio_util::sync::CancellationToken;
use tower::{Layer, Service};

use crate::{
    Claims, SanCertExtension, ServiceRespBody, SrvBody, SrvError,
    configuration::{
        CacheScope, CompiledCacheConfig, CompiledCacheRule, GlobalCacheConfig, ServerMetrics,
    },
    middleware::{
        compression::{accepts_coding, append_vary_accept_encoding},
        path_sanitizer::sanitize_and_normalize_path_cow,
        rbac::extract_user_roles_from_extensions,
        router::{BufferBudget, BufferReservation, BudgetedBytesBody, global_response_buffer_budget},
    },
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

impl<T> Flight<T> {
    /// Atomically attaches a new waiter unless the flight is already cancelled or drained.
    #[inline]
    fn try_acquire_waiter(&self) -> bool {
        if self.cancel_token.is_cancelled() {
            return false;
        }
        let mut w = self.waiters.load(Ordering::Acquire);
        while w > 0 {
            match self.waiters.compare_exchange_weak(
                w,
                w + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(next) => w = next,
            }
        }
        false
    }
}

/// Result of [`Singleflight::work_with_input`], returning unused input to followers.
enum CoalescedResult<T, I> {
    Leader(T),
    Follower(T, I),
}

/// Coordinates concurrent async computations for identical keys `K` so the
/// underlying operation executes only once across concurrent callers.
///
/// Cheaply cloneable (`Arc`-backed), shard-locked via [`DashMap`], and thread-safe.
pub struct Singleflight<K, T> {
    flights: Arc<DashMap<K, Arc<Flight<T>>>>,
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
            flights: Arc::new(DashMap::new()),
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
        //    DashMap shard guards are scoped strictly inside this block and dropped before `.await`.
        let (flight, leader_handle) = if let Some(existing) = self.flights.get(&key)
            && existing.try_acquire_waiter()
        {
            (Arc::clone(&*existing), None)
        } else {
            match self.flights.entry(key.clone()) {
                dashmap::mapref::entry::Entry::Occupied(mut occ) => {
                    if occ.get().try_acquire_waiter() {
                        (Arc::clone(occ.get()), None)
                    } else {
                        let (tx, rx) = watch::channel(None);
                        let cancel_token = CancellationToken::new();

                        let flight = Arc::new(Flight {
                            rx,
                            waiters: AtomicUsize::new(1),
                            cancel_token: cancel_token.clone(),
                        });

                        occ.insert(Arc::clone(&flight));
                        (flight, Some((tx, cancel_token)))
                    }
                }
                dashmap::mapref::entry::Entry::Vacant(vac) => {
                    let (tx, rx) = watch::channel(None);
                    let cancel_token = CancellationToken::new();

                    let flight = Arc::new(Flight {
                        rx,
                        waiters: AtomicUsize::new(1),
                        cancel_token: cancel_token.clone(),
                    });

                    vac.insert(Arc::clone(&flight));
                    (flight, Some((tx, cancel_token)))
                }
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
    flights: Arc<DashMap<K, Arc<Flight<T>>>>,
    key: K,
    flight: Arc<Flight<T>>,
}

impl<K: Eq + Hash, T> Drop for MapCleanupGuard<K, T> {
    fn drop(&mut self) {
        let _ = self
            .flights
            .remove_if(&self.key, |_, current| Arc::ptr_eq(current, &self.flight));
    }
}

// ============================================================================
//  Cache Key, Stored Response & Process-Wide Moka Cache
// ============================================================================

/// Response extension marker inserted by handlers (such as partially degraded
/// `aggregate` routes with `_errors`) to prevent [`CacheLayer`] from storing the response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CacheBypass;

/// Minimum uncompressed body length in bytes required to precompute a compressed variant.
const MIN_PRECOMPRESS_BYTES: usize = 64;

/// Supported precompression encodings cached lazily on [`CachedResponse`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PrecompressAlgo {
    None,
    Gzip,
    Brotli,
}

#[derive(Debug, Clone)]
struct PrecompressedVariant {
    body: Bytes,
    content_length: Option<HeaderValue>,
}

enum PrecompressedLookup<'a> {
    Ready(Option<&'a PrecompressedVariant>),
    NeedsInit,
}

/// Formats a `u64` into a [`HeaderValue`] using a 20-byte stack buffer (zero heap allocation).
#[inline]
fn u64_to_header_value(mut n: u64) -> Option<HeaderValue> {
    if n == 0 {
        return Some(HeaderValue::from_static("0"));
    }
    let mut buf = [0u8; 20];
    let mut idx = buf.len();
    while n > 0 {
        idx -= 1;
        buf[idx] = b'0' + (n % 10) as u8;
        n /= 10;
    }
    HeaderValue::from_bytes(&buf[idx..]).ok()
}

async fn compress_bytes_variant(raw: &Bytes, algo: PrecompressAlgo) -> Option<PrecompressedVariant> {
    if raw.len() < MIN_PRECOMPRESS_BYTES || algo == PrecompressAlgo::None {
        return None;
    }
    let cursor = std::io::Cursor::new(raw.clone());
    let mut out = Vec::with_capacity(raw.len() / 2);
    let res = match algo {
        PrecompressAlgo::Gzip => GzipEncoder::new(cursor).read_to_end(&mut out).await,
        PrecompressAlgo::Brotli => BrotliEncoder::new(cursor).read_to_end(&mut out).await,
        PrecompressAlgo::None => return None,
    };
    if res.is_err() || out.is_empty() || out.len() >= raw.len() {
        return None;
    }
    let compressed = Bytes::from(out);
    let content_length = u64_to_header_value(compressed.len() as u64);
    Some(PrecompressedVariant {
        body: compressed,
        content_length,
    })
}

/// Canonical lookup key for [`SharedResponseCache`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub struct CacheKey {
    /// Logical cache namespace (defaults to the server name or an explicit shared namespace).
    pub namespace: Arc<str>,
    /// Generation fence `(global_generation, namespace_generation)` for O(1) lock-free invalidation.
    pub generation: (u64, u64),
    /// Configured [`CacheScope`] isolation level (`Public`, `PerRole`, `PerSubject`).
    pub scope: CacheScope,
    /// Canonical HTTP method used as the stored slot (`"GET"` for `GET`/`HEAD`, `"POST"` for exact `POST` RPCs).
    pub method: &'static str,
    /// Sanitized path plus lexicographically sorted query parameters.
    pub path_and_query: Arc<str>,
    /// Lowercase header name/value pairs requested via `vary_headers`.
    pub vary_values: SmallVec<[(Arc<str>, String); 2]>,
    /// Isolation scope key (`""` for `public`, sorted roles for `per_role`, issuer+subject for `per_subject`).
    pub scope_key: Arc<str>,
    /// SHA-256 digest of the request body for `POST` requests (`None` for `GET`/`HEAD`).
    pub body_hash: Option<[u8; 32]>,
    /// Normalized `(content-type, content-encoding, grpc-encoding)` tuple for `POST` requests.
    pub post_encoding: Option<(String, String, String)>,
}

/// Cached HTTP / gRPC response stored inside [`SharedResponseCache`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CachedResponse {
    /// Cached HTTP status code.
    pub status: StatusCode,
    /// Cache-safe HTTP headers (stripped of hop-by-hop, `Set-Cookie`, and per-request headers).
    pub headers: HeaderMap,
    /// Buffered uncompressed response body payload.
    pub body: Bytes,
    /// Precomputed `Content-Length` header value for the uncompressed body.
    content_length: Option<HeaderValue>,
    /// Lazily populated precompressed `gzip` variant (shared zero-copy across HITs).
    compressed_gzip: Arc<OnceCell<Option<PrecompressedVariant>>>,
    /// Lazily populated precompressed `br` variant (shared zero-copy across HITs).
    compressed_br: Arc<OnceCell<Option<PrecompressedVariant>>>,
    /// Optional sanitized HTTP/2 trailers (e.g. `grpc-status: 0` for unary gRPC responses).
    pub trailers: Option<HeaderMap>,
    /// Monotonic timestamp when the entry was inserted.
    pub stored_at: Instant,
    /// Effective time-to-live for this entry.
    pub ttl: Duration,
    /// Approximate memory footprint in bytes used by `moka`'s weigher.
    pub byte_weight: u32,
}

impl CachedResponse {
    fn new(
        status: StatusCode,
        headers: HeaderMap,
        body: Bytes,
        trailers: Option<HeaderMap>,
        ttl: Duration,
    ) -> Self {
        let approx_header_bytes: usize = headers
            .iter()
            .map(|(k, v)| k.as_str().len() + v.as_bytes().len() + 16)
            .sum();
        let approx_trailer_bytes: usize = trailers.as_ref().map_or(0, |tr| {
            tr.iter()
                .map(|(k, v)| k.as_str().len() + v.as_bytes().len() + 16)
                .sum()
        });
        let total = body
            .len()
            .saturating_add(approx_header_bytes)
            .saturating_add(approx_trailer_bytes)
            .saturating_add(64);
        let byte_weight = u32::try_from(total.max(1)).unwrap_or(u32::MAX);
        let content_length = u64_to_header_value(body.len() as u64);

        Self {
            status,
            headers,
            body,
            content_length,
            compressed_gzip: Arc::new(OnceCell::new()),
            compressed_br: Arc::new(OnceCell::new()),
            trailers,
            stored_at: Instant::now(),
            ttl,
            byte_weight,
        }
    }

    #[inline]
    fn precompressed_slot(
        &self,
        algo: PrecompressAlgo,
    ) -> Option<&OnceCell<Option<PrecompressedVariant>>> {
        match algo {
            PrecompressAlgo::None => None,
            PrecompressAlgo::Gzip => Some(&self.compressed_gzip),
            PrecompressAlgo::Brotli => Some(&self.compressed_br),
        }
    }

    #[inline]
    fn get_precompressed_sync(&self, algo: PrecompressAlgo) -> PrecompressedLookup<'_> {
        let Some(slot) = self.precompressed_slot(algo) else {
            return PrecompressedLookup::Ready(None);
        };
        match slot.get() {
            Some(opt) => PrecompressedLookup::Ready(opt.as_ref()),
            None => PrecompressedLookup::NeedsInit,
        }
    }

    async fn ensure_precompressed(&self, algo: PrecompressAlgo) -> Option<&PrecompressedVariant> {
        let slot = self.precompressed_slot(algo)?;
        slot.get_or_init(|| compress_bytes_variant(&self.body, algo))
            .await
            .as_ref()
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

/// Outcome broadcast over [`Singleflight`] for a cacheable miss.
#[derive(Clone)]
enum SingleflightOutcome {
    Cached(Arc<CachedResponse>),
    Bypass,
    UpstreamError(String),
}

/// Maximum number of distinct namespaces tracked in [`SharedResponseCache::namespace_generations`].
/// Unknown namespaces beyond this cap fall back to advancing `global_generation` to prevent
/// unbounded `DashMap` growth from arbitrary admin `?namespace=...` queries.
const MAX_TRACKED_NAMESPACES: usize = 4096;

/// Process-wide W-TinyLFU HTTP & gRPC response cache shared across all `[[Server]]` instances.
pub struct SharedResponseCache {
    store: Cache<CacheKey, Arc<CachedResponse>>,
    singleflight: Singleflight<CacheKey, SingleflightOutcome>,
    global_generation: Arc<AtomicU64>,
    namespace_generations: Arc<DashMap<String, AtomicU64>>,
    config: GlobalCacheConfig,
}

impl SharedResponseCache {
    /// Creates a new [`SharedResponseCache`] bounded by `config.max_bytes`.
    pub fn new(config: GlobalCacheConfig) -> Arc<Self> {
        let store = Self::build_store(config.max_bytes);
        Arc::new(Self {
            store,
            singleflight: Singleflight::new(),
            global_generation: Arc::new(AtomicU64::new(0)),
            namespace_generations: Arc::new(DashMap::new()),
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

    /// Returns the current `(global_generation, namespace_generation)` fence token for `namespace`.
    pub fn current_generation(&self, namespace: &str) -> (u64, u64) {
        let global_gen = self.global_generation.load(Ordering::Acquire);
        let ns_gen = self
            .namespace_generations
            .get(namespace)
            .map_or(0, |entry| entry.load(Ordering::Acquire));
        (global_gen, ns_gen)
    }

    /// Looks up an unexpired [`CachedResponse`] by `key`.
    pub fn get(&self, key: &CacheKey) -> Option<Arc<CachedResponse>> {
        if !self.config.enabled {
            return None;
        }
        if key.generation != self.current_generation(&key.namespace) {
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

    /// Inserts `entry` only if no global or namespace invalidation occurred since `expected_generation`.
    pub fn insert_if_generation(
        &self,
        key: CacheKey,
        entry: Arc<CachedResponse>,
        expected_generation: (u64, u64),
    ) -> bool {
        if !self.config.enabled || entry.ttl.is_zero() || key.generation != expected_generation {
            return false;
        }
        if self.current_generation(&key.namespace) != expected_generation {
            return false;
        }
        self.store.insert(key.clone(), entry);
        if self.current_generation(&key.namespace) != expected_generation {
            self.store.invalidate(&key);
            return false;
        }
        true
    }

    /// Discards all cached entries across all namespaces and advances the global generation fence.
    pub fn invalidate_all(&self) {
        self.global_generation.fetch_add(1, Ordering::AcqRel);
        self.store.invalidate_all();
    }

    /// Discards all cached entries belonging to `namespace` in O(1) by advancing its generation fence.
    ///
    /// Because `(global_generation, namespace_generation)` is embedded directly in [`CacheKey`],
    /// bumping the atomic counter immediately obsoletes all cached keys for `namespace` without
    /// registering a Moka predicate closure on reads. Caps tracked namespaces at
    /// [`MAX_TRACKED_NAMESPACES`]; overflow namespaces bump `global_generation` instead.
    pub fn invalidate_namespace(&self, namespace: &str) {
        if let Some(counter) = self.namespace_generations.get(namespace) {
            counter.fetch_add(1, Ordering::AcqRel);
            return;
        }
        if self.namespace_generations.len() < MAX_TRACKED_NAMESPACES {
            self.namespace_generations
                .entry(namespace.to_string())
                .or_insert_with(|| AtomicU64::new(0))
                .fetch_add(1, Ordering::AcqRel);
        } else {
            self.global_generation.fetch_add(1, Ordering::AcqRel);
        }
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

#[inline]
fn global_response_cache_guard() -> arc_swap::Guard<Arc<SharedResponseCache>> {
    global_cache_holder().load()
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
            global_generation: Arc::clone(&current.global_generation),
            namespace_generations: Arc::clone(&current.namespace_generations),
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
    server_name_arc: Arc<str>,
    precompression: bool,
    cache: Option<Arc<SharedResponseCache>>,
}

impl CacheLayer {
    /// Creates a new [`CacheLayer`] bound to the process-wide [`global_response_cache`].
    pub fn new(rules: Arc<CompiledCacheConfig>, server_name: &'static str) -> Self {
        Self {
            rules,
            server_name,
            server_name_arc: Arc::from(server_name),
            precompression: false,
            cache: None,
        }
    }

    /// Overrides the backing [`SharedResponseCache`] (useful for isolated tests or embedded setups).
    pub fn with_cache(mut self, cache: Arc<SharedResponseCache>) -> Self {
        self.cache = Some(cache);
        self
    }

    /// Enables serving and caching lazy precompressed (`gzip`/`br`) variants on [`CachedResponse`]
    /// so outer [`SrvCompressionLayer`](crate::middleware::compression::SrvCompressionLayer) skips
    /// re-compressing cache HITs.
    pub fn with_precompression(mut self, enabled: bool) -> Self {
        self.precompression = enabled;
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
            server_name_arc: Arc::clone(&self.server_name_arc),
            precompression: self.precompression,
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
    server_name_arc: Arc<str>,
    precompression: bool,
    cache: Option<Arc<SharedResponseCache>>,
}

/// Future returned by [`CacheService`].
#[pin_project(project = CacheFutureProj)]
pub enum CacheFuture<F> {
    /// Synchronous L1 cache hit returned without boxing.
    Hit {
        response: Option<Response<ServiceRespBody>>,
    },
    /// Passthrough request (unmatched path, unsupported method, or disabled cache) polling `S::Future` inline.
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
    /// Asynchronous L1 `GET` miss or `POST` RPC lookup/coalescing path.
    Coalesce {
        #[pin]
        fut: Pin<Box<dyn Future<Output = Result<Response<ServiceRespBody>, SrvError>> + Send>>,
    },
    /// Zero-copy mutation passthrough that invalidates target namespaces once the upstream
    /// response completes cleanly (`HTTP 2xx` or gRPC `grpc-status: 0`).
    Invalidate {
        #[pin]
        inner: F,
        cache: Arc<SharedResponseCache>,
        namespaces: Vec<String>,
        server_name: &'static str,
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
            CacheFutureProj::Invalidate {
                inner,
                cache,
                namespaces,
                server_name,
            } => {
                let resp = std::task::ready!(inner.poll(cx))?;
                Poll::Ready(Ok(wrap_invalidation_response(
                    resp,
                    Arc::clone(cache),
                    std::mem::take(namespaces),
                    server_name,
                )))
            }
        }
    }
}

/// Response body that replays cached bytes followed by optional HTTP/2 trailers without altering framing.
#[pin_project]
struct CachedRespBody {
    data: Option<Bytes>,
    trailers: Option<HeaderMap>,
}

impl http_body::Body for CachedRespBody {
    type Data = Bytes;
    type Error = SrvError;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.project();
        if let Some(bytes) = this.data.take()
            && !bytes.is_empty()
        {
            return Poll::Ready(Some(Ok(Frame::data(bytes))));
        }
        if let Some(tr) = this.trailers.take() {
            return Poll::Ready(Some(Ok(Frame::trailers(tr))));
        }
        Poll::Ready(None)
    }

    fn is_end_stream(&self) -> bool {
        self.data.as_ref().is_none_or(Bytes::is_empty) && self.trailers.is_none()
    }
}

/// Zero-copy invalidation trigger mode matching either standard HTTP `2xx` or HTTP/2 gRPC streams.
enum InvalidationMode {
    Http2xx,
    Grpc { saw_grpc_ok: bool },
}

fn trigger_namespace_invalidations(
    cache: &SharedResponseCache,
    namespaces: &[String],
    server_name: &'static str,
) {
    for ns in namespaces {
        cache.invalidate_namespace(ns);
    }
    ServerMetrics::inc_cache_invalidation(server_name);
}

/// Zero-copy body wrapper that triggers namespace invalidation once a mutation response
/// finishes cleanly without transport errors or non-zero `grpc-status` trailers.
#[pin_project]
struct InvalidateOnSuccessBody {
    #[pin]
    inner: ServiceRespBody,
    cache: Arc<SharedResponseCache>,
    namespaces: Vec<String>,
    server_name: &'static str,
    mode: InvalidationMode,
    done: bool,
}

impl http_body::Body for InvalidateOnSuccessBody {
    type Data = Bytes;
    type Error = SrvError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let mut this = self.project();
        match this.inner.as_mut().poll_frame(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(None) => {
                if !*this.done {
                    *this.done = true;
                    let should_invalidate = match this.mode {
                        InvalidationMode::Http2xx => true,
                        InvalidationMode::Grpc { saw_grpc_ok } => *saw_grpc_ok,
                    };
                    if should_invalidate {
                        trigger_namespace_invalidations(
                            this.cache,
                            this.namespaces,
                            this.server_name,
                        );
                    }
                }
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(e))) => {
                *this.done = true;
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(Some(Ok(frame))) => {
                if !*this.done {
                    match this.mode {
                        InvalidationMode::Grpc { saw_grpc_ok } => {
                            if let Some(tr) = frame.trailers_ref() {
                                let ok = grpc_status_is_ok(tr);
                                *this.done = true;
                                if ok {
                                    trigger_namespace_invalidations(
                                        this.cache,
                                        this.namespaces,
                                        this.server_name,
                                    );
                                }
                            } else if *saw_grpc_ok && this.inner.is_end_stream() {
                                *this.done = true;
                                trigger_namespace_invalidations(
                                    this.cache,
                                    this.namespaces,
                                    this.server_name,
                                );
                            }
                        }
                        InvalidationMode::Http2xx => {
                            if let Some(tr) = frame.trailers_ref()
                                && tr.get("grpc-status").is_some()
                                && !grpc_status_is_ok(tr)
                            {
                                *this.done = true;
                            } else if this.inner.is_end_stream() {
                                *this.done = true;
                                trigger_namespace_invalidations(
                                    this.cache,
                                    this.namespaces,
                                    this.server_name,
                                );
                            }
                        }
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
}

fn wrap_invalidation_response(
    resp: Response<ServiceRespBody>,
    cache: Arc<SharedResponseCache>,
    namespaces: Vec<String>,
    server_name: &'static str,
) -> Response<ServiceRespBody> {
    if !resp.status().is_success() || namespaces.is_empty() {
        return resp;
    }

    let headers = resp.headers();
    if let Some(raw_status) = headers.get("grpc-status")
        && raw_status.to_str().ok().map(str::trim) != Some("0")
    {
        return resp;
    }

    let is_grpc = is_header_grpc_content_type(headers);
    let header_grpc_ok = headers
        .get("grpc-status")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        == Some("0");

    if resp.body().is_end_stream() {
        if !is_grpc || header_grpc_ok {
            trigger_namespace_invalidations(&cache, &namespaces, server_name);
        }
        return resp;
    }

    let (parts, body) = resp.into_parts();
    let mode = if is_grpc {
        InvalidationMode::Grpc {
            saw_grpc_ok: header_grpc_ok,
        }
    } else {
        InvalidationMode::Http2xx
    };
    let wrapped = InvalidateOnSuccessBody {
        inner: body,
        cache,
        namespaces,
        server_name,
        mode,
        done: false,
    }
    .boxed();
    Response::from_parts(parts, wrapped)
}

/// Streaming fallback body used when a response exceeds `max_entry_bytes`,
/// budget capacity, or collection deadline mid-stream, seamlessly yielding
/// already-buffered frames before polling the remaining upstream body.
#[pin_project]
struct ChainedStreamBody {
    buffered: VecDeque<Frame<Bytes>>,
    reservation: BufferReservation,
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
            if let Some(data) = frame.data_ref() {
                this.reservation.release(data.len());
            }
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

#[inline]
fn public_scope_key() -> Arc<str> {
    static PUBLIC_KEY: OnceLock<Arc<str>> = OnceLock::new();
    Arc::clone(PUBLIC_KEY.get_or_init(|| Arc::from("")))
}

#[inline]
fn guest_scope_key() -> Arc<str> {
    static GUEST_KEY: OnceLock<Arc<str>> = OnceLock::new();
    Arc::clone(GUEST_KEY.get_or_init(|| Arc::from("Guest")))
}

/// Normalizes a URI path and query string (sorting query pairs lexicographically)
/// so `?a=1&b=2` and `?b=2&a=1` resolve to the same [`CacheKey`].
fn canonical_path_and_query(canonical_path: &str, query: Option<&str>) -> Arc<str> {
    let Some(q) = query.filter(|s| !s.is_empty()) else {
        return Arc::from(canonical_path);
    };

    // Fast-path for a single unencoded `key=value` query pair withoutpercent/plus encoding.
    if !q.contains('&')
        && q.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'='))
        && q.matches('=').count() == 1
    {
        let mut combined = String::with_capacity(canonical_path.len() + 1 + q.len());
        combined.push_str(canonical_path);
        combined.push('?');
        combined.push_str(q);
        return Arc::from(combined);
    }

    let mut pairs: SmallVec<[(Cow<'_, str>, Cow<'_, str>); 8]> =
        url::form_urlencoded::parse(q.as_bytes()).collect();
    if pairs.is_empty() {
        return Arc::from(canonical_path);
    }
    pairs.sort_unstable();
    let mut serializer = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in pairs {
        serializer.append_pair(&k, &v);
    }
    let normalized_query = serializer.finish();
    if normalized_query.is_empty() {
        Arc::from(canonical_path)
    } else {
        let mut combined = String::with_capacity(canonical_path.len() + 1 + normalized_query.len());
        combined.push_str(canonical_path);
        combined.push('?');
        combined.push_str(&normalized_query);
        Arc::from(combined)
    }
}

/// Computes the isolation key for the configured [`CacheScope`].
///
/// Returns `None` for [`CacheScope::PerSubject`] when no verified identity is present,
/// signalling callers to bypass the cache fail-safely.
fn build_scope_key(
    scope: CacheScope,
    extensions: &hyper::http::Extensions,
) -> Option<Arc<str>> {
    match scope {
        CacheScope::Public => Some(public_scope_key()),
        CacheScope::PerRole => {
            let Some(roles_slice) = extract_user_roles_from_extensions(extensions) else {
                return Some(guest_scope_key());
            };
            if roles_slice.is_empty() {
                return Some(guest_scope_key());
            }
            if roles_slice.len() == 1 {
                return Some(Arc::from(roles_slice[0].0.as_str()));
            }
            let mut roles: SmallVec<[&str; 6]> =
                roles_slice.iter().map(|r| r.0.as_str()).collect();
            roles.sort_unstable();
            roles.dedup();
            Some(Arc::from(roles.join(",")))
        }
        CacheScope::PerSubject => {
            if let Some(claims) = extensions.get::<Claims>()
                && !claims.sub.trim().is_empty()
            {
                // Length-prefixed `(iss, sub)` prevents cross-issuer collisions even with delimiter chars.
                return Some(Arc::from(format!(
                    "jwt:{}:{}:{}:{}",
                    claims.iss.len(),
                    claims.iss,
                    claims.sub.len(),
                    claims.sub
                )));
            }
            if let Some(san) = extensions.get::<SanCertExtension>()
                && !san.0.trim().is_empty()
            {
                return Some(Arc::from(format!("san:{}:{}", san.0.len(), san.0)));
            }
            None
        }
    }
}

fn collect_vary_values(
    headers: &HeaderMap,
    vary_headers: &[Arc<str>],
) -> SmallVec<[(Arc<str>, String); 2]> {
    if vary_headers.is_empty() {
        return SmallVec::new();
    }
    vary_headers
        .iter()
        .map(|name| {
            let mut iter = headers
                .get_all(name.as_ref())
                .iter()
                .filter_map(|v| v.to_str().ok())
                .map(str::trim);
            let joined = match iter.next() {
                None => String::new(),
                Some(first) => match iter.next() {
                    None => first.to_string(),
                    Some(second) => {
                        let mut acc = String::with_capacity(first.len() + 1 + second.len());
                        acc.push_str(first);
                        acc.push(',');
                        acc.push_str(second);
                        for next in iter {
                            acc.push(',');
                            acc.push_str(next);
                        }
                        acc
                    }
                },
            };
            (Arc::clone(name), joined)
        })
        .collect()
}

#[inline]
fn negotiate_request_encoding(
    req_headers: &HeaderMap,
    precompression_enabled: bool,
    is_head: bool,
) -> PrecompressAlgo {
    if !precompression_enabled || is_head {
        return PrecompressAlgo::None;
    }
    let Some(accept_encoding) = req_headers
        .get(header::ACCEPT_ENCODING)
        .and_then(|h| h.to_str().ok())
    else {
        return PrecompressAlgo::None;
    };
    if accepts_coding(accept_encoding, "gzip") {
        PrecompressAlgo::Gzip
    } else if accepts_coding(accept_encoding, "br") {
        PrecompressAlgo::Brotli
    } else {
        PrecompressAlgo::None
    }
}

#[inline]
fn entry_eligible_for_precompression(entry: &CachedResponse) -> bool {
    entry.trailers.is_none()
        && entry.body.len() >= MIN_PRECOMPRESS_BYTES
        && !entry.headers.contains_key(header::CONTENT_ENCODING)
        && !is_header_grpc_content_type(&entry.headers)
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
    precompress_algo: PrecompressAlgo,
) -> Response<ServiceRespBody> {
    let is_grpc = is_header_grpc_content_type(&entry.headers);
    let precompressed_variant = if !is_head
        && precompress_algo != PrecompressAlgo::None
        && entry_eligible_for_precompression(entry)
        && let PrecompressedLookup::Ready(opt) = entry.get_precompressed_sync(precompress_algo)
    {
        opt
    } else {
        None
    };

    let (body_bytes, content_length_val, content_encoding_val) =
        if let Some(variant) = precompressed_variant {
            let enc = match precompress_algo {
                PrecompressAlgo::Gzip => Some(HeaderValue::from_static("gzip")),
                PrecompressAlgo::Brotli => Some(HeaderValue::from_static("br")),
                PrecompressAlgo::None => None,
            };
            (variant.body.clone(), variant.content_length.clone(), enc)
        } else {
            (entry.body.clone(), entry.content_length.clone(), None)
        };

    let body: ServiceRespBody = if is_head {
        Empty::<Bytes>::new().map_err(SrvError::from).boxed()
    } else if let Some(ref trailers) = entry.trailers {
        CachedRespBody {
            data: (!body_bytes.is_empty()).then_some(body_bytes),
            trailers: Some(trailers.clone()),
        }
        .boxed()
    } else {
        Full::new(body_bytes).map_err(SrvError::from).boxed()
    };

    let mut resp = crate::build_infallible_response(entry.status, None, body);
    for (name, val) in entry.headers.iter() {
        resp.headers_mut().append(name.clone(), val.clone());
    }
    if let Some(enc_val) = content_encoding_val {
        resp.headers_mut().insert(header::CONTENT_ENCODING, enc_val);
        append_vary_accept_encoding(resp.headers_mut());
    }
    if entry.trailers.is_none()
        && !is_grpc
        && let Some(cl) = content_length_val
    {
        resp.headers_mut().insert(header::CONTENT_LENGTH, cl);
    }
    if expose_cache_header {
        attach_cache_status_header(&mut resp, outcome_label);
        let age_secs = entry.stored_at.elapsed().as_secs();
        if let Some(age_val) = u64_to_header_value(age_secs) {
            resp.headers_mut().insert(header::AGE, age_val);
        }
    }
    resp
}

#[inline]
fn is_header_grpc_content_type(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(crate::is_grpc_content_type)
}

#[inline]
fn is_header_grpc_web_binary(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| {
            let media = ct.split(';').next().unwrap_or(ct).trim();
            media.eq_ignore_ascii_case("application/grpc-web")
                || (media.len() > "application/grpc-web+".len()
                    && media[.."application/grpc-web+".len()]
                        .eq_ignore_ascii_case("application/grpc-web+")
                    && !media.eq_ignore_ascii_case("application/grpc-web-text"))
        })
}

#[inline]
fn is_header_grpc_web_text(headers: &HeaderMap) -> bool {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|ct| {
            let media = ct.split(';').next().unwrap_or(ct).trim();
            media.eq_ignore_ascii_case("application/grpc-web-text")
                || (media.len() > "application/grpc-web-text+".len()
                    && media[.."application/grpc-web-text+".len()]
                        .eq_ignore_ascii_case("application/grpc-web-text+"))
        })
}

#[inline]
fn grpc_status_is_ok(headers: &HeaderMap) -> bool {
    headers
        .get("grpc-status")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        == Some("0")
}

fn extract_post_encoding(headers: &HeaderMap) -> (String, String, String) {
    let norm = |name: &str| -> String {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_ascii_lowercase())
            .unwrap_or_default()
    };
    (norm("content-type"), norm("content-encoding"), norm("grpc-encoding"))
}

/// Validates binary `application/grpc-web` length-prefixed frames and ensures at least
/// one embedded trailer frame (`flag & 0x80 != 0`) is present and reports `grpc-status: 0`.
fn grpc_web_body_has_error(body: &[u8]) -> bool {
    let mut offset = 0usize;
    let mut saw_ok_trailer = false;
    while offset < body.len() {
        let Some(header_slice) = body.get(offset..offset + 5) else {
            return true;
        };
        let flag = header_slice[0];
        let frame_len = u32::from_be_bytes([
            header_slice[1],
            header_slice[2],
            header_slice[3],
            header_slice[4],
        ]) as usize;
        let payload_start = offset + 5;
        let Some(payload_end) = payload_start.checked_add(frame_len) else {
            return true;
        };
        let Some(payload) = body.get(payload_start..payload_end) else {
            return true;
        };
        if (flag & 0x80) != 0 {
            let Ok(text) = std::str::from_utf8(payload) else {
                return true;
            };
            let mut found_status = None;
            for line in text.lines() {
                let trimmed = line.trim();
                if let Some((k, v)) = trimmed.split_once(':')
                    && k.trim().eq_ignore_ascii_case("grpc-status")
                {
                    found_status = Some(v.trim());
                }
            }
            if found_status != Some("0") {
                return true;
            }
            saw_ok_trailer = true;
        }
        offset = payload_end;
    }
    !saw_ok_trailer
}

fn has_non_identity_content_encoding(headers: &HeaderMap) -> bool {
    headers.get_all(header::CONTENT_ENCODING).iter().any(|val| {
        let Ok(raw) = val.to_str() else {
            return true;
        };
        raw.split(',')
            .map(str::trim)
            .filter(|tok| !tok.is_empty())
            .any(|tok| !tok.eq_ignore_ascii_case("identity"))
    })
}

/// Enforces RFC 9111 §4.1 response `Vary` rules: `Vary: *` is never cacheable, and any
/// nominated header must be covered by the rule's `vary_headers` (with `Accept-Encoding`
/// allowed automatically only when the cached payload is not already `Content-Encoding`-encoded).
fn response_vary_is_cacheable(headers: &HeaderMap, rule: &CompiledCacheRule) -> bool {
    for val in headers.get_all(header::VARY) {
        let Ok(raw) = val.to_str() else {
            return false;
        };
        for token in raw.split(',').map(str::trim).filter(|t| !t.is_empty()) {
            if token == "*" {
                return false;
            }
            if rule
                .vary_headers
                .iter()
                .any(|vh| vh.eq_ignore_ascii_case(token))
            {
                continue;
            }
            if token.eq_ignore_ascii_case("accept-encoding")
                && !has_non_identity_content_encoding(headers)
            {
                continue;
            }
            return false;
        }
    }
    true
}

/// Evaluates response status and headers to determine whether the response may be cached
/// and computes its effective TTL. Returns `None` if the response must bypass the cache.
fn evaluate_response_cacheability(
    resp: &Response<ServiceRespBody>,
    rule: &CompiledCacheRule,
    global_cfg: &GlobalCacheConfig,
    respect_cache_control: bool,
    max_entry_bytes: usize,
    is_post: bool,
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
    if is_header_grpc_content_type(headers) && !is_post {
        return None;
    }
    if is_header_grpc_web_text(headers) {
        return None;
    }
    if let Some(raw_grpc_status) = headers.get("grpc-status")
        && raw_grpc_status.to_str().ok().map(str::trim) != Some("0")
    {
        return None;
    }
    if !response_vary_is_cacheable(headers, rule) {
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

const POST_BODY_READ_TIMEOUT: Duration = Duration::from_secs(5);
const RESPONSE_BODY_COLLECT_TIMEOUT: Duration = Duration::from_secs(10);
const GRPC_UNARY_EOF_GRACE: Duration = Duration::from_millis(10);
const GRPC_RESP_TRAILER_TIMEOUT: Duration = Duration::from_millis(250);

enum PostReqBody {
    Buffered(Bytes, BufferReservation),
    Bypass(SrvBody),
}

fn spill_accumulated_stream(
    accumulated: BytesMut,
    extra_frames: Vec<Frame<Bytes>>,
    rest: SrvBody,
    reservation: BufferReservation,
) -> SrvBody {
    let mut buffered = VecDeque::with_capacity(extra_frames.len() + 1);
    if !accumulated.is_empty() {
        buffered.push_back(Frame::data(accumulated.freeze()));
    }
    for frame in extra_frames {
        buffered.push_back(frame);
    }
    ChainedStreamBody {
        buffered,
        reservation,
        rest,
        rest_done: false,
    }
    .boxed()
}

/// Reads at most `max_bytes` from a `POST` request body for SHA-256 cache-key computation.
///
/// Enforces a fixed total deadline (`timeout_at`) and incremental reservations against the
/// process-wide `BufferBudget`. For native HTTP/2 gRPC (`is_grpc = true`), validates that
/// exactly one 5-byte length-prefixed gRPC message is followed by `EOF` (bounded by
/// [`GRPC_UNARY_EOF_GRACE`]), spilling client-streaming, slow, or oversized requests into
/// [`PostReqBody::Bypass`] without stalling or losing frames.
async fn read_post_request_body(
    body: SrvBody,
    max_bytes: usize,
    is_grpc: bool,
) -> Result<PostReqBody, SrvError> {
    read_post_request_body_with_limits(
        body,
        max_bytes,
        is_grpc,
        POST_BODY_READ_TIMEOUT,
        global_response_buffer_budget(),
    )
    .await
}

async fn read_post_request_body_with_limits(
    mut body: SrvBody,
    max_bytes: usize,
    is_grpc: bool,
    timeout_dur: Duration,
    budget: &Arc<BufferBudget>,
) -> Result<PostReqBody, SrvError> {
    let deadline = tokio::time::Instant::now() + timeout_dur;
    let mut reservation = BufferReservation::new(Arc::clone(budget));
    let mut accumulated = BytesMut::new();

    loop {
        if is_grpc && accumulated.len() >= 5 {
            if accumulated[0] > 1 {
                return Ok(PostReqBody::Bypass(spill_accumulated_stream(
                    accumulated,
                    Vec::new(),
                    body,
                    reservation,
                )));
            }
            let msg_len = u32::from_be_bytes([
                accumulated[1],
                accumulated[2],
                accumulated[3],
                accumulated[4],
            ]) as usize;
            let frame_end = 5usize.saturating_add(msg_len);
            if frame_end > max_bytes || accumulated.len() > frame_end {
                return Ok(PostReqBody::Bypass(spill_accumulated_stream(
                    accumulated,
                    Vec::new(),
                    body,
                    reservation,
                )));
            }
            if accumulated.len() == frame_end {
                if body.is_end_stream() {
                    return Ok(PostReqBody::Buffered(accumulated.freeze(), reservation));
                }
                let grace_deadline =
                    (tokio::time::Instant::now() + GRPC_UNARY_EOF_GRACE).min(deadline);
                loop {
                    match tokio::time::timeout_at(grace_deadline, body.frame()).await {
                        Ok(None) => {
                            return Ok(PostReqBody::Buffered(accumulated.freeze(), reservation));
                        }
                        Ok(Some(Err(e))) => return Err(e),
                        Ok(Some(Ok(extra))) => {
                            if extra.data_ref().is_some_and(Bytes::is_empty) {
                                continue;
                            }
                            return Ok(PostReqBody::Bypass(spill_accumulated_stream(
                                accumulated,
                                vec![extra],
                                body,
                                reservation,
                            )));
                        }
                        Err(_elapsed) => {
                            return Ok(PostReqBody::Bypass(spill_accumulated_stream(
                                accumulated,
                                Vec::new(),
                                body,
                                reservation,
                            )));
                        }
                    }
                }
            }
        }

        match tokio::time::timeout_at(deadline, body.frame()).await {
            Err(_elapsed) => {
                return Ok(PostReqBody::Bypass(spill_accumulated_stream(
                    accumulated,
                    Vec::new(),
                    body,
                    reservation,
                )));
            }
            Ok(None) => {
                if is_grpc {
                    let valid_unary = accumulated.len() >= 5
                        && accumulated[0] <= 1
                        && 5usize.saturating_add(u32::from_be_bytes([
                            accumulated[1],
                            accumulated[2],
                            accumulated[3],
                            accumulated[4],
                        ]) as usize)
                            == accumulated.len();
                    if !valid_unary {
                        return Ok(PostReqBody::Bypass(
                            BudgetedBytesBody::new(accumulated.freeze(), reservation).boxed(),
                        ));
                    }
                }
                return Ok(PostReqBody::Buffered(accumulated.freeze(), reservation));
            }
            Ok(Some(Err(e))) => return Err(e),
            Ok(Some(Ok(frame))) => match frame.into_data() {
                Ok(data) => {
                    if accumulated.len().saturating_add(data.len()) > max_bytes
                        || !reservation.try_reserve(data.len())
                    {
                        return Ok(PostReqBody::Bypass(spill_accumulated_stream(
                            accumulated,
                            vec![Frame::data(data)],
                            body,
                            reservation,
                        )));
                    }
                    accumulated.extend_from_slice(&data);
                }
                Err(non_data_frame) => {
                    return Ok(PostReqBody::Bypass(spill_accumulated_stream(
                        accumulated,
                        vec![non_data_frame],
                        body,
                        reservation,
                    )));
                }
            },
        }
    }
}

enum CollectedResponse {
    Cacheable {
        body: Bytes,
        trailers: Option<HeaderMap>,
    },
    Bypass {
        buffered: VecDeque<Frame<Bytes>>,
        reservation: BufferReservation,
        rest: SrvBody,
    },
}

fn empty_srv_body() -> SrvBody {
    Empty::<Bytes>::new().map_err(SrvError::from).boxed()
}

fn bypass_with_accumulated(
    accumulated: BytesMut,
    extra_frames: Vec<Frame<Bytes>>,
    rest: SrvBody,
    reservation: BufferReservation,
) -> CollectedResponse {
    let mut buffered = VecDeque::with_capacity(extra_frames.len() + 1);
    if !accumulated.is_empty() {
        buffered.push_back(Frame::data(accumulated.freeze()));
    }
    for f in extra_frames {
        buffered.push_back(f);
    }
    CollectedResponse::Bypass {
        buffered,
        reservation,
        rest,
    }
}

/// Collects a cacheable HTTP/JSON or unary gRPC response body (and HTTP/2 `grpc-status: 0`
/// trailers when `content-type` is `application/grpc*`), bounded by a total wall-clock
/// deadline and the global [`BufferBudget`], spilling seamlessly to streaming bypass on
/// timeout, budget exhaustion, oversized payloads, multi-frame server streams, or non-zero
/// `grpc-status`.
async fn collect_response_for_cache(
    resp_headers: &HeaderMap,
    body: SrvBody,
    max_entry_bytes: usize,
) -> Result<CollectedResponse, SrvError> {
    collect_response_for_cache_with_limits(
        resp_headers,
        body,
        max_entry_bytes,
        RESPONSE_BODY_COLLECT_TIMEOUT,
        global_response_buffer_budget(),
    )
    .await
}

async fn collect_response_for_cache_with_limits(
    resp_headers: &HeaderMap,
    mut body: SrvBody,
    max_entry_bytes: usize,
    timeout_dur: Duration,
    budget: &Arc<BufferBudget>,
) -> Result<CollectedResponse, SrvError> {
    let deadline = tokio::time::Instant::now() + timeout_dur;
    let mut reservation = BufferReservation::new(Arc::clone(budget));

    if is_header_grpc_content_type(resp_headers) {
        let header_grpc_ok = grpc_status_is_ok(resp_headers);
        let mut accumulated = BytesMut::new();

        loop {
            if accumulated.len() >= 5 {
                if accumulated[0] > 1 {
                    return Ok(bypass_with_accumulated(
                        accumulated,
                        Vec::new(),
                        body,
                        reservation,
                    ));
                }
                let msg_len = u32::from_be_bytes([
                    accumulated[1],
                    accumulated[2],
                    accumulated[3],
                    accumulated[4],
                ]) as usize;
                let frame_end = 5usize.saturating_add(msg_len);
                if frame_end > max_entry_bytes || accumulated.len() > frame_end {
                    return Ok(bypass_with_accumulated(
                        accumulated,
                        Vec::new(),
                        body,
                        reservation,
                    ));
                }
                if accumulated.len() == frame_end {
                    if body.is_end_stream() {
                        if header_grpc_ok {
                            return Ok(CollectedResponse::Cacheable {
                                body: accumulated.freeze(),
                                trailers: None,
                            });
                        }
                        return Ok(bypass_with_accumulated(
                            accumulated,
                            Vec::new(),
                            body,
                            reservation,
                        ));
                    }
                    let trailer_deadline =
                        (tokio::time::Instant::now() + GRPC_RESP_TRAILER_TIMEOUT).min(deadline);
                    loop {
                        match tokio::time::timeout_at(trailer_deadline, body.frame()).await {
                            Ok(Some(Err(e))) => return Err(e),
                            Ok(Some(Ok(frame))) => {
                                if frame.data_ref().is_some_and(Bytes::is_empty) {
                                    continue;
                                }
                                if frame.is_trailers() {
                                    let Ok(tr) = frame.into_trailers() else {
                                        return Ok(bypass_with_accumulated(
                                            accumulated,
                                            Vec::new(),
                                            body,
                                            reservation,
                                        ));
                                    };
                                    if grpc_status_is_ok(&tr) {
                                        return Ok(CollectedResponse::Cacheable {
                                            body: accumulated.freeze(),
                                            trailers: Some(sanitize_response_headers(&tr)),
                                        });
                                    }
                                    return Ok(bypass_with_accumulated(
                                        accumulated,
                                        vec![Frame::trailers(tr)],
                                        body,
                                        reservation,
                                    ));
                                }
                                // 2nd message frame -> server streaming response, bypass immediately
                                return Ok(bypass_with_accumulated(
                                    accumulated,
                                    vec![frame],
                                    body,
                                    reservation,
                                ));
                            }
                            Ok(None) => {
                                if header_grpc_ok {
                                    return Ok(CollectedResponse::Cacheable {
                                        body: accumulated.freeze(),
                                        trailers: None,
                                    });
                                }
                                return Ok(bypass_with_accumulated(
                                    accumulated,
                                    Vec::new(),
                                    body,
                                    reservation,
                                ));
                            }
                            Err(_elapsed) => {
                                return Ok(bypass_with_accumulated(
                                    accumulated,
                                    Vec::new(),
                                    body,
                                    reservation,
                                ));
                            }
                        }
                    }
                }
            }

            match tokio::time::timeout_at(deadline, body.frame()).await {
                Err(_elapsed) => {
                    return Ok(bypass_with_accumulated(
                        accumulated,
                        Vec::new(),
                        body,
                        reservation,
                    ));
                }
                Ok(None) => {
                    if accumulated.is_empty() && header_grpc_ok {
                        return Ok(CollectedResponse::Cacheable {
                            body: Bytes::new(),
                            trailers: None,
                        });
                    }
                    return Ok(bypass_with_accumulated(
                        accumulated,
                        Vec::new(),
                        empty_srv_body(),
                        reservation,
                    ));
                }
                Ok(Some(Err(e))) => return Err(e),
                Ok(Some(Ok(frame))) => {
                    if frame.is_trailers() {
                        let Ok(tr) = frame.into_trailers() else {
                            return Ok(bypass_with_accumulated(
                                accumulated,
                                Vec::new(),
                                body,
                                reservation,
                            ));
                        };
                        if accumulated.is_empty() && grpc_status_is_ok(&tr) {
                            return Ok(CollectedResponse::Cacheable {
                                body: Bytes::new(),
                                trailers: Some(sanitize_response_headers(&tr)),
                            });
                        }
                        return Ok(bypass_with_accumulated(
                            accumulated,
                            vec![Frame::trailers(tr)],
                            body,
                            reservation,
                        ));
                    }
                    match frame.into_data() {
                        Ok(data) => {
                            if accumulated.len().saturating_add(data.len()) > max_entry_bytes
                                || !reservation.try_reserve(data.len())
                            {
                                return Ok(bypass_with_accumulated(
                                    accumulated,
                                    vec![Frame::data(data)],
                                    body,
                                    reservation,
                                ));
                            }
                            accumulated.extend_from_slice(&data);
                        }
                        Err(other) => {
                            return Ok(bypass_with_accumulated(
                                accumulated,
                                vec![other],
                                body,
                                reservation,
                            ));
                        }
                    }
                }
            }
        }
    }

    // Standard HTTP / JSON / gRPC-Web response buffering up to `max_entry_bytes`
    let mut frames: VecDeque<Frame<Bytes>> = VecDeque::new();
    let mut total_bytes: usize = 0;

    loop {
        let frame = match tokio::time::timeout_at(deadline, body.frame()).await {
            Ok(Some(Ok(frame))) => frame,
            Ok(Some(Err(e))) => return Err(e),
            Ok(None) => break,
            Err(_elapsed) => {
                return Ok(CollectedResponse::Bypass {
                    buffered: frames,
                    reservation,
                    rest: body,
                });
            }
        };
        if let Some(data) = frame.data_ref() {
            let next_total = total_bytes.saturating_add(data.len());
            if next_total > max_entry_bytes || !reservation.try_reserve(data.len()) {
                frames.push_back(frame);
                return Ok(CollectedResponse::Bypass {
                    buffered: frames,
                    reservation,
                    rest: body,
                });
            }
            total_bytes = next_total;
            frames.push_back(frame);
        } else {
            frames.push_back(frame);
            return Ok(CollectedResponse::Bypass {
                buffered: frames,
                reservation,
                rest: body,
            });
        }
    }

    let bytes = if frames.len() == 1
        && let Some(only) = frames.pop_front()
        && let Ok(single) = only.into_data()
    {
        single
    } else {
        let mut out = BytesMut::with_capacity(total_bytes);
        for frame in frames {
            if let Ok(chunk) = frame.into_data() {
                out.extend_from_slice(&chunk);
            }
        }
        out.freeze()
    };

    if is_header_grpc_web_binary(resp_headers) && grpc_web_body_has_error(&bytes) {
        return Ok(CollectedResponse::Bypass {
            buffered: VecDeque::from([Frame::data(bytes)]),
            reservation,
            rest: empty_srv_body(),
        });
    }

    Ok(CollectedResponse::Cacheable {
        body: bytes,
        trailers: None,
    })
}

/// Drives `poll_ready` to completion before invoking `call` on a cloned inner [`Service`].
async fn ready_and_call<S>(
    svc: &mut S,
    req: Request<SrvBody>,
) -> Result<Response<ServiceRespBody>, SrvError>
where
    S: Service<Request<SrvBody>, Response = Response<ServiceRespBody>, Error = SrvError>,
{
    std::future::poll_fn(|cx| svc.poll_ready(cx)).await?;
    svc.call(req).await
}

struct CoalesceContext {
    cache: Arc<SharedResponseCache>,
    key: CacheKey,
    rule: CompiledCacheRule,
    global_cfg: GlobalCacheConfig,
    server_name: &'static str,
    expose_cache_header: bool,
    respect_cache_control: bool,
    max_entry_bytes: usize,
    precompress_algo: PrecompressAlgo,
    is_post: bool,
}

async fn coalesce_and_execute<S>(
    ctx: CoalesceContext,
    req: Request<SrvBody>,
    mut inner: S,
) -> Result<Response<ServiceRespBody>, SrvError>
where
    S: Service<Request<SrvBody>, Response = Response<ServiceRespBody>, Error = SrvError>
        + Clone
        + Send
        + 'static,
    S::Future: Send + 'static,
{
    let CoalesceContext {
        cache,
        key,
        rule,
        global_cfg,
        server_name,
        expose_cache_header,
        respect_cache_control,
        max_entry_bytes,
        precompress_algo,
        is_post,
    } = ctx;

    let (direct_tx, mut direct_rx) = oneshot::channel::<Response<ServiceRespBody>>();
    let cache_for_worker = Arc::clone(&cache);
    let key_for_worker = key.clone();
    let rule_for_worker = rule;
    let global_cfg_for_worker = global_cfg;
    let mut inner_for_worker = inner.clone();

    let coalesced = cache
        .singleflight
        .work_with_input(key, req, move |leader_req| async move {
            let gen_before = key_for_worker.generation;
            let resp = match ready_and_call(&mut inner_for_worker, leader_req).await {
                Ok(r) => r,
                Err(e) => return SingleflightOutcome::UpstreamError(e.to_string()),
            };

            let Some(ttl) = evaluate_response_cacheability(
                &resp,
                &rule_for_worker,
                &global_cfg_for_worker,
                respect_cache_control,
                max_entry_bytes,
                is_post,
            ) else {
                let _ = direct_tx.send(resp);
                return SingleflightOutcome::Bypass;
            };

            let (parts, body) = resp.into_parts();
            match collect_response_for_cache(&parts.headers, body, max_entry_bytes).await {
                Ok(CollectedResponse::Cacheable { body, trailers }) => {
                    let clean_headers = sanitize_response_headers(&parts.headers);
                    let entry = Arc::new(CachedResponse::new(
                        parts.status,
                        clean_headers,
                        body,
                        trailers,
                        ttl,
                    ));
                    if precompress_algo != PrecompressAlgo::None
                        && entry_eligible_for_precompression(&entry)
                    {
                        entry.ensure_precompressed(precompress_algo).await;
                    }
                    let _ = cache_for_worker.insert_if_generation(
                        key_for_worker,
                        Arc::clone(&entry),
                        gen_before,
                    );
                    SingleflightOutcome::Cached(entry)
                }
                Ok(CollectedResponse::Bypass {
                    buffered,
                    reservation,
                    rest,
                }) => {
                    let chained = ChainedStreamBody {
                        buffered,
                        reservation,
                        rest,
                        rest_done: false,
                    }
                    .boxed();
                    let mut rebuilt = Response::from_parts(parts, chained);
                    if !is_header_grpc_content_type(rebuilt.headers()) {
                        rebuilt.headers_mut().remove(header::CONTENT_LENGTH);
                    }
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
                precompress_algo,
            ))
        }
        CoalescedResult::Follower(SingleflightOutcome::Cached(entry), _unused_req) => {
            if precompress_algo != PrecompressAlgo::None
                && entry_eligible_for_precompression(&entry)
            {
                entry.ensure_precompressed(precompress_algo).await;
            }
            ServerMetrics::inc_cache_coalesced(server_name);
            Ok(build_response_from_cached(
                &entry,
                false,
                expose_cache_header,
                "COALESCED",
                precompress_algo,
            ))
        }
        CoalescedResult::Leader(SingleflightOutcome::Bypass) => {
            ServerMetrics::inc_cache_bypass(server_name);
            let mut resp = direct_rx
                .try_recv()
                .map_err(|_| SrvError::Other("Cache leader bypass response channel closed".into()))?;
            if expose_cache_header {
                attach_cache_status_header(&mut resp, "BYPASS");
            }
            Ok(resp)
        }
        CoalescedResult::Follower(SingleflightOutcome::Bypass, follower_req) => {
            ServerMetrics::inc_cache_bypass(server_name);
            let mut resp = ready_and_call(&mut inner, follower_req).await?;
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
        if !matches!(
            *method,
            Method::GET | Method::HEAD | Method::POST | Method::PUT | Method::PATCH | Method::DELETE
        ) {
            return CacheFuture::Passthrough {
                inner: self.inner.call(req),
            };
        }

        let guard = if self.cache.is_none() {
            Some(global_response_cache_guard())
        } else {
            None
        };
        let cache: &Arc<SharedResponseCache> = match (&self.cache, &guard) {
            (Some(c), _) => c,
            (None, Some(g)) => g,
            (None, None) => unreachable!(),
        };
        let global_cfg = cache.config();
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
            if matches!(
                *method,
                Method::POST | Method::PUT | Method::PATCH | Method::DELETE
            ) {
                let body = Full::new(Bytes::from_static(b"Bad Request: invalid path"))
                    .map_err(SrvError::from)
                    .boxed();
                return CacheFuture::Hit {
                    response: Some(crate::build_infallible_response(
                        StatusCode::BAD_REQUEST,
                        None,
                        body,
                    )),
                };
            }
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

        let matched_rule = if matches!(*method, Method::GET | Method::HEAD | Method::POST) {
            self.rules
                .match_request(method.as_str(), &canonical_path)
                .or_else(|| {
                    (*method == Method::HEAD)
                        .then(|| self.rules.match_request("GET", &canonical_path))
                        .flatten()
                })
        } else {
            None
        };

        let Some(rule) = matched_rule else {
            if matches!(
                *method,
                Method::POST | Method::PUT | Method::PATCH | Method::DELETE
            ) && let Some(namespaces) = self
                .rules
                .match_invalidations(method.as_str(), &canonical_path)
            {
                return CacheFuture::Invalidate {
                    inner: self.inner.call(req),
                    cache: Arc::clone(cache),
                    namespaces: namespaces.to_vec(),
                    server_name: self.server_name,
                };
            }
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

        let namespace: Arc<str> = rule
            .namespace_arc
            .as_ref()
            .or(self.rules.default_namespace_arc.as_ref())
            .map_or_else(|| Arc::clone(&self.server_name_arc), Arc::clone);

        if *method == Method::POST {
            let max_req_bytes = rule
                .max_request_body_bytes
                .unwrap_or(global_cfg.max_request_body_bytes)
                .min(global_cfg.max_request_body_bytes);

            if let Some(cl) = req
                .headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<usize>().ok())
                && cl > max_req_bytes
            {
                ServerMetrics::inc_cache_bypass(server_name);
                return CacheFuture::Bypass {
                    inner: self.inner.call(req),
                    expose_cache_header,
                };
            }

            let path_and_query = canonical_path_and_query(&canonical_path, req.uri().query());
            let vary_values = collect_vary_values(req.headers(), &rule.vary_headers_arc);
            let post_encoding = extract_post_encoding(req.headers());
            let is_grpc_req = is_header_grpc_content_type(req.headers());
            let precompress_algo =
                negotiate_request_encoding(req.headers(), self.precompression, false);
            let rule_cloned = rule.clone();
            let global_cfg_cloned = global_cfg.clone();
            let cache_cloned = Arc::clone(cache);
            let scope = rule.scope;
            let mut inner = self.inner.clone();

            return CacheFuture::Coalesce {
                fut: Box::pin(async move {
                    let (req_parts, req_body) = req.into_parts();
                    let (req_bytes, req_reservation) = match read_post_request_body(
                        req_body,
                        max_req_bytes,
                        is_grpc_req,
                    )
                    .await?
                    {
                        PostReqBody::Buffered(bytes, reservation) => (bytes, reservation),
                        PostReqBody::Bypass(bypass_body) => {
                            ServerMetrics::inc_cache_bypass(server_name);
                            let rebuilt_req = Request::from_parts(req_parts, bypass_body);
                            let mut resp = ready_and_call(&mut inner, rebuilt_req).await?;
                            if expose_cache_header {
                                attach_cache_status_header(&mut resp, "BYPASS");
                            }
                            return Ok(resp);
                        }
                    };

                    let generation = cache_cloned.current_generation(&namespace);
                    let digest: [u8; 32] = Sha256::digest(&req_bytes).into();
                    let key = CacheKey {
                        namespace,
                        generation,
                        scope,
                        method: "POST",
                        path_and_query,
                        vary_values,
                        scope_key,
                        body_hash: Some(digest),
                        post_encoding: Some(post_encoding),
                    };

                    if let Some(entry) = cache_cloned.get(&key) {
                        drop(req_reservation);
                        if precompress_algo != PrecompressAlgo::None
                            && entry_eligible_for_precompression(&entry)
                        {
                            entry.ensure_precompressed(precompress_algo).await;
                        }
                        ServerMetrics::inc_cache_hit(server_name);
                        return Ok(build_response_from_cached(
                            &entry,
                            false,
                            expose_cache_header,
                            "HIT",
                            precompress_algo,
                        ));
                    }

                    let rebuilt_body = BudgetedBytesBody::new(req_bytes, req_reservation).boxed();
                    let rebuilt_req = Request::from_parts(req_parts, rebuilt_body);
                    coalesce_and_execute(
                        CoalesceContext {
                            cache: cache_cloned,
                            key,
                            rule: rule_cloned,
                            global_cfg: global_cfg_cloned,
                            server_name,
                            expose_cache_header,
                            respect_cache_control,
                            max_entry_bytes,
                            precompress_algo,
                            is_post: true,
                        },
                        rebuilt_req,
                        inner,
                    )
                    .await
                }),
            };
        }

        let generation = cache.current_generation(&namespace);
        let key = CacheKey {
            namespace,
            generation,
            scope: rule.scope,
            method: "GET",
            path_and_query: canonical_path_and_query(&canonical_path, req.uri().query()),
            vary_values: collect_vary_values(req.headers(), &rule.vary_headers_arc),
            scope_key,
            body_hash: None,
            post_encoding: None,
        };

        let is_head = *method == Method::HEAD;
        let precompress_algo =
            negotiate_request_encoding(req.headers(), self.precompression, is_head);

        // Synchronous L1 hit fast-path
        if let Some(entry) = cache.get(&key) {
            let ready_sync = if !is_head
                && precompress_algo != PrecompressAlgo::None
                && entry_eligible_for_precompression(&entry)
            {
                !matches!(
                    entry.get_precompressed_sync(precompress_algo),
                    PrecompressedLookup::NeedsInit
                )
            } else {
                true
            };
            if ready_sync {
                ServerMetrics::inc_cache_hit(server_name);
                let resp = build_response_from_cached(
                    &entry,
                    is_head,
                    expose_cache_header,
                    "HIT",
                    precompress_algo,
                );
                return CacheFuture::Hit {
                    response: Some(resp),
                };
            }
            return CacheFuture::Coalesce {
                fut: Box::pin(async move {
                    entry.ensure_precompressed(precompress_algo).await;
                    ServerMetrics::inc_cache_hit(server_name);
                    Ok(build_response_from_cached(
                        &entry,
                        false,
                        expose_cache_header,
                        "HIT",
                        precompress_algo,
                    ))
                }),
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
        let rule_cloned = rule.clone();
        let global_cfg_cloned = global_cfg.clone();
        let cache_cloned = Arc::clone(cache);
        let inner = self.inner.clone();
        CacheFuture::Coalesce {
            fut: Box::pin(coalesce_and_execute(
                CoalesceContext {
                    cache: cache_cloned,
                    key,
                    rule: rule_cloned,
                    global_cfg: global_cfg_cloned,
                    server_name,
                    expose_cache_header,
                    respect_cache_control,
                    max_entry_bytes,
                    precompress_algo,
                    is_post: false,
                },
                req,
                inner,
            )),
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
    use std::collections::HashMap;
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
        });

        let cfg = CacheLayerConfig {
            namespace: None,
            rules: HashMap::from([("/*".to_string(), CacheRuleConfig::default())]),
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
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
            ..Default::default()
        });

        let cfg = CacheLayerConfig {
            namespace: None,
            rules: HashMap::from([("/*".to_string(), CacheRuleConfig::default())]),
            ..Default::default()
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
            namespace: Arc::from("reload_test_ns"),
            generation: (0, 0),
            scope: CacheScope::Public,
            method: "GET",
            path_and_query: Arc::from("/item"),
            vary_values: SmallVec::new(),
            scope_key: Arc::from(""),
            body_hash: None,
            post_encoding: None,
        };

        let initial_cfg = GlobalCacheConfig {
            enabled: true,
            max_bytes: 2 * 1024 * 1024,
            default_ttl_seconds: 60,
            max_entry_bytes: 64 * 1024,
            respect_cache_control: true,
            expose_cache_header: false,
            ..Default::default()
        };
        configure_global_response_cache(Some(&initial_cfg));
        let c1 = global_response_cache();
        c1.insert(
            key.clone(),
            Arc::new(CachedResponse::new(
                StatusCode::OK,
                HeaderMap::new(),
                Bytes::from_static(b"cached"),
                None,
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
                None,
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

    fn grpc_unary_frame(payload: &[u8]) -> Bytes {
        let mut buf = BytesMut::with_capacity(5 + payload.len());
        buf.extend_from_slice(&[0u8]);
        buf.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        buf.extend_from_slice(payload);
        buf.freeze()
    }

    fn post_json_req(uri: &str, body: &'static [u8]) -> Request<SrvBody> {
        Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from_static(body)).map_err(SrvError::from).boxed())
            .unwrap()
    }

    fn post_grpc_req(uri: &str, frame: Bytes) -> Request<SrvBody> {
        Request::builder()
            .method(Method::POST)
            .uri(uri)
            .header(header::CONTENT_TYPE, "application/grpc")
            .header(header::TE, "trailers")
            .body(Full::new(frame).map_err(SrvError::from).boxed())
            .unwrap()
    }

    #[tokio::test]
    async fn test_post_json_body_hash_isolation_and_coalescing() {
        let cache = SharedResponseCache::new(GlobalCacheConfig {
            enabled: true,
            max_bytes: 1024 * 1024,
            default_ttl_seconds: 60,
            max_entry_bytes: 64 * 1024,
            max_request_body_bytes: 16,
            respect_cache_control: true,
            expose_cache_header: true,
        });

        let cfg = CacheLayerConfig {
            namespace: None,
            rules: HashMap::from([(
                "POST /api/GetUsers".to_string(),
                CacheRuleConfig {
                    ttl_seconds: Some(60),
                    scope: CacheScope::Public,
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };
        let compiled = Arc::new(CompiledCacheConfig::from_raw(&cfg, "srv_post_json").unwrap());

        let calls = Arc::new(AtomicU64::new(0));
        let calls_ref = Arc::clone(&calls);
        let svc = CacheLayer::new(compiled, "srv_post_json")
            .with_cache(Arc::clone(&cache))
            .layer(
                tower::service_fn(move |req: Request<SrvBody>| {
                    let c = Arc::clone(&calls_ref);
                    async move {
                        let n = c.fetch_add(1, Ordering::SeqCst) + 1;
                        let body = req.into_body().collect().await.unwrap().to_bytes();
                        let text = String::from_utf8_lossy(&body).into_owned();
                        Ok::<_, SrvError>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .header(header::CONTENT_TYPE, "application/json")
                                .body(
                                    Full::new(Bytes::from(format!("n={n};req={text}")))
                                        .map_err(SrvError::from)
                                        .boxed(),
                                )
                                .unwrap(),
                        )
                    }
                })
                .boxed_clone_sync(),
            );

        // 1. Page 1 MISS -> HIT
        let r1 = svc
            .clone()
            .oneshot(post_json_req("/api/GetUsers", br#"{"page":1}"#))
            .await
            .unwrap();
        assert_eq!(r1.headers().get("x-praeco-cache").unwrap(), "MISS");
        let b1 = r1.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&b1[..], br#"n=1;req={"page":1}"#);

        let r2 = svc
            .clone()
            .oneshot(post_json_req("/api/GetUsers", br#"{"page":1}"#))
            .await
            .unwrap();
        assert_eq!(r2.headers().get("x-praeco-cache").unwrap(), "HIT");
        let b2 = r2.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&b2[..], br#"n=1;req={"page":1}"#);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // 2. Page 2 -> different SHA-256 key -> MISS
        let r3 = svc
            .clone()
            .oneshot(post_json_req("/api/GetUsers", br#"{"page":2}"#))
            .await
            .unwrap();
        assert_eq!(r3.headers().get("x-praeco-cache").unwrap(), "MISS");
        let b3 = r3.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&b3[..], br#"n=2;req={"page":2}"#);

        // 3. Different Content-Type -> isolated even for same bytes
        let xml_req = Request::builder()
            .method(Method::POST)
            .uri("/api/GetUsers")
            .header(header::CONTENT_TYPE, "application/problem+json")
            .body(
                Full::new(Bytes::from_static(br#"{"page":1}"#))
                    .map_err(SrvError::from)
                    .boxed(),
            )
            .unwrap();
        let r_ct = svc.clone().oneshot(xml_req).await.unwrap();
        assert_eq!(r_ct.headers().get("x-praeco-cache").unwrap(), "MISS");
        assert_eq!(calls.load(Ordering::SeqCst), 3);

        // 4. Request body exceeding max_request_body_bytes (16B) streams through as BYPASS
        let r_big = svc
            .clone()
            .oneshot(post_json_req("/api/GetUsers", br#"{"page":9999999999}"#))
            .await
            .unwrap();
        assert_eq!(r_big.headers().get("x-praeco-cache").unwrap(), "BYPASS");
        let b_big = r_big.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&b_big[..], br#"n=4;req={"page":9999999999}"#);
    }

    #[tokio::test]
    async fn test_post_grpc_unary_trailers_cached_and_nonzero_status_bypassed() {
        let cache = SharedResponseCache::new(GlobalCacheConfig {
            enabled: true,
            max_bytes: 1024 * 1024,
            default_ttl_seconds: 60,
            max_entry_bytes: 64 * 1024,
            max_request_body_bytes: 64 * 1024,
            respect_cache_control: true,
            expose_cache_header: true,
        });

        let cfg = CacheLayerConfig {
            namespace: None,
            rules: HashMap::from([(
                "POST /chat.ChatService/GetRoomProducts".to_string(),
                CacheRuleConfig::default(),
            )]),
            ..Default::default()
        };
        let compiled = Arc::new(CompiledCacheConfig::from_raw(&cfg, "srv_grpc").unwrap());

        let calls = Arc::new(AtomicU64::new(0));
        let calls_ref = Arc::clone(&calls);
        let svc = CacheLayer::new(compiled, "srv_grpc")
            .with_cache(Arc::clone(&cache))
            .layer(
                tower::service_fn(move |req: Request<SrvBody>| {
                    let c = Arc::clone(&calls_ref);
                    async move {
                        c.fetch_add(1, Ordering::SeqCst);
                        let req_bytes = req.into_body().collect().await.unwrap().to_bytes();
                        let deny = req_bytes.ends_with(b"deny");
                        let msg = grpc_unary_frame(if deny { b"" } else { b"products-ok" });
                        let mut trailers = HeaderMap::new();
                        trailers.insert(
                            "grpc-status",
                            HeaderValue::from_static(if deny { "7" } else { "0" }),
                        );
                        trailers.insert(
                            "x-custom-trailer",
                            HeaderValue::from_static("preserved"),
                        );
                        let stream = futures_util::stream::iter(vec![
                            Ok::<_, SrvError>(Frame::data(msg)),
                            Ok::<_, SrvError>(Frame::trailers(trailers)),
                        ]);
                        Ok::<_, SrvError>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .header(header::CONTENT_TYPE, "application/grpc")
                                .body(http_body_util::StreamBody::new(stream).boxed())
                                .unwrap(),
                        )
                    }
                })
                .boxed_clone_sync(),
            );

        // 1. Unary gRPC grpc-status: 0 -> MISS then HIT with preserved trailers and NO content-length
        let req1 = post_grpc_req(
            "/chat.ChatService/GetRoomProducts",
            grpc_unary_frame(b"room-1"),
        );
        let r1 = svc.clone().oneshot(req1).await.unwrap();
        assert_eq!(r1.headers().get("x-praeco-cache").unwrap(), "MISS");
        assert!(r1.headers().get(header::CONTENT_LENGTH).is_none());
        let collected1 = r1.into_body().collect().await.unwrap();
        assert_eq!(collected1.trailers().unwrap().get("grpc-status").unwrap(), "0");
        assert_eq!(
            collected1.trailers().unwrap().get("x-custom-trailer").unwrap(),
            "preserved"
        );
        assert_eq!(collected1.to_bytes(), grpc_unary_frame(b"products-ok"));

        let req2 = post_grpc_req(
            "/chat.ChatService/GetRoomProducts",
            grpc_unary_frame(b"room-1"),
        );
        let r2 = svc.clone().oneshot(req2).await.unwrap();
        assert_eq!(r2.headers().get("x-praeco-cache").unwrap(), "HIT");
        assert!(r2.headers().get(header::CONTENT_LENGTH).is_none());
        let collected2 = r2.into_body().collect().await.unwrap();
        assert_eq!(collected2.trailers().unwrap().get("grpc-status").unwrap(), "0");
        assert_eq!(
            collected2.trailers().unwrap().get("x-custom-trailer").unwrap(),
            "preserved"
        );
        assert_eq!(collected2.to_bytes(), grpc_unary_frame(b"products-ok"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // 2. Non-zero grpc-status (7) MUST NOT be cached and still preserve trailers
        let err_req1 = post_grpc_req(
            "/chat.ChatService/GetRoomProducts",
            grpc_unary_frame(b"deny"),
        );
        let re1 = svc.clone().oneshot(err_req1).await.unwrap();
        assert_eq!(re1.headers().get("x-praeco-cache").unwrap(), "BYPASS");
        let err_col1 = re1.into_body().collect().await.unwrap();
        assert_eq!(err_col1.trailers().unwrap().get("grpc-status").unwrap(), "7");

        let err_req2 = post_grpc_req(
            "/chat.ChatService/GetRoomProducts",
            grpc_unary_frame(b"deny"),
        );
        let re2 = svc.clone().oneshot(err_req2).await.unwrap();
        assert_eq!(re2.headers().get("x-praeco-cache").unwrap(), "BYPASS");
        assert_eq!(calls.load(Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn test_post_grpc_streaming_request_and_response_bypass_without_hanging() {
        let cache = SharedResponseCache::new(GlobalCacheConfig::default());
        let cache = SharedResponseCache::new(GlobalCacheConfig {
            expose_cache_header: true,
            ..cache.config().clone()
        });

        let cfg = CacheLayerConfig {
            namespace: None,
            rules: HashMap::from([(
                "POST /chat.ChatService/MaybeStream".to_string(),
                CacheRuleConfig::default(),
            )]),
            ..Default::default()
        };
        let compiled = Arc::new(CompiledCacheConfig::from_raw(&cfg, "srv_grpc_stream").unwrap());

        let svc = CacheLayer::new(compiled, "srv_grpc_stream")
            .with_cache(Arc::clone(&cache))
            .layer(
                tower::service_fn(|req: Request<SrvBody>| async move {
                    let req_bytes = req.into_body().collect().await.unwrap().to_bytes();
                    let mut trailers = HeaderMap::new();
                    trailers.insert("grpc-status", HeaderValue::from_static("0"));
                    // Yield two gRPC data frames (server streaming) + trailers
                    let stream = futures_util::stream::iter(vec![
                        Ok::<_, SrvError>(Frame::data(grpc_unary_frame(&req_bytes))),
                        Ok::<_, SrvError>(Frame::data(grpc_unary_frame(b"chunk2"))),
                        Ok::<_, SrvError>(Frame::trailers(trailers)),
                    ]);
                    Ok::<_, SrvError>(
                        Response::builder()
                            .status(StatusCode::OK)
                            .header(header::CONTENT_TYPE, "application/grpc")
                            .body(http_body_util::StreamBody::new(stream).boxed())
                            .unwrap(),
                    )
                })
                .boxed_clone_sync(),
            );

        // Client keeps stream open for 40ms after frame 1 before sending frame 2 -> must spill into BYPASS immediately
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, SrvError>>(4);
        tokio::spawn(async move {
            let _ = tx.send(Ok(Frame::data(grpc_unary_frame(b"f1")))).await;
            tokio::time::sleep(Duration::from_millis(40)).await;
            let _ = tx.send(Ok(Frame::data(grpc_unary_frame(b"f2")))).await;
        });
        let req_stream = tokio_stream::wrappers::ReceiverStream::new(rx);
        let client_stream_req = Request::builder()
            .method(Method::POST)
            .uri("/chat.ChatService/MaybeStream")
            .header(header::CONTENT_TYPE, "application/grpc")
            .body(http_body_util::StreamBody::new(req_stream).boxed())
            .unwrap();

        let resp = tokio::time::timeout(
            Duration::from_secs(2),
            svc.clone().oneshot(client_stream_req),
        )
        .await
        .expect("streaming request must not deadlock")
        .unwrap();
        assert_eq!(resp.headers().get("x-praeco-cache").unwrap(), "BYPASS");
        let col = resp.into_body().collect().await.unwrap();
        assert_eq!(col.trailers().unwrap().get("grpc-status").unwrap(), "0");

        // Multi-frame server-streaming response on a unary request also spills to BYPASS without caching
        let unary_req = post_grpc_req("/chat.ChatService/MaybeStream", grpc_unary_frame(b"u1"));
        let resp2 = svc.clone().oneshot(unary_req).await.unwrap();
        assert_eq!(resp2.headers().get("x-praeco-cache").unwrap(), "BYPASS");
        let _ = resp2.into_body().collect().await.unwrap();
        cache.run_pending_tasks();
        assert_eq!(cache.entry_count(), 0);
    }

    #[tokio::test]
    async fn test_declarative_cross_server_mutation_invalidation_and_generation_guard() {
        let cache = SharedResponseCache::new(GlobalCacheConfig {
            enabled: true,
            max_bytes: 1024 * 1024,
            default_ttl_seconds: 60,
            max_entry_bytes: 64 * 1024,
            max_request_body_bytes: 64 * 1024,
            respect_cache_control: true,
            expose_cache_header: true,
        });

        let read_cfg = CompiledCacheConfig::from_raw(
            &CacheLayerConfig {
                namespace: Some("shared_products".to_string()),
                rules: HashMap::from([(
                    "POST /chat.ChatService/GetProducts".to_string(),
                    CacheRuleConfig::default(),
                )]),
                ..Default::default()
            },
            "read_srv",
        )
        .unwrap();

        let write_cfg = CompiledCacheConfig::from_raw(
            &CacheLayerConfig {
                namespace: None,
                rules: HashMap::new(),
                invalidations: HashMap::from([(
                    "POST /chat.ChatService/CreateProduct".to_string(),
                    vec!["shared_products".to_string()],
                )]),
            },
            "write_srv",
        )
        .unwrap();

        let slow_gate = Arc::new(Notify::new());
        let slow_started = Arc::new(Notify::new());
        let slow_once = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let slow_gate_ref = Arc::clone(&slow_gate);
        let slow_started_ref = Arc::clone(&slow_started);
        let slow_once_ref = Arc::clone(&slow_once);
        let read_calls = Arc::new(AtomicU64::new(0));
        let read_calls_ref = Arc::clone(&read_calls);

        let read_svc = CacheLayer::new(Arc::new(read_cfg), "read_srv")
            .with_cache(Arc::clone(&cache))
            .layer(
                tower::service_fn(move |req: Request<SrvBody>| {
                    let calls = Arc::clone(&read_calls_ref);
                    let gate = Arc::clone(&slow_gate_ref);
                    let started = Arc::clone(&slow_started_ref);
                    let once = Arc::clone(&slow_once_ref);
                    async move {
                        let req_bytes = req.into_body().collect().await.unwrap().to_bytes();
                        if req_bytes.as_ref() == br#"{"slow":true}"#
                            && !once.swap(true, Ordering::SeqCst)
                        {
                            started.notify_one();
                            gate.notified().await;
                        }
                        let n = calls.fetch_add(1, Ordering::SeqCst) + 1;
                        Ok::<_, SrvError>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .header(header::CONTENT_TYPE, "application/json")
                                .body(
                                    Full::new(Bytes::from(format!("products-v{n}")))
                                        .map_err(SrvError::from)
                                        .boxed(),
                                )
                                .unwrap(),
                        )
                    }
                })
                .boxed_clone_sync(),
            );

        let write_svc = CacheLayer::new(Arc::new(write_cfg), "write_srv")
            .with_cache(Arc::clone(&cache))
            .layer(
                tower::service_fn(|req: Request<SrvBody>| async move {
                    let req_bytes = req.into_body().collect().await.unwrap().to_bytes();
                    if req_bytes.as_ref() == b"fail-http" {
                        return Ok::<_, SrvError>(
                            Response::builder()
                                .status(StatusCode::INTERNAL_SERVER_ERROR)
                                .body(Full::new(Bytes::from_static(b"err")).map_err(SrvError::from).boxed())
                                .unwrap(),
                        );
                    }
                    if req_bytes.as_ref() == b"fail-grpc" {
                        let mut tr = HeaderMap::new();
                        tr.insert("grpc-status", HeaderValue::from_static("7"));
                        let s = futures_util::stream::iter(vec![
                            Ok::<_, SrvError>(Frame::data(grpc_unary_frame(b""))),
                            Ok::<_, SrvError>(Frame::trailers(tr)),
                        ]);
                        return Ok(Response::builder()
                            .status(StatusCode::OK)
                            .header(header::CONTENT_TYPE, "application/grpc")
                            .body(http_body_util::StreamBody::new(s).boxed())
                            .unwrap());
                    }
                    let mut tr = HeaderMap::new();
                    tr.insert("grpc-status", HeaderValue::from_static("0"));
                    let s = futures_util::stream::iter(vec![
                        Ok::<_, SrvError>(Frame::data(grpc_unary_frame(b"created"))),
                        Ok::<_, SrvError>(Frame::trailers(tr)),
                    ]);
                    Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/grpc")
                        .body(http_body_util::StreamBody::new(s).boxed())
                        .unwrap())
                })
                .boxed_clone_sync(),
            );

        // 1. Populate read_svc -> HIT
        let r1 = read_svc
            .clone()
            .oneshot(post_json_req("/chat.ChatService/GetProducts", br#"{"all":true}"#))
            .await
            .unwrap();
        assert_eq!(r1.headers().get("x-praeco-cache").unwrap(), "MISS");
        let r2 = read_svc
            .clone()
            .oneshot(post_json_req("/chat.ChatService/GetProducts", br#"{"all":true}"#))
            .await
            .unwrap();
        assert_eq!(r2.headers().get("x-praeco-cache").unwrap(), "HIT");

        // 2. Failed mutations (HTTP 500 or gRPC grpc-status: 7) MUST NOT invalidate
        let _ = write_svc
            .clone()
            .oneshot(post_json_req("/chat.ChatService/CreateProduct", b"fail-http"))
            .await
            .unwrap();
        let fail_grpc_resp = write_svc
            .clone()
            .oneshot(post_json_req("/chat.ChatService/CreateProduct", b"fail-grpc"))
            .await
            .unwrap();
        let _ = fail_grpc_resp.into_body().collect().await.unwrap();
        cache.run_pending_tasks();
        let r3 = read_svc
            .clone()
            .oneshot(post_json_req("/chat.ChatService/GetProducts", br#"{"all":true}"#))
            .await
            .unwrap();
        assert_eq!(r3.headers().get("x-praeco-cache").unwrap(), "HIT");

        // 3. Successful gRPC mutation (grpc-status: 0 trailer) invalidates shared_products upon stream completion
        let before_inv = ServerMetrics::for_server("write_srv")
            .cache_invalidations
            .load(Ordering::Relaxed);
        let ok_mut = write_svc
            .clone()
            .oneshot(post_json_req("/chat.ChatService/CreateProduct", b"ok"))
            .await
            .unwrap();
        let _ = ok_mut.into_body().collect().await.unwrap();
        cache.run_pending_tasks();
        assert_eq!(
            ServerMetrics::for_server("write_srv")
                .cache_invalidations
                .load(Ordering::Relaxed),
            before_inv + 1
        );

        let r4 = read_svc
            .clone()
            .oneshot(post_json_req("/chat.ChatService/GetProducts", br#"{"all":true}"#))
            .await
            .unwrap();
        assert_eq!(r4.headers().get("x-praeco-cache").unwrap(), "MISS");

        // 4. Write-read race protection: in-flight slow MISS must NOT overwrite post-invalidation generation
        let r_slow_fut = tokio::spawn({
            let svc = read_svc.clone();
            async move {
                svc.oneshot(post_json_req("/chat.ChatService/GetProducts", br#"{"slow":true}"#))
                    .await
                    .unwrap()
            }
        });
        slow_started.notified().await;
        let ok_mut2 = write_svc
            .clone()
            .oneshot(post_json_req("/chat.ChatService/CreateProduct", b"ok2"))
            .await
            .unwrap();
        let _ = ok_mut2.into_body().collect().await.unwrap();
        slow_gate.notify_waiters();
        let slow_resp = r_slow_fut.await.unwrap();
        assert_eq!(slow_resp.headers().get("x-praeco-cache").unwrap(), "MISS");
        cache.run_pending_tasks();

        // Next call must still be MISS (stale slow response was not inserted)
        let r_after = read_svc
            .clone()
            .oneshot(post_json_req("/chat.ChatService/GetProducts", br#"{"slow":true}"#))
            .await
            .unwrap();
        assert_eq!(r_after.headers().get("x-praeco-cache").unwrap(), "MISS");
    }

    #[tokio::test]
    async fn test_p01_o1_generation_invalidation_and_namespace_cap() {
        let cache = SharedResponseCache::new(GlobalCacheConfig {
            enabled: true,
            max_bytes: 1024 * 1024,
            default_ttl_seconds: 60,
            max_entry_bytes: 64 * 1024,
            max_request_body_bytes: 64 * 1024,
            respect_cache_control: true,
            expose_cache_header: true,
        });

        let cfg = CacheLayerConfig {
            namespace: None,
            rules: HashMap::from([
                (
                    "/ns_a/*".to_string(),
                    CacheRuleConfig {
                        namespace: Some("ns_a".to_string()),
                        ..Default::default()
                    },
                ),
                (
                    "/ns_b/*".to_string(),
                    CacheRuleConfig {
                        namespace: Some("ns_b".to_string()),
                        ..Default::default()
                    },
                ),
            ]),
            ..Default::default()
        };
        let compiled = Arc::new(CompiledCacheConfig::from_raw(&cfg, "srv_p01").unwrap());
        let calls = Arc::new(AtomicU64::new(0));
        let calls_ref = Arc::clone(&calls);

        let svc = CacheLayer::new(compiled, "srv_p01")
            .with_cache(Arc::clone(&cache))
            .layer(
                tower::service_fn(move |req: Request<SrvBody>| {
                    let c = Arc::clone(&calls_ref);
                    async move {
                        let n = c.fetch_add(1, Ordering::SeqCst) + 1;
                        let body = format!("{}:{n}", req.uri().path());
                        Ok::<_, SrvError>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .body(Full::new(Bytes::from(body)).map_err(SrvError::from).boxed())
                                .unwrap(),
                        )
                    }
                })
                .boxed_clone_sync(),
            );

        // Populate both namespaces and verify HIT
        assert_eq!(
            svc.clone().oneshot(empty_req("/ns_a/item")).await.unwrap().headers().get("x-praeco-cache").unwrap(),
            "MISS"
        );
        assert_eq!(
            svc.clone().oneshot(empty_req("/ns_b/item")).await.unwrap().headers().get("x-praeco-cache").unwrap(),
            "MISS"
        );
        assert_eq!(
            svc.clone().oneshot(empty_req("/ns_a/item")).await.unwrap().headers().get("x-praeco-cache").unwrap(),
            "HIT"
        );

        // Stale CacheKey lookup must immediately miss after O(1) invalidate_namespace without Moka predicates
        let stale_key = CacheKey {
            namespace: Arc::from("ns_a"),
            generation: cache.current_generation("ns_a"),
            scope: CacheScope::Public,
            method: "GET",
            path_and_query: Arc::from("/ns_a/item"),
            vary_values: SmallVec::new(),
            scope_key: Arc::from(""),
            body_hash: None,
            post_encoding: None,
        };
        assert!(cache.get(&stale_key).is_some());

        cache.invalidate_namespace("ns_a");
        assert!(cache.get(&stale_key).is_none());

        // ns_a immediately misses while unrelated ns_b stays HIT
        assert_eq!(
            svc.clone().oneshot(empty_req("/ns_a/item")).await.unwrap().headers().get("x-praeco-cache").unwrap(),
            "MISS"
        );
        assert_eq!(
            svc.clone().oneshot(empty_req("/ns_b/item")).await.unwrap().headers().get("x-praeco-cache").unwrap(),
            "HIT"
        );

        // Overflow guard beyond MAX_TRACKED_NAMESPACES (4096) caps DashMap growth and bumps global_generation
        for i in 0..MAX_TRACKED_NAMESPACES {
            cache.invalidate_namespace(&format!("cap_ns_{i}"));
        }
        let len_at_cap = cache.namespace_generations.len();
        assert!(len_at_cap <= MAX_TRACKED_NAMESPACES);
        let global_before = cache.current_generation("ns_b").0;
        cache.invalidate_namespace("unbounded_overflow_ns");
        assert_eq!(cache.namespace_generations.len(), len_at_cap);
        assert_eq!(cache.current_generation("ns_b").0, global_before + 1);

        // Global generation advance also invalidates ns_b immediately
        assert_eq!(
            svc.clone().oneshot(empty_req("/ns_b/item")).await.unwrap().headers().get("x-praeco-cache").unwrap(),
            "MISS"
        );
    }

    #[tokio::test]
    async fn test_s01_total_deadline_and_buffer_budget_enforcement() {
        // 1. Total deadline defeats Slowloris per-frame reset on POST request bodies
        let budget = BufferBudget::new(1024);
        let (tx, rx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, SrvError>>(16);
        tokio::spawn(async move {
            for _ in 0..10 {
                if tx.send(Ok(Frame::data(Bytes::from_static(b"ab")))).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        });
        let slow_body = http_body_util::StreamBody::new(tokio_stream::wrappers::ReceiverStream::new(rx)).boxed();
        let start = Instant::now();
        let res = read_post_request_body_with_limits(
            slow_body,
            1024,
            false,
            Duration::from_millis(55),
            &budget,
        )
        .await
        .unwrap();
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(200),
            "slowloris drip must hit total deadline instead of resetting per frame (took {elapsed:?})"
        );
        match res {
            PostReqBody::Bypass(stream) => {
                let collected = stream.collect().await.unwrap().to_bytes();
                assert_eq!(&collected[..], b"abababababababababab");
                assert_eq!(budget.remaining(), 1024);
            }
            PostReqBody::Buffered(_, _) => panic!("expected Bypass on total deadline"),
        }

        // 2. Response collection hits fixed total deadline and releases reservation upon drain
        let (rtx, rrx) = tokio::sync::mpsc::channel::<Result<Frame<Bytes>, SrvError>>(8);
        tokio::spawn(async move {
            for _ in 0..8 {
                if rtx.send(Ok(Frame::data(Bytes::from_static(b"xyz")))).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(30)).await;
            }
        });
        let slow_resp_body = http_body_util::StreamBody::new(tokio_stream::wrappers::ReceiverStream::new(rrx)).boxed();
        let rstart = Instant::now();
        let col = collect_response_for_cache_with_limits(
            &HeaderMap::new(),
            slow_resp_body,
            1024,
            Duration::from_millis(55),
            &budget,
        )
        .await
        .unwrap();
        assert!(rstart.elapsed() < Duration::from_millis(200));
        match col {
            CollectedResponse::Bypass {
                buffered,
                reservation,
                rest,
            } => {
                let chained = ChainedStreamBody {
                    buffered,
                    reservation,
                    rest,
                    rest_done: false,
                };
                let bytes = chained.collect().await.unwrap().to_bytes();
                assert_eq!(&bytes[..], b"xyzxyzxyzxyzxyzxyzxyzxyz");
                assert_eq!(budget.remaining(), 1024);
            }
            CollectedResponse::Cacheable { .. } => panic!("expected Bypass on slow response"),
        }

        // 3. Exhausting BufferBudget spills immediately to Bypass and restores capacity on drain/drop
        let tiny_budget = BufferBudget::new(10);
        let req_stream = http_body_util::StreamBody::new(futures_util::stream::iter(vec![
            Ok::<_, SrvError>(Frame::data(Bytes::from_static(b"123456"))),
            Ok::<_, SrvError>(Frame::data(Bytes::from_static(b"789012"))),
        ]))
        .boxed();
        match read_post_request_body_with_limits(
            req_stream,
            1024,
            false,
            Duration::from_secs(1),
            &tiny_budget,
        )
        .await
        .unwrap()
        {
            PostReqBody::Bypass(stream) => {
                // While holding first 6 bytes buffered before consuming, only 4 remain in tiny_budget
                assert_eq!(tiny_budget.remaining(), 4);
                let drained = stream.collect().await.unwrap().to_bytes();
                assert_eq!(&drained[..], b"123456789012");
                assert_eq!(tiny_budget.remaining(), 10);
            }
            PostReqBody::Buffered(_, _) => panic!("expected Bypass when BufferBudget is exhausted"),
        }

        let resp_stream = http_body_util::StreamBody::new(futures_util::stream::iter(vec![
            Ok::<_, SrvError>(Frame::data(Bytes::from_static(b"123456"))),
            Ok::<_, SrvError>(Frame::data(Bytes::from_static(b"789012"))),
        ]))
        .boxed();
        match collect_response_for_cache_with_limits(
            &HeaderMap::new(),
            resp_stream,
            1024,
            Duration::from_secs(1),
            &tiny_budget,
        )
        .await
        .unwrap()
        {
            CollectedResponse::Bypass {
                buffered,
                reservation,
                rest,
            } => {
                assert_eq!(tiny_budget.remaining(), 4);
                let chained = ChainedStreamBody {
                    buffered,
                    reservation,
                    rest,
                    rest_done: false,
                };
                // Dropping without draining must still release the reservation cleanly
                drop(chained);
                assert_eq!(tiny_budget.remaining(), 10);
            }
            CollectedResponse::Cacheable { .. } => {
                panic!("expected Bypass when BufferBudget is exhausted")
            }
        }
    }

    #[tokio::test]
    async fn test_s02_response_vary_validation_prevents_cache_poisoning() {
        let cache = SharedResponseCache::new(GlobalCacheConfig {
            enabled: true,
            max_bytes: 1024 * 1024,
            default_ttl_seconds: 60,
            max_entry_bytes: 64 * 1024,
            max_request_body_bytes: 64 * 1024,
            respect_cache_control: true,
            expose_cache_header: true,
        });

        let cfg = CacheLayerConfig {
            namespace: None,
            rules: HashMap::from([
                ("/open/*".to_string(), CacheRuleConfig::default()),
                (
                    "/cors/*".to_string(),
                    CacheRuleConfig {
                        vary_headers: vec!["origin".to_string()],
                        ..Default::default()
                    },
                ),
            ]),
            ..Default::default()
        };
        let compiled = Arc::new(CompiledCacheConfig::from_raw(&cfg, "srv_s02").unwrap());

        let svc = CacheLayer::new(compiled, "srv_s02")
            .with_cache(Arc::clone(&cache))
            .layer(
                tower::service_fn(|req: Request<SrvBody>| async move {
                    let mut b = Response::builder().status(StatusCode::OK);
                    match req.uri().path() {
                        "/open/star" => {
                            b = b.header(header::VARY, "*");
                        }
                        "/open/origin_uncovered" => {
                            b = b.header(header::VARY, "Origin");
                        }
                        "/open/accept_enc_plain" => {
                            b = b.header(header::VARY, "Accept-Encoding");
                        }
                        "/open/accept_enc_compressed" => {
                            b = b
                                .header(header::VARY, "Accept-Encoding")
                                .header(header::CONTENT_ENCODING, "gzip");
                        }
                        "/cors/ok" => {
                            let origin = req
                                .headers()
                                .get(header::ORIGIN)
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("none");
                            b = b
                                .header(header::VARY, "Origin, Accept-Encoding")
                                .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, origin);
                        }
                        _ => {}
                    }
                    Ok::<_, SrvError>(
                        b.body(Full::new(Bytes::from_static(b"ok")).map_err(SrvError::from).boxed())
                            .unwrap(),
                    )
                })
                .boxed_clone_sync(),
            );

        // 1. Vary: * must never be cached (RFC 9111)
        let r_star = svc.clone().oneshot(empty_req("/open/star")).await.unwrap();
        assert_eq!(r_star.headers().get("x-praeco-cache").unwrap(), "BYPASS");

        // 2. Vary: Origin without `origin` in vary_headers must BYPASS
        let r_uncovered = svc.clone().oneshot(empty_req("/open/origin_uncovered")).await.unwrap();
        assert_eq!(r_uncovered.headers().get("x-praeco-cache").unwrap(), "BYPASS");

        // 3. Vary: Accept-Encoding without Content-Encoding is safe (Compression layer wraps outside)
        assert_eq!(
            svc.clone().oneshot(empty_req("/open/accept_enc_plain")).await.unwrap().headers().get("x-praeco-cache").unwrap(),
            "MISS"
        );
        assert_eq!(
            svc.clone().oneshot(empty_req("/open/accept_enc_plain")).await.unwrap().headers().get("x-praeco-cache").unwrap(),
            "HIT"
        );

        // 4. Vary: Accept-Encoding WITH Content-Encoding: gzip (without vary_headers) must BYPASS
        assert_eq!(
            svc.clone().oneshot(empty_req("/open/accept_enc_compressed")).await.unwrap().headers().get("x-praeco-cache").unwrap(),
            "BYPASS"
        );

        // 5. Rule with vary_headers = ["origin"] caches cleanly and partitions by Origin
        let mut req_app = empty_req("/cors/ok");
        req_app.headers_mut().insert(header::ORIGIN, HeaderValue::from_static("https://app.example"));
        let r_app1 = svc.clone().oneshot(req_app).await.unwrap();
        assert_eq!(r_app1.headers().get("x-praeco-cache").unwrap(), "MISS");
        assert_eq!(
            r_app1.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
            "https://app.example"
        );

        let mut req_evil = empty_req("/cors/ok");
        req_evil.headers_mut().insert(header::ORIGIN, HeaderValue::from_static("https://evil.example"));
        let r_evil = svc.clone().oneshot(req_evil).await.unwrap();
        assert_eq!(r_evil.headers().get("x-praeco-cache").unwrap(), "MISS");
        assert_eq!(
            r_evil.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
            "https://evil.example"
        );

        let mut req_app2 = empty_req("/cors/ok");
        req_app2.headers_mut().insert(header::ORIGIN, HeaderValue::from_static("https://app.example"));
        let r_app2 = svc.clone().oneshot(req_app2).await.unwrap();
        assert_eq!(r_app2.headers().get("x-praeco-cache").unwrap(), "HIT");
        assert_eq!(
            r_app2.headers().get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
            "https://app.example"
        );
    }

    #[tokio::test]
    async fn test_s03_multi_issuer_jwt_subject_isolation_and_scope_keying() {
        let cache = SharedResponseCache::new(GlobalCacheConfig {
            enabled: true,
            max_bytes: 1024 * 1024,
            default_ttl_seconds: 60,
            max_entry_bytes: 64 * 1024,
            max_request_body_bytes: 64 * 1024,
            respect_cache_control: true,
            expose_cache_header: true,
        });

        let cfg = CacheLayerConfig {
            namespace: None,
            rules: HashMap::from([(
                "/me/*".to_string(),
                CacheRuleConfig {
                    scope: CacheScope::PerSubject,
                    ..Default::default()
                },
            )]),
            ..Default::default()
        };
        let compiled = Arc::new(CompiledCacheConfig::from_raw(&cfg, "srv_s03").unwrap());
        let calls = Arc::new(AtomicU64::new(0));
        let calls_ref = Arc::clone(&calls);

        let svc = CacheLayer::new(compiled, "srv_s03")
            .with_cache(Arc::clone(&cache))
            .layer(
                tower::service_fn(move |req: Request<SrvBody>| {
                    let c = Arc::clone(&calls_ref);
                    async move {
                        let n = c.fetch_add(1, Ordering::SeqCst) + 1;
                        let claims = req.extensions().get::<Claims>().cloned();
                        let tag = claims
                            .map(|cl| format!("{}:{}:{n}", cl.iss, cl.sub))
                            .unwrap_or_else(|| format!("none:{n}"));
                        Ok::<_, SrvError>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .body(Full::new(Bytes::from(tag)).map_err(SrvError::from).boxed())
                                .unwrap(),
                        )
                    }
                })
                .boxed_clone_sync(),
            );

        let make_claims_req = |iss: &str, sub: &str| {
            let mut r = empty_req("/me/data");
            r.extensions_mut().insert(Claims {
                sub: sub.to_string(),
                iss: iss.to_string(),
                aud: None,
                exp: 9_999_999_999,
                oids: vec![],
                jti: None,
            });
            r
        };

        // Two distinct issuers sharing identical sub = "42" must stay isolated
        let r1 = svc.clone().oneshot(make_claims_req("https://idp1.example", "42")).await.unwrap();
        assert_eq!(r1.headers().get("x-praeco-cache").unwrap(), "MISS");
        let b1 = r1.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&b1[..], b"https://idp1.example:42:1");

        let r2 = svc.clone().oneshot(make_claims_req("https://idp2.example", "42")).await.unwrap();
        assert_eq!(r2.headers().get("x-praeco-cache").unwrap(), "MISS");
        let b2 = r2.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&b2[..], b"https://idp2.example:42:2");

        // Second request for idp1 + "42" hits idp1's cached entry
        let r1_hit = svc.clone().oneshot(make_claims_req("https://idp1.example", "42")).await.unwrap();
        assert_eq!(r1_hit.headers().get("x-praeco-cache").unwrap(), "HIT");
        let b1_hit = r1_hit.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&b1_hit[..], b"https://idp1.example:42:1");

        // Delimiter ambiguity check ("a:1:b" + "c" vs "a" + "b:1:c") must NOT collide thanks to length prefixing
        let r_amb1 = svc.clone().oneshot(make_claims_req("a:1:b", "c")).await.unwrap();
        assert_eq!(r_amb1.headers().get("x-praeco-cache").unwrap(), "MISS");
        let r_amb2 = svc.clone().oneshot(make_claims_req("a", "b:1:c")).await.unwrap();
        assert_eq!(r_amb2.headers().get("x-praeco-cache").unwrap(), "MISS");

        // Scope field inside CacheKey isolates otherwise identical keys
        let pub_key = CacheKey {
            namespace: Arc::from("scope_iso"),
            generation: (0, 0),
            scope: CacheScope::Public,
            method: "GET",
            path_and_query: Arc::from("/me/data"),
            vary_values: SmallVec::new(),
            scope_key: Arc::from("same"),
            body_hash: None,
            post_encoding: None,
        };
        let subj_key = CacheKey {
            scope: CacheScope::PerSubject,
            ..pub_key.clone()
        };
        cache.insert(
            pub_key.clone(),
            Arc::new(CachedResponse::new(
                StatusCode::OK,
                HeaderMap::new(),
                Bytes::from_static(b"pub"),
                None,
                Duration::from_secs(60),
            )),
        );
        assert!(cache.get(&pub_key).is_some());
        assert!(cache.get(&subj_key).is_none());
    }

    #[tokio::test]
    async fn test_p02_precompressed_gzip_and_brotli_zero_recompression_on_hits() {
        use async_compression::tokio::bufread::{BrotliDecoder, GzipDecoder};
        use crate::middleware::compression::SrvCompressionLayer;

        let cache = SharedResponseCache::new(GlobalCacheConfig {
            enabled: true,
            max_bytes: 1024 * 1024,
            default_ttl_seconds: 60,
            max_entry_bytes: 64 * 1024,
            max_request_body_bytes: 64 * 1024,
            respect_cache_control: true,
            expose_cache_header: true,
        });

        let cfg = CacheLayerConfig {
            namespace: None,
            rules: HashMap::from([("/assets/*".to_string(), CacheRuleConfig::default())]),
            ..Default::default()
        };
        let compiled = Arc::new(CompiledCacheConfig::from_raw(&cfg, "srv_p02").unwrap());
        let payload = "praeco-precompress-payload-".repeat(20);
        let payload_bytes = Bytes::from(payload.clone());
        let calls = Arc::new(AtomicU64::new(0));
        let calls_ref = Arc::clone(&calls);
        let p_ref = payload_bytes.clone();

        let inner = tower::service_fn(move |_req: Request<SrvBody>| {
            let c = Arc::clone(&calls_ref);
            let body = p_ref.clone();
            async move {
                c.fetch_add(1, Ordering::SeqCst);
                Ok::<_, SrvError>(
                    Response::builder()
                        .status(StatusCode::OK)
                        .header(header::CONTENT_TYPE, "application/json")
                        .body(Full::new(body).map_err(SrvError::from).boxed())
                        .unwrap(),
                )
            }
        })
        .boxed_clone_sync();

        let cached_svc = CacheLayer::new(compiled, "srv_p02")
            .with_cache(cache)
            .with_precompression(true)
            .layer(inner);
        let svc = SrvCompressionLayer::new("srv_p02").layer(cached_svc);

        // 1. Cold MISS with Accept-Encoding: gzip -> precompresses once inside CacheLayer
        let mut r_miss = empty_req("/assets/bundle.json");
        r_miss.headers_mut().insert(header::ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
        let res_miss = svc.clone().oneshot(r_miss).await.unwrap();
        assert_eq!(res_miss.headers().get("x-praeco-cache").unwrap(), "MISS");
        assert_eq!(res_miss.headers().get(header::CONTENT_ENCODING).unwrap(), "gzip");
        assert!(res_miss.headers().get(header::CONTENT_LENGTH).is_some());
        let miss_gz = res_miss.into_body().collect().await.unwrap().to_bytes();
        let mut miss_dec = Vec::new();
        GzipDecoder::new(std::io::Cursor::new(miss_gz))
            .read_to_end(&mut miss_dec)
            .await
            .unwrap();
        assert_eq!(miss_dec, payload.as_bytes());

        // 2. Warm HIT with Accept-Encoding: gzip -> synchronous precompressed HIT (Content-Length preserved!)
        let mut r_hit_gz = empty_req("/assets/bundle.json");
        r_hit_gz.headers_mut().insert(header::ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
        let res_hit_gz = svc.clone().oneshot(r_hit_gz).await.unwrap();
        assert_eq!(res_hit_gz.headers().get("x-praeco-cache").unwrap(), "HIT");
        assert_eq!(res_hit_gz.headers().get(header::CONTENT_ENCODING).unwrap(), "gzip");
        assert!(
            res_hit_gz.headers().get(header::CONTENT_LENGTH).is_some(),
            "outer SrvCompressionLayer must see already_encoded and preserve Content-Length"
        );
        let hit_gz = res_hit_gz.into_body().collect().await.unwrap().to_bytes();
        let mut hit_dec = Vec::new();
        GzipDecoder::new(std::io::Cursor::new(hit_gz))
            .read_to_end(&mut hit_dec)
            .await
            .unwrap();
        assert_eq!(hit_dec, payload.as_bytes());

        // 3. First Brotli HIT lazily populates `br`, second Brotli HIT is synchronous with Content-Length preserved
        for _ in 0..2 {
            let mut r_br = empty_req("/assets/bundle.json");
            r_br.headers_mut().insert(header::ACCEPT_ENCODING, HeaderValue::from_static("br"));
            let res_br = svc.clone().oneshot(r_br).await.unwrap();
            assert_eq!(res_br.headers().get("x-praeco-cache").unwrap(), "HIT");
            assert_eq!(res_br.headers().get(header::CONTENT_ENCODING).unwrap(), "br");
            assert!(res_br.headers().get(header::CONTENT_LENGTH).is_some());
            let hit_br = res_br.into_body().collect().await.unwrap().to_bytes();
            let mut br_dec = Vec::new();
            BrotliDecoder::new(std::io::Cursor::new(hit_br))
                .read_to_end(&mut br_dec)
                .await
                .unwrap();
            assert_eq!(br_dec, payload.as_bytes());
        }

        // 4. Plain client HIT gets uncompressed payload without Content-Encoding
        let res_plain = svc.clone().oneshot(empty_req("/assets/bundle.json")).await.unwrap();
        assert_eq!(res_plain.headers().get("x-praeco-cache").unwrap(), "HIT");
        assert!(res_plain.headers().get(header::CONTENT_ENCODING).is_none());
        let plain_bytes = res_plain.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(plain_bytes, payload_bytes);
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn test_s05_grpc_web_missing_trailer_grpc_web_text_and_mutation_semicolon_fail_closed() {
        let cache = SharedResponseCache::new(GlobalCacheConfig {
            enabled: true,
            max_bytes: 1024 * 1024,
            default_ttl_seconds: 60,
            max_entry_bytes: 64 * 1024,
            max_request_body_bytes: 64 * 1024,
            respect_cache_control: true,
            expose_cache_header: true,
        });

        let cfg = CacheLayerConfig {
            namespace: None,
            rules: HashMap::from([
                (
                    "POST /rpc/MissingTrailer".to_string(),
                    CacheRuleConfig::default(),
                ),
                (
                    "POST /rpc/WithTrailer".to_string(),
                    CacheRuleConfig::default(),
                ),
                (
                    "POST /rpc/TextMode".to_string(),
                    CacheRuleConfig::default(),
                ),
            ]),
            invalidations: HashMap::from([(
                "POST /api/Mutate".to_string(),
                vec!["srv_s05".to_string()],
            )]),
        };
        let compiled = Arc::new(CompiledCacheConfig::from_raw(&cfg, "srv_s05").unwrap());
        let calls = Arc::new(AtomicU64::new(0));
        let calls_ref = Arc::clone(&calls);

        let svc = CacheLayer::new(compiled, "srv_s05")
            .with_cache(cache)
            .layer(
                tower::service_fn(move |req: Request<SrvBody>| {
                    let c = Arc::clone(&calls_ref);
                    async move {
                        c.fetch_add(1, Ordering::SeqCst);
                        match req.uri().path() {
                            "/rpc/MissingTrailer" => {
                                let mut frame = vec![0x00u8];
                                frame.extend_from_slice(&4u32.to_be_bytes());
                                frame.extend_from_slice(b"data");
                                Ok::<_, SrvError>(
                                    Response::builder()
                                        .status(StatusCode::OK)
                                        .header(header::CONTENT_TYPE, "application/grpc-web+proto")
                                        .body(Full::new(Bytes::from(frame)).map_err(SrvError::from).boxed())
                                        .unwrap(),
                                )
                            }
                            "/rpc/WithTrailer" => {
                                let mut frame = vec![0x00u8];
                                frame.extend_from_slice(&4u32.to_be_bytes());
                                frame.extend_from_slice(b"data");
                                let trailer = b"grpc-status: 0\r\n";
                                frame.push(0x80u8);
                                frame.extend_from_slice(&(trailer.len() as u32).to_be_bytes());
                                frame.extend_from_slice(trailer);
                                Ok::<_, SrvError>(
                                    Response::builder()
                                        .status(StatusCode::OK)
                                        .header(header::CONTENT_TYPE, "application/grpc-web")
                                        .body(Full::new(Bytes::from(frame)).map_err(SrvError::from).boxed())
                                        .unwrap(),
                                )
                            }
                            "/rpc/TextMode" => Ok::<_, SrvError>(
                                Response::builder()
                                    .status(StatusCode::OK)
                                    .header(header::CONTENT_TYPE, "application/grpc-web-text+proto")
                                    .body(Full::new(Bytes::from_static(b"AAAA")).map_err(SrvError::from).boxed())
                                    .unwrap(),
                            ),
                            _ => Ok::<_, SrvError>(text_resp("mutated")),
                        }
                    }
                })
                .boxed_clone_sync(),
            );

        // 1. Binary grpc-web without 0x80 trailer frame -> BYPASS
        let r_no_tr = svc
            .clone()
            .oneshot(post_json_req("/rpc/MissingTrailer", b"{}"))
            .await
            .unwrap();
        assert_eq!(r_no_tr.headers().get("x-praeco-cache").unwrap(), "BYPASS");

        // 2. Binary grpc-web with 0x80 grpc-status: 0 trailer -> MISS then HIT
        let r_ok1 = svc
            .clone()
            .oneshot(post_json_req("/rpc/WithTrailer", b"{}"))
            .await
            .unwrap();
        assert_eq!(r_ok1.headers().get("x-praeco-cache").unwrap(), "MISS");
        let r_ok2 = svc
            .clone()
            .oneshot(post_json_req("/rpc/WithTrailer", b"{}"))
            .await
            .unwrap();
        assert_eq!(r_ok2.headers().get("x-praeco-cache").unwrap(), "HIT");

        // 3. application/grpc-web-text -> BYPASS
        let r_text = svc
            .clone()
            .oneshot(post_json_req("/rpc/TextMode", b"{}"))
            .await
            .unwrap();
        assert_eq!(r_text.headers().get("x-praeco-cache").unwrap(), "BYPASS");

        // 4. Semicolon matrix parameter on mutating request in standalone CacheLayer -> 400 Bad Request
        let before_semi = calls.load(Ordering::SeqCst);
        let r_semi = svc
            .clone()
            .oneshot(post_json_req("/api/Mutate;jsessionid=1", b"{}"))
            .await
            .unwrap();
        assert_eq!(r_semi.status(), StatusCode::BAD_REQUEST);
        let r_pct3b = svc
            .clone()
            .oneshot(post_json_req("/api/Mutate%3bbypass", b"{}"))
            .await
            .unwrap();
        assert_eq!(r_pct3b.status(), StatusCode::BAD_REQUEST);
        assert_eq!(calls.load(Ordering::SeqCst), before_semi);
    }

    #[tokio::test]
    async fn test_p02_p03_edge_cases_mixed_coalescing_head_incompressible_and_query_fastpath() {
        use async_compression::tokio::bufread::GzipDecoder;

        // 1. P-03 canonical_path_and_query fast-path and percent/plus normalization equivalence
        assert_eq!(&*canonical_path_and_query("/items", None), "/items");
        assert_eq!(&*canonical_path_and_query("/items", Some("")), "/items");
        assert_eq!(&*canonical_path_and_query("/items", Some("k=v")), "/items?k=v");
        assert_eq!(&*canonical_path_and_query("/items", Some("a=")), "/items?a=");
        assert_eq!(&*canonical_path_and_query("/items", Some("=1")), "/items?=1");
        assert_eq!(
            canonical_path_and_query("/items", Some("a=1&b=2")),
            canonical_path_and_query("/items", Some("b=2&a=1"))
        );
        assert_eq!(
            canonical_path_and_query("/items", Some("q=a+b")),
            canonical_path_and_query("/items", Some("q=a%20b"))
        );

        let cache = SharedResponseCache::new(GlobalCacheConfig {
            enabled: true,
            max_bytes: 1024 * 1024,
            default_ttl_seconds: 60,
            max_entry_bytes: 64 * 1024,
            max_request_body_bytes: 64 * 1024,
            respect_cache_control: true,
            expose_cache_header: true,
        });

        let cfg = CacheLayerConfig {
            namespace: Some("p02_edge_ns".to_string()),
            rules: HashMap::from([("/assets/*".to_string(), CacheRuleConfig::default())]),
            ..Default::default()
        };
        let compiled = Arc::new(CompiledCacheConfig::from_raw(&cfg, "srv_p02_edge").unwrap());

        let compressible = "edge-coalesce-compressible-payload-".repeat(12);
        let compressible_bytes = Bytes::from(compressible.clone());
        let compressible_len = compressible_bytes.len();

        // Deterministic pseudo-random incompressible payload (> MIN_PRECOMPRESS_BYTES = 64)
        let mut seed: u64 = 0x9e37_79b9_7f4a_7c15;
        let incompressible: Vec<u8> = (0..256)
            .map(|_| {
                seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
                (seed >> 32) as u8
            })
            .collect();
        let incompressible_bytes = Bytes::from(incompressible);

        let mixed_started = Arc::new(Notify::new());
        let mixed_release = Arc::new(Notify::new());
        let calls = Arc::new(AtomicU64::new(0));

        let mixed_started_ref = Arc::clone(&mixed_started);
        let mixed_release_ref = Arc::clone(&mixed_release);
        let calls_ref = Arc::clone(&calls);
        let comp_ref = compressible_bytes.clone();
        let incomp_ref = incompressible_bytes.clone();

        let mut svc = CacheLayer::new(compiled, "srv_p02_edge")
            .with_cache(Arc::clone(&cache))
            .with_precompression(true)
            .layer(
                tower::service_fn(move |req: Request<SrvBody>| {
                    let st = Arc::clone(&mixed_started_ref);
                    let rel = Arc::clone(&mixed_release_ref);
                    let c = Arc::clone(&calls_ref);
                    let comp = comp_ref.clone();
                    let incomp = incomp_ref.clone();
                    async move {
                        c.fetch_add(1, Ordering::SeqCst);
                        let body = match req.uri().path() {
                            "/assets/mixed" => {
                                st.notify_one();
                                rel.notified().await;
                                comp
                            }
                            "/assets/tiny" => Bytes::from_static(b"tiny"),
                            "/assets/incomp" => incomp,
                            _ => Bytes::new(),
                        };
                        Ok::<_, SrvError>(
                            Response::builder()
                                .status(StatusCode::OK)
                                .header(header::CONTENT_TYPE, "application/octet-stream")
                                .body(Full::new(body).map_err(SrvError::from).boxed())
                                .unwrap(),
                        )
                    }
                })
                .boxed_clone_sync(),
            );

        // 2. Mixed-encoding Singleflight: plain leader + concurrent gzip follower
        let svc_leader = svc.clone();
        let leader_fut = tokio::spawn(async move {
            svc_leader.oneshot(empty_req("/assets/mixed")).await.unwrap()
        });
        mixed_started.notified().await;

        let svc_follower = svc.clone();
        let follower_fut = tokio::spawn(async move {
            let mut req_gz = empty_req("/assets/mixed");
            req_gz
                .headers_mut()
                .insert(header::ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
            svc_follower.oneshot(req_gz).await.unwrap()
        });
        tokio::task::yield_now().await;
        mixed_release.notify_waiters();

        let (resp_leader, resp_follower) = tokio::join!(leader_fut, follower_fut);
        let resp_leader = resp_leader.unwrap();
        let resp_follower = resp_follower.unwrap();
        assert_eq!(resp_leader.headers().get("x-praeco-cache").unwrap(), "MISS");
        assert!(resp_leader.headers().get(header::CONTENT_ENCODING).is_none());
        let leader_body = resp_leader.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(leader_body, compressible_bytes);

        assert_eq!(resp_follower.headers().get("x-praeco-cache").unwrap(), "COALESCED");
        assert_eq!(
            resp_follower.headers().get(header::CONTENT_ENCODING).unwrap(),
            "gzip"
        );
        let follower_gz = resp_follower.into_body().collect().await.unwrap().to_bytes();
        let mut dec = Vec::new();
        GzipDecoder::new(std::io::Cursor::new(follower_gz))
            .read_to_end(&mut dec)
            .await
            .unwrap();
        assert_eq!(dec, compressible.as_bytes());
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        // 3. HEAD with Accept-Encoding: gzip on precompressed entry returns uncompressed Content-Length + empty body
        let mut req_head = Request::builder()
            .method(Method::HEAD)
            .uri("/assets/mixed")
            .header(header::ACCEPT_ENCODING, "gzip")
            .body(Empty::<Bytes>::new().map_err(SrvError::from).boxed())
            .unwrap();
        let resp_head = svc.clone().oneshot(std::mem::replace(&mut req_head, empty_req("/"))).await.unwrap();
        assert_eq!(resp_head.headers().get("x-praeco-cache").unwrap(), "HIT");
        assert!(resp_head.headers().get(header::CONTENT_ENCODING).is_none());
        assert_eq!(
            resp_head
                .headers()
                .get(header::CONTENT_LENGTH)
                .unwrap()
                .to_str()
                .unwrap(),
            compressible_len.to_string()
        );
        let head_body = resp_head.into_body().collect().await.unwrap().to_bytes();
        assert!(head_body.is_empty());

        // 4. Small (< 64B) payload skips precompression and serves synchronously as plain HIT
        let mut req_tiny = empty_req("/assets/tiny");
        req_tiny
            .headers_mut()
            .insert(header::ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
        let r_tiny1 = svc.clone().oneshot(req_tiny).await.unwrap();
        assert_eq!(r_tiny1.headers().get("x-praeco-cache").unwrap(), "MISS");
        assert!(r_tiny1.headers().get(header::CONTENT_ENCODING).is_none());

        let mut req_tiny_hit = empty_req("/assets/tiny");
        req_tiny_hit
            .headers_mut()
            .insert(header::ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
        assert!(matches!(svc.call(req_tiny_hit), CacheFuture::Hit { .. }));

        // 5. Incompressible >= 64B payload caches Ready(None) in OnceCell and takes synchronous CacheFuture::Hit thereafter
        let mut req_inc1 = empty_req("/assets/incomp");
        req_inc1
            .headers_mut()
            .insert(header::ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
        let r_inc1 = svc.clone().oneshot(req_inc1).await.unwrap();
        assert_eq!(r_inc1.headers().get("x-praeco-cache").unwrap(), "MISS");
        assert!(r_inc1.headers().get(header::CONTENT_ENCODING).is_none());
        let inc_body1 = r_inc1.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(inc_body1, incompressible_bytes);

        let inc_key = CacheKey {
            namespace: Arc::from("p02_edge_ns"),
            generation: cache.current_generation("p02_edge_ns"),
            scope: CacheScope::Public,
            method: "GET",
            path_and_query: Arc::from("/assets/incomp"),
            vary_values: SmallVec::new(),
            scope_key: public_scope_key(),
            body_hash: None,
            post_encoding: None,
        };
        let stored_inc = cache.get(&inc_key).expect("incompressible entry must be cached");
        assert!(matches!(
            stored_inc.get_precompressed_sync(PrecompressAlgo::Gzip),
            PrecompressedLookup::Ready(None)
        ));

        let mut req_inc2 = empty_req("/assets/incomp");
        req_inc2
            .headers_mut()
            .insert(header::ACCEPT_ENCODING, HeaderValue::from_static("gzip"));
        let hit_fut = svc.call(req_inc2);
        assert!(
            matches!(hit_fut, CacheFuture::Hit { .. }),
            "subsequent HIT after Ready(None) must execute synchronously without re-compressing"
        );
        let r_inc2 = hit_fut.await.unwrap();
        assert_eq!(r_inc2.headers().get("x-praeco-cache").unwrap(), "HIT");
        assert!(r_inc2.headers().get(header::CONTENT_ENCODING).is_none());
    }

    #[tokio::test]
    async fn test_p04_g04_sharded_singleflight_multi_key_and_cache_before_concurrency_limit() {
        // 1. P-04: Concurrent multi-key Singleflight coalescing across shards + cancellation replacement
        let sf: Singleflight<String, usize> = Singleflight::new();
        let execs = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for key_idx in 0..8usize {
            let barrier = Arc::new(tokio::sync::Barrier::new(2));
            for caller_idx in 0..2usize {
                let sf_c = sf.clone();
                let execs_c = Arc::clone(&execs);
                let barrier_c = Arc::clone(&barrier);
                handles.push(tokio::spawn(async move {
                    barrier_c.wait().await;
                    let key = format!("key-{key_idx}");
                    let (val, _shared) = sf_c
                        .work(key, move || async move {
                            execs_c.fetch_add(1, Ordering::SeqCst);
                            tokio::time::sleep(Duration::from_millis(10)).await;
                            key_idx * 10 + caller_idx - caller_idx
                        })
                        .await
                        .unwrap();
                    assert_eq!(val, key_idx * 10);
                }));
            }
        }
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(execs.load(Ordering::SeqCst), 8);
        assert!(
            sf.flights.is_empty(),
            "all sharded Singleflight entries must be cleaned up after completion"
        );

        // 2. G-04: CacheLayer outside ConcurrencyLimitLayer(1) serves L1 HITs even when
        //    the single backend concurrency permit is held by a slow uncached request.
        let uncached_entered = Arc::new(Notify::new());
        let uncached_release = Arc::new(Notify::new());
        let uncached_entered_c = Arc::clone(&uncached_entered);
        let uncached_release_c = Arc::clone(&uncached_release);

        let backend = tower::service_fn(move |req: Request<SrvBody>| {
            let entered = Arc::clone(&uncached_entered_c);
            let release = Arc::clone(&uncached_release_c);
            async move {
                if req.uri().path() == "/uncached_slow" {
                    entered.notify_one();
                    release.notified().await;
                    return Ok::<_, SrvError>(text_resp("slow-uncached"));
                }
                Ok::<_, SrvError>(text_resp("fast-cached"))
            }
        })
        .boxed_clone_sync();

        let limited = crate::middleware::limit::ConcurrencyLimitLayer::new(1, "test_g04")
            .layer(backend);

        let cache = SharedResponseCache::new(GlobalCacheConfig {
            enabled: true,
            max_bytes: 1024 * 1024,
            default_ttl_seconds: 60,
            max_entry_bytes: 64 * 1024,
            expose_cache_header: true,
            respect_cache_control: false,
            ..Default::default()
        });
        let raw_rules = crate::configuration::CacheLayerConfig {
            namespace: Some("p04_g04_ns".to_string()),
            rules: HashMap::from([("/cached".to_string(), CacheRuleConfig::default())]),
            invalidations: HashMap::new(),
        };
        let compiled = Arc::new(CompiledCacheConfig::from_raw(&raw_rules, "test_g04").unwrap());
        let svc = CacheLayer::new(compiled, "test_g04")
            .with_cache(cache)
            .layer(limited);

        // Populate L1 entry for /cached
        let warm = svc.clone().oneshot(empty_req("/cached")).await.unwrap();
        assert_eq!(warm.status(), StatusCode::OK);
        assert_eq!(warm.headers().get("x-praeco-cache").unwrap(), "MISS");

        // Saturate the single backend permit with /uncached_slow
        let svc_slow = svc.clone();
        let slow_task = tokio::spawn(async move {
            svc_slow.oneshot(empty_req("/uncached_slow")).await.unwrap()
        });
        uncached_entered.notified().await;

        // While the sole backend permit is occupied:
        // a) Uncached /other_miss hits ConcurrencyLimit -> 503 Service Unavailable
        let shed_resp = svc.clone().oneshot(empty_req("/other_miss")).await.unwrap();
        assert_eq!(shed_resp.status(), StatusCode::SERVICE_UNAVAILABLE);

        // b) Cached GET /cached still returns 200 OK (x-praeco-cache: HIT) without touching ConcurrencyLimit!
        let hit_resp = svc.clone().oneshot(empty_req("/cached")).await.unwrap();
        assert_eq!(hit_resp.status(), StatusCode::OK);
        assert_eq!(hit_resp.headers().get("x-praeco-cache").unwrap(), "HIT");

        uncached_release.notify_one();
        let slow_resp = slow_task.await.unwrap();
        assert_eq!(slow_resp.status(), StatusCode::OK);
    }
}
