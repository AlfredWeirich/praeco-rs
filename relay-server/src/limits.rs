//! Rate limiting and connection tracking for the Praeco Relay Server.

use dashmap::DashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

/// Maximum entries retained in the data-plane per-IP rate-limit table before
/// sweeping expired entries and evicting the least-recently-used bucket.
pub(crate) const MAX_RATE_LIMIT_ENTRIES: usize = 100_000;

/// Minimum interval between expiry sweeps when the rate-limit table is at capacity.
const SATURATED_SWEEP_INTERVAL: Duration = Duration::from_secs(1);

/// Idle age after which rate-limit buckets are purged during sweeps.
const BUCKET_IDLE_TTL: Duration = Duration::from_secs(120);

/// Bounded per-IP rate-limit map with throttled expiry sweeps and an O(1) shared
/// overflow bucket on saturation, preventing O(n) scans and cache-thrashing attacks.
pub(crate) struct RateLimitTable {
    pub(crate) buckets: DashMap<IpAddr, TokenBucket>,
    max_entries: usize,
    last_sweep: std::sync::Mutex<Instant>,
    overflow_bucket: std::sync::Mutex<Option<TokenBucket>>,
}

impl RateLimitTable {
    pub(crate) fn with_capacity(max_entries: usize) -> Self {
        Self {
            buckets: DashMap::new(),
            max_entries: max_entries.max(1),
            last_sweep: std::sync::Mutex::new(Instant::now()),
            overflow_bucket: std::sync::Mutex::new(None),
        }
    }

    pub(crate) fn sweep_expired(&self, max_idle: Duration) {
        self.buckets
            .retain(|_, bucket| bucket.last_update().elapsed() < max_idle);
    }

    fn maybe_sweep_when_saturated(&self) {
        if let Ok(mut last) = self.last_sweep.try_lock()
            && last.elapsed() >= SATURATED_SWEEP_INTERVAL
        {
            *last = Instant::now();
            drop(last);
            self.sweep_expired(BUCKET_IDLE_TTL);
        }
    }

    pub(crate) fn check_and_consume(&self, ip: IpAddr, rate: f32, burst: f32) -> bool {
        if let Some(mut bucket) = self.buckets.get_mut(&ip) {
            return bucket.consume(rate, burst);
        }

        if self.buckets.len() >= self.max_entries {
            self.maybe_sweep_when_saturated();
            if self.buckets.len() >= self.max_entries {
                let mut guard = self
                    .overflow_bucket
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                let bucket = guard.get_or_insert_with(|| TokenBucket::new(burst));
                return bucket.consume(rate, burst);
            }
        }

        let mut bucket = self
            .buckets
            .entry(ip)
            .or_insert_with(|| TokenBucket::new(burst));
        bucket.consume(rate, burst)
    }
}


/// Basic token bucket rate limiter tracking connection capacity per canonical IP.
pub struct TokenBucket {
    tokens: f32,
    last_update: Instant,
}

impl TokenBucket {
    /// Creates a new `TokenBucket` initialized with the maximum burst capacity.
    ///
    /// # Arguments
    ///
    /// * `burst` - The maximum number of tokens this bucket can hold.
    pub fn new(burst: f32) -> Self {
        Self {
            tokens: burst,
            last_update: Instant::now(),
        }
    }

    /// Attempts to consume a single token from the bucket.
    ///
    /// The bucket is refilled based on the elapsed time since the last update
    /// multiplied by the refill `rate`.
    ///
    /// # Arguments
    ///
    /// * `rate` - The number of tokens added per second.
    /// * `burst` - The maximum capacity of the bucket.
    ///
    /// # Returns
    ///
    /// Returns `true` if a token was successfully consumed, or `false` if the bucket is empty
    /// (indicating the rate limit has been exceeded).
    pub fn consume(&mut self, rate: f32, burst: f32) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_update).as_secs_f32();

        // Refill tokens based on elapsed time and rate
        self.tokens += elapsed * rate;
        if self.tokens > burst {
            self.tokens = burst;
        }
        self.last_update = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Returns the timestamp of the last bucket update.
    pub fn last_update(&self) -> Instant {
        self.last_update
    }
}

/// Canonicalizes an IP address:
/// - IPv4 addresses remain unchanged.
/// - IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are unwrapped to IPv4.
/// - Loopback (`::1`) and unspecified (`::`) IPv6 addresses remain unchanged.
/// - Standard IPv6 addresses are masked to a `/64` subnet prefix to prevent rate-limit and connection-limit evasion.
///
/// Re-exported from [`common::canonical_client_ip`] to keep the public
/// `praeco_relay_server::canonicalize_ip` API SemVer-compatible without duplicating logic.
pub use common::canonical_client_ip as canonicalize_ip;

/// Central connection tracker for the Relay Server.
/// Enforces global and per-canonical-IP concurrency limits using RAII guards.
pub struct RelayConnectionTracker {
    max_global: usize,
    max_per_ip: usize,
    global_count: AtomicUsize,
    pub(crate) ip_counts: DashMap<IpAddr, usize>,
}

/// RAII guard that decrements the connection count when dropped.
pub struct RelayConnectionGuard {
    tracker: Arc<RelayConnectionTracker>,
    ip: IpAddr,
}

impl Drop for RelayConnectionGuard {
    fn drop(&mut self) {
        self.tracker.global_count.fetch_sub(1, Ordering::SeqCst);
        if let Some(mut count) = self.tracker.ip_counts.get_mut(&self.ip)
            && *count > 0
        {
            *count -= 1;
        }
        // Atomically remove only if still zero under the shard write lock
        // so a concurrent acquire() cannot have its increment wiped out.
        self.tracker.ip_counts.remove_if(&self.ip, |_, c| *c == 0);
    }
}

impl RelayConnectionTracker {
    /// Creates a new [`RelayConnectionTracker`] with the given global and per-IP connection limits.
    pub fn new(max_global: usize, max_per_ip: usize) -> Self {
        Self {
            max_global,
            max_per_ip,
            global_count: AtomicUsize::new(0),
            ip_counts: DashMap::new(),
        }
    }

    /// Attempts to acquire a connection slot for `raw_ip`.
    ///
    /// # Errors
    ///
    /// Returns an error message if either the global or per-IP limit is reached.
    pub fn acquire(
        self: &Arc<Self>,
        raw_ip: IpAddr,
    ) -> Result<RelayConnectionGuard, &'static str> {
        let ip = canonicalize_ip(raw_ip);

        // 1. Check global limit
        let prev_global = self.global_count.fetch_add(1, Ordering::SeqCst);
        if prev_global >= self.max_global {
            self.global_count.fetch_sub(1, Ordering::SeqCst);
            return Err("Global connection limit reached");
        }

        // 2. Check per-IP limit
        let mut entry = self.ip_counts.entry(ip).or_insert(0);
        if *entry >= self.max_per_ip {
            self.global_count.fetch_sub(1, Ordering::SeqCst);
            return Err("Per-IP connection limit reached");
        }
        *entry += 1;
        drop(entry);

        Ok(RelayConnectionGuard {
            tracker: self.clone(),
            ip,
        })
    }

    /// Returns the current number of active connections across all IPs.
    pub fn current_global(&self) -> usize {
        self.global_count.load(Ordering::Relaxed)
    }

    /// Returns the current number of active connections for the canonicalized `raw_ip`.
    pub fn current_for_ip(&self, raw_ip: IpAddr) -> usize {
        let ip = canonicalize_ip(raw_ip);
        self.ip_counts.get(&ip).map(|v| *v).unwrap_or(0)
    }
}

