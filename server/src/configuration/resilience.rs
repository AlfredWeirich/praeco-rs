//! Load-balancing strategies, upstream node circuit-breaker state, and route targets.

use hyper::Uri;
use serde::Deserialize;

const EMA_INITIALIZED_BIT: u64 = 1u64 << 63;
const MAX_EMA_US: u64 = u64::MAX >> 1;

/// Atomic microsecond-precision EMA tracker (`alpha = 0.25`) packed into a single `u64`
/// with bit 63 marking initialization, preventing 0 ms rounding decay from triggering
/// 100% latency spikes on subsequent requests (`Q2-08`).
#[derive(Debug, Default)]
pub(crate) struct EmaState(std::sync::atomic::AtomicU64);

impl EmaState {
    /// Updates `last_ms` and `ema_ms` atomically from a new `sample_ms` observation.
    #[inline]
    pub(crate) fn update(
        &self,
        last_ms: &std::sync::atomic::AtomicU64,
        ema_ms: &std::sync::atomic::AtomicU64,
        sample_ms: u64,
    ) {
        last_ms.store(sample_ms, std::sync::atomic::Ordering::Relaxed);
        let sample_us = sample_ms.saturating_mul(1000).min(MAX_EMA_US);
        let mut prev = self.0.load(std::sync::atomic::Ordering::Relaxed);
        let out_ms = loop {
            let next_us = if prev & EMA_INITIALIZED_BIT == 0 {
                sample_us
            } else {
                let prev_us = prev & !EMA_INITIALIZED_BIT;
                (prev_us.saturating_mul(3).saturating_add(sample_us)) / 4
            };
            let next = EMA_INITIALIZED_BIT | next_us.min(MAX_EMA_US);
            match self.0.compare_exchange_weak(
                prev,
                next,
                std::sync::atomic::Ordering::Relaxed,
                std::sync::atomic::Ordering::Relaxed,
            ) {
                Ok(_) => break next_us / 1000,
                Err(actual) => prev = actual,
            }
        };
        ema_ms.store(out_ms, std::sync::atomic::Ordering::Relaxed);
    }
}


/// A load balancing strategy for downstream forwarding.
#[derive(Debug, Deserialize, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum LbStrategy {
    #[default]
    RoundRobin,
    Random,
    LeastConnections,
    Sticky,
    HighestScore,
}

/// A single upstream node within a load-balanced route target, equipped with
/// a lock-free 3-state circuit breaker (`Closed` -> `Open` -> `HalfOpen`).
#[derive(Debug)]
pub struct UpstreamNode {
    /// The parsed URI for this upstream node.
    pub uri: Uri,
    /// Number of active connections to this upstream (used for LeastConnections).
    pub active_connections: std::sync::atomic::AtomicUsize,
    /// Whether the node is currently considered alive (`CircuitState::Closed`).
    pub is_alive: std::sync::atomic::AtomicBool,
    /// Timestamp of the last failure that opened or re-opened the circuit (seconds since UNIX epoch).
    pub last_failure_time: std::sync::atomic::AtomicU64,
    /// The health score of this node (0-100) reported by active health checks.
    pub current_score: std::sync::atomic::AtomicUsize,
    /// Number of consecutive failures (502/503/504 or transport errors) observed on this node.
    pub consecutive_failures: std::sync::atomic::AtomicUsize,
    /// Current circuit breaker state (`0 = Closed`, `1 = Open`, `2 = HalfOpen`).
    pub circuit_state: std::sync::atomic::AtomicU8,
    /// Monotonic generation counter incremented whenever the circuit transitions
    /// between states, preventing stale in-flight requests from corrupting newer states.
    pub circuit_epoch: std::sync::atomic::AtomicU64,
    /// True while a single `HalfOpen` probe request is actively testing node recovery.
    pub half_open_probe_in_flight: std::sync::atomic::AtomicBool,
    /// Total number of requests dispatched to this upstream node since startup.
    pub total_requests: std::sync::atomic::AtomicU64,
    /// Total number of transport/timeout/outlier failures observed on this node since startup.
    pub total_failures: std::sync::atomic::AtomicU64,
    /// Total number of times the circuit breaker tripped to `Open` for this node.
    pub circuit_trips: std::sync::atomic::AtomicU64,
    /// Total number of requests that failed over away from this node to an alternate healthy node.
    pub failover_retries: std::sync::atomic::AtomicU64,
    /// Response header latency (in milliseconds) of the most recent request to this node.
    pub last_response_ms: std::sync::atomic::AtomicU64,
    /// Exponential moving average (EMA) of response header latency (in milliseconds).
    pub ema_response_ms: std::sync::atomic::AtomicU64,
    /// Packed microsecond EMA state distinguishing "uninitialized" from 0 ms (`Q2-08`).
    ema_state: EmaState,
}

impl UpstreamNode {
    /// Creates a new healthy (`CircuitState::Closed`) upstream node for `uri`.
    pub fn new(uri: Uri) -> Self {
        Self {
            uri,
            active_connections: std::sync::atomic::AtomicUsize::new(0),
            is_alive: std::sync::atomic::AtomicBool::new(true),
            last_failure_time: std::sync::atomic::AtomicU64::new(0),
            current_score: std::sync::atomic::AtomicUsize::new(0),
            consecutive_failures: std::sync::atomic::AtomicUsize::new(0),
            circuit_state: std::sync::atomic::AtomicU8::new(
                crate::middleware::router::circuit_breaker::CircuitState::Closed as u8,
            ),
            circuit_epoch: std::sync::atomic::AtomicU64::new(0),
            half_open_probe_in_flight: std::sync::atomic::AtomicBool::new(false),
            total_requests: std::sync::atomic::AtomicU64::new(0),
            total_failures: std::sync::atomic::AtomicU64::new(0),
            circuit_trips: std::sync::atomic::AtomicU64::new(0),
            failover_retries: std::sync::atomic::AtomicU64::new(0),
            last_response_ms: std::sync::atomic::AtomicU64::new(0),
            ema_response_ms: std::sync::atomic::AtomicU64::new(0),
            ema_state: EmaState::default(),
        }
    }

    /// Records the observed response header latency (in milliseconds) and updates the EMA.
    #[inline]
    pub fn record_latency_ms(&self, sample_ms: u64) {
        self.ema_state
            .update(&self.last_response_ms, &self.ema_response_ms, sample_ms);
    }

    /// Returns the current [`CircuitState`](crate::middleware::router::circuit_breaker::CircuitState) of this node.
    #[inline]
    pub fn circuit_state(&self) -> crate::middleware::router::circuit_breaker::CircuitState {
        crate::middleware::router::circuit_breaker::CircuitState::from_u8(
            self.circuit_state.load(std::sync::atomic::Ordering::Acquire),
        )
    }

    /// Immediately trips the circuit breaker to `Open`, marks the node as dead,
    /// releases any in-flight `HalfOpen` probe lock, and records the current failure timestamp.
    pub fn mark_dead(&self) {
        self.circuit_epoch
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        self.total_failures
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let was_alive = self
            .is_alive
            .swap(false, std::sync::atomic::Ordering::AcqRel);
        let prev_state = self.circuit_state.swap(
            crate::middleware::router::circuit_breaker::CircuitState::Open as u8,
            std::sync::atomic::Ordering::AcqRel,
        );
        self.half_open_probe_in_flight
            .store(false, std::sync::atomic::Ordering::Release);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_failure_time
            .store(now, std::sync::atomic::Ordering::Release);

        if was_alive
            || prev_state != crate::middleware::router::circuit_breaker::CircuitState::Open as u8
        {
            self.circuit_trips
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::warn!(
                "[CIRCUIT BREAKER] State -> OPEN (node marked dead): {}",
                self.uri
            );
        }
    }

    /// Marks the node as alive (`CircuitState::Closed`), clears the failure timestamp,
    /// and resets consecutive failure counters.
    pub fn mark_alive(&self) {
        self.circuit_epoch
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        self.consecutive_failures
            .store(0, std::sync::atomic::Ordering::Release);
        self.half_open_probe_in_flight
            .store(false, std::sync::atomic::Ordering::Release);
        let prev_state = self.circuit_state.swap(
            crate::middleware::router::circuit_breaker::CircuitState::Closed as u8,
            std::sync::atomic::Ordering::AcqRel,
        );
        let was_alive = self
            .is_alive
            .swap(true, std::sync::atomic::Ordering::AcqRel);
        self.last_failure_time
            .store(0, std::sync::atomic::Ordering::Release);

        if !was_alive
            || prev_state != crate::middleware::router::circuit_breaker::CircuitState::Closed as u8
        {
            tracing::warn!(
                "[CIRCUIT BREAKER] State -> CLOSED (node recovered): {}",
                self.uri
            );
        }
    }

    /// Records a successful upstream response, closing the circuit breaker if it was `HalfOpen`
    /// and resetting `consecutive_failures` to `0` while `Closed`.
    ///
    /// **Guard:** If the circuit is currently `Open`, a late `2xx` response never closes it
    /// directly; recovery must go through a `HalfOpen` probe or explicit [`UpstreamNode::mark_alive`].
    #[inline]
    pub fn record_success(&self) {
        match self.circuit_state() {
            crate::middleware::router::circuit_breaker::CircuitState::Open => {
                // Never allow a late in-flight 2xx to close an Open circuit.
            }
            crate::middleware::router::circuit_breaker::CircuitState::HalfOpen => {
                self.mark_alive();
            }
            crate::middleware::router::circuit_breaker::CircuitState::Closed => {
                if self
                    .consecutive_failures
                    .load(std::sync::atomic::Ordering::Relaxed)
                    > 0
                {
                    self.consecutive_failures
                        .store(0, std::sync::atomic::Ordering::Release);
                }
            }
        }
    }

    /// Epoch-checked variant of [`UpstreamNode::record_success`] that ignores stale
    /// in-flight responses belonging to an earlier [`UpstreamNode::circuit_epoch`].
    #[inline]
    pub fn record_success_with_epoch(&self, expected_epoch: u64) {
        if self
            .circuit_epoch
            .load(std::sync::atomic::Ordering::Acquire)
            != expected_epoch
        {
            return;
        }
        self.record_success();
    }

    /// Records an upstream outlier failure (e.g. HTTP `502`/`503`/`504` or gRPC `UNAVAILABLE`).
    ///
    /// - Increments `consecutive_failures`.
    /// - If the circuit was in `HalfOpen` (probe failed) or `consecutive_failures >= failure_threshold`,
    ///   trips the circuit breaker to `Open` (`mark_dead`) and returns `true`.
    /// - Otherwise keeps the circuit `Closed` and returns `false`.
    pub fn record_failure(&self, failure_threshold: usize) -> bool {
        let failures = self
            .consecutive_failures
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
            + 1;
        let was_probe = self
            .half_open_probe_in_flight
            .swap(false, std::sync::atomic::Ordering::AcqRel)
            || self.circuit_state()
                == crate::middleware::router::circuit_breaker::CircuitState::HalfOpen;

        if was_probe || failures >= failure_threshold.max(1) {
            self.mark_dead();
            true
        } else {
            self.total_failures
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            tracing::warn!(
                "[CIRCUIT BREAKER] Outlier failure ({}/{}): {}",
                failures,
                failure_threshold,
                self.uri
            );
            false
        }
    }

    /// Epoch-checked variant of [`UpstreamNode::record_failure`] that avoids letting a
    /// stale in-flight failure from an earlier epoch abort a newer `HalfOpen` probe.
    pub fn record_failure_with_epoch(&self, failure_threshold: usize, expected_epoch: u64) -> bool {
        let current_epoch = self
            .circuit_epoch
            .load(std::sync::atomic::Ordering::Acquire);
        if current_epoch != expected_epoch
            && self.circuit_state()
                == crate::middleware::router::circuit_breaker::CircuitState::HalfOpen
        {
            return false;
        }
        self.record_failure(failure_threshold)
    }

    /// Attempts to claim the single `HalfOpen` probe slot for an `Open` node whose
    /// `cooldown_seconds` has elapsed.
    ///
    /// Returns `true` if and only if this caller transitioned the node into `HalfOpen`.
    /// All other concurrent callers will receive `false` and avoid a thundering herd.
    pub fn try_enter_half_open_probe(&self, cooldown_seconds: u64) -> bool {
        self.try_enter_half_open_probe_epoch(cooldown_seconds)
            .is_some()
    }

    /// Atomically transitions `Open -> HalfOpen` under `half_open_probe_in_flight` and
    /// returns the new `circuit_epoch` for epoch-checked completion/rollback.
    pub fn try_enter_half_open_probe_epoch(&self, cooldown_seconds: u64) -> Option<u64> {
        if self.is_alive.load(std::sync::atomic::Ordering::Acquire) {
            return None;
        }
        let last_fail = self
            .last_failure_time
            .load(std::sync::atomic::Ordering::Acquire);
        if last_fail == 0 {
            return None;
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if now <= last_fail + cooldown_seconds {
            return None;
        }

        if self
            .half_open_probe_in_flight
            .compare_exchange(
                false,
                true,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            )
            .is_ok()
        {
            if self
                .circuit_state
                .compare_exchange(
                    crate::middleware::router::circuit_breaker::CircuitState::Open as u8,
                    crate::middleware::router::circuit_breaker::CircuitState::HalfOpen as u8,
                    std::sync::atomic::Ordering::AcqRel,
                    std::sync::atomic::Ordering::Acquire,
                )
                .is_err()
            {
                self.half_open_probe_in_flight
                    .store(false, std::sync::atomic::Ordering::Release);
                return None;
            }
            let epoch = self
                .circuit_epoch
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel)
                .wrapping_add(1);
            tracing::warn!(
                "[CIRCUIT BREAKER] State -> HALF-OPEN (single probe): {} (cooldown {}s elapsed)",
                self.uri,
                cooldown_seconds
            );
            Some(epoch)
        } else {
            None
        }
    }

    /// Checks if the node is considered available for routing.
    ///
    /// A node is available if:
    /// 1. Its circuit is `Closed` (`is_alive == true`), OR
    /// 2. Its circuit is `Open`, `cooldown_seconds` has elapsed, **and** no `HalfOpen` probe
    ///    request is currently in flight (`half_open_probe_in_flight == false`).
    pub fn is_available(&self, cooldown_seconds: u64) -> bool {
        if self.is_alive.load(std::sync::atomic::Ordering::Acquire) {
            return true;
        }

        // While a single HalfOpen probe is in flight, hold back other traffic
        if self
            .half_open_probe_in_flight
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return false;
        }

        let last_fail = self
            .last_failure_time
            .load(std::sync::atomic::Ordering::Acquire);
        if last_fail == 0 {
            // Node is explicitly marked dead but has no failure timestamp: not available
            return false;
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        now > last_fail + cooldown_seconds
    }
}

/// Cached gRPC DescriptorPool with creation timestamp for TTL-based cache expiration.
#[derive(Debug, Clone)]
pub struct CachedDescriptorPool {
    /// The loaded descriptor pool containing protobuf definitions.
    pub pool: std::sync::Arc<prost_reflect::DescriptorPool>,
    /// Instant when this pool was retrieved via gRPC reflection.
    pub created_at: std::time::Instant,
}

/// The load-balanced target configuration for a parsed route.
#[derive(Debug)]
pub struct RouteTarget {
    /// The available upstream nodes.
    pub upstreams: Vec<UpstreamNode>,
    /// The strategy to distribute requests among `upstreams`.
    pub strategy: LbStrategy,
    /// Atomic counter used for RoundRobin selection.
    pub rr_counter: std::sync::atomic::AtomicUsize,
    /// Cooldown time for dead nodes before they can be retried.
    pub cooldown_seconds: u64,
    /// Maximum amount of automatic retry attempts.
    pub max_retries: usize,
    /// Consecutive 502/503/504 outlier failures required to trip the circuit breaker to `Open`.
    pub failure_threshold: usize,
    /// Maximum request body size in bytes buffered in RAM for automatic retries.
    pub max_retry_buffer_bytes: usize,
    /// Interval in seconds for actively polling the /health endpoint of upstreams. 0 means disabled.
    pub active_health_check_interval: u64,
    /// Cached gRPC DescriptorPool from reflection, lazily loaded by the router with TTL.
    /// Only used if backend_type is Grpc.
    pub grpc_pool: tokio::sync::RwLock<Option<CachedDescriptorPool>>,
    /// Mutex to synchronize reflection fetches without holding the read/write lock across network I/O.
    pub grpc_reflection_lock: tokio::sync::Mutex<()>,
}

impl RouteTarget {
    /// Immediately marks an upstream node as dead (`CircuitState::Open`) due to a hard connection/timeout failure.
    pub fn mark_dead(&self, uri: &Uri) {
        for node in &self.upstreams {
            if &node.uri == uri {
                node.mark_dead();
                break;
            }
        }
    }

    /// Records an upstream outlier failure (HTTP `502`/`503`/`504` or gRPC `UNAVAILABLE`)
    /// and trips the node's circuit breaker to `Open` once `failure_threshold` is reached
    /// (or immediately if the node was in `HalfOpen`).
    pub fn record_failure(&self, uri: &Uri) -> bool {
        for node in &self.upstreams {
            if &node.uri == uri {
                return node.record_failure(self.failure_threshold);
            }
        }
        false
    }

    /// Marks an upstream node as alive (`CircuitState::Closed`) after a successful request or health check.
    pub fn mark_alive(&self, uri: &Uri) {
        for node in &self.upstreams {
            if &node.uri == uri {
                node.mark_alive();
                break;
            }
        }
    }

    /// Selects the next upstream node based on the configured load-balancing strategy,
    /// returning `None` if no upstreams are configured (`Q2-08`, panic-free).
    ///
    /// Stack-allocated for up to 8 upstream nodes via `SmallVec` to eliminate per-request
    /// heap allocations on the router hot path.
    pub fn next_upstream(
        &self,
        client_ip: Option<&std::net::SocketAddr>,
        failed_uris: &[Uri],
    ) -> Option<&UpstreamNode> {
        if self.upstreams.is_empty() {
            return None;
        }

        // Fast-path for single-backend routes: zero heap allocations, no circuit-breaker filtering needed
        if self.upstreams.len() == 1 {
            return self.upstreams.first();
        }

        // Collect available candidates on the stack (no heap alloc for <= 8 nodes).
        let mut candidates: smallvec::SmallVec<[&UpstreamNode; 8]> = self
            .upstreams
            .iter()
            .filter(|n| n.is_available(self.cooldown_seconds) && !failed_uris.contains(&n.uri))
            .collect();

        if candidates.is_empty() {
            // Fallback 1: try nodes not explicitly failed this request
            candidates = self
                .upstreams
                .iter()
                .filter(|n| !failed_uris.contains(&n.uri))
                .collect();
            if candidates.is_empty() {
                // Fallback 2: consider all upstreams
                candidates = self.upstreams.iter().collect();
            }
        }

        if candidates.is_empty() {
            return None;
        }
        if candidates.len() == 1 {
            return candidates.first().copied();
        }

        match self.strategy {
            LbStrategy::RoundRobin => {
                let count = self
                    .rr_counter
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                candidates.get(count % candidates.len()).copied()
            }
            LbStrategy::Random => {
                let index = rand::random_range(0..candidates.len());
                candidates.get(index).copied()
            }
            LbStrategy::LeastConnections => candidates
                .iter()
                .copied()
                .min_by_key(|node| {
                    node.active_connections
                        .load(std::sync::atomic::Ordering::Relaxed)
                })
                .or_else(|| candidates.first().copied()),
            LbStrategy::Sticky => {
                let hash = if let Some(addr) = client_ip {
                    use std::hash::{Hash, Hasher};
                    let mut hasher = std::collections::hash_map::DefaultHasher::new();
                    addr.ip().hash(&mut hasher);
                    hasher.finish() as usize
                } else {
                    // Fallback to random if no IP is provided
                    rand::random_range(0..candidates.len())
                };
                candidates.get(hash % candidates.len()).copied()
            }
            LbStrategy::HighestScore => candidates
                .iter()
                .copied()
                .max_by_key(|node| {
                    node.current_score
                        .load(std::sync::atomic::Ordering::Relaxed)
                })
                .or_else(|| candidates.first().copied()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    #[test]
    fn test_next_upstream_returns_none_on_empty_upstreams_across_all_strategies() {
        let strategies = [
            LbStrategy::RoundRobin,
            LbStrategy::Random,
            LbStrategy::LeastConnections,
            LbStrategy::Sticky,
            LbStrategy::HighestScore,
        ];
        let ip: std::net::SocketAddr = match "127.0.0.1:4000".parse() {
            Ok(a) => a,
            Err(e) => panic!("valid test addr: {e}"),
        };
        for strategy in strategies {
            let target = RouteTarget {
                upstreams: Vec::new(),
                strategy,
                rr_counter: std::sync::atomic::AtomicUsize::new(0),
                cooldown_seconds: 10,
                max_retries: 0,
                failure_threshold: 3,
                max_retry_buffer_bytes: 65536,
                active_health_check_interval: 0,
                grpc_pool: tokio::sync::RwLock::new(None),
                grpc_reflection_lock: tokio::sync::Mutex::new(()),
            };
            assert!(target.next_upstream(Some(&ip), &[]).is_none());
            assert!(target.next_upstream(None, &[]).is_none());
        }
    }

    #[test]
    fn test_ema_state_avoids_zero_reset_spike_after_sub_millisecond_samples() {
        let last = AtomicU64::new(0);
        let ema = AtomicU64::new(0);
        let state = EmaState::default();

        // Initial sub-millisecond sample initializes EMA to 0 ms (and marks initialized)
        state.update(&last, &ema, 0);
        assert_eq!(last.load(Ordering::Relaxed), 0);
        assert_eq!(ema.load(Ordering::Relaxed), 0);

        // Next 40 ms sample must smooth to (0*3 + 40)/4 = 10 ms, NOT spike to 40 ms
        state.update(&last, &ema, 40);
        assert_eq!(last.load(Ordering::Relaxed), 40);
        assert_eq!(ema.load(Ordering::Relaxed), 10);

        // Decay back to 0 ms via many 0 ms samples, then verify next 40 ms still smooths to 10 ms
        for _ in 0..40 {
            state.update(&last, &ema, 0);
        }
        assert_eq!(ema.load(Ordering::Relaxed), 0);
        state.update(&last, &ema, 40);
        assert_eq!(ema.load(Ordering::Relaxed), 10);
    }
}
