//! # Dragonfly / Redis Production L2 Backend (`otp-actor` Supervision Tree)
//!
//! Implements [`L2CacheBackend`] backed by Dragonfly (or Redis) over multiplexed async
//! connections with strict `aws-lc-rs` TLS (`K-04`), fail-open 0-ns readiness checks (`K-03`),
//! bounded micro-batched background writes (`K-06`), and live Pub/Sub cluster invalidation with
//! restart-resilient generation resync (`K-07`).
//!
//! ## Supervision Hierarchy
//! ```text
//! Supervisor ("l2-cache", OneForOne, ShutdownPolicy::Timeout(3s))
//!   ├── 1. L2ConnectionActor  (ResourceActor<Conn>)   — registered 1st, stopped last
//!   ├── 2. L2WriterActor      (StatefulActor)         — flushes pending batches on_stop
//!   └── 3. L2InvalidationActor(StatefulActor + Scope) — INCR + PUBLISH + Pub/Sub resync
//! ```

use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use bytes::Bytes;
use dashmap::DashMap;
use futures_util::StreamExt as _;
use otp_actor::{
    ActorClient, ActorContext, CacheState, LocalNodeMonitor, ResourceActor, ResourceClient,
    RestartPolicy, RestartType, StatefulActor, StatefulActorBuilder, SupervisionStrategy,
    Supervisor, SupervisorHandle, TimedResource, WorkerContext,
};
use redis::{ConnectionAddr, IntoConnectionInfo as _};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{
    configuration::L2CacheConfig,
    middleware::{
        cache::CacheKey,
        cache_l2::{
            L2CacheBackend, L2CircuitBreaker, L2CircuitState, L2InvalidationEvent,
            L2LookupOutcome, L2StatusSnapshot, L2WriteBudget, L2WritePermit,
            MIN_L2_HIT_REMAINING_TTL, MIN_L2_WRITE_TTL, decode_wire_v1, encode_l2_entry_key,
            encode_l2_global_gen_key, encode_l2_inv_channel, encode_l2_ns_gen_key, encode_wire_v1,
        },
    },
};

/// Maximum tracked namespace entries in [`RemoteGenBookkeeper`] (`K-07`, matches `cache.rs`).
const MAX_TRACKED_NAMESPACES: usize = 4096;

/// Minimum interval between asynchronous background `force_refresh()` triggers.
const REFRESH_THROTTLE_MS: u64 = 250;

/// Maximum exponential backoff ceiling for Pub/Sub reconnects (`K-07`).
const PUBSUB_RECONNECT_MAX_MS: u64 = 5_000;

/// Base delay for Pub/Sub reconnect exponential backoff.
const PUBSUB_RECONNECT_BASE_MS: u64 = 100;

/// Minimum `ConnectionManager` response timeout ceiling so slow operations obey explicit timeouts.
const MIN_CONN_MANAGER_RESPONSE_TIMEOUT: Duration = Duration::from_secs(2);

/// Callback invoked when cluster invalidations arrive from Dragonfly Pub/Sub or reconnect resync.
pub type InvalidationCallback = Arc<dyn Fn(L2InvalidationEvent) + Send + Sync>;

/// Errors returned when constructing or managing [`DragonflyL2Backend`].
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DragonflyL2Error {
    /// Invalid or disabled `[cache.l2]` configuration.
    #[error("invalid L2 cache configuration: {0}")]
    InvalidConfig(String),
    /// Password resolution from `password_env` or `password_file` failed.
    #[error("L2 authentication secret error: {0}")]
    AuthConfig(String),
    /// TLS root CA or mTLS client certificate/key loading failed.
    #[error("L2 TLS configuration error for '{path}': {reason}")]
    TlsConfig { path: String, reason: String },
    /// Underlying Redis/Dragonfly client construction failure.
    #[error("Dragonfly/Redis client error: {0}")]
    Redis(#[from] redis::RedisError),
    /// `otp-actor` supervision startup error.
    #[error("L2 supervision startup failed: {0}")]
    Supervisor(#[from] otp_actor::SupervisorError),
}

// ============================================================================
//  Config Secret Resolution & Pure aws-lc-rs TLS Client Builder (K-04, K-10)
// ============================================================================

async fn resolve_l2_password(cfg: &L2CacheConfig) -> Result<Option<String>, DragonflyL2Error> {
    if let Some(ref env_name) = cfg.password_env {
        let trimmed = env_name.trim();
        let val = std::env::var(trimmed).map_err(|_| {
            DragonflyL2Error::AuthConfig(format!(
                "environment variable '{trimmed}' is not set or not valid UTF-8"
            ))
        })?;
        if val.is_empty() {
            return Err(DragonflyL2Error::AuthConfig(format!(
                "environment variable '{trimmed}' is empty"
            )));
        }
        return Ok(Some(val));
    }

    if let Some(ref file_path) = cfg.password_file {
        let trimmed_path = file_path.trim();
        let raw = tokio::fs::read_to_string(trimmed_path).await.map_err(|e| {
            DragonflyL2Error::AuthConfig(format!(
                "failed to read password_file '{trimmed_path}': {e}"
            ))
        })?;
        let cleaned = raw.trim_end_matches(&['\r', '\n'][..]);
        if cleaned.is_empty() {
            return Err(DragonflyL2Error::AuthConfig(format!(
                "password_file '{trimmed_path}' is empty"
            )));
        }
        return Ok(Some(cleaned.to_string()));
    }

    Ok(None)
}

async fn read_tls_file(path: &str) -> Result<Vec<u8>, DragonflyL2Error> {
    let trimmed = path.trim();
    tokio::fs::read(trimmed)
        .await
        .map_err(|e| DragonflyL2Error::TlsConfig {
            path: trimmed.to_string(),
            reason: e.to_string(),
        })
}

/// Validates `cfg`, resolves out-of-band authentication secrets (`K-10`), and configures
/// `aws-lc-rs` TLS/mTLS (`K-04`) to construct a `redis::Client`.
#[tracing::instrument(skip(cfg), fields(endpoint = %cfg.redacted_url()), err)]
pub(crate) async fn build_redis_client(
    cfg: &L2CacheConfig,
) -> Result<redis::Client, DragonflyL2Error> {
    cfg.validate()
        .map_err(|e| DragonflyL2Error::InvalidConfig(e.to_string()))?;
    if !cfg.enabled {
        return Err(DragonflyL2Error::InvalidConfig(
            "L2 cache is disabled".to_string(),
        ));
    }

    let password = resolve_l2_password(cfg).await?;
    let mut conn_info = cfg.url.trim().into_connection_info()?;

    if conn_info.redis_settings().password().is_some() {
        return Err(DragonflyL2Error::InvalidConfig(
            "inline password in URL is forbidden; use password_env or password_file".to_string(),
        ));
    }

    if let Some(pw) = password {
        let redis_settings = conn_info.redis_settings().clone().set_password(pw);
        conn_info = conn_info.set_redis_settings(redis_settings);
    }

    let is_tls = matches!(conn_info.addr(), ConnectionAddr::TcpTls { .. });
    let has_custom_tls =
        cfg.tls_ca_file.is_some() || cfg.tls_cert_file.is_some() || cfg.tls_key_file.is_some();

    if !is_tls && has_custom_tls {
        return Err(DragonflyL2Error::InvalidConfig(
            "tls_ca_file / tls_cert_file / tls_key_file require a rediss:// URL".to_string(),
        ));
    }

    if is_tls {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        if has_custom_tls {
            let root_cert = match cfg.tls_ca_file.as_deref() {
                Some(path) => Some(read_tls_file(path).await?),
                None => None,
            };
            let client_tls = match (cfg.tls_cert_file.as_deref(), cfg.tls_key_file.as_deref()) {
                (Some(cert_path), Some(key_path)) => Some(redis::ClientTlsConfig {
                    client_cert: read_tls_file(cert_path).await?,
                    client_key: read_tls_file(key_path).await?,
                }),
                (None, None) => None,
                _ => {
                    return Err(DragonflyL2Error::InvalidConfig(
                        "tls_cert_file and tls_key_file must both be configured".to_string(),
                    ));
                }
            };
            let client = redis::Client::build_with_tls(
                conn_info,
                redis::TlsCertificates {
                    client_tls,
                    root_cert,
                },
            )?;
            return Ok(client);
        }
    }

    Ok(redis::Client::open(conn_info)?)
}

// ============================================================================
//  Zero-Cost Transport Abstraction (Redis/Dragonfly + Deterministic Tests)
// ============================================================================

pub(crate) struct RawPipelineRead {
    pub global_gen: u64,
    pub ns_gen: u64,
    pub raw_entry: Option<Bytes>,
    pub pttl_ms: i64,
}

#[derive(Clone)]
pub(crate) struct PreparedWriteItem {
    pub entry_key: String,
    pub wire_bytes: Bytes,
    pub ttl_ms: u64,
}

pub(crate) type PubSubPayloadStream = Pin<Box<dyn futures::Stream<Item = Vec<u8>> + Send + 'static>>;

pub(crate) trait DragonflyTransport: Send + Sync + 'static {
    type Conn: Clone + Send + Sync + 'static;

    fn connect(&self) -> impl Future<Output = Result<Self::Conn, String>> + Send;

    fn read_entry<'a>(
        &'a self,
        conn: &'a mut Self::Conn,
        global_gen_key: &'a str,
        ns_gen_key: &'a str,
        entry_key: &'a str,
    ) -> impl Future<Output = Result<RawPipelineRead, String>> + Send;

    fn fetch_generations<'a>(
        &'a self,
        conn: &'a mut Self::Conn,
        keys: &'a [String],
    ) -> impl Future<Output = Result<Vec<Option<u64>>, String>> + Send;

    fn write_batch<'a>(
        &'a self,
        conn: &'a mut Self::Conn,
        items: &'a [PreparedWriteItem],
    ) -> impl Future<Output = Result<(), String>> + Send;

    fn incr_and_publish<'a>(
        &'a self,
        conn: &'a mut Self::Conn,
        gen_key: &'a str,
        inv_channel: &'a str,
        payload: &'a [u8],
    ) -> impl Future<Output = Result<u64, String>> + Send;

    fn subscribe_invalidations<'a>(
        &'a self,
        inv_channel: &'a str,
    ) -> impl Future<Output = Result<PubSubPayloadStream, String>> + Send;
}

pub(crate) struct RedisTransport {
    client: redis::Client,
    connect_timeout: Duration,
    read_timeout: Duration,
    write_timeout: Duration,
}

impl RedisTransport {
    fn new(
        client: redis::Client,
        connect_timeout: Duration,
        read_timeout: Duration,
        write_timeout: Duration,
    ) -> Self {
        Self {
            client,
            connect_timeout,
            read_timeout,
            write_timeout,
        }
    }
}

impl DragonflyTransport for RedisTransport {
    type Conn = redis::aio::ConnectionManager;

    async fn connect(&self) -> Result<Self::Conn, String> {
        let response_timeout = self
            .read_timeout
            .max(self.write_timeout)
            .max(MIN_CONN_MANAGER_RESPONSE_TIMEOUT);
        let mgr_cfg = redis::aio::ConnectionManagerConfig::new()
            .set_connection_timeout(Some(self.connect_timeout))
            .set_response_timeout(Some(response_timeout))
            .set_number_of_retries(1)
            .set_min_delay(Duration::from_millis(50))
            .set_max_delay(Duration::from_millis(250));

        tokio::time::timeout(
            self.connect_timeout,
            redis::aio::ConnectionManager::new_with_config(self.client.clone(), mgr_cfg),
        )
        .await
        .map_err(|_| format!("Dragonfly connect timed out after {:?}", self.connect_timeout))?
        .map_err(|e| e.to_string())
    }

    async fn read_entry(
        &self,
        conn: &mut Self::Conn,
        global_gen_key: &str,
        ns_gen_key: &str,
        entry_key: &str,
    ) -> Result<RawPipelineRead, String> {
        // 1-RTT cluster-slot-safe pipeline (`K-01`).
        let mut pipe = redis::pipe();
        pipe.get(global_gen_key)
            .get(ns_gen_key)
            .get(entry_key)
            .cmd("PTTL")
            .arg(entry_key);
        let (global_gen, ns_gen, raw_entry, pttl_ms): (Option<u64>, Option<u64>, Option<Vec<u8>>, i64) =
            pipe.query_async(conn).await.map_err(|e| e.to_string())?;
        Ok(RawPipelineRead {
            global_gen: global_gen.unwrap_or(0),
            ns_gen: ns_gen.unwrap_or(0),
            raw_entry: raw_entry.map(Bytes::from),
            pttl_ms,
        })
    }

    async fn fetch_generations(
        &self,
        conn: &mut Self::Conn,
        keys: &[String],
    ) -> Result<Vec<Option<u64>>, String> {
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        let mut pipe = redis::pipe();
        for key in keys {
            pipe.get(key);
        }
        pipe.query_async(conn).await.map_err(|e| e.to_string())
    }

    async fn write_batch(
        &self,
        conn: &mut Self::Conn,
        items: &[PreparedWriteItem],
    ) -> Result<(), String> {
        if items.is_empty() {
            return Ok(());
        }
        let mut pipe = redis::pipe();
        for item in items {
            pipe.cmd("SET")
                .arg(&item.entry_key)
                .arg(item.wire_bytes.as_ref())
                .arg("PX")
                .arg(item.ttl_ms)
                .ignore();
        }
        pipe.exec_async(conn).await.map_err(|e| e.to_string())
    }

    async fn incr_and_publish(
        &self,
        conn: &mut Self::Conn,
        gen_key: &str,
        inv_channel: &str,
        payload: &[u8],
    ) -> Result<u64, String> {
        let mut pipe = redis::pipe();
        pipe.incr(gen_key, 1u64)
            .publish(inv_channel, payload)
            .ignore();
        let (new_gen,): (u64,) = pipe.query_async(conn).await.map_err(|e| e.to_string())?;
        Ok(new_gen)
    }

    async fn subscribe_invalidations(&self, inv_channel: &str) -> Result<PubSubPayloadStream, String> {
        let mut pubsub = tokio::time::timeout(self.connect_timeout, self.client.get_async_pubsub())
            .await
            .map_err(|_| {
                format!(
                    "Dragonfly Pub/Sub connect timed out after {:?}",
                    self.connect_timeout
                )
            })?
            .map_err(|e| e.to_string())?;

        tokio::time::timeout(self.connect_timeout, pubsub.subscribe(inv_channel))
            .await
            .map_err(|_| {
                format!(
                    "Dragonfly Pub/Sub subscribe timed out after {:?}",
                    self.connect_timeout
                )
            })?
            .map_err(|e| e.to_string())?;

        let stream = pubsub
            .into_on_message()
            .map(|msg| msg.get_payload_bytes().to_vec());
        Ok(Box::pin(stream))
    }
}

// ============================================================================
//  Shared Generation Tracker (K-07) & Throttled Reconnect Helper (K-03)
// ============================================================================

#[derive(Default)]
struct RemoteGenBookkeeper {
    has_global: AtomicBool,
    last_global_gen: AtomicU64,
    ns_gens: DashMap<String, AtomicU64>,
}

impl RemoteGenBookkeeper {
    fn observe_global(&self, gen_val: u64) {
        self.last_global_gen.store(gen_val, Ordering::Release);
        self.has_global.store(true, Ordering::Release);
    }

    fn observe_namespace(&self, namespace: &str, gen_val: u64) {
        if let Some(counter) = self.ns_gens.get(namespace) {
            counter.store(gen_val, Ordering::Release);
            return;
        }
        if self.ns_gens.len() < MAX_TRACKED_NAMESPACES {
            self.ns_gens
                .entry(namespace.to_string())
                .or_insert_with(|| AtomicU64::new(gen_val))
                .store(gen_val, Ordering::Release);
        }
    }

    fn snapshot(&self) -> (Option<u64>, Vec<(String, u64)>) {
        let global = self
            .has_global
            .load(Ordering::Acquire)
            .then(|| self.last_global_gen.load(Ordering::Acquire));
        let namespaces = self
            .ns_gens
            .iter()
            .map(|entry| (entry.key().clone(), entry.value().load(Ordering::Acquire)))
            .collect();
        (global, namespaces)
    }
}

#[inline]
fn now_epoch_ms() -> u64 {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX)
}

#[inline]
fn connection_cache_is_ready(state: CacheState) -> bool {
    matches!(
        state,
        CacheState::Fresh { .. } | CacheState::RefreshDue { .. } | CacheState::StaleUsable { .. }
    )
}

fn maybe_trigger_throttled_refresh<C>(
    conn_client: &ResourceClient<C, String>,
    last_refresh_ms: &AtomicU64,
) where
    C: Clone + Send + Sync + 'static,
{
    let now = now_epoch_ms();
    let prev = last_refresh_ms.load(Ordering::Acquire);
    if now.saturating_sub(prev) < REFRESH_THROTTLE_MS {
        return;
    }
    if last_refresh_ms
        .compare_exchange(prev, now, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        let client = conn_client.clone();
        tokio::spawn(async move {
            let _ = client.force_refresh().await;
        });
    }
}

fn record_failure_and_maybe_refresh<C>(
    cb: &L2CircuitBreaker,
    conn_client: &ResourceClient<C, String>,
    last_refresh_ms: &AtomicU64,
) where
    C: Clone + Send + Sync + 'static,
{
    let tripped = cb.record_failure();
    if tripped || !connection_cache_is_ready(conn_client.cache_state()) {
        maybe_trigger_throttled_refresh(conn_client, last_refresh_ms);
    }
}

// ============================================================================
//  L2WriterActor (StatefulActor: Micro-Batching, L2WriteBudget, on_stop Drain)
// ============================================================================

enum WriterMsg {
    Write {
        entry_key: String,
        namespace: String,
        ns_gen_key: String,
        entry: Arc<crate::middleware::cache::CachedResponse>,
        expected_remote_gen: Option<(u64, u64)>,
        estimated_bytes: usize,
        permit: L2WritePermit,
    },
    Flush,
}

struct PendingWrite {
    namespace: String,
    ns_gen_key: String,
    entry: Arc<crate::middleware::cache::CachedResponse>,
    expected_remote_gen: Option<(u64, u64)>,
    estimated_bytes: usize,
    _permit: L2WritePermit,
}

struct L2WriterActor<T: DragonflyTransport> {
    transport: Arc<T>,
    conn_client: ResourceClient<T::Conn, String>,
    circuit_breaker: Arc<L2CircuitBreaker>,
    last_refresh_ms: Arc<AtomicU64>,
    remote_gens: Arc<RemoteGenBookkeeper>,
    global_gen_key: String,
    compress_min_bytes: usize,
    write_timeout: Duration,
    write_batch_size: usize,
    write_batch_max_bytes: usize,
    write_flush_delay: Duration,
    pending: HashMap<String, PendingWrite>,
    pending_bytes: usize,
    flush_scheduled: bool,
    flush_timer: Option<tokio::task::AbortHandle>,
}

impl<T: DragonflyTransport> L2WriterActor<T> {
    async fn flush_batch(&mut self, timeout: Duration) {
        if let Some(handle) = self.flush_timer.take() {
            handle.abort();
        }
        self.flush_scheduled = false;
        self.pending_bytes = 0;

        if self.pending.is_empty() {
            return;
        }
        let batch: Vec<(String, PendingWrite)> = self.pending.drain().collect();

        if !self.circuit_breaker.allow_request() {
            return;
        }
        if !connection_cache_is_ready(self.conn_client.cache_state()) {
            maybe_trigger_throttled_refresh(&self.conn_client, &self.last_refresh_ms);
            return;
        }

        let Ok(mut conn) = self.conn_client.get_timeout(timeout).await else {
            record_failure_and_maybe_refresh(
                &self.circuit_breaker,
                &self.conn_client,
                &self.last_refresh_ms,
            );
            return;
        };

        // Resolve canonical Dragonfly generations once per batch if any entry missed earlier.
        let mut missing_ns: Vec<(String, String)> = Vec::new();
        for (_, item) in &batch {
            if item.expected_remote_gen.is_none()
                && !missing_ns.iter().any(|(_, k)| k == &item.ns_gen_key)
            {
                missing_ns.push((item.namespace.clone(), item.ns_gen_key.clone()));
            }
        }

        let resolved_gens: Option<(u64, HashMap<String, u64>)> = if missing_ns.is_empty() {
            None
        } else {
            let mut gen_keys = Vec::with_capacity(1 + missing_ns.len());
            gen_keys.push(self.global_gen_key.clone());
            for (_, ns_key) in &missing_ns {
                gen_keys.push(ns_key.clone());
            }

            let Ok(Ok(vals)) =
                tokio::time::timeout(timeout, self.transport.fetch_generations(&mut conn, &gen_keys))
                    .await
            else {
                record_failure_and_maybe_refresh(
                    &self.circuit_breaker,
                    &self.conn_client,
                    &self.last_refresh_ms,
                );
                return;
            };

            let global_gen = vals.first().copied().flatten().unwrap_or(0);
            self.remote_gens.observe_global(global_gen);
            let mut ns_map = HashMap::with_capacity(missing_ns.len());
            for (idx, (ns_name, ns_key)) in missing_ns.into_iter().enumerate() {
                let ns_gen = vals.get(idx + 1).copied().flatten().unwrap_or(0);
                self.remote_gens.observe_namespace(&ns_name, ns_gen);
                ns_map.insert(ns_key, ns_gen);
            }
            Some((global_gen, ns_map))
        };

        let mut prepared = Vec::with_capacity(batch.len());
        for (entry_key, item) in batch {
            let remaining = item.entry.ttl.saturating_sub(item.entry.stored_at.elapsed());
            if remaining < MIN_L2_HIT_REMAINING_TTL {
                continue;
            }
            let ttl_ms = u64::try_from(remaining.as_millis())
                .unwrap_or(u64::MAX)
                .max(1);
            let remote_gen = match item.expected_remote_gen {
                Some(g) => g,
                None => match &resolved_gens {
                    Some((g_gen, ns_map)) => (
                        *g_gen,
                        ns_map.get(&item.ns_gen_key).copied().unwrap_or(0),
                    ),
                    None => (0, 0),
                },
            };

            match encode_wire_v1(&item.entry, remote_gen, self.compress_min_bytes).await {
                Ok(wire_bytes) => {
                    prepared.push(PreparedWriteItem {
                        entry_key,
                        wire_bytes,
                        ttl_ms,
                    });
                }
                Err(err) => {
                    tracing::debug!(error = %err, "Skipping L2 wire encode for batch item");
                }
            }
        }

        if prepared.is_empty() {
            return;
        }

        match tokio::time::timeout(timeout, self.transport.write_batch(&mut conn, &prepared)).await {
            Ok(Ok(())) => {
                self.circuit_breaker.record_success();
            }
            Ok(Err(err)) => {
                tracing::debug!(error = %err, "Dragonfly L2 write batch failed (fail-open)");
                record_failure_and_maybe_refresh(
                    &self.circuit_breaker,
                    &self.conn_client,
                    &self.last_refresh_ms,
                );
            }
            Err(_) => {
                tracing::debug!(timeout = ?timeout, "Dragonfly L2 write batch timed out (fail-open)");
                record_failure_and_maybe_refresh(
                    &self.circuit_breaker,
                    &self.conn_client,
                    &self.last_refresh_ms,
                );
            }
        }
    }
}

impl<T: DragonflyTransport> StatefulActor for L2WriterActor<T> {
    type Message = WriterMsg;
    type Response = ();
    type Error = String;

    async fn handle(
        &mut self,
        msg: Self::Message,
        ctx: &mut ActorContext<Self>,
    ) -> Result<Self::Response, Self::Error> {
        self.handle_cast(msg, ctx).await?;
        Ok(())
    }

    async fn handle_cast(
        &mut self,
        msg: Self::Message,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), Self::Error> {
        match msg {
            WriterMsg::Write {
                entry_key,
                namespace,
                ns_gen_key,
                entry,
                expected_remote_gen,
                estimated_bytes,
                permit,
            } => {
                if let Some(prev) = self.pending.insert(
                    entry_key,
                    PendingWrite {
                        namespace,
                        ns_gen_key,
                        entry,
                        expected_remote_gen,
                        estimated_bytes,
                        _permit: permit,
                    },
                ) {
                    self.pending_bytes = self.pending_bytes.saturating_sub(prev.estimated_bytes);
                }
                self.pending_bytes = self.pending_bytes.saturating_add(estimated_bytes);

                if self.pending.len() >= self.write_batch_size
                    || self.pending_bytes >= self.write_batch_max_bytes
                {
                    self.flush_batch(self.write_timeout).await;
                } else if !self.flush_scheduled {
                    self.flush_scheduled = true;
                    self.flush_timer =
                        Some(ctx.send_after(self.write_flush_delay, WriterMsg::Flush));
                }
            }
            WriterMsg::Flush => {
                self.flush_scheduled = false;
                self.flush_timer = None;
                if !self.pending.is_empty() {
                    self.flush_batch(self.write_timeout).await;
                }
            }
        }
        Ok(())
    }

    async fn on_stop(&mut self, _ctx: &mut ActorContext<Self>) {
        if let Some(handle) = self.flush_timer.take() {
            handle.abort();
        }
        if !self.pending.is_empty() {
            let drain_timeout = self.write_timeout.min(Duration::from_secs(1));
            self.flush_batch(drain_timeout).await;
        }
    }
}

// ============================================================================
//  L2InvalidationActor (StatefulActor + ctx.spawn_scoped Pub/Sub, K-07)
// ============================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum InvalidationWireKind {
    All,
    Ns,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InvalidationWireMsg {
    origin: String,
    kind: InvalidationWireKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    ns: Option<String>,
}

enum InvalidationMsg {
    PublishNamespace(String),
    PublishAll,
    RemotePayload(Vec<u8>),
    PubSubConnected { epoch: u64 },
    PubSubDisconnected { epoch: u64 },
    ReconnectPubSub { epoch: u64 },
}

struct L2InvalidationActor<T: DragonflyTransport> {
    transport: Arc<T>,
    conn_client: ResourceClient<T::Conn, String>,
    circuit_breaker: Arc<L2CircuitBreaker>,
    last_refresh_ms: Arc<AtomicU64>,
    remote_gens: Arc<RemoteGenBookkeeper>,
    origin_node_id: Arc<str>,
    key_prefix: String,
    global_gen_key: String,
    inv_channel: String,
    write_timeout: Duration,
    on_invalidation: InvalidationCallback,
    pubsub_connected_instance: Arc<AtomicUsize>,
    sub_epoch: u64,
    reconnect_attempts: u32,
    reconnect_timer: Option<tokio::task::AbortHandle>,
    has_synced_once: bool,
}

impl<T: DragonflyTransport> L2InvalidationActor<T> {
    fn spawn_pubsub_listener(&mut self, ctx: &ActorContext<Self>) {
        if let Some(timer) = self.reconnect_timer.take() {
            timer.abort();
        }
        self.sub_epoch = self.sub_epoch.wrapping_add(1);
        let epoch = self.sub_epoch;
        let instance_id = ctx.instance_id();
        let transport = Arc::clone(&self.transport);
        let inv_channel = self.inv_channel.clone();
        let connected_flag = Arc::clone(&self.pubsub_connected_instance);

        ctx.spawn_scoped(move |mut scope| async move {
            let sub_res = tokio::select! {
                biased;
                _ = scope.cancelled() => return,
                res = transport.subscribe_invalidations(&inv_channel) => res,
            };

            let mut stream = match sub_res {
                Ok(stream) => stream,
                Err(err) => {
                    tracing::debug!(error = %err, "L2 Pub/Sub subscription failed");
                    let _ = connected_flag.compare_exchange(
                        instance_id,
                        0,
                        Ordering::AcqRel,
                        Ordering::Acquire,
                    );
                    let _ = scope.cast(InvalidationMsg::PubSubDisconnected { epoch }).await;
                    return;
                }
            };

            connected_flag.store(instance_id, Ordering::Release);
            if scope
                .cast(InvalidationMsg::PubSubConnected { epoch })
                .await
                .is_err()
            {
                let _ = connected_flag.compare_exchange(
                    instance_id,
                    0,
                    Ordering::AcqRel,
                    Ordering::Acquire,
                );
                return;
            }

            loop {
                tokio::select! {
                    biased;
                    _ = scope.cancelled() => break,
                    maybe_payload = stream.next() => {
                        match maybe_payload {
                            Some(payload) => {
                                if scope.cast(InvalidationMsg::RemotePayload(payload)).await.is_err() {
                                    break;
                                }
                            }
                            None => {
                                let _ = connected_flag.compare_exchange(
                                    instance_id,
                                    0,
                                    Ordering::AcqRel,
                                    Ordering::Acquire,
                                );
                                let _ = scope.cast(InvalidationMsg::PubSubDisconnected { epoch }).await;
                                return;
                            }
                        }
                    }
                }
            }

            let _ = connected_flag.compare_exchange(
                instance_id,
                0,
                Ordering::AcqRel,
                Ordering::Acquire,
            );
        });
    }

    async fn publish_invalidation(&self, ns: Option<String>) {
        if !self.circuit_breaker.allow_request() {
            return;
        }
        if !connection_cache_is_ready(self.conn_client.cache_state()) {
            maybe_trigger_throttled_refresh(&self.conn_client, &self.last_refresh_ms);
            return;
        }

        let (gen_key, wire) = match ns.as_deref() {
            Some(namespace) => (
                encode_l2_ns_gen_key(namespace, &self.key_prefix),
                InvalidationWireMsg {
                    origin: self.origin_node_id.to_string(),
                    kind: InvalidationWireKind::Ns,
                    ns: Some(namespace.to_string()),
                },
            ),
            None => (
                self.global_gen_key.clone(),
                InvalidationWireMsg {
                    origin: self.origin_node_id.to_string(),
                    kind: InvalidationWireKind::All,
                    ns: None,
                },
            ),
        };

        let Ok(payload) = serde_json::to_vec(&wire) else {
            return;
        };

        let Ok(mut conn) = self.conn_client.get_timeout(self.write_timeout).await else {
            record_failure_and_maybe_refresh(
                &self.circuit_breaker,
                &self.conn_client,
                &self.last_refresh_ms,
            );
            return;
        };

        match tokio::time::timeout(
            self.write_timeout,
            self.transport
                .incr_and_publish(&mut conn, &gen_key, &self.inv_channel, &payload),
        )
        .await
        {
            Ok(Ok(new_gen)) => {
                self.circuit_breaker.record_success();
                match ns {
                    Some(namespace) => self.remote_gens.observe_namespace(&namespace, new_gen),
                    None => self.remote_gens.observe_global(new_gen),
                }
            }
            Ok(Err(err)) => {
                tracing::debug!(error = %err, "Dragonfly L2 INCR+PUBLISH failed (fail-open)");
                record_failure_and_maybe_refresh(
                    &self.circuit_breaker,
                    &self.conn_client,
                    &self.last_refresh_ms,
                );
            }
            Err(_) => {
                tracing::debug!(timeout = ?self.write_timeout, "Dragonfly L2 INCR+PUBLISH timed out (fail-open)");
                record_failure_and_maybe_refresh(
                    &self.circuit_breaker,
                    &self.conn_client,
                    &self.last_refresh_ms,
                );
            }
        }
    }

    async fn resync_remote_generations(&mut self, ctx: &ActorContext<Self>) {
        if !connection_cache_is_ready(self.conn_client.cache_state()) {
            maybe_trigger_throttled_refresh(&self.conn_client, &self.last_refresh_ms);
            return;
        }
        let Ok(mut conn) = self.conn_client.get_timeout(self.write_timeout).await else {
            record_failure_and_maybe_refresh(
                &self.circuit_breaker,
                &self.conn_client,
                &self.last_refresh_ms,
            );
            return;
        };

        let (prev_global, prev_ns_list) = self.remote_gens.snapshot();
        let mut keys = Vec::with_capacity(1 + prev_ns_list.len());
        keys.push(self.global_gen_key.clone());
        for (ns, _) in &prev_ns_list {
            keys.push(encode_l2_ns_gen_key(ns, &self.key_prefix));
        }

        let Ok(Ok(vals)) = tokio::time::timeout(
            self.write_timeout,
            self.transport.fetch_generations(&mut conn, &keys),
        )
        .await
        else {
            record_failure_and_maybe_refresh(
                &self.circuit_breaker,
                &self.conn_client,
                &self.last_refresh_ms,
            );
            return;
        };

        self.circuit_breaker.record_success();
        let cur_global = vals.first().copied().flatten().unwrap_or(0);
        self.remote_gens.observe_global(cur_global);

        let mut ns_deltas = Vec::with_capacity(prev_ns_list.len());
        for (idx, (ns, prev_ns_gen)) in prev_ns_list.into_iter().enumerate() {
            let cur_ns_gen = vals.get(idx + 1).copied().flatten().unwrap_or(0);
            self.remote_gens.observe_namespace(&ns, cur_ns_gen);
            if cur_ns_gen != prev_ns_gen {
                ns_deltas.push(ns);
            }
        }

        // K-07: On reconnect or actor restart, ANY generation mismatch (including `cur < prev`
        // after an in-memory Dragonfly restart) forces local invalidation.
        let is_reconnect = self.has_synced_once || prev_global.is_some() || ctx.instance_id() > 1;
        if is_reconnect {
            if prev_global.is_some_and(|prev| cur_global != prev)
                || (ctx.instance_id() > 1 && prev_global.is_none())
            {
                (self.on_invalidation)(L2InvalidationEvent::All);
            } else {
                for ns in ns_deltas {
                    (self.on_invalidation)(L2InvalidationEvent::Namespace(ns));
                }
            }
        }

        self.has_synced_once = true;
    }
}

impl<T: DragonflyTransport> StatefulActor for L2InvalidationActor<T> {
    type Message = InvalidationMsg;
    type Response = ();
    type Error = String;

    async fn on_start(&mut self, ctx: &mut ActorContext<Self>) -> Result<(), Self::Error> {
        self.spawn_pubsub_listener(ctx);
        Ok(())
    }

    async fn handle(
        &mut self,
        msg: Self::Message,
        ctx: &mut ActorContext<Self>,
    ) -> Result<Self::Response, Self::Error> {
        self.handle_cast(msg, ctx).await?;
        Ok(())
    }

    async fn handle_cast(
        &mut self,
        msg: Self::Message,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), Self::Error> {
        match msg {
            InvalidationMsg::PublishNamespace(ns) => {
                self.publish_invalidation(Some(ns)).await;
            }
            InvalidationMsg::PublishAll => {
                self.publish_invalidation(None).await;
            }
            InvalidationMsg::RemotePayload(payload) => {
                match serde_json::from_slice::<InvalidationWireMsg>(&payload) {
                    Ok(wire) => {
                        if wire.origin == self.origin_node_id.as_ref() {
                            return Ok(());
                        }
                        match wire.kind {
                            InvalidationWireKind::All => {
                                (self.on_invalidation)(L2InvalidationEvent::All);
                            }
                            InvalidationWireKind::Ns => {
                                if let Some(ns) = wire.ns {
                                    (self.on_invalidation)(L2InvalidationEvent::Namespace(ns));
                                }
                            }
                        }
                    }
                    Err(err) => {
                        tracing::debug!(error = %err, "Ignoring malformed L2 invalidation Pub/Sub frame");
                    }
                }
            }
            InvalidationMsg::PubSubConnected { epoch } => {
                if epoch != self.sub_epoch {
                    return Ok(());
                }
                self.reconnect_attempts = 0;
                self.resync_remote_generations(ctx).await;
            }
            InvalidationMsg::PubSubDisconnected { epoch } => {
                if epoch != self.sub_epoch {
                    return Ok(());
                }
                let shift = self.reconnect_attempts.min(10);
                let delay_ms = PUBSUB_RECONNECT_BASE_MS
                    .saturating_mul(1u64 << shift)
                    .min(PUBSUB_RECONNECT_MAX_MS);
                self.reconnect_attempts = self.reconnect_attempts.saturating_add(1);
                self.reconnect_timer = Some(ctx.send_after(
                    Duration::from_millis(delay_ms),
                    InvalidationMsg::ReconnectPubSub { epoch },
                ));
            }
            InvalidationMsg::ReconnectPubSub { epoch } => {
                if epoch == self.sub_epoch {
                    self.spawn_pubsub_listener(ctx);
                }
            }
        }
        Ok(())
    }

    async fn on_stop(&mut self, ctx: &mut ActorContext<Self>) {
        if let Some(timer) = self.reconnect_timer.take() {
            timer.abort();
        }
        let _ = self.pubsub_connected_instance.compare_exchange(
            ctx.instance_id(),
            0,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }
}

// ============================================================================
//  DragonflyL2Backend & Generic Supervision Core
// ============================================================================

struct DragonflyL2BackendInner<T: DragonflyTransport> {
    transport: Arc<T>,
    supervisor: SupervisorHandle,
    monitor: LocalNodeMonitor,
    conn_client: ResourceClient<T::Conn, String>,
    writer_client: ActorClient<L2WriterActor<T>>,
    inv_client: ActorClient<L2InvalidationActor<T>>,
    circuit_breaker: Arc<L2CircuitBreaker>,
    write_budget: Arc<L2WriteBudget>,
    writes_dropped: AtomicU64,
    last_refresh_ms: Arc<AtomicU64>,
    remote_gens: Arc<RemoteGenBookkeeper>,
    pubsub_connected_instance: Arc<AtomicUsize>,
    endpoint_redacted: String,
    key_prefix: String,
    global_gen_key: String,
    l1_max_ttl: Duration,
    read_timeout: Duration,
}

impl<T: DragonflyTransport> DragonflyL2BackendInner<T> {
    async fn start(
        cfg: &L2CacheConfig,
        transport: Arc<T>,
        on_invalidation: InvalidationCallback,
    ) -> Result<Arc<Self>, DragonflyL2Error> {
        let endpoint_redacted = cfg.redacted_url();
        let key_prefix = cfg.key_prefix.clone();
        let global_gen_key = encode_l2_global_gen_key(&key_prefix);
        let inv_channel = encode_l2_inv_channel(&key_prefix);
        let origin_node_id: Arc<str> = Arc::from(uuid::Uuid::new_v4().simple().to_string());

        let connect_timeout = Duration::from_millis(cfg.connect_timeout_ms);
        let read_timeout = Duration::from_millis(cfg.read_timeout_ms);
        let write_timeout = Duration::from_millis(cfg.write_timeout_ms);
        let l1_max_ttl = Duration::from_secs(cfg.l1_max_ttl_seconds);

        let write_budget = L2WriteBudget::new(cfg.max_write_queue_bytes);
        let circuit_breaker = Arc::new(L2CircuitBreaker::new(
            cfg.cb_failure_threshold,
            Duration::from_secs(cfg.cb_open_seconds),
        ));
        let last_refresh_ms = Arc::new(AtomicU64::new(0));
        let remote_gens = Arc::new(RemoteGenBookkeeper::default());
        let pubsub_connected_instance = Arc::new(AtomicUsize::new(0));

        let child_restart_policy = RestartPolicy::new(20, Duration::from_secs(60))
            .initial_backoff(Duration::from_millis(100))
            .max_backoff(Duration::from_secs(5))
            .backoff_multiplier(2.0);

        let supervisor = Supervisor::builder("l2-cache")
            .strategy(SupervisionStrategy::OneForOne)
            .spawn_root();

        // 1. Connection actor registered FIRST so it shuts down LAST (after writer on_stop flush).
        let t_conn = Arc::clone(&transport);
        let conn_client = ResourceActor::builder("l2-connection")
            .worker(move |_ctx: WorkerContext| {
                let t = Arc::clone(&t_conn);
                async move {
                    let conn = t.connect().await?;
                    Ok::<_, String>(TimedResource::perpetual(conn))
                }
            })
            .eager_prewarm(true)
            .proactive_refresh(false)
            .worker_timeout(connect_timeout.saturating_add(Duration::from_millis(100)))
            .failure_cooldown(Duration::from_millis(250))
            .restart_type(RestartType::Permanent)
            .restart_policy(child_restart_policy)
            .shutdown_timeout(Duration::from_secs(3))
            .spawn(&supervisor)
            .await?;

        // 2. Bounded micro-batching writer actor.
        let t_writer = Arc::clone(&transport);
        let conn_for_writer = conn_client.clone();
        let cb_for_writer = Arc::clone(&circuit_breaker);
        let refresh_for_writer = Arc::clone(&last_refresh_ms);
        let gens_for_writer = Arc::clone(&remote_gens);
        let global_key_writer = global_gen_key.clone();
        let compress_min_bytes = cfg.compress_min_bytes;
        let write_batch_size = cfg.write_batch_size;
        let write_batch_max_bytes = cfg.write_batch_max_bytes;
        let write_flush_delay = Duration::from_millis(cfg.write_flush_ms);

        let writer_client = StatefulActorBuilder::new("l2-writer", move |_inst_id| L2WriterActor {
            transport: Arc::clone(&t_writer),
            conn_client: conn_for_writer.clone(),
            circuit_breaker: Arc::clone(&cb_for_writer),
            last_refresh_ms: Arc::clone(&refresh_for_writer),
            remote_gens: Arc::clone(&gens_for_writer),
            global_gen_key: global_key_writer.clone(),
            compress_min_bytes,
            write_timeout,
            write_batch_size,
            write_batch_max_bytes,
            write_flush_delay,
            pending: HashMap::new(),
            pending_bytes: 0,
            flush_scheduled: false,
            flush_timer: None,
        })
        .channel_capacity(cfg.write_queue_capacity)
        .restart_type(RestartType::Permanent)
        .restart_policy(child_restart_policy)
        .shutdown_timeout(Duration::from_secs(3))
        .spawn(&supervisor)
        .await?;

        // 3. Dedicated Pub/Sub invalidation & resync actor (`K-07`).
        let t_inv = Arc::clone(&transport);
        let conn_for_inv = conn_client.clone();
        let cb_for_inv = Arc::clone(&circuit_breaker);
        let refresh_for_inv = Arc::clone(&last_refresh_ms);
        let gens_for_inv = Arc::clone(&remote_gens);
        let origin_for_inv = Arc::clone(&origin_node_id);
        let prefix_for_inv = key_prefix.clone();
        let global_key_inv = global_gen_key.clone();
        let channel_for_inv = inv_channel;
        let on_inv_cb = Arc::clone(&on_invalidation);
        let connected_for_inv = Arc::clone(&pubsub_connected_instance);

        let inv_client =
            StatefulActorBuilder::new("l2-invalidation", move |_inst_id| L2InvalidationActor {
                transport: Arc::clone(&t_inv),
                conn_client: conn_for_inv.clone(),
                circuit_breaker: Arc::clone(&cb_for_inv),
                last_refresh_ms: Arc::clone(&refresh_for_inv),
                remote_gens: Arc::clone(&gens_for_inv),
                origin_node_id: Arc::clone(&origin_for_inv),
                key_prefix: prefix_for_inv.clone(),
                global_gen_key: global_key_inv.clone(),
                inv_channel: channel_for_inv.clone(),
                write_timeout,
                on_invalidation: Arc::clone(&on_inv_cb),
                pubsub_connected_instance: Arc::clone(&connected_for_inv),
                sub_epoch: 0,
                reconnect_attempts: 0,
                reconnect_timer: None,
                has_synced_once: false,
            })
            .channel_capacity(256)
            .restart_type(RestartType::Permanent)
            .restart_policy(child_restart_policy)
            .shutdown_timeout(Duration::from_secs(3))
            .spawn(&supervisor)
            .await?;

        let monitor = LocalNodeMonitor::new(supervisor.clone());

        Ok(Arc::new(Self {
            transport,
            supervisor,
            monitor,
            conn_client,
            writer_client,
            inv_client,
            circuit_breaker,
            write_budget,
            writes_dropped: AtomicU64::new(0),
            last_refresh_ms,
            remote_gens,
            pubsub_connected_instance,
            endpoint_redacted,
            key_prefix,
            global_gen_key,
            l1_max_ttl,
            read_timeout,
        }))
    }
}

impl<T: DragonflyTransport> L2CacheBackend for DragonflyL2BackendInner<T> {
    fn get<'a>(
        &'a self,
        key: &'a CacheKey,
        max_entry_bytes: usize,
    ) -> Pin<Box<dyn Future<Output = L2LookupOutcome> + Send + 'a>> {
        Box::pin(async move {
            if !self.circuit_breaker.allow_request() {
                return L2LookupOutcome::Unavailable;
            }

            // K-03: 0-ns lock-free check prevents piling onto ResourceClient::get() while cold or offline.
            if !connection_cache_is_ready(self.conn_client.cache_state()) {
                maybe_trigger_throttled_refresh(&self.conn_client, &self.last_refresh_ms);
                return L2LookupOutcome::Unavailable;
            }

            let Ok(mut conn) = self.conn_client.get_timeout(self.read_timeout).await else {
                record_failure_and_maybe_refresh(
                    &self.circuit_breaker,
                    &self.conn_client,
                    &self.last_refresh_ms,
                );
                return L2LookupOutcome::Unavailable;
            };

            let entry_key = encode_l2_entry_key(key, &self.key_prefix);
            let ns_gen_key = encode_l2_ns_gen_key(&key.namespace, &self.key_prefix);

            let raw_read = match tokio::time::timeout(
                self.read_timeout,
                self.transport
                    .read_entry(&mut conn, &self.global_gen_key, &ns_gen_key, &entry_key),
            )
            .await
            {
                Ok(Ok(read)) => read,
                Ok(Err(err)) => {
                    tracing::debug!(error = %err, "Dragonfly L2 read pipeline failed (fail-open)");
                    record_failure_and_maybe_refresh(
                        &self.circuit_breaker,
                        &self.conn_client,
                        &self.last_refresh_ms,
                    );
                    return L2LookupOutcome::Unavailable;
                }
                Err(_) => {
                    tracing::debug!(timeout = ?self.read_timeout, "Dragonfly L2 read pipeline timed out (fail-open)");
                    record_failure_and_maybe_refresh(
                        &self.circuit_breaker,
                        &self.conn_client,
                        &self.last_refresh_ms,
                    );
                    return L2LookupOutcome::Unavailable;
                }
            };

            self.circuit_breaker.record_success();
            let remote_gen = (raw_read.global_gen, raw_read.ns_gen);
            self.remote_gens.observe_global(remote_gen.0);
            self.remote_gens
                .observe_namespace(&key.namespace, remote_gen.1);

            let Some(raw_bytes) = raw_read.raw_entry else {
                return L2LookupOutcome::Miss {
                    observed_remote_gen: Some(remote_gen),
                };
            };

            if raw_read.pttl_ms <= 0 {
                return L2LookupOutcome::Miss {
                    observed_remote_gen: Some(remote_gen),
                };
            }
            let pttl_ms = u64::try_from(raw_read.pttl_ms).unwrap_or(0);
            if Duration::from_millis(pttl_ms) < MIN_L2_HIT_REMAINING_TTL {
                return L2LookupOutcome::Miss {
                    observed_remote_gen: Some(remote_gen),
                };
            }

            let decoded = match decode_wire_v1(raw_bytes, max_entry_bytes).await {
                Ok(frame) => frame,
                Err(err) => {
                    tracing::debug!(error = %err, "Ignoring corrupt or oversized PRC2 wire frame");
                    return L2LookupOutcome::Miss {
                        observed_remote_gen: Some(remote_gen),
                    };
                }
            };

            // K-01: Reject stale entries written under an older canonical Dragonfly generation.
            if decoded.remote_gen != remote_gen {
                return L2LookupOutcome::Miss {
                    observed_remote_gen: Some(remote_gen),
                };
            }

            let entry = Arc::new(decoded.into_cached_response(pttl_ms, self.l1_max_ttl));
            L2LookupOutcome::Hit {
                entry,
                remote_gen,
                pttl_ms,
            }
        })
    }

    fn enqueue_set(
        &self,
        key: CacheKey,
        entry: Arc<crate::middleware::cache::CachedResponse>,
        expected_remote_gen: Option<(u64, u64)>,
    ) {
        if entry.ttl < MIN_L2_WRITE_TTL {
            return;
        }
        if self.circuit_breaker.state() == L2CircuitState::Open {
            self.writes_dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }

        let estimated_bytes = entry.byte_weight as usize;
        let Some(permit) = self.write_budget.try_reserve(estimated_bytes) else {
            self.writes_dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };

        let entry_key = encode_l2_entry_key(&key, &self.key_prefix);
        let ns_gen_key = encode_l2_ns_gen_key(&key.namespace, &self.key_prefix);

        if self
            .writer_client
            .try_cast(WriterMsg::Write {
                entry_key,
                namespace: key.namespace.to_string(),
                ns_gen_key,
                entry,
                expected_remote_gen,
                estimated_bytes,
                permit,
            })
            .is_err()
        {
            self.writes_dropped.fetch_add(1, Ordering::Relaxed);
        }
    }

    fn enqueue_invalidate_namespace(&self, namespace: &str) {
        let _ = self
            .inv_client
            .try_cast(InvalidationMsg::PublishNamespace(namespace.to_string()));
    }

    fn enqueue_invalidate_all(&self) {
        let _ = self.inv_client.try_cast(InvalidationMsg::PublishAll);
    }

    fn status_snapshot(&self) -> L2StatusSnapshot {
        let writer_qs = self.writer_client.queue_stats();
        let inv_qs = self.inv_client.queue_stats();
        let invalidation_connected = self.pubsub_connected_instance.load(Ordering::Acquire) != 0;
        let circuit_state = self.circuit_breaker.state();
        let node_health = self.monitor.health();

        let actor_health = if !node_health.alive {
            otp_actor::HealthState::Unavailable.as_str()
        } else if writer_qs.is_closed
            || inv_qs.is_closed
            || circuit_state != L2CircuitState::Closed
            || !invalidation_connected
            || !connection_cache_is_ready(self.conn_client.cache_state())
        {
            otp_actor::HealthState::Degraded.as_str()
        } else {
            otp_actor::HealthState::Healthy.as_str()
        };

        L2StatusSnapshot {
            enabled: true,
            endpoint_redacted: self.endpoint_redacted.clone(),
            circuit_state,
            writer_queue_len: writer_qs.queued,
            writer_queue_capacity: writer_qs.max_capacity,
            writer_queue_bytes: self.write_budget.used_bytes(),
            writer_queue_max_bytes: self.write_budget.max_bytes(),
            writes_dropped: self.writes_dropped.load(Ordering::Relaxed),
            invalidation_connected,
            actor_health,
        }
    }

    fn shutdown(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        Box::pin(async move {
            let _ = self.supervisor.shutdown().await;
            self.pubsub_connected_instance.store(0, Ordering::Release);
        })
    }
}

/// Supervised Dragonfly/Redis implementation of [`L2CacheBackend`].
pub struct DragonflyL2Backend {
    inner: Arc<DragonflyL2BackendInner<RedisTransport>>,
}

impl DragonflyL2Backend {
    /// Connects to Dragonfly using `cfg` (resolving out-of-band secrets and `aws-lc-rs` TLS),
    /// spawns the `"l2-cache"` `otp-actor` supervision tree (`OneForOne`, `Permanent`), and
    /// returns an [`Arc<DragonflyL2Backend>`].
    #[tracing::instrument(skip(cfg, on_invalidation), fields(endpoint = %cfg.redacted_url()), err)]
    pub async fn connect(
        cfg: L2CacheConfig,
        on_invalidation: InvalidationCallback,
    ) -> Result<Arc<Self>, DragonflyL2Error> {
        let client = build_redis_client(&cfg).await?;
        let transport = Arc::new(RedisTransport::new(
            client,
            Duration::from_millis(cfg.connect_timeout_ms),
            Duration::from_millis(cfg.read_timeout_ms),
            Duration::from_millis(cfg.write_timeout_ms),
        ));
        let inner = DragonflyL2BackendInner::start(&cfg, transport, on_invalidation).await?;
        Ok(Arc::new(Self { inner }))
    }

    /// Returns the underlying `otp-actor` [`SupervisorHandle`] for diagnostics or lifecycle control.
    #[inline]
    pub fn supervisor(&self) -> &SupervisorHandle {
        &self.inner.supervisor
    }

    /// Returns the cumulative number of L2 writes dropped due to backpressure or open circuit.
    #[inline]
    pub fn writes_dropped(&self) -> u64 {
        self.inner.writes_dropped.load(Ordering::Relaxed)
    }

    /// Returns the instantaneous circuit breaker state.
    #[inline]
    pub fn circuit_state(&self) -> L2CircuitState {
        self.inner.circuit_breaker.state()
    }

    /// Injects an intentional crash into `L2ConnectionActor` (`cache-l2-chaos` only).
    #[cfg(feature = "cache-l2-chaos")]
    pub async fn simulate_connection_crash(
        &self,
    ) -> Result<(), otp_actor::ResourceError<String>> {
        self.inner.conn_client.simulate_crash().await
    }

    /// Injects an intentional crash into `L2WriterActor` (`cache-l2-chaos` only).
    #[cfg(feature = "cache-l2-chaos")]
    pub async fn simulate_writer_crash(
        &self,
    ) -> Result<(), otp_actor::ActorError<String>> {
        self.inner.writer_client.simulate_crash().await
    }

    /// Injects an intentional crash into `L2InvalidationActor` (`cache-l2-chaos` only).
    #[cfg(feature = "cache-l2-chaos")]
    pub async fn simulate_invalidation_crash(
        &self,
    ) -> Result<(), otp_actor::ActorError<String>> {
        self.inner.inv_client.simulate_crash().await
    }
}

impl L2CacheBackend for DragonflyL2Backend {
    fn get<'a>(
        &'a self,
        key: &'a CacheKey,
        max_entry_bytes: usize,
    ) -> Pin<Box<dyn Future<Output = L2LookupOutcome> + Send + 'a>> {
        self.inner.get(key, max_entry_bytes)
    }

    fn enqueue_set(
        &self,
        key: CacheKey,
        entry: Arc<crate::middleware::cache::CachedResponse>,
        expected_remote_gen: Option<(u64, u64)>,
    ) {
        self.inner.enqueue_set(key, entry, expected_remote_gen);
    }

    fn enqueue_invalidate_namespace(&self, namespace: &str) {
        self.inner.enqueue_invalidate_namespace(namespace);
    }

    fn enqueue_invalidate_all(&self) {
        self.inner.enqueue_invalidate_all();
    }

    fn status_snapshot(&self) -> L2StatusSnapshot {
        self.inner.status_snapshot()
    }

    fn shutdown(&self) -> Pin<Box<dyn Future<Output = ()> + Send + '_>> {
        self.inner.shutdown()
    }
}

// ============================================================================
//  Unit & Chaos Tests (L2Cache.md Abschnitt 10.4)
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configuration::CacheScope;
    use crate::middleware::cache::CachedResponse;
    use hyper::{HeaderMap, StatusCode};
    use smallvec::SmallVec;
    use std::sync::Mutex;
    use std::time::Instant;
    use tokio::sync::{Notify, broadcast};

    fn test_l2_config(url: &str) -> L2CacheConfig {
        L2CacheConfig {
            enabled: true,
            url: url.to_string(),
            password_env: None,
            password_file: None,
            tls_ca_file: None,
            tls_cert_file: None,
            tls_key_file: None,
            key_prefix: "praeco".to_string(),
            read_timeout_ms: 50,
            write_timeout_ms: 100,
            connect_timeout_ms: 250,
            l1_max_ttl_seconds: 15,
            write_queue_capacity: 64,
            max_write_queue_bytes: 1024 * 1024,
            write_batch_size: 4,
            write_batch_max_bytes: 64 * 1024,
            write_flush_ms: 10,
            compress_min_bytes: 512,
            cb_failure_threshold: 3,
            cb_open_seconds: 10,
        }
    }

    fn sample_key(suffix: &str) -> CacheKey {
        CacheKey {
            namespace: Arc::from("catalog"),
            generation: (0, 0),
            scope: CacheScope::Public,
            method: "GET",
            path_and_query: Arc::from(format!("/api/items/{suffix}")),
            vary_values: SmallVec::new(),
            scope_key: Arc::from(""),
            body_hash: None,
            post_encoding: None,
        }
    }

    #[derive(Clone)]
    struct MockSlot {
        wire_bytes: Bytes,
        expires_at: Instant,
    }

    #[derive(Default)]
    struct MockDbState {
        gens: HashMap<String, u64>,
        entries: HashMap<String, MockSlot>,
    }

    struct MockDragonflyTransport {
        db: Mutex<MockDbState>,
        connect_gate: Arc<Notify>,
        gate_connects: AtomicBool,
        connect_calls: AtomicU64,
        write_batch_calls: AtomicU64,
        written_items_total: AtomicU64,
        fail_reads: AtomicBool,
        write_gate: Arc<Notify>,
        gate_writes: AtomicBool,
        pubsub_tx: Mutex<broadcast::Sender<Vec<u8>>>,
        write_done_notify: Arc<Notify>,
    }

    impl MockDragonflyTransport {
        fn new() -> Arc<Self> {
            let (tx, _) = broadcast::channel(64);
            Arc::new(Self {
                db: Mutex::new(MockDbState::default()),
                connect_gate: Arc::new(Notify::new()),
                gate_connects: AtomicBool::new(false),
                connect_calls: AtomicU64::new(0),
                write_batch_calls: AtomicU64::new(0),
                written_items_total: AtomicU64::new(0),
                fail_reads: AtomicBool::new(false),
                write_gate: Arc::new(Notify::new()),
                gate_writes: AtomicBool::new(false),
                pubsub_tx: Mutex::new(tx),
                write_done_notify: Arc::new(Notify::new()),
            })
        }

        fn set_remote_gen(&self, gen_key: &str, val: u64) {
            self.db.lock().unwrap().gens.insert(gen_key.to_string(), val);
        }

        fn simulate_dragonfly_restart(&self) {
            let mut guard = self.db.lock().unwrap();
            guard.gens.clear();
            guard.entries.clear();
        }

        fn drop_all_pubsub_streams(&self) {
            let (new_tx, _) = broadcast::channel(64);
            *self.pubsub_tx.lock().unwrap() = new_tx;
        }

        fn broadcast_raw(&self, payload: Vec<u8>) {
            let _ = self.pubsub_tx.lock().unwrap().send(payload);
        }
    }

    impl DragonflyTransport for MockDragonflyTransport {
        type Conn = ();

        async fn connect(&self) -> Result<Self::Conn, String> {
            self.connect_calls.fetch_add(1, Ordering::Relaxed);
            if self.gate_connects.load(Ordering::Acquire) {
                self.connect_gate.notified().await;
            }
            Ok(())
        }

        async fn read_entry(
            &self,
            _conn: &mut Self::Conn,
            global_gen_key: &str,
            ns_gen_key: &str,
            entry_key: &str,
        ) -> Result<RawPipelineRead, String> {
            if self.fail_reads.load(Ordering::Acquire) {
                return Err("injected read error".to_string());
            }
            let guard = self.db.lock().unwrap();
            let global_gen = guard.gens.get(global_gen_key).copied().unwrap_or(0);
            let ns_gen = guard.gens.get(ns_gen_key).copied().unwrap_or(0);
            let (raw_entry, pttl_ms) = match guard.entries.get(entry_key) {
                Some(slot) => {
                    let rem = slot.expires_at.saturating_duration_since(Instant::now());
                    if rem.is_zero() {
                        (None, -2)
                    } else {
                        (
                            Some(slot.wire_bytes.clone()),
                            i64::try_from(rem.as_millis()).unwrap_or(i64::MAX),
                        )
                    }
                }
                None => (None, -2),
            };
            Ok(RawPipelineRead {
                global_gen,
                ns_gen,
                raw_entry,
                pttl_ms,
            })
        }

        async fn fetch_generations(
            &self,
            _conn: &mut Self::Conn,
            keys: &[String],
        ) -> Result<Vec<Option<u64>>, String> {
            let guard = self.db.lock().unwrap();
            Ok(keys.iter().map(|k| guard.gens.get(k).copied()).collect())
        }

        async fn write_batch(
            &self,
            _conn: &mut Self::Conn,
            items: &[PreparedWriteItem],
        ) -> Result<(), String> {
            if self.gate_writes.load(Ordering::Acquire) {
                self.write_gate.notified().await;
            }
            self.write_batch_calls.fetch_add(1, Ordering::Relaxed);
            self.written_items_total
                .fetch_add(items.len() as u64, Ordering::Relaxed);
            {
                let mut guard = self.db.lock().unwrap();
                for item in items {
                    guard.entries.insert(
                        item.entry_key.clone(),
                        MockSlot {
                            wire_bytes: item.wire_bytes.clone(),
                            expires_at: Instant::now() + Duration::from_millis(item.ttl_ms),
                        },
                    );
                }
            }
            self.write_done_notify.notify_waiters();
            Ok(())
        }

        async fn incr_and_publish(
            &self,
            _conn: &mut Self::Conn,
            gen_key: &str,
            _inv_channel: &str,
            payload: &[u8],
        ) -> Result<u64, String> {
            let new_gen = {
                let mut guard = self.db.lock().unwrap();
                let entry = guard.gens.entry(gen_key.to_string()).or_insert(0);
                *entry += 1;
                *entry
            };
            let _ = self.pubsub_tx.lock().unwrap().send(payload.to_vec());
            Ok(new_gen)
        }

        async fn subscribe_invalidations(
            &self,
            _inv_channel: &str,
        ) -> Result<PubSubPayloadStream, String> {
            let rx = self.pubsub_tx.lock().unwrap().subscribe();
            let stream = futures_util::stream::unfold(rx, |mut rx| async move {
                loop {
                    match rx.recv().await {
                        Ok(bytes) => return Some((bytes, rx)),
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                        Err(broadcast::error::RecvError::Closed) => return None,
                    }
                }
            });
            Ok(Box::pin(stream))
        }
    }

    async fn wait_for_condition<F: Fn() -> bool>(cond: F) {
        for _ in 0..200 {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        panic!("condition was not satisfied within timeout");
    }

    #[tokio::test]
    async fn test_build_redis_client_auth_and_tls_validation() {
        let mut disabled = test_l2_config("redis://127.0.0.1:6379/0");
        disabled.enabled = false;
        assert!(matches!(
            build_redis_client(&disabled).await,
            Err(DragonflyL2Error::InvalidConfig(_))
        ));

        let mut missing_env = test_l2_config("redis://127.0.0.1:6379/0");
        missing_env.password_env = Some("PRAECO_TEST_NONEXISTENT_L2_PW_XYZ".to_string());
        assert!(matches!(
            build_redis_client(&missing_env).await,
            Err(DragonflyL2Error::AuthConfig(_))
        ));

        let pw_path =
            std::env::temp_dir().join(format!("praeco_l2_pw_{}.secret", uuid::Uuid::new_v4()));
        tokio::fs::write(&pw_path, "s3cret-dragonfly-pw\r\n")
            .await
            .unwrap();

        let pki = common::test_pki::TestPki::new();
        let mut tls_on_plain = test_l2_config("redis://127.0.0.1:6379/0");
        tls_on_plain.tls_ca_file = Some(pki.public_ca_pem.to_string_lossy().into_owned());
        assert!(matches!(
            build_redis_client(&tls_on_plain).await,
            Err(DragonflyL2Error::InvalidConfig(_))
        ));

        let mut tls_mtls = test_l2_config("rediss://127.0.0.1:6379/0");
        tls_mtls.password_file = Some(pw_path.to_string_lossy().into_owned());
        tls_mtls.tls_ca_file = Some(pki.relay_ca_pem.to_string_lossy().into_owned());
        tls_mtls.tls_cert_file = Some(pki.praeco_client_pem.to_string_lossy().into_owned());
        tls_mtls.tls_key_file = Some(pki.praeco_client_key.to_string_lossy().into_owned());

        let client = build_redis_client(&tls_mtls).await.unwrap();
        assert_eq!(
            client.get_connection_info().redis_settings().password(),
            Some("s3cret-dragonfly-pw")
        );

        let _ = tokio::fs::remove_file(&pw_path).await;
    }

    #[tokio::test]
    async fn test_k03_zero_ns_fast_fail_when_connection_not_ready() {
        let transport = MockDragonflyTransport::new();
        transport.gate_connects.store(true, Ordering::Release);

        let mut cfg = test_l2_config("redis://127.0.0.1:6379/0");
        cfg.connect_timeout_ms = 5_000;
        let backend = DragonflyL2BackendInner::start(&cfg, Arc::clone(&transport), Arc::new(|_| {}))
            .await
            .unwrap();

        let key = sample_key("k03");
        let t0 = Instant::now();
        for _ in 0..10 {
            let outcome = backend.get(&key, 4096).await;
            assert!(matches!(outcome, L2LookupOutcome::Unavailable));
        }
        assert!(
            t0.elapsed() < Duration::from_millis(200),
            "K-03 fast-fail must not block waiting for connect_timeout_ms"
        );
        // Cold-start Empty state must NOT trip the circuit breaker into Open!
        assert_eq!(backend.circuit_breaker.state(), L2CircuitState::Closed);

        // Unblock connect and verify backend recovers immediately to Miss
        transport.gate_connects.store(false, Ordering::Release);
        transport.connect_gate.notify_waiters();
        wait_for_condition(|| connection_cache_is_ready(backend.conn_client.cache_state())).await;

        assert!(matches!(
            backend.get(&key, 4096).await,
            L2LookupOutcome::Miss {
                observed_remote_gen: Some((0, 0))
            }
        ));

        backend.shutdown().await;
    }

    #[tokio::test]
    async fn test_read_pipeline_hit_gen_mismatch_and_circuit_breaker() {
        let transport = MockDragonflyTransport::new();
        let cfg = test_l2_config("redis://127.0.0.1:6379/0");
        let backend = DragonflyL2BackendInner::start(&cfg, Arc::clone(&transport), Arc::new(|_| {}))
            .await
            .unwrap();
        wait_for_condition(|| backend.pubsub_connected_instance.load(Ordering::Acquire) != 0).await;

        let key = sample_key("pipeline");
        let entry = Arc::new(CachedResponse::new_for_test(
            StatusCode::OK,
            HeaderMap::new(),
            Bytes::from_static(b"hello-l2-dragonfly"),
            None,
            Duration::from_secs(30),
        ));
        backend.enqueue_set(key.clone(), entry, Some((0, 0)));
        wait_for_condition(|| transport.written_items_total.load(Ordering::Acquire) == 1).await;

        match backend.get(&key, 4096).await {
            L2LookupOutcome::Hit {
                entry,
                remote_gen,
                pttl_ms,
            } => {
                assert_eq!(remote_gen, (0, 0));
                assert!(pttl_ms > 20_000);
                assert_eq!(entry.body, Bytes::from_static(b"hello-l2-dragonfly"));
            }
            other => panic!("expected L2 Hit, got {other:?}"),
        }

        // Advance remote namespace gen without deleting entry slot -> K-01 rejects stale generation
        let ns_gen_key = encode_l2_ns_gen_key(&key.namespace, "praeco");
        transport.set_remote_gen(&ns_gen_key, 2);
        assert!(matches!(
            backend.get(&key, 4096).await,
            L2LookupOutcome::Miss {
                observed_remote_gen: Some((0, 2))
            }
        ));

        // 3 consecutive read failures trip circuit breaker to Open
        transport.fail_reads.store(true, Ordering::Release);
        for _ in 0..3 {
            assert!(matches!(
                backend.get(&key, 4096).await,
                L2LookupOutcome::Unavailable
            ));
        }
        assert_eq!(backend.circuit_breaker.state(), L2CircuitState::Open);

        backend.shutdown().await;
    }

    #[tokio::test]
    async fn test_writer_micro_batching_size_bytes_and_timer_flush() {
        let transport = MockDragonflyTransport::new();
        let mut cfg = test_l2_config("redis://127.0.0.1:6379/0");
        cfg.write_batch_size = 3;
        cfg.write_batch_max_bytes = 512;
        cfg.write_flush_ms = 60;

        let backend = DragonflyL2BackendInner::start(&cfg, Arc::clone(&transport), Arc::new(|_| {}))
            .await
            .unwrap();
        wait_for_condition(|| connection_cache_is_ready(backend.conn_client.cache_state())).await;

        // 1. Trigger flush by item count (`write_batch_size = 3`)
        for i in 0..3 {
            let entry = Arc::new(CachedResponse::new_for_test(
                StatusCode::OK,
                HeaderMap::new(),
                Bytes::from(vec![b'a'; 64]),
                None,
                Duration::from_secs(30),
            ));
            backend.enqueue_set(sample_key(&format!("count-{i}")), entry, Some((0, 0)));
        }
        wait_for_condition(|| transport.written_items_total.load(Ordering::Acquire) == 3).await;
        assert_eq!(transport.write_batch_calls.load(Ordering::Acquire), 1);

        // 2. Trigger immediate flush by batch byte threshold (`write_batch_max_bytes = 512`)
        let big_entry = Arc::new(CachedResponse::new_for_test(
            StatusCode::OK,
            HeaderMap::new(),
            Bytes::from(vec![b'x'; 520]),
            None,
            Duration::from_secs(30),
        ));
        backend.enqueue_set(sample_key("big-item"), big_entry, Some((0, 0)));
        wait_for_condition(|| transport.written_items_total.load(Ordering::Acquire) == 4).await;
        assert_eq!(transport.write_batch_calls.load(Ordering::Acquire), 2);

        // 3. Single small item with write_flush_ms = 60ms waits for timer flush
        let timer_entry = Arc::new(CachedResponse::new_for_test(
            StatusCode::OK,
            HeaderMap::new(),
            Bytes::from(vec![b'b'; 64]),
            None,
            Duration::from_secs(30),
        ));
        backend.enqueue_set(sample_key("timer-item"), timer_entry, Some((0, 0)));
        tokio::time::sleep(Duration::from_millis(15)).await;
        assert_eq!(transport.written_items_total.load(Ordering::Acquire), 4);

        wait_for_condition(|| transport.written_items_total.load(Ordering::Acquire) == 5).await;
        assert_eq!(transport.write_batch_calls.load(Ordering::Acquire), 3);

        backend.shutdown().await;
    }

    #[tokio::test]
    async fn test_writer_key_deduplication_and_budget_release() {
        let transport = MockDragonflyTransport::new();
        let mut cfg = test_l2_config("redis://127.0.0.1:6379/0");
        cfg.write_batch_size = 10;
        cfg.write_flush_ms = 25;

        let backend = DragonflyL2BackendInner::start(&cfg, Arc::clone(&transport), Arc::new(|_| {}))
            .await
            .unwrap();
        wait_for_condition(|| connection_cache_is_ready(backend.conn_client.cache_state())).await;

        let key = sample_key("dedup");
        for v in ["v1", "v2", "v3"] {
            let entry = Arc::new(CachedResponse::new_for_test(
                StatusCode::OK,
                HeaderMap::new(),
                Bytes::from(v.as_bytes().to_vec()),
                None,
                Duration::from_secs(30),
            ));
            backend.enqueue_set(key.clone(), entry, Some((0, 0)));
        }

        wait_for_condition(|| transport.written_items_total.load(Ordering::Acquire) == 1).await;
        assert_eq!(transport.write_batch_calls.load(Ordering::Acquire), 1);
        assert_eq!(backend.write_budget.used_bytes(), 0);

        match backend.get(&key, 4096).await {
            L2LookupOutcome::Hit { entry, .. } => {
                assert_eq!(entry.body, Bytes::from_static(b"v3"));
            }
            other => panic!("expected deduplicated v3 Hit, got {other:?}"),
        }

        backend.shutdown().await;
    }

    #[tokio::test]
    async fn test_writer_backpressure_byte_budget_and_mailbox_full() {
        let transport = MockDragonflyTransport::new();
        let mut cfg = test_l2_config("redis://127.0.0.1:6379/0");
        cfg.write_queue_capacity = 4;
        cfg.max_write_queue_bytes = 256;
        cfg.write_batch_size = 1;

        let backend = DragonflyL2BackendInner::start(&cfg, Arc::clone(&transport), Arc::new(|_| {}))
            .await
            .unwrap();
        wait_for_condition(|| connection_cache_is_ready(backend.conn_client.cache_state())).await;

        // Hold first flush in-flight so mailbox & budget saturate cleanly
        transport.gate_writes.store(true, Ordering::Release);
        for i in 0..16 {
            let entry = Arc::new(CachedResponse::new_for_test(
                StatusCode::OK,
                HeaderMap::new(),
                Bytes::from(vec![b'X'; 128]),
                None,
                Duration::from_secs(30),
            ));
            backend.enqueue_set(sample_key(&format!("bp-{i}")), entry, Some((0, 0)));
        }
        assert!(
            backend.writes_dropped.load(Ordering::Acquire) > 0,
            "byte budget / bounded mailbox must drop excess writes without blocking"
        );

        transport.gate_writes.store(false, Ordering::Release);
        transport.write_gate.notify_waiters();
        wait_for_condition(|| backend.write_budget.used_bytes() == 0).await;

        backend.shutdown().await;
    }

    #[tokio::test]
    async fn test_writer_on_stop_flushes_pending_batch() {
        let transport = MockDragonflyTransport::new();
        let mut cfg = test_l2_config("redis://127.0.0.1:6379/0");
        cfg.write_batch_size = 100;
        cfg.write_flush_ms = 60_000;

        let backend = DragonflyL2BackendInner::start(&cfg, Arc::clone(&transport), Arc::new(|_| {}))
            .await
            .unwrap();
        wait_for_condition(|| connection_cache_is_ready(backend.conn_client.cache_state())).await;

        for i in 0..3 {
            let entry = Arc::new(CachedResponse::new_for_test(
                StatusCode::OK,
                HeaderMap::new(),
                Bytes::from_static(b"flush-on-stop"),
                None,
                Duration::from_secs(30),
            ));
            backend.enqueue_set(sample_key(&format!("stop-{i}")), entry, Some((0, 0)));
        }
        assert_eq!(transport.written_items_total.load(Ordering::Acquire), 0);

        backend.shutdown().await;
        assert_eq!(transport.written_items_total.load(Ordering::Acquire), 3);
        assert_eq!(backend.write_budget.used_bytes(), 0);
    }

    #[tokio::test]
    async fn test_invalidation_actor_echo_filter_scope_cancel_and_k07_resync() {
        let transport = MockDragonflyTransport::new();
        let events: Arc<Mutex<Vec<L2InvalidationEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let ev_cb_ref = Arc::clone(&events);
        let cfg = test_l2_config("redis://127.0.0.1:6379/0");

        let backend = DragonflyL2BackendInner::start(
            &cfg,
            Arc::clone(&transport),
            Arc::new(move |ev| ev_cb_ref.lock().unwrap().push(ev)),
        )
        .await
        .unwrap();
        wait_for_condition(|| backend.pubsub_connected_instance.load(Ordering::Acquire) != 0).await;

        // 1. Self-published invalidation must increment remote gen without echoing locally
        backend.enqueue_invalidate_namespace("catalog");
        let ns_gen_key = encode_l2_ns_gen_key("catalog", "praeco");
        wait_for_condition(|| {
            transport
                .db
                .lock()
                .unwrap()
                .gens
                .get(&ns_gen_key)
                .copied()
                .unwrap_or(0)
                == 1
        })
        .await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(events.lock().unwrap().is_empty());

        // 2. Foreign origin payload triggers local invalidation
        let foreign = serde_json::to_vec(&InvalidationWireMsg {
            origin: "foreign-node-id".to_string(),
            kind: InvalidationWireKind::Ns,
            ns: Some("orders".to_string()),
        })
        .unwrap();
        transport.broadcast_raw(foreign);
        wait_for_condition(|| {
            events
                .lock()
                .unwrap()
                .contains(&L2InvalidationEvent::Namespace("orders".to_string()))
        })
        .await;

        // 3. Simulate Pub/Sub drop + Dragonfly in-memory restart (`ns_gen` resets 1 -> 0, K-07)
        events.lock().unwrap().clear();
        transport.simulate_dragonfly_restart();
        transport.drop_all_pubsub_streams();
        wait_for_condition(|| {
            events
                .lock()
                .unwrap()
                .contains(&L2InvalidationEvent::Namespace("catalog".to_string()))
        })
        .await;

        // 4. Shutdown cancels ActorScope and clears invalidation_connected
        backend.shutdown().await;
        assert_eq!(backend.pubsub_connected_instance.load(Ordering::Acquire), 0);
    }

    #[cfg(feature = "cache-l2-chaos")]
    #[tokio::test]
    async fn test_supervisor_one_for_one_crash_recovery() {
        let transport = MockDragonflyTransport::new();
        let events: Arc<Mutex<Vec<L2InvalidationEvent>>> = Arc::new(Mutex::new(Vec::new()));
        let ev_ref = Arc::clone(&events);
        let cfg = test_l2_config("redis://127.0.0.1:6379/0");

        let backend = DragonflyL2BackendInner::start(
            &cfg,
            Arc::clone(&transport),
            Arc::new(move |ev| ev_ref.lock().unwrap().push(ev)),
        )
        .await
        .unwrap();
        wait_for_condition(|| {
            connection_cache_is_ready(backend.conn_client.cache_state())
                && backend.pubsub_connected_instance.load(Ordering::Acquire) != 0
        })
        .await;
        assert_eq!(transport.connect_calls.load(Ordering::Acquire), 1);

        // Crash Writer and Invalidation actors intentionally via otp-actor chaos_test
        backend.writer_client.simulate_crash().await.unwrap();
        backend.inv_client.simulate_crash().await.unwrap();

        // Wait until OneForOne restarts both actors and instance_id advances on Pub/Sub (> 1)
        wait_for_condition(|| backend.pubsub_connected_instance.load(Ordering::Acquire) >= 2).await;

        // OneForOne guarantees L2ConnectionActor stayed alive (still 1 connect)
        assert_eq!(transport.connect_calls.load(Ordering::Acquire), 1);

        // Reactive SlotState rebinding allows subsequent writes & invalidations seamlessly
        let entry = Arc::new(CachedResponse::new_for_test(
            StatusCode::OK,
            HeaderMap::new(),
            Bytes::from_static(b"post-crash-ok"),
            None,
            Duration::from_secs(30),
        ));
        backend.enqueue_set(sample_key("post-crash"), entry, Some((0, 0)));
        wait_for_condition(|| transport.written_items_total.load(Ordering::Acquire) >= 1).await;

        backend.shutdown().await;
    }
}
