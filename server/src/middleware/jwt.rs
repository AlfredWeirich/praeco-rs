//! # JWT Authentication Middleware
//!
//! Validates incoming requests against one or more Ed25519 public keys,
//! extracts the [`Claims`](common::Claims) payload, and maps the contained
//! OID strings to internal [`UserRole`](crate::configuration::UserRole)
//! values.
//!
//! ## Request Flow
//!
//! 1. Extract the `Authorization: Bearer <token>` header.
//! 2. Verify the JWT signature against a list of [`DecodingKey`]s (supports
//!    key rotation / multiple issuers).
//! 3. Map the custom `oids` claim entries to [`UserRole`] variants using the
//!    global configuration's OID→role table.
//! 4. Inject both the raw [`Claims`] and the resolved `Vec<UserRole>` into
//!    the request's [extensions](hyper::Request::extensions) for downstream
//!    layers to consume (e.g. the logger, the router's RBAC check).
//!
//! If the token is missing or invalid, a **401 Unauthorized** response is
//! returned immediately without forwarding the request.


// === Standard Library ===
use std::{
    cmp::Reverse,
    collections::BinaryHeap,
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

// === External Crates ===
use bytes::Bytes;
use dashmap::DashMap;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode};
use jsonwebtoken::DecodingKey;
use pin_project::pin_project;
use tower::{Layer, Service};
#[allow(unused_imports)]
use tracing::error;

// === Internal Modules ===
use crate::{ServiceRespBody, SrvError};
use common::{Claims, JwtVerifyOptions, load_decoding_keys, verify_jwt_with_options};

const MAX_REVOKED_ENTRIES: usize = 50_000;
const REVOCATION_CLEANUP_INTERVAL_SECS: u64 = 30;
const MAX_JTI_LEN: usize = 256;

/// Leeway in seconds applied by `jsonwebtoken::Validation::new` by default when
/// checking `exp`. Revocation entries must outlive `exp + JWT_EXP_LEEWAY_SECS`
/// so a token revoked near expiration cannot be replayed during the grace window.
pub const JWT_EXP_LEEWAY_SECS: u64 = 60;

/// Min-heap of `(expires_at, jti)` pairs ordered by earliest expiration timestamp.
type ExpiryMinHeap = BinaryHeap<Reverse<(u64, String)>>;

/// Thread-safe storage for revoked JWT IDs (`jti`).
#[derive(Clone, Default)]
pub struct JwtRevocationStore {
    /// Maps `jti` to expiration UNIX timestamp (seconds).
    revoked: Arc<DashMap<String, u64>>,
    /// Min-heap index of `(expires_at, jti)` for O(log n) earliest-expiry eviction and sweeping.
    exp_index: Arc<std::sync::Mutex<ExpiryMinHeap>>,
    /// Timestamp (UNIX seconds) of last expired-entries cleanup.
    last_cleanup: Arc<std::sync::atomic::AtomicU64>,
    /// Number of revocations dropped because all capacity was held by >= `expires_at` entries.
    overflow_drops: Arc<std::sync::atomic::AtomicU64>,
}

impl JwtRevocationStore {
    pub fn new() -> Self {
        Self {
            revoked: Arc::new(DashMap::new()),
            exp_index: Arc::new(std::sync::Mutex::new(BinaryHeap::new())),
            last_cleanup: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            overflow_drops: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    fn lock_exp_index(&self) -> std::sync::MutexGuard<'_, ExpiryMinHeap> {
        self.exp_index
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn insert_with_index(
        &self,
        jti_str: String,
        expires_at: u64,
        heap: &mut ExpiryMinHeap,
    ) {
        self.revoked.insert(jti_str.clone(), expires_at);
        heap.push(Reverse((expires_at, jti_str)));
        if heap.len() > MAX_REVOKED_ENTRIES * 2 {
            *heap = self
                .revoked
                .iter()
                .map(|entry| Reverse((*entry.value(), entry.key().clone())))
                .collect();
        }
    }

    /// Marks a JWT with the given `jti` as revoked until `expires_at`.
    pub fn revoke(&self, jti: impl Into<String>, expires_at: u64) {
        let _ = self.try_revoke(jti, expires_at);
    }

    /// Marks a JWT with the given `jti` as revoked until `expires_at`, returning `false`
    /// only if the input is invalid or the store is at capacity with exclusively equal/longer-lived
    /// entries.
    ///
    /// When at `MAX_REVOKED_ENTRIES`:
    /// 1. Sweeps expired entries from the min-heap head in O(k log n).
    /// 2. If still full, evicts the earliest-expiring active entry in O(log n) if
    ///    `expires_at > min_exp` so shorter-lived revocations do not silently block
    ///    longer-lived token revocations.
    /// 3. If all retained entries live at least as long as `expires_at`, refuses eviction to
    ///    prevent revocation-eviction DoS attacks, increments [`Self::overflow_drops`], and
    ///    returns `false`.
    pub fn try_revoke(&self, jti: impl Into<String>, expires_at: u64) -> bool {
        let jti_str = jti.into();
        if jti_str.is_empty() || jti_str.len() > MAX_JTI_LEN {
            return false;
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let last = self.last_cleanup.load(std::sync::atomic::Ordering::Relaxed);
        if self.revoked.len() < MAX_REVOKED_ENTRIES
            && now.saturating_sub(last) >= REVOCATION_CLEANUP_INTERVAL_SECS
            && self
                .last_cleanup
                .compare_exchange(
                    last,
                    now,
                    std::sync::atomic::Ordering::Relaxed,
                    std::sync::atomic::Ordering::Relaxed,
                )
                .is_ok()
        {
            self.cleanup_expired();
        }

        let mut heap = self.lock_exp_index();

        if self.revoked.len() < MAX_REVOKED_ENTRIES || self.revoked.contains_key(&jti_str) {
            self.insert_with_index(jti_str, expires_at, &mut heap);
            return true;
        }

        // Store is at capacity: pop expired entries and locate the earliest active entry in O(log n).
        let earliest = loop {
            let Some(Reverse((heap_exp, heap_jti))) = heap.peek().cloned() else {
                break None;
            };
            match self.revoked.get(&heap_jti) {
                Some(entry) if *entry.value() == heap_exp => {
                    drop(entry);
                    if heap_exp <= now {
                        heap.pop();
                        self.revoked.remove_if(&heap_jti, |_, v| *v == heap_exp);
                        continue;
                    }
                    break Some((heap_jti, heap_exp));
                }
                _ => {
                    heap.pop();
                }
            }
        };

        if self.revoked.len() < MAX_REVOKED_ENTRIES {
            self.insert_with_index(jti_str, expires_at, &mut heap);
            return true;
        }

        if let Some((min_key, min_exp)) = earliest
            && expires_at > min_exp
            && heap.pop().is_some()
            && self.revoked.remove_if(&min_key, |_, exp| *exp == min_exp).is_some()
            && self.revoked.len() < MAX_REVOKED_ENTRIES
        {
            tracing::warn!(
                "JwtRevocationStore capacity ({}) reached; evicted earliest-expiring entry (exp={}) for longer-lived jti (exp={})",
                MAX_REVOKED_ENTRIES,
                min_exp,
                expires_at
            );
            self.insert_with_index(jti_str, expires_at, &mut heap);
            return true;
        }

        drop(heap);
        self.overflow_drops
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        tracing::error!(
            "JwtRevocationStore capacity ({}) exhausted by active entries (>= exp {}); dropping revocation for jti",
            MAX_REVOKED_ENTRIES,
            expires_at
        );
        false
    }

    /// Returns the cumulative number of revocations dropped due to store saturation.
    pub fn overflow_drops(&self) -> u64 {
        self.overflow_drops.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Checks if a `jti` has been revoked. If expired, lazily prunes it.
    pub fn is_revoked(&self, jti: &str) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if let Some(entry) = self.revoked.get(jti) {
            if now < *entry.value() {
                return true;
            } else {
                drop(entry);
                self.revoked.remove(jti);
            }
        }
        false
    }

    /// Explicitly purges all expired revocations.
    pub fn cleanup_expired(&self) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.revoked.retain(|_, exp| now < *exp);
        if let Ok(mut heap) = self.exp_index.try_lock()
            && heap.len() > MAX_REVOKED_ENTRIES * 2
        {
            *heap = self
                .revoked
                .iter()
                .map(|entry| Reverse((*entry.value(), entry.key().clone())))
                .collect();
        }
    }

    pub fn len(&self) -> usize {
        self.revoked.len()
    }

    pub fn is_empty(&self) -> bool {
        self.revoked.is_empty()
    }
}

static GLOBAL_REVOCATION_STORE: std::sync::OnceLock<JwtRevocationStore> = std::sync::OnceLock::new();

/// Returns the singleton instance of the global JWT revocation store.
pub fn get_jwt_revocation_store() -> &'static JwtRevocationStore {
    GLOBAL_REVOCATION_STORE.get_or_init(JwtRevocationStore::new)
}

/// A Tower [`Layer`] for JWT-based Authentication.
///
/// This layer prepares a [`JwtAuthService`] with the necessary decoding keys
/// and server identification.
#[derive(Clone)]
pub struct JwtAuthLayer {
    /// Pre-loaded Ed25519 decoding keys shared across all service clones.
    /// Wrapped in `Arc` because `DecodingKey` is not `Clone`-cheap.
    decoding_keys: Arc<Vec<DecodingKey>>,
    /// Server name label for tracing/logging.
    server_name: &'static str,
    /// Server-specific OID mapping (stored as a Vec for fast linear search of small maps).
    oid_mapping: Arc<Vec<(String, crate::configuration::UserRole)>>,
    /// Optional cookie name to extract the JWT from.
    cookie_fallback: Option<String>,
    /// Optional URL to redirect to instead of returning 401.
    redirect_on_failure: Option<String>,
    /// Expected issuer.
    expected_issuer: String,
    /// Expected audience.
    expected_audience: String,
    /// Request paths on which a valid JWT's `jti` is automatically revoked upon forwarding.
    revoke_on_paths: Arc<Vec<String>>,
    /// Verification policy options (`require_jti`, `max_token_lifetime_secs`).
    verify_options: JwtVerifyOptions,
}

impl JwtAuthLayer {
    /// Creates a new `JwtAuthLayer`.
    ///
    /// # Arguments
    /// * `key_files` - A list of paths to PEM-encoded public keys used for token verification.
    /// * `server_name` - A static string identifying the server for logging purposes.
    pub fn new(
        key_files: Vec<String>,
        server_name: &'static str,
        oid_mapping_hash: Arc<std::collections::HashMap<String, crate::configuration::UserRole>>,
        cookie_fallback: Option<String>,
        redirect_on_failure: Option<String>,
        expected_issuer: String,
        expected_audience: String,
    ) -> Result<Self, anyhow::Error> {
        if expected_issuer.split(',').all(|s| s.trim().is_empty()) {
            anyhow::bail!("{server_name}: JwtAuthLayer expected_issuer must not be empty");
        }
        if expected_audience.split(',').all(|s| s.trim().is_empty()) {
            anyhow::bail!("{server_name}: JwtAuthLayer expected_audience must not be empty");
        }
        let decoding_keys = load_decoding_keys(&key_files)?;

        // Convert HashMap to Vec for faster linear search (avoids SipHash overhead on small sets)
        let oid_mapping: Vec<_> = oid_mapping_hash
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        Ok(Self {
            decoding_keys: Arc::new(decoding_keys),
            server_name,
            oid_mapping: Arc::new(oid_mapping),
            cookie_fallback,
            redirect_on_failure,
            expected_issuer,
            expected_audience,
            revoke_on_paths: Arc::new(Vec::new()),
            verify_options: JwtVerifyOptions::default(),
        })
    }

    /// Configures request paths (such as `["/api/Logout"]`) that automatically add
    /// a verified token's `jti` to the global [`JwtRevocationStore`].
    pub fn with_revoke_on_paths(mut self, paths: Vec<String>) -> Self {
        self.revoke_on_paths = Arc::new(paths);
        self
    }

    /// Configures whether incoming JWTs must carry a non-empty `jti` claim (default: `true`).
    pub fn with_require_jti(mut self, require_jti: bool) -> Self {
        self.verify_options.require_jti = require_jti;
        self
    }

    /// Configures the maximum allowed remaining lifetime (`exp - now`) for incoming JWTs.
    /// Pass `None` to disable the upper lifetime bound.
    pub fn with_max_token_lifetime_seconds(mut self, max_lifetime_secs: Option<u64>) -> Self {
        self.verify_options.max_token_lifetime_secs = max_lifetime_secs;
        self
    }
}

impl<S> Layer<S> for JwtAuthLayer {
    type Service = JwtAuthService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        JwtAuthService {
            inner,
            decoding_keys: Arc::clone(&self.decoding_keys),
            server_name: self.server_name,
            oid_mapping: Arc::clone(&self.oid_mapping),
            cookie_fallback: self.cookie_fallback.clone(),
            redirect_on_failure: self.redirect_on_failure.clone(),
            expected_issuer: self.expected_issuer.clone(),
            expected_audience: self.expected_audience.clone(),
            revoke_on_paths: Arc::clone(&self.revoke_on_paths),
            verify_options: self.verify_options,
        }
    }
}

/// A Tower [`Service`] that validates JWTs and maps claims to roles.
///
/// On success the service injects two extensions into the request:
/// * `Claims` — the raw decoded JWT payload.
/// * `Vec<UserRole>` — the mapped internal roles.
///
/// On failure it short-circuits with a 401 response.
#[derive(Clone)]
pub struct JwtAuthService<S> {
    /// The next service in the middleware chain.
    inner: S,
    /// Arc-shared list of decoding keys for signature verification.
    decoding_keys: Arc<Vec<DecodingKey>>,
    /// Server name for logging contexts.
    server_name: &'static str,
    /// Server-specific OID mapping (stored as a Vec for fast linear search).
    oid_mapping: Arc<Vec<(String, crate::configuration::UserRole)>>,
    /// Optional cookie name to extract the JWT from.
    cookie_fallback: Option<String>,
    /// Optional URL to redirect to instead of returning 401.
    redirect_on_failure: Option<String>,
    /// Expected issuer.
    expected_issuer: String,
    /// Expected audience.
    expected_audience: String,
    /// Request paths on which a valid JWT's `jti` is automatically revoked upon forwarding.
    revoke_on_paths: Arc<Vec<String>>,
    /// Verification policy options (`require_jti`, `max_token_lifetime_secs`).
    verify_options: JwtVerifyOptions,
}

/// Case-insensitively strips the RFC 7235 `"Bearer "` authorization scheme prefix.
#[inline]
fn strip_bearer_prefix(header_val: &str) -> Option<&str> {
    let prefix = header_val.get(..7)?;
    if prefix.eq_ignore_ascii_case("bearer ") {
        header_val.get(7..)
    } else {
        None
    }
}

#[pin_project(project = JwtAuthFutureProj)]
pub enum JwtAuthFuture<S, ReqBody>
where
    S: Service<Request<ReqBody>>,
{
    /// Short-circuit response if token is missing or invalid.
    Unauthorized {
        response: Option<Response<ServiceRespBody>>,
    },
    /// Verification succeeded, the request was forwarded to the inner service.
    Inner {
        #[pin]
        inner_fut: S::Future,
    },
}

impl<S, ReqBody> Future for JwtAuthFuture<S, ReqBody>
where
    S: Service<Request<ReqBody>, Response = Response<ServiceRespBody>>,
{
    type Output = Result<Response<ServiceRespBody>, S::Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.as_mut().project() {
            JwtAuthFutureProj::Unauthorized { response } => crate::poll_ready_response(response),
            JwtAuthFutureProj::Inner { inner_fut } => inner_fut.poll(cx),
        }
    }
}

impl<S, ReqBody> Service<Request<ReqBody>> for JwtAuthService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ServiceRespBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ReqBody: Send + 'static,
{
    type Response = Response<ServiceRespBody>;
    type Error = S::Error;
    type Future = JwtAuthFuture<S, ReqBody>;

    /// Delegates back-pressure to the inner service.
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    /// Extracts, validates, and processes the JWT from the `Authorization` header
    /// or configured fallback cookie.
    ///
    /// ## Happy Path
    ///
    /// 1. Strips the `Bearer ` prefix (case-insensitively per RFC 7235) from the
    ///    `Authorization` header, falling back to `cookie_fallback` if configured.
    /// 2. Calls [`verify_jwt_with_options`] inline (~50–100 µs for Ed25519 after a fast
    ///    4 KiB length and 3-segment structure pre-check, avoiding `spawn_blocking`
    ///    thread-pool exhaustion under unauthenticated token floods).
    /// 3. Checks the global [`JwtRevocationStore`] denylist for the token's `jti`.
    /// 4. Maps each OID in the claims to a [`UserRole`](crate::configuration::UserRole)
    ///    via the server's OID mapping table (defaulting to `UserRole::Guest`).
    /// 5. Inserts the raw `Claims` and `Arc<RoleVec<6>>` into request extensions and
    ///    forwards the enriched request to the inner service.
    fn call(&mut self, mut req: Request<ReqBody>) -> Self::Future {
        let server_name = self.server_name;

        tracing::trace!(
            "{}: Processing JWT Authentication for path: {}",
            server_name,
            req.uri().path()
        );

        // Extract the token from the "Authorization: Bearer <token>" header (borrowed, zero-alloc).
        let mut token: Option<&str> = req
            .headers()
            .get(hyper::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(strip_bearer_prefix)
            .map(str::trim)
            .filter(|s| !s.is_empty());

        // If not found in header, check the cookie fallback (if configured).
        if token.is_none()
            && let Some(cookie_name) = &self.cookie_fallback
        {
            for cookie_header in req.headers().get_all(hyper::header::COOKIE) {
                if let Ok(v) = cookie_header.to_str() {
                    for cookie in v.split(';') {
                        let cookie = cookie.trim();
                        if let Some(rest) = cookie.strip_prefix(cookie_name.as_str())
                            && let Some(val) = rest.strip_prefix('=')
                        {
                            let trimmed = val.trim();
                            if !trimmed.is_empty() {
                                token = Some(trimmed);
                                break;
                            }
                        }
                    }
                }
                if token.is_some() {
                    break;
                }
            }
        }

        let Some(token_str) = token else {
            crate::configuration::ServerMetrics::inc_blocked_jwt_auth(server_name);
            tracing::debug!("{}: Missing Authorization header or cookie", server_name);
            return JwtAuthFuture::Unauthorized {
                response: Some(unauthorized_response(self.redirect_on_failure.as_deref())),
            };
        };

        let claims = match verify_jwt_with_options(
            token_str,
            &self.decoding_keys,
            self.expected_issuer.as_str(),
            self.expected_audience.as_str(),
            self.verify_options,
        ) {
            Ok(claims) => claims,
            Err(e) => {
                crate::configuration::ServerMetrics::inc_blocked_jwt_auth(server_name);
                tracing::warn!("{}: Invalid JWT: {:#}", server_name, e);
                return JwtAuthFuture::Unauthorized {
                    response: Some(unauthorized_response(self.redirect_on_failure.as_deref())),
                };
            }
        };

        // --- Revocation Check (jti Denylist) ---
        if let Some(ref jti) = claims.jti
            && get_jwt_revocation_store().is_revoked(jti)
        {
            crate::configuration::ServerMetrics::inc_blocked_jwt_auth(server_name);
            tracing::warn!("{}: Rejected revoked JWT (jti: {})", server_name, jti);
            return JwtAuthFuture::Unauthorized {
                response: Some(unauthorized_response(self.redirect_on_failure.as_deref())),
            };
        }

        // --- Role Mapping Logic ---
        let mut roles: crate::configuration::RoleVec<6> = claims
            .oids
            .iter()
            .map(|suffix| {
                self.oid_mapping
                    .iter()
                    .find(|(k, _)| k == suffix)
                    .map(|(_, v)| v.clone())
                    .unwrap_or_else(crate::configuration::UserRole::guest)
            })
            .filter(|role| *role != crate::configuration::UserRole::guest())
            .collect();

        if roles.is_empty() {
            roles.push(crate::configuration::UserRole::guest());
        }

        tracing::trace!("{}: JWT Roles mapped: {:?}", server_name, roles);

        // --- Auto-Revoke JTI on Configured Logout Paths ([F-11]) ---
        if !self.revoke_on_paths.is_empty()
            && self.revoke_on_paths.iter().any(|p| p == req.uri().path())
            && let Some(ref jti) = claims.jti
        {
            let exp = if claims.exp > 0 {
                claims.exp as u64
            } else {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    + 3600
            };
            get_jwt_revocation_store().revoke(
                jti.clone(),
                exp.saturating_add(JWT_EXP_LEEWAY_SECS),
            );
            tracing::info!(
                "{}: Auto-revoked JWT jti '{}' on logout path '{}'",
                server_name,
                jti,
                req.uri().path()
            );
        }

        req.extensions_mut().insert::<Claims>(claims);
        req.extensions_mut()
            .insert::<Arc<crate::configuration::RoleVec<6>>>(Arc::new(roles));

        let fut = self.inner.call(req);
        JwtAuthFuture::Inner { inner_fut: fut }
    }
}

/// Helper function to create a standardized **401 Unauthorized** (or **302 Found** redirect) response.
fn unauthorized_response(redirect: Option<&str>) -> Response<ServiceRespBody> {
    if let Some(url) = redirect
        && let Ok(loc_val) = hyper::header::HeaderValue::from_str(url) {
            let body: ServiceRespBody = Full::new(Bytes::new())
                .map_err(SrvError::from)
                .boxed();
            let mut resp = Response::new(body);
            *resp.status_mut() = StatusCode::FOUND;
            resp.headers_mut().insert(hyper::header::LOCATION, loc_val);
            return resp;
        }

    let body: ServiceRespBody = Full::new(Bytes::from("Unauthorized"))
        .map_err(SrvError::from)
        .boxed();

    crate::build_infallible_response(StatusCode::UNAUTHORIZED, None, body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    const TEST_PRIV_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/IrnOV6maFjmtsjchLt6\n-----END PRIVATE KEY-----\n";
    const TEST_PUB_KEY: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAk2Zye1IFLZDkM9awuejFhYgrETKpGldlqBFSGOEM/os=\n-----END PUBLIC KEY-----\n";

    #[test]
    fn test_jwt_revocation_store_lifecycle() {
        let store = JwtRevocationStore::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // 1. Initially empty
        assert!(!store.is_revoked("token-1"));
        assert_eq!(store.len(), 0);

        // 2. Revoke active token
        store.revoke("token-1", now + 300);
        assert!(store.is_revoked("token-1"));
        assert!(!store.is_revoked("token-2"));
        assert_eq!(store.len(), 1);

        // 3. Expired token is lazily pruned
        store.revoke("token-expired", now - 10);
        assert!(!store.is_revoked("token-expired"));

        // 4. Cleanup expired
        store.revoke("token-stale", now - 5);
        store.cleanup_expired();
        assert!(!store.is_revoked("token-stale"));
    }

    #[test]
    fn test_jwt_revocation_store_enforces_capacity_cap() {
        let store = JwtRevocationStore::new();
        let far_future = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;

        for i in 0..MAX_REVOKED_ENTRIES {
            store.revoke(format!("jti-{i}"), far_future);
        }
        assert_eq!(store.len(), MAX_REVOKED_ENTRIES);

        // A new jti beyond the cap must be dropped (bounded memory, no eviction).
        store.revoke("jti-overflow", far_future);
        assert_eq!(store.len(), MAX_REVOKED_ENTRIES);
        assert!(!store.is_revoked("jti-overflow"));
        assert!(store.is_revoked("jti-0"), "existing revocations must not be evicted");

        // Refreshing an already-known jti is still allowed at capacity.
        store.revoke("jti-0", far_future + 10);
        assert_eq!(store.len(), MAX_REVOKED_ENTRIES);
        assert!(store.is_revoked("jti-0"));
    }

    #[test]
    fn test_jwt_revocation_store_cleanup_frees_capacity() {
        let store = JwtRevocationStore::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Fill the store completely with already-expired entries.
        for i in 0..MAX_REVOKED_ENTRIES {
            store.revoke(format!("old-{i}"), now.saturating_sub(1));
        }
        // At capacity, revoke() triggers an expiry sweep and then accepts the new entry.
        store.revoke("fresh", now + 300);
        assert!(store.is_revoked("fresh"));
        assert!(store.len() <= 1 + MAX_REVOKED_ENTRIES);
        assert!(store.len() < MAX_REVOKED_ENTRIES, "expired entries must be swept");
    }

    #[test]
    fn test_jwt_revocation_store_rejects_empty_and_oversized_jti() {
        let store = JwtRevocationStore::new();
        let far_future = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 3600;

        store.revoke("", far_future);
        store.revoke("x".repeat(MAX_JTI_LEN + 1), far_future);
        assert!(store.is_empty());

        store.revoke("x".repeat(MAX_JTI_LEN), far_future);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_jwt_revocation_store_evicts_earliest_expiring_when_longer_jti_revoked() {
        let store = JwtRevocationStore::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let shorter_exp = now + 60;
        let medium_exp = now + 600;
        let longer_exp = now + 3600;

        store.revoke("short-jti", shorter_exp);
        for i in 1..MAX_REVOKED_ENTRIES {
            store.revoke(format!("med-{i}"), medium_exp);
        }
        assert_eq!(store.len(), MAX_REVOKED_ENTRIES);

        // Longer-lived token evicts the earliest-expiring entry ("short-jti")
        assert!(store.try_revoke("long-jti", longer_exp));
        assert_eq!(store.len(), MAX_REVOKED_ENTRIES);
        assert!(store.is_revoked("long-jti"));
        assert!(!store.is_revoked("short-jti"));
        assert_eq!(store.overflow_drops(), 0);

        // Shorter/equal token cannot evict longer-lived active entries and increments overflow_drops
        assert!(!store.try_revoke("too-short", now + 30));
        assert_eq!(store.overflow_drops(), 1);
        assert!(store.is_revoked("long-jti"));
    }

    #[test]
    fn test_jwt_revocation_store_skips_stale_heap_entries_after_refresh() {
        let store = JwtRevocationStore::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Insert with short exp, then refresh to a long exp so a stale (now+10) entry remains in heap.
        assert!(store.try_revoke("refreshed-jti", now + 10));
        assert!(store.try_revoke("true-earliest", now + 60));
        assert!(store.try_revoke("refreshed-jti", now + 5000));

        for i in 2..MAX_REVOKED_ENTRIES {
            assert!(store.try_revoke(format!("filler-{i}"), now + 600));
        }
        assert_eq!(store.len(), MAX_REVOKED_ENTRIES);

        // Eviction must discard the stale heap entry for "refreshed-jti" and evict "true-earliest".
        assert!(store.try_revoke("incoming-long", now + 3600));
        assert!(store.is_revoked("refreshed-jti"));
        assert!(!store.is_revoked("true-earliest"));
        assert!(store.is_revoked("incoming-long"));
    }

    #[test]
    fn test_jwt_revocation_store_rebuilds_oversized_heap_and_stays_bounded() {
        let store = JwtRevocationStore::new();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let total_updates = (MAX_REVOKED_ENTRIES * 2) + 10;
        for i in 0..total_updates {
            assert!(store.try_revoke("churn-jti", now + 1000 + i as u64));
        }

        assert_eq!(store.len(), 1);
        assert!(store.is_revoked("churn-jti"));
        assert!(
            store.lock_exp_index().len() <= MAX_REVOKED_ENTRIES,
            "min-heap index must stay bounded after rebuild"
        );
    }

    #[tokio::test]
    async fn test_jwtauth_service_rejects_revoked_jti() {
        use tower::service_fn;

        let enc_key = jsonwebtoken::EncodingKey::from_ed_pem(TEST_PRIV_KEY.as_bytes()).unwrap();
        let dec_key = jsonwebtoken::DecodingKey::from_ed_pem(TEST_PUB_KEY.as_bytes()).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let jti = "test-jti-uuid-999".to_string();
        let claims = Claims {
            sub: "admin-user".to_string(),
            iss: "test-issuer".to_string(),
            aud: Some("test-aud".to_string()),
            exp: now as usize + 3600,
            oids: vec!["1".to_string()],
            jti: Some(jti.clone()),
        };

        let token = common::sign_jwt(&claims, &enc_key).unwrap();

        let inner_svc = service_fn(|_req: Request<Full<Bytes>>| async {
            let body: ServiceRespBody = Full::new(Bytes::from("OK")).map_err(SrvError::from).boxed();
            Ok::<Response<ServiceRespBody>, std::convert::Infallible>(Response::new(body))
        });

        let mut jwt_svc = JwtAuthService {
            inner: inner_svc,
            decoding_keys: Arc::new(vec![dec_key]),
            server_name: "test-server",
            oid_mapping: Arc::new(vec![("1".to_string(), crate::configuration::UserRole("Admin".to_string()))]),
            cookie_fallback: None,
            redirect_on_failure: None,
            expected_issuer: "test-issuer".to_string(),
            expected_audience: "test-aud".to_string(),
            revoke_on_paths: Arc::new(Vec::new()),
            verify_options: JwtVerifyOptions::default(),
        };

        // First request: token is NOT revoked -> should succeed (200 OK)
        let req1 = Request::builder()
            .uri("/api/test")
            .header("Authorization", format!("Bearer {}", token))
            .body(Full::new(Bytes::new()))
            .unwrap();

        let resp1 = jwt_svc.ready().await.unwrap().call(req1).await.unwrap();
        assert_eq!(resp1.status(), StatusCode::OK);

        // Now revoke the token's JTI
        get_jwt_revocation_store().revoke(&jti, now + 3600);

        // Second request: token's JTI IS revoked -> should be rejected (401 Unauthorized)
        let req2 = Request::builder()
            .uri("/api/test")
            .header("Authorization", format!("Bearer {}", token))
            .body(Full::new(Bytes::new()))
            .unwrap();

        let resp2 = jwt_svc.ready().await.unwrap().call(req2).await.unwrap();
        assert_eq!(resp2.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_jwtauth_service_auto_revokes_jti_on_configured_logout_path() {
        use tower::service_fn;

        let enc_key = jsonwebtoken::EncodingKey::from_ed_pem(TEST_PRIV_KEY.as_bytes()).unwrap();
        let dec_key = jsonwebtoken::DecodingKey::from_ed_pem(TEST_PUB_KEY.as_bytes()).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let jti = "logout-auto-revoke-jti-42".to_string();
        let claims = Claims {
            sub: "admin-user".to_string(),
            iss: "test-issuer".to_string(),
            aud: Some("test-aud".to_string()),
            exp: now as usize + 3600,
            oids: vec!["1".to_string()],
            jti: Some(jti.clone()),
        };

        let token = common::sign_jwt(&claims, &enc_key).unwrap();
        assert!(!get_jwt_revocation_store().is_revoked(&jti));

        let inner_svc = service_fn(|_req: Request<Full<Bytes>>| async {
            let body: ServiceRespBody = Full::new(Bytes::from(r#"{"status":"logged_out"}"#))
                .map_err(SrvError::from)
                .boxed();
            Ok::<Response<ServiceRespBody>, std::convert::Infallible>(Response::new(body))
        });

        let mut jwt_svc = JwtAuthService {
            inner: inner_svc,
            decoding_keys: Arc::new(vec![dec_key]),
            server_name: "test-server",
            oid_mapping: Arc::new(vec![("1".to_string(), crate::configuration::UserRole("Admin".to_string()))]),
            cookie_fallback: Some("admin-jwt".to_string()),
            redirect_on_failure: None,
            expected_issuer: "test-issuer".to_string(),
            expected_audience: "test-aud".to_string(),
            revoke_on_paths: Arc::new(vec!["/api/Logout".to_string()]),
            verify_options: JwtVerifyOptions::default(),
        };

        // 1. Regular API call (/api/WhoAmI) succeeds and does NOT revoke the JTI
        let req_whoami = Request::builder()
            .method(hyper::Method::POST)
            .uri("/api/WhoAmI")
            .header("Cookie", format!("admin-jwt={}", token))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp_whoami = jwt_svc.ready().await.unwrap().call(req_whoami).await.unwrap();
        assert_eq!(resp_whoami.status(), StatusCode::OK);
        assert!(!get_jwt_revocation_store().is_revoked(&jti));

        // 2. Logout call (/api/Logout) is forwarded to the backend (200 OK) AND revokes the JTI
        let req_logout = Request::builder()
            .method(hyper::Method::POST)
            .uri("/api/Logout")
            .header("Cookie", format!("admin-jwt={}", token))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp_logout = jwt_svc.ready().await.unwrap().call(req_logout).await.unwrap();
        assert_eq!(resp_logout.status(), StatusCode::OK);
        assert!(
            get_jwt_revocation_store().is_revoked(&jti),
            "JTI must be revoked in global store immediately upon hitting /api/Logout"
        );

        // 3. Replaying the same token after logout must now be rejected with 401 Unauthorized
        let req_replay = Request::builder()
            .method(hyper::Method::POST)
            .uri("/api/WhoAmI")
            .header("Cookie", format!("admin-jwt={}", token))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp_replay = jwt_svc.ready().await.unwrap().call(req_replay).await.unwrap();
        assert_eq!(resp_replay.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_jwtauth_preceding_rate_limiter_protects_authenticated_quota() {
        use tower::service_fn;
        use crate::middleware::rate_limiter::{TokenBucketRateLimiterService, RateLimitKeyStrategy};

        let enc_key = jsonwebtoken::EncodingKey::from_ed_pem(TEST_PRIV_KEY.as_bytes()).unwrap();
        let dec_key = jsonwebtoken::DecodingKey::from_ed_pem(TEST_PUB_KEY.as_bytes()).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let alice_claims = Claims {
            sub: "alice-uuid".to_string(),
            iss: "test-issuer".to_string(),
            aud: Some("test-aud".to_string()),
            exp: now as usize + 3600,
            oids: vec!["1".to_string()],
            jti: Some("alice-jti".to_string()),
        };
        let alice_token = common::sign_jwt(&alice_claims, &enc_key).unwrap();

        let bob_claims = Claims {
            sub: "bob-uuid".to_string(),
            iss: "test-issuer".to_string(),
            aud: Some("test-aud".to_string()),
            exp: now as usize + 3600,
            oids: vec!["1".to_string()],
            jti: Some("bob-jti".to_string()),
        };
        let bob_token = common::sign_jwt(&bob_claims, &enc_key).unwrap();

        let inner_svc = service_fn(|_req: Request<Full<Bytes>>| async {
            let body: ServiceRespBody = Full::new(Bytes::from("OK")).map_err(SrvError::from).boxed();
            Ok::<Response<ServiceRespBody>, std::convert::Infallible>(Response::new(body))
        });

        // Inner rate limiter with capacity = 1 per identity
        let rate_limited_svc = TokenBucketRateLimiterService::with_config(
            inner_svc,
            1,
            1,
            std::time::Duration::from_secs(60),
            RateLimitKeyStrategy::Identity,
            100,
            std::time::Duration::from_secs(300),
            "test-server",
        );

        // JwtAuth runs BEFORE rate limiter (outer layer)
        let mut pipeline = JwtAuthService {
            inner: rate_limited_svc,
            decoding_keys: Arc::new(vec![dec_key]),
            server_name: "test-server",
            oid_mapping: Arc::new(vec![("1".to_string(), crate::configuration::UserRole("Admin".to_string()))]),
            cookie_fallback: None,
            redirect_on_failure: None,
            expected_issuer: "test-issuer".to_string(),
            expected_audience: "test-aud".to_string(),
            revoke_on_paths: Arc::new(Vec::new()),
            verify_options: JwtVerifyOptions::default(),
        };

        // 1. Unauthenticated attacker sends 10 requests without token
        for _ in 0..10 {
            let unauth_req = Request::builder()
                .uri("/api/admin")
                .body(Full::new(Bytes::new()))
                .unwrap();
            let resp = pipeline.ready().await.unwrap().call(unauth_req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        }

        // 2. Alice makes her first request -> passes auth and rate limit (200 OK)
        let req_alice1 = Request::builder()
            .uri("/api/admin")
            .header("Authorization", format!("Bearer {}", alice_token))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp_alice1 = pipeline.ready().await.unwrap().call(req_alice1).await.unwrap();
        assert_eq!(resp_alice1.status(), StatusCode::OK);

        // 3. Alice makes her second request -> rate limited (429 Too Many Requests)
        let req_alice2 = Request::builder()
            .uri("/api/admin")
            .header("Authorization", format!("Bearer {}", alice_token))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp_alice2 = pipeline.ready().await.unwrap().call(req_alice2).await.unwrap();
        assert_eq!(resp_alice2.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(resp_alice2.headers().contains_key(hyper::header::RETRY_AFTER));

        // 4. Bob makes his request -> Bob has his own bucket, so Alice's limit does NOT block Bob!
        let req_bob1 = Request::builder()
            .uri("/api/admin")
            .header("Authorization", format!("Bearer {}", bob_token))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp_bob1 = pipeline.ready().await.unwrap().call(req_bob1).await.unwrap();
        assert_eq!(resp_bob1.status(), StatusCode::OK);

        let metrics = crate::configuration::ServerMetrics::for_server("test-server");
        assert!(
            metrics
                .blocked_jwt_auth
                .load(std::sync::atomic::Ordering::Relaxed)
                >= 10
        );
        assert!(
            metrics
                .rate_limited
                .load(std::sync::atomic::Ordering::Relaxed)
                >= 1
        );
        assert_eq!(
            metrics
                .blocked_auth_rbac
                .load(std::sync::atomic::Ordering::Relaxed),
            0
        );
    }

    #[tokio::test]
    async fn test_jwt_revocation_covers_exp_leeway_window() {
        use tower::service_fn;

        let enc_key = jsonwebtoken::EncodingKey::from_ed_pem(TEST_PRIV_KEY.as_bytes()).unwrap();
        let dec_key = jsonwebtoken::DecodingKey::from_ed_pem(TEST_PUB_KEY.as_bytes()).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Token expired 10s ago: still accepted by jsonwebtoken's default 60s leeway.
        let jti = "leeway-window-jti-1".to_string();
        let claims = Claims {
            sub: "leeway-user".to_string(),
            iss: "test-issuer".to_string(),
            aud: Some("test-aud".to_string()),
            exp: (now - 10) as usize,
            oids: vec!["1".to_string()],
            jti: Some(jti.clone()),
        };
        let token = common::sign_jwt(&claims, &enc_key).unwrap();

        let inner_svc = service_fn(|_req: Request<Full<Bytes>>| async {
            let body: ServiceRespBody = Full::new(Bytes::from("OK")).map_err(SrvError::from).boxed();
            Ok::<Response<ServiceRespBody>, std::convert::Infallible>(Response::new(body))
        });

        let mut svc = JwtAuthService {
            inner: inner_svc,
            decoding_keys: Arc::new(vec![dec_key]),
            server_name: "test-leeway-server",
            oid_mapping: Arc::new(vec![("1".to_string(), crate::configuration::UserRole("Admin".to_string()))]),
            cookie_fallback: None,
            redirect_on_failure: None,
            expected_issuer: "test-issuer".to_string(),
            expected_audience: "test-aud".to_string(),
            revoke_on_paths: Arc::new(vec!["/logout".to_string()]),
            verify_options: JwtVerifyOptions::default(),
        };

        // First call to /logout succeeds and revokes the jti until exp + JWT_EXP_LEEWAY_SECS.
        let logout_req = Request::builder()
            .uri("/logout")
            .header("Authorization", format!("Bearer {}", token))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let logout_resp = svc.ready().await.unwrap().call(logout_req).await.unwrap();
        assert_eq!(logout_resp.status(), StatusCode::OK);
        assert!(get_jwt_revocation_store().is_revoked(&jti));

        // Replay within the remaining ~50s leeway window must be rejected (401).
        let replay_req = Request::builder()
            .uri("/api/data")
            .header("Authorization", format!("Bearer {}", token))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let replay_resp = svc.ready().await.unwrap().call(replay_req).await.unwrap();
        assert_eq!(replay_resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_jwtauth_service_case_insensitive_bearer_and_policy_enforcement() {
        use tower::service_fn;

        let enc_key = jsonwebtoken::EncodingKey::from_ed_pem(TEST_PRIV_KEY.as_bytes()).unwrap();
        let dec_key = jsonwebtoken::DecodingKey::from_ed_pem(TEST_PUB_KEY.as_bytes()).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let valid_claims = Claims {
            sub: "policy-user".to_string(),
            iss: "test-issuer".to_string(),
            aud: Some("test-aud".to_string()),
            exp: (now + 300) as usize,
            oids: vec!["1".to_string()],
            jti: Some("policy-jti-1".to_string()),
        };
        let valid_token = common::sign_jwt(&valid_claims, &enc_key).unwrap();

        let no_jti_claims = Claims {
            jti: None,
            ..valid_claims.clone()
        };
        let no_jti_token = common::sign_jwt(&no_jti_claims, &enc_key).unwrap();

        let long_lived_claims = Claims {
            exp: (now + 7200) as usize,
            jti: Some("policy-jti-2".to_string()),
            ..valid_claims.clone()
        };
        let long_lived_token = common::sign_jwt(&long_lived_claims, &enc_key).unwrap();

        let inner_svc = service_fn(|_req: Request<Full<Bytes>>| async {
            let body: ServiceRespBody = Full::new(Bytes::from("OK")).map_err(SrvError::from).boxed();
            Ok::<Response<ServiceRespBody>, std::convert::Infallible>(Response::new(body))
        });

        let mut svc = JwtAuthService {
            inner: inner_svc,
            decoding_keys: Arc::new(vec![dec_key]),
            server_name: "test-policy-server",
            oid_mapping: Arc::new(vec![("1".to_string(), crate::configuration::UserRole("Admin".to_string()))]),
            cookie_fallback: None,
            redirect_on_failure: None,
            expected_issuer: "test-issuer".to_string(),
            expected_audience: "test-aud".to_string(),
            revoke_on_paths: Arc::new(Vec::new()),
            verify_options: JwtVerifyOptions {
                require_jti: true,
                max_token_lifetime_secs: Some(600),
            },
        };

        // 1. Lowercase "bearer " and uppercase "BEARER " schemes are accepted (RFC 7235)
        for prefix in ["bearer", "BEARER", "BeArEr"] {
            let req = Request::builder()
                .uri("/api/data")
                .header("Authorization", format!("{prefix} {valid_token}"))
                .body(Full::new(Bytes::new()))
                .unwrap();
            let resp = svc.ready().await.unwrap().call(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }

        // 2. Missing jti is rejected with 401 when require_jti = true
        let req_no_jti = Request::builder()
            .uri("/api/data")
            .header("Authorization", format!("Bearer {no_jti_token}"))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp_no_jti = svc.ready().await.unwrap().call(req_no_jti).await.unwrap();
        assert_eq!(resp_no_jti.status(), StatusCode::UNAUTHORIZED);

        // 3. Token exceeding max_token_lifetime_secs (7200 > 600) is rejected with 401
        let req_long = Request::builder()
            .uri("/api/data")
            .header("Authorization", format!("Bearer {long_lived_token}"))
            .body(Full::new(Bytes::new()))
            .unwrap();
        let resp_long = svc.ready().await.unwrap().call(req_long).await.unwrap();
        assert_eq!(resp_long.status(), StatusCode::UNAUTHORIZED);
    }
}

