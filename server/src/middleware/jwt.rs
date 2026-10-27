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
use common::{Claims, load_decoding_keys, verify_jwt};

const MAX_REVOKED_ENTRIES: usize = 50_000;
const REVOCATION_CLEANUP_INTERVAL_SECS: u64 = 30;
const MAX_JTI_LEN: usize = 256;

/// Thread-safe storage for revoked JWT IDs (`jti`).
#[derive(Clone, Default)]
pub struct JwtRevocationStore {
    /// Maps `jti` to expiration UNIX timestamp (seconds).
    revoked: Arc<DashMap<String, u64>>,
    /// Timestamp (UNIX seconds) of last expired-entries cleanup.
    last_cleanup: Arc<std::sync::atomic::AtomicU64>,
}

impl JwtRevocationStore {
    pub fn new() -> Self {
        Self {
            revoked: Arc::new(DashMap::new()),
            last_cleanup: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        }
    }

    /// Marks a JWT with the given `jti` as revoked until `expires_at`.
    pub fn revoke(&self, jti: impl Into<String>, expires_at: u64) {
        let jti_str = jti.into();
        if jti_str.is_empty() || jti_str.len() > MAX_JTI_LEN {
            return;
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let last = self.last_cleanup.load(std::sync::atomic::Ordering::Relaxed);
        if self.revoked.len() >= MAX_REVOKED_ENTRIES
            || now.saturating_sub(last) >= REVOCATION_CLEANUP_INTERVAL_SECS
        {
            if self
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
        }

        if self.revoked.len() < MAX_REVOKED_ENTRIES || self.revoked.contains_key(&jti_str) {
            self.revoked.insert(jti_str, expires_at);
        } else {
            tracing::warn!(
                "JwtRevocationStore capacity ({}) reached; dropping revocation for jti",
                MAX_REVOKED_ENTRIES
            );
        }
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
        })
    }

    /// Configures request paths (such as `["/api/Logout"]`) that automatically add
    /// a verified token's `jti` to the global [`JwtRevocationStore`].
    pub fn with_revoke_on_paths(mut self, paths: Vec<String>) -> Self {
        self.revoke_on_paths = Arc::new(paths);
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
    /// The token is currently being verified asynchronously in a blocking thread.
    Verifying {
        verify_task: tokio::task::JoinHandle<Result<Claims, anyhow::Error>>,
        req: Option<Request<ReqBody>>,
        inner: S,
        server_name: &'static str,
        oid_mapping: Arc<Vec<(String, crate::configuration::UserRole)>>,
        redirect: Option<String>,
        revoke_on_paths: Arc<Vec<String>>,
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
        loop {
            match self.as_mut().project() {
                JwtAuthFutureProj::Unauthorized { response } => {
                    let res = response.take().expect("polled after complete");
                    return Poll::Ready(Ok(res));
                }
                JwtAuthFutureProj::Inner { inner_fut } => {
                    return inner_fut.poll(cx);
                }
                JwtAuthFutureProj::Verifying {
                    verify_task,
                    req,
                    inner,
                    server_name,
                    oid_mapping,
                    redirect,
                    revoke_on_paths,
                } => {
                    // Wait for the blocking task to finish decoding the JWT
                    let claims_result = std::task::ready!(Pin::new(verify_task).poll(cx));

                    let claims_res = match claims_result {
                        Ok(Ok(c)) => Ok(c),
                        Ok(Err(e)) => Err(format!("{:?}", e)),
                        Err(e) => Err(format!("Task error: {}", e)),
                    };

                    match claims_res {
                        Ok(claims) => {
                            // --- Revocation Check (jti Denylist) ---
                            if let Some(ref jti) = claims.jti {
                                if get_jwt_revocation_store().is_revoked(jti) {
                                    crate::configuration::ServerMetrics::inc_blocked_auth_rbac(server_name);
                                    tracing::warn!("{}: Rejected revoked JWT (jti: {})", server_name, jti);
                                    let resp = unauthorized_response::<()>(redirect.as_deref()).unwrap();
                                    self.set(JwtAuthFuture::Unauthorized { response: Some(resp) });
                                    continue;
                                }
                            }

                            // --- Role Mapping Logic ---
                            let mut roles: Vec<crate::configuration::UserRole> = claims
                                .oids
                                .iter()
                                .map(|suffix| {
                                    oid_mapping
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

                            let mut request = req.take().unwrap();

                            // --- Auto-Revoke JTI on Configured Logout Paths ([F-11]) ---
                            if !revoke_on_paths.is_empty()
                                && revoke_on_paths.iter().any(|p| p == request.uri().path())
                            {
                                if let Some(ref jti) = claims.jti {
                                    let exp = if claims.exp > 0 {
                                        claims.exp as u64
                                    } else {
                                        std::time::SystemTime::now()
                                            .duration_since(std::time::UNIX_EPOCH)
                                            .unwrap_or_default()
                                            .as_secs()
                                            + 3600
                                    };
                                    get_jwt_revocation_store().revoke(jti.clone(), exp);
                                    tracing::info!(
                                        "{}: Auto-revoked JWT jti '{}' on logout path '{}'",
                                        server_name,
                                        jti,
                                        request.uri().path()
                                    );
                                }
                            }

                            request.extensions_mut().insert::<Claims>(claims);
                            request
                                .extensions_mut()
                                .insert::<Arc<Vec<crate::configuration::UserRole>>>(Arc::new(
                                    roles,
                                ));

                            let fut = inner.call(request);
                            self.set(JwtAuthFuture::Inner { inner_fut: fut });
                            // Loop around to poll the newly created Inner future
                        }
                        Err(e) => {
                            crate::configuration::ServerMetrics::inc_blocked_auth_rbac(server_name);
                            tracing::warn!("{}: Invalid JWT: {}", server_name, e);
                            let resp = unauthorized_response::<()>(redirect.as_deref()).unwrap();
                            self.set(JwtAuthFuture::Unauthorized { response: Some(resp) });
                            // Loop around to return the Unauthorized response
                        }
                    }
                }
            }
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

    /// Extracts, validates, and processes the JWT from the `Authorization` header.
    ///
    /// ## Happy Path
    ///
    /// 1. Strips the `Bearer ` prefix from the `Authorization` header.
    /// 2. Calls [`verify_jwt`] , which tries every decoding key until one
    ///    succeeds (supporting key rotation).
    /// 3. Maps each OID in the claims to a [`UserRole`](crate::configuration::UserRole)
    ///    via the global config. If no specific roles are matched, defaults to
    ///    `UserRole::Guest`.
    /// 4. Inserts the raw `Claims` and the `Vec<UserRole>` into the request
    ///    extensions.
    /// 5. Forwards the enriched request to the inner service.
    ///
    /// ## Error Path
    ///
    /// Returns **401 Unauthorized** if:
    /// * The `Authorization` header is missing.
    /// * The token cannot be verified by any of the configured keys.
    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let decoding_keys = Arc::clone(&self.decoding_keys);
        let server_name = self.server_name;
        let oid_mapping = Arc::clone(&self.oid_mapping);

        tracing::trace!("{}: Processing JWT Authentication for path: {}", server_name, req.uri().path());

        // Extract the token from the "Authorization: Bearer <token>" header.
        let mut token = req
            .headers()
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .map(|s| s.trim().to_string());

        // If not found in header, check the cookie fallback (if configured).
        if token.is_none() {
            if let Some(cookie_name) = &self.cookie_fallback {
                let cookie_prefix = format!("{}=", cookie_name);
                for cookie_header in req.headers().get_all("Cookie").iter() {
                    if let Ok(v) = cookie_header.to_str() {
                        for cookie in v.split(';') {
                            let cookie = cookie.trim();
                            if let Some(val) = cookie.strip_prefix(&cookie_prefix) {
                                token = Some(val.trim().to_string());
                                break;
                            }
                        }
                    }
                    if token.is_some() {
                        break;
                    }
                }
            }
        }

        let inner = self.inner.clone();
        let redirect = self.redirect_on_failure.clone();
        let revoke_on_paths = Arc::clone(&self.revoke_on_paths);

        let expected_iss = self.expected_issuer.clone();
        let expected_aud = self.expected_audience.clone();

        match token {
            Some(token_str) => {
                let verify_task = tokio::task::spawn_blocking(move || {
                    verify_jwt(&token_str, &decoding_keys, expected_iss.as_str(), expected_aud.as_str())
                });

                JwtAuthFuture::Verifying {
                    verify_task,
                    req: Some(req),
                    inner,
                    server_name,
                    oid_mapping,
                    redirect,
                    revoke_on_paths,
                }
            }
            None => {
                crate::configuration::ServerMetrics::inc_blocked_auth_rbac(server_name);
                tracing::debug!("{}: Missing Authorization header or cookie", server_name);
                JwtAuthFuture::Unauthorized {
                    response: Some(unauthorized_response::<()>(redirect.as_deref()).unwrap()),
                }
            }
        }
    }
}

/// Helper function to create a standardized **401 Unauthorized** response.
///
/// Generic over the error type `T` so it can be used in any `Result<Response, T>`
/// context — the `Ok` variant is always returned, making the error type irrelevant.
fn unauthorized_response<T>(redirect: Option<&str>) -> Result<Response<ServiceRespBody>, T> {
    if let Some(url) = redirect {
        if let Ok(loc_val) = hyper::header::HeaderValue::from_str(url) {
            let body: ServiceRespBody = Full::new(Bytes::new())
                .map_err(SrvError::from)
                .boxed();
            let mut resp = Response::new(body);
            *resp.status_mut() = StatusCode::FOUND;
            resp.headers_mut().insert(hyper::header::LOCATION, loc_val);
            return Ok(resp);
        }
    }

    let body: ServiceRespBody = Full::new(Bytes::from("Unauthorized"))
        .map_err(SrvError::from)
        .boxed();

    let mut resp: Response<ServiceRespBody> = Response::new(body);
    *resp.status_mut() = StatusCode::UNAUTHORIZED;
    Ok(resp)
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
    }
}

