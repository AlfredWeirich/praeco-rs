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
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode};
use jsonwebtoken::DecodingKey;
use tower::{Layer, Service};
use tracing::error;

// === Internal Modules ===
use crate::{ServiceRespBody, SrvError};
use common::{Claims, load_decoding_keys, verify_jwt};

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
    ) -> Self {
        let decoding_keys = load_decoding_keys(&key_files);

        // Convert HashMap to Vec for faster linear search (avoids SipHash overhead on small sets)
        let oid_mapping: Vec<_> = oid_mapping_hash
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();

        Self {
            decoding_keys: Arc::new(decoding_keys),
            server_name,
            oid_mapping: Arc::new(oid_mapping),
        }
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
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

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
        tracing::trace!("{}: Processing JWT Authentication", server_name);

        // Extract the token from the "Authorization: Bearer <token>" header.
        let token = req
            .headers()
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .map(|s| s.trim().to_string());

        let mut inner = self.inner.clone();

        Box::pin(async move {
            match token {
                Some(token_str) => {
                    let claims_result =
                        tokio::task::spawn_blocking(move || verify_jwt(&token_str, &decoding_keys))
                            .await;

                    let claims = match claims_result {
                        Ok(Ok(c)) => Ok(c),
                        Ok(Err(e)) => Err(format!("{:?}", e)),
                        Err(e) => Err(format!("Task error: {}", e)),
                    };

                    match claims {
                        Ok(claims) => {
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

                            let mut req = req;
                            req.extensions_mut().insert::<Claims>(claims);
                            req.extensions_mut()
                                .insert::<Arc<Vec<crate::configuration::UserRole>>>(Arc::new(
                                    roles,
                                ));

                            inner.call(req).await
                        }
                        Err(e) => {
                            error!("{}: Invalid JWT: {}", server_name, e);
                            unauthorized_response()
                        }
                    }
                }
                None => {
                    error!("{}: Missing Authorization header", server_name);
                    unauthorized_response()
                }
            }
        })
    }
}

/// Helper function to create a standardized **401 Unauthorized** response.
///
/// Generic over the error type `T` so it can be used in any `Result<Response, T>`
/// context — the `Ok` variant is always returned, making the error type irrelevant.
fn unauthorized_response<T>() -> Result<Response<ServiceRespBody>, T> {
    let body: ServiceRespBody = Full::new(Bytes::from("Unauthorized"))
        .map_err(SrvError::from)
        .boxed();

    let mut resp: Response<ServiceRespBody> = Response::new(body);
    *resp.status_mut() = StatusCode::UNAUTHORIZED;
    Ok(resp)
}
