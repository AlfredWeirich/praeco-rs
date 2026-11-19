//! # Identity Provider (IdP) Service
//!
//! A native end-service for `praeco-rs` that issues JWTs based on mTLS or DeviceAuth.

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use common::{sign_jwt, Claims};
use http_body_util::{BodyExt, Full};
use hyper::{Method, Request, Response, StatusCode};
use jsonwebtoken::{DecodingKey, EncodingKey};
use pin_project::pin_project;
use tower::Service;
use tracing::{debug, error, info};
use anyhow::Context as _;

use crate::{configuration::IdpParams, SrvError, ServiceRespBody};

mod session;
use session::{SessionStore, SessionStatus, ConfirmError, CreateSessionError, PollError};

pub mod webhook;
use webhook::WebhookClient;

/// The Identity Provider service.
#[derive(Clone)]
pub struct IdpService {
    params: IdpParams,
    session_store: SessionStore,
    encoding_key: Arc<EncodingKey>,
    decoding_keys: Arc<Vec<DecodingKey>>,
    server_name: &'static str,
    jwks_payload: Option<Arc<String>>,
    webhook_client: Option<WebhookClient>,
}

impl IdpService {
    /// Creates a new IdpService.
    pub fn new(params: IdpParams, server_name: &'static str) -> Result<Self, anyhow::Error> {
        crate::configuration::validate_idp_cookie_and_redirect(&params, server_name)?;

        let session_store = SessionStore::new(params.session_ttl_seconds);
        
        let webhook_client = WebhookClient::new(&params).context("Failed to init webhook client")?;

        let encoding_key = common::load_encoding_key(&params.jwt_private_key)?;

        let decoding_keys = if let Some(pub_key_path) = &params.jwt_public_key {
            match common::load_decoding_keys(std::slice::from_ref(pub_key_path)) {
                Ok(keys) => Arc::new(keys),
                Err(e) => {
                    tracing::warn!("{}: Failed to load public key for JWT validation/revocation: {}", server_name, e);
                    Arc::new(Vec::new())
                }
            }
        } else {
            Arc::new(Vec::new())
        };

        let mut jwks_payload = None;
        if let Some(pub_key_path) = &params.jwt_public_key {
            match std::fs::read_to_string(pub_key_path) {
                Ok(pem_str) => {
                    if let Ok(pem) = pem::parse(&pem_str) {
                        let der = pem.contents();
                        // Ed25519 SubjectPublicKeyInfo is 44 bytes:
                        // 12 bytes prefix (30 2a 30 05 06 03 2b 65 70 03 21 00, OID 1.3.101.112)
                        // followed by 32 bytes raw public key.
                        const ED25519_SPKI_PREFIX: [u8; 12] = [
                            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
                        ];
                        let raw_key = if der.len() == 44 && der.starts_with(&ED25519_SPKI_PREFIX) {
                            Some(&der[12..44])
                        } else if der.len() == 32 {
                            Some(der)
                        } else {
                            None
                        };

                        if let Some(key_bytes) = raw_key {
                            use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
                            let x = URL_SAFE_NO_PAD.encode(key_bytes);
                            let jwks = serde_json::json!({
                                "keys": [{
                                    "kty": "OKP",
                                    "crv": "Ed25519",
                                    "use": "sig",
                                    "kid": "praeco-key-1",
                                    "x": x,
                                }]
                            })
                            .to_string();
                            jwks_payload = Some(Arc::new(jwks));
                        } else {
                            tracing::warn!(
                                "{}: Public key in {} is not a valid Ed25519 key (expected 44-byte SPKI with OID 1.3.101.112 or 32-byte raw key)",
                                server_name, pub_key_path
                            );
                        }
                    } else {
                        tracing::warn!("{}: Failed to parse PEM in {}", server_name, pub_key_path);
                    }
                }
                Err(e) => {
                    tracing::warn!("{}: Failed to read public key {}: {}", server_name, pub_key_path, e);
                }
            }
        }

        Ok(Self {
            params,
            session_store,
            encoding_key: Arc::new(encoding_key),
            decoding_keys,
            server_name,
            jwks_payload,
            webhook_client,
        })
    }

    fn response_with_content_type(
        status: StatusCode,
        content_type: &'static str,
        body: Bytes,
    ) -> Response<ServiceRespBody> {
        let mut resp = Response::new(Full::new(body).map_err(SrvError::from).boxed());
        *resp.status_mut() = status;
        resp.headers_mut().insert(
            hyper::header::CONTENT_TYPE,
            hyper::header::HeaderValue::from_static(content_type),
        );
        resp
    }

    fn response_ok(body: impl Into<String>) -> Response<ServiceRespBody> {
        Self::response_with_content_type(
            StatusCode::OK,
            "application/json",
            Bytes::from(body.into()),
        )
    }

    fn response_err(status: StatusCode, msg: &str) -> Response<ServiceRespBody> {
        Self::response_with_content_type(
            status,
            "text/plain",
            Bytes::from(msg.to_string()),
        )
    }

    fn generate_jwt_cookie_response(
        &self,
        mut claims: Claims,
    ) -> Result<Response<ServiceRespBody>, anyhow::Error> {
        // Update exp and ensure jti is assigned
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        claims.exp = now as usize + self.params.token_expiry_seconds as usize;
        if claims.jti.is_none() {
            claims.jti = Some(uuid::Uuid::new_v4().to_string());
        }

        let token = sign_jwt(&claims, &self.encoding_key)?;

        let mut cookie_val = format!(
            "{}={}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={}",
            self.params.cookie_name, token, self.params.token_expiry_seconds
        );
        if let Some(domain) = &self.params.cookie_domain {
            if self.params.cookie_name.starts_with("__Host-") {
                tracing::warn!(
                    "{}: cookie_domain '{}' ignored because cookie name '{}' uses __Host- prefix (RFC 6265bis mandates no Domain attribute)",
                    self.server_name, domain, self.params.cookie_name
                );
            } else {
                cookie_val.push_str(&format!("; Domain={}", domain));
            }
        }

        let cookie_header = hyper::header::HeaderValue::from_str(&cookie_val)
            .context("Failed to encode Set-Cookie header value")?;
        let body = serde_json::json!({
            "status": "confirmed",
            "redirect": self.params.redirect_after_login,
        })
        .to_string();

        let mut resp =
            Self::response_with_content_type(StatusCode::OK, "application/json", Bytes::from(body));
        resp.headers_mut()
            .insert(hyper::header::SET_COOKIE, cookie_header);
        Ok(resp)
    }

    fn handle_auth_confirm(
        &self,
        sid: &str,
        user_code: Option<&str>,
        mut claims: Claims,
        dynamic_oids_res: Option<Result<Vec<String>, webhook::WebhookError>>,
    ) -> Response<ServiceRespBody> {
        if let Some(res) = dynamic_oids_res {
            match res {
                Ok(dynamic_oids) => {
                    info!("{}: Webhook returned OIDs: {:?}", self.server_name, dynamic_oids);
                    claims.oids = dynamic_oids;
                }
                Err(e) => {
                    error!("{}: Claims webhook failed: {}", self.server_name, e);
                    match self.params.on_webhook_failure {
                        crate::configuration::WebhookFailurePolicy::Reject => {
                            return Self::response_err(
                                StatusCode::SERVICE_UNAVAILABLE,
                                "Claims resolution failed",
                            );
                        }
                        crate::configuration::WebhookFailurePolicy::FallbackToCert => {
                            // keep original certificate OIDs
                        }
                    }
                }
            }
        }

        match self.session_store.confirm_session(sid, user_code, claims) {
            Ok(()) => Self::response_ok(r#"{"status":"confirmed"}"#),
            Err(ConfirmError::InvalidUserCode) => {
                Self::response_err(StatusCode::BAD_REQUEST, "Invalid confirmation user code")
            }
            Err(ConfirmError::AlreadyConfirmed) => {
                Self::response_err(StatusCode::CONFLICT, "Session already confirmed")
            }
            Err(ConfirmError::NotFound | ConfirmError::Expired) => {
                Self::response_err(StatusCode::NOT_FOUND, "Session not found or expired")
            }
        }
    }

    fn handle_auth_token(&self, mut claims: Claims, dynamic_oids_res: Option<Result<Vec<String>, webhook::WebhookError>>) -> Response<ServiceRespBody> {
        if let Some(res) = dynamic_oids_res {
            match res {
                Ok(dynamic_oids) => {
                    info!("{}: Webhook returned OIDs: {:?}", self.server_name, dynamic_oids);
                    claims.oids = dynamic_oids;
                }
                Err(e) => {
                    error!("{}: Claims webhook failed: {}", self.server_name, e);
                    match self.params.on_webhook_failure {
                        crate::configuration::WebhookFailurePolicy::Reject => {
                            return Self::response_err(
                                StatusCode::SERVICE_UNAVAILABLE,
                                "Claims resolution failed",
                            );
                        }
                        crate::configuration::WebhookFailurePolicy::FallbackToCert => {
                            // keep original certificate OIDs
                        }
                    }
                }
            }
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        claims.exp = now as usize + self.params.token_expiry_seconds as usize;
        if claims.jti.is_none() {
            claims.jti = Some(uuid::Uuid::new_v4().to_string());
        }

        match sign_jwt(&claims, &self.encoding_key) {
            Ok(token) => {
                let body = serde_json::json!({ "token": token }).to_string();
                Self::response_ok(body)
            }
            Err(e) => {
                error!("{}: JWT Generation failed: {}", self.server_name, e);
                Self::response_err(StatusCode::INTERNAL_SERVER_ERROR, "JWT Error")
            }
        }
    }
}

enum WebhookEndpoint {
    Token,
    Confirm { sid: String, code: Option<String> },
}

/// Deferred state for an IdP request awaiting an external claims webhook.
pub struct IdpWebhookState {
    claims: Claims,
    endpoint: WebhookEndpoint,
    idp: IdpService,
}

#[pin_project(project = IdpFutureProj)]
pub enum IdpFuture {
    Ready {
        response: Option<Response<ServiceRespBody>>,
    },
    Webhook {
        #[pin]
        fetch_fut: webhook::WebhookFetchFuture,
        state: Box<IdpWebhookState>,
    },
}

impl Future for IdpFuture {
    type Output = Result<Response<ServiceRespBody>, SrvError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        match this {
            IdpFutureProj::Ready { response } => {
                let resp = response.take().unwrap_or_else(|| {
                    IdpService::response_err(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Internal Future Error",
                    )
                });
                Poll::Ready(Ok(resp))
            }
            IdpFutureProj::Webhook { fetch_fut, state } => {
                let dynamic_oids_res = std::task::ready!(fetch_fut.poll(cx));

                let claims_owned = state.claims.clone();
                let resp = match &state.endpoint {
                    WebhookEndpoint::Token => {
                        state.idp.handle_auth_token(claims_owned, Some(dynamic_oids_res))
                    }
                    WebhookEndpoint::Confirm { sid, code } => state.idp.handle_auth_confirm(
                        sid,
                        code.as_deref(),
                        claims_owned,
                        Some(dynamic_oids_res),
                    ),
                };
                Poll::Ready(Ok(resp))
            }
        }
    }
}

impl Service<Request<crate::SrvBody>> for IdpService {
    type Response = Response<ServiceRespBody>;
    type Error = SrvError;
    type Future = IdpFuture;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<crate::SrvBody>) -> Self::Future {
        let path = req.uri().path().to_string();
        let method = req.method().clone();
        
        // Handle JWKS endpoint directly
        if method == Method::GET && path == "/.well-known/jwks.json" {
            if let Some(jwks) = &self.jwks_payload {
                let resp = Self::response_with_content_type(
                    StatusCode::OK,
                    "application/jwk-set+json",
                    Bytes::from(jwks.as_str().to_string()),
                );
                return IdpFuture::Ready { response: Some(resp) };
            } else {
                return IdpFuture::Ready { response: Some(Self::response_err(StatusCode::NOT_FOUND, "JWKS not configured")) };
            }
        }

        // Extract query parameters and headers manually
        let query = req.uri().query().unwrap_or("").to_string();
        let session_id = query.split('&')
            .find_map(|kv| {
                let mut parts = kv.splitn(2, '=');
                if parts.next()? == "session" {
                    parts.next().map(|s| s.to_string())
                } else {
                    None
                }
            });

        let poll_secret = query.split('&')
            .find_map(|kv| {
                let mut parts = kv.splitn(2, '=');
                if parts.next()? == "poll_secret" {
                    parts.next().map(|s| s.to_string())
                } else {
                    None
                }
            })
            .or_else(|| {
                req.headers()
                    .get("x-poll-secret")
                    .and_then(|v| v.to_str().ok().map(|s| s.to_string()))
            });

        let user_code = query.split('&')
            .find_map(|kv| {
                let mut parts = kv.splitn(2, '=');
                if parts.next()? == "code" {
                    parts.next().map(|s| s.to_string())
                } else {
                    None
                }
            })
            .or_else(|| {
                req.headers()
                    .get("x-user-code")
                    .and_then(|v| v.to_str().ok().map(|s| s.to_string()))
            });

        let requested_aud = query.split('&')
            .find_map(|kv| {
                let mut parts = kv.splitn(2, '=');
                if parts.next()? == "aud" {
                    parts.next().map(|s| s.to_string())
                } else {
                    None
                }
            });

        let client_ip = req.extensions().get::<std::net::SocketAddr>().map(|a| a.ip());

        let aud = requested_aud.as_ref()
            .filter(|a| self.params.allowed_audiences.contains(a))
            .cloned()
            .or_else(|| self.params.allowed_audiences.first().cloned());

        // Determine if the request has a valid mTLS certificate.
        let mtls_claims = if req.extensions().get::<crate::PemCertExtension>().is_some() {
            let sub = if let Some(san) = req.extensions().get::<crate::SanCertExtension>() {
                san.0.clone()
            } else if let Some(pem_ext) = req.extensions().get::<crate::PemCertExtension>() {
                extract_cn_from_pem(&pem_ext.0)
                    .or_else(|| cert_fingerprint_subject(&pem_ext.0))
                    .unwrap_or_else(|| "device".to_string())
            } else {
                "device".to_string()
            };

            let oids = req.extensions().get::<crate::OidCertExtension>()
                .map(|ext| ext.0.clone())
                .unwrap_or_default();

            Some(Claims {
                sub,
                iss: self.params.issuer.clone(),
                aud,
                exp: 0,
                oids,
                jti: None,
            })
        } else {
            None
        };

        match (method, path.as_str()) {
            // 0. Serve the generic HTML login page (Frontend UI)
            (Method::GET, "/auth/login_page") => {
                let html = include_str!("idp_login.html");
                let mut res = Self::response_with_content_type(
                    StatusCode::OK,
                    "text/html; charset=utf-8",
                    Bytes::from_static(html.as_bytes()),
                );
                res.headers_mut().insert(
                    hyper::header::CACHE_CONTROL,
                    hyper::header::HeaderValue::from_static("no-store, no-cache, must-revalidate"),
                );
                IdpFuture::Ready { response: Some(res) }
            }

            // 1. Start a new DeviceAuth login session (Frontend calls this)
            (Method::POST, "/auth/login") => {
                if let Some(ref a) = requested_aud
                    && !self.params.allowed_audiences.is_empty() && !self.params.allowed_audiences.contains(a) {
                        return IdpFuture::Ready {
                            response: Some(Self::response_err(
                                StatusCode::BAD_REQUEST,
                                "Requested audience is not in allowed_audiences",
                            )),
                        };
                    }
                let target_aud = requested_aud.or_else(|| self.params.allowed_audiences.first().cloned());

                match self.session_store.create_session(client_ip, target_aud) {
                    Ok(info) => {
                        debug!(
                            "{}: Created login session {}",
                            self.server_name,
                            session::redact_session_id(&info.session_id)
                        );
                        let body = serde_json::json!({
                            "session": info.session_id,
                            "poll_secret": info.poll_secret,
                            "user_code": info.user_code,
                        })
                        .to_string();
                        IdpFuture::Ready { response: Some(Self::response_ok(body)) }
                    }
                    Err(CreateSessionError::RateLimited) => {
                        IdpFuture::Ready {
                            response: Some(Self::response_err(
                                StatusCode::TOO_MANY_REQUESTS,
                                "Rate limit exceeded. Please wait before creating a new login session.",
                            )),
                        }
                    }
                    Err(CreateSessionError::CapacityExceeded) => {
                        IdpFuture::Ready {
                            response: Some(Self::response_err(
                                StatusCode::SERVICE_UNAVAILABLE,
                                "Server busy: maximum active sessions reached.",
                            )),
                        }
                    }
                }
            }

            // 2. Poll the status of a login session (Frontend calls this, requires poll_secret)
            (Method::GET, "/auth/status") => {
                let sid = match session_id {
                    Some(sid) => sid,
                    None => return IdpFuture::Ready {
                        response: Some(Self::response_err(StatusCode::BAD_REQUEST, "Missing session parameter")),
                    },
                };

                let secret = match poll_secret {
                    Some(s) => s,
                    None => return IdpFuture::Ready {
                        response: Some(Self::response_err(
                            StatusCode::UNAUTHORIZED,
                            "Missing poll_secret parameter or X-Poll-Secret header",
                        )),
                    },
                };

                let resp = match self.session_store.get_and_consume(&sid, &secret) {
                    Ok(SessionStatus::Pending) => {
                        Self::response_ok(r#"{"status":"pending"}"#)
                    }
                    Ok(SessionStatus::Confirmed(claims)) => {
                        info!(
                            "{}: Session {} confirmed, issuing JWT.",
                            self.server_name,
                            session::redact_session_id(&sid)
                        );
                        match self.generate_jwt_cookie_response(claims) {
                            Ok(r) => r,
                            Err(e) => {
                                error!("{}: JWT Generation failed: {}", self.server_name, e);
                                Self::response_err(StatusCode::INTERNAL_SERVER_ERROR, "JWT Error")
                            }
                        }
                    }
                    Err(PollError::Unauthorized) => {
                        Self::response_err(StatusCode::UNAUTHORIZED, "Invalid poll secret")
                    }
                    Err(PollError::NotFound) => {
                        Self::response_err(StatusCode::NOT_FOUND, "Session not found or expired")
                    }
                };
                IdpFuture::Ready { response: Some(resp) }
            }

            // 2b. View session user_code on device (requires mTLS client cert or valid poll_secret)
            (Method::GET, "/auth/session_info") => {
                if let Err(msg) = verify_same_origin(req.headers()) {
                    tracing::warn!("{}: Blocked cross-site GET /auth/session_info", self.server_name);
                    return IdpFuture::Ready {
                        response: Some(Self::response_err(StatusCode::FORBIDDEN, msg)),
                    };
                }
                let sid = match session_id {
                    Some(sid) => sid,
                    None => return IdpFuture::Ready {
                        response: Some(Self::response_err(StatusCode::BAD_REQUEST, "Missing session parameter")),
                    },
                };
                let authorized = mtls_claims.is_some()
                    || poll_secret
                        .as_deref()
                        .is_some_and(|secret| self.session_store.verify_poll_secret(&sid, secret));
                if !authorized {
                    return IdpFuture::Ready {
                        response: Some(Self::response_err(
                            StatusCode::UNAUTHORIZED,
                            "Unauthorized: mTLS certificate or valid poll_secret required",
                        )),
                    };
                }
                let resp = match self.session_store.get_session_user_code(&sid) {
                    Some(code) => {
                        let body = serde_json::json!({ "user_code": code }).to_string();
                        Self::response_ok(body)
                    }
                    None => Self::response_err(StatusCode::NOT_FOUND, "Session not found or expired"),
                };
                IdpFuture::Ready { response: Some(resp) }
            }

            // 3. Confirm a session (Device with mTLS calls this)
            (Method::POST, "/auth/confirm") => {
                if let Err(msg) = verify_same_origin(req.headers()) {
                    tracing::warn!("{}: Blocked cross-site POST /auth/confirm", self.server_name);
                    return IdpFuture::Ready {
                        response: Some(Self::response_err(StatusCode::FORBIDDEN, msg)),
                    };
                }
                let sid = match session_id {
                    Some(sid) => sid,
                    None => return IdpFuture::Ready {
                        response: Some(Self::response_err(StatusCode::BAD_REQUEST, "Missing session parameter")),
                    },
                };

                let claims = match mtls_claims {
                    Some(c) => c,
                    None => return IdpFuture::Ready {
                        response: Some(Self::response_err(StatusCode::UNAUTHORIZED, "mTLS required to confirm session")),
                    },
                };

                // Pre-validate session and mandatory user_code BEFORE triggering outbound Claims Webhook
                if let Err(err) = self.session_store.verify_session_code(&sid, user_code.as_deref()) {
                    let resp = match err {
                        ConfirmError::InvalidUserCode => {
                            Self::response_err(StatusCode::BAD_REQUEST, "Invalid confirmation user code")
                        }
                        ConfirmError::AlreadyConfirmed => {
                            Self::response_err(StatusCode::CONFLICT, "Session already confirmed")
                        }
                        ConfirmError::NotFound | ConfirmError::Expired => {
                            Self::response_err(StatusCode::NOT_FOUND, "Session not found or expired")
                        }
                    };
                    return IdpFuture::Ready { response: Some(resp) };
                }

                if let Some(wh) = &self.webhook_client {
                    let sub = claims.sub.clone();
                    let oids = claims.oids.clone();
                    
                    match wh.fetch_claims(&sub, &oids) {
                        Ok(fetch_fut) => {
                            return IdpFuture::Webhook {
                                fetch_fut,
                                state: Box::new(IdpWebhookState {
                                    claims,
                                    endpoint: WebhookEndpoint::Confirm {
                                        sid,
                                        code: user_code,
                                    },
                                    idp: self.clone(),
                                }),
                            };
                        }
                        Err(e) => {
                            let resp = self.handle_auth_confirm(&sid, user_code.as_deref(), claims, Some(Err(e)));
                            return IdpFuture::Ready { response: Some(resp) };
                        }
                    }
                }

                let resp = self.handle_auth_confirm(&sid, user_code.as_deref(), claims, None);
                IdpFuture::Ready { response: Some(resp) }
            }

            // 4. Direct JWT issuance via mTLS (for devices that don't need QR code)
            (Method::POST, "/auth/token") => {
                let claims = match mtls_claims {
                    Some(c) => c,
                    None => return IdpFuture::Ready { response: Some(Self::response_err(StatusCode::UNAUTHORIZED, "mTLS required")) },
                };

                if let Some(wh) = &self.webhook_client {
                    let sub = claims.sub.clone();
                    let oids = claims.oids.clone();
                    
                    match wh.fetch_claims(&sub, &oids) {
                        Ok(fetch_fut) => {
                            return IdpFuture::Webhook {
                                fetch_fut,
                                state: Box::new(IdpWebhookState {
                                    claims,
                                    endpoint: WebhookEndpoint::Token,
                                    idp: self.clone(),
                                }),
                            };
                        }
                        Err(e) => {
                            let resp = self.handle_auth_token(claims, Some(Err(e)));
                            return IdpFuture::Ready { response: Some(resp) };
                        }
                    }
                }

                let resp = self.handle_auth_token(claims, None);
                IdpFuture::Ready { response: Some(resp) }
            }

            // 5. Revoke a JWT session / token (Logout & Revocation)
            (Method::POST, "/auth/revoke") => {
                let token_from_header = req.headers()
                    .get(hyper::header::AUTHORIZATION)
                    .and_then(|v| v.to_str().ok())
                    .and_then(|s| {
                        s.get(..7)
                            .filter(|p| p.eq_ignore_ascii_case("bearer "))
                            .and_then(|_| s.get(7..))
                    })
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty());

                let token_from_cookie = if token_from_header.is_none() {
                    let prefix = format!("{}=", self.params.cookie_name);
                    req.headers()
                        .get_all(hyper::header::COOKIE)
                        .iter()
                        .find_map(|h| {
                            h.to_str().ok().and_then(|s| {
                                s.split(';').find_map(|c| {
                                    let c = c.trim();
                                    c.strip_prefix(&prefix).map(|v| v.to_string())
                                })
                            })
                        })
                } else {
                    None
                };

                let token_opt = token_from_header.or(token_from_cookie);
                let mut revoked_any = false;

                if let Some(token_str) = token_opt {
                    if self.decoding_keys.is_empty() {
                        return IdpFuture::Ready {
                            response: Some(Self::response_err(
                                StatusCode::SERVICE_UNAVAILABLE,
                                "JWT revocation unavailable: no decoding keys configured",
                            )),
                        };
                    }
                    if token_str.is_empty() || token_str.len() > common::MAX_JWT_TOKEN_LEN {
                        return IdpFuture::Ready {
                            response: Some(Self::response_err(
                                StatusCode::UNAUTHORIZED,
                                "Unauthorized: invalid token for revocation",
                            )),
                        };
                    }

                    let mut verified_token = false;
                    for key in self.decoding_keys.iter() {
                        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
                        validation.validate_exp = false;
                        validation.validate_aud = false;
                        if let Ok(data) = jsonwebtoken::decode::<Claims>(&token_str, key, &validation) {
                            verified_token = true;
                            if let Some(jti) = data.claims.jti {
                                let exp = if data.claims.exp > 0 {
                                    data.claims.exp as u64
                                } else {
                                    let now = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs();
                                    now + self.params.token_expiry_seconds
                                };
                                if !crate::middleware::jwt::get_jwt_revocation_store().try_revoke(
                                    &jti,
                                    exp.saturating_add(crate::middleware::jwt::JWT_EXP_LEEWAY_SECS),
                                ) {
                                    error!(
                                        "{}: JwtRevocationStore capacity exhausted during /auth/revoke",
                                        self.server_name
                                    );
                                    return IdpFuture::Ready {
                                        response: Some(Self::response_err(
                                            StatusCode::SERVICE_UNAVAILABLE,
                                            "Service Unavailable: revocation store capacity exceeded",
                                        )),
                                    };
                                }
                                info!("{}: Revoked JWT jti: {}", self.server_name, jti);
                                revoked_any = true;
                            }
                            break;
                        }
                    }

                    if !verified_token {
                        return IdpFuture::Ready {
                            response: Some(Self::response_err(
                                StatusCode::UNAUTHORIZED,
                                "Unauthorized: invalid token for revocation",
                            )),
                        };
                    }
                }

                // Explicit ?jti=... query parameter revocation is restricted to mTLS-authenticated callers
                // to prevent unauthenticated JTI revocation DoS and RevocationStore memory exhaustion.
                if let Some(explicit_jti) = query.split('&').find_map(|kv| {
                    let mut parts = kv.splitn(2, '=');
                    if parts.next()? == "jti" {
                        parts.next().map(|s| s.to_string())
                    } else {
                        None
                    }
                }) {
                    if mtls_claims.is_none() {
                        return IdpFuture::Ready {
                            response: Some(Self::response_err(
                                StatusCode::UNAUTHORIZED,
                                "Unauthorized: mTLS required to revoke explicit JTI",
                            )),
                        };
                    }
                    if !explicit_jti.is_empty() && explicit_jti.len() <= 256 {
                        let now = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_secs();
                        let exp = (now + self.params.token_expiry_seconds)
                            .saturating_add(crate::middleware::jwt::JWT_EXP_LEEWAY_SECS);
                        if !crate::middleware::jwt::get_jwt_revocation_store().try_revoke(&explicit_jti, exp) {
                            error!(
                                "{}: JwtRevocationStore capacity exhausted during explicit /auth/revoke",
                                self.server_name
                            );
                            return IdpFuture::Ready {
                                response: Some(Self::response_err(
                                    StatusCode::SERVICE_UNAVAILABLE,
                                    "Service Unavailable: revocation store capacity exceeded",
                                )),
                            };
                        }
                        info!("{}: Explicitly revoked jti via mTLS: {}", self.server_name, explicit_jti);
                        revoked_any = true;
                    }
                }

                let mut cookie_clear = format!(
                    "{}=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; HttpOnly; Secure; SameSite=Lax",
                    self.params.cookie_name
                );
                if let Some(domain) = &self.params.cookie_domain
                    && !self.params.cookie_name.starts_with("__Host-") {
                        cookie_clear.push_str(&format!("; Domain={}", domain));
                    }

                let body = if revoked_any {
                    r#"{"status":"revoked"}"#
                } else {
                    r#"{"status":"cleared"}"#
                };

                let res = match hyper::header::HeaderValue::from_str(&cookie_clear) {
                    Ok(cookie_hv) => {
                        let mut r = Self::response_with_content_type(
                            StatusCode::OK,
                            "application/json",
                            Bytes::from_static(body.as_bytes()),
                        );
                        r.headers_mut().insert(hyper::header::SET_COOKIE, cookie_hv);
                        r
                    }
                    Err(e) => {
                        error!(
                            "{}: Invalid Set-Cookie clear header during /auth/revoke: {}",
                            self.server_name, e
                        );
                        Self::response_err(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "Cookie Configuration Error",
                        )
                    }
                };

                IdpFuture::Ready { response: Some(res) }
            }

            _ => IdpFuture::Ready { response: Some(Self::response_err(StatusCode::NOT_FOUND, "Not Found")) },
        }
    }
}

/// Extracts the Common Name (CN) from a PEM-encoded X.509 certificate.
///
/// Used as a fallback for the JWT `sub` field when no SAN (Subject Alternative Name) is present.
/// Returns `None` if parsing fails or no CN is found.
fn extract_cn_from_pem(pem_str: &str) -> Option<String> {
    let pem = pem::parse(pem_str).ok()?;
    use x509_parser::prelude::FromDer;
    let (_, cert) = x509_parser::prelude::X509Certificate::from_der(pem.contents()).ok()?;
    cert.subject()
        .iter_common_name()
        .next()
        .and_then(|cn| cn.as_str().ok())
        .map(|s| s.to_string())
}

/// Computes a deterministic `"sha256:<hex>"` subject identifier from the leaf X.509
/// certificate's DER bytes when neither SAN nor CN is present.
///
/// Returns `None` if `pem_str` is not a valid PEM-encoded X.509 certificate.
fn cert_fingerprint_subject(pem_str: &str) -> Option<String> {
    let pem = pem::parse(pem_str).ok()?;
    use x509_parser::prelude::FromDer;
    let _ = x509_parser::prelude::X509Certificate::from_der(pem.contents()).ok()?;
    let sha256 = rustls::crypto::aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256
        .tls13()?
        .common
        .hash_provider;
    let digest = sha256.hash(pem.contents());
    let mut sub = String::with_capacity("sha256:".len() + digest.as_ref().len() * 2);
    sub.push_str("sha256:");
    for byte in digest.as_ref() {
        use std::fmt::Write;
        let _ = write!(&mut sub, "{:02x}", byte);
    }
    Some(sub)
}

/// Rejects browser cross-site / cross-origin requests while permitting native
/// non-browser clients (e.g., mobile apps or `curl`) that omit `Sec-Fetch-Site`
/// and `Origin` headers.
fn verify_same_origin(headers: &hyper::HeaderMap) -> Result<(), &'static str> {
    if let Some(sec_fetch_site) = headers
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
        && !sec_fetch_site.eq_ignore_ascii_case("same-origin")
        && !sec_fetch_site.eq_ignore_ascii_case("none")
    {
        return Err("Cross-site request blocked");
    }

    if let Some(origin) = headers.get(hyper::header::ORIGIN).and_then(|v| v.to_str().ok()) {
        let origin_authority = origin
            .strip_prefix("https://")
            .or_else(|| origin.strip_prefix("http://"))
            .map(|rest| rest.split('/').next().unwrap_or(rest));
        let host = headers.get(hyper::header::HOST).and_then(|v| v.to_str().ok());
        match (origin_authority, host) {
            (Some(orig_host), Some(req_host)) if orig_host.eq_ignore_ascii_case(req_host) => {}
            _ => return Err("Cross-origin request blocked"),
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;

    const TEST_PRIV_KEY: &str = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/IrnOV6maFjmtsjchLt6\n-----END PRIVATE KEY-----\n";
    const TEST_PUB_KEY: &str = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAk2Zye1IFLZDkM9awuejFhYgrETKpGldlqBFSGOEM/os=\n-----END PUBLIC KEY-----\n";

    fn create_test_idp_service() -> IdpService {
        let enc_key = jsonwebtoken::EncodingKey::from_ed_pem(TEST_PRIV_KEY.as_bytes()).unwrap();
        let dec_key = jsonwebtoken::DecodingKey::from_ed_pem(TEST_PUB_KEY.as_bytes()).unwrap();

        let pem = pem::parse(TEST_PUB_KEY).unwrap();
        let der = pem.contents();
        let raw_key = &der[12..44];
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        let x = URL_SAFE_NO_PAD.encode(raw_key);
        let jwks = format!(
            r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","use":"sig","kid":"praeco-key-1","x":"{}"}}]}}"#,
            x
        );

        let params = IdpParams {
            jwt_private_key: "".to_string(),
            jwt_public_key: None,
            token_expiry_seconds: 3600,
            session_ttl_seconds: 120,
            cookie_name: "jwt".to_string(),
            cookie_domain: None,
            redirect_after_login: "/".to_string(),
            allowed_audiences: vec!["praeco-admin".to_string()],
            issuer: "praeco-idp".to_string(),
            claims_webhook_url: None,
            claims_webhook_timeout_ms: 1000,
            on_webhook_failure: crate::configuration::WebhookFailurePolicy::Reject,
            debug_show_session_id: Some(false),
            claims_webhook_client_cert: None,
            claims_webhook_client_key: None,
            claims_webhook_ca_cert: None,
        };

        IdpService {
            params,
            session_store: SessionStore::new(120),
            encoding_key: Arc::new(enc_key),
            decoding_keys: Arc::new(vec![dec_key]),
            server_name: "test-idp",
            jwks_payload: Some(Arc::new(jwks)),
            webhook_client: None,
        }
    }

    #[tokio::test]
    async fn test_idp_jwks_endpoint() {
        let mut idp = create_test_idp_service();
        let body: crate::SrvBody = Full::new(Bytes::new()).map_err(SrvError::from).boxed();
        let req = Request::builder()
            .method(Method::GET)
            .uri("/.well-known/jwks.json")
            .body(body)
            .unwrap();

        let resp = idp.ready().await.unwrap().call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(resp.headers().get("Content-Type").unwrap(), "application/jwk-set+json");

        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body_str = String::from_utf8(body_bytes.to_vec()).unwrap();
        assert!(body_str.contains(r#""kid":"praeco-key-1""#));
        assert!(body_str.contains(r#""crv":"Ed25519""#));
    }

    #[tokio::test]
    async fn test_idp_revoke_via_bearer_token() {
        let mut idp = create_test_idp_service();
        let enc_key = jsonwebtoken::EncodingKey::from_ed_pem(TEST_PRIV_KEY.as_bytes()).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let jti = "revoke-test-jti-123".to_string();

        let claims = Claims {
            sub: "test-user".to_string(),
            iss: "praeco-idp".to_string(),
            aud: Some("praeco-admin".to_string()),
            exp: now as usize + 3600,
            oids: vec!["1".to_string()],
            jti: Some(jti.clone()),
        };
        let token = common::sign_jwt(&claims, &enc_key).unwrap();

        assert!(!crate::middleware::jwt::get_jwt_revocation_store().is_revoked(&jti));

        let body: crate::SrvBody = Full::new(Bytes::new()).map_err(SrvError::from).boxed();
        let req = Request::builder()
            .method(Method::POST)
            .uri("/auth/revoke")
            .header("Authorization", format!("Bearer {}", token))
            .body(body)
            .unwrap();

        let resp = idp.ready().await.unwrap().call(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // Check Set-Cookie clears the cookie
        let set_cookie = resp.headers().get("Set-Cookie").unwrap().to_str().unwrap();
        assert!(set_cookie.contains("jwt=;"));
        assert!(set_cookie.contains("Max-Age=0"));

        // Check JTI is now revoked in store
        assert!(crate::middleware::jwt::get_jwt_revocation_store().is_revoked(&jti));

        // 2. Lowercase "bearer " prefix works and oversized token (> MAX_JWT_TOKEN_LEN) is rejected with 401
        let jti_lower = "revoke-test-jti-lowercase-bearer".to_string();
        let token_lower = common::sign_jwt(
            &Claims {
                jti: Some(jti_lower.clone()),
                ..claims
            },
            &enc_key,
        )
        .unwrap();
        let req_lower = Request::builder()
            .method(Method::POST)
            .uri("/auth/revoke")
            .header("Authorization", format!("bearer {token_lower}"))
            .body(Full::new(Bytes::new()).map_err(SrvError::from).boxed())
            .unwrap();
        let resp_lower = idp.ready().await.unwrap().call(req_lower).await.unwrap();
        assert_eq!(resp_lower.status(), StatusCode::OK);
        assert!(crate::middleware::jwt::get_jwt_revocation_store().is_revoked(&jti_lower));

        let oversized_token = "a".repeat(common::MAX_JWT_TOKEN_LEN + 10);
        let req_oversized = Request::builder()
            .method(Method::POST)
            .uri("/auth/revoke")
            .header("Authorization", format!("Bearer {oversized_token}"))
            .body(Full::new(Bytes::new()).map_err(SrvError::from).boxed())
            .unwrap();
        let resp_oversized = idp.ready().await.unwrap().call(req_oversized).await.unwrap();
        assert_eq!(resp_oversized.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_idp_revoke_via_query_param_requires_mtls() {
        let mut idp = create_test_idp_service();
        let jti = "query-param-jti-456";

        assert!(!crate::middleware::jwt::get_jwt_revocation_store().is_revoked(jti));

        // 1. Unauthenticated caller attempting ?jti= revocation must NOT revoke the JTI
        let body1: crate::SrvBody = Full::new(Bytes::new()).map_err(SrvError::from).boxed();
        let req_unauth = Request::builder()
            .method(Method::POST)
            .uri(format!("/auth/revoke?jti={}", jti))
            .body(body1)
            .unwrap();

        let resp_unauth = idp.ready().await.unwrap().call(req_unauth).await.unwrap();
        assert_eq!(resp_unauth.status(), StatusCode::UNAUTHORIZED);
        assert!(!crate::middleware::jwt::get_jwt_revocation_store().is_revoked(jti));

        // 2. mTLS-authenticated caller with PemCertExtension is allowed to revoke via ?jti=
        let body2: crate::SrvBody = Full::new(Bytes::new()).map_err(SrvError::from).boxed();
        let mut req_mtls = Request::builder()
            .method(Method::POST)
            .uri(format!("/auth/revoke?jti={}", jti))
            .body(body2)
            .unwrap();
        req_mtls
            .extensions_mut()
            .insert(crate::PemCertExtension("dummy-pem".to_string()));
        req_mtls
            .extensions_mut()
            .insert(crate::SanCertExtension("admin-device".to_string()));

        let resp_mtls = idp.ready().await.unwrap().call(req_mtls).await.unwrap();
        assert_eq!(resp_mtls.status(), StatusCode::OK);

        let set_cookie = resp_mtls.headers().get("Set-Cookie").unwrap().to_str().unwrap();
        assert!(set_cookie.contains("jwt=;"));
        assert!(set_cookie.contains("; HttpOnly; Secure; SameSite=Lax"));

        assert!(crate::middleware::jwt::get_jwt_revocation_store().is_revoked(jti));
    }

    #[tokio::test]
    async fn test_idp_revoke_fails_closed_without_keys_or_valid_signature() {
        let mut idp = create_test_idp_service();

        // 1. Valid decoding keys present, but provided token has an invalid/forged signature -> 401
        let forged_token = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhdHRhY2tlciIsImlzcyI6InByYWVjby1pZHAiLCJleHAiOjk5OTk5OTk5OTksIm9pZHMiOltdLCJqdGkiOiJmb3JnZWQtanRpIn0.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let body1: crate::SrvBody = Full::new(Bytes::new()).map_err(SrvError::from).boxed();
        let req_forged = Request::builder()
            .method(Method::POST)
            .uri("/auth/revoke")
            .header(hyper::header::AUTHORIZATION, format!("Bearer {}", forged_token))
            .body(body1)
            .unwrap();
        let resp_forged = idp.ready().await.unwrap().call(req_forged).await.unwrap();
        assert_eq!(resp_forged.status(), StatusCode::UNAUTHORIZED);
        assert!(!crate::middleware::jwt::get_jwt_revocation_store().is_revoked("forged-jti"));

        // 2. Cookie-only forged token must also fail closed -> 401
        let body2: crate::SrvBody = Full::new(Bytes::new()).map_err(SrvError::from).boxed();
        let req_cookie_forged = Request::builder()
            .method(Method::POST)
            .uri("/auth/revoke")
            .header(hyper::header::COOKIE, format!("jwt={}", forged_token))
            .body(body2)
            .unwrap();
        let resp_cookie_forged = idp.ready().await.unwrap().call(req_cookie_forged).await.unwrap();
        assert_eq!(resp_cookie_forged.status(), StatusCode::UNAUTHORIZED);

        // 3. Decoding keys unconfigured while token is present -> 503 Service Unavailable
        idp.decoding_keys = Arc::new(Vec::new());
        let body3: crate::SrvBody = Full::new(Bytes::new()).map_err(SrvError::from).boxed();
        let req_no_keys = Request::builder()
            .method(Method::POST)
            .uri("/auth/revoke")
            .header(hyper::header::AUTHORIZATION, format!("Bearer {}", forged_token))
            .body(body3)
            .unwrap();
        let resp_no_keys = idp.ready().await.unwrap().call(req_no_keys).await.unwrap();
        assert_eq!(resp_no_keys.status(), StatusCode::SERVICE_UNAVAILABLE);

        // 4. Logout without any token still clears cookie cleanly (200 OK + Secure flag)
        let body4: crate::SrvBody = Full::new(Bytes::new()).map_err(SrvError::from).boxed();
        let req_clear = Request::builder()
            .method(Method::POST)
            .uri("/auth/revoke")
            .body(body4)
            .unwrap();
        let resp_clear = idp.ready().await.unwrap().call(req_clear).await.unwrap();
        assert_eq!(resp_clear.status(), StatusCode::OK);
        let clear_cookie = resp_clear
            .headers()
            .get(hyper::header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(clear_cookie.contains("; Secure"));
    }

    #[test]
    fn test_idp_cert_fingerprint_subject_uniqueness() {
        let pki = common::test_pki::TestPki::new();
        let cert_a = std::fs::read_to_string(&pki.nosan_client_pem).unwrap();
        let cert_b = std::fs::read_to_string(&pki.praeco_client_pem).unwrap();

        let sub_a1 = cert_fingerprint_subject(&cert_a).expect("valid cert A fingerprint");
        let sub_a2 = cert_fingerprint_subject(&cert_a).expect("deterministic cert A fingerprint");
        let sub_b = cert_fingerprint_subject(&cert_b).expect("valid cert B fingerprint");

        assert_eq!(sub_a1, sub_a2);
        assert_ne!(sub_a1, sub_b);
        assert!(sub_a1.starts_with("sha256:"));
        assert_eq!(sub_a1.len(), "sha256:".len() + 64);
        assert_eq!(cert_fingerprint_subject("dummy-pem"), None);
    }

    #[tokio::test]
    async fn test_idp_confirm_blocks_cross_site_csrf_and_session_info_requires_auth() {
        let mut idp = create_test_idp_service();

        // 1. Start a login session
        let body_login: crate::SrvBody = Full::new(Bytes::new()).map_err(SrvError::from).boxed();
        let req_login = Request::builder()
            .method(Method::POST)
            .uri("/auth/login")
            .body(body_login)
            .unwrap();
        let resp_login = idp.ready().await.unwrap().call(req_login).await.unwrap();
        assert_eq!(resp_login.status(), StatusCode::OK);
        let login_bytes = resp_login.into_body().collect().await.unwrap().to_bytes();
        let login_json: serde_json::Value = serde_json::from_slice(&login_bytes).unwrap();
        let session = login_json["session"].as_str().unwrap().to_string();
        let poll_secret = login_json["poll_secret"].as_str().unwrap().to_string();
        let user_code = login_json["user_code"].as_str().unwrap().to_string();

        // 2. Unauthenticated /auth/session_info without mTLS or poll_secret -> 401
        let body_info1: crate::SrvBody = Full::new(Bytes::new()).map_err(SrvError::from).boxed();
        let req_info_unauth = Request::builder()
            .method(Method::GET)
            .uri(format!("/auth/session_info?session={session}"))
            .body(body_info1)
            .unwrap();
        let resp_info_unauth = idp.ready().await.unwrap().call(req_info_unauth).await.unwrap();
        assert_eq!(resp_info_unauth.status(), StatusCode::UNAUTHORIZED);

        // 3. /auth/session_info with matching poll_secret -> 200
        let body_info2: crate::SrvBody = Full::new(Bytes::new()).map_err(SrvError::from).boxed();
        let req_info_secret = Request::builder()
            .method(Method::GET)
            .uri(format!("/auth/session_info?session={session}&poll_secret={poll_secret}"))
            .body(body_info2)
            .unwrap();
        let resp_info_secret = idp.ready().await.unwrap().call(req_info_secret).await.unwrap();
        assert_eq!(resp_info_secret.status(), StatusCode::OK);

        // 4. /auth/session_info with mTLS cert -> 200
        let body_info3: crate::SrvBody = Full::new(Bytes::new()).map_err(SrvError::from).boxed();
        let mut req_info_mtls = Request::builder()
            .method(Method::GET)
            .uri(format!("/auth/session_info?session={session}"))
            .body(body_info3)
            .unwrap();
        req_info_mtls
            .extensions_mut()
            .insert(crate::PemCertExtension("dummy-pem".to_string()));
        let resp_info_mtls = idp.ready().await.unwrap().call(req_info_mtls).await.unwrap();
        assert_eq!(resp_info_mtls.status(), StatusCode::OK);

        // 5. POST /auth/confirm with Sec-Fetch-Site: cross-site -> 403 Forbidden
        let body_csrf1: crate::SrvBody = Full::new(Bytes::new()).map_err(SrvError::from).boxed();
        let mut req_confirm_csrf = Request::builder()
            .method(Method::POST)
            .uri(format!("/auth/confirm?session={session}&code={user_code}"))
            .header("sec-fetch-site", "cross-site")
            .body(body_csrf1)
            .unwrap();
        req_confirm_csrf
            .extensions_mut()
            .insert(crate::PemCertExtension("dummy-pem".to_string()));
        let resp_confirm_csrf = idp.ready().await.unwrap().call(req_confirm_csrf).await.unwrap();
        assert_eq!(resp_confirm_csrf.status(), StatusCode::FORBIDDEN);

        // 6. POST /auth/confirm with mismatched Origin vs Host -> 403 Forbidden
        let body_csrf2: crate::SrvBody = Full::new(Bytes::new()).map_err(SrvError::from).boxed();
        let mut req_confirm_origin = Request::builder()
            .method(Method::POST)
            .uri(format!("/auth/confirm?session={session}&code={user_code}"))
            .header(hyper::header::HOST, "idp.example.test")
            .header(hyper::header::ORIGIN, "https://evil.example.net")
            .body(body_csrf2)
            .unwrap();
        req_confirm_origin
            .extensions_mut()
            .insert(crate::PemCertExtension("dummy-pem".to_string()));
        let resp_confirm_origin = idp.ready().await.unwrap().call(req_confirm_origin).await.unwrap();
        assert_eq!(resp_confirm_origin.status(), StatusCode::FORBIDDEN);

        // 7. Native/same-origin POST /auth/confirm with mTLS + valid user_code -> 200 OK
        let body_ok: crate::SrvBody = Full::new(Bytes::new()).map_err(SrvError::from).boxed();
        let mut req_confirm_ok = Request::builder()
            .method(Method::POST)
            .uri(format!("/auth/confirm?session={session}&code={user_code}"))
            .body(body_ok)
            .unwrap();
        req_confirm_ok
            .extensions_mut()
            .insert(crate::PemCertExtension("dummy-pem".to_string()));
        let resp_confirm_ok = idp.ready().await.unwrap().call(req_confirm_ok).await.unwrap();
        assert_eq!(resp_confirm_ok.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_idp_status_escapes_redirect_json_and_validates_params() {
        let mut idp = create_test_idp_service();
        idp.params.redirect_after_login = r#"/admin?q="quoted"&ok=1"#.to_string();

        let claims = Claims {
            sub: "alice".to_string(),
            iss: "praeco-idp".to_string(),
            aud: Some("praeco-admin".to_string()),
            exp: 0,
            oids: vec!["1".to_string()],
            jti: None,
        };
        let resp = idp.generate_jwt_cookie_response(claims).unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body_bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let parsed: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(parsed["status"], "confirmed");
        assert_eq!(parsed["redirect"], r#"/admin?q="quoted"&ok=1"#);

        // IdpService::new rejects malformed cookie/redirect settings at startup
        let pki = common::test_pki::TestPki::new();
        let dir = std::env::temp_dir().join(format!("praeco_idp_s07_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let key_path = dir.join("idp_priv.pem");
        std::fs::write(&key_path, TEST_PRIV_KEY).unwrap();
        let mut bad_params = idp.params.clone();
        bad_params.jwt_private_key = key_path.display().to_string();
        bad_params.cookie_name = "bad;cookie".to_string();
        let res = IdpService::new(bad_params, "test-idp");
        let _ = std::fs::remove_dir_all(&dir);
        let _ = pki;
        assert!(res.is_err());
    }

    #[tokio::test]
    async fn test_idp_http_login_confirm_status_cookie_and_auth_token_flow() {
        // 1. Confirm __Host- cookie omits Domain while delivering safe serialized redirect JSON
        let mut idp_host = create_test_idp_service();
        idp_host.params.cookie_name = "__Host-jwt".to_string();
        idp_host.params.cookie_domain = Some("ignored.example.test".to_string());
        idp_host.params.redirect_after_login = "/admin?tab=\"users\"".to_string();

        let req_login = Request::builder()
            .method(Method::POST)
            .uri("/auth/login")
            .body(Full::new(Bytes::new()).map_err(SrvError::from).boxed())
            .unwrap();
        let resp_login = idp_host.ready().await.unwrap().call(req_login).await.unwrap();
        assert_eq!(resp_login.status(), StatusCode::OK);
        let login_json: serde_json::Value = serde_json::from_slice(
            &resp_login.into_body().collect().await.unwrap().to_bytes(),
        )
        .unwrap();
        let sid = login_json["session"].as_str().unwrap().to_string();
        let poll_secret = login_json["poll_secret"].as_str().unwrap().to_string();
        let user_code = login_json["user_code"].as_str().unwrap().to_string();

        let mut req_confirm = Request::builder()
            .method(Method::POST)
            .uri(format!("/auth/confirm?session={sid}&code={user_code}"))
            .body(Full::new(Bytes::new()).map_err(SrvError::from).boxed())
            .unwrap();
        req_confirm
            .extensions_mut()
            .insert(crate::PemCertExtension("dummy-pem".to_string()));
        req_confirm
            .extensions_mut()
            .insert(crate::SanCertExtension("alice@example.test".to_string()));
        let resp_confirm = idp_host.ready().await.unwrap().call(req_confirm).await.unwrap();
        assert_eq!(resp_confirm.status(), StatusCode::OK);

        let req_status = Request::builder()
            .method(Method::GET)
            .uri(format!("/auth/status?session={sid}&poll_secret={poll_secret}"))
            .body(Full::new(Bytes::new()).map_err(SrvError::from).boxed())
            .unwrap();
        let resp_status = idp_host.ready().await.unwrap().call(req_status).await.unwrap();
        assert_eq!(resp_status.status(), StatusCode::OK);
        let set_cookie = resp_status
            .headers()
            .get(hyper::header::SET_COOKIE)
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert!(set_cookie.starts_with("__Host-jwt="));
        assert!(set_cookie.contains("; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=3600"));
        assert!(!set_cookie.contains("Domain="));

        let status_json: serde_json::Value = serde_json::from_slice(
            &resp_status.into_body().collect().await.unwrap().to_bytes(),
        )
        .unwrap();
        assert_eq!(status_json["status"], "confirmed");
        assert_eq!(status_json["redirect"], "/admin?tab=\"users\"");

        // 2. Non-__Host- cookie includes validated Domain and POST /auth/token issues verifiable JWT JSON
        let mut idp_domain = create_test_idp_service();
        idp_domain.params.cookie_name = "admin-jwt".to_string();
        idp_domain.params.cookie_domain = Some("idp.example.test".to_string());

        let mut req_token = Request::builder()
            .method(Method::POST)
            .uri("/auth/token")
            .body(Full::new(Bytes::new()).map_err(SrvError::from).boxed())
            .unwrap();
        req_token
            .extensions_mut()
            .insert(crate::PemCertExtension("dummy-pem".to_string()));
        req_token
            .extensions_mut()
            .insert(crate::SanCertExtension("svc@example.test".to_string()));
        let resp_token = idp_domain.ready().await.unwrap().call(req_token).await.unwrap();
        assert_eq!(resp_token.status(), StatusCode::OK);
        let token_json: serde_json::Value = serde_json::from_slice(
            &resp_token.into_body().collect().await.unwrap().to_bytes(),
        )
        .unwrap();
        let token_str = token_json["token"].as_str().unwrap();
        let claims = common::verify_jwt(
            token_str,
            &idp_domain.decoding_keys,
            "praeco-idp",
            "praeco-admin",
        )
        .expect("token from POST /auth/token must pass verify_jwt");
        assert_eq!(claims.sub, "svc@example.test");
    }
}
