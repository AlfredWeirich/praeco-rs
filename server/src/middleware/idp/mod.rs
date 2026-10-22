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
        let session_store = SessionStore::new(params.session_ttl_seconds);
        
        let webhook_client = WebhookClient::new(&params).context("Failed to init webhook client")?;

        let encoding_key = common::load_encoding_key(&params.jwt_private_key)?;

        let decoding_keys = if let Some(pub_key_path) = &params.jwt_public_key {
            match common::load_decoding_keys(&[pub_key_path.clone()]) {
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
                            let jwks = format!(
                                r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","use":"sig","kid":"praeco-key-1","x":"{}"}}]}}"#,
                                x
                            );
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

    fn response_ok(body: impl Into<String>) -> Response<ServiceRespBody> {
        let body_bytes = Bytes::from(body.into());
        Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(Full::new(body_bytes).map_err(SrvError::from).boxed())
            .unwrap()
    }

    fn response_err(status: StatusCode, msg: &str) -> Response<ServiceRespBody> {
        Response::builder()
            .status(status)
            .header(hyper::header::CONTENT_TYPE, "text/plain")
            .body(Full::new(Bytes::from(msg.to_string())).map_err(SrvError::from).boxed())
            .unwrap()
    }

    fn generate_jwt_cookie_response(
        &self,
        mut claims: Claims,
    ) -> Result<Response<ServiceRespBody>, anyhow::Error> {
        // Update exp and ensure jti is assigned
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
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

        let body = format!(r#"{{"status":"confirmed","redirect":"{}"}}"#, self.params.redirect_after_login);
        
        let resp = Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::SET_COOKIE, cookie_val)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(body)).map_err(SrvError::from).boxed())
            .unwrap();
            
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
                    if self.params.on_webhook_failure != "fallback_to_cert" {
                        return Self::response_err(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "Claims resolution failed",
                        );
                    }
                    // "fallback_to_cert" -> keep original OIDs
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
                    if self.params.on_webhook_failure != "fallback_to_cert" {
                        return Self::response_err(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "Claims resolution failed"
                        );
                    }
                    // "fallback_to_cert" -> keep original OIDs
                }
            }
        }

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        claims.exp = now as usize + self.params.token_expiry_seconds as usize;
        if claims.jti.is_none() {
            claims.jti = Some(uuid::Uuid::new_v4().to_string());
        }

        match sign_jwt(&claims, &self.encoding_key) {
            Ok(token) => {
                let body = format!(r#"{{"token":"{}"}}"#, token);
                Self::response_ok(body)
            }
            Err(e) => {
                error!("{}: JWT Generation failed: {}", self.server_name, e);
                Self::response_err(StatusCode::INTERNAL_SERVER_ERROR, "JWT Error")
            }
        }
    }
}

#[pin_project(project = IdpFutureProj)]
pub enum IdpFuture {
    Ready {
        response: Option<Response<ServiceRespBody>>,
    },
    Webhook {
        #[pin]
        fetch_fut: webhook::WebhookFetchFuture,
        claims: Claims,
        sid: Option<String>,
        code: Option<String>,
        idp: IdpService,
        is_token_endpoint: bool,
    },
}

impl Future for IdpFuture {
    type Output = Result<Response<ServiceRespBody>, SrvError>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        match this {
            IdpFutureProj::Ready { response } => {
                Poll::Ready(Ok(response.take().unwrap()))
            }
            IdpFutureProj::Webhook { fetch_fut, claims, sid, code, idp, is_token_endpoint } => {
                let dynamic_oids_res = std::task::ready!(fetch_fut.poll(cx));
                
                let claims_owned = claims.clone();
                let resp = if *is_token_endpoint {
                    idp.handle_auth_token(claims_owned, Some(dynamic_oids_res))
                } else {
                    let sid_str = sid.as_ref().unwrap();
                    idp.handle_auth_confirm(sid_str, code.as_deref(), claims_owned, Some(dynamic_oids_res))
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
                let body_bytes = Bytes::from(jwks.as_str().to_string());
                let resp = Response::builder()
                    .status(StatusCode::OK)
                    .header(hyper::header::CONTENT_TYPE, "application/jwk-set+json")
                    .body(Full::new(body_bytes).map_err(SrvError::from).boxed())
                    .unwrap();
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
                extract_cn_from_pem(&pem_ext.0).unwrap_or_else(|| "device".to_string())
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
                let res = Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "text/html; charset=utf-8")
                    .header("Cache-Control", "no-store, no-cache, must-revalidate")
                    .body(Full::new(Bytes::from(html)).map_err(SrvError::from).boxed())
                    .unwrap();
                IdpFuture::Ready { response: Some(res) }
            }

            // 1. Start a new DeviceAuth login session (Frontend calls this)
            (Method::POST, "/auth/login") => {
                if let Some(ref a) = requested_aud {
                    if !self.params.allowed_audiences.is_empty() && !self.params.allowed_audiences.contains(a) {
                        return IdpFuture::Ready {
                            response: Some(Self::response_err(
                                StatusCode::BAD_REQUEST,
                                "Requested audience is not in allowed_audiences",
                            )),
                        };
                    }
                }
                let target_aud = requested_aud.or_else(|| self.params.allowed_audiences.first().cloned());

                match self.session_store.create_session(client_ip, target_aud) {
                    Ok(info) => {
                        debug!("{}: Created login session {}", self.server_name, info.session_id);
                        let body = format!(
                            r#"{{"session":"{}","poll_secret":"{}","user_code":"{}"}}"#,
                            info.session_id, info.poll_secret, info.user_code
                        );
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
                        info!("{}: Session {} confirmed, issuing JWT.", self.server_name, sid);
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

            // 2b. View session user_code on device (for Quishing verification by Swift URLSession before mTLS confirm)
            (Method::GET, "/auth/session_info") => {
                let sid = match session_id {
                    Some(sid) => sid,
                    None => return IdpFuture::Ready {
                        response: Some(Self::response_err(StatusCode::BAD_REQUEST, "Missing session parameter")),
                    },
                };
                let resp = match self.session_store.get_session_user_code(&sid) {
                    Some(code) => {
                        let body = format!(r#"{{"user_code":"{}"}}"#, code);
                        Self::response_ok(body)
                    }
                    None => Self::response_err(StatusCode::NOT_FOUND, "Session not found or expired"),
                };
                IdpFuture::Ready { response: Some(resp) }
            }

            // 3. Confirm a session (Device with mTLS calls this)
            (Method::POST, "/auth/confirm") => {
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
                                claims,
                                sid: Some(sid),
                                code: user_code,
                                idp: self.clone(),
                                is_token_endpoint: false,
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
                                claims,
                                sid: None,
                                code: None,
                                idp: self.clone(),
                                is_token_endpoint: true,
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
                    .and_then(|s| s.strip_prefix("Bearer "))
                    .map(|s| s.trim().to_string());

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
                    for key in self.decoding_keys.iter() {
                        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::EdDSA);
                        validation.validate_exp = false;
                        validation.validate_aud = false;
                        if let Ok(data) = jsonwebtoken::decode::<Claims>(&token_str, key, &validation) {
                            if let Some(jti) = data.claims.jti {
                                let exp = if data.claims.exp > 0 { data.claims.exp as u64 } else {
                                    let now = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap()
                                        .as_secs();
                                    now + self.params.token_expiry_seconds
                                };
                                crate::middleware::jwt::get_jwt_revocation_store().revoke(&jti, exp);
                                info!("{}: Revoked JWT jti: {}", self.server_name, jti);
                                revoked_any = true;
                                break;
                            }
                        }
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
                        let exp = now + self.params.token_expiry_seconds;
                        crate::middleware::jwt::get_jwt_revocation_store().revoke(&explicit_jti, exp);
                        info!("{}: Explicitly revoked jti via mTLS: {}", self.server_name, explicit_jti);
                        revoked_any = true;
                    }
                }

                let mut cookie_clear = format!(
                    "{}=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Max-Age=0; HttpOnly; SameSite=Lax",
                    self.params.cookie_name
                );
                if let Some(domain) = &self.params.cookie_domain {
                    if !self.params.cookie_name.starts_with("__Host-") {
                        cookie_clear.push_str(&format!("; Domain={}", domain));
                    }
                }

                let body = if revoked_any {
                    r#"{"status":"revoked"}"#
                } else {
                    r#"{"status":"cleared"}"#
                };

                let res = Response::builder()
                    .status(StatusCode::OK)
                    .header(hyper::header::SET_COOKIE, cookie_clear)
                    .header(hyper::header::CONTENT_TYPE, "application/json")
                    .body(Full::new(Bytes::from(body)).map_err(SrvError::from).boxed())
                    .unwrap();

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
            on_webhook_failure: "reject".to_string(),
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

        assert!(crate::middleware::jwt::get_jwt_revocation_store().is_revoked(jti));
    }
}
