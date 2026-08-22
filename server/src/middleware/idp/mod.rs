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
use jsonwebtoken::EncodingKey;
use tower::Service;
use tracing::{debug, error, info};
use anyhow::Context as _;

use crate::{configuration::IdpParams, SrvError, ServiceRespBody};

mod session;
use session::{SessionStore, SessionStatus};

pub mod webhook;
use webhook::WebhookClient;

/// The Identity Provider service.
#[derive(Clone)]
pub struct IdpService {
    params: IdpParams,
    session_store: SessionStore,
    encoding_key: Arc<EncodingKey>,
    server_name: &'static str,
    jwks_payload: Option<Arc<String>>,
    webhook_client: Option<WebhookClient>,
}

impl IdpService {
    /// Creates a new IdpService.
    pub fn new(params: IdpParams, server_name: &'static str) -> Result<Self, anyhow::Error> {
        let session_store = SessionStore::new(params.session_ttl_seconds);
        
        let webhook_client = WebhookClient::new(&params).context("Failed to init webhook client")?;

        let encoding_key = common::load_encoding_key(&params.jwt_private_key);

        let mut jwks_payload = None;
        if let Some(pub_key_path) = &params.jwt_public_key {
            match std::fs::read_to_string(pub_key_path) {
                Ok(pem_str) => {
                    if let Ok(pem) = pem::parse(&pem_str) {
                        let der = pem.contents();
                        // For Ed25519 SubjectPublicKeyInfo, it's 44 bytes and the last 32 bytes are the raw key.
                        if der.len() >= 32 {
                            let raw_key = &der[der.len() - 32..];
                            use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
                            let x = URL_SAFE_NO_PAD.encode(raw_key);
                            let jwks = format!(
                                r#"{{"keys":[{{"kty":"OKP","crv":"Ed25519","use":"sig","kid":"praeco-key-1","x":"{}"}}]}}"#,
                                x
                            );
                            jwks_payload = Some(Arc::new(jwks));
                        } else {
                            tracing::warn!("{}: Invalid public key length in {}", server_name, pub_key_path);
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
        // Update exp
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        claims.exp = now as usize + self.params.token_expiry_seconds as usize;

        let token = sign_jwt(&claims, &self.encoding_key)?;

        let mut cookie_val = format!(
            "{}={}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={}",
            self.params.cookie_name, token, self.params.token_expiry_seconds
        );
        if let Some(domain) = &self.params.cookie_domain {
            cookie_val.push_str(&format!("; Domain={}", domain));
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
}

impl Service<Request<crate::SrvBody>> for IdpService {
    type Response = Response<ServiceRespBody>;
    type Error = SrvError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

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
                return Box::pin(async move { Ok(resp) });
            } else {
                return Box::pin(async move { Ok(Self::response_err(StatusCode::NOT_FOUND, "JWKS not configured")) });
            }
        }

        // Extract query parameters manually
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

        let requested_aud = query.split('&')
            .find_map(|kv| {
                let mut parts = kv.splitn(2, '=');
                if parts.next()? == "aud" {
                    parts.next().map(|s| s.to_string())
                } else {
                    None
                }
            });

        let aud = requested_aud.filter(|a| self.params.allowed_audiences.contains(a))
            .or_else(|| self.params.allowed_audiences.first().cloned());

        // Determine if the request has a valid mTLS certificate.
        // ConnectionHandler always injects PemCertExtension on successful mTLS.
        // OidCertExtension carries the raw OID suffixes for JWT embedding.
        // SanCertExtension is only present if the cert has a SAN.
        let mtls_claims = if req.extensions().get::<crate::PemCertExtension>().is_some() {
            // 1. Subject: prefer SAN, then extract CN from PEM, then fallback "device"
            let sub = if let Some(san) = req.extensions().get::<crate::SanCertExtension>() {
                san.0.clone()
            } else if let Some(pem_ext) = req.extensions().get::<crate::PemCertExtension>() {
                // Parse the PEM to extract the Common Name (CN) from the Subject
                extract_cn_from_pem(&pem_ext.0).unwrap_or_else(|| "device".to_string())
            } else {
                "device".to_string()
            };

            // 2. OIDs: use the raw OID suffixes, NOT the mapped UserRole names
            let oids = req.extensions().get::<crate::OidCertExtension>()
                .map(|ext| ext.0.clone())
                .unwrap_or_default();

            Some(Claims {
                sub,
                iss: self.params.issuer.clone(),
                aud,
                exp: 0, // Will be set before signing
                oids,
                jti: None,
            })
        } else {
            None
        };

        let this = self.clone();

        Box::pin(async move {
            match (method, path.as_str()) {
                // 0. Serve the generic HTML login page (Frontend UI)
                (Method::GET, "/auth/login_page") => {
                    let mut html = include_str!("idp_login.html").to_string();
                    let debug_flag = if this.params.debug_show_session_id.unwrap_or(false) { "true" } else { "false" };
                    html = html.replace("{{DEBUG_SESSION_FLAG}}", debug_flag);
                    
                    let res = Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "text/html")
                        .header("Cache-Control", "no-store, no-cache, must-revalidate")
                        .body(Full::new(Bytes::from(html)).map_err(SrvError::from).boxed())
                        .unwrap();
                    Ok(res)
                }

                // 1. Start a new DeviceAuth login session (Frontend calls this)
                (Method::POST, "/auth/login") => {
                    let sid = this.session_store.create_session();
                    debug!("{}: Created login session {}", this.server_name, sid);
                    let body = format!(r#"{{"session":"{sid}"}}"#);
                    Ok(Self::response_ok(body))
                }

                // 2. Poll the status of a login session (Frontend calls this)
                (Method::GET, "/auth/status") => {
                    let sid = match session_id {
                        Some(sid) => sid,
                        None => return Ok(Self::response_err(StatusCode::BAD_REQUEST, "Missing session parameter")),
                    };

                    match this.session_store.get_and_consume(&sid) {
                        Some(SessionStatus::Pending) => {
                            Ok(Self::response_ok(r#"{"status":"pending"}"#))
                        }
                        Some(SessionStatus::Confirmed(claims)) => {
                            info!("{}: Session {} confirmed, issuing JWT.", this.server_name, sid);
                            match this.generate_jwt_cookie_response(claims) {
                                Ok(resp) => Ok(resp),
                                Err(e) => {
                                    error!("{}: JWT Generation failed: {}", this.server_name, e);
                                    Ok(Self::response_err(StatusCode::INTERNAL_SERVER_ERROR, "JWT Error"))
                                }
                            }
                        }
                        None => {
                            Ok(Self::response_err(StatusCode::NOT_FOUND, "Session not found or expired"))
                        }
                    }
                }

                // 3. Confirm a session (Device with mTLS calls this)
                (Method::POST, "/auth/confirm") => {
                    let sid = match session_id {
                        Some(sid) => sid,
                        None => return Ok(Self::response_err(StatusCode::BAD_REQUEST, "Missing session parameter")),
                    };

                    let mut claims = match mtls_claims {
                        Some(c) => c,
                        None => return Ok(Self::response_err(StatusCode::UNAUTHORIZED, "mTLS required to confirm session")),
                    };

                    // Webhook: dynamic role resolution
                    if let Some(wh) = &this.webhook_client {
                        match wh.fetch_claims(&claims.sub, &claims.oids).await {
                            Ok(dynamic_oids) => {
                                info!("{}: Webhook returned OIDs: {:?}", this.server_name, dynamic_oids);
                                claims.oids = dynamic_oids;
                            }
                            Err(e) => {
                                error!("{}: Claims webhook failed: {}", this.server_name, e);
                                if this.params.on_webhook_failure == "reject" {
                                    return Ok(Self::response_err(
                                        StatusCode::SERVICE_UNAVAILABLE,
                                        "Claims resolution failed"
                                    ));
                                }
                                // "fallback_to_cert" -> keep original OIDs
                            }
                        }
                    }

                    if this.session_store.confirm_session(&sid, claims) {
                        Ok(Self::response_ok(r#"{"status":"confirmed"}"#))
                    } else {
                        Ok(Self::response_err(StatusCode::NOT_FOUND, "Session not found or expired"))
                    }
                }

                // 4. Direct JWT issuance via mTLS (for devices that don't need QR code)
                (Method::POST, "/auth/token") => {
                    let mut claims = match mtls_claims {
                        Some(c) => c,
                        None => return Ok(Self::response_err(StatusCode::UNAUTHORIZED, "mTLS required")),
                    };

                    // Webhook: dynamic role resolution
                    if let Some(wh) = &this.webhook_client {
                        match wh.fetch_claims(&claims.sub, &claims.oids).await {
                            Ok(dynamic_oids) => {
                                info!("{}: Webhook returned OIDs: {:?}", this.server_name, dynamic_oids);
                                claims.oids = dynamic_oids;
                            }
                            Err(e) => {
                                error!("{}: Claims webhook failed: {}", this.server_name, e);
                                if this.params.on_webhook_failure == "reject" {
                                    return Ok(Self::response_err(
                                        StatusCode::SERVICE_UNAVAILABLE,
                                        "Claims resolution failed"
                                    ));
                                }
                                // "fallback_to_cert" -> keep original OIDs
                            }
                        }
                    }

                    // Here we could just return the JWT in JSON or set a cookie.
                    // For now, let's return it as JSON so API clients can use it in headers.
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    claims.exp = now as usize + this.params.token_expiry_seconds as usize;

                    match sign_jwt(&claims, &this.encoding_key) {
                        Ok(token) => {
                            let body = format!(r#"{{"token":"{}"}}"#, token);
                            Ok(Self::response_ok(body))
                        }
                        Err(e) => {
                            error!("{}: JWT Generation failed: {}", this.server_name, e);
                            Ok(Self::response_err(StatusCode::INTERNAL_SERVER_ERROR, "JWT Error"))
                        }
                    }
                }

                _ => Ok(Self::response_err(StatusCode::NOT_FOUND, "Not Found")),
            }
        })
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
