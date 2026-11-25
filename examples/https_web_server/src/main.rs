//! # Embedded HTTPS (HTTP/1.1 + HTTP/2 + HTTP/3 QUIC) Web Server Example
//!
//! Demonstrates how an external Rust binary can embed `praeco-rs` with
//! `default-features = false, features = ["web"]` and **without any `Config.toml`**:
//!
//! - Reusable routing, typed extractors (`Query`, `Path`, `Json`, `TraceId`),
//!   and automatic `Inspection` WAF allowlist generation come from `praeco_rs::web`.
//! - App-specific server defaults and graceful shutdown live in [`bootstrap`].
//! - Endpoint handlers and DTOs live in [`endpoints`].
//! - This file only wires routes together and starts the server.

mod bootstrap;
mod endpoints;

use praeco_rs::web::WebRouter;

/// Builds the endpoint router (single source of truth for WAF and RBAC rules).
fn build_app_router() -> anyhow::Result<WebRouter> {
    Ok(WebRouter::new()
        .get_with_roles("/", &["*"], endpoints::index)?
        .get_with_roles("/healthz", &["*"], endpoints::healthz)?
        .get_with_roles("/whoami", &["*"], endpoints::whoami)?
        .get_with_roles("/admin/stats", &["Admin"], endpoints::admin_stats)?
        .get_with_waf_and_roles(
            "/users/{id}",
            "/users/*",
            "^/users/[A-Za-z0-9_-]+$",
            &["*"],
            endpoints::get_user,
        )?
        .get_with_waf_and_roles(
            "/greet",
            "/greet",
            r"^/greet\?(?:user_name=[A-Za-z0-9_-]+(?:&age=[0-9]{1,3})?|age=[0-9]{1,3}&user_name=[A-Za-z0-9_-]+)$",
            &["*"],
            endpoints::greet,
        )?
        .post_with_roles("/api/echo", &["*"], endpoints::echo_json)?)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    bootstrap::run_https_server(build_app_router()?).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use common::test_pki::TestPki;
    use http_body_util::{BodyExt, Empty, Full};
    use hyper::{Method, Request, StatusCode};
    use praeco_rs::{SrvBody, SrvError, build_rustls_config, build_service_stack_with_base};
    use std::net::SocketAddr;
    use tower::ServiceExt;

    fn make_req(method: Method, uri: &str, body: Option<&'static [u8]>) -> Request<SrvBody> {
        let srv_body = match body {
            Some(bytes) => Full::new(Bytes::from_static(bytes))
                .map_err(SrvError::from)
                .boxed(),
            None => Empty::<Bytes>::new().map_err(SrvError::from).boxed(),
        };
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .body(srv_body)
            .expect("valid test request");
        let peer: SocketAddr = "127.0.0.1:50000".parse().expect("valid SocketAddr");
        req.extensions_mut().insert(peer);
        req
    }

    #[tokio::test]
    async fn test_hardened_https_stack_and_endpoints() -> anyhow::Result<()> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let pki = TestPki::new();
        let router = build_app_router()?;
        let cfg = bootstrap::build_server_config_with_options(
            8443,
            router.allowed_pathes(),
            router.rbac_rules(),
            TestPki::s(&pki.praeco_public_pem).to_owned(),
            TestPki::s(&pki.praeco_public_key).to_owned(),
            Some(TestPki::s(&pki.relay_ca_pem).to_owned()),
            None,
        )?;

        // Verify TLS/QUIC rustls ServerConfig builds cleanly from the ephemeral TestPki certs.
        let _tls = build_rustls_config(&cfg)?;

        let stack = build_service_stack_with_base(&cfg, router.into_service())?;

        // 1. GET / -> 200 OK + Alt-Svc + SecurityHeaders + TraceId in handler
        let res = stack.clone().oneshot(make_req(Method::GET, "/", None)).await?;
        assert_eq!(res.status(), StatusCode::OK);
        assert!(res.headers().contains_key("alt-svc"));
        assert!(res.headers().contains_key("strict-transport-security"));
        let root_body = res.collect().await?.to_bytes();
        let root_text = std::str::from_utf8(&root_body)?;
        assert!(root_text.contains("x-trace-id=00-"));

        // 2. GET /users/42 -> 200 OK + Path<String> + TraceId
        let res = stack
            .clone()
            .oneshot(make_req(Method::GET, "/users/42", None))
            .await?;
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.collect().await?.to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(json["id"], "42");
        assert!(
            json["trace_id"]
                .as_str()
                .is_some_and(|s| s.starts_with("00-"))
        );

        // 3. GET /greet?user_name=alice -> 200 OK (optional `age` omitted)
        let res = stack
            .clone()
            .oneshot(make_req(Method::GET, "/greet?user_name=alice", None))
            .await?;
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.collect().await?.to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(json["user_name"], "alice");
        assert!(json.get("age").is_none());
        assert_eq!(json["greeting"], "Hallo alice!");

        // 3b. GET /greet?user_name=alice&age=17 -> 200 OK (typed u8 deserialization)
        let res = stack
            .clone()
            .oneshot(make_req(Method::GET, "/greet?user_name=alice&age=17", None))
            .await?;
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.collect().await?.to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(json["user_name"], "alice");
        assert_eq!(json["age"], 17);
        assert_eq!(json["greeting"], "Hallo alice (17 Jahre)!");

        // 3c. GET /greet?age=17&user_name=alice -> 200 OK (parameter order independent)
        let res = stack
            .clone()
            .oneshot(make_req(Method::GET, "/greet?age=17&user_name=alice", None))
            .await?;
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.collect().await?.to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(json["user_name"], "alice");
        assert_eq!(json["age"], 17);

        // 3d. GET /greet?user_name=alice&age=999 -> 400 Bad Request (u8 overflow)
        let res = stack
            .clone()
            .oneshot(make_req(Method::GET, "/greet?user_name=alice&age=999", None))
            .await?;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // 4. GET /greet (missing query param) -> 403 Forbidden from Inspection WAF layer
        let res = stack
            .clone()
            .oneshot(make_req(Method::GET, "/greet", None))
            .await?;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        // 5. POST /api/echo -> 200 OK + Json<Value> extractor
        let res = stack
            .clone()
            .oneshot(make_req(Method::POST, "/api/echo", Some(br#"{"ok":true}"#)))
            .await?;
        assert_eq!(res.status(), StatusCode::OK);
        let body = res.collect().await?.to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(json["body"]["ok"], true);

        // 6. GET /admin -> 403 Forbidden from Inspection WAF layer
        let res = stack
            .clone()
            .oneshot(make_req(Method::GET, "/admin", None))
            .await?;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        // 7. Router 400 Bad Request when Query<GreetQuery> is missing (direct on WebRouter)
        let raw_router = build_app_router()?.into_service();
        let res = raw_router
            .clone()
            .oneshot(make_req(Method::GET, "/greet", None))
            .await?;
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);

        // 8. Router 405 Method Not Allowed (direct on WebRouter)
        let res = raw_router
            .oneshot(make_req(Method::DELETE, "/healthz", None))
            .await?;
        assert_eq!(res.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            res.headers().get("allow").and_then(|v| v.to_str().ok()),
            Some("GET")
        );

        // 9. Protected /admin/stats is denied (403 Forbidden) without Admin role
        let res = stack
            .clone()
            .oneshot(make_req(Method::GET, "/admin/stats", None))
            .await?;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        // 10. Public /whoami works unauthenticated
        let res = stack
            .clone()
            .oneshot(make_req(Method::GET, "/whoami", None))
            .await?;
        assert_eq!(res.status(), StatusCode::OK);

        // 11. mTLS OID ("1" -> "Admin") via ConnectionHandler grants access to /admin/stats
        let handler = praeco_rs::ConnectionHandler::new(
            stack.clone(),
            "127.0.0.1:50000".parse().expect("valid SocketAddr"),
            vec!["1".to_string()],
            None,
            Some("admin.example.com".to_string()),
            std::sync::Arc::new(cfg.oid_mapping.clone()),
        );
        let res = handler
            .handle(make_req(Method::GET, "/admin/stats", None))
            .await?;
        assert_eq!(res.status(), StatusCode::OK);
        let stats_json: serde_json::Value = serde_json::from_slice(&res.collect().await?.to_bytes())?;
        assert_eq!(stats_json["status"], "admin-ok");
        assert_eq!(stats_json["roles"], serde_json::json!(["Admin"]));

        let whoami_handler = praeco_rs::ConnectionHandler::new(
            stack,
            "127.0.0.1:50000".parse().expect("valid SocketAddr"),
            vec!["1".to_string()],
            None,
            Some("admin.example.com".to_string()),
            std::sync::Arc::new(cfg.oid_mapping.clone()),
        );
        let res = whoami_handler
            .handle(make_req(Method::GET, "/whoami", None))
            .await?;
        assert_eq!(res.status(), StatusCode::OK);
        let whoami_json: serde_json::Value = serde_json::from_slice(&res.collect().await?.to_bytes())?;
        assert_eq!(whoami_json["roles"], serde_json::json!(["Admin"]));
        assert_eq!(whoami_json["oids"], serde_json::json!(["1"]));
        assert_eq!(whoami_json["san"], "admin.example.com");

        Ok(())
    }

    #[tokio::test]
    async fn test_optional_jwt_with_rbac_layer_and_claims_extractor() -> anyhow::Result<()> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let pki = TestPki::new();
        let dir = tempfile::tempdir()?;
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
        let pub_pem_path = dir.path().join("idp_pub.pem");
        std::fs::write(&pub_pem_path, key_pair.public_key_pem())?;
        let enc_key = jsonwebtoken::EncodingKey::from_ed_pem(key_pair.serialize_pem().as_bytes())?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        let make_jwt = |sub: &str, oid: &str, jti: &str| -> anyhow::Result<String> {
            common::sign_jwt(
                &common::Claims {
                    sub: sub.to_string(),
                    iss: "praeco-idp".to_string(),
                    aud: Some("https-web-server".to_string()),
                    exp: (now + 300) as usize,
                    oids: vec![oid.to_string()],
                    jti: Some(jti.to_string()),
                },
                &enc_key,
            )
        };

        let router = build_app_router()?;
        let jwt_cfg = praeco_rs::configuration::JwtAuthConfig {
            jwt_public_keys: vec![TestPki::s(&pub_pem_path).to_owned()],
            cookie_fallback: None,
            redirect_on_failure: None,
            expected_issuer: "praeco-idp".to_string(),
            expected_audience: "https-web-server".to_string(),
            revoke_on_paths: Vec::new(),
            require_jti: true,
            max_token_lifetime_seconds: 86_400,
            optional: true,
        };
        let cfg = bootstrap::build_server_config_with_options(
            8443,
            router.allowed_pathes(),
            router.rbac_rules(),
            TestPki::s(&pki.praeco_public_pem).to_owned(),
            TestPki::s(&pki.praeco_public_key).to_owned(),
            None,
            Some(jwt_cfg),
        )?;
        let stack = build_service_stack_with_base(&cfg, router.into_service())?;

        // 1. Missing token passes OptionalJwt with Guest role and reaches public /whoami -> 200 OK
        let res = stack
            .clone()
            .oneshot(make_req(Method::GET, "/whoami", None))
            .await?;
        assert_eq!(res.status(), StatusCode::OK);
        let anon_json: serde_json::Value = serde_json::from_slice(&res.collect().await?.to_bytes())?;
        assert_eq!(anon_json["roles"], serde_json::json!(["Guest"]));
        assert_eq!(anon_json["oids"], serde_json::json!([]));
        assert!(anon_json["jwt_sub"].is_null());

        // 2. Missing token on protected /admin/stats -> 403 Forbidden from RbacLayer
        let res = stack
            .clone()
            .oneshot(make_req(Method::GET, "/admin/stats", None))
            .await?;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        // 3. Invalid token is still rejected with 401 Unauthorized
        let mut bad_req = make_req(Method::GET, "/whoami", None);
        bad_req
            .headers_mut()
            .insert("authorization", "Bearer invalid.jwt.token".parse()?);
        let res = stack.clone().oneshot(bad_req).await?;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);

        // 4. Valid Viewer JWT (OID "2") is denied on /admin/stats (403 Forbidden)
        let viewer_jwt = make_jwt("bob", "2", "jti-viewer")?;
        let mut viewer_req = make_req(Method::GET, "/admin/stats", None);
        viewer_req
            .headers_mut()
            .insert("authorization", format!("Bearer {viewer_jwt}").parse()?);
        let res = stack.clone().oneshot(viewer_req).await?;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        // 5. Valid Admin JWT (OID "1") succeeds on /admin/stats and /whoami
        let admin_jwt = make_jwt("alice", "1", "jti-admin")?;
        let mut admin_req = make_req(Method::GET, "/admin/stats", None);
        admin_req
            .headers_mut()
            .insert("authorization", format!("Bearer {admin_jwt}").parse()?);
        let res = stack.clone().oneshot(admin_req).await?;
        assert_eq!(res.status(), StatusCode::OK);

        let mut whoami_req = make_req(Method::GET, "/whoami", None);
        whoami_req
            .headers_mut()
            .insert("authorization", format!("Bearer {admin_jwt}").parse()?);
        let res = stack.oneshot(whoami_req).await?;
        assert_eq!(res.status(), StatusCode::OK);
        let whoami_json: serde_json::Value = serde_json::from_slice(&res.collect().await?.to_bytes())?;
        assert_eq!(whoami_json["roles"], serde_json::json!(["Admin"]));
        assert_eq!(whoami_json["oids"], serde_json::json!(["1"]));
        assert_eq!(whoami_json["jwt_sub"], "alice");

        Ok(())
    }
}
