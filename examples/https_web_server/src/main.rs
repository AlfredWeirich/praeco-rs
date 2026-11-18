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

/// Builds the endpoint router (including single-source-of-truth WAF rules).
fn build_app_router() -> anyhow::Result<WebRouter> {
    Ok(WebRouter::new()
        .get("/", endpoints::index)?
        .get("/healthz", endpoints::healthz)?
        .get_with_waf(
            "/users/{id}",
            "/users/*",
            "^/users/[A-Za-z0-9_-]+$",
            endpoints::get_user,
        )?
        .get_with_waf(
            "/greet",
            "/greet",
            r"^/greet\?(?:user_name=[A-Za-z0-9_-]+(?:&age=[0-9]{1,3})?|age=[0-9]{1,3}&user_name=[A-Za-z0-9_-]+)$",
            endpoints::greet,
        )?
        .post("/api/echo", endpoints::echo_json)?)
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
    use praeco_rs::{
        SrvBody, SrvError, build_rustls_config, build_service_stack_with_base,
        configuration::ServerCertConfig,
    };
    use std::net::SocketAddr;
    use std::sync::Arc;
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
        let _ = rustls::crypto::ring::default_provider().install_default();
        let pki = TestPki::new();
        let router = build_app_router()?;
        let mut cfg = bootstrap::build_server_config(8443, router.allowed_pathes())?;
        Arc::make_mut(&mut cfg).server_certs = Some(ServerCertConfig {
            ssl_certificate: TestPki::s(&pki.praeco_public_pem).to_owned(),
            ssl_certificate_key: TestPki::s(&pki.praeco_public_key).to_owned(),
        });

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

        Ok(())
    }
}
