//! # Role-Based Access Control (RBAC) Middleware
//!
//! Enforces fail-closed path- and method-based Role-Based Access Control
//! ([`CompiledRbac`]) as a standalone Tower [`Layer`] / [`Service`] before
//! requests reach any inner service (`RouterService`, `WebRouter`, `StaticFiles`,
//! `AdminService`, or embedded Tonic gRPC routes).
//!
//! ## Policy Semantics (Fail-Closed)
//!
//! 1. Semicolon matrix parameters (`;` / `%3b`) are rejected immediately (`403 Forbidden`).
//! 2. Paths are canonicalized with [`sanitize_and_normalize_path_cow`](crate::middleware::path_sanitizer::sanitize_and_normalize_path_cow)
//!    before rule lookup.
//! 3. Rules are matched in order: `"METHOD /exact"`, `"/exact"`, then longest prefix across
//!    `"METHOD /prefix*"` and `"/prefix*"` (method-specific wins ties at equal prefix length).
//! 4. **Unmatched paths** are rejected fail-closed (`403 Forbidden`).
//! 5. **Empty role list (`[]`)** acts as an explicit Deny-All rule (`403 Forbidden`).
//! 6. **Wildcard (`["*"]`)** permits any caller (including unauthenticated requests).
//! 7. Otherwise, request extensions (`Arc<RoleVec<6>>`, `RoleVec<6>`, or `Arc<Vec<UserRole>>`)
//!    must contain at least one role listed in the matched rule.

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{Request, Response, StatusCode};
use pin_project::pin_project;
use tower::{Layer, Service};
use tracing::warn;

use crate::{
    ServiceRespBody, SrvError,
    configuration::{CompiledRbac, RoleVec, ServerMetrics, UserRole},
    middleware::path_sanitizer::sanitize_and_normalize_path_cow,
};

/// Extracts the client's assigned user roles from HTTP request [`Extensions`](hyper::http::Extensions).
///
/// Supports `Arc<RoleVec<6>>` (hot-path), stack-allocated `RoleVec<6>`,
/// and legacy `Arc<Vec<UserRole>>`.
#[inline]
pub fn extract_user_roles_from_extensions(
    extensions: &hyper::http::Extensions,
) -> Option<&[UserRole]> {
    extensions
        .get::<Arc<RoleVec<6>>>()
        .map(|r| r.as_slice())
        .or_else(|| extensions.get::<RoleVec<6>>().map(|r| r.as_slice()))
        .or_else(|| extensions.get::<Arc<Vec<UserRole>>>().map(|r| r.as_slice()))
}

/// Extracts the client's assigned user roles from [`hyper::http::request::Parts`].
#[inline]
pub fn extract_user_roles(parts: &hyper::http::request::Parts) -> Option<&[UserRole]> {
    extract_user_roles_from_extensions(&parts.extensions)
}

/// Tower [`Layer`] enforcing fail-closed [`CompiledRbac`] rules across any inner service.
#[derive(Clone)]
pub struct RbacLayer {
    rules: Arc<CompiledRbac>,
    server_name: &'static str,
}

impl RbacLayer {
    /// Creates a new [`RbacLayer`] backed by compiled RBAC rules and a server label.
    pub fn new(rules: Arc<CompiledRbac>, server_name: &'static str) -> Self {
        Self { rules, server_name }
    }
}

impl<S> Layer<S> for RbacLayer {
    type Service = RbacService<S>;

    fn layer(&self, inner: S) -> Self::Service {
        RbacService {
            inner,
            rules: Arc::clone(&self.rules),
            server_name: self.server_name,
        }
    }
}

/// Tower [`Service`] enforcing [`CompiledRbac`] authorization before forwarding to `inner`.
#[derive(Clone)]
pub struct RbacService<S> {
    inner: S,
    rules: Arc<CompiledRbac>,
    server_name: &'static str,
}

/// Future returned by [`RbacService`]: either forwards the inner future or yields `403 Forbidden`.
#[pin_project(project = RbacFutureProj)]
pub enum RbacFuture<F> {
    /// Request passed RBAC; poll the wrapped service future.
    Allowed {
        #[pin]
        inner: F,
    },
    /// Request denied by RBAC; immediately yield the pre-built `403 Forbidden` response.
    Blocked {
        response: Option<Response<ServiceRespBody>>,
    },
}

impl<F, E> Future for RbacFuture<F>
where
    F: Future<Output = Result<Response<ServiceRespBody>, E>>,
{
    type Output = Result<Response<ServiceRespBody>, E>;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.project() {
            RbacFutureProj::Allowed { inner } => inner.poll(cx),
            RbacFutureProj::Blocked { response } => crate::poll_ready_response(response),
        }
    }
}

impl<S, ReqBody> Service<Request<ReqBody>> for RbacService<S>
where
    S: Service<Request<ReqBody>, Response = Response<ServiceRespBody>> + Clone + Send + 'static,
    S::Future: Send + 'static,
    S::Error: Send + 'static,
    ReqBody: Send + 'static,
{
    type Response = Response<ServiceRespBody>;
    type Error = S::Error;
    type Future = RbacFuture<S::Future>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: Request<ReqBody>) -> Self::Future {
        let server_name = self.server_name;
        let path = req.uri().path();

        if path.contains(';')
            || path
                .as_bytes()
                .windows(3)
                .any(|w| w.eq_ignore_ascii_case(b"%3b"))
        {
            ServerMetrics::inc_blocked_auth_rbac(server_name);
            warn!(
                "{}: Forbidden: matrix parameter ';' is not permitted in RBAC path '{}'",
                server_name, path
            );
            return RbacFuture::Blocked {
                response: Some(build_forbidden_response()),
            };
        }

        let canonical_path = match sanitize_and_normalize_path_cow(path) {
            Ok(p) => p,
            Err(e) => {
                ServerMetrics::inc_blocked_auth_rbac(server_name);
                warn!(
                    "{}: Forbidden: invalid path '{}' rejected by RBAC: {}",
                    server_name, path, e
                );
                return RbacFuture::Blocked {
                    response: Some(build_forbidden_response()),
                };
            }
        };

        let method = req.method().as_str();
        let Some(required_roles) = self.rules.match_request(method, &canonical_path) else {
            ServerMetrics::inc_blocked_auth_rbac(server_name);
            warn!(
                "{}: Forbidden: no RBAC rule matched '{} {}' (fail-closed)",
                server_name, method, canonical_path
            );
            return RbacFuture::Blocked {
                response: Some(build_forbidden_response()),
            };
        };

        if required_roles.is_empty() {
            ServerMetrics::inc_blocked_auth_rbac(server_name);
            warn!(
                "{}: Forbidden: explicit empty RBAC rule for '{} {}' denies all requests",
                server_name, method, canonical_path
            );
            return RbacFuture::Blocked {
                response: Some(build_forbidden_response()),
            };
        }

        let user_roles = extract_user_roles_from_extensions(req.extensions());
        let is_authorized = if required_roles.iter().any(|r| r.0 == "*") {
            true
        } else {
            user_roles.is_some_and(|roles| roles.iter().any(|r| required_roles.contains(r)))
        };

        if !is_authorized {
            ServerMetrics::inc_blocked_auth_rbac(server_name);
            warn!(
                "{}: Forbidden: RBAC required one of {:?} for '{} {}', but client has {:?}",
                server_name, required_roles, method, canonical_path, user_roles
            );
            return RbacFuture::Blocked {
                response: Some(build_forbidden_response()),
            };
        }

        RbacFuture::Allowed {
            inner: self.inner.call(req),
        }
    }
}

/// Builds a minimal `403 Forbidden` plain-text response.
fn build_forbidden_response() -> Response<ServiceRespBody> {
    let body: ServiceRespBody = Full::new(Bytes::from_static(b"Forbidden"))
        .map_err(SrvError::from)
        .boxed();
    crate::build_infallible_response(StatusCode::FORBIDDEN, None, body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use http_body_util::Empty;
    use hyper::Method;
    use std::collections::HashMap;
    use tower::ServiceExt;

    fn make_req(method: Method, uri: &str, roles: Option<Vec<&str>>) -> Request<crate::SrvBody> {
        let mut req = Request::builder()
            .method(method)
            .uri(uri)
            .body(Empty::<Bytes>::new().map_err(SrvError::from).boxed())
            .expect("valid test request");
        if let Some(r) = roles {
            let role_objs: RoleVec<6> = r.into_iter().map(|s| UserRole(s.to_string())).collect();
            req.extensions_mut().insert(Arc::new(role_objs));
        }
        req
    }

    fn ok_service() -> crate::BoxedCloneService {
        use crate::BoxCloneSyncServiceExt;
        tower::service_fn(|_req: Request<crate::SrvBody>| async move {
            Ok::<_, SrvError>(Response::new(
                Full::new(Bytes::from_static(b"ok"))
                    .map_err(SrvError::from)
                    .boxed(),
            ))
        })
        .boxed_clone_sync()
    }

    #[tokio::test]
    async fn test_rbac_layer_fail_closed_exact_prefix_wildcard_and_deny() -> anyhow::Result<()> {
        let mut raw = HashMap::new();
        raw.insert("/public/*".to_string(), vec![UserRole("*".to_string())]);
        raw.insert("/api/*".to_string(), vec![UserRole("Admin".to_string())]);
        raw.insert(
            "/api/GetOrders".to_string(),
            vec![UserRole("Admin".to_string()), UserRole("Seller".to_string())],
        );
        raw.insert("/api/Blocked".to_string(), vec![]);

        let compiled = Arc::new(CompiledRbac::from_raw(&raw)?);
        let svc = RbacLayer::new(compiled, "test_srv").layer(ok_service());

        // Unmatched path -> 403 Forbidden (fail-closed)
        let res = svc
            .clone()
            .oneshot(make_req(Method::GET, "/unknown", Some(vec!["Admin"])))
            .await?;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        // Public wildcard -> 200 OK even without roles
        let res = svc
            .clone()
            .oneshot(make_req(Method::GET, "/public/logo.png", None))
            .await?;
        assert_eq!(res.status(), StatusCode::OK);

        // Exact exception allows Seller
        let res = svc
            .clone()
            .oneshot(make_req(Method::POST, "/api/GetOrders", Some(vec!["Seller"])))
            .await?;
        assert_eq!(res.status(), StatusCode::OK);

        // Prefix rule restricts other /api/* paths to Admin
        let res = svc
            .clone()
            .oneshot(make_req(Method::POST, "/api/DeleteUser", Some(vec!["Seller"])))
            .await?;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        let res = svc
            .clone()
            .oneshot(make_req(Method::POST, "/api/DeleteUser", Some(vec!["Admin"])))
            .await?;
        assert_eq!(res.status(), StatusCode::OK);

        // Empty role list denies everyone, including Admin
        let res = svc
            .clone()
            .oneshot(make_req(Method::GET, "/api/Blocked", Some(vec!["Admin"])))
            .await?;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        // Matrix parameter ';' and encoded '%3b' are rejected fail-closed
        let res = svc
            .clone()
            .oneshot(make_req(Method::GET, "/public/x;role=admin", None))
            .await?;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        let res = svc
            .oneshot(make_req(Method::GET, "/public/x%3brole=admin", None))
            .await?;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        Ok(())
    }

    #[tokio::test]
    async fn test_rbac_layer_method_specific_precedence_and_traversal_canonicalization()
    -> anyhow::Result<()> {
        let mut raw = HashMap::new();
        raw.insert(
            "GET /users/*".to_string(),
            vec![UserRole("Viewer".to_string()), UserRole("Admin".to_string())],
        );
        raw.insert(
            "DELETE /users/*".to_string(),
            vec![UserRole("Admin".to_string())],
        );
        raw.insert("/users/*".to_string(), vec![UserRole("Admin".to_string())]);
        raw.insert("GET /public".to_string(), vec![UserRole("*".to_string())]);

        let compiled = Arc::new(CompiledRbac::from_raw(&raw)?);
        let svc = RbacLayer::new(compiled, "test_srv").layer(ok_service());

        // Viewer can GET /users/42, but cannot DELETE or POST /users/42
        let res = svc
            .clone()
            .oneshot(make_req(Method::GET, "/users/42", Some(vec!["Viewer"])))
            .await?;
        assert_eq!(res.status(), StatusCode::OK);

        let res = svc
            .clone()
            .oneshot(make_req(Method::DELETE, "/users/42", Some(vec!["Viewer"])))
            .await?;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        let res = svc
            .clone()
            .oneshot(make_req(Method::DELETE, "/users/42", Some(vec!["Admin"])))
            .await?;
        assert_eq!(res.status(), StatusCode::OK);

        // Traversal attempt is blocked by sanitize_and_normalize_path_cow
        let res = svc
            .clone()
            .oneshot(make_req(Method::GET, "/public/../users/42", None))
            .await?;
        assert_eq!(res.status(), StatusCode::FORBIDDEN);

        // Trailing slash normalized on exact method rule
        let res = svc
            .oneshot(make_req(Method::GET, "/public/", None))
            .await?;
        assert_eq!(res.status(), StatusCode::OK);

        Ok(())
    }

    #[tokio::test]
    async fn test_rbac_supports_smallvec_and_arc_and_legacy_vec() -> anyhow::Result<()> {
        let mut raw = HashMap::new();
        raw.insert("/api/test".to_string(), vec![UserRole("Admin".to_string())]);
        let compiled = Arc::new(CompiledRbac::from_raw(&raw)?);
        let svc = RbacLayer::new(compiled, "test_srv").layer(ok_service());

        // 1. Stack RoleVec directly
        let mut req1 = make_req(Method::GET, "/api/test", None);
        let mut rv: RoleVec<6> = RoleVec::new();
        rv.push(UserRole("Admin".to_string()));
        req1.extensions_mut().insert(rv);
        assert_eq!(svc.clone().oneshot(req1).await?.status(), StatusCode::OK);

        // 2. Legacy Arc<Vec<UserRole>>
        let mut req2 = make_req(Method::GET, "/api/test", None);
        req2.extensions_mut()
            .insert(Arc::new(vec![UserRole("Admin".to_string())]));
        assert_eq!(svc.oneshot(req2).await?.status(), StatusCode::OK);

        Ok(())
    }
}
