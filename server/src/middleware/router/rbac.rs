use hyper::{Response, StatusCode};
use std::sync::Arc;
use tracing::warn;

use super::build_error_response;
use crate::{
    ServiceRespBody,
    configuration::{CompiledRbac, ParsedRoute, UserRole},
};

/// Enforces Role-Based Access Control (RBAC).
///
/// Priority:
/// 1. If fine-grained path-based RBAC (`CompiledRbac`) is configured for the server and matches
///    the request path, it is evaluated:
///    - If the required roles list is empty `[]`, access is unconditionally DENIED (403 Forbidden, fail-close).
///    - If the required roles list contains `*`, access is granted to all callers.
///    - Otherwise, client roles (from extensions) must contain at least one required role.
/// 2. If no path-specific RBAC rule matched, fallback to `route_info.allowed_roles`:
///    - If non-empty, client roles must contain at least one allowed role.
///    - If empty, access is unrestricted.
pub fn enforce_rbac(
    parts: &hyper::http::request::Parts,
    route_info: &ParsedRoute,
    compiled_rbac: Option<&CompiledRbac>,
    server_name: &str,
) -> Result<(), Response<ServiceRespBody>> {
    let path = parts.uri.path();

    // 1. Path-specific granular RBAC (Option B)
    if let Some(rbac) = compiled_rbac {
        if let Some(required_roles) = rbac.match_path(path) {
            // Fail-closed: empty role list acts as explicit Deny-All
            if required_roles.is_empty() {
                warn!(
                    "{}: Forbidden: explicit empty RBAC rule for '{}' denies all requests",
                    server_name, path
                );
                return Err(build_error_response("Forbidden", StatusCode::FORBIDDEN));
            }

            let is_authorized = if required_roles.iter().any(|r| r.0 == "*") {
                true
            } else {
                let user_roles = parts.extensions.get::<Arc<Vec<UserRole>>>();
                match user_roles {
                    Some(roles) => roles.iter().any(|r| required_roles.contains(r)),
                    None => false,
                }
            };

            if !is_authorized {
                let user_roles = parts.extensions.get::<Arc<Vec<UserRole>>>();
                warn!(
                    "{}: Forbidden: RBAC required one of {:?} for path '{}', but client has {:?}",
                    server_name, required_roles, path, user_roles
                );
                return Err(build_error_response("Forbidden", StatusCode::FORBIDDEN));
            }

            return Ok(());
        }
    }

    // 2. Fallback: Route-level RBAC
    if !route_info.allowed_roles.is_empty() {
        let user_roles = parts.extensions.get::<Arc<Vec<UserRole>>>();
        let is_authorized = match user_roles {
            Some(roles) => roles.iter().any(|r| route_info.allowed_roles.contains(r)),
            None => false,
        };

        if !is_authorized {
            warn!(
                "{}: Forbidden for roles {:?} at {} (required route roles: {:?})",
                server_name,
                user_roles,
                path,
                route_info.allowed_roles
            );
            return Err(build_error_response("Forbidden", StatusCode::FORBIDDEN));
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hyper::Request;
    use std::collections::HashMap;

    fn create_test_route(allowed_roles: Vec<&str>) -> ParsedRoute {
        let node =
            crate::configuration::UpstreamNode::new("http://127.0.0.1:8080".parse().unwrap());
        ParsedRoute {
            prefix: "/".to_string(),
            target: Arc::new(crate::configuration::RouteTarget {
                upstreams: vec![node],
                strategy: crate::configuration::LbStrategy::RoundRobin,
                rr_counter: std::sync::atomic::AtomicUsize::new(0),
                cooldown_seconds: 10,
                max_retries: 2,
                failure_threshold: 3,
                max_retry_buffer_bytes: 65536,
                active_health_check_interval: 0,
                grpc_pool: tokio::sync::RwLock::new(None),
                grpc_reflection_lock: tokio::sync::Mutex::new(()),
            }),
            allowed_roles: allowed_roles.into_iter().map(|s| UserRole(s.to_string())).collect(),
            backend_type: crate::configuration::RouteBackendType::Rest,
        }
    }

    fn create_request(path: &str, roles: Option<Vec<&str>>) -> hyper::http::request::Parts {
        let mut req = Request::builder()
            .uri(path)
            .body(())
            .unwrap();
        if let Some(r) = roles {
            let role_objs: Vec<UserRole> = r.into_iter().map(|s| UserRole(s.to_string())).collect();
            req.extensions_mut().insert(Arc::new(role_objs));
        }
        let (parts, _) = req.into_parts();
        parts
    }

    #[test]
    fn test_route_level_unrestricted() {
        let route = create_test_route(vec![]);
        let parts = create_request("/public", None);
        assert!(enforce_rbac(&parts, &route, None, "test_srv").is_ok());
    }

    #[test]
    fn test_route_level_authorized() {
        let route = create_test_route(vec!["Admin", "Seller"]);
        let parts = create_request("/api/test", Some(vec!["Admin"]));
        assert!(enforce_rbac(&parts, &route, None, "test_srv").is_ok());

        let parts_seller = create_request("/api/test", Some(vec!["Seller"]));
        assert!(enforce_rbac(&parts_seller, &route, None, "test_srv").is_ok());
    }

    #[test]
    fn test_route_level_forbidden() {
        let route = create_test_route(vec!["Admin"]);
        let parts = create_request("/api/test", Some(vec!["Seller"]));
        let res = enforce_rbac(&parts, &route, None, "test_srv");
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_route_level_missing_extensions() {
        let route = create_test_route(vec!["Admin"]);
        let parts = create_request("/api/test", None);
        let res = enforce_rbac(&parts, &route, None, "test_srv");
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_path_rbac_exact_match_privilege_separation() {
        let route = create_test_route(vec!["Admin", "Seller"]);
        let mut raw_rbac = HashMap::new();
        raw_rbac.insert("/api/GetDatabaseTables".to_string(), vec![UserRole("Admin".to_string())]);
        let compiled = CompiledRbac::from_raw(&raw_rbac);

        // Admin calling sensitive API -> OK
        let admin_parts = create_request("/api/GetDatabaseTables", Some(vec!["Admin"]));
        assert!(enforce_rbac(&admin_parts, &route, Some(&compiled), "test_srv").is_ok());

        // Seller calling sensitive API -> 403 Forbidden!
        let seller_parts = create_request("/api/GetDatabaseTables", Some(vec!["Seller"]));
        let res = enforce_rbac(&seller_parts, &route, Some(&compiled), "test_srv");
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().status(), StatusCode::FORBIDDEN);

        // Seller calling other route not in path rbac -> falls back to route allowed_roles ["Admin", "Seller"] -> OK
        let seller_orders = create_request("/api/GetAdminOrders", Some(vec!["Seller"]));
        assert!(enforce_rbac(&seller_orders, &route, Some(&compiled), "test_srv").is_ok());
    }

    #[test]
    fn test_path_rbac_wildcard_prefix() {
        let route = create_test_route(vec!["Admin", "Seller"]);
        let mut raw_rbac = HashMap::new();
        raw_rbac.insert("/api/Admin*".to_string(), vec![UserRole("Admin".to_string())]);
        let compiled = CompiledRbac::from_raw(&raw_rbac);

        // Seller calling /api/AdminDeleteUser -> 403 Forbidden
        let seller_parts = create_request("/api/AdminDeleteUser", Some(vec!["Seller"]));
        let res = enforce_rbac(&seller_parts, &route, Some(&compiled), "test_srv");
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().status(), StatusCode::FORBIDDEN);

        // Admin calling /api/AdminDeleteUser -> OK
        let admin_parts = create_request("/api/AdminDeleteUser", Some(vec!["Admin"]));
        assert!(enforce_rbac(&admin_parts, &route, Some(&compiled), "test_srv").is_ok());
    }

    #[test]
    fn test_path_rbac_exact_overrides_prefix() {
        let route = create_test_route(vec![]);
        let mut raw_rbac = HashMap::new();
        // Catch-all admin prefix requires Admin
        raw_rbac.insert("/api/Admin*".to_string(), vec![UserRole("Admin".to_string())]);
        // Specific exception allows Seller as well
        raw_rbac.insert("/api/AdminGetProducts".to_string(), vec![UserRole("Admin".to_string()), UserRole("Seller".to_string())]);
        let compiled = CompiledRbac::from_raw(&raw_rbac);

        // Seller on /api/AdminGetProducts -> OK because exact match took precedence
        let seller_exact = create_request("/api/AdminGetProducts", Some(vec!["Seller"]));
        assert!(enforce_rbac(&seller_exact, &route, Some(&compiled), "test_srv").is_ok());

        // Seller on /api/AdminDeleteUser -> 403 Forbidden because prefix matched
        let seller_prefix = create_request("/api/AdminDeleteUser", Some(vec!["Seller"]));
        assert_eq!(
            enforce_rbac(&seller_prefix, &route, Some(&compiled), "test_srv").unwrap_err().status(),
            StatusCode::FORBIDDEN
        );
    }

    #[test]
    fn test_path_rbac_empty_role_list_fail_closed() {
        let route = create_test_route(vec!["Admin"]);
        let mut raw_rbac = HashMap::new();
        // Empty role list acts as explicit Deny-All
        raw_rbac.insert("/api/Blocked".to_string(), vec![]);
        let compiled = CompiledRbac::from_raw(&raw_rbac);

        let admin_parts = create_request("/api/Blocked", Some(vec!["Admin"]));
        let res = enforce_rbac(&admin_parts, &route, Some(&compiled), "test_srv");
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().status(), StatusCode::FORBIDDEN);
    }

    #[test]
    fn test_path_rbac_wildcard_role_public() {
        let route = create_test_route(vec!["Admin"]);
        let mut raw_rbac = HashMap::new();
        raw_rbac.insert("/public/*".to_string(), vec![UserRole("*".to_string())]);
        let compiled = CompiledRbac::from_raw(&raw_rbac);

        // Unauthenticated request with no roles allowed by wildcard role
        let no_auth_parts = create_request("/public/assets/logo.png", None);
        assert!(enforce_rbac(&no_auth_parts, &route, Some(&compiled), "test_srv").is_ok());
    }
}

