use hyper::{Response, StatusCode};
use std::sync::Arc;
use tracing::warn;

use super::build_error_response;
use crate::{
    ServiceRespBody,
    configuration::{ParsedRoute, UserRole},
};

/// Enforces Role-Based Access Control (RBAC).
///
/// Checks if the client's roles (extracted from extensions) intersect with the
/// `allowed_roles` defined for the matched route. Returns `Ok(())` if authorized,
/// or an HTTP 403 Forbidden response otherwise.
pub fn enforce_rbac(
    parts: &hyper::http::request::Parts,
    route_info: &ParsedRoute,
    server_name: &str,
) -> Result<(), Response<ServiceRespBody>> {
    if !route_info.allowed_roles.is_empty() {
        let user_roles = parts.extensions.get::<Arc<Vec<UserRole>>>();
        let is_authorized = match user_roles {
            Some(roles) => roles.iter().any(|r| route_info.allowed_roles.contains(r)),
            None => false,
        };

        if !is_authorized {
            warn!(
                "{}: Forbidden for roles {:?} at {}",
                server_name,
                user_roles,
                parts.uri.path()
            );
            return Err(build_error_response("Forbidden", StatusCode::FORBIDDEN));
        }
    }
    Ok(())
}
