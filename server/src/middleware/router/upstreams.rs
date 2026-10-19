use crate::SrvError;
use hyper::http::uri::{PathAndQuery, Uri};

/// Reconstructs the Request URI for the upstream server.
///
/// Combines the backend's base URI with the matched sub-path (`*rest`) and
/// preserves any original query parameters.
pub fn build_upstream_uri(
    backend_base_uri: &Uri,
    matched_params: &matchit::Params,
    original_uri: &Uri,
) -> Result<Uri, SrvError> {
    let mut pq_string = String::with_capacity(64);
    pq_string.push_str(backend_base_uri.path().trim_end_matches('/'));

    if let Some(rest) = matched_params.get("rest") {
        // Defense-in-depth: Reject any sub-path containing traversal or illegal characters
        if rest.split('/').any(|seg| seg == "..")
            || rest.contains("%2f")
            || rest.contains("%2F")
            || rest.contains('\0')
            || rest.contains("%00")
            || rest.contains('\\')
            || rest.contains("%5c")
            || rest.contains("%5C")
        {
            return Err(SrvError::from("Suspicious path traversal or illegal characters detected in upstream URI".to_string()));
        }
        if !rest.starts_with('/') {
            pq_string.push('/');
        }
        pq_string.push_str(rest);
    } else if pq_string.is_empty() {
        pq_string.push('/');
    }

    if let Some(query) = original_uri.query() {
        pq_string.push('?');
        pq_string.push_str(query);
    }

    let mut uri_parts = backend_base_uri.clone().into_parts();
    uri_parts.path_and_query = Some(
        pq_string
            .parse::<PathAndQuery>()
            .map_err(|e| SrvError::from(format!("Invalid PathAndQuery: {e}")))?,
    );

    Uri::from_parts(uri_parts).map_err(|e| SrvError::from(format!("URI Build Error: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_upstream_uri_normal() {
        let base: Uri = "https://backend.local:8080/api".parse().unwrap();
        let orig: Uri = "/api/v1/users?page=1".parse().unwrap();
        let mut router = matchit::Router::new();
        router.insert("/api/{*rest}", ()).unwrap();
        let matched = router.at("/api/v1/users").unwrap();

        let upstream = build_upstream_uri(&base, &matched.params, &orig).unwrap();
        assert_eq!(upstream.to_string(), "https://backend.local:8080/api/v1/users?page=1");
    }

    #[test]
    fn test_build_upstream_uri_traversal_rejected() {
        let base: Uri = "https://backend.local:8080/api".parse().unwrap();
        let orig: Uri = "/public/../admin".parse().unwrap();
        let mut router = matchit::Router::new();
        router.insert("/public/{*rest}", ()).unwrap();
        let matched = router.at("/public/../admin").unwrap();

        let err = build_upstream_uri(&base, &matched.params, &orig).unwrap_err();
        assert!(err.to_string().contains("Suspicious path traversal"));
    }
}
