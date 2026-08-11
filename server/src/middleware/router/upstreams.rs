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
