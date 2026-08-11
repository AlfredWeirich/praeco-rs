use hyper::{Response, StatusCode, header};
use tracing::warn;

use super::build_error_response;
use crate::{ServiceRespBody, configuration::ServerConfig};

/// HTTP hop-by-hop headers that **must not** be forwarded by a proxy.
static HOP_BY_HOP_HEADERS: [header::HeaderName; 9] = [
    header::CONNECTION,
    header::PROXY_AUTHENTICATE,
    header::PROXY_AUTHORIZATION,
    header::TE,
    header::TRAILER,
    header::TRANSFER_ENCODING,
    header::UPGRADE,
    header::HeaderName::from_static("keep-alive"),
    header::HeaderName::from_static("proxy-connection"),
];

/// Extracts the client's IP from request extensions and injects it as the `X-Real-IP` header.
pub fn inject_real_ip(parts: &mut hyper::http::request::Parts) {
    let client_addr = parts.extensions.get::<std::net::SocketAddr>().copied();
    if let Some(addr) = client_addr {
        let ip_str = addr.ip().to_string();
        if let Ok(hv) = header::HeaderValue::from_str(&ip_str) {
            parts.headers.insert("X-Real-IP", hv);
        }
    }
}

/// Cleans and prepares HTTP headers for upstream forwarding.
pub fn prepare_proxy_headers(
    original_headers: &mut hyper::HeaderMap,
    server_name: &str,
    jwt_token: Option<&hyper::header::HeaderValue>,
    extensions: &hyper::http::Extensions,
    config: &ServerConfig,
) -> Result<(), Response<ServiceRespBody>> {
    let mut max_forwards = 10;
    if let Some(mf_val) = original_headers.get(header::MAX_FORWARDS) {
        if let Ok(mf_str) = mf_val.to_str() {
            if let Ok(mut mf) = mf_str.parse::<u8>() {
                if mf == 0 {
                    warn!("{}: Max-Forwards reached 0, Loop Detected!", server_name);
                    return Err(build_error_response(
                        "Loop Detected",
                        StatusCode::LOOP_DETECTED,
                    ));
                }
                mf -= 1;
                max_forwards = mf;
            }
        }
    }
    original_headers.insert(
        header::MAX_FORWARDS,
        header::HeaderValue::from(max_forwards as u16),
    );

    for h in &HOP_BY_HOP_HEADERS {
        original_headers.remove(h);
    }

    if let Some(hv) = jwt_token {
        original_headers.insert(header::AUTHORIZATION, hv.clone());
    }

    if let Some(forward_config) = &config.client_cert_forwarding {
        if let Some(header_cert) = &forward_config.header_cert {
            if let Ok(hdr_name) = header::HeaderName::from_bytes(header_cert.as_bytes()) {
                original_headers.remove(&hdr_name);
            }
        }
        if let Some(header_san) = &forward_config.header_san {
            if let Ok(hdr_name) = header::HeaderName::from_bytes(header_san.as_bytes()) {
                original_headers.remove(&hdr_name);
            }
        }
        if let Some(header_roles) = &forward_config.header_roles {
            if let Ok(hdr_name) = header::HeaderName::from_bytes(header_roles.as_bytes()) {
                original_headers.remove(&hdr_name);
            }
        }
        if let Some(header_ip) = &forward_config.header_client_ip {
            if let Ok(hdr_name) = header::HeaderName::from_bytes(header_ip.as_bytes()) {
                original_headers.remove(&hdr_name);
            }
        }

        tracing::trace!("Client cert forwarding is ENABLED in config!");
        if let Some(header_cert) = &forward_config.header_cert {
            if let Some(pem) = extensions.get::<crate::PemCertExtension>() {
                let pem_escaped = urlencoding::encode(&pem.0).into_owned();
                if let Ok(hdr_val) = header::HeaderValue::from_str(&pem_escaped) {
                    if let Ok(hdr_name) = header::HeaderName::from_bytes(header_cert.as_bytes()) {
                        tracing::trace!("Injecting PEM into header: {}", hdr_name);
                        original_headers.insert(hdr_name, hdr_val);
                    }
                } else {
                    tracing::warn!("FAILED to convert escaped PEM to HeaderValue");
                }
            }
        }
        if let Some(header_san) = &forward_config.header_san {
            tracing::trace!("Config expects SAN header name: '{}'", header_san);
            if let Some(san) = extensions.get::<crate::SanCertExtension>() {
                tracing::trace!("Found SanCertExtension with value: '{}'", san.0);
                match header::HeaderValue::from_str(&san.0) {
                    Ok(hdr_val) => match header::HeaderName::from_bytes(header_san.as_bytes()) {
                        Ok(hdr_name) => {
                            tracing::trace!("SUCCESS! Injecting SAN into header: {}", hdr_name);
                            original_headers.insert(hdr_name, hdr_val);
                        }
                        Err(e) => tracing::warn!(
                            "FAILED to parse HeaderName from config '{}': {}",
                            header_san,
                            e
                        ),
                    },
                    Err(e) => {
                        tracing::warn!("FAILED to parse HeaderValue from SAN '{}': {}", san.0, e)
                    }
                }
            } else {
                tracing::trace!(
                    "extensions.get::<SanCertExtension>() returned None! No SAN found in request extensions."
                );
            }
        }
        if let Some(header_roles) = &forward_config.header_roles {
            if let Some(roles) = extensions.get::<std::sync::Arc<Vec<crate::configuration::UserRole>>>() {
                if !roles.is_empty() {
                    let roles_str = roles.iter().map(|r| r.0.as_str()).collect::<Vec<_>>().join(", ");
                    if let Ok(hdr_val) = header::HeaderValue::from_str(&roles_str) {
                        if let Ok(hdr_name) = header::HeaderName::from_bytes(header_roles.as_bytes()) {
                            tracing::trace!("Injecting User Roles into header: {}", hdr_name);
                            original_headers.insert(hdr_name, hdr_val);
                        }
                    }
                }
            }
        }
        if let Some(header_ip) = &forward_config.header_client_ip {
            if let Some(addr) = extensions.get::<std::net::SocketAddr>() {
                let ip_str = addr.ip().to_string();
                if let Ok(hdr_val) = header::HeaderValue::from_str(&ip_str) {
                    if let Ok(hdr_name) = header::HeaderName::from_bytes(header_ip.as_bytes()) {
                        tracing::trace!("Injecting Client IP into header: {}", hdr_name);
                        original_headers.insert(hdr_name, hdr_val);
                    }
                }
            }
        }
    } else {
        tracing::trace!("Client cert forwarding is NOT enabled in config!");
    }

    Ok(())
}
