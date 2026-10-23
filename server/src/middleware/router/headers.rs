use hyper::{Response, StatusCode, header};
use tracing::warn;

use super::build_error_response;
use crate::{ServiceRespBody, configuration::ServerConfig};

/// HTTP hop-by-hop headers that **must not** be forwarded by a proxy per RFC 7230 §6.1.
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

/// Global deny-list of identity and client-cert headers that MUST ALWAYS be stripped
/// from incoming client requests to prevent Identity Spoofing.
static IDENTITY_HEADERS_DENYLIST: &[&str] = &[
    // Client certificates
    "x-client-cert",
    "x-client-certificate",
    "x-ssl-client-cert",
    "x-ssl-certificate",
    "ssl-client-cert",
    "x-forwarded-tls-client-cert",
    "x-forwarded-client-cert",
    // Subject Alternative Name (SAN)
    "x-client-san",
    "x-ssl-client-san",
    "ssl-client-san",
    "x-client-cert-san",
    // User Roles / OIDs
    "x-client-roles",
    "x-client-role",
    "x-user-roles",
    "x-user-role",
    "x-auth-roles",
    "x-auth-role",
    "x-user-role-oid",
    "x-authenticated-user",
    // Certificate metadata & DNs
    "x-client-dn",
    "x-client-subject-dn",
    "x-client-issuer-dn",
    "x-client-serial",
    "x-ssl-client-subject-dn",
    "x-ssl-client-issuer-dn",
    "x-ssl-client-serial",
    "x-ssl-client-verify",
    // Client IP header if forwarded via client-cert config
    "x-client-ip",
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
///
/// Security operations performed:
/// 1. Loop detection via `Max-Forwards`.
/// 2. Strips hop-by-hop headers per RFC 7230 §6.1 (including custom headers listed in `Connection`).
/// 3. Unconditionally strips all known client-identity headers (anti-spoofing).
/// 4. Sanitizes and manages `Forwarded` / `X-Forwarded-*` headers.
/// 5. Injects JWT authorization tokens if configured for the upstream route.
/// 6. Injects verified mTLS identity headers if (and only if) `client_cert_forwarding` is enabled.
pub fn prepare_proxy_headers(
    original_headers: &mut hyper::HeaderMap,
    server_name: &str,
    jwt_token: Option<&hyper::header::HeaderValue>,
    extensions: &hyper::http::Extensions,
    config: &ServerConfig,
) -> Result<(), Response<ServiceRespBody>> {
    // 1. Loop Detection
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

    // 2. Strip Hop-by-Hop headers (including headers named in Connection header, RFC 7230 §6.1)
    let custom_hops: Vec<header::HeaderName> = if let Some(conn_val) = original_headers.get(header::CONNECTION) {
        if let Ok(conn_str) = conn_val.to_str() {
            conn_str
                .split(',')
                .filter_map(|h| header::HeaderName::from_bytes(h.trim().as_bytes()).ok())
                .collect()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };
    for h in custom_hops {
        original_headers.remove(&h);
    }
    for h in &HOP_BY_HOP_HEADERS {
        original_headers.remove(h);
    }

    // 3. Unconditionally strip all known identity headers to prevent identity spoofing
    for h in IDENTITY_HEADERS_DENYLIST {
        if let Ok(hdr_name) = header::HeaderName::from_bytes(h.as_bytes()) {
            original_headers.remove(&hdr_name);
        }
    }

    // Also strip any custom header names configured for this server
    if let Some(forward_config) = &config.client_cert_forwarding {
        if let Some(h) = &forward_config.header_cert {
            if let Ok(hdr) = header::HeaderName::from_bytes(h.as_bytes()) {
                original_headers.remove(&hdr);
            }
        }
        if let Some(h) = &forward_config.header_san {
            if let Ok(hdr) = header::HeaderName::from_bytes(h.as_bytes()) {
                original_headers.remove(&hdr);
            }
        }
        if let Some(h) = &forward_config.header_roles {
            if let Ok(hdr) = header::HeaderName::from_bytes(h.as_bytes()) {
                original_headers.remove(&hdr);
            }
        }
        if let Some(h) = &forward_config.header_client_ip {
            if let Ok(hdr) = header::HeaderName::from_bytes(h.as_bytes()) {
                original_headers.remove(&hdr);
            }
        }
    }

    // 4. Sanitize and manage Forwarded / X-Forwarded-* headers
    // Unconditionally strip client-supplied forwarding headers at the edge proxy to prevent spoofing
    original_headers.remove(&header::HeaderName::from_static("forwarded"));
    original_headers.remove(&header::HeaderName::from_static("x-forwarded-for"));
    original_headers.remove(&header::HeaderName::from_static("x-real-ip"));
    original_headers.remove(&header::HeaderName::from_static("x-forwarded-host"));
    original_headers.remove(&header::HeaderName::from_static("x-forwarded-proto"));

    // Authoritatively set Client IP headers from verified socket / PROXY-v2 address
    if let Some(addr) = extensions.get::<std::net::SocketAddr>() {
        if !addr.ip().is_unspecified() {
            let ip_str = addr.ip().to_string();
            if let Ok(ip_val) = header::HeaderValue::from_str(&ip_str) {
                original_headers.insert("x-real-ip", ip_val.clone());
                original_headers.insert("x-forwarded-for", ip_val);
            }
        }
    }

    // Manage X-Forwarded-Proto (always authoritative from gateway configuration)
    let proto_val = match config.protocol {
        crate::configuration::Protocol::Https => header::HeaderValue::from_static("https"),
        crate::configuration::Protocol::Http => header::HeaderValue::from_static("http"),
    };
    original_headers.insert("x-forwarded-proto", proto_val);

    // Manage X-Forwarded-Host (from Host header if present, or tunnel sni_domain fallback)
    if let Some(host_val) = original_headers.get(header::HOST).cloned() {
        original_headers.insert("x-forwarded-host", host_val);
    } else if let Some(tunnel) = &config.tunnel {
        if let Ok(sni_val) = header::HeaderValue::from_str(&tunnel.sni_domain) {
            original_headers.insert("x-forwarded-host", sni_val);
        }
    }

    // 5. Inject JWT Bearer Token if configured
    if let Some(hv) = jwt_token {
        original_headers.insert(header::AUTHORIZATION, hv.clone());
    }

    // 6. Inject verified client-cert identity headers IF AND ONLY IF client_cert_forwarding is configured
    if let Some(forward_config) = &config.client_cert_forwarding {
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

/// Cleans upstream response headers before sending them back to the client.
///
/// Strips hop-by-hop headers per RFC 7230 §6.1 / RFC 9110 and removes the upstream
/// `Server` header to prevent leaking internal backend implementation details.
pub fn clean_response_headers(headers: &mut hyper::HeaderMap) {
    // 1. Strip headers named in Connection header
    let custom_hops: Vec<header::HeaderName> = if let Some(conn_val) = headers.get(header::CONNECTION) {
        if let Ok(conn_str) = conn_val.to_str() {
            conn_str
                .split(',')
                .filter_map(|h| header::HeaderName::from_bytes(h.trim().as_bytes()).ok())
                .collect()
        } else {
            Vec::new()
        }
    } else {
        Vec::new()
    };
    for h in custom_hops {
        headers.remove(&h);
    }

    // 2. Strip standard hop-by-hop headers
    for h in &HOP_BY_HOP_HEADERS {
        headers.remove(h);
    }

    // 3. Strip internal upstream server identification to avoid information disclosure
    headers.remove(header::SERVER);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use crate::configuration::{
        AuthenticationMethod, ClientCertForwardingConfig, Protocol, UserRole,
    };

    fn make_test_config(forwarding: Option<ClientCertForwardingConfig>) -> ServerConfig {
        ServerConfig {
            name: "test_server".to_string(),
            static_name: Some("test_server"),
            ip: Some("127.0.0.1".to_string()),
            port: Some(8080),
            protocol: Protocol::Https,
            service: crate::configuration::ServiceType::Router,
            enabled: true,
            authentication: AuthenticationMethod::None,
            server_certs: None,
            client_certs: None,
            client_cert_forwarding: forwarding,
            connection_limits: Default::default(),
            router_params: None,
            tunnel: None,
            layers: crate::configuration::Layers::default(),
            rev_routes: None,
            allowed_pathes: None,
            compiled_allowed_pathes: None,
            parsed_routes: Vec::new(),
            oid_mapping: std::collections::HashMap::new(),
            idp_params: None,
            static_files_params: None,
            certified_key: None,
            rbac: None,
            compiled_rbac: None,
        }
    }

    #[test]
    fn test_untrusted_identity_headers_stripped_without_forwarding_config() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-client-cert", header::HeaderValue::from_static("fake-cert"));
        headers.insert("x-client-san", header::HeaderValue::from_static("fake-admin"));
        headers.insert("x-client-roles", header::HeaderValue::from_static("Admin"));
        headers.insert("x-ssl-client-cert", header::HeaderValue::from_static("fake-ssl"));
        headers.insert("x-user-roles", header::HeaderValue::from_static("SuperAdmin"));
        headers.insert("forwarded", header::HeaderValue::from_static("for=1.2.3.4"));

        let config = make_test_config(None);
        let extensions = hyper::http::Extensions::new();

        prepare_proxy_headers(&mut headers, "test_server", None, &extensions, &config).unwrap();

        assert!(!headers.contains_key("x-client-cert"));
        assert!(!headers.contains_key("x-client-san"));
        assert!(!headers.contains_key("x-client-roles"));
        assert!(!headers.contains_key("x-ssl-client-cert"));
        assert!(!headers.contains_key("x-user-roles"));
        assert!(!headers.contains_key("forwarded"));
    }

    #[test]
    fn test_forwarded_headers_and_real_ip_managed() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(header::HOST, header::HeaderValue::from_static("api.example.com"));
        headers.insert("x-forwarded-for", header::HeaderValue::from_static("10.0.0.1"));
        headers.insert("x-forwarded-proto", header::HeaderValue::from_static("http"));
        headers.insert("x-forwarded-host", header::HeaderValue::from_static("evil.com"));

        let config = make_test_config(None);
        let mut extensions = hyper::http::Extensions::new();
        let peer_addr: std::net::SocketAddr = "192.168.1.100:54321".parse().unwrap();
        extensions.insert(peer_addr);

        prepare_proxy_headers(&mut headers, "test_server", None, &extensions, &config).unwrap();

        assert_eq!(headers.get("x-real-ip").unwrap(), "192.168.1.100");
        assert_eq!(headers.get("x-forwarded-for").unwrap(), "192.168.1.100");
        assert_eq!(headers.get("x-forwarded-proto").unwrap(), "https");
        assert_eq!(headers.get("x-forwarded-host").unwrap(), "api.example.com");
    }

    #[test]
    fn test_spoofed_forwarded_host_and_xff_stripped_when_no_host_or_unspecified_ip() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-forwarded-for", header::HeaderValue::from_static("1.2.3.4"));
        headers.insert("x-real-ip", header::HeaderValue::from_static("1.2.3.4"));
        headers.insert("x-forwarded-host", header::HeaderValue::from_static("attacker.tld"));

        let config = make_test_config(None);
        let mut extensions = hyper::http::Extensions::new();
        let unspec_addr: std::net::SocketAddr = "0.0.0.0:0".parse().unwrap();
        extensions.insert(unspec_addr);

        prepare_proxy_headers(&mut headers, "test_server", None, &extensions, &config).unwrap();

        assert!(!headers.contains_key("x-forwarded-for"));
        assert!(!headers.contains_key("x-real-ip"));
        assert!(!headers.contains_key("x-forwarded-host"));
    }

    #[test]
    fn test_client_cert_forwarding_injects_verified_extensions() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-client-cert", header::HeaderValue::from_static("spoofed"));
        headers.insert("x-client-san", header::HeaderValue::from_static("spoofed"));
        headers.insert("x-client-roles", header::HeaderValue::from_static("spoofed"));

        let forwarding = ClientCertForwardingConfig {
            header_cert: Some("x-client-cert".to_string()),
            header_san: Some("x-client-san".to_string()),
            header_roles: Some("x-client-roles".to_string()),
            header_client_ip: Some("x-client-ip".to_string()),
        };
        let config = make_test_config(Some(forwarding));

        let mut extensions = hyper::http::Extensions::new();
        extensions.insert(crate::PemCertExtension("VERIFIED_PEM".to_string()));
        extensions.insert(crate::SanCertExtension("alice@praeco.internal".to_string()));
        extensions.insert(Arc::new(vec![UserRole("Operator".to_string())]));
        let peer_addr: std::net::SocketAddr = "10.10.10.1:12345".parse().unwrap();
        extensions.insert(peer_addr);

        prepare_proxy_headers(&mut headers, "test_server", None, &extensions, &config).unwrap();

        assert_eq!(headers.get("x-client-cert").unwrap(), "VERIFIED_PEM");
        assert_eq!(headers.get("x-client-san").unwrap(), "alice@praeco.internal");
        assert_eq!(headers.get("x-client-roles").unwrap(), "Operator");
        assert_eq!(headers.get("x-client-ip").unwrap(), "10.10.10.1");
    }

    #[test]
    fn test_clean_response_headers_strips_hop_by_hop_and_server() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, header::HeaderValue::from_static("application/json"));
        headers.insert(header::SERVER, header::HeaderValue::from_static("InternalBackend/1.0"));
        headers.insert(header::CONNECTION, header::HeaderValue::from_static("close, X-Upstream-Metric"));
        headers.insert("x-upstream-metric", header::HeaderValue::from_static("42"));
        headers.insert(header::TRANSFER_ENCODING, header::HeaderValue::from_static("chunked"));

        clean_response_headers(&mut headers);

        assert_eq!(headers.get(header::CONTENT_TYPE).unwrap(), "application/json");
        assert!(!headers.contains_key(header::SERVER));
        assert!(!headers.contains_key(header::CONNECTION));
        assert!(!headers.contains_key("x-upstream-metric"));
        assert!(!headers.contains_key(header::TRANSFER_ENCODING));
    }
}
