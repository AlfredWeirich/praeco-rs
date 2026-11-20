use std::collections::HashSet;

use hyper::{Response, StatusCode, header};
use smallvec::SmallVec;
use tracing::warn;

use super::build_error_response;
use crate::{
    ServiceRespBody,
    configuration::{RoleVec, RouteHeaderPolicy, ServerConfig, UserRole},
};

/// Stack-allocated header vector: holds up to `N` (default 6) headers on the stack without heap allocation.
pub type HeaderVec<const N: usize = 6> = SmallVec<[header::HeaderName; N]>;

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

/// Returns `true` if `name` is an untrusted client-identity, certificate-forwarding,
/// or proxy-forwarding header that must be stripped before Praeco injects authoritative values (`S-05`).
fn is_identity_like(name: &header::HeaderName) -> bool {
    let n = name.as_str();
    const PREFIXES: &[&str] = &[
        "x-forwarded-",
        "x-auth-",
        "x-authenticated-",
        "x-remote-",
        "x-user",
        "x-client-",
        "x-ssl-",
        "ssl-client-",
        "x-original-",
        "x-rewrite-",
    ];
    PREFIXES.iter().any(|p| n.starts_with(p))
        || matches!(
            n,
            "forwarded"
                | "x-real-ip"
                | "remote-user"
                | "remote-groups"
                | "remote-email"
                | "true-client-ip"
                | "cf-connecting-ip"
                | "x-cluster-client-ip"
                | "x-auth"
        )
}

/// Returns `true` if `name` matches any custom header name configured in `client_cert_forwarding`.
fn is_configured_cert_forwarding_header(name: &header::HeaderName, config: &ServerConfig) -> bool {
    let Some(fwd) = &config.client_cert_forwarding else {
        return false;
    };
    let n = name.as_str();
    fwd.header_cert.as_deref().is_some_and(|h| h.eq_ignore_ascii_case(n))
        || fwd.header_san.as_deref().is_some_and(|h| h.eq_ignore_ascii_case(n))
        || fwd.header_roles.as_deref().is_some_and(|h| h.eq_ignore_ascii_case(n))
        || fwd.header_client_ip.as_deref().is_some_and(|h| h.eq_ignore_ascii_case(n))
}

/// Returns `true` for HTTP/gRPC wire-framing headers that remain preserved in strict `forward_headers` allowlist mode.
fn is_essential_wire_header(name: &header::HeaderName) -> bool {
    matches!(
        name.as_str(),
        "host"
            | "content-type"
            | "content-length"
            | "content-encoding"
            | "accept-encoding"
            | "te"
            | "grpc-timeout"
            | "grpc-encoding"
            | "grpc-accept-encoding"
    )
}

/// Filters named cookies out of all `Cookie` headers without disturbing remaining application cookies.
fn filter_cookie_header(headers: &mut hyper::HeaderMap, strip_cookie_names: &HashSet<String>) {
    if strip_cookie_names.is_empty() || !headers.contains_key(header::COOKIE) {
        return;
    }

    let (changed, rebuilt) = {
        let mut kept_parts: SmallVec<[&str; 8]> = SmallVec::new();
        let mut changed = false;

        for val in headers.get_all(header::COOKIE) {
            let Ok(raw) = val.to_str() else {
                changed = true;
                continue;
            };
            for part in raw.split(';') {
                let trimmed = part.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let cookie_name = trimmed
                    .split_once('=')
                    .map(|(name, _)| name.trim())
                    .unwrap_or(trimmed);
                if strip_cookie_names.contains(cookie_name) {
                    changed = true;
                } else {
                    kept_parts.push(trimmed);
                }
            }
        }

        let rebuilt = if changed && !kept_parts.is_empty() {
            Some(kept_parts.join("; "))
        } else {
            None
        };
        (changed, rebuilt)
    };

    if !changed {
        return;
    }

    headers.remove(header::COOKIE);
    if let Some(joined) = rebuilt
        && let Ok(hv) = header::HeaderValue::from_str(&joined)
    {
        headers.insert(header::COOKIE, hv);
    }
}

/// Formats an [`std::net::IpAddr`] onto a fixed stack buffer and converts it into a
/// [`header::HeaderValue`] without heap `String` allocation (`P2-05`).
fn ip_addr_to_header_value(ip: std::net::IpAddr) -> Option<header::HeaderValue> {
    use std::io::Write as _;
    let mut buf = [0u8; 64];
    let mut cursor = std::io::Cursor::new(&mut buf[..]);
    write!(cursor, "{ip}").ok()?;
    let len = cursor.position() as usize;
    header::HeaderValue::from_bytes(&buf[..len]).ok()
}

/// Cleans and prepares HTTP headers for upstream forwarding according to the route's [`RouteHeaderPolicy`].
///
/// Security operations performed:
/// 1. Loop detection via `Max-Forwards` across all HTTP methods (stricter than RFC 9110 §7.6.2,
///    which limits `Max-Forwards` to `TRACE`/`OPTIONS`, in order to protect any routed backend against
///    forwarding loops). Rejects unparseable or duplicate `Max-Forwards` values with `400 Bad Request`.
/// 2. Strips hop-by-hop headers per RFC 7230 §6.1 (including custom headers listed in `Connection`).
/// 3. Strips all client-identity and proxy-forwarding headers via prefix/exact matching (`S-05`).
/// 4. Enforces per-route credential isolation (`Authorization` / `Cookie` / `strip_cookie_names`)
///    and optional strict header allowlisting (`forward_headers`).
/// 5. Authoritatively sets `Max-Forwards`, `X-Real-IP`, and `X-Forwarded-*` headers.
/// 6. Injects upstream JWT authorization tokens if configured via `[Server.RouterParams].jwt`.
/// 7. Injects verified mTLS identity headers if (and only if) `client_cert_forwarding` is enabled.
pub fn prepare_proxy_headers(
    original_headers: &mut hyper::HeaderMap,
    server_name: &str,
    jwt_token: Option<&hyper::header::HeaderValue>,
    extensions: &hyper::http::Extensions,
    config: &ServerConfig,
    policy: &RouteHeaderPolicy,
) -> Result<(), Box<Response<ServiceRespBody>>> {
    // 1. Loop Detection across all HTTP methods (gateway policy; RFC 9110 §7.6.2 covers TRACE/OPTIONS).
    //    Reject malformed/duplicate Max-Forwards values with 400 Bad Request instead of resetting to 10.
    let mut max_forwards = 10u8;
    let mut mf_iter = original_headers.get_all(header::MAX_FORWARDS).iter();
    if let Some(mf_val) = mf_iter.next() {
        if mf_iter.next().is_some() {
            warn!("{}: Duplicate Max-Forwards header rejected", server_name);
            return Err(Box::new(build_error_response(
                "Bad Request: Duplicate Max-Forwards header",
                StatusCode::BAD_REQUEST,
            )));
        }
        let Ok(mf_str) = mf_val.to_str() else {
            warn!("{}: Non-UTF-8 Max-Forwards header rejected", server_name);
            return Err(Box::new(build_error_response(
                "Bad Request: Invalid Max-Forwards header",
                StatusCode::BAD_REQUEST,
            )));
        };
        let Ok(mut mf) = mf_str.trim().parse::<u8>() else {
            warn!(
                "{}: Invalid Max-Forwards header value rejected",
                server_name
            );
            return Err(Box::new(build_error_response(
                "Bad Request: Invalid Max-Forwards header",
                StatusCode::BAD_REQUEST,
            )));
        };
        if mf == 0 {
            warn!("{}: Max-Forwards reached 0, Loop Detected!", server_name);
            return Err(Box::new(build_error_response(
                "Loop Detected",
                StatusCode::LOOP_DETECTED,
            )));
        }
        mf -= 1;
        max_forwards = mf;
    }

    // 2. Strip Hop-by-Hop headers (including headers named in all Connection headers, RFC 7230 §6.1),
    //    while protecting essential HTTP/gRPC wire framing headers from being stripped.
    let mut custom_hops: HeaderVec<6> = SmallVec::new();
    for conn_val in original_headers.get_all(header::CONNECTION) {
        if let Ok(conn_str) = conn_val.to_str() {
            for token in conn_str.split(',') {
                if let Ok(hdr_name) = header::HeaderName::from_bytes(token.trim().as_bytes())
                    && !is_essential_wire_header(&hdr_name)
                {
                    custom_hops.push(hdr_name);
                }
            }
        }
    }
    for h in &custom_hops {
        original_headers.remove(h);
    }
    for h in &HOP_BY_HOP_HEADERS {
        original_headers.remove(h);
    }

    // 3. Strip untrusted identity/forwarding headers, credentials (`Authorization`/`Cookie`),
    //    and non-allowlisted headers (when `forward_headers` allowlist is active).
    let allow_client_auth =
        !policy.strip_authorization || policy.preserve_authorization_for_subtargets;
    let allow_client_cookie = !policy.strip_cookies || policy.preserve_cookies_for_subtargets;

    let headers_to_strip: SmallVec<[header::HeaderName; 16]> = original_headers
        .keys()
        .filter(|name| {
            if is_identity_like(name) || is_configured_cert_forwarding_header(name, config) {
                return true;
            }
            let n = name.as_str();
            if n == header::AUTHORIZATION.as_str() {
                return !allow_client_auth;
            }
            if n == header::COOKIE.as_str() {
                return !allow_client_cookie;
            }
            if let Some(allowlist) = &policy.forward_headers {
                return !is_essential_wire_header(name) && !allowlist.contains(n);
            }
            false
        })
        .cloned()
        .collect();
    for h in &headers_to_strip {
        original_headers.remove(h);
    }

    if !policy.strip_cookie_names.is_empty() {
        filter_cookie_header(original_headers, &policy.strip_cookie_names);
    }

    // 4. Authoritatively set Max-Forwards and Client IP / Forwarded headers
    original_headers.insert(
        header::MAX_FORWARDS,
        header::HeaderValue::from(u16::from(max_forwards)),
    );

    let peer_addr = extensions.get::<std::net::SocketAddr>();
    let client_ip_val = peer_addr.and_then(|addr| ip_addr_to_header_value(addr.ip()));
    if let (Some(addr), Some(ip_val)) = (peer_addr, &client_ip_val)
        && !addr.ip().is_unspecified()
    {
        original_headers.insert("x-real-ip", ip_val.clone());
        original_headers.insert("x-forwarded-for", ip_val.clone());
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
    } else if let Some(tunnel) = &config.tunnel
        && let Ok(sni_val) = header::HeaderValue::from_str(&tunnel.sni_domain) {
            original_headers.insert("x-forwarded-host", sni_val);
        }

    // 5. Inject JWT Bearer Token if configured
    if let Some(hv) = jwt_token {
        original_headers.insert(header::AUTHORIZATION, hv.clone());
    }

    // 6. Inject verified client-cert identity headers IF AND ONLY IF client_cert_forwarding is configured
    if let Some(forward_config) = &config.client_cert_forwarding {
        tracing::trace!("Client cert forwarding is ENABLED in config!");
        if let Some(header_cert) = &forward_config.header_cert {
            let encoded_hdr = extensions
                .get::<crate::EncodedPemCertHeaderExtension>()
                .map(|ext| ext.0.clone())
                .or_else(|| {
                    extensions.get::<crate::PemCertExtension>().and_then(|pem| {
                        let pem_escaped = urlencoding::encode(&pem.0);
                        header::HeaderValue::from_str(pem_escaped.as_ref()).ok()
                    })
                });
            if let Some(hdr_val) = encoded_hdr {
                if let Ok(hdr_name) = header::HeaderName::from_bytes(header_cert.as_bytes()) {
                    tracing::trace!("Injecting PEM into header: {}", hdr_name);
                    original_headers.insert(hdr_name, hdr_val);
                }
            } else if extensions.get::<crate::PemCertExtension>().is_some() {
                tracing::warn!("FAILED to convert escaped PEM to HeaderValue");
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
            let roles_slice = extensions
                .get::<std::sync::Arc<RoleVec<6>>>()
                .map(|r| r.as_slice())
                .or_else(|| {
                    extensions
                        .get::<RoleVec<6>>()
                        .map(|r| r.as_slice())
                })
                .or_else(|| {
                    extensions
                        .get::<std::sync::Arc<Vec<UserRole>>>()
                        .map(|r| r.as_slice())
                });
            if let Some(roles) = roles_slice
                && !roles.is_empty() {
                    let roles_str = roles
                        .iter()
                        .map(|r| r.0.as_str())
                        .collect::<SmallVec<[&str; 6]>>()
                        .join(", ");
                    if let Ok(hdr_val) = header::HeaderValue::from_str(&roles_str)
                        && let Ok(hdr_name) = header::HeaderName::from_bytes(header_roles.as_bytes()) {
                            tracing::trace!("Injecting User Roles into header: {}", hdr_name);
                            original_headers.insert(hdr_name, hdr_val);
                        }
                }
        }
        if let Some(header_ip) = &forward_config.header_client_ip
            && let Some(hdr_val) = client_ip_val
            && let Ok(hdr_name) = header::HeaderName::from_bytes(header_ip.as_bytes())
        {
            tracing::trace!("Injecting Client IP into header: {}", hdr_name);
            original_headers.insert(hdr_name, hdr_val);
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
    // 1. Strip headers named in all Connection headers (preserving essential wire headers)
    let mut custom_hops: HeaderVec<6> = SmallVec::new();
    for conn_val in headers.get_all(header::CONNECTION) {
        if let Ok(conn_str) = conn_val.to_str() {
            for token in conn_str.split(',') {
                if let Ok(hdr_name) = header::HeaderName::from_bytes(token.trim().as_bytes())
                    && !is_essential_wire_header(&hdr_name)
                {
                    custom_hops.push(hdr_name);
                }
            }
        }
    }
    for h in &custom_hops {
        headers.remove(h);
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
            metrics: Default::default(),
            pki_info: Default::default(),
            ..Default::default()
        }
    }

    #[test]
    fn test_untrusted_identity_headers_stripped_without_forwarding_config() {
        let mut headers = hyper::HeaderMap::new();
        for name in [
            "x-client-cert",
            "x-client-san",
            "x-client-roles",
            "x-ssl-client-cert",
            "x-user-roles",
            "forwarded",
            "x-forwarded-user",
            "x-forwarded-email",
            "x-forwarded-groups",
            "x-remote-user",
            "remote-user",
            "x-user-id",
            "x-user",
            "x-auth-request-user",
            "x-auth-request-email",
            "x-authenticated-user",
            "true-client-ip",
            "cf-connecting-ip",
            "x-forwarded-port",
            "x-forwarded-prefix",
            "x-original-url",
            "x-rewrite-url",
        ] {
            headers.insert(
                header::HeaderName::from_bytes(name.as_bytes()).unwrap(),
                header::HeaderValue::from_static("spoofed"),
            );
        }

        let config = make_test_config(None);
        let extensions = hyper::http::Extensions::new();
        let policy = RouteHeaderPolicy::default();

        prepare_proxy_headers(
            &mut headers,
            "test_server",
            None,
            &extensions,
            &config,
            &policy,
        )
        .unwrap();

        for name in [
            "x-client-cert",
            "x-client-san",
            "x-client-roles",
            "x-ssl-client-cert",
            "x-user-roles",
            "forwarded",
            "x-forwarded-user",
            "x-forwarded-email",
            "x-forwarded-groups",
            "x-remote-user",
            "remote-user",
            "x-user-id",
            "x-user",
            "x-auth-request-user",
            "x-auth-request-email",
            "x-authenticated-user",
            "true-client-ip",
            "cf-connecting-ip",
            "x-forwarded-port",
            "x-forwarded-prefix",
            "x-original-url",
            "x-rewrite-url",
        ] {
            assert!(
                !headers.contains_key(name),
                "identity header '{name}' must be stripped"
            );
        }
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
        let policy = RouteHeaderPolicy::default();

        prepare_proxy_headers(
            &mut headers,
            "test_server",
            None,
            &extensions,
            &config,
            &policy,
        )
        .unwrap();

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
        let policy = RouteHeaderPolicy::default();

        prepare_proxy_headers(
            &mut headers,
            "test_server",
            None,
            &extensions,
            &config,
            &policy,
        )
        .unwrap();

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
        extensions.insert(crate::PemCertExtension::from("VERIFIED_PEM"));
        extensions.insert(crate::SanCertExtension::from("alice@praeco.internal"));
        extensions.insert(Arc::new(vec![UserRole("Operator".to_string())]));
        let peer_addr: std::net::SocketAddr = "10.10.10.1:12345".parse().unwrap();
        extensions.insert(peer_addr);
        let policy = RouteHeaderPolicy::default();

        prepare_proxy_headers(
            &mut headers,
            "test_server",
            None,
            &extensions,
            &config,
            &policy,
        )
        .unwrap();

        assert_eq!(headers.get("x-client-cert").unwrap(), "VERIFIED_PEM");
        assert_eq!(headers.get("x-client-san").unwrap(), "alice@praeco.internal");
        assert_eq!(headers.get("x-client-roles").unwrap(), "Operator");
        assert_eq!(headers.get("x-client-ip").unwrap(), "10.10.10.1");
    }

    #[test]
    fn test_default_policy_strips_authorization_and_cookie_unless_router_jwt_set() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            header::HeaderValue::from_static("Bearer gateway-user-jwt"),
        );
        headers.insert(
            header::COOKIE,
            header::HeaderValue::from_static("admin-jwt=secret; app_sid=abc"),
        );
        headers.insert("x-request-id", header::HeaderValue::from_static("req-123"));

        let config = make_test_config(None);
        let extensions = hyper::http::Extensions::new();
        let policy = RouteHeaderPolicy::default();

        prepare_proxy_headers(
            &mut headers,
            "test_server",
            None,
            &extensions,
            &config,
            &policy,
        )
        .unwrap();

        assert!(!headers.contains_key(header::AUTHORIZATION));
        assert!(!headers.contains_key(header::COOKIE));
        assert_eq!(headers.get("x-request-id").unwrap(), "req-123");

        // When RouterParams.jwt is configured, authoritative backend JWT is injected
        let mut headers_with_jwt = hyper::HeaderMap::new();
        headers_with_jwt.insert(
            header::AUTHORIZATION,
            header::HeaderValue::from_static("Bearer client-jwt"),
        );
        let upstream_jwt = header::HeaderValue::from_static("Bearer upstream-service-jwt");
        prepare_proxy_headers(
            &mut headers_with_jwt,
            "test_server",
            Some(&upstream_jwt),
            &extensions,
            &config,
            &policy,
        )
        .unwrap();
        assert_eq!(
            headers_with_jwt.get(header::AUTHORIZATION).unwrap(),
            "Bearer upstream-service-jwt"
        );
    }

    #[test]
    fn test_selective_cookie_and_authorization_forwarding() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            header::HeaderValue::from_static("Bearer forwarded-client-token"),
        );
        headers.append(
            header::COOKIE,
            header::HeaderValue::from_static("theme=dark; admin-jwt=topsecret"),
        );
        headers.append(
            header::COOKIE,
            header::HeaderValue::from_static("csrf=xyz; extra_secret=nope"),
        );

        let config = make_test_config(None);
        let extensions = hyper::http::Extensions::new();
        let mut strip_names = HashSet::new();
        strip_names.insert("admin-jwt".to_string());
        strip_names.insert("extra_secret".to_string());

        let policy = RouteHeaderPolicy {
            strip_authorization: false,
            strip_cookies: false,
            strip_cookie_names: strip_names.clone(),
            forward_headers: None,
            preserve_authorization_for_subtargets: false,
            preserve_cookies_for_subtargets: false,
        };

        prepare_proxy_headers(
            &mut headers,
            "test_server",
            None,
            &extensions,
            &config,
            &policy,
        )
        .unwrap();

        assert_eq!(
            headers.get(header::AUTHORIZATION).unwrap(),
            "Bearer forwarded-client-token"
        );
        assert_eq!(headers.get(header::COOKIE).unwrap(), "theme=dark; csrf=xyz");

        // If all cookies match strip_cookie_names, the Cookie header is removed completely
        let mut only_secret = hyper::HeaderMap::new();
        only_secret.insert(
            header::COOKIE,
            header::HeaderValue::from_static("admin-jwt=topsecret"),
        );
        prepare_proxy_headers(
            &mut only_secret,
            "test_server",
            None,
            &extensions,
            &config,
            &policy,
        )
        .unwrap();
        assert!(!only_secret.contains_key(header::COOKIE));
    }

    #[test]
    fn test_forward_headers_allowlist_drops_unlisted_headers_and_preserves_wire_headers() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(header::HOST, header::HeaderValue::from_static("api.example.com"));
        headers.insert(
            header::CONTENT_TYPE,
            header::HeaderValue::from_static("application/json"),
        );
        headers.insert("x-request-id", header::HeaderValue::from_static("req-42"));
        headers.insert("x-custom-secret", header::HeaderValue::from_static("leak"));
        headers.insert(
            header::USER_AGENT,
            header::HeaderValue::from_static("curl/8.0"),
        );
        headers.insert("x-forwarded-user", header::HeaderValue::from_static("evil"));

        let config = make_test_config(None);
        let mut extensions = hyper::http::Extensions::new();
        extensions.insert::<std::net::SocketAddr>("192.0.2.5:1234".parse().unwrap());

        let mut allowlist = HashSet::new();
        allowlist.insert("x-request-id".to_string());
        // Even if misconfigured with an identity header, is_identity_like always takes precedence
        allowlist.insert("x-forwarded-user".to_string());

        let policy = RouteHeaderPolicy {
            strip_authorization: true,
            strip_cookies: true,
            strip_cookie_names: HashSet::new(),
            forward_headers: Some(allowlist),
            preserve_authorization_for_subtargets: false,
            preserve_cookies_for_subtargets: false,
        };

        prepare_proxy_headers(
            &mut headers,
            "test_server",
            None,
            &extensions,
            &config,
            &policy,
        )
        .unwrap();

        assert_eq!(headers.get(header::HOST).unwrap(), "api.example.com");
        assert_eq!(headers.get(header::CONTENT_TYPE).unwrap(), "application/json");
        assert_eq!(headers.get("x-request-id").unwrap(), "req-42");
        assert!(headers.contains_key(header::MAX_FORWARDS));
        assert_eq!(headers.get("x-real-ip").unwrap(), "192.0.2.5");
        assert_eq!(headers.get("x-forwarded-proto").unwrap(), "https");
        assert!(!headers.contains_key("x-custom-secret"));
        assert!(!headers.contains_key(header::USER_AGENT));
        assert!(!headers.contains_key("x-forwarded-user"));
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

    #[test]
    fn test_max_forwards_validation_decrement_and_loop_detection() {
        let config = make_test_config(None);
        let extensions = hyper::http::Extensions::new();
        let policy = RouteHeaderPolicy::default();

        // Valid Max-Forwards is decremented
        let mut h_ok = hyper::HeaderMap::new();
        h_ok.insert(header::MAX_FORWARDS, header::HeaderValue::from_static("3"));
        prepare_proxy_headers(&mut h_ok, "test_server", None, &extensions, &config, &policy)
            .unwrap();
        assert_eq!(h_ok.get(header::MAX_FORWARDS).unwrap(), "2");

        // Zero returns 508 Loop Detected
        let mut h_zero = hyper::HeaderMap::new();
        h_zero.insert(header::MAX_FORWARDS, header::HeaderValue::from_static("0"));
        let err_zero =
            prepare_proxy_headers(&mut h_zero, "test_server", None, &extensions, &config, &policy)
                .unwrap_err();
        assert_eq!(err_zero.status(), StatusCode::LOOP_DETECTED);

        // Out-of-range ("300") and non-numeric ("abc") return 400 Bad Request
        for invalid in ["300", "abc"] {
            let mut h_bad = hyper::HeaderMap::new();
            h_bad.insert(header::MAX_FORWARDS, header::HeaderValue::from_static(invalid));
            let err_bad = prepare_proxy_headers(
                &mut h_bad,
                "test_server",
                None,
                &extensions,
                &config,
                &policy,
            )
            .unwrap_err();
            assert_eq!(err_bad.status(), StatusCode::BAD_REQUEST);
        }

        // Duplicate Max-Forwards headers return 400 Bad Request
        let mut h_dup = hyper::HeaderMap::new();
        h_dup.append(header::MAX_FORWARDS, header::HeaderValue::from_static("5"));
        h_dup.append(header::MAX_FORWARDS, header::HeaderValue::from_static("4"));
        let err_dup =
            prepare_proxy_headers(&mut h_dup, "test_server", None, &extensions, &config, &policy)
                .unwrap_err();
        assert_eq!(err_dup.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn test_multiple_connection_headers_strip_custom_hops_and_preserve_essential_wire_headers() {
        let config = make_test_config(None);
        let extensions = hyper::http::Extensions::new();
        let policy = RouteHeaderPolicy::default();

        let mut headers = hyper::HeaderMap::new();
        headers.insert(header::HOST, header::HeaderValue::from_static("api.example.com"));
        headers.insert(header::CONTENT_TYPE, header::HeaderValue::from_static("application/json"));
        headers.insert(header::CONTENT_LENGTH, header::HeaderValue::from_static("12"));
        headers.insert("x-hop-one", header::HeaderValue::from_static("1"));
        headers.insert("x-hop-two", header::HeaderValue::from_static("2"));
        headers.append(header::CONNECTION, header::HeaderValue::from_static("x-hop-one, host"));
        headers.append(
            header::CONNECTION,
            header::HeaderValue::from_static("x-hop-two, content-length, content-type"),
        );

        let res = prepare_proxy_headers(
            &mut headers,
            "test_server",
            None,
            &extensions,
            &config,
            &policy,
        );
        assert!(res.is_ok());
        assert!(!headers.contains_key("x-hop-one"));
        assert!(!headers.contains_key("x-hop-two"));
        assert!(headers.contains_key(header::HOST));
        assert!(headers.contains_key(header::CONTENT_TYPE));
        assert!(headers.contains_key(header::CONTENT_LENGTH));
    }

    #[test]
    fn test_prepare_proxy_headers_prefers_preencoded_pem_and_reuses_ip_value()
    -> Result<(), Box<dyn std::error::Error>> {
        let forwarding = ClientCertForwardingConfig {
            header_cert: Some("x-client-cert".to_string()),
            header_san: None,
            header_roles: None,
            header_client_ip: Some("x-client-ip".to_string()),
        };
        let config = make_test_config(Some(forwarding));
        let policy = RouteHeaderPolicy::default();

        // 1. Pre-encoded PEM extension is used directly, and IPv6 populates all 3 IP headers
        let mut headers = hyper::HeaderMap::new();
        let mut extensions = hyper::http::Extensions::new();
        extensions.insert(crate::PemCertExtension::from("RAW_SHOULD_NOT_BE_REENCODED"));
        extensions.insert(crate::EncodedPemCertHeaderExtension(
            header::HeaderValue::from_static("PRE_ENCODED_PEM%0A"),
        ));
        let ipv6_addr: std::net::SocketAddr = "[2001:db8::1]:8443".parse()?;
        extensions.insert(ipv6_addr);

        prepare_proxy_headers(&mut headers, "test_server", None, &extensions, &config, &policy)
            .map_err(|resp| format!("unexpected error status: {}", resp.status()))?;

        assert_eq!(headers.get("x-client-cert").and_then(|v| v.to_str().ok()), Some("PRE_ENCODED_PEM%0A"));
        assert_eq!(headers.get("x-real-ip").and_then(|v| v.to_str().ok()), Some("2001:db8::1"));
        assert_eq!(headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()), Some("2001:db8::1"));
        assert_eq!(headers.get("x-client-ip").and_then(|v| v.to_str().ok()), Some("2001:db8::1"));

        // 2. Unspecified peer IP omits x-real-ip / x-forwarded-for while still setting header_client_ip
        let mut unspec_headers = hyper::HeaderMap::new();
        let mut unspec_ext = hyper::http::Extensions::new();
        let unspec_addr: std::net::SocketAddr = "0.0.0.0:1234".parse()?;
        unspec_ext.insert(unspec_addr);
        prepare_proxy_headers(&mut unspec_headers, "test_server", None, &unspec_ext, &config, &policy)
            .map_err(|resp| format!("unexpected error status: {}", resp.status()))?;

        assert!(!unspec_headers.contains_key("x-real-ip"));
        assert!(!unspec_headers.contains_key("x-forwarded-for"));
        assert_eq!(unspec_headers.get("x-client-ip").and_then(|v| v.to_str().ok()), Some("0.0.0.0"));

        // 3. Fallback URL-encodes raw PemCertExtension when pre-encoded extension is absent
        let mut fallback_headers = hyper::HeaderMap::new();
        let mut fallback_ext = hyper::http::Extensions::new();
        fallback_ext.insert(crate::PemCertExtension::from("LINE1\nLINE2"));
        prepare_proxy_headers(
            &mut fallback_headers,
            "test_server",
            None,
            &fallback_ext,
            &config,
            &policy,
        )
        .map_err(|resp| format!("unexpected error status: {}", resp.status()))?;
        assert_eq!(
            fallback_headers.get("x-client-cert").and_then(|v| v.to_str().ok()),
            Some("LINE1%0ALINE2")
        );
        Ok(())
    }
}
