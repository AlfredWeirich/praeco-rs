#![cfg_attr(all(not(test), not(feature = "test-pki")), deny(clippy::unwrap_used, clippy::expect_used))]
//! # Common Utilities Crate
//!
//! Shared types and helper functions used by both the server and client
//! crates. This crate has **no runtime dependencies** on the server and can be
//! compiled independently.
//!
//! ## Contents
//!
//! | Item | Purpose |
//! |------|---------|
//! | [`load_certs`] | Load PEM-encoded X.509 certificates from disk. |
//! | [`load_single_key`] | Load a single private key (PKCS#1/8, SEC1). |
//! | [`load_decoding_keys`] | Load Ed25519 public keys for JWT verification. |
//! | [`verify_jwt`] | Verify a JWT token against multiple keys (rotation support). |
//! | [`Claims`] | The JWT payload structure (subject, expiration, OIDs). |
//! | [`build_tls_client_config`] | Build a Rustls `ClientConfig` (with optional mTLS). |
//! | [`build_root_store`] | Build a `RootCertStore` from system + custom CAs. |

// === External Crates ===
#[cfg(any(feature = "tls", feature = "jwt"))]
use anyhow::{Context, Error};
#[cfg(feature = "tls")]
use anyhow::anyhow;
#[cfg(feature = "jwt")]
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode};
#[cfg(feature = "tls")]
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
};
#[cfg(feature = "jwt")]
use serde::{Deserialize, Serialize};

// Note: tracing 'info' was unused, so it was removed.

#[cfg(feature = "crl")]
pub mod crl;
#[cfg(any(test, feature = "test-pki"))]
pub mod test_pki;

/// Loads a list of DER-encoded certificates from a PEM file.
///
/// Reads the file at `path`, parses every `-----BEGIN CERTIFICATE-----` block,
/// and returns the decoded certificates.
///
/// # Arguments
///
/// * `path` – File path to a PEM-encoded certificate chain.
/// * `server_name` – Label for error context.
///
/// # Errors
///
/// Returns an error if the file cannot be read, contains invalid PEM data,
/// or contains no certificates.
#[cfg(feature = "tls")]
pub fn load_certs(path: &str, server_name: &str) -> Result<Vec<CertificateDer<'static>>, Error> {
    let data = std::fs::read(path)
        .with_context(|| format!("{server_name}: Failed to read certificate file '{path}'"))?;

    let certs = CertificateDer::pem_slice_iter(&data)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("{server_name}: Invalid certificate in '{path}'"))?;

    if certs.is_empty() {
        return Err(anyhow!("{server_name}: No certificates found in '{path}'"));
    }

    Ok(certs)
}

/// Loads a single private key from a PEM file.
///
/// Supports **PKCS#1** (RSA), **PKCS#8** (generic), and **SEC1** (EC)
/// key formats. The first recognised key item in the file is returned.
///
/// # Arguments
///
/// * `path` – File path to the PEM-encoded private key.
/// * `server_name` – Label for error context.
///
/// # Errors
///
/// Returns an error if the file cannot be opened, contains no recognised key, or
/// has a PEM parse error.
#[cfg(feature = "tls")]
pub fn load_single_key(path: &str, server_name: &str) -> Result<PrivateKeyDer<'static>, Error> {
    match PrivateKeyDer::from_pem_file(path) {
        Ok(key) => Ok(key),
        Err(rustls::pki_types::pem::Error::NoItemsFound) => {
            Err(anyhow!("{server_name}: No private key found in '{path}'"))
        }
        Err(rustls::pki_types::pem::Error::Io(e)) => {
            Err(e).with_context(|| format!("{server_name}: Cannot open key file '{path}'"))
        }
        Err(e) => Err(anyhow!(
            "{server_name}: PEM parse error in '{path}': {e}"
        )),
    }
}

/// JWT Claims payload for authentication and authorization.
///
/// This structure is serialized into / deserialized from the JWT body.
/// The `oids` field carries custom OID suffixes extracted from the
/// signing identity, which are later mapped to [`UserRole`](crate)
/// values by the server.
#[cfg(feature = "jwt")]
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Claims {
    /// Subject identifier (usually user ID or account ID).
    pub sub: String,
    /// Issuer of the JWT.
    pub iss: String,
    /// Optional Audience of the JWT.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    /// Expiration time as a UNIX timestamp (seconds since epoch).
    pub exp: usize,
    /// Custom OID suffixes for role mapping (e.g. `["1", "2.3"]`).
    pub oids: Vec<String>,
    /// Optional JWT ID (for revocation, e.g. QR code sessions).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

/// Loads Ed25519 public key files and converts them into [`DecodingKey`]s.
///
/// Used by the JWT authentication layer to support **key rotation**: the
/// server can hold multiple valid keys simultaneously, and any one of them
/// can verify an incoming token.
///
/// # Arguments
///
/// * `key_paths` – Slice of PEM file paths, each containing an Ed25519
///   public key.
///
/// # Errors
///
/// Returns an error if any file cannot be read or is not a valid Ed25519 PEM.
#[cfg(feature = "jwt")]
pub fn load_decoding_keys(key_paths: &[String]) -> Result<Vec<DecodingKey>, Error> {
    let mut keys = Vec::with_capacity(key_paths.len());
    for path in key_paths {
        let pem = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read JWT public key file: '{path}'"))?;
        let key = DecodingKey::from_ed_pem(pem.as_bytes())
            .with_context(|| format!("Failed to parse JWT public key in '{path}'"))?;
        keys.push(key);
    }
    Ok(keys)
}

/// Loads an Ed25519 private key file and converts it into an [`EncodingKey`].
///
/// Used by the JWT IdP layer to sign new tokens.
///
/// # Arguments
///
/// * `path` – PEM file path containing an Ed25519 private key.
///
/// # Errors
///
/// Returns an error if the file cannot be read or is not a valid Ed25519 PEM.
#[cfg(feature = "jwt")]
pub fn load_encoding_key(path: &str) -> Result<EncodingKey, Error> {
    let pem = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read private key file: '{path}'"))?;
    let key = EncodingKey::from_ed_pem(pem.as_bytes())
        .with_context(|| format!("Failed to parse private key in '{path}'"))?;
    Ok(key)
}

/// Maximum allowed serialized JWT length in bytes (4 KiB) to reject oversized
/// payloads before base64 decoding or Ed25519 signature verification ([P-01]).
#[cfg(feature = "jwt")]
pub const MAX_JWT_TOKEN_LEN: usize = 4096;

/// Default maximum allowed remaining JWT lifetime (`exp - now`) in seconds (30 days, [S-06]).
#[cfg(feature = "jwt")]
pub const DEFAULT_MAX_JWT_LIFETIME_SECS: u64 = 30 * 24 * 3600;

/// Maximum allowed `jti` claim length in bytes.
#[cfg(feature = "jwt")]
const MAX_JTI_CLAIM_LEN: usize = 256;

/// Clock-skew leeway in seconds applied to the upper token lifetime bound check.
#[cfg(feature = "jwt")]
const JWT_LIFETIME_LEEWAY_SECS: u64 = 60;

/// Policy options for JWT verification ([`verify_jwt_with_options`]).
#[cfg(feature = "jwt")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JwtVerifyOptions {
    /// Whether a non-empty `jti` claim is mandatory (default: `true`).
    ///
    /// Enforcing `jti` ensures issued tokens can be revoked via the `jti` denylist.
    pub require_jti: bool,
    /// Maximum allowed remaining token lifetime (`exp - now`) in seconds.
    ///
    /// Defaults to `Some(DEFAULT_MAX_JWT_LIFETIME_SECS)` (30 days).
    /// Set to `None` to disable the upper lifetime bound.
    pub max_token_lifetime_secs: Option<u64>,
}

#[cfg(feature = "jwt")]
impl Default for JwtVerifyOptions {
    fn default() -> Self {
        Self {
            require_jti: true,
            max_token_lifetime_secs: Some(DEFAULT_MAX_JWT_LIFETIME_SECS),
        }
    }
}

/// Verifies a JWT token against a set of decoding keys using default policy options
/// ([`JwtVerifyOptions::default()`]: mandatory `jti` and a 30-day maximum lifetime).
///
/// Tries the key selected by the JWS header `kid` (`"praeco-key-<1-based-index>"`)
/// when present, or each key in order when no `kid` is set.
///
/// # Algorithm
///
/// Strictly enforces **EdDSA** (Ed25519).
///
/// # Errors
///
/// Returns an error if the token exceeds [`MAX_JWT_TOKEN_LEN`], has a malformed
/// compact JWS structure, specifies an unknown `kid`, misses required claims
/// (`exp`, `iss`, `aud`, `sub`, and `jti`), exceeds the maximum lifetime policy,
/// or fails signature verification.
#[cfg(feature = "jwt")]
pub fn verify_jwt(
    token: &str,
    decoding_keys: &[DecodingKey],
    expected_issuer: &str,
    expected_audience: &str,
) -> Result<Claims, Error> {
    verify_jwt_with_options(
        token,
        decoding_keys,
        expected_issuer,
        expected_audience,
        JwtVerifyOptions::default(),
    )
}

/// Verifies a JWT token against a set of decoding keys with explicit [`JwtVerifyOptions`].
#[cfg(feature = "jwt")]
pub fn verify_jwt_with_options(
    token: &str,
    decoding_keys: &[DecodingKey],
    expected_issuer: &str,
    expected_audience: &str,
    options: JwtVerifyOptions,
) -> Result<Claims, Error> {
    if token.is_empty() || token.len() > MAX_JWT_TOKEN_LEN {
        return Err(Error::msg(
            "JWT verification failed: token length out of bounds",
        ));
    }

    let mut segments = token.split('.');
    let (Some(h), Some(p), Some(s), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return Err(Error::msg(
            "JWT verification failed: malformed compact JWS structure",
        ));
    };
    if h.is_empty() || p.is_empty() || s.is_empty() {
        return Err(Error::msg("JWT verification failed: empty JWS segment"));
    }

    if decoding_keys.is_empty() {
        return Err(Error::msg(
            "JWT verification failed: no decoding keys configured",
        ));
    }

    let iss_list: Vec<&str> = expected_issuer
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    if iss_list.is_empty() {
        return Err(Error::msg(
            "JWT verification failed: expected_issuer must not be empty",
        ));
    }

    let aud_list: Vec<&str> = expected_audience
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    if aud_list.is_empty() {
        return Err(Error::msg(
            "JWT verification failed: expected_audience must not be empty",
        ));
    }

    let header = decode_header(token)
        .map_err(|_| Error::msg("JWT verification failed: invalid JWS header"))?;
    if header.alg != jsonwebtoken::Algorithm::EdDSA {
        return Err(Error::msg(
            "JWT verification failed: unsupported algorithm",
        ));
    }

    // If the token header specifies a `kid` of the form `"praeco-key-<N>"`,
    // route directly to the 1-based key slot (O(1) single-key verification).
    // Fail fast if `<N>` is out of range or malformed.
    let candidate_keys: &[DecodingKey] = match header.kid.as_deref() {
        Some(kid) => {
            if let Some(idx_str) = kid.strip_prefix("praeco-key-") {
                let idx = idx_str
                    .parse::<usize>()
                    .ok()
                    .filter(|&i| i >= 1 && i <= decoding_keys.len())
                    .ok_or_else(|| {
                        Error::msg("JWT verification failed: unknown key ID (kid)")
                    })?;
                &decoding_keys[idx - 1..idx]
            } else {
                decoding_keys
            }
        }
        None => decoding_keys,
    };

    let mut validation = Validation::new(jsonwebtoken::Algorithm::EdDSA);
    validation.set_issuer(&iss_list);
    validation.set_audience(&aud_list);
    validation.validate_nbf = true;
    if options.require_jti {
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub", "jti"]);
    } else {
        validation.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
    }

    let mut verified_claims: Option<Claims> = None;
    for key in candidate_keys {
        if let Ok(data) = decode::<Claims>(token, key, &validation) {
            verified_claims = Some(data.claims);
            break;
        }
    }

    let claims =
        verified_claims.ok_or_else(|| Error::msg("JWT verification failed with all keys"))?;

    if claims.sub.trim().is_empty() {
        return Err(Error::msg(
            "JWT verification failed: subject (sub) must not be empty",
        ));
    }

    if options.require_jti {
        let valid_jti = claims
            .jti
            .as_deref()
            .is_some_and(|jti| !jti.trim().is_empty() && jti.len() <= MAX_JTI_CLAIM_LEN);
        if !valid_jti {
            return Err(Error::msg(
                "JWT verification failed: missing or invalid jti claim",
            ));
        }
    }

    if let Some(max_lifetime_secs) = options.max_token_lifetime_secs {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let remaining = (claims.exp as u64).saturating_sub(now);
        if remaining > max_lifetime_secs.saturating_add(JWT_LIFETIME_LEEWAY_SECS) {
            return Err(Error::msg(
                "JWT verification failed: token lifetime exceeds maximum policy",
            ));
        }
    }

    Ok(claims)
}

/// Signs a JWT token with the given `Claims` and `EncodingKey`.
/// Signs a JWT token with the given `Claims` and `EncodingKey`.
///
/// # Algorithm
///
/// Hard-coded to **EdDSA** (Ed25519) with `kid: "praeco-key-1"`.
///
/// # Errors
///
/// Returns an error if token signing fails.
#[cfg(feature = "jwt")]
pub fn sign_jwt(claims: &Claims, encoding_key: &EncodingKey) -> Result<String, Error> {
    sign_jwt_with_kid(claims, encoding_key, Some("praeco-key-1"))
}

/// Signs a JWT token with the given `Claims`, `EncodingKey`, and optional Key ID (`kid`).
#[cfg(feature = "jwt")]
pub fn sign_jwt_with_kid(
    claims: &Claims,
    encoding_key: &EncodingKey,
    kid: Option<&str>,
) -> Result<String, Error> {
    let mut header = Header::new(jsonwebtoken::Algorithm::EdDSA);
    header.kid = kid.map(|s| s.to_string());
    let token = encode(&header, claims, encoding_key)
        .map_err(|e| Error::msg(format!("Failed to sign JWT: {}", e)))?;
    Ok(token)
}

/// Builds a Rustls [`ClientConfig`] for outgoing TLS connections.
///
/// # Arguments
///
/// * `root_store` – Trusted CA certificates for server verification.
/// * `cert` – Optional path to a client certificate (for mTLS).
/// * `key` – Optional path to a client private key (for mTLS).
///
/// If **both** `cert` and `key` are `Some`, mTLS client authentication is
/// configured. Otherwise, the client connects without presenting a certificate.
///
/// # Errors
///
/// Returns an error if client certificates or private keys cannot be loaded or parsed.
#[cfg(feature = "tls")]
pub fn build_tls_client_config(
    root_store: RootCertStore,
    cert: Option<&str>,
    key: Option<&str>,
) -> Result<ClientConfig, Error> {
    match (cert, key) {
        (Some(cert_path), Some(key_path)) => {
            // mTLS: load client cert chain + private key
            let certs = load_certs(cert_path, "mtlsclient")?;
            let key = load_single_key(key_path, "mtlsclient")?;
            ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_client_auth_cert(certs, key)
                .map_err(|e| anyhow!("Failed to build client TLS config: {e}"))
        }
        // No client auth — standard TLS
        _ => Ok(ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()),
    }
}

/// Builds a [`RootCertStore`] containing the system-wide WebPKI roots plus
/// an optional custom CA certificate.
///
/// Builds a `RootCertStore` for TLS client configurations.
///
/// # Security (S-17: Strict PKI Isolation)
///
/// * When `ca_path` is `Some(path)`, a strict, isolated trust store is created
///   containing **only** the custom CA certificates loaded from that file. This
///   enforces private PKI pinning and prevents rogue/commercial WebPKI certificates
///   from being accepted for internal upstreams or webhooks.
/// * When `ca_path` is `None`, the trust store defaults to well-known public
///   WebPKI root certificates (`webpki_roots`).
///
/// # Arguments
///
/// * `ca_path` – Optional path to a PEM file with trusted CA certificates
///   (e.g. self-signed CAs used in internal environments).
///
/// # Errors
///
/// Returns an error if the custom CA certificate file cannot be read or parsed.
#[cfg(feature = "tls")]
pub fn build_root_store(ca_path: &Option<String>) -> Result<RootCertStore, Error> {
    let mut root_store = RootCertStore::empty();
    if let Some(path) = ca_path {
        // Enforce strict private PKI isolation: only trust the configured custom CA!
        let root_cert = load_certs(path, "root_store")?;
        root_store.add_parsable_certificates(root_cert);
    } else {
        // No custom CA configured: fall back to well-known WebPKI roots for public internet
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    Ok(root_store)
}

/// Builds a `RootCertStore` containing both public WebPKI roots and an optional custom CA.
#[cfg(feature = "tls")]
pub fn build_root_store_with_webpki(ca_path: &Option<String>) -> Result<RootCertStore, Error> {
    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    if let Some(path) = ca_path {
        let root_cert = load_certs(path, "root_store")?;
        root_store.add_parsable_certificates(root_cert);
    }
    Ok(root_store)
}
/// Canonicalizes a client IP address for rate-limiting and connection-tracking:
/// - IPv4 addresses remain unchanged.
/// - IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are unwrapped to their IPv4 address.
/// - Loopback (`::1`) and unspecified (`::`) IPv6 addresses remain unchanged.
/// - All other IPv6 addresses are masked to their `/64` subnet prefix so that a single
///   residential/cloud `/64` allocation cannot bypass per-IP limits or exhaust rate-limit tables.
pub fn canonical_client_ip(ip: std::net::IpAddr) -> std::net::IpAddr {
    match ip {
        std::net::IpAddr::V4(v4) => std::net::IpAddr::V4(v4),
        std::net::IpAddr::V6(v6) => {
            if let Some(mapped_v4) = v6.to_ipv4_mapped() {
                return std::net::IpAddr::V4(mapped_v4);
            }
            if v6.is_loopback() || v6.is_unspecified() {
                return std::net::IpAddr::V6(v6);
            }
            let segs = v6.segments();
            std::net::IpAddr::V6(std::net::Ipv6Addr::new(
                segs[0], segs[1], segs[2], segs[3], 0, 0, 0, 0,
            ))
        }
    }
}

/// Extracts the client IP address from an `X-Forwarded-For` header value by
/// walking from the **right** and skipping `trusted_hops - 1` trusted proxy entries.
///
/// Reverse proxies append entries to the right of `X-Forwarded-For`, making the
/// leftmost entries client-controlled and easily spoofed. Walking from the right
/// ensures only entries appended by trusted proxies are honored.
///
/// Returns `None` if `trusted_hops == 0`, if the header has fewer than
/// `trusted_hops` entries, if the selected entry cannot be parsed as an `IpAddr`,
/// or if the parsed IP is unspecified (`0.0.0.0` or `::`).
pub fn client_ip_from_xff(header: &str, trusted_hops: usize) -> Option<std::net::IpAddr> {
    if trusted_hops == 0 {
        return None;
    }
    header
        .rsplit(',')
        .map(str::trim)
        .nth(trusted_hops - 1)
        .and_then(|s| s.parse::<std::net::IpAddr>().ok())
        .filter(|ip| !ip.is_unspecified())
}

#[cfg(feature = "client")]
pub mod client;
pub mod proxy_protocol;

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "tls")]
    #[test]
    fn test_load_certs_nonexistent_file_returns_err() {
        let res = load_certs("nonexistent_cert_path_12345.pem", "test_server");
        assert!(res.is_err());
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_load_single_key_nonexistent_file_returns_err() {
        let res = load_single_key("nonexistent_key_path_12345.pem", "test_server");
        assert!(res.is_err());
    }

    #[cfg(feature = "jwt")]
    #[test]
    fn test_load_decoding_keys_nonexistent_file_returns_err() {
        let res = load_decoding_keys(&["nonexistent_jwt_key_12345.pem".to_string()]);
        assert!(res.is_err());
    }

    #[cfg(feature = "jwt")]
    #[test]
    fn test_load_encoding_key_nonexistent_file_returns_err() {
        let res = load_encoding_key("nonexistent_jwt_priv_12345.pem");
        assert!(res.is_err());
    }

    #[cfg(feature = "jwt")]
    #[test]
    fn test_verify_jwt_multiple_audiences() {
        let priv_pem = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/IrnOV6maFjmtsjchLt6\n-----END PRIVATE KEY-----\n";
        let pub_pem = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAk2Zye1IFLZDkM9awuejFhYgrETKpGldlqBFSGOEM/os=\n-----END PUBLIC KEY-----\n";

        let enc_key = EncodingKey::from_ed_pem(priv_pem.as_bytes()).unwrap();
        let dec_key = DecodingKey::from_ed_pem(pub_pem.as_bytes()).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;

        let claims = Claims {
            sub: "user-1".to_string(),
            iss: "praeco-idp".to_string(),
            aud: Some("admin-dashboard".to_string()),
            exp: now + 3600,
            oids: vec!["1".to_string()],
            jti: Some("jti-123".to_string()),
        };

        let token = sign_jwt(&claims, &enc_key).unwrap();

        // 1. Single matching audience
        assert!(verify_jwt(&token, std::slice::from_ref(&dec_key), "praeco-idp", "admin-dashboard").is_ok());

        // 2. Comma-separated audience list including admin-dashboard
        assert!(verify_jwt(&token, std::slice::from_ref(&dec_key), "praeco-idp", "praeco-admin, admin-dashboard").is_ok());

        // 3. Mismatched audience fails
        assert!(verify_jwt(&token, &[dec_key], "praeco-idp", "wrong-aud").is_err());
    }

    #[cfg(feature = "jwt")]
    #[test]
    fn test_verify_jwt_rejects_empty_issuer_or_audience() {
        let priv_pem = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/IrnOV6maFjmtsjchLt6\n-----END PRIVATE KEY-----\n";
        let pub_pem = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAk2Zye1IFLZDkM9awuejFhYgrETKpGldlqBFSGOEM/os=\n-----END PUBLIC KEY-----\n";

        let enc_key = EncodingKey::from_ed_pem(priv_pem.as_bytes()).unwrap();
        let dec_key = DecodingKey::from_ed_pem(pub_pem.as_bytes()).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;

        let claims = Claims {
            sub: "test-user".to_string(),
            iss: "praeco-idp".to_string(),
            aud: Some("admin-dashboard".to_string()),
            exp: now + 3600,
            oids: vec!["1".to_string()],
            jti: Some("jti-valid".to_string()),
        };

        let token = sign_jwt(&claims, &enc_key).unwrap();

        assert!(verify_jwt(&token, std::slice::from_ref(&dec_key), "", "admin-dashboard").is_err());
        assert!(verify_jwt(&token, std::slice::from_ref(&dec_key), " , ", "admin-dashboard").is_err());
        assert!(verify_jwt(&token, std::slice::from_ref(&dec_key), "praeco-idp", "").is_err());
        assert!(verify_jwt(&token, &[dec_key], "praeco-idp", " , ").is_err());
    }

    #[cfg(feature = "jwt")]
    #[test]
    fn test_verify_jwt_enforces_jti_max_lifetime_kid_and_size_bounds() {
        let priv_pem = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/IrnOV6maFjmtsjchLt6\n-----END PRIVATE KEY-----\n";
        let pub_pem = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAk2Zye1IFLZDkM9awuejFhYgrETKpGldlqBFSGOEM/os=\n-----END PUBLIC KEY-----\n";
        let other_pub_pem = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA1111111111111111111111111111111111111111110=\n-----END PUBLIC KEY-----\n";

        let enc_key = EncodingKey::from_ed_pem(priv_pem.as_bytes()).unwrap();
        let dec_key = DecodingKey::from_ed_pem(pub_pem.as_bytes()).unwrap();
        let other_dec_key = DecodingKey::from_ed_pem(other_pub_pem.as_bytes()).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as usize;

        // 1. Missing jti rejected by default, accepted when require_jti = false
        let claims_no_jti = Claims {
            sub: "user-1".to_string(),
            iss: "praeco-idp".to_string(),
            aud: Some("admin-dashboard".to_string()),
            exp: now + 3600,
            oids: vec!["1".to_string()],
            jti: None,
        };
        let token_no_jti = sign_jwt(&claims_no_jti, &enc_key).unwrap();
        assert!(verify_jwt(&token_no_jti, std::slice::from_ref(&dec_key), "praeco-idp", "admin-dashboard").is_err());
        assert!(
            verify_jwt_with_options(
                &token_no_jti,
                std::slice::from_ref(&dec_key),
                "praeco-idp",
                "admin-dashboard",
                JwtVerifyOptions {
                    require_jti: false,
                    max_token_lifetime_secs: Some(DEFAULT_MAX_JWT_LIFETIME_SECS),
                },
            )
            .is_ok()
        );

        // 2. Excessive lifetime (year 2286) rejected by default, accepted when max_token_lifetime_secs = None
        let claims_far_exp = Claims {
            sub: "user-1".to_string(),
            iss: "praeco-idp".to_string(),
            aud: Some("admin-dashboard".to_string()),
            exp: 9_999_999_999,
            oids: vec!["1".to_string()],
            jti: Some("jti-far".to_string()),
        };
        let token_far_exp = sign_jwt(&claims_far_exp, &enc_key).unwrap();
        assert!(verify_jwt(&token_far_exp, std::slice::from_ref(&dec_key), "praeco-idp", "admin-dashboard").is_err());
        assert!(
            verify_jwt_with_options(
                &token_far_exp,
                std::slice::from_ref(&dec_key),
                "praeco-idp",
                "admin-dashboard",
                JwtVerifyOptions {
                    require_jti: true,
                    max_token_lifetime_secs: None,
                },
            )
            .is_ok()
        );

        // 3. kid routing: "praeco-key-2" routes to index 1; out-of-range "praeco-key-99" fails fast
        let valid_claims = Claims {
            sub: "user-1".to_string(),
            iss: "praeco-idp".to_string(),
            aud: Some("admin-dashboard".to_string()),
            exp: now + 3600,
            oids: vec!["1".to_string()],
            jti: Some("jti-kid".to_string()),
        };
        let token_kid_2 = sign_jwt_with_kid(&valid_claims, &enc_key, Some("praeco-key-2")).unwrap();
        let keys = vec![other_dec_key, dec_key.clone()];
        assert!(verify_jwt(&token_kid_2, &keys, "praeco-idp", "admin-dashboard").is_ok());

        let token_kid_oob = sign_jwt_with_kid(&valid_claims, &enc_key, Some("praeco-key-99")).unwrap();
        assert!(verify_jwt(&token_kid_oob, &keys, "praeco-idp", "admin-dashboard").is_err());

        // 4. Oversized token (> MAX_JWT_TOKEN_LEN) and malformed structure rejected before crypto
        let oversized = format!("a.{}.c", "b".repeat(MAX_JWT_TOKEN_LEN));
        assert!(verify_jwt(&oversized, std::slice::from_ref(&dec_key), "praeco-idp", "admin-dashboard").is_err());
        assert!(verify_jwt("not-a-jwt", std::slice::from_ref(&dec_key), "praeco-idp", "admin-dashboard").is_err());

        // 5. Empty/whitespace subject or whitespace/oversized jti (> 256 bytes) rejected
        let empty_sub_token = sign_jwt(
            &Claims {
                sub: "   ".to_string(),
                ..valid_claims.clone()
            },
            &enc_key,
        )
        .unwrap();
        assert!(verify_jwt(&empty_sub_token, std::slice::from_ref(&dec_key), "praeco-idp", "admin-dashboard").is_err());

        let blank_jti_token = sign_jwt(
            &Claims {
                jti: Some("   ".to_string()),
                ..valid_claims.clone()
            },
            &enc_key,
        )
        .unwrap();
        assert!(verify_jwt(&blank_jti_token, std::slice::from_ref(&dec_key), "praeco-idp", "admin-dashboard").is_err());

        let huge_jti_token = sign_jwt(
            &Claims {
                jti: Some("j".repeat(257)),
                ..valid_claims.clone()
            },
            &enc_key,
        )
        .unwrap();
        assert!(verify_jwt(&huge_jti_token, std::slice::from_ref(&dec_key), "praeco-idp", "admin-dashboard").is_err());

        // 6. Future `nbf` (Not Before) claim is enforced (`validate_nbf = true`)
        #[derive(Serialize)]
        struct ClaimsWithNbf {
            sub: String,
            iss: String,
            aud: String,
            exp: usize,
            nbf: usize,
            oids: Vec<String>,
            jti: String,
        }
        let mut header = Header::new(jsonwebtoken::Algorithm::EdDSA);
        header.kid = Some("praeco-key-1".to_string());
        let future_nbf_token = encode(
            &header,
            &ClaimsWithNbf {
                sub: "user-1".to_string(),
                iss: "praeco-idp".to_string(),
                aud: "admin-dashboard".to_string(),
                exp: now + 7200,
                nbf: now + 3600,
                oids: vec!["1".to_string()],
                jti: "jti-future-nbf".to_string(),
            },
            &enc_key,
        )
        .unwrap();
        assert!(verify_jwt(&future_nbf_token, &[dec_key], "praeco-idp", "admin-dashboard").is_err());
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_build_root_store_none_uses_webpki() {
        let store = build_root_store(&None).expect("build_root_store should succeed with None");
        // Should contain all WebPKI roots (> 100)
        assert!(store.len() > 100);
    }

    #[cfg(feature = "tls")]
    #[test]
    fn test_build_root_store_custom_ca_isolates_and_excludes_webpki() {
        let pki = crate::test_pki::TestPki::new();
        let ca_path = pki.relay_ca_pem.to_string_lossy().to_string();

        let store = build_root_store(&Some(ca_path.clone()))
            .expect("build_root_store should succeed with custom CA");
        // Strict isolation: must contain ONLY the custom CA (1 cert), NOT the 100+ WebPKI roots!
        assert_eq!(store.len(), 1);

        // Meanwhile, build_root_store_with_webpki includes both
        let combined_store = build_root_store_with_webpki(&Some(ca_path))
            .expect("build_root_store_with_webpki should succeed");
        assert!(combined_store.len() > 100);
    }

    #[test]
    fn test_canonical_client_ip() {
        use std::net::IpAddr;

        let ip4: IpAddr = "192.168.1.50".parse().unwrap();
        assert_eq!(canonical_client_ip(ip4), ip4);

        let ip4_mapped: IpAddr = "::ffff:192.168.1.50".parse().unwrap();
        assert_eq!(canonical_client_ip(ip4_mapped), ip4);

        let loopback6: IpAddr = "::1".parse().unwrap();
        assert_eq!(canonical_client_ip(loopback6), loopback6);

        let ip6_a: IpAddr = "2001:db8:abcd:0012:0000:0000:0000:0001".parse().unwrap();
        let ip6_b: IpAddr = "2001:db8:abcd:0012:ffff:ffff:ffff:ffff".parse().unwrap();
        let ip6_masked: IpAddr = "2001:db8:abcd:0012::".parse().unwrap();
        assert_eq!(canonical_client_ip(ip6_a), ip6_masked);
        assert_eq!(canonical_client_ip(ip6_b), ip6_masked);
    }

    #[test]
    fn test_client_ip_from_xff_right_to_left() {
        use std::net::{IpAddr, Ipv4Addr};

        // 1 trusted hop: rightmost entry wins, spoofed leftmost is ignored
        assert_eq!(
            client_ip_from_xff("1.2.3.4, 198.51.100.7", 1),
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)))
        );

        // 2 trusted hops: skips outermost proxy (10.0.0.1) and picks inner client
        assert_eq!(
            client_ip_from_xff("1.2.3.4, 198.51.100.7, 10.0.0.1", 2),
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)))
        );

        // trusted_hops == 0 disables XFF extraction
        assert_eq!(client_ip_from_xff("198.51.100.7", 0), None);

        // Fewer entries than trusted_hops fails closed (no fallback to spoofed left)
        assert_eq!(client_ip_from_xff("1.2.3.4", 2), None);

        // Unspecified or invalid entries are rejected
        assert_eq!(client_ip_from_xff("1.2.3.4, 0.0.0.0", 1), None);
        assert_eq!(client_ip_from_xff("1.2.3.4, garbage", 1), None);
    }
}
