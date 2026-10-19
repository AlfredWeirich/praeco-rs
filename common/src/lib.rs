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
use anyhow::{Context, Error, anyhow};
#[allow(unused_imports)]
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, decode_header, encode};
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, PrivateKeyDer},
};
use serde::{Deserialize, Serialize};

// Note: tracing 'info' was unused, so it was removed.

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
pub fn load_certs(path: &str, server_name: &str) -> Result<Vec<CertificateDer<'static>>, Error> {
    let data = std::fs::read(path)
        .with_context(|| format!("{server_name}: Failed to read certificate file '{path}'"))?;

    let certs = rustls_pemfile::certs(&mut &data[..])
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
/// * `_server_name` – Reserved for future logging (currently unused).
///
/// # Panics
///
/// Panics if the file cannot be opened, contains no recognised key, or
///   has a PEM parse error.
// pub fn load_single_key(path: &str, server_name: &str) -> PrivateKeyDer<'static> {
//     // Read the private key file contents into memory
//     let key_data = std::fs::read(path).unwrap_or_else(|_| {
//         error!("{server_name}: Failed to read {path}");
//         panic!("{server_name}: Failed to read {path}");
//     });

//     // Attempt to parse one or more private keys in PKCS#8 format
//     let mut keys = rustls_pemfile::pkcs8_private_keys(&mut &key_data[..])
//         .map(|res| {
//             res.map(PrivateKeyDer::from)
//                 .expect("Invalid private key format")
//         })
//         .collect::<Vec<_>>();

//     // Ensure exactly one key is used; log and panic if none, warn if multiple
//     match keys.len() {
//         0 => {
//             error!("{server_name}: No private key found in server key file");
//             panic!("{server_name}: No private key found in server key file");
//         }
//         1 => {
//             trace!("{server_name}: Single private key loaded successfully.");
//         }
//         _ => {
//             warn!("{server_name}: Multiple private keys found, using the first one");
//         }
//     }

//     // Return the first parsed key
//     keys.remove(0)
// }
pub fn load_single_key(path: &str, server_name: &str) -> Result<PrivateKeyDer<'static>, Error> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("{server_name}: Cannot open key file '{path}'"))?;
    let mut reader = std::io::BufReader::new(file);

    // Use read_all to catch PKCS1, PKCS8, or SEC1 automatically.
    // This is more robust than parsing only PKCS#8.
    for item in rustls_pemfile::read_all(&mut reader) {
        let item = item.with_context(|| format!("{server_name}: PEM parse error in '{path}'"))?;
        match item {
            rustls_pemfile::Item::Pkcs1Key(key) => return Ok(PrivateKeyDer::Pkcs1(key)),
            rustls_pemfile::Item::Pkcs8Key(key) => return Ok(PrivateKeyDer::Pkcs8(key)),
            rustls_pemfile::Item::Sec1Key(key) => return Ok(PrivateKeyDer::Sec1(key)),
            _ => continue, // Skip non-key items (certificates, etc.)
        }
    }
    Err(anyhow!("{server_name}: No private key found in '{path}'"))
}

/// JWT Claims payload for authentication and authorization.
///
/// This structure is serialized into / deserialized from the JWT body.
/// The `oids` field carries custom OID suffixes extracted from the
/// signing identity, which are later mapped to [`UserRole`](crate)
/// values by the server.
#[derive(Debug, Serialize, Deserialize, Clone)]
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
pub fn load_encoding_key(path: &str) -> Result<EncodingKey, Error> {
    let pem = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read private key file: '{path}'"))?;
    let key = EncodingKey::from_ed_pem(pem.as_bytes())
        .with_context(|| format!("Failed to parse private key in '{path}'"))?;
    Ok(key)
}

/// Verifies a JWT token against a set of decoding keys.
///
/// Tries each key in order; the **first** successful verification wins.
/// This enables seamless key rotation: both the old and new keys can be
/// active simultaneously during a rollover window.
///
/// # Algorithm
///
/// Currently hard-coded to **EdDSA** (Ed25519). If algorithm negotiation
/// is needed in the future, the commented-out `decode_header` block can be
/// re-enabled.
///
/// # Errors
///
/// Returns an error if **none** of the provided keys can verify the token.
pub fn verify_jwt(
    token: &str,
    decoding_keys: &[DecodingKey],
    expected_issuer: &str,
    expected_audience: &str,
) -> Result<Claims, Error> {
    let mut validation = Validation::new(jsonwebtoken::Algorithm::EdDSA);
    
    validation.set_issuer(&[expected_issuer]);
    validation.set_audience(&[expected_audience]);

    // Try verifying the JWT with each decoding key
    for key in decoding_keys {
        if let Ok(data) = decode::<Claims>(token, key, &validation) {
            return Ok(data.claims);
        }
    }
    Err(Error::msg("JWT verification failed with all keys"))
}

/// Signs a JWT token with the given `Claims` and `EncodingKey`.
///
/// # Algorithm
///
/// Hard-coded to **EdDSA** (Ed25519).
///
/// # Errors
///
/// Returns an error if token signing fails.
pub fn sign_jwt(claims: &Claims, encoding_key: &EncodingKey) -> Result<String, Error> {
    let header = Header::new(jsonwebtoken::Algorithm::EdDSA);
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
/// # Arguments
///
/// * `ca_path` – Optional path to a PEM file with additional trusted CA
///   certificates (e.g. self-signed CAs used in internal environments).
pub fn build_root_store(ca_path: &Option<String>) -> Result<RootCertStore, Error> {
    let mut root_store = RootCertStore::empty();
    // Start with the well-known WebPKI root certificates (Let's Encrypt, etc.)
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    // Optionally add a custom CA (e.g. self-signed for internal environments)
    if let Some(path) = ca_path {
        let root_cert = load_certs(path, "root_store")?;
        root_store.add_parsable_certificates(root_cert);
    }
    Ok(root_store)
}
pub mod client;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_certs_nonexistent_file_returns_err() {
        let res = load_certs("nonexistent_cert_path_12345.pem", "test_server");
        assert!(res.is_err());
    }

    #[test]
    fn test_load_single_key_nonexistent_file_returns_err() {
        let res = load_single_key("nonexistent_key_path_12345.pem", "test_server");
        assert!(res.is_err());
    }

    #[test]
    fn test_load_decoding_keys_nonexistent_file_returns_err() {
        let res = load_decoding_keys(&["nonexistent_jwt_key_12345.pem".to_string()]);
        assert!(res.is_err());
    }

    #[test]
    fn test_load_encoding_key_nonexistent_file_returns_err() {
        let res = load_encoding_key("nonexistent_jwt_priv_12345.pem");
        assert!(res.is_err());
    }
}
