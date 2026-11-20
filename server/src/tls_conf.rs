//! # TLS Configuration Builder
//!
//! Builds a [`rustls::ServerConfig`] for the server's TLS stack. Supports two
//! modes:
//!
//! * **Standard HTTPS** – The server presents its certificate; no client
//!   authentication is required.
//! * **Mutual TLS (mTLS)** – In addition to the server certificate, the client
//!   must present a valid certificate signed by one of the configured CAs.
//!   Optionally, Certificate Revocation Lists (CRLs) can be loaded for
//!   revocation checks.
//!
//! This module also provides [`extract_oids_from_cert`], which extracts
//! custom OID suffixes from a DER-encoded client certificate. These suffixes
//! are used downstream for role-based access control (RBAC).

// === Standard Library ===
use std::sync::Arc;

// === External Crates ===
use anyhow::Error;
use rustls::ServerConfig as RustlsServerConfig;
use rustls::crypto::CryptoProvider;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use rustls_pki_types::{CertificateDer, CertificateRevocationListDer, pem::PemObject};
use std::fmt::Debug;
use tracing::trace;
use x509_parser::prelude::*;

// === Internal Modules ===
use crate::configuration::{ClientCertConfig, ServerCertConfig};
use common::{load_certs, load_single_key};

pub fn load_certified_key(
    server_name: &str,
    server_cert_config: &ServerCertConfig,
) -> Result<Arc<CertifiedKey>, Error> {
    let server_certs = load_certs(&server_cert_config.ssl_certificate, server_name)?;
    trace!("{}: Server certificates loaded successfully.", server_name);

    let server_key = load_single_key(&server_cert_config.ssl_certificate_key, server_name)?;
    trace!("{}: Server private key loaded successfully.", server_name);

    let provider = CryptoProvider::get_default()
        .ok_or_else(|| Error::msg("No default crypto provider available"))?;
    let signing_key = provider
        .key_provider
        .load_private_key(server_key)
        .map_err(|e| {
            Error::msg(format!(
                "{}: Invalid or unsupported private key type: {}",
                server_name, e
            ))
        })?;

    Ok(Arc::new(CertifiedKey::new(server_certs, signing_key)))
}

#[derive(Debug)]
pub struct DynamicCertResolver {
    server_name: &'static str,
    fallback_key: Option<Arc<CertifiedKey>>,
}

impl DynamicCertResolver {
    pub fn new(server_name: &'static str) -> Self {
        Self {
            server_name,
            fallback_key: None,
        }
    }

    /// Creates a [`DynamicCertResolver`] that prefers the hot-reloaded key from
    /// [`Config::try_global`](crate::configuration::Config::try_global) and falls
    /// back to `fallback_key` when the global config singleton is not initialized
    /// or does not contain `server_name`.
    pub fn with_fallback(server_name: &'static str, fallback_key: Arc<CertifiedKey>) -> Self {
        Self {
            server_name,
            fallback_key: Some(fallback_key),
        }
    }
}

impl ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        if let Some(config) = crate::configuration::Config::try_global()
            && let Some(key) = config
                .servers
                .iter()
                .find(|s| s.static_name == Some(self.server_name))
                .and_then(|s| s.certified_key.clone())
        {
            return Some(key);
        }
        self.fallback_key.clone()
    }
}

/// Builds and returns a Rustls `ServerConfig` with optional mutual TLS (mTLS) support.
///
/// This function loads server certificates and keys for use in TLS communication,
/// and configures a client certificate verifier using a provided CA bundle.
/// The resulting configuration enforces client authentication using mTLS.
///
/// # Parameters
///
/// - `server_name`: Identifier for tracing/logging context (usually the hostname).
/// - `server_cert_config`: Contains file paths to the server certificate and private key.
/// - `client_ca_configs`: Optional list of client CA configs. Required if client authentication is enabled.
/// - `authentication_method`: Client authentication mode (`None`, `ClientCert`, `OptionalClientCert`, or `Jwt`).
///
/// # Returns
///
/// Returns a fully configured [`RustlsServerConfig`] supporting TLS 1.3 and TLS 1.2
/// with (optional) client certificate verification.
///
/// # ALPN Protocols
/// Snapshot of the loaded client PKI and session resumption handles produced when building
/// a [`rustls::ServerConfig`].
///
/// Passing this state to [`tls_config_preserving_sessions`] on a `SIGHUP` hot-reload
/// reuses the in-memory session cache and session ticketer whenever client PKI material
/// (`ca_ders`, `crl_ders`), authentication mode, and session resumption settings are
/// unchanged, avoiding full-handshake storms across connected clients (`P2-08`).
#[derive(Clone)]
pub struct PreservedTlsSessionState {
    require_client_auth: bool,
    session_cache_size: Option<usize>,
    session_tickets: bool,
    ca_ders: Vec<Vec<u8>>,
    crl_ders: Vec<Vec<u8>>,
    session_storage: Arc<dyn rustls::server::StoresServerSessions>,
    ticketer: Arc<dyn rustls::server::ProducesTickets>,
}

/// Builds a [`rustls::ServerConfig`] for HTTPS or mTLS listeners.
///
/// Delegates to [`tls_config_preserving_sessions`] with `previous = None`.
///
/// The returned config advertises support for `h3`, `h2`, and `http/1.1` in
/// that preference order, enabling HTTP/3, HTTP/2, and HTTP/1.1 negotiation.
///
/// # Errors
///
/// Returns an error if any certificate, CRL, or private key file fails to load, is malformed,
/// if CRL validation rejects an expired/corrupt CRL, or if `session_tickets` is paired with CRLs.
pub fn tls_config(
    server_name: &'static str,
    server_cert_config: &ServerCertConfig,
    client_ca_configs: Option<&[ClientCertConfig]>,
    authentication_method: crate::configuration::AuthenticationMethod,
) -> Result<RustlsServerConfig, Error> {
    tls_config_preserving_sessions(
        server_name,
        server_cert_config,
        client_ca_configs,
        authentication_method,
        None,
    )
    .map(|(cfg, _)| cfg)
}

/// Like [`tls_config`], but preserves the TLS [`ServerSessionMemoryCache`](rustls::server::ServerSessionMemoryCache)
/// and `Ticketer` from `previous` when client authentication mode, session policy, and
/// loaded client CA/CRL DER bytes are unchanged (`P2-08`).
///
/// # Errors
///
/// Returns an error under the same conditions as [`tls_config`].
pub fn tls_config_preserving_sessions(
    server_name: &'static str,
    server_cert_config: &ServerCertConfig,
    client_ca_configs: Option<&[ClientCertConfig]>,
    authentication_method: crate::configuration::AuthenticationMethod,
    previous: Option<&PreservedTlsSessionState>,
) -> Result<(RustlsServerConfig, PreservedTlsSessionState), Error> {
    let fallback_key = load_certified_key(server_name, server_cert_config)?;
    let cert_resolver = Arc::new(DynamicCertResolver::with_fallback(
        server_name,
        fallback_key,
    ));

    // Create a fresh Rustls config builder (supports TLS 1.3 and TLS 1.2)
    let config_builder = rustls::ServerConfig::builder();

    let require_client_auth = authentication_method == crate::configuration::AuthenticationMethod::ClientCert
        || authentication_method == crate::configuration::AuthenticationMethod::OptionalClientCert;

    let mut loaded_ca_ders: Vec<Vec<u8>> = Vec::new();
    let mut loaded_crl_ders: Vec<Vec<u8>> = Vec::new();

    // Determine if client authentication (mTLS) is required
    let config = if require_client_auth {
        // === mTLS: Load client CA roots and (optional) CRLs for client certificate verification ===
        let mut root_store = rustls::RootCertStore::empty();

        // Ensure client CA configs are provided if mTLS is enabled
        let client_certs = client_ca_configs.ok_or_else(|| {
            Error::msg(format!(
                "{server_name}: Client certs required for mTLS, but none provided.",
            ))
        })?;

        let enforce_crl_expiration =
            crate::configuration::ensure_uniform_crl_strictness(server_name, client_certs)
                .map_err(|e| Error::msg(e.to_string()))?;

        // Collect Certificate Revocation Lists (CRLs) if specified in client CA configs.
        // CRLs allow the server to reject certificates that have been revoked by the CA.
        let mut crls: Vec<CertificateRevocationListDer<'_>> = Vec::with_capacity(20);
        for config in client_certs {
            // Load one or more CA certs for this config
            let ca_certs = load_certs(&config.ssl_client_ca, server_name)?;
            for ca in ca_certs {
                loaded_ca_ders.push(ca.as_ref().to_vec());
                // Add each CA cert to the root store for client verification
                root_store
                    .add(ca)
                    .map_err(|e| Error::msg(format!("{server_name}: Failed to add CA: {e}")))?;
                trace!("{server_name}: Added CA from {}", config.ssl_client_ca);
            }
            if let Some(ref crl_path) = config.ssl_client_crl {
                let loaded_crls = CertificateRevocationListDer::pem_file_iter(crl_path)
                    .map_err(|e| {
                        Error::msg(format!(
                            "{server_name}: Failed to open CRL '{crl_path}': {e}"
                        ))
                    })?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| {
                        Error::msg(format!(
                            "{server_name}: Failed to load CRL from '{crl_path}': {e}"
                        ))
                    })?;
                if loaded_crls.is_empty() {
                    return Err(Error::msg(format!(
                        "{server_name}: CRL file '{crl_path}' contains no CRL entries"
                    )));
                }
                let strict = config.strict_crl;
                for crl in loaded_crls {
                    if !warn_if_crl_expired(server_name, crl_path, crl.as_ref()) && strict {
                        return Err(Error::msg(format!(
                            "{server_name}: Rejecting CRL '{crl_path}' because strict CRL validation is enabled and the CRL is expired or invalid"
                        )));
                    }
                    loaded_crl_ders.push(crl.as_ref().to_vec());
                    trace!("{server_name}: Added CRL from {crl_path}");
                    crls.push(crl);
                }
            }
        }

        // Build a WebPKI-based client certificate verifier with loaded root CAs and CRLs.
        // This verifier checks that client certificates are signed by a trusted CA
        // and have not been revoked (if CRLs are provided).
        let mut builder = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
            .with_crls(crls);

        if enforce_crl_expiration {
            builder = builder.enforce_revocation_expiration();
        }

        if authentication_method == crate::configuration::AuthenticationMethod::OptionalClientCert {
            builder = builder.allow_unauthenticated();
        }

        let client_verifier = builder.build()
            .map_err(|e| {
                Error::msg(format!(
                    "{server_name}: Failed to build client verifier: {e}",
                ))
            })?;

        // Attach verifier and a dynamic cert resolver to the config builder

        config_builder
            .with_client_cert_verifier(client_verifier)
            .with_cert_resolver(cert_resolver)
    } else {
        // No client authentication; set up standard HTTPS only

        config_builder
            .with_no_client_auth()
            .with_cert_resolver(cert_resolver)
    };

    let mut config = config;
    let has_crl =
        client_ca_configs.is_some_and(|cas| cas.iter().any(|c| c.ssl_client_crl.is_some()));

    if server_cert_config.session_tickets && has_crl {
        return Err(Error::msg(format!(
            "{server_name}: 'session_tickets = true' cannot be combined with mTLS CRL verification ('ssl_client_crl')"
        )));
    }

    let can_preserve_resumption = previous.is_some_and(|prev| {
        prev.require_client_auth == require_client_auth
            && prev.session_cache_size == server_cert_config.session_cache_size
            && prev.session_tickets == server_cert_config.session_tickets
            && (!require_client_auth
                || (prev.ca_ders == loaded_ca_ders && prev.crl_ders == loaded_crl_ders))
    });

    if let Some(prev) = previous.filter(|_| can_preserve_resumption) {
        config.session_storage = Arc::clone(&prev.session_storage);
        config.ticketer = Arc::clone(&prev.ticketer);
        trace!(
            "{}: Preserved TLS session cache and ticketer across hot-reload",
            server_name
        );
    } else {
        let effective_cache_size = server_cert_config.session_cache_size.unwrap_or({
            if !require_client_auth {
                crate::configuration::DEFAULT_TLS_SESSION_CACHE_SIZE
            } else if has_crl {
                0
            } else {
                crate::configuration::DEFAULT_MTLS_TLS_SESSION_CACHE_SIZE
            }
        });

        if effective_cache_size == 0 {
            config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
        } else {
            if require_client_auth && has_crl {
                tracing::warn!(
                    "{}: Stateful TLS session cache ({} slots) enabled alongside mTLS CRLs; resumed sessions skip client certificate & CRL re-verification.",
                    server_name,
                    effective_cache_size
                );
            }
            config.session_storage =
                rustls::server::ServerSessionMemoryCache::new(effective_cache_size);
        }

        if server_cert_config.session_tickets {
            if require_client_auth {
                tracing::warn!(
                    "{}: Stateless TLS session tickets enabled on mTLS server; resumed sessions skip client certificate checks for up to 12h.",
                    server_name
                );
            }
            config.ticketer = rustls::crypto::aws_lc_rs::Ticketer::new().map_err(|e| {
                Error::msg(format!(
                    "{server_name}: Failed to initialize TLS session ticketer: {e}"
                ))
            })?;
        }
    }

    // Enable ALPN for HTTP/3, HTTP/2, and HTTP/1.1 negotiation.
    // The order indicates server preference (H3 > H2 > H1.1).
    config.alpn_protocols = vec![b"h3".to_vec(), b"h2".to_vec(), b"http/1.1".to_vec()];

    trace!(
        "{}: {} server TLS configuration completed.",
        server_name,
        if require_client_auth { "mTLS" } else { "HTTPS" }
    );

    let preserved_state = PreservedTlsSessionState {
        require_client_auth,
        session_cache_size: server_cert_config.session_cache_size,
        session_tickets: server_cert_config.session_tickets,
        ca_ders: loaded_ca_ders,
        crl_ders: loaded_crl_ders,
        session_storage: Arc::clone(&config.session_storage),
        ticketer: Arc::clone(&config.ticketer),
    };

    Ok((config, preserved_state))
}

/// Validates a DER-encoded X.509 CRL against expiration (`nextUpdate`) and returns
/// an `Err` when `strict` is `true` and the CRL is expired, lacks `nextUpdate`, or
/// cannot be parsed.
pub fn validate_crl_not_expired(
    server_name: &str,
    crl_path: &str,
    crl_der: &[u8],
    strict: bool,
) -> Result<(), String> {
    if warn_if_crl_expired(server_name, crl_path, crl_der) || !strict {
        Ok(())
    } else {
        Err(format!(
            "{server_name}: CRL '{crl_path}' is expired, lacks nextUpdate, or failed parsing"
        ))
    }
}

/// Checks a DER-encoded X.509 CRL for expiration (`nextUpdate` in the past) or missing
/// `nextUpdate` field, emitting a warning log if stale. Returns `true` if the CRL is
/// valid and not expired, or `false` if expired, missing `nextUpdate`, or unparseable.
pub fn warn_if_crl_expired(server_name: &str, crl_path: &str, crl_der: &[u8]) -> bool {
    match common::crl::check_crl_not_expired(crl_der) {
        Ok(()) => true,
        Err(err) => {
            tracing::warn!("{}: CRL '{}' check failed: {}", server_name, crl_path, err);
            false
        }
    }
}

/// Extracts custom PKI OIDs from a DER-encoded X.509 certificate using the
/// globally configured `pki_base_oid` in [`Config::try_global`].
///
/// Prefer [`extract_oids_from_cert_with_base`] when a per-server
/// [`ServerConfig::parsed_pki_base_oid`](crate::configuration::ServerConfig::parsed_pki_base_oid)
/// is available.
pub fn extract_oids_from_cert(cert_der: &[u8]) -> Vec<String> {
    let config = match crate::configuration::Config::try_global() {
        Some(c) => c,
        None => return Vec::new(),
    };
    extract_oids_from_cert_with_base(cert_der, config.parsed_pki_base_oid.as_deref())
}

/// Extracts custom PKI OIDs from a DER-encoded X.509 certificate using an
/// explicit `base_oid` prefix.
///
/// Iterates over every extension in the certificate, checks if its OID starts
/// with `base_oid`, and if so, returns the trailing suffix components as
/// dot-separated strings.
///
/// # Performance Optimized
///
/// This function avoids allocating strings for every OID in the certificate.
/// It compares the raw integer components of the OID against `base_oid`.
/// Allocations only occur if a valid match is found and we need to return the suffix.
///
/// # Example
///
/// If `base_oid` is `Some(&[2, 25])` and the certificate contains an extension with
/// OID `2.25.42.7`, this function returns `vec!["42.7"]`.
///
/// # Arguments
///
/// * `cert_der` – Raw DER-encoded bytes of the X.509 certificate.
/// * `base_oid` – Pre-computed integer components of the base OID, or `None` if unconfigured.
///
/// # Returns
///
/// A `Vec<String>` of OID suffixes (e.g. `["1", "2.3"]`). Empty if no
/// matching extensions are found or if `base_oid` is `None`/empty.
/// Extracts matching OID suffixes relative to `base_oid` from an already-parsed [`X509Certificate`].
fn extract_oids_from_x509(x509: &X509Certificate<'_>, base_oid: Option<&[u64]>) -> Vec<String> {
    let mut oids = Vec::new();
    let base_components = match base_oid {
        Some(v) if !v.is_empty() => v,
        _ => return oids,
    };

    for ext in x509.extensions() {
        // Get an iterator over the OID's integer components.
        let mut oid_iter = match ext.oid.iter() {
            Some(iter) => iter, // Correct for x509-parser v0.16+
            None => continue,   // Parsing failed or empty
        };

        // CHECK PREFIX — Compare each component of the base OID against
        // the certificate extension's OID, both in u64 space.
        let mut is_match = true;
        for &base_part in base_components {
            match oid_iter.next() {
                Some(cert_part) => {
                    if cert_part != base_part {
                        is_match = false;
                        break;
                    }
                }
                None => {
                    // The extension's OID is shorter than the base — no match.
                    is_match = false;
                    break;
                }
            }
        }

        // EXTRACT SUFFIX — Collect the remaining components after the
        // base prefix into a dot-separated string.
        if is_match {
            let suffix_parts: Vec<String> = oid_iter.map(|u| u.to_string()).collect();

            if !suffix_parts.is_empty() {
                oids.push(suffix_parts.join("."));
            }
        }
    }
    oids
}

/// Extracts the first `DNSName` SAN entry from an already-parsed [`X509Certificate`].
fn extract_san_from_x509(x509: &X509Certificate<'_>) -> Option<String> {
    tracing::debug!("Successfully parsed X509 cert. Looking for SAN extension...");
    let mut found_san_ext = false;
    for ext in x509.extensions() {
        if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) =
            ext.parsed_extension()
        {
            found_san_ext = true;
            tracing::debug!(
                "Found SubjectAlternativeName extension. Iterating GeneralNames..."
            );
            for name in &san.general_names {
                tracing::debug!("Found GeneralName: {:?}", name);
                if let x509_parser::extensions::GeneralName::DNSName(domain) = name {
                    tracing::debug!("Extracted DNSName SAN: {}", domain);
                    return Some(domain.to_string());
                }
            }
        }
    }
    if !found_san_ext {
        tracing::debug!("No SubjectAlternativeName extension found in client cert!");
    }
    None
}

pub fn extract_oids_from_cert_with_base(cert_der: &[u8], base_oid: Option<&[u64]>) -> Vec<String> {
    match base_oid {
        Some(v) if !v.is_empty() => {}
        _ => return Vec::new(),
    }

    if let Ok((_, x509)) = X509Certificate::from_der(cert_der) {
        extract_oids_from_x509(&x509, base_oid)
    } else {
        Vec::new()
    }
}

/// Extracts the full PEM-encoded certificate and its SAN (Subject Alternative Name)
/// from a DER-encoded X.509 certificate.
pub fn extract_cert_san_and_pem(cert_der: &[u8]) -> (Option<String>, Option<String>) {
    // 1. Encode DER to PEM
    let pem = ::pem::encode(&::pem::Pem::new("CERTIFICATE", cert_der));

    // 2. Extract SAN
    let san_dns = match X509Certificate::from_der(cert_der) {
        Ok((_, x509)) => extract_san_from_x509(&x509),
        Err(e) => {
            tracing::warn!("Failed to parse client cert DER: {:?}", e);
            None
        }
    };
    (Some(pem), san_dns)
}

/// Identity metadata extracted from a client certificate presented during mTLS.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientIdentityMetadata {
    /// OID suffixes matching the configured `pki_base_oid` (used to determine roles).
    pub oids: Vec<String>,
    /// Full PEM-encoded certificate string, if available.
    pub pem: Option<String>,
    /// Subject Alternative Name (DNS), if present in the certificate.
    pub san: Option<String>,
}

/// Extracts identity metadata strictly from the client's **leaf** certificate
/// (the first certificate in the provided chain), using the globally configured
/// `pki_base_oid`.
///
/// Prefer [`extract_client_metadata_with_base`] when a per-server `pki_base_oid`
/// is available.
pub fn extract_client_metadata(
    certs: Option<&[CertificateDer<'_>]>,
) -> ClientIdentityMetadata {
    let global_base = crate::configuration::Config::try_global()
        .and_then(|c| c.parsed_pki_base_oid.clone());
    extract_client_metadata_with_base(certs, global_base.as_deref())
}

/// Extracts identity metadata strictly from the client's **leaf** certificate
/// (the first certificate in the provided chain) using an explicit `base_oid`.
///
/// Any subsequent intermediate or extra certificates in the chain are intentionally
/// ignored to prevent privilege escalation via injected certificates. Parses the
/// leaf DER certificate at most once for both SAN and OID extraction (`P2-09`).
pub fn extract_client_metadata_with_base(
    certs: Option<&[CertificateDer<'_>]>,
    base_oid: Option<&[u64]>,
) -> ClientIdentityMetadata {
    if let Some(leaf) = certs.and_then(|c| c.first()) {
        let leaf_der = leaf.as_ref();
        let pem = ::pem::encode(&::pem::Pem::new("CERTIFICATE", leaf_der));
        let (san, oids) = match X509Certificate::from_der(leaf_der) {
            Ok((_, x509)) => (
                extract_san_from_x509(&x509),
                extract_oids_from_x509(&x509, base_oid),
            ),
            Err(e) => {
                tracing::warn!("Failed to parse client cert DER: {:?}", e);
                (None, Vec::new())
            }
        };
        ClientIdentityMetadata {
            oids,
            pem: Some(pem),
            san,
        }
    } else {
        ClientIdentityMetadata::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_client_metadata_none() {
        let meta = extract_client_metadata(None);
        assert_eq!(meta, ClientIdentityMetadata::default());
        assert!(meta.oids.is_empty());
        assert!(meta.pem.is_none());
        assert!(meta.san.is_none());
    }

    #[test]
    fn test_extract_client_metadata_empty_slice() {
        let meta = extract_client_metadata(Some(&[]));
        assert_eq!(meta, ClientIdentityMetadata::default());
        assert!(meta.oids.is_empty());
        assert!(meta.pem.is_none());
        assert!(meta.san.is_none());
    }

    #[test]
    fn test_extract_client_metadata_only_uses_first_leaf_cert() {
        let leaf_bytes = b"leaf_certificate_dummy_payload";
        let extra_bytes = b"injected_intermediate_or_admin_payload";

        let leaf_cert = CertificateDer::from(leaf_bytes.as_slice());
        let extra_cert = CertificateDer::from(extra_bytes.as_slice());

        let chain = [leaf_cert, extra_cert];
        let meta = extract_client_metadata(Some(&chain));

        // PEM must belong solely to the leaf certificate (first in chain)
        let pem = meta.pem.expect("PEM should be present");
        assert!(pem.contains("bGVhZl9jZXJ0aWZpY2F0ZV9kdW1teV9wYXlsb2Fk"));
        assert!(!pem.contains("aW5qZWN0ZWRfaW50ZXJtZWRpYXRl"));
    }

    #[test]
    fn test_extract_oids_with_base_cert() {
        let pki = common::test_pki::TestPki::new();
        let certs = common::load_certs(
            common::test_pki::TestPki::s(&pki.praeco_client_pem),
            "test_oid",
        )
        .expect("load generated client cert");
        let leaf_der = certs.first().unwrap().as_ref();

        let matched = extract_oids_from_cert_with_base(leaf_der, Some(&[1, 3, 6, 1, 4, 1, 65111]));
        assert_eq!(matched, vec!["1"]);

        let non_matching =
            extract_oids_from_cert_with_base(leaf_der, Some(&[1, 3, 6, 1, 4, 1, 99999]));
        assert!(non_matching.is_empty());

        assert!(extract_oids_from_cert_with_base(leaf_der, None).is_empty());
        assert!(extract_oids_from_cert_with_base(leaf_der, Some(&[])).is_empty());
    }

    #[test]
    fn test_validate_crl_not_expired_strict_vs_permissive() {
        let invalid_der = b"not-a-valid-crl";
        // Non-strict emits warning and allows fallback compatibility
        assert!(validate_crl_not_expired("srv", "stale.crl", invalid_der, false).is_ok());
        // Strict mode fails hard
        assert!(validate_crl_not_expired("srv", "stale.crl", invalid_der, true).is_err());
    }

    #[test]
    fn test_tls_config_strict_crl_rejects_empty_and_corrupt_crl_by_default() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let pki = common::test_pki::TestPki::new();
        let empty_crl = std::env::temp_dir().join(format!(
            "praeco_server_empty_crl_{}.pem",
            std::process::id()
        ));
        std::fs::write(&empty_crl, "").unwrap();

        let srv_cert = ServerCertConfig {
            ssl_certificate: common::test_pki::TestPki::s(&pki.praeco_public_pem).to_string(),
            ssl_certificate_key: common::test_pki::TestPki::s(&pki.praeco_public_key).to_string(),
            ..Default::default()
        };
        let client_ca = vec![ClientCertConfig {
            ssl_client_ca: common::test_pki::TestPki::s(&pki.relay_ca_pem).to_string(),
            ssl_client_crl: Some(empty_crl.to_string_lossy().to_string()),
            strict_crl: true,
        }];

        let res = tls_config(
            "test_srv",
            &srv_cert,
            Some(&client_ca),
            crate::configuration::AuthenticationMethod::ClientCert,
        );
        let _ = std::fs::remove_file(&empty_crl);
        assert!(res.is_err(), "empty CRL file must be rejected");
    }

    #[test]
    fn test_tls_session_cache_and_tickets_policy() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let pki = common::test_pki::TestPki::new();
        let base_cert = || ServerCertConfig {
            ssl_certificate: common::test_pki::TestPki::s(&pki.praeco_public_pem).to_string(),
            ssl_certificate_key: common::test_pki::TestPki::s(&pki.praeco_public_key).to_string(),
            ..Default::default()
        };

        // 1. Non-mTLS: session cache enabled by default (20k), ticketer off unless enabled
        let cfg_public = tls_config(
            "pub",
            &base_cert(),
            None,
            crate::configuration::AuthenticationMethod::None,
        )
        .unwrap();
        assert!(cfg_public.session_storage.can_cache());
        assert!(!cfg_public.ticketer.enabled());

        // Non-mTLS with session_cache_size = 0 and session_tickets = true
        let mut ticket_cert = base_cert();
        ticket_cert.session_cache_size = Some(0);
        ticket_cert.session_tickets = true;
        let cfg_tickets = tls_config(
            "pub_tickets",
            &ticket_cert,
            None,
            crate::configuration::AuthenticationMethod::Jwt,
        )
        .unwrap();
        assert!(!cfg_tickets.session_storage.can_cache());
        assert!(cfg_tickets.ticketer.enabled());

        // 2. mTLS without CRL keeps session cache enabled by default
        let ca_no_crl = vec![ClientCertConfig {
            ssl_client_ca: common::test_pki::TestPki::s(&pki.relay_ca_pem).to_string(),
            ssl_client_crl: None,
            strict_crl: true,
        }];
        let cfg_mtls_no_crl = tls_config(
            "mtls_no_crl",
            &base_cert(),
            Some(&ca_no_crl),
            crate::configuration::AuthenticationMethod::ClientCert,
        )
        .unwrap();
        assert!(cfg_mtls_no_crl.session_storage.can_cache());

        // 3. mTLS with CRL defaults to NoServerSessionStorage (0) and rejects session_tickets = true
        let ca_with_crl = vec![ClientCertConfig {
            ssl_client_ca: common::test_pki::TestPki::s(&pki.relay_ca_pem).to_string(),
            ssl_client_crl: Some(common::test_pki::TestPki::s(&pki.relay_crl_pem).to_string()),
            strict_crl: true,
        }];
        let cfg_mtls_crl = tls_config(
            "mtls_crl",
            &base_cert(),
            Some(&ca_with_crl),
            crate::configuration::AuthenticationMethod::ClientCert,
        )
        .unwrap();
        assert!(!cfg_mtls_crl.session_storage.can_cache());

        let mut crl_with_tickets = base_cert();
        crl_with_tickets.session_tickets = true;
        assert!(
            tls_config(
                "mtls_crl_tickets",
                &crl_with_tickets,
                Some(&ca_with_crl),
                crate::configuration::AuthenticationMethod::ClientCert,
            )
            .is_err()
        );
    }

    #[test]
    fn test_tls_config_rejects_mixed_strict_crl_across_client_cas()
    -> Result<(), Box<dyn std::error::Error>> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let pki = common::test_pki::TestPki::new();
        let srv_cert = ServerCertConfig {
            ssl_certificate: common::test_pki::TestPki::s(&pki.praeco_public_pem).to_string(),
            ssl_certificate_key: common::test_pki::TestPki::s(&pki.praeco_public_key).to_string(),
            ..Default::default()
        };

        // 1. Mixed strict_crl on two CRL-bearing client_certs must fail closed
        let mixed_cas = vec![
            ClientCertConfig {
                ssl_client_ca: common::test_pki::TestPki::s(&pki.relay_ca_pem).to_string(),
                ssl_client_crl: Some(common::test_pki::TestPki::s(&pki.relay_crl_pem).to_string()),
                strict_crl: true,
            },
            ClientCertConfig {
                ssl_client_ca: common::test_pki::TestPki::s(&pki.public_ca_pem).to_string(),
                ssl_client_crl: Some(
                    common::test_pki::TestPki::s(&pki.relay_crl_revoking_client_pem).to_string(),
                ),
                strict_crl: false,
            },
        ];
        assert!(
            tls_config(
                "mixed_crl_strictness",
                &srv_cert,
                Some(&mixed_cas),
                crate::configuration::AuthenticationMethod::ClientCert,
            )
            .is_err()
        );

        // 2. Second CA without CRL (strict_crl = false) does not conflict with first CA's CRL
        let non_conflicting_cas = vec![
            ClientCertConfig {
                ssl_client_ca: common::test_pki::TestPki::s(&pki.relay_ca_pem).to_string(),
                ssl_client_crl: Some(common::test_pki::TestPki::s(&pki.relay_crl_pem).to_string()),
                strict_crl: true,
            },
            ClientCertConfig {
                ssl_client_ca: common::test_pki::TestPki::s(&pki.public_ca_pem).to_string(),
                ssl_client_crl: None,
                strict_crl: false,
            },
        ];
        assert!(
            tls_config(
                "non_conflicting_crl_strictness",
                &srv_cert,
                Some(&non_conflicting_cas),
                crate::configuration::AuthenticationMethod::ClientCert,
            )
            .is_ok()
        );

        Ok(())
    }

    #[test]
    fn test_tls_config_preserving_sessions_resumes_across_reload_and_invalidates_on_crl_change()
    -> Result<(), Box<dyn std::error::Error>> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let pki = common::test_pki::TestPki::new();

        let drive_handshake = |server_cfg: &Arc<RustlsServerConfig>,
                               client_cfg: &Arc<rustls::ClientConfig>|
         -> Result<Option<rustls::HandshakeKind>, Box<dyn std::error::Error>> {
            let sni = rustls::pki_types::ServerName::try_from("localhost".to_string())?;
            let mut client = rustls::ClientConnection::new(Arc::clone(client_cfg), sni)?;
            let mut server = rustls::ServerConnection::new(Arc::clone(server_cfg))?;

            let mut c2s = Vec::new();
            let mut s2c = Vec::new();
            for _ in 0..16 {
                let mut tmp = Vec::new();
                while client.wants_write() {
                    client.write_tls(&mut tmp)?;
                }
                c2s.extend_from_slice(&tmp);

                if !c2s.is_empty() {
                    let mut cursor = std::io::Cursor::new(&c2s);
                    let read = server.read_tls(&mut cursor)?;
                    c2s.drain(..read);
                    server.process_new_packets()?;
                }

                let mut stmp = Vec::new();
                while server.wants_write() {
                    server.write_tls(&mut stmp)?;
                }
                s2c.extend_from_slice(&stmp);

                if !s2c.is_empty() {
                    let mut cursor = std::io::Cursor::new(&s2c);
                    let read = client.read_tls(&mut cursor)?;
                    s2c.drain(..read);
                    client.process_new_packets()?;
                }

                if !client.is_handshaking() && !server.is_handshaking() {
                    // Drain any post-handshake TLS 1.3 NewSessionTicket messages from server to client
                    if !s2c.is_empty() {
                        let mut cursor = std::io::Cursor::new(&s2c);
                        let read = client.read_tls(&mut cursor)?;
                        s2c.drain(..read);
                        client.process_new_packets()?;
                    }
                    if !server.wants_write() && !client.wants_write() && s2c.is_empty() && c2s.is_empty() {
                        break;
                    }
                }
            }

            Ok(server.handshake_kind())
        };

        let mut root_store = rustls::RootCertStore::empty();
        for cert in load_certs(common::test_pki::TestPki::s(&pki.public_ca_pem), "test_client")? {
            root_store.add(cert)?;
        }

        // 1. Non-mTLS HTTPS with session_cache + session_tickets resumes seamlessly after reload
        let srv_cert = ServerCertConfig {
            ssl_certificate: common::test_pki::TestPki::s(&pki.praeco_public_pem).to_string(),
            ssl_certificate_key: common::test_pki::TestPki::s(&pki.praeco_public_key).to_string(),
            session_cache_size: Some(64),
            session_tickets: true,
        };
        let (cfg_v1, state_v1) = tls_config_preserving_sessions(
            "resumption_pub",
            &srv_cert,
            None,
            crate::configuration::AuthenticationMethod::None,
            None,
        )?;
        let (cfg_v2, _state_v2) = tls_config_preserving_sessions(
            "resumption_pub",
            &srv_cert,
            None,
            crate::configuration::AuthenticationMethod::None,
            Some(&state_v1),
        )?;

        let mut pub_client_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(root_store.clone())
            .with_no_client_auth();
        pub_client_cfg.resumption = rustls::client::Resumption::in_memory_sessions(32);
        let pub_client_cfg = Arc::new(pub_client_cfg);

        assert_eq!(
            drive_handshake(&Arc::new(cfg_v1), &pub_client_cfg)?,
            Some(rustls::HandshakeKind::Full)
        );
        assert_eq!(
            drive_handshake(&Arc::new(cfg_v2), &pub_client_cfg)?,
            Some(rustls::HandshakeKind::Resumed)
        );

        // 2. mTLS with explicit session cache preserves sessions when CRL bytes are unchanged,
        //    and invalidates resumption immediately when CRL bytes change on reload.
        let mtls_srv_cert = ServerCertConfig {
            ssl_certificate: common::test_pki::TestPki::s(&pki.praeco_public_pem).to_string(),
            ssl_certificate_key: common::test_pki::TestPki::s(&pki.praeco_public_key).to_string(),
            session_cache_size: Some(64),
            session_tickets: false,
        };
        let ca_v1 = vec![ClientCertConfig {
            ssl_client_ca: common::test_pki::TestPki::s(&pki.relay_ca_pem).to_string(),
            ssl_client_crl: Some(common::test_pki::TestPki::s(&pki.relay_crl_pem).to_string()),
            strict_crl: true,
        }];
        let (mtls_v1, mtls_state_v1) = tls_config_preserving_sessions(
            "resumption_mtls",
            &mtls_srv_cert,
            Some(&ca_v1),
            crate::configuration::AuthenticationMethod::ClientCert,
            None,
        )?;
        let (mtls_v2_same_crl, mtls_state_v2) = tls_config_preserving_sessions(
            "resumption_mtls",
            &mtls_srv_cert,
            Some(&ca_v1),
            crate::configuration::AuthenticationMethod::ClientCert,
            Some(&mtls_state_v1),
        )?;

        let ca_v3_updated_crl = vec![ClientCertConfig {
            ssl_client_ca: common::test_pki::TestPki::s(&pki.relay_ca_pem).to_string(),
            ssl_client_crl: Some(
                common::test_pki::TestPki::s(&pki.relay_crl_revoking_client_pem).to_string(),
            ),
            strict_crl: true,
        }];
        let (mtls_v3_new_crl, _) = tls_config_preserving_sessions(
            "resumption_mtls",
            &mtls_srv_cert,
            Some(&ca_v3_updated_crl),
            crate::configuration::AuthenticationMethod::ClientCert,
            Some(&mtls_state_v2),
        )?;

        let client_certs = load_certs(common::test_pki::TestPki::s(&pki.nosan_client_pem), "cli")?;
        let client_key = load_single_key(common::test_pki::TestPki::s(&pki.nosan_client_key), "cli")?;
        let mut mtls_client_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(client_certs, client_key)?;
        mtls_client_cfg.resumption = rustls::client::Resumption::in_memory_sessions(32);
        let mtls_client_cfg = Arc::new(mtls_client_cfg);

        assert_eq!(
            drive_handshake(&Arc::new(mtls_v1), &mtls_client_cfg)?,
            Some(rustls::HandshakeKind::Full)
        );
        assert_eq!(
            drive_handshake(&Arc::new(mtls_v2_same_crl), &mtls_client_cfg)?,
            Some(rustls::HandshakeKind::Resumed)
        );
        assert_eq!(
            drive_handshake(&Arc::new(mtls_v3_new_crl), &mtls_client_cfg)?,
            Some(rustls::HandshakeKind::Full)
        );

        Ok(())
    }

    #[test]
    fn test_extract_client_metadata_with_base_single_der_parse_extracts_pem_san_and_oids()
    -> Result<(), Box<dyn std::error::Error>> {
        let pki = common::test_pki::TestPki::new();
        let certs = common::load_certs(
            common::test_pki::TestPki::s(&pki.praeco_client_pem),
            "test_single_pass_meta",
        )?;
        let leaf_der = certs
            .first()
            .ok_or("missing leaf cert in praeco_client_pem")?
            .as_ref();
        let base_oid = [1u64, 3, 6, 1, 4, 1, 65111];

        let meta = extract_client_metadata_with_base(Some(&certs), Some(&base_oid));
        let (expected_pem, expected_san) = extract_cert_san_and_pem(leaf_der);
        let expected_oids = extract_oids_from_cert_with_base(leaf_der, Some(&base_oid));

        assert!(meta.pem.is_some());
        assert!(meta.san.as_deref().is_some_and(|s| s.ends_with(".aweirich.eu")));
        assert_eq!(meta.pem, expected_pem);
        assert_eq!(meta.san, expected_san);
        assert_eq!(meta.oids, vec!["1"]);
        assert_eq!(meta.oids, expected_oids);
        Ok(())
    }
}
