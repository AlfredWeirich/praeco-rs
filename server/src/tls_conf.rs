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
use rustls_pki_types::{CertificateRevocationListDer, pem::PemObject};
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
    let server_certs = load_certs(&server_cert_config.ssl_certificate, server_name);
    trace!("{}: Server certificates loaded successfully.", server_name);

    let server_key = load_single_key(&server_cert_config.ssl_certificate_key, server_name);
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
}

impl DynamicCertResolver {
    pub fn new(server_name: &'static str) -> Self {
        Self { server_name }
    }
}

impl ResolvesServerCert for DynamicCertResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let config = crate::configuration::Config::global();
        config
            .servers
            .iter()
            .find(|s| s.static_name == Some(self.server_name))
            .and_then(|s| s.certified_key.clone())
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
/// - `require_client_auth`: Whether to enforce mTLS (client certificate verification).
///
/// # Returns
///
/// Returns a fully configured [`RustlsServerConfig`] that can be used to run
/// a secure TLS server with (optional) client certificate verification.
///
/// # ALPN Protocols
///
/// The returned config advertises support for `h3`, `h2`, and `http/1.1` in
/// that preference order, enabling HTTP/3, HTTP/2, and HTTP/1.1 negotiation.
///
/// # Errors
///
/// Returns an error if any certificate or private key file fails to load, is malformed, or if
/// configuration cannot be completed.
///
/// # Panics
///
/// This function will panic only if a `.expect()` is triggered inside a utility function
/// (not expected if `load_certs`/`load_single_key` are implemented with Result).
pub fn tls_config(
    server_name: &'static str,
    _server_cert_config: &ServerCertConfig, // Kept for signature compatibility for now, but not used directly
    client_ca_configs: Option<&[ClientCertConfig]>,
    require_client_auth: bool,
) -> Result<RustlsServerConfig, Error> {
    // Create a fresh Rustls config builder (TLS 1.3 by default)
    let config_builder = rustls::ServerConfig::builder();

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

        // Collect Certificate Revocation Lists (CRLs) if specified in client CA configs.
        // CRLs allow the server to reject certificates that have been revoked by the CA.
        let mut crls: Vec<CertificateRevocationListDer<'_>> = Vec::with_capacity(20);
        for config in client_certs {
            // Load one or more CA certs for this config
            let ca_certs = load_certs(&config.ssl_client_ca, server_name);
            for ca in ca_certs {
                // Add each CA cert to the root store for client verification
                root_store
                    .add(ca)
                    .map_err(|e| Error::msg(format!("{server_name}: Failed to add CA: {e}")))?;
                trace!("{server_name}: Added CA from {}", config.ssl_client_ca);
            }
            if let Some(ref crl_path) = config.ssl_client_crl {
                let crl = CertificateRevocationListDer::from_pem_file(crl_path).map_err(|e| {
                    Error::msg(format!(
                        "{server_name}: Failed to load CRL from '{crl_path}': {e}"
                    ))
                })?;
                trace!("{server_name}: Added CRL from {crl_path}");
                crls.push(crl);
            }
        }

        // Build a WebPKI-based client certificate verifier with loaded root CAs and CRLs.
        // This verifier checks that client certificates are signed by a trusted CA
        // and have not been revoked (if CRLs are provided).
        let client_verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
            .with_crls(crls)
            //.allow_unknown_revocation_status()
            .build()
            .map_err(|e| {
                Error::msg(format!(
                    "{server_name}: Failed to build client verifier: {e}",
                ))
            })?;

        // Attach verifier and a dynamic cert resolver to the config builder

        config_builder
            .with_client_cert_verifier(client_verifier)
            .with_cert_resolver(Arc::new(DynamicCertResolver::new(server_name)))
    } else {
        // No client authentication; set up standard HTTPS only

        config_builder
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(DynamicCertResolver::new(server_name)))
    };

    let mut config = config;
    // Optimization 7
    // Enable TLS session resumption — reconnecting clients skip the full
    // handshake, saving a round-trip. 1024 entries covers high-concurrency.
    config.session_storage = rustls::server::ServerSessionMemoryCache::new(1024);
    // Enable ALPN for HTTP/3, HTTP/2, and HTTP/1.1 negotiation.
    // The order indicates server preference (H3 > H2 > H1.1).
    config.alpn_protocols = vec![b"h3".to_vec(), b"h2".to_vec(), b"http/1.1".to_vec()];

    trace!(
        "{}: {} server TLS configuration completed.",
        server_name,
        if require_client_auth { "mTLS" } else { "HTTPS" }
    );

    Ok(config)
}

/// Extracts custom PKI OIDs from a DER-encoded X.509 certificate.
///
/// Iterates over every extension in the certificate, checks if its OID starts
/// with the globally configured `pki_base_oid` prefix, and if so, returns the
/// trailing suffix components as dot-separated strings.
///
/// # Performance Optimized
///
/// This function avoids allocating strings for every OID in the certificate.
/// It compares the raw integer components of the OID against the pre-computed
/// base OID configuration stored in [`Config::parsed_pki_base_oid`](crate::configuration::Config::parsed_pki_base_oid).
///
/// Allocations only occur if a valid match is found and we need to return the suffix.
///
/// # Example
///
/// If the base OID is `2.25` and the certificate contains an extension with
/// OID `2.25.42.7`, this function returns `vec!["42.7"]`.
///
/// # Arguments
///
/// * `cert_der` – Raw DER-encoded bytes of the X.509 certificate.
///
/// # Returns
///
/// A `Vec<String>` of OID suffixes (e.g. `["1", "2.3"]`). Empty if no
/// matching extensions are found or if `pki_base_oid` is not configured.
pub fn extract_oids_from_cert(cert_der: &[u8]) -> Vec<String> {
    let mut oids = Vec::new();
    let config = crate::configuration::Config::global();

    // 1. Get the pre-computed base OID (Vec<u64>).
    //    If not configured or empty, there's nothing to match against.
    let base_components = match config.parsed_pki_base_oid.as_deref() {
        Some(v) if !v.is_empty() => v,
        _ => return oids,
    };

    // 2. Parse the DER-encoded certificate using x509-parser.
    if let Ok((_, x509)) = X509Certificate::from_der(cert_der) {
        for ext in x509.extensions() {
            // Get an iterator over the OID's integer components.
            let mut oid_iter = match ext.oid.iter() {
                Some(iter) => iter, // Correct for x509-parser v0.16+
                None => continue,   // Parsing failed or empty
            };

            // 3. CHECK PREFIX — Compare each component of the base OID against
            //    the certificate extension's OID, both in u64 space.
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

            // 4. EXTRACT SUFFIX — Collect the remaining components after the
            //    base prefix into a dot-separated string.
            if is_match {
                let suffix_parts: Vec<String> = oid_iter.map(|u| u.to_string()).collect();

                if !suffix_parts.is_empty() {
                    oids.push(suffix_parts.join("."));
                }
            }
        }
    }
    oids
}

/// Extracts the full PEM-encoded certificate and its SAN (Subject Alternative Name)
/// from a DER-encoded X.509 certificate.
pub fn extract_cert_san_and_pem(cert_der: &[u8]) -> (Option<String>, Option<String>) {
    // 1. Encode DER to PEM
    let pem = ::pem::encode(&::pem::Pem::new("CERTIFICATE", cert_der));

    // 2. Extract SAN
    let mut san_dns = None;
    match X509Certificate::from_der(cert_der) {
        Ok((_, x509)) => {
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
                            san_dns = Some(domain.to_string());
                            tracing::debug!("Extracted DNSName SAN: {}", domain);
                            break;
                        }
                    }
                }
            }
            if !found_san_ext {
                tracing::debug!("No SubjectAlternativeName extension found in client cert!");
            }
        }
        Err(e) => {
            tracing::warn!("Failed to parse client cert DER: {:?}", e);
        }
    }
    (Some(pem), san_dns)
}
