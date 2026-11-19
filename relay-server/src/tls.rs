//! TLS/mTLS acceptor setup, CRL expiration checks, live reload watcher, and X.509 helpers.

use crate::RelayError;
use rustls::RootCertStore;
use rustls::pki_types::{
    CertificateDer, CertificateRevocationListDer, PrivateKeyDer, pem::PemObject,
};
use rustls::server::WebPkiClientVerifier;
use std::sync::Arc;
use std::time::Duration;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

/// Computes a 32-byte SHA-256 fingerprint of a DER-encoded X.509 certificate
/// using `rustls`'s active `aws-lc-rs` hash provider.
pub(crate) fn cert_sha256_fingerprint(cert_der: &[u8]) -> Option<[u8; 32]> {
    let hash_provider = rustls::crypto::aws_lc_rs::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256
        .tls13()?
        .common
        .hash_provider;
    let digest = hash_provider.hash(cert_der);
    let mut out = [0u8; 32];
    if digest.as_ref().len() == 32 {
        out.copy_from_slice(digest.as_ref());
        Some(out)
    } else {
        None
    }
}


/// Loads certificates and constructs a [`TlsAcceptor`] configured for strict mTLS.
///
/// # Errors
///
/// Returns a [`RelayError`] if any certificate, CRL, or private key file cannot be read or parsed,
/// or if the `rustls` verifier or server config fails to build.
pub fn setup_mtls_acceptor(
    ca_path: &str,
    cert_path: &str,
    key_path: &str,
    crl_path: Option<&String>,
) -> Result<TlsAcceptor, RelayError> {
    let mut root_store = RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(ca_path)? {
        root_store.add(cert?)?;
    }

    let mut verifier_builder = WebPkiClientVerifier::builder(Arc::new(root_store));

    if let Some(path) = crl_path {
        let strict_crl = std::env::var("PRAECO_STRICT_CRL")
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let crls =
            CertificateRevocationListDer::pem_file_iter(path)?.collect::<Result<Vec<_>, _>>()?;
        for crl_der in &crls {
            let mut crl_invalid_or_expired = false;
            match x509_parser::parse_x509_crl(crl_der.as_ref()) {
                Ok((_, parsed_crl)) => {
                    if let Some(next_update) = parsed_crl.next_update() {
                        let now_ts = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs() as i64)
                            .unwrap_or(0);
                        if next_update.timestamp() < now_ts {
                            warn!(
                                crl_path = %path,
                                next_update = %next_update,
                                "Loaded CRL has expired (nextUpdate is in the past)! Revocation checks may use stale data."
                            );
                            crl_invalid_or_expired = true;
                        }
                    } else {
                        warn!(crl_path = %path, "Loaded CRL does not contain a nextUpdate field.");
                        crl_invalid_or_expired = true;
                    }
                }
                Err(e) => {
                    warn!(crl_path = %path, error = %e, "Failed to parse CRL with x509-parser for expiration check");
                    crl_invalid_or_expired = true;
                }
            }
            if crl_invalid_or_expired && strict_crl {
                return Err(RelayError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "Rejecting CRL '{path}' because PRAECO_STRICT_CRL is enabled and the CRL is expired or invalid"
                    ),
                )));
            }
        }
        verifier_builder = verifier_builder.with_crls(crls);
    }

    let verifier = verifier_builder.build()?;

    let certs: Vec<CertificateDer> =
        CertificateDer::pem_file_iter(cert_path)?.collect::<Result<Vec<_>, _>>()?;
    let key = PrivateKeyDer::from_pem_file(key_path)?;

    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

/// Parses all revoked certificate serial numbers (raw DER integer bytes) from a PEM-encoded CRL file.
pub fn parse_revoked_serials_from_crl_pem(
    crl_path: &str,
) -> Result<std::collections::HashSet<Vec<u8>>, RelayError> {
    let mut serials = std::collections::HashSet::new();
    let crls =
        CertificateRevocationListDer::pem_file_iter(crl_path)?.collect::<Result<Vec<_>, _>>()?;
    for crl_der in &crls {
        if let Ok((_, parsed_crl)) = x509_parser::parse_x509_crl(crl_der.as_ref()) {
            for revoked in parsed_crl.iter_revoked_certificates() {
                serials.insert(revoked.raw_serial().to_vec());
            }
        }
    }
    Ok(serials)
}

/// Extracts the leaf certificate's `notAfter` UNIX timestamp (seconds) and raw serial bytes.
pub fn extract_cert_expiry_and_serial(cert_der: &[u8]) -> Option<(i64, Vec<u8>)> {
    let (_, cert) = x509_parser::parse_x509_certificate(cert_der).ok()?;
    let not_after = cert.validity().not_after.timestamp();
    let serial = cert.raw_serial().to_vec();
    Some((not_after, serial))
}

pub(crate) fn current_unix_timestamp() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Live-reloaded mTLS acceptor and revoked certificate serial set for the Control Plane.
#[derive(Clone)]
pub struct ControlPlaneReloadState {
    /// Updated mTLS acceptor constructed with the latest CA/cert/key/CRL files.
    pub acceptor: TlsAcceptor,
    /// Set of raw certificate serial numbers present in the latest CRL.
    pub revoked_serials: Arc<std::collections::HashSet<Vec<u8>>>,
}


/// Spawns a background task that periodically reloads the mTLS [`TlsAcceptor`] and CRL serial
/// denylist from disk (and on `SIGHUP` on Unix), broadcasting updates to the Control Plane
/// and all active tunnel drivers.
pub fn spawn_crl_reload_watcher(
    ca_path: String,
    cert_path: String,
    key_path: String,
    crl_path: Option<String>,
    initial_acceptor: TlsAcceptor,
    reload_interval: Duration,
    cancel_token: CancellationToken,
) -> tokio::sync::watch::Receiver<ControlPlaneReloadState> {
    let initial_serials = crl_path
        .as_deref()
        .and_then(|p| parse_revoked_serials_from_crl_pem(p).ok())
        .unwrap_or_default();
    let (tx, rx) = tokio::sync::watch::channel(ControlPlaneReloadState {
        acceptor: initial_acceptor,
        revoked_serials: Arc::new(initial_serials),
    });

    if crl_path.is_none() || reload_interval.is_zero() {
        // Keep sender alive in a lightweight task until shutdown so receivers don't see channel close.
        tokio::spawn(async move {
            let _tx = tx;
            cancel_token.cancelled().await;
        });
        return rx;
    }

    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(reload_interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Consume immediate first tick
        ticker.tick().await;

        #[cfg(unix)]
        let mut sighup = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::hangup()).ok();

        loop {
            #[cfg(unix)]
            tokio::select! {
                _ = cancel_token.cancelled() => break,
                _ = ticker.tick() => {}
                Some(_) = async {
                    match sighup.as_mut() {
                        Some(sig) => sig.recv().await,
                        None => std::future::pending().await,
                    }
                } => {
                    info!(target: "relay::control_plane", "Received SIGHUP, reloading mTLS acceptor and CRL");
                }
            }

            #[cfg(not(unix))]
            tokio::select! {
                _ = cancel_token.cancelled() => break,
                _ = ticker.tick() => {}
            }

            let Some(ref path) = crl_path else {
                continue;
            };
            match (
                setup_mtls_acceptor(&ca_path, &cert_path, &key_path, Some(path)),
                parse_revoked_serials_from_crl_pem(path),
            ) {
                (Ok(new_acceptor), Ok(serials)) => {
                    let _ = tx.send(ControlPlaneReloadState {
                        acceptor: new_acceptor,
                        revoked_serials: Arc::new(serials),
                    });
                }
                (Err(e), _) | (_, Err(e)) => {
                    warn!(
                        target: "relay::control_plane",
                        crl_path = %path,
                        error = %e,
                        "Failed to reload CRL on control plane; keeping previous CRL state"
                    );
                }
            }
        }
    });

    rx
}

/// Extracts all DNS Subject Alternative Names (SANs) from a DER-encoded X.509 certificate.
pub fn extract_allowed_snis(cert_der: &[u8]) -> Vec<String> {
    let mut allowed_snis = Vec::new();
    if let Ok((_, cert)) = x509_parser::parse_x509_certificate(cert_der) {
        for ext in cert.iter_extensions() {
            if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) =
                ext.parsed_extension()
            {
                for name in &san.general_names {
                    if let x509_parser::extensions::GeneralName::DNSName(dns) = name {
                        allowed_snis.push(dns.to_string());
                    }
                }
            }
        }
    }
    allowed_snis
}

