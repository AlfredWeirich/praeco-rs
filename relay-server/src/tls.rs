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


/// Loads certificates and constructs a [`TlsAcceptor`] configured for strict mTLS
/// with strict CRL enforcement enabled by default (`strict_crl = true`).
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
    setup_mtls_acceptor_with_strict(ca_path, cert_path, key_path, crl_path, true)
}

/// Like [`setup_mtls_acceptor`], with an explicit `strict_crl` default (still overridable via
/// `PRAECO_STRICT_CRL`).
///
/// When strict CRL mode is active, expired, empty, unparseable, or `nextUpdate`-less CRLs are
/// rejected at load time and `rustls`'s `enforce_revocation_expiration()` enforces `nextUpdate`
/// during every subsequent mTLS handshake.
pub fn setup_mtls_acceptor_with_strict(
    ca_path: &str,
    cert_path: &str,
    key_path: &str,
    crl_path: Option<&String>,
    strict_crl_default: bool,
) -> Result<TlsAcceptor, RelayError> {
    let mut root_store = RootCertStore::empty();
    for cert in CertificateDer::pem_file_iter(ca_path)? {
        root_store.add(cert?)?;
    }

    let mut verifier_builder = WebPkiClientVerifier::builder(Arc::new(root_store));

    if let Some(path) = crl_path {
        let strict_crl = common::crl::resolve_strict_crl(strict_crl_default);
        let crls =
            CertificateRevocationListDer::pem_file_iter(path)?.collect::<Result<Vec<_>, _>>()?;
        if crls.is_empty() {
            return Err(RelayError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("CRL file '{path}' contains no CRL entries"),
            )));
        }
        for crl_der in &crls {
            if let Err(err) = common::crl::check_crl_not_expired(crl_der.as_ref()) {
                warn!(crl_path = %path, error = %err, "CRL validation check failed");
                if strict_crl {
                    return Err(RelayError::Io(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "Rejecting CRL '{path}' because strict CRL validation is enabled: {err}"
                        ),
                    )));
                }
            }
        }
        verifier_builder = verifier_builder.with_crls(crls);
        if strict_crl {
            verifier_builder = verifier_builder.enforce_revocation_expiration();
        }
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
///
/// Fails closed if the file contains no CRL PEM blocks or any CRL fails DER parsing.
pub fn parse_revoked_serials_from_crl_pem(
    crl_path: &str,
) -> Result<std::collections::HashSet<Vec<u8>>, RelayError> {
    let crls =
        CertificateRevocationListDer::pem_file_iter(crl_path)?.collect::<Result<Vec<_>, _>>()?;
    common::crl::extract_revoked_serials_from_crls(&crls).map_err(|err| {
        RelayError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("Invalid CRL '{crl_path}': {err}"),
        ))
    })
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
///
/// # Errors
///
/// Fails closed if `crl_path` is configured and the initial CRL cannot be parsed.
pub fn spawn_crl_reload_watcher(
    ca_path: String,
    cert_path: String,
    key_path: String,
    crl_path: Option<String>,
    initial_acceptor: TlsAcceptor,
    reload_interval: Duration,
    cancel_token: CancellationToken,
) -> Result<tokio::sync::watch::Receiver<ControlPlaneReloadState>, RelayError> {
    spawn_crl_reload_watcher_with_strict(
        ca_path,
        cert_path,
        key_path,
        crl_path,
        initial_acceptor,
        reload_interval,
        cancel_token,
        true,
    )
}

/// Like [`spawn_crl_reload_watcher`], with an explicit `strict_crl_default` flag.
#[allow(clippy::too_many_arguments)]
pub fn spawn_crl_reload_watcher_with_strict(
    ca_path: String,
    cert_path: String,
    key_path: String,
    crl_path: Option<String>,
    initial_acceptor: TlsAcceptor,
    reload_interval: Duration,
    cancel_token: CancellationToken,
    strict_crl_default: bool,
) -> Result<tokio::sync::watch::Receiver<ControlPlaneReloadState>, RelayError> {
    let initial_serials = match crl_path.as_deref() {
        Some(p) => parse_revoked_serials_from_crl_pem(p)?,
        None => std::collections::HashSet::new(),
    };
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
        return Ok(rx);
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
            let reload_res = tokio::task::spawn_blocking({
                let ca = ca_path.clone();
                let cert = cert_path.clone();
                let key = key_path.clone();
                let crl = path.clone();
                move || -> Result<(TlsAcceptor, std::collections::HashSet<Vec<u8>>), RelayError> {
                    let acceptor =
                        setup_mtls_acceptor_with_strict(&ca, &cert, &key, Some(&crl), strict_crl_default)?;
                    let serials = parse_revoked_serials_from_crl_pem(&crl)?;
                    Ok((acceptor, serials))
                }
            })
            .await;

            match reload_res {
                Ok(Ok((new_acceptor, serials))) => {
                    let _ = tx.send(ControlPlaneReloadState {
                        acceptor: new_acceptor,
                        revoked_serials: Arc::new(serials),
                    });
                }
                Ok(Err(e)) => {
                    warn!(
                        target: "relay::control_plane",
                        crl_path = %path,
                        error = %e,
                        "Failed to reload CRL on control plane; keeping previous CRL state"
                    );
                }
                Err(e) => {
                    warn!(
                        target: "relay::control_plane",
                        crl_path = %path,
                        error = %e,
                        "CRL reload task failed; keeping previous CRL state"
                    );
                }
            }
        }
    });

    Ok(rx)
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

