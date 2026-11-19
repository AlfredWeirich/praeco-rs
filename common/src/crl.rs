//! Shared X.509 CRL parsing, expiration validation, and strict-mode helpers.
//!
//! Used by both `praeco-rs` and `praeco-relay-server` so CRL handling cannot diverge.

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use rustls_pki_types::CertificateRevocationListDer;
use thiserror::Error;

/// Error returned when validating or parsing a DER-encoded X.509 CRL.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CrlValidationError {
    /// The CRL file contained zero `X509 CRL` PEM blocks.
    #[error("CRL contains no entries/blocks")]
    Empty,

    /// DER parsing of the X.509 CRL failed.
    #[error("Failed to parse CRL: {0}")]
    Parse(String),

    /// The CRL lacks the mandatory `nextUpdate` timestamp.
    #[error("CRL does not contain a nextUpdate field")]
    MissingNextUpdate,

    /// The CRL's `nextUpdate` timestamp is in the past.
    #[error("CRL has expired (nextUpdate: {next_update})")]
    Expired { next_update: String },
}

/// Checks a single DER-encoded X.509 CRL for structural validity and expiration (`nextUpdate`).
pub fn check_crl_not_expired(crl_der: &[u8]) -> Result<(), CrlValidationError> {
    let (_, parsed_crl) = x509_parser::parse_x509_crl(crl_der)
        .map_err(|e| CrlValidationError::Parse(e.to_string()))?;

    let Some(next_update) = parsed_crl.next_update() else {
        return Err(CrlValidationError::MissingNextUpdate);
    };

    let now_ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    if next_update.timestamp() < now_ts {
        return Err(CrlValidationError::Expired {
            next_update: next_update.to_string(),
        });
    }

    Ok(())
}

/// Extracts all revoked certificate serial numbers from a non-empty slice of DER-encoded CRLs.
///
/// Fails closed if `crls` is empty or any CRL fails X.509 DER parsing so corrupt/truncated
/// CRL files can never silently downgrade to an empty revocation list.
pub fn extract_revoked_serials_from_crls(
    crls: &[CertificateRevocationListDer<'_>],
) -> Result<HashSet<Vec<u8>>, CrlValidationError> {
    if crls.is_empty() {
        return Err(CrlValidationError::Empty);
    }

    let mut serials = HashSet::new();
    for crl_der in crls {
        let (_, parsed_crl) = x509_parser::parse_x509_crl(crl_der.as_ref())
            .map_err(|e| CrlValidationError::Parse(e.to_string()))?;
        for revoked in parsed_crl.iter_revoked_certificates() {
            serials.insert(revoked.raw_serial().to_vec());
        }
    }
    Ok(serials)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_revoked_serials_rejects_empty_and_corrupt_crls() {
        assert_eq!(
            extract_revoked_serials_from_crls(&[]),
            Err(CrlValidationError::Empty)
        );

        let corrupt = vec![CertificateRevocationListDer::from(b"not-a-crl".to_vec())];
        assert!(matches!(
            extract_revoked_serials_from_crls(&corrupt),
            Err(CrlValidationError::Parse(_))
        ));
    }

    #[test]
    fn test_check_crl_not_expired_rejects_corrupt_der() {
        assert!(matches!(
            check_crl_not_expired(b"corrupt-der"),
            Err(CrlValidationError::Parse(_))
        ));
    }
}
