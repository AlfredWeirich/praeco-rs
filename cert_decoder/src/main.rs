//! # Certificate Decoder — X.509 Extension Inspector
//!
//! A command-line diagnostic tool that parses a PEM-encoded X.509 certificate
//! and prints all extension OIDs together with their decoded values.
//!
//! This is particularly useful for verifying that custom UUID-based OIDs
//! (arc `2.25`) are correctly embedded in client certificates before
//! deploying them in the mTLS authentication flow.
//!
//! ## Usage
//!
//! ```bash
//! cargo run -p cert_decoder -- path/to/client.cert.pem
//! ```

use std::env;
use std::error::Error;
use std::fs;
use x509_parser::der_parser::ber::BerObjectContent;
use x509_parser::prelude::*;

/// Returns `true` if `oid_str` belongs to the UUID-based OID arc (`2.25.*`).
fn is_uuid_based_oid(oid_str: &str) -> bool {
    oid_str.starts_with("2.25.")
}

/// Replaces control characters (including ANSI/CSI escape sequences) with U+FFFD
/// so untrusted X.509 strings cannot manipulate the operator's terminal.
fn sanitize_terminal_text(input: &str) -> String {
    input
        .chars()
        .map(|c| if c.is_control() { '\u{FFFD}' } else { c })
        .collect()
}

/// Main entry point for the certificate decoder.
///
/// Usage: `cert_decoder <path_to_cert.pem>`
///
/// It performs the following steps:
/// 1. Reads a PEM-encoded certificate from disk.
/// 2. Parses the certificate using `x509_parser`.
/// 3. Iterates through UUID-based (`2.25.*`) extensions and prints sanitized values.
fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <path_to_cert.pem>", args[0]);
        return Ok(());
    }

    let cert_file_content = fs::read(&args[1])?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(&cert_file_content)?;
    let (_, x509) = X509Certificate::from_der(&pem.contents)?;

    let safe_subject = sanitize_terminal_text(&x509.subject().to_string());
    println!("Subject: {}", safe_subject);
    println!("\n--- Extensions Found ---");

    for ext in x509.extensions() {
        let oid_str = ext.oid.to_string();
        if !is_uuid_based_oid(&oid_str) {
            continue;
        }

        println!("OID: {} [UUID-based]", sanitize_terminal_text(&oid_str));

        // Attempt to parse the DER-encoded value of the extension.
        if let Ok((_, ber)) = x509_parser::der_parser::parse_der(ext.value)
            && let BerObjectContent::UTF8String(s) = ber.content
        {
            let safe_value = sanitize_terminal_text(s);
            println!("  -> Value: \x1b[32m{}\x1b[0m", safe_value);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{is_uuid_based_oid, sanitize_terminal_text};

    #[test]
    fn test_is_uuid_based_oid_filters_non_uuid_arcs() {
        assert!(is_uuid_based_oid("2.25.123456789"));
        assert!(!is_uuid_based_oid("2.5.29.17"));
        assert!(!is_uuid_based_oid("1.3.6.1.5.5.7.1.1"));
        assert!(!is_uuid_based_oid("2.25"));
    }

    #[test]
    fn test_sanitize_terminal_text_replaces_control_and_ansi_escapes() {
        let malicious = "role\x1b[31m_admin\r\n\x07";
        let sanitized = sanitize_terminal_text(malicious);
        assert!(!sanitized.contains('\x1b'));
        assert!(!sanitized.contains('\r'));
        assert!(!sanitized.contains('\n'));
        assert!(!sanitized.contains('\x07'));
        assert_eq!(sanitized, "role\u{FFFD}[31m_admin\u{FFFD}\u{FFFD}\u{FFFD}");
        assert_eq!(sanitize_terminal_text("Operator-Role_1"), "Operator-Role_1");
    }
}
