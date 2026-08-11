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

/// Recursive OID value testing utility.
///
/// This tool parses X.509 certificates and extracts custom extensions,
/// specifically focusing on UUID-based OIDs.
use std::env;
use std::error::Error;
use std::fs;
use x509_parser::der_parser::ber::BerObjectContent;
use x509_parser::prelude::*;

/// Main entry point for the certificate decoder.
///
/// Usage: `cert_decoder <path_to_cert.pem>`
///
/// It performs the following steps:
/// 1. Reads a PEM-encoded certificate from the disk.
/// 2. Parses the certificate using `x509_parser`.
/// 3. Iterates through all extensions and print them
fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <path_to_cert.pem>", args[0]);
        return Ok(());
    }

    // Load and parse the certificate
    let cert_file_content = fs::read(&args[1])?;
    let (_, pem) = x509_parser::pem::parse_x509_pem(&cert_file_content)?;
    let (_, x509) = X509Certificate::from_der(&pem.contents)?;

    println!("Subject: {}", x509.subject());
    println!("\n--- Extensions Found ---");

    ////////////// All extensions

    // for ext in x509.extensions() {
    //     let oid_str = ext.oid.to_string();
    //     print!("OID: {:<30}", oid_str);

    //     // 1st attempt: Parse known X.509 standard extensions
    //     match ext.parsed_extension() {
    //         ParsedExtension::BasicConstraints(bc) => {
    //             // Field is called 'path_len_constraint' instead of 'path_len'
    //             println!(
    //                 "-> Basic Constraints: CA={}, MaxPathLen={:?}",
    //                 bc.ca, bc.path_len_constraint
    //             );
    //         }
    //         ParsedExtension::KeyUsage(ku) => {
    //             // Flags are available as bit properties
    //             println!(
    //                 "-> Key Usage: DigitalSig={}, KeyEnciph={}",
    //                 ku.digital_signature(),
    //                 ku.key_encipherment()
    //             );
    //         }
    //         ParsedExtension::ExtendedKeyUsage(eku) => {
    //             // Instead of a list of OIDs, the library offers flags for the most common types
    //             println!(
    //                 "-> Extended Key Usage: ClientAuth={}, ServerAuth={}",
    //                 eku.client_auth, eku.server_auth
    //             );
    //         }
    //         ParsedExtension::SubjectKeyIdentifier(ski) => {
    //             println!("-> SKI: {:02X?}", ski.0);
    //         }
    //         ParsedExtension::AuthorityKeyIdentifier(aki) => {
    //             // Field is called 'key_identifier'
    //             println!("-> AKI: {:02X?}", aki.key_identifier);
    //         }
    //         _ => {
    //             // Your custom OIDs end up here
    //             if let Ok((_, ber)) = x509_parser::der_parser::parse_der(ext.value) {
    //                 decode_ber_content(&ber.content, 0);
    //             }
    //         }
    //     }
    // }

    ////////////// Only custom extensions
    for ext in x509.extensions() {
        let oid_str = ext.oid.to_string(); // Note: This works with large OIDs thanks to internal bigint support.

        // We are specifically looking for UUID-based OIDs (2.25.x)
        //if oid_str.starts_with("2.25.") {
        println!("OID: {} [UUID-based]", oid_str);

        // Attempt to parse the DER-encoded value of the extension.
        if let Ok((_, ber)) = x509_parser::der_parser::parse_der(ext.value) {
            // If it's a UTF8String (common for our mappings), print the value in green.
            if let BerObjectContent::UTF8String(s) = ber.content {
                println!("  -> Value: \x1b[32m{}\x1b[0m", s);
            }
        }
        //}
    }

    Ok(())
}

/// A recursive helper function to decode and display ASN.1 / BER structures.
///
/// This is useful for inspecting complex or nested extension values.
#[allow(dead_code)]
fn decode_ber_content(content: &BerObjectContent, depth: usize) {
    let indent = "  ".repeat(depth);
    match content {
        // Direct string types
        BerObjectContent::UTF8String(s)
        | BerObjectContent::PrintableString(s)
        | BerObjectContent::IA5String(s) => {
            println!("{}-> Value: \x1b[32m{}\x1b[0m", indent, s);
        }
        // Nested containers (like OCTET STRING in X.509)
        BerObjectContent::OctetString(bytes) => {
            // Try to interpret the content of the OctetString as DER again.
            if let Ok((_, inner_ber)) = x509_parser::der_parser::parse_der(bytes) {
                decode_ber_content(&inner_ber.content, depth + 1);
            } else {
                // If it's not valid DER, it might be a raw hash or opaque data.
                println!("{}-> OctetString (Hex): {:02X?}", indent, bytes);
            }
        }
        // Sequences (used for things like Key Usage, Basic Constraints, etc.)
        BerObjectContent::Sequence(nodes) => {
            println!("{}-> Sequence:", indent);
            for node in nodes {
                decode_ber_content(&node.content, depth + 1);
            }
        }
        BerObjectContent::Integer(i) => {
            println!("{}-> Integer: {:?}", indent, i);
        }
        BerObjectContent::OID(oid) => {
            println!("{}-> OID: {}", indent, oid);
        }
        BerObjectContent::Boolean(b) => {
            println!("{}-> Boolean: {}", indent, b);
        }
        _ => {
            println!("{}-> [Complex/Other Type: {:?}]", indent, content);
        }
    }
}

/*
// --- VERSION 1: Working with "short" UUIDs ---
// (Commented out for reference)

fn main_short() -> Result<(), Box<dyn Error>> {
    // ...
    for ext in x509.extensions() {
        let oid_str = ext.oid.to_string();
        // Filter for 2.25... or the hex overflow "69..."
        let is_uuid_oid = oid_str.starts_with("69") || oid_str.starts_with("2.25");
        // ... decoding logic ...
    }
    Ok(())
}
*/

/*
// --- VERSION 2: Working with "real" UUIDs and manual VLQ decoding ---
// (Commented out for reference)

fn format_huge_oid(oid: &Oid) -> String {
    let bytes = oid.as_bytes();
    // ... manual decoding logic for huge OIDs ...
}
*/
