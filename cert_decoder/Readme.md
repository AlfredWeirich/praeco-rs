# praeco-cert-decoder

**praeco-cert-decoder** is a lightweight utility crate for decoding and inspecting X.509 certificates.

In the `praeco-rs` ecosystem, this tool is essential for the zero-trust RBAC (Role-Based Access Control) architecture. It allows the proxy to parse client certificates during the mTLS handshake and extract custom enterprise OIDs (Object Identifiers). These OIDs are then mapped to specific user roles dynamically.

## Features

- Parse PEM-encoded X.509 certificates.
- Extract generic extensions and custom OID payloads.
- Fast and memory-safe utilizing `asn1-rs` and `x509-parser`.

## Usage

```toml
[dependencies]
praeco-cert-decoder = "0.1.0"
```

## Example (CLI)

You can run the decoder directly against any PEM certificate to inspect the extracted OIDs and their values:

```bash
# Run the decoder against a test client certificate
$ cargo run -p praeco-cert-decoder -- client_certs/client.cert.pem

Subject: CN=Client
--- Extensions Found ---
OID: 2.5.29.19 [UUID-based]
OID: 2.25.1234567890 [UUID-based]
  -> Value: UserRole("Admin")
```

## Example (Rust Integration)

If you want to invoke the decoder programmatically in tests:

```rust
use std::process::Command;

fn main() {
    // Call the CLI tool programmatically
    let output = Command::new("cargo")
        .args(["run", "-p", "praeco-cert-decoder", "--", "client_certs/client.cert.pem"])
        .output()
        .expect("Failed to execute cert decoder");

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        println!("Decoder Output:\n{}", stdout);
    } else {
        println!("Error running decoder");
    }
}
```
