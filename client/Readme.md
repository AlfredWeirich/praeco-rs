# praeco-client

**praeco-client** is a high-performance command-line HTTP/gRPC client designed to interact with and test the `praeco-rs` API Gateway.

*(The name **praeco** comes from Latin, meaning "herald" or "crier" — just as a historical herald controlled the flow of information and announced messages to the public, this gateway acts as the sovereign announcer and gatekeeper for your network traffic).*

> **Note:** This crate is part of the [praeco-rs](https://github.com/AlfredWeirich/praeco-rs) project — an ultra-fast, highly configurable, and secure API Gateway and Reverse Proxy written in Rust. Check out the main repository to see how all the pieces fit together!

## Features

- **mTLS Support**: Easily perform mutual TLS authentication by providing client certificates and private keys.
- **Next-Generation Protocols**: Full support for HTTP/2 and HTTP/3 (QUIC) connections.
- **Diagnostics**: Built-in integration with OpenTelemetry and `tracing` to log connection metrics and request flows.

## Usage

You can run the client from the workspace root:

```bash
cargo run -p praeco-client --release -- --help
```

Use it to securely test your gateway routes that are protected by zero-trust OID-based RBAC policies.

## Example (CLI)

Below is an example of issuing an HTTP/3 (QUIC) POST request with mutual TLS (mTLS) certificates attached:

```bash
# Send an HTTP/3 request to the gateway
$ cargo run -p praeco-client --release -- \
    --http3 \
    --cert client_certs/client.cert.pem \
    --key client_certs/client.key.pem \
    --cacert server_certs/self_signed/myca.pem \
    -X POST \
    -d '{"status": "testing"}' \
    https://127.0.0.1:1337/api/update
```

## Example (Rust Integration)

You can script the client within Rust tests to verify the gateway:

```rust
use std::process::Command;

fn main() {
    // Execute the client CLI programmatically
    let output = Command::new("cargo")
        .args([
            "run", "-p", "praeco-client", "--release", "--",
            "--http3",
            "--cert", "client_certs/client.cert.pem",
            "--key", "client_certs/client.key.pem",
            "--cacert", "server_certs/self_signed/myca.pem",
            "-X", "GET",
            "https://127.0.0.1:1337/help"
        ])
        .output()
        .expect("Failed to execute praeco-client");

    println!("Client Exit Status: {}", output.status);
    println!("Response:\n{}", String::from_utf8_lossy(&output.stdout));
}
```
