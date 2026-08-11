# praeco-common

**praeco-common** provides shared utilities, types, and connection logic for the `praeco-rs` ecosystem.

It is designed to be a central repository for reusable components such as:
- **HTTP/TLS Connection Pooling**: Pre-configured `hyper` clients with `rustls` integration, ensuring consistent performance and connection limits across the gateway and client utilities.
- **JWT Validation Structures**: Shared token claims and parsing helpers.
- **Security Primitives**: Core structures used for authentication and authorization.

## Usage

This crate is primarily intended to be consumed by other `praeco-*` crates (like `praeco-rs` and `praeco-client`), but can be used standalone if you need a highly optimized HTTP/2 or HTTP/3 compatible Hyper client.

```toml
[dependencies]
praeco-common = "0.1.0"
```

## Example (Rust)

Here is a quick example of how to build a shared hyper client using `praeco-common`:

```rust
use praeco_common::client::{build_hyper_client, ClientPoolConfig};
use praeco_common::tls::build_tls_client_config;
use hyper::body::Bytes;
use http_body_util::Full;

fn main() {
    // 1. Build TLS config (with custom certs if needed)
    // In a real scenario, you'd pass paths to your actual certs.
    let tls_config = build_tls_client_config(None, None, None).unwrap();

    // 2. Define pool configuration
    let pool_config = ClientPoolConfig {
        pool_idle_timeout: std::time::Duration::from_secs(90),
        pool_max_idle_per_host: 1024,
        http2_only: false, // Set true to enforce HTTP/2
    };

    // 3. Build the highly optimized client
    let _client = build_hyper_client::<Full<Bytes>>(tls_config, pool_config);
    println!("Hyper client successfully configured!");
}
```
