# praeco-common

**praeco-common** provides shared utilities, types, and connection logic for the `praeco-rs` ecosystem.

It is designed to be a central repository for reusable components such as:
- **HTTP/TLS Connection Pooling**: Pre-configured `hyper` clients with `rustls` integration, active keep-alive probes, connect timeouts, and strict custom PKI isolation (`build_root_store` trusts *only* the configured custom CA without merging public Mozilla WebPKI roots unless `ca_path` is `None` or `build_root_store_with_webpki` is explicitly used).
- **Client IP Canonicalization (`canonical_client_ip`)**: Normalizes client IP addresses across all rate limiters, connection trackers, and session stores by unwrapping IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d` $\to$ `a.b.c.d`), preserving loopback (`::1`) and unspecified (`::`) addresses, and masking standard IPv6 unicast addresses to their `/64` subnet prefix (`segments[0..4]`) to prevent IPv6 `/64` rotation bypasses.
- **HAProxy PROXY-Protocol v2 (`proxy_protocol`)**: Binary encoder (`encode_proxy_v2`), strict fail-closed parser (`read_proxy_v2` with full 16-byte `InvalidMagic` header preservation and 512-byte payload bounds), and `PrefixedStream` for propagating real client IPs across Yamux Layer-4 tunnels.
- **JWT Validation Structures**: Shared token claims (`Claims`) and parsing helpers.
- **Security Primitives**: Core structures used for authentication, OID role mapping (`UserRole`, `MtlsClaims`), and authorization.

*(The name **praeco** comes from Latin, meaning "herald" or "crier" — just as a historical herald controlled the flow of information and announced messages to the public, this gateway acts as the sovereign announcer and gatekeeper for your network traffic).*

> **Note:** This crate is part of the [praeco-rs](https://github.com/AlfredWeirich/praeco-rs) project — an ultra-fast, highly configurable, and secure API Gateway and Reverse Proxy written in Rust. Check out the main repository to see how all the pieces fit together!

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
use praeco_common::{build_root_store, build_tls_client_config};
use hyper::body::Bytes;
use http_body_util::Full;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Build Root Certificate Store (with optional custom CA)
    let root_store = build_root_store(&None)?;

    // 2. Build TLS config (with optional client certificates for mTLS)
    let tls_config = build_tls_client_config(root_store, None, None)?;

    // 3. Define connection pool configuration
    let pool_config = ClientPoolConfig {
        idle_timeout: Some(std::time::Duration::from_secs(90)),
        max_idle_per_host: Some(1024),
        http2_only: false, // Set true to enforce HTTP/2 (e.g. for gRPC)
    };

    // 4. Build the highly optimized client
    let _client = build_hyper_client::<Full<Bytes>>(tls_config, pool_config);
    println!("Hyper client successfully configured!");
    Ok(())
}
```
