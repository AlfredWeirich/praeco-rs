# praeco-jwt-creator

**praeco-jwt-creator** is a developer utility designed to generate valid JSON Web Tokens (JWT) for testing the authentication layer of `praeco-rs`.

*(The name **praeco** comes from Latin, meaning "herald" or "crier" — just as a historical herald controlled the flow of information and announced messages to the public, this gateway acts as the sovereign announcer and gatekeeper for your network traffic).*

> **Note:** This crate is part of the [praeco-rs](https://github.com/AlfredWeirich/praeco-rs) project — an ultra-fast, highly configurable, and secure API Gateway and Reverse Proxy written in Rust. Check out the main repository to see how all the pieces fit together!

## Features

- Easily generate signed JWTs using local private keys.
- Inject custom claims, roles, and expiration times for testing various authorization edge cases.
- Seamlessly integrates with the `JwtAuth` middleware layer of the `praeco-rs` gateway.

## Key Generation (`create_keys.sh`)

To generate a fresh Ed25519 key pair (`jwt_private.pem` / `jwt_public.pem`) safely with `umask 077` (mode `0600` on private keys, refusing to overwrite existing keys unless `-f` / `--force` is passed):

```bash
./jwt_creator/create_keys.sh
```

## Usage

Run the utility from the workspace root to generate a new token (backed directly by `praeco-common`'s shared `Claims`, `sign_jwt`, and `verify_jwt` helpers with the `jwt` feature):

```bash
cargo run -p praeco-jwt-creator --release
```

## Example (Rust Claims)

The JWT utility generates tokens using `common::Claims`, which includes the custom `oids` array used for authorization mapping in the gateway:

```rust
use common::Claims;

fn main() {
    // Example of constructing the shared Claims payload for serialization
    let my_claims = Claims {
        sub: "1234567890".to_string(),
        iss: "praeco-auth".to_string(),
        aud: Some("praeco-gateway".to_string()),
        exp: 1690003600,
        oids: vec!["1".to_string(), "2".to_string()],
        jti: Some("550e8400-e29b-41d4-a716-446655440000".to_string()),
    };

    // Pass this struct to `common::sign_jwt(&my_claims, &encoding_key)`
    println!("Claims struct created: {:?}", my_claims);
}
```
