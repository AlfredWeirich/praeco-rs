# praeco-jwt-creator

**praeco-jwt-creator** is a developer utility designed to generate valid JSON Web Tokens (JWT) for testing the authentication layer of `praeco-rs`.

## Features

- Easily generate signed JWTs using local private keys.
- Inject custom claims, roles, and expiration times for testing various authorization edge cases.
- Seamlessly integrates with the `JwtAuth` middleware layer of the `praeco-rs` gateway.

## Usage

Run the utility from the workspace root to generate a new token:

```bash
cargo run -p praeco-jwt-creator --release
```

## Example (Rust Claims)

The JWT utility generates tokens containing the following payload structure (`Claims`), which includes the custom `oids` array used for authorization mapping in the gateway:

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,       // Subject ID (e.g. "1234567890")
    name: String,      // User Name (e.g. "John Doe")
    iat: u64,          // Issued At Timestamp
    exp: u64,          // Expiration Timestamp
    jti: String,       // Unique Token Identifier (UUID)
    oids: Vec<String>, // Custom RBAC OIDs (e.g. ["1", "2"])
}

fn main() {
    // Example of constructing the Claims payload for serialization
    let my_claims = Claims {
        sub: "1234567890".to_string(),
        name: "Admin User".to_string(),
        iat: 1690000000,
        exp: 1690003600,
        jti: "550e8400-e29b-41d4-a716-446655440000".to_string(),
        oids: vec!["1".to_string(), "2".to_string()],
    };
    
    // In reality, you'd pass this struct to the jsonwebtoken::encode function
    println!("Claims struct created: {:?}", my_claims);
}
```
