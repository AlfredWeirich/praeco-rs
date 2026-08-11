//! # JWT Creator — Ed25519 Token Generator & Verifier
//!
//! A command-line utility that creates and verifies JSON Web Tokens using the
//! **EdDSA** (Ed25519) algorithm. Designed for development and testing alongside
//! the server's [`JwtAuthService`](server::middleware::jwt::JwtAuthService).
//!
//! ## Output
//!
//! Writes two tokens to disk: `token1.jwt` (long-lived, 30-day) and
//! `token2.jwt` (short-lived, 1-hour), then verifies both against the
//! corresponding public key.
//!
//! ## Usage
//!
//! ```bash
//! cargo run -p jwt_creator
//! ```

// === Standard Library ===
use std::fs::{read_to_string, write};
use std::time::{SystemTime, UNIX_EPOCH};

// === External Crates ===
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

/// Represents the claims contained within the JWT (Version 1).
/// Includes standard fields like sub, iat, exp, and jti, as well as a custom 'oids' field.
#[derive(Debug, Serialize, Deserialize)]
struct Claims1 {
    sub: String,
    name: String,
    iat: u64,
    exp: u64,
    jti: String, // Unique identifier for the token
    oids: Vec<String>,
}

/// Represents a simplified version of the claims (Version 2).
#[derive(Debug, Serialize, Deserialize)]
struct Claims2 {
    sub: String,
    name: String,
    oids: Vec<String>,
}

/// Returns the current Unix timestamp in seconds.
fn current_timestamp() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|e| format!("Time error: {e}"))
}

/// Creates a new JWT using the EdDSA algorithm and a private key.
fn create_jwt(claims: &Claims1, private_key_path: &str) -> Result<String, String> {
    let private_key =
        read_to_string(private_key_path).map_err(|e| format!("Failed to read private key: {e}"))?;

    encode(
        &Header::new(Algorithm::EdDSA),
        claims,
        &EncodingKey::from_ed_pem(private_key.as_bytes())
            .map_err(|e| format!("Encoding key error: {e}"))?,
    )
    .map_err(|e| format!("JWT creation error: {e}"))
}

/// Verifies a JWT using a public key and returns the decoded claims.
fn verify_jwt<C: serde::de::DeserializeOwned + std::fmt::Debug>(
    token: &str,
    public_key_path: &str,
) -> Result<C, String> {
    let public_key =
        read_to_string(public_key_path).map_err(|e| format!("Failed to read public key: {e}"))?;

    decode::<C>(
        token,
        &DecodingKey::from_ed_pem(public_key.as_bytes())
            .map_err(|e| format!("Decoding key error: {e}"))?,
        &Validation::new(Algorithm::EdDSA),
    )
    .map(|data| data.claims)
    .map_err(|e| format!("JWT verification error: {e}"))
}

/// Entry point for the JWT creator utility.
/// Demonstrates creating two different JWTs and verifying them.
fn main() -> Result<(), String> {
    let now = current_timestamp()?;

    // Create claims for a long-lived admin token.
    let claims1 = Claims1 {
        sub: "1234567890".to_string(),
        name: "John Doe".to_string(),
        iat: now,
        exp: now + 3600 * 24 * 30, // 30 days
        jti: uuid::Uuid::new_v4().to_string(),
        oids: ["1".to_string(), "2".to_string()].to_vec(),
    };

    // Create claims for a short-lived user token.
    let claims2 = Claims1 {
        sub: "1234567890".to_string(),
        name: "John Doe".to_string(),
        iat: now,
        exp: now + 3600, // 1h
        jti: uuid::Uuid::new_v4().to_string(),
        oids: ["1".to_string(), "2".to_string()].to_vec(),
    };

    // Create and save JWT 1
    let token1 = create_jwt(&claims1, "./jwt_creator/private_key.pem")?;
    println!("JWT 1: {token1}");
    write("./jwt_creator/token1.jwt", &token1)
        .map_err(|e| format!("Failed to write token1: {e}"))?;

    // Create and save JWT 2
    let token2 = create_jwt(&claims2, "./jwt_creator/private_key.pem")?;
    println!("JWT 2: {token2}");
    write("./jwt_creator/token2.jwt", &token2)
        .map_err(|e| format!("Failed to write token2: {e}"))?;

    // Verify the tokens and print the results to stdout.
    let decoded_claims1 = verify_jwt::<Claims2>(&token1, "./jwt_creator/public_key.pem")?;
    println!("Decoded Claims 1: {decoded_claims1:?}");

    let decoded_claims2 = verify_jwt::<Claims2>(&token2, "./jwt_creator/public_key.pem")?;
    println!("Decoded Claims 2: {decoded_claims2:?}");

    Ok(())
}
