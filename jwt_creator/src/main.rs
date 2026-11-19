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
use std::fs::write;
use std::time::{SystemTime, UNIX_EPOCH};

// === Internal Crates ===
use common::{Claims, load_decoding_keys, load_encoding_key, sign_jwt, verify_jwt};

/// Returns the current Unix timestamp in seconds.
fn current_timestamp() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|e| format!("Time error: {e}"))
}

/// Builds signed JWTs for long-lived (`30d`) and short-lived (`1h`) test claims
/// using shared `common::Claims` and verifies them against `public_key_path`.
fn create_and_verify_pair(
    private_key_path: &str,
    public_key_path: &str,
    issuer: &str,
    audience: &str,
    now: u64,
) -> Result<(String, String, Claims, Claims), String> {
    let encoding_key = load_encoding_key(private_key_path).map_err(|e| format!("{e:#}"))?;
    let decoding_keys =
        load_decoding_keys(&[public_key_path.to_string()]).map_err(|e| format!("{e:#}"))?;

    let claims1 = Claims {
        sub: "1234567890".to_string(),
        iss: issuer.to_string(),
        aud: Some(audience.to_string()),
        exp: (now + 3600 * 24 * 30) as usize,
        oids: vec!["1".to_string(), "2".to_string()],
        jti: Some(uuid::Uuid::new_v4().to_string()),
    };

    let claims2 = Claims {
        sub: "1234567890".to_string(),
        iss: issuer.to_string(),
        aud: Some(audience.to_string()),
        exp: (now + 3600) as usize,
        oids: vec!["1".to_string(), "2".to_string()],
        jti: Some(uuid::Uuid::new_v4().to_string()),
    };

    let token1 = sign_jwt(&claims1, &encoding_key).map_err(|e| format!("{e:#}"))?;
    let token2 = sign_jwt(&claims2, &encoding_key).map_err(|e| format!("{e:#}"))?;

    let decoded1 = verify_jwt(&token1, &decoding_keys, issuer, audience).map_err(|e| format!("{e:#}"))?;
    let decoded2 = verify_jwt(&token2, &decoding_keys, issuer, audience).map_err(|e| format!("{e:#}"))?;

    Ok((token1, token2, decoded1, decoded2))
}

/// Entry point for the JWT creator utility.
/// Demonstrates creating two different JWTs and verifying them.
fn main() -> Result<(), String> {
    let now = current_timestamp()?;
    let (token1, token2, decoded_claims1, decoded_claims2) = create_and_verify_pair(
        "./jwt_creator/private_key.pem",
        "./jwt_creator/public_key.pem",
        "praeco-auth",
        "praeco-gateway",
        now,
    )?;

    println!("JWT 1: {token1}");
    write("./jwt_creator/token1.jwt", &token1)
        .map_err(|e| format!("Failed to write token1: {e}"))?;

    println!("JWT 2: {token2}");
    write("./jwt_creator/token2.jwt", &token2)
        .map_err(|e| format!("Failed to write token2: {e}"))?;

    println!("Decoded Claims 1: {decoded_claims1:?}");
    println!("Decoded Claims 2: {decoded_claims2:?}");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_verify_pair_uses_common_claims() {
        let priv_pem = "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/IrnOV6maFjmtsjchLt6\n-----END PRIVATE KEY-----\n";
        let pub_pem = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEAk2Zye1IFLZDkM9awuejFhYgrETKpGldlqBFSGOEM/os=\n-----END PUBLIC KEY-----\n";

        let dir = std::env::temp_dir().join(format!("praeco_jwt_creator_test_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let priv_path = dir.join("priv.pem");
        let pub_path = dir.join("pub.pem");
        std::fs::write(&priv_path, priv_pem).unwrap();
        std::fs::write(&pub_path, pub_pem).unwrap();

        let now = current_timestamp().unwrap();
        let res = create_and_verify_pair(
            priv_path.to_str().unwrap(),
            pub_path.to_str().unwrap(),
            "praeco-auth",
            "praeco-gateway",
            now,
        );
        let _ = std::fs::remove_dir_all(&dir);

        let (_t1, _t2, d1, d2) = res.expect("create_and_verify_pair must succeed");
        assert_eq!(d1.iss, "praeco-auth");
        assert_eq!(d1.aud.as_deref(), Some("praeco-gateway"));
        assert_eq!(d1.oids, vec!["1", "2"]);
        assert_eq!(d2.exp, (now + 3600) as usize);
    }
}
