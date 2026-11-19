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

const DEFAULT_PRIVATE_KEY: &str = "./jwt_creator/private_key.pem";
const DEFAULT_PUBLIC_KEY: &str = "./jwt_creator/public_key.pem";
const DEFAULT_OUT1: &str = "./jwt_creator/token1.jwt";
const DEFAULT_OUT2: &str = "./jwt_creator/token2.jwt";
const DEFAULT_ISSUER: &str = "praeco-auth";
const DEFAULT_AUDIENCE: &str = "praeco-gateway";
const DEFAULT_SUBJECT: &str = "1234567890";
const DEFAULT_TTL1_SECS: u64 = 3600 * 24 * 30;
const DEFAULT_TTL2_SECS: u64 = 3600;

#[derive(Debug, Clone, PartialEq, Eq)]
struct CreatorConfig {
    private_key_path: String,
    public_key_path: String,
    out1_path: String,
    out2_path: String,
    issuer: String,
    audience: String,
    subject: String,
    oids: Vec<String>,
    ttl1_secs: u64,
    ttl2_secs: u64,
}

impl Default for CreatorConfig {
    fn default() -> Self {
        Self {
            private_key_path: DEFAULT_PRIVATE_KEY.to_string(),
            public_key_path: DEFAULT_PUBLIC_KEY.to_string(),
            out1_path: DEFAULT_OUT1.to_string(),
            out2_path: DEFAULT_OUT2.to_string(),
            issuer: DEFAULT_ISSUER.to_string(),
            audience: DEFAULT_AUDIENCE.to_string(),
            subject: DEFAULT_SUBJECT.to_string(),
            oids: vec!["1".to_string(), "2".to_string()],
            ttl1_secs: DEFAULT_TTL1_SECS,
            ttl2_secs: DEFAULT_TTL2_SECS,
        }
    }
}

impl CreatorConfig {
    fn parse_from<I, S>(args: I) -> Result<Option<Self>, String>
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let mut cfg = Self::default();
        let mut iter = args.into_iter().map(Into::into);
        let _bin = iter.next();

        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "-h" | "--help" => {
                    println!(
                        "Usage: praeco-jwt-creator [--private-key PATH] [--public-key PATH] \
[--out1 PATH] [--out2 PATH] [--iss ISSUER] [--aud AUDIENCE] [--sub SUBJECT] \
[--oids 1,2] [--ttl1 SECS] [--ttl2 SECS]"
                    );
                    return Ok(None);
                }
                "--private-key" => {
                    cfg.private_key_path = iter
                        .next()
                        .ok_or_else(|| "Missing value for --private-key".to_string())?;
                }
                "--public-key" => {
                    cfg.public_key_path = iter
                        .next()
                        .ok_or_else(|| "Missing value for --public-key".to_string())?;
                }
                "--out1" => {
                    cfg.out1_path = iter
                        .next()
                        .ok_or_else(|| "Missing value for --out1".to_string())?;
                }
                "--out2" => {
                    cfg.out2_path = iter
                        .next()
                        .ok_or_else(|| "Missing value for --out2".to_string())?;
                }
                "--iss" => {
                    cfg.issuer = iter
                        .next()
                        .ok_or_else(|| "Missing value for --iss".to_string())?;
                }
                "--aud" => {
                    cfg.audience = iter
                        .next()
                        .ok_or_else(|| "Missing value for --aud".to_string())?;
                }
                "--sub" => {
                    cfg.subject = iter
                        .next()
                        .ok_or_else(|| "Missing value for --sub".to_string())?;
                }
                "--oids" => {
                    let raw = iter
                        .next()
                        .ok_or_else(|| "Missing value for --oids".to_string())?;
                    cfg.oids = raw
                        .split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(str::to_string)
                        .collect();
                }
                "--ttl1" => {
                    let raw = iter
                        .next()
                        .ok_or_else(|| "Missing value for --ttl1".to_string())?;
                    cfg.ttl1_secs = raw
                        .parse::<u64>()
                        .map_err(|e| format!("Invalid --ttl1 '{raw}': {e}"))?;
                }
                "--ttl2" => {
                    let raw = iter
                        .next()
                        .ok_or_else(|| "Missing value for --ttl2".to_string())?;
                    cfg.ttl2_secs = raw
                        .parse::<u64>()
                        .map_err(|e| format!("Invalid --ttl2 '{raw}': {e}"))?;
                }
                unknown => return Err(format!("Unknown argument: {unknown}")),
            }
        }

        if cfg.issuer.trim().is_empty() || cfg.audience.trim().is_empty() {
            return Err("--iss and --aud must not be empty".to_string());
        }

        Ok(Some(cfg))
    }
}

/// Returns the current Unix timestamp in seconds.
fn current_timestamp() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|e| format!("Time error: {e}"))
}

/// Builds signed JWTs for `ttl1_secs` and `ttl2_secs` using shared `common::Claims`
/// and verifies both against `cfg.public_key_path`.
fn create_and_verify_pair(
    cfg: &CreatorConfig,
    now: u64,
) -> Result<(String, String, Claims, Claims), String> {
    let encoding_key = load_encoding_key(&cfg.private_key_path).map_err(|e| format!("{e:#}"))?;
    let decoding_keys = load_decoding_keys(std::slice::from_ref(&cfg.public_key_path))
        .map_err(|e| format!("{e:#}"))?;

    let claims1 = Claims {
        sub: cfg.subject.clone(),
        iss: cfg.issuer.clone(),
        aud: Some(cfg.audience.clone()),
        exp: now.saturating_add(cfg.ttl1_secs) as usize,
        oids: cfg.oids.clone(),
        jti: Some(uuid::Uuid::new_v4().to_string()),
    };

    let claims2 = Claims {
        sub: cfg.subject.clone(),
        iss: cfg.issuer.clone(),
        aud: Some(cfg.audience.clone()),
        exp: now.saturating_add(cfg.ttl2_secs) as usize,
        oids: cfg.oids.clone(),
        jti: Some(uuid::Uuid::new_v4().to_string()),
    };

    let token1 = sign_jwt(&claims1, &encoding_key).map_err(|e| format!("{e:#}"))?;
    let token2 = sign_jwt(&claims2, &encoding_key).map_err(|e| format!("{e:#}"))?;

    let decoded1 = verify_jwt(&token1, &decoding_keys, &cfg.issuer, &cfg.audience)
        .map_err(|e| format!("{e:#}"))?;
    let decoded2 = verify_jwt(&token2, &decoding_keys, &cfg.issuer, &cfg.audience)
        .map_err(|e| format!("{e:#}"))?;

    Ok((token1, token2, decoded1, decoded2))
}

/// Entry point for the JWT creator utility.
/// Demonstrates creating two different JWTs and verifying them.
fn main() -> Result<(), String> {
    let Some(cfg) = CreatorConfig::parse_from(std::env::args())? else {
        return Ok(());
    };
    let now = current_timestamp()?;
    let (token1, token2, decoded_claims1, decoded_claims2) = create_and_verify_pair(&cfg, now)?;

    println!("JWT 1: {token1}");
    write(&cfg.out1_path, &token1)
        .map_err(|e| format!("Failed to write {}: {e}", cfg.out1_path))?;

    println!("JWT 2: {token2}");
    write(&cfg.out2_path, &token2)
        .map_err(|e| format!("Failed to write {}: {e}", cfg.out2_path))?;

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
        let cfg = CreatorConfig::parse_from([
            "praeco-jwt-creator",
            "--private-key",
            priv_path.to_str().unwrap(),
            "--public-key",
            pub_path.to_str().unwrap(),
            "--iss",
            "custom-iss",
            "--aud",
            "custom-aud",
            "--sub",
            "alice",
            "--oids",
            "10,20",
            "--ttl1",
            "7200",
            "--ttl2",
            "900",
        ])
        .unwrap()
        .unwrap();

        let res = create_and_verify_pair(&cfg, now);
        let _ = std::fs::remove_dir_all(&dir);

        let (_t1, _t2, d1, d2) = res.expect("create_and_verify_pair must succeed");
        assert_eq!(d1.iss, "custom-iss");
        assert_eq!(d1.aud.as_deref(), Some("custom-aud"));
        assert_eq!(d1.sub, "alice");
        assert_eq!(d1.oids, vec!["10", "20"]);
        assert_eq!(d1.exp, (now + 7200) as usize);
        assert_eq!(d2.exp, (now + 900) as usize);
    }

    #[test]
    fn test_cli_parse_rejects_empty_issuer_or_invalid_ttl() {
        assert!(CreatorConfig::parse_from(["bin", "--iss", ""]).is_err());
        assert!(CreatorConfig::parse_from(["bin", "--ttl1", "abc"]).is_err());
        assert!(CreatorConfig::parse_from(["bin", "--unknown"]).is_err());
    }
}
