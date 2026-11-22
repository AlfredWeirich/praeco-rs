# Changelog

All notable changes to the `praeco-common` crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [0.6.0] - 2026-11-22

CRL parsing & expiration module, stricter fail-closed JWT/PKI defaults, and shared XFF IP extraction.

### Added
* **Shared CRL Module & Default `crl` Feature (`Cargo.toml`, `src/crl.rs`):**
  * Added the `crl` feature (included in `default`, enabling `rustls-pki-types` and `x509-parser`) with `CrlValidationError`, `check_crl_not_expired`, and `extract_revoked_serials_from_crls`.
* **Hardened JWT Verification API (`src/lib.rs`):**
  * Added `JwtVerifyOptions`, `verify_jwt_with_options`, `MAX_JWT_TOKEN_LEN` (4 KiB), and `DEFAULT_MAX_JWT_LIFETIME_SECS` (30 days) with `nbf` validation, O(1) `"praeco-key-<N>"` routing (rejecting unknown `kid`s immediately), mandatory non-empty `jti` (`require_jti = true` by default), and bounded remaining lifetime.
* **Right-to-Left `X-Forwarded-For` Extraction (`src/lib.rs`):**
  * Added `client_ip_from_xff(header, trusted_hops)` supporting multiple hops cleanly across IPv4/IPv6.

### Changed (Breaking Behavioral / Default-Feature Changes for `0.6.0`)
* `verify_jwt` now delegates to `verify_jwt_with_options(..., JwtVerifyOptions::default())`, enforcing the 4 KiB token limit, non-empty `jti`, `nbf`, and 30-day lifetime cap by default.
* `build_root_store` / `build_root_store_with_webpki` now fail closed via `root_store.add(cert)` on invalid or unparseable custom CA certificates instead of skipping them with a warning.
* `default` features changed from `["client", "jwt", "tls"]` to `["client", "crl", "jwt", "tls"]`.
