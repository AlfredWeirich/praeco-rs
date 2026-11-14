# Changelog

All notable changes to the `praeco-relay-server` crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.3.2] - 2026-11-14

A high-performance, lightweight update for the Praeco SNI Relay Server featuring a modular crate architecture, full E2E test coverage, persistent file logging, and security dependency hardening.

### Added
* **Modular Crate Architecture (`lib.rs` & `main.rs`):**
  * Core networking, reverse-tunnel orchestration, mTLS acceptor construction, connection tracking, and rate limiting logic are now encapsulated in a reusable library (`lib.rs`).
  * `main.rs` is refactored into a clean, lightweight binary entry point handling CLI arguments, configuration loading, and signal management.
  * Stream handlers are generic over `AsyncRead + AsyncWrite + Unpin + Send + 'static`, enabling deterministic in-memory integration testing via duplex streams.
* **Asynchronous Rolling File Logging (`log_dir`):**
  * Added support for non-blocking, daily rotating file logging (`log/relay.YYYY-MM-DD.log`) via `tracing-appender` (configurable via `log_dir` in `RelayConfig.toml`).
* **High-Performance Memory Allocator (`mimalloc`):**
  * Integrated `mimalloc` as the global memory allocator to minimize heap fragmentation across thousands of concurrent TCP streams and maximize Layer-4 proxy throughput.
* **End-to-End Integration Test Suite (`tests/integration_tests.rs`):**
  * Reverse-tunnel flow: Client ➔ Relay Data Plane ➔ Yamux stream ➔ Backend TLS termination.
  * Binary HAProxy PROXY Protocol v2 negotiation and client IP propagation (`REGISTER <sni> PROXY_V2`).
  * High-concurrency Yamux multiplexing across multiple simultaneous client streams over a single tunnel connection.
  * Cryptographic SAN-to-SNI authorization checks against client certificates.
  * Active tunnel overwrite protection & clean re-registration with generation IDs.
  * Clean connection drop on unregistered SNIs.
* **Graceful Shutdown via `CancellationToken`:**
  * Control Plane and Data Plane accept loops and cleanup tasks now support coordinated shutdown, eliminating socket leaks and orphaned background tasks.
* **Domain-Specific Error Handling (`thiserror`):**
  * Introduced typed `RelayError` enum for library callers, keeping `anyhow` strictly at the binary level.

### Changed
* **Audit & Dependency Hardening:**
  * Fully migrated away from the deprecated `rustls-pemfile` crate to native `rustls::pki_types::pem::PemObject` traits (`CertificateDer::pem_file_iter`, `PrivateKeyDer::from_pem_file`, `CertificateRevocationListDer`).
  * Resolved all `cargo audit` security advisories and unmaintained warnings.

---

## [0.3.1] - 2026-10-23

Security and concurrency hardening release for production reverse-tunnel deployments.

### Added
* **HAProxy PROXY Protocol v2 Support:**
  * Dynamic capability negotiation on the Control Plane (`REGISTER <sni> PROXY_V2`).
  * Forwards client IP addresses to Praeco gateways via binary PROXY v2 headers for accurate upstream rate limiting and logging.
* **Tunnel Overwrite Protection & Generation IDs:**
  * Prevents hijacking or blackholing of active, healthy reverse-tunnel routes.
  * Atomic generation counter prevents race conditions during reconnects.
* **CRL Expiration Validation:**
  * Verifies X.509 `nextUpdate` timestamp when loading Certificate Revocation Lists to warn about stale revocation data.

### Changed
* **Yamux Stream Scaling:**
  * Configurable `max_yamux_streams` (default: 4096) with automatically scaled receive window buffers.
* **DoS Protection:**
  * Aggregated IPv6 rate limiting using `/64` subnet prefixes to prevent evasion.
  * Slowloris protection with a dedicated `client_hello_timeout_secs` watchdog.

---

## [0.3.0] - 2026-10-22

Initial standalone crates.io release of `praeco-relay-server`.

### Added
* Layer-4 TCP reverse proxy with SNI routing.
* Outbound mTLS Control Plane with X.509 SAN-to-SNI cryptographic authorization.
* Yamux stream multiplexing over persistent reverse tunnels.
* OpenTelemetry / OTLP distributed tracing integration.
* Token-bucket L4 connection rate limiter and concurrency tracking.
