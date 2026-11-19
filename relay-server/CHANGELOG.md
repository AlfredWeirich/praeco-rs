# Changelog

All notable changes to the `praeco-relay-server` crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Security & Hardening (Breaking API Changes for Next Minor `0.4.0`)
* **Fail-Closed CRL Loading, Handshake Expiration Enforcement & Non-Blocking Reload (`src/tls.rs`, `src/config.rs`, `src/lib.rs`, `src/main.rs`):**
  * Propagated CRL PEM/DER parse errors and empty-CRL errors in `parse_revoked_serials_from_crl_pem` and `setup_mtls_acceptor_with_strict` (using shared `common::crl`) instead of silently downgrading to an empty revocation set.
  * Changed `spawn_crl_reload_watcher` (and added `spawn_crl_reload_watcher_with_strict`) to return `Result<watch::Receiver<ControlPlaneReloadState>, RelayError>` so corrupt initial CRLs fail startup fast, while failed live/SIGHUP reloads preserve the previous CRL state and run off the async executor via `tokio::task::spawn_blocking`.
  * Removed the `PRAECO_STRICT_CRL` environment variable and made strict CRL validation the TOML-only default (`RelayConfig::strict_crl: Option<bool>`, default `Some(true)`), enabling `rustls`'s `enforce_revocation_expiration()` on `WebPkiClientVerifier`.

---

## [0.3.4] - 2026-11-19

Control-plane limits, live CRL & certificate expiry enforcement, Yamux/SNI/LRU runtime hardening, and modularization.

### Added
* **Control-Plane Connection Limits & Live CRL / Certificate Expiry Enforcement (`src/config.rs`, `src/lib.rs`, `src/main.rs`):**
  * Added optional `#[serde(default)]` settings `control_plane_max_concurrent_connections` (default: `256`), `control_plane_max_concurrent_connections_per_ip` (default: `16`), and `crl_reload_interval_secs` (default: `60`) to `RelayConfig`.
  * Added `ControlPlaneOptions`, `ControlPlaneReloadState`, `run_control_plane_with_options`, `spawn_crl_reload_watcher`, `parse_revoked_serials_from_crl_pem`, and `extract_cert_expiry_and_serial` to enforce pre-mTLS connection limits on Port `7001`, periodically (and on `SIGHUP`) reload CRLs, and actively terminate existing Yamux tunnels when a client certificate expires (`notAfter`) or is revoked.
* **Configurable Stream-Open Timeout (`src/config.rs`, `src/lib.rs`, `RelayConfig.toml`):**
  * Added `tunnel_stream_open_timeout_secs` (default: `5` s) plus SemVer-compatible `handle_data_connection_with_stream_timeout` and `run_data_plane_with_stream_timeout` to bound `control.open_stream()` and initial `PROXY v2` / `ClientHello` writes.

### Fixed & Hardened
* **Concurrency & Config Hardening (`src/config.rs`, `src/lib.rs`):**
  * Added `#[serde(deny_unknown_fields)]` to `RelayConfig` so unknown configuration keys fail fast.
  * Fixed `RelayConnectionGuard::drop` race using atomic `DashMap::remove_if` cleanup and made `try_register_tunnel` atomic via `DashMap::entry()` to eliminate concurrent `REGISTER` races.
* **Self-Contained Test PKI & Leaner Dependencies (`Cargo.toml`, `src/lib.rs`, `tests/integration_tests.rs`):**
  * Enabled `praeco-common` with `default-features = false` (omitting unused `hyper`, `hyper-rustls`, and `jsonwebtoken` dependencies from non-test builds) and delegated `canonicalize_ip` via SemVer-compatible `pub use common::canonical_client_ip as canonicalize_ip` (preserving `::1` and `::`).
  * Replaced all `server_certs/` / `client_certs/` references and external `openssl` CLI calls in unit and integration tests with ephemeral `common::test_pki::TestPki` (`praeco-common/test-pki`).
* **Yamux Driver, Same-Cert Takeover, LRU Rate Limiter, Strict CRL & Modularization (`src/lib.rs`, `src/limits.rs`, `src/tls.rs`, `src/protocol.rs`, `src/tests.rs`):**
  * Fixed Yamux driver lost-wakeup and inbound stream drain loops (using `std::task::Waker::noop()`) and scaled `build_yamux_config` receive windows tightly to `max(4 MiB, 256 KiB * max_streams)` instead of the `1 GiB` default.
  * Added safe same-certificate dead-peer tunnel takeover (`Control::with_identity`, `try_register_tunnel_with_takeover`) after an unlocked liveness probe.
  * Replaced fail-closed `RateLimitTable` saturation with expiry sweep and LRU eviction, sanitized SNI log strings via `sanitize_log_str`, added opt-in `PRAECO_STRICT_CRL` enforcement in `tls.rs`, and split `lib.rs` into `limits.rs`, `tls.rs`, `protocol.rs`, and `tests.rs` while keeping all `pub` exports intact.

---

## [0.3.3] - 2026-11-17

Lifecycle & accept-loop hardening, supervised cross-plane shutdown, and a comprehensive expansion of the unit and integration test suites to 38 tests.

### Added
* **Comprehensive Unit & Configuration Test Suite (`src/lib.rs`, `src/config.rs`):**
  * Added tests for `RelayConfig::default()` and `RelayConfig::load(...)` (`ConfigNotFound`, `ConfigParse`, valid TOML file loading).
  * Added unit tests for `TokenBucket` (burst consumption, refill rate, capacity cap), `is_valid_sni`, `parse_register_command` (case normalization & invalid inputs), and `extract_allowed_snis` edge cases.
  * Added unit tests for `extract_sni` (real `rustls` `ClientHello`, IP-literal without SNI extension, non-TLS & `ChangeCipherSpec` records), `read_client_hello_record` error paths (empty EOF, truncated header/payload, oversized `> 16384` records, Slowloris timeout), and `setup_mtls_acceptor` error/CRL loading paths.
  * Added virtual-time tests (`tokio` `test-util`, `start_paused = true`) for `copy_bidirectional_with_idle_timeout` and `ActivityTracker` (clean copy, `IdleTimeout`, and activity-based timeout reset).
* **TCP Accept-Loop, Security & Edge-Case Integration Tests (`tests/integration_tests.rs`):**
  * Added real TCP socket E2E tests for `run_control_plane` and `run_data_plane` including `PROXY_V2` propagation and coordinated `CancellationToken` graceful shutdown (`poll_close` + task draining).
  * Added TCP enforcement tests for `TokenBucket` rate limiting (`run_data_plane` dropping excess burst connections) and `RelayConnectionTracker` per-IP concurrency caps.
  * Added Control Plane security tests for live CRL certificate revocation (via `openssl ca`), rejection of CA-signed client certificates without DNS SANs, mTLS handshake timeouts, missing client certificates, malformed/oversized/non-UTF-8 `REGISTER` commands, generation-ID cleanup guards (`remove_if`), and resilience against unexpected client-initiated Yamux streams.
  * Added Data Plane edge-case tests for case-insensitive SNI routing, plaintext HTTP scanner probes, Slowloris timeouts, and dead/closed tunnel cleanup.

### Changed
* **Accept-Loop Supervision, Task Draining & Shutdown Hardening (`src/lib.rs`, `src/main.rs`):**
  * `run_control_plane` and `run_data_plane` now track all spawned connection tasks in `tokio::task::JoinSet`s, log panics/errors via `log_relay_task_result`, and drain active tasks with a 5-second timeout (`drain_relay_tasks` / `RELAY_DRAIN_TIMEOUT`) before aborting stalled tasks on shutdown.
  * Added a 50 ms cancellable backoff (`ACCEPT_ERROR_BACKOFF`) on transient `accept()` errors (e.g. `EMFILE`) in both Control Plane and Data Plane accept loops to prevent CPU busy-loops.
  * Control Plane connections now send a Yamux `poll_close` frame (with 1-second timeout) upon `CancellationToken` shutdown before dropping the tunnel.
  * `main.rs` now supervises Control Plane and Data Plane tasks via `tokio::select!` and triggers cross-cancellation if either plane exits unexpectedly.
* **Dev-Dependencies (`Cargo.toml`):**
  * Added `tokio` with `test-util` under `[dev-dependencies]` for deterministic virtual-time idle-timeout testing.

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
