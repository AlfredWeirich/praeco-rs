# Changelog

All notable changes to the `praeco-rs` crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.5.4] - 2026-11-16

Library/CLI decoupling (Stage 1) and dual-stack / HTTP/3 test coverage.

### Added
* **Library Runner Module (`src/runner.rs`):**
  * Extracted listener and lifecycle orchestration (`run_servers`, `start_single_server`, `run_dual_stack`, `spawn_router_health_checks`, `run_tunnel`, plus HTTP/3 QUIC listener/connection handling) from `src/server.rs` into `praeco_rs::runner` and re-exported them at the crate root.
  * Extracted pure health-check score decoders (`parse_grpc_health_score`, `parse_rest_health_score`) and `record_health_check_failure` for deterministic unit testing and cleaner error propagation (`SrvError`).
* **`cli` Feature Gate (`Cargo.toml`):**
  * Added `default = ["cli"]` with `required-features = ["cli"]` on `[[bin]] name = "praeco-rs"`.
  * Made binary-only dependencies (`mimalloc`, `num_cpus`, `opentelemetry-otlp`, `opentelemetry_sdk`, `tracing-appender`, `tracing-subscriber`) optional so external Rust applications can depend on `praeco-rs = { version = "0.5.4", default-features = false }` without global allocator, tracing subscriber, or OTLP exporter side effects.
* **Runner & HTTP/3 Dual-Stack Tests (`src/runner.rs`, `tests/integration_tests.rs`):**
  * Added unit tests for gRPC/REST health-check payload parsing, health-check failure transitions, missing `static_name` handling, `run_dual_stack` port-bind conflict reporting, and `run_tunnel` error paths.
  * Added end-to-end integration tests for `run_servers` lifecycle/graceful shutdown and `run_dual_stack` serving both TLS 1.3 HTTP/2 (TCP) and HTTP/3 over QUIC (UDP) on the same port.

### Changed
* **Thin Binary Entry Point (`src/server.rs`):**
  * Reduced `src/server.rs` to CLI argument parsing, `mimalloc` global allocator setup, `tracing`/`OTLP` subscriber initialization, Tokio runtime creation, and `Ctrl-C`/`SIGHUP` signal orchestration.

---

## [0.5.3] - 2026-11-14

Architecture modularization, comprehensive integration & cross-crate End-to-End (E2E) test suites, zero-allocation RBAC/routing optimizations, and security dependency hardening.

### Added
* **Modular Stack & Stream Runner Architecture (`src/stack.rs`):**
  * Extracted Tower service stack assembly (`build_service_stack`, `apply_layers`, `wrap_serve_dir`), TLS configuration builders (`build_rustls_config`, `build_tunnel_tls_connector`), and transport-agnostic stream runners (`serve_http_connection`, `serve_tls_connection`, `resolve_tunnel_peer`, `run_tunnel_over_stream`) into `praeco_rs::stack` (re-exported at the crate root).
  * Stream handlers are generic over `AsyncRead + AsyncWrite + Unpin + Send + 'static`, allowing full gateway pipelines to run over TCP sockets, Yamux reverse-tunnel streams, or in-memory `tokio::io::duplex` streams.
* **Gateway Integration Test Suite (`tests/integration_tests.rs`):**
  * Full HTTP/1.1 & HTTP/2 pipeline testing across `TraceId`, `SecurityHeaders`, `Cors`, `Decompression`, `Inspection`, `Compression`, and path allowlist layers.
  * Internal `Admin` & telemetry endpoint verification (`/healthz`, `/status`, `/metrics`).
  * `IpFilter` CIDR evaluation (`403 Forbidden`) combined with `TokenBucket` rate limiting (`429 Too Many Requests` + `retry-after`).
  * End-to-end TLS 1.3 (`ALPN h2`) multiplexing and lock-free `ArcSwap` service stack hot-reloading on active connections.
  * Yamux reverse-tunnel stream multiplexing with binary HAProxy `PROXY v2` client IP extraction.
  * Mutual TLS (`Authentication::ClientCert`) enforcement and static file serving (`ServeDir`).
* **Cross-Crate End-to-End System Tests (`tests/e2e_relay_tunnel_tests.rs`):**
  * Connects a real `praeco-rs` Gateway instance with a real `praeco-relay-server` instance without protocol mocks.
  * Verifies Control Plane mTLS 1.3 + X.509 SAN-to-SNI authorization, `REGISTER <sni> PROXY_V2` negotiation, Zero-Knowledge SNI peeking on the Relay Data Plane, and end-to-end HTTP/2 + TLS 1.3 termination at Praeco.
  * Verifies propagation of external client IPs via `PROXY v2` into Praeco's `IpFilter` and `ConnectionTracker` per-IP limits (`max_connections_per_ip`), as well as session failover with generation counters.

### Changed
* **Isolated TLS Certificate Resolution (`src/tls_conf.rs`):**
  * Enhanced `DynamicCertResolver::with_fallback` to support lock-free SIGHUP certificate rotation via `Config::try_global()` in production while safely falling back to the initial `CertifiedKey` in isolated multi-instance test environments.
* **Zero-Allocation Routing & RBAC (`SmallVec`):**
  * Eliminated per-request heap allocations on the routing and RBAC hot paths by using `SmallVec<[_; 6]>`.
* **Observability Log Prefix:**
  * Standardized rolling file log prefix to `praeco.YYYY-MM-DD.log`.
* **Security & Dependency Hardening (`cargo audit`):**
  * Migrated away from the deprecated `rustls-pemfile` crate to `rustls::pki_types::pem::PemObject` traits.
  * Replaced unmaintained `instant` and `serde_States` dependencies with `web-time` and updated `aws-lc-rs`, `quinn-proto`, and `rand` to resolve all `cargo audit` advisories.

---

## [0.5.2] - 2026-10-29

### Added
* **Internal Admin & Telemetry Service (`Service::Admin`):**
  * Added `/healthz`, `/status`, and Prometheus `/metrics` endpoints with per-server request/block counters, active connection gauges, and PKI certificate expiration telemetry.
  * Added `ConnectionTracker` for global and per-IP active stream concurrency enforcement across HTTP, HTTPS, QUIC/HTTP3, and Relay tunnel listeners.
* **Resilience & Traffic Control:**
  * Added 3-state circuit breaker (`Closed`, `Open`, `HalfOpen`), passive outlier detection, and bounded gRPC/HTTP retry buffering in the router middleware.
  * Added zero-allocation `IpFilterLayer` supporting IPv4/IPv6 CIDR `allow_cidrs` and `deny_cidrs` with `PROXY v2` and optional `X-Forwarded-For` extraction.
* **Distributed Tracing:**
  * End-to-end W3C `traceparent` extraction, generation, and upstream propagation attached to the root request span.

---

## [0.5.0] - 2026-10-22

Initial crates.io release of the refactored `praeco-rs` API Gateway.

### Added
* Tower / Hyper / Rustls 0.23 architecture supporting HTTP/1.1, HTTP/2, HTTP/3 (QUIC), gRPC passthrough, gRPC-Web, and Protobuf/JSON transcoding.
* Built-in Identity Provider (IdP), JWT authentication with JTI revocation, and mTLS X.509 OID-to-role authorization.
* Outbound mTLS + Yamux reverse-tunnel client (`[Server.tunnel]`) with HAProxy `PROXY v2` support.
* Lock-free SIGHUP hot-reloading of routes, middleware layers, and TLS certificates via `ArcSwap`.
