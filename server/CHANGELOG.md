# Changelog

All notable changes to the `praeco-rs` crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Security & Hardening (Breaking API Changes for Next Minor `0.7.0`)
* **Right-to-Left `X-Forwarded-For` Resolution (`src/middleware/ip_filter.rs`, `src/middleware/rate_limiter.rs`, `src/configuration/mod.rs`, `src/stack.rs`):**
  * Fixed spoofable leftmost `X-Forwarded-For` extraction when `trust_forwarded_headers = true`: both `IpFilter` and rate limiters now share `extract_forwarded_ip_from_headers`, walking `X-Forwarded-For` (including multiple header lines) from right to left using `trusted_proxy_hops` (default `1`, `0` disables XFF) without falling back to `X-Real-IP` when `X-Forwarded-For` is present.
  * Added `pub trusted_proxy_hops: usize` to `IpFilterConfig`, `SimpleRateLimiterConfig`, and `TokenBucketRateLimiterConfig` (TOML-compatible via `#[serde(default)]`, SemVer-breaking for struct literals without `..Default::default()`), plus backward-compatible `extract_client_ip_with_hops`, `extract_rate_limit_key_with_hops`, and `.with_trusted_proxy_hops(...)` builders.
* **Fail-Closed CRL Defaults & Handshake Expiration Enforcement (`src/tls_conf.rs`, `src/configuration/mod.rs`, `common/src/crl.rs`):**
  * Centralised CRL parsing/expiration checks in `praeco-common::crl`, removed the `PRAECO_STRICT_CRL` environment variable and `strict_crl_enabled()` in favour of pure TOML configuration, and switched strict CRL mode to **fail-closed by default** (`ClientCertConfig::strict_crl: bool` defaulting to `true`).
  * Enabled `WebPkiClientVerifierBuilder::enforce_revocation_expiration()` in strict mode so `rustls` enforces CRL `nextUpdate` on every handshake, and rejected empty CRL PEM files at load/reload time.

---

## [0.6.2] - 2026-11-19

SemVer-compatible security, resilience, hot-reload, runtime, modularization, and workspace hardening release.

### Added
* **Library Re-Export (`src/lib.rs`):**
  * Re-exported `common::Claims` at the crate root (`praeco_rs::Claims`) so library embedders do not need an explicit dependency on `praeco-common`.
* **Per-Server `pki_base_oid` (`src/configuration.rs`, `src/tls_conf.rs`, `src/runner.rs`, `src/stack.rs`):**
  * Added optional `pki_base_oid` on `[[Server]]` blocks with fallback to global `Config::pki_base_oid`, plus SemVer-safe `*_with_base` / `*_with_base_oid` variants so multi-server setups can use separate client PKIs without changing existing public signatures.
* **Resilience & Hardening Items 8–11 (`src/middleware/limit.rs`, `src/lib.rs`, `src/runner.rs`, `src/configuration.rs`, `src/middleware/router/`):**
  * **gRPC Stream Body Cap & Bounded Concurrency Queue (`Middleware M-6`):** Added cumulative stream byte cap (`MaxPayloadLayer::with_max_stream_bytes`, defaulting to `64 × max_bytes`) for `application/grpc` requests alongside per-frame validation, and bounded the `ConcurrencyLimitLayer` waiting queue (`with_queue_limit`, defaulting to `4 × max_concurrent_requests` clamped to `[64, 4096]`) so excess queued requests fail fast with `503 Service Unavailable`.
  * **HTTP/1.1, HTTP/2 & HTTP/3 Timeouts (`Server M-02`, `M-03`):** Added a 30 s per-frame idle body timeout (`IdleTimeoutBody` for HTTP/1.1 & HTTP/2, `H3Body::with_timeout` for HTTP/3), a 10 s HTTP/3 request header resolution timeout, explicit HTTP/3 error logging / `500` fallback responses instead of silently swallowing errors, and disabled QUIC server `keep_alive_interval` so `max_idle_timeout` (`30s`) can close idle connections.
  * **Circuit-Breaker Epoch Guards & `grpc_web` Hardening (`Router R-04`..`R-11`):** Added monotonic `UpstreamNode::circuit_epoch`, epoch-checked `record_success_with_epoch` / `record_failure_with_epoch`, and `ProbeGuard::epoch()` CAS rollbacks so late `2xx` responses cannot close an `Open` circuit or race `HalfOpen` probes; enforced `failure_threshold` on request timeouts; completed `grpc_web` circuit breaker / `ProbeGuard` tracking, non-blocking stale-while-revalidate reflection refresh (`try_lock`), sanitized error responses, `grpc-accept-encoding: identity`, and compression-flag / checked-length frame validation.
  * **Router Typed Errors & Early `Content-Length` Guard (`Router R-14`, `R-15`):** Eliminated `Display`-string error matching across `limit.rs`, `router/mod.rs`, and `http_proxy.rs` via typed `.source()` downcasts (`classify_error_chain`, `is_payload_too_large_error`), and enforced `Content-Length > max_request_bytes` upfront on buffered routes before polling/allocating body frames.
  * **`JwtRevocationStore` Overflow Handling (`IdP M-14`):** Added `JwtRevocationStore::try_revoke` & `overflow_drops()` with immediate full-store expiry sweeping, earliest-expiry eviction when incoming revocations outlive the shortest retained entry, `tracing::error!` reporting without evicting equal/longer-lived active revocations, and fail-closed `503 Service Unavailable` in `POST /auth/revoke` when capacity is exhausted.
  * **Unified Workspace Crypto Provider (`Workspace F-27`):** Standardized the entire workspace on `aws-lc-rs` (`rustls`, `tokio-rustls`, `hyper-rustls`, `tonic/tls-aws-lc`, `quinn/rustls-aws-lc-rs`, `rcgen/aws_lc_rs`, and `jsonwebtoken/aws_lc_rs`), eliminating duplicate `ring` cryptography and keeping `cargo audit` clean with zero advisories.
* **Server & Relay Runtime Hardening, Modularization & Workspace Polish (Items 13, 19, 20):**
  * **Server Runtime (`src/stack.rs`, `src/lib.rs`, `src/runner.rs`, `src/tls_conf.rs`):** Removed `unsafe impl Sync` from `SyncWrapper` (using safe `std::sync::Mutex::get_mut`), reduced per-request client-certificate string clones in `ConnectionHandler` via `Option<Arc<str>>` + `with_dynamic_stack_shared_arc`, verified outer `PathSanitizerLayer` ordering via `sanitizer_precedes_security_layers`, ensured `run_servers` exits when no listeners start or all terminate early, and added opt-in `PRAECO_STRICT_CRL=true|1|yes` fail-closed handling for expired CRLs (`strict_crl_enabled`, `validate_crl_not_expired`).
  * **Relay Runtime (`relay-server/src/`):** Fixed the Yamux driver wakeup and inbound drain loops (with `std::task::Waker::noop()`), scaled Yamux connection receive windows tightly to `max(4 MiB, 256 KiB * max_streams)` (down from the fixed `1 GiB` default), replaced fail-closed `RateLimitTable` saturation with expiry sweep + LRU eviction (`limits.rs`), sanitized SNI values in logs (`sanitize_log_str`), added safe same-certificate stale-tunnel takeover (`try_register_tunnel_with_takeover`) after an unlocked liveness probe, and added `PRAECO_STRICT_CRL` enforcement in `tls.rs`.
  * **Modularization, Hot-Path Allocations & Tracing (`src/configuration/`, `src/middleware/`):** Split `configuration.rs` (`mod.rs`, `resilience.rs`, `tests.rs`), `aggregator.rs` (`mod.rs`, `tests.rs`), and `relay-server/src/lib.rs` (`lib.rs`, `limits.rs`, `tls.rs`, `protocol.rs`, `tests.rs`) while preserving 100 % of public paths via `pub use`; reduced hot-path allocations in `UpstreamNode` selection (`SmallVec`), `headers.rs` (`IDENTITY_HEADER_NAMES`), `path_sanitizer.rs` (`sanitize_and_normalize_path_cow`), and `logger.rs` (`tracing::enabled!` guards); and added `#[tracing::instrument]` to `ConnectionHandler::handle`, `run_servers`, `start_single_server_reloadable`, `handle_http_proxy`, `handle_grpc_web`, and `handle_grpc_passthrough`.
  * **Workspace Polish (`Cargo.toml` & member crates):** Narrowed `tokio` from `features = ["full"]` to used features only, declared `rust-version = "1.88"`, and enabled `[workspace.lints]` (`unused_imports`, `dead_code`, `clippy::all`).

### Security & Hardening
* **Strict Config, CORS & JWT Validation (`src/configuration.rs`, `src/stack.rs`, `src/middleware/jwt.rs`):**
  * Added `#[serde(deny_unknown_fields)]` across `Config`, `ServerConfig`, `Layers`, routes, and middleware structs so unknown/misspelled fields fail fast at startup and `SIGHUP` reload.
  * Rejected CORS `allow_credentials = true` paired with `"*"` in `allowed_methods` or `allowed_headers`.
  * Enforced non-empty `expected_issuer`, `expected_audience`, and `jwt_public_keys` in JWT validation and redacted sensitive `RouterParams::jwt` paths in `Debug` as well as query strings / full config dumps from logs.
* **Admin Endpoint Guardrails (`src/middleware/admin.rs`, `src/configuration.rs`):**
  * Enforced loopback-only binding, disallowed `[Server.tunnel]`, and enforced read-only mode (`403 Forbidden` on `POST ?action=...`) for unauthenticated standalone `ServiceType::Admin` listeners.
  * Required authentication or explicit non-wildcard RBAC on `backend_type = "admin"` router routes, added `Sec-Fetch-Site` anti-CSRF verification and `admin::audit` warning logs for `mark_dead` / `mark_alive`, and eliminated deep `ServerConfig` vector cloning per admin/metrics request.
* **RBAC & gRPC Passthrough Fixes (`src/middleware/path_sanitizer.rs`, `src/middleware/router/rbac.rs`, `src/middleware/router/http_proxy.rs`):**
  * Rejected semicolon matrix parameters (`;` / `%3b`) in `PathSanitizerLayer` (`400`) and `enforce_rbac` (`403`), and normalized trailing slashes on exact RBAC rules in `CompiledRbac`.
  * Added `buffer_grpc_first_frame_or_stream` (preserving initial frames via `PrefixedStreamBody` with a `408` read timeout) so bidirectional/client-streaming gRPC passthrough streams immediately without hanging while unary/server-streaming calls stay retryable strictly on `RetryReason::ConnectError`.
* **Contradiction Validation, Router Init, Compression & W3C Trace Hygiene (`src/configuration.rs`, `src/server.rs`, `src/middleware/router/mod.rs`, `src/middleware/compression.rs`, `src/middleware/trace_id.rs`, `.cargo/config.toml`, `Cargo.toml`):**
  * Rejected `ClientCert` / `OptionalClientCert` with `protocol != "https"`, `__Host-` cookies paired with `cookie_domain`, and `tokio_threads = 0` at config load / `finalize()` time.
  * Propagated route insertion errors (`router.insert(prefix, ...)`) and invalid `[Server.RouterParams].jwt` header values during `RouterService::new` instead of discarding them.
  * Fixed off-by-one EOF rejection in `LimitedReader::poll_read`, normalized `Content-Encoding` case-insensitively during request decompression, and added `Vary: Accept-Encoding` to compressed responses.
  * Validated `x-trace-id` against W3C `traceparent` syntax in `TraceIdLayer` before populating `traceparent` (preserving non-W3C `x-trace-id` headers while synthesizing a valid `traceparent`).
  * Enabled `overflow-checks = true` in `[profile.release]` and commented out host-specific `-C target-cpu=native` in `.cargo/config.toml` for portable builds.
* **IdP & JWT Edge-Case Hardening (`src/middleware/idp/mod.rs`, `src/middleware/idp/session.rs`, `src/middleware/jwt.rs`):**
  * Added `; Secure` attribute to the `POST /auth/revoke` logout cookie invalidation header (required by RFC 6265bis for `__Host-`-prefixed cookies).
  * Made `POST /auth/revoke` fail closed when a bearer/cookie token is supplied: returns `503 Service Unavailable` if `decoding_keys` is empty and `401 Unauthorized` if no configured key verifies the token signature (preserving `200 OK {"status":"cleared"}` when called without a token to clear cookies).
  * Added `JWT_EXP_LEEWAY_SECS` (`60` s, matching `jsonwebtoken::Validation` default `leeway`) to `JwtRevocationStore` revocation expiry timestamps in both `POST /auth/revoke` and `JwtAuthService::revoke_on_paths` so tokens revoked near `exp` cannot be replayed during the leeway grace window.
  * Replaced the shared `"device"` mTLS `sub` fallback in `IdpService` with a deterministic `"sha256:<hex>"` leaf-certificate DER fingerprint (`cert_fingerprint_subject`) whenever SAN and CN are both absent (falling back to `"device"` only for non-PEM synthetic inputs).
  * Removed plaintext `user_code` from `SessionStore::create_session` `trace!` logs and truncated `session_id` values in `session.rs` / `idp/mod.rs` logs via `redact_session_id` (first 8 characters + `"…"`).
  * Added anti-CSRF `Sec-Fetch-Site` / `Origin` checks on `POST /auth/confirm` and `GET /auth/session_info`, and required mTLS client certificate or valid `poll_secret` authentication (`verify_poll_secret`) to read `user_code` via `GET /auth/session_info`.

### Changed & Fixed
* **Hot-Reload (`SIGHUP`) Completeness & Per-Request `dynamic_stack` (`src/lib.rs`, `src/connection_tracker.rs`, `src/stack.rs`, `src/runner.rs`, `src/server.rs`):**
  * Added SemVer-compatible `ConnectionHandler::with_dynamic_stack`, `with_dynamic_stack_and_oids`, and `with_dynamic_stack_shared` so long-lived HTTP/1.1, HTTP/2, HTTP/3 (QUIC), and Relay-tunneled connections load the active `ArcSwap` service stack on every request and detect `oid_mapping` updates with a single `Arc::ptr_eq` check on the hot path.
  * Added `ConnectionTracker::update_limits`, `ServerReloadUpdate`, and `start_single_server_reloadable` so `SIGHUP` hot-reloads live TLS/mTLS/CRL configurations (`TlsAcceptor` + `quinn::Endpoint::set_server_config`), `oid_mapping`, `pki_base_oid`, `connection_limits`, and restarts active router health-check loops against the newly built `UpstreamNode` instances without dropping listening sockets.
* **Lifecycle & Reproducible Test PKI (`src/server.rs`, `src/runner.rs`, `src/tls_conf.rs`, `tests/`):**
  * Handled `SIGTERM` (`SignalKind::terminate`) alongside `Ctrl-C` for graceful connection draining and OTLP flush.
  * Fixed a shutdown deadlock in `supervise_reloadable_health_checks` (`src/runner.rs`) where closing `reload_rx` during `server.rs` shutdown awaited `std::future::pending()` inside a `tokio::select!` arm body instead of disabling the branch.
  * Migrated all unit, integration, and relay E2E tests (plus `examples/https_web_server`) from gitignored `server_certs/` / `client_certs/` files to ephemeral `common::test_pki::TestPki` (`praeco-common` `test-pki` feature).

---

## [0.6.1] - 2026-11-17

Optional `web` feature introducing `praeco_rs::web` (composable HTTP router, Axum-style typed extractors, `IntoResponse`, and automatic `Inspection` WAF allowlist synchronization), plus the standalone `examples/https_web_server` embedded HTTPS + HTTP/3 example crate.

### Added
* **Embedded Web Router & Typed Extractors (`web` Feature, `src/web.rs`):**
  * Added optional Cargo feature `web` (`dep:serde_urlencoded`) exposing `praeco_rs::web` so embedded applications can build typed HTTP/JSON APIs directly on top of Praeco's hardened Tower middleware stack without adding dependencies to the default reverse-proxy build.
  * Added `WebRouter` backed by `matchit` with method shorthands (`.get()`, `.post()`, `.put()`, `.delete()`, `.patch()`, `.route()`) and explicit WAF overrides (`*_with_waf()`), returning `405 Method Not Allowed` (with `Allow` header) and `404 Not Found` automatically.
  * Added single-source-of-truth WAF synchronization via `WebRouter::allowed_pathes()`, automatically deriving exact/prefix `Inspection` allowlist rules from registered routes for `ServerConfig::allowed_pathes`.
  * Added `FromRequestParts` / `FromRequest` extractors (`Query<T>` via `serde_urlencoded`, `Path<T>`, `PathParams`, `Json<T>`, `TraceId`, `Request<SrvBody>`) combinable for 0–4 handler arguments (`Handler<T>`), `IntoResponse` (`Json<T>`, `String`, `&'static str`, `StatusCode`, `(StatusCode, T)`, `Response<ServiceRespBody>`, `Result<T, E>`), structured `Rejection` / `ExtractError` preserving `SrvError` propagation (e.g. `413 Payload Too Large`), and `thiserror`-backed `WebRouterError`.
* **Embedded HTTPS + HTTP/3 Web Server Example (`examples/https_web_server`):**
  * Added standalone example workspace crate embedding `praeco-rs` with `default-features = false, features = ["web"]` and programmatic `ServerConfig` (no `Config.toml`), demonstrating dual-stack HTTP/1.1 + HTTP/2 + HTTP/3 (QUIC), `src/bootstrap.rs` lifecycle separation, and concise endpoints (`/`, `/healthz`, `/users/{id}`, `/greet?user_name=...[&age=...]`, `POST /api/echo`) protected by Praeco's full hardened security middleware stack.
* **Tests & Documentation:**
  * Added unit tests in `praeco_rs::web` (`test_extractors_and_into_response`) and hardened stack integration tests in `examples/https_web_server` (`test_hardened_https_stack_and_endpoints`).
  * Documented the `web` feature, `praeco_rs::web` APIs, and the embedded HTTPS/HTTP3 example in `Readme.md` and `examples/https_web_server/README.md`.

---

## [0.6.0] - 2026-11-17

Parallel REST & gRPC fan-out aggregation (`backend_type = "aggregate"`), SemVer-safe `#[non_exhaustive]` public types, programmatic `ServerConfig::default()`, embedded binary gRPC aggregator example, and supervised listener/tunnel lifecycle with graceful connection draining.

### Breaking Changes
* **Public Configuration & Routing Types (`src/configuration.rs`):**
  * Extended `RouteBackendType` with `Aggregate`, added `targets` / `payload_mode` / `expose_upstream_errors` to `RouteConfig`, and added `aggregate_targets` / `aggregate_payload_mode` / `expose_upstream_errors` to `ParsedRoute`.
  * Marked extensible public enums (`RouteBackendType`, `ServiceType`, `MiddlewareLayer`, `LbStrategy`, `AggregatePayloadMode`) and compiled route structs (`ParsedRoute`, `ParsedAggregateTarget`) as `#[non_exhaustive]` so future additions stay SemVer-compatible for library embedders.

### Added
* **Parallel Fan-Out / Aggregator Route (`RouteBackendType::Aggregate`, `src/middleware/router/aggregator.rs`):**
  * Added `backend_type = "aggregate"` (alias `"fanout"`) with `[[Server.ReverseRoutes."/path".targets]]` (`AggregateTargetConfig` / `ParsedAggregateTarget`) supporting mixed `rest` and `grpc_transcoding` sub-targets within a single `RouterService` route.
  * Executes all configured sub-targets concurrently via `tokio::task::JoinSet` with OpenTelemetry `traceparent` / `x-trace-id` propagation, per-target load balancing, 3-state circuit breakers, and gRPC reflection schema caching.
  * Enforces strict `payload_mode` (`"keyed"` default or `"broadcast"`): in `keyed` mode each target receives only a zero-copy `Bytes::slice_ref` view of `body[target.key]` parsed via `serde_json::value::RawValue` (absent keys receive `{}`, never sibling payloads; unknown top-level keys return `400 Bad Request`). `GET` query parameters are forwarded to `rest` targets and converted to JSON objects for `grpc_transcoding` targets.
  * Enforces zero-trust query and header isolation per target: operator-pinned query parameters in `target.path` are pre-parsed at startup and always take precedence over client parameters (preventing parameter pollution), optional `forward_query` allowlists restrict forwarded parameters, conditional/range headers (`if-*`, `range`) are stripped once before fan-out, and client `Authorization`/`Cookie` headers are stripped by default unless opted in via `forward_headers`.
  * Supports `required = true` (fail-fast `abort_all()` returning `502`/`504`) and `required = false` graceful degradation (`"<key>": null` plus `"_errors": { "<key>": { "status", "grpc_status", "message" } }`), using zero-copy `ChunkedBytesBody` frame assembly (with pre-encoded JSON key prefixes and `serde::de::IgnoredAny` validation) so upstream JSON payloads are never copied or parsed into a DOM. Raw upstream error bodies are logged internally and replaced with canonical HTTP reason phrases by default (`expose_upstream_errors = false`).
  * Added per-target `timeout_ms`, route-wide `deadline_ms` (bounding tail latency of optional targets), buffered `max_request_bytes` (default 4 MiB, returning `413 Payload Too Large`), and cumulative `max_response_bytes` (default 16 MiB across all fan-out targets).
  * Enhanced `grpc_web` JSON-to-gRPC transcoding to inspect both Trailers-Only initial headers and HTTP/2 trailing `grpc-status` headers (mapping `NOT_FOUND` $\rightarrow$ `404`, `UNAVAILABLE` $\rightarrow$ `503` + circuit-breaker failure, `DEADLINE_EXCEEDED` $\rightarrow$ `504`, `PERMISSION_DENIED` $\rightarrow$ `403`, `UNAUTHENTICATED` $\rightarrow$ `401`, etc., and rejecting trailing error frames after partial data).
  * Integrated `aggregate_targets` into `RouterService::handle_health_check`, active health checks / reflection pre-warming in `src/runner.rs`, and `/upstreams` / `mark_dead` / `mark_alive` telemetry in `src/middleware/admin.rs`.
* **Programmatic Configuration, Custom Stack Embedding & Binary gRPC Aggregator Example:**
  * Implemented `Default` for `ServerConfig` (`enabled: true`, `ConnectionLimitsConfig::default()`, etc.) and `RouteConfig` so library embedders can construct configs purely in Rust (`..Default::default()`) without a `Config.toml` file, and rejected empty/whitespace `ServerConfig::name` in `ServerConfig::finalize()`.
  * Added and re-exported `build_service_stack_with_base(server_config, base_service)` and `wrap_tonic_routes(routes)` in `praeco_rs::stack` so embedded applications can wrap any custom Tower service or `tonic::service::Routes` with Praeco's full hardening stack (configured middleware layers, `TraceLayer`/`ServerMetrics`, and outer `PathSanitizerLayer`) without duplicating boilerplate.
  * Added runnable `server/examples/embedded_grpc_aggregator.rs` demonstrating `praeco-rs` with `default-features = false`, wrapping a typed binary Protobuf-to-Protobuf `tonic` aggregator service via `wrap_tonic_routes`, `build_service_stack_with_base`, and `start_single_server`.
* **Supervised Listeners, Tunnel Draining & Configurable Shutdown Timeout (`src/configuration.rs`, `src/runner.rs`, `src/stack.rs`, `src/lib.rs`):**
  * Added `ServerConfig::graceful_shutdown_timeout_seconds` (default `10` s) and `ServerConfig::drain_timeout()`, plus `CONNECTION_DRAIN_TIMEOUT` re-exported at the crate root.
  * Added and re-exported `spawn_dual_stack` returning `DualStackHandles` (`tcp_task`, `udp_task`) and `start_single_server_with_socket_signal`: TCP and UDP sockets are both bound before any task spawns so partial bind failures never leave an orphaned listener running (`run_dual_stack` stays non-blocking for backward compatibility).
  * Added `spawn_router_health_checks_in`, `run_tunnel_with_timeout`, and `run_tunnel_over_stream_with_drain_timeout` to track active connections, HTTP/3 streams, Yamux tunneled streams, and router health checks in `JoinSet`s with panic logging.

### Changed & Fixed
* **Graceful Shutdown & Accept-Loop Hardening (`src/runner.rs`, `src/stack.rs`, `src/server.rs`):**
  * `start_single_server` now supervises TCP, UDP/QUIC, HTTP, tunnel, and active health-check tasks until full shutdown, cancels sibling tasks if one dual-stack listener dies unexpectedly, and logs unexpected early exits.
  * HTTP/3 (`handle_h3_connection`) now observes cancellation, sends `GOAWAY`, drains in-flight request streams while keeping the `h3` connection alive, and closes the `quinn::Endpoint` (`set_server_config(None)`, `close`, `wait_idle`) only after draining.
  * Outbound Yamux tunnels (`run_tunnel_over_stream_with_drain_timeout`) keep driving the Yamux multiplexer during graceful drain so active HTTP/2 streams complete `GOAWAY` cleanly before `poll_close`.
  * Added `50 ms` cancellable backoff (`ACCEPT_ERROR_BACKOFF`) on transient `accept()` errors (e.g. `EMFILE`) in HTTP and HTTPS/TCP accept loops to prevent CPU busy-loops.
  * `SIGHUP` hot-reload restarts in `src/server.rs` now retire the old `ActiveServer` and wait for its `sockets_released` signal (`SocketReleaseBarrier`) before binding a replacement on the same address/tunnel, eliminating `EADDRINUSE` races without stalling behind slow HTTP connection drains.
* **Relay Server Lifecycle Hardening (`relay-server`):**
  * `praeco-relay-server` Control Plane and Data Plane accept loops now track tasks in `JoinSet`s, back off `50 ms` on transient `accept()` errors, close active Yamux control connections via `poll_close` on shutdown, and cross-cancel if either plane exits unexpectedly.
* **Tests & Documentation:**
  * Added unit, mock, security regression, admin, and `RouterService` end-to-end integration tests covering config validation, keyed payload isolation, sanitized upstream error responses, query precedence/allowlists, credential/conditional header stripping, mixed gRPC/REST fan-out, `GET` query conversion, invalid REST JSON, `504` optional timeouts, `405` method guards, RBAC enforcement, and `/health` checks.
  * Added runner lifecycle tests covering partial dual-stack bind failure cleanup, HTTPS socket release on shutdown, `graceful_shutdown_timeout_seconds` parsing/defaults, and immediate socket release with full in-flight HTTP request draining (`test_http_server_drains_inflight_request_while_releasing_socket_early`).
  * Documented `backend_type = "aggregate"` and `graceful_shutdown_timeout_seconds` / ordered hot-reload restarts in `Config.md`, and the embedded example + runner/stack APIs in `Readme.md`.

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
