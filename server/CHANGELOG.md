# Changelog

All notable changes to the `praeco-rs` crate will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

---

## [0.8.1] - 2026-11-26

Non-breaking feature release adding a process-wide W-TinyLFU HTTP response cache (`CacheLayer` / `SharedResponseCache`) shared across all configured `[[Server]]` instances, backed by a cancellation-safe `Singleflight` request coalescer.

### Security & Performance
* **O(1) Generation-Keyed Cache Invalidation (`src/middleware/cache.rs`):**
  * Embedded `generation: (u64, u64)` (`(global_generation, namespace_generation)`) directly into `CacheKey` and converted `SharedResponseCache::namespace_generations` to `DashMap<String, AtomicU64>`.
  * Removed Moka `invalidate_entries_if` predicate closures and `.support_invalidation_closures()`, eliminating UUID allocations per write and predicate scans on every read while preserving atomic write-read race fencing in `insert_if_generation`.
  * Capped `namespace_generations` at `MAX_TRACKED_NAMESPACES` (`4096`), falling back to advancing `global_generation` on overflow so untrusted `Admin` `?namespace=...` inputs cannot grow memory unboundedly.
* **Bounded Caching Deadlines & `BufferBudget` Integration (`src/middleware/cache.rs`):**
  * Replaced per-frame timeouts in `read_post_request_body` and unbounded frame polling in `collect_response_for_cache` with fixed wall-clock deadlines (`tokio::time::timeout_at`, 5 s request / 10 s response + bounded gRPC EOF/trailer grace windows) to prevent Slowloris reset loops and stalled upstream flights.
  * Integrated `read_post_request_body`, `collect_response_for_cache`, `ChainedStreamBody`, and `POST` request replay (`BudgetedBytesBody`) with the process-wide 256 MiB router `BufferBudget` (`BufferReservation`), spilling cleanly to `BYPASS` if budget capacity is exhausted.
* **CORS Layer Ordering & RFC 9111 Response `Vary` Validation (`src/configuration/mod.rs`, `src/middleware/cache.rs`):**
  * Required `"Cache"` to appear **after** `"Cors"` in `Layers::validate_middleware_order()` so `CorsLayer` never writes origin-specific headers into shared cache entries.
  * Validated upstream `Vary` response headers in `evaluate_response_cacheability()`: `Vary: *` and headers not listed in `vary_headers` always bypass caching (`Accept-Encoding` is implicitly accepted only for unencoded cache entries handled by the outer `Compression` layer).
* **Multi-Issuer `PerSubject` Isolation & `CacheKey` Scope (`src/middleware/cache.rs`, `src/configuration/mod.rs`):**
  * Added `pub scope: CacheScope` to `CacheKey` and encoded `per_subject` JWT keys as length-prefixed `(claims.iss, claims.sub)` tuples (and length-prefixed SANs) to eliminate cross-issuer collisions when multiple `expected_issuer` values are configured.
* **Lazy Gzip/Brotli Precompression & Synchronous HIT Zero-Copy Fast-Path (`src/middleware/cache.rs`, `src/stack.rs`, `src/configuration/mod.rs`, `src/middleware/compression.rs`):**
  * Added `CacheLayer::with_precompression(...)` (wired automatically from `apply_layers_internal` when `"Compression"` is enabled) and lazy `OnceCell<Option<PrecompressedVariant>>` storage for `gzip`/`br` payloads (`>= 64` bytes when smaller than uncompressed) with precomputed `Content-Length` and `Vary: Accept-Encoding`, allowing outer `SrvCompressionLayer` to skip re-compressing cache HITs.
  * Reduced allocations on synchronous `GET` HITs via `Arc<str>` + `SmallVec` fields in `CacheKey`/`CompiledCacheConfig`, `global_response_cache_guard()` (`ArcSwap::load()`), borrowed rules/configs, a single-parameter `canonical_path_and_query` fast path, precomputed `Content-Length`, and a stack-buffer `u64_to_header_value` formatter for `Age`.
* **Fallback `Cache-Control: no-store` & `grpc-web` / Semicolon Mutation Hardening (`src/lib.rs`, `src/middleware/cache.rs`):**
  * Updated `ConnectionHandler::handle` to skip `is_grpc_content_type` responses and apply `.entry(CACHE_CONTROL).or_insert("no-store")` so explicit `Cache-Control` headers from `StaticFiles`, `CacheLayer`, or upstreams are preserved.
  * Required at least one `0x80` trailer frame with `grpc-status: 0` in `grpc_web_body_has_error`, bypassed `application/grpc-web-text*` in `evaluate_response_cacheability`, and enforced `400 Bad Request` in `CacheService::call` for mutating methods containing `;`/`%3b` path matrix parameters.

### Added
* **Cancellation-Safe `Singleflight<K, T>` (`src/middleware/cache.rs`):**
  * Decouples in-flight work onto a dedicated Tokio task using `tokio::sync::watch` (`borrow_and_update`), `WaiterGuard`, `CancellationToken`, and an `Arc::ptr_eq`-guarded `MapCleanupGuard`.
  * Dropping a single caller future does not abort work for remaining waiters; dropping all waiters cancels the background task and cleans up the key safely without racing new callers.
* **Process-Wide W-TinyLFU Response Cache (`SharedResponseCache`, `CacheLayer`, `[cache]`, `[Server.Layers.Cache]`):**
  * Backed by `moka::sync::Cache` with byte-level `weigher` accounting (`max_bytes`, default `256 MiB`) and per-entry `Expiry` TTLs (`default_ttl_seconds`, default `60` s), shared across every enabled `[[Server]]` instance and preserved across `SIGHUP` reloads when `max_bytes` is unchanged.
  * Opt-in rule matching under `[Server.Layers.Cache.rules]` supporting `"/exact"`, `"/prefix*"`, `"GET /..."`, `"HEAD /..."` (unprefixed rules match only `GET`/`HEAD`), plus exact `"POST /path"` rules for JSON-over-POST, gRPC-Web, and native HTTP/2 Unary gRPC (`grpc-status: 0` trailer preservation, SHA-256 request body hashing bounded by `max_request_body_bytes`, automatic streaming/non-zero `grpc-status` bypass) with lexicographic query normalization, `vary_headers`, `CacheScope` (`public`, `per_role`, `per_subject`), and explicit cross-server sharing via `namespace`.
  * Declarative cross-server mutation invalidation via `[Server.Layers.Cache.invalidations]` (`POST`/`PUT`/`PATCH`/`DELETE`), invalidating target namespaces zero-copy upon clean `HTTP 2xx` or gRPC `grpc-status: 0` completion with per-namespace generation fences preventing stale write-read races.
  * Enforces strict Zero-Trust ordering in `ServerConfig::finalize()` / `Layers::validate_middleware_order()`: `"Cache"` must follow `IpFilter`, `PathSanitizer`, `Decompression`, `MaxPayload`, `Inspection`, `JwtAuth`, `Rbac`, `RateLimiter`, and `Compression`, and is rejected on `ServiceType::Idp` and `ServiceType::Admin`.
  * Streaming responses exceeding `max_entry_bytes` seamlessly switch to `ChainedStreamBody` bypass without buffering unbounded RAM; `aggregate` routes with partial optional failures (`_errors`) attach `CacheBypass` so degraded `200 OK` responses are never cached.
* **Admin Telemetry & Cache Purge (`src/middleware/admin.rs`):**
  * Exposed `.cache` and `.servers[*].cache` in JSON `/status`, added `praeco_cache_entries`, `praeco_cache_bytes_used`, `praeco_server_cache_requests_total{server,outcome}`, and `praeco_server_cache_invalidations_total{server}` to Prometheus `/metrics`, plus CSRF-protected & audit-logged `POST ?action=purge_cache[&namespace=...]` control support.

---

## [0.8.0] - 2026-11-25

Major SemVer-breaking security & architecture release decoupling Role-Based Access Control into a standalone fail-closed Tower middleware (`RbacLayer`), adding `OptionalJwt` symmetry, and bringing first-class RBAC & auth extractors to `praeco_rs::web`.

### Breaking Changes
* **Standalone Fail-Closed `RbacLayer` & Removal of Router-Embedded RBAC (`src/middleware/rbac.rs`, `src/middleware/router/mod.rs`, `src/configuration/mod.rs`):**
  * Removed `RouteConfig::allowed_roles` and `ParsedRoute::allowed_roles` as well as router-internal `enforce_rbac()` (`src/middleware/router/rbac.rs` deleted); `[Server.rbac]` enforced by `"Rbac"` (`MiddlewareLayer::Rbac`) in `[Server.Layers].enabled` is now the single source of truth across all services (`Router`, `WebRouter`, `StaticFiles`, `Admin`, and Tonic gRPC).
  * `RbacLayer` enforces strict fail-closed semantics (`403 Forbidden` on unmatched paths, empty `[]` rules, or matrix parameters `;` / `%3b`; explicit `["*"]` required for public paths such as `"/health"`).
  * `ServerConfig::finalize()` validates `[Server.rbac]` ↔ `"Rbac"` layer consistency, requires `"Rbac"` to appear after `"JwtAuth"`/`"JWT"` when both are enabled, and updates `ServiceType::Admin` / `RouteBackendType::Admin` guardrails so `OptionalJwt` without `"Rbac"` is not treated as strict authentication.
  * Changed `CompiledRbac::from_raw(...)` to return `Result<Self, anyhow::Error>`, rejecting empty keys, unsupported HTTP methods, paths without leading `/`, matrix parameters, and mid-path `*` wildcards at config load/finalize time.
* **Updated `apply_layers` Signature (`src/stack.rs`):**
  * Added `compiled_rbac: Option<Arc<CompiledRbac>>` parameter to `praeco_rs::apply_layers` (after `compiled_allowed_pathes`).
* **`JwtAuthConfig.optional` Field (`src/configuration/mod.rs`):**
  * Added `pub optional: bool` (`#[serde(default)]`) to `JwtAuthConfig` (TOML-compatible; SemVer-breaking for struct literals without `..Default::default()`).

### Added
* **Method-Aware `CompiledRbac` (`src/configuration/mod.rs`, `src/middleware/rbac.rs`):**
  * Supports optional HTTP method prefixes (e.g. `"GET /users/*"`, `"DELETE /users/*"`), matching `"METHOD /exact"` → `"/exact"` → longest prefix across `"METHOD /prefix*"` and `"/prefix*"` (method-specific rules win ties at equal prefix length).
* **`AuthenticationMethod::OptionalJwt` (`src/configuration/mod.rs`, `src/middleware/jwt.rs`, `src/stack.rs`):**
  * Missing tokens pass through with `UserRole::guest()` fallback (preserving pre-existing mTLS roles), while invalid, expired, or revoked tokens still fail with `401 Unauthorized`.
* **Embedded `WebRouter` Auth Extractors & Declarative RBAC (`src/web.rs`, `examples/https_web_server`):**
  * Added `UserRoles`, `ClientOids`, `ClientSan`, and `JwtClaims` extractors plus `*_with_roles` / `*_with_waf_and_roles` route builders and `WebRouter::rbac_rules()` for single-source-of-truth WAF & RBAC derivation.
  * Updated `examples/https_web_server` to `0.2.0`, demonstrating `RbacLayer`, `OptionalClientCert`, `OptionalJwt`, `/whoami`, and `/admin/stats`.

---

## [0.7.1] - 2026-11-23

### Security & Dependencies
* **Security Dependency Update (`RUSTSEC-2026-0592`):** Raised workspace `url` minimum requirement from `2.5` to `2.5.9` to pull the stack-overflow fix in `Url::origin()` on nested `blob:` URLs.

---

## [0.7.0] - 2026-11-22

Major security, PKI/CRL fail-closed defaults, protocol resilience, hot-reload session preservation, zero-copy/zero-alloc hot paths, and gRPC reflection stream optimization release.

### Security, Hardening & Performance (Breaking API Changes)
* **Right-to-Left `X-Forwarded-For` Resolution (`src/middleware/ip_filter.rs`, `src/middleware/rate_limiter.rs`, `src/configuration/mod.rs`, `src/stack.rs`):**
  * Fixed spoofable leftmost `X-Forwarded-For` extraction when `trust_forwarded_headers = true`: both `IpFilter` and rate limiters now share `extract_forwarded_ip_from_headers`, walking `X-Forwarded-For` (including multiple header lines) from right to left using `trusted_proxy_hops` (default `1`, `0` disables XFF) without falling back to `X-Real-IP` when `X-Forwarded-For` is present.
  * Added `pub trusted_proxy_hops: usize` to `IpFilterConfig`, `SimpleRateLimiterConfig`, and `TokenBucketRateLimiterConfig` (TOML-compatible via `#[serde(default)]`, SemVer-breaking for struct literals without `..Default::default()`), plus backward-compatible `extract_client_ip_with_hops`, `extract_rate_limit_key_with_hops`, and `.with_trusted_proxy_hops(...)` builders.
* **Fail-Closed CRL Defaults & Handshake Expiration Enforcement (`src/tls_conf.rs`, `src/configuration/mod.rs`, `common/src/crl.rs`):**
  * Centralised CRL parsing/expiration checks in `praeco-common::crl`, removed the `PRAECO_STRICT_CRL` environment variable and `strict_crl_enabled()` in favour of pure TOML configuration, and switched strict CRL mode to **fail-closed by default** (`ClientCertConfig::strict_crl: bool` defaulting to `true`).
  * Enabled `WebPkiClientVerifierBuilder::enforce_revocation_expiration()` in strict mode so `rustls` enforces CRL `nextUpdate` on every handshake, and rejected empty CRL PEM files at load/reload time.
* **IdP Webhook Validation & O(log n) `JwtRevocationStore` Index (`src/middleware/idp/webhook.rs`, `src/middleware/jwt.rs`):**
  * Replaced prefix-based `claims_webhook_url` validation with strict `url::Url` host/scheme checking (rejecting embedded userinfo and spoofed prefixes like `http://localhost.evil.example`) and bounded returned `oids` (`<= 64` entries, `<= 64` chars each, numeric dot-arc format only).
  * Added an `ExpiryMinHeap` (`BinaryHeap<Reverse<(u64, String)>>` with lazy deletion) to `JwtRevocationStore` so capacity-saturation sweeps and earliest-expiry eviction run in O(log n) instead of scanning all `50,000` entries via `min_by_key`.
* **JWT Verification Hardening & Inline Execution (`common/src/lib.rs`, `src/middleware/jwt.rs`, `src/middleware/idp/mod.rs`, `src/configuration/mod.rs`, `src/stack.rs`):**
  * Added `JwtVerifyOptions`, `verify_jwt_with_options`, `MAX_JWT_TOKEN_LEN` (4 KiB), and `DEFAULT_MAX_JWT_LIFETIME_SECS` (30 days) in `praeco-common`: enforces a 4 KiB length bound and 3-segment JWS check before base64/cryptographic work, validates `nbf`, routes `"praeco-key-<N>"` `kid` headers in O(1) to the matching decoding key (rejecting unknown indices immediately), requires a non-empty `jti` claim (`require_jti = true` by default), and bounds remaining token lifetime (`max_token_lifetime_seconds = 2_592_000` by default).
  * Added `pub require_jti: bool` and `pub max_token_lifetime_seconds: u64` to `JwtAuthConfig` (TOML-compatible via `#[serde(default)]`) plus `.with_require_jti(...)` and `.with_max_token_lifetime_seconds(...)` builders on `JwtAuthLayer`.
  * Eliminated `tokio::task::spawn_blocking` and per-request `String`/`Service` clones in `JwtAuthService::call`, performing Ed25519 verification inline after length/structure pre-filtering and matching `"Bearer "` case-insensitively per RFC 7235.
* **Global 256 MiB Response Buffer Budget & 4 MiB Per-Route Default (`src/configuration/mod.rs`, `src/middleware/router/mod.rs`, `src/middleware/router/grpc_web.rs`, `src/middleware/router/aggregator/mod.rs`):**
  * Lowered `DEFAULT_MAX_AGGREGATE_RESPONSE_BYTES` from 16 MiB to 4 MiB (`4 * 1024 * 1024`) and wired `route_info.max_response_bytes` into `grpc_transcoding` routes (`handle_grpc_web_with_limit`).
  * Added a lock-free process-wide 256 MiB `BufferBudget` (`DEFAULT_GLOBAL_RESPONSE_BUFFER_BUDGET_BYTES`) with RAII `BufferReservation` and `BudgetedBytesBody` / `ChunkedBytesBody` incremental release across `grpc_web` and `aggregator`, shedding excess buffered memory load with `503 Service Unavailable` without penalizing upstream circuit breakers.
* **Upstream Header Policy, Credential Isolation & Health-Probe Body Timeout (`src/configuration/mod.rs`, `src/middleware/router/headers.rs`, `src/middleware/router/mod.rs`, `src/runner.rs`):**
  * Replaced the fixed 28-header identity denylist in `headers::prepare_proxy_headers` with prefix/exact matching (`is_identity_like`: `x-forwarded-*`, `x-auth-*`, `x-authenticated-*`, `x-remote-*`, `x-user*`, `x-client-*`, `x-ssl-*`, `ssl-client-*`, `x-original-*`, `x-rewrite-*`, `remote-*`, `true-client-ip`, `cf-connecting-ip`, etc.) before authoritative header injection.
  * Added `RouteHeaderPolicy` on `ParsedRoute` and per-route `RouteConfig` fields (`strip_authorization`, `forward_authorization`, `strip_cookies`, `strip_cookie_names`, `forward_headers`) stripping client `Authorization` and `Cookie` headers by default (with automatic `[Server.Layers.JWT].cookie_fallback` redaction when selective cookie forwarding is active, while preserving all cookies when a route explicitly sets `strip_cookies = false` without `strip_cookie_names` or includes `"cookie"` in `forward_headers`), rejecting contradictory configs at startup, and preserving per-target `forward_headers` opt-ins on `aggregate` routes.
  * Extracted `execute_health_probe` in `src/runner.rs` so both `client.request(req)` and the bounded (`64 KiB`) health-check response body read run inside the shared 5-second timeout (`ACTIVE_HEALTH_CHECK_TIMEOUT`).
* **IdP JSON/Cookie Validation & Panic Removal (`src/middleware/idp/mod.rs`, `src/configuration/mod.rs`):**
  * Replaced all manual `format!` JSON string construction in `IdpService` with `serde_json::json!`, eliminated all `.unwrap()` calls across production IdP paths (`Response::new`, `unwrap_or_default`, and typed `WebhookEndpoint` state enum), and validated `cookie_name`, `cookie_domain`, and `redirect_after_login` at startup in both `ServerConfig::finalize` and `IdpService::new`.
* **Workspace-Wide `.unwrap()` / `.expect()` Elimination & Crate Lints (`Q-01`):**
  * Enabled `#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]` in `server` (`lib.rs`, `server.rs`), `relay-server` (`lib.rs`, `main.rs`), and `common` (`lib.rs`, exempting `test-pki`).
  * Replaced all remaining production `Response::builder()...unwrap()`/`expect(...)`, `unauthorized_response::<T>(...).unwrap()` (`jwt.rs`), `pool_opt.expect(...)` (`grpc_web.rs` returning `502 Bad Gateway`), `DelayService::poll_ready` `as_mut().unwrap()` (`get_or_insert_with`), `LbStrategy::{LeastConnections,HighestScore}` `expect(...)`, `rustls::crypto::default_provider().install_default().expect(...)` (`server.rs`), and future `take().expect("polled after completion")` calls across middleware with shared infallible helpers (`build_infallible_response`, `poll_ready_response`) and explicit error returns.
* **Configurable TLS Session Cache & CRL-Safe Resumption Policy (`src/configuration/mod.rs`, `src/tls_conf.rs`):**
  * Added `pub session_cache_size: Option<usize>` and `pub session_tickets: bool` to `ServerCertConfig` (TOML-compatible via `#[serde(default)]`).
  * Raised the default `ServerSessionMemoryCache` size from `1024` to `20_000` (`DEFAULT_TLS_SESSION_CACHE_SIZE`) for non-mTLS listeners, kept `1024` (`DEFAULT_MTLS_TLS_SESSION_CACHE_SIZE`) for mTLS listeners without CRLs, and defaulted mTLS listeners with `ssl_client_crl` to `NoServerSessionStorage` (`0`) so revoked certificates are not bypassed by resumed sessions.
  * Added opt-in stateless `session_tickets` (`rustls::crypto::aws_lc_rs::Ticketer`, 12 h max lifetime), rejected at startup (`ServerConfig::finalize` and `tls_conf::tls_config`) when paired with `ssl_client_crl`.
* **Substring Log Redaction (`src/middleware/logger.rs`, `S-09`):**
  * Replaced exact header/query key matching in `sanitize_headers` and `sanitize_uri` with case-insensitive substring matching (`token`, `secret`, `session`, `jwt`, `key`, `pass`, `sig`, `auth`, `credential`) so variants such as `access_token`, `id_token`, `refresh_token`, `api_key`, `password`, `signature`, `x-api-key`, and `x-auth-token` are redacted consistently.
  * Restricted unmasked `code` query parameter logging strictly to `/auth/confirm` (onboarding flow) while redacting `code` on all other paths (e.g., OAuth callbacks).
* **Workspace Dependency Deduplication (`Cargo.toml`, `deny.toml`, `src/middleware/idp/session.rs`, `src/configuration/resilience.rs`, `src/runner.rs`, `Q-03`):**
  * Upgraded workspace `rand` (`0.8` → `0.10`), `socket2` (`0.5` → `0.6`), and aligned `pem` (`4.0` → `3.0` matching `jsonwebtoken`/`rcgen`), eliminating duplicate `pem 4.0`, `socket2 0.5`, `rand 0.8`, `rand_core 0.6`, `rand_chacha 0.3`, and `getrandom 0.2` from `Cargo.lock`.
  * Added root `deny.toml` with `[bans] multiple-versions = "warn"`.
* **Doc Comment Alignment & Logic Edge-Case Hardening (`Q-07`, `Q-08`):**
  * Moved the misplaced `sanitize_and_normalize_path_cow` doc comment off `contains_ascii_ignore_case` (`src/middleware/path_sanitizer.rs`), aligned `tls_config` parameter/protocol docs (`src/tls_conf.rs`), and documented the intentional difference between the fail-closed L7 middleware limiter (`src/middleware/rate_limiter.rs`) and L4 relay `overflow_bucket` (`relay-server/src/limits.rs`).
  * Rejected malformed, non-UTF-8, or duplicate `Max-Forwards` headers with `400 Bad Request` instead of silently resetting to `10` (`src/middleware/router/headers.rs`), replaced `as u16` with `u16::from(max_forwards)`, and documented gateway-wide method loop detection.
  * Fixed `normalize_segment` to preserve multi-byte UTF-8 via byte accumulation and bounds-check truncated `%` escapes with `bytes.get(...)` (`src/middleware/path_sanitizer.rs`).
  * Added `checked_add` length arithmetic in `parse_grpc_health_score` (`src/runner.rs`), penalized upstream circuit breakers (`record_failure_with_epoch`) on corrupt/short `< 5` byte or truncated gRPC-Web responses (`src/middleware/router/grpc_web.rs`), and added per-route `RouteConfig::retry_put_delete: Option<bool>` / `ParsedRoute::retry_put_delete: bool` (`true` by default) to opt out of `PUT`/`DELETE` retries (`src/configuration/mod.rs`, `src/middleware/router/{mod,http_proxy}.rs`).
* **Typed `WebhookFailurePolicy` & Logging/Dead-Code Cleanup (`Q-05`, `Q-06`):**
  * Replaced stringly-typed `IdpParams::on_webhook_failure: String` with `pub enum WebhookFailurePolicy` (`Reject` default, `FallbackToCert`; `#[serde(rename_all = "snake_case")]`, `#[non_exhaustive]`) so configuration typos fail fast at TOML load time (`src/configuration/mod.rs`, `src/middleware/idp/{mod,webhook}.rs`).
  * Removed unused `tracing::error` import (`src/middleware/jwt.rs`), replaced `println!` calls with `tracing::info!` in `grpc_reflection`, removed commented-out extension blocks in `cert_decoder`, and added `--quiet` / stderr token-output notice to `jwt_creator`.
  * **Breaking (`P2-01`)**: Changed `PemCertExtension`, `SanCertExtension`, and `OidCertExtension` to hold `Arc<str>` and `Arc<Vec<String>>` respectively (with `PartialEq`, `Eq`, `From`, `Deref`, and `AsRef` implementations) so `ConnectionHandler::handle` shares client certificate extensions zero-copy across requests without per-request heap clones.
  * **Log Hygiene & CLI Hardening (`Q2-09`, `Q-05`):** Registered a dedicated `FileFormatFields` wrapper on `praeco-relay-server`'s file tracing layer (`relay-server/src/main.rs`) to prevent `stdout_layer` ANSI escape sequences and duplicate fields from leaking into rotating relay log files; removed dead/commented code from `cert_decoder/src/main.rs`, restored the `2.25.*` UUID-OID filter, and sanitized terminal output against control/ANSI characters.
  * **Hot-Reload Alignment (`Q2-01`):** Aligned `CONFIG` documentation in `server/src/configuration/mod.rs` with existing `ArcSwap` `SIGHUP` updates (`Config::update_global`) and added a dynamic stack hot-reload regression test verifying updated `InspectionLayer` and `JwtAuthLayer` `oid_mapping` rules.
  * **`MaxPayloadLayer` gRPC Stream Scope Hardening (`S2-04`):** Added `GrpcStreamPolicy` (`Disabled`, `AllowPrefixes`, `AllowAnyGrpcContentType`) to `MaxPayloadLayer` so `build_service_stack` restricts the `64 × max_bytes` gRPC framing allowance strictly to `RouteBackendType::GrpcPassthrough` route prefixes (and disables it on REST/non-gRPC routes and `Echo`/`Admin`/`Idp`/`StaticFiles` servers), blocking chunked `Content-Type: application/grpc` payload limit bypasses.
  * **PKI, CRL & JWT Hardening (`S2-07`, `S2-08`):** Switched `common::build_root_store` / `build_root_store_with_webpki` to fail closed via `root_store.add(cert)` on invalid CA certificates; rejected unknown non-`praeco-key-*` `kid` headers in `common::verify_jwt_with_options` without scanning all keys; updated `ServerConfig::finalize()` to iterate all PEM CRL blocks via `pem_file_iter` for `pki_info`; and rejected mixed `strict_crl` values across CRL-bearing `[[Server.client_certs]]` entries in `finalize()` and `tls_conf::tls_config()`.
  * **Hot-Path Security Headers & Reload Session Preservation (`P2-04`, `P2-08`):** Pre-parsed all 5 `SecurityHeadersLayer` values once into `Arc<PrecomputedSecurityHeaders>` to eliminate per-request `String` clones and `HeaderValue::from_str` parsing (`src/middleware/security_headers.rs`); added `PreservedTlsSessionState` (`tls_conf::tls_config_preserving_sessions`, `stack::build_rustls_config_preserving_sessions`, `server.rs`, `runner.rs`) so `SIGHUP` reloads preserve `ServerSessionMemoryCache` and `Ticketer` across non-PKI changes while invalidating them whenever client CA/CRL DER bytes or session settings change.
  * **Breaking (`Q2-08`)**: Changed `RouteTarget::next_upstream` to return `Option<&UpstreamNode>` (`None` when `upstreams` is empty instead of panicking), handled fail-closed (`502 Bad Gateway`) in `http_proxy.rs` / `grpc_web.rs`, and replaced `update_ema_ms` with `EmaState` (microsecond precision + initialization bit) to prevent zero-reset latency spikes after `< 1 ms` responses.
  * **Relay `SIGHUP` & Single-Pass CRL Reload (`Q2-07`):** Always run the Unix `SIGHUP` reload watcher in `relay-server/src/tls.rs` even when `crl_path` is `None` or `reload_interval` is zero, and parse CRL PEMs once per reload via `setup_mtls_acceptor_and_serials`.
  * **Router IP/PEM Header Caching & Zero-Allocation Middleware Hot Paths (`P2-05`, `P2-06`):** Eliminated repeated `addr.ip().to_string()` formatting and per-request PEM `urlencoding::encode` work by formatting peer IPs once on a stack buffer (`ip_addr_to_header_value` in `headers.rs`) and caching `EncodedPemCertHeaderExtension` once per mTLS/QUIC connection (`ConnectionHandler`, `runner.rs`); removed per-request `String` allocations across `InspectionService` (`sanitize_and_normalize_path_cow`), `CompiledAllowedPathes::is_allowed` (`Cow::Borrowed`), `SrvCompressionService` (`NegotiatedEncoding` copy enum), `rbac::enforce_rbac` (`windows(3).eq_ignore_ascii_case`), and `WebRouter::into_service` (borrowed method/path).
  * **Single-Stream gRPC Reflection & Descriptor Deduplication (`P2-07`):** Refactored `grpc_web::build_grpc_pool` to reuse one bidirectional `server_reflection_info` stream for `ListServices` and all `FileContainingSymbol` lookups, deduplicate shared imported `FileDescriptorProto` payloads via `seen_files`, and enforce `MAX_REFLECTION_SERVICES` (`256`) and `MAX_DESCRIPTOR_FILES` (`1024`) bounds.
  * **Single-Pass Client X.509 Metadata Extraction (`P2-09`):** Refactored `tls_conf::extract_client_metadata_with_base` to parse the leaf DER certificate once (`X509Certificate::from_der`) for both SAN and OID extraction instead of parsing twice per mTLS/QUIC connection.

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
