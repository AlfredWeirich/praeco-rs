
# praeco-rs - Enterprise Zero-Trust API Gateway: the European sovereign proxy

https://medium.com/@alfred.weirich/tokio-tower-hyper-and-rustls-building-high-performance-and-secure-servers-in-rust-part-11-7782d195ce2a?source=friends_link&sk=00042bfce222ddd16d8cd5f0380f161a
(Part 1 to 11)

---

`praeco-rs` is an ultra-fast, highly configurable, and secure API Gateway and Reverse Proxy written in Rust. It is built on top of the Tokio async runtime, Hyper v1, Tower, and Rustls.

*(The name **praeco** comes from Latin, meaning "herald" or "crier" — just as a historical herald controlled the flow of information and announced messages to the public, this gateway acts as the sovereign announcer and gatekeeper for your network traffic).*

Designed for zero-trust enterprise environments, it provides deep mTLS integration, declarative middleware pipelines, dynamic JSON-to-gRPC transcoding (acting as a REST-to-gRPC Gateway), and zero-downtime hot-reloading.

---
> **Quality & Verification:** Hardened with workspace-wide `deny(clippy::unwrap_used, clippy::expect_used)` in production code, strict `#[serde(deny_unknown_fields)]` schema validation, an extensive automated unit & integration test suite, and regular AI-assisted security & code reviews.

**Newly Added**: 
* **Embeddable Library Crate & `cli` Feature Gate (`v0.5.4`)**: Decoupled listener/lifecycle orchestration (`praeco_rs::runner`) and stream-generic Tower stack assembly (`praeco_rs::stack`) from the CLI binary (`src/server.rs`). External Rust applications can depend on `praeco-rs = { version = "0.5.4", default-features = false }` without pulling in `mimalloc`, `tracing-subscriber`, or OTLP exporters, and run full gateway pipelines over TCP, QUIC, Yamux tunnels, or in-memory `tokio::io::duplex` streams.
* **Built-in Admin & Telemetry Service (`Admin`)**: Dedicated `service = "Admin"` listener or router-mounted `backend_type = "admin"` exposing `/healthz` (`/health`), `/status`, `/upstreams`, and Prometheus `/metrics` (with strict label escaping against exposition format injection) with strict `404` routing, per-layer security block counters, circuit-breaker telemetry, response latency EMA, and X.509 certificate / CRL expiration monitoring. Unauthenticated standalone `Admin` listeners are enforced loopback-only and read-only (`POST ?action=...` returns `403`), `backend_type = "admin"` requires authentication or explicit RBAC, and `POST` control actions enforce fail-closed `Sec-Fetch-Site` and `Origin` anti-CSRF checks plus `admin::audit` logging.
* **3-State Circuit Breaker, Outlier Detection & Bounded Retry Buffering**: Lock-free `Closed` $\rightarrow$ `Open` $\rightarrow$ `HalfOpen` (single-probe) circuit breaking across both single-node and multi-node routes with passive `502`/`503`/`504` & gRPC `UNAVAILABLE` outlier detection, connect-only retry discipline for non-idempotent gRPC calls, and configurable `max_retry_buffer_bytes` (default 64 KiB).
* **Zero-Allocation `IpFilterLayer` & RFC 3986 `PathSanitizerLayer`**: Pre-compiled IPv4/IPv6 CIDR allowlists/blocklists (`deny`-before-`allow`, `PROXY v2` aware) plus mandatory URI canonicalization and path-traversal rejection.
* **Built-in Identity Provider (IdP), Claims Webhook & JWKS**: Issues signed Ed25519 JWTs from mTLS identities (with `OptionalClientCert` support, `iss`/`aud` enforcement, live role-fetching webhooks, `/.well-known/jwks.json`, and `revoke_on_paths` automatic JTI revocation).
* **Outbound Zero-Trust Tunneling (SNI Relay) & Static File Server**: Multiplexed outbound mTLS (`yamux`) reverse tunnels with fail-closed `PROXY v2` client IP propagation, plus a native SPA-capable static file server (`StaticFiles`).
* **Parallel Fan-Out / Aggregator Routes (`backend_type = "aggregate"`, `v0.6.0`)**: Accepts a single `GET` or `POST` client request, fans out concurrently across mixed `grpc_transcoding` (via Reflection) and `rest` targets with zero-copy `keyed`/`broadcast` payload slicing (`RawValue` + `Bytes::slice_ref`), per-target query/header policies, independent circuit breakers, sanitized `required = false` graceful degradation (`null` + `_errors`), and zero-copy `ChunkedBytesBody` JSON frame assembly.
* **Supervised Listeners, Graceful Draining & Ordered Hot-Reload Restarts (`v0.6.0`)**: `start_single_server` and `spawn_dual_stack` supervise TCP, UDP/QUIC (`h3` `GOAWAY`), Yamux tunnel streams, and active health-check tasks end-to-end with configurable `graceful_shutdown_timeout_seconds` (default `10` s), transient `accept()` error backoff, and `SocketReleaseBarrier`-coordinated `SIGHUP` restarts that release old sockets before re-binding without `EADDRINUSE`.
* **Embedded Web Router, Typed Extractors & WAF Sync (`web` feature, `v0.6.1`)**: Optional `praeco_rs::web` module (`features = ["web"]`) providing a `matchit`-backed `WebRouter`, Axum-style typed extractors (`Query<T>`, `Path<T>`, `PathParams`, `Json<T>`, `TraceId`, `Request<SrvBody>`), `IntoResponse`, and single-source-of-truth `WebRouter::allowed_pathes()` generation for Praeco's `Inspection` WAF layer.
* **Live `SIGHUP` Hot-Reload Completeness, Per-Server `pki_base_oid` & Resilience Hardening (`v0.6.2`)**: Per-request `ArcSwap` stack and OID-mapping reload (`ConnectionHandler::with_dynamic_stack_and_oids`), live TLS/mTLS/CRL reload (`start_single_server_reloadable`), per-server `pki_base_oid`, `SIGTERM` handling, unified `aws-lc-rs` crypto, `#[serde(deny_unknown_fields)]`, `IdleTimeoutBody`/`H3Body` timeouts, circuit-breaker epoch guards, `grpc_web` hardening, and self-contained ephemeral `TestPki`.
* **Fail-Closed CRL/JWT Hardening, 256 MiB Buffer Budget & Zero-Alloc Hot Paths (`v0.7.0`, Breaking)**: Fail-closed CRL defaults (`strict_crl = true` + handshake `nextUpdate`), right-to-left `X-Forwarded-For` (`trusted_proxy_hops`), inline Ed25519 JWT verification (`4 KiB` cap, O(1) `kid` routing, `require_jti = true`, `max_token_lifetime_seconds`, `ExpiryMinHeap`), 256 MiB global response buffer budget & 4 MiB per-route default, `RouteHeaderPolicy` default `Authorization`/`Cookie` stripping, workspace-wide `deny(clippy::unwrap_used, clippy::expect_used)`, `PreservedTlsSessionState` across reloads, single-stream gRPC reflection, single-pass X.509 DER parsing, typed `WebhookFailurePolicy`, and zero-copy `Arc` certificate extensions.
* **Security Dependency Update (`v0.7.1`)**: Raised workspace `url` minimum requirement to `2.5.9` (`RUSTSEC-2026-0592`).
* **Standalone Fail-Closed `RbacLayer`, `OptionalJwt` & `WebRouter` Auth Integration (`v0.8.0`, Breaking)**: Extracted RBAC out of `RouterService` (removing `RouteConfig::allowed_roles` / `ParsedRoute::allowed_roles`) into a generic fail-closed `"Rbac"` middleware layer (`RbacLayer`) with method-aware rules (`"GET /users/*"`), startup pattern validation (`CompiledRbac::from_raw -> Result`), and enforced `JwtAuth` $\rightarrow$ `Rbac` ordering; added `AuthenticationMethod::OptionalJwt` & `JwtAuthConfig.optional` (with `Guest` fallback); added `praeco_rs::web` auth extractors (`UserRoles`, `ClientOids`, `ClientSan`, `JwtClaims`) plus `*_with_roles` / `WebRouter::rbac_rules()`; updated `examples/https_web_server` to `0.2.0`.
* **Process-Wide W-TinyLFU Response Cache & Cancellation-Safe `Singleflight` (`v0.8.1`)**: Added [`CacheLayer`](server/src/middleware/cache.rs) (`"Cache"` in `[Server.Layers].enabled`) backed by a process-wide `moka` W-TinyLFU [`SharedResponseCache`](server/src/middleware/cache.rs) shared across all `[[Server]]` instances (preserved across `SIGHUP` reloads when `max_bytes` is unchanged) and a cancellation-safe [`Singleflight`](server/src/middleware/cache.rs) coalescer (`watch` + `WaiterGuard` + `Arc::ptr_eq`-guarded `MapCleanupGuard`). Supports opt-in per-path rules (`[Server.Layers.Cache.rules]`, including exact `"POST /path"` rules with SHA-256 body hashing for JSON RPCs, gRPC-Web, and native HTTP/2 Unary gRPC with `grpc-status: 0` trailer replay), declarative cross-server `[Server.Layers.Cache.invalidations]`, cross-server `namespace` sharing, `public` / `per_role` / `per_subject` isolation scopes, `CacheBypass` for partially degraded `aggregate` (`_errors`) responses, JSON `/status` & Prometheus cache metrics, and `POST ?action=purge_cache` in `Admin`.

> **Full Changelogs:** See [`server/CHANGELOG.md`](https://github.com/AlfredWeirich/praeco-rs/blob/main/server/CHANGELOG.md) (`praeco-rs`), [`common/CHANGELOG.md`](https://github.com/AlfredWeirich/praeco-rs/blob/main/common/CHANGELOG.md) (`praeco-common`), and [`relay-server/CHANGELOG.md`](https://github.com/AlfredWeirich/praeco-rs/blob/main/relay-server/CHANGELOG.md) (`praeco-relay-server`).

---

## 1. Features

| Feature | `praeco-rs` | Pingora (Cloudflare) | Sōzu |
| :--- | :--- | :--- | :--- |
| **Primary Architecture** | Tokio, Hyper v1, Tower, Rustls | Custom Async Runtime & State Machine | Custom Event Loop (Mio) |
| **HTTP Protocols** | HTTP/1.1, HTTP/2, HTTP/3 (QUIC) + `Alt-Svc` | HTTP/1.1, HTTP/2 (H3 in progress) | HTTP/1.1, HTTP/2 |
| **Security & Auth** | mTLS (`ClientCert` / `OptionalClientCert`) & JWT (`Jwt` / `OptionalJwt`, `revoke_on_paths`), unified fail-closed `RbacLayer` (method & path OID RBAC), Built-in IdP (JWKS/Webhook), CIDR `IpFilter`, RFC 3986 `PathSanitizer` | Pluggable, but requires custom code | Standard TLS, SNI routing |
| **gRPC Support** | **Full (Passthrough & JSON Transcoding via Reflection)** | Basic Proxying | Basic Proxying |
| **Observability** | OpenTelemetry (OTLP + W3C `traceparent`), Prometheus `/metrics`, Admin JSON (`/status`, `/upstreams`, `/healthz`) | Pluggable via Rust code | Pluggable via Rust code |
| **Middleware Model** | Declarative `tower::Service` stack via TOML (with order validation) | Callbacks / Traits on Session | Custom Filters |
| **WAF / Inspection** | Built-in Regex Path/Query Allow-Listing + Decompression Bomb & Payload Limits | Pluggable / Scriptable | Custom Filters |
| **Configuration** | Hot-Reloadable (SIGHUP + ArcSwap + Dry-Run) | Programmable (in Rust) | Dynamic (Zero-Downtime Hot-Reload) |
| **Load Balancing** | Advanced (RoundRobin, LeastConn, Sticky, Random, HighestScore) + 3-State Circuit Breaker | Advanced (Consistent Hash, Least Conn) | Advanced |
| **Library / Embedding** | **Embeddable (`runner` + `stack`, `cli` feature gate, `AsyncRead + AsyncWrite` generic)** | Library-first (Rust) | Binary daemon |

---

## 2. Advantages of `praeco-rs`

> [!TIP]
> **Why choose `praeco-rs`?** It shines in highly secure, zero-trust enterprise environments where gRPC interoperability, advanced load distribution, and strict rate control are primary requirements.

- **Declarative Middleware Pipeline & Automatic Security Baselines**: The entire middleware stack (`TraceId`, `Logger`, `IpFilter`, `Decompression`, `MaxPayload`, `Inspection`, `JwtAuth`, `Rbac`, `RateLimiter`, `ConcurrencyLimit`, `Compression`, `Cache`, `Cors`, `SecurityHeaders`, `AltSvc`, `Timing`, `Counter`, `Delay`) can be configured, reordered, and toggled on/off in `Config.toml` in seconds **without writing or recompiling Rust code**. Startup/reload validation enforces safe ordering (`TraceId` first, `Inspection` after `Decompression`, `Rbac` after `JwtAuth`, `Cache` after security/RBAC/compression) and automatically injects `PathSanitizerLayer` and `SecurityHeadersLayer` so even short-circuit responses (`401`/`403`/`429`/`503`) carry hardened headers.
- **Zero-Allocation IP Allowlist / Blocklist (`IpFilter` Layer)**: Pre-compiles IPv4 (`u32`) and IPv6 (`u128`) CIDR masks (`allow_cidrs` and `deny_cidrs`) with strict `deny`-before-`allow` precedence, dual-stack `::ffff:a.b.c.d` canonicalization, right-to-left `X-Forwarded-For` hop extraction (`trusted_proxy_hops`, when `trust_forwarded_headers = true`), and full compatibility with Relay Server `PROXY v2` client IP propagation—allowing administrative or internal servers to be locked down to VPN/office subnets at the edge with `403 Forbidden`.
- **Native OpenTelemetry (OTLP) Integration**: `praeco-rs` integrates directly with the `tracing` and `opentelemetry` ecosystem, exporting distributed traces to Jaeger, Zipkin, or Datadog via standard OTLP out of the box with configurable sampling (`otel_sample_ratio`). Incoming W3C `traceparent` (or `x-trace-id`) headers are extracted at the edge (`TraceIdLayer` & `TraceLayer`), linked as the OpenTelemetry parent context prior to span entry, and automatically propagated (`traceparent` + `x-trace-id`) across REST, gRPC passthrough, and dynamic JSON-to-gRPC transcoding hops.
- **Lightweight WAF, Decompression Bomb & Payload Protection**: Includes a Regex-based `InspectionLayer` validating `(method, path, query)` against an allow-list with zero heap allocations on the happy path, paired with `SrvDecompressionLayer` (`max_decompressed_bytes`) bomb protection and streaming `MaxPayloadLayer` (`max_bytes`) enforcement.
- **Strict RFC 3986 Path Sanitization & Traversal Protection**: Enforces canonical URI paths across all layers and upstream dispatch. Rejects directory traversal attempts (`..`, `%2e%2e`), encoded slashes (`%2f`), null bytes (`%00`), semicolon matrix parameters (`;` / `%3b`), and backslashes with `400 Bad Request`, normalizes trailing slashes on exact RBAC rules, and collapses multi-slashes (`//`) to eliminate semantic desync and RBAC/WAF bypasses.
- **Out-of-the-box REST to gRPC Gateway**: Unlike Pingora or Sōzu, `praeco-rs` can dynamically reflect backend gRPC schemas and translate incoming REST/JSON requests into binary Protobuf on the fly (JSON-to-gRPC transcoding) with non-blocking async I/O, upstream deadlines (`request_timeout_seconds`), configurable per-route response caps (`max_response_bytes`, default 4 MiB) paired with a 256 MiB process-wide response buffer budget, and automatic compression bypass for `application/grpc*` streams to preserve HTTP/2 trailers. This eliminates the need for separate sidecars like Envoy for transcoding.
- **Bespoke Zero-Trust RBAC via Custom OIDs & Flexible Auth Modes**: The proxy natively extracts custom Object Identifiers (OIDs) directly from mTLS client certificates (`ClientCert` or `OptionalClientCert` for mixed authenticated/guest endpoints) or JWTs (`Jwt` or `OptionalJwt` for mixed public/JWT-protected endpoints) and maps them to internal `UserRole`s (e.g., Admin, Operator, Seller) using stack-allocated `SmallVec<[UserRole; 6]>` slices to avoid per-request heap allocations.
  * **Unified Fail-Closed `RbacLayer` (All Services)**: Define method- and path-level rules (`[Server.rbac] "/*" = ["Admin", "Seller"]`, `"/api/*" = ["Admin"]`, `"GET /users/*" = ["Viewer", "Admin"]`, explicit `["Admin", "Seller"]` endpoint exceptions, fail-closed empty deny-rules `[]`, and explicit public `["*"]`) enforced uniformly by the `"Rbac"` middleware layer across `Router`, `WebRouter`, `StaticFiles`, `Admin`, and embedded Tonic gRPC services. The gateway acts as a strict Policy Enforcement Point (PEP), rejecting unmatched or unauthorized calls at the edge with 403 Forbidden before backend resources are consumed.
  * **Identity Forwarding & Edge Header Sanitization**: Unconditionally strips client-supplied `Forwarded`, `X-Forwarded-*`, `X-Real-IP`, and `x-client-*` headers across HTTP/1.1, HTTP/2, and HTTP/3, re-populating `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Proto`, and `X-Forwarded-Host` (including `:authority`) authoritatively from the verified socket/PROXY-v2 peer. If the upstream server needs to know who the caller is, the proxy forwards verified roles (`header_roles`), client IP (`header_client_ip`), SAN (`header_san`), or the client certificate (`header_cert`) via `[Server.client_cert_forwarding]`.
- **Advanced Upstream Management & 3-State Circuit Breaker**: Built-in support for multiple load-balancing strategies (`RoundRobin`, `Random`, `LeastConnections`, `Sticky`, `HighestScore`) combined with **Active Health Checking**, **Outlier Detection (`502`/`503`/`504` & gRPC `UNAVAILABLE`)**, a lock-free **3-State Circuit Breaker (`Closed` $\rightarrow$ `Open` $\rightarrow$ `HalfOpen` single-probe)**, and **Bounded Retry Buffering (`max_retry_buffer_bytes`, default 64 KiB)** ensures traffic is only routed to healthy nodes without thundering-herd probes or unbounded RAM buffering on large uploads. Client-side errors (payload limits, decompression bombs, client aborts on request bodies) are cleanly isolated from upstream transport failures so healthy upstreams are never blacklisted by malicious or broken clients.
- **Built-in Rate Limiting & Traffic Shaping**: Includes flexible token-bucket and fixed-window rate limiting strategies, global concurrency limits, and request timeouts. Rate limiters feature IPv6 `/64` subnet canonicalization (`canonical_client_ip`), ignore `X-Forwarded-For` headers by default (`trust_forwarded_headers = false`, and evaluate them right-to-left via `trusted_proxy_hops` when enabled), use an allocation-free $O(1)$ fast-path with throttled 10s TTL sweeps, and enforce a **fail-closed `max_entries` cap** (`429 Too Many Requests` for unknown keys at capacity without evicting active buckets) to defeat cache-thrashing attacks.
- **Connection Limits & DoS / Protocol-Hardening**: Protects against Slowloris, socket exhaustion, and HTTP/2 Rapid-Reset attacks (CVE-2023-44487) via global and per-IP (IPv6 `/64`-aggregated) connection limits, strict stream caps (128 concurrent streams, max 20 pending reset streams), 64 KB header limits, bounded QUIC transport buffers with stateless address validation (`retry`), and Tokio task fault isolation (`panic = "unwind"` in release builds).
- **Built-in Admin & Telemetry Service (`Admin`)**: Exposes `/healthz`, `/status`, `/upstreams`, and Prometheus `/metrics` either on a dedicated internal loopback listener (`service = "Admin"`, read-only when unauthenticated) or mounted behind mTLS/JWT/RBAC inside a router (`backend_type = "admin"`, CSRF-protected & audit-logged `POST` controls), including per-layer security block counters, circuit-breaker states, and X.509 leaf certificate / CRL expiration monitoring.
- **Crash-Safe Zero-Downtime Configuration Reloads & Graceful Shutdown**: `praeco-rs` handles both `SIGINT` (`Ctrl-C`) and `SIGTERM` for graceful draining and OTel flush, and listens for `SIGHUP` signals to dynamically reload `Config.toml` (with strict `#[serde(deny_unknown_fields)]` schema checking) and rebuild its routing tables and TLS contexts on the fly using `ArcSwap` without dropping active connections. Reloads run through an isolated validation and dry-run phase: if a syntax, route, CORS/JWT constraint, or certificate error is detected, the old working configuration is preserved and the process continues safely without crashing. When listener bind parameters (`ip`, `port`, `protocol`, `tunnel`) change, old instances release their listening sockets before the replacement binds while draining in-flight requests for up to `graceful_shutdown_timeout_seconds`.
- **End-to-End mTLS Bridging & Strict PKI Isolation**: In addition to mTLS termination at the gateway (with fail-closed X.509 CRL `nextUpdate` validation and handshake-time `enforce_revocation_expiration()` enabled by default via `strict_crl = true`), the proxy can establish a completely **new mTLS connection to the upstream servers** using strictly isolated custom Root CAs (never polluting private PKI trust stores with public WebPKI roots).
- **Built-in Identity Provider (IdP) & JWT Revocation**: `praeco-rs` can act as a standalone Identity Provider, issuing its own signed JWTs directly to clients for downstream use. It utilizes its own mTLS capabilities to securely authenticate devices and support QR-code-based cross-device logins protected by a mandatory 6-character visual confirmation code (`user_code`, verified in constant time with a 3-attempt lockout **before** invoking external Claims Webhooks), mTLS-authenticated explicit JTI revocation (`POST /auth/revoke?jti=...`), automatic logout-path revocation (`revoke_on_paths` in `[Server.Layers.JWT]`), mandatory `jti` (`require_jti = true`), bounded token lifetimes (`max_token_lifetime_seconds = 2592000`), O(1) `kid` key routing (`"praeco-key-<N>"`), inline Ed25519 verification with 4 KiB pre-filtering, and a bounded `JwtRevocationStore` (`50,000` entries).
- **Built-in Static File Server**: Beyond proxying and Identity Provider functions, Praeco can act as a highly performant static file server. It supports SPA-Routing (fallback to `index.html`) out of the box, completely eliminating the need for Nginx when serving React, Vue, or WebAssembly (e.g. Iced) frontends alongside your APIs.
- **HTTP/3 Native & `Alt-Svc` Advertisement**: Full support for HTTP/3 over QUIC out of the box using `quinn` and `h3` on dual-stack HTTPS listeners (with optional `AltSvc` header advertisement), providing better performance on unreliable networks.
- **High-Throughput Runtime & Modular Embedding**: The CLI binary uses `mimalloc` (gated behind the default `cli` feature) and supports modular multi-file `includes` (`conf.d/*.toml`) as well as automatic local LAN binding (`ip = "local"`). Library consumers can disable `cli` (`default-features = false`) and embed `praeco_rs::runner` or `praeco_rs::stack` (`AsyncRead + AsyncWrite` generic) directly, including deterministic in-memory testing via `tokio::io::duplex`.
- **Outbound Zero-Trust Tunneling (SNI Relay)**: For deployments behind restrictive NATs or firewalls, `praeco-rs` can bypass local port binding entirely. Instead, it establishes an outbound, multiplexed mTLS connection (via Yamux) to a standalone Relay Server. The Relay Server verifies client certificate SAN-to-SNI authorization on `REGISTER`, propagates the real client IP via fail-closed HAProxy PROXY-Protocol v2 (`proxy_protocol = true`), and routes incoming internet traffic (Port 443) strictly via SNI to the corresponding Praeco instance with complete End-to-End TLS.

---

## 3. Disadvantages of `praeco-rs`

> [!WARNING]
> **Where it falls short**: `praeco-rs` is an incredibly feature-rich API Gateway, but differs from edge-tier CDNs in a few specific areas.

- **Local-Only Response Caching (No L2 Distributed Cache Yet)**: Since `v0.8.1`, `praeco-rs` includes a process-wide W-TinyLFU in-memory HTTP response cache (`CacheLayer` + cancellation-safe `Singleflight`) shared across all local `[[Server]]` instances. However, unlike Pingora's multi-node edge CDN caching, cache entries are currently node-local (no shared Redis L2 tier or cross-node invalidation yet).
- **Community & Maturity**: Pingora is backed by Cloudflare processing trillions of requests. `praeco-rs` is currently a bespoke, highly specialized enterprise solution. While its core leverages production-ready crates (`hyper`, `tower`), the proxy itself lacks the widespread community testing of older proxies.

---

## 4. Open Points & Roadmap

To elevate `praeco-rs` even further, the following points remain on the roadmap:

### 1. Distributed L2 Caching (Redis) & Aggregator Sub-Target Caching
Local process-wide W-TinyLFU caching with cancellation-safe `Singleflight`, unary `grpc_passthrough` / JSON `POST` caching, and declarative cross-server invalidations are implemented (`v0.8.1`). Next steps are an optional shared **Redis (L2)** tier with Pub/Sub invalidation across multiple `praeco-rs` instances and per-sub-target caching inside `aggregate` fan-out routes.

### 2. Pluggable End-Services (Beyond Routing)
Currently, `praeco-rs` terminates the middleware pipeline into a `Router` (for proxying and `aggregate` fan-out routes), an `Idp` (Identity Provider), a `StaticFiles` service, an `Admin` telemetry service, or an `Echo` service (for testing). Due to the modular `tower::Service` architecture, future roadmap items include adding new native end-services, such as:
- **Redirect Service**: Simple port-to-port or HTTP-to-HTTPS redirects at the edge.
- **Mock / Stub Service**: Returning predefined JSON responses for specific routes, allowing frontend teams to develop against the gateway before backend APIs are finished.

---

## Usage / Quick Start

`praeco-rs` is entirely driven by its declarative configuration file. 
Here is a **minimal example** of a `Config.toml` that sets up a simple reverse proxy with logging and compression:

```toml
# Config.toml
enable_opentelemetry = false
pki_base_oid = "1.3.6.1.4.1.65111"

[[Server]]
name = "api_gateway"
ip = "0.0.0.0"
port = 1336
protocol = "http"
authentication = "None"
service = "Router"
enabled = true

[Server.ReverseRoutes."/api/"]
upstreams = ["http://127.0.0.1:8080"]
backend_type = "rest"

[Server.RouterParams]
protocol = "http"
authentication = "None"

[Server.Layers]
enabled = ["Logger", "Compression", "ConcurrencyLimit"]

[Server.Layers.ConcurrencyLimit]
max_concurrent_requests = 1000
```

> **Full Configuration Reference:**
> The proxy offers extensive settings for mTLS, RBAC OIDs, JSON-to-gRPC transcoding, and rate limiting. 
> **See [Config.md](https://github.com/AlfredWeirich/praeco-rs/blob/main/Config.md) for a complete documentation of all available parameters.**

### Installation & Running

**Option 1: Install via Cargo (Recommended)**
If you just want to run the proxy, you can install the pre-compiled executable directly from GitHub. Cargo will automatically download the source and compile it in release mode:

```bash
cargo install --git https://github.com/AlfredWeirich/praeco-rs.git --package praeco-rs
```

Then start the proxy by simply calling the executable (it looks for `Config.toml` in the current directory, or you can pass the path):

```bash
praeco-rs
# OR with a specific config:
praeco-rs /path/to/your/Config.toml
```

**Option 2: Run from Source (Development)**
If you cloned the repository and want to run it directly from the source code:

```bash
cargo run -p praeco-rs --release
# OR using the provided start script:
./start_praeco.sh
```

By default, it will look for `Config.toml` in the current working directory. You can instantly reload configuration changes at runtime without dropping connections by sending a `SIGHUP` signal to the process (or shut down gracefully via `Ctrl-C` / `SIGTERM`). Reloads are crash-safe: unknown config keys are rejected fail-fast (`#[serde(deny_unknown_fields)]`), and the new configuration, middleware constraints, and TLS certificates are fully validated in an isolated dry-run before activating, keeping the existing configuration intact if errors are found.

To run the full self-contained workspace test suite (using ephemeral runtime `rcgen` certificates via `common::test_pki::TestPki`, requiring no local `server_certs/` or `client_certs/` files):

```bash
cargo test --workspace --locked
```

**Option 3: Embed `praeco-rs` as a Library Crate**
You can embed Praeco's gateway stack, Tower middlewares, or full dual-stack / tunnel listeners inside your own Rust application without pulling in CLI-only dependencies (`mimalloc`, `tracing-subscriber`, `tracing-appender`, `opentelemetry-otlp`, `opentelemetry_sdk`, `num_cpus`) by disabling the default `cli` feature:

```toml
[dependencies]
praeco-rs = { version = "0.8.0", default-features = false }
# Enable the embedded WebRouter & typed extractors (Query, Path, Json, TraceId, UserRoles, JwtClaims, ...):
# praeco-rs = { version = "0.8.0", default-features = false, features = ["web"] }
```

Key library entry points re-exported at the crate root:
- `praeco_rs::runner` (`run_servers`, `start_single_server`, `start_single_server_with_socket_signal`, `run_dual_stack`, `spawn_dual_stack`, `DualStackHandles`, `run_tunnel`, `run_tunnel_with_timeout`, `spawn_router_health_checks`, `spawn_router_health_checks_in`, `CONNECTION_DRAIN_TIMEOUT`) – supervised TCP (HTTP/1.1, HTTP/2), UDP/QUIC (HTTP/3), active health-check loops, graceful connection draining, and outbound mTLS/Yamux tunnel orchestration.
- `praeco_rs::stack` (`build_service_stack`, `build_service_stack_with_base`, `wrap_tonic_routes`, `apply_layers`, `build_rustls_config`, `serve_http_connection`, `serve_tls_connection`, `run_tunnel_over_stream`, `run_tunnel_over_stream_with_drain_timeout`) – composable Tower pipelines, custom/Tonic service wrappers, and stream-level runners.
- `praeco_rs::web` *(feature `web`)* – composable `WebRouter` (`.get()`, `.post()`, `*_with_waf()`, `*_with_roles()`, `*_with_waf_and_roles()`, `.allowed_pathes()`, `.rbac_rules()`), Axum-style typed extractors (`Query<T>`, `Path<T>`, `PathParams`, `Json<T>`, `TraceId`, `UserRoles`, `ClientOids`, `ClientSan`, `JwtClaims`), and `IntoResponse` for building embedded HTTPS/HTTP3 APIs directly behind Praeco's security stack.
- `praeco_rs::middleware` & `praeco_rs::configuration` – standalone Tower layers (`IpFilterLayer`, `JwtAuthLayer`, `RbacLayer`, `TokenBucketRateLimiterLayer`, `RouterService`, …) and TOML config parsing/finalization.

```rust,no_run
use tokio_util::sync::CancellationToken;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rustls::crypto::aws_lc_rs::default_provider().install_default().ok();
    // Use Config::init (instead of Config::load) to also populate the global config
    // singleton used by mTLS OID extraction and the Admin telemetry service.
    let config = praeco_rs::configuration::Config::init("Config.toml")?;
    let cancel = CancellationToken::new();
    praeco_rs::run_servers(config, cancel).await;
    Ok(())
}
```

#### Programmatic Embedding Without `Config.toml` (Binary gRPC Aggregator Example)
For applications that configure `ServerConfig` purely in Rust (`..Default::default()`, no `Config.toml` on disk) and wrap a typed `tonic` gRPC service (e.g. binary Protobuf-to-Protobuf fan-out) with Praeco's middleware stack, see [`server/examples/embedded_grpc_aggregator.rs`](server/examples/embedded_grpc_aggregator.rs):

- **What it does:** Spawns two typed `tonic` gRPC backend services (`user.UserService/GetUser` and `order.OrderService/CountOrders`), implements a typed Protobuf-to-Protobuf `aggregator.DashboardService/GetDashboard` service that fans out concurrently via `tokio::join!` while forwarding Praeco's `x-trace-id`, bridges `tonic::service::Routes` via `praeco_rs::wrap_tonic_routes`, wraps it with `praeco_rs::build_service_stack_with_base` (`TraceId`, `IpFilter`, `MaxPayload`, `TraceLayer`/`ServerMetrics`, and `PathSanitizerLayer`), starts the gateway with `start_single_server`, executes a real binary gRPC request against it, and shuts down cleanly via `CancellationToken`.
- **How to run it (with `--no-default-features`):**

```bash
cargo run -p praeco-rs --example embedded_grpc_aggregator --no-default-features
```

```text
Aggregator received request with x-trace-id="00-..."
Aggregated gRPC Response -> user_name='Alice (42)', order_count=7, cache-control=no-store
```

#### Programmatic Embedding Without `Config.toml` (HTTPS + HTTP/3 Web Server Crate)
For a standalone binary crate embedding `praeco-rs` (`default-features = false, features = ["web"]`) as a hardened HTTPS + HTTP/3 (QUIC) web server with composable endpoint handlers, see [`examples/https_web_server`](https://github.com/AlfredWeirich/praeco-rs/tree/main/examples/https_web_server):

- **What it does:** Keeps `src/main.rs` focused purely on domain endpoints (`/`, `/healthz`, `/users/{id}`, `/greet?user_name=alice[&age=17]`, `POST /api/echo`) using `praeco_rs::web::{WebRouter, Path, Query, Json, TraceId}` and `IntoResponse`, while `src/bootstrap.rs` encapsulates programmatic `ServerConfig` defaults, TLS 1.3 certs, and graceful `Ctrl+C` shutdown.
- **Full Praeco security stack:** Every endpoint is automatically protected by Praeco's full hardened middleware pipeline (`TraceId`, `SecurityHeaders`, `AltSvc`, `IpFilter`, `RateLimiter:TokenBucket`, `ConcurrencyLimit`, `MaxPayload`, `Decompression`, and `Inspection` WAF whose `AllowedPathes` rules are derived directly from `router.allowed_pathes()`) plus TCP/UDP dual-stack HTTP/1.1, HTTP/2, and HTTP/3 (QUIC) via `start_single_server`.

```rust,no_run
use praeco_rs::web::{Json, Path, Query, TraceId, WebRouter};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct GreetQuery { user_name: String, age: Option<u8> }

#[derive(Serialize)]
struct GreetPayload { user_name: String, age: Option<u8>, greeting: String }

async fn greet(Query(GreetQuery { user_name, age }): Query<GreetQuery>) -> Json<GreetPayload> {
    let greeting = match age {
        Some(years) => format!("Hallo {user_name} ({years} Jahre)!"),
        None => format!("Hallo {user_name}!"),
    };
    Json(GreetPayload { user_name, age, greeting })
}

async fn get_user(Path(id): Path<String>, TraceId(trace_id): TraceId) -> String {
    format!("user={id}, trace_id={trace_id:?}\n")
}
```

- **How to run and test it from the workspace:**

```bash
cargo run -p https_web_server
cargo test -p https_web_server
```


### Attachment:
Here is a **FULL example** of a `Config.toml` from a production system:

```toml
###############################################################################
# GLOBAL SYSTEM SETTINGS
# These settings affect the overall performance and base identity of the gateway.
###############################################################################

# The number of worker threads for the Tokio async runtime.
# Default: number of logical CPU cores (num_cpus::get()).
# Manual override is useful for high-performance tuning on dedicated hardware.
tokio_threads = 50

# Enable or disable background OpenTelemetry Tracing (Jaeger)
# If false, TraceLayer is silently skipped and no background export tasks are started.
enable_opentelemetry = true
jaeger_endpoint = "http://localhost:4317"
otel_log_level = "info"
# otel_sample_ratio = 1.0  # Trace sampling ratio (0.0 to 1.0, default: 1.0)

# The Base Object Identifier (OID) used for security validation (global fallback;
# can also be overridden per [[Server]] block).
# This acts as the root for interpreting client certificate extensions and JWT claims.
# Private Enterprise Number (PEN)
pki_base_oid = "1.3.6.1.4.1.65111"

# Automatically include all server configurations from the conf.d directory
includes = ["conf.d/*.toml"]

# Directory path for persistent log files.
# If commented out or omitted, the application will only log to Standard Output (stdout).
log_dir = "logs"

# =============================================================================
# XYZ_APP CONFIGURATION
# This file contains all server instances required for the XYZ_APP backend.
# =============================================================================

[[Server]]
# =============================================================================
# Main API Gateway (Internal - mTLS Required)
# =============================================================================
    name = "server_name" 
    ip = "0.0.0.0"
    port = 1336
    enabled = true
    protocol = "https"
    authentication = "ClientCert"
    service = "Router"

    [Server.Layers]
    enabled = ["TraceId", "Logger", "IpFilter", "Decompression", "MaxPayload", "Inspection", "RateLimiter:TokenBucket", "ConcurrencyLimit"]

    [Server.Layers.IpFilter]
    allow_cidrs = []
    deny_cidrs = []
    trust_forwarded_headers = false

    [Server.Layers.Decompression]
    max_decompressed_bytes = 10485760  # 10 MB limit

    [Server.connection_limits]
    max_connections = 10000
    max_connections_per_ip = 100

    [Server.server_certs]
    ssl_certificate = "PATH_TO_CERT/fullchain12.pem"
    ssl_certificate_key = "PATH_TO_CERT/privkey12.pem"

    [[Server.client_certs]]
    ssl_client_ca = "PATH_TO_CERT/ca.pem"
    ssl_client_crl = "PATH_TO_CERT/ca.crl.pem"

    [Server.client_cert_forwarding]
    header_cert = "x-client-cert"
    header_san = "x-client-san"

    [Server.Layers.ConcurrencyLimit]
    max_concurrent_requests = 10000

    [Server.Layers.MaxPayload]
    max_bytes = 10485760 # 10 MB Limit

    [Server.AllowedPathes.POST]
    "/ENDPOINT.ABC_Service/GetConversations" = ["^/ENDPOINT\\.ABC_Service/GetConversations$"]
    "/ENDPOINT.ABC_Service/GetMessages" = ["^/ENDPOINT\\.ABC_Service/GetMessages$"]
    # ...
    "/ENDPOINT.ABC_Service/UpdateMemberRole" = ["^/ENDPOINT\\.ABC_Service/UpdateMemberRole$"]
    "/ENDPOINT.ABC_Service/GetOrders" = ["^/ENDPOINT\\.ABC_Service/GetOrders$"]
    "/ENDPOINT.ABC_Service/UpdateOrderStatus" = ["^/ENDPOINT\\.ABC_Service/UpdateOrderStatus$"]

    [Server.ReverseRoutes."/"]
    upstreams = ["https://127.0.0.1:50051"]
    active_health_check_interval = 60
    backend_type = "grpc_passthrough"
    cooldown_seconds = 10
    max_retries = 2
    failure_threshold = 3
    max_retry_buffer_bytes = 65536

    [Server.RouterParams]
    protocol = "https"
    authentication = "ClientCert"
    ssl_client_certificate = "PATH_TO_CERT/proxy-client.pem"
    ssl_client_key = "PATH_TO_CERT/proxy-client.key"
    ssl_root_certificate = "PATH_TO_CERT/ca.pem"

    [Server.Layers.TokenBucketRateLimiter]
    max_capacity = 1000     
    refill = 50           
    duration_micros = 10000 

[[Server]]
# =============================================================================
# Onboarding Server (Public - no mTLS)
# =============================================================================
    name = "onboarding"
    ip = "0.0.0.0"
    port = 1337
    protocol = "https"
    service = "Router"
    enabled = true
    authentication = "None"

    [Server.server_certs]
    ssl_certificate = "PATH_TO_CERT/fullchain12.pem"
    ssl_certificate_key = "PATH_TO_CERT/privkey12.pem"

    [Server.Layers]
    enabled = ["MaxPayload", "Logger", "Inspection", "RateLimiter:TokenBucket", "ConcurrencyLimit"]

    [Server.Layers.ConcurrencyLimit]
    max_concurrent_requests = 128

    [Server.Layers.MaxPayload]
    max_bytes = 2000000 # 2 MB Limit (CSR requests are small)

    [Server.Layers.TokenBucketRateLimiter]
    max_capacity = 15     
    refill = 5           
    duration_micros = 1000000 
    key_by = "ip"

    [Server.AllowedPathes.POST]
    "/ENDPOINT.ObSrv/RequestOnboarding" = ["^/ENDPOINT\\.ObSrv/RequestOnboarding$"]
    "/ENDPOINT.ObSrv/SubmitOnboarding" = ["^/ENDPOINT\\.ObSrv/SubmitOnboarding$"]

    [Server.ReverseRoutes."/"]
    upstreams = ["https://127.0.0.1:50052"]
    backend_type = "grpc_passthrough"

    [Server.RouterParams]
    protocol = "https"
    authentication = "None"
    ssl_root_certificate = "PATH_TO_CERT/ca.pem"

    [Server.client_cert_forwarding]
    header_cert = "x-client-cert"
    header_san = "x-client-san"

[[Server]]
# =============================================================================
# Management & Admin Server (Port 1338 /admin & gRPC-Web)
# =============================================================================
    name = "admin"
    ip = "0.0.0.0"
    port = 1338
    protocol = "https"
    authentication = "ClientCert"
    service = "Router"
    enabled = true
    
    [Server.oid_mapping]
        "1" = "Admin"
        "2" = "Seller"
    
    [Server.server_certs]
        ssl_certificate = "PATH_TO_CERT/fullchain12.pem"
        ssl_certificate_key = "PATH_TO_CERT/privkey12.pem"
    
    [[Server.client_certs]]
        ssl_client_ca = "PATH_TO_CERT/ca.pem"
        ssl_client_crl = "PATH_TO_CERT/ca.crl.pem"
    
    [Server.client_cert_forwarding]
        header_cert = "x-client-cert"
        header_san = "x-client-san"
    
    [Server.Layers]
        enabled = ["Logger", "SecurityHeaders", "Decompression", "MaxPayload", "Inspection", "Rbac", "RateLimiter:TokenBucket", "ConcurrencyLimit"]
    
    [Server.Layers.SecurityHeaders]
        content_security_policy = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'"
        strict_transport_security = "max-age=63072000; includeSubDomains; preload"
        x_content_type_options = "nosniff"
        x_frame_options = "DENY"
    
    [Server.Layers.Decompression]
        max_decompressed_bytes = 10485760
    
    [Server.Layers.ConcurrencyLimit]
        max_concurrent_requests = 10000
    
    [Server.Layers.MaxPayload]
        max_bytes = 10485760
    
    [Server.Layers.TokenBucketRateLimiter]
        max_capacity = 1000
        refill = 50
        duration_micros = 10000
    
    [Server.AllowedPathes.GET]
        "/admin" = ["^/admin$"]
        "/admin/" = ["^/admin/$"]
        "/admin/index.html" = ["^/admin/index\\.html$"]
        "/favicon.ico" = ["^/favicon\\.ico$"]
        "/apple-touch-icon.png" = ["^/apple-touch-icon\\.png$"]
        "/apple-touch-icon-precomposed.png" = ["^/apple-touch-icon-precomposed\\.png$"]
    
    [Server.AllowedPathes.POST]
        "/api/WhoAmI" = ["^/api/WhoAmI$"]
        "/api/GetUsers" = ["^/api/GetUsers$"]
        "/api/GetAdminDevices" = ["^/api/GetAdminDevices$"]
        "/api/AdminBlockDevice" = ["^/api/AdminBlockDevice$"]
        # ...
        "/api/AdminAddMember" = ["^/api/AdminAddMember$"]
        "/api/AdminUpdateProductCreator" = ["^/api/AdminUpdateProductCreator$"]
        "/api/AdminCreateChannel" = ["^/api/AdminCreateChannel$"]
    
    [Server.ReverseRoutes."/"]
        upstreams = ["https://127.0.0.1:50053"]
        backend_type = "grpc_passthrough"

    [Server.rbac]
        "/*"                      = ["Admin", "Seller"]
        "/api/*"                  = ["Admin"]
        "/api/WhoAmI"             = ["Admin", "Seller"]
        "/api/AdminGetProducts"   = ["Admin", "Seller"]
        "/api/AdminUpsertProduct" = ["Admin", "Seller"]
        "/api/AdminDeleteProduct" = ["Admin", "Seller"]
    
    [Server.RouterParams]
        protocol = "https"
        authentication = "ClientCert"
        ssl_client_certificate = "PATH_TO_CERT/proxy-client.pem"
        ssl_client_key = "PATH_TO_CERT/proxy-client.key"
        ssl_root_certificate = "PATH_TO_CERT/ca.pem"

[[Server]]
# =============================================================================
# Local Admin & Prometheus Telemetry Server (/healthz, /status, /metrics)
# Tip: Can also be mounted behind mTLS/RBAC on a Router via backend_type = "admin"
# =============================================================================
    name = "local_admin"
    ip = "127.0.0.1"
    port = 9090
    enabled = true
    protocol = "http"
    authentication = "None"
    service = "Admin"

    [Server.Layers]
    enabled = []
```

---

## Workspace Crates

This repository is organized as a Cargo workspace containing `praeco-rs` and companion crates/tools:

* [`server/` (`praeco-rs`)](https://github.com/AlfredWeirich/praeco-rs/blob/main/server/Cargo.toml) – Core Zero-Trust API Gateway, library crate (`runner` + `stack` + optional `web` router), and CLI binary.
* [`relay-server/` (`praeco-relay-server`)](https://github.com/AlfredWeirich/praeco-rs/blob/main/relay-server/README.md) – Standalone Layer-4 SNI Relay Server for outbound zero-trust reverse tunnels (`yamux` + `PROXY v2`).
* [`common/` (`praeco-common`)](https://github.com/AlfredWeirich/praeco-rs/blob/main/common/Readme.md) – Shared JWT helpers (`jwt`), TLS/PKI builders (`tls`), HTTP client pool (`client`), `PROXY v2` parser/encoder, canonical IP normalization, and feature-gated `test-pki` ephemeral test PKI.
* [`client/` (`praeco-client`)](https://github.com/AlfredWeirich/praeco-rs/blob/main/client/Readme.md) – High-performance HTTP/2, HTTP/3 (QUIC), and gRPC load/test client with mTLS support.
* [`jwt_creator/`](https://github.com/AlfredWeirich/praeco-rs/blob/main/jwt_creator/Readme.md) – CLI utility for generating Ed25519 keys and signing test JWTs.
* [`cert_decoder/`](https://github.com/AlfredWeirich/praeco-rs/blob/main/cert_decoder/Readme.md) – Helper tool to inspect X.509 certificates and custom PKI OIDs.
* [`grpc_reflection/`](https://github.com/AlfredWeirich/praeco-rs/blob/main/grpc_reflection/Readme.md) – Example gRPC backend with Server Reflection for testing JSON-to-gRPC transcoding.
* [`examples/https_web_server/`](https://github.com/AlfredWeirich/praeco-rs/blob/main/examples/https_web_server/README.md) – Standalone embedded HTTPS + HTTP/3 web server example using `praeco-rs` with `features = ["web"]`, `RbacLayer` (mTLS / `OptionalJwt`), and no `Config.toml`.
* [`server/examples/aggregate_fanout/`](https://github.com/AlfredWeirich/praeco-rs/blob/main/server/examples/aggregate_fanout/README.md) – Standalone `backend_type = "aggregate"` fan-out gateway example combining gRPC-transcoding (via Reflection) and REST sub-targets.