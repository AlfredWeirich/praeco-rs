# Praeco Configuration Reference Manual (`Config.toml`)

This manual provides an exhaustive, production-grade technical reference for all configuration parameters available in `Config.toml` (Praeco API Gateway) and `RelayConfig.toml` (Praeco Relay Server).

Every parameter includes:
- **Exact data type and syntax**
- **Mandatory vs. Optional status**
- **Default value when omitted**
- **Internal runtime mechanics and architectural side effects** (e.g. thread allocation, memory buffering, network connections, logging behavior)
- **Validation rules, constraints, and fail-closed security behaviors**
- **Practical TOML configuration snippets**

---

## Table of Contents

1. [Startup, Lifecycle & Hot-Reloading](#startup-lifecycle--hot-reloading)
2. [Global System Settings](#global-system-settings)
   - [Includes (`includes`)](#includes-includes)
   - [Tokio Worker Threads (`tokio_threads`)](#tokio-worker-threads-tokio_threads)
   - [Log Directory & Stdout Interaction (`log_dir`)](#log-directory--stdout-interaction-log_dir)
   - [PKI Base Object Identifier (`pki_base_oid`)](#pki-base-object-identifier-pki_base_oid)
3. [Telemetry & Distributed Tracing](#telemetry--distributed-tracing)
   - [Enable OpenTelemetry (`enable_opentelemetry`)](#enable-opentelemetry-enable_opentelemetry)
   - [Jaeger / OTLP Endpoint (`jaeger_endpoint`)](#jaeger--otlp-endpoint-jaeger_endpoint)
   - [Telemetry Log Level (`otel_log_level`)](#telemetry-log-level-otel_log_level)
   - [Sampling Ratio (`otel_sample_ratio`)](#sampling-ratio-otel_sample_ratio)
4. [Server Instances (`[[Server]]`)](#server-instances-server)
   - [Instance Identification & Lifecycle (`name`, `enabled`)](#instance-identification--lifecycle)
   - [Network Binding & Dual Protocol (`protocol`, `ip`, `port`)](#network-binding--dual-protocol)
   - [Authentication Modes (`authentication`)](#authentication-modes-authentication)
   - [Base Service Selection (`service`)](#base-service-selection-service)
   - [Outbound Zero-Trust Tunneling (`[Server.tunnel]`)](#outbound-zero-trust-tunneling-servertunnel)
   - [Connection Limits & Protocol Defense (`[Server.connection_limits]`)](#connection-limits--protocol-defense-serverconnection_limits)
   - [Role-Based Access Control & OID Mapping (`[Server.oid_mapping]`)](#role-based-access-control--oid-mapping-serveroid_mapping)
   - [TLS & Client Certificate Verification (`[Server.server_certs]`, `[[Server.client_certs]]`)](#tls--client-certificate-verification)
   - [Client Certificate Header Forwarding & Anti-Spoofing (`[Server.client_cert_forwarding]`)](#client-certificate-header-forwarding--anti-spoofing-serverclient_cert_forwarding)
5. [Base Services Deep-Dive](#base-services-deep-dive)
   - [Echo Service (`service = "Echo"`)](#echo-service-service--echo)
   - [Static File Server & SPA Routing (`service = "StaticFiles"`)](#static-file-server--spa-routing-service--staticfiles)
   - [Identity Provider (`service = "Idp"`)](#identity-provider-service--idp)
   - [Reverse Proxy Router (`service = "Router"`)](#reverse-proxy-router-service--router)
6. [gRPC Architecture & Features Deep-Dive](#grpc-architecture--features-deep-dive)
   - [Mode Comparison: Passthrough vs. Transcoding](#mode-comparison-passthrough-vs-transcoding)
   - [Native gRPC Passthrough (`backend_type = "grpc_passthrough"`)](#native-grpc-passthrough-backend_type--grpc_passthrough)
   - [Dynamic JSON-to-gRPC Transcoding (`backend_type = "grpc"`)](#dynamic-json-to-grpc-transcoding-backend_type--grpc)
   - [gRPC Server Reflection & Schema Caching](#grpc-server-reflection--schema-caching)
   - [Active Health Checking & Score Metrics for gRPC](#active-health-checking--score-metrics-for-grpc)
   - [HTTP/2 Upstream Connection Pool & Keep-Alive Mechanics](#http2-upstream-connection-pool--keep-alive-mechanics)
   - [HTTP/2 Trailers Preservation & Compression Layer Bypass](#http2-trailers-preservation--compression-layer-bypass)
   - [gRPC Error Propagation & Gateway Status Codes](#grpc-error-propagation--gateway-status-codes)
7. [Granular Path-Level RBAC (`[Server.rbac]`)](#granular-path-level-rbac-serverrbac)
8. [Lightweight WAF / Inspection Layer (`[Server.AllowedPathes]`)](#lightweight-waf--inspection-layer-serverallowedpathes)
9. [Middleware Layer Pipeline (`[Server.Layers]`)](#middleware-layer-pipeline-serverlayers)
   - [Ordering Constraints & Execution Model](#ordering-constraints--execution-model)
   - [Detailed Layer Reference](#detailed-layer-reference)
10. [Relay Server Configuration (`RelayConfig.toml`)](#relay-server-configuration-relayconfigtoml)
11. [Appendix: Cryptographic Keys & Certificates Overview](#appendix-cryptographic-keys--certificates-overview)
12. [Complete Production Configuration Examples](#complete-production-configuration-examples)

---

## Startup, Lifecycle & Hot-Reloading

### Launching the Gateway

Praeco can be started with a default or custom configuration file:

```bash
# Standard startup (searches for ./Config.toml in current working directory)
./server

# Custom configuration file passed as first CLI argument
./server /etc/praeco/production.toml

# Via Cargo during development
cargo run --bin server -- /path/to/custom_config.toml
```

### Atomic Hot-Reloading via `SIGHUP`

To trigger a live configuration reload without dropping client connections:

```bash
kill -HUP <PID_OF_PRAECO>
```

#### Under the Hood: The Crash-Safe Dry-Run Process
1. **File Reading & Deserialization:** The configuration file specified at launch (and all globbed `includes`) is read and parsed into memory.
2. **Regex Pre-Compilation:** All regular expressions in `[Server.AllowedPathes]` and path patterns in `[Server.rbac]` are compiled.
3. **Eager Cryptographic Validation:** Server TLS certificate chains, private keys, client CA roots, CRLs, and JWT public/private keys are read and validated from disk. If a certificate file is missing or contains invalid PEM data, the process stops here.
4. **Middleware Ordering & Constraint Checks:** The middleware stack of every server is validated (e.g. verifying that `TraceId` is first and CORS credentials rules are satisfied).
5. **Atomic Swap:** Only if **all** validation checks pass, Praeco swaps the running configuration in memory via an `arc-swap` atomic pointer swap (`Config::update_global`).
   - Existing in-flight connections continue processing against their existing middleware stacks.
   - All newly accepted connections immediately run on the newly loaded configuration.
   - **Rollback Guarantee:** If any step fails (syntax error, missing certificate, invalid regex), an error log is emitted and the running gateway continues operating on the previous valid configuration **with zero downtime and zero dropped sockets**.

---

## Global System Settings

Global settings are defined at the root of `Config.toml` (outside any `[[Server]]` table). They control system-wide concurrency, logging architecture, modularity, and PKI root definitions.

| Parameter | Data Type | Requirement | Default Value | Summary |
| :--- | :--- | :--- | :--- | :--- |
| [`includes`](#includes-includes) | Array of Strings | Optional | `[]` (None) | Glob patterns to external modular configuration files. |
| [`tokio_threads`](#tokio-worker-threads-tokio_threads) | Integer | Optional | Available CPU Cores * 2 | Number of async worker OS threads for the Tokio runtime. |
| [`log_dir`](#log-directory--stdout-interaction-log_dir) | String | Optional | `None` (Stdout only) | Directory for asynchronous, non-blocking rolling log files. |
| [`pki_base_oid`](#pki-base-object-identifier-pki_base_oid) | String | Optional | `None` | Base Private Enterprise Number (PEN) OID for role mapping. |

---

### Includes (`includes`)

- **Data Type:** Array of Strings (e.g. `["conf.d/*.toml", "/etc/praeco/apps/*.toml"]`)
- **Requirement:** Optional
- **Default Value:** `[]` (Empty list; only the main configuration file is parsed)

#### Detailed Mechanics & System Impact:
- **Evaluation Order:** At startup and during `SIGHUP` reload, Praeco processes the patterns in the order declared using the `glob` crate.
- **Path Resolution:** Relative paths are resolved against the **parent directory of the root configuration file** (not the current working directory). Absolute paths are respected as-is.
- **Merging Behavior:** All `[[Server]]` blocks found across matching files are appended to the internal server registry. 
- **Isolation:** Global parameters (such as `tokio_threads` or `log_dir`) defined inside included files are **safely ignored**. Global settings can only be set from the root `Config.toml`.
- **Error Handling:** If an include pattern matches no files, Praeco logs an informational trace and continues. However, if an included file contains syntax errors or invalid TOML, the entire startup/reload fails closed.

```toml
# Root Config.toml
includes = [
    "conf.d/*.toml",
    "/etc/praeco/extra_servers.toml"
]
```

---

### Tokio Worker Threads (`tokio_threads`)

- **Data Type:** Integer (`usize`)
- **Requirement:** Optional
- **Default Value:** `Available Logical CPU Cores * 2` (e.g. `16` on an 8-core CPU)

#### Detailed Mechanics & System Impact:
- **Under the Hood:** Initializes the asynchronous runtime via `tokio::runtime::Builder::new_multi_thread().worker_threads(threads).enable_all().build()`.
- **Resource Allocation:** Each worker thread is an OS thread pinned to an async event loop polling non-blocking sockets (epoll on Linux, kqueue on macOS).
- **Impact of Setting Too High:** Setting this value significantly higher than the number of hardware threads (e.g. `128` on a 4-core CPU) induces heavy thread context switching and cache thrashing, reducing overall throughput.
- **Impact of Setting Too Low:** Setting this to `1` or `2` on high-concurrency systems can cause async tasks to stall if CPU-intensive operations (such as TLS handshakes, Gzip compression, or regex evaluation) occupy the threads.
- **Recommended Tuning:** On bare-metal servers or dedicated VMs, setting `tokio_threads` equal to the number of physical CPU cores or keeping the default `num_cpus * 2` provides optimal latency and throughput.

```toml
# Restrict Tokio to 16 dedicated worker threads
tokio_threads = 16
```

---

### Log Directory & Stdout Interaction (`log_dir`)

- **Data Type:** String (Filesystem directory path)
- **Requirement:** Optional
- **Default Value:** `None` (Stdout-only logging)

#### Detailed Mechanics & System Impact:
- **Does stdout still receive logs when `log_dir` is set?**
  **YES, DEFINITELY.** Setting `log_dir` does **not** disable terminal logging. Praeco uses a composite subscriber architecture (`tracing_subscriber::Registry`):
  1. **Standard Output Layer (`stdout_layer`):** Always active. Outputs colored, human-readable log lines with ANSI formatting (`with_ansi(true)`).
  2. **File Logging Layer (`file_layer`):** Dynamically attached only when `log_dir` is configured.
  3. **Telemetry Layer (`telemetry_layer`):** Active when `enable_opentelemetry = true`.
  All active layers receive every log event simultaneously.

- **Non-Blocking Asynchronous Disk I/O:**
  File logging wraps `tracing_appender::rolling::RollingFileAppender` inside `tracing_appender::non_blocking`. Log records are dispatched to an internal memory buffer and written to disk by a dedicated background worker thread (`WorkerGuard`). **Disk latency or disk I/O stalls never block the async Tokio worker threads.**

- **File Rotation & Naming:**
  - **Rotation Cadence:** Daily rotation (`Rotation::DAILY`).
  - **Filename Convention:** Files are named `app.YYYY-MM-DD.log` inside the specified directory.
  - **Formatting:** ANSI color codes are stripped (`with_ansi(false)`) so logs are clean for ingest by tools like Filebeat, Vector, Promtail, or Fluentbit.

- **Log Level Filtering:**
  Both `stdout` and file logging evaluate the `RUST_LOG` environment variable (e.g. `RUST_LOG=info,praeco_rs=debug`), defaulting to `"info"` if unset.

```toml
# Enable rolling daily logs in the /var/log/praeco directory
# Logs will appear BOTH on stdout (with ANSI color) AND in /var/log/praeco/app.YYYY-MM-DD.log
log_dir = "/var/log/praeco"
```

---

### PKI Base Object Identifier (`pki_base_oid`)

- **Data Type:** String (Dotted decimal ASN.1 OID notation, e.g. `"1.3.6.1.4.1.65111"`)
- **Requirement:** Optional (Mandatory if certificate OID role mapping or JWT OID claims are used)
- **Default Value:** `None`

#### Detailed Mechanics & System Impact:
- **Under the Hood:** During `Config::init`, Praeco parses each numeric component into an optimized vector of 64-bit integers (`Vec<u64>`). If the string contains non-numeric segments or invalid characters, startup fails immediately.
- **OID Extraction from Certificates:** When an incoming client certificate is verified during an mTLS handshake, Praeco's ASN.1 parser (`extract_oids_from_cert`) scans all X.509 extensions.
- **Prefix Matching:** An extension is recognized as an authorization OID only if its integer sequence starts with `pki_base_oid`. The final component is extracted as the role suffix (e.g. OID `1.3.6.1.4.1.65111.1` yields suffix `"1"`).
- **What happens if omitted?** If `pki_base_oid` is omitted from `Config.toml`, Praeco cannot extract role suffixes from client certificates. Any client authenticating via mTLS will receive the fallback role **`Guest`**, regardless of what extensions are in the certificate.

```toml
# Private Enterprise Number (PEN) assigned by IANA: 65111
pki_base_oid = "1.3.6.1.4.1.65111"
```

---

## Telemetry & Distributed Tracing

Praeco includes native OpenTelemetry (OTLP) integration using Tonic gRPC export. Telemetry settings are defined at the top level of `Config.toml`.

| Parameter | Data Type | Requirement | Default Value | Summary |
| :--- | :--- | :--- | :--- | :--- |
| [`enable_opentelemetry`](#enable-opentelemetry-enable_opentelemetry) | Boolean | Optional | `false` | Master switch for exporting spans to an OTLP collector. |
| [`jaeger_endpoint`](#jaeger--otlp-endpoint-jaeger_endpoint) | String | Optional | `"http://localhost:4317"` | OTLP gRPC endpoint URL. |
| [`otel_log_level`](#telemetry-log-level-otel_log_level) | String | Optional | `"info"` | Log level filter for spans sent to the collector. |
| [`otel_sample_ratio`](#sampling-ratio-otel_sample_ratio) | Float (`f64`) | Optional | `1.0` (100%) | Probabilistic sampling ratio (`0.0` to `1.0`). |

---

### Enable OpenTelemetry (`enable_opentelemetry`)

- **Data Type:** Boolean (`true` or `false`)
- **Requirement:** Optional
- **Default Value:** `false`

#### Detailed Mechanics & System Impact:
- **When `false`:** The OpenTelemetry SDK is not initialized. No OTLP background exporter tasks are spawned, no gRPC channels to collectors are opened, and zero network overhead is incurred.
- **When `true`:** Initializes `opentelemetry_sdk::trace::SdkTracerProvider` with a batch exporter and registers the global `TextMapPropagator` (`TraceContextPropagator`) to inject and extract W3C `traceparent` headers across incoming and outgoing reverse-proxy requests.
- **Resilience:** If the telemetry collector is unreachable at startup, Tonic attempts reconnections in the background without crashing the gateway.

---

### Jaeger / OTLP Endpoint (`jaeger_endpoint`)

- **Data Type:** String (URL with scheme, host, and port)
- **Requirement:** Optional
- **Default Value:** `"http://localhost:4317"`

#### Detailed Mechanics & System Impact:
- **Protocol:** Uses OTLP over **gRPC** (standard port `4317`), compatible with Jaeger v1.35+, OpenTelemetry Collector, Grafana Tempo, and Datadog Agent.
- **Note on HTTP vs gRPC:** Do not specify port `4318` (which is standard OTLP HTTP/protobuf), as Praeco uses Tonic gRPC transport.
- **Batching:** Spans are buffered in memory and flushed in batches asynchronously to minimize network round-trips.

---

### Telemetry Log Level (`otel_log_level`)

- **Data Type:** String (`"trace"`, `"debug"`, `"info"`, `"warn"`, `"error"`)
- **Requirement:** Optional
- **Default Value:** `"info"`

#### Detailed Mechanics & System Impact:
- **Dedicated Filtering:** Operates independently of the console logger. You can set stdout to `"debug"` while restricting exported telemetry spans to `"info"` or `"warn"`, saving telemetry storage and network bandwidth.

---

### Sampling Ratio (`otel_sample_ratio`)

- **Data Type:** Float (`f64`) between `0.0` and `1.0`
- **Requirement:** Optional
- **Default Value:** `1.0` (100% sampling / `AlwaysOn`)

#### Detailed Mechanics & System Impact:
- **Under the Hood:**
  - If set to `1.0`, uses `opentelemetry_sdk::trace::Sampler::AlwaysOn`.
  - If set to `< 1.0`, uses `opentelemetry_sdk::trace::Sampler::ParentBased(Box::new(TraceIdRatioBased(ratio)))`.
- **Parent-Based Behavior:** If an incoming HTTP request arrives with a W3C `traceparent` header that was already sampled upstream (e.g. by an API client or external gateway), Praeco **always** records and exports the span, ensuring complete end-to-end distributed traces.
- **Probabilistic Roots:** For un-traced incoming requests, the span is sampled probabilistically according to `otel_sample_ratio` (e.g. `0.1` samples 10% of requests).

```toml
# Production Telemetry Configuration
enable_opentelemetry = true
jaeger_endpoint = "http://jaeger-collector.monitoring:4317"
otel_log_level = "info"
otel_sample_ratio = 0.25 # Sample 25% of new root traces
```

---

## Server Instances (`[[Server]]`)

Multiple `[[Server]]` blocks can be declared to run distinct listeners (or tunnels) side-by-side.

### Instance Identification & Lifecycle

| Parameter | Data Type | Requirement | Default Value | Description & Runtime Behavior |
| :--- | :--- | :--- | :--- | :--- |
| `name` | String | **Mandatory** | *None* | Unique name identifier. Leaked into `'static str` during initialization to allow zero-copy reference passing in middleware logs and metrics. Matches against TLS certificate resolvers. |
| `enabled` | Boolean | Optional | `true` | When `false`, the server instance is completely ignored. No listener socket is bound, no tunnel is opened, and no memory structures are allocated. |

---

### Network Binding & Dual Protocol

| Parameter | Data Type | Requirement | Default Value | Description & Runtime Behavior |
| :--- | :--- | :--- | :--- | :--- |
| `protocol` | String | Optional | `"http"` | `"http"` (plaintext HTTP/1.1 or cleartext HTTP/2) or `"https"` (TLS 1.3/1.2). If `"https"`, `[Server.server_certs]` is **mandatory**. |
| `ip` | String | **Conditional** | *None* | IP address to bind. **Mandatory** unless `[Server.tunnel]` is configured. Options: `"0.0.0.0"` (all IPv4), `"::"` (IPv6), `"127.0.0.1"`, or `"local"` (resolves dynamically to host's primary local IP). |
| `port` | Integer (`u16`) | **Conditional** | *None* | TCP listening port (e.g. `443`, `8080`). **Mandatory** unless `[Server.tunnel]` is configured. |

#### HTTP/3 (QUIC) & Dual-Stack Binding:
When `protocol = "https"`, Praeco automatically:
1. Binds a standard non-blocking **TCP socket** on `ip:port` for HTTP/1.1 and HTTP/2.
2. Simultaneously binds a **UDP socket** on the exact same `ip:port` for **HTTP/3 (QUIC)**.
3. Configures ALPN on the TLS stack to advertise `h3`, `h2`, and `http/1.1` in preference order.
4. Enables session resumption (`ServerSessionMemoryCache` with 1024 slots) to reduce TLS handshake overhead.

---

### Authentication Modes (`authentication`)

Controls how clients are verified during the TLS handshake or request lifecycle:

| Value | Handshake & Request Behavior | Use Case |
| :--- | :--- | :--- |
| `"None"` | Public access. No client certificate is requested during TLS. No JWT verification is performed unless explicitly added to `[Server.Layers]`. | Public APIs, static file downloads, health-check endpoints. |
| `"ClientCert"` or `"mTLS"` | **Strict mutual TLS.** During the TLS handshake, Praeco's `WebPkiClientVerifier` demands a client certificate signed by a CA in `[[Server.client_certs]]`. If missing, expired, or revoked by a CRL, the connection is aborted with a TLS fatal alert before any HTTP data is exchanged. | Zero-Trust microservice communication, enterprise device backends. |
| `"OptionalClientCert"` | **Permissive mutual TLS.** The server requests a client certificate during the TLS handshake (`allow_unauthenticated()`), but allows the connection to proceed if omitted. | **Identity Provider (IdP):** Allows browsers without client certs to load the HTML login page, while allowing mobile scanners to authenticate with device certs. |
| `"JWT"` | Inbound HTTP requests must contain a valid JWT in `Authorization: Bearer <token>` or in a configured cookie fallback. Validates signature, `iss`, and `aud`. | Web application dashboards, mobile APIs. |

---

### Base Service Selection (`service`)

Determines what handles the request once it passes all middleware layers:

| Value | Base Service Description | Required Sibling Section |
| :--- | :--- | :--- |
| `"Echo"` | Reflects request method, URI, headers, and body back to client for load testing and latency measurement. | *None* |
| `"StaticFiles"` | High-performance static asset server with SPA client-side routing fallback. | `[Server.StaticFilesParams]` |
| `"Idp"` | Built-in Identity Provider issuing Ed25519-signed JWTs via QR-code or mTLS. | `[Server.IdpParams]` |
| `"Router"` | Reverse proxy with upstream connection pooling, load balancing, health checks, and gRPC transcoding. | `[Server.ReverseRoutes]` |

---

### Outbound Zero-Trust Tunneling (`[Server.tunnel]`)

Enables Praeco instances located in private subnets, behind NATs, or inside edge devices to serve public traffic without opening inbound firewall ports.

| Parameter | Data Type | Requirement | Default Value | Description & Runtime Impact |
| :--- | :--- | :--- | :--- | :--- |
| `target_url` | String | **Mandatory** | *None* | Control-plane address of Relay Server (e.g. `"tls://relay.example.com:7001"`). |
| `sni_domain` | String | **Mandatory** | *None* | Public SNI domain registered with Relay (e.g. `"api.example.com"`). Relay verifies that this SNI matches a SAN/CN in the gateway's certificate. |
| `client_cert_path` | String | **Mandatory** | *None* | Path to PEM client certificate for mTLS against Relay. |
| `client_key_path` | String | **Mandatory** | *None* | Path to unencrypted PEM private key. |
| `ca_cert_path` | String | **Mandatory** | *None* | Path to PEM CA certificate that signed Relay's server certificate. |
| `max_yamux_streams` | Integer | Optional | `4096` | Maximum concurrent multiplexed client streams over the tunnel connection. (Replaces Yamux default of 512). |
| `proxy_protocol` | Boolean | Optional | `true` | Negotiates HAProxy PROXY-Protocol v2. Operates **strictly fail-closed**: if enabled, any stream lacking a valid 16-byte PROXY-v2 header signature is immediately aborted. Extracts real client IP before TLS handshake for rate limiting and logging. |

```toml
[Server.tunnel]
target_url = "tls://relay.example.com:7001"
sni_domain = "api.example.com"
client_cert_path = "certs/praeco_tunnel.pem"
client_key_path = "certs/praeco_tunnel.key"
ca_cert_path = "certs/relay_ca.pem"
max_yamux_streams = 4096
proxy_protocol = true
```

---

### Connection Limits & Protocol Defense (`[Server.connection_limits]`)

Defines layer-4 and layer-7 connection boundaries to prevent connection starvation and Slowloris attacks.

| Parameter | Data Type | Requirement | Default Value | Description & Runtime Impact |
| :--- | :--- | :--- | :--- | :--- |
| `max_connections` | Integer | Optional | `10000` | Global connection cap for this server instance. Must be `> 0`. Excess connections are closed immediately. |
| `max_connections_per_ip` | Integer | Optional | `100` | Maximum simultaneous active connections from a single IP or IPv6 `/64` subnet. Must be `> 0`. |

#### Canonical Client IP Mechanics (`canonical_client_ip`):
- **IPv4-Mapped IPv6:** Addresses like `::ffff:192.0.2.1` are automatically unwrapped to `192.0.2.1`.
- **IPv6 Subnet Masking (`/64`):** An attacker with an IPv6 allocation can rotate interface identifiers (the lower 64 bits) across billions of IP addresses. Praeco masks all standard IPv6 addresses with a `/64` bitmask, aggregating all connections from that subnet into a single quota bucket.

---

### Role-Based Access Control & OID Mapping (`[Server.oid_mapping]`)

Maps OID suffix numbers extracted from certificates or JWT claims to internal `UserRole` values:

```toml
[Server.oid_mapping]
"1" = "Admin"
"2" = "Seller"
"3" = "Viewer"
```

- **Per-Server Scope:** Suffix `"1"` can map to `"Admin"` on an internal server, but to `"Customer"` on an external server.
- **Fallback Role:** If a client presents a valid certificate containing no recognized OIDs, Praeco assigns the internal fallback role **`Guest`**.

---

### TLS & Client Certificate Verification

#### Server TLS Certificates (`[Server.server_certs]`)
**Mandatory** when `protocol = "https"`.

| Parameter | Data Type | Requirement | Default Value | Description |
| :--- | :--- | :--- | :--- | :--- |
| `ssl_certificate` | String | **Mandatory** | *None* | Path to PEM-encoded certificate chain (leaf certificate followed by any intermediate CAs). |
| `ssl_certificate_key` | String | **Mandatory** | *None* | Path to unencrypted PEM private key (PKCS#8, RSA, or SEC1). |

#### Client CA Certificates (`[[Server.client_certs]]`)
**Mandatory** when `authentication = "ClientCert"` or `"OptionalClientCert"`. Multiple blocks can be defined to trust multiple independent CAs.

| Parameter | Data Type | Requirement | Default Value | Description |
| :--- | :--- | :--- | :--- | :--- |
| `ssl_client_ca` | String | **Mandatory** | *None* | Path to PEM-encoded CA certificate used to verify client certificates. |
| `ssl_client_crl` | String | Optional | `None` | Path to PEM-encoded Certificate Revocation List (CRL). Parsed at startup and reload. Praeco validates the X.509 `nextUpdate` timestamp and logs an explicit security warning if the CRL has expired. |

---

### Client Certificate Header Forwarding & Anti-Spoofing (`[Server.client_cert_forwarding]`)

Injects verified client identity attributes into headers forwarded to backend servers.

| Parameter | Data Type | Requirement | Default Value | Description |
| :--- | :--- | :--- | :--- | :--- |
| `header_cert` | String | Optional | `None` | Header name for the full URL-encoded DER client certificate (e.g. `"x-client-cert"`). |
| `header_san` | String | Optional | `None` | Header name for the Subject Alternative Name (SAN) or CN (e.g. `"x-client-san"`). |
| `header_roles` | String | Optional | `None` | Header name for mapped roles as a comma-separated list (e.g. `"x-user-roles"`). |
| `header_client_ip` | String | Optional | `None` | Header name for the verified client IP address (e.g. `"x-client-ip"`). |

> [!IMPORTANT]
> **Anti-Spoofing Guarantee:**
> Praeco unconditionally strips all incoming client-supplied headers matching `x-client-*`, `x-ssl-*`, `x-forwarded-*`, and `x-real-ip`. Upstream headers are authoritatively populated strictly from verified socket state or PROXY-v2 signatures.

---

## Base Services Deep-Dive

### Echo Service (`service = "Echo"`)
Reflects incoming request headers, method, path, and body back to the caller. Requires no sibling configuration blocks. Ideal for baseline throughput and latency benchmarking.

---

### Static File Server & SPA Routing (`service = "StaticFiles"`)

Serves web applications directly from disk with chunked streaming and cache controls. Requires `[Server.StaticFilesParams]`.

| Parameter | Data Type | Requirement | Default Value | Description & Runtime Behavior |
| :--- | :--- | :--- | :--- | :--- |
| `root` | String | **Mandatory** | *None* | Filesystem directory to serve files from (e.g. `"./server/www"`). Validated at startup; logs a warning if directory does not exist yet. |
| `fallback_to_index` | Boolean | Optional | `false` | When `true`, requests for nonexistent files return `index.html` with status `200 OK`. Essential for single-page applications (React, Vue, Angular) relying on client-side routing. |

```toml
[Server.StaticFilesParams]
root = "./server/www"
fallback_to_index = true
```

---

### Identity Provider (`service = "Idp"`)

The built-in IdP issues Ed25519-signed JWTs via device mTLS authentication or visual QR-code login. Requires `[Server.IdpParams]`.

| Parameter | Data Type | Requirement | Default Value | Description & Runtime Behavior |
| :--- | :--- | :--- | :--- | :--- |
| `jwt_private_key` | String | **Mandatory** | *None* | Path to PEM-encoded Ed25519 or RSA private key used to sign issued JWTs. Validated at startup. |
| `jwt_public_key` | String | Optional | `None` | Path to PEM-encoded public key. When configured, automatically exposed in RFC 7517 format at `/.well-known/jwks.json` for key rotation. |
| `token_expiry_seconds` | Integer | Optional | `900` (15 mins) | Lifetime of issued JWTs in seconds (`exp` claim). |
| `session_ttl_seconds` | Integer | Optional | `120` (2 mins) | Lifetime of QR-code login sessions. |
| `cookie_name` | String | Optional | `"__Host-jwt"` | Name of auth cookie set upon login. If prefixed with `__Host-`, protocol **must** be `"https"` and `cookie_domain` must be omitted per RFC 6265bis. |
| `cookie_domain` | String | Optional | `None` | Domain scope for cookie sharing across subdomains (e.g. `".example.com"`). Ignored if `cookie_name` starts with `__Host-`. |
| `redirect_after_login` | String | Optional | `"/"` | Default redirect URL after successful browser login if no `?redirect=` parameter was provided. |
| `debug_show_session_id` | Boolean | Optional | `false` | When `true`, displays raw session UUID on web UI for testing. |
| `issuer` | String | Optional | `"praeco-idp"` | Issuer claim (`iss`) written into issued JWTs. |
| `allowed_audiences` | Array of Strings | Optional | `[]` | Allowed audience values (`aud`). If client requests `?aud=...`, it must match an entry here; unlisted audiences return `400 Bad Request`. |
| `claims_webhook_url` | String | Optional | `None` | HTTPS webhook URL for dynamic role resolution. Praeco POSTs to this endpoint during authentication to fetch current roles from a database, overriding certificate OIDs. Response body cap is 64 KB. |
| `claims_webhook_timeout_ms`| Integer | Optional | `3000` (3s) | Network timeout in milliseconds for claims webhook execution. |
| `on_webhook_failure` | String | Optional | `"reject"` | Failure handling: `"reject"` (fail-closed: denies login with 503) or `"fallback_to_cert"` (fail-open: falls back to certificate OIDs). |
| `claims_webhook_client_cert`| String | Optional | `None` | Path to PEM client certificate for mTLS against webhook. |
| `claims_webhook_client_key` | String | Optional | `None` | Path to PEM client private key for webhook mTLS. |
| `claims_webhook_ca_cert` | String | Optional | `None` | Path to PEM CA certificate for verifying webhook server TLS. |

#### IdP Security & Endpoints:
- `GET /auth/login_page`: Serves QR-code login page.
- `GET /auth/session_info?session=<id>`: Retrieves session state.
- `POST /auth/confirm?session=<id>&code=<user_code>`: Confirms session. Strictly requires 6-character visual confirmation code verified in constant time (`constant_time_eq`). Invalided after 3 failed attempts (`MAX_CONFIRM_ATTEMPTS = 3`).
- `POST /auth/revoke?jti=<UUID>`: Revokes token ID in global `JwtRevocationStore` (50,000 entry cap). **Requires valid mTLS client certificate.**

---

### Reverse Proxy Router (`service = "Router"`)

Handles reverse proxying, load balancing, circuit breaking, and gRPC transcoding.

#### Route Definitions (`[Server.ReverseRoutes."/prefix"]`)
Routes are matched using **longest prefix first**. The matched prefix is stripped from the request URI before forwarding to upstream servers.

| Parameter | Data Type | Requirement | Default Value | Description & Runtime Behavior |
| :--- | :--- | :--- | :--- | :--- |
| `upstreams` | Array of Strings | **Mandatory** | *None* | List of target backend URLs (e.g. `["https://10.0.0.1:8080", "https://10.0.0.2:8080"]`). |
| `strategy` | String | Optional | `"RoundRobin"` | Load balancing strategy: `"RoundRobin"`, `"LeastConnections"`, `"Random"`, `"Sticky"` (client IP hash), or `"HighestScore"` (routes to upstream reporting highest score in active health checks). |
| `backend_type` | String | Optional | `"rest"` | Upstream protocol handler: `"rest"`, `"grpc_passthrough"` (transparent HTTP/2 gRPC framing), or `"grpc"` / `"grpc_transcoding"` (JSON-to-Protobuf transcoding via gRPC reflection; 16 MiB response body cap). |
| `allowed_roles` | Array of Strings | Optional | `[]` (Public) | Route-level RBAC. Empty `[]` means unrestricted public access. If roles are listed (e.g. `["Admin", "Seller"]`), caller must hold at least one matching role. |
| `cooldown_seconds` | Integer | Optional | `10` | Seconds a dead upstream is benched after connection failure before being retried in half-open state. |
| `max_retries` | Integer | Optional | `2` | Automatic retries on alternate healthy nodes before returning 502/504 to client. |
| `active_health_check_interval` | Integer | Optional | `0` (Disabled) | Polling interval in seconds. Proactively pings `/health` (REST) or gRPC `health` method. Expected score payload: `{"score": 100}` (REST) or field tag 1 integer (gRPC). Score 0 quarantines node. |

#### Upstream Connection Parameters (`[Server.RouterParams]`)

| Parameter | Data Type | Requirement | Default Value | Description & Runtime Behavior |
| :--- | :--- | :--- | :--- | :--- |
| `protocol` | String | Optional | `"http"` | Upstream transport protocol: `"http"` or `"https"`. |
| `authentication` | String | Optional | `"None"` | Upstream authentication mode: `"None"`, `"ClientCert"` (mTLS to upstream), or `"JWT"`. |
| `ssl_root_certificate` | String | Optional | `None` | Path to custom CA certificate for verifying upstream server certificates. **Strict Custom PKI Isolation:** Trusts *exclusively* this CA, completely isolating upstream traffic from public WebPKI roots. |
| `ssl_client_certificate` | String | Optional | `None` | Path to PEM client certificate for upstream mTLS. |
| `ssl_client_key` | String | Optional | `None` | Path to PEM client private key for upstream mTLS. |
| `jwt` | String | Optional | `None` | Path to a file containing a JWT injected into `Authorization: Bearer <token>` on outbound requests. |
| `connect_timeout_seconds` | Integer | Optional | `5` | TCP and TLS connection establishment deadline in seconds. |
| `request_timeout_seconds` | Integer | Optional | `30` | Upstream response header deadline in seconds (`0` disables). Terminates stalling requests with `504 Gateway Timeout` and marks node dead. |
| `idle_timeout_seconds` | Integer | Optional | `90` | Connection pool idle keepalive timeout in seconds. Sockets idle longer than this duration are evicted. |
| `grpc_reflection_timeout_seconds`| Integer | Optional | `10` | Timeout in seconds for gRPC reflection schema discovery RPCs. |
| `grpc_reflection_ttl_seconds` | Integer | Optional | `600` (10 mins) | Time-to-live for cached Protobuf descriptor pools before refreshing schema. |

---

## gRPC Architecture & Features Deep-Dive

Praeco provides first-class, industrial-grade support for gRPC microservices. It can operate in two distinct modes depending on your architecture: **Pure Pass-Through** or **Dynamic JSON-to-gRPC Transcoding**.

```text
                               ┌────────────────────────────────────────────────────────┐
                               │                     praeco-rs                          │
Native gRPC Client             │                                                        │       gRPC Backend
(iOS / Android / Go / Rust) ───┼─► [HTTP/2 + Protobuf] ────► grpc_passthrough ──────────┼─────► (Tonic / Go / Java)
(speaks HTTP/2 + Protobuf)     │                                                        │       (speaks HTTP/2 + Protobuf)
                               │                                                        │
REST / Web Browser Client      │                                                        │
(JavaScript / Fetch / cURL) ───┼─► [HTTP/1.1 or H2 + JSON] ─► grpc_transcoding (Web) ───┼─────► (Tonic / Go / Java)
(speaks standard JSON)         │                                (Dynamic Schema Fetch   │       (speaks HTTP/2 + Protobuf)
                               │                                 via Server Reflection) │
                               └────────────────────────────────────────────────────────┘
```

---

### Mode Comparison: Passthrough vs. Transcoding

| Feature / Behavior | Native Passthrough (`"grpc_passthrough"`) | Dynamic Transcoding (`"grpc"` / `"grpc_transcoding"`) |
| :--- | :--- | :--- |
| **Inbound Protocol** | HTTP/2 with binary Protobuf payloads (`application/grpc`) | Standard HTTP/1.1, HTTP/2, or HTTP/3 with JSON payloads (`application/json`) |
| **Outbound Protocol** | Forced HTTP/2 with binary Protobuf (`application/grpc`) | Forced HTTP/2 with binary Protobuf (`application/grpc`) |
| **Target Client** | Real gRPC client SDKs, mobile apps, backend microservices | Web browsers, Single Page Apps (SPAs), cURL, third-party REST consumers |
| **Schema Requirement** | **None.** Operates at wire speed without inspecting message fields. | **Automatic Reflection.** Fetches protobuf definitions at runtime via gRPC Reflection v1. |
| **Recompilation on Schema Change**| **Never.** Fully schema-agnostic. | **Never.** Automatically re-syncs schema based on `grpc_reflection_ttl_seconds`. |
| **Streaming Support** | **Full:** Unary, Client-Streaming, Server-Streaming, Bidirectional | **Unary:** Request-Response (buffers request body and responses up to 16 MiB). |
| **CPU & Memory Overhead** | **Zero-Copy / Wire-Speed.** Passes raw HTTP/2 frames directly. | **Minimal.** Performs dynamic JSON-to-Protobuf serialization via `prost-reflect`. |
| **HTTP/2 Trailers (`grpc-status`)** | Preserved end-to-end to the client in trailing HEADERS frames. | Translated into HTTP status codes and JSON error responses. |

---

### Native gRPC Passthrough (`backend_type = "grpc_passthrough"`)

Configured when you want Praeco to act as an edge reverse proxy and load balancer for native gRPC traffic while applying mTLS client certificate validation, OID-based RBAC, rate limiting, and connection limits.

#### 1. Wire-Level Framing & Hop-by-Hop Header Sanitization
- Praeco forces the outbound connection version to **HTTP/2** (`hyper::Version::HTTP_2`).
- Hyper's strict HTTP/2 client rejects standard HTTP/1.1 hop-by-hop headers. Praeco automatically strips:
  - `Connection`
  - `Transfer-Encoding`
  - `Upgrade`
  - `TE`
- **Crucial gRPC Exception:** In HTTP/2, the `TE` header is strictly forbidden *except* for the exact value `"trailers"`. Praeco authoritatively injects `TE: trailers` into the outgoing request:
  ```rust
  current_headers.remove(hyper::header::TE);
  current_headers.insert(hyper::header::TE, hyper::header::HeaderValue::from_static("trailers"));
  ```
  This guarantees that backend gRPC servers transmit status codes and metadata in trailing HTTP/2 HEADERS frames instead of dropping them.

#### 2. Streaming Integrity & Retry Semantics
- **Non-Streaming Calls:** If an upstream node fails or times out before transmitting headers, Praeco automatically retries alternate healthy nodes up to `max_retries`.
- **Streaming Calls (Client / Server / Bidi):** Streaming bodies (`RequestBody::Stream`) cannot be rewound once frames have been dispatched across the wire. If a stream fails midway, Praeco detects the consumed stream state and **aborts immediately** rather than attempting retries on a second node (which would send corrupted, partial payloads to the backend).

#### 3. Client Fault Isolation (Zero Upstream Penalization)
When proxying gRPC streams, failures can originate either from the backend or the client. Praeco isolates client errors:
- If a client exceeds `max_bytes` during a streaming upload, Praeco cleanly returns `413 Payload Too Large`.
- If a client abruptly terminates its TCP socket, Praeco terminates the upstream stream.
- **Circuit Breaker Protection:** The backend upstream node is **not** penalized, marked dead, or removed from the load balancer pool when the client is at fault. Upstream nodes are quarantined *only* when the backend itself drops connection or exceeds `request_timeout_seconds`.

```toml
# Example Native gRPC Passthrough Route
[Server.ReverseRoutes."/chat.ChatService"]
upstreams = ["https://10.0.0.1:50051", "https://10.0.0.2:50051"]
strategy = "LeastConnections"
backend_type = "grpc_passthrough"
allowed_roles = ["Admin", "Customer"]
cooldown_seconds = 10
max_retries = 2
active_health_check_interval = 30
```

---

### Dynamic JSON-to-gRPC Transcoding (`backend_type = "grpc"`)

Enables web browsers, frontend applications, and standard HTTP clients to communicate directly with backend gRPC microservices without compiling `.proto` files into client-side code and without requiring Envoy or grpc-web proxies.

#### The Transcoding Request Lifecycle

```text
Client (Browser)                      Praeco Router                      Backend (gRPC/Tonic)
       │                                    │                                      │
       │── POST /chat.ChatService/Send ────►│                                      │
       │   Body: {"room_id":1, "msg":"hi"}  │                                      │
       │                                    │── [Step 1: Check Schema Cache] ─────►│ (If expired, queries
       │                                    │◄─ [gRPC Reflection v1 Schema] ───────│  ListServices/FileDesc)
       │                                    │                                      │
       │                                    │── [Step 2: Validate JSON types]      │
       │                                    │── [Step 3: Encode Protobuf Bytes]    │
       │                                    │── [Step 4: Prepend 5-byte Frame]     │
       │                                    │                                      │
       │                                    │── HTTP/2 POST /chat.ChatService/Send►│
       │                                    │   content-type: application/grpc     │
       │                                    │   [0x00][4-byte len][protobuf_bytes] │
       │                                    │                                      │
       │                                    │◄── HTTP/2 200 OK (gRPC Stream) ──────│
       │                                    │    [0x00][4-byte len][res_protobuf]  │
       │                                    │    trailers: grpc-status: 0          │
       │                                    │                                      │
       │                                    │── [Step 5: Enforce 16 MB Cap]        │
       │                                    │── [Step 6: Decode Protobuf to JSON]  │
       │                                    │                                      │
       │◄─ HTTP 200 OK (application/json) ──│                                      │
       │   Body: {"success":true}           │                                      │
```

1. **Path Routing:** Client sends `POST /<package>.<Service>/<Method>` with a standard JSON body.
2. **Dynamic In-Memory Validation:** Praeco resolves the method in its `DescriptorPool`. It parses the client's JSON against the input message schema using `prost-reflect`. If a required field is missing or has the wrong type, Praeco rejects the call immediately with `400 Bad Request` and a descriptive JSON error, saving backend compute resources.
3. **Protobuf Encoding & 5-Byte Framing:** Praeco encodes the validated dynamic message into raw Protobuf bytes and wraps it in a standard 5-byte gRPC frame:
   - **Byte 0:** Compression flag (`0` = uncompressed, `1` = compressed).
   - **Bytes 1–4:** Big-endian 32-bit unsigned integer representing the exact payload byte length (`u32::to_be_bytes`).
4. **Header Injection:** Dispatches an HTTP/2 request with `content-type: application/grpc`, `te: trailers`, and propagated W3C `traceparent` headers.
5. **Response Translation & 16 MiB Protection:**
   - Praeco bounds response body collection to **16 MiB** (`http_body_util::Limited::new(res.body_mut(), 16 * 1024 * 1024)`). This prevents malfunctioning or malicious upstream services from causing out-of-memory (OOM) crashes in the gateway.
   - Extracts the 5-byte gRPC frame, decodes the Protobuf response payload using `DynamicMessage::merge`, serializes it into a JSON string, and responds to the client with `200 OK` and `content-type: application/json`.

```toml
# Example Dynamic JSON-to-gRPC Route
[Server.ReverseRoutes."/chat.ChatService"]
upstreams = ["https://10.0.0.1:50051"]
strategy = "RoundRobin"
backend_type = "grpc" # Enables dynamic transcoding
allowed_roles = ["Admin", "Seller"]
```

---

### gRPC Server Reflection & Schema Caching

When `backend_type = "grpc"` or when active health checking is enabled for gRPC, Praeco connects to the backend's gRPC Server Reflection service (v1 and v1alpha) to download the Protobuf schema.

#### Configuration Parameters in `[Server.RouterParams]`

| Parameter | Data Type | Requirement | Default Value | Description & Runtime Behavior |
| :--- | :--- | :--- | :--- | :--- |
| `grpc_reflection_ttl_seconds` | Integer | Optional | `600` (10 mins) | Time-to-live for the cached in-memory `DescriptorPool`. When expired, the next incoming request lazily triggers a refresh from the upstream backend. |
| `grpc_reflection_timeout_seconds` | Integer | Optional | `10` | Overall network timeout in seconds for executing the gRPC reflection discovery RPCs (`ListServices` and `FileContainingSymbol`). |

#### Concurrency & High-Availability Protections:
1. **Single-Flight Synchronization (`grpc_reflection_lock`):**
   When a cached schema expires, hundreds of concurrent client requests might arrive simultaneously. Rather than triggering hundreds of parallel reflection queries against the backend (a thundering herd), Praeco acquires a single-flight asynchronous mutex (`grpc_reflection_lock.lock()`). Exactly **one** task executes the network discovery; all other tasks await the result and then immediately read the refreshed schema from memory.
2. **Lock-Free Read Fast-Path:**
   During ordinary operation, schema reads occur under a shared `RwLock::read` without holding any write locks, enabling thousands of requests per second with zero lock contention.
3. **Stale-While-Revalidate Fallback:**
   If a backend service is temporarily restarting or unreachable when the TTL expires, Praeco catches the reflection network error and **falls back to the existing stale schema**, logging a warning while continuing to serve client requests uninterrupted.
4. **Custom PKI & mTLS Support:**
   Reflection channels fully inherit the TLS configuration from `[Server.RouterParams]`. If your backend requires mutual TLS (`ssl_client_certificate` / `ssl_client_key`) and a private root CA (`ssl_root_certificate`), the reflection client connects using those exact certificates.

---

### Active Health Checking & Score Metrics for gRPC

When `active_health_check_interval > 0` is configured on a route whose `backend_type` is `"grpc"` or `"grpc_passthrough"`, Praeco launches a dedicated background polling task for each upstream node.

```text
Praeco Background Task                         Backend gRPC Server
        │                                              │
        │── [Step 1: Discover /<Service>/health] ────►│ (Via Server Reflection)
        │                                              │
        │── POST /<Service>/health ───────────────────►│
        │   Payload: [0x00, 0x00, 0x00, 0x00, 0x00]    │ (Empty gRPC Message Frame)
        │                                              │
        │◄── 200 OK + Health Score Message ────────────│
        │    Protobuf: Tag 1 Varint = 85               │
        │                                              │
        │── [Score > 0: Mark Alive, Score = 85]        │
```

#### 1. Automatic Endpoint Discovery
- Praeco inspects the loaded Protobuf schema for any service exposing an RPC method named **`health`** (e.g. `/system.HealthService/health` or `/chat.ChatService/health`).
- Once discovered, Praeco remembers the fully qualified path (`/<package>.<Service>/health`).

#### 2. Ping Framing
Every interval (e.g. every 15 seconds), Praeco sends an HTTP/2 request with an empty gRPC frame:
```text
[0x00, 0x00, 0x00, 0x00, 0x00] (1 byte uncompressed + 4 bytes zero length)
```

#### 3. Health Score Decoding (Varint Wire Format)
The backend service must return a Protobuf message whose **first field (Field Tag 1)** is an integer representing its health score:
```protobuf
message HealthResponse {
  uint32 score = 1; // 0 = unhealthy, 1..100 = healthy
}
```
- Praeco bounds the response body collection to 64 KB and decodes the Protobuf varint tag (`0x08`).
- **Score Semantics:**
  - `score == 0`: Node is immediately marked dead (`is_alive = false`) and removed from the load balancer rotation.
  - `score > 0`: Node is marked alive (`is_alive = true`) and its atomic score is updated (`current_score.store(score)`).
- **Load Balancing Integration (`strategy = "HighestScore"`):**
  If your route uses `strategy = "HighestScore"`, Praeco forwards incoming client requests to the node reporting the highest health score (e.g. reporting available CPU or lowest latency).

---

### HTTP/2 Upstream Connection Pool & Keep-Alive Mechanics

To handle massive concurrency with low latency, Praeco maintains persistent HTTP/2 connection pools for gRPC upstreams via `common::client::build_hyper_client`.

#### Hardcoded Performance & Resilience Defaults:
- **`http2_only = true`:** Eliminates HTTP/1.1 negotiation roundtrips. The client establishes direct HTTP/2 framing immediately.
- **`http2_adaptive_window = true`:** Dynamically adjusts HTTP/2 stream and connection flow control windows based on throughput and network delay, preventing stream starvation on large file transfers.
- **`http2_keep_alive_while_idle = true`:** Sends HTTP/2 `PING` frames every **30 seconds** with a **10-second acknowledgment timeout** even when no traffic is flowing. Sockets silently killed by stateful firewalls or cloud NAT gateways are pruned immediately rather than failing customer requests.
- **`tcp_nodelay = true`:** Disables Nagle's algorithm on all upstream TCP sockets, ensuring small gRPC frames are transmitted without artificial buffering latency.
- **`tcp_keepalive = 60s`:** Sets OS-level TCP keepalive probes.
- **`pool_max_idle_per_host = 1024`:** Retains up to 1024 idle HTTP/2 multiplexed connections per upstream host.

---

### HTTP/2 Trailers Preservation & Compression Layer Bypass

In HTTP/2 and gRPC, status codes are not transmitted in the HTTP status line; they are transmitted in trailing HEADERS frames (`grpc-status` and `grpc-message`).

> [!WARNING]
> **Why Compression Middleware Must Skip gRPC:**
> If a standard HTTP compression layer (e.g. Gzip or Brotli) compresses a streaming gRPC response body, it buffers or wraps the stream, which strips or breaks HTTP/2 trailers.
> 
> **Praeco's Protection:**
> The `Compression` middleware (`SrvCompressionLayer`) automatically inspects the response `Content-Type`. If it starts with `application/grpc`, compression is **unconditionally bypassed**:
> ```rust
> let is_grpc = resp.headers()
>     .get(hyper::header::CONTENT_TYPE)
>     .and_then(|v| v.to_str().ok())
>     .is_some_and(|ct| ct.starts_with("application/grpc"));
> 
> if already_encoded || is_grpc {
>     // Skip compression to preserve trailing HTTP/2 HEADERS frames!
> }
> ```
> This guarantees that all gRPC clients correctly receive `grpc-status: 0` (OK) or specific error codes.

---

### gRPC Error Propagation & Gateway Status Codes

When errors occur during gRPC proxying, Praeco maps them consistently to standard HTTP status codes:

| Scenario | Gateway Response Status | Trigger & System Behavior |
| :--- | :--- | :--- |
| **Invalid Method / Path** | `400 Bad Request` | Request path does not conform to `/<package>.<Service>/<Method>` or HTTP method is not `POST`. |
| **Malformed JSON (Transcoding)** | `400 Bad Request` | Request JSON body fails dynamic Protobuf schema deserialization. Descriptive JSON error returned. |
| **Service Not Found in Schema** | `404 Not Found` | Requested service is not registered in backend's reflection schema. |
| **Method Not Found in Schema** | `404 Not Found` | Requested method does not exist on the targeted service. |
| **Payload Limit Exceeded** | `413 Payload Too Large` | Client payload exceeds `max_bytes` in `[Server.Layers.MaxPayload]`. Upstream node remains healthy. |
| **Backend Unreachable** | `502 Bad Gateway` | TCP connection refused or backend closed connection before sending headers. Retries alternative nodes if configured. |
| **Backend Timeout** | `504 Gateway Timeout` | Upstream backend accepted connection but failed to respond within `request_timeout_seconds`. |
| **Upstream Response > 16 MB** | `502 Bad Gateway` | Transcoding response body exceeds the 16 MiB safety limit. Prevents memory exhaustion. |

---

## Granular Path-Level RBAC (`[Server.rbac]`)

Enforces method- and path-level privilege separation within the same route prefix:

```toml
[Server.rbac]
# Exact match (O(1) lookup)
"/chat.ChatService/AdminDeleteUser"   = ["Admin"]

# Wildcard prefix match (ends with '*')
"/chat.ChatService/Admin*"            = ["Admin"]

# Exact match overrides prefix match
"/chat.ChatService/AdminGetProducts"  = ["Admin", "Seller"]

# Explicit Deny-All (fail-closed: empty role list denies all callers)
"/chat.ChatService/InternalSecret"    = []

# Public override (wildcard '*' permits all callers)
"/chat.ChatService/PublicPing"        = ["*"]
```

### Precedence:
1. **Exact Path Match:** If request path matches an exact key, enforced immediately.
2. **Longest Prefix Wildcard Match:** Evaluates keys ending with `*` in descending order of prefix length.
3. **Empty Role List (`[]`) = Fail-Closed:** Access is unconditionally denied with `403 Forbidden`.
4. **Fallback to Route `allowed_roles`:** If no rule in `[Server.rbac]` matches, falls back to the enclosing route's `allowed_roles`.

---

## Lightweight WAF / Inspection Layer (`[Server.AllowedPathes]`)

When `"Inspection"` is active, acts as a zero-allocation WAF allow-list. Unmatched requests are rejected with `403 Forbidden`.

Partitions by HTTP method: `GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `HEAD`.

```toml
[Server.AllowedPathes.GET]
# Exact match
"/" = ["^/?$", "^/\\?name=.*$"]

# Prefix wildcard match
"/assets/*" = ["^/assets/[a-zA-Z0-9_.-]+\\.(js|css|png|svg)$"]

[Server.AllowedPathes.POST]
# Allows specific gRPC calls
"/chat.ChatService/SendMessage" = ["^/chat\\.ChatService/SendMessage$"]

# Prefix wildcard allowing all methods under ChatService
"/chat.ChatService/*" = ["^/chat\\.ChatService/[a-zA-Z0-9]+$"]
```

- **Recombined Matching:** Recombines base path and query string (`path?query`) before testing regexes.
- **HEAD & OPTIONS:** Requests with method `HEAD` automatically test against `HEAD` rules, falling back to `GET` rules. `OPTIONS` evaluates across all method tables.

---

## Middleware Layer Pipeline (`[Server.Layers]`)

### Ordering Constraints & Execution Model
1. **`TraceId` Must Be First:** If present, `"TraceId"` must be the first entry in `enabled` (index 0).
2. **`Inspection` After `Decompression`:** If both are enabled, `"Inspection"` must appear after `"Decompression"`. Otherwise, the WAF inspects compressed bytes.
3. **Automatic `SecurityHeaders` Injection:** If omitted from `enabled`, Praeco automatically injects `SecurityHeaders` near the top of the stack so that all early rejection responses (401, 403, 429, 503) carry security headers.

---

### Detailed Layer Reference

#### `[Server.Layers.MaxPayload]`
| Parameter | Data Type | Requirement | Default Value | Description |
| :--- | :--- | :--- | :--- | :--- |
| `max_bytes` | Integer | **Mandatory** | *None* | Maximum allowed request payload in bytes. Rejects requests with `413 Payload Too Large`. Upstream nodes are **never** quarantined for client payload errors. |

#### `[Server.Layers.Decompression]`
| Parameter | Data Type | Requirement | Default Value | Description |
| :--- | :--- | :--- | :--- | :--- |
| `max_decompressed_bytes` | Integer | **Mandatory** | *None* | Maximum decompressed request body size in bytes. Prevents decompression bomb attacks from exhausting memory. |

#### `[Server.Layers.Delay]`
| Parameter | Data Type | Requirement | Default Value | Description |
| :--- | :--- | :--- | :--- | :--- |
| `delay_micros` | Integer | **Mandatory** | *None* | Microseconds of artificial delay injected before processing each request. |

#### `[Server.Layers.ConcurrencyLimit]`
| Parameter | Data Type | Requirement | Default Value | Description |
| :--- | :--- | :--- | :--- | :--- |
| `max_concurrent_requests` | Integer | **Mandatory** | *None* | Maximum concurrent in-flight requests. Must be `> 0`. Permits are retained across the entire duration of streaming response bodies. |
| `load_shed` | Boolean | Optional | `true` | When `true`, requests arriving at capacity immediately fail fast with `503 Service Unavailable` and `Retry-After: 1`. |
| `queue_timeout_ms` | Integer | Optional | `None` | If `load_shed = false`, maximum milliseconds to wait in queue before failing with 503. |

#### `[Server.Layers.Cors]`
| Parameter | Data Type | Requirement | Default Value | Description |
| :--- | :--- | :--- | :--- | :--- |
| `allowed_origins` | Array of Strings | Optional | `[]` | Allowed origins (e.g. `["https://app.example.com"]`) or `["*"]`. **Security Constraint:** Cannot combine wildcard `["*"]` with `allow_credentials = true`. |
| `allowed_methods` | Array of Strings | Optional | `[]` | Allowed HTTP methods (e.g. `["GET", "POST", "OPTIONS"]`). |
| `allowed_headers` | Array of Strings | Optional | `[]` | Allowed request headers. |
| `allow_credentials` | Boolean | Optional | `false` | Whether credentials (cookies, auth headers) are exposed to cross-origin callers. |

#### `[Server.Layers.SecurityHeaders]`
| Parameter | Data Type | Requirement | Default Value | Description |
| :--- | :--- | :--- | :--- | :--- |
| `content_security_policy` | String | Optional | `"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:"` | CSP header. For APIs, use `"default-src 'none'"`. |
| `strict_transport_security` | String | Optional | `"max-age=63072000; includeSubDomains; preload"` | HSTS header enforcing HTTPS for 2 years. |
| `x_content_type_options` | String | Optional | `"nosniff"` | Disables MIME sniffing. |
| `x_frame_options` | String | Optional | `"DENY"` | Clickjacking protection: `"DENY"` or `"SAMEORIGIN"`. |
| `referrer_policy` | String | Optional | `"strict-origin-when-cross-origin"` | Referrer policy header. |

#### `[Server.Layers.JWT]`
| Parameter | Data Type | Requirement | Default Value | Description |
| :--- | :--- | :--- | :--- | :--- |
| `jwt_public_keys` | Array of Strings | **Mandatory** | *None* | File paths to PEM-encoded Ed25519 or RSA public keys used to verify token signatures. |
| `expected_issuer` | String | **Mandatory** | *None* | Expected `iss` claim. |
| `expected_audience` | String | **Mandatory** | *None* | Expected `aud` claim. |
| `cookie_fallback` | String | Optional | `None` | Cookie name to extract JWT if `Authorization` header is missing. |
| `redirect_on_failure` | String | Optional | `None` | Target URL (HTTP 302/307) to redirect unauthenticated browser requests. |
| `revoke_on_paths` | Array of Strings | Optional | `[]` | Request paths (e.g. `["/api/Logout"]`) on which a validated JWT's `jti` is automatically added to the global `JwtRevocationStore`. |

#### `[Server.Layers.RateLimiter]` (Simple Fixed-Window)
| Parameter | Data Type | Requirement | Default Value | Description |
| :--- | :--- | :--- | :--- | :--- |
| `requests_per_second` | Integer | **Mandatory** | *None* | Maximum requests allowed per 1-second window. Must be `> 0`. |
| `key_by` | String | Optional | `"identity"` | Partitioning strategy: `"identity"`, `"ip"`, or `"global"`. |
| `max_entries` | Integer | Optional | `10000` | Maximum client keys tracked in memory. When full, unknown keys fail closed (`429 Too Many Requests`). |
| `ttl_seconds` | Integer | Optional | `300` | Inactive key TTL in seconds before pruning. |
| `trust_forwarded_headers` | Boolean | Optional | `false` | Whether to trust `X-Forwarded-For` / `X-Real-IP` headers for client IP extraction. |

#### `[Server.Layers.TokenBucketRateLimiter]`
| Parameter | Data Type | Requirement | Default Value | Description |
| :--- | :--- | :--- | :--- | :--- |
| `max_capacity` | Integer | **Mandatory** | *None* | Maximum burst capacity. Must be `> 0`. |
| `refill` | Integer | **Mandatory** | *None* | Tokens replenished per interval. Must be `> 0`. |
| `duration_micros` | Integer | **Mandatory** | *None* | Replenishment interval in microseconds. Must be `> 0`. |
| `key_by` | String | Optional | `"identity"` | Partitioning strategy: `"identity"`, `"ip"`, or `"global"`. |
| `max_entries` | Integer | Optional | `10000` | Maximum tracked client buckets in memory before fail-closed protection activates. |
| `ttl_seconds` | Integer | Optional | `300` | Inactive bucket TTL in seconds. |
| `trust_forwarded_headers` | Boolean | Optional | `false` | Whether to trust forwarded headers for client IP extraction. |

---

## Relay Server Configuration (`RelayConfig.toml`)

The Praeco Relay Server operates as a standalone public TCP/SNI edge router.

| Parameter | Data Type | Requirement | Default Value | Description & Runtime Behavior |
| :--- | :--- | :--- | :--- | :--- |
| `control_plane_addr` | String | Optional | `"0.0.0.0:7001"` | Address where Relay listens for incoming mTLS tunnel connections from Praeco instances. |
| `data_plane_addr` | String | Optional | `"0.0.0.0:443"` | Public address where Relay accepts incoming HTTPS internet traffic. |
| `ca_cert_path` | String | Optional | `"server_certs/self_signed/myca.pem"` | Path to PEM CA certificate used to verify connecting Praeco backend instances. |
| `server_cert_path` | String | Optional | `"server_certs/self_signed/fullchain_self.pem"` | Path to Relay's own server TLS certificate for the control-plane listener. |
| `server_key_path` | String | Optional | `"server_certs/self_signed/privkey_self.pem"` | Path to Relay's private key for the control plane. |
| `crl_path` | String | Optional | `None` | Path to Certificate Revocation List (CRL) for revoking compromised backend gateways. Parsed with `nextUpdate` expiration checks. |
| `enable_opentelemetry` | Boolean | Optional | `false` | Enables OpenTelemetry tracing for Relay connection events. |
| `jaeger_endpoint` | String | Optional | `"http://localhost:4317"` | OTLP gRPC endpoint for Relay traces. |
| `otel_log_level` | String | Optional | `"info"` | Log level filter for exported Relay telemetry spans. |
| `otel_sample_ratio` | Float (`f64`) | Optional | `1.0` | Sampling ratio for Relay traces (`0.0` to `1.0`). |
| `rate_limit_connections_per_sec` | Integer | Optional | `50` | Maximum new TCP connections permitted per second per client IP / IPv6 `/64` subnet on the data plane (bounded to 100,000 active buckets). |
| `rate_limit_burst` | Integer | Optional | `100` | Maximum burst of new TCP connections permitted per client IP / IPv6 `/64` subnet. |
| `data_plane_idle_timeout_secs` | Integer | Optional | `1800` (30 mins) | Inactivity timeout in seconds for established data-plane connections (`0` disables). |
| `tcp_keepalive_secs` | Integer | Optional | `60` | TCP keepalive probe interval on data-plane sockets. |
| `max_concurrent_connections` | Integer | Optional | `10000` | Global maximum simultaneous public TCP connections on the data plane. |
| `max_concurrent_connections_per_ip` | Integer | Optional | `100` | Maximum simultaneous public connections allowed from a single IP or IPv6 `/64` subnet. |
| `client_hello_timeout_secs` | Integer | Optional | `10` | Timeout in seconds to read the complete TLS `ClientHello` record (handles TCP fragmentation up to 16 KB). Protects against slowloris SNI probing. |
| `control_plane_handshake_timeout_secs`| Integer | Optional | `10` | Timeout in seconds for mTLS handshake and `REGISTER` command on the control plane. |
| `max_yamux_streams` | Integer | Optional | `4096` | Maximum concurrent multiplexed Yamux streams per tunnel connection. |
| `enable_proxy_protocol` | Boolean | Optional | `true` | When `true`, injects HAProxy PROXY-Protocol v2 headers into tunnel streams, propagating real client IPs to Praeco backend instances. |

---

## Appendix: Cryptographic Keys & Certificates Overview

| Key / Certificate Type | Usage & Purpose | Configuration Parameter | Generation Tool / Source |
| :--- | :--- | :--- | :--- |
| **Server TLS Certificate (Public)** | Authenticates the server to incoming HTTPS clients. Must be fullchain PEM. | `[Server.server_certs.ssl_certificate]` | Production: Let's Encrypt (Certbot).<br>Testing: OpenSSL or `rcgen`. |
| **Server TLS Key (Private)** | Private key for the server certificate. Must be unencrypted PEM. | `[Server.server_certs.ssl_certificate_key]` | Generated with server CSR. |
| **Client CA Certificate (Public)** | Trust anchor used by Praeco to authenticate client mTLS certificates. | `[[Server.client_certs.ssl_client_ca]]`<br>`[Server.RouterParams.ssl_root_certificate]` | Script: `./client_certs/generate_mtls_oid_certs.sh` |
| **Client mTLS Certificate & Key** | Issued to clients (apps, microservices) to authenticate against Praeco. Contains OIDs for RBAC. | Used by client.<br>For Proxy-to-Upstream:<br>`ssl_client_certificate` / `key` | Script:<br>`./client_certs/generate_mtls_oid_certs.sh -c <cn> -o <roles>` |
| **JWT Private Key** | Used by IdP (`service = "Idp"`) to sign issued JWTs. | `[Server.IdpParams.jwt_private_key]` | OpenSSL (Ed25519):<br>`openssl genpkey -algorithm ed25519 -out idp_private.pem` |
| **JWT Public Key** | Used by resource servers (`JwtAuth` layer) to verify token signatures. | `[Server.IdpParams.jwt_public_key]`<br>`[Server.Layers.JWT.jwt_public_keys]` | OpenSSL:<br>`openssl pkey -in idp_private.pem -pubout -out idp_public.pem` |

---

## Complete Production Configuration Examples

### Minimal High-Throughput REST Reverse Proxy (`Config.toml`)

```toml
tokio_threads = 16
pki_base_oid = "1.3.6.1.4.1.65111"
log_dir = "/var/log/praeco" # Logs to stdout AND /var/log/praeco/app.YYYY-MM-DD.log

[[Server]]
name = "api_gateway"
ip = "0.0.0.0"
port = 443
enabled = true
protocol = "https"
authentication = "None"
service = "Router"

[Server.connection_limits]
max_connections = 10000
max_connections_per_ip = 100

[Server.server_certs]
ssl_certificate = "certs/fullchain.pem"
ssl_certificate_key = "certs/privkey.pem"

[Server.Layers]
enabled = [
    "TraceId",
    "Logger",
    "SecurityHeaders",
    "PathSanitizer",
    "MaxPayload",
    "RateLimiter:TokenBucket",
    "ConcurrencyLimit"
]

[Server.Layers.MaxPayload]
max_bytes = 10485760 # 10 MB

[Server.Layers.ConcurrencyLimit]
max_concurrent_requests = 5000
load_shed = true

[Server.Layers.TokenBucketRateLimiter]
max_capacity = 500
refill = 50
duration_micros = 1000000 # 50 req/sec with burst to 500
key_by = "ip"

[Server.ReverseRoutes."/"]
upstreams = ["http://127.0.0.1:8080", "http://127.0.0.1:8081"]
strategy = "LeastConnections"
backend_type = "rest"
cooldown_seconds = 10
max_retries = 2
active_health_check_interval = 15
```

### Zero-Trust Outbound Tunnel with mTLS, Dynamic Claims & gRPC (`conf.d/api.toml`)

```toml
[[Server]]
name = "secure_grpc_gateway"
enabled = true
protocol = "https"
authentication = "ClientCert"
service = "Router"

# Outbound Yamux tunnel to Relay (no inbound open ports)
[Server.tunnel]
target_url = "tls://relay.example.com:7001"
sni_domain = "api.example.com"
client_cert_path = "certs/praeco_tunnel.pem"
client_key_path = "certs/praeco_tunnel.key"
ca_cert_path = "certs/relay_ca.pem"
max_yamux_streams = 4096
proxy_protocol = true

[Server.server_certs]
ssl_certificate = "certs/api_fullchain.pem"
ssl_certificate_key = "certs/api_privkey.pem"

[[Server.client_certs]]
ssl_client_ca = "certs/client_root_ca.pem"
ssl_client_crl = "certs/client_root_ca.crl.pem"

[Server.oid_mapping]
"1" = "Admin"
"2" = "Seller"
"3" = "Viewer"

[Server.client_cert_forwarding]
header_cert = "x-client-cert"
header_san = "x-client-san"
header_roles = "x-user-roles"
header_client_ip = "x-client-ip"

[Server.Layers]
enabled = [
    "TraceId",
    "Logger",
    "SecurityHeaders",
    "PathSanitizer",
    "Decompression",
    "MaxPayload",
    "Inspection",
    "RateLimiter:TokenBucket",
    "ConcurrencyLimit"
]

[Server.Layers.Decompression]
max_decompressed_bytes = 10485760

[Server.Layers.MaxPayload]
max_bytes = 10485760

[Server.Layers.ConcurrencyLimit]
max_concurrent_requests = 10000
load_shed = true

[Server.Layers.TokenBucketRateLimiter]
max_capacity = 1000
refill = 50
duration_micros = 10000
key_by = "identity"

[Server.AllowedPathes.POST]
"/chat.ChatService/*" = ["^/chat\\.ChatService/[a-zA-Z0-9]+$"]

[Server.rbac]
"/chat.ChatService/Admin*" = ["Admin"]
"/chat.ChatService/UpdateRoomProduct" = ["Admin", "Seller"]

[Server.ReverseRoutes."/"]
upstreams = ["https://127.0.0.1:50051"]
strategy = "RoundRobin"
backend_type = "grpc_passthrough"
allowed_roles = ["Admin", "Seller", "Viewer"]
active_health_check_interval = 60

[Server.RouterParams]
protocol = "https"
authentication = "ClientCert"
ssl_root_certificate = "certs/backend_internal_ca.pem"
ssl_client_certificate = "certs/proxy_to_backend.pem"
ssl_client_key = "certs/proxy_to_backend.key"
connect_timeout_seconds = 5
request_timeout_seconds = 30
idle_timeout_seconds = 90
```
