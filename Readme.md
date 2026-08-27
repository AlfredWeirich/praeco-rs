
# praeco-rs - Enterprise Zero-Trust API Gateway: the European sovereign proxy

https://medium.com/@alfred.weirich/tokio-tower-hyper-and-rustls-building-high-performance-and-secure-servers-in-rust-part-11-7782d195ce2a?source=friends_link&sk=00042bfce222ddd16d8cd5f0380f161a

Part 1 to 11

---

`praeco-rs` is an ultra-fast, highly configurable, and secure API Gateway and Reverse Proxy written in Rust. It is built on top of the Tokio async runtime, Hyper v1, Tower, and Rustls.

*(The name **praeco** comes from Latin, meaning "herald" or "crier" — just as a historical herald controlled the flow of information and announced messages to the public, this gateway acts as the sovereign announcer and gatekeeper for your network traffic).*

Designed for zero-trust enterprise environments, it provides deep mTLS integration, declarative middleware pipelines, dynamic JSON-to-gRPC transcoding (acting as a REST-to-gRPC Gateway), and zero-downtime hot-reloading.

---

**Newly Added**: 
* **Built-in Identity Provider (IdP)**: Issues signed JWTs by leveraging the gateway's existing mTLS infrastructure. The IdP securely manages identities and issues tokens containing strict `iss` (Issuer) and `aud` (Audience) claims to prevent confused-deputy attacks across services.
* **Dynamic Claims Webhook**: The IdP can query a backend webhook in real-time during the auth flow to fetch dynamic user roles, allowing role updates without reissuing underlying mTLS certificates.
* **Dynamic Key Discovery (JWKS)**: The IdP exposes a standard `/.well-known/jwks.json` endpoint to serve its public keys dynamically. This enables downstream Resource Servers to fetch and verify JWT signatures automatically, supporting seamless, zero-downtime key rotation.
* **Advanced Role Mapping (RBAC)**: Extracted custom Object Identifiers (OIDs) from mTLS client certificates are mapped to internal roles (`UserRole`), extending the strict access control directly into the JWTs issued by the IdP.
* **Outbound Zero-Trust Tunneling (SNI Relay)**: Enables Praeco instances to run behind strict NATs or firewalls without opening local ports. Instances establish outbound multiplexed mTLS connections (`yamux`) to a standalone Relay Server, which routes incoming internet traffic securely back to the correct instance using SNI (Server Name Indication).

---

## 1. Features

| Feature | `praeco-rs` | Pingora (Cloudflare) | Sōzu |
| :--- | :--- | :--- | :--- |
| **Primary Architecture** | Tokio, Hyper v1, Tower, Rustls | Custom Async Runtime & State Machine | Custom Event Loop (Mio) |
| **HTTP Protocols** | HTTP/1.1, HTTP/2, HTTP/3 (QUIC) | HTTP/1.1, HTTP/2 (H3 in progress) | HTTP/1.1, HTTP/2 |
| **Security & Auth** | Deep mTLS OID-extraction (RBAC), JWT | Pluggable, but requires custom code | Standard TLS, SNI routing |
| **gRPC Support** | **Full (with JSON Transcoding via Reflection)** | Basic Proxying | Basic Proxying |
| **Observability** | Native OpenTelemetry (OTLP) Tracing | Pluggable via Rust code | Pluggable via Rust code |
| **Middleware Model** | Declarative `tower::Service` stack via TOML | Callbacks / Traits on Session | Custom Filters |
| **WAF / Inspection** | Built-in Regex Path/Query Allow-Listing | Pluggable / Scriptable | Custom Filters |
| **Configuration** | Hot-Reloadable (SIGHUP + ArcSwap) | Programmable (in Rust) | Dynamic (Zero-Downtime Hot-Reload) |
| **Load Balancing** | Advanced (RoundRobin, LeastConn, Sticky, Random, HighestScore) | Advanced (Consistent Hash, Least Conn) | Advanced |

---

## 2. Advantages of `praeco-rs`

> [!TIP]
> **Why choose `praeco-rs`?** It shines in highly secure, zero-trust enterprise environments where gRPC interoperability, advanced load distribution, and strict rate control are primary requirements.

- **Declarative Middleware Pipeline**: The entire middleware stack (Timeout, Concurrency Limits, Rate Limiting, Compression, CORS, OTLP Tracing) can be configured, reordered, and toggled on/off in `Config.toml` in seconds, **without writing or recompiling any Rust code**.
- **Native OpenTelemetry (OTLP) Integration**: `praeco-rs` integrates directly with the `tracing` and `opentelemetry` ecosystem, allowing you to export distributed traces directly to Jaeger, Zipkin, or Datadog via standard OTLP right out of the box.
- **Lightweight WAF (Inspection Layer)**: Includes a highly optimized Regex-based inspection middleware that validates the `(method, path, query)` against a configured allow-list. It operates with zero heap allocations on the happy path, dropping malicious requests before they consume downstream resources.
- **Out-of-the-box REST to gRPC Gateway**: Unlike Pingora or Sōzu, `praeco-rs` can dynamically reflect backend gRPC schemas and translate incoming REST/JSON requests into binary Protobuf on the fly (JSON-to-gRPC transcoding). This eliminates the need for separate sidecars like Envoy for transcoding.
- **Bespoke Zero-Trust RBAC via Custom OIDs**: The proxy natively extracts custom Object Identifiers (OIDs) directly from mTLS client certificates (or JWTs) and maps them to internal `UserRole`s (e.g., Admin, Operator). 
  * **Upstream Protection**: This allows you to define route-level permissions (`allowed_roles = ["Admin"]`) in the config. The proxy acts as a strict Policy Enforcement Point (PEP). Malicious or unauthorized requests are rejected at the edge with a 403, **shielding your upstream servers** from ever needing to implement complex certificate parsing or role-validation logic themselves.
  * **Identity Forwarding**: If the upstream server needs to know who the caller is (e.g., for detailed logs or resource-based authorization), the proxy can forward the extracted roles (from the OID), the SAN, or even the entire client certificate as secure HTTP headers (`client_cert_forwarding`) to the upstream.
- **Advanced Upstream Management**: Built-in support for multiple load-balancing strategies (`RoundRobin`, `Random`, `LeastConnections`, `Sticky`, `HighestScore`) combined with **Active Health Checking** ensures traffic is only routed to healthy nodes.
- **Built-in Rate Limiting & Traffic Shaping**: Includes flexible token-bucket/window rate limiting strategies, global concurrency limits, and request timeouts to prevent abuse and cascaded failures, right out of the box.
- **Zero-Downtime Configuration Reloads**: `praeco-rs` listens for `SIGHUP` signals to dynamically reload the `Config.toml` and rebuild its routing tables on the fly using `ArcSwap`, without dropping active connections.
- **End-to-End mTLS Bridging**: In addition to mTLS termination at the gateway, the proxy can establish a completely **new mTLS connection to the upstream servers** (including its own client certificate). This guarantees a fully encrypted and authenticated zero-trust chain deep into the internal backend.
- **Built-in Identity Provider (IdP)**: `praeco-rs` can act as a standalone Identity Provider, issuing its own signed JWTs directly to clients for downstream use. It utilizes its own mTLS capabilities to securely authenticate devices and support advanced authentication flows like QR-code-based cross-device logins.
- **Built-in Static File Server**: Beyond proxying and Identity Provider functions, Praeco can act as a highly performant static file server. It supports SPA-Routing (fallback to `index.html`) out of the box, completely eliminating the need for Nginx when serving React, Vue, or WebAssembly (e.g. Iced) frontends alongside your APIs.
- **HTTP/3 Native**: Full support for HTTP/3 over QUIC out of the box using `quinn` and `h3`, providing better performance on unreliable networks.
- **Outbound Zero-Trust Tunneling (SNI Relay)**: For deployments behind restrictive NATs or firewalls, `praeco-rs` can bypass local port binding entirely. Instead, it establishes an outbound, multiplexed mTLS connection (via Yamux) to a standalone Relay Server. The Relay Server accepts incoming internet traffic (Port 443) and routes it strictly via SNI to the corresponding Praeco instance, achieving complete End-to-End TLS without the Relay Server terminating the client connection.

---

## 3. Disadvantages of `praeco-rs`

> [!WARNING]
> **Where it falls short**: `praeco-rs` is an incredibly feature-rich API Gateway, but differs from edge-tier CDNs in a few specific areas.

- **No Native Caching Layer**: Unlike Pingora, which is designed to replace Nginx as an edge cache, `praeco-rs` acts strictly as an API Gateway and auth bridge. It does not cache HTTP responses.
- **Community & Maturity**: Pingora is backed by Cloudflare processing trillions of requests. `praeco-rs` is currently a bespoke, highly specialized enterprise solution. While its core leverages production-ready crates (`hyper`, `tower`), the proxy itself lacks the widespread community testing of older proxies.

---

## 4. Open Points & Roadmap

To elevate `praeco-rs` even further, the following points remain on the roadmap:

### 1. Distributed Caching
Implementing an HTTP response caching layer (e.g., using Redis) for specific routes to reduce backend load, similar to what Pingora offers out of the box for CDN use-cases.

### 2. Flawless Trace Propagation (Tracing Polish)
OpenTelemetry is already built-in. However, if the proxy translates an incoming JSON/REST request into a gRPC request on-the-fly, it must be absolutely ensured that the unique Request ID (Trace ID) is never lost. This is the only way tools like Jaeger can exactly map an error in the backend to the original REST request of the client. This requires more in-depth testing in complex edge cases.

### 3. Circuit Breaking
Currently, the proxy regularly checks in the background (Health Checks) whether a backend is still alive. If it is dead, no more traffic is sent there.
A **Circuit Breaker** would go one step further: If a backend suddenly becomes extremely slow or throws errors (even though the last health check was still "OK"), the circuit "trips" immediately. The proxy instantly blocks further traffic to this node to prevent a complete traffic jam in the system (Cascading Failure).

### 4. Pluggable End-Services (Beyond Routing)
Currently, `praeco-rs` terminates the middleware pipeline into a `Router` (for proxying), an `Idp` (Identity Provider), a `StaticFiles` service, or an `Echo` service (for testing). Due to the modular `tower::Service` architecture, future roadmap items include adding new native end-services, such as:
- **Redirect Service**: Simple port-to-port or HTTP-to-HTTPS redirects at the edge.
- **Mock / Stub Service**: Returning predefined JSON responses for specific routes, allowing frontend teams to develop against the gateway before backend APIs are finished.
- **Aggregator / Fan-Out Service**: Accepting a single client request and internally fanning it out to multiple backend microservices, assembling their JSON responses into a single cohesive payload before returning it to the client.

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

[Server.Layers]
enabled = ["Logger", "Compression", "ConcurrencyLimit"]

[Server.Layers.ConcurrencyLimit]
max_requests = 1000
```

> **Full Configuration Reference:**
> The proxy offers extensive settings for mTLS, RBAC OIDs, JSON-to-gRPC transcoding, and rate limiting. 
> **See the [Config.md](Config.md) file for a complete documentation of all available parameters.**

### Installation & Running

**Option 1: Install via Cargo (Recommended)**
If you just want to run the proxy, you can install the pre-compiled executable directly from GitHub. Cargo will automatically download the source and compile it in release mode:

```bash
cargo install --git https://github.com/AlfredWeirich/praeco-rs.git
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
./start_server.sh
```

By default, it will look for `Config.toml` in the current working directory. You can instantly reload configuration changes at runtime without dropping connections by sending a `SIGHUP` signal to the process.


### Attachment:
Here is a **FULL example** of a `Config.toml` from a productiove system:

```toml
###############################################################################
# GLOBAL SYSTEM SETTINGS
# These settings affect the overall performance and base identity of the gateway.
###############################################################################

# The number of worker threads for the Tokio async runtime.
# Default: (Available CPU Cores * 2). 
# Manual override is useful for high-performance tuning on dedicated hardware.
tokio_threads = 50

# Enable or disable background OpenTelemetry Tracing (Jaeger)
# If false, TraceLayer is silently skipped and no background export tasks are started.
enable_opentelemetry = true
jaeger_endpoint = "http://localhost:4317"
otel_log_level = "info"

# The Base Object Identifier (OID) used for security validation.
# This acts as the root for interpreting client certificate extensions and JWT claims.
# Private Enterprise Number (PEN)
pki_base_oid = "1.3.6.1.4.1.65111"

# Automatically include all server configurations from the apps.d directory
includes = ["./apps.d/*.toml"]

# Directory path for persistent log files.
# If commented out or omitted, the application will only log to Standard Output (stdout).
log_dir = "log"

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
    enabled = ["Decompression", "MaxPayload", "Logger", "Inspection", "RateLimiter:TokenBucket", "ConcurrencyLimit"]

    [Server.Layers.Decompression]
    max_decompressed_bytes = 10485760  # 10 MB limit

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
   ...
    "/ENDPOINT.ABC_Service/UpdateMemberRole" = ["^/ENDPOINT\\.ABC_Service/UpdateMemberRole$"]
    "/ENDPOINT.ABC_Service/GetOrders" = ["^/ENDPOINT\\.ABC_Service/GetOrders$"]
    "/ENDPOINT.ABC_Service/UpdateOrderStatus" = ["^/ENDPOINT\\.ABC_Service/UpdateOrderStatus$"]

    [Server.ReverseRoutes."/"]
    upstreams = ["https://127.0.0.1:50051"]
    active_health_check_interval = 60
    backend_type = "grpc_passthrough"

    [Server.RouterParams]
    protocol = "https"
    authentication = "ClientCert"
    ssl_client_certificate = "PATH_TO_CERT/proxy-client.pem"
    ssl_client_key = "PATH_TO_CERT/proxy-client.key"
    ssl_root_certificate = "PATH_TO_CERT/ca.pem"

    [Server.Layers.RateLimiter]
    requests_per_second = 500000

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
        enabled = ["Logger",  "Decompression", "MaxPayload", "Inspection", "RateLimiter:TokenBucket", "ConcurrencyLimit"]
    
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
        ...
        "/api/AdminAddMember" = ["^/api/AdminAddMember$"]
        "/api/AdminUpdateProductCreator" = ["^/api/AdminUpdateProductCreator$"]
        "/api/AdminCreateChannel" = ["^/api/AdminCreateChannel$"]
    
    [Server.ReverseRoutes."/"]
        upstreams = ["https://127.0.0.1:50053"]
        backend_type = "grpc_passthrough"
        allowed_roles = ["Admin", "Seller"]
    
    [Server.RouterParams]
        protocol = "https"
        authentication = "ClientCert"
        ssl_client_certificate = "PATH_TO_CERT/proxy-client.pem"
        ssl_client_key = "PATH_TO_CERT/proxy-client.key"
        ssl_root_certificate = "PATH_TO_CERT/ca.pem"
```toml