# Configuration Manual (`Config.toml`)

This manual describes all available parameters of the `Config.toml` and their possible values. The configuration controls the global behavior of the gateway as well as the detailed settings of individual server instances (listeners, routes, middleware).

## Starting with an Alternative Configuration File
 
By default, the server looks for a file named `Config.toml` in the current directory upon startup. However, you can pass an alternative configuration file to the server by specifying the path as the first command-line argument:
 
```bash
# When running the compiled binary
./server /path/to/another_config.toml

# When running via Cargo (during development)
cargo run --bin server -- /path/to/another_config.toml
```

When receiving a `SIGHUP` signal, `praeco-rs` dynamically hot-reloads from the exact configuration file specified at startup. The reload process runs an atomic, crash-safe dry-run: all service stacks and TLS contexts are validated in memory before any live listeners or global state are swapped. If validation fails, the running configuration remains completely untouched.

---

## Global System Settings

These parameters are located at the top level of the file and affect the overall system.

| Parameter | Data Type | Description | Possible Values / Default Value |
| :--- | :--- | :--- | :--- |
| `tokio_threads` | Integer | Sets the number of worker threads for the asynchronous Tokio runtime. Useful for performance tuning on dedicated hardware. | **Default:** `Available CPU cores * 2`<br>**Example:** `50` |
| `pki_base_oid` | String | The base OID (Object Identifier) for security validation. Serves as the root for interpreting certificate extensions (Private Enterprise Number). | **Example:** `"1.3.6.1.4.1.65111"` |
| `log_dir` | String | Directory path for persistent log files. If commented out or omitted, logs are only written to standard output (`stdout`). | **Example:** `"log"` |
| `includes` | Array of Strings | A list of glob patterns pointing to external TOML configuration files. All `[[Server]]` blocks defined in the included files will be merged dynamically at startup. Global settings in included files are ignored. | **Example:** `["./conf.d/*.toml", "/etc/praeco/apps.toml"]` |

---

## Telemetry (`[telemetry]`)

This block controls the OpenTelemetry (OTLP) tracing settings for Jaeger or other tracing backends.

| Parameter | Data Type | Description | Possible Values / Default Value |
| :--- | :--- | :--- | :--- |
| `enable_opentelemetry` | Boolean | Enables or disables the export of spans to an OTLP collector. | `true`, `false` (**Default:** `true`) |
| `jaeger_endpoint` | String | The URL of the OTLP-compatible tracing collector (e.g., Jaeger). | **Default:** `"http://localhost:4317"` |
| `otel_log_level` | String | The log level of the telemetry events sent to the collector. Filters out internal logs. | `"trace"`, `"debug"`, `"info"`, `"warn"`, `"error"` (**Default:** `"info"`) |

Jaeger is started with:
jaeger-1.60.0-darwin-arm64/jaeger-all-in-one --collector.otlp.enabled=true
The results can be viewed at: http://localhost:16686/

### Generating Client Certificates with OIDs
To easily create valid client certificates for testing or production purposes, the project includes the script [`client_certs/generate_mtls_oid_certs.sh`](file:///Users/fredi/Data/Projekte/Rust/260225_Tower_Hyper_Rustls_refactor_client_gprc/client_certs/generate_mtls_oid_certs.sh).

**Using the script**
The script can be conveniently controlled via command line parameters:

* **`-c`**: Common Name (CN) of the certificate (Default: `client.weirich`). Serves for clarity for administrators.
* **`-e`**: E-Mail address (Default: `alfred.weirich@gmail.com`).
* **`-o`**: Comma-separated list of OID suffixes from which the permissions (roles) should be derived (Default: `1`).

**Examples:**
```bash
# Creates a certificate for an Admin (Role 1):
./generate_mtls_oid_certs.sh -c admin.weirich -o 1

# Creates a multi-role certificate (e.g., Operator and Viewer):
./generate_mtls_oid_certs.sh -c dev.weirich -o 2,3

# Creates a certificate WITHOUT ANY roles (Guest access):
./generate_mtls_oid_certs.sh -c guest.weirich -o "none"
```

**How does the assignment work technically?**
1. The script fully automatically reads the `pki_base_oid` from your current `Config.toml` (e.g., `1.3.6.1.4.1.65111`).
2. It generates a local Root CA (`ca.cert.pem`), which you can later configure in the server as a trust anchor (`Server.mtls_client_ca_file`).
3. It dynamically injects the selected OID suffixes into the new certificate. For example, if `-o 1,2` are passed, it injects `...65111.1` and `...65111.2`.
4. The proxy evaluates *only* these OIDs. If a suffix is contained in the certificate (e.g., `1`), the client automatically gets the role specified in the `[oid_mapping]` table (here: `Admin`).
5. **Fallback:** If `-o "none"` is passed, the certificate contains no OIDs. The proxy then automatically downgrades this validly authenticated but role-less client to the **`Guest`** role.
6. In the end, the script outputs a `client.p12` file, which you can directly import into Postman, cURL, or the browser.

---

## Server Instances (`[[Server]]`)

You can define multiple `[[Server]]` blocks to run multiple listeners simultaneously (e.g., one for API, one for Onboarding).

### Network Configuration & Basics

| Parameter | Data Type | Description | Possible Values |
| :--- | :--- | :--- | :--- |
| `name` | String | Unique name of the instance (for logs and metrics). | **Example:** `"first_server"` |
| `ip` | String *(optional with tunnel)* | The IP address to bind to. Mandatory if no `[Server.tunnel]` is defined. | `"0.0.0.0"` (all), `"192.168.x.x"`, `"local"` (automatic local IP) |
| `port` | Integer *(optional with tunnel)* | The TCP port of the listener. Mandatory if no `[Server.tunnel]` is defined. | **Example:** `1336` |
| `enabled` | Boolean | Main switch to turn the server on or off. | `true`, `false` (**Default:** `true`) |
| `protocol` | String | Transport protocol. (If `https`, `[Server.server_certs]` must be configured). | `"http"`, `"https"` (**Default:** `"http"`) |
| `authentication` | String | Authentication method for incoming connections. | `"None"` (Public)<br>`"ClientCert"` or `"mTLS"` (Strict Certificate-based)<br>`"OptionalClientCert"` (Client cert requested but not required, useful for IdP device auth)<br>`"JWT"` (Token-based) |
| `service` | String | The base service that processes the request after the middleware. | `"Echo"` (Returns request)<br>`"Router"` (Reverse proxy)<br>`"Idp"` (Identity Provider for JWT issuance)<br>`"StaticFiles"` (Static File Server for SPAs and assets) |

### Server.oid_mapping
Defines **per server** how the OID suffixes (Object Identifiers) extracted from certificates or JWT tokens are mapped to internal permission roles (Roles).
Since this is now configured at the server level, the same certificate IDs (e.g., "1") can have completely different meanings depending on the server.

**Example:**
```toml
[Server.oid_mapping]
"1" = "Admin"
"2" = "Seller"
"3" = "Viewer"
```
Explanation: If a client certificate has the OID `1.3.6.1.4.1.65111.1` (where `1.3.6.1.4.1.65111` is the `pki_base_oid` from the global config), the user is assigned the role `Admin`. Any string can be used as a role name.

### Certificate Configurations (TLS & mTLS)

#### `[Server.server_certs]` (Required if `protocol = "https"`)
* `ssl_certificate`: String. Path to the public certificate file (PEM or fullchain).
* `ssl_certificate_key`: String. Path to the unencrypted private key file (PEM).

#### `[[Server.client_certs]]` (Required if `authentication = "ClientCert"`)
Array of tables (multiple CAs can be trusted).
* `ssl_client_ca`: String. Path to the CA certificate to verify client certificates.
* `ssl_client_crl`: String (Optional). Path to the Certificate Revocation List. On startup and hot-reload, Praeco parses the X.509 CRL and validates its `nextUpdate` timestamp, logging an explicit security warning if the CRL has expired.

#### `[Server.client_cert_forwarding]` (Optional)
This configuration controls the passing of verified client identities to backend servers.
1. **Global Identity & Forwarding Header Sanitizing (Protection against Spoofing):**
   Unconditionally — across **all** servers, protocols (HTTP/1.1, HTTP/2, HTTP/3), and routes, regardless of whether `client_cert_forwarding` is enabled — Praeco-rs removes all incoming client-supplied identity headers (`x-client-cert`, `x-client-san`, `x-client-roles`, `x-ssl-*`, etc.) as well as all untrusted client forwarding headers (`forwarded`, `x-forwarded-for`, `x-real-ip`, `x-forwarded-host`, `x-forwarded-proto`). Hop-by-hop headers per RFC 7230 §6.1 are removed, `X-Real-IP` and `X-Forwarded-*` (`For`, `Proto`, and `Host` including HTTP/2 & HTTP/3 `:authority` fallback) are authoritatively re-created from the verified socket or PROXY-v2 peer address, and backend `Server` headers are stripped from responses.
2. **Verified Injection:**
   If the client has successfully authenticated via mTLS, this section allows injecting the verified certificate, SAN, roles, or client IP under the specified header names into the request forwarded to the backend.

* `header_cert`: String. HTTP header name for the URL-encoded client certificate.
* `header_san`: String. HTTP header name for the SAN (Subject Alternative Name).
* `header_roles`: String. HTTP header name for the forwarded user roles (e.g., `x-user-roles`).
* `header_client_ip`: String. HTTP header name for the client IP address (e.g., `x-client-ip`).

### Connection Limits (`[Server.connection_limits]`) (Optional)

Protects against connection starvation, Slowloris, and socket exhaustion attacks across TCP, QUIC, and Yamux tunnel listeners. If omitted, secure defaults are applied automatically without requiring any manual configuration entries.

* `max_connections`: Integer (Optional, **Default:** `10000`). Maximum number of simultaneous active client connections across TCP, QUIC, and tunnel listeners for this server instance.
* `max_connections_per_ip`: Integer (Optional, **Default:** `100`). Maximum number of simultaneous active connections permitted from a single client IP or IPv6 `/64` subnet (`canonical_client_ip` unwraps IPv4-mapped IPv6 addresses and masks standard IPv6 addresses to their `/64` prefix so attackers cannot bypass per-IP limits by rotating interface identifiers within a `/64` allocation; unspecified addresses bypass the per-IP check and only count towards the global limit).

```toml
[Server.connection_limits]
max_connections = 10000
max_connections_per_ip = 100
```

> [!NOTE]
> **Hardcoded Protocol Security Defaults (No Configuration Required):**
> To keep configuration files slim while guaranteeing maximum resilience against known protocol-level attacks, low-level transport and protocol limits are enforced internally with secure defaults:
> - **HTTP/2 Rapid Reset Mitigation (CVE-2023-44487):** `max_pending_accept_reset_streams = 20` (capped from hyper's default of 16,384), `max_concurrent_streams = 128` (capped from 1,024).
> - **HTTP/2 Frame & Header Flood Mitigation:** `max_header_list_size = 65536` (64 KB, mitigates HPACK compression bombs), `max_frame_size = 16384` (16 KB standard frame cap).
> - **HTTP/3 & QUIC Transport Hardening:** Stream receive window reduced to 1 MB and connection receive window to 8 MB (preventing unbounded memory exhaustion from oversized defaults); concurrent streams capped at 128; RFC 9000 §8 anti-amplification stateless address validation (`retry`) automatically active for unvalidated UDP peers; and concurrent request stream tasks bounded by a 128-permit semaphore.

### Identity Provider (IdP) Configuration

#### `[Server.IdpParams]` (Required if `service = "Idp"`)
Configures the built-in Identity Provider, which issues JWTs based on mTLS or Device Authentication (QR-Code flow). When using this service, you should typically set `authentication = "OptionalClientCert"`.

* `jwt_private_key`: String. Path to the Ed25519 or RSA private key (PEM format) used to sign the issued JWTs.
* `jwt_public_key`: String. Path to the corresponding public key. Required to expose the `/.well-known/jwks.json` endpoint for dynamic key discovery by APIs.
* `token_expiry_seconds`: Integer. Time to live (TTL) for the issued JWT in seconds.
* `session_ttl_seconds`: Integer. Time to live for the QR-Code login session in seconds (how long the user has to scan the code).
* `cookie_name`: String. The name of the cookie in which the JWT will be stored (e.g., `"__Host-jwt"`). If using a `__Host-` prefixed cookie, the `protocol` MUST be `"https"`.
* `cookie_domain`: String *(optional)*. The domain for which the cookie is valid. Useful for sharing login sessions across subdomains (e.g. `".aweirich.eu"`). If omitted, the cookie is restricted to the exact hostname of the IdP. **Note:** If `cookie_name` starts with `__Host-`, RFC 6265bis mandates that no `Domain` attribute may be set; any configured `cookie_domain` will be safely ignored.
* `redirect_after_login`: String. The URL path to which the user's browser is redirected after successfully obtaining the JWT via the `/auth/status` endpoint (e.g., `"/dashboard"`).
* `issuer`: String. The issuer claim (`iss`) injected into the generated JWTs (default: `"praeco-idp"`).
* `allowed_audiences`: Array of strings. A list of allowed target audiences (`aud`). If a client requests a specific audience via the `?aud=` query parameter, it must match one of the entries in this list. Any unlisted audience request is rejected with `400 Bad Request`.

**Claims Webhook (Dynamic Role Resolution)**
* `claims_webhook_url`: String *(optional)*. The HTTPS endpoint to POST to for dynamic claims resolution. Plain HTTP is strictly forbidden for remote endpoints to prevent credential/role tampering and is only permitted for local loopback (`http://127.0.0.1:...` or `http://localhost:...`). If set, Praeco calls this endpoint during login to fetch the current user roles from the backend database, replacing the OIDs baked into the certificate.
* `claims_webhook_timeout_ms`: Integer. Overall timeout for the webhook HTTP call in milliseconds including connection, headers, and body collection (default: `3000`). Maximum allowed response body size is 64 KB.
* `on_webhook_failure`: String. Behavior if the webhook fails, times out, or returns a non-200 status. Options: `"reject"` (default, fail-closed: denies the login with 503) or `"fallback_to_cert"` (fail-open: fallback to OIDs from the mTLS certificate).
* `claims_webhook_client_cert`: String *(optional)*. Path to client certificate PEM for mTLS authentication against the webhook.
* `claims_webhook_client_key`: String *(optional)*. Path to client private key for mTLS.
* `claims_webhook_ca_cert`: String *(optional)*. Path to CA certificate for verifying the webhook server's certificate.

> [!IMPORTANT]
> **IdP Hardening (Quishing Protection, Webhook Pre-Validation & Revocation):**
> - **Mandatory 6-Character `user_code` Verification:** `POST /auth/confirm?session=<id>&code=<user_code>` strictly requires the 6-character visual confirmation code displayed by the browser (`GET /auth/session_info?session=<id>` allows the mobile scanner to retrieve the code prior to confirmation). Verification is performed in constant time (`constant_time_eq`) **before** invoking any external `claims_webhook_url`, and the session is permanently invalidated after `3` failed attempts (`MAX_CONFIRM_ATTEMPTS = 3`).
> - **mTLS-Protected Explicit JTI Revocation:** Calling `POST /auth/revoke?jti=<UUID>` to revoke an arbitrary token ID requires a valid mTLS client certificate (`401 Unauthorized` without mTLS), whereas standard browser logout via cookie or `Authorization: Bearer` header remains available to end-users. The in-memory `JwtRevocationStore` is bounded to `50,000` entries (`MAX_REVOKED_ENTRIES`) with throttled 30-second expiry cleanup.
> - **Per-IP Session Limits:** `SessionStore` applies IPv6 `/64` prefix canonicalization (`canonical_client_ip`) to per-IP session creation quotas (`max 20 sessions/IP`, `10,000` global sessions).

### Static File Server Configuration

#### `[Server.StaticFilesParams]` (Required if `service = "StaticFiles"`)
Configures the built-in Static File Server. This is highly optimized for serving Single Page Applications (SPAs) like React or Vue, as well as static assets (images, fonts, downloads) directly from the local disk without needing an external web server like Nginx.

* `root`: String. The local directory path from which files should be served (e.g., `"./www"` or `"/var/www/frontend"`).
* `fallback_to_index`: Boolean. If set to `true`, any request for a file that does not exist on disk will instead return the `index.html` file from the root directory. This is mandatory for Client-Side SPA Routing to work properly. (Default: `false`).

### Outbound Zero-Trust Tunneling (SNI Relay)

#### `[Server.tunnel]` (Optional)
Configures this server instance to bypass opening a local listening port (ignores `ip` and `port`), and instead establish an outbound, multiplexed mTLS connection to a standalone Relay Server. The Relay Server handles incoming internet traffic and routes it back to this instance based on SNI (Server Name Indication).

> **Note on `ip` and `port`:** When a `[Server.tunnel]` is configured, `ip` and `port` are completely optional and can be omitted. They are only mandatory for standalone servers that open a local TCP/UDP listener.

* `target_url`: String. The URL of the relay server control plane (e.g., `"tls://relay.example.com:7001"`).
* `sni_domain`: String. The domain name this server is responsible for. The relay server routes traffic for this SNI to this tunnel. (e.g., `"api.example.com"`).
* `client_cert_path`: String. Path to the client certificate (PEM) used to authenticate against the relay.
* `client_key_path`: String. Path to the client private key (PEM).
* `ca_cert_path`: String. Path to the CA certificate (PEM) that signed the relay server's certificate.
* `max_yamux_streams`: Integer (Optional). Maximum number of concurrent Yamux multiplexed streams over the tunnel connection. **Default:** `4096` (replaces Yamux default of `512`). Each forwarded public client connection occupies exactly 1 Yamux stream.
* `proxy_protocol`: Boolean (Optional). Whether to negotiate HAProxy PROXY-Protocol v2 with the Relay Server to propagate the real client IP (IPv4 and IPv6). **Default:** `true`. When active, Praeco operates **strictly fail-closed** on the tunnel stream (terminating any stream that lacks a valid 16-byte PROXY-v2 header signature rather than falling back to an unattributed connection) and extracts the verified client IP before the TLS handshake for IP rate limiting, per-IP connection limits, access logging, and `X-Forwarded-For` / `X-Real-IP` headers.

**Example without `ip` and `port`:**
```toml
[[Server]]
name = "api_gateway"
enabled = true
protocol = "https"
authentication = "ClientCert"
service = "Router"

[Server.tunnel]
target_url = "tls://relay.example.com:7001"
sni_domain = "api.example.com"
client_cert_path = "certs/praeco_client.pem"
client_key_path = "certs/praeco_client.key"
ca_cert_path = "certs/relay_ca.pem"
max_yamux_streams = 4096
proxy_protocol = true
```

---

## Middleware Layer (`[Server.Layers]`)

Defines the execution pipeline of the middleware. The layers are processed in the specified order.

* **`enabled`**: Array of strings. Defines the activated layers in the given order.

### Available Middleware Layers
Each layer takes over a specific task in the request lifecycle:

| Layer Name | Brief Explanation |
| :--- | :--- |
| `"TraceId"` | Extracts or generates a W3C-compliant Trace ID and injects it into the request context for end-to-end tracing. Must be the FIRST layer! |
| `"Timing"` | Measures the processing duration of each request (useful for metrics). |
| `"Counter"` | Counts the number of currently processed requests. |
| `"Logger"` | Logs details about the request and response (e.g., path, status code, IP). |
| `"PathSanitizer"` | Enforces RFC 3986 path canonicalization (Option A). Rejects traversal (`..`, `%2e%2e`), encoded slashes (`%2f`), null bytes (`%00`), and backslashes (`\`) with 400 Bad Request. Automatically active on all servers! |
| `"Inspection"` | Checks the URL path of the request against a regex whitelist and blocks unauthorized calls. |
| `"Cors"` | Adds CORS headers (Cross-Origin Resource Sharing) and handles preflight requests. |
| `"SecurityHeaders"` | Adds HTTP security headers (like CSP, HSTS, anti-sniffing) to the server response. |
| `"Compression"` | Compresses HTTP responses (e.g., Gzip) to save bandwidth. Automatically skips already-compressed responses (`Content-Encoding`) and gRPC streams (`Content-Type: application/grpc*`) to preserve HTTP/2 trailers. |
| `"Decompression"` | Decompresses the incoming request body (includes protection against "decompression bombs"). |
| `"RateLimiter:Simple"` | Limits requests per second via a hard limit (Fixed-Window Algorithm). |
| `"RateLimiter:TokenBucket"` | Allows short-term bursts and periodically refills the limit. |
| `"Delay"` | Artificially delays each request by a defined time (for debugging / throttling). |
| `"JwtAuth"` | Verifies authentication via a JSON Web Token in the `Authorization` header. |
| `"ConcurrencyLimit"` | Limits the maximum number of concurrent connections in processing (overload protection). |
| `"MaxPayload"` | Rejects requests whose request body exceeds a specified byte size. |
| `"AltSvc"` | Injects the `Alt-Svc` header into responses to tell the client that HTTP/3 (QUIC) is available. |

Additional configuration blocks for specific layers:

#### `[Server.Layers.SecurityHeaders]`
Defines the security headers that the proxy sends to the client. 
**Note:** Even if `"SecurityHeaders"` is omitted from the `enabled` array, the proxy automatically injects `SecurityHeadersLayer` for your protection! If you have defined a custom `[Server.Layers.SecurityHeaders]` block on the server, those custom values are honored automatically; otherwise, strict API default values (e.g., `default-src 'none'`) are applied. When defining a custom `[Server.Layers.SecurityHeaders]` block, you must specify all 4 values.

Here is an overview of the most useful values for configuration:

* **`content_security_policy`** (CSP)
  * **For APIs (Default):** `"default-src 'none'"` (Blocks loading of any external resources).
  * **For Dashboards / Web Apps:** `"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'"` (Allows resources from its own domain as well as inline scripts/styles and Base64 images).
  * **Very strict Web App:** `"default-src 'self'"` (Only allows external files from its own domain, no inline scripts).

* **`strict_transport_security`** (HSTS)
  * **Recommended default:** `"max-age=63072000; includeSubDomains; preload"` (Enforces secure HTTPS for 2 years including all subdomains).
  * **For testing:** `"max-age=86400"` (Enforces HTTPS only for 1 day without subdomains).

* **`x_content_type_options`**
  * **Always:** `"nosniff"` (Forbids the browser from guessing the file type. There is de facto no other sensible value for this).

* **`x_frame_options`**
  * **Highest Security:** `"DENY"` (Completely forbids embedding the page in iframes - protection against Clickjacking).
  * **For Dashboards (if embedding is needed):** `"SAMEORIGIN"` (Allows embedding in iframes, but only on the exact same domain).

#### `[Server.Layers.Cors]`
* `allowed_origins`: Array of strings. List of allowed origins (e.g., `["https://admin.aweirich.eu", "http://localhost:3000"]`). Set `["*"]` to allow all.
* `allowed_methods`: Array of strings. Allowed HTTP methods (e.g., `["GET", "POST", "OPTIONS"]`).
* `allowed_headers`: Array of strings. Allowed HTTP headers (e.g., `["content-type", "authorization", "x-client-cert"]`).
* `allow_credentials`: Boolean. Indicates whether credentials (e.g., cookies or mTLS headers) are allowed.

> [!IMPORTANT]
> **CORS Security Constraint:** In accordance with the W3C CORS specification, `allow_credentials = true` **cannot** be combined with a wildcard origin `allowed_origins = ["*"]`. Praeco validates this constraint during configuration finalization and rejects invalid combinations with a configuration error before any traffic or reload occurs.

#### `[Server.Layers.Decompression]`
* `max_decompressed_bytes`: Integer. Maximum size of the decompressed body in bytes (protection against Decompression Bombs).

#### `[Server.Layers.MaxPayload]`
* `max_bytes`: Integer. Maximum allowed request payload size in bytes.
* *Header Fast-Path & Streaming Enforcement:* If `Content-Length` is present and exceeds `max_bytes`, the request is rejected immediately with `413 Payload Too Large`. For chunked or streaming uploads (REST and gRPC-Passthrough), bytes are tracked on the fly.
* *Zero Upstream Blacklisting:* When a client exceeds `max_bytes` during a streaming upload, Praeco cleanly returns `413 Payload Too Large`. The error is isolated as a client-side fault (`ProxyErrorKind::PayloadTooLarge`); the upstream backend is **never** marked dead or removed from the load balancer pool.

#### `[Server.Layers.ConcurrencyLimit]`
* `max_concurrent_requests`: Integer. Maximum number of concurrent connections in processing. Must be strictly greater than `0`.
* `load_shed`: Boolean *(optional, default: `true`)*. When enabled, requests arriving while at maximum capacity immediately fail fast with `503 Service Unavailable` and a `Retry-After: 1` header instead of queueing indefinitely into memory.
* `queue_timeout_ms`: Integer *(optional)*. If `load_shed = false`, maximum duration in milliseconds to wait for an available permit before timing out with `503 Service Unavailable`.
* *Body-Aware Permits:* Concurrency permits are retained across the entire duration of response body streaming (EOF or client disconnect) to accurately account for streaming resources.

#### `[Server.Layers.JWT]`
* `jwt_public_keys`: Array of strings. File paths to public keys (PEM, e.g. Ed25519) to verify JWT signatures. Keys are validated and parsed eagerly during startup and hot-reload.
* `cookie_fallback`: String *(optional)*. The name of the HTTP cookie to read the JWT from if the `Authorization: Bearer <token>` header is absent (e.g. `"admin-jwt"`).
* `redirect_on_failure`: String *(optional)*. The target URL to redirect the browser to (HTTP 302 / 307) if JWT authentication fails or is missing (e.g. `"https://localhost:1339/auth/login_page"`). Useful for redirecting unauthenticated users to the IdP login page.
* `expected_issuer`: String. **Mandatory.** The JWT must contain an `iss` claim that matches one of the expected issuers (supports comma-separated lists).
* `expected_audience`: String. **Mandatory.** The JWT must contain an `aud` claim that matches one of the expected audiences (supports comma-separated lists).

#### `[Server.Layers.RateLimiter]` (Simple)
* `requests_per_second`: Integer. Strict limit of requests per second. Must be strictly greater than `0`.
* `key_by`: String *(optional, default: `"identity"`)*. Partitioning strategy:
  * `"identity"`: Keyed by authenticated user (`sub` from JWT or SAN from mTLS cert), falling back to canonicalized client IP (`canonical_client_ip`).
  * `"ip"`: Keyed strictly by canonicalized client IP (`SocketAddr` / `PROXY_V2`). Standard IPv6 addresses are masked to their `/64` subnet prefix and IPv4-mapped IPv6 addresses (`::ffff:x.x.x.x`) are unwrapped to IPv4 so attackers cannot bypass limits by rotating IPv6 interface identifiers.
  * `"global"`: Server-wide shared bucket.
* `max_entries`: Integer *(optional, default: `10000`)*. Maximum tracked client keys.
* `ttl_seconds`: Integer *(optional, default: `300`)*. Inactive key time-to-live before pruning.
* `trust_forwarded_headers`: Boolean *(optional, default: `false`)*. When `false` (default), `X-Forwarded-For` and `X-Real-IP` headers are ignored for rate-limiting key extraction to prevent IP spoofing, using only the verified socket / PROXY-v2 peer IP. Set to `true` only if Praeco runs behind a trusted L7 reverse proxy that does not use PROXY-Protocol v2.
* *Performance & Anti-Cache-Thrashing (Fail-Closed):* Known keys are updated via an allocation-free $O(1)$ fast-path (`get_mut`), TTL cleanup is throttled to at most once every 10 seconds (`CLEANUP_INTERVAL_SECS = 10`), and when `entries.len() >= max_entries` is reached after TTL cleanup, requests from unknown keys fail closed with `429 Too Many Requests` (`Retry-After: 1`) without evicting active rate-limit buckets.
* *RFC 6585 compliance:* Rejections (`429 Too Many Requests`) include a calculated `Retry-After: <seconds>` header.

#### `[Server.Layers.TokenBucketRateLimiter]`
* `max_capacity`: Integer. Maximum burst size (number of tokens). Must be strictly greater than `0`.
* `refill`: Integer. Number of added tokens per interval. Must be strictly greater than `0`.
* `duration_micros`: Integer. Refill interval in microseconds. Must be strictly greater than `0`.
* `key_by`: String *(optional, default: `"identity"`)*. Partitioning strategy (`"identity"`, `"ip"`, or `"global"`), using `canonical_client_ip` (IPv6 `/64` subnet aggregation and IPv4-mapped IPv6 unwrapping).
* `max_entries`: Integer *(optional, default: `10000`)*. Maximum tracked client keys (fail-closed with `429 Too Many Requests` for unknown keys when at capacity, protecting existing buckets against cache-thrashing).
* `ttl_seconds`: Integer *(optional, default: `300`)*. Inactive key time-to-live before pruning (throttled 10s sweep).
* `trust_forwarded_headers`: Boolean *(optional, default: `false`)*. Whether to trust `X-Forwarded-For` / `X-Real-IP` headers for IP extraction (default `false`).
* *Float-precision refill:* Eliminates token drift by preserving fractional intervals without truncation. Rejections (`429 Too Many Requests`) include a calculated `Retry-After: <seconds>` header.

#### `[Server.Layers.Delay]`
* `delay_micros`: Integer. Artificially delays each request (for debugging).

---

## Inspection Layer (Path Whitelist)

When the `Inspection` layer is enabled, it acts as a lightweight Web Application Firewall (WAF). It checks the URL path (and query string) of each incoming request against regular expressions (regex). Only requests that are explicitly allowed pass through the layer. All others are immediately rejected with `403 Forbidden`.

The configuration is divided by HTTP methods:
* `[Server.AllowedPathes.GET]`
* `[Server.AllowedPathes.POST]`
* `[Server.AllowedPathes.PUT]`
* `[Server.AllowedPathes.DELETE]`

### Functionality & Syntax

**Format:** `"/exact_path" = ["Regex1", "Regex2"]`

1. **The Key (Left Side):** Must be the *exact* base path of the URL (without query parameters). The proxy looks in its internal map for exactly this string. If the path is not listed here, the request is immediately blocked.
2. **The Value (Right Side):** Is an array of regular expressions. 
3. **The Matching:** The proxy puts the base path and the query string back together (e.g., `/api/search?q=test`) and checks this complete string against all regular expressions defined in the array. As soon as *at least one* regex matches, the request is let through.

> [!TIP]
> **Why doesn't the key (Base-Path) allow Regex? (Performance)**
> This is a deliberate architectural decision for extremely high performance. The keys are loaded into a so-called hash map (`HashMap`) at startup. An exact path match (`map.get(path)`) in a hash map requires almost `0` computation time ($O(1)$). If the server were to allow regex for the key, it would have to loop over *all* configured routes for *every* incoming request and perform compute-intensive regex operations ($O(N)$). Through the exact key, the correct regex list is found lightning fast, and only then the (more expensive) regex check is performed.

### Examples

```toml
[Server.AllowedPathes.GET]
# Allows the root path "/" and optionally a query parameter "name" (e.g., /?name=Fredi)
"/" = ["^/?$", "^/\\?name=.*$"]

# Allows the path "/name", but ONLY if a numerical ID is strictly passed (e.g., /name?id=123).
# Explanation of the syntax "\\?id":
# 1. '\\'   : In TOML, a backslash must be doubled.
# 2. '\\?'  : Corresponds to '\?' in regex, which stands for a mandatory literal question mark (in the URL).
"/name" = ["^/name\\?id=\\d+$"]

[Server.AllowedPathes.POST]
# For gRPC calls, there are usually no query parameters.
# ".*" here simply allows everything on this exact path.
"/chat.ChatService/SendMessage" = [".*"]
```

---

## Reverse Proxy Routing (`[Server.ReverseRoutes."/prefix"]`)

*This section is only active if `service = "Router"` is set for the server instance.*

A reverse proxy accepts incoming requests from clients and forwards them - completely transparently for the client - to one or more background servers (upstreams). The response from the background server is then played back to the client via the proxy. This is the heart of the gateway and enables central authentication, intelligent load balancing, and failover.

### How does Prefix Routing work?
Each block defines a route based on a URL prefix (the path inside the square brackets). When a request comes in, the proxy compares the path with all configured routes and **always selects the longest (most specific) match**.

* **Example:** You configure two routes: `[Server.ReverseRoutes."/"]` (Catch-All) and `[Server.ReverseRoutes."/api/v1"]`.
* A request to `/api/v1/users` is processed by the specific route `/api/v1`.
* A request to `/help` falls back to the catch-all `/`.

### Core Functions per Route
Each route acts isolated and offers four essential functions:
1. **Load Balancing:** You can specify an array of backend servers (upstreams). Traffic is distributed among these according to a chosen strategy.
2. **Health Checks:** The proxy can dynamically detect dead servers, pause them for a time (Cooldown), and automatically put them back into rotation when they are reachable again.
3. **Authorization (RBAC):** You can restrict routes to specific roles (see `[oid_mapping]`).
4. **URL Stripping:** The configured prefix is *removed* from the URL during forwarding and replaced by the path of the backend server.
   * *Example:* A request to `/api/v1/users` (Prefix `/api/v1`) is forwarded to an upstream with the address `http://backend:8080/` as `http://backend:8080/users`. 
   * A request to `/help` (Prefix `/`) goes to the backend as `/help` accordingly.

### Parameters of a Route

| Parameter | Data Type | Description | Possible Values |
| :--- | :--- | :--- | :--- |
| `upstreams` | Array | List of backend server URLs. <br><br>**Note:** If more than one server is specified, the proxy automatically performs load balancing between these servers. | **Example:** `["https://backend1:50051", "https://backend2:50051"]` |
| `strategy` | String | Load balancing strategy. | `"RoundRobin"` (Default, sequential)<br>`"LeastConnections"` (Fewest active connections)<br>`"Random"` (Random)<br>`"Sticky"` (Hash on client IP)<br>`"HighestScore"` (Based on health checks) |
| `backend_type` | String | Type of the backend. | `"rest"` (Standard HTTP)<br>`"grpc_passthrough"` (Pure gRPC/HTTP2)<br>`"grpc"` (gRPC with JSON-Transcoding) |
| `allowed_roles` | Array | **RBAC (Role-Based Access Control):** Determines which roles are allowed to access this route. <br><br>• If the array is **empty** `[]`, the route is completely public (authorization check is skipped).<br>• If roles are entered (e.g., `["Admin", "Operator"]`), the client must have been assigned exactly one of these roles. **Attention: The system is not hierarchical!** A client with role `"Admin"` may *not* automatically access routes where *only* `"Guest"` is stated, unless you explicitly enter `["Admin", "Guest"]`. | `["Admin", "Operator", "Viewer", "Guest"]` |
| `active_health_check_interval` | Integer | Interval in seconds for active polling. `0` means disabled. | **Example:** `15` |
| `grpc_pool_refresh_secs` | Integer | (Only for type `"grpc"`) How often the gRPC Reflection schema should be updated in the background. | `60` |
| `cooldown_seconds` | Integer | Duration in seconds how long a dead node is not targeted. | **Default:** `10` |
| `max_retries` | Integer | Maximum automatic retry attempts for failed requests. | **Default:** `2` |

### Fine-Grained Path-Level RBAC (`[Server.rbac]`)

While `allowed_roles` on a route prefix (`[Server.ReverseRoutes."..."]`) secures entire subtrees, modern APIs often require **fine-grained method- and path-level privilege separation** within the same reverse route (e.g. distinguishing between seller operations and super-admin commands under `/api/*`).

The `[Server.rbac]` table maps specific URI paths or wildcard patterns to required roles:

```toml
[Server.rbac]
# Exact path match (O(1) lookup)
"/api/GetDatabaseTables"         = ["Admin"]
"/api/GetTableContent"           = ["Admin"]
"/api/AdminDeleteUser"           = ["Admin"]

# Wildcard prefix match (ends with '*')
"/api/Admin*"                    = ["Admin"]

# Specific exception (exact match takes precedence over wildcard prefix)
"/api/AdminGetProducts"          = ["Admin", "Seller"]

# Explicit Deny-All (fail-closed: empty role list denies all callers)
"/api/InternalSecret"            = []

# Public override (wildcard role '*' permits all callers)
"/api/PublicPing"                = ["*"]
```

#### Evaluation Order & Precedence:
1. **Exact Path Match:** If the request URI matches an exact key in `[Server.rbac]`, that rule is enforced immediately.
2. **Longest Prefix Wildcard Match:** If not matched exactly, keys ending with `*` are evaluated in order of descending prefix length (most specific prefix wins).
3. **Empty Role List (`[]`) = Fail-Closed:** If a matched path rule has an empty role list, access is unconditionally denied with `403 Forbidden`.
4. **Fallback to Route-Level `allowed_roles`:** If no path-specific rule in `[Server.rbac]` matches the request, authorization falls back to the enclosing route's `allowed_roles`. If the route's `allowed_roles` is empty `[]`, the route is unrestricted.


#### Excursion: Backend Types (`backend_type`)
The choice of backend type largely determines how the proxy handles data streams, especially if the backend is a gRPC server:

* **`"rest"`:** Default behavior for classic web servers and REST APIs. The HTTP calls (incl. headers and body) are passed through 1:1.
* **`"grpc_passthrough"`:** Pure pass-through of gRPC. 
  * *Client:* Must be a real gRPC client (speaks HTTP/2 and Protobuf).
  * *Behavior:* The proxy passes the pure gRPC frames on the TCP/HTTP2 level through to the backend without looking into the payload or modifying it. This is extremely fast and performant.
* **`"grpc"` (JSON-Transcoding):** The proxy acts as a translator between the REST/JSON world and the gRPC world.
  * *Client:* Can be a normal web browser, a frontend (JavaScript/Fetch), or `curl` that speaks normal HTTP(s) with JSON.
  * *Behavior:* The proxy receives the JSON request, translates it "on the fly" into the binary Protobuf format (based on the schema loaded from the server via Reflection) and sends it via HTTP/2 to the gRPC server. The gRPC response of the server is translated back into readable JSON by the proxy and sent back to the client. This allows modern gRPC backends to be addressed without special client libraries.

### Health Checks & Failover

The proxy protects your applications through two combined monitoring systems to intercept failures of backend servers (upstreams) and intelligently reroute traffic:

**1. Passive Health Checks (Circuit Breaker)**
This system is always automatically active as soon as traffic flows.
* If the proxy sends a request to a backend and it is unreachable (e.g., Connection Refused or Timeout), the error is registered immediately.
* The backend is marked as "dead" and put on the "bench" for the duration of `cooldown_seconds` (Default: 10s). The load balancer does not route new requests there during this time.
* After the cooldown phase has expired, the backend gets a new chance ("Half-Open" state) and the next regular request is tentatively routed there again.
* **Failover (`max_retries`):** If a backend fails exactly during a customer request, the proxy does not simply abort. It catches the error and automatically sends the customer request to the next healthy backend in the list. The parameter `max_retries` (Default: 2) controls how often this is attempted. For the customer, the server failure is thus completely invisible.

**2. Active Health Checks (Background Polling)**
This feature is enabled by setting `active_health_check_interval` to a value greater than 0 (e.g., `15`).
* The proxy then starts an asynchronous task in the background for each backend, which (in the example every 15 seconds) proactively checks reachability, even if there is currently no customer traffic.
* **REST Backends:** An HTTP GET request is automatically sent to the `/health` path of the backend server.
* **gRPC Backends:** The proxy uses "gRPC Server Reflection" to load the server's schema. It searches all offered services for a method that exactly carries the name `health` (e.g., `/MyService/health`). If it finds this method, it is cyclically pinged with an empty Protobuf payload. If it does not find such a method, the active health check is skipped for this node.
* **Health Score (Important for the `HighestScore` strategy):** The proxy not only evaluates the HTTP status code, but also reads the payload of the health check response to assign a "score" to the servers.
  * *For REST:* The backend must return a JSON object: `{"score": 100}`.
  * *For gRPC:* The method must return a Protobuf message whose very first field (Field Tag 1) is an integer (e.g., `uint32 score = 1;`).
  * *Meaning & Value Range:* A score of `0` immediately marks the server as dead (unhealthy). At a value `> 0` it is considered healthy. A **value range of 0 to 100** (e.g., analogous to percent) is **strongly recommended for both protocols**. (Note: For performance reasons, the internal gRPC parser currently only evaluates the Protobuf field from the first byte, which is why gRPC scores technically cannot be greater than 127 anyway).
  * If you have chosen the strategy `"HighestScore"` for Load Balancing, the proxy always forwards new requests to the server that reported the highest value during the last check (useful to prioritize servers according to their current CPU load).
* **Advantage:** Dead servers are detected even before a customer tries to access them. If a dead server is reachable again at the next proactive ping, it is immediately and without risk taken back into the load balancer.

### Upstream Connection Parameters (`[Server.RouterParams]`)

Configures the outgoing connection of the proxy to the backend servers.

| Parameter | Data Type | Description | Possible Values / Example |
| :--- | :--- | :--- | :--- |
| `protocol` | String | Protocol for outgoing connections. | `"http"`, `"https"` |
| `authentication` | String | Auth method that the proxy uses towards the backend. | `"None"`, `"ClientCert"`, `"JWT"` |
| `ssl_root_certificate` | String | Path to the CA certificate for checking the backend certificate. | `"/path/to/ca.pem"` |
| `ssl_client_certificate` | String | Proxy Client Certificate for mTLS to the backend. | `"/path/to/proxy-client.pem"` |
| `ssl_client_key` | String | Proxy Private Key for mTLS to the backend. | `"/path/to/proxy-client.key"` |
| `jwt` | String | Path to a JWT file, which is sent to the backend when `authentication = "JWT"`. | `"/path/to/token.jwt"` |
| `connect_timeout_seconds` | Integer | TCP connect timeout to upstreams in seconds (default: 5). | `5` |
| `request_timeout_seconds` | Integer | Request header timeout for upstream responses in seconds (default: 30, 0 = disabled). Returns 504 on expiry. | `30` |
| `idle_timeout_seconds` | Integer | Connection pool idle keep-alive timeout in seconds (default: 90). | `90` |
| `grpc_reflection_timeout_seconds` | Integer | gRPC reflection discovery RPC timeout in seconds (default: 10). | `10` |
| `grpc_reflection_ttl_seconds` | Integer | Schema cache TTL in seconds before refreshing protobuf definitions (default: 600 / 10m). | `600` |

#### Upstream Timeouts & Keep-Alive Mechanics (Zero-Hang Architecture)
1. **Connect & Request Timeouts:**
   - `connect_timeout_seconds`: Bound TCP and TLS connection establishment time. If a backend drops packets or stalls during the handshake, Praeco terminates the attempt after this duration instead of hanging indefinitely.
   - `request_timeout_seconds`: Wraps REST, gRPC-Passthrough, and gRPC-Web (`backend_type = "grpc"`, which also enforces a 16 MiB upstream response body cap via `http_body_util::Limited`) requests in an asynchronous deadline. If an upstream server accepts the connection but fails to reply within the timeout, Praeco returns `504 Gateway Timeout` and marks that specific upstream dead.
2. **TCP & HTTP/2 Keepalive:**
   - Praeco enables `TCP_NODELAY` and sets TCP Keepalive probes to 60 seconds on all upstream sockets.
   - For HTTP/2 connections, keepalive PING frames are transmitted every 30 seconds with a 10-second acknowledgment timeout. Both active requests and idle connections in the pool are probed (`http2_keep_alive_while_idle = true`), allowing broken connections or silent state-table drops by middleboxes/firewalls to be pruned immediately.
   - All connection pools run an active Tokio timer (`builder.pool_timer` & `builder.timer`) ensuring idle connections older than `idle_timeout_seconds` are evicted cleanly from memory.
3. **gRPC Reflection Schema Caching & Fail-Closed TLS:**
   - **Non-blocking Async I/O:** gRPC-Web reflection fetches and TLS key/CA reads (`tokio::fs::read`) occur completely outside `RwLock` read/write locks using single-flight mutexes, preventing concurrent gRPC-Web client requests or Tokio worker threads from stalling during schema queries.
   - **TTL Invalidation:** Schema reflection caches expire after `grpc_reflection_ttl_seconds` (default 10 minutes) to accommodate dynamic upstream proto updates. In case of transient upstream discovery errors while an expired schema is present, Praeco applies stale-while-revalidate to ensure continuous uptime.
   - **Strict Custom PKI Isolation & Fail-Closed Security:** When a custom `ssl_root_certificate` is configured in `RouterParams`, Praeco trusts **exclusively** that custom CA (without merging public Mozilla WebPKI roots). If custom CA certificates or mTLS keys cannot be read from disk, reflection and upstream connections immediately fail closed with an error rather than silently degrading to system WebPKI trust stores.


---

## Appendix: Certificates and Keys Overview

In a Zero-Trust architecture, `praeco-rs` relies heavily on various cryptographic keys and certificates. Here is a compact overview of what they do, where they are configured, and how to generate them.

| Type | Used For | Parameter in `Config.toml` | How to Generate / Where to Get |
| :--- | :--- | :--- | :--- |
| **Server TLS Certificate (Public)** | Authenticates the server to incoming clients (HTTPS). Must be a fullchain/PEM. | `[Server.server_certs.ssl_certificate]` | Production: **Let's Encrypt** (Certbot).<br>Local/Test: OpenSSL or `rcgen`. |
| **Server TLS Key (Private)** | Private key belonging to the server certificate. Must be unencrypted PEM. | `[Server.server_certs.ssl_certificate_key]` | Along with the Server TLS Certificate. |
| **Root CA Certificate (Public)** | The Trust Anchor. Used by the proxy to verify incoming mTLS client certificates, or by the proxy to verify backend server certificates. | `[[Server.client_certs.ssl_client_ca]]`<br>`[Server.RouterParams.ssl_root_certificate]` | Created automatically by `./client_certs/generate_mtls_oid_certs.sh` (`ca.cert.pem`). |
| **Client mTLS Certificate & Key** | Given to clients (Devices, iOS App) to authenticate themselves against the proxy. Contains OIDs for Role Mapping. | (Used by Clients)<br>For Proxy-to-Backend:<br>`ssl_client_certificate` / `key` | Use the provided script:<br>`./client_certs/generate_mtls_oid_certs.sh -c <name> -o <roles>` |
| **JWT Private Key** | Used by the Identity Provider (`service = "Idp"`) to securely sign the issued JWTs. | `[Server.IdpParams.jwt_private_key]` | OpenSSL (Ed25519 recommended):<br>`openssl genpkey -algorithm ed25519 -out idp_private.pem` |
| **JWT Public Key** | Used by Resource Servers (and the IdP's JWKS endpoint) to verify the signatures of the JWTs. | `[Server.IdpParams.jwt_public_key]`<br>`[Server.Layers.JWT.jwt_public_keys]` | Extracted from Private Key:<br>`openssl pkey -in idp_private.pem -pubout -out idp_public.pem` |

---

## Relay Server Configuration (`RelayConfig.toml`)

The Praeco Relay Server operates as a standalone proxy (TCP/SNI router) and uses its own configuration file, typically named `RelayConfig.toml`. In addition to mTLS authentication, the Relay Server enforces **SAN-to-SNI authorization** on the Control Plane (a Praeco client certificate may only `REGISTER <sni>` if its X.509 SAN or CN matches the requested domain), generation-tagged routing entries, and IPv6 `/64` prefix canonicalization (`canonical_client_ip`) on the Data Plane.

| Parameter | Data Type | Description | Default Value |
| :--- | :--- | :--- | :--- |
| `control_plane_addr` | String | The address where the Relay accepts incoming mTLS Yamux tunnels from Praeco backend instances. | `"0.0.0.0:7001"` |
| `data_plane_addr` | String | The address where the Relay accepts public internet HTTPS traffic (SNI Routing). | `"0.0.0.0:443"` |
| `ca_cert_path` | String | Path to the CA certificate used to verify the mTLS connections from backend instances. | `"../client_certs/ca.cert.pem"` |
| `crl_path` | String *(optional)* | Path to a Certificate Revocation List (CRL) for revoking compromised tunnel client certificates; parsed at startup with X.509 `nextUpdate` expiration verification. | `None` |
| `server_cert_path` | String | Path to the Relay's own public TLS certificate (for the control plane). | `"server.crt"` |
| `server_key_path` | String | Path to the Relay's private key. | `"server.key"` |
| `enable_opentelemetry` | Boolean | Enables Jaeger tracing for the Relay. | `false` |
| `rate_limit_connections_per_sec` | Integer | Limits the number of new TCP connections allowed per second per IP / IPv6 `/64` subnet on the Data Plane (bounded to `100,000` active buckets). | `50` |
| `rate_limit_burst` | Integer | The maximum burst of TCP connections allowed at once per IP / IPv6 `/64` subnet. | `100` |
| `max_concurrent_connections` | Integer | Global maximum of simultaneous Data Plane TCP connections. | `10000` |
| `max_concurrent_connections_per_ip` | Integer | Maximum simultaneous Data Plane TCP connections per client IP / IPv6 `/64` subnet. | `100` |
| `client_hello_timeout_secs` | Integer | Maximum duration in seconds to receive and parse the complete TLS `ClientHello` record (handles TCP fragmentation up to 16 KB). | `10` |
| `control_plane_handshake_timeout_secs` | Integer | Timeout in seconds for mTLS handshake and `REGISTER` command on the Control Plane. | `10` |
| `max_yamux_streams` | Integer | Maximum concurrent Yamux streams per tunnel connection. | `4096` |
