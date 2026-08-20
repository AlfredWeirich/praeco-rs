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
| `ip` | String | The IP address to bind to. | `"0.0.0.0"` (all), `"192.168.x.x"`, `"local"` (automatic local IP) |
| `port` | Integer | The TCP port of the listener. | **Example:** `1336` |
| `enabled` | Boolean | Main switch to turn the server on or off. | `true`, `false` (**Default:** `true`) |
| `protocol` | String | Transport protocol. (If `https`, `[Server.server_certs]` must be configured). | `"http"`, `"https"` (**Default:** `"http"`) |
| `authentication` | String | Authentication method for incoming connections. | `"None"` (Public)<br>`"ClientCert"` or `"mTLS"` (Strict Certificate-based)<br>`"OptionalClientCert"` (Client cert requested but not required, useful for IdP device auth)<br>`"JWT"` (Token-based) |
| `service` | String | The base service that processes the request after the middleware. | `"Echo"` (Returns request)<br>`"Router"` (Reverse proxy)<br>`"Idp"` (Identity Provider for JWT issuance) |

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
* `ssl_client_crl`: String (Optional). Path to the Certificate Revocation List.

#### `[Server.client_cert_forwarding]` (Optional)
This configuration controls the secure passing of client identities to backend servers. It fulfills two essential tasks:
1. **Security / Header Sanitizing (Protection against Spoofing):** Before the request goes to the backend, the proxy strictly removes all incoming headers that match these configured names. This prevents an attacker from manually sending headers (e.g., `x-client-san: <foreign-id>`) on a public port and impersonating someone else (Identity Spoofing).
2. **Injection:** If the client has successfully authenticated via mTLS, the proxy extracts the certificate and the SAN (Subject Alternative Name) and re-injects these trusted values under the specified header names into the request to the backend.

* `header_cert`: String. HTTP header name for the URL-encoded client certificate.
* `header_san`: String. HTTP header name for the SAN (Subject Alternative Name).
* `header_roles`: String. HTTP header name for the forwarded user roles (e.g., `x-user-roles`).
* `header_client_ip`: String. HTTP header name for the client IP address (e.g., `x-forwarded-for`).

### Identity Provider (IdP) Configuration

#### `[Server.IdpParams]` (Required if `service = "Idp"`)
Configures the built-in Identity Provider, which issues JWTs based on mTLS or Device Authentication (QR-Code flow). When using this service, you should typically set `authentication = "OptionalClientCert"`.

* `jwt_private_key`: String. Path to the Ed25519 or RSA private key (PEM format) used to sign the issued JWTs.
* `jwt_public_key`: String. Path to the corresponding public key. Required to expose the `/.well-known/jwks.json` endpoint for dynamic key discovery by APIs.
* `token_expiry_seconds`: Integer. Time to live (TTL) for the issued JWT in seconds.
* `session_ttl_seconds`: Integer. Time to live for the QR-Code login session in seconds (how long the user has to scan the code).
* `cookie_name`: String. The name of the cookie in which the JWT will be stored. (e.g., `"__Host-jwt"`). If using a `__Host-` prefixed cookie, the `protocol` MUST be `"https"`.
* `cookie_domain`: String *(optional)*. The domain for which the cookie is valid. Useful for sharing login sessions across subdomains (e.g. `".aweirich.eu"`). If omitted, the cookie is restricted to the exact hostname of the IdP.
* `redirect_after_login`: String. The URL path to which the user's browser is redirected after successfully obtaining the JWT via the `/auth/status` endpoint (e.g., `"/dashboard"`).
* `issuer`: String. The issuer claim (`iss`) injected into the generated JWTs (default: `"praeco-idp"`).
* `allowed_audiences`: Array of strings. A list of allowed target audiences (`aud`). If a client requests a specific audience via the `?aud=` query parameter, it must match one of the entries in this list.

### Outbound Zero-Trust Tunneling (SNI Relay)

#### `[Server.tunnel]` (Optional)
Configures this server instance to bypass opening a local listening port (ignores `ip` and `port`), and instead establish an outbound, multiplexed mTLS connection to a standalone Relay Server. The Relay Server handles incoming internet traffic and routes it back to this instance based on SNI (Server Name Indication).

> **Note on `ip` and `port`:** Even when the tunnel is active and Praeco does not open a local port, the `ip` and `port` fields **must** still be provided in the `[[Server]]` block due to the strict typing of the TOML parser. You can set them to dummy values in this case (e.g., `ip = "0.0.0.0"` and `port = 0`).

* `target_url`: String. The URL of the relay server control plane (e.g., `"tls://relay.example.com:7001"`).
* `sni_domain`: String. The domain name this server is responsible for. The relay server routes traffic for this SNI to this tunnel. (e.g., `"api.example.com"`).
* `client_cert_path`: String. Path to the client certificate (PEM) used to authenticate against the relay.
* `client_key_path`: String. Path to the client private key (PEM).
* `ca_cert_path`: String. Path to the CA certificate (PEM) that signed the relay server's certificate.

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
| `"Inspection"` | Checks the URL path of the request against a regex whitelist and blocks unauthorized calls. |
| `"Cors"` | Adds CORS headers (Cross-Origin Resource Sharing) and handles preflight requests. |
| `"SecurityHeaders"` | Adds HTTP security headers (like CSP, HSTS, anti-sniffing) to the server response. |
| `"Compression"` | Compresses HTTP responses (e.g., Gzip) to save bandwidth. |
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
**Note:** If this layer is *missing* from the `enabled` array, the proxy automatically injects it for your protection with extremely strict default values (e.g., `default-src 'none'`)! If you want to override these values (e.g., for a dashboard), you must explicitly activate the layer and define *all* 4 values. If values are missing, the server will not start and will display an error message.

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

#### `[Server.Layers.Decompression]`
* `max_decompressed_bytes`: Integer. Maximum size of the decompressed body in bytes (protection against Decompression Bombs).

#### `[Server.Layers.MaxPayload]`
* `max_bytes`: Integer. Maximum allowed payload size in bytes.

#### `[Server.Layers.ConcurrencyLimit]`
* `max_concurrent_requests`: Integer. Maximum number of concurrent connections in processing.

#### `[Server.Layers.JWT]`
* `jwt_public_keys`: Array of strings. File paths to public keys (PEM, e.g. Ed25519) to verify JWT signatures.
* `cookie_fallback`: String *(optional)*. The name of the HTTP cookie to read the JWT from if the `Authorization: Bearer <token>` header is absent (e.g. `"admin-jwt"`).
* `redirect_on_failure`: String *(optional)*. The target URL to redirect the browser to (HTTP 302 / 307) if JWT authentication fails or is missing (e.g. `"https://localhost:1339/auth/login_page"`). Useful for redirecting unauthenticated users to the IdP login page.
* `expected_issuer`: String. **Mandatory.** The JWT must contain an `iss` claim that exactly matches this string. This prevents the "Confused Deputy" problem by ensuring tokens from other Identity Providers using the same key cannot be used.
* `expected_audience`: String. **Mandatory.** The JWT must contain an `aud` claim that exactly matches this string. Ensures the token was specifically issued for this gateway/application.

#### `[Server.Layers.RateLimiter]` (Simple)
* `requests_per_second`: Integer. Strict limit of requests per second.

#### `[Server.Layers.TokenBucketRateLimiter]`
* `max_capacity`: Integer. Maximum burst size (number of tokens).
* `refill`: Integer. Number of added tokens per interval.
* `duration_micros`: Integer. Refill interval in microseconds.

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

The Praeco Relay Server operates as a standalone proxy (TCP/SNI router) and uses its own configuration file, typically named `RelayConfig.toml`.

| Parameter | Data Type | Description | Default Value |
| :--- | :--- | :--- | :--- |
| `control_plane_addr` | String | The address where the Relay accepts incoming mTLS Yamux tunnels from Praeco backend instances. | `"0.0.0.0:7001"` |
| `data_plane_addr` | String | The address where the Relay accepts public internet HTTPS traffic (SNI Routing). | `"0.0.0.0:443"` |
| `ca_cert_path` | String | Path to the CA certificate used to verify the mTLS connections from backend instances. | `"../client_certs/ca.cert.pem"` |
| `server_cert_path` | String | Path to the Relay's own public TLS certificate (for the control plane). | `"server.crt"` |
| `server_key_path` | String | Path to the Relay's private key. | `"server.key"` |
| `enable_opentelemetry` | Boolean | Enables Jaeger tracing for the Relay. | `false` |
| `rate_limit_connections_per_sec` | Integer | Limits the number of new TCP connections allowed per second per IP address on the Data Plane (DDoS mitigation). | `50` |
| `rate_limit_burst` | Integer | The maximum burst of TCP connections allowed at once per IP. | `100` |
