# RouterService — Reverse-Proxy Routing

> **Directory:** [`router/`](./)

This module implements a Tower `Service` that acts as a **configurable reverse proxy**.
Incoming HTTP requests are matched against prefix-based routes and forwarded to upstream backend servers, with URI rewriting, hop-by-hop header management, and specialized protocol handlers (REST, gRPC, gRPC-Web).

---

## Architecture

```text
                              ┌──────────────────┐
   Client Request ──────────► │  RouterService   │
                              │                  │
                              │  1. Route Lookup │
                              │  2. Headers Mgt  │
                              │  3. Dispatch     │
                              │     │  │  │      │
                              └─────┼──┼──┼──────┘
                                    ▼  ▼  ▼
                     ┌──────────────┴──┼──┴───────────────┐
                     │                 │                  │
               http_proxy       grpc_passthrough       grpc_web
                     │                 │                  │
                     ▼                 ▼                  ▼
                  Upstream REST     Upstream gRPC      Upstream gRPC (Transcoded)
```

## Features

| Feature | Description |
|---------|-------------|
| **Prefix Routing** | Uses [`matchit`](https://docs.rs/matchit) radix-tree router for efficient O(1)-ish path matching with wildcard support (`{*rest}`). |
| **Path Canonicalization** | Enforces RFC 3986 path canonicalization, rejecting traversal (`..`, `%2e%2e`), encoded slashes (`%2f`), semicolon matrix parameters (`;` / `%3b`), and null bytes with `400 Bad Request`. |
| **Specialized Handlers** | Dynamically dispatches requests to standard HTTP proxies, transparent gRPC passthroughs, JSON-to-gRPC transcoding backends, fan-out aggregators, or RBAC-protected internal `admin` endpoints. |
| **RBAC (Middleware)** | Enforced upstream of `RouterService` by the generic fail-closed `RbacLayer` (`[Server.rbac]` with method-aware rules, exact trailing-slash normalization, longest-prefix matching, `[]` deny-all, and `*` public wildcard). |
| **Hop-by-Hop, Identity & Credential Sanitization** | Removes connection-level headers (`Connection`, `Transfer-Encoding`, `Upgrade`, etc.) per RFC 7230 §6.1, strips untrusted client identity/forwarding headers via prefix rules (`x-forwarded-*`, `x-auth-*`, `x-remote-*`, `x-user*`, `x-client-*`, `x-ssl-*`, `x-original-*`, `x-rewrite-*`, `remote-user`, etc.), strips `Authorization` and `Cookie` headers by default per route (`strip_authorization`, `forward_authorization`, `strip_cookies`, `strip_cookie_names`, optional `forward_headers` allowlist), and authoritatively sets `X-Real-IP`, `X-Forwarded-For`, `X-Forwarded-Proto`, and `X-Forwarded-Host` (including `:authority`). |
| **Upstream Authentication** | Supports **mTLS** (client certificate with strict custom CA isolation) or **JWT bearer token** injection toward backends. |
| **Dual Connection Pooling** | Maintains separate optimized connection pools for standard REST (`client`) and HTTP/2-only gRPC traffic (`grpc_client`). |
| **Client Fault Isolation** | Isolates client payload limits (`413`) and client request-body aborts (`400`, verified via `err.is_user()`) from upstream socket resets (`502`), so healthy upstreams are never blacklisted (`mark_dead`) by client faults while dead upstreams reliably trigger failover. |

## Request Processing Pipeline

Each incoming request passes through the `call()` method:

1. **Health Check** — Intercepts `GET /health` to verify upstream availability based on active background probes.
2. **Authoritative IP & Forwarding Header Sanitization** — Strips any client-supplied `forwarded`, `x-forwarded-for`, `x-real-ip`, `x-forwarded-host`, and `x-forwarded-proto` headers and sets `X-Real-IP`, `X-Forwarded-For`, `X-Forwarded-Proto`, and `X-Forwarded-Host` (from `Host` or HTTP/2 & HTTP/3 `:authority`) using the verified socket or PROXY-v2 peer address.
3. **Path Canonicalization** — Validates and canonicalizes the request path (RFC 3986), rejecting traversal attempts and illegal encodings before routing.
4. **Route Lookup** — Matches the canonical request path against the radix-tree router. Returns `404 Not Found` on miss.
5. **Header Management** — Delegates to `headers::prepare_proxy_headers()` to strip hop-by-hop headers, prefix-filter untrusted client identity/forwarding headers (`x-forwarded-*`, `x-auth-*`, `x-remote-*`, `x-user*`, `x-client-*`, `x-ssl-*`, `x-original-*`, `x-rewrite-*`, `remote-user`, etc.), enforce the route's [`RouteHeaderPolicy`] (stripping `Authorization`/`Cookie` by default, optional `strip_cookie_names` / `forward_headers` allowlist), and inject verified identity/forwarding tokens.
6. **Buffering Decision** — Determines whether the request body can be buffered (`max_retry_buffer_bytes`) or should stream immediately. For `grpc_passthrough`, `buffer_grpc_first_frame_or_stream` peeks up to one gRPC frame (bounded by a read timeout returning `408`) so unary/server-streaming calls stay retryable on connect errors while open bidirectional/client streams flow without blocking.
7. **Dispatch** — Routes the request to `http_proxy`, `grpc_passthrough`, `grpc_web`, `aggregator` (fan-out), or the built-in `admin` handler (protected by route/server auth or `RbacLayer`, anti-CSRF `Sec-Fetch-Site`, and `admin::audit` logs) based on the configured `RouteBackendType`.

## Struct & API Reference

### `RouterService`

```rust
#[derive(Clone)]
pub struct RouterService {
    client:      Client<HttpsConnector<HttpConnector>, ServiceRespBody>,
    grpc_client: Client<HttpsConnector<HttpConnector>, ServiceRespBody>,
    router:      Arc<Router<ParsedRoute>>,
    config:      Arc<ServerConfig>,
    jwt_token:   Option<HeaderValue>,
}
```

| Field | Purpose |
|-------|---------|
| `client` | Pooled HTTP/1+2 client for REST upstreams. |
| `grpc_client` | Pooled HTTP/2-only client specifically for gRPC upstreams. |
| `router` | `Arc`-wrapped `matchit::Router` for zero-copy shared routing. |
| `config` | Shared reference to the full server configuration. |
| `jwt_token` | Pre-formatted `Bearer <token>` value for upstream JWT auth. |

## Submodules

| Module | Purpose |
|--------|---------|
| `http_proxy` | Handles standard REST/HTTP forwarding, URI rewrites, and retries. Hosts the shared failover engine `forward_with_failover` (retry loop, `ProbeGuard`/`ConnectionGuard`, outlier detection, OTel injection, client-fault isolation) parameterized by `ProxyMode::{Http, GrpcPassthrough}`. |
| `grpc_passthrough` | Thin wrapper around `forward_with_failover(ProxyMode::GrpcPassthrough, …)`: enforces HTTP/2, strips hop-by-hop headers, sets `te: trailers`, buffers only up to the first gRPC frame (`buffer_grpc_first_frame_or_stream`) so bidi streams do not stall, retries strictly on `ConnectError`, applies gRPC outlier detection, and returns gRPC Trailers-Only error responses (`grpc-status`). |
| `aggregator` | Fan-out route (`backend_type = "aggregate"`): splits a `GET`/`POST` request into concurrent `rest` / `grpc_transcoding` sub-requests (zero-copy keyed payload slicing, per-target query/header policies, `required` vs. optional targets, cumulative response cap) and assembles the JSON result (`null` + `_errors` for failed optional targets) via a zero-copy chunked body. Delegates the actual upstream calls to `http_proxy` and `grpc_web`. |
| `grpc_web` | Handles dynamic JSON-to-Protobuf transcoding using non-blocking async reflection (`tokio::fs::read`), preserving `content-type: application/grpc` and `te: trailers`, propagating W3C `traceparent` (`HeaderInjector`) and `x-trace-id` headers end-to-end, enforcing `request_timeout_seconds`, and bounding upstream responses to `16 MiB` (`http_body_util::Limited`). |
| `headers` | Prepares proxy headers, unconditionally strips client identity and forwarding headers, strips hop-by-hop headers, authoritatively sets `X-Forwarded-*` / `X-Real-IP`, and cleans upstream responses. |
| `upstreams` | Upstream management and target evaluation logic. |
| `error` | Upstream error classification and body error tracking. |

## Error Classification & Upstream Protection

To prevent client-induced Denial of Service (where client-side errors like oversized payloads or early socket disconnects trip upstream health failovers):

- **`BodyErrorTracker`**: Wraps streaming request bodies (`RequestBody::Stream`) to capture and preserve client-side stream errors (`SrvError::PayloadTooLarge`, `SrvError::DecompressionLimitExceeded`, `SrvError::ClientAborted`) before Hyper or H2 can translate them into generic transport resets.
- **`classify_proxy_error`**: Distinguishes between:
  - **Client Faults**: `PayloadTooLarge` (`413 Payload Too Large`), `DecompressionLimitExceeded` (`413 Payload Too Large`), and `ClientAborted` (`400 Bad Request`). Raw `std::io::Error` resets (`ConnectionReset`, `BrokenPipe`, `UnexpectedEof`) are **only** classified as `ClientAborted` when `err.is_user()` is true (originating from the client request body). Upstream nodes are **never** marked dead, and retries are bypassed.
  - **Upstream Failures**: Connect timeouts, connection refused, or unexpected broken pipes / connection resets on the upstream connection (`err.is_user() == false`, returning `502 Bad Gateway`). The target node is marked dead (`mark_dead`), and remaining healthy nodes are tried if retries are configured.

## Cloning & Performance

`RouterService` is **cheaply cloneable**:

- The `Router` and `ServerConfig` are wrapped in `Arc`.
- The Hyper `Client`s use internal atomic-reference-counted connection pools.
- The `jwt_token` is a small `Option<HeaderValue>`.

This makes it safe to clone once per connection in the TCP/UDP accept loops without performance concerns.
