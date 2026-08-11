# RouterService — Reverse-Proxy Routing

> **Directory:** [`router/`](./)

This module implements a Tower `Service` that acts as a **configurable reverse proxy**.
Incoming HTTP requests are matched against prefix-based routes and forwarded to upstream backend servers, with built-in RBAC, URI rewriting, hop-by-hop header management, and specialized protocol handlers (REST, gRPC, gRPC-Web).

---

## Architecture

```text
                              ┌──────────────────┐
   Client Request ──────────► │  RouterService   │
                              │                  │
                              │  1. Route Lookup │
                              │  2. RBAC Check   │
                              │  3. Headers Mgt  │
                              │  4. Dispatch     │
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
| **Specialized Handlers** | Dynamically dispatches requests to standard HTTP proxies, transparent gRPC passthroughs, or JSON-to-gRPC transcoding backends. |
| **RBAC** | Routes can restrict access to specific `UserRole`s (`Admin`, `Operator`, `Viewer`, `Guest`). Roles are injected by earlier middleware. |
| **Hop-by-Hop Header Stripping** | Removes connection-level headers (`Connection`, `Transfer-Encoding`, `Upgrade`, etc.) per RFC 7230 §6.1. |
| **Upstream Authentication** | Supports **mTLS** (client certificate) or **JWT bearer token** injection toward backends. |
| **Dual Connection Pooling** | Maintains separate optimized connection pools for standard REST (`client`) and HTTP/2-only gRPC traffic (`grpc_client`). |

## Request Processing Pipeline

Each incoming request passes through the `call()` method:

1. **Health Check** — Intercepts `GET /health` to verify upstream availability based on active background probes.
2. **IP Address Management** — Extracts the client socket address and sets `X-Real-IP`.
3. **Route Lookup** — Matches the request path against the radix-tree router. Returns `404 Not Found` on miss.
4. **RBAC Enforcement** — Delegates to `rbac::enforce_rbac()`. Returns `403 Forbidden` on denial.
5. **Header Management** — Delegates to `headers::prepare_proxy_headers()` to strip hop-by-hop headers and inject tokens.
6. **Buffering Decision** — Determines if the request body should be streamed or buffered in memory (required for retries or transcoding).
7. **Dispatch** — Routes the request to `http_proxy`, `grpc_passthrough`, or `grpc_web` based on the configured `RouteBackendType`.

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
| `http_proxy` | Handles standard REST/HTTP forwarding, URI rewrites, and retries. |
| `grpc_passthrough` | Proxies pure gRPC traffic, fixing `te: trailers` and managing streaming. |
| `grpc_web` | Handles dynamic JSON-to-Protobuf transcoding using reflection. |
| `rbac` | Enforces Role-Based Access Control logic based on configured OIDs. |
| `headers` | Prepares proxy headers and strips restricted hop-by-hop HTTP headers. |
| `upstreams` | Upstream management and target evaluation logic. |

## Cloning & Performance

`RouterService` is **cheaply cloneable**:

- The `Router` and `ServerConfig` are wrapped in `Arc`.
- The Hyper `Client`s use internal atomic-reference-counted connection pools.
- The `jwt_token` is a small `Option<HeaderValue>`.

This makes it safe to clone once per connection in the TCP/UDP accept loops without performance concerns.
