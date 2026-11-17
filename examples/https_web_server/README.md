# HTTPS & HTTP/3 Embedded Web Server Example

Eigenständiges Beispiel-Crate, das `praeco-rs` mit `default-features = false` und **ohne `Config.toml`** einbindet:

- **Dual-Stack HTTPS:** HTTP/1.1 + HTTP/2 (TCP) und HTTP/3 (QUIC/UDP) auf Port `8443` (konfigurierbar via `PORT`).
- **Modulares Endpoint-Routing:** Endpunkte sind als normale `async fn` außerhalb von `main()` definiert und werden über `WebRouter` registriert.
- **Sicherheitslayer:** `TraceId`, `SecurityHeaders`, `AltSvc`, `IpFilter` (`127.0.0.1/32`, `::1/128`), `RateLimiter:TokenBucket`, `ConcurrencyLimit`, `MaxPayload`, `Decompression` und `Inspection` (`AllowedPathes`).

## Starten

Vom Workspace-Root aus:

```bash
cargo run -p https_web_server
```

## Testen mit `curl` (HTTP/1.1 & HTTP/2)

```bash
# HTTP/2 GET /
curl -v --http2 --cacert server_certs/self_signed/public_ca.pem https://127.0.0.1:8443/

# HTTP/2 GET /users/42
curl -v --http2 --cacert server_certs/self_signed/public_ca.pem https://127.0.0.1:8443/users/42

# POST /api/echo
curl -v --http2 --cacert server_certs/self_signed/public_ca.pem \
  -H "Content-Type: application/json" \
  -d '{"hello":"praeco"}' \
  https://127.0.0.1:8443/api/echo

# WAF-Block durch Inspection-Layer (erwartet: 403 Forbidden)
curl -i --http2 --cacert server_certs/self_signed/public_ca.pem https://127.0.0.1:8443/admin
```

## HTTP/3 (QUIC) testen

Das mit macOS vorinstallierte `/usr/bin/curl` (LibreSSL) unterstützt kein `--http3`. Du kannst HTTP/3 direkt mit dem eingebauten `praeco-client` testen:

```bash
RUST_LOG=client=trace cargo run -p praeco-client --bin client -- \
  -s https -v h3 \
  --ca server_certs/self_signed/public_ca.pem \
  -u 127.0.0.1:8443 \
  -p /users/42 \
  -i 1
```

Alternativ via Homebrew-`curl` mit HTTP/3-Support (`brew install curl`):

```bash
/opt/homebrew/opt/curl/bin/curl -v --http3 --cacert server_certs/self_signed/public_ca.pem https://127.0.0.1:8443/users/42
```
