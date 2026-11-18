# HTTPS & HTTP/3 Embedded Web Server Example

Eigenständiges Beispiel-Crate, das `praeco-rs` mit `default-features = false, features = ["web"]` und **ohne `Config.toml`** einbindet:

- **Dual-Stack HTTPS:** HTTP/1.1 + HTTP/2 (TCP) und HTTP/3 (QUIC/UDP) auf Port `8443` (konfigurierbar via `PORT`).
- **Universeller Router & Extractors (`praeco_rs::web`):** Endpunkte sind schlanke `async fn`s mit typisierten Extractors (`Query<T>`, `Path<T>`, `Json<T>`, `TraceId`), `IntoResponse` und automatischer `AllowedPathes`-Ableitung für die WAF.
- **Saubere Trennung:** `src/main.rs` verdrahtet nur noch die Routen und startet den Server; Endpunkte & DTOs liegen in `src/endpoints.rs`, Server-Konfiguration und Shutdown in `src/bootstrap.rs`.
- **Sicherheitslayer:** `TraceId`, `SecurityHeaders`, `AltSvc`, `IpFilter` (`127.0.0.1/32`, `::1/128`), `RateLimiter:TokenBucket`, `ConcurrencyLimit`, `MaxPayload`, `Decompression` und `Inspection` (`AllowedPathes`).

## Starten & Testen

Vom Workspace-Root aus (der Stack-Test nutzt automatisch eine ephemere `TestPki` ohne lokale `server_certs/`):

```bash
cargo test -p https_web_server
```

Für `cargo run` werden Zertifikate über `PRAECO_TLS_CERT` / `PRAECO_TLS_KEY` oder unter `server_certs/self_signed/praeco_public.{pem,key}` erwartet:

```bash
cargo run -p https_web_server
```

## Testen mit `curl` (HTTP/1.1 & HTTP/2)

```bash
# HTTP/2 GET /
curl -v --http2 --cacert server_certs/self_signed/public_ca.pem https://127.0.0.1:8443/

# HTTP/2 GET /users/42
curl -v --http2 --cacert server_certs/self_signed/public_ca.pem https://127.0.0.1:8443/users/42

# HTTP/2 GET /greet?user_name=alice (Query<GreetQuery>-Extractor, optionales age: Option<u8>)
curl -v --http2 --cacert server_certs/self_signed/public_ca.pem "https://127.0.0.1:8443/greet?user_name=alice"
curl -v --http2 --cacert server_certs/self_signed/public_ca.pem "https://127.0.0.1:8443/greet?user_name=alice&age=17"

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
