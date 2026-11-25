# HTTPS & HTTP/3 Embedded Web Server Example

Eigenständiges Beispiel-Crate, das `praeco-rs` mit `default-features = false, features = ["web"]` und **ohne `Config.toml`** einbindet:

- **Dual-Stack HTTPS:** HTTP/1.1 + HTTP/2 (TCP) und HTTP/3 (QUIC/UDP) auf Port `8443` (konfigurierbar via `PORT`).
- **Universeller Router & Extractors (`praeco_rs::web`):** Endpunkte sind schlanke `async fn`s mit typisierten Extractors (`Query<T>`, `Path<T>`, `Json<T>`, `TraceId`, `UserRoles`, `ClientOids`, `ClientSan`, `JwtClaims`), `IntoResponse` und automatischer `AllowedPathes`- & `Rbac`-Ableitung für WAF und RBAC-Middleware.
- **Saubere Trennung:** `src/main.rs` verdrahtet nur noch die Routen und startet den Server; Endpunkte & DTOs liegen in `src/endpoints.rs`, Server-Konfiguration und Shutdown in `src/bootstrap.rs`.
- **Sicherheitslayer & OID-RBAC:** `TraceId`, `SecurityHeaders`, `AltSvc`, `IpFilter` (`127.0.0.1/32`, `::1/128`), `RateLimiter:TokenBucket`, `ConcurrencyLimit`, `MaxPayload`, `Decompression`, `Inspection` (`AllowedPathes`), optional `JwtAuth` (`OptionalJwt` via `PRAECO_JWT_PUBLIC_KEY`) sowie fail-closed `Rbac` (`RbacLayer` + `OptionalClientCert` via `PRAECO_CLIENT_CA`).

## Starten & Testen

Vom Workspace-Root aus (der Stack-Test nutzt automatisch eine ephemere `TestPki` ohne lokale `server_certs/`):

```bash
cargo test -p https_web_server
```

Für `cargo run` werden Zertifikate über `PRAECO_TLS_CERT` / `PRAECO_TLS_KEY` oder unter `server_certs/self_signed/praeco_public.{pem,key}` erwartet. Optional lassen sich mTLS-OID-RBAC (`PRAECO_CLIENT_CA`) oder optionales JWT (`PRAECO_JWT_PUBLIC_KEY`, `PRAECO_JWT_ISSUER`, `PRAECO_JWT_AUDIENCE`) aktivieren:

```bash
# Standard (ohne Client-CA / JWT; /admin/stats liefert 403 Forbidden)
cargo run -p https_web_server

# Mit mTLS-OID-RBAC (OptionalClientCert gegen client_certs/ca.cert.pem)
PRAECO_CLIENT_CA=client_certs/ca.cert.pem cargo run -p https_web_server

# Mit optionalem JWT (OptionalJwt gegen jwt_creator/public_key.pem)
PRAECO_JWT_PUBLIC_KEY=jwt_creator/public_key.pem cargo run -p https_web_server
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

# Identität & aufgelöste Rollen prüfen (öffentlich via ["*"])
curl -v --http2 --cacert server_certs/self_signed/public_ca.pem https://127.0.0.1:8443/whoami

# RBAC-geschützter Admin-Endpunkt ohne Admin-Rolle (erwartet: 403 Forbidden)
curl -i --http2 --cacert server_certs/self_signed/public_ca.pem https://127.0.0.1:8443/admin/stats

# mTLS mit Client-Zertifikat (OID 1.3.6.1.4.1.65111.1 -> Admin, erfordert PRAECO_CLIENT_CA=client_certs/ca.cert.pem)
# Hinweis: Zertifikate lassen sich bei Bedarf mit `./client_certs/generate_mtls_oid_certs.sh -o 1` erzeugen.
curl -v --http2 --cacert server_certs/self_signed/public_ca.pem \
  --cert client_certs/client.cert.pem --key client_certs/client.key.pem \
  https://127.0.0.1:8443/admin/stats

# Optionales JWT mit Admin-OID "1" (erfordert PRAECO_JWT_PUBLIC_KEY=jwt_creator/public_key.pem)
# Passendes Token erzeugen (TTL <= 86400 s, Issuer=praeco-idp, Audience=https-web-server):
cargo run -p praeco-jwt-creator -- \
  --private-key jwt_creator/private_key.pem \
  --public-key jwt_creator/public_key.pem \
  --iss praeco-idp --aud https-web-server --sub alice --oids 1 --ttl1 3600 --ttl2 3600
curl -v --http2 --cacert server_certs/self_signed/public_ca.pem \
  -H "Authorization: Bearer $(cat jwt_creator/token1.jwt)" \
  https://127.0.0.1:8443/admin/stats
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
