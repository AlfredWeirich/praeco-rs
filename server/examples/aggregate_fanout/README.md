# Praeco `backend_type = "aggregate"` Parallel Fan-Out Example

Eigenständiges Beispiel-Crate mit vollständiger [Config.toml](Config.toml) und [Cargo.toml](Cargo.toml), das Praecos deklarativen Parallel-Fan-Out-Aggregator (`backend_type = "aggregate"`) Ende-zu-Ende demonstriert.

## Architektur & Datenfluss

```text
  Client (GET / POST /api/dashboard)
         │
         ▼
  Praeco Gateway (`AggregateFanoutGateway`, 127.0.0.1:8080, aus Config.toml)
         │  ├── TraceIdLayer         (W3C traceparent + x-trace-id)
         │  ├── IpFilterLayer        (127.0.0.1/32, ::1/128)
         │  ├── MaxPayloadLayer      (1 MiB Limit)
         │  └── SecurityHeadersLayer (CSP, HSTS, X-Content-Type-Options, ...)
         │
         ├──▶ Target "user" (grpc_transcoding, required = true, timeout_ms = 1000)
         │      └─ gRPC Server Reflection (v1alpha) -> Tonic `user.UserService/GetUser` (127.0.0.1:50051)
         │
         └──▶ Target "notifications" (rest, method = "GET", required = false, timeout_ms = 500)
                └─ REST `/v1/notifications?tenant=acme` (127.0.0.1:8081)
         │
         ▼
  Aggregiertes JSON (`{"user": {...}, "notifications": {...}}`)
```

## Ausführen

### 1. Selbstlaufende End-to-End-Demo (Standardmodus)

Startet beide lokalen Mock-Backends (`user` mit Tonic + Server Reflection sowie `notifications` mit Hyper HTTP/1.1) und das über `Config.toml` konfigurierte Praeco-Gateway, führt 6 Prüfszenarien aus und fährt alles geordnet über `CancellationToken` herunter:

```bash
cargo run -p aggregate_fanout
```

Demonstrierte Szenarien:
1. `GET /health` → `200 OK`
2. `POST /api/dashboard?limit=2&tenant=evil&extra=1` mit `{"user":{"user_id":"42"}}` + `Authorization`/`Cookie`/`If-None-Match` → `200 OK`, `tenant=acme` überschreibt `tenant=evil`, `extra=1` wird gefiltert, Client-Credentials werden gestrippt
3. `GET /api/dashboard?user_id=42&limit=1&tenant=evil` → `200 OK` (Query-Parameter als JSON für gRPC + gefilterte Query für REST)
4. `POST /api/dashboard?limit=slow` → `200 OK` mit `"notifications": null` und `"_errors.notifications.status": 504` (Graceful Degradation)
5. `POST /api/dashboard` mit `{"user":{"user_id":"missing"}}` → `404 Not Found` mit sanitiziertem Body `"Not Found"` (`required = true` + `expose_upstream_errors = false`)
6. `POST /api/dashboard` mit flachem `{"user_id":"42"}` → `400 Bad Request` (`payload_mode = "keyed"` lehnt unbekannte Top-Level-Keys ab)

### 2. Tests ausführen

```bash
cargo test -p aggregate_fanout
```

### 3. Dauerhafter Server-Modus (`--serve`) für `curl`

```bash
cargo run -p aggregate_fanout -- --serve
```

Danach in einem zweiten Terminal testen:

```bash
# 1) POST keyed Fan-Out + Query-Precedence & Allowlist
curl -i -X POST 'http://127.0.0.1:8080/api/dashboard?limit=2&tenant=evil&extra=1' \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer client-secret' \
  -H 'Cookie: session=abc' \
  -d '{"user":{"user_id":"42"}}'

# 2) GET mit Query-Parametern
curl -i 'http://127.0.0.1:8080/api/dashboard?user_id=42&limit=1&tenant=evil'

# 3) Optionales Target Timeout -> Graceful Degradation (_errors)
curl -i -X POST 'http://127.0.0.1:8080/api/dashboard?limit=slow' \
  -H 'Content-Type: application/json' \
  -d '{"user":{"user_id":"42"}}'

# 4) Required gRPC-Fehler (sanitiziert durch expose_upstream_errors = false)
curl -i -X POST 'http://127.0.0.1:8080/api/dashboard' \
  -H 'Content-Type: application/json' \
  -d '{"user":{"user_id":"missing"}}'

# 5) Keyed-Payload-Ablehnung bei flachem JSON
curl -i -X POST 'http://127.0.0.1:8080/api/dashboard' \
  -H 'Content-Type: application/json' \
  -d '{"user_id":"42"}'

# 6) Gateway-Health-Check
curl -i 'http://127.0.0.1:8080/health'
```

## Hinweis zu `Config.toml` mit `praeco-rs`

Die enthaltene [Config.toml](Config.toml) ist eine reguläre, vollständige Praeco-Konfiguration und kann direkt an die Praeco-CLI übergeben werden (sofern auf `127.0.0.1:50051` und `127.0.0.1:8081` entsprechende Backends laufen):

```bash
cargo run -p praeco-rs -- server/examples/aggregate_fanout/Config.toml
```
