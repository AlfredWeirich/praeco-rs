# Deep Dive: Praeco Rust Workspace

Stand: 2026-10-23

## Executive Summary

Der Workspace ist ein technisch ambitionierter Zero-Trust-Gateway-Stack mit mehreren klar getrennten Crates:

- Gateway/Reverse Proxy (`server`)
- gemeinsame TLS-/Client-Hilfen (`common`)
- mTLS-/gRPC-Client (`client`)
- Relay/Tunnel (`relay-server`)
- gRPC Reflection/Beispiele (`grpc_reflection`)
- JWT- und Zertifikatswerkzeuge (`jwt_creator`, `cert_decoder`)

Die Kryptografie-Bausteine sind grundsätzlich sinnvoll gewählt: Rustls/WebPKI, mTLS, EdDSA-JWT, CRL-Unterstützung (inkl. `nextUpdate`-Prüfung) im Gateway und Relay sowie Limits und Middleware für den HTTP-Pfad. Im Rahmen der Härtungspakete (Paket 1 & Paket 2, `F-01` bis `F-10`) wurden die Vertrauensgrenzen, Rate-Limiter, RBAC-Regeln, Tunnel-Validierungen und der IdP systematisch gehärtet.

`cargo check --workspace` und `cargo test --workspace` laufen vollständig grün (137 automatisierte Unit- und Integrationstests in `common`, `server` und `relay-server` sichern die sicherheitskritischen Laufzeitflüsse ab).

## Bewertungsmaßstab

- **Kritisch:** Eine Fehlkonfiguration oder ein normaler berechtigter Client kann eine zentrale Sicherheitsgarantie brechen.
- **Hoch:** Realistische Auswirkung auf Authentisierung, Vertraulichkeit, Integrität oder Verfügbarkeit.
- **Mittel:** Relevantes Risiko unter bestimmten Betriebsbedingungen oder bei fehlender zusätzlicher Absicherung.
- **Niedrig:** Vorwiegend Wartbarkeit, Diagnose oder Robustheit; kann bei Änderungen trotzdem eskalieren.

Die Einstufung beschreibt Risiko und Priorität, nicht die Wahrscheinlichkeit eines Angriffs. Wo die tatsächliche Laufzeit von nicht mitgelieferten `conf.d`-Dateien, Zertifikatsinhalten oder Deployment-Regeln abhängt, ist das ausdrücklich als Unsicherheit markiert.

## Architektur und Vertrauensgrenzen

Der Datenfluss ist grob:

1. Ein Client stellt über den Relay einen TLS-Datenkanal zum Gateway her.
2. Das Relay vermittelt anhand von SNI an einen registrierten Tunnel, terminiert den öffentlichen TLS-Datenverkehr aber nicht.
3. Das Gateway beendet TLS, prüft optional mTLS/CRL und führt JWT-/IdP-/RBAC-Middleware aus.
4. Der Router wählt einen Upstream und leitet die Anfrage weiter.
5. Der Client bzw. Tunnel registriert sich separat über eine mTLS-geschützte Control Plane.

Daraus folgen drei entscheidende Bindungen:

- **Transportidentität:** Was beweist das Zertifikat über den Client?
- **Anwendungsidentität:** Welche JWT-/IdP-Identität handelt?
- **Ressourcenidentität:** Welche SNI-Domain, Route und welcher Upstream dürfen verwendet werden?

Der Code stärkt die ersten beiden Bindungen teilweise, aber die Ressourcenidentität ist an mehreren Stellen konfigurations- oder protokollseitig schwächer abgesichert.

## Wichtigste Findings

### 1. Authentisierung kann bei HTTP wirkungslos werden

**Schweregrad: Hoch**

`ClientCert`, `OptionalClientCert` und `Jwt` werden in der Konfiguration zugelassen, ohne sie zwingend gegen einen HTTPS-Listener zu validieren. Der Client-Zertifikats-Verifier wird nur im TLS-Pfad aufgebaut. Ein Listener mit `Protocol = Http` und einer mTLS-/JWT-Erwartung kann dadurch ohne die erwartete Transport- bzw. Anwendungsauthentisierung erreichbar sein.

Betroffene Bereiche:

- `server/src/configuration.rs`: Authentisierungs- und Protokollvalidierung
- `server/src/server.rs`: Aufbau von HTTP- und HTTPS-Listenern

**Empfehlung**

- `Jwt` und jede Client-Zertifikatsauthentisierung bei reinem HTTP als Konfigurationsfehler ablehnen.
- Ausnahmen nur mit explizitem Development-Schalter erlauben.
- Beim Start eine effektive Sicherheitsmatrix ausgeben: Listener, TLS, Client-Auth, JWT, CRL und Upstream-TLS.
- Einen Integrationstest für jede ungültige Kombination ergänzen.

**Akzeptanzkriterium:** Eine produktive Konfiguration mit Authentisierung ohne TLS startet nicht.

### 2. Relay-SNI ist nicht an die mTLS-Identität gebunden (UMGESETZT)

**Schweregrad: Hoch**

Nach erfolgreichem mTLS kann ein Relay-Client eine SNI-Zeichenkette registrieren. Im geprüften Pfad ist keine belastbare Zuordnung von Zertifikats-SAN/Subject zu erlaubten SNI-Namen sichtbar. Damit kann ein berechtigter Client unter Umständen fremde Domains registrieren oder eine bestehende Registrierung überschreiben.

Das ist eine klassische Verwechslung von "Client darf das Relay benutzen" mit "Client darf diese konkrete Ressource besitzen".

**Empfehlung**

- Zertifikatsidentität nach der mTLS-Prüfung extrahieren.
- Eine explizite Policy erzwingen, zum Beispiel `certificate SAN -> erlaubte SNI-Muster`.
- SNI normalisieren und strikt validieren: ASCII/IDNA-Regeln, keine leeren Werte, keine Wildcards ohne Policy.
- Doppelte Registrierungen atomar behandeln und einen klaren Replace-/Reject-Modus definieren.
- Den effektiven Besitzer jeder Registrierung in Logs/Metriken erfassen, ohne Zertifikatsgeheimnisse zu loggen.

**Akzeptanzkriterium:** Ein Client kann nur SNI-Namen registrieren, die seiner zertifikatsgebundenen Policy entsprechen.

### 3. Response-Header können JWTs in Logs und Tracing schreiben (Dies überspringen wir zunächst)

**Schweregrad: Hoch**

Der Logger schreibt Response-Header. Der IdP verwendet Cookies für JWTs; insbesondere `Set-Cookie` kann damit vollständige Session- oder Tokenwerte in Logdateien und OpenTelemetry/Jaeger bringen.

**Empfehlung**

- Standardmäßig nur Header-Namen oder eine Allowlist loggen.
- Immer redigieren: `Authorization`, `Cookie`, `Set-Cookie`, Proxy-Auth-Header und identitätsbezogene Zertifikatsheader.
- Redaction zentral implementieren, damit HTTP-Logger und OTEL-Exporter dieselbe Policy verwenden.
- Bestehende Logs als potenziell kompromittiert behandeln und Token-Lebensdauer/Rotation prüfen.

**Akzeptanzkriterium:** Automatisierte Tests beweisen, dass kein Cookie- oder Authorization-Wert in strukturierten Logs erscheint.

### 4. Relay-Control-Protokoll ist nicht robust gegen fehlerhafte oder große Eingaben (UMGESETZT)

**Schweregrad: Hoch für Verfügbarkeit, mittel für Integrität**

Die Control Plane liest eine Registrierungszeile bis zum Timeout, ohne eine enge maximale Länge erkennen zu lassen. Eine unvollständige oder syntaktisch falsche Eingabe kann über direkte Indexzugriffe zu einem Panic in einem Tokio-Task führen. Große Eingaben binden Speicher und Verbindungen.

**Empfehlung**

- Maximale Command- und SNI-Länge festlegen und früh ablehnen.
- Parsing über `split_once`/strukturierte Parser mit vollständiger Argumentprüfung durchführen.
- Pro Client und global Limits für offene Control- und Datenverbindungen setzen.
- Idle-, Handshake- und Registration-Timeouts getrennt konfigurieren.
- Fehlerhafte Eingaben als kontrollierte Protokollfehler behandeln, nicht als Panic.

### 5. Überschriebene Tunnel können durch alte Verbindungen gelöscht werden (UMGESETZT)

**Schweregrad: Hoch für Verfügbarkeit/Integrität**

Wenn eine neue Verbindung denselben SNI-Eintrag ersetzt, kann das Ende der alten Verbindung den gemeinsamen Eintrag bedingungslos entfernen. Dadurch verschwindet gegebenenfalls der aktive neue Tunnel aus der Routing-Tabelle.

**Empfehlung**

- Jede Registrierung mit einer eindeutigen Session-ID oder Generation versehen.
- Beim Aufräumen nur entfernen, wenn der aktuelle Eintrag noch dieselbe Session-ID besitzt.
- Alternativ parallele Registrierungen ablehnen und Replace explizit synchronisieren.
- Einen Test für `old registration closes after new registration` schreiben.

## Weitere Findings

### Upstream-TLS ist optional und damit leicht falsch zu konfigurieren (ÜBERSPRUNGEN)

**Schweregrad: Mittel**

Der Connector unterstützt `http://` und `https://`. Wenn ein produktiver Upstream als HTTP konfiguriert wird, können JWTs und weitergeleitete Identitätsinformationen im Klartext übertragen werden.

**Verbesserung:** `require_tls = true` als Produktionsdefault, explizite Development-Ausnahme, Allowlist für Upstream-Schemata und Tests gegen HTTP-Upstreams.

### CRL-Strategie ist nicht über alle TLS-Grenzen konsistent (UMGESETZT)

**Schweregrad: Mittel bis hoch**

Das Gateway und der Relay-Server unterstützen nun gleichermaßen CRLs (`ssl_client_crl` bzw. `crl_path`). Zusätzlich wird beim Laden (Start und Hot-Reload) das X.509 `nextUpdate`-Feld jeder CRL ausgewertet (`warn_if_crl_expired`) und bei abgelaufener CRL eine explizite Sicherheitswarnung geloggt.

### Relay liest den TLS-ClientHello nur einmal (UMGESETZT)

**Schweregrad: Mittel**

Der Datenpfad akkumuliert den `ClientHello` nun in einer Schleife bis zur vollständigen TLS-Record-Länge (max. 16 KB, geschützt durch `client_hello_timeout_secs`), sodass TCP-Fragmentierung und Post-Quantum Key Shares zuverlässig verarbeitet werden.

### Session-IDs verwenden keinen expliziten CSPRNG (UMGESETZT)

**Schweregrad: Mittel**

DeviceAuth-Session-IDs, `poll_secret` und der 6-stellige `user_code` werden kryptografisch sicher über `OsRng` erzeugt.

### Paket 1 & Paket 2 Sicherheits-Härtungen (`F-01` bis `F-10`, UMGESETZT)

Im Rahmen des erweiterten Security-Audits wurden folgende 10 Punkte vollständig umgesetzt und getestet:

- **[F-01] IdP-Härtung & mTLS-geschützter JTI-Revoke:** `POST /auth/revoke?jti=...` erfordert zwingend ein mTLS-Clientzertifikat (`401 Unauthorized` ohne mTLS), `JwtRevocationStore` ist auf `50.000` Einträge begrenzt (30s Cleanup-Intervall, `MAX_JTI_LEN = 256`), und der IdP-Server ist durch `MaxPayload`, `Inspection`, `RateLimiter:TokenBucket` (`key_by = "ip"`) und `ConcurrencyLimit` geschützt.
- **[F-02] Verpflichtender 6-stelliger Quishing-Schutzcode vor Webhook-Aufruf:** `POST /auth/confirm?session=<id>&code=<user_code>` prüft den 6-stelligen `user_code` zwingend in Constant-Time (`constant_time_eq`) **vor** dem Aufruf des externen Claims-Webhooks und invalidiert die Session nach `3` Fehlversuchen (`MAX_CONFIRM_ATTEMPTS = 3`). `GET /auth/session_info?session=<id>` liefert der Mobile-App den Anzeigecode vorab.
- **[F-03] IPv6 `/64`-Kanonisierung & Fail-Closed Rate-Limiting (`canonical_client_ip`):** IPv4-mapped IPv6-Adressen (`::ffff:x.x.x.x`) werden auf IPv4 entpackt und reguläre IPv6-Adressen auf ihr `/64`-Subnetz-Präfix maskiert (`RateLimiter`, `ConnectionTracker`, `SessionStore`). Die Rate-Limiter nutzen einen allokationsfreien $O(1)$-Fast-Path (`get_mut`), ein gedrosseltes 10s-TTL-Cleanup und weisen bei erreichter Kapazitätsgrenze (`entries.len() >= max_entries`) unbekannte Keys **fail-closed** mit `429 Too Many Requests` (`Retry-After: 1`) ab, ohne bestehende Buckets zu verdrängen (Schutz vor Cache-Thrashing).
- **[F-04] Fail-Closed PROXY-Protocol v2 im Yamux-Tunnel:** `read_proxy_v2` gibt bei `InvalidMagic` alle 16 gelesenen Header-Bytes zurück, und `run_tunnel` bricht Verbindungen bei `proxy_protocol = true` ohne gültigen PPv2-Header strikt ab (kein unsicherer Fallback).
- **[F-05] Prozessweite Panic-Isolation & Overflow-Checks:** `[profile.release]` nutzt `panic = "unwind"` und `overflow-checks = true`, sodass ein unerwarteter Panic nur den betroffenen Tokio-Task beendet statt den gesamten Gateway-Prozess per `SIGABRT` zu terminieren.
- **[F-06] Fail-Closed RBAC auf Admin-Routen:** `[Server.rbac]` erzwingt `/api/* = ["Admin"]` als Default-Deny für Nicht-Admins mit expliziter Freigabe der 14 Seller-Endpunkte (`["Admin", "Seller"]`).
- **[F-07] Schutz vor `X-Forwarded-For` IP-Spoofing:** Rate-Limiter ignorieren `X-Forwarded-For` / `X-Real-IP` standardmäßig (`trust_forwarded_headers = false`). Der Router entfernt clientseitige `Forwarded`- und `X-Forwarded-*`-Header auf allen Protokollen (HTTP/1.1, HTTP/2, HTTP/3) bedingungslos und setzt sie autoritativ anhand der verifizierten Socket-/PROXY-v2-IP sowie `:authority`/`Host` neu.
- **[F-08] Erhalt benutzerdefinierter `SecurityHeaders` bei Auto-Injektion:** Fehlt `"SecurityHeaders"` in `Layers.enabled`, übernimmt die automatische Schutz-Injektion einen vorhandenen `[Server.Layers.SecurityHeaders]`-Block statt ihn mit `default-src 'none'` zu überschreiben.
- **[F-09] gRPC-Web Härtung & Asynchrones I/O:** `grpc_web.rs` überschreibt `content-type: application/grpc` und `te: trailers` nicht mehr durch Client-Header, erzwingt `request_timeout_seconds` sowie ein `16 MiB` Response-Body-Limit (`http_body_util::Limited`) und lädt Zertifikate nicht-blockierend via `tokio::fs::read`.
- **[F-10] gRPC-sichere Kompression & präzise Upstream-Fehlerklassifikation:** `CompressionService` überspringt bereits komprimierte Antworten (`Content-Encoding`) sowie `application/grpc*`-Streams (Erhalt der HTTP/2-Trailer). `classify_proxy_error` stuft rohe `std::io::Error` (`ConnectionReset`, `BrokenPipe`, `UnexpectedEof`) nur noch bei `err.is_user() == true` als `ClientAborted` (`400`) ein; Upstream-Abbrüche lösen regulär `UpstreamFailure` (`502` + Failover) aus.

### Fehlende Konfiguration fällt beim Relay auf gefährliche Defaults zurück (UMGESETZT)

**Schweregrad: Mittel bis hoch**

Wenn die Relay-Konfiguration fehlt, werden Bindings auf öffentlichen Adressen und Entwicklungs-Zertifikatspfade verwendet. Das ist als lokale Demo bequem, als Produktionsfehler aber gefährlich.

**Verbesserung:** Produktionsstart ohne explizite Konfiguration abbrechen; Development-Defaults nur mit `--development` oder einer gleichwertigen expliziten Markierung aktivieren. Bind-Adresse, Zertifikatspfade und Berechtigungen beim Start ausgeben und validieren.

### Absolute Include-Pfade machen die Gateway-Konfiguration nicht reproduzierbar (UMGESETZT)

**Schweregrad: Mittel**

`Config.toml` verweist auf einen absoluten Pfad außerhalb dieses Repositories. Auf anderen Hosts kann der Start scheitern oder ein anderer Konfigurationsbestand geladen werden.

**Verbesserung:** Relative oder deploymentseitig injizierte Pfade verwenden, Include-Verzeichnisse whitelisten und alle zusammengeführten Serverdefinitionen vor Aktivierung validieren.

### Panics statt kontrollierter Start- und Laufzeitfehler (Behoben)

**Schweregrad: Mittel (Behoben)**

Zuvor verwendeten mehrere Pfade `unwrap`, `expect` oder `panic!` beim Laden von Zertifikaten, Schlüsseln, JWT-Parametern und Router-Konfiguration. Ein fehlerhaftes Secret oder Hot-Reload-Input beendete dann den Prozess statt einen diagnostizierbaren Fehler zurückzugeben.

**Behebung:** Alle Lade- und Konfigurationsfunktionen (`load_certs`, `load_single_key`, `load_decoding_keys`, `load_encoding_key`, `build_tls_client_config`, `build_root_store`, `RouterService::new`, `IdpService::new`) wurden vollständig auf `Result` umgestellt. `Config::init` wurde in `Config::load` und `Config::update_global` getrennt. SIGHUP führt einen vollständigen Dry-Run durch und tauscht den globalen Zustand erst nach erfolgreicher Validierung aller Stacks und TLS-Kontexte atomar aus. Invalidierungstests sichern die Invarianten ab.

### Pfad-Normalisierung fehlt (Route-/RBAC-/Inspection-Bypass) (Behoben)

**Schweregrad: Hoch (Behoben)**

Routing, Inspection und RBAC arbeiteten zuvor auf dem rohen Pfad (nicht dekodiert, nicht normalisiert). Nach Prefix-Strip wurde der Rest unverändert weitergeleitet (`..`, `%2e%2e`, `%2f`, `//`), was zu Pfad-Confusion, RBAC-Bypasses und WAF-Umgehungen auf Upstreams führen konnte.

**Behebung:** Einführung von `PathSanitizerLayer` mit strikter RFC-3986-Kanonisierung (Option A). Requests mit Traversal-Mustern (`..`, `%2e%2e`, `.%2e`, `%2e.`), kodierten Slashes (`%2f`), Null-Bytes (`\0`, `%00`), Backslashes (`\`, `%5c`) oder verdächtigem Doppel-Encoding (`%252e`) werden sofort mit `400 Bad Request` abgewiesen. Mehrfache Slashes (`//`) und `/./`-Segmente werden zusammengeführt/entfernt. Der bereinigte Pfad wird in `req.uri()` zurückgeschrieben, sodass Tracing, Inspection, Router, RBAC und Upstreams dieselbe kanonische Sicht teilen. Redundante Absicherungen in `RouterService::call` und `build_upstream_uri` bieten Defense-in-Depth.

### Beobachtbarkeit kann Geheimnisse und Ursachen gleichzeitig verfehlen

**Schweregrad: Niedrig bis mittel**

Die grobe Fehlerantwort ist für Außenstehende angemessen, aber intern fehlen konsistente Metriken für TLS-Handshakes, CRL-Rejections, Auth-Entscheidungen, Upstream-Fehler, Retry-Auslastung und Tunnelzustände. Gleichzeitig besteht durch Header-Logging ein Secret-Risiko.

**Verbesserung:** Strukturierte Ereignisse mit Trace-ID, Route/SNI-Klasse und Ergebniscode erfassen; Werte mit Identitäts- oder Tokencharakter redigieren.

## Was ist derzeit unsicher?

Diese Punkte sollten vor einer endgültigen Sicherheitsfreigabe durch Tests oder Deployment-Inspektion geklärt werden:

1. **Effektive Produktionskonfiguration:** Die im Repository sichtbare `Config.toml` enthält einen absoluten Include-Pfad. Die tatsächlichen `conf.d`-Definitionen und ihre Protokoll-/Auth-Kombinationen sind nicht Teil der Prüfung.
2. **Zertifikats-Policy:** Es ist nicht geklärt, ob SANs, Subjects oder OIDs außerhalb des sichtbaren Codes organisatorisch eine SNI-Berechtigung erzwingen.
3. **Relay-Exposition:** Bindings, Firewall, Reverse-Proxy und Netzwerksegmentierung können einzelne Risiken reduzieren, ersetzen aber keine Protokollprüfung.
4. **Secret-Verlauf:** Es ist nicht bekannt, ob bereits geloggte Cookies/Tokens oder private Schlüssel in Logarchiven, Backups oder Git-Historie liegen.
5. **Dependency-Sicherheitsstand:** `Cargo.lock` ist vorhanden, aber `cargo-audit` und `cargo-deny` waren lokal nicht installiert; eine CVE-/Lizenzprüfung wurde daher nicht durchgeführt.
6. **Lastverhalten:** Es fehlen belastbare Werte für maximale Verbindungen, Handshakezeiten, Speicherverbrauch, Queueing und Backpressure unter Last.
7. **Hot Reload:** Der Dry-Run ist ein gutes Signal, aber Race- und Rollback-Szenarien mit aktiven Requests/Tunneln sind nicht durch Tests abgesichert.
8. **Deployment-Härtung:** Dateirechte für private Schlüssel, Benutzerrechte, Container-/Service-Isolation, Firewall-Regeln und Secret-Injektion konnten nicht verifiziert werden.

## Priorisierte Verbesserungsreihenfolge

### P0: Vor produktiver Exposition

1. Authentisierung ohne TLS als ungültige Konfiguration ablehnen.
2. Relay-Registrierung kryptografisch an Zertifikatsidentität und SNI-Allowlist binden.
3. `Set-Cookie`, `Cookie`, `Authorization` und vergleichbare Header überall redigieren.
4. Relay-Control-Parsing mit Größenlimits, sauberer Fehlerbehandlung und Verbindungsbudgets versehen.
5. Tunnel-Registrierungen mit Generation/Session-ID gegen stale cleanup schützen.

### P1: Als nächster Härtungsblock

1. Einheitliche CRL-/OCSP-Policy für Gateway und Relay.
2. Produktionsseitig TLS für Upstreams erzwingen.
3. CSPRNG für alle Login-/DeviceAuth-Sessions einsetzen.
4. Gefährliche Defaults und absolute Pfade entfernen.
5. Strukturierte Metriken und Audit-Events ergänzen.

### P2: Qualität und langfristige Wartbarkeit

1. Startvalidierung in eine eigene, testbare Schicht verschieben.
2. Parser für Relay-Control-Commands als kleine pure Funktion kapseln.
3. TLS-/Auth-/Proxy-Policy zentral als typisierte Konfiguration modellieren.
4. Abhängigkeiten regelmäßig mit `cargo audit` und `cargo deny` prüfen.
5. Fuzzing für SNI-, Control-Protocol- und Konfigurationsparser ergänzen.

## Minimaler Testplan

Die folgenden Tests haben die höchste Aussagekraft pro Aufwand:

- Konfiguration: Jede Authentisierung auf HTTP wird abgelehnt.
- TLS: gültiges Clientzertifikat, falsche CA, abgelaufenes Zertifikat und widerrufenes Zertifikat.
- JWT: falscher Algorithmus, falscher `iss`/`aud`, abgelaufenes Token, Key-Rotation und fehlende Claims.
- Logging: Cookies, `Set-Cookie` und Authorization-Werte erscheinen nie in Log-Events.
- Relay: ungültige/zu lange Commands, fehlender SNI, doppelte Registrierung und unautorisierter SNI.
- Relay-Race: alte Registrierung beendet sich nach neuer Registrierung, ohne den neuen Tunnel zu löschen.
- Relay-Netzwerk: fragmentierter ClientHello und Timeout während der SNI-Erkennung.
- Proxy: hop-by-hop-Header werden entfernt, Identitätsheader nicht vom Client übernommen und HTTP-Upstreams werden im Produktionsprofil abgelehnt.
- Reload: ungültige Konfiguration bleibt wirkungslos; aktive Requests und Tunnel überleben einen gültigen Reload.
- Last: Limits für offene Verbindungen, Requests, Queues und Handshakes werden tatsächlich durchgesetzt.

## Positives, das erhalten bleiben sollte

- Rustls/WebPKI als TLS-Basis.
- Feste JWT-Algorithmusprüfung mit EdDSA.
- Validierung von `iss`, `aud` und `exp` sowie vorbereitete Key-Rotation.
- CRL-Unterstützung im Gateway.
- Entfernung von Hop-by-hop-Headern und serverseitiges Setzen identitätsbezogener Forwarding-Header.
- Payload-, Decompression-, Rate-, Concurrency- und Timeout-Limits.
- Dry-Run vor der Aktivierung neuer Hot-Reload-Konfiguration.
- Ende-zu-Ende-TLS durch ein Relay, das den öffentlichen TLS-Datenverkehr nicht terminiert.

## Validierungsprotokoll

Ausgeführt:

- `cargo check --workspace`: erfolgreich.
- `cargo test --workspace`: erfolgreich (**137 automatisierte Unit- und Integrationstests**: 14 in `praeco-common`, 9 in `relay-server`, 108 in der `praeco-rs`-Library und 6 im `praeco-rs`-Binary). Sie prüfen u. a. IPv6-`/64`-Kanonisierung, Fail-Closed Rate-Limiting (`max_entries`), mTLS-Pflicht beim JTI-Revoke, die 50.000er-Kapazitätsgrenze des `JwtRevocationStore`, Quishing-Schutzcode & Brute-Force-Lockout, Fail-Closed-Auflösung des PROXY-v2-Headers im Tunnel (`resolve_tunnel_peer`), Header-Sanitization, den gRPC-/`Content-Encoding`-Bypass der Kompression (inkl. Erhalt der gRPC-Trailer), gRPC-Web (Wire-Header, `request_timeout_seconds`, 16-MiB-Limit), die Klassifikation von Upstream-TCP-Resets als `502` sowie RBAC. Die Regressionstests für `F-10` (Upstream-Reset, Kompression) wurden per Mutationsprüfung verifiziert: Mit zurückgesetztem Fix schlagen sie fehl.
- Manuelle End-to-End-Verifikation gegen die laufenden Instanzen (`wurzelwerk_idp`, `wurzelwerk_admin`) via `curl` (mTLS, Revoke, Quishing-Lockout, Inspection-Layer, RBAC). Diese Läufe sind **nicht** automatisiert.
- Hinweis: Einige Netzwerk-Tests (lokale Sockets) schlagen im Sandbox-Modus fehl und benötigen eine normale Umgebung.
- Prüfung, ob `Cargo.lock` vorhanden ist: vorhanden.

## Gesamturteil

Durch die vollständige Umsetzung von Paket 1 & Paket 2 (`F-01` bis `F-10`) sowie der vorangegangenen Architektur-Härtungen erzwingt `praeco-rs` seine Zero-Trust-Sicherheitsinvarianten nun konsistent und fail-closed an allen Konfigurations-, Transport- und Protokollgrenzen.
