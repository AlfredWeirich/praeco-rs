# Deep Dive: Praeco Rust Workspace

Stand: 2026-08-19

## Executive Summary

Der Workspace ist ein technisch ambitionierter Zero-Trust-Gateway-Stack mit mehreren klar getrennten Crates:

- Gateway/Reverse Proxy (`server`)
- gemeinsame TLS-/Client-Hilfen (`common`)
- mTLS-/gRPC-Client (`client`)
- Relay/Tunnel (`relay-server`)
- gRPC Reflection/Beispiele (`grpc_reflection`)
- JWT- und Zertifikatswerkzeuge (`jwt_creator`, `cert_decoder`)

Die Kryptografie-Bausteine sind grundsätzlich sinnvoll gewählt: Rustls/WebPKI, mTLS, EdDSA-JWT, CRL-Unterstützung im Gateway sowie Limits und Middleware für den HTTP-Pfad. Die größte Unsicherheit liegt nicht in der Wahl der Primitive, sondern in der effektiven Vertrauensgrenze zur Laufzeit: Konfigurationskombinationen können Sicherheitsannahmen aushebeln, und einige Identitäten werden nicht stark genug an die erlaubten Ressourcen gebunden.

`cargo check --workspace` und `cargo test --workspace` waren erfolgreich. Die Tests meldeten jedoch für alle geprüften Binaries und Bibliotheken `0 tests`; damit ist der grüne Build kein Nachweis für die sicherheitskritischen Laufzeitflüsse.

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

### Upstream-TLS ist optional und damit leicht falsch zu konfigurieren

**Schweregrad: Mittel**

Der Connector unterstützt `http://` und `https://`. Wenn ein produktiver Upstream als HTTP konfiguriert wird, können JWTs und weitergeleitete Identitätsinformationen im Klartext übertragen werden.

**Verbesserung:** `require_tls = true` als Produktionsdefault, explizite Development-Ausnahme, Allowlist für Upstream-Schemata und Tests gegen HTTP-Upstreams.

### CRL-Strategie ist nicht über alle TLS-Grenzen konsistent

**Schweregrad: Mittel bis hoch**

Das Gateway berücksichtigt CRLs über den WebPKI-Client-Verifier. Für den Relay-Control-Plane-Verifier ist im geprüften Code keine gleichwertige CRL-/OCSP-Prüfung erkennbar. Revokationen können dadurch am Relay länger wirksam bleiben als am Gateway.

**Verbesserung:** Einheitliche Revocation-Policy für Gateway und Relay, dokumentierte Aktualisierungsintervalle, Fehlerverhalten bei nicht ladbarer oder veralteter CRL sowie Rotationstests.

### Relay liest den TLS-ClientHello nur einmal

**Schweregrad: Mittel**

Der Datenpfad versucht, SNI aus einem einzelnen begrenzten Read zu gewinnen. TCP garantiert weder Vollständigkeit noch Segmentgrenzen. Ein fragmentierter ClientHello kann deshalb unter realen Netzbedingungen fälschlich verworfen werden.

**Verbesserung:** Bis zu einer festen Maximalgröße akkumulieren, bis SNI sicher erkannt ist oder ein kurzer Handshake-Timeout abläuft. Kein unbeschränktes Puffern.

### Session-IDs verwenden keinen expliziten CSPRNG

**Schweregrad: Mittel**

DeviceAuth-Session-IDs werden mit `fastrand` erzeugt. Für Login-/Polling-Sessions sollte die Nichtvorhersagbarkeit explizit kryptografisch garantiert sein.

**Verbesserung:** `OsRng` verwenden, mindestens 128 Bit Zufall erzeugen, Session-IDs nur gekürzt oder gehasht loggen und Ablauf/Einmaligkeit serverseitig erzwingen.

### Fehlende Konfiguration fällt beim Relay auf gefährliche Defaults zurück

**Schweregrad: Mittel bis hoch**

Wenn die Relay-Konfiguration fehlt, werden Bindings auf öffentlichen Adressen und Entwicklungs-Zertifikatspfade verwendet. Das ist als lokale Demo bequem, als Produktionsfehler aber gefährlich.

**Verbesserung:** Produktionsstart ohne explizite Konfiguration abbrechen; Development-Defaults nur mit `--development` oder einer gleichwertigen expliziten Markierung aktivieren. Bind-Adresse, Zertifikatspfade und Berechtigungen beim Start ausgeben und validieren.

### Absolute Include-Pfade machen die Gateway-Konfiguration nicht reproduzierbar

**Schweregrad: Mittel**

`Config.toml` verweist auf einen absoluten Pfad außerhalb dieses Repositories. Auf anderen Hosts kann der Start scheitern oder ein anderer Konfigurationsbestand geladen werden.

**Verbesserung:** Relative oder deploymentseitig injizierte Pfade verwenden, Include-Verzeichnisse whitelisten und alle zusammengeführten Serverdefinitionen vor Aktivierung validieren.

### Panics statt kontrollierter Start- und Laufzeitfehler

**Schweregrad: Mittel**

Mehrere Pfade verwenden `unwrap`, `expect` oder `panic!` beim Laden von Zertifikaten, Schlüsseln, JWT-Parametern und Router-Konfiguration. Ein fehlerhaftes Secret oder Hot-Reload-Input beendet dann den Prozess statt einen diagnostizierbaren Fehler zurückzugeben.

**Verbesserung:** Öffentliche Lade-/Validierungsfunktionen auf `Result` umstellen, Fehler mit Kontext versehen und Panics auf unveränderliche Programm-Invarianten beschränken.

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
- `cargo test --workspace`: erfolgreich, aber keine ausgeführten Tests in den geprüften Targets.
- Suche nach Testdateien außerhalb von `target`: keine separaten Testdateien gefunden.
- Prüfung, ob `Cargo.lock` vorhanden ist: vorhanden.
- Prüfung auf lokale Tools: `cargo-audit` und `cargo-deny` nicht installiert.

Nicht durchgeführt:

- dynamischer Penetrationstest
- Lasttest
- Prüfung der nicht im Repository enthaltenen Include-Konfiguration
- CVE-/Lizenzreport der Dependencies
- Prüfung von Git-Historie, Logarchiven, Zertifikatsinhalten und Produktionsdeployment

## Gesamturteil

Der Workspace ist eine brauchbare technische Basis, aber noch nicht ausreichend beweiskräftig für eine Sicherheitsfreigabe. Der wichtigste nächste Schritt ist keine große Umstrukturierung, sondern das Erzwingen der Sicherheitsinvarianten an den Konfigurations- und Protokollgrenzen. Sobald P0 umgesetzt und durch Integrationstests abgesichert ist, lohnt sich die weitere Optimierung von Observability, Reloading und Lastverhalten.
