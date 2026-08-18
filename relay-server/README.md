# Praeco SNI Relay Server

Der **Praeco SNI Relay Server** ist eine hochperformante, leichtgewichtige Komponente für **Zero-Trust Reverse Tunneling**. Er ermöglicht es, Praeco-Instanzen sicher hinter restriktiven Firewalls oder NAT-Routern (z.B. im Heimnetzwerk oder im Unternehmensnetzwerk) zu betreiben, ohne Ports nach außen öffnen zu müssen.

## Architektur & Funktionsweise

Der Relay Server operiert als reiner **Layer-4 Router** mit SNI-Erkennung (Server Name Indication) und terminiert den TLS-Traffic der Endnutzer **nicht**. Dies garantiert echte End-to-End-Verschlüsselung (E2EE) bis in die lokale Praeco-Instanz.

Das System besteht aus zwei Ebenen:

1. **Control Plane (Standard Port 7001 / mTLS + Yamux):**
   - Lokale Praeco-Instanzen verbinden sich ausgehend (outbound) mit diesem Port.
   - Die Verbindung ist zwingend durch strenges gegenseitiges TLS (mTLS) abgesichert.
   - Praeco meldet über ein einfaches Textprotokoll (`REGISTER <sni_domain>\n`), für welche Domain es verantwortlich ist (z.B. `api.aweirich.eu`).
   - Anschließend wird die Verbindung auf das **Yamux** Multiplexing-Protokoll umgeschaltet, sodass mehrere unabhängige Streams durch eine einzige TCP-Verbindung geleitet werden können.
   - **Health Checks:** Der Relay-Server überwacht die Tunnel-Gesundheit durch aktives Ping-Verhalten. Alle 30 Sekunden werden Yamux-Streams getestet, um unsauber beendete TCP-Verbindungen (Praeco-Zombies) aufzuspüren und aus dem System zu entfernen.

2. **Data Plane (Standard Port 443 / SNI-Routing):**
   - Nimmt öffentliche Client-Verbindungen (z.B. aus dem Webbrowser) unverschlüsselt auf TCP-Ebene an.
   - Der Server liest den initialen TLS-Handshake (`ClientHello`), um die angefragte SNI (Domain) zu extrahieren.
   - Er sucht nach einer aktiven Praeco-Verbindung für diese SNI.
   - Es wird asynchron ein neuer **Yamux-Stream** in der bestehenden Control-Plane-Verbindung geöffnet.
   - Der gesamte TCP-Traffic wird blind durch diesen Stream geleitet. Praeco terminiert das TLS lokal.

## Kompilieren

Da der Relay-Server als eigenständiges Projekt im Workspace läuft, kann er ganz normal über Cargo gebaut werden:

```bash
cargo build --release -p relay-server
```

Das fertige Binary liegt danach in `target/release/relay-server`.

## Konfiguration (`RelayConfig.toml`)

Der Relay Server wird über eine TOML-Datei namens `RelayConfig.toml` (im Arbeitsverzeichnis) gesteuert. Fehlt die Datei, lädt er Standardwerte.
Hier ist eine Beispielkonfiguration:

```toml
control_plane_addr = "0.0.0.0:7001"
data_plane_addr = "0.0.0.0:443"

# Zertifikate für die Control-Plane Authentifizierung
ca_cert_path = "server_certs/self_signed/myca.pem"
server_cert_path = "server_certs/self_signed/fullchain_self.pem"
server_key_path = "server_certs/self_signed/privkey_self.pem"

# Tracing / OpenTelemetry
enable_opentelemetry = false
jaeger_endpoint = "http://localhost:4317"
otel_log_level = "info"
```

### Logging & Tracing
Analog zu Praeco ist der Relay-Server in **OpenTelemetry** integriert. Sind die OTLP-Parameter konfiguriert und `enable_opentelemetry = true` gesetzt, schickt der Relay-Server seine strukturierten Kontext-Logs (wie z.B. SNI, Client IPs) direkt in das zentrale Jaeger-Backend. Das ermöglicht ein nahtloses Tracing über die gesamte Netzwerk-Infrastruktur hinweg!

## Ausführen

```bash
# Starten mit den Einstellungen aus der RelayConfig.toml
cargo run --bin=relay-server
```

> **Wichtig:** Auf Linux/Mac-Systemen benötigt der Prozess Root-Rechte (bzw. `CAP_NET_BIND_SERVICE`), wenn er wie im Standard konfiguriert auf Port 443 (Data Plane) lauscht. Durch Anpassen der `data_plane_addr` in der Config kann dies bei Bedarf auf unprivilegierte Ports verlegt werden.
