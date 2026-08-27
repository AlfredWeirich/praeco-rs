# Praeco SNI Relay Server

Der **Praeco SNI Relay Server** ist eine hochperformante, leichtgewichtige Komponente für **Zero-Trust Reverse Tunneling**. Er ermöglicht es, Praeco-Instanzen sicher hinter restriktiven Firewalls oder NAT-Routern (z.B. im Heimnetzwerk oder im Unternehmensnetzwerk) zu betreiben, ohne Ports nach außen öffnen zu müssen.

## Architektur & Funktionsweise

Der Relay Server operiert als reiner **Layer-4 Router** mit SNI-Erkennung (Server Name Indication) und terminiert den TLS-Traffic der Endnutzer **nicht**. Dies garantiert echte End-to-End-Verschlüsselung (E2EE) bis in die lokale Praeco-Instanz.

### Sicherheitsvorteile der Zero-Trust Architektur
1. **Keine offenen Inbound-Ports (Unsichtbarkeit):** Der Praeco-Server muss nicht aus dem Internet erreichbar sein. Automatisierte Port-Scans und OS-Level Exploits laufen ins Leere, da der Server physisch "nicht existiert" (er verbindet sich nur ausgehend zum Relay).
2. **Isolierter "Blast Radius" (DDoS Schutz):** Layer-3/4 DDoS-Angriffe treffen ausschließlich den Relay-Server in der Cloud. Das Heimnetzwerk / Rechenzentrum bleibt unberührt.
3. **Echte End-to-End Verschlüsselung (E2EE):** Im Gegensatz zu Cloudflare oder Nginx terminiert der Relay den Traffic nicht. Bei einer Kompromittierung des Relays sieht der Angreifer nur verschlüsselten Datenmüll. Die privaten TLS-Zertifikate verlassen den Praeco-Server nie.
4. **Minimale Angriffsfläche (Attack Surface):** Da der Relay nur TCP-Streams routet und keine HTTP(s)-Header parst, ist er immun gegen komplexe Layer-7 Exploits (wie *HTTP/2 Rapid Reset* oder Header Smuggling).

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

## Einschränkungen: HTTP/3 und Encrypted Client Hello (ECH)

Da der Relay-Server als reiner **Layer-4 TCP-Proxy** arbeitet und TLS nicht terminiert, gibt es bei neuen Protokollen und Standards folgende architektonische Einschränkungen zu beachten:

* **HTTP/3 (QUIC):** Der Relay-Server unterstützt aktuell **kein HTTP/3**. QUIC basiert auf UDP, der Relay-Server lauscht jedoch ausschließlich auf TCP-Ports und tunnelt Traffic über TCP-basierte Yamux-Streams. Eingehender UDP-Traffic wird ignoriert.
* **Encrypted Client Hello (ECH):** Neue Browser verschlüsseln zunehmend die SNI. Da der Relay-Server den Datenstrom nicht entschlüsseln kann (ihm fehlen die privaten TLS-Schlüssel), sieht er bei aktiviertem ECH nur die unverschlüsselte "Outer SNI" (einen Dummy-Namen).
  * **Sicherheitshinweis:** Clients nutzen ECH **nur dann**, wenn du als Betreiber ECH-Konfigurationen aktiv über das DNS (via `HTTPS`-Records, Typ 65) ankündigst. Solange du solche Records in deiner DNS-Zone nicht anlegst, fallen alle Clients auf das herkömmliche Klartext-SNI zurück, womit das Routing des Relay-Servers problemlos funktioniert.

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
