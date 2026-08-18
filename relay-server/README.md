# Praeco SNI Relay Server

Der **Praeco SNI Relay Server** ist eine hochperformante, leichtgewichtige Komponente für **Zero-Trust Reverse Tunneling**. Er ermöglicht es, Praeco-Instanzen sicher hinter restriktiven Firewalls oder NAT-Routern (z.B. im Heimnetzwerk oder im Unternehmensnetzwerk) zu betreiben, ohne Ports nach außen öffnen zu müssen.

## Architektur & Funktionsweise

Der Relay Server operiert als reiner **Layer-4 Router** mit SNI-Erkennung (Server Name Indication) und terminiert den TLS-Traffic der Endnutzer **nicht**. Dies garantiert echte End-to-End-Verschlüsselung (E2EE) bis in die lokale Praeco-Instanz.

Das System besteht aus zwei Ebenen:

1. **Control Plane (Port 7001 / mTLS + Yamux):**
   - Lokale Praeco-Instanzen verbinden sich ausgehend (outbound) mit diesem Port.
   - Die Verbindung ist zwingend durch strenges gegenseitiges TLS (mTLS) abgesichert.
   - Praeco meldet über ein einfaches Textprotokoll (`REGISTER <sni_domain>\n`), für welche Domain es verantwortlich ist (z.B. `api.aweirich.eu`).
   - Anschließend wird die Verbindung auf das **Yamux** Multiplexing-Protokoll umgeschaltet, sodass mehrere unabhängige Streams durch eine einzige TCP-Verbindung geleitet werden können.

2. **Data Plane (Port 443 / SNI-Routing):**
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

## Konfiguration (Umgebungsvariablen)

Der Relay Server benötigt zwingend Zertifikate für die Control Plane, um sich gegenüber der Praeco-Instanz zu authentifizieren und deren Zertifikate zu überprüfen.

Folgende Umgebungsvariablen werden unterstützt:

| Variable | Standardwert (Fallback) | Beschreibung |
| :--- | :--- | :--- |
| `RELAY_CA_CERT` | `server_certs/self_signed/myca.pem` | Pfad zur Root-CA, mit der die Client-Zertifikate von Praeco geprüft werden. |
| `RELAY_SERVER_CERT` | `server_certs/self_signed/fullchain_self.pem` | Pfad zum Server-Zertifikat (Public Key) für die Control Plane. |
| `RELAY_SERVER_KEY` | `server_certs/self_signed/privkey_self.pem` | Pfad zum privaten Schlüssel des Servers. |

## Ausführen

```bash
# Starten mit den Default-Zertifikatspfaden
cargo run --bin=relay-server

# Starten mit spezifischen Zertifikaten (z.B. für die Produktion)
RELAY_CA_CERT=/etc/ssl/myca.pem \
RELAY_SERVER_CERT=/etc/ssl/server.pem \
RELAY_SERVER_KEY=/etc/ssl/server.key \
./target/release/relay-server
```

> **Wichtig:** Auf Linux/Mac-Systemen benötigt der Prozess Root-Rechte (bzw. `CAP_NET_BIND_SERVICE`), um auf Port 443 (Data Plane) lauschen zu dürfen.
