# Deep-Dive: OpenTelemetry & Jaeger im Rust Backend

Dieses Dokument beschreibt die Architektur, Funktionsweise und Performance-Aspekte unseres Observability-Setups mit **OpenTelemetry (OTel)** und **Jaeger** in einer asynchronen Rust-Umgebung (Tokio, Hyper, Tonic).

---

## 1. Was ist Observability?

Observability (Beobachtbarkeit) in verteilten Systemen stützt sich typischerweise auf drei Säulen:
1. **Metriken (Metrics):** Aggregierte Zahlen (z. B. CPU-Auslastung, Requests per Second).
2. **Logs:** Einzelne Ereignisse als Text (z. B. "Server gestartet", "Datenbankfehler").
3. **Traces (Spuren):** Der Weg eines *einzelnen* Requests durch das gesamte verteilte System.

**OpenTelemetry** ist der herstellerunabhängige Standard (Cloud Native Computing Foundation), der definiert, wie diese Daten generiert, gesammelt und exportiert werden. 
**Jaeger** ist in unserem Setup das Backend (die Datenbank und Web-UI), welches die Traces empfängt und visuell als Gantt-Diagramm darstellt.

---

## 2. Wie Tracing funktioniert: Spans und Kontexte

Ein **Trace** besteht aus einem Baum von **Spans**.
* Ein **Span** repräsentiert eine zusammenhängende Zeiteinheit (z. B. einen Datenbankaufruf oder die Bearbeitung eines kompletten HTTP-Requests). Er hat einen Startzeitpunkt, eine Dauer und Metadaten (Attribute).
* Ein Span kann **Child-Spans** (Kinder) haben. 
* Um Spans über Netzwerkgrenzen hinweg (z. B. vom Reverse-Proxy zum Chat-Backend) zu verknüpfen, wird der **Trace-Kontext** in die HTTP-Header injiziert (sogenannte *Context Propagation*).

### Unsere Architektur

Wir nutzen das Rust-Ökosystem um `tracing`, `tower-http` und `opentelemetry`.

1. **Der Root-Span (Eingang):** 
   Die `tower-http` Middleware (TraceLayer) fängt jeden HTTP-Request im Proxy und im Backend ab. Sie erstellt den Root-Span (z. B. `POST /chat.ChatService/StreamMessages`).
   *Besonderheit:* Wir extrahieren hierbei manuell den `TraceContext` aus den HTTP-Headern (`opentelemetry::global::get_text_map_propagator`), damit das Backend weiß, dass es an einen bestehenden Trace des Proxys anknüpfen soll.

2. **Sub-Spans (Methoden-Ebene):** 
   Mit dem Makro `#[tracing::instrument(skip_all)]` instrumentieren wir asynchrone Handler-Methoden (wie `do_stream_messages` oder `authorize_request`). Rust erstellt beim Aufruf dieser Funktionen automatisch einen Child-Span.

---

## 3. Performance & Overhead (Warum Rust hier glänzt)

In vielen dynamischen Sprachen kann tiefgreifendes Tracing das System merklich ausbremsen. **In Rust ist der Overhead für dieses Setup mikroskopisch klein (im einstelligen Mikrosekunden-Bereich).**

Hier sind die Gründe dafür:

### A. Zero-Cost Filtering (Lazy Evaluation)
Das Rust `tracing`-Crate nutzt Makros. Wenn ein Span oder ein Log durch das eingestellte Log-Level (z. B. `INFO`) herausgefiltert wird (weil der Span auf `DEBUG` steht), prüft das Programm zur Laufzeit nur ein winziges, atomares Boolean-Flag. Die Argumente (Strings formatieren, Variablen klonen) werden **gar nicht erst evaluiert**. Der CPU-Overhead ist praktisch null.

### B. Speichereffizienz (`skip_all`)
Standardmäßig würde `#[tracing::instrument]` versuchen, alle Argumente einer Funktion im Span als Attribute abzuspeichern. Bei gRPC-Requests (die riesige Payloads oder Zertifikate enthalten können) würde das ständige Klonen und Formatieren RAM und CPU belasten.
Durch das Flag **`skip_all`** weisen wir Rust an, nur den Zeitzähler und den Funktionsnamen als Span-Rahmen zu erzeugen, aber die Nutzdaten völlig in Ruhe zu lassen.

### C. Asynchroner Batch-Export
Wie kommen die Daten zu Jaeger? Würde das Backend bei jedem Request synchron auf eine Netzwerkantwort von Jaeger warten, wäre das fatal für die Latenz.
Stattdessen nutzen wir `install_batch(opentelemetry_sdk::runtime::Tokio)`. 
* Wenn ein Span beendet wird, wird er lediglich in einen extrem schnellen Ringbuffer im Arbeitsspeicher gelegt.
* Ein separater Tokio-Hintergrundthread sammelt diese Spans und schickt sie in großen Blöcken (Batches) asynchron per gRPC an Jaeger.
* Der eigentliche Client (Nutzer) hat seine Antwort da schon längst erhalten.

---

## 4. Konfiguration steuern (`Config.toml`)

Unser System erlaubt es, das Tracing live und ohne Code-Änderungen zu steuern:

```toml
[telemetry]
enable_opentelemetry = true
jaeger_endpoint = "http://localhost:4317"
otel_log_level = "info"
```

* **`enable_opentelemetry`**: Schaltet den Export an Jaeger komplett ein oder aus.
* **`otel_log_level`**: Steuert den `EnvFilter`. 
  * Bei `"info"` werden alle Requests und unsere instrumentierten Business-Logiken an Jaeger geschickt.
  * Bei `"debug"` werden **zusätzlich** interne Ereignisse aus Fremd-Bibliotheken (`hyper`, `rustls`) exportiert. Diese tauchen in Jaeger als "Logs" (Events) **innerhalb** der einzelnen Spans auf, was hervorragend ist, um Low-Level Netzwerkprobleme (z.B. TLS-Handshake-Fehler) zu debuggen.

---

## 5. Besonderheiten bei Streaming (gRPC / SSE)

Ein optisches Phänomen in Jaeger tritt bei Streaming-Endpunkten auf (z. B. `StreamMessages`). 
Da ein Stream per Definition über lange Zeit offen bleibt (oft Minuten oder Stunden), misst der Root-Span der HTTP-Middleware exakt diese Gesamtzeit. 

Wenn du in Jaeger einen 9-Sekunden-Trace siehst, bei dem ein Sub-Span (wie `authorize_request`) augenscheinlich am Anfang steht, bedeutet dies **nicht**, dass die Autorisierung 9 Sekunden gedauert hat. Die Autorisierung lief in 1-2 Millisekunden ab. Der restliche, 9 Sekunden lange Span ist lediglich die "Wartezeit" der offenen Serververbindung, bevor der Client (oder Server) den Stream geschlossen hat.

---

## Zusammenfassung
Dieses Setup bietet das Beste aus zwei Welten: **Maximum Observability** bei der Fehlersuche in Microservices, gepaart mit **Maximum Performance**, da keine Hot-Paths durch synchrone I/O blockiert werden und Rusts Zero-Cost-Abstraktionen voll ausgeschöpft werden.

---

## 6. Jaeger starten und aufrufen

Damit Jaeger die OTLP-Daten (OpenTelemetry) vom Proxy und Backend empfangen kann, muss es mit aktiviertem OTLP-Kollektor gestartet werden.

### Startbefehl (macOS ARM64 Beispiel)
```bash
./jaeger-1.60.0-darwin-arm64/jaeger-all-in-one --collector.otlp.enabled=true
```

### Ports und UI
Sobald Jaeger läuft, lauscht es auf verschiedenen Ports:
* **`4317` (gRPC):** Hierhin senden unsere Rust-Server ihre Traces. (Das ist der Port, der in der `Config.toml` als `jaeger_endpoint` eingetragen ist).
* **`16686` (HTTP):** Das ist die **Web-Oberfläche (UI)**.

**Ergebnisse ansehen:**
Öffne einfach deinen Browser und navigiere zu:
👉 **[http://localhost:16686](http://localhost:16686)**

Dort kannst du links unter "Service" deinen Server (z.B. `chatapp_server` oder `praeco-rs`) auswählen und auf "Find Traces" klicken, um die visualisierten Spans zu sehen.
