# Deep-Dive: OpenTelemetry & Jaeger in the Rust Backend

This document describes the architecture, functionality, and performance aspects of our observability setup using **OpenTelemetry (OTel)** and **Jaeger** in an asynchronous Rust environment (Tokio, Hyper, Tonic).

---

## 1. What is Observability?

Observability in distributed systems typically relies on three pillars:
1. **Metrics:** Aggregated numbers (e.g., CPU utilization, Requests per Second).
2. **Logs:** Individual events as text (e.g., "Server started", "Database error").
3. **Traces:** The path of a *single* request through the entire distributed system.

**OpenTelemetry** is the vendor-neutral standard (Cloud Native Computing Foundation) that defines how this data is generated, collected, and exported. 
**Jaeger** is the backend (database and Web UI) in our setup that receives the traces and visually displays them as a Gantt chart.

---

## 2. How Tracing Works: Spans and Contexts

A **Trace** consists of a tree of **Spans**.
* A **Span** represents a contiguous unit of time (e.g., a database call or processing an entire HTTP request). It has a start time, a duration, and metadata (attributes).
* A Span can have **Child Spans**. 
* To link Spans across network boundaries (e.g., from the reverse proxy to the chat backend), the **Trace Context** is injected into the HTTP headers (known as *Context Propagation*).

### Our Architecture

We leverage the Rust ecosystem around `tracing`, `tower-http`, and `opentelemetry`.

1. **The Root Span (Entry):** 
   The `tower-http` middleware (TraceLayer) intercepts every HTTP request in the proxy and backend. It creates the root span (e.g., `POST /chat.ChatService/StreamMessages`).
   *Special Note:* We manually extract the `TraceContext` from the HTTP headers here (`opentelemetry::global::get_text_map_propagator`) so the backend knows to attach to an existing trace from the proxy.

2. **Sub-Spans (Method Level):** 
   Using the `#[tracing::instrument(skip_all)]` macro, we instrument asynchronous handler methods (like `do_stream_messages` or `authorize_request`). Rust automatically creates a child span when these functions are called.

---

## 3. Performance & Overhead (Why Rust Shines Here)

In many dynamic languages, deep tracing can noticeably slow down the system. **In Rust, the overhead for this setup is microscopically small (in the single-digit microsecond range).**

Here are the reasons why:

### A. Zero-Cost Filtering (Lazy Evaluation)
The Rust `tracing` crate uses macros. When a span or log is filtered out by the configured log level (e.g., `INFO`) because the span is set to `DEBUG`, the program only checks a tiny, atomic boolean flag at runtime. The arguments (formatting strings, cloning variables) are **not evaluated at all**. The CPU overhead is practically zero.

### B. Memory Efficiency (`skip_all`)
By default, `#[tracing::instrument]` would attempt to save all function arguments in the span as attributes. For gRPC requests (which can contain huge payloads or certificates), constant cloning and formatting would strain RAM and CPU.
By using the **`skip_all`** flag, we instruct Rust to only generate the time counter and function name as the span framework, leaving the payload data completely alone.

### C. Asynchronous Batch Export
How does the data get to Jaeger? If the backend synchronously waited for a network response from Jaeger on every request, it would be fatal for latency.
Instead, we use `install_batch(opentelemetry_sdk::runtime::Tokio)`. 
* When a span is completed, it is simply placed in an extremely fast ring buffer in memory.
* A separate Tokio background thread collects these spans and sends them in large blocks (batches) asynchronously via gRPC to Jaeger.
* The actual client (user) has long since received their response.

---

## 4. Controlling Configuration (`Config.toml`)

Our system allows tracing to be controlled live without code changes:

```toml
enable_opentelemetry = true
jaeger_endpoint = "http://localhost:4317"
otel_log_level = "info"
```

* **`enable_opentelemetry`**: Turns the export to Jaeger completely on or off.
* **`otel_log_level`**: Controls the `EnvFilter`. 
  * At `"info"`, all requests and our instrumented business logic are sent to Jaeger.
  * At `"debug"`, internal events from third-party libraries (`hyper`, `rustls`) are **additionally** exported. These appear in Jaeger as "Logs" (Events) **inside** the individual spans, which is excellent for debugging low-level network issues (e.g., TLS handshake errors).

---

## 5. Streaming Considerations (gRPC / SSE)

A visual phenomenon occurs in Jaeger with streaming endpoints (e.g., `StreamMessages`). 
Since a stream by definition remains open for a long time (often minutes or hours), the root span of the HTTP middleware measures exactly this total time. 

If you see a 9-second trace in Jaeger where a sub-span (like `authorize_request`) appears at the beginning, this does **not** mean the authorization took 9 seconds. The authorization ran in 1-2 milliseconds. The remaining 9-second long span is simply the "waiting time" of the open server connection before the client (or server) closed the stream.

---

## Summary
This setup offers the best of both worlds: **Maximum Observability** when troubleshooting in microservices, paired with **Maximum Performance**, as no hot paths are blocked by synchronous I/O and Rust's zero-cost abstractions are fully utilized.

---

## 6. Starting and Accessing Jaeger

For Jaeger to receive OTLP data (OpenTelemetry) from the proxy and backend, it must be started with the OTLP collector enabled.

### Start Command (macOS ARM64 Example)
```bash
./jaeger-1.60.0-darwin-arm64/jaeger-all-in-one --collector.otlp.enabled=true
```

### Ports and UI
Once Jaeger is running, it listens on several ports:
* **`4317` (gRPC):** Our Rust servers send their traces here. (This is the port configured in `Config.toml` as `jaeger_endpoint`).
* **`16686` (HTTP):** This is the **Web UI**.

**Viewing Results:**
Simply open your browser and navigate to:
👉 **[http://localhost:16686](http://localhost:16686)**

There, you can select your server (e.g., `chatapp_server` or `praeco-rs`) under "Service" on the left and click "Find Traces" to see the visualized spans.
