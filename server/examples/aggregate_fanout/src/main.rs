#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

//! # Praeco `backend_type = "aggregate"` Parallel Fan-Out Example
//!
//! Eigenständiges Beispiel-Crate, das Praecos deklarativen Fan-Out-Aggregator
//! (`backend_type = "aggregate"`) anhand einer vollständigen [`Config.toml`]
//! Ende-zu-Ende demonstriert — inklusive gemischter Sub-Targets:
//!
//! ```text
//!   HTTP-Client (GET / POST auf /api/dashboard)
//!          │
//!          ▼
//!   Praeco API Gateway (Config.toml -> RouterService)
//!          │  ├── TraceIdLayer         (erzeugt W3C traceparent / x-trace-id)
//!          │  ├── IpFilterLayer        (Loopback-Allowlist 127.0.0.1/32)
//!          │  ├── MaxPayloadLayer      (1 MiB Request-Limit)
//!          │  └── SecurityHeadersLayer (CSP, HSTS, X-Content-Type-Options, ...)
//!          │
//!          ├──▶ [key = "user",          required = true,  timeout_ms = 1000]
//!          │       └─ gRPC-Transcoding (Server Reflection v1alpha) ──▶ Tonic `user.UserService/GetUser`
//!          │
//!          └──▶ [key = "notifications", required = false, timeout_ms = 500]
//!                  └─ REST GET /v1/notifications?tenant=acme&limit=… ──▶ Hyper REST-Backend
//!          │
//!          ▼
//!   Aggregiertes JSON: { "user": { ... }, "notifications": { ... } }
//!   (oder bei Timeout des optionalen Targets: "notifications": null + "_errors")
//! ```
//!
//! ## Aufruf
//!
//! ```bash
//! # Selbstlaufende End-to-End-Demo (6 Szenarien, fährt danach sauber herunter):
//! cargo run -p aggregate_fanout
//!
//! # Dauerhafter Server-Modus zum manuellen Testen mit curl (beenden mit Ctrl+C):
//! cargo run -p aggregate_fanout -- --serve
//!
//! # Optional mit eigener Konfigurationsdatei:
//! cargo run -p aggregate_fanout -- --config /pfad/zu/Config.toml
//! ```

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use anyhow::{Context as _, bail};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode, header};
use hyper_util::client::legacy::Client;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::rt::{TokioExecutor, TokioIo};
use praeco_rs::SrvBody;
use praeco_rs::configuration::{Config, RouteBackendType};
use prost::Message;
use prost_reflect::prost_types::{
    DescriptorProto, FieldDescriptorProto, FileDescriptorProto, FileDescriptorSet,
    MethodDescriptorProto, ServiceDescriptorProto,
    field_descriptor_proto::{Label, Type},
};
use serde::Serialize;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;
use tonic::body::Body as TonicBody;
use tonic::server::{Grpc as TonicServer, NamedService, UnaryService};
use tonic::{Request as TonicRequest, Response as TonicResponse, Status};
use tonic_prost::ProstCodec;
use tonic_reflection::server::Builder as ReflectionBuilder;
use tower::Service;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

// ============================================================================
//  CLI-Argumente
// ============================================================================

/// Geparste Kommandozeilen-Optionen des Beispiels.
struct CliArgs {
    /// Bei `true` laufen Backends + Gateway weiter bis `Ctrl+C`.
    serve: bool,
    /// Pfad zur zu ladenden Praeco-`Config.toml`.
    config_path: String,
}

/// Ermittelt den Standardpfad zu `Config.toml` dieses Beispiel-Crates.
fn default_config_path() -> String {
    let manifest_config = concat!(env!("CARGO_MANIFEST_DIR"), "/Config.toml");
    if Path::new(manifest_config).exists() {
        manifest_config.to_string()
    } else {
        "Config.toml".to_string()
    }
}

/// Parst die CLI-Argumente (`--serve`, `--config <path>`, `--help`).
fn parse_cli_args() -> anyhow::Result<Option<CliArgs>> {
    let mut serve = false;
    let mut config_path = default_config_path();
    let mut args = std::env::args().skip(1);

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--serve" => serve = true,
            "--config" => {
                let Some(path) = args.next() else {
                    bail!("Fehlender Pfad nach --config");
                };
                config_path = path;
            }
            "--help" | "-h" => {
                println!(
                    "Nutzung: aggregate_fanout [--serve] [--config <pfad/zur/Config.toml>]\n\
                     \n\
                     Optionen:\n\
                       --serve           Startet Backends + Praeco-Gateway dauerhaft bis Ctrl+C\n\
                       --config <pfad>   Pfad zur Config.toml (Standard: Crate-Config.toml)\n\
                       -h, --help        Zeigt diese Hilfe an"
                );
                return Ok(None);
            }
            other => bail!("Unbekanntes Argument: {other} (siehe --help)"),
        }
    }

    Ok(Some(CliArgs { serve, config_path }))
}

// ============================================================================
//  Protobuf-Nachrichten & Server-Reflection-Schema (ohne protoc / build.rs)
// ============================================================================

/// Request-Payload für `user.UserService/GetUser`.
#[derive(Clone, PartialEq, Message)]
struct UserReq {
    #[prost(string, tag = "1")]
    user_id: String,
}

/// Response-Payload für `user.UserService/GetUser`.
#[derive(Clone, PartialEq, Message)]
struct UserRes {
    #[prost(string, tag = "1")]
    id: String,
    #[prost(string, tag = "2")]
    name: String,
    #[prost(string, tag = "3")]
    role: String,
}

/// Erzeugt ein binäres `FileDescriptorSet` für `user.proto`, damit Praeco das
/// gRPC-Schema per Server Reflection (`ListServices` / `FileContainingSymbol`)
/// automatisch entdecken kann.
fn build_user_descriptor_set_bytes() -> Vec<u8> {
    let string_field = |name: &str, number: i32| FieldDescriptorProto {
        name: Some(name.to_string()),
        json_name: Some(name.to_string()),
        number: Some(number),
        label: Some(Label::Optional as i32),
        r#type: Some(Type::String as i32),
        ..Default::default()
    };

    let file = FileDescriptorProto {
        name: Some("user.proto".to_string()),
        package: Some("user".to_string()),
        syntax: Some("proto3".to_string()),
        message_type: vec![
            DescriptorProto {
                name: Some("UserReq".to_string()),
                field: vec![string_field("user_id", 1)],
                ..Default::default()
            },
            DescriptorProto {
                name: Some("UserRes".to_string()),
                field: vec![
                    string_field("id", 1),
                    string_field("name", 2),
                    string_field("role", 3),
                ],
                ..Default::default()
            },
        ],
        service: vec![ServiceDescriptorProto {
            name: Some("UserService".to_string()),
            method: vec![MethodDescriptorProto {
                name: Some("GetUser".to_string()),
                input_type: Some(".user.UserReq".to_string()),
                output_type: Some(".user.UserRes".to_string()),
                ..Default::default()
            }],
            ..Default::default()
        }],
        ..Default::default()
    };

    FileDescriptorSet { file: vec![file] }.encode_to_vec()
}

// ============================================================================
//  Mock-Backend 1: Tonic gRPC-Server mit Server Reflection (`user.UserService`)
// ============================================================================

/// Simuliert einen internen gRPC-User-Microservice (`user.UserService/GetUser`).
#[derive(Clone)]
struct UserBackendService;

impl NamedService for UserBackendService {
    const NAME: &'static str = "user.UserService";
}

impl Service<Request<TonicBody>> for UserBackendService {
    type Response = Response<TonicBody>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<TonicBody>) -> Self::Future {
        let rpc_path = req.uri().path().to_string();
        Box::pin(async move {
            if rpc_path != "/user.UserService/GetUser" {
                return Ok(Status::unimplemented(format!("Unknown RPC: {rpc_path}")).into_http());
            }

            struct Handler;
            impl UnaryService<UserReq> for Handler {
                type Response = UserRes;
                type Future =
                    Pin<Box<dyn Future<Output = Result<TonicResponse<UserRes>, Status>> + Send>>;

                fn call(&mut self, request: TonicRequest<UserReq>) -> Self::Future {
                    Box::pin(async move {
                        let trace_id = request
                            .metadata()
                            .get("x-trace-id")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("<none>")
                            .to_string();
                        let traceparent = request
                            .metadata()
                            .get("traceparent")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("<none>")
                            .to_string();
                        let uid = request.into_inner().user_id;

                        info!(
                            target: "backend.grpc",
                            user_id = %uid,
                            x_trace_id = %trace_id,
                            traceparent = %traceparent,
                            "UserService/GetUser verarbeitet"
                        );

                        if uid == "missing" {
                            // Demonstriert, dass `expose_upstream_errors = false` diesen
                            // internen Fehlertext vor dem Client verbirgt ("Not Found").
                            return Err(Status::not_found(
                                "secret internal user directory details: db_shard=7",
                            ));
                        }

                        let effective_id = if uid.is_empty() {
                            "anonymous".to_string()
                        } else {
                            uid
                        };
                        Ok(TonicResponse::new(UserRes {
                            id: effective_id.clone(),
                            name: format!("Alice ({effective_id})"),
                            role: "Admin".to_string(),
                        }))
                    })
                }
            }

            let mut grpc = TonicServer::new(ProstCodec::<UserRes, UserReq>::default());
            Ok(grpc.unary(Handler, req).await)
        })
    }
}

/// Startet den lokalen Tonic gRPC-Server inkl. `v1alpha` + `v1` Server Reflection auf `addr`.
#[tracing::instrument(skip(cancel), err)]
async fn spawn_grpc_backend(addr: SocketAddr, cancel: CancellationToken) -> anyhow::Result<()> {
    let fds = build_user_descriptor_set_bytes();
    // Praeco's `build_grpc_pool` fragt `grpc.reflection.v1alpha.ServerReflection` ab;
    // wir registrieren sowohl v1alpha als auch v1 für volle Kompatibilität.
    let reflection_v1alpha = ReflectionBuilder::configure()
        .register_encoded_file_descriptor_set(&fds)
        .build_v1alpha()
        .context("Konnte gRPC Reflection v1alpha Service nicht bauen")?;
    let reflection_v1 = ReflectionBuilder::configure()
        .register_encoded_file_descriptor_set(&fds)
        .build_v1()
        .context("Konnte gRPC Reflection v1 Service nicht bauen")?;

    tokio::spawn(async move {
        if let Err(err) = tonic::transport::Server::builder()
            .add_service(reflection_v1alpha)
            .add_service(reflection_v1)
            .add_service(UserBackendService)
            .serve_with_shutdown(addr, cancel.cancelled())
            .await
        {
            error!(target: "backend.grpc", error = %err, "gRPC-Backend beendet mit Fehler");
        }
    });

    Ok(())
}

// ============================================================================
//  Mock-Backend 2: Hyper REST-Server (`/v1/notifications`)
// ============================================================================

/// Einzelne Benachrichtigung in der REST-Antwort.
#[derive(Serialize)]
struct NotificationItem {
    id: u64,
    message: String,
}

/// JSON-Antwort des REST-Backends inkl. Diagnosedaten für Header- und Query-Filterung.
#[derive(Serialize)]
struct NotificationsResponse {
    tenant: String,
    limit: usize,
    credentials_received: bool,
    observed_query: BTreeMap<String, String>,
    items: Vec<NotificationItem>,
}

/// Erzeugt eine HTTP-Antwort mit einfachem Byte-Body und Content-Type.
fn json_response(status: StatusCode, body: Vec<u8>) -> Response<Full<Bytes>> {
    let mut resp = Response::new(Full::new(Bytes::from(body)));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    resp
}

/// Verarbeitet einen einzelnen HTTP-Request im Mock-REST-Backend.
async fn handle_rest_request(
    req: Request<Incoming>,
    cancel: CancellationToken,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if req.method() != Method::GET || req.uri().path() != "/v1/notifications" {
        return Ok(json_response(
            StatusCode::NOT_FOUND,
            br#"{"error":"not found"}"#.to_vec(),
        ));
    }

    let credentials_received = req.headers().contains_key(header::AUTHORIZATION)
        || req.headers().contains_key(header::COOKIE);
    let traceparent = req
        .headers()
        .get("traceparent")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("<none>")
        .to_string();

    let mut tenant = String::new();
    let mut limit_raw: Option<String> = None;
    let mut observed_query = BTreeMap::new();

    if let Some(query) = req.uri().query() {
        for (k, v) in url::form_urlencoded::parse(query.as_bytes()) {
            let key = k.into_owned();
            let val = v.into_owned();
            if key == "tenant" {
                tenant = val.clone();
            } else if key == "limit" {
                limit_raw = Some(val.clone());
            }
            observed_query.insert(key, val);
        }
    }

    info!(
        target: "backend.rest",
        path = %req.uri(),
        tenant = %tenant,
        limit = ?limit_raw,
        credentials_received,
        traceparent = %traceparent,
        "REST /v1/notifications verarbeitet"
    );

    if limit_raw.as_deref() == Some("slow") {
        // Überschreitet `timeout_ms = 500` in Config.toml, um Graceful Degradation auszulösen.
        tokio::select! {
            () = tokio::time::sleep(Duration::from_millis(800)) => {}
            () = cancel.cancelled() => {
                return Ok(json_response(StatusCode::SERVICE_UNAVAILABLE, br#"{"error":"shutting down"}"#.to_vec()));
            }
        }
    }

    let limit = limit_raw
        .as_deref()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(3)
        .min(3);

    let mut items = vec![
        NotificationItem {
            id: 1,
            message: format!("Welcome to {tenant}"),
        },
        NotificationItem {
            id: 2,
            message: "Aggregate fan-out ready".to_string(),
        },
        NotificationItem {
            id: 3,
            message: "Zero-copy response splicing active".to_string(),
        },
    ];
    items.truncate(limit);

    let payload = NotificationsResponse {
        tenant,
        limit,
        credentials_received,
        observed_query,
        items,
    };

    match serde_json::to_vec(&payload) {
        Ok(bytes) => Ok(json_response(StatusCode::OK, bytes)),
        Err(err) => {
            error!(target: "backend.rest", error = %err, "JSON-Serialisierung fehlgeschlagen");
            Ok(json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                br#"{"error":"serialization failed"}"#.to_vec(),
            ))
        }
    }
}

/// Startet den lokalen HTTP/1.1 REST-Server für `/v1/notifications` auf `addr`.
#[tracing::instrument(skip(cancel), err)]
async fn spawn_rest_backend(addr: SocketAddr, cancel: CancellationToken) -> anyhow::Result<()> {
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("Konnte REST-Backend nicht auf {addr} binden"))?;

    tokio::spawn(async move {
        loop {
            tokio::select! {
                () = cancel.cancelled() => break,
                accepted = listener.accept() => {
                    let Ok((socket, _)) = accepted else {
                        break;
                    };
                    let conn_cancel = cancel.clone();
                    tokio::spawn(async move {
                        let io = TokioIo::new(socket);
                        let shutdown_cancel = conn_cancel.clone();
                        let svc = service_fn(move |req| {
                            let req_cancel = conn_cancel.clone();
                            handle_rest_request(req, req_cancel)
                        });
                        let conn = http1::Builder::new().serve_connection(io, svc);
                        tokio::pin!(conn);
                        tokio::select! {
                            res = &mut conn => {
                                if let Err(err) = res {
                                    warn!(target: "backend.rest", error = %err, "REST-Verbindung beendet");
                                }
                            }
                            () = shutdown_cancel.cancelled() => {
                                conn.as_mut().graceful_shutdown();
                            }
                        }
                    });
                }
            }
        }
    });

    Ok(())
}

// ============================================================================
//  Config-Extraktion & Readiness
// ============================================================================

/// Aus `Config.toml` abgeleitete Socket-Adressen und Query-Policy für Gateway und beide Backends.
struct ExampleEndpoints {
    gateway: SocketAddr,
    grpc_user: SocketAddr,
    rest_notifications: SocketAddr,
    notifications_extra_allowed: bool,
}

/// Konvertiert eine `hyper::Uri` (z. B. `http://127.0.0.1:50051`) in eine `SocketAddr`.
fn uri_to_socket_addr(uri: &hyper::Uri) -> anyhow::Result<SocketAddr> {
    let host = uri.host().context("Upstream-URI enthält keinen Host")?;
    let port = uri.port_u16().context("Upstream-URI enthält keinen Port")?;
    format!("{host}:{port}")
        .parse::<SocketAddr>()
        .with_context(|| format!("Ungültige Upstream-SocketAddr '{host}:{port}'"))
}

/// Liest die gebundene Gateway-Adresse und die Upstream-Adressen aus `Config`.
fn extract_endpoints(config: &Config) -> anyhow::Result<ExampleEndpoints> {
    let server = config
        .servers
        .iter()
        .find(|s| s.enabled)
        .context("Config enthält keinen aktivierten [[Server]]-Block")?;

    let ip = server
        .ip
        .as_deref()
        .context("Server-Konfiguration benötigt 'ip'")?;
    let port = server
        .port
        .context("Server-Konfiguration benötigt 'port'")?;
    let gateway: SocketAddr = format!("{ip}:{port}")
        .parse()
        .with_context(|| format!("Ungültige Gateway-Adresse '{ip}:{port}'"))?;

    let route = server
        .parsed_routes
        .iter()
        .find(|r| r.prefix == "/api/dashboard")
        .context("Route '/api/dashboard' fehlt in Config.toml")?;

    if route.backend_type != RouteBackendType::Aggregate {
        bail!("Route '/api/dashboard' muss backend_type = \"aggregate\" verwenden");
    }

    let find_target = |key: &str| {
        route
            .aggregate_targets
            .iter()
            .find(|t| t.key == key)
            .with_context(|| format!("Aggregate-Target '{key}' fehlt in Config.toml"))
    };
    let user_target = find_target("user")?;
    let notifications_target = find_target("notifications")?;
    let notifications_extra_allowed = notifications_target
        .forward_query
        .as_ref()
        .is_none_or(|fq| fq.contains("extra"));

    let first_upstream_addr = |target: &praeco_rs::configuration::ParsedAggregateTarget,
                               key: &str|
     -> anyhow::Result<SocketAddr> {
        let node = target
            .target
            .upstreams
            .first()
            .with_context(|| format!("Target '{key}' hat keine Upstreams"))?;
        uri_to_socket_addr(&node.uri)
    };

    Ok(ExampleEndpoints {
        gateway,
        grpc_user: first_upstream_addr(user_target, "user")?,
        rest_notifications: first_upstream_addr(notifications_target, "notifications")?,
        notifications_extra_allowed,
    })
}

/// Wartet, bis ein TCP-Listener auf `addr` Verbindungen annimmt.
async fn wait_until_listening(addr: SocketAddr, timeout: Duration) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if TcpStream::connect(addr).await.is_ok() {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            bail!("Zeitüberschreitung beim Warten auf TCP-Listener {addr}");
        }
        tokio::time::sleep(Duration::from_millis(15)).await;
    }
}

// ============================================================================
//  End-to-End Demo-Szenarien gegen das laufende Praeco-Gateway
// ============================================================================

/// Hilfsfunktion zum Senden eines HTTP-Requests an das Praeco-Gateway.
async fn send_gateway_request(
    client: &Client<HttpConnector, SrvBody>,
    gateway: SocketAddr,
    method: Method,
    path_and_query: &str,
    headers: &[(&str, &str)],
    body: Option<&'static [u8]>,
) -> anyhow::Result<(StatusCode, hyper::HeaderMap, Bytes)> {
    let uri = format!("http://{gateway}{path_and_query}");
    let srv_body: SrvBody = match body {
        Some(raw) => Full::new(Bytes::from_static(raw))
            .map_err(praeco_rs::SrvError::from)
            .boxed(),
        None => Empty::<Bytes>::new()
            .map_err(praeco_rs::SrvError::from)
            .boxed(),
    };

    let mut builder = Request::builder().method(method).uri(&uri);
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let req = builder
        .body(srv_body)
        .with_context(|| format!("Konnte Request für {uri} nicht bauen"))?;

    let resp = client
        .request(req)
        .await
        .with_context(|| format!("HTTP-Request an Gateway {uri} fehlgeschlagen"))?;

    let status = resp.status();
    let resp_headers = resp.headers().clone();
    let resp_bytes = resp
        .into_body()
        .collect()
        .await
        .context("Konnte Gateway-Response-Body nicht lesen")?
        .to_bytes();

    Ok((status, resp_headers, resp_bytes))
}

/// Führt alle 6 End-to-End-Szenarien gegen `gateway` aus und validiert Status, Header und JSON.
#[tracing::instrument(err)]
async fn run_demo_scenarios(gateway: SocketAddr, extra_allowed: bool) -> anyhow::Result<()> {
    let client: Client<HttpConnector, SrvBody> =
        Client::builder(TokioExecutor::new()).build(HttpConnector::new());

    println!("\n=== Praeco backend_type = \"aggregate\" End-to-End Demo ===");
    println!("Gateway: http://{gateway}\n");

    // 1. Health-Check
    let (status, _, body) =
        send_gateway_request(&client, gateway, Method::GET, "/health", &[], None).await?;
    let health_text = String::from_utf8_lossy(&body);
    println!("[1] GET /health -> {status} | {health_text}");
    anyhow::ensure!(status == StatusCode::OK, "Erwartet 200 OK für /health, bekam {status}");

    // 2. POST keyed Fan-Out + Header-Sanitizing + Query-Precedence/Allowlist
    let (status, resp_headers, body) = send_gateway_request(
        &client,
        gateway,
        Method::POST,
        "/api/dashboard?limit=2&tenant=evil&extra=1&blocked=99",
        &[
            ("content-type", "application/json"),
            ("authorization", "Bearer client-secret"),
            ("cookie", "session=abc"),
            ("if-none-match", "\"etag-1\""),
        ],
        Some(br#"{"user":{"user_id":"42"}}"#),
    )
    .await?;
    let cache_control = resp_headers
        .get(header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("<none>");
    let body_str = String::from_utf8_lossy(&body);
    println!(
        "[2] POST /api/dashboard (keyed + auth/query filter) -> {status} (cache-control={cache_control})"
    );
    println!("    {body_str}");
    anyhow::ensure!(status == StatusCode::OK, "Szenario 2 erwartet 200 OK, bekam {status}");
    anyhow::ensure!(
        cache_control == "no-store",
        "ConnectionHandler cache-control=no-store fehlt (bekam: {cache_control})"
    );
    anyhow::ensure!(
        resp_headers
            .get("x-content-type-options")
            .and_then(|v| v.to_str().ok())
            == Some("nosniff"),
        "SecurityHeaders x-content-type-options=nosniff fehlt"
    );

    let parsed: serde_json::Value = serde_json::from_slice(&body)?;
    anyhow::ensure!(parsed["user"]["id"] == "42");
    anyhow::ensure!(parsed["user"]["name"] == "Alice (42)");
    anyhow::ensure!(parsed["user"]["role"] == "Admin");
    anyhow::ensure!(
        parsed["notifications"]["tenant"] == "acme",
        "Operator-pinned tenant=acme muss tenant=evil überschreiben"
    );
    anyhow::ensure!(parsed["notifications"]["limit"] == 2);
    anyhow::ensure!(
        parsed["notifications"]["credentials_received"] == false,
        "Client Authorization/Cookie müssen standardmäßig gestrippt werden"
    );
    let observed_query = parsed["notifications"]["observed_query"]
        .as_object()
        .context("observed_query fehlt")?;
    anyhow::ensure!(observed_query.get("tenant").is_some_and(|v| v == "acme"));
    anyhow::ensure!(observed_query.get("limit").is_some_and(|v| v == "2"));
    anyhow::ensure!(
        !observed_query.contains_key("blocked"),
        "Unbekannter Query-Parameter 'blocked' hätte gefiltert werden müssen"
    );
    if extra_allowed {
        anyhow::ensure!(
            observed_query.get("extra").is_some_and(|v| v == "1"),
            "Erlaubter Query-Parameter 'extra=1' fehlt in observed_query"
        );
    } else {
        anyhow::ensure!(
            !observed_query.contains_key("extra"),
            "Nicht erlaubter Query-Parameter 'extra' hätte gefiltert werden müssen"
        );
    }
    anyhow::ensure!(
        parsed["notifications"]["items"]
            .as_array()
            .is_some_and(|arr| arr.len() == 2)
    );
    anyhow::ensure!(parsed.get("_errors").is_none());

    // 3. GET mit Query-Parametern -> gRPC (JSON aus Query) + REST
    let (status, _, body) = send_gateway_request(
        &client,
        gateway,
        Method::GET,
        "/api/dashboard?user_id=42&limit=1&tenant=evil",
        &[],
        None,
    )
    .await?;
    let body_str = String::from_utf8_lossy(&body);
    println!("[3] GET /api/dashboard?user_id=42&limit=1&tenant=evil -> {status}");
    println!("    {body_str}");
    anyhow::ensure!(status == StatusCode::OK, "Szenario 3 erwartet 200 OK, bekam {status}");
    let parsed: serde_json::Value = serde_json::from_slice(&body)?;
    anyhow::ensure!(parsed["user"]["id"] == "42");
    anyhow::ensure!(parsed["user"]["name"] == "Alice (42)");
    anyhow::ensure!(parsed["notifications"]["tenant"] == "acme");
    anyhow::ensure!(parsed["notifications"]["limit"] == 1);
    anyhow::ensure!(
        parsed["notifications"]["items"]
            .as_array()
            .is_some_and(|arr| arr.len() == 1)
    );
    anyhow::ensure!(parsed.get("_errors").is_none());

    // 4. Optionales REST-Target Timeout -> Graceful Degradation (null + _errors)
    let (status, _, body) = send_gateway_request(
        &client,
        gateway,
        Method::POST,
        "/api/dashboard?limit=slow",
        &[("content-type", "application/json")],
        Some(br#"{"user":{"user_id":"42"}}"#),
    )
    .await?;
    let body_str = String::from_utf8_lossy(&body);
    println!("[4] POST /api/dashboard?limit=slow (optional timeout -> 504 in _errors) -> {status}");
    println!("    {body_str}");
    anyhow::ensure!(status == StatusCode::OK, "Szenario 4 erwartet 200 OK, bekam {status}");
    let parsed: serde_json::Value = serde_json::from_slice(&body)?;
    anyhow::ensure!(parsed["user"]["id"] == "42");
    anyhow::ensure!(parsed["notifications"].is_null());
    anyhow::ensure!(parsed["_errors"]["notifications"]["status"] == 504);
    anyhow::ensure!(parsed["_errors"]["notifications"]["message"] == "Gateway Timeout");

    // 5. Required gRPC-Target Fehler -> Abbruch & Fehler-Sanitizing (`expose_upstream_errors = false`)
    let (status, _, body) = send_gateway_request(
        &client,
        gateway,
        Method::POST,
        "/api/dashboard",
        &[("content-type", "application/json")],
        Some(br#"{"user":{"user_id":"missing"}}"#),
    )
    .await?;
    let body_text = String::from_utf8_lossy(&body);
    println!("[5] POST /api/dashboard (required gRPC NOT_FOUND, sanitized) -> {status} | {body_text}");
    anyhow::ensure!(status == StatusCode::NOT_FOUND, "Szenario 5 erwartet 404, bekam {status}");
    anyhow::ensure!(
        !body_text.contains("secret internal"),
        "Rohe Upstream-Fehlermeldung darf bei expose_upstream_errors=false nicht durchdringen"
    );
    anyhow::ensure!(body_text == "Not Found");

    // 6. Keyed-Payload-Schutz: Flacher JSON-Body ohne Target-Key -> 400 Bad Request
    let (status, _, body) = send_gateway_request(
        &client,
        gateway,
        Method::POST,
        "/api/dashboard",
        &[("content-type", "application/json")],
        Some(br#"{"user_id":"42"}"#),
    )
    .await?;
    let body_text = String::from_utf8_lossy(&body);
    println!("[6] POST /api/dashboard (flaches JSON abgelehnt durch keyed) -> {status} | {body_text}");
    anyhow::ensure!(status == StatusCode::BAD_REQUEST, "Szenario 6 erwartet 400, bekam {status}");
    anyhow::ensure!(body_text.contains("Unknown target key"));

    println!("\nAlle 6 Szenarien erfolgreich abgeschlossen.");
    Ok(())
}

/// Startet Backends + Praeco-Gateway anhand von `config` und wartet auf Readiness.
async fn start_stack_and_wait(
    config: Arc<Config>,
    cancel: CancellationToken,
) -> anyhow::Result<(ExampleEndpoints, tokio::task::JoinHandle<()>)> {
    let endpoints = extract_endpoints(&config)?;

    spawn_grpc_backend(endpoints.grpc_user, cancel.clone()).await?;
    spawn_rest_backend(endpoints.rest_notifications, cancel.clone()).await?;

    wait_until_listening(endpoints.grpc_user, Duration::from_secs(3)).await?;
    wait_until_listening(endpoints.rest_notifications, Duration::from_secs(3)).await?;

    let gateway_handle = tokio::spawn(praeco_rs::run_servers(config, cancel));
    wait_until_listening(endpoints.gateway, Duration::from_secs(3)).await?;

    Ok((endpoints, gateway_handle))
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let Some(args) = parse_cli_args()? else {
        return Ok(());
    };

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,praeco_rs=info,aggregate_fanout=info"));
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    info!(config_path = %args.config_path, "Lade Praeco-Konfiguration");
    let config = Config::init(&args.config_path)?;
    let cancel = CancellationToken::new();

    let (endpoints, gateway_handle) = start_stack_and_wait(config, cancel.clone()).await?;

    if args.serve {
        let gw = endpoints.gateway;
        println!("\nPraeco Aggregate Gateway läuft auf http://{gw}");
        println!("gRPC-Backend (user):          {}", endpoints.grpc_user);
        println!("REST-Backend (notifications): {}", endpoints.rest_notifications);
        println!("\nBeispiel-Aufrufe mit curl:");
        println!(
            "  curl -sS -X POST 'http://{gw}/api/dashboard?limit=2&tenant=evil&extra=1&blocked=99' \\\n    -H 'Content-Type: application/json' \\\n    -d '{{\"user\":{{\"user_id\":\"42\"}}}}'"
        );
        println!("  curl -sS 'http://{gw}/api/dashboard?user_id=42&limit=1'");
        println!("  curl -sS -X POST 'http://{gw}/api/dashboard?limit=slow' -H 'Content-Type: application/json' -d '{{\"user\":{{\"user_id\":\"42\"}}}}'");
        println!("\nBeenden mit Ctrl+C...");

        tokio::signal::ctrl_c().await?;
        info!("Shutdown angefordert, fahre Gateway und Backends herunter...");
        cancel.cancel();
        let _ = gateway_handle.await;
        return Ok(());
    }

    let demo_result = run_demo_scenarios(endpoints.gateway, endpoints.notifications_extra_allowed).await;
    cancel.cancel();
    let _ = gateway_handle.await;
    demo_result
}

#[cfg(test)]
mod tests {
    use super::*;
    use praeco_rs::configuration::AggregatePayloadMode;
    use std::io::Write;
    use tempfile::NamedTempFile;

    async fn reserve_free_port() -> anyhow::Result<u16> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        Ok(listener.local_addr()?.port())
    }

    #[test]
    fn test_config_toml_parses_and_finalizes() -> anyhow::Result<()> {
        let config_path = concat!(env!("CARGO_MANIFEST_DIR"), "/Config.toml");
        let cfg = Config::load(config_path)?;
        assert_eq!(cfg.servers.len(), 1);
        let srv = &cfg.servers[0];
        assert_eq!(srv.name, "AggregateFanoutGateway");

        let route = srv
            .parsed_routes
            .iter()
            .find(|r| r.prefix == "/api/dashboard")
            .expect("/api/dashboard route exists");
        assert_eq!(route.backend_type, RouteBackendType::Aggregate);
        assert_eq!(route.aggregate_payload_mode, AggregatePayloadMode::Keyed);
        assert!(!route.expose_upstream_errors);
        assert_eq!(route.aggregate_targets.len(), 2);

        let user = &route.aggregate_targets[0];
        assert_eq!(user.key, "user");
        assert_eq!(user.backend_type, RouteBackendType::GrpcTranscoding);
        assert!(user.required);

        let notifications = &route.aggregate_targets[1];
        assert_eq!(notifications.key, "notifications");
        assert_eq!(notifications.backend_type, RouteBackendType::Rest);
        assert!(!notifications.required);
        assert_eq!(notifications.method, Some(Method::GET));

        Ok(())
    }

    #[tokio::test]
    async fn test_aggregate_fanout_end_to_end() -> anyhow::Result<()> {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

        let gw_port = reserve_free_port().await?;
        let grpc_port = reserve_free_port().await?;
        let rest_port = reserve_free_port().await?;

        let raw_toml = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/Config.toml"))?;
        let patched_toml = raw_toml
            .replace("port = 8080", &format!("port = {gw_port}"))
            .replace("127.0.0.1:50051", &format!("127.0.0.1:{grpc_port}"))
            .replace("127.0.0.1:8081", &format!("127.0.0.1:{rest_port}"));

        let mut tmp = NamedTempFile::new()?;
        tmp.write_all(patched_toml.as_bytes())?;
        tmp.flush()?;
        let tmp_path = tmp.path().to_str().expect("UTF-8 temp path");

        let config = Config::load(tmp_path)?;
        let cancel = CancellationToken::new();

        let (endpoints, gateway_handle) = start_stack_and_wait(config, cancel.clone()).await?;
        let res = run_demo_scenarios(endpoints.gateway, endpoints.notifications_extra_allowed).await;

        cancel.cancel();
        let _ = gateway_handle.await;
        res
    }
}
