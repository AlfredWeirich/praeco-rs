//! # Embedded Binary Protobuf-to-Protobuf gRPC Aggregator Example
//!
//! Demonstrates how an external Rust application can embed `praeco-rs` as a
//! library crate (`default-features = false`, without `mimalloc`,
//! `tracing-subscriber`, or OTLP exporters) and construct [`ServerConfig`]
//! purely in Rust (`..Default::default()`, **without any `Config.toml`**).
//!
//! ## What this example does end-to-end
//!
//! ```text
//!   Tonic gRPC Client (binary Protobuf: DashboardReq { user_id: "42" })
//!          │
//!          ▼
//!   Praeco Listener (`start_single_server`)
//!          │  ├── ConnectionHandler (`cache-control: no-store`, peer IP, OID roles)
//!          │  ├── PathSanitizerLayer (RFC 3986 traversal protection)
//!          │  ├── TraceIdLayer       (generates W3C `traceparent` / `x-trace-id`)
//!          │  ├── IpFilterLayer      (CIDR allowlist `127.0.0.1/32`)
//!          │  └── MaxPayloadLayer    (1 MiB body limit)
//!          ▼
//!   `wrap_tonic_routes` (`SyncBody` bridges `tonic::body::Body` -> `ServiceRespBody`)
//!          │
//!          ▼
//!   `AggregatorService` (`aggregator.DashboardService/GetDashboard`)
//!          ├──▶ tokio::join! ──▶ `UserBackendService`  (`user.UserService/GetUser`)
//!          └──▶              ──▶ `OrderBackendService` (`order.OrderService/CountOrders`)
//!          │
//!          ▼
//!   Aggregated binary Protobuf response (`DashboardRes { user_name: "Alice (42)", order_count: 7 }`)
//! ```
//!
//! ## Execution flow in `main()`
//!
//! 1. **Start two local gRPC backends:** Spawns two minimal `tonic` HTTP/2 servers
//!    (`UserBackendService` and `OrderBackendService`) on ephemeral loopback ports
//!    and opens multiplexed `tonic::transport::Channel`s to each.
//! 2. **Configure Praeco programmatically:** Builds [`ServerConfig`] via
//!    `..Default::default()` with `TraceId`, `IpFilter`, and `MaxPayload` layers
//!    and validates/finalizes it via [`ServerConfig::finalize`].
//! 3. **Assemble the Tower stack:** Wraps `tonic::service::Routes` in a
//!    [`BoxedCloneService`] via [`wrap_tonic_routes`] (using [`SyncBody`] so
//!    streaming `tonic` bodies satisfy Praeco's `Send + Sync` body bound),
//!    applies the configured layers with [`apply_layers`], and places
//!    [`PathSanitizerLayer`] on the outside (matching `build_service_stack`).
//! 4. **Run the embedded gateway:** Starts [`start_single_server`] inside an
//!    `ArcSwap` stack holder so hot-reloads remain possible at runtime.
//! 5. **Send a real typed gRPC call:** Calls `/aggregator.DashboardService/GetDashboard`
//!    over HTTP/2 using `tonic::client::Grpc`, prints the propagated `x-trace-id`
//!    inside the aggregator and the decoded `DashboardRes` + `cache-control`
//!    header on the client, then shuts down gracefully via [`CancellationToken`].
//!
//! ## Running the example
//!
//! ```bash
//! cargo run -p praeco-rs --example embedded_grpc_aggregator --no-default-features
//! ```
//!
//! Expected output:
//!
//! ```text
//! Aggregator received request with x-trace-id="00-..."
//! Aggregated gRPC Response -> user_name='Alice (42)', order_count=7, cache-control=no-store
//! ```
//!
//! ## Adapting for production
//!
//! - Replace the manual `#[derive(prost::Message)]` / `UnaryService` structs with
//!   code generated from `.proto` files via `tonic-prost-build`.
//! - Switch `protocol: Protocol::Http` to `Protocol::Https` and populate
//!   `server_certs` / `client_certs` + `authentication: AuthenticationMethod::ClientCert`
//!   for TLS 1.3, mTLS, and HTTP/3 (QUIC) support.
//! - Read Praeco's resolved mTLS/JWT roles (`Arc<praeco_rs::configuration::RoleVec<6>>`)
//!   from `request.extensions()` inside your `tonic` service or a `tonic` interceptor.

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use arc_swap::ArcSwap;
use http_body_util::BodyExt;
use hyper::{Request, Response};
use prost::Message;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tonic::body::Body as TonicBody;
use tonic::client::Grpc as TonicClient;
use tonic::server::{Grpc as TonicServer, NamedService, UnaryService};
use tonic::service::Routes;
use tonic::transport::Endpoint;
use tonic::{Request as TonicRequest, Response as TonicResponse, Status};
use tonic_prost::ProstCodec;
use tower::{Layer, Service};

use praeco_rs::{
    BoxCloneSyncServiceExt, BoxedCloneService, ServiceRespBody, SrvBody, SrvError, apply_layers,
    configuration::{IpFilterConfig, Layers, MaxPayloadConfig, Protocol, ServerConfig},
    middleware::PathSanitizerLayer,
    start_single_server,
};

// ============================================================================
//  Typed Protobuf Messages (normally generated from .proto via tonic-prost-build)
// ============================================================================
// Defined inline with `#[derive(prost::Message)]` so this example compiles
// standalone without adding a `build.rs` or `.proto` codegen step.

/// Request payload for `user.UserService/GetUser`.
#[derive(Clone, PartialEq, Message)]
struct UserReq {
    #[prost(string, tag = "1")]
    user_id: String,
}

/// Response payload for `user.UserService/GetUser`.
#[derive(Clone, PartialEq, Message)]
struct UserRes {
    #[prost(string, tag = "1")]
    name: String,
}

/// Request payload for `order.OrderService/CountOrders`.
#[derive(Clone, PartialEq, Message)]
struct OrderReq {
    #[prost(string, tag = "1")]
    user_id: String,
}

/// Response payload for `order.OrderService/CountOrders`.
#[derive(Clone, PartialEq, Message)]
struct OrderRes {
    #[prost(int32, tag = "1")]
    count: i32,
}

/// Aggregated client request payload for `aggregator.DashboardService/GetDashboard`.
#[derive(Clone, PartialEq, Message)]
struct DashboardReq {
    #[prost(string, tag = "1")]
    user_id: String,
}

/// Aggregated binary Protobuf response combining user profile and order count.
#[derive(Clone, PartialEq, Message)]
struct DashboardRes {
    #[prost(string, tag = "1")]
    user_name: String,
    #[prost(int32, tag = "2")]
    order_count: i32,
}

// ============================================================================
//  Minimal Tonic Unary Services (Backends + Typed Aggregator)
// ============================================================================

/// Mock gRPC backend simulating an internal User microservice (`user.UserService`).
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
        Box::pin(async move {
            struct Handler;
            impl UnaryService<UserReq> for Handler {
                type Response = UserRes;
                type Future =
                    Pin<Box<dyn Future<Output = Result<TonicResponse<UserRes>, Status>> + Send>>;
                fn call(&mut self, request: TonicRequest<UserReq>) -> Self::Future {
                    Box::pin(async move {
                        let uid = request.into_inner().user_id;
                        Ok(TonicResponse::new(UserRes {
                            name: format!("Alice ({uid})"),
                        }))
                    })
                }
            }

            let mut grpc = TonicServer::new(ProstCodec::<UserRes, UserReq>::default());
            Ok(grpc.unary(Handler, req).await)
        })
    }
}

/// Mock gRPC backend simulating an internal Order microservice (`order.OrderService`).
#[derive(Clone)]
struct OrderBackendService;

impl NamedService for OrderBackendService {
    const NAME: &'static str = "order.OrderService";
}

impl Service<Request<TonicBody>> for OrderBackendService {
    type Response = Response<TonicBody>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<TonicBody>) -> Self::Future {
        Box::pin(async move {
            struct Handler;
            impl UnaryService<OrderReq> for Handler {
                type Response = OrderRes;
                type Future =
                    Pin<Box<dyn Future<Output = Result<TonicResponse<OrderRes>, Status>> + Send>>;
                fn call(&mut self, request: TonicRequest<OrderReq>) -> Self::Future {
                    Box::pin(async move {
                        let count = if request.into_inner().user_id == "42" {
                            7
                        } else {
                            0
                        };
                        Ok(TonicResponse::new(OrderRes { count }))
                    })
                }
            }

            let mut grpc = TonicServer::new(ProstCodec::<OrderRes, OrderReq>::default());
            Ok(grpc.unary(Handler, req).await)
        })
    }
}

/// Typed Protobuf-to-Protobuf Aggregator Service:
/// Receives `DashboardReq`, fans out concurrently via `tokio::join!` to both
/// gRPC backends over HTTP/2 channels, and returns `DashboardRes`.
#[derive(Clone)]
struct AggregatorService {
    user_channel: tonic::transport::Channel,
    order_channel: tonic::transport::Channel,
}

impl NamedService for AggregatorService {
    const NAME: &'static str = "aggregator.DashboardService";
}

impl Service<Request<TonicBody>> for AggregatorService {
    type Response = Response<TonicBody>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<TonicBody>) -> Self::Future {
        let user_channel = self.user_channel.clone();
        let order_channel = self.order_channel.clone();

        Box::pin(async move {
            struct Handler {
                user_channel: tonic::transport::Channel,
                order_channel: tonic::transport::Channel,
            }

            impl UnaryService<DashboardReq> for Handler {
                type Response = DashboardRes;
                type Future = Pin<
                    Box<dyn Future<Output = Result<TonicResponse<DashboardRes>, Status>> + Send>,
                >;

                fn call(&mut self, request: TonicRequest<DashboardReq>) -> Self::Future {
                    let user_channel = self.user_channel.clone();
                    let order_channel = self.order_channel.clone();
                    Box::pin(async move {
                        let trace_id = request
                            .metadata()
                            .get("x-trace-id")
                            .cloned();
                        if let Some(ref tid) = trace_id {
                            println!("Aggregator received request with x-trace-id={:?}", tid);
                        }
                        let user_id = request.into_inner().user_id;

                        let call_user = async {
                            let mut client = TonicClient::new(user_channel);
                            client.ready().await.map_err(|e| {
                                Status::unavailable(format!("user backend not ready: {e}"))
                            })?;
                            let path = hyper::http::uri::PathAndQuery::from_static(
                                "/user.UserService/GetUser",
                            );
                            let codec = ProstCodec::<UserReq, UserRes>::default();
                            let mut sub_req = TonicRequest::new(UserReq {
                                user_id: user_id.clone(),
                            });
                            if let Some(ref tid) = trace_id {
                                sub_req.metadata_mut().insert("x-trace-id", tid.clone());
                            }
                            client.unary(sub_req, path, codec).await
                        };

                        let call_orders = async {
                            let mut client = TonicClient::new(order_channel);
                            client.ready().await.map_err(|e| {
                                Status::unavailable(format!("order backend not ready: {e}"))
                            })?;
                            let path = hyper::http::uri::PathAndQuery::from_static(
                                "/order.OrderService/CountOrders",
                            );
                            let codec = ProstCodec::<OrderReq, OrderRes>::default();
                            let mut sub_req = TonicRequest::new(OrderReq {
                                user_id: user_id.clone(),
                            });
                            if let Some(ref tid) = trace_id {
                                sub_req.metadata_mut().insert("x-trace-id", tid.clone());
                            }
                            client.unary(sub_req, path, codec).await
                        };

                        let (user_res, order_res) = tokio::join!(call_user, call_orders);
                        Ok(TonicResponse::new(DashboardRes {
                            user_name: user_res?.into_inner().name,
                            order_count: order_res?.into_inner().count,
                        }))
                    })
                }
            }

            let mut grpc = TonicServer::new(ProstCodec::<DashboardRes, DashboardReq>::default());
            Ok(grpc
                .unary(
                    Handler {
                        user_channel,
                        order_channel,
                    },
                    req,
                )
                .await)
        })
    }
}

// ============================================================================
//  Bridge: tonic::service::Routes <-> praeco_rs::BoxedCloneService
// ============================================================================

/// Zero-cost `Sync` adapter for `tonic::body::Body` (which wraps `UnsyncBoxBody`),
/// allowing streaming gRPC responses to fit `praeco_rs::ServiceRespBody` (`Send + Sync`).
struct SyncBody<B>(std::sync::Mutex<B>);

impl<B> http_body::Body for SyncBody<B>
where
    B: http_body::Body + Unpin + Send,
    B::Error: std::fmt::Display,
{
    type Data = B::Data;
    type Error = SrvError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<http_body::Frame<Self::Data>, Self::Error>>> {
        let inner = self
            .get_mut()
            .0
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Pin::new(inner)
            .poll_frame(cx)
            .map_err(|e| SrvError::Other(e.to_string()))
    }

    fn is_end_stream(&self) -> bool {
        self.0
            .lock()
            .map(|b| b.is_end_stream())
            .unwrap_or(false)
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.0
            .lock()
            .map(|b| b.size_hint())
            .unwrap_or_default()
    }
}

/// Adapts a `tonic::service::Routes` router into a [`BoxedCloneService`] compatible
/// with Praeco's [`apply_layers`] pipeline.
///
/// Converts `SrvBody` -> `tonic::body::Body` on the way in and wraps the resulting
/// `tonic::body::Body` in [`SyncBody`] on the way out so gRPC responses stream
/// without full-message buffering.
fn wrap_tonic_routes(routes: Routes) -> BoxedCloneService {
    let svc = routes.prepare();
    tower::service_fn(move |req: Request<SrvBody>| {
        let mut svc = svc.clone();
        async move {
            let (parts, body) = req.into_parts();
            let tonic_body =
                TonicBody::new(body.map_err(|e| Status::internal(e.to_string())));
            let tonic_req = Request::from_parts(parts, tonic_body);

            let res = svc.call(tonic_req).await.unwrap_or_else(|e| match e {});
            let (res_parts, res_body) = res.into_parts();
            let boxed_resp: ServiceRespBody =
                SyncBody(std::sync::Mutex::new(res_body)).boxed();
            Ok::<_, SrvError>(Response::from_parts(res_parts, boxed_resp))
        }
    })
    .boxed_clone_sync()
}

// ============================================================================
//  Helpers to spawn local backend tonic servers & pick a free port
// ============================================================================

/// Binds an ephemeral loopback port and immediately releases it so
/// `start_single_server` (which accepts a fixed `port: Option<u16>`) can bind it.
async fn reserve_free_port() -> anyhow::Result<u16> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    Ok(listener.local_addr()?.port())
}

/// Spawns a local `tonic` HTTP/2 backend server on a free loopback port and
/// registers graceful shutdown on `cancel`.
async fn spawn_tonic_backend<S>(service: S, cancel: CancellationToken) -> anyhow::Result<SocketAddr>
where
    S: Service<Request<TonicBody>, Response = Response<TonicBody>, Error = Infallible>
        + NamedService
        + Clone
        + Send
        + Sync
        + 'static,
    S::Future: Send + 'static,
{
    let port = reserve_free_port().await?;
    let addr: SocketAddr = format!("127.0.0.1:{port}").parse()?;
    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(service)
            .serve_with_shutdown(addr, cancel.cancelled())
            .await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    Ok(addr)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let cancel = CancellationToken::new();

    // 1. Start two typed gRPC backend services
    let user_addr = spawn_tonic_backend(UserBackendService, cancel.clone()).await?;
    let order_addr = spawn_tonic_backend(OrderBackendService, cancel.clone()).await?;

    let user_channel = Endpoint::from_shared(format!("http://{user_addr}"))?
        .connect()
        .await?;
    let order_channel = Endpoint::from_shared(format!("http://{order_addr}"))?
        .connect()
        .await?;

    // 2. Build Praeco ServerConfig programmatically (Weg 3 — NO Config.toml!)
    let gateway_port = reserve_free_port().await?;
    let mut cfg = ServerConfig {
        name: "embedded_grpc_aggregator".into(),
        ip: Some("127.0.0.1".into()),
        port: Some(gateway_port),
        protocol: Protocol::Http,
        layers: Layers {
            enabled: vec![
                "TraceId".into(),
                "IpFilter".into(),
                "MaxPayload".into(),
            ],
            ip_filter_config: Some(IpFilterConfig {
                allow_cidrs: vec!["127.0.0.1/32".into()],
                deny_cidrs: vec![],
                trust_forwarded_headers: false,
            }),
            max_payload_config: Some(MaxPayloadConfig {
                max_bytes: 1024 * 1024,
            }),
            ..Default::default()
        },
        ..Default::default()
    };
    cfg.finalize()?;
    let server_cfg = Arc::new(cfg);

    let static_name = server_cfg.static_name.expect("set by finalize()");
    let layers = server_cfg.layers.build_middleware_layers(&server_cfg.name)?;
    let allowed_paths = server_cfg
        .compiled_allowed_pathes
        .as_ref()
        .expect("set by finalize()")
        .clone();

    // 3. Wrap the typed tonic aggregator with Praeco's middleware stack
    let routes = Routes::new(AggregatorService {
        user_channel,
        order_channel,
    });
    let base_svc = wrap_tonic_routes(routes);
    let stacked = apply_layers(
        base_svc,
        layers,
        static_name,
        allowed_paths,
        gateway_port,
        Arc::new(server_cfg.oid_mapping.clone()),
    )?;
    let hardened = PathSanitizerLayer::new(static_name)
        .layer(stacked)
        .boxed_clone_sync();

    // 4. Start Praeco's listener via start_single_server
    let dynamic_stack = Arc::new(ArcSwap::from_pointee(hardened));
    let server_task = tokio::spawn(start_single_server(
        server_cfg,
        cancel.clone(),
        dynamic_stack,
    ));
    tokio::time::sleep(Duration::from_millis(80)).await;

    // 5. Execute a real binary Protobuf gRPC request against the embedded gateway
    let gw_channel = Endpoint::from_shared(format!("http://127.0.0.1:{gateway_port}"))?
        .connect()
        .await?;
    let mut client = TonicClient::new(gw_channel);
    client.ready().await?;

    let path =
        hyper::http::uri::PathAndQuery::from_static("/aggregator.DashboardService/GetDashboard");
    let codec = ProstCodec::<DashboardReq, DashboardRes>::default();
    let resp = client
        .unary(
            TonicRequest::new(DashboardReq {
                user_id: "42".into(),
            }),
            path,
            codec,
        )
        .await?;

    let cache_ctl = resp
        .metadata()
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("<none>")
        .to_string();
    let payload = resp.into_inner();
    println!(
        "Aggregated gRPC Response -> user_name='{}', order_count={}, cache-control={}",
        payload.user_name, payload.order_count, cache_ctl
    );

    // 6. Graceful shutdown
    cancel.cancel();
    let _ = server_task.await;
    Ok(())
}
