//! src/server.rs
//!
//! This is the backend gRPC Microservice.
//! It implements the business logic defined in `system_services.proto` and, crucially,
//! exposes the gRPC Server Reflection endpoint so dynamic clients (like our Router)
//! can query its schema at runtime.
//!
//! usage: curl -v -k -X POST -H "Content-Type: application/json" -d '{"includeCpu":true,"includeMemory":true}' https://192.168.178.175:1336/api/grpc/system.SystemMetrics/GetHealth

use clap::{Parser, ValueEnum};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tonic::{
    Request, Response, Status,
    transport::{Certificate, Identity, Server, ServerTlsConfig},
};
use tonic_reflection::server::Builder as ReflectionBuilder;
use tracing::{debug, info, instrument};

// This module includes the Rust code that `build.rs` automatically generated
// from our `system_services.proto` file.
pub mod system {
    tonic::include_proto!("system");
}

// Import generated traits and servers
use system::identity_service_server::{IdentityService, IdentityServiceServer};
use system::store_service_server::{StoreService, StoreServiceServer};
use system::system_metrics_server::{SystemMetrics, SystemMetricsServer};
// Import generated types
use system::{
    AuthTokenResponse, HealthQuery, HealthStatus, LoginRequest, MetricsQuery, RetrieveRequest,
    RetrieveResponse, StoreRequest, StoreResponse,
};

// LOAD THE DESCRIPTOR SET FOR REFLECTION
pub const FILE_DESCRIPTOR_SET: &[u8] =
    tonic::include_file_descriptor_set!("system_services_descriptor");

// -----------------------------------------------------------------------------
// 1. Identity Service Implementation
// -----------------------------------------------------------------------------
#[derive(Default)]
pub struct MyIdentityService {}

#[tonic::async_trait]
impl IdentityService for MyIdentityService {
    #[instrument(skip_all, fields(username = %request.get_ref().username))]
    async fn login(
        &self,
        request: Request<LoginRequest>,
    ) -> Result<Response<AuthTokenResponse>, Status> {
        // Extract the inner request
        let req = request.into_inner();
        info!("IdentityService handling Login");

        // Dummy authentication logic
        if req.username == "admin" && req.password == "admin123" {
            Ok(Response::new(AuthTokenResponse {
                token: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummy_token".into(),
                expires_in_seconds: 3600,
            }))
        } else {
            Err(Status::unauthenticated("Invalid username or password"))
        }
    }
}

// -----------------------------------------------------------------------------
// 2. System Metrics Implementation
// -----------------------------------------------------------------------------
#[derive(Default)]
pub struct MySystemMetrics {}

#[tonic::async_trait]
impl SystemMetrics for MySystemMetrics {
    #[instrument(skip_all)]
    async fn get_system_status(
        &self,
        request: Request<MetricsQuery>,
    ) -> Result<Response<HealthStatus>, Status> {
        // trace!("SystemMetrics handling GetHealth request {:?}", request.metadata());
        let req = request.into_inner();
        debug!(
            "SystemMetrics handling GetHealth request: include_cpu={}, include_memory={}",
            req.include_cpu, req.include_memory
        );

        let mut cpu = 0.0;
        let mut mem = 0.0;

        if req.include_cpu {
            cpu = 12.3; // Dummy data
        }
        if req.include_memory {
            mem = 1024.5;
        }

        Ok(Response::new(HealthStatus {
            status: "Healthy".into(),
            cpu_usage_percent: cpu,
            memory_usage_mb: mem,
            uptime_seconds: 86400,
        }))
    }

    #[instrument(skip_all)]
    async fn health(
        &self,
        _request: Request<HealthQuery>,
    ) -> Result<Response<system::HealthScore>, Status> {
        debug!("SystemMetrics handling health() request");
        Ok(Response::new(system::HealthScore {
            score: 100, // 0 to 100 health score
        }))
    }
}

// -----------------------------------------------------------------------------
// 3. Stateful Store Service Implementation
// -----------------------------------------------------------------------------
#[derive(Default)]
pub struct MyStoreService {
    // Thread-safe map to hold global state between requests
    store: Arc<RwLock<HashMap<String, String>>>,
}

#[tonic::async_trait]
impl StoreService for MyStoreService {
    #[instrument(skip_all, fields(key = %request.get_ref().key))]
    async fn store_data(
        &self,
        request: Request<StoreRequest>,
    ) -> Result<Response<StoreResponse>, Status> {
        let req = request.into_inner();
        debug!("StoreService handling StoreData");

        let mut map = self.store.write().await;
        map.insert(req.key.clone(), req.value.clone());

        Ok(Response::new(StoreResponse {
            success: true,
            message: format!("Successfully stored key '{}'", req.key),
        }))
    }

    #[instrument(skip_all, fields(key = %request.get_ref().key))]
    async fn retrieve_data(
        &self,
        request: Request<RetrieveRequest>,
    ) -> Result<Response<RetrieveResponse>, Status> {
        let req = request.into_inner();
        debug!("StoreService handling RetrieveData");

        let map = self.store.read().await;
        if let Some(val) = map.get(&req.key) {
            Ok(Response::new(RetrieveResponse {
                found: true,
                value: val.clone(),
            }))
        } else {
            Ok(Response::new(RetrieveResponse {
                found: false,
                value: String::new(),
            }))
        }
    }
}

/// Command-line arguments for configuring the gRPC server.
#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Cli {
    /// Authentication / security mode.
    #[clap(short = 's', long, value_enum, default_value_t = Protocol::Mtls)]
    security: Protocol,

    /// Server address and port to bind to.
    #[clap(short = 'u', long, default_value = "0.0.0.0:50051")]
    uri: String,

    /// Path to the server's certificate (PEM).
    #[clap(long, default_value = "./server_certs/self_signed/fullchain_self.pem")]
    cert: String,

    /// Path to the server's private key (PEM).
    #[clap(long, default_value = "./server_certs/self_signed/privkey_self.pem")]
    key: String,

    /// Path to the root CA certificate (PEM) for verifying client certificates.
    #[clap(long, default_value = "./client_certs/ca.cert.pem")]
    ca: String,
}

/// Authentication / security protocols supported by the server.
#[derive(Debug, Clone, ValueEnum, PartialEq)]
enum Protocol {
    Http,
    Https,
    Mtls,
}

// -----------------------------------------------------------------------------
// Server Entrypoint
// -----------------------------------------------------------------------------
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();
    let addr = cli.uri.parse()?;

    // Instantiate all our services
    let identity_service = MyIdentityService::default();
    let system_metrics = MySystemMetrics::default();
    let store_service = MyStoreService::default();

    // Configure Reflection Service
    let reflection_service = ReflectionBuilder::configure()
        .register_encoded_file_descriptor_set(FILE_DESCRIPTOR_SET)
        .build_v1()?; // Implements grpc.reflection.v1.ServerReflection

    let mut server = Server::builder();

    if cli.security == Protocol::Https || cli.security == Protocol::Mtls {
        info!(
            "gRPC Server listening on https://{} (Security: {:?})",
            addr, cli.security
        );

        // Read TLS cert and key
        let cert = std::fs::read(&cli.cert)?;
        let key = std::fs::read(&cli.key)?;
        let identity = Identity::from_pem(cert, key);

        let mut tls_config = ServerTlsConfig::new().identity(identity);

        if cli.security == Protocol::Mtls {
            // Read the Root CA to require mTLS client certificates
            let ca_cert = std::fs::read(&cli.ca)?;
            let ca_cert = Certificate::from_pem(ca_cert);
            tls_config = tls_config.client_ca_root(ca_cert);
        }

        server = server.tls_config(tls_config)?;
    } else {
        info!("gRPC Server listening on http://{} (Security: HTTP)", addr);
    }

    // Boot up the server and register all 4 endpoints (3 custom + 1 reflection)
    server
        .add_service(IdentityServiceServer::new(identity_service))
        .add_service(SystemMetricsServer::new(system_metrics))
        .add_service(StoreServiceServer::new(store_service))
        .add_service(reflection_service) // Exposes the schemas to the outside world
        .serve(addr)
        .await?;

    Ok(())
}
