//! # gRPC Echo Client
//!
//! A Tonic-based gRPC client for the server's Echo service. Demonstrates how
//! to build a Hyper + Rustls HTTPS client, attach mTLS or JWT credentials,
//! and invoke a unary RPC call.
//!
//! ## Usage
//!
//! ```bash
//! cargo run -p client --bin=grpc_client -- -s mtls \
//!   --ca server_certs/self_signed/myca.pem \
//!   -c client_certs/client.cert.pem \
//!   -k client_certs/client.key.pem
//! ```
//!
//! > **Note:** This binary is a scaffold / example. The `EchoClient` and
//! > `EchoRequest` types referenced below must be generated from a `.proto`
//! > definition via `tonic-build` before this will compile.

// === Standard Library ===
use std::time::Instant;

// === External Crates ===
use anyhow::{Context, Error};
use bytes::Bytes;
use clap::{Parser, ValueEnum};
use futures::{StreamExt, stream::FuturesUnordered};
use http_body_util::{BodyExt, Full};
use hyper::{Request, http::uri::Uri};
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use tracing::{error, trace};

// === Internal Modules ===
use common;

/// The main entry point for the gRPC client.
/// It initializes tracing, parses CLI arguments, and executes the client logic.
#[tokio::main]
async fn main() -> Result<(), Error> {
    // Initialize logging/tracing
    // console_subscriber::init(); // Optional: used for tokio console debugging
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    // Validate the provided CLI parameters based on the selected protocol
    validate_cli(&cli);

    // Optional: Retrieve JWT token from file if security protocol requires it
    let _jwt_token = read_jwt(&cli);

    // Construct the networking client (Hyper-based) with appropriate TLS/Auth settings
    let client = build_client(&cli);

    // Build the URI from the CLI parameters
    let scheme = match cli.security {
        Protocol::Https | Protocol::Mtls | Protocol::Jwt => "https",
        Protocol::Http => "http",
    };
    let uri_string = format!("{}://{}", scheme, cli.uri);
    let uri: Uri = uri_string.parse().expect("Invalid URI");

    let concurrency = cli.num_parallel as usize;
    let total_requests = cli.num_req as usize;

    // We clone the client for the closure since the HTTP connector needs to be shared
    run_sliding_window(total_requests, concurrency, "gRPC request failed", || {
        let uri = uri.clone();
        let client_clone = client.clone();

        async move {
            // Placeholder: Demonstrates how to use the generated EchoClient
            // with a specific origin and the configured Hyper client.
            let mut grpc_client = EchoClient::with_origin(client_clone, uri);

            // Construct a standard gRPC Request
            let request = tonic::Request::new(EchoRequest {
                message: "hello".into(),
            });

            // Execute the RPC and await the response
            match grpc_client.unary_echo(request).await {
                Ok(response) => {
                    trace!("RESPONSE={:?}", response);
                    Ok(format!("{:?}", response))
                }
                Err(e) => Err(anyhow::anyhow!("gRPC error: {}", e)),
            }
        }
    })
    .await;

    Ok(())
}

/// Command-line arguments for configuring the client.
#[derive(Parser, Debug)]
#[clap(author, version, about)]
struct Cli {
    /// Total number of requests to send.
    #[clap(short = 'i', long, default_value_t = 10)]
    num_req: u32,

    /// Maximum number of requests in flight at the same time.
    /// Higher values increase throughput but also resource usage.
    #[clap(long, default_value_t = 128)]
    num_parallel: u16,

    #[clap(short = 's', long, value_enum, default_value_t = Protocol::Https)]
    security: Protocol,
    #[clap(short = 'r', long, value_name = "Root ca")]
    ca: Option<String>,
    #[clap(long, short = 'j', value_name = "jwt file")]
    jwt: Option<String>,
    #[clap(short = 'c', long, value_name = "client cert")]
    cert: Option<String>,
    #[clap(short = 'k', long, value_name = "client-key")]
    key: Option<String>,
    #[clap(short = 'u', long, default_value = "192.168.178.31:1337")]
    uri: String,
}

/// Supported protocols.
#[derive(Debug, Clone, ValueEnum, PartialEq)]
enum Protocol {
    Http,
    Https,
    Jwt,
    Mtls,
}

/// Validate CLI arguments according to the protocol requirements.
fn validate_cli(cli: &Cli) {
    match cli.security {
        Protocol::Https => {
            if cli.ca.is_none() {
                // error!("--ca <Root ca> must be set for HTTPS");
                // std::process::exit(1);
            }
        }
        Protocol::Jwt => {
            if cli.ca.is_none() {
                // error!("--ca <Root ca> must be set for JWT");
                // std::process::exit(1);
            }
            if cli.jwt.is_none() {
                error!("--jwt <jwt file> must be set for JWT");
                std::process::exit(1);
            }
        }
        Protocol::Mtls => {
            if cli.ca.is_none() {
                // error!("--ca <Root ca> must be set for mTLS");
                // std::process::exit(1);
            }
            if cli.cert.is_none() || cli.key.is_none() {
                error!("--cert <client cert> and --key <client-key> must be set for mTLS");
                std::process::exit(1);
            }
        }
        Protocol::Http => {}
    }
}

fn build_client(cli: &Cli) -> Client<common::client::HttpsConnector<HttpConnector>, Full<Bytes>> {
    let root_store = common::build_root_store(&cli.ca);
    let tls_client_config = match cli.security {
        Protocol::Http | Protocol::Https | Protocol::Jwt => {
            common::build_tls_client_config(root_store, None, None)
        }
        Protocol::Mtls => {
            common::build_tls_client_config(root_store, cli.cert.as_deref(), cli.key.as_deref())
        }
    };

    let pool_config = common::client::ClientPoolConfig {
        idle_timeout: None,
        max_idle_per_host: Some(1024),
        http2_only: false,
    };

    common::client::build_hyper_client(tls_client_config, pool_config)
}

/// Reads a JWT token from the provided file, if applicable.
fn read_jwt(cli: &Cli) -> Option<String> {
    if let Protocol::Jwt = cli.security {
        let path = cli.jwt.as_ref().unwrap();
        Some(
            std::fs::read_to_string(path)
                .expect("Failed to read JWT")
                .trim()
                .to_string(),
        )
    } else {
        None
    }
}

// /// Build the full request URI based on the protocol and user input.
// fn build_uri(cli: &Cli) -> Uri {
//     let scheme = match cli.security {
//         Protocol::Https | Protocol::Mtls | Protocol::Jwt => "https",
//         Protocol::Http => "http",
//     };
//     let uri = format!("{}://{}{}", scheme, cli.uri, cli.path);
//     let uri = uri.parse().expect("Invalid URI");
//     trace!("Built URI: {}", uri);
//     uri
// }

/// A sliding-window task executor.
/// Keeps up to `concurrency` tasks in flight, running `total_requests` tasks in total,
/// polling them as they complete, and refilling the window.
async fn run_sliding_window<F, Fut>(
    total_requests: usize,
    concurrency: usize,
    err_prefix: &str,
    mut make_future: F,
) where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<String, Error>>,
{
    let mut futs = FuturesUnordered::new();
    let start = Instant::now();
    let mut completed = 0;
    let mut launched = 0;

    // Seed the initial batch
    let first_batch = std::cmp::min(concurrency, total_requests);
    for _ in 0..first_batch {
        futs.push(make_future());
        launched += 1;
    }

    // Poll completions and refill until all are done
    while completed < total_requests {
        if let Some(res) = futs.next().await {
            completed += 1;
            match res {
                Ok(_) => {}
                Err(e) => error!("{err_prefix}: {e}"),
            }

            if launched < total_requests {
                futs.push(make_future());
                launched += 1;
            }
        }
    }

    print_stats(start, total_requests, concurrency);
}

/// Prints throughput statistics after all requests have completed.
fn print_stats(start: Instant, total_requests: usize, concurrency: usize) {
    let duration = start.elapsed();
    let mean = total_requests as f64 / duration.as_secs_f64();
    tracing::info!(
        "\nDuration: {}ms with {} total requests at concurrency {}\nMean requests per second: {mean:.0}  --> per request: {:.1}us",
        duration.as_millis(),
        total_requests,
        concurrency,
        1000000. / mean
    );
}
