use hyper::body::Body;
pub use hyper_rustls::HttpsConnector;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::TokioExecutor;
use rustls::ClientConfig;
use std::time::Duration;

/// Configuration options for the hyper connection pool.
#[derive(Debug, Clone)]
pub struct ClientPoolConfig {
    /// Closes idle connections in the pool after this duration.
    pub idle_timeout: Option<Duration>,
    /// The maximum number of idle connections maintained per host.
    pub max_idle_per_host: Option<usize>,
    /// If true, HTTP/1.1 is omitted from the ALPN negotiation and only HTTP/2 is used.
    pub http2_only: bool,
}

impl Default for ClientPoolConfig {
    fn default() -> Self {
        Self {
            idle_timeout: Some(Duration::from_secs(90)),
            max_idle_per_host: Some(1024),
            http2_only: false,
        }
    }
}

/// Builds a `hyper_util::client::legacy::Client` equipped with a Rustls HTTPS connector.
///
/// This shared helper reduces boilerplate and ensures connection pool settings (like timeouts
/// and connection limits) are configured consistently across all backend connections, whether
/// used by the router, background health checks, or the testing client.
///
/// # Arguments
///
/// * `tls_config` – A customized Rustls `ClientConfig` (e.g. built by `common::build_tls_client_config`).
/// * `pool_config` – Pool and protocol behaviour settings.
///
/// # Returns
///
/// A generic `Client` that can issue requests with generic body types `B`.
pub fn build_hyper_client<B>(
    tls_config: ClientConfig,
    pool_config: ClientPoolConfig,
) -> Client<HttpsConnector<HttpConnector>, B>
where
    B: Body + Send + Unpin + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    // Build the underlying TLS connector.
    // It is configured to accept both `http://` and `https://` schemes.
    let https_builder = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http();

    let https_connector = if pool_config.http2_only {
        https_builder.enable_http2().build()
    } else {
        https_builder.enable_http1().enable_http2().build()
    };

    // Configure the connection builder on top of Tokio logic.
    let mut builder = Client::builder(TokioExecutor::new());

    if let Some(timeout) = pool_config.idle_timeout {
        builder.pool_idle_timeout(timeout);
    }

    if let Some(max_idle) = pool_config.max_idle_per_host {
        builder.pool_max_idle_per_host(max_idle);
    }

    if pool_config.http2_only {
        builder.http2_only(true);
    }

    // You can add further generic options here (e.g. keeping TCP_NODELAY sync)
    // builder.http2_initial_stream_window_size(1024 * 1024);

    builder.build(https_connector)
}
