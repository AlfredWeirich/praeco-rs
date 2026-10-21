use hyper::body::Body;
pub use hyper_rustls::HttpsConnector;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::client::legacy::{Client, connect::HttpConnector};
use hyper_util::rt::{TokioExecutor, TokioTimer};
use rustls::ClientConfig;
use std::time::Duration;

/// Configuration options for the hyper connection pool and transport.
#[derive(Debug, Clone)]
pub struct ClientPoolConfig {
    /// Closes idle connections in the pool after this duration.
    pub idle_timeout: Option<Duration>,
    /// The maximum number of idle connections maintained per host.
    pub max_idle_per_host: Option<usize>,
    /// If true, HTTP/1.1 is omitted from the ALPN negotiation and only HTTP/2 is used.
    pub http2_only: bool,
    /// TCP connection establishment timeout (default: 5s).
    pub connect_timeout: Option<Duration>,
    /// TCP keep-alive probe interval (default: 60s).
    pub tcp_keepalive: Option<Duration>,
    /// Whether to enable TCP_NODELAY (default: true).
    pub tcp_nodelay: bool,
    /// HTTP/2 PING interval to detect dead connections (default: 30s).
    pub http2_keep_alive_interval: Option<Duration>,
    /// Timeout for HTTP/2 PING response before dropping connection (default: 10s).
    pub http2_keep_alive_timeout: Option<Duration>,
    /// Whether to send HTTP/2 PING probes even when connection is idle (default: true).
    pub http2_keep_alive_while_idle: bool,
    /// Automatically adjust HTTP/2 flow control window size based on throughput (default: true).
    pub http2_adaptive_window: bool,
}

impl Default for ClientPoolConfig {
    fn default() -> Self {
        Self {
            idle_timeout: Some(Duration::from_secs(90)),
            max_idle_per_host: Some(1024),
            http2_only: false,
            connect_timeout: Some(Duration::from_secs(5)),
            tcp_keepalive: Some(Duration::from_secs(60)),
            tcp_nodelay: true,
            http2_keep_alive_interval: Some(Duration::from_secs(30)),
            http2_keep_alive_timeout: Some(Duration::from_secs(10)),
            http2_keep_alive_while_idle: true,
            http2_adaptive_window: true,
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
    // Build and configure the underlying TCP connector
    let mut http_connector = HttpConnector::new();
    http_connector.enforce_http(false);
    if let Some(ct) = pool_config.connect_timeout {
        http_connector.set_connect_timeout(Some(ct));
    }
    http_connector.set_keepalive(pool_config.tcp_keepalive);
    http_connector.set_nodelay(pool_config.tcp_nodelay);

    // Build the underlying TLS connector wrapping our configured TCP connector.
    // It is configured to accept both `http://` and `https://` schemes.
    let https_builder = HttpsConnectorBuilder::new()
        .with_tls_config(tls_config)
        .https_or_http();

    let https_connector = if pool_config.http2_only {
        https_builder.enable_http2().wrap_connector(http_connector)
    } else {
        https_builder
            .enable_http1()
            .enable_http2()
            .wrap_connector(http_connector)
    };

    // Configure the connection builder on top of Tokio logic.
    let mut builder = Client::builder(TokioExecutor::new());

    // Register Tokio timer so pool_idle_timeout and HTTP/2 keep-alive are actively scheduled
    builder.pool_timer(TokioTimer::new());
    builder.timer(TokioTimer::new());

    if let Some(timeout) = pool_config.idle_timeout {
        builder.pool_idle_timeout(timeout);
    }

    if let Some(max_idle) = pool_config.max_idle_per_host {
        builder.pool_max_idle_per_host(max_idle);
    }

    if pool_config.http2_only {
        builder.http2_only(true);
    }

    if let Some(interval) = pool_config.http2_keep_alive_interval {
        builder.http2_keep_alive_interval(interval);
    }

    if let Some(timeout) = pool_config.http2_keep_alive_timeout {
        builder.http2_keep_alive_timeout(timeout);
    }

    builder.http2_keep_alive_while_idle(pool_config.http2_keep_alive_while_idle);

    if pool_config.http2_adaptive_window {
        builder.http2_adaptive_window(true);
    }

    builder.build(https_connector)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_client_pool_config_defaults() {
        let cfg = ClientPoolConfig::default();
        assert_eq!(cfg.idle_timeout, Some(Duration::from_secs(90)));
        assert_eq!(cfg.max_idle_per_host, Some(1024));
        assert!(!cfg.http2_only);
        assert_eq!(cfg.connect_timeout, Some(Duration::from_secs(5)));
        assert_eq!(cfg.tcp_keepalive, Some(Duration::from_secs(60)));
        assert!(cfg.tcp_nodelay);
        assert_eq!(cfg.http2_keep_alive_interval, Some(Duration::from_secs(30)));
        assert_eq!(cfg.http2_keep_alive_timeout, Some(Duration::from_secs(10)));
        assert!(cfg.http2_keep_alive_while_idle);
        assert!(cfg.http2_adaptive_window);
    }

    #[test]
    fn test_build_hyper_client_with_custom_keepalive_and_timeouts() {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
        let root_store = rustls::RootCertStore::empty();
        let tls_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let cfg = ClientPoolConfig {
            connect_timeout: Some(Duration::from_secs(3)),
            tcp_keepalive: Some(Duration::from_secs(15)),
            tcp_nodelay: true,
            http2_keep_alive_interval: Some(Duration::from_secs(10)),
            http2_keep_alive_timeout: Some(Duration::from_secs(5)),
            http2_keep_alive_while_idle: false,
            http2_adaptive_window: true,
            http2_only: true,
            idle_timeout: Some(Duration::from_secs(45)),
            max_idle_per_host: Some(32),
        };

        let _client: Client<HttpsConnector<HttpConnector>, hyper::body::Incoming> =
            build_hyper_client(tls_config, cfg);
    }
}
