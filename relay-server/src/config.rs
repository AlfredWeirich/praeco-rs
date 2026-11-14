//! # Relay Server Configuration
//!
//! This module defines the `RelayConfig` struct which contains all
//! configuration options for the Praeco Relay Server, including
//! network addresses, TLS certificate paths, and OpenTelemetry settings.

use crate::RelayError;
use serde::Deserialize;
use std::fs;

/// Configuration for the Praeco Relay Server.
#[derive(Debug, Deserialize, Clone)]
pub struct RelayConfig {
    /// The address (IP:Port) where the control plane (mTLS from Praeco) listens.
    pub control_plane_addr: String,
    /// The address (IP:Port) where the data plane (public HTTPS traffic) listens.
    pub data_plane_addr: String,
    
    /// Path to the Certificate Authority (CA) used to verify connecting Praeco instances.
    pub ca_cert_path: String,
    /// Path to the server's public certificate chain for the control plane.
    pub server_cert_path: String,
    /// Path to the server's private key for the control plane.
    pub server_key_path: String,
    
    /// Optional path to a Certificate Revocation List (CRL) for rejecting revoked Gateways.
    pub crl_path: Option<String>,
    
    /// Flag to enable or disable OpenTelemetry Tracing (Jaeger).
    pub enable_opentelemetry: Option<bool>,
    /// Jaeger OTLP gRPC endpoint.
    pub jaeger_endpoint: Option<String>,
    /// Log level for traces exported to Jaeger.
    pub otel_log_level: Option<String>,
    /// Sampling ratio for OTLP traces (0.0 to 1.0).
    pub otel_sample_ratio: Option<f64>,
    
    /// Optional directory path for persistent, non-blocking daily rolling log files.
    /// If omitted or None, the relay server will only log to Standard Output (stdout).
    pub log_dir: Option<String>,
    
    /// Max allowed new TCP connections per second per IP.
    pub rate_limit_connections_per_sec: Option<u32>,
    /// Max allowed burst of TCP connections per IP.
    pub rate_limit_burst: Option<u32>,

    /// Idle timeout in seconds for data plane connections (0 or None = disabled).
    pub data_plane_idle_timeout_secs: Option<u64>,
    /// TCP keepalive probe interval in seconds on the data plane sockets.
    pub tcp_keepalive_secs: Option<u64>,

    /// Optional limit on the total number of concurrent data plane connections (default: 10000).
    pub max_concurrent_connections: Option<usize>,
    /// Optional limit on the number of concurrent data plane connections per IP /64 (default: 100).
    pub max_concurrent_connections_per_ip: Option<usize>,
    /// Timeout in seconds to read the TLS ClientHello on the data plane (default: 10).
    pub client_hello_timeout_secs: Option<u64>,
    /// Timeout in seconds for the mTLS handshake on the control plane (default: 10).
    pub control_plane_handshake_timeout_secs: Option<u64>,
    /// Max concurrent Yamux streams per tunnel connection (default: 4096).
    pub max_yamux_streams: Option<usize>,
    /// Whether to enable PROXY-Protocol v2 for tunnels that negotiate it (default: true).
    pub enable_proxy_protocol: Option<bool>,
}

impl Default for RelayConfig {
    /// Provides sensible default values for local development and testing.
    fn default() -> Self {
        Self {
            control_plane_addr: "0.0.0.0:7001".into(),
            data_plane_addr: "0.0.0.0:443".into(),
            ca_cert_path: "server_certs/self_signed/myca.pem".into(),
            server_cert_path: "server_certs/self_signed/fullchain_self.pem".into(),
            server_key_path: "server_certs/self_signed/privkey_self.pem".into(),
            crl_path: None,
            enable_opentelemetry: Some(false),
            jaeger_endpoint: Some("http://localhost:4317".into()),
            otel_log_level: Some("info".into()),
            otel_sample_ratio: Some(1.0),
            log_dir: None,
            rate_limit_connections_per_sec: Some(50),
            rate_limit_burst: Some(100),
            data_plane_idle_timeout_secs: Some(1800),
            tcp_keepalive_secs: Some(60),
            max_concurrent_connections: Some(10000),
            max_concurrent_connections_per_ip: Some(100),
            client_hello_timeout_secs: Some(10),
            control_plane_handshake_timeout_secs: Some(10),
            max_yamux_streams: Some(4096),
            enable_proxy_protocol: Some(true),
        }
    }
}

impl RelayConfig {
    /// Loads the configuration from a TOML file at the specified path.
    /// 
    /// # Arguments
    /// 
    /// * `path` - The file path to the TOML configuration file.
    /// 
    /// # Errors
    /// 
    /// Returns a [`RelayError`] if the file does not exist, cannot be read, or fails to parse.
    pub fn load(path: &str) -> Result<Self, RelayError> {
        if !std::path::Path::new(path).exists() {
            return Err(RelayError::ConfigNotFound(path.to_string()));
        }
        let content = fs::read_to_string(path).map_err(|source| RelayError::ConfigRead {
            path: path.to_string(),
            source,
        })?;
        let config: RelayConfig = toml::from_str(&content)?;
        Ok(config)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_relay_config_log_dir_parsing() {
        let toml_str = r#"
            control_plane_addr = "0.0.0.0:7001"
            data_plane_addr = "0.0.0.0:443"
            ca_cert_path = "ca.pem"
            server_cert_path = "cert.pem"
            server_key_path = "key.pem"
            log_dir = "log/relay"
        "#;
        let config: RelayConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.log_dir.as_deref(), Some("log/relay"));
    }

    #[test]
    fn test_relay_config_log_dir_optional_default() {
        let toml_str = r#"
            control_plane_addr = "0.0.0.0:7001"
            data_plane_addr = "0.0.0.0:443"
            ca_cert_path = "ca.pem"
            server_cert_path = "cert.pem"
            server_key_path = "key.pem"
        "#;
        let config: RelayConfig = toml::from_str(toml_str).unwrap();
        assert_eq!(config.log_dir, None);
    }
}
