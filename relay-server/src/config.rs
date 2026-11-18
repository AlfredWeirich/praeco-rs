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
#[serde(deny_unknown_fields)]
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

    #[test]
    fn test_relay_config_default_values() {
        let cfg = RelayConfig::default();
        assert_eq!(cfg.control_plane_addr, "0.0.0.0:7001");
        assert_eq!(cfg.data_plane_addr, "0.0.0.0:443");
        assert_eq!(cfg.crl_path, None);
        assert_eq!(cfg.enable_opentelemetry, Some(false));
        assert_eq!(cfg.rate_limit_connections_per_sec, Some(50));
        assert_eq!(cfg.rate_limit_burst, Some(100));
        assert_eq!(cfg.data_plane_idle_timeout_secs, Some(1800));
        assert_eq!(cfg.tcp_keepalive_secs, Some(60));
        assert_eq!(cfg.max_concurrent_connections, Some(10000));
        assert_eq!(cfg.max_concurrent_connections_per_ip, Some(100));
        assert_eq!(cfg.client_hello_timeout_secs, Some(10));
        assert_eq!(cfg.control_plane_handshake_timeout_secs, Some(10));
        assert_eq!(cfg.max_yamux_streams, Some(4096));
        assert_eq!(cfg.enable_proxy_protocol, Some(true));
    }

    #[test]
    fn test_relay_config_load_success_and_errors() {
        // 1. Missing file returns ConfigNotFound
        let missing = std::env::temp_dir().join("praeco_relay_nonexistent_config_12345.toml");
        let missing_str = missing.to_string_lossy().to_string();
        assert!(matches!(
            RelayConfig::load(&missing_str),
            Err(RelayError::ConfigNotFound(_))
        ));

        // 2. Invalid TOML returns ConfigParse
        let bad_path = std::env::temp_dir().join(format!(
            "praeco_relay_bad_config_{}.toml",
            std::process::id()
        ));
        fs::write(&bad_path, "this is = [not valid toml").unwrap();
        let bad_res = RelayConfig::load(&bad_path.to_string_lossy());
        let _ = fs::remove_file(&bad_path);
        assert!(matches!(bad_res, Err(RelayError::ConfigParse(_))));

        // 3. Valid TOML file loads cleanly
        let ok_path = std::env::temp_dir().join(format!(
            "praeco_relay_ok_config_{}.toml",
            std::process::id()
        ));
        let valid_toml = r#"
            control_plane_addr = "127.0.0.1:7101"
            data_plane_addr = "127.0.0.1:8443"
            ca_cert_path = "ca.pem"
            server_cert_path = "cert.pem"
            server_key_path = "key.pem"
            enable_proxy_protocol = false
        "#;
        fs::write(&ok_path, valid_toml).unwrap();
        let loaded = RelayConfig::load(&ok_path.to_string_lossy()).expect("valid config should load");
        let _ = fs::remove_file(&ok_path);
        assert_eq!(loaded.control_plane_addr, "127.0.0.1:7101");
        assert_eq!(loaded.data_plane_addr, "127.0.0.1:8443");
        assert_eq!(loaded.enable_proxy_protocol, Some(false));

        // 4. Unknown fields (e.g. typo in crl_path) must be rejected
        let typo_path = std::env::temp_dir().join(format!(
            "praeco_relay_typo_config_{}.toml",
            std::process::id()
        ));
        let typo_toml = r#"
            control_plane_addr = "127.0.0.1:7101"
            data_plane_addr = "127.0.0.1:8443"
            ca_cert_path = "ca.pem"
            server_cert_path = "cert.pem"
            server_key_path = "key.pem"
            crl_pth = "revoked.crl.pem"
        "#;
        fs::write(&typo_path, typo_toml).unwrap();
        let typo_res = RelayConfig::load(&typo_path.to_string_lossy());
        let _ = fs::remove_file(&typo_path);
        assert!(matches!(typo_res, Err(RelayError::ConfigParse(_))));
    }
}
