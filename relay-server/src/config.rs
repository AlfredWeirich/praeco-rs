//! # Relay Server Configuration
//!
//! This module defines the `RelayConfig` struct which contains all
//! configuration options for the Praeco Relay Server, including
//! network addresses, TLS certificate paths, and OpenTelemetry settings.

use anyhow::{Context, Result};
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
    
    /// Max allowed new TCP connections per second per IP.
    pub rate_limit_connections_per_sec: Option<u32>,
    /// Max allowed burst of TCP connections per IP.
    pub rate_limit_burst: Option<u32>,
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
            rate_limit_connections_per_sec: Some(50),
            rate_limit_burst: Some(100),
        }
    }
}

impl RelayConfig {
    /// Loads the configuration from a TOML file at the specified path.
    /// If the file does not exist, it falls back to `RelayConfig::default()`.
    /// 
    /// # Arguments
    /// 
    /// * `path` - The file path to the TOML configuration file.
    /// 
    /// # Returns
    /// 
    /// Returns a parsed `RelayConfig` or an error if parsing fails.
    pub fn load(path: &str) -> Result<Self> {
        if !std::path::Path::new(path).exists() {
            anyhow::bail!("Configuration file not found at path: {}. A valid configuration is strictly required for secure Relay operation.", path);
        }
        let content = fs::read_to_string(path).context("Failed to read Config.toml")?;
        let config: RelayConfig = toml::from_str(&content).context("Failed to parse Config.toml")?;
        Ok(config)
    }
}
