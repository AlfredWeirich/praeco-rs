use anyhow::{Context, Result};
use serde::Deserialize;
use std::fs;

#[derive(Debug, Deserialize, Clone)]
pub struct RelayConfig {
    pub control_plane_addr: String,
    pub data_plane_addr: String,
    
    pub ca_cert_path: String,
    pub server_cert_path: String,
    pub server_key_path: String,
    
    pub enable_opentelemetry: Option<bool>,
    pub jaeger_endpoint: Option<String>,
    pub otel_log_level: Option<String>,
    pub otel_sample_ratio: Option<f64>,
}

impl Default for RelayConfig {
    fn default() -> Self {
        Self {
            control_plane_addr: "0.0.0.0:7001".into(),
            data_plane_addr: "0.0.0.0:443".into(),
            ca_cert_path: "server_certs/self_signed/myca.pem".into(),
            server_cert_path: "server_certs/self_signed/fullchain_self.pem".into(),
            server_key_path: "server_certs/self_signed/privkey_self.pem".into(),
            enable_opentelemetry: Some(false),
            jaeger_endpoint: Some("http://localhost:4317".into()),
            otel_log_level: Some("info".into()),
            otel_sample_ratio: Some(1.0),
        }
    }
}

impl RelayConfig {
    pub fn load(path: &str) -> Result<Self> {
        if !std::path::Path::new(path).exists() {
            // Return default config if file doesn't exist
            return Ok(Self::default());
        }
        let content = fs::read_to_string(path).context("Failed to read Config.toml")?;
        let config: RelayConfig = toml::from_str(&content).context("Failed to parse Config.toml")?;
        Ok(config)
    }
}
