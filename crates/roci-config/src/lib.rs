//! Configuration schema for roci. Zero-config by default; a declarative file
//! overrides individual fields as the deployment grows.
#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Top-level runtime configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Address the HTTP server binds to.
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// Root directory of the content-addressable store.
    #[serde(default = "default_storage_root")]
    pub storage_root: PathBuf,
    /// Whether manifest and blob deletion are allowed. Disabled deployments
    /// return 405 on deletion endpoints (CVE-2026-41888 mitigation track).
    #[serde(default = "default_delete_config")]
    pub delete: DeleteConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteConfig {
    /// When true, delete endpoints are accepted; false returns 405.
    #[serde(default = "default_delete_enabled")]
    pub enabled: bool,
}

impl Default for DeleteConfig {
    fn default() -> Self {
        Self {
            enabled: default_delete_enabled(),
        }
    }
}

/// Return a `DeleteConfig` (used by serde `default` for the `Config.delete` field).
fn default_delete_config() -> DeleteConfig {
    DeleteConfig::default()
}

fn default_delete_enabled() -> bool {
    true
}

fn default_listen() -> SocketAddr {
    "127.0.0.1:5000".parse().expect("valid default listen addr")
}

fn default_storage_root() -> PathBuf {
    PathBuf::from("./roci-data")
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            storage_root: default_storage_root(),
            delete: DeleteConfig::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_sane() {
        let c = Config::default();
        assert_eq!(c.listen.port(), 5000);
        assert!(c.listen.ip().is_loopback());
        assert!(c.delete.enabled);
    }

    #[test]
    fn omitted_delete_section_or_field_defaults_to_enabled() {
        // Pre-Phase-3 configs have no `delete` section at all.
        let c: Config = serde_json::from_str(r#"{"listen":"127.0.0.1:1"}"#).unwrap();
        assert!(c.delete.enabled);
        // An empty `delete` object keeps the per-field default.
        let c: Config = serde_json::from_str(r#"{"delete":{}}"#).unwrap();
        assert!(c.delete.enabled);
    }

    #[test]
    fn delete_can_be_disabled_via_config() {
        let c: Config = serde_json::from_str(r#"{"delete":{"enabled":false}}"#).unwrap();
        assert!(!c.delete.enabled);
    }
}
