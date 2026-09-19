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
    }
}
