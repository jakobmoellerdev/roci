//! Configuration schema for roci. Zero-config by default; a single declarative
//! TOML file overrides individual fields as the deployment grows
//! (ARCHITECTURE.md §Configuration model). Every section and field is optional;
//! unknown keys are rejected, and [`Config::validate`] runs on every load so a
//! bad file fails fast with a field-qualified message.
#![forbid(unsafe_code)]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Top-level runtime configuration.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub http: HttpConfig,
    pub storage: StorageConfig,
    pub limits: LimitsConfig,
    pub delete: DeleteConfig,
    pub log: LogConfig,
    pub telemetry: TelemetryConfig,
}

/// `[http]` — listener, TLS, timeouts, rate limits.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HttpConfig {
    /// Address the HTTP server binds to.
    pub listen: SocketAddr,
    /// TLS termination; absent → plaintext (HTTP/1.1 + h2c).
    pub tls: Option<TlsConfig>,
    pub timeouts: TimeoutsConfig,
    pub rate_limit: RateLimitConfig,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:5000".parse().expect("valid default listen addr"),
            tls: None,
            timeouts: TimeoutsConfig::default(),
            rate_limit: RateLimitConfig::default(),
        }
    }
}

/// `[http.tls]` — PEM server certificate chain + private key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub cert: PathBuf,
    pub key: PathBuf,
}

/// `[http.timeouts]` — slow-loris / stalled-peer bounds (SECURITY inv. 14).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TimeoutsConfig {
    /// Max seconds to receive a complete request head.
    pub read_header_secs: u64,
    /// Seconds an idle keep-alive connection is held open.
    pub idle_secs: u64,
}

impl Default for TimeoutsConfig {
    fn default() -> Self {
        Self {
            read_header_secs: 10,
            idle_secs: 120,
        }
    }
}

/// `[http.rate_limit]` — token buckets; exhausted → `429 TOOMANYREQUESTS`.
/// Disabled by default (zero-config local registry).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RateLimitConfig {
    pub enabled: bool,
    /// Bucket for methods without a `per_method` entry; `None` → unlimited.
    pub default: Option<Bucket>,
    /// Per-HTTP-method buckets keyed by upper-case method (`GET`, `PUT`, …).
    pub per_method: BTreeMap<String, Bucket>,
}

/// One token bucket: sustained `rate` requests/second, `burst` capacity.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bucket {
    pub rate: u32,
    pub burst: u32,
}

/// `[storage]` — local backend.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageConfig {
    /// Root directory of the content-addressable store.
    pub root: PathBuf,
    /// Byte budget of the small-blob LRU content cache (0 disables it).
    pub cache_max_bytes: usize,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            root: PathBuf::from("./roci-data"),
            cache_max_bytes: 256 * 1024 * 1024,
        }
    }
}

/// `[limits]` — bounded-input guards (SECURITY inv. 14).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    /// Max accepted request-body bytes (one chunk / monolithic body).
    pub max_body: usize,
    /// Max cumulative bytes of one upload session.
    pub max_upload: u64,
    /// Max manifest bytes, checked before JSON parse.
    pub max_manifest: usize,
    /// Server-side cap on `n` for tag/referrer pagination.
    pub max_page: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_body: 256 * 1024 * 1024,
            max_upload: 5 * 1024 * 1024 * 1024,
            max_manifest: 4 * 1024 * 1024,
            max_page: 1000,
        }
    }
}

/// `[delete]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DeleteConfig {
    /// When true, delete endpoints are accepted; false returns 405
    /// (CVE-2026-41888 mitigation track).
    pub enabled: bool,
}

impl Default for DeleteConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// `[log]`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LogConfig {
    /// `EnvFilter` directive (e.g. `info`, `roci_core=debug`); `RUST_LOG` wins.
    pub level: String,
    pub format: LogFormat,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".into(),
            format: LogFormat::Text,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

/// `[telemetry]` — OpenTelemetry export (effective only in `otel` builds).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TelemetryConfig {
    /// OTLP export of traces+metrics+logs; absent → no export.
    pub otlp: Option<OtlpConfig>,
    /// Head-sampling ratio in `[0, 1]` for root traces.
    pub sample_ratio: f64,
    /// Prometheus scrape view over the same meters.
    pub metrics: MetricsConfig,
}

impl Default for TelemetryConfig {
    fn default() -> Self {
        Self {
            otlp: None,
            sample_ratio: 0.01,
            metrics: MetricsConfig::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OtlpConfig {
    /// Collector endpoint, e.g. `http://localhost:4317` (gRPC) or `:4318` (HTTP).
    pub endpoint: String,
    #[serde(default)]
    pub protocol: OtlpProtocol,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OtlpProtocol {
    #[default]
    Grpc,
    Http,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MetricsConfig {
    /// Serve `GET <path>` in Prometheus text format.
    pub enabled: bool,
    pub path: String,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: "/metrics".into(),
        }
    }
}

/// Load/validation failure, carrying the offending field path.
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading config {path}: {source}")]
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("parsing config {path}: {source}")]
    Parse {
        path: PathBuf,
        source: Box<toml::de::Error>,
    },
    #[error("invalid config: {field}: {reason}")]
    Invalid { field: String, reason: String },
}

fn invalid(field: impl Into<String>, reason: impl Into<String>) -> ConfigError {
    ConfigError::Invalid {
        field: field.into(),
        reason: reason.into(),
    }
}

const METHODS: [&str; 6] = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"];

impl Config {
    /// Read, parse, and validate a TOML config file.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let config: Config = toml::from_str(&text).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source: Box::new(source),
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Check cross-field invariants serde cannot express.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let l = &self.limits;
        for (field, v) in [
            ("limits.max_body", l.max_body as u64),
            ("limits.max_upload", l.max_upload),
            ("limits.max_manifest", l.max_manifest as u64),
            ("limits.max_page", l.max_page as u64),
            (
                "http.timeouts.read_header_secs",
                self.http.timeouts.read_header_secs,
            ),
        ] {
            if v == 0 {
                return Err(invalid(field, "must be > 0"));
            }
        }
        if l.max_manifest > l.max_body {
            return Err(invalid("limits.max_manifest", "must be <= limits.max_body"));
        }
        let rl = &self.http.rate_limit;
        let buckets = rl
            .default
            .iter()
            .map(|b| ("http.rate_limit.default".to_string(), b))
            .chain(
                rl.per_method
                    .iter()
                    .map(|(m, b)| (format!("http.rate_limit.per_method.{m}"), b)),
            );
        for (field, b) in buckets {
            if b.rate == 0 || b.burst == 0 {
                return Err(invalid(field, "rate and burst must be > 0"));
            }
        }
        if let Some(m) = rl
            .per_method
            .keys()
            .find(|m| !METHODS.contains(&m.as_str()))
        {
            return Err(invalid(
                format!("http.rate_limit.per_method.{m}"),
                format!("unknown method; expected one of {METHODS:?}"),
            ));
        }
        let t = &self.telemetry;
        if !(0.0..=1.0).contains(&t.sample_ratio) {
            return Err(invalid("telemetry.sample_ratio", "must be within [0, 1]"));
        }
        if !t.metrics.path.starts_with('/') || t.metrics.path.starts_with("/v2") {
            return Err(invalid(
                "telemetry.metrics.path",
                "must start with '/' and not collide with /v2",
            ));
        }
        if let Some(o) = &t.otlp {
            if o.endpoint.is_empty() {
                return Err(invalid("telemetry.otlp.endpoint", "must not be empty"));
            }
        }
        if self.log.level.trim().is_empty() {
            return Err(invalid("log.level", "must not be empty"));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<Config, String> {
        let c: Config = toml::from_str(s).map_err(|e| e.to_string())?;
        c.validate().map_err(|e| e.to_string())?;
        Ok(c)
    }

    #[test]
    fn empty_file_equals_zero_config_defaults() {
        let c = parse("").unwrap();
        assert_eq!(c, Config::default());
        assert!(c.http.listen.ip().is_loopback());
        assert_eq!(c.http.listen.port(), 5000);
        assert!(c.delete.enabled);
        assert!(!c.http.rate_limit.enabled);
        c.validate().unwrap();
    }

    #[test]
    fn full_file_round_trips() {
        let c = parse(
            r#"
            [http]
            listen = "0.0.0.0:8443"
            tls = { cert = "/c.pem", key = "/k.pem" }
            timeouts = { read_header_secs = 5, idle_secs = 30 }
            [http.rate_limit]
            enabled = true
            default = { rate = 100, burst = 200 }
            per_method.PUT = { rate = 10, burst = 20 }
            [storage]
            root = "/var/lib/roci"
            cache_max_bytes = 0
            [limits]
            max_page = 50
            [delete]
            enabled = false
            [log]
            level = "debug"
            format = "json"
            [telemetry]
            sample_ratio = 0.5
            otlp = { endpoint = "http://otel:4318", protocol = "http" }
            metrics = { enabled = true }
            "#,
        )
        .unwrap();
        assert_eq!(c.http.listen.port(), 8443);
        assert_eq!(c.http.rate_limit.per_method["PUT"].rate, 10);
        assert_eq!(c.limits.max_page, 50);
        assert_eq!(c.limits.max_body, LimitsConfig::default().max_body);
        assert_eq!(c.log.format, LogFormat::Json);
        assert_eq!(
            c.telemetry.otlp.as_ref().unwrap().protocol,
            OtlpProtocol::Http
        );
        assert_eq!(c.telemetry.metrics.path, "/metrics");
        let back: Config = toml::from_str(&toml::to_string(&c).unwrap()).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn rejects_unknown_keys_and_bad_values() {
        for (src, needle) in [
            ("bogus = 1", "unknown field"),
            ("[storage]\nroott = \"x\"", "unknown field"),
            ("[limits]\nmax_page = 0", "limits.max_page"),
            (
                "[limits]\nmax_body = 10\nmax_manifest = 20",
                "limits.max_manifest",
            ),
            (
                "[http.rate_limit.per_method]\nFETCH = { rate = 1, burst = 1 }",
                "per_method.FETCH",
            ),
            (
                "[http.rate_limit]\ndefault = { rate = 0, burst = 1 }",
                "http.rate_limit.default",
            ),
            ("[telemetry]\nsample_ratio = 1.5", "sample_ratio"),
            ("[telemetry.metrics]\npath = \"/v2/m\"", "metrics.path"),
            ("[telemetry.otlp]\nendpoint = \"\"", "otlp.endpoint"),
            ("[log]\nlevel = \" \"", "log.level"),
            ("[http.timeouts]\nread_header_secs = 0", "read_header_secs"),
        ] {
            let err = parse(src).unwrap_err();
            assert!(err.contains(needle), "{src:?} → {err}");
        }
    }

    #[test]
    fn load_reports_io_and_parse_errors_with_path() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.toml");
        assert!(matches!(
            Config::load(&missing),
            Err(ConfigError::Io { .. })
        ));
        let bad = dir.path().join("bad.toml");
        std::fs::write(&bad, "[http\n").unwrap();
        let err = Config::load(&bad).unwrap_err();
        assert!(matches!(err, ConfigError::Parse { .. }));
        assert!(err.to_string().contains("bad.toml"));
        let ok = dir.path().join("ok.toml");
        std::fs::write(&ok, "[delete]\nenabled = false\n").unwrap();
        assert!(!Config::load(&ok).unwrap().delete.enabled);
        std::fs::write(&ok, "[limits]\nmax_page = 0\n").unwrap();
        assert!(matches!(
            Config::load(&ok),
            Err(ConfigError::Invalid { .. })
        ));
    }
}
