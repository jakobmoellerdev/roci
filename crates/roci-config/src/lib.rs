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

/// `[storage]` — the default backend plus every storage subsystem knob.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageConfig {
    /// Root directory. For the filesystem backend it is the OCI-layout root;
    /// with `s3` set it holds only local state (metadata log, upload staging).
    pub root: PathBuf,
    /// Byte budget of the small-blob LRU content cache (0 disables it).
    pub cache_max_bytes: usize,
    /// Cross-repo dedupe of uploaded blobs: a blob already stored in another
    /// repo is linked (reflink → hard link) instead of kept as a second copy.
    pub dedupe: bool,
    /// Remote object-store backend for this root (needs the `s3` build).
    pub s3: Option<S3Config>,
    /// Repo-name prefix → backend routing (zot `subPaths`); the longest
    /// matching prefix (on a `/` component boundary) wins.
    pub subpaths: BTreeMap<String, SubpathConfig>,
    pub gc: GcConfig,
    pub scrub: ScrubConfig,
    pub quota: QuotaConfig,
    pub metadata: MetadataConfig,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            root: PathBuf::from("./roci-data"),
            cache_max_bytes: 256 * 1024 * 1024,
            dedupe: true,
            s3: None,
            subpaths: BTreeMap::new(),
            gc: GcConfig::default(),
            scrub: ScrubConfig::default(),
            quota: QuotaConfig::default(),
            metadata: MetadataConfig::default(),
        }
    }
}

/// `[storage.subpaths."<prefix>"]` — a separate backend for one repo prefix.
/// Subsystem policies (`gc`, `scrub`, `quota`, `metadata`, `dedupe`) are
/// shared with `[storage]`; only the backend location differs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubpathConfig {
    /// Root directory (layout root, or local state dir when `s3` is set).
    pub root: PathBuf,
    #[serde(default)]
    pub s3: Option<S3Config>,
}

/// `s3 = { … }` — an S3-compatible object-store backend.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct S3Config {
    pub bucket: String,
    #[serde(default = "default_s3_region")]
    pub region: String,
    /// Custom endpoint for S3-compatible stores (MinIO, R2, Ceph); absent →
    /// AWS for `region`.
    #[serde(default)]
    pub endpoint: Option<String>,
    /// Key prefix inside the bucket (no leading/trailing `/`).
    #[serde(default)]
    pub prefix: String,
    /// Static access key id; absent → the environment/instance credential chain.
    #[serde(default)]
    pub access_key_id: Option<String>,
    /// File holding the secret access key (kept out of the config file so it
    /// can carry stricter permissions / a Kubernetes Secret mount).
    #[serde(default)]
    pub secret_access_key_file: Option<PathBuf>,
    /// Permit a plaintext `http://` endpoint (local MinIO); off by default.
    #[serde(default)]
    pub allow_http: bool,
    /// Blob GETs at or above this size are answered with a `307` to a
    /// short-lived signed URL; smaller blobs are proxied. `0` disables.
    #[serde(default = "default_redirect_min_size")]
    pub redirect_min_size: u64,
    /// Lifetime of a redirect's signed URL, `1..=60` seconds.
    #[serde(default = "default_redirect_ttl_secs")]
    pub redirect_ttl_secs: u64,
    /// Multipart part size in bytes (≥ 5 MiB, the S3 minimum).
    #[serde(default = "default_multipart_part_size")]
    pub multipart_part_size: u64,
    /// Parts transferred in parallel per multipart upload/copy.
    #[serde(default = "default_multipart_concurrency")]
    pub multipart_concurrency: usize,
}

fn default_s3_region() -> String {
    "us-east-1".into()
}
fn default_redirect_min_size() -> u64 {
    1024 * 1024
}
fn default_redirect_ttl_secs() -> u64 {
    60
}
fn default_multipart_part_size() -> u64 {
    16 * 1024 * 1024
}
fn default_multipart_concurrency() -> usize {
    8
}

/// The S3 multipart minimum part size (every part but the last).
pub const S3_MIN_PART_SIZE: u64 = 5 * 1024 * 1024;

/// `[storage.gc]` — online garbage collection (zot `gc`/`gcDelay`/`gcInterval`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GcConfig {
    pub enabled: bool,
    /// Grace period: an unreferenced blob is collected only after it has been
    /// unreferenced and untouched for this long.
    pub delay_secs: u64,
    /// Period between sweeps.
    pub interval_secs: u64,
}

impl Default for GcConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            delay_secs: 3600,
            interval_secs: 3600,
        }
    }
}

/// `[storage.scrub]` — background integrity verification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ScrubConfig {
    pub enabled: bool,
    /// Target period of one full pass over the store.
    pub interval_secs: u64,
    /// Read-bandwidth ceiling for the scrub pass (bytes/second).
    pub max_bytes_per_sec: u64,
    pub mode: ScrubMode,
}

impl Default for ScrubConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: 24 * 3600,
            max_bytes_per_sec: 64 * 1024 * 1024,
            mode: ScrubMode::Auto,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScrubMode {
    /// Delegate to the filesystem's own scrub on btrfs/ZFS (app pass off);
    /// run the application pass everywhere else.
    #[default]
    Auto,
    /// Always run the application pass, even on a self-checksumming FS.
    App,
}

/// `[storage.quota]` — exhaustion guards (SECURITY §Storage boundary).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct QuotaConfig {
    /// Per-repository byte cap; `0` = unlimited. Exceeded → `413`.
    pub max_repo_bytes: u64,
    /// Registry-wide byte cap; `0` = unlimited. Exceeded → `507`.
    pub max_total_bytes: u64,
    /// Concurrent upload sessions across the registry; `0` = unlimited.
    /// Exceeded → `429 TOOMANYREQUESTS`.
    pub max_upload_sessions: usize,
}

impl Default for QuotaConfig {
    fn default() -> Self {
        Self {
            max_repo_bytes: 0,
            max_total_bytes: 0,
            max_upload_sessions: 1024,
        }
    }
}

/// `[storage.metadata]` — the derived metadata index engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MetadataConfig {
    pub engine: MetadataEngine,
    /// Serve the log engine's state from an rkyv `mmap` snapshot plus the
    /// post-snapshot log tail (fast cold start, demand-paged RSS).
    pub snapshot: bool,
    /// Compact the log (or cut a new snapshot) once it grows past this size.
    pub compact_threshold_bytes: u64,
    /// File holding a per-deployment HMAC key authenticating every log record
    /// and snapshot (compromised-storage-volume threat model).
    pub hmac_key_file: Option<PathBuf>,
}

impl Default for MetadataConfig {
    fn default() -> Self {
        Self {
            engine: MetadataEngine::Log,
            snapshot: false,
            compact_threshold_bytes: 64 * 1024 * 1024,
            hmac_key_file: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MetadataEngine {
    /// Append-only CRC32C-framed log + in-RAM maps (the minimal default).
    #[default]
    Log,
    /// Embedded B-tree KV (redb) for out-of-RAM metadata (needs the `redb` build).
    Redb,
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
        self.storage.validate()
    }
}

impl StorageConfig {
    /// Cross-field storage invariants: subsystem periods, S3 bounds, subpath
    /// grammar, and pairwise-disjoint backend roots.
    fn validate(&self) -> Result<(), ConfigError> {
        if self.gc.enabled {
            for (field, v) in [
                ("storage.gc.delay_secs", self.gc.delay_secs),
                ("storage.gc.interval_secs", self.gc.interval_secs),
            ] {
                if v == 0 {
                    return Err(invalid(field, "must be > 0 when gc is enabled"));
                }
            }
        }
        if self.scrub.enabled {
            for (field, v) in [
                ("storage.scrub.interval_secs", self.scrub.interval_secs),
                (
                    "storage.scrub.max_bytes_per_sec",
                    self.scrub.max_bytes_per_sec,
                ),
            ] {
                if v == 0 {
                    return Err(invalid(field, "must be > 0 when scrub is enabled"));
                }
            }
        }
        let m = &self.metadata;
        if m.compact_threshold_bytes == 0 {
            return Err(invalid(
                "storage.metadata.compact_threshold_bytes",
                "must be > 0",
            ));
        }
        if m.engine != MetadataEngine::Log {
            if m.snapshot {
                return Err(invalid(
                    "storage.metadata.snapshot",
                    "requires engine = \"log\"",
                ));
            }
            if m.hmac_key_file.is_some() {
                return Err(invalid(
                    "storage.metadata.hmac_key_file",
                    "requires engine = \"log\"",
                ));
            }
        }
        if let Some(s3) = &self.s3 {
            s3.validate("storage.s3")?;
        }
        let mut roots: Vec<(String, &Path)> = vec![("storage.root".into(), &self.root)];
        for (prefix, sub) in &self.subpaths {
            let field = format!("storage.subpaths.{prefix}");
            if !is_repo_prefix(prefix) {
                return Err(invalid(
                    field,
                    "must be a repository-name prefix (`/`-separated `[a-z0-9]+([._-][a-z0-9]+)*` components)",
                ));
            }
            if let Some(s3) = &sub.s3 {
                s3.validate(&format!("{field}.s3"))?;
            }
            roots.push((format!("{field}.root"), &sub.root));
        }
        // Backend roots must be pairwise disjoint: a root nested in another
        // would surface one backend's layouts as repos of the other.
        for (i, (fa, a)) in roots.iter().enumerate() {
            for (fb, b) in &roots[i + 1..] {
                if a.starts_with(b) || b.starts_with(a) {
                    return Err(invalid(
                        fb.clone(),
                        format!("must not equal or nest with {fa}"),
                    ));
                }
            }
        }
        Ok(())
    }
}

impl S3Config {
    fn validate(&self, field: &str) -> Result<(), ConfigError> {
        if self.bucket.trim().is_empty() {
            return Err(invalid(format!("{field}.bucket"), "must not be empty"));
        }
        if self.prefix.starts_with('/') || self.prefix.ends_with('/') {
            return Err(invalid(
                format!("{field}.prefix"),
                "must not start or end with '/'",
            ));
        }
        if !(1..=60).contains(&self.redirect_ttl_secs) {
            return Err(invalid(
                format!("{field}.redirect_ttl_secs"),
                "must be within [1, 60]",
            ));
        }
        if self.multipart_part_size < S3_MIN_PART_SIZE {
            return Err(invalid(
                format!("{field}.multipart_part_size"),
                format!("must be >= {S3_MIN_PART_SIZE} (the S3 minimum part size)"),
            ));
        }
        if self.multipart_concurrency == 0 {
            return Err(invalid(
                format!("{field}.multipart_concurrency"),
                "must be > 0",
            ));
        }
        if let Some(ep) = &self.endpoint {
            let plaintext = ep.starts_with("http://");
            if !(plaintext || ep.starts_with("https://")) {
                return Err(invalid(
                    format!("{field}.endpoint"),
                    "must be an http(s) URL",
                ));
            }
            if plaintext && !self.allow_http {
                return Err(invalid(
                    format!("{field}.endpoint"),
                    "plaintext http:// requires allow_http = true",
                ));
            }
        }
        Ok(())
    }
}

/// Whether `s` is a repository-name prefix: `/`-separated components, each
/// matching the dist-spec component grammar `[a-z0-9]+((\.|_|__|-+)[a-z0-9]+)*`.
fn is_repo_prefix(s: &str) -> bool {
    fn component(c: &str) -> bool {
        let b = c.as_bytes();
        let alnum = |x: u8| x.is_ascii_lowercase() || x.is_ascii_digit();
        if b.is_empty() || !alnum(b[0]) || !alnum(b[b.len() - 1]) {
            return false;
        }
        let mut i = 0;
        while i < b.len() {
            if alnum(b[i]) {
                i += 1;
                continue;
            }
            // A separator run: `.`, `_`, `__`, or one-or-more `-`.
            let start = i;
            while i < b.len() && !alnum(b[i]) {
                i += 1;
            }
            let sep = &c[start..i];
            if !(sep == "." || sep == "_" || sep == "__" || sep.bytes().all(|x| x == b'-')) {
                return false;
            }
        }
        true
    }
    s.len() <= 255 && s.split('/').all(component)
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
            dedupe = false
            gc = { enabled = true, delay_secs = 60, interval_secs = 30 }
            scrub = { enabled = true, interval_secs = 600, max_bytes_per_sec = 1024, mode = "app" }
            quota = { max_repo_bytes = 10, max_total_bytes = 100, max_upload_sessions = 0 }
            metadata = { snapshot = true, compact_threshold_bytes = 4096, hmac_key_file = "/k" }
            [storage.subpaths."team-a/x"]
            root = "/srv/team-a"
            [storage.subpaths.mirror]
            root = "/srv/mirror-state"
            s3 = { bucket = "b", endpoint = "http://minio:9000", allow_http = true, prefix = "p/q" }
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
        let s = &c.storage;
        assert!(!s.dedupe);
        assert_eq!(s.gc.delay_secs, 60);
        assert_eq!(s.scrub.mode, ScrubMode::App);
        assert_eq!(s.quota.max_upload_sessions, 0);
        assert!(s.metadata.snapshot);
        assert_eq!(s.metadata.engine, MetadataEngine::Log);
        let mirror = s.subpaths["mirror"].s3.as_ref().unwrap();
        assert_eq!(mirror.region, "us-east-1");
        assert_eq!(mirror.redirect_ttl_secs, 60);
        assert_eq!(mirror.multipart_part_size, 16 * 1024 * 1024);
        let back: Config = toml::from_str(&toml::to_string(&c).unwrap()).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn storage_defaults_match_zot_policy() {
        let s = StorageConfig::default();
        assert!(s.dedupe && s.gc.enabled && !s.scrub.enabled);
        assert_eq!((s.gc.delay_secs, s.gc.interval_secs), (3600, 3600));
        assert_eq!((s.quota.max_repo_bytes, s.quota.max_total_bytes), (0, 0));
        assert_eq!(s.quota.max_upload_sessions, 1024);
        assert!(s.subpaths.is_empty() && s.s3.is_none());
    }

    #[test]
    fn repo_prefix_grammar() {
        for ok in ["a", "a/b", "a.b", "a_b", "a__b", "a---b", "x9/y-z/0"] {
            assert!(is_repo_prefix(ok), "{ok}");
        }
        for bad in [
            "", "A", "a/", "/a", "a//b", "-a", "a-", "a._b", "a___b", "..", "a/../b",
        ] {
            assert!(!is_repo_prefix(bad), "{bad}");
        }
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
            ("[storage.gc]\ndelay_secs = 0", "storage.gc.delay_secs"),
            (
                "[storage.gc]\ninterval_secs = 0",
                "storage.gc.interval_secs",
            ),
            (
                "[storage.scrub]\nenabled = true\nmax_bytes_per_sec = 0",
                "storage.scrub.max_bytes_per_sec",
            ),
            (
                "[storage.metadata]\ncompact_threshold_bytes = 0",
                "compact_threshold_bytes",
            ),
            (
                "[storage.metadata]\nengine = \"redb\"\nsnapshot = true",
                "storage.metadata.snapshot",
            ),
            (
                "[storage.metadata]\nengine = \"redb\"\nhmac_key_file = \"/k\"",
                "storage.metadata.hmac_key_file",
            ),
            ("[storage.s3]\nbucket = \" \"", "storage.s3.bucket"),
            (
                "[storage.s3]\nbucket = \"b\"\nprefix = \"/p\"",
                "storage.s3.prefix",
            ),
            (
                "[storage.s3]\nbucket = \"b\"\nredirect_ttl_secs = 61",
                "redirect_ttl_secs",
            ),
            (
                "[storage.s3]\nbucket = \"b\"\nmultipart_part_size = 1",
                "multipart_part_size",
            ),
            (
                "[storage.s3]\nbucket = \"b\"\nmultipart_concurrency = 0",
                "multipart_concurrency",
            ),
            (
                "[storage.s3]\nbucket = \"b\"\nendpoint = \"ftp://x\"",
                "storage.s3.endpoint",
            ),
            (
                "[storage.s3]\nbucket = \"b\"\nendpoint = \"http://x\"",
                "allow_http",
            ),
            (
                "[storage.subpaths.\"Bad\"]\nroot = \"/x\"",
                "storage.subpaths.Bad",
            ),
            (
                "[storage.subpaths.a]\nroot = \"/x\"\ns3 = { bucket = \"\" }",
                "storage.subpaths.a.s3.bucket",
            ),
            (
                "[storage]\nroot = \"/data\"\n[storage.subpaths.a]\nroot = \"/data/a\"",
                "storage.subpaths.a.root",
            ),
            (
                "[storage.subpaths.a]\nroot = \"/s\"\n[storage.subpaths.b]\nroot = \"/s\"",
                "storage.subpaths.b.root",
            ),
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
