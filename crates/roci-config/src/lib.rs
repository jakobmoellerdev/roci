//! Configuration schema for roci (ARCHITECTURE.md §Configuration model).
//! Zero-config by default; unknown keys rejected; [`Config::validate`] runs on every load.
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub http: HttpConfig,
    pub storage: StorageConfig,
    pub limits: LimitsConfig,
    pub delete: DeleteConfig,
    pub log: LogConfig,
    pub telemetry: TelemetryConfig,
    pub auth: AuthConfig,
    pub access_control: Option<AccessControlConfig>,
}

/// `[http]` — listener, TLS, timeouts, rate limits.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HttpConfig {
    pub listen: SocketAddr,
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

/// `[http.tls]` — PEM cert chain + key, optional mTLS.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub cert: PathBuf,
    pub key: PathBuf,
    #[serde(default)]
    pub client_auth: ClientAuth,
    #[serde(default)]
    pub client_ca: Option<PathBuf>,
    #[serde(default)]
    pub client_cert_sha256: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientAuth {
    #[default]
    None,
    /// Requested; missing cert → anonymous.
    Optional,
    /// Required; handshake fails without it.
    Required,
}

/// `[http.timeouts]` — slow-loris bounds (SECURITY inv. 14).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TimeoutsConfig {
    pub read_header_secs: u64,
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

/// `[http.rate_limit]` — token buckets; exhausted → `429`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub default: Option<Bucket>,
    pub per_method: BTreeMap<String, Bucket>,
    pub per_client: Option<PerClientConfig>,
}

/// `[http.rate_limit.per_client]` — per-client bucket keyed by
/// principal or peer IP; LRU-bounded by `max_clients`.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PerClientConfig {
    pub rate: u32,
    pub burst: u32,
    #[serde(default = "default_max_clients")]
    pub max_clients: u32,
}

fn default_max_clients() -> u32 {
    10_000
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bucket {
    pub rate: u32,
    pub burst: u32,
}

/// `[storage]` — default backend and subsystem knobs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct StorageConfig {
    pub root: PathBuf,
    pub cache_max_bytes: usize,
    pub small_blob_threshold: usize,
    pub dedupe: bool,
    /// `fsync` blob data before ack; manifests/WAL always synced.
    pub commit: bool,
    pub fast_restart: bool,
    pub s3: Option<S3Config>,
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
            small_blob_threshold: 100 * 1024,
            dedupe: true,
            commit: false,
            fast_restart: false,
            s3: None,
            subpaths: BTreeMap::new(),
            gc: GcConfig::default(),
            scrub: ScrubConfig::default(),
            quota: QuotaConfig::default(),
            metadata: MetadataConfig::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SubpathConfig {
    pub root: PathBuf,
    #[serde(default)]
    pub s3: Option<S3Config>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct S3Config {
    pub bucket: String,
    #[serde(default = "default_s3_region")]
    pub region: String,
    /// Custom endpoint (MinIO, R2, Ceph); absent → AWS.
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub prefix: String,
    /// Static access key; absent → env/instance credential chain.
    #[serde(default)]
    pub access_key_id: Option<String>,
    /// File holding the secret access key.
    #[serde(default)]
    pub secret_access_key_file: Option<PathBuf>,
    /// Permit plaintext `http://` endpoint.
    #[serde(default)]
    pub allow_http: bool,
    /// Blob GETs ≥ this size redirect to signed URL; `0` disables.
    #[serde(default = "default_redirect_min_size")]
    pub redirect_min_size: u64,
    /// Signed URL lifetime, `1..=60`s.
    #[serde(default = "default_redirect_ttl_secs")]
    pub redirect_ttl_secs: u64,
    /// Multipart part size in bytes (≥ 5 MiB, the S3 minimum).
    #[serde(default = "default_multipart_part_size")]
    pub multipart_part_size: u64,
    /// Parallel parts per multipart upload.
    #[serde(default = "default_multipart_concurrency")]
    pub multipart_concurrency: usize,
    /// If `true`, create the S3 bucket at backend startup when it does not
    /// exist. Idempotent: `200` and `409 BucketAlreadyOwnedByYou` are both
    /// treated as success; transport errors are retried with backoff.
    #[serde(default)]
    pub create_bucket: bool,
    /// Path to a PEM file containing one or more CA certificates to trust
    /// when connecting to the S3 endpoint over HTTPS (e.g. a private CA
    /// serving a cert-manager-issued certificate).
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
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

pub const S3_MIN_PART_SIZE: u64 = 5 * 1024 * 1024;

/// `[storage.gc]` — online garbage collection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct GcConfig {
    pub enabled: bool,
    pub delay_secs: u64,
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
    pub interval_secs: u64,
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
    #[default]
    Auto,
    App,
}

/// `[storage.quota]` — exhaustion guards (SECURITY §Storage boundary).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct QuotaConfig {
    /// Per-repo byte cap; `0` = unlimited.
    pub max_repo_bytes: u64,
    /// Registry-wide byte cap; `0` = unlimited.
    pub max_total_bytes: u64,
    /// Concurrent upload sessions; `0` = unlimited.
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
    /// Serve from mmap snapshot + log tail (fast cold start).
    pub snapshot: bool,
    /// Compact the log (or cut a new snapshot) once it grows past this size.
    pub compact_threshold_bytes: u64,
    /// HMAC key file for log/snapshot auth; with LMDB derives a
    /// ChaCha20-Poly1305 encryption key.
    pub hmac_key_file: Option<PathBuf>,
    /// Max LMDB mmap region; log engine ignores this.
    pub map_size_bytes: u64,
}

impl Default for MetadataConfig {
    fn default() -> Self {
        Self {
            engine: MetadataEngine::Log,
            snapshot: false,
            compact_threshold_bytes: 64 * 1024 * 1024,
            hmac_key_file: None,
            map_size_bytes: 68_719_476_736, // 64 GiB
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MetadataEngine {
    /// Append-only CRC32C-framed log + in-RAM maps (the minimal default).
    #[default]
    Log,
    /// LMDB (heed3), optional encryption-at-rest.
    Lmdb,
    /// Removed — kept for a clear error on old configs.
    #[doc(hidden)]
    Redb,
}

/// `[limits]` — bounded-input guards (SECURITY inv. 14).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LimitsConfig {
    pub max_body: usize,
    pub max_upload: u64,
    pub max_manifest: usize,
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct DeleteConfig {
    /// Accept delete endpoints; false → 405.
    pub enabled: bool,
}

impl Default for DeleteConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LogConfig {
    /// `EnvFilter` directive; `RUST_LOG` overrides.
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
    /// OTLP export; absent → none.
    pub otlp: Option<OtlpConfig>,
    pub sample_ratio: f64,
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

/// `[auth]` — authentication; all absent → unauthenticated.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AuthConfig {
    pub realm: String,
    pub htpasswd: Option<HtpasswdConfig>,
    pub ldap: Option<LdapConfig>,
    pub bearer: Option<BearerConfig>,
    /// Cached Basic auth TTL; `0` disables.
    pub cache_ttl_secs: u64,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            realm: "roci".into(),
            htpasswd: None,
            ldap: None,
            bearer: None,
            cache_ttl_secs: 60,
        }
    }
}

/// `[auth.htpasswd]` — a local bcrypt htpasswd file.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HtpasswdConfig {
    pub path: PathBuf,
}

/// `[auth.ldap]` — authenticate Basic credentials by LDAP bind.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LdapConfig {
    pub url: String,
    #[serde(default)]
    pub start_tls: bool,
    pub bind_dn: String,
    pub bind_password_file: PathBuf,
    pub base_dn: String,
    #[serde(default = "default_ldap_user_attribute")]
    pub user_attribute: String,
    #[serde(default)]
    pub user_filter: Option<String>,
    #[serde(default)]
    pub group_attribute: Option<String>,
    /// PEM CA bundle; absent → system roots.
    #[serde(default)]
    pub ca_file: Option<PathBuf>,
    #[serde(default = "default_ldap_timeout_secs")]
    pub timeout_secs: u64,
}

fn default_ldap_user_attribute() -> String {
    "uid".into()
}
fn default_ldap_timeout_secs() -> u64 {
    5
}

/// `[auth.bearer]` — Docker v2 bearer tokens.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BearerConfig {
    pub realm: String,
    pub service: String,
    pub issuer: String,
    pub verify_key_file: PathBuf,
}

/// `[access_control]` — identity-based access control.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccessControlConfig {
    #[serde(default)]
    pub admins: Vec<String>,
    #[serde(default)]
    pub groups: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub repositories: Vec<RepositoryPolicy>,
}

/// `[[access_control.repositories]]` — grants for matching repos.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryPolicy {
    pub pattern: String,
    #[serde(default)]
    pub anonymous: Vec<Action>,
    #[serde(default)]
    pub authenticated: Vec<Action>,
    #[serde(default)]
    pub policies: Vec<IdentityPolicy>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdentityPolicy {
    #[serde(default)]
    pub users: Vec<String>,
    #[serde(default)]
    pub groups: Vec<String>,
    pub actions: Vec<Action>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    Pull,
    Push,
    Delete,
}

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

fn require_nonzero(fields: &[(&str, u64)]) -> Result<(), ConfigError> {
    for &(field, v) in fields {
        if v == 0 {
            return Err(invalid(field, "must be > 0"));
        }
    }
    Ok(())
}

fn require_nonempty(fields: &[(&str, &str)]) -> Result<(), ConfigError> {
    for &(field, v) in fields {
        if v.trim().is_empty() {
            return Err(invalid(field, "must not be empty"));
        }
    }
    Ok(())
}

const METHODS: [&str; 6] = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"];

impl Config {
    /// Load, parse, and validate a TOML config file.
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

    /// Validate cross-field invariants.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let l = &self.limits;
        require_nonzero(&[
            ("limits.max_body", l.max_body as u64),
            ("limits.max_upload", l.max_upload),
            ("limits.max_manifest", l.max_manifest as u64),
            ("limits.max_page", l.max_page as u64),
            (
                "http.timeouts.read_header_secs",
                self.http.timeouts.read_header_secs,
            ),
        ])?;
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
        if let Some(pc) = &rl.per_client {
            if pc.rate == 0 || pc.burst == 0 {
                return Err(invalid(
                    "http.rate_limit.per_client",
                    "rate and burst must be > 0",
                ));
            }
            require_nonzero(&[(
                "http.rate_limit.per_client.max_clients",
                pc.max_clients as u64,
            )])?;
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
        require_nonempty(&[("log.level", &self.log.level)])?;
        if let Some(tls) = &self.http.tls {
            tls.validate()?;
        }
        self.auth.validate()?;
        if let Some(ac) = &self.access_control {
            ac.validate()?;
        }
        self.storage.validate()
    }
}

fn is_quotable(s: &str) -> bool {
    !s.is_empty() && !s.chars().any(|c| c == '"' || c == '\\' || c.is_control())
}

impl TlsConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if self.client_auth != ClientAuth::None && self.client_ca.is_none() {
            return Err(invalid(
                "http.tls.client_ca",
                "required when client_auth is optional or required",
            ));
        }
        if self.client_auth == ClientAuth::None
            && (self.client_ca.is_some() || !self.client_cert_sha256.is_empty())
        {
            return Err(invalid(
                "http.tls.client_auth",
                "must be optional or required when client_ca/client_cert_sha256 is set",
            ));
        }
        for (i, pin) in self.client_cert_sha256.iter().enumerate() {
            if pin.len() != 64 || !pin.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(invalid(
                    format!("http.tls.client_cert_sha256[{i}]"),
                    "must be 64 hex characters (a SHA-256 fingerprint)",
                ));
            }
        }
        Ok(())
    }
}

impl AuthConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if !is_quotable(&self.realm) {
            return Err(invalid(
                "auth.realm",
                "must be non-empty without '\"', '\\' or control characters",
            ));
        }
        if self.cache_ttl_secs > 3600 {
            return Err(invalid("auth.cache_ttl_secs", "must be <= 3600"));
        }
        if let Some(h) = &self.htpasswd {
            if h.path.as_os_str().is_empty() {
                return Err(invalid("auth.htpasswd.path", "must not be empty"));
            }
        }
        if let Some(l) = &self.ldap {
            l.validate()?;
        }
        if let Some(b) = &self.bearer {
            if !(b.realm.starts_with("https://") || b.realm.starts_with("http://")) {
                return Err(invalid("auth.bearer.realm", "must be an http(s) URL"));
            }
            for (field, v) in [
                ("auth.bearer.realm", &b.realm),
                ("auth.bearer.service", &b.service),
                ("auth.bearer.issuer", &b.issuer),
            ] {
                if !is_quotable(v) {
                    return Err(invalid(
                        field,
                        "must be non-empty without '\"', '\\' or control characters",
                    ));
                }
            }
        }
        Ok(())
    }
}

impl LdapConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        if !(self.url.starts_with("ldaps://") || self.url.starts_with("ldap://")) {
            return Err(invalid(
                "auth.ldap.url",
                "must be an ldap:// or ldaps:// URL",
            ));
        }
        if self.url.starts_with("ldap://") && !self.start_tls {
            return Err(invalid(
                "auth.ldap.url",
                "plaintext ldap:// requires start_tls = true",
            ));
        }
        require_nonempty(&[
            ("auth.ldap.bind_dn", &self.bind_dn),
            ("auth.ldap.base_dn", &self.base_dn),
        ])?;
        let a = self.user_attribute.as_bytes();
        if a.is_empty()
            || !a[0].is_ascii_alphabetic()
            || !a.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'-')
        {
            return Err(invalid(
                "auth.ldap.user_attribute",
                "must match [A-Za-z][A-Za-z0-9-]*",
            ));
        }
        if let Some(f) = &self.user_filter {
            if !(f.starts_with('(') && f.ends_with(')')) {
                return Err(invalid(
                    "auth.ldap.user_filter",
                    "must be a parenthesized LDAP filter",
                ));
            }
        }
        require_nonzero(&[("auth.ldap.timeout_secs", self.timeout_secs)])?;
        Ok(())
    }
}

impl AccessControlConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        let mut seen = HashSet::new();
        for (i, r) in self.repositories.iter().enumerate() {
            let field = format!("access_control.repositories[{i}]");
            if !is_repo_pattern(&r.pattern) {
                return Err(invalid(
                    format!("{field}.pattern"),
                    "must be `/`-separated components of [a-z0-9._-*], or `**`",
                ));
            }
            if !seen.insert(r.pattern.as_str()) {
                return Err(invalid(format!("{field}.pattern"), "duplicate pattern"));
            }
            for (j, p) in r.policies.iter().enumerate() {
                if p.actions.is_empty() || (p.users.is_empty() && p.groups.is_empty()) {
                    return Err(invalid(
                        format!("{field}.policies[{j}]"),
                        "needs non-empty actions and at least one user or group",
                    ));
                }
            }
        }
        Ok(())
    }
}

fn is_repo_pattern(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 255
        && s.split('/').all(|c| {
            c == "**"
                || (!c.is_empty()
                    && !c.contains("**")
                    && c.bytes().all(|b| {
                        b.is_ascii_lowercase() || b.is_ascii_digit() || b"._-*".contains(&b)
                    }))
        })
}

/// Whether `host` is loopback/private/link-local (SSRF guard).
pub fn is_internal_host(host: &str) -> bool {
    let h = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    if h == "localhost" || h.ends_with(".localhost") {
        return true;
    }
    fn v4(ip: std::net::Ipv4Addr) -> bool {
        let o = ip.octets();
        ip.is_loopback()
            || ip.is_private()
            || ip.is_link_local()
            || ip.is_unspecified()
            || ip.is_broadcast()
            || o[0] == 0
            || (o[0] == 100 && (o[1] & 0xc0) == 64)
    }
    match h.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => v4(ip),
        Ok(IpAddr::V6(ip)) => {
            let seg0 = ip.segments()[0];
            ip.is_loopback()
                || ip.is_unspecified()
                || (seg0 & 0xfe00) == 0xfc00
                || (seg0 & 0xffc0) == 0xfe80
                || ip.to_ipv4_mapped().is_some_and(v4)
        }
        Err(_) => false,
    }
}

fn url_host(url: &str) -> Option<&str> {
    let rest = url.split_once("://").map_or(url, |(_, r)| r);
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit_once('@').map_or(authority, |(_, a)| a);
    let host = if authority.starts_with('[') {
        &authority[..=authority.find(']')?]
    } else {
        authority.split(':').next()?
    };
    (!host.is_empty()).then_some(host)
}

impl StorageConfig {
    /// Validate storage cross-field invariants.
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
        const MAX_THRESHOLD: usize = 8 * 1024 * 1024;
        require_nonzero(&[(
            "storage.small_blob_threshold",
            self.small_blob_threshold as u64,
        )])?;
        if self.small_blob_threshold > MAX_THRESHOLD {
            return Err(invalid(
                "storage.small_blob_threshold",
                format!("must be <= {MAX_THRESHOLD} (8 MiB)"),
            ));
        }
        if self.cache_max_bytes > 0 && self.small_blob_threshold > self.cache_max_bytes {
            return Err(invalid(
                "storage.small_blob_threshold",
                "must be <= cache_max_bytes when the cache is enabled",
            ));
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
        if m.engine == MetadataEngine::Redb {
            return Err(invalid(
                "storage.metadata.engine",
                "the redb engine has been removed; \
                 use \"lmdb\" instead — metadata is rebuilt from the layout",
            ));
        }
        require_nonzero(&[(
            "storage.metadata.compact_threshold_bytes",
            m.compact_threshold_bytes,
        )])?;
        if m.engine != MetadataEngine::Log && m.snapshot {
            return Err(invalid(
                "storage.metadata.snapshot",
                "requires engine = \"log\"",
            ));
        }
        require_nonzero(&[("storage.metadata.map_size_bytes", m.map_size_bytes)])?;
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
        // Roots must be pairwise disjoint.
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
        let bucket_field = format!("{field}.bucket");
        require_nonempty(&[(&bucket_field, &self.bucket)])?;
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
        let concurrency_field = format!("{field}.multipart_concurrency");
        require_nonzero(&[(&concurrency_field, self.multipart_concurrency as u64)])?;
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
            if self.redirect_min_size > 0 && url_host(ep).is_some_and(is_internal_host) {
                return Err(invalid(
                    format!("{field}.endpoint"),
                    "redirect target is a loopback/private/link-local host; set redirect_min_size = 0 to proxy blobs",
                ));
            }
        }
        // Reject a ca_file that doesn't exist or can't be read at config time
        // so a bad path fails fast at startup instead of on first S3 request.
        if let Some(ca) = &self.ca_file {
            if !ca.is_file() {
                return Err(invalid(
                    format!("{field}.ca_file"),
                    format!("file does not exist: {}", ca.display()),
                ));
            }
        }
        Ok(())
    }
}

/// Valid repository-name prefix.
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
            tls = { cert = "/c.pem", key = "/k.pem", client_auth = "optional", client_ca = "/ca.pem", client_cert_sha256 = ["AB00000000000000000000000000000000000000000000000000000000000000"] }
            timeouts = { read_header_secs = 5, idle_secs = 30 }
            [http.rate_limit]
            enabled = true
            default = { rate = 100, burst = 200 }
            per_method.PUT = { rate = 10, burst = 20 }
            per_client = { rate = 50, burst = 100, max_clients = 5000 }
            [storage]
            root = "/var/lib/roci"
            cache_max_bytes = 0
            small_blob_threshold = 51200
            dedupe = false
            commit = true
            fast_restart = true
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
            [auth]
            realm = "reg"
            cache_ttl_secs = 0
            [auth.htpasswd]
            path = "/etc/roci/htpasswd"
            [auth.ldap]
            url = "ldap://dir:389"
            start_tls = true
            bind_dn = "cn=svc,dc=x"
            bind_password_file = "/pw"
            base_dn = "dc=x"
            user_filter = "(objectClass=person)"
            group_attribute = "memberOf"
            [auth.bearer]
            realm = "https://auth.example/token"
            service = "roci"
            issuer = "auth.example"
            verify_key_file = "/jwt.pem"
            [access_control]
            admins = ["root"]
            groups = { devs = ["alice", "bob"] }
            [[access_control.repositories]]
            pattern = "team/**"
            anonymous = ["pull"]
            authenticated = ["pull"]
            policies = [{ users = ["alice"], groups = ["devs"], actions = ["push", "delete"] }]
            "#,
        )
        .unwrap();
        assert_eq!(c.http.listen.port(), 8443);
        assert_eq!(c.http.rate_limit.per_method["PUT"].rate, 10);
        let pc = c.http.rate_limit.per_client.as_ref().unwrap();
        assert_eq!((pc.rate, pc.burst, pc.max_clients), (50, 100, 5000));
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
        assert!(s.commit);
        assert_eq!(s.small_blob_threshold, 51200);
        assert!(s.fast_restart);
        assert_eq!(s.gc.delay_secs, 60);
        assert_eq!(s.scrub.mode, ScrubMode::App);
        assert_eq!(s.quota.max_upload_sessions, 0);
        assert!(s.metadata.snapshot);
        assert_eq!(s.metadata.engine, MetadataEngine::Log);
        let mirror = s.subpaths["mirror"].s3.as_ref().unwrap();
        assert_eq!(mirror.region, "us-east-1");
        assert_eq!(mirror.redirect_ttl_secs, 60);
        assert_eq!(mirror.multipart_part_size, 16 * 1024 * 1024);
        let tls = c.http.tls.as_ref().unwrap();
        assert_eq!(tls.client_auth, ClientAuth::Optional);
        assert_eq!(c.auth.realm, "reg");
        let ldap = c.auth.ldap.as_ref().unwrap();
        assert_eq!(
            (ldap.user_attribute.as_str(), ldap.timeout_secs),
            ("uid", 5)
        );
        let ac = c.access_control.as_ref().unwrap();
        assert_eq!(
            ac.repositories[0].policies[0].actions,
            [Action::Push, Action::Delete]
        );
        let back: Config = toml::from_str(&toml::to_string(&c).unwrap()).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn storage_defaults_match_zot_policy() {
        let s = StorageConfig::default();
        assert!(s.dedupe && s.gc.enabled && !s.scrub.enabled && !s.fast_restart);
        assert_eq!((s.gc.delay_secs, s.gc.interval_secs), (3600, 3600));
        assert_eq!((s.quota.max_repo_bytes, s.quota.max_total_bytes), (0, 0));
        assert_eq!(s.quota.max_upload_sessions, 1024);
        assert!(s.subpaths.is_empty() && s.s3.is_none());
        assert_eq!(s.small_blob_threshold, 100 * 1024);
    }

    #[test]
    fn subsystem_checks_apply_only_when_relevant() {
        for ok in [
            "[storage.gc]\nenabled = false\ndelay_secs = 0\ninterval_secs = 0",
            "[storage.scrub]\nenabled = false\ninterval_secs = 0",
            "[storage.metadata]\nengine = \"lmdb\"",
            "[storage.s3]\nbucket = \"b\"\nendpoint = \"https://s3.example\"",
            "[storage.s3]\nbucket = \"b\"",
        ] {
            parse(ok).unwrap_or_else(|e| panic!("{ok:?} → {e}"));
        }
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
            (
                "[http.rate_limit]\nper_client = { rate = 0, burst = 1 }",
                "http.rate_limit.per_client",
            ),
            (
                "[http.rate_limit]\nper_client = { rate = 1, burst = 0 }",
                "http.rate_limit.per_client",
            ),
            (
                "[http.rate_limit]\nper_client = { rate = 1, burst = 1, max_clients = 0 }",
                "http.rate_limit.per_client.max_clients",
            ),
            ("[telemetry]\nsample_ratio = 1.5", "sample_ratio"),
            ("[telemetry.metrics]\npath = \"/v2/m\"", "metrics.path"),
            ("[telemetry.otlp]\nendpoint = \"\"", "otlp.endpoint"),
            ("[log]\nlevel = \" \"", "log.level"),
            ("[http.timeouts]\nread_header_secs = 0", "read_header_secs"),
            (
                "[storage]\nsmall_blob_threshold = 0",
                "storage.small_blob_threshold",
            ),
            (
                "[storage]\nsmall_blob_threshold = 8388609",
                "storage.small_blob_threshold",
            ),
            (
                "[storage]\ncache_max_bytes = 1024\nsmall_blob_threshold = 2048",
                "storage.small_blob_threshold",
            ),
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
                "[storage.metadata]\nengine = \"redb\"",
                "storage.metadata.engine",
            ),
            (
                "[storage.metadata]\nengine = \"lmdb\"\nsnapshot = true",
                "storage.metadata.snapshot",
            ),
            (
                "[storage.metadata]\nmap_size_bytes = 0",
                "storage.metadata.map_size_bytes",
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
            ("[auth]\nrealm = \"a\\\"b\"", "auth.realm"),
            ("[auth]\nrealm = \"\"", "auth.realm"),
            ("[auth]\ncache_ttl_secs = 3601", "auth.cache_ttl_secs"),
            ("[auth.htpasswd]\npath = \"\"", "auth.htpasswd.path"),
            (
                "[auth.ldap]\nurl = \"ldap://d\"\nbind_dn = \"a\"\nbind_password_file = \"/p\"\nbase_dn = \"b\"",
                "plaintext ldap:// requires start_tls = true",
            ),
            (
                "[auth.ldap]\nurl = \"http://d\"\nbind_dn = \"a\"\nbind_password_file = \"/p\"\nbase_dn = \"b\"",
                "auth.ldap.url",
            ),
            (
                "[auth.ldap]\nurl = \"ldaps://d\"\nbind_dn = \" \"\nbind_password_file = \"/p\"\nbase_dn = \"b\"",
                "auth.ldap.bind_dn",
            ),
            (
                "[auth.ldap]\nurl = \"ldaps://d\"\nbind_dn = \"a\"\nbind_password_file = \"/p\"\nbase_dn = \"\"",
                "auth.ldap.base_dn",
            ),
            (
                "[auth.ldap]\nurl = \"ldaps://d\"\nbind_dn = \"a\"\nbind_password_file = \"/p\"\nbase_dn = \"b\"\nuser_attribute = \"u)(x\"",
                "auth.ldap.user_attribute",
            ),
            (
                "[auth.ldap]\nurl = \"ldaps://d\"\nbind_dn = \"a\"\nbind_password_file = \"/p\"\nbase_dn = \"b\"\nuser_filter = \"x=y\"",
                "auth.ldap.user_filter",
            ),
            (
                "[auth.ldap]\nurl = \"ldaps://d\"\nbind_dn = \"a\"\nbind_password_file = \"/p\"\nbase_dn = \"b\"\ntimeout_secs = 0",
                "auth.ldap.timeout_secs",
            ),
            (
                "[auth.bearer]\nrealm = \"auth.example\"\nservice = \"s\"\nissuer = \"i\"\nverify_key_file = \"/k\"",
                "auth.bearer.realm",
            ),
            (
                "[auth.bearer]\nrealm = \"https://a\"\nservice = \"s\\\"\"\nissuer = \"i\"\nverify_key_file = \"/k\"",
                "auth.bearer.service",
            ),
            (
                "[auth.bearer]\nrealm = \"https://a\"\nservice = \"s\"\nissuer = \"\"\nverify_key_file = \"/k\"",
                "auth.bearer.issuer",
            ),
            (
                "[http.tls]\ncert = \"/c\"\nkey = \"/k\"\nclient_auth = \"required\"",
                "http.tls.client_ca",
            ),
            (
                "[http.tls]\ncert = \"/c\"\nkey = \"/k\"\nclient_ca = \"/ca\"",
                "http.tls.client_auth",
            ),
            (
                "[http.tls]\ncert = \"/c\"\nkey = \"/k\"\nclient_cert_sha256 = [\"ab\"]",
                "http.tls.client_auth",
            ),
            (
                "[http.tls]\ncert = \"/c\"\nkey = \"/k\"\nclient_auth = \"optional\"\nclient_ca = \"/ca\"\nclient_cert_sha256 = [\"zz\"]",
                "http.tls.client_cert_sha256[0]",
            ),
            (
                "[[access_control.repositories]]\npattern = \"Team\"",
                "access_control.repositories[0].pattern",
            ),
            (
                "[[access_control.repositories]]\npattern = \"a/**b\"",
                "access_control.repositories[0].pattern",
            ),
            (
                "[[access_control.repositories]]\npattern = \"a//b\"",
                "access_control.repositories[0].pattern",
            ),
            (
                "[[access_control.repositories]]\npattern = \"a\"\n[[access_control.repositories]]\npattern = \"a\"",
                "access_control.repositories[1].pattern",
            ),
            (
                "[[access_control.repositories]]\npattern = \"a\"\npolicies = [{ users = [\"u\"], actions = [] }]",
                "access_control.repositories[0].policies[0]",
            ),
            (
                "[[access_control.repositories]]\npattern = \"a\"\npolicies = [{ actions = [\"pull\"] }]",
                "access_control.repositories[0].policies[0]",
            ),
            (
                "[storage.s3]\nbucket = \"b\"\nendpoint = \"https://169.254.169.254\"",
                "redirect target is a loopback",
            ),
            (
                "[storage.subpaths.a]\nroot = \"/x\"\ns3 = { bucket = \"b\", endpoint = \"http://[::1]:9000\", allow_http = true }",
                "storage.subpaths.a.s3.endpoint",
            ),
        ] {
            let err = parse(src).unwrap_err();
            assert!(err.contains(needle), "{src:?} → {err}");
        }
    }

    #[test]
    fn internal_endpoints_allowed_when_redirects_disabled() {
        parse("[storage.s3]\nbucket = \"b\"\nendpoint = \"http://127.0.0.1:9000\"\nallow_http = true\nredirect_min_size = 0").unwrap();
    }

    #[test]
    fn per_client_rate_limit_defaults_and_absent() {
        let c = parse("[http.rate_limit]\nenabled = true\ndefault = { rate = 10, burst = 20 }")
            .unwrap();
        assert!(c.http.rate_limit.per_client.is_none());

        let c = parse("[http.rate_limit]\nper_client = { rate = 5, burst = 10 }").unwrap();
        let pc = c.http.rate_limit.per_client.unwrap();
        assert_eq!(pc.rate, 5);
        assert_eq!(pc.burst, 10);
        assert_eq!(pc.max_clients, 10_000);
    }

    #[test]
    fn internal_host_classification() {
        for h in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.1.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",
            "255.255.255.255",
            "::1",
            "::",
            "[fd00::1]",
            "fe80::1",
            "::ffff:10.0.0.1",
            "localhost",
            "a.LOCALHOST",
        ] {
            assert!(is_internal_host(h), "{h}");
        }
        for h in [
            "s3.us-east-1.amazonaws.com",
            "8.8.8.8",
            "100.128.0.1",
            "2001:db8::1",
            "::ffff:8.8.8.8",
            "minio",
        ] {
            assert!(!is_internal_host(h), "{h}");
        }
    }

    #[test]
    fn url_host_extraction() {
        for (url, host) in [
            ("https://s3.example", Some("s3.example")),
            ("http://minio:9000/path?q", Some("minio")),
            ("https://user@h.example:1#f", Some("h.example")),
            ("http://[::1]:9000", Some("[::1]")),
            ("https://", None),
            ("http://[::1", None),
        ] {
            assert_eq!(url_host(url), host, "{url}");
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

    #[test]
    fn s3_create_bucket_defaults_false() {
        let toml = r#"
            [storage]
            root = "/tmp/roci"
            [storage.s3]
            bucket = "test"
            region = "us-east-1"
            endpoint = "http://localhost:9000"
            allow_http = true
        "#;
        let config: Config = toml::from_str(toml).unwrap();
        let s3 = config.storage.s3.as_ref().unwrap();
        assert!(!s3.create_bucket, "create_bucket should default to false");
    }

    #[test]
    fn s3_create_bucket_true_round_trip() {
        let toml = r#"
            [storage]
            root = "/tmp/roci"
            [storage.s3]
            bucket = "test"
            region = "us-east-1"
            endpoint = "http://localhost:9000"
            allow_http = true
            create_bucket = true
        "#;
        let config: Config = toml::from_str(toml).unwrap();
        let s3 = config.storage.s3.as_ref().unwrap();
        assert!(s3.create_bucket, "create_bucket should be true");

        // Round-trip through TOML serialization.
        let re_toml = toml::to_string(&config).unwrap();
        let re_config: Config = toml::from_str(&re_toml).unwrap();
        assert!(re_config.storage.s3.as_ref().unwrap().create_bucket);
    }

    #[test]
    fn s3_ca_file_missing_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.pem");
        let toml = format!(
            r#"
            [storage]
            root = "/tmp/roci"
            [storage.s3]
            bucket = "test"
            region = "us-east-1"
            endpoint = "http://localhost:9000"
            allow_http = true
            redirect_min_size = 0
            ca_file = "{}"
            "#,
            missing.display()
        );
        let config: Config = toml::from_str(&toml).unwrap();
        let err = config.validate();
        assert!(
            err.is_err(),
            "ca_file pointing to missing file should be rejected"
        );
        let msg = err.unwrap_err().to_string();
        assert!(
            msg.contains("ca_file"),
            "error should mention ca_file: {msg}"
        );
    }

    #[test]
    fn s3_ca_file_valid_path_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let ca = dir.path().join("ca.pem");
        std::fs::write(&ca, "not a real PEM but the file exists").unwrap();
        let toml = format!(
            r#"
            [storage]
            root = "{}"
            [storage.s3]
            bucket = "test"
            region = "us-east-1"
            endpoint = "http://localhost:9000"
            allow_http = true
            redirect_min_size = 0
            ca_file = "{}"
            "#,
            dir.path().display(),
            ca.display()
        );
        let config: Config = toml::from_str(&toml).unwrap();
        // Validation checks file existence, not PEM content (client.rs handles PEM parse).
        config.validate().unwrap();
        assert_eq!(
            config.storage.s3.as_ref().unwrap().ca_file.as_deref(),
            Some(ca.as_path())
        );
    }

    #[test]
    fn s3_ca_file_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let ca = dir.path().join("bundle.pem");
        std::fs::write(&ca, "PEM data").unwrap();
        let toml = format!(
            r#"
            [storage]
            root = "{}"
            [storage.s3]
            bucket = "test"
            region = "us-east-1"
            endpoint = "http://localhost:9000"
            allow_http = true
            redirect_min_size = 0
            ca_file = "{}"
            "#,
            dir.path().display(),
            ca.display()
        );
        let config: Config = toml::from_str(&toml).unwrap();
        let re_toml = toml::to_string(&config).unwrap();
        let re_config: Config = toml::from_str(&re_toml).unwrap();
        assert_eq!(
            re_config.storage.s3.as_ref().unwrap().ca_file.as_deref(),
            Some(ca.as_path())
        );
    }
}
