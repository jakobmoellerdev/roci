//! S3 client construction and abstraction.

use object_store::aws::AmazonS3Builder;
use object_store::client::HttpConnector;
#[cfg(test)]
use object_store::memory::InMemory;
use object_store::signer::Signer;
use object_store::ObjectStore;
use roci_config::S3Config;
use std::io;
use std::sync::Arc;
use std::time::Duration;
use url::Url;

/// SSRF containment: only redirect to pre-approved hosts.
#[derive(Debug, Clone)]
pub(crate) struct RedirectGuard {
    hosts: Vec<String>,
    allow_http: bool,
}

impl RedirectGuard {
    /// Derive the allowlist from config.
    pub(crate) fn from_config(s3: &S3Config) -> Self {
        let allow_http = s3.allow_http;
        let hosts = if let Some(ep) = &s3.endpoint {
            Url::parse(ep)
                .ok()
                .and_then(|u| u.host_str().map(str::to_lowercase))
                .into_iter()
                .collect()
        } else {
            let region = s3.region.to_lowercase();
            let bucket = s3.bucket.to_lowercase();
            vec![
                format!("s3.{region}.amazonaws.com"),
                format!("{bucket}.s3.{region}.amazonaws.com"),
            ]
        };
        Self { hosts, allow_http }
    }

    #[cfg(test)]
    pub(crate) fn new(hosts: Vec<String>, allow_http: bool) -> Self {
        Self { hosts, allow_http }
    }

    /// Returns `true` when the signed URL may be safely redirected.
    pub(crate) fn permits(&self, url: &Url) -> bool {
        let scheme_ok = url.scheme() == "https" || (self.allow_http && url.scheme() == "http");
        scheme_ok
            && url.host_str().is_some_and(|host| {
                let host = host.to_lowercase();
                !roci_config::is_internal_host(&host) && self.hosts.contains(&host)
            })
    }
}

/// S3 client wrapper with optional signer and config knobs.
#[derive(Clone)]
pub(crate) struct S3Client {
    pub store: Arc<dyn ObjectStore>,
    pub signer: Option<Arc<dyn Signer>>,
    pub prefix: String,
    pub redirect_min_size: u64,
    pub redirect_ttl: Duration,
    pub multipart_part_size: u64,
    pub multipart_concurrency: usize,
    /// CopyObject ceiling; larger objects use parallel ranged-read copy.
    pub copy_limit: u64,
    pub redirect_guard: RedirectGuard,
    /// Raw HTTP client sharing the store's `ClientOptions` (TLS roots,
    /// `allow_http`), for bucket-level calls object_store has no API for.
    pub bucket_http: Option<object_store::client::HttpClient>,
}

/// Install the `ring` crypto provider for rustls. Idempotent.
pub(crate) fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

impl S3Client {
    pub fn from_config(s3: &S3Config) -> io::Result<Self> {
        install_crypto_provider();
        let mut builder = AmazonS3Builder::new()
            .with_bucket_name(&s3.bucket)
            .with_region(&s3.region);

        if let Some(endpoint) = &s3.endpoint {
            builder = builder
                .with_endpoint(endpoint)
                .with_virtual_hosted_style_request(false);
        }

        // One ClientOptions for the store and the bucket-level HTTP client, so
        // `allow_http` and the `ca_file` roots apply to both.
        let mut opts = object_store::ClientOptions::default().with_allow_http(s3.allow_http);

        if let Some(key_id) = &s3.access_key_id {
            let secret = match &s3.secret_access_key_file {
                Some(path) => std::fs::read_to_string(path).map_err(|e| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!("reading secret_access_key_file {}: {e}", path.display()),
                    )
                })?,
                None => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "access_key_id set but secret_access_key_file is missing",
                    ))
                }
            };
            builder = builder
                .with_access_key_id(key_id)
                .with_secret_access_key(secret.trim());
        }

        // Custom CA bundle for private-CA HTTPS endpoints.
        if let Some(ca_path) = &s3.ca_file {
            let pem = std::fs::read(ca_path).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("reading ca_file {}: {e}", ca_path.display()),
                )
            })?;
            let certs = object_store::Certificate::from_pem_bundle(&pem).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("parsing PEM ca_file {}: {e}", ca_path.display()),
                )
            })?;
            if certs.is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "ca_file {} contains no valid PEM certificates",
                        ca_path.display()
                    ),
                ));
            }
            for cert in certs {
                opts = opts.with_root_certificate(cert);
            }
        }
        builder = builder.with_client_options(opts.clone());
        let bucket_http = object_store::client::ReqwestConnector::default()
            .connect(&opts)
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("building S3 HTTP client: {e}"),
                )
            })?;

        let store = builder.build().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("building S3 client: {e}"),
            )
        })?;

        let signer: Arc<dyn Signer> = Arc::new(store.clone());

        let redirect_guard = RedirectGuard::from_config(s3);

        Ok(Self {
            store: Arc::new(store),
            signer: Some(signer),
            prefix: s3.prefix.clone(),
            redirect_min_size: s3.redirect_min_size,
            redirect_ttl: Duration::from_secs(s3.redirect_ttl_secs),
            multipart_part_size: s3.multipart_part_size,
            multipart_concurrency: s3.multipart_concurrency,
            copy_limit: super::storage_impl::S3_COPY_LIMIT,
            redirect_guard,
            bucket_http: Some(bucket_http),
        })
    }

    /// In-memory client for tests.
    #[cfg(test)]
    pub fn in_memory(
        store: Arc<InMemory>,
        signer: Option<Arc<dyn Signer>>,
        prefix: String,
        redirect_min_size: u64,
        redirect_ttl: Duration,
        multipart_part_size: u64,
        multipart_concurrency: usize,
    ) -> Self {
        Self {
            store: store as Arc<dyn ObjectStore>,
            signer,
            prefix,
            redirect_min_size,
            redirect_ttl,
            multipart_part_size,
            multipart_concurrency,
            copy_limit: super::storage_impl::S3_COPY_LIMIT,
            redirect_guard: RedirectGuard::new(vec!["s3.test.example".into()], false),
            bucket_http: None,
        }
    }

    #[cfg(test)]
    pub fn with_redirect_guard(mut self, g: RedirectGuard) -> Self {
        self.redirect_guard = g;
        self
    }

    #[cfg(test)]
    pub fn with_bucket_http(mut self, http: object_store::client::HttpClient) -> Self {
        self.bucket_http = Some(http);
        self
    }
}
