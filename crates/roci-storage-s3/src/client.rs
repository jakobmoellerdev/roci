//! S3 client construction and abstraction: `AmazonS3` from `S3Config` or
//! `InMemory` for tests.

use object_store::aws::AmazonS3Builder;
#[cfg(test)]
use object_store::memory::InMemory;
use object_store::signer::Signer;
use object_store::ObjectStore;
use roci_config::S3Config;
use std::io;
use std::sync::Arc;
use std::time::Duration;

/// Wraps `Arc<dyn ObjectStore>` plus an optional signer and config knobs.
#[derive(Clone)]
pub(crate) struct S3Client {
    pub store: Arc<dyn ObjectStore>,
    /// When available, generates signed GET URLs for blob redirects.
    pub signer: Option<Arc<dyn Signer>>,
    /// Key prefix inside the bucket (no leading/trailing `/`).
    pub prefix: String,
    /// Blobs ≥ this size get a 307 redirect to a signed URL.
    pub redirect_min_size: u64,
    /// Lifetime of redirect signed URLs.
    pub redirect_ttl: Duration,
    /// Multipart part size in bytes.
    pub multipart_part_size: u64,
    /// Parts transferred in parallel per multipart upload/copy. Preserved
    /// for future ranged-read→multipart-write server-side copy paths; the
    /// `object_store` crate handles upload concurrency internally.
    #[allow(dead_code)]
    pub multipart_concurrency: usize,
}

impl S3Client {
    /// Build a real `AmazonS3` from config. Sync (credential file read only).
    pub fn from_config(s3: &S3Config) -> io::Result<Self> {
        let mut builder = AmazonS3Builder::new()
            .with_bucket_name(&s3.bucket)
            .with_region(&s3.region);

        if let Some(endpoint) = &s3.endpoint {
            builder = builder
                .with_endpoint(endpoint)
                .with_virtual_hosted_style_request(false);
        }

        if s3.allow_http {
            builder = builder.with_allow_http(true);
        }

        // Static credentials: key id + secret from file.
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

        let store = builder.build().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("building S3 client: {e}"),
            )
        })?;

        // AmazonS3 implements Signer.
        let signer: Arc<dyn Signer> = Arc::new(store.clone());

        Ok(Self {
            store: Arc::new(store),
            signer: Some(signer),
            prefix: s3.prefix.clone(),
            redirect_min_size: s3.redirect_min_size,
            redirect_ttl: Duration::from_secs(s3.redirect_ttl_secs),
            multipart_part_size: s3.multipart_part_size,
            multipart_concurrency: s3.multipart_concurrency,
        })
    }

    /// Build an in-memory client for tests. Supports signing via a provided
    /// signer or no signing (proxied reads only).
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
        }
    }
}
