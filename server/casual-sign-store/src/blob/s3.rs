//! Blobs in an S3-compatible bucket (AWS S3, MinIO, SeaweedFS, ...), object name = key hex.
//!
//! Requests are presigned with SigV4 by `rusty-s3` (sans-IO) and carried by `ureq` over
//! rustls on aws-lc-rs, the HTTP stack `casual-sign-cli` already uses. Write-once: `PUT`
//! carries `If-None-Match: *`, so a store that honours conditional writes (AWS S3 since
//! 2024, MinIO) refuses to replace an object (`412`, treated as "already stored", which for
//! a content-addressed key means the same bytes). A store that ignores the header can at
//! worst rewrite identical bytes, since the name is the bytes' hash; `get` verifies either
//! way. Bucket-level object lock or versioning is the operator's second line (docs/22 §9).

use std::sync::Arc;
use std::time::Duration;

use rusty_s3::actions::S3Action;
use rusty_s3::{Bucket, Credentials, UrlStyle};

use super::{BlobKey, BlobStore, DEFAULT_MAX_BLOB_BYTES, verified, within};
use crate::error::{Result, StoreError};

/// How long a presigned request stays valid.
const PRESIGN: Duration = Duration::from_secs(120);

/// Where and how to reach the bucket.
#[derive(Clone)]
pub struct S3Config {
    /// Endpoint, `https://s3.eu-west-1.amazonaws.com` or `http://127.0.0.1:9000`.
    pub endpoint: String,
    /// Bucket name.
    pub bucket: String,
    /// Region.
    pub region: String,
    /// Access key id.
    pub access_key: String,
    /// Secret access key (never printed by `Debug`).
    pub secret_key: String,
    /// Path-style URLs (MinIO and most self-hosted stores) rather than virtual hosts.
    pub path_style: bool,
    /// PEM certificates the store's TLS certificate may chain to besides the platform's
    /// roots: the deployment's private CA, so the hop to a self-hosted store is TLS too
    /// (`HRD-06`). Ignored for an `http` endpoint.
    pub ca_pem: Option<Vec<u8>>,
}

impl core::fmt::Debug for S3Config {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("S3Config")
            .field("endpoint", &self.endpoint)
            .field("bucket", &self.bucket)
            .field("region", &self.region)
            .field("path_style", &self.path_style)
            .finish_non_exhaustive()
    }
}

/// An S3 blob store. Cheap to clone.
#[derive(Clone)]
pub struct S3BlobStore {
    inner: Arc<Inner>,
}

struct Inner {
    bucket: Bucket,
    credentials: Credentials,
    agent: ureq::Agent,
    max_bytes: u64,
}

impl core::fmt::Debug for S3BlobStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("S3BlobStore")
            .field("bucket", &self.inner.bucket.name())
            .field("max_bytes", &self.inner.max_bytes)
            .finish_non_exhaustive()
    }
}

fn unavailable(status: Option<u16>) -> StoreError {
    StoreError::BlobUnavailable {
        status: status.map(i64::from),
    }
}

impl S3BlobStore {
    /// A store for `config`, refusing blobs over [`DEFAULT_MAX_BLOB_BYTES`].
    ///
    /// # Errors
    ///
    /// `CS-BLOB-0001` for an endpoint that is not an `http` or `https` URL with a host.
    pub fn new(config: &S3Config) -> Result<Self> {
        Self::with_max_bytes(config, DEFAULT_MAX_BLOB_BYTES)
    }

    /// As [`S3BlobStore::new`] with another size cap.
    ///
    /// # Errors
    ///
    /// As [`S3BlobStore::new`].
    pub fn with_max_bytes(config: &S3Config, max_bytes: u64) -> Result<Self> {
        let endpoint = url::Url::parse(&config.endpoint).map_err(|_| unavailable(None))?;
        let style = if config.path_style {
            UrlStyle::Path
        } else {
            UrlStyle::VirtualHost
        };
        let bucket = Bucket::new(
            endpoint,
            style,
            config.bucket.clone(),
            config.region.clone(),
        )
        .map_err(|_| unavailable(None))?;
        let credentials = Credentials::new(config.access_key.clone(), config.secret_key.clone());
        let mut extra = Vec::new();
        if let Some(pem) = &config.ca_pem {
            for item in ureq::tls::parse_pem(pem) {
                if let ureq::tls::PemItem::Certificate(c) = item.map_err(|_| unavailable(None))? {
                    extra.push(c);
                }
            }
            if extra.is_empty() {
                return Err(unavailable(None));
            }
        }
        Ok(Self {
            inner: Arc::new(Inner {
                bucket,
                credentials,
                agent: agent(extra),
                max_bytes,
            }),
        })
    }

    /// Create the bucket (tests and first-run setup). An existing bucket owned by these
    /// credentials is not an error.
    ///
    /// # Errors
    ///
    /// `CS-BLOB-0001` when the store refuses.
    pub async fn create_bucket(&self) -> Result<()> {
        let inner = Arc::clone(&self.inner);
        blocking(move || {
            let url = inner.bucket.create_bucket(&inner.credentials).sign(PRESIGN);
            let r = inner
                .agent
                .put(url.as_str())
                .send_empty()
                .map_err(|_| unavailable(None))?;
            match r.status().as_u16() {
                200..=299 | 409 => Ok(()),
                s => Err(unavailable(Some(s))),
            }
        })
        .await
    }
}

/// rustls on aws-lc-rs with the platform's roots and `extra`, 60-second budget, no
/// redirects, and HTTP error statuses returned as responses so 404 and 412 can be told
/// apart.
fn agent(extra: Vec<ureq::tls::Certificate<'static>>) -> ureq::Agent {
    let native = rustls_native_certs::load_native_certs();
    let mut roots: Vec<ureq::tls::Certificate<'static>> = native
        .certs
        .iter()
        .map(|c| ureq::tls::Certificate::from_der(c.as_ref()).to_owned())
        .collect();
    roots.extend(extra);
    let tls = ureq::tls::TlsConfig::builder()
        .provider(ureq::tls::TlsProvider::Rustls)
        .root_certs(ureq::tls::RootCerts::new_with_certs(&roots))
        .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .build();
    ureq::Agent::config_builder()
        .tls_config(tls)
        .timeout_global(Some(Duration::from_secs(60)))
        .max_redirects(0)
        .http_status_as_error(false)
        .user_agent("openseal")
        .build()
        .into()
}

/// Run blocking HTTP off the async executor.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|_| unavailable(None))?
}

impl BlobStore for S3BlobStore {
    async fn put(&self, bytes: &[u8]) -> Result<BlobKey> {
        within(
            u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            self.inner.max_bytes,
        )?;
        let key = BlobKey::of(bytes);
        let inner = Arc::clone(&self.inner);
        let bytes = bytes.to_vec();
        blocking(move || {
            let name = key.hex();
            let url = inner
                .bucket
                .put_object(Some(&inner.credentials), &name)
                .sign(PRESIGN);
            let r = inner
                .agent
                .put(url.as_str())
                .header("If-None-Match", "*")
                .header("Content-Type", "application/octet-stream")
                .send(&bytes[..])
                .map_err(|_| unavailable(None))?;
            match r.status().as_u16() {
                // Stored now, or already there (412: the conditional write found it).
                200..=299 | 412 => Ok(key),
                s => Err(unavailable(Some(s))),
            }
        })
        .await
    }

    async fn get(&self, key: &BlobKey) -> Result<Vec<u8>> {
        let key = *key;
        let inner = Arc::clone(&self.inner);
        blocking(move || {
            let name = key.hex();
            let url = inner
                .bucket
                .get_object(Some(&inner.credentials), &name)
                .sign(PRESIGN);
            let mut r = inner
                .agent
                .get(url.as_str())
                .call()
                .map_err(|_| unavailable(None))?;
            match r.status().as_u16() {
                200 => {}
                404 => return Err(StoreError::BlobNotFound),
                s => return Err(unavailable(Some(s))),
            }
            let limit = inner.max_bytes.saturating_add(1);
            let bytes = r
                .body_mut()
                .with_config()
                .limit(limit)
                .read_to_vec()
                .map_err(|e| match e {
                    ureq::Error::BodyExceedsLimit(_) => StoreError::BlobTooLarge {
                        max: inner.max_bytes,
                    },
                    _ => unavailable(None),
                })?;
            within(
                u64::try_from(bytes.len()).unwrap_or(u64::MAX),
                inner.max_bytes,
            )?;
            verified(&key, bytes)
        })
        .await
    }

    async fn exists(&self, key: &BlobKey) -> Result<bool> {
        let key = *key;
        let inner = Arc::clone(&self.inner);
        blocking(move || {
            let name = key.hex();
            let url = inner
                .bucket
                .head_object(Some(&inner.credentials), &name)
                .sign(PRESIGN);
            let r = inner
                .agent
                .head(url.as_str())
                .call()
                .map_err(|_| unavailable(None))?;
            match r.status().as_u16() {
                200 => Ok(true),
                404 => Ok(false),
                s => Err(unavailable(Some(s))),
            }
        })
        .await
    }
}
