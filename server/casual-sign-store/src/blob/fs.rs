//! Blobs on a local filesystem: `<root>/<k[0..2]>/<k[2..4]>/<key>`.
//!
//! Write-once by construction: bytes go to a fresh temporary file (`create_new`), are
//! synced, made read-only, then hard-linked to their final name. `link` never replaces an
//! existing name, so two writers racing on the same key both succeed and neither
//! overwrites the other; the temporary name is then removed. The path is built from the
//! key's hex digits only, never from a caller's string.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use super::{BlobKey, BlobListing, BlobStore, DEFAULT_MAX_BLOB_BYTES, verified, within};
use crate::error::{Result, StoreError};

/// A filesystem blob store. Cheap to clone.
#[derive(Debug, Clone)]
pub struct FsBlobStore {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    root: PathBuf,
    max_bytes: u64,
    counter: AtomicU64,
}

fn io(e: &std::io::Error) -> StoreError {
    StoreError::BlobUnavailable {
        status: e.raw_os_error().map(i64::from),
    }
}

impl FsBlobStore {
    /// A store rooted at `root` (created if missing), refusing blobs over
    /// [`DEFAULT_MAX_BLOB_BYTES`].
    ///
    /// # Errors
    ///
    /// `CS-BLOB-0001` when the root cannot be created.
    pub fn new(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(root.join("tmp")).map_err(|e| io(&e))?;
        Ok(Self {
            inner: Arc::new(Inner {
                root,
                max_bytes: DEFAULT_MAX_BLOB_BYTES,
                counter: AtomicU64::new(0),
            }),
        })
    }

    /// A store rooted at `root` with another size cap.
    ///
    /// # Errors
    ///
    /// `CS-BLOB-0001` when the root cannot be created.
    pub fn with_max_bytes(root: impl Into<PathBuf>, max_bytes: u64) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(root.join("tmp")).map_err(|e| io(&e))?;
        Ok(Self {
            inner: Arc::new(Inner {
                root,
                max_bytes,
                counter: AtomicU64::new(0),
            }),
        })
    }
}

impl Inner {
    fn path(&self, key: &BlobKey) -> PathBuf {
        let hex = key.hex();
        let (a, rest) = hex.split_at(2);
        let (b, _) = rest.split_at(2);
        self.root.join(a).join(b).join(&hex)
    }

    fn put_blocking(&self, key: BlobKey, bytes: &[u8]) -> Result<()> {
        let final_path = self.path(&key);
        if final_path.exists() {
            return Ok(());
        }
        if let Some(dir) = final_path.parent() {
            fs::create_dir_all(dir).map_err(|e| io(&e))?;
        }
        let n = self.counter.fetch_add(1, Ordering::Relaxed);
        let tmp = self
            .root
            .join("tmp")
            .join(format!("{}.{}.{n}", key.hex(), std::process::id()));
        let outcome =
            write_new(&tmp, bytes).and_then(|()| match fs::hard_link(&tmp, &final_path) {
                Ok(()) => Ok(()),
                // Another writer stored the same content first: same key, same bytes.
                Err(e) if e.kind() == ErrorKind::AlreadyExists => Ok(()),
                Err(e) => Err(io(&e)),
            });
        // The temporary name is removed whatever happened; its bytes live on under the
        // final name if the link succeeded.
        let _ = fs::remove_file(&tmp);
        outcome
    }

    fn get_blocking(&self, key: BlobKey) -> Result<Vec<u8>> {
        let file = match File::open(self.path(&key)) {
            Ok(f) => f,
            Err(e) if e.kind() == ErrorKind::NotFound => return Err(StoreError::BlobNotFound),
            Err(e) => return Err(io(&e)),
        };
        let len = file.metadata().map_err(|e| io(&e))?.len();
        within(len, self.max_bytes)?;
        let mut bytes = Vec::with_capacity(usize::try_from(len).unwrap_or(0));
        // Read at most one byte past the cap, so a file growing underneath is caught.
        file.take(self.max_bytes.saturating_add(1))
            .read_to_end(&mut bytes)
            .map_err(|e| io(&e))?;
        within(
            u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            self.max_bytes,
        )?;
        verified(&key, bytes)
    }
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|e| io(&e))?;
    f.write_all(bytes).map_err(|e| io(&e))?;
    f.sync_all().map_err(|e| io(&e))?;
    let mut perms = f.metadata().map_err(|e| io(&e))?.permissions();
    perms.set_readonly(true);
    fs::set_permissions(path, perms).map_err(|e| io(&e))
}

/// Run blocking filesystem work off the async executor.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(|_| StoreError::BlobUnavailable { status: None })?
}

impl BlobStore for FsBlobStore {
    async fn put(&self, bytes: &[u8]) -> Result<BlobKey> {
        within(
            u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            self.inner.max_bytes,
        )?;
        let key = BlobKey::of(bytes);
        let inner = Arc::clone(&self.inner);
        let bytes = bytes.to_vec();
        blocking(move || inner.put_blocking(key, &bytes)).await?;
        Ok(key)
    }

    async fn get(&self, key: &BlobKey) -> Result<Vec<u8>> {
        let key = *key;
        let inner = Arc::clone(&self.inner);
        blocking(move || inner.get_blocking(key)).await
    }

    async fn exists(&self, key: &BlobKey) -> Result<bool> {
        let path = self.inner.path(key);
        blocking(move || match fs::metadata(&path) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
            Err(e) => Err(io(&e)),
        })
        .await
    }

    async fn list(&self, after: Option<String>) -> Result<BlobListing> {
        let inner = Arc::clone(&self.inner);
        blocking(move || inner.list_blocking(after.as_deref())).await
    }
}

/// Keys per page of [`FsBlobStore`]'s listing.
const LIST_PAGE: usize = 1000;

impl Inner {
    /// Every key under the root (`aa/bb/<hex>`), past `after`, at most [`LIST_PAGE`].
    /// The `tmp` directory holds writes in flight and is not listed; anything else that
    /// is not a key in its own place is counted as ignored.
    fn list_blocking(&self, after: Option<&str>) -> Result<BlobListing> {
        let mut keys = Vec::new();
        let mut ignored: u64 = 0;
        for a in fs::read_dir(&self.root).map_err(|e| io(&e))? {
            let a = a.map_err(|e| io(&e))?;
            let a_name = a.file_name();
            if a_name == "tmp" {
                continue;
            }
            if !a.file_type().map_err(|e| io(&e))?.is_dir() {
                ignored = ignored.saturating_add(1);
                continue;
            }
            for b in fs::read_dir(a.path()).map_err(|e| io(&e))? {
                let b = b.map_err(|e| io(&e))?;
                if !b.file_type().map_err(|e| io(&e))?.is_dir() {
                    ignored = ignored.saturating_add(1);
                    continue;
                }
                for f in fs::read_dir(b.path()).map_err(|e| io(&e))? {
                    let f = f.map_err(|e| io(&e))?;
                    let key = f
                        .file_name()
                        .to_str()
                        .and_then(|n| BlobKey::parse(n).ok())
                        .filter(|k| self.path(k) == f.path());
                    match key {
                        Some(k) if f.file_type().map_err(|e| io(&e))?.is_file() => keys.push(k),
                        _ => ignored = ignored.saturating_add(1),
                    }
                }
            }
        }
        keys.sort_unstable();
        // Every page walks the whole tree; what is not a blob is reported once, on the
        // first page, so a caller summing the pages counts each stray name once.
        if let Some(after) = after {
            ignored = 0;
            let after =
                BlobKey::parse(after).map_err(|_| StoreError::BlobUnavailable { status: None })?;
            keys.retain(|k| *k > after);
        }
        let next = if keys.len() > LIST_PAGE {
            keys.truncate(LIST_PAGE);
            keys.last().map(BlobKey::hex)
        } else {
            None
        };
        Ok(BlobListing {
            keys,
            ignored,
            next,
        })
    }
}
