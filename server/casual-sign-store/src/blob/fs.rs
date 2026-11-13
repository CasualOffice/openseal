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
    /// Up to [`LIST_PAGE`] keys under the root (`aa/bb/<hex>`), past `after`, walking the
    /// tree once in key order: each directory's names are read and sorted, the ones
    /// before the cursor skipped, and the walk stops at the page's last key. A page costs
    /// the directories it covers, not the whole tree, so listing N blobs reads each
    /// directory about once. The `tmp` directory holds writes in flight and is not
    /// listed; anything else that is not a key in its own place is counted as ignored,
    /// once: a directory's strays on the page that enters it from its start (the root's
    /// on the first page), never on a page that resumes inside it.
    fn list_blocking(&self, after: Option<&str>) -> Result<BlobListing> {
        let after = after
            .map(BlobKey::parse)
            .transpose()
            .map_err(|_| StoreError::BlobUnavailable { status: None })?
            .map(|k| k.hex());
        let mut page = Page::default();
        let root = sorted_entries(&self.root)?;
        if after.is_none() {
            page.stray(
                root.iter()
                    .filter(|(n, d)| n != "tmp" && !(*d && is_hex_pair(n)))
                    .count(),
            );
        }
        let (resume_a, resume_b) = after
            .as_deref()
            .map_or((None, None), |h| (h.get(..2), h.get(2..4)));
        for (a, is_dir) in &root {
            if !is_dir || !is_hex_pair(a) || resume_a.is_some_and(|r| a.as_str() < r) {
                continue;
            }
            let a_resumed = resume_a == Some(a.as_str());
            let a_path = self.root.join(a);
            let subdirs = sorted_entries(&a_path)?;
            if !a_resumed {
                page.stray(subdirs.iter().filter(|(_, d)| !d).count());
            }
            for (b, is_dir) in &subdirs {
                if !is_dir || (a_resumed && resume_b.is_some_and(|r| b.as_str() < r)) {
                    continue;
                }
                let resumed = a_resumed && resume_b == Some(b.as_str());
                let b_path = a_path.join(b);
                let files = sorted_entries(&b_path)?;
                for (name, is_dir) in files {
                    let key = BlobKey::parse(&name)
                        .ok()
                        .filter(|k| !is_dir && self.path(k) == b_path.join(&name));
                    let past = after.as_deref().is_none_or(|h| name.as_str() > h);
                    match key {
                        Some(k) if past => {
                            page.keys.push(k);
                            if page.keys.len() == LIST_PAGE {
                                let next = page.keys.last().map(BlobKey::hex);
                                return Ok(page.done(next));
                            }
                        }
                        Some(_) => {}
                        None if !resumed => page.stray(1),
                        None => {}
                    }
                }
            }
        }
        Ok(page.done(None))
    }
}

/// A listing page being filled.
#[derive(Default)]
struct Page {
    keys: Vec<BlobKey>,
    ignored: usize,
}

impl Page {
    fn stray(&mut self, n: usize) {
        self.ignored = self.ignored.saturating_add(n);
    }

    fn done(self, next: Option<String>) -> BlobListing {
        BlobListing {
            keys: self.keys,
            ignored: u64::try_from(self.ignored).unwrap_or(u64::MAX),
            next,
        }
    }
}

/// Two lower-case hexadecimal digits: a level of the key tree.
fn is_hex_pair(name: &str) -> bool {
    name.len() == 2 && name.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
}

/// A directory's entries as (name, is a directory), sorted by name; a name that is not
/// UTF-8 is kept as its lossy form (never a key, so only ever counted as ignored).
fn sorted_entries(dir: &Path) -> Result<Vec<(String, bool)>> {
    let mut out = Vec::new();
    for e in fs::read_dir(dir).map_err(|e| io(&e))? {
        let e = e.map_err(|e| io(&e))?;
        let is_dir = e.file_type().map_err(|e| io(&e))?.is_dir();
        out.push((e.file_name().to_string_lossy().into_owned(), is_dir));
    }
    out.sort_unstable();
    Ok(out)
}
