//! Copy a blob store to a directory and back (ASVS-14, docs/65 §Backups): what
//! `casual-sign-server blobs-export` and `blobs-import` run, whatever the store (a
//! directory or an S3 bucket). The directory is flat, one file per blob named by its key,
//! so it is content-addressed like the store: an export into a directory that already
//! holds a blob checks that file and keeps it, and an import puts each file and refuses
//! one whose bytes are not its name's.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::Path;

use super::{BlobKey, BlobStore, DEFAULT_MAX_BLOB_BYTES, verified, within};
use crate::error::{Result, StoreError};

/// What [`export_to_dir`] did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExportReport {
    /// Blobs written to the directory.
    pub exported: u64,
    /// Blobs the directory already held, checked against their names.
    pub present: u64,
    /// Names in the store that are not blob keys, skipped.
    pub ignored: u64,
}

/// What [`import_from_dir`] did.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ImportReport {
    /// Files put into the store (a blob it already held counts too: puts are no-ops).
    pub imported: u64,
}

fn io(e: &std::io::Error) -> StoreError {
    StoreError::BlobUnavailable {
        status: e.raw_os_error().map(i64::from),
    }
}

/// Read a file of at most [`DEFAULT_MAX_BLOB_BYTES`] bytes.
fn read_capped(path: &Path) -> Result<Vec<u8>> {
    let file = File::open(path).map_err(|e| io(&e))?;
    let mut bytes = Vec::new();
    file.take(DEFAULT_MAX_BLOB_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| io(&e))?;
    within(
        u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        DEFAULT_MAX_BLOB_BYTES,
    )?;
    Ok(bytes)
}

/// Write every blob of `store` to `dir` (created when missing) as `dir/<key>`.
///
/// # Errors
///
/// `CS-BLOB-0003` when a blob read from the store, or a file already in `dir`, does not
/// hash to its key; `CS-BLOB-0001` for the store or the directory; `CS-BLOB-0004` over
/// the size cap.
pub async fn export_to_dir(store: &impl BlobStore, dir: &Path) -> Result<ExportReport> {
    fs::create_dir_all(dir).map_err(|e| io(&e))?;
    let mut report = ExportReport::default();
    let mut after = None;
    loop {
        let page = store.list(after).await?;
        report.ignored = report.ignored.saturating_add(page.ignored);
        for key in page.keys {
            let path = dir.join(key.hex());
            match fs::symlink_metadata(&path) {
                Ok(m) if m.is_file() => {
                    verified(&key, read_capped(&path)?)?;
                    report.present = report.present.saturating_add(1);
                    continue;
                }
                Ok(_) => return Err(StoreError::BlobUnavailable { status: None }),
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => return Err(io(&e)),
            }
            let bytes = store.get(&key).await?;
            let part = dir.join(format!("{}.part", key.hex()));
            let mut f = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .open(&part)
                .map_err(|e| io(&e))?;
            f.write_all(&bytes).map_err(|e| io(&e))?;
            f.sync_all().map_err(|e| io(&e))?;
            fs::rename(&part, &path).map_err(|e| io(&e))?;
            report.exported = report.exported.saturating_add(1);
        }
        match page.next {
            Some(next) => after = Some(next),
            None => return Ok(report),
        }
    }
}

/// Put every file of `dir` into `store`. Every entry must be a regular file named by a
/// blob key whose bytes hash to that name; anything else stops the import before it is
/// put, since a restore directory holds nothing else.
///
/// # Errors
///
/// `CS-BLOB-0005` for an entry that is not a key-named regular file; `CS-BLOB-0003` for a
/// file whose bytes are not its name's; `CS-BLOB-0004` over the size cap;
/// `CS-BLOB-0001` for the directory or the store.
pub async fn import_from_dir(store: &impl BlobStore, dir: &Path) -> Result<ImportReport> {
    let mut entries = Vec::new();
    for entry in fs::read_dir(dir).map_err(|e| io(&e))? {
        let entry = entry.map_err(|e| io(&e))?;
        let key = entry
            .file_name()
            .to_str()
            .ok_or(StoreError::BlobKey)
            .and_then(BlobKey::parse)?;
        if !entry.file_type().map_err(|e| io(&e))?.is_file() {
            return Err(StoreError::BlobKey);
        }
        entries.push((key, entry.path()));
    }
    entries.sort_unstable_by_key(|(k, _)| *k);
    let mut report = ImportReport::default();
    for (key, path) in entries {
        let bytes = verified(&key, read_capped(&path)?)?;
        if store.put(&bytes).await? != key {
            return Err(StoreError::BlobCorrupt);
        }
        report.imported = report.imported.saturating_add(1);
    }
    Ok(report)
}
