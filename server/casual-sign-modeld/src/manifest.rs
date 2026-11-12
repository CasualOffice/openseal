//! The model bundle and its manifest (docs/33 §8, `SEC-I03`, `SEC-I11`).
//!
//! The manifest is compiled into the binary ([`Manifest::embedded`], from
//! `server/casual-sign-modeld/models.tsv`, which `tools/ml/fetch-models.py` writes from
//! `tools/ml/models.toml`). An operator's volume therefore cannot bring its own list: a
//! weight swapped on disk, with or without a matching manifest beside it, fails here.
//!
//! ```text
//! # comment
//! id  profile  sha256  bytes  licence  path          (tab-separated, one file per line)
//! ```
//!
//! - `id` and `profile` are identifiers (`[A-Za-z0-9._-]{1,64}`); ids are unique.
//! - `sha256` is 64 lowercase hex digits; `bytes` the exact size.
//! - `licence` is one SPDX identifier from [`ALLOWED_LICENCES`] (deny.toml's list; anything
//!   else needs an ADR), else `CS-ML-0003`.
//! - `path` is relative to the bundle directory: `/`-separated segments of
//!   `[A-Za-z0-9._-]`, no `.` or `..` segment, unique. A pickle format (`.bin`, `.pt`,
//!   `.pth`, `.pkl`, `.ckpt`) is refused (`CS-ML-0003`): pickle loading runs code.
//!
//! At start, [`Bundle::verify`] walks the bundle directory. Every regular file must be
//! listed (symbolic links and other kinds are refused), every listed file present must
//! have its size and SHA-256, and every file of each profile the operator enabled must be
//! present. Any failure is `CS-ML-0002` and modeld does not start.
//!
//! The bundle id is the hex SHA-256 of the installed entries' canonical lines
//! (`id\tprofile\tsha256\tbytes\tlicence\tpath\n`, sorted by id). `fetch-models.py`
//! computes the same value for `bundle.json`.

use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use aws_lc_rs::digest::{Context, SHA256};

use crate::error::{BundleProblem, ModelRefusal, ModeldError};
use crate::oplog::hex;
use crate::wire::valid_id;

/// The licences a weight or runtime file may carry: deny.toml's `[licenses] allow`.
pub const ALLOWED_LICENCES: &[&str] = &[
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "MIT",
    "NCSA",
    "Unicode-3.0",
    "Unlicense",
    "Zlib",
];

/// Largest single file in a bundle (docs/33 §4; to be set from the measured int8 exports,
/// review defect 6).
pub const MAX_FILE: u64 = 1 << 30;
/// Largest bundle.
pub const MAX_BUNDLE: u64 = 2 << 30;
/// Most files a bundle directory may hold.
pub const MAX_FILES: usize = 256;
/// Deepest directory nesting in a bundle.
pub const MAX_DEPTH: usize = 6;

const PICKLE: &[&str] = &["bin", "pt", "pth", "pkl", "pickle", "ckpt"];

/// One manifest line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Model file id, as INFO and every suggestion name it.
    pub id: String,
    /// The profile it belongs to (`ocr`, `templates`, `extraction`, `personal_data`,
    /// `runtime`, ...).
    pub profile: String,
    /// Its SHA-256.
    pub sha256: [u8; 32],
    /// Its size in bytes.
    pub bytes: u64,
    /// Its SPDX licence.
    pub licence: String,
    /// Its path under the bundle directory.
    pub path: String,
}

impl Entry {
    fn canonical(&self) -> String {
        format!(
            "{}\t{}\t{}\t{}\t{}\t{}\n",
            self.id,
            self.profile,
            hex(&self.sha256),
            self.bytes,
            self.licence,
            self.path
        )
    }
}

/// The parsed manifest.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Manifest {
    entries: Vec<Entry>,
}

fn valid_path(p: &str) -> bool {
    !p.is_empty()
        && p.len() <= 255
        && p.split('/').all(|seg| {
            !seg.is_empty()
                && seg != "."
                && seg != ".."
                && seg
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        })
}

fn parse_sha(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, slot) in out.iter_mut().enumerate() {
        let at = i.checked_mul(2)?;
        *slot = u8::from_str_radix(s.get(at..at.checked_add(2)?)?, 16).ok()?;
    }
    Some(out)
}

impl Manifest {
    /// The manifest compiled into this binary.
    ///
    /// # Errors
    /// As [`Manifest::parse`]; a build whose manifest does not parse never serves.
    pub fn embedded() -> Result<Self, ModeldError> {
        Self::parse(include_str!("../models.tsv"))
    }

    /// Parse manifest text.
    ///
    /// # Errors
    /// `CS-ML-0002` for a line that does not parse, a duplicate id or path, a file over
    /// [`MAX_FILE`] or a total over [`MAX_BUNDLE`]; `CS-ML-0003` for a licence not on the
    /// allow list or a pickle file.
    pub fn parse(text: &str) -> Result<Self, ModeldError> {
        let mut entries: Vec<Entry> = Vec::new();
        let mut total: u64 = 0;
        for (i, line) in text.lines().enumerate() {
            let n = i.saturating_add(1);
            let bad = || ModeldError::Bundle(BundleProblem::ManifestLine(n));
            if line.trim().is_empty() || line.starts_with('#') {
                continue;
            }
            let fields: Vec<&str> = line.split('\t').collect();
            let [id, profile, sha, bytes, licence, path] = fields.as_slice() else {
                return Err(bad());
            };
            if !valid_id(id) || !valid_id(profile) || !valid_path(path) {
                return Err(bad());
            }
            let sha256 = parse_sha(sha).ok_or_else(bad)?;
            let bytes: u64 = bytes.parse().map_err(|_| bad())?;
            if !ALLOWED_LICENCES.contains(licence) {
                return Err(ModeldError::ModelRefused(ModelRefusal::Licence(
                    (*id).to_owned(),
                )));
            }
            let ext = path.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase());
            if ext.is_some_and(|e| PICKLE.contains(&e.as_str())) {
                return Err(ModeldError::ModelRefused(ModelRefusal::Pickle(
                    (*path).to_owned(),
                )));
            }
            if bytes > MAX_FILE {
                return Err(ModeldError::Bundle(BundleProblem::OverCap(
                    (*id).to_owned(),
                )));
            }
            total = total.saturating_add(bytes);
            if total > MAX_BUNDLE {
                return Err(ModeldError::Bundle(BundleProblem::OverCap("bundle".into())));
            }
            if entries.iter().any(|e| e.id == *id || e.path == *path) {
                return Err(ModeldError::Bundle(BundleProblem::Duplicate(
                    (*id).to_owned(),
                )));
            }
            entries.push(Entry {
                id: (*id).to_owned(),
                profile: (*profile).to_owned(),
                sha256,
                bytes,
                licence: (*licence).to_owned(),
                path: (*path).to_owned(),
            });
        }
        Ok(Self { entries })
    }

    /// The entries, in manifest order.
    #[must_use]
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }
}

/// A verified, installed bundle: what INFO reports and what the ops may load.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bundle {
    /// The bundle id (see the module docs).
    pub id: String,
    /// The bundle directory.
    pub dir: PathBuf,
    /// The installed entries, sorted by id.
    pub installed: Vec<Entry>,
}

fn unreadable(e: &std::io::Error) -> ModeldError {
    ModeldError::Bundle(BundleProblem::Unreadable(e.kind().to_string()))
}

/// Every regular file under `dir`, as `/`-joined relative paths. Symbolic links and
/// other file kinds are refused; so is a tree deeper than [`MAX_DEPTH`] or with more than
/// [`MAX_FILES`] files.
fn walk(dir: &Path, rel: &str, depth: usize, out: &mut Vec<String>) -> Result<(), ModeldError> {
    if depth > MAX_DEPTH {
        return Err(ModeldError::Bundle(BundleProblem::OverCap(
            "directory depth".into(),
        )));
    }
    let mut items = std::fs::read_dir(dir)
        .map_err(|e| unreadable(&e))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| unreadable(&e))?;
    items.sort_by_key(std::fs::DirEntry::file_name);
    for item in items {
        let name = item.file_name();
        // A name that is not UTF-8 cannot be listed; it is reported by its lossy form.
        let name = name.to_string_lossy();
        let path = if rel.is_empty() {
            name.into_owned()
        } else {
            format!("{rel}/{name}")
        };
        let kind = item.file_type().map_err(|e| unreadable(&e))?;
        if kind.is_dir() {
            walk(&item.path(), &path, depth.saturating_add(1), out)?;
        } else if kind.is_file() {
            if out.len() >= MAX_FILES {
                return Err(ModeldError::Bundle(BundleProblem::OverCap(
                    "file count".into(),
                )));
            }
            out.push(path);
        } else {
            // A symbolic link could point outside the read-only mount.
            return Err(ModeldError::Bundle(BundleProblem::Unlisted(path)));
        }
    }
    Ok(())
}

/// The SHA-256 of `path`, read in bounded chunks, refusing a file longer than `limit`.
fn file_sha256(path: &Path, limit: u64) -> Result<([u8; 32], u64), ModeldError> {
    let mut f = File::open(path).map_err(|e| unreadable(&e))?;
    let mut ctx = Context::new(&SHA256);
    let mut buf = vec![0u8; 1 << 20];
    let mut total: u64 = 0;
    loop {
        let n = match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(unreadable(&e)),
        };
        total = total.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        if total > limit {
            return Err(ModeldError::Bundle(BundleProblem::Size(
                path.display().to_string(),
            )));
        }
        ctx.update(buf.get(..n).unwrap_or_default());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(ctx.finish().as_ref());
    Ok((out, total))
}

impl Bundle {
    /// Verify the bundle directory `dir` against `manifest`, requiring every file of each
    /// profile in `profiles`.
    ///
    /// # Errors
    /// `CS-ML-0002` naming the first file that is missing, unlisted, the wrong size or the
    /// wrong hash, or a profile no entry has.
    pub fn verify(
        dir: &Path,
        manifest: &Manifest,
        profiles: &[String],
    ) -> Result<Self, ModeldError> {
        for p in profiles {
            if !manifest.entries.iter().any(|e| &e.profile == p) {
                return Err(ModeldError::Bundle(BundleProblem::UnknownProfile(
                    p.clone(),
                )));
            }
        }
        let mut present = Vec::new();
        walk(dir, "", 0, &mut present)?;
        for p in &present {
            if !manifest.entries.iter().any(|e| &e.path == p) {
                return Err(ModeldError::Bundle(BundleProblem::Unlisted(p.clone())));
            }
        }
        let mut installed = Vec::new();
        for e in &manifest.entries {
            let here = present.contains(&e.path);
            if !here {
                if profiles.contains(&e.profile) {
                    return Err(ModeldError::Bundle(BundleProblem::Missing(e.path.clone())));
                }
                continue;
            }
            let file = dir.join(&e.path);
            let meta = std::fs::symlink_metadata(&file).map_err(|err| unreadable(&err))?;
            if meta.len() != e.bytes {
                return Err(ModeldError::Bundle(BundleProblem::Size(e.path.clone())));
            }
            let (sha, len) = file_sha256(&file, e.bytes)?;
            if len != e.bytes {
                return Err(ModeldError::Bundle(BundleProblem::Size(e.path.clone())));
            }
            if sha != e.sha256 {
                return Err(ModeldError::Bundle(BundleProblem::Hash(e.path.clone())));
            }
            installed.push(e.clone());
        }
        installed.sort_by(|a, b| a.id.cmp(&b.id));
        let mut ctx = Context::new(&SHA256);
        for e in &installed {
            ctx.update(e.canonical().as_bytes());
        }
        Ok(Self {
            id: hex(ctx.finish().as_ref()),
            dir: dir.to_owned(),
            installed,
        })
    }

    /// The installed entry with this id.
    #[must_use]
    pub fn model(&self, id: &str) -> Option<&Entry> {
        self.installed.iter().find(|e| e.id == id)
    }
}

#[cfg(test)]
mod tests {
    // Test code: a panic is the failure report.
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    fn sha_hex(b: &[u8]) -> String {
        hex(aws_lc_rs::digest::digest(&SHA256, b).as_ref())
    }

    #[test]
    fn the_embedded_manifest_parses() {
        Manifest::embedded().unwrap();
    }

    #[test]
    fn manifest_lines_that_do_not_parse_are_refused() {
        let good = format!("m1\tocr\t{}\t3\tApache-2.0\tocr/det.onnx", sha_hex(b"abc"));
        assert_eq!(Manifest::parse(&good).unwrap().entries().len(), 1);
        let cases = [
            ("missing field", good.replacen("\tApache-2.0", "", 1)),
            ("short hash", good.replacen(&sha_hex(b"abc"), "abcd", 1)),
            (
                "upper-case hash",
                good.replacen(&sha_hex(b"abc"), &sha_hex(b"abc").to_uppercase(), 1),
            ),
            ("size", good.replacen("\t3\t", "\t-3\t", 1)),
            ("id", good.replacen("m1", "m 1", 1)),
            (
                "dot-dot path",
                good.replacen("ocr/det.onnx", "../det.onnx", 1),
            ),
            (
                "absolute path",
                good.replacen("ocr/det.onnx", "/det.onnx", 1),
            ),
            (
                "empty segment",
                good.replacen("ocr/det.onnx", "ocr//det.onnx", 1),
            ),
        ];
        for (what, text) in cases {
            let e = Manifest::parse(&text).unwrap_err();
            assert_eq!(e.code(), "CS-ML-0002", "{what}");
        }
        let dup = format!("{good}\n{}", good.replacen("ocr/det", "ocr/other", 1));
        assert!(matches!(
            Manifest::parse(&dup).unwrap_err(),
            ModeldError::Bundle(BundleProblem::Duplicate(_))
        ));
        let over = good.replacen("\t3\t", &format!("\t{}\t", MAX_FILE + 1), 1);
        assert!(matches!(
            Manifest::parse(&over).unwrap_err(),
            ModeldError::Bundle(BundleProblem::OverCap(_))
        ));
    }

    /// `SEC-I11`: a weight under a non-commercial or copyleft licence never enters a
    /// bundle, and pickle files are never listed.
    #[test]
    fn disallowed_licences_and_pickle_files_are_refused() {
        let line = |licence: &str, path: &str| {
            format!("m1\tner\t{}\t3\t{licence}\t{path}", sha_hex(b"abc"))
        };
        for licence in [
            "CC-BY-NC-4.0",
            "AGPL-3.0",
            "GPL-3.0-only",
            "CC-BY-SA-4.0",
            "",
            "apache-2.0",
        ] {
            let e = Manifest::parse(&line(licence, "m.onnx")).unwrap_err();
            assert_eq!(e.code(), "CS-ML-0003", "{licence}");
        }
        for path in ["pytorch_model.bin", "m.pt", "w/m.PTH", "m.pkl", "m.ckpt"] {
            let e = Manifest::parse(&line("MIT", path)).unwrap_err();
            assert_eq!(e.code(), "CS-ML-0003", "{path}");
        }
        assert!(Manifest::parse(&line("NCSA", "m.onnx")).is_ok());
    }
}
