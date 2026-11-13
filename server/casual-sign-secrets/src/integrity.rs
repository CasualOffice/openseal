//! The SHA-256 of a daemon's security configuration, logged at start and checked
//! against an operator's manifest (ASVS 14.1.5, `ASVS-24`, `HRD-06`).
//!
//! # Why
//!
//! keyd's allow list decides who may obtain a seal; the worker's trust anchors and TSA
//! list decide what a seal is checked against. Each is a file or a variable an
//! operator edits, and each is read **once, at start**: a change on disk has no effect
//! until a restart. The restart is where a change could slip in unnoticed, so at start
//! the daemon hashes every such setting, logs the digests, and, when
//! `OPENSEAL_CONFIG_MANIFEST` names a manifest, refuses to start unless the settings are
//! exactly the ones the manifest records: no setting changed, none added, none removed.
//! The manifest is written by the operator after an approved change
//! (`casual-sign-keyd config-manifest`, `casual-sign-worker config-manifest`) and mounted
//! read-only, so changing the configuration takes two edits in two places, and the
//! digest in the log lets anyone compare.
//!
//! Secrets (a PIN, a private key, a password) are never items: the hash of a
//! low-entropy secret is a way to guess it.
//!
//! # Format
//!
//! One line per setting, sorted by name, `sha256:<64 hex digits>  <NAME>`. Blank lines
//! and lines starting with `#` are ignored. A file setting hashes the file's bytes; a
//! value setting hashes the variable's bytes. A setting that is unset has no line.

use std::path::Path;

use sha2::{Digest as _, Sha256};

/// The variable naming the manifest a daemon checks its configuration against.
pub const MANIFEST_VAR: &str = "OPENSEAL_CONFIG_MANIFEST";

/// The digest of one security setting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigItem {
    name: String,
    sha256: [u8; 32],
}

impl ConfigItem {
    /// A setting whose value is the content of the file at `path`.
    ///
    /// # Errors
    ///
    /// [`IntegrityError::Unreadable`] when the file cannot be read.
    pub fn file(name: &str, path: &Path) -> Result<Self, IntegrityError> {
        let bytes = std::fs::read(path).map_err(|_| IntegrityError::Unreadable {
            name: name.to_owned(),
        })?;
        Ok(Self::value(name, &bytes))
    }

    /// A setting whose value is `bytes` itself.
    #[must_use]
    pub fn value(name: &str, bytes: &[u8]) -> Self {
        Self {
            name: name.to_owned(),
            sha256: Sha256::digest(bytes).into(),
        }
    }

    /// The setting's name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// `sha256:` and the digest in lower-case hex.
    #[must_use]
    pub fn digest(&self) -> String {
        format!("sha256:{}", hex(&self.sha256))
    }
}

/// Every security setting of one daemon, sorted by name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigDigest {
    items: Vec<ConfigItem>,
}

impl ConfigDigest {
    /// The digest of these settings. A name given twice keeps the last.
    #[must_use]
    pub fn new(items: Vec<ConfigItem>) -> Self {
        let mut items = items;
        items.sort_by(|a, b| a.name.cmp(&b.name));
        items.reverse();
        items.dedup_by(|a, b| a.name == b.name);
        items.reverse();
        Self { items }
    }

    /// Read from the environment: each of `files` that is set names a file to hash, each
    /// of `values` that is set is hashed as it stands. Unset or empty settings are absent.
    ///
    /// # Errors
    ///
    /// [`IntegrityError::Unreadable`] when a named file cannot be read.
    pub fn from_env(files: &[&str], values: &[&str]) -> Result<Self, IntegrityError> {
        let get = |n: &str| std::env::var(n).ok().filter(|v| !v.is_empty());
        let mut items = Vec::new();
        for name in files {
            if let Some(path) = get(name) {
                items.push(ConfigItem::file(name, Path::new(&path))?);
            }
        }
        for name in values {
            if let Some(v) = get(name) {
                items.push(ConfigItem::value(name, v.as_bytes()));
            }
        }
        Ok(Self::new(items))
    }

    /// The settings, sorted by name.
    #[must_use]
    pub fn items(&self) -> &[ConfigItem] {
        &self.items
    }

    /// The manifest these settings match, in the format the module documents.
    #[must_use]
    pub fn manifest(&self) -> String {
        self.items
            .iter()
            .map(|i| format!("{}  {}\n", i.digest(), i.name))
            .collect()
    }

    /// One digest over the whole configuration: the SHA-256 of [`Self::manifest`], the
    /// value an operator compares between the log and the manifest file.
    #[must_use]
    pub fn combined(&self) -> String {
        let d: [u8; 32] = Sha256::digest(self.manifest().as_bytes()).into();
        format!("sha256:{}", hex(&d))
    }

    /// Check these settings against `manifest`: every setting it lists has the digest
    /// it records, and nothing is set that it does not list.
    ///
    /// # Errors
    ///
    /// The first difference, by setting name ([`IntegrityError`]); never a digest or a
    /// value.
    pub fn check(&self, manifest: &str) -> Result<(), IntegrityError> {
        let mut expected: Vec<(String, String)> = Vec::new();
        for (n, line) in manifest.lines().enumerate() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let number = n.saturating_add(1);
            let mut parts = line.split_whitespace();
            let (Some(digest), Some(name), None) = (parts.next(), parts.next(), parts.next())
            else {
                return Err(IntegrityError::Malformed { line: number });
            };
            let well_formed = digest
                .strip_prefix("sha256:")
                .is_some_and(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit()));
            if !well_formed || expected.iter().any(|(e, _)| e == name) {
                return Err(IntegrityError::Malformed { line: number });
            }
            expected.push((name.to_owned(), digest.to_ascii_lowercase()));
        }
        for item in &self.items {
            match expected.iter().find(|(n, _)| *n == item.name) {
                None => {
                    return Err(IntegrityError::Unlisted {
                        name: item.name.clone(),
                    });
                }
                Some((_, digest)) if *digest != item.digest() => {
                    return Err(IntegrityError::Changed {
                        name: item.name.clone(),
                    });
                }
                Some(_) => {}
            }
        }
        if let Some((name, _)) = expected
            .iter()
            .find(|(n, _)| !self.items.iter().any(|i| i.name == *n))
        {
            return Err(IntegrityError::Missing { name: name.clone() });
        }
        Ok(())
    }

    /// Log the digests to standard error as `{who}: config …` lines, then, when
    /// `OPENSEAL_CONFIG_MANIFEST` is set, check them against that file. Returns whether
    /// a manifest was checked.
    ///
    /// # Errors
    ///
    /// [`IntegrityError`] when the manifest cannot be read or does not match.
    pub fn log_and_check(&self, who: &str) -> Result<bool, IntegrityError> {
        for item in &self.items {
            eprintln!("{who}: config {} {}", item.name, item.digest());
        }
        eprintln!(
            "{who}: security configuration {} ({} settings)",
            self.combined(),
            self.items.len()
        );
        let Some(path) = std::env::var(MANIFEST_VAR).ok().filter(|v| !v.is_empty()) else {
            eprintln!("{who}: {MANIFEST_VAR} is not set; the configuration is not checked");
            return Ok(false);
        };
        let text = std::fs::read_to_string(&path).map_err(|_| IntegrityError::Unreadable {
            name: MANIFEST_VAR.to_owned(),
        })?;
        self.check(&text)?;
        eprintln!("{who}: security configuration matches {MANIFEST_VAR}");
        Ok(true)
    }
}

/// Why a configuration does not verify. Every variant names a setting or a line, never
/// a value or a digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntegrityError {
    /// A file setting, or the manifest itself, could not be read.
    Unreadable {
        /// The setting's name.
        name: String,
    },
    /// A manifest line is not `sha256:<64 hex>  NAME`, or names a setting twice.
    Malformed {
        /// The 1-based line number.
        line: usize,
    },
    /// A setting's digest differs from the manifest's.
    Changed {
        /// The setting's name.
        name: String,
    },
    /// A setting is set that the manifest does not list.
    Unlisted {
        /// The setting's name.
        name: String,
    },
    /// The manifest lists a setting that is not set.
    Missing {
        /// The setting's name.
        name: String,
    },
}

impl IntegrityError {
    /// The stable docs/20 code: always `CS-KEY-0014`.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        "CS-KEY-0014"
    }
}

impl core::fmt::Display for IntegrityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let code = self.code();
        match self {
            Self::Unreadable { name } => write!(f, "{code}: {name} could not be read"),
            Self::Malformed { line } => write!(f, "{code}: manifest line {line} is malformed"),
            Self::Changed { name } => {
                write!(f, "{code}: {name} differs from the configuration manifest")
            }
            Self::Unlisted { name } => {
                write!(
                    f,
                    "{code}: {name} is set but not in the configuration manifest"
                )
            }
            Self::Missing { name } => {
                write!(
                    f,
                    "{code}: {name} is in the configuration manifest but not set"
                )
            }
        }
    }
}

impl std::error::Error for IntegrityError {}

fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    bytes.iter().fold(String::with_capacity(64), |mut s, b| {
        let _ = write!(s, "{b:02x}");
        s
    })
}

#[cfg(test)]
// Test code: a panic is the failure report (CLAUDE.md).
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn config(allow: &[u8]) -> ConfigDigest {
        ConfigDigest::new(vec![
            ConfigItem::value("OPENSEAL_KEYD_ALLOW_LIST", allow),
            ConfigItem::value("OPENSEAL_KEYD_ALIAS", b"platform"),
        ])
    }

    #[test]
    fn a_configuration_matches_its_own_manifest() {
        let c = config(b"ab12 worker\n");
        assert_eq!(c.check(&c.manifest()), Ok(()));
        assert!(c.manifest().starts_with("sha256:"));
        assert_eq!(c.items()[0].name(), "OPENSEAL_KEYD_ALIAS");
    }

    #[test]
    fn a_changed_allow_list_is_refused_by_name() {
        let manifest = config(b"ab12 worker\n").manifest();
        let changed = config(b"ab12 worker\ncd34 intruder\n");
        assert_eq!(
            changed.check(&manifest),
            Err(IntegrityError::Changed {
                name: "OPENSEAL_KEYD_ALLOW_LIST".into()
            })
        );
        assert_ne!(changed.combined(), config(b"ab12 worker\n").combined());
    }

    #[test]
    fn an_added_setting_is_refused() {
        let manifest = config(b"x").manifest();
        let mut items = config(b"x").items().to_vec();
        items.push(ConfigItem::value("OPENSEAL_KEYD_ADMIN_ALLOW_LIST", b"y"));
        assert_eq!(
            ConfigDigest::new(items).check(&manifest),
            Err(IntegrityError::Unlisted {
                name: "OPENSEAL_KEYD_ADMIN_ALLOW_LIST".into()
            })
        );
    }

    #[test]
    fn a_removed_setting_is_refused() {
        let manifest = config(b"x").manifest();
        let fewer = ConfigDigest::new(vec![ConfigItem::value("OPENSEAL_KEYD_ALIAS", b"platform")]);
        assert_eq!(
            fewer.check(&manifest),
            Err(IntegrityError::Missing {
                name: "OPENSEAL_KEYD_ALLOW_LIST".into()
            })
        );
    }

    #[test]
    fn malformed_manifests_are_refused_with_their_line() {
        let c = config(b"x");
        let good = c.manifest();
        for (bad, line) in [
            ("sha256:zz  OPENSEAL_KEYD_ALIAS\n".to_owned(), 1),
            ("# comment\n\nOPENSEAL_KEYD_ALIAS\n".to_owned(), 3),
            (format!("{good}{good}"), 3),
            (
                good.replace("  OPENSEAL_KEYD_ALIAS", "  OPENSEAL_KEYD_ALIAS extra"),
                1,
            ),
        ] {
            assert_eq!(
                c.check(&bad),
                Err(IntegrityError::Malformed { line }),
                "{bad}"
            );
        }
    }

    #[test]
    fn comments_blank_lines_and_upper_case_hex_are_accepted() {
        let c = config(b"x");
        let text = format!("# approved 2026-11-13\n\n{}", c.manifest().to_uppercase())
            .replace("SHA256:", "sha256:");
        // The names are upper case already, so only the hex digits changed case.
        assert_eq!(c.check(&text), Ok(()));
    }

    #[test]
    fn errors_name_settings_never_values() {
        let e = IntegrityError::Changed {
            name: "OPENSEAL_TSA_URLS".into(),
        };
        assert_eq!(e.code(), "CS-KEY-0014");
        assert!(e.to_string().contains("OPENSEAL_TSA_URLS"));
        assert!(!e.to_string().contains("sha256:"));
    }

    #[test]
    fn a_file_item_hashes_the_file_and_an_unreadable_one_is_named() {
        let dir = std::env::temp_dir().join(format!("openseal-integrity-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("allow");
        std::fs::write(&path, b"ab12 worker\n").unwrap();
        let item = ConfigItem::file("OPENSEAL_KEYD_ALLOW_LIST", &path).unwrap();
        assert_eq!(
            item,
            ConfigItem::value("OPENSEAL_KEYD_ALLOW_LIST", b"ab12 worker\n")
        );
        // The SHA-256 of "abc" (FIPS 180-2 example), to pin the encoding.
        assert_eq!(
            ConfigItem::value("X", b"abc").digest(),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        std::fs::remove_dir_all(&dir).unwrap();
        assert_eq!(
            ConfigItem::file("OPENSEAL_KEYD_ALLOW_LIST", &path),
            Err(IntegrityError::Unreadable {
                name: "OPENSEAL_KEYD_ALLOW_LIST".into()
            })
        );
    }
}
