//! modeld's operation log (docs/33 §3): one line per request, appended, synced, and
//! hash-chained so a removed, reordered or edited line is detected. Copied from keyd's
//! `oplog.rs` (`server/casual-sign-keyd/src/oplog.rs`, stage 2E) with modeld's fields.
//!
//! ```text
//! seq  time  caller  op  account  job  pages  items  millis  outcome  bundle  prev  hash
//! ```
//!
//! Tab-separated ASCII. `caller` is the SHA-256 fingerprint of the client certificate;
//! `pages` the pages asked for; `items` the words, vectors or spans answered; `millis`
//! the time taken; `outcome` `ok` or a `CS-ML-` code; `bundle` the bundle id. **Counts and
//! ids only** (docs/33 invariant 5, `SEC-I05`): never text, labels, boxes, hashes of
//! content or vectors. Every field is either a number or an identifier the wire protocol
//! has already restricted to `[A-Za-z0-9._-]`, so nothing a caller sends can forge a
//! line.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

use aws_lc_rs::digest::{SHA256, digest};

use crate::error::ModeldError;

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const FIELDS: usize = 13;

/// One record before it is chained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpRecord {
    /// Unix seconds.
    pub time: u64,
    /// The caller's certificate fingerprint (hex SHA-256).
    pub caller: String,
    /// The op's name (`info`, `ocr`, ..., or `connect` for a refused caller).
    pub op: &'static str,
    /// The account id, or empty.
    pub account: String,
    /// The job id, or empty.
    pub job: String,
    /// Pages asked for.
    pub pages: u32,
    /// Words, vectors or spans answered.
    pub items: u32,
    /// Milliseconds taken.
    pub millis: u64,
    /// `ok` or the `CS-ML-` code.
    pub outcome: &'static str,
    /// The bundle id.
    pub bundle: String,
}

/// Lowercase hex.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// A field as written: anything outside printable ASCII would break the format, so it is
/// refused upstream; this is the last guard.
fn clean(s: &str) -> String {
    if s.is_empty() {
        return "-".into();
    }
    s.chars()
        .map(|c| if c.is_ascii_graphic() { c } else { '?' })
        .collect()
}

fn line_hash(fields: &[&str]) -> String {
    hex(digest(&SHA256, fields.join("\t").as_bytes()).as_ref())
}

/// The append-only, hash-chained operation log.
#[derive(Debug)]
pub struct OpLog {
    file: File,
    next_seq: u64,
    head: String,
}

impl OpLog {
    /// Open (or create) the log at `path`, verifying every existing line's chain.
    ///
    /// # Errors
    /// `CS-ML-0001` when the file cannot be opened or its chain does not verify.
    pub fn open(path: &Path) -> Result<Self, ModeldError> {
        let (count, head) = if path.exists() {
            verify(path)?
        } else {
            (0, GENESIS.to_owned())
        };
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| ModeldError::OperationLog(format!("open: {}", e.kind())))?;
        Ok(Self {
            file,
            next_seq: count.saturating_add(1),
            head,
        })
    }

    /// Append `record`, chained to the previous line, and sync it to disk.
    ///
    /// # Errors
    /// `CS-ML-0001` when the write or the sync fails.
    pub fn append(&mut self, record: &OpRecord) -> Result<(), ModeldError> {
        let fields = [
            self.next_seq.to_string(),
            record.time.to_string(),
            clean(&record.caller),
            record.op.to_owned(),
            clean(&record.account),
            clean(&record.job),
            record.pages.to_string(),
            record.items.to_string(),
            record.millis.to_string(),
            record.outcome.to_owned(),
            clean(&record.bundle),
            self.head.clone(),
        ];
        let refs: Vec<&str> = fields.iter().map(String::as_str).collect();
        let hash = line_hash(&refs);
        let line = format!("{}\t{hash}\n", refs.join("\t"));
        let io = |e: std::io::Error| ModeldError::OperationLog(format!("write: {}", e.kind()));
        self.file.write_all(line.as_bytes()).map_err(io)?;
        self.file.sync_data().map_err(io)?;
        self.next_seq = self.next_seq.saturating_add(1);
        self.head = hash;
        Ok(())
    }
}

/// Verify the chain of the log at `path`: sequence numbers from 1, each `prev` the
/// previous `hash`, each `hash` recomputed. Returns the number of lines and the head.
///
/// # Errors
/// `CS-ML-0001` naming the first line that fails.
pub fn verify(path: &Path) -> Result<(u64, String), ModeldError> {
    let file =
        File::open(path).map_err(|e| ModeldError::OperationLog(format!("read: {}", e.kind())))?;
    let mut head = GENESIS.to_owned();
    let mut count: u64 = 0;
    for line in BufReader::new(file).lines() {
        let line = line.map_err(|e| ModeldError::OperationLog(format!("read: {}", e.kind())))?;
        let n = count.saturating_add(1);
        let broken = || ModeldError::OperationLog(format!("chain broken at line {n}"));
        let fields: Vec<&str> = line.split('\t').collect();
        let [body @ .., prev, hash] = fields.as_slice() else {
            return Err(broken());
        };
        if fields.len() != FIELDS
            || body.first().copied() != Some(n.to_string().as_str())
            || *prev != head
        {
            return Err(broken());
        }
        let mut chained: Vec<&str> = body.to_vec();
        chained.push(prev);
        if line_hash(&chained) != *hash {
            return Err(broken());
        }
        head = (*hash).to_owned();
        count = n;
    }
    Ok((count, head))
}

#[cfg(test)]
mod tests {
    // Test code: a panic is the failure report.
    #![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]
    use super::*;

    fn record(i: u64) -> OpRecord {
        OpRecord {
            time: 1_800_000_000 + i,
            caller: "ab".repeat(32),
            op: "ocr",
            account: "acc-1".into(),
            job: format!("job-{i}"),
            pages: 3,
            items: 412,
            millis: 1_250,
            outcome: "ok",
            bundle: "cd".repeat(32),
        }
    }

    /// The log is append-only and chained: an edited or removed line stops modeld from
    /// starting (as keyd's).
    #[test]
    fn an_edited_operation_log_is_refused() {
        let dir = std::env::temp_dir().join(format!("modeld-oplog-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("oplog.tsv");
        let mut log = OpLog::open(&path).unwrap();
        for i in 0..3 {
            log.append(&record(i)).unwrap();
        }
        drop(log);
        let mut log = OpLog::open(&path).unwrap();
        log.append(&record(9)).unwrap();
        drop(log);
        assert_eq!(verify(&path).unwrap().0, 4);

        let text = std::fs::read_to_string(&path).unwrap();
        for (what, edited) in [
            ("an edited job", text.replacen("job-1", "job-8", 1)),
            ("an edited count", text.replacen("\t412\t", "\t413\t", 1)),
            (
                "a removed line",
                text.lines()
                    .enumerate()
                    .filter(|(i, _)| *i != 1)
                    .map(|(_, l)| format!("{l}\n"))
                    .collect(),
            ),
        ] {
            std::fs::write(&path, edited).unwrap();
            assert_eq!(
                OpLog::open(&path).unwrap_err().code(),
                "CS-ML-0001",
                "{what}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
