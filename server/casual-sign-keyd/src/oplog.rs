//! keyd's own operation log (docs/31 §5, `SEC-S05`): one line per request, appended,
//! synced to disk before a signature is released, and hash-chained so a removed,
//! reordered or edited line is detected.
//!
//! ```text
//! seq  time  caller  op  alias  alg  digest  envelope  outcome  prev  hash
//! ```
//!
//! Tab-separated ASCII. `time` is Unix seconds; `caller` the SHA-256 fingerprint of the
//! client certificate; `digest` the hex digest that was signed (a hash of the CMS signed
//! attributes, never document content); `outcome` is `ok` or a `CS-KEY-` code; `prev` the
//! previous line's `hash` (64 zeros for the first); `hash` the SHA-256 of the line's other
//! fields joined by tabs. There is no update or delete: the file is opened for append
//! only, and [`OpLog::open`] refuses a file whose chain does not verify.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use aws_lc_rs::digest::{SHA256, digest};

use crate::error::KeydError;
use crate::wire::LogEntry;

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";
const FIELDS: usize = 11;

/// One record before it is chained.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpRecord {
    /// Unix seconds.
    pub time: u64,
    /// The caller's certificate fingerprint (hex SHA-256), or `-`.
    pub caller: String,
    /// `chain` or `sign` (or `connect` for a refused caller), or an admin operation:
    /// `list-keys`, `oplog-head`, `oplog-range`, `health` (`CON-06`).
    pub op: &'static str,
    /// The key alias, or `-`.
    pub alias: String,
    /// The algorithm's wire id, or `-`.
    pub alg: String,
    /// The hex digest signed, or `-`.
    pub digest: String,
    /// The envelope id, or `-`.
    pub envelope: String,
    /// `ok` or the `CS-KEY-` code.
    pub outcome: &'static str,
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

/// A field as written: tabs, newlines and anything outside printable ASCII would break
/// the format, so they are refused upstream; this is the last guard.
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
    path: PathBuf,
    file: File,
    next_seq: u64,
    head: String,
}

impl OpLog {
    /// Open (or create) the log at `path`, verifying every existing line's chain.
    ///
    /// # Errors
    /// `CS-KEY-0009` when the file cannot be opened or its chain does not verify.
    pub fn open(path: &Path) -> Result<Self, KeydError> {
        let (count, head) = if path.exists() {
            verify(path)?
        } else {
            (0, GENESIS.to_owned())
        };
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| KeydError::OperationLog(format!("open: {}", e.kind())))?;
        Ok(Self {
            path: path.to_path_buf(),
            file,
            next_seq: count.saturating_add(1),
            head,
        })
    }

    /// Append `record`, chained to the previous line, and sync it to disk.
    ///
    /// # Errors
    /// `CS-KEY-0009` when the write or the sync fails; the caller then releases nothing.
    pub fn append(&mut self, record: &OpRecord) -> Result<(), KeydError> {
        let seq = self.next_seq.to_string();
        let time = record.time.to_string();
        let fields = [
            seq,
            time,
            clean(&record.caller),
            record.op.to_owned(),
            clean(&record.alias),
            clean(&record.alg),
            clean(&record.digest),
            clean(&record.envelope),
            record.outcome.to_owned(),
            self.head.clone(),
        ];
        let refs: Vec<&str> = fields.iter().map(String::as_str).collect();
        let hash = line_hash(&refs);
        let line = format!("{}\t{hash}\n", refs.join("\t"));
        let io = |e: std::io::Error| KeydError::OperationLog(format!("write: {}", e.kind()));
        self.file.write_all(line.as_bytes()).map_err(io)?;
        self.file.sync_data().map_err(io)?;
        self.next_seq = self.next_seq.saturating_add(1);
        self.head = hash;
        Ok(())
    }
}

impl OpLog {
    /// The last sequence number written (0 for an empty log) and its hash (hex; 64 zeros
    /// for an empty log).
    #[must_use]
    pub fn head(&self) -> (u64, &str) {
        (self.next_seq.saturating_sub(1), &self.head)
    }

    /// Up to `n` records from sequence `from`, read back from the file (the lines this
    /// log verified at open and has written since). Hashes, ids and codes only.
    ///
    /// # Errors
    /// `CS-KEY-0009` when the file cannot be read or a line does not have its fields.
    pub fn range(&self, from: u64, n: usize) -> Result<Vec<LogEntry>, KeydError> {
        let file = File::open(&self.path)
            .map_err(|e| KeydError::OperationLog(format!("read: {}", e.kind())))?;
        let mut out = Vec::new();
        for line in BufReader::new(file).lines() {
            if out.len() >= n {
                break;
            }
            let line = line.map_err(|e| KeydError::OperationLog(format!("read: {}", e.kind())))?;
            let f: Vec<&str> = line.split('\t').collect();
            let [
                seq,
                time,
                caller,
                op,
                alias,
                alg,
                digest,
                envelope,
                outcome,
                _prev,
                _hash,
            ] = f.as_slice()
            else {
                return Err(KeydError::OperationLog("a line without its fields".into()));
            };
            let bad = || KeydError::OperationLog("a line with a bad number".into());
            let seq: u64 = seq.parse().map_err(|_| bad())?;
            if seq < from {
                continue;
            }
            out.push(LogEntry {
                seq,
                time: time.parse().map_err(|_| bad())?,
                caller: (*caller).to_owned(),
                op: (*op).to_owned(),
                alias: (*alias).to_owned(),
                alg: (*alg).to_owned(),
                digest: (*digest).to_owned(),
                envelope: (*envelope).to_owned(),
                outcome: (*outcome).to_owned(),
            });
        }
        Ok(out)
    }
}

/// Verify the chain of the log at `path`: sequence numbers from 1, each `prev` the
/// previous `hash`, each `hash` recomputed. Returns the number of lines and the head.
///
/// # Errors
/// `CS-KEY-0009` naming the first line that fails.
pub fn verify(path: &Path) -> Result<(u64, String), KeydError> {
    let file =
        File::open(path).map_err(|e| KeydError::OperationLog(format!("read: {}", e.kind())))?;
    let mut head = GENESIS.to_owned();
    let mut count: u64 = 0;
    for line in BufReader::new(file).lines() {
        let line = line.map_err(|e| KeydError::OperationLog(format!("read: {}", e.kind())))?;
        let n = count.saturating_add(1);
        let broken = || KeydError::OperationLog(format!("chain broken at line {n}"));
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
