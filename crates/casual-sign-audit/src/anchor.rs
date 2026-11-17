//! Public anchoring of chain heads (docs/32 §5, `FG-158`): what is time-stamped and
//! published for a period's Merkle tree of chain heads, and the proof an envelope keeps
//! that its head is a leaf of it.
//!
//! - The tree is [`crate::merkle::MerkleTree::from_chain_heads`] over the heads, in the
//!   order the host gives (the platform orders by envelope id).
//! - What the time-stamping authority signs is the [`anchor_statement`]:
//!   `SHA-256("openseal.anchor.v1" ‖ 0x00 ‖ tree_size as u64 big-endian ‖ root)`. The
//!   size is inside it because an inclusion proof is checked against a size that must
//!   come from the trusted side ([`crate::merkle::verify_inclusion`]); the token is that
//!   side.
//! - [`Anchor`] is what is published: the period, size, root, statement and the RFC 3161
//!   token. It names no envelope and no account.
//! - [`AnchorProof`] is what an envelope keeps: its id, the sequence number and hash of
//!   the event that was its head, the leaf's index and audit path, and the anchor.
//!
//! The token itself is checked by `casual-sign-verify` (its signature, imprint and the
//! TSA's chain); this module checks shapes, the statement and inclusion, and that a
//! proof's head is an event of a given trail. No I/O, no clock, no randomness.

use casual_sign_model::Id;

use crate::error::{AuditError, ShapeFault};
use crate::hash::Hash256;
use crate::jcs;
use crate::json::{self, Value};
use crate::merkle::{InclusionProof, MAX_PATH, verify_inclusion};
use crate::time::Timestamp;
use crate::verify::{VerifyOptions, verify_trail};

/// `format` of a published anchor.
pub const ANCHOR_FORMAT: &str = "openseal.anchor";
/// `format` of an envelope's anchor proof file.
pub const ANCHOR_PROOF_FORMAT: &str = "openseal.anchor-proof";
/// The version of both formats this build writes and reads.
pub const ANCHOR_VERSION: u64 = 1;
/// The domain separator of the statement.
pub const STATEMENT_DOMAIN: &[u8] = b"openseal.anchor.v1";
/// Most leaves in one anchor's tree (docs/21).
pub const MAX_ANCHOR_LEAVES: u64 = 1_000_000;
/// Longest RFC 3161 token accepted, in bytes (docs/21; real tokens are 2 to 8 KiB).
pub const MAX_TOKEN_BYTES: usize = 64 * 1024;
/// Longest anchor or proof file read, in bytes (docs/21).
pub const MAX_PROOF_BYTES: usize = 256 * 1024;

/// The digest the time-stamping authority signs for a tree of `tree_size` leaves whose
/// root is `root`.
#[must_use]
pub fn anchor_statement(root: &Hash256, tree_size: u64) -> Hash256 {
    Hash256::digest_parts(&[
        STATEMENT_DOMAIN,
        &[0x00],
        &tree_size.to_be_bytes(),
        root.as_bytes(),
    ])
}

/// One period's anchor, as published.
#[derive(Clone, PartialEq, Eq)]
pub struct Anchor {
    /// The anchor's id.
    pub id: Id,
    /// The UTC day whose changed heads it covers, `YYYY-MM-DD`.
    pub period: String,
    /// Leaves in the tree.
    pub tree_size: u64,
    /// The tree's root.
    pub root: Hash256,
    /// The time-stamping authority's `genTime`, as the host read it (informative: a
    /// verifier takes the time from the token).
    pub tsa_time: Timestamp,
    /// The RFC 3161 `TimeStampToken` (DER) over [`anchor_statement`].
    pub timestamp_token: Vec<u8>,
}

impl core::fmt::Debug for Anchor {
    /// Ids, sizes and hashes; the token by its length.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Anchor")
            .field("id", &self.id.as_str())
            .field("period", &self.period)
            .field("tree_size", &self.tree_size)
            .field("root", &self.root.hex())
            .field("token_len", &self.timestamp_token.len())
            .finish()
    }
}

/// An envelope's proof that its chain head is a leaf of an anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnchorProof {
    /// The envelope.
    pub envelope_id: Id,
    /// The sequence number of the event that was the head.
    pub seq: u64,
    /// That event's hash: the leaf.
    pub head: Hash256,
    /// The leaf's index and audit path.
    pub proof: InclusionProof,
    /// The anchor.
    pub anchor: Anchor,
}

fn bad(member: &'static str) -> AuditError {
    AuditError::shape(ShapeFault::Member(member))
}

fn num(n: u64) -> Value {
    // Every number written is at most 2^53 − 1 (checked where it is read), so exact.
    #[allow(clippy::cast_precision_loss)]
    // Bounded: sizes, indexes and sequence numbers below 2^53.
    Value::Number(n as f64)
}

fn str_member<'a>(v: &'a Value, name: &'static str) -> Result<&'a str, AuditError> {
    v.get(name).and_then(Value::as_str).ok_or_else(|| bad(name))
}

fn u64_member(v: &Value, name: &'static str) -> Result<u64, AuditError> {
    v.get(name)
        .and_then(Value::as_safe_u64)
        .ok_or_else(|| bad(name))
}

fn hash_member(v: &Value, name: &'static str) -> Result<Hash256, AuditError> {
    Hash256::parse(str_member(v, name)?)
}

fn hex_encode(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        for nibble in [b >> 4, b & 0x0f] {
            if let Some(&d) = DIGITS.get(usize::from(nibble)) {
                s.push(char::from(d));
            }
        }
    }
    s
}

fn hex_decode(text: &str) -> Option<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return None;
    }
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(c.wrapping_sub(b'a').wrapping_add(10)),
        _ => None,
    };
    text.as_bytes()
        .chunks(2)
        .map(|p| match p {
            [h, l] => Some(digit(*h)?.wrapping_shl(4) | digit(*l)?),
            _ => None,
        })
        .collect()
}

/// `YYYY-MM-DD` with digits in place, month 01–12 and day 01–31.
fn period_ok(p: &str) -> bool {
    let b = p.as_bytes();
    let digits =
        |r: core::ops::Range<usize>| b.get(r).is_some_and(|s| s.iter().all(u8::is_ascii_digit));
    let two = |i: usize| -> Option<u8> {
        let s = p.get(i..i.saturating_add(2))?;
        s.parse().ok()
    };
    b.len() == 10
        && digits(0..4)
        && b.get(4) == Some(&b'-')
        && digits(5..7)
        && b.get(7) == Some(&b'-')
        && digits(8..10)
        && two(5).is_some_and(|m| (1..=12).contains(&m))
        && two(8).is_some_and(|d| (1..=31).contains(&d))
}

impl Anchor {
    /// The statement this anchor's token must be over.
    #[must_use]
    pub fn statement(&self) -> Hash256 {
        anchor_statement(&self.root, self.tree_size)
    }

    /// The anchor as a JSON tree (`format`, `v`, `id`, `period`, `tree_size`, `root`,
    /// `statement`, `tsa_time`, `timestamp_token` as lower-case hex).
    #[must_use]
    pub fn to_value(&self) -> Value {
        Value::Object(vec![
            ("format".into(), Value::String(ANCHOR_FORMAT.into())),
            ("v".into(), num(ANCHOR_VERSION)),
            ("id".into(), Value::String(self.id.as_str().into())),
            ("period".into(), Value::String(self.period.clone())),
            ("tree_size".into(), num(self.tree_size)),
            ("root".into(), Value::String(self.root.to_string())),
            (
                "statement".into(),
                Value::String(self.statement().to_string()),
            ),
            ("tsa_time".into(), Value::String(self.tsa_time.to_string())),
            (
                "timestamp_token".into(),
                Value::String(hex_encode(&self.timestamp_token)),
            ),
        ])
    }

    /// The published line: canonical JSON (RFC 8785) of [`Anchor::to_value`].
    ///
    /// # Errors
    ///
    /// `CS-AUD-0003` when the anchor is out of shape (as [`Anchor::from_value`] reads it).
    pub fn to_json(&self) -> Result<Vec<u8>, AuditError> {
        self.check()?;
        jcs::to_vec(&self.to_value())
    }

    fn check(&self) -> Result<(), AuditError> {
        if !period_ok(&self.period) {
            return Err(bad("period"));
        }
        if self.tree_size == 0 || self.tree_size > MAX_ANCHOR_LEAVES {
            return Err(bad("tree_size"));
        }
        if self.timestamp_token.is_empty() || self.timestamp_token.len() > MAX_TOKEN_BYTES {
            return Err(bad("timestamp_token"));
        }
        Ok(())
    }

    /// Read an anchor from its JSON tree.
    ///
    /// # Errors
    ///
    /// `CS-AUD-0003` naming the member that is absent or out of shape, or
    /// [`ShapeFault::Format`] / [`ShapeFault::Version`]; `CS-AUD-0009` when `statement`
    /// is not the statement of `root` and `tree_size`.
    pub fn from_value(v: &Value) -> Result<Self, AuditError> {
        if str_member(v, "format")? != ANCHOR_FORMAT {
            return Err(AuditError::shape(ShapeFault::Format));
        }
        if u64_member(v, "v")? != ANCHOR_VERSION {
            return Err(AuditError::shape(ShapeFault::Version));
        }
        let id = Id::new(str_member(v, "id")?).map_err(|_| AuditError::shape(ShapeFault::Id))?;
        let token_hex = str_member(v, "timestamp_token")?;
        if token_hex.len() > MAX_TOKEN_BYTES.saturating_mul(2) {
            return Err(bad("timestamp_token"));
        }
        let anchor = Self {
            id,
            period: str_member(v, "period")?.to_owned(),
            tree_size: u64_member(v, "tree_size")?,
            root: hash_member(v, "root")?,
            tsa_time: Timestamp::parse(str_member(v, "tsa_time")?)?,
            timestamp_token: hex_decode(token_hex).ok_or_else(|| bad("timestamp_token"))?,
        };
        anchor.check()?;
        if hash_member(v, "statement")? != anchor.statement() {
            return Err(AuditError::ProofInvalid);
        }
        Ok(anchor)
    }

    /// Read a published anchor line.
    ///
    /// # Errors
    ///
    /// `CS-AUD-0002` over [`MAX_PROOF_BYTES`], `CS-AUD-0001` for malformed JSON, else as
    /// [`Anchor::from_value`].
    pub fn from_json(bytes: &[u8]) -> Result<Self, AuditError> {
        Self::from_value(&parse_bounded(bytes)?)
    }
}

fn parse_bounded(bytes: &[u8]) -> Result<Value, AuditError> {
    if bytes.len() > MAX_PROOF_BYTES {
        return Err(AuditError::Limit {
            limit: "anchor proof bytes",
            max: MAX_PROOF_BYTES as u64,
        });
    }
    json::parse(bytes, 8)
}

impl AnchorProof {
    /// The proof file: canonical JSON (RFC 8785) of `{format, v, envelope_id, seq, head,
    /// leaf_index, path, anchor}`.
    ///
    /// # Errors
    ///
    /// `CS-AUD-0003` when the anchor is out of shape; `CS-AUD-0009` when the path is
    /// longer than [`MAX_PATH`] or the proof names another size than the anchor.
    pub fn to_json(&self) -> Result<Vec<u8>, AuditError> {
        self.anchor.check()?;
        if self.proof.path.len() > MAX_PATH || self.proof.tree_size != self.anchor.tree_size {
            return Err(AuditError::ProofInvalid);
        }
        let v = Value::Object(vec![
            ("format".into(), Value::String(ANCHOR_PROOF_FORMAT.into())),
            ("v".into(), num(ANCHOR_VERSION)),
            (
                "envelope_id".into(),
                Value::String(self.envelope_id.as_str().into()),
            ),
            ("seq".into(), num(self.seq)),
            ("head".into(), Value::String(self.head.to_string())),
            ("leaf_index".into(), num(self.proof.leaf_index)),
            (
                "path".into(),
                Value::Array(
                    self.proof
                        .path
                        .iter()
                        .map(|h| Value::String(h.to_string()))
                        .collect(),
                ),
            ),
            ("anchor".into(), self.anchor.to_value()),
        ]);
        jcs::to_vec(&v)
    }

    /// Read a proof file. Shapes only: [`AnchorProof::check_inclusion`] checks the proof.
    ///
    /// # Errors
    ///
    /// `CS-AUD-0002` over [`MAX_PROOF_BYTES`], `CS-AUD-0001` for malformed JSON,
    /// `CS-AUD-0003` naming a member out of shape, `CS-AUD-0009` for a path longer than
    /// [`MAX_PATH`] or a statement that does not match.
    pub fn from_json(bytes: &[u8]) -> Result<Self, AuditError> {
        let v = parse_bounded(bytes)?;
        if str_member(&v, "format")? != ANCHOR_PROOF_FORMAT {
            return Err(AuditError::shape(ShapeFault::Format));
        }
        if u64_member(&v, "v")? != ANCHOR_VERSION {
            return Err(AuditError::shape(ShapeFault::Version));
        }
        let anchor = Anchor::from_value(v.get("anchor").ok_or_else(|| bad("anchor"))?)?;
        let items = v
            .get("path")
            .and_then(Value::as_array)
            .ok_or_else(|| bad("path"))?;
        if items.len() > MAX_PATH {
            return Err(AuditError::ProofInvalid);
        }
        let path = items
            .iter()
            .map(|h| Hash256::parse(h.as_str().ok_or_else(|| bad("path"))?))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            envelope_id: Id::new(str_member(&v, "envelope_id")?)
                .map_err(|_| AuditError::shape(ShapeFault::Id))?,
            seq: u64_member(&v, "seq")?,
            head: hash_member(&v, "head")?,
            proof: InclusionProof {
                leaf_index: u64_member(&v, "leaf_index")?,
                tree_size: anchor.tree_size,
                path,
            },
            anchor,
        })
    }

    /// Check that [`AnchorProof::head`] is leaf `leaf_index` of the anchor's tree: the
    /// path leads to the anchor's root at the anchor's size. The size and root are only
    /// as trustworthy as the token over [`Anchor::statement`], which the caller checks.
    ///
    /// # Errors
    ///
    /// `CS-AUD-0009` when it does not.
    pub fn check_inclusion(&self) -> Result<(), AuditError> {
        verify_inclusion(
            &self.anchor.root,
            self.anchor.tree_size,
            self.head.as_bytes(),
            &self.proof,
        )
    }

    /// Check that `trail` (an `audit-trail.json`) verifies, is this proof's envelope's,
    /// and that its event `seq` has hash [`AnchorProof::head`]: the chain up to that
    /// event is the one anchored.
    ///
    /// # Errors
    ///
    /// `CS-AUD-0008` when the trail does not verify; `CS-AUD-0012` when it is another
    /// envelope's, is shorter than `seq`, or its event `seq` has another hash.
    pub fn check_trail(&self, trail: &[u8], options: &VerifyOptions) -> Result<(), AuditError> {
        let report = verify_trail(trail, options);
        if !report.is_valid() {
            return Err(AuditError::ChainInvalid {
                problems: report.problems.len(),
            });
        }
        if report.envelope_id.as_ref() != Some(&self.envelope_id) {
            return Err(AuditError::AnchorMismatch);
        }
        let tree = json::parse(trail, options.limits.max_depth)?;
        let event = tree
            .get("events")
            .and_then(Value::as_array)
            .and_then(|e| e.get(usize::try_from(self.seq).ok()?))
            .ok_or(AuditError::AnchorMismatch)?;
        let hash = hash_member(event, "hash")?;
        if hash == self.head {
            Ok(())
        } else {
            Err(AuditError::AnchorMismatch)
        }
    }
}

// Tests may unwrap, index and panic (CLAUDE.md).
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::merkle::MerkleTree;

    fn anchor_over(heads: &[Hash256]) -> (MerkleTree, Anchor) {
        let tree = MerkleTree::from_chain_heads(heads);
        let anchor = Anchor {
            id: Id::new("0193a1b2-0000-7000-8000-000000000001").unwrap(),
            period: "2026-11-16".into(),
            tree_size: tree.len() as u64,
            root: tree.root(),
            tsa_time: Timestamp::from_unix_millis(1_763_337_600_000).unwrap(),
            timestamp_token: vec![0x30, 0x03, 0x02, 0x01, 0x01],
        };
        (tree, anchor)
    }

    fn proof_for(tree: &MerkleTree, anchor: &Anchor, heads: &[Hash256], i: usize) -> AnchorProof {
        AnchorProof {
            envelope_id: Id::new(format!("env-{i}")).unwrap(),
            seq: 4,
            head: heads[i],
            proof: tree.inclusion_proof(i).unwrap(),
            anchor: anchor.clone(),
        }
    }

    fn heads(n: u8) -> Vec<Hash256> {
        (0..n).map(|i| Hash256::digest(&[i, 0xa5])).collect()
    }

    #[test]
    fn anchoring_a_set_of_heads_proves_each_one_through_its_file() {
        let hs = heads(11);
        let (tree, anchor) = anchor_over(&hs);
        for i in 0..hs.len() {
            let p = proof_for(&tree, &anchor, &hs, i);
            let bytes = p.to_json().unwrap();
            let back = AnchorProof::from_json(&bytes).unwrap();
            assert_eq!(back, p);
            back.check_inclusion().unwrap();
            // Canonical: the same proof writes the same bytes.
            assert_eq!(back.to_json().unwrap(), bytes);
        }
        let line = anchor.to_json().unwrap();
        assert_eq!(Anchor::from_json(&line).unwrap(), anchor);
        // Published: no envelope id appears in the anchor.
        let text = String::from_utf8(line).unwrap();
        assert!(!text.contains("env-"), "{text}");
    }

    #[test]
    fn a_tampered_head_fails_the_proof() {
        let hs = heads(7);
        let (tree, anchor) = anchor_over(&hs);
        let mut p = proof_for(&tree, &anchor, &hs, 3);
        p.head.0[0] ^= 1;
        assert_eq!(p.check_inclusion(), Err(AuditError::ProofInvalid));
        // Another anchored head presented as this one's leaf fails too.
        let mut q = proof_for(&tree, &anchor, &hs, 3);
        q.head = hs[4];
        assert_eq!(q.check_inclusion().unwrap_err().code(), "CS-AUD-0009");
    }

    #[test]
    fn a_rewritten_root_or_size_fails_against_the_statement() {
        let hs = heads(5);
        let (tree, anchor) = anchor_over(&hs);
        let p = proof_for(&tree, &anchor, &hs, 2);
        let text = String::from_utf8(p.to_json().unwrap()).unwrap();
        // The root changed without the statement: refused.
        let other = Hash256::digest(b"other");
        let forged = text.replace(&anchor.root.to_string(), &other.to_string());
        assert_eq!(
            AnchorProof::from_json(forged.as_bytes()).unwrap_err(),
            AuditError::ProofInvalid
        );
        // The statement is the size too.
        assert_ne!(
            anchor_statement(&anchor.root, 5),
            anchor_statement(&anchor.root, 6)
        );
    }

    #[test]
    fn out_of_shape_files_are_refused_with_codes() {
        let hs = heads(3);
        let (tree, anchor) = anchor_over(&hs);
        let text = String::from_utf8(proof_for(&tree, &anchor, &hs, 0).to_json().unwrap()).unwrap();
        for (from, to) in [
            ("openseal.anchor-proof", "openseal.other"),
            ("\"period\":\"2026-11-16\"", "\"period\":\"2026-13-16\""),
            ("\"tree_size\":3", "\"tree_size\":0"),
            (
                "\"timestamp_token\":\"3003020101\"",
                "\"timestamp_token\":\"30030\"",
            ),
        ] {
            let bad = text.replace(from, to);
            assert_ne!(bad, text, "{from}");
            let e = AnchorProof::from_json(bad.as_bytes()).unwrap_err();
            assert!(
                e.code() == "CS-AUD-0003" || e.code() == "CS-AUD-0009",
                "{e}"
            );
        }
        assert_eq!(
            AnchorProof::from_json(&vec![b' '; MAX_PROOF_BYTES + 1])
                .unwrap_err()
                .code(),
            "CS-AUD-0002"
        );
        assert_eq!(
            AnchorProof::from_json(b"{").unwrap_err().code(),
            "CS-AUD-0001"
        );
    }

    #[test]
    fn hex_round_trips() {
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(hex_decode(&hex_encode(&all)).unwrap(), all);
        assert!(hex_decode("0g").is_none());
        assert!(hex_decode("ABCD").is_none());
    }
}
