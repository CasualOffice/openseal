//! Anchoring (docs/32 §5): a Merkle tree over chain heads, its root, inclusion proofs and
//! their verification, with the tree hashing of RFC 6962 §2.1 (RFC 9162 §2.1).
//!
//! Domain separation: a leaf hashes as `SHA-256(0x00 ‖ data)` and an interior node as
//! `SHA-256(0x01 ‖ left ‖ right)`, so no leaf can pass for a node. The tree over `n`
//! leaves splits at the largest power of two below `n`; built level by level, that is the
//! same as carrying an unpaired last node up unchanged. An empty tree's root is
//! `SHA-256("")`.
//!
//! Only the root is published, so nothing published identifies an envelope; each
//! envelope keeps its own proof.

use crate::error::AuditError;
use crate::hash::Hash256;

/// Longest audit path accepted: a tree of 2^64 leaves.
pub const MAX_PATH: usize = 64;

/// `SHA-256(0x00 ‖ data)`.
#[must_use]
pub fn leaf_hash(data: &[u8]) -> Hash256 {
    Hash256::digest_parts(&[&[0x00], data])
}

/// `SHA-256(0x01 ‖ left ‖ right)`.
#[must_use]
pub fn node_hash(left: &Hash256, right: &Hash256) -> Hash256 {
    Hash256::digest_parts(&[&[0x01], left.as_bytes(), right.as_bytes()])
}

/// A built tree: every level's hashes, leaves first.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleTree {
    levels: Vec<Vec<Hash256>>,
}

/// The proof that a leaf is in a tree of `tree_size` leaves (RFC 9162 §2.1.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InclusionProof {
    /// The leaf's position, from 0.
    pub leaf_index: u64,
    /// Leaves in the tree.
    pub tree_size: u64,
    /// Sibling hashes from the leaf up.
    pub path: Vec<Hash256>,
}

impl MerkleTree {
    /// The tree over `leaves` (each hashed with [`leaf_hash`]), in order.
    #[must_use]
    pub fn new<T: AsRef<[u8]>>(leaves: &[T]) -> Self {
        let first: Vec<Hash256> = leaves.iter().map(|l| leaf_hash(l.as_ref())).collect();
        let mut levels = vec![first];
        while let Some(top) = levels.last() {
            if top.len() <= 1 {
                break;
            }
            let next: Vec<Hash256> = top
                .chunks(2)
                .map(|pair| match pair {
                    [l, r] => node_hash(l, r),
                    [only] => *only,
                    _ => Hash256::default(),
                })
                .collect();
            levels.push(next);
        }
        Self { levels }
    }

    /// The tree over chain heads (docs/32 §5): each head's 32 bytes is a leaf.
    #[must_use]
    pub fn from_chain_heads(heads: &[Hash256]) -> Self {
        let leaves: Vec<&[u8]> = heads.iter().map(|h| h.as_bytes().as_slice()).collect();
        Self::new(&leaves)
    }

    /// Number of leaves.
    #[must_use]
    pub fn len(&self) -> usize {
        self.levels.first().map_or(0, Vec::len)
    }

    /// True for the empty tree.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The root: what is timestamped and published.
    #[must_use]
    pub fn root(&self) -> Hash256 {
        match self.levels.last().and_then(|l| l.first()) {
            Some(r) if !self.is_empty() => *r,
            _ => Hash256::digest(b""),
        }
    }

    /// The proof for leaf `index`.
    ///
    /// # Errors
    ///
    /// `CS-AUD-0009` when there is no such leaf.
    pub fn inclusion_proof(&self, index: usize) -> Result<InclusionProof, AuditError> {
        if index >= self.len() {
            return Err(AuditError::ProofInvalid);
        }
        let mut path = Vec::new();
        let mut i = index;
        for level in &self.levels {
            if level.len() <= 1 {
                break;
            }
            let sibling = if i % 2 == 1 {
                i.checked_sub(1)
            } else {
                i.checked_add(1)
            };
            // An unpaired last node has no sibling at this level: it is carried up.
            if let Some(h) = sibling.and_then(|s| level.get(s)) {
                path.push(*h);
            }
            i /= 2;
        }
        Ok(InclusionProof {
            leaf_index: u64::try_from(index).map_err(|_| AuditError::ProofInvalid)?,
            tree_size: u64::try_from(self.len()).map_err(|_| AuditError::ProofInvalid)?,
            path,
        })
    }
}

/// Check that `leaf_data` is leaf `proof.leaf_index` of the tree of `tree_size` leaves
/// whose root is `root` (RFC 9162 §2.1.3.2). The root and its size are published
/// together and both come from the trusted side: a proof is not evidence of the size,
/// since a proof for a left-hand leaf can hold for several sizes.
///
/// # Errors
///
/// `CS-AUD-0009` when it is not, or the proof is malformed or names another size.
pub fn verify_inclusion(
    root: &Hash256,
    tree_size: u64,
    leaf_data: &[u8],
    proof: &InclusionProof,
) -> Result<(), AuditError> {
    if proof.tree_size != tree_size
        || proof.leaf_index >= proof.tree_size
        || proof.path.len() > MAX_PATH
    {
        return Err(AuditError::ProofInvalid);
    }
    let mut f_n = proof.leaf_index;
    let mut s_n = proof.tree_size.saturating_sub(1);
    let mut r = leaf_hash(leaf_data);
    for p in &proof.path {
        if s_n == 0 {
            return Err(AuditError::ProofInvalid);
        }
        if f_n & 1 == 1 || f_n == s_n {
            r = node_hash(p, &r);
            if f_n & 1 == 0 {
                while f_n & 1 == 0 && f_n != 0 {
                    f_n >>= 1;
                    s_n >>= 1;
                }
            }
        } else {
            r = node_hash(&r, p);
        }
        f_n >>= 1;
        s_n >>= 1;
    }
    if s_n == 0 && r == *root {
        Ok(())
    } else {
        Err(AuditError::ProofInvalid)
    }
}

// Tests may unwrap, index and panic (CLAUDE.md).
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    // Indexes name leaves in the assertions.
    clippy::needless_range_loop
)]
#[cfg(test)]
mod tests {
    use super::*;

    /// The leaves of the Certificate Transparency reference tests (RFC 6962 trees).
    fn ct_leaves() -> Vec<Vec<u8>> {
        vec![
            vec![],
            vec![0x00],
            vec![0x10],
            vec![0x20, 0x21],
            vec![0x30, 0x31],
            vec![0x40, 0x41, 0x42, 0x43],
            vec![0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57],
            (0x60..=0x6f).collect(),
        ]
    }

    /// The roots of the first 1 to 8 of those leaves.
    const CT_ROOTS: [&str; 8] = [
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
        "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
        "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
        "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
        "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
        "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
        "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
        "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
    ];

    /// RFC 6962 §2.1 as written: recursive split at the largest power of two below n.
    fn mth(leaves: &[Vec<u8>]) -> Hash256 {
        match leaves.len() {
            0 => Hash256::digest(b""),
            1 => leaf_hash(&leaves[0]),
            n => {
                let mut k = 1;
                while k * 2 < n {
                    k *= 2;
                }
                node_hash(&mth(&leaves[..k]), &mth(&leaves[k..]))
            }
        }
    }

    #[test]
    fn roots_match_the_certificate_transparency_vectors() {
        let leaves = ct_leaves();
        for (n, want) in CT_ROOTS.iter().enumerate() {
            let tree = MerkleTree::new(&leaves[..=n]);
            assert_eq!(tree.root().hex(), *want, "{} leaves", n + 1);
        }
        assert_eq!(
            MerkleTree::new::<Vec<u8>>(&[]).root().hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn level_build_equals_the_recursive_definition_and_every_proof_verifies() {
        for n in 1..=70usize {
            let leaves: Vec<Vec<u8>> = (0..n).map(|i| format!("head-{i}").into_bytes()).collect();
            let tree = MerkleTree::new(&leaves);
            assert_eq!(tree.root(), mth(&leaves), "{n}");
            for (i, leaf) in leaves.iter().enumerate() {
                let proof = tree.inclusion_proof(i).unwrap();
                verify_inclusion(&tree.root(), tree.len() as u64, leaf, &proof).unwrap();
            }
        }
    }

    #[test]
    fn tampered_proofs_fail() {
        let leaves: Vec<Vec<u8>> = (0..13).map(|i| vec![i]).collect();
        let tree = MerkleTree::new(&leaves);
        let root = tree.root();
        for i in 0..leaves.len() {
            let good = tree.inclusion_proof(i).unwrap();
            // Wrong leaf data.
            assert!(verify_inclusion(&root, 13, b"other", &good).is_err());
            // Each sibling flipped.
            for k in 0..good.path.len() {
                let mut bad = good.clone();
                bad.path[k].0[0] ^= 1;
                assert!(
                    verify_inclusion(&root, 13, &leaves[i], &bad).is_err(),
                    "{i} {k}"
                );
            }
            // A sibling dropped or added.
            let mut bad = good.clone();
            bad.path.pop();
            assert!(verify_inclusion(&root, 13, &leaves[i], &bad).is_err());
            let mut bad = good.clone();
            bad.path.push(root);
            assert!(verify_inclusion(&root, 13, &leaves[i], &bad).is_err());
            // Another index or size.
            for (li, ts) in [(i as u64 ^ 1, 13), (i as u64, 12), (i as u64, 14), (13, 13)] {
                if li == i as u64 && ts == 13 {
                    continue;
                }
                let bad = InclusionProof {
                    leaf_index: li,
                    tree_size: ts,
                    path: good.path.clone(),
                };
                // The trusted size is 13: a proof naming another size, or another
                // index, fails.
                let ok = verify_inclusion(&root, 13, &leaves[i], &bad).is_ok();
                assert!(!ok, "{i}: index {li} size {ts}");
            }
            // Another root.
            let mut other = root;
            other.0[31] ^= 1;
            assert!(verify_inclusion(&other, 13, &leaves[i], &good).is_err());
        }
        assert!(tree.inclusion_proof(13).is_err());
    }

    #[test]
    fn a_leaf_cannot_pass_for_a_node() {
        // Second-preimage: present an interior node's children as a leaf.
        let leaves: Vec<Vec<u8>> = (0..4).map(|i| vec![i]).collect();
        let tree = MerkleTree::new(&leaves);
        let l = leaf_hash(&leaves[0]);
        let r = leaf_hash(&leaves[1]);
        let mut forged = Vec::new();
        forged.extend_from_slice(l.as_bytes());
        forged.extend_from_slice(r.as_bytes());
        let proof = InclusionProof {
            leaf_index: 0,
            tree_size: 2,
            path: vec![node_hash(&leaf_hash(&leaves[2]), &leaf_hash(&leaves[3]))],
        };
        assert!(verify_inclusion(&tree.root(), 2, &forged, &proof).is_err());
    }

    #[test]
    fn chain_heads_are_leaves() {
        let heads: Vec<Hash256> = (0..5u8).map(|i| Hash256::digest(&[i])).collect();
        let tree = MerkleTree::from_chain_heads(&heads);
        let p = tree.inclusion_proof(3).unwrap();
        verify_inclusion(&tree.root(), 5, heads[3].as_bytes(), &p).unwrap();
    }
}
