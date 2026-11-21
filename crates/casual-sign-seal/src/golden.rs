//! `RSP-01` gate 1: `seal()` writes exactly the bytes it wrote before the
//! `prepare`/`complete` split (ADR-046 §3.3). The reference is a frozen copy of the
//! pre-split code (`legacy.rs`). ECDSA signatures, TSA tokens and OCSP answers are
//! randomized, so every source is wrapped to answer a repeated request with the bytes it
//! gave the first time: both paths then see identical answers, and any difference in the
//! output is the code's.
// Test code: a panic is the failure report.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::cell::RefCell;
use std::collections::BTreeMap;

use casual_sign_crypto::{Certificate, KeyError, KeyProvider, Signature, SignatureAlgorithm};

use crate::common::*;
use crate::{
    Appearance, CrlQuery, DocMdp, NoRevocation, NoTimestamps, OcspQuery, Profile, Rect,
    RevocationSource, SealKind, SealRequest, SourceError, TimestampSource, Visible,
};

/// Answers each distinct input once from `inner`, then from memory.
struct ReplayKey<K> {
    inner: K,
    seen: RefCell<BTreeMap<Vec<u8>, Vec<u8>>>,
}

impl<K: KeyProvider> KeyProvider for ReplayKey<K> {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.inner.algorithm()
    }
    fn certificate_chain(&self) -> &[Certificate] {
        self.inner.certificate_chain()
    }
    fn sign(&self, der: &[u8]) -> Result<Signature, KeyError> {
        if let Some(s) = self.seen.borrow().get(der) {
            return Ok(Signature::new(s.clone()));
        }
        let s = self.inner.sign(der)?;
        self.seen
            .borrow_mut()
            .insert(der.to_vec(), s.as_bytes().to_vec());
        Ok(s)
    }
}

/// A TSA whose nonces restart for each run and whose tokens replay by request.
struct ReplayTsa<'a> {
    inner: &'a TestTsa,
    nonce: RefCell<u64>,
    seen: &'a RefCell<BTreeMap<Vec<u8>, Vec<u8>>>,
}

impl TimestampSource for ReplayTsa<'_> {
    fn token_len_bound(&self) -> usize {
        self.inner.token_len_bound()
    }
    fn nonce(&self) -> Vec<u8> {
        let mut n = self.nonce.borrow_mut();
        *n = n.wrapping_add(1);
        let mut v = n.to_be_bytes().to_vec();
        v[0] |= 0x40;
        v
    }
    fn timestamp(&self, request_der: &[u8]) -> Result<Vec<u8>, SourceError> {
        if let Some(r) = self.seen.borrow().get(request_der) {
            return Ok(r.clone());
        }
        let r = self.inner.timestamp(request_der)?;
        self.seen
            .borrow_mut()
            .insert(request_der.to_vec(), r.clone());
        Ok(r)
    }
}

struct ReplayRevocation<'a> {
    inner: &'a TestRevocation,
    seen: &'a RefCell<BTreeMap<Vec<u8>, Option<Vec<u8>>>>,
}

impl RevocationSource for ReplayRevocation<'_> {
    fn certificates(&self) -> &[Certificate] {
        self.inner.certificates()
    }
    fn ocsp(&self, query: &OcspQuery<'_>) -> Result<Option<Vec<u8>>, SourceError> {
        if let Some(r) = self.seen.borrow().get(query.request_der) {
            return Ok(r.clone());
        }
        let r = self.inner.ocsp(query)?;
        self.seen
            .borrow_mut()
            .insert(query.request_der.to_vec(), r.clone());
        Ok(r)
    }
    fn crl(&self, query: &CrlQuery<'_>) -> Result<Option<Vec<u8>>, SourceError> {
        self.inner.crl(query)
    }
}

fn requests() -> Vec<(&'static str, SealRequest)> {
    let base = |profile: Profile| {
        let mut r = SealRequest::new(profile, "Seal1", SIGNING_TIME);
        r.name = Some("OpenSeal test platform".into());
        r.reason = Some("Agreement completed".into());
        r.trust = trust();
        r
    };
    let mut certified = base(Profile::BaselineLt);
    certified.kind = SealKind::Certification { docmdp: DocMdp::P2 };
    let mut visible = base(Profile::BaselineT);
    visible.visible = Some(Visible {
        page: 0,
        rect: Rect {
            llx: 72.0,
            lly: 72.0,
            urx: 272.0,
            ury: 132.0,
        },
        appearance: Appearance::Border,
    });
    vec![
        ("B-B", base(Profile::BaselineB)),
        ("B-T", base(Profile::BaselineT)),
        ("B-LT", base(Profile::BaselineLt)),
        ("B-LTA", base(Profile::BaselineLta)),
        ("certified P2 B-LT", certified),
        ("visible B-T", visible),
    ]
}

fn inputs() -> Vec<(&'static str, Vec<u8>)> {
    vec![
        ("one page", one_page("Agreement")),
        ("existing form", form_pdf()),
    ]
}

#[test]
fn seal_is_byte_identical_to_the_pre_split_code() {
    let mut compared = 0usize;
    for key_name in ["p256", "rsa3072"] {
        let key = ReplayKey {
            inner: if key_name == "p256" { p256() } else { rsa() },
            seen: RefCell::new(BTreeMap::new()),
        };
        for (input_name, input) in inputs() {
            for (req_name, request) in requests() {
                let tsa = TestTsa::new(SIGNING_TIME);
                let tokens = RefCell::new(BTreeMap::new());
                let answers = RefCell::new(BTreeMap::new());
                let revocation = TestRevocation::default();
                let run = |reference: bool| {
                    let ts = ReplayTsa {
                        inner: &tsa,
                        nonce: RefCell::new(0x0102_0304),
                        seen: &tokens,
                    };
                    let rv = ReplayRevocation {
                        inner: &revocation,
                        seen: &answers,
                    };
                    let (ts, rv): (&dyn TimestampSource, &dyn RevocationSource) =
                        if request.profile == Profile::BaselineB {
                            (&NoTimestamps, &NoRevocation)
                        } else {
                            (&ts, &rv)
                        };
                    if reference {
                        crate::legacy::seal_reference(&input, &request, &key, ts, rv)
                    } else {
                        crate::seal(&input, &request, &key, ts, rv)
                    }
                };
                let before = run(true).unwrap_or_else(|e| {
                    panic!("reference {key_name} {input_name} {req_name}: {e}")
                });
                let after = run(false)
                    .unwrap_or_else(|e| panic!("seal {key_name} {input_name} {req_name}: {e}"));
                assert!(
                    before.bytes == after.bytes,
                    "{key_name} {input_name} {req_name}: seal() output changed ({} bytes before, {} after)",
                    before.bytes.len(),
                    after.bytes.len()
                );
                assert_eq!(
                    before.report.signature, after.report.signature,
                    "{key_name} {input_name} {req_name}: layout changed"
                );
                compared += 1;
            }
        }
    }
    assert_eq!(compared, 24);
}
