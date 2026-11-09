//! No panic on malformed DER (T-1F acceptance 4): 10,000 deterministic mutations of the
//! interop fixtures through every parser and verifier. A panic fails the test. The
//! libFuzzer target proposed for `fuzz/` is in the T-1F report.

// Tests may unwrap, index and panic (CLAUDE.md); the product lints target src/.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use core::time::Duration;

use casual_sign_crypto::cms::ParsedCms;
use casual_sign_crypto::revocation;
use casual_sign_crypto::tsp::{self, TimestampRequest};
use casual_sign_crypto::{DigestAlgorithm, SerialNumber};
use common::{cert, fixture};

/// xorshift64*: deterministic, so a failure reproduces from its iteration number.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

fn mutate(rng: &mut Rng, input: &[u8]) -> Vec<u8> {
    let mut d = input.to_vec();
    let rounds = 1 + rng.below(4);
    for _ in 0..rounds {
        let len = d.len();
        match rng.below(8) {
            0 => {
                let i = rng.below(len);
                d[i] ^= 1 << rng.below(8);
            }
            1 => {
                let i = rng.below(len);
                d[i] = rng.next() as u8;
            }
            2 => d.truncate(rng.below(len)),
            3 => {
                let i = rng.below(len + 1);
                d.insert(i, rng.next() as u8);
            }
            4 => {
                // Length octets are where DER parsers break: make one long or huge.
                let i = rng.below(len);
                d[i] = [0x80, 0x81, 0x82, 0x84, 0x88, 0xFF][rng.below(6)];
            }
            5 => {
                let i = rng.below(len);
                d[i] = [0x30, 0x31, 0xA0, 0xA1, 0x04, 0x02, 0x00][rng.below(7)];
            }
            6 => {
                let a = rng.below(len);
                let b = (a + rng.below(64)).min(len);
                let chunk = d[a..b].to_vec();
                let at = rng.below(d.len() + 1);
                d.splice(at..at, chunk);
            }
            _ => {
                let a = rng.below(len);
                let b = (a + rng.below(32)).min(len);
                d.drain(a..b);
            }
        }
        if d.is_empty() {
            d.push(0x30);
        }
    }
    d
}

#[test]
fn ten_thousand_mutations_never_panic() {
    let message = fixture("message.bin");
    let imprint = DigestAlgorithm::Sha256.digest(&message);
    let request =
        TimestampRequest::new(&imprint, &[0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]).unwrap();
    let root = cert("root.der");
    let serials = [
        SerialNumber::new(&[0x10, 0x01]).unwrap(),
        SerialNumber::new(&[0x10, 0x02]).unwrap(),
    ];
    let june = Duration::from_secs(1_780_272_000);

    let cms_inputs = [
        "cms-p256-sha256.der",
        "cms-p256-unsorted.der",
        "cms-p384-sha384.der",
        "cms-rsa-pkcs1-sha256.der",
        "cms-rsa-pss-sha256.der",
    ];
    let corpus: Vec<(&str, Vec<u8>)> = cms_inputs
        .iter()
        .chain(&[
            "tsr-granted.der",
            "tsr-pyhanko-dummy.der",
            "ocsp-revoked-by-ca.der",
            "ocsp-good-delegated.der",
            "crl.der",
        ])
        .map(|n| (*n, fixture(n)))
        .collect();

    let mut rng = Rng(0x7F1F_0000_C0FF_EE01);
    let mut ok = 0usize;
    const N: usize = 10_000;
    for i in 0..N {
        let (name, input) = &corpus[i % corpus.len()];
        let m = mutate(&mut rng, input);
        let accepted = if name.starts_with("cms") {
            ParsedCms::parse(&m)
                .and_then(|p| {
                    let _ = p.timestamp_token();
                    let _ = p.certificates().count();
                    p.verify_detached(&p.digest_algorithm().digest(&message))
                })
                .is_ok()
        } else if name.starts_with("tsr") {
            let a = tsp::verify_timestamp_response(&m, &request).is_ok();
            let _ = tsp::verify_timestamp_token(&m, &imprint);
            a
        } else if name.starts_with("ocsp") {
            serials
                .iter()
                .any(|s| revocation::ocsp_status(&m, s, &root, june).is_ok())
        } else {
            serials
                .iter()
                .any(|s| revocation::crl_status(&m, s, &root, june).is_ok())
        };
        ok += usize::from(accepted);
    }
    println!("{N} mutations, no panic; {ok} still accepted (mutations in unsigned bytes)");
}
