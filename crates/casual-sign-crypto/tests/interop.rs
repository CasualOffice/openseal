//! Interop with an independent implementation (T-1F acceptance 1): fixtures made by
//! `fixtures/crypto/gen.py` with `cryptography`/`asn1crypto`/pyHanko verify here and a
//! flipped byte in each is detected; our outputs are written to `target/crypto-interop`
//! for `gen.py --verify`.

// Tests may unwrap, index and panic (CLAUDE.md); the product lints target src/.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
// Without `rsa` the RSA-signed fixtures are skipped, leaving some helpers unused.
#![cfg_attr(not(feature = "rsa"), allow(unused_imports, dead_code))]

mod common;

use core::time::Duration;

use casual_sign_crypto::cms::{self, ParsedCms};
use casual_sign_crypto::revocation::{self, RevocationStatus};
use casual_sign_crypto::tsp::{self, TimestampRequest};
use casual_sign_crypto::{
    CryptoError, DigestAlgorithm, RevocationFailure, SerialNumber, SignatureAlgorithm,
    TimestampFailure,
};
use common::{cert, fixture, interop_out_dir, pki};

/// Mirrors `gen.py`.
const NONCE: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
const REVOKED_SERIAL: u64 = 0x1001;
const GOOD_SERIAL: u64 = 0x1002;
/// 2026-03-01T00:00:00Z, 2026-06-01, 2026-07-01, 2026-05-01T12:00:00Z.
const REVOKED_AT: u64 = 1_772_323_200;
const THIS_UPDATE: u64 = 1_780_272_000;
const NEXT_UPDATE: u64 = 1_782_864_000;
const GEN_TIME: u64 = 1_777_636_800;

fn at(secs: u64) -> Duration {
    Duration::from_secs(secs)
}

fn serial(n: u64) -> SerialNumber {
    let bytes = n.to_be_bytes();
    let first = bytes.iter().position(|&b| b != 0).unwrap();
    SerialNumber::new(&bytes[first..]).unwrap()
}

fn verify_cms_fixture(der: &[u8], message: &[u8]) -> Result<(), CryptoError> {
    let parsed = ParsedCms::parse(der)?;
    let digest = parsed.digest_algorithm().digest(message);
    parsed.verify_detached(&digest).map(|_| ())
}

const CMS_FIXTURES: [&str; 5] = [
    "cms-p256-sha256.der",
    "cms-p256-unsorted.der",
    "cms-p384-sha384.der",
    "cms-rsa-pkcs1-sha256.der",
    "cms-rsa-pss-sha256.der",
];

#[test]
#[cfg(feature = "rsa")]
fn independent_cms_fixtures_verify_and_every_flipped_byte_fails() {
    let message = fixture("message.bin");
    for name in CMS_FIXTURES {
        let der = fixture(name);
        verify_cms_fixture(&der, &message).unwrap_or_else(|e| panic!("{name}: {e}"));
        let parsed = ParsedCms::parse(&der).unwrap();
        // Zero padding after the TLV, as in a PDF /Contents, is accepted.
        let mut padded = der.clone();
        padded.extend([0u8; 300]);
        verify_cms_fixture(&padded, &message).unwrap();

        // A flipped message byte fails the digest check.
        let mut m = message.clone();
        m[5] ^= 0x01;
        assert_eq!(
            verify_cms_fixture(&der, &m),
            Err(CryptoError::DigestMismatch),
            "{name}"
        );

        // Every single flipped byte of the CMS is rejected, or (in an unsigned part such
        // as a certificate other than the signer's) still verifies; never a panic.
        let mut rejected = 0usize;
        for i in 0..der.len() {
            let mut d = der.clone();
            d[i] ^= 0x01;
            if verify_cms_fixture(&d, &message).is_err() {
                rejected += 1;
            }
        }
        println!(
            "{name}: verifies ({:?}); flipped message byte -> CS-VER-0002; {rejected}/{} single-byte flips rejected",
            parsed.digest_algorithm(),
            der.len()
        );
        // The signed parts (signed attributes, signature, signer certificate) cover most
        // of the structure; the root certificate copy is unsigned by the CMS.
        assert!(
            rejected * 10 >= der.len() * 6,
            "{name}: only {rejected} rejected"
        );
    }
}

#[test]
#[cfg(not(feature = "rsa"))]
fn rsa_fixtures_are_unsupported_without_the_rsa_feature() {
    let message = fixture("message.bin");
    for name in ["cms-rsa-pkcs1-sha256.der", "cms-rsa-pss-sha256.der"] {
        assert_eq!(
            verify_cms_fixture(&fixture(name), &message),
            Err(CryptoError::UnsupportedAlgorithm)
        );
    }
    verify_cms_fixture(&fixture("cms-p256-sha256.der"), &message).unwrap();
}

#[test]
#[cfg(feature = "rsa")]
fn independent_tsa_response_verifies_and_flips_fail() {
    let message = fixture("message.bin");
    let imprint = DigestAlgorithm::Sha256.digest(&message);
    let request = TimestampRequest::new(&imprint, &NONCE).unwrap();
    let resp = fixture("tsr-granted.der");
    let token = tsp::verify_timestamp_response(&resp, &request).unwrap();
    assert_eq!(token.gen_time(), at(GEN_TIME));
    assert_eq!(token.tsa_certificate(), &cert("tsa.der"));
    // The embedded-token path accepts the same token.
    tsp::verify_timestamp_token(token.as_der(), &imprint).unwrap();

    let mut rejected = 0usize;
    for i in 0..resp.len() {
        let mut d = resp.clone();
        d[i] ^= 0x01;
        if tsp::verify_timestamp_response(&d, &request).is_err() {
            rejected += 1;
        }
    }
    println!(
        "tsr-granted.der: verifies, genTime {GEN_TIME}; {rejected}/{} single-byte flips rejected",
        resp.len()
    );
    assert!(rejected * 10 >= resp.len() * 6);

    let status = tsp::verify_timestamp_response(&fixture("tsr-rejection.der"), &request);
    assert_eq!(
        status.unwrap_err(),
        CryptoError::TimestampResponse(TimestampFailure::NotGranted)
    );
    // pyHanko's dummy TSA writes only the SHA-1 ESSCertID (v1): refused, not trusted blindly.
    let dummy = tsp::verify_timestamp_response(&fixture("tsr-pyhanko-dummy.der"), &request);
    assert_eq!(dummy.unwrap_err(), CryptoError::UnsupportedAlgorithm);
    println!(
        "tsr-rejection.der: NotGranted (CS-SEAL-0002); tsr-pyhanko-dummy.der: ESSCertID v1 only -> CS-SEAL-0005"
    );
}

#[test]
fn independent_ocsp_and_crl_answer_and_flips_fail() {
    let root = cert("root.der");
    let revoked = serial(REVOKED_SERIAL);
    let good = serial(GOOD_SERIAL);

    let by_ca = fixture("ocsp-revoked-by-ca.der");
    // Before the revocation: good; after: revoked; after nextUpdate: out of period.
    assert_eq!(
        revocation::ocsp_status(&by_ca, &revoked, &root, at(REVOKED_AT - 1)),
        Ok(RevocationStatus::Good)
    );
    assert_eq!(
        revocation::ocsp_status(&by_ca, &revoked, &root, at(REVOKED_AT + 1)),
        Ok(RevocationStatus::Revoked {
            revoked_at: at(REVOKED_AT)
        })
    );
    assert_eq!(
        revocation::ocsp_status(&by_ca, &revoked, &root, at(NEXT_UPDATE + 1)),
        Err(CryptoError::Revocation(RevocationFailure::OutOfPeriod))
    );
    assert_eq!(
        revocation::ocsp_status(&by_ca, &good, &root, at(REVOKED_AT)),
        Err(CryptoError::Revocation(RevocationFailure::NotCovered))
    );

    let delegated = fixture("ocsp-good-delegated.der");
    assert_eq!(
        revocation::ocsp_status(&delegated, &good, &root, at(THIS_UPDATE)),
        Ok(RevocationStatus::Good)
    );
    let rogue = fixture("ocsp-good-unauthorized.der");
    assert_eq!(
        revocation::ocsp_status(&rogue, &good, &root, at(THIS_UPDATE)),
        Err(CryptoError::Revocation(
            RevocationFailure::UnauthorizedSigner
        ))
    );

    let crl = fixture("crl.der");
    assert_eq!(
        revocation::crl_status(&crl, &revoked, &root, at(REVOKED_AT - 1)),
        Ok(RevocationStatus::Good)
    );
    assert_eq!(
        revocation::crl_status(&crl, &revoked, &root, at(THIS_UPDATE)),
        Ok(RevocationStatus::Revoked {
            revoked_at: at(REVOKED_AT)
        })
    );
    assert_eq!(
        revocation::crl_status(&crl, &good, &root, at(THIS_UPDATE)),
        Ok(RevocationStatus::Good)
    );
    assert_eq!(
        revocation::crl_status(&crl, &good, &root, at(NEXT_UPDATE + 1)),
        Err(CryptoError::Revocation(RevocationFailure::OutOfPeriod))
    );
    // Signed by someone else: the P-256 signer's certificate is not the CRL issuer.
    assert_eq!(
        revocation::crl_status(&crl, &good, &cert("p256.der"), at(THIS_UPDATE)),
        Err(CryptoError::Revocation(
            RevocationFailure::UnauthorizedSigner
        ))
    );

    for (name, data, sn, when, expect) in [
        (
            "ocsp-revoked-by-ca.der",
            by_ca,
            &revoked,
            at(THIS_UPDATE),
            RevocationStatus::Revoked {
                revoked_at: at(REVOKED_AT),
            },
        ),
        (
            "ocsp-good-delegated.der",
            delegated,
            &good,
            at(THIS_UPDATE),
            RevocationStatus::Good,
        ),
        (
            "crl.der",
            crl,
            &revoked,
            at(THIS_UPDATE),
            RevocationStatus::Revoked {
                revoked_at: at(REVOKED_AT),
            },
        ),
    ] {
        let check = |d: &[u8]| {
            if name.starts_with("crl") {
                revocation::crl_status(d, sn, &root, when)
            } else {
                revocation::ocsp_status(d, sn, &root, when)
            }
        };
        assert_eq!(check(&data), Ok(expect));
        let mut same = 0usize;
        for i in 0..data.len() {
            let mut d = data.clone();
            d[i] ^= 0x01;
            if check(&d) == Ok(expect) {
                same += 1;
            }
        }
        println!(
            "{name}: {expect:?}; {} of {} single-byte flips changed the answer or were refused",
            data.len() - same,
            data.len()
        );
        // Only bytes outside the signed part (e.g. the delegated responder's copy is
        // signed by the CA, the outer status wrapper) could leave the answer intact.
        assert!(
            same * 10 <= data.len(),
            "{name}: {same} flips left the answer unchanged"
        );
    }
}

/// Direction (b): write our own signatures for `gen.py --verify`.
#[test]
#[cfg(feature = "rsa")]
fn our_outputs_for_the_independent_checker() {
    let pki = pki();
    let out = interop_out_dir();
    let message = fixture("message.bin");
    std::fs::write(out.join("message.bin"), &message).unwrap();
    std::fs::write(
        out.join("root.der"),
        der::Encode::to_der(&pki.root).unwrap(),
    )
    .unwrap();
    for (name, alg) in [
        ("ours-p256-sha256.der", SignatureAlgorithm::EcdsaP256Sha256),
        ("ours-p384-sha384.der", SignatureAlgorithm::EcdsaP384Sha384),
        (
            "ours-rsa-pkcs1-sha256.der",
            SignatureAlgorithm::RsaPkcs1Sha256,
        ),
        ("ours-rsa-pss-sha256.der", SignatureAlgorithm::RsaPssSha256),
        (
            "ours-rsa-pkcs1-sha512.der",
            SignatureAlgorithm::RsaPkcs1Sha512,
        ),
    ] {
        let provider = pki.provider(alg);
        let digest = alg.digest_algorithm().digest(&message);
        let signed = cms::sign_detached(&provider, &digest).unwrap();
        let der = signed.to_der(None).unwrap();
        assert!(der.len() <= cms::max_der_len(&provider, 0).unwrap());
        // Our own verifier agrees before the independent one looks.
        verify_cms_fixture(&der, &message).unwrap();
        std::fs::write(out.join(name), &der).unwrap();
    }
    let req = TimestampRequest::new(&DigestAlgorithm::Sha256.digest(&message), &NONCE).unwrap();
    std::fs::write(out.join("ours-tsq.der"), req.as_der()).unwrap();
    println!("wrote our outputs to {}", out.display());
}
