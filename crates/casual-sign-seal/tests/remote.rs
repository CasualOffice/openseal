//! Two-phase signing for remote providers (ADR-046 §3.3, `RSP-01` gate 1): `prepare`
//! lays out the revision and gives the hash to sign; `complete` embeds a value made
//! elsewhere and refuses one over other bytes, by another key, or too large for the
//! placeholder. The "provider" here is the test key signing the prepared attributes, as
//! a CSC `signHash` would.
// Test code: a panic is the failure report.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use casual_sign_crypto::{DigestAlgorithm, KeyProvider};
use casual_sign_seal::{
    CompleteOptions, ExternalSigner, Limits, NoRevocation, NoTimestamps, Prepared, Profile,
    RemoteProblem, SealError, SealRequest, TimestampSource, complete, prepare, seal,
};
use casual_sign_verify::{Indication, ModificationClass, SignatureKind, VerifyOptions, verify};
use common::*;

fn request(profile: Profile, field: &str) -> SealRequest {
    let mut r = SealRequest::new(profile, field, SIGNING_TIME);
    r.name = Some("Remote signer".into());
    r.trust = trust();
    r
}

fn signer(key: &TestProvider) -> ExternalSigner {
    ExternalSigner {
        chain: key.certificate_chain().to_vec(),
        algorithm: key.algorithm(),
    }
}

fn options() -> CompleteOptions {
    CompleteOptions {
        trust: trust(),
        limits: Limits::default(),
    }
}

/// What a provider does: sign the prepared attributes (it receives their digest; our
/// test key hashes and signs in one call, as `KeyProvider::sign`).
fn provider_value(key: &TestProvider, p: &Prepared) -> Vec<u8> {
    key.sign(&p.signed_attributes).unwrap().as_bytes().to_vec()
}

fn indications(bytes: &[u8]) -> Vec<(SignatureKind, Indication)> {
    let report = verify(bytes, &trust(), &VerifyOptions::at(VALIDATION_TIME));
    assert!(report.error.is_none(), "{:?}", report.error);
    report
        .signatures
        .iter()
        .map(|s| (s.kind, s.indication))
        .collect()
}

/// `r‖s` from a DER `Ecdsa-Sig-Value` of P-256 (each integer left-padded to 32 bytes).
fn raw_rs(der: &[u8]) -> Vec<u8> {
    assert_eq!(der[0], 0x30);
    let mut at = 2;
    let mut out = Vec::new();
    for _ in 0..2 {
        assert_eq!(der[at], 0x02);
        let len = der[at + 1] as usize;
        let mut v = der[at + 2..at + 2 + len].to_vec();
        while v.len() > 32 && v[0] == 0 {
            v.remove(0);
        }
        let mut padded = vec![0u8; 32 - v.len()];
        padded.extend_from_slice(&v);
        out.extend_from_slice(&padded);
        at += 2 + len;
    }
    out
}

#[test]
fn a_prepared_revision_completes_at_every_remote_level_for_each_key() {
    for key in [p256(), rsa()] {
        for profile in [Profile::BaselineB, Profile::BaselineT, Profile::BaselineLt] {
            let tsa = TestTsa::new(SIGNING_TIME);
            let rev = TestRevocation::default();
            let input = one_page("Agreement");
            let p = prepare(
                &input,
                &request(profile, "Remote1"),
                &signer(&key),
                tsa.token_len_bound(),
            )
            .unwrap();
            assert!(p.bytes.starts_with(&input), "the input is a prefix");
            assert_eq!(
                p.byte_range[2] + p.byte_range[3],
                p.bytes.len() as u64,
                "the ByteRange reaches the end"
            );
            // The hash sent to the provider is the digest of the DER signed attributes,
            // whose message-digest is the ByteRange digest (ADR-046 §3.5).
            let alg = key.algorithm().digest_algorithm();
            assert_eq!(
                alg.digest(&p.signed_attributes).as_bytes(),
                p.to_be_signed.as_slice()
            );
            assert_eq!(p.signed_attributes[0], 0x31, "explicit SET OF tag");
            let s = complete(&p, &provider_value(&key, &p), &tsa, &rev, &options()).unwrap();
            // Completion embeds into exactly the prepared bytes: only the placeholder
            // changes, then later revisions (the DSS) follow.
            let a = p.byte_range[1] as usize;
            let b = p.byte_range[2] as usize;
            assert_eq!(&s.bytes[..a], &p.bytes[..a]);
            assert_eq!(&s.bytes[b..p.bytes.len()], &p.bytes[b..]);
            let v = indications(&s.bytes);
            assert_eq!(v.len(), 1);
            match profile {
                // Without revocation data a signature waits for it (TryLater).
                Profile::BaselineB | Profile::BaselineT => {
                    assert!(matches!(v[0].1, Indication::Indeterminate(_)), "{v:?}");
                }
                _ => assert_eq!(v[0].1, Indication::TotalPassed, "{profile:?} {v:?}"),
            }
            assert_eq!(
                s.report.dss.is_some(),
                profile == Profile::BaselineLt,
                "DSS right after the remote signature at B-LT"
            );
            assert_eq!(s.report.signature.unwrap().byte_range, p.byte_range);
        }
    }
}

#[test]
fn a_raw_ecdsa_value_is_accepted_and_re_encoded() {
    let key = p256();
    let p = prepare(
        &one_page("Agreement"),
        &request(Profile::BaselineB, "Remote1"),
        &signer(&key),
        0,
    )
    .unwrap();
    let raw = raw_rs(&provider_value(&key, &p));
    assert_eq!(raw.len(), 64);
    let s = complete(&p, &raw, &NoTimestamps, &NoRevocation, &options()).unwrap();
    assert_eq!(indications(&s.bytes).len(), 1);
}

/// Guard: a value over other bytes (another document's or another revision's hash) is
/// refused and nothing is written.
#[test]
fn a_value_over_other_bytes_is_refused() {
    let key = p256();
    let p = prepare(
        &one_page("Agreement"),
        &request(Profile::BaselineB, "Remote1"),
        &signer(&key),
        0,
    )
    .unwrap();
    let other = prepare(
        &one_page("Another agreement"),
        &request(Profile::BaselineB, "Remote1"),
        &signer(&key),
        0,
    )
    .unwrap();
    assert_ne!(other.to_be_signed, p.to_be_signed);
    let e = complete(
        &p,
        &provider_value(&key, &other),
        &NoTimestamps,
        &NoRevocation,
        &options(),
    )
    .unwrap_err();
    assert_eq!(e, SealError::Remote(RemoteProblem::SignatureValue));
    assert_eq!(e.code(), "CS-RSP-0004");
}

/// Guard: a value made by another credential's key is refused.
#[test]
fn another_certificates_value_is_refused() {
    for (chain_of, signed_by) in [(rsa(), rsa_other()), (p256(), p256_other())] {
        let p = prepare(
            &one_page("Agreement"),
            &request(Profile::BaselineB, "Remote1"),
            &signer(&chain_of),
            0,
        )
        .unwrap();
        let e = complete(
            &p,
            &provider_value(&signed_by, &p),
            &NoTimestamps,
            &NoRevocation,
            &options(),
        )
        .unwrap_err();
        assert_eq!(e.code(), "CS-RSP-0004", "{e:?}");
    }
}

/// Another key of the same kind as the test signers: the RSA key's value for the P-256
/// chain is a wrong length, so "another certificate" needs a same-kind key.
fn rsa_other() -> TestProvider {
    other_rsa_key()
}

fn p256_other() -> TestProvider {
    other_p256_key()
}

/// Guard: a CMS larger than the planned placeholder is `CS-RSP-0005` and is never
/// re-laid out (one TSA call, no second attempt).
#[test]
fn a_cms_larger_than_its_placeholder_is_refused_without_relayout() {
    let key = p256();
    let mut tsa = TestTsa::new(SIGNING_TIME);
    tsa.bound = Some(10);
    tsa.grow_step = 4096;
    let p = prepare(
        &one_page("Agreement"),
        &request(Profile::BaselineT, "Remote1"),
        &signer(&key),
        tsa.token_len_bound(),
    )
    .unwrap();
    let e = complete(
        &p,
        &provider_value(&key, &p),
        &tsa,
        &NoRevocation,
        &options(),
    )
    .unwrap_err();
    assert!(matches!(e, SealError::RemoteOverflow { .. }), "{e:?}");
    assert_eq!(e.code(), "CS-RSP-0005");
    assert_eq!(tsa.calls.get(), 1, "never re-laid out");
}

/// Guard: prepared bytes changed after the hash was given out are refused.
#[test]
fn altered_prepared_bytes_are_refused() {
    let key = p256();
    let mut p = prepare(
        &one_page("Agreement"),
        &request(Profile::BaselineB, "Remote1"),
        &signer(&key),
        0,
    )
    .unwrap();
    let value = provider_value(&key, &p);
    // A byte inside the covered range.
    let at = p.byte_range[1] as usize - 40;
    p.bytes[at] ^= 0x01;
    let e = complete(&p, &value, &NoTimestamps, &NoRevocation, &options()).unwrap_err();
    assert_eq!(e, SealError::Remote(RemoteProblem::PreparedAltered));
    assert_eq!(e.code(), "CS-RSP-0004");
}

/// Two remote signers one after the other, then the platform seal last (ADR-046 §3.2):
/// every signature passes, each later revision is an allowed change for the earlier
/// ones, and the platform seal covers the whole file.
#[test]
fn two_remote_signatures_then_the_platform_seal_all_pass() {
    let tsa = TestTsa::new(SIGNING_TIME);
    let rev = TestRevocation::default();
    let mut bytes = one_page("Agreement");
    for (i, key) in [rsa(), p256()].iter().enumerate() {
        let p = prepare(
            &bytes,
            &request(Profile::BaselineLt, &format!("Remote{}", i + 1)),
            &signer(key),
            tsa.token_len_bound(),
        )
        .unwrap();
        bytes = complete(&p, &provider_value(key, &p), &tsa, &rev, &options())
            .unwrap()
            .bytes;
    }
    let mut platform = request(Profile::BaselineLt, "Seal1");
    platform.name = Some("OpenSeal platform".into());
    let sealed = seal(&bytes, &platform, &p256(), &tsa, &rev).unwrap();
    let report = verify(&sealed.bytes, &trust(), &VerifyOptions::at(VALIDATION_TIME));
    assert_eq!(report.signatures.len(), 3);
    for s in &report.signatures {
        assert_eq!(s.indication, Indication::TotalPassed, "{s:?}");
        for m in &s.modifications_after {
            assert!(m.allowed(), "{m:?}");
            assert!(
                m.classes.iter().all(|c| matches!(
                    c,
                    ModificationClass::Signature | ModificationClass::DssUpdate
                )),
                "{m:?}"
            );
        }
    }
}

/// A remote signature never takes B-LTA itself: the account's B-LTA is applied once at
/// completion (ADR-046 §3.6).
#[test]
fn b_lta_is_refused_at_prepare() {
    let e = prepare(
        &one_page("Agreement"),
        &request(Profile::BaselineLta, "Remote1"),
        &signer(&p256()),
        0,
    )
    .unwrap_err();
    assert_eq!(e.code(), "CS-SEAL-0006");
}

#[test]
fn the_hash_is_the_signed_attributes_digest_under_the_keys_algorithm() {
    let p = prepare(
        &one_page("Agreement"),
        &request(Profile::BaselineB, "Remote1"),
        &signer(&rsa()),
        0,
    )
    .unwrap();
    assert_eq!(p.digest_algorithm(), DigestAlgorithm::Sha256);
    assert_eq!(p.to_be_signed.len(), 32);
    assert_eq!(p.byte_range_digest.len(), 32);
}
