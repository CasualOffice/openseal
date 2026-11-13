//! keyd over mTLS with a development file key (no HSM needed): who is refused, what is
//! logged, the rate limit, the log's chain, and a seal made remotely that our verifier
//! and pyHanko accept. The file-key refusal lives here too.
// Test code: a panic is the failure report.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use std::sync::Arc;

use casual_sign_crypto::KeyProvider;
use casual_sign_keyd::{
    DevKeyConsent, DigestSigner, FileKey, KeyConfigProblem, KeydError, KeydLimits, OpLog,
    RemoteKey, digest_for, oplog,
};
use common::*;
use rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};

fn consent() -> DevKeyConsent {
    DevKeyConsent::from_env_value(Some("1")).unwrap()
}

/// A P-256 development file key certified by the seal CA.
fn file_key(pki: &Pki) -> FileKey {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = pki.signer("T-2E file key signer", &key);
    FileKey::load(
        consent(),
        key.serialize_pem().as_bytes(),
        vec![cert, pki.seal_root()],
        None,
    )
    .unwrap()
}

/// **A file key is refused unless `OPENSEAL_DEV_INSECURE_KEY` is exactly `1`**
/// (docs/31 §5, `CS-KEY-0004`). Without consent there is no `FileKey` to load.
#[test]
fn a_file_key_is_refused_without_explicit_consent() {
    for value in [
        None,
        Some(""),
        Some("0"),
        Some("true"),
        Some("yes"),
        Some(" 1"),
    ] {
        let err = DevKeyConsent::from_env_value(value).unwrap_err();
        assert_eq!(err, KeydError::InsecureKeyRefused, "{value:?}");
        assert_eq!(err.code(), "CS-KEY-0004");
    }
    assert!(DevKeyConsent::from_env_value(Some("1")).is_ok());
}

#[test]
fn a_file_key_that_is_not_its_certificates_is_refused() {
    let pki = Pki::new();
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let other = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let cert = pki.signer("T-2E mismatched", &other);
    let err =
        FileKey::load(consent(), key.serialize_pem().as_bytes(), vec![cert], None).unwrap_err();
    assert_eq!(
        err,
        KeydError::KeyConfig(KeyConfigProblem::KeyCertificateMismatch)
    );
    assert_eq!(err.code(), "CS-KEY-0006");
}

/// The allowed caller seals remotely; the seal passes our verifier and pyHanko, carries
/// the development reason, and keyd's log records the signature with its envelope id.
#[test]
fn an_allowed_caller_seals_through_keyd() {
    let pki = Pki::new();
    let dir = scratch("keyd-mtls-seal");
    let worker = pki.client_identity("worker");
    let keyd = start_keyd(
        &pki,
        vec![("dev", Arc::new(file_key(&pki)) as Arc<dyn DigestSigner>)],
        &[&worker.2],
        KeydLimits::default(),
        &dir,
    );
    let remote = RemoteKey::connect(endpoint(&pki, &keyd, Some(&worker)), "dev")
        .unwrap()
        .for_envelope("env-0001")
        .unwrap();
    assert!(
        remote.is_development(),
        "keyd says it serves a development key"
    );
    assert_eq!(KeyProvider::certificate_chain(&remote).len(), 2);
    let sealed = seal_with(&pki, &remote, remote.is_development());
    // /Reason is not ASCII (an em dash), so it is written as UTF-16BE hex.
    let mut reason = String::from("<FEFF");
    for unit in casual_sign_keyd::DEV_REASON.encode_utf16() {
        reason.push_str(&format!("{unit:04X}"));
    }
    reason.push('>');
    assert!(
        sealed.windows(reason.len()).any(|w| w == reason.as_bytes()),
        "the development reason is written"
    );
    eprintln!("ours (file key via keyd): {}", ours(&pki, &sealed));
    let out = scratch("keyd-mtls-validators");
    write_validator_dir(
        &pki,
        &out,
        &[("filekey-via-keyd-p256-bb.pdf".into(), sealed)],
    );
    pyhanko(&out);

    let log = std::fs::read_to_string(&keyd.oplog).unwrap();
    let lines: Vec<&str> = log.lines().collect();
    assert_eq!(lines.len(), 2, "{log}");
    assert!(lines[0].contains("\tchain\tdev\t"));
    let sign: Vec<&str> = lines[1].split('\t').collect();
    assert_eq!(sign[2], worker.2, "caller fingerprint");
    assert_eq!(sign[3], "sign");
    assert_eq!(sign[7], "env-0001");
    assert_eq!(sign[8], "ok");
    assert_eq!(sign[6].len(), 64, "the SHA-256 digest, hex");
    assert_eq!(oplog::verify(&keyd.oplog).unwrap().0, 2);
}

fn refused_setup(name: &str) -> (Pki, RunningKeyd, (String, String, String)) {
    let pki = Pki::new();
    let dir = scratch(name);
    let worker = pki.client_identity("worker");
    let keyd = start_keyd(
        &pki,
        vec![("dev", Arc::new(file_key(&pki)) as Arc<dyn DigestSigner>)],
        &[&worker.2],
        KeydLimits::default(),
        &dir,
    );
    (pki, keyd, worker)
}

/// **A client without a certificate never completes the handshake**, and is told so
/// as a TLS refusal (`CS-KEY-0013`), not as keyd being unreachable (`HRD-01`).
#[test]
fn a_client_without_a_certificate_is_refused() {
    let (pki, keyd, _) = refused_setup("keyd-mtls-nocert");
    let err = RemoteKey::connect(endpoint(&pki, &keyd, None), "dev").unwrap_err();
    assert_eq!(err.code(), "CS-KEY-0013", "{err}");
    eprintln!("no certificate: {err}");
}

/// **A certificate from another CA never completes the handshake** (`CS-KEY-0013`).
/// In TLS 1.3 the client finishes its side before keyd checks its certificate, so keyd's
/// alert can lose the race to a reset and read as `CS-KEY-0011` (seen on Linux CI; the
/// HRD-01 open note). Either way nothing is signed.
#[test]
fn a_client_with_an_untrusted_certificate_is_refused() {
    let (pki, keyd, _) = refused_setup("keyd-mtls-rogue");
    let rogue = pki.rogue_client_identity("worker");
    let err = RemoteKey::connect(endpoint(&pki, &keyd, Some(&rogue)), "dev").unwrap_err();
    assert!(matches!(err.code(), "CS-KEY-0013" | "CS-KEY-0011"), "{err}");
    eprintln!("untrusted certificate: {err}");
}

/// **A client that does not trust keyd's CA refuses keyd** (`CS-KEY-0013`, `HRD-01`):
/// a misconfiguration, never mistaken for keyd being down.
#[test]
fn a_client_with_the_wrong_ca_refuses_keyd() {
    let (pki, keyd, worker) = refused_setup("keyd-mtls-wrongca");
    let other = Pki::new();
    let mut ep = endpoint(&pki, &keyd, Some(&worker));
    ep.tls = casual_sign_keyd::client_tls(
        other.tls_ca.pem().as_bytes(),
        Some((worker.0.as_bytes(), worker.1.as_bytes())),
    )
    .unwrap();
    let err = RemoteKey::connect(ep, "dev").unwrap_err();
    assert_eq!(err.code(), "CS-KEY-0013", "{err}");
}

/// **keyd's certificate under another name is refused** (`CS-KEY-0013`, `HRD-01`).
#[test]
fn a_server_name_mismatch_refuses_keyd() {
    let (pki, keyd, worker) = refused_setup("keyd-mtls-name");
    let mut ep = endpoint(&pki, &keyd, Some(&worker));
    ep.server_name = "keyd.elsewhere.test".into();
    let err = RemoteKey::connect(ep, "dev").unwrap_err();
    assert_eq!(err.code(), "CS-KEY-0013", "{err}");
}

/// **keyd that cannot be reached is `CS-KEY-0011`**, not a TLS refusal: nothing
/// listening, and a listener that closes before TLS answers (`HRD-01`).
#[test]
fn an_unreachable_keyd_is_a_transport_failure() {
    let (pki, keyd, worker) = refused_setup("keyd-mtls-unreachable");
    // Nothing listens on a port just freed.
    let free = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = free.local_addr().unwrap().to_string();
    drop(free);
    let mut ep = endpoint(&pki, &keyd, Some(&worker));
    ep.addr = addr;
    let err = RemoteKey::connect(ep, "dev").unwrap_err();
    assert_eq!(err.code(), "CS-KEY-0011", "{err}");
    // A listener that accepts and closes at once.
    let closer = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut ep = endpoint(&pki, &keyd, Some(&worker));
    ep.addr = closer.local_addr().unwrap().to_string();
    std::thread::spawn(move || {
        for c in closer.incoming().flatten() {
            let _ = c.shutdown(std::net::Shutdown::Both);
        }
    });
    let err = RemoteKey::connect(ep, "dev").unwrap_err();
    assert_eq!(err.code(), "CS-KEY-0011", "{err}");
}

/// **A certificate from the right CA but not on the allow-list is answered
/// `CS-KEY-0001` and recorded.**
#[test]
fn a_client_not_on_the_allow_list_is_refused_and_logged() {
    let (pki, keyd, _) = refused_setup("keyd-mtls-notlisted");
    let stranger = pki.client_identity("stranger");
    let err = RemoteKey::connect(endpoint(&pki, &keyd, Some(&stranger)), "dev").unwrap_err();
    assert_eq!(err, KeydError::NotAuthorized, "{err}");
    let log = std::fs::read_to_string(&keyd.oplog).unwrap();
    assert!(
        log.contains(&format!(
            "\t{}\tconnect\t-\t-\t-\t-\tCS-KEY-0001\t",
            stranger.2
        )),
        "{log}"
    );
}

/// **Rotating the worker's keyd identity** (`HRD-06`, docs/65 §Rotation): keyd restarts
/// with both fingerprints listed, the worker moves to its new certificate (old and new
/// both seal meanwhile, so a worker restart in between loses nothing), then keyd
/// restarts with the new one alone and the old certificate is refused.
#[test]
fn a_worker_identity_rotates_with_an_overlap_and_the_old_one_is_then_refused() {
    let pki = Pki::new();
    let old = pki.client_identity("worker");
    let new = pki.client_identity("worker");
    assert_ne!(old.2, new.2);
    let key = || vec![("dev", Arc::new(file_key(&pki)) as Arc<dyn DigestSigner>)];

    let overlap = start_keyd(
        &pki,
        key(),
        &[&old.2, &new.2],
        KeydLimits::default(),
        &scratch("keyd-rotate-overlap"),
    );
    for who in [&old, &new] {
        let remote = RemoteKey::connect(endpoint(&pki, &overlap, Some(who)), "dev").unwrap();
        assert_eq!(KeyProvider::certificate_chain(&remote).len(), 2);
    }

    let after = start_keyd(
        &pki,
        key(),
        &[&new.2],
        KeydLimits::default(),
        &scratch("keyd-rotate-after"),
    );
    assert!(RemoteKey::connect(endpoint(&pki, &after, Some(&new)), "dev").is_ok());
    assert_eq!(
        RemoteKey::connect(endpoint(&pki, &after, Some(&old)), "dev").unwrap_err(),
        KeydError::NotAuthorized
    );
}

#[test]
fn an_unknown_alias_is_refused() {
    let (pki, keyd, worker) = refused_setup("keyd-mtls-alias");
    let err = RemoteKey::connect(endpoint(&pki, &keyd, Some(&worker)), "other").unwrap_err();
    assert_eq!(err, KeydError::UnknownAlias);
}

#[test]
fn signatures_over_the_rate_are_refused_and_logged() {
    let pki = Pki::new();
    let dir = scratch("keyd-mtls-rate");
    let worker = pki.client_identity("worker");
    let limits = KeydLimits {
        signatures_per_minute: 2,
        ..KeydLimits::default()
    };
    let keyd = start_keyd(
        &pki,
        vec![("dev", Arc::new(file_key(&pki)) as Arc<dyn DigestSigner>)],
        &[&worker.2],
        limits,
        &dir,
    );
    let remote = RemoteKey::connect(endpoint(&pki, &keyd, Some(&worker)), "dev").unwrap();
    let d = digest_for(DigestSigner::algorithm(&remote), b"attrs");
    assert!(remote.sign_digest(&d).is_ok());
    assert!(remote.sign_digest(&d).is_ok());
    assert_eq!(remote.sign_digest(&d).unwrap_err(), KeydError::RateLimited);
    let log = std::fs::read_to_string(&keyd.oplog).unwrap();
    assert!(log.lines().last().unwrap().contains("\tCS-KEY-0008\t"));
}

/// The log is append-only and chained: an edited line stops keyd from starting.
#[test]
fn an_edited_operation_log_is_refused() {
    let dir = scratch("keyd-oplog-tamper");
    let path = dir.join("oplog.tsv");
    let mut log = OpLog::open(&path).unwrap();
    for i in 0..3u64 {
        log.append(&casual_sign_keyd::OpRecord {
            time: 1_800_000_000 + i,
            caller: "ab".repeat(32),
            op: "sign",
            alias: "platform".into(),
            alg: "1".into(),
            digest: "cd".repeat(32),
            envelope: format!("env-{i}"),
            outcome: "ok",
        })
        .unwrap();
    }
    drop(log);
    assert_eq!(oplog::verify(&path).unwrap().0, 3);
    // Reopening continues the chain.
    let mut log = OpLog::open(&path).unwrap();
    log.append(&casual_sign_keyd::OpRecord {
        time: 1_800_000_010,
        caller: "-".into(),
        op: "chain",
        alias: "platform".into(),
        alg: "1".into(),
        digest: String::new(),
        envelope: String::new(),
        outcome: "ok",
    })
    .unwrap();
    drop(log);
    assert_eq!(oplog::verify(&path).unwrap().0, 4);

    let text = std::fs::read_to_string(&path).unwrap();
    for (what, edited) in [
        ("an edited envelope", text.replacen("env-1", "env-9", 1)),
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
        let err = OpLog::open(&path).unwrap_err();
        assert_eq!(err.code(), "CS-KEY-0009", "{what}");
    }
}
