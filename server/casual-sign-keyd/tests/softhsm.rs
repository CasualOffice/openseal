//! The stage 2E gate: keys generated in a SoftHSM token seal a PDF through
//! casual-sign-seal, both with the PKCS#11 provider in process and through keyd over
//! mTLS, and every output passes our verifier and pyHanko (`tools/verify-sealed.py`,
//! when `OPENSEAL_VERIFY_PYTHON` names a Python with pyHanko).
//!
//! SoftHSM reads its configuration from `SOFTHSM2_CONF`, and a test may not set an
//! environment variable (`set_var` is `unsafe` in edition 2024, which the workspace
//! forbids). So [`softhsm_seals_verify_through_pkcs11_and_keyd`] writes a configuration
//! with a token directory under `target/` and runs this test binary again, filtered to
//! [`softhsm_child`], with the variable set on the child process. Without SoftHSM
//! (`SOFTHSM2_MODULE`, or a library at a usual path) it skips with a note.
// Test code: a panic is the failure report.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use std::path::PathBuf;
use std::sync::Arc;

use casual_sign_crypto::{Certificate, SignatureAlgorithm};
use casual_sign_keyd::{
    ChainSource, DigestSigner, KeyConfigProblem, KeydError, KeydLimits, Pkcs11Key, Pkcs11KeyConfig,
    Pkcs11Module, RemoteKey, Secret, oplog,
};
use common::*;
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, CertificateType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::types::{AuthPin, Ulong};
use der::asn1::{ObjectIdentifier, OctetString, UintRef};
use der::{Decode, Encode};

const TOKEN: &str = "openseal-test";
const USER_PIN: &str = "user-pin-1234";
const SO_PIN: &str = "so-pin-5678";

fn module_path() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("SOFTHSM2_MODULE") {
        return Some(PathBuf::from(p));
    }
    [
        "/opt/homebrew/lib/softhsm/libsofthsm2.so",
        "/usr/local/lib/softhsm/libsofthsm2.so",
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/lib/aarch64-linux-gnu/softhsm/libsofthsm2.so",
    ]
    .iter()
    .map(PathBuf::from)
    .find(|p| p.is_file())
}

/// **The gate.** Runs [`softhsm_child`] in a child process with `SOFTHSM2_CONF` set.
#[test]
fn softhsm_seals_verify_through_pkcs11_and_keyd() {
    let Some(module) = module_path() else {
        eprintln!("NOTE: SoftHSM not found (install softhsm2 or set SOFTHSM2_MODULE); skipped");
        return;
    };
    let dir = scratch("keyd-softhsm");
    let tokens = dir.join("tokens");
    std::fs::create_dir_all(&tokens).unwrap();
    let conf = dir.join("softhsm2.conf");
    std::fs::write(
        &conf,
        format!(
            "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
            tokens.display()
        ),
    )
    .unwrap();
    let out = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "softhsm_child",
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("SOFTHSM2_CONF", &conf)
        .env("OPENSEAL_SOFTHSM_MODULE", &module)
        .env("OPENSEAL_SOFTHSM_DIR", &dir)
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    eprintln!("{text}");
    assert!(out.status.success(), "the SoftHSM run failed");
    assert!(text.contains("1 passed"), "the SoftHSM run did not run");
}

fn attr_bytes(session: &Session, obj: ObjectHandle, t: AttributeType) -> Vec<u8> {
    match session.get_attributes(obj, &[t]).unwrap().pop().unwrap() {
        Attribute::EcPoint(v) | Attribute::Modulus(v) | Attribute::PublicExponent(v) => v,
        other => panic!("{other:?}"),
    }
}

fn private_template(label: &str, id: u8) -> Vec<Attribute> {
    vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Sign(true),
        Attribute::Label(label.as_bytes().to_vec()),
        Attribute::Id(vec![id]),
    ]
}

/// An EC key pair in the token; returns the uncompressed public point.
fn ec_key(session: &Session, label: &str, id: u8, curve: &str) -> Vec<u8> {
    let params = ObjectIdentifier::new_unwrap(curve).to_der().unwrap();
    let (public, _) = session
        .generate_key_pair(
            &Mechanism::EccKeyPairGen,
            &[
                Attribute::Token(true),
                Attribute::Verify(true),
                Attribute::EcParams(params),
                Attribute::Label(label.as_bytes().to_vec()),
                Attribute::Id(vec![id]),
            ],
            &private_template(label, id),
        )
        .unwrap();
    // CKA_EC_POINT is a DER OCTET STRING around the point.
    let wrapped = attr_bytes(session, public, AttributeType::EcPoint);
    OctetString::from_der(&wrapped).unwrap().as_bytes().to_vec()
}

#[derive(der::Sequence)]
struct RsaPublicKey<'a> {
    modulus: UintRef<'a>,
    exponent: UintRef<'a>,
}

/// An RSA key pair in the token; returns the `RSAPublicKey` DER.
fn rsa_key(session: &Session, label: &str, id: u8, bits: u64) -> Vec<u8> {
    let (public, _) = session
        .generate_key_pair(
            &Mechanism::RsaPkcsKeyPairGen,
            &[
                Attribute::Token(true),
                Attribute::Verify(true),
                Attribute::ModulusBits(Ulong::try_from(usize::try_from(bits).unwrap()).unwrap()),
                Attribute::PublicExponent(vec![1, 0, 1]),
                Attribute::Label(label.as_bytes().to_vec()),
                Attribute::Id(vec![id]),
            ],
            &private_template(label, id),
        )
        .unwrap();
    let n = attr_bytes(session, public, AttributeType::Modulus);
    let e = attr_bytes(session, public, AttributeType::PublicExponent);
    RsaPublicKey {
        modulus: UintRef::new(&n).unwrap(),
        exponent: UintRef::new(&e).unwrap(),
    }
    .to_der()
    .unwrap()
}

fn store_certificate(session: &Session, cert: &Certificate, label: &str, id: u8) {
    session
        .create_object(&[
            Attribute::Class(ObjectClass::CERTIFICATE),
            Attribute::CertificateType(CertificateType::X_509),
            Attribute::Token(true),
            Attribute::Label(label.as_bytes().to_vec()),
            Attribute::Id(vec![id]),
            Attribute::Subject(cert.tbs_certificate().subject().to_der().unwrap()),
            Attribute::Value(der(cert)),
        ])
        .unwrap();
}

struct Case {
    name: &'static str,
    label: &'static str,
    chain: ChainSource,
    rsa: Option<SignatureAlgorithm>,
}

fn pin(s: &str) -> Secret {
    Secret::new(s.to_owned())
}

fn config(
    case_label: &str,
    chain: ChainSource,
    rsa: Option<SignatureAlgorithm>,
) -> Pkcs11KeyConfig {
    Pkcs11KeyConfig {
        token_label: TOKEN.into(),
        key_label: Some(case_label.into()),
        key_id: None,
        pin: pin(USER_PIN),
        chain,
        rsa_algorithm: rsa,
    }
}

/// The body of the gate, run in a child process by
/// [`softhsm_seals_verify_through_pkcs11_and_keyd`].
#[test]
#[ignore = "run by softhsm_seals_verify_through_pkcs11_and_keyd with SOFTHSM2_CONF set"]
fn softhsm_child() {
    let module_path = PathBuf::from(std::env::var("OPENSEAL_SOFTHSM_MODULE").unwrap());
    let dir = PathBuf::from(std::env::var("OPENSEAL_SOFTHSM_DIR").unwrap());
    let module = Pkcs11Module::open(&module_path).unwrap();
    let ctx = module.context();

    // A fresh token: SoftHSM offers one uninitialized slot and renumbers it on init.
    let free = ctx.get_slots_with_token().unwrap()[0];
    ctx.init_token(free, &AuthPin::from(SO_PIN), TOKEN).unwrap();
    let slot = module.slot(TOKEN).unwrap();
    let rw = ctx.open_rw_session(slot).unwrap();
    rw.login(UserType::So, Some(&AuthPin::from(SO_PIN)))
        .unwrap();
    rw.init_pin(&AuthPin::from(USER_PIN)).unwrap();
    rw.logout().unwrap();
    rw.login(UserType::User, Some(&AuthPin::from(USER_PIN)))
        .unwrap();

    let pki = Pki::new();
    let root = pki.seal_root();
    let p256 = ExternalPublicKey {
        raw: ec_key(&rw, "seal-p256", 1, "1.2.840.10045.3.1.7"),
        alg: &rcgen::PKCS_ECDSA_P256_SHA256,
    };
    let p384 = ExternalPublicKey {
        raw: ec_key(&rw, "seal-p384", 2, "1.3.132.0.34"),
        alg: &rcgen::PKCS_ECDSA_P384_SHA384,
    };
    let rsa = ExternalPublicKey {
        raw: rsa_key(&rw, "seal-rsa3072", 3, 3072),
        alg: &rcgen::PKCS_RSA_SHA256,
    };
    let p256_cert = pki.signer("T-2E HSM P-256 signer", &p256);
    let p384_cert = pki.signer("T-2E HSM P-384 signer", &p384);
    let rsa_cert = pki.signer("T-2E HSM RSA-3072 signer", &rsa);
    // The P-256 signer certificate lives in the token, beside its key.
    store_certificate(&rw, &p256_cert, "seal-p256", 1);
    drop(rw);

    let cases = [
        Case {
            name: "p256-token-cert",
            label: "seal-p256",
            chain: ChainSource::Token {
                rest: vec![root.clone()],
            },
            rsa: None,
        },
        Case {
            name: "p384",
            label: "seal-p384",
            chain: ChainSource::Supplied(vec![p384_cert.clone(), root.clone()]),
            rsa: None,
        },
        Case {
            name: "rsa3072-pkcs1-sha256",
            label: "seal-rsa3072",
            chain: ChainSource::Supplied(vec![rsa_cert.clone(), root.clone()]),
            rsa: Some(SignatureAlgorithm::RsaPkcs1Sha256),
        },
        Case {
            name: "rsa3072-pss-sha256",
            label: "seal-rsa3072",
            chain: ChainSource::Supplied(vec![rsa_cert.clone(), root.clone()]),
            rsa: Some(SignatureAlgorithm::RsaPssSha256),
        },
    ];

    // The PIN never prints.
    let shown = format!(
        "{:?}",
        config("seal-p256", ChainSource::Token { rest: vec![] }, None)
    );
    assert!(
        !shown.contains(USER_PIN) && shown.contains("Secret(..)"),
        "{shown}"
    );

    // Refusals first: a wrong PIN, a label that names nothing, a certificate that is
    // not the key's (the probe).
    let err = module
        .key(Pkcs11KeyConfig {
            pin: pin("wrong-pin"),
            ..config(
                "seal-p256",
                ChainSource::Supplied(vec![p256_cert.clone()]),
                None,
            )
        })
        .unwrap_err();
    assert_eq!(err.code(), "CS-KEY-0003", "{err}");
    println!("wrong PIN: {err}");
    let err = module
        .key(config(
            "no-such-key",
            ChainSource::Supplied(vec![p256_cert.clone()]),
            None,
        ))
        .unwrap_err();
    assert_eq!(err, KeydError::KeyConfig(KeyConfigProblem::KeyNotFound));
    // A P-256 certificate for another key, offered for the HSM's P-256 key.
    let other = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let wrong = pki.signer("T-2E not the HSM key", &other);
    let err = module
        .key(config(
            "seal-p256",
            ChainSource::Supplied(vec![wrong]),
            None,
        ))
        .unwrap_err();
    assert_eq!(
        err,
        KeydError::KeyConfig(KeyConfigProblem::KeyCertificateMismatch)
    );
    println!("certificate of another key: {err}");

    let mut outputs: Vec<(String, Vec<u8>)> = Vec::new();
    let mut served: Vec<(&str, Arc<dyn DigestSigner>)> = Vec::new();

    // 1. In process: casual-sign-seal signs through the PKCS#11 KeyProvider.
    for case in &cases {
        let key: Pkcs11Key = module
            .key(config(case.label, case.chain.clone(), case.rsa))
            .unwrap();
        assert!(!key.is_development());
        let sealed = seal_with(&pki, &key, false);
        println!("ours  pkcs11 {:<22} {}", case.name, ours(&pki, &sealed));
        outputs.push((format!("pkcs11-{}-bb.pdf", case.name), sealed));
        served.push((case.name, Arc::new(key)));
    }

    // 2. Through keyd over mTLS: the worker holds no key.
    let worker = pki.client_identity("worker");
    let keyd = start_keyd(&pki, served, &[&worker.2], KeydLimits::default(), &dir);
    for (i, case) in cases.iter().enumerate() {
        let remote = RemoteKey::connect(endpoint(&pki, &keyd, Some(&worker)), case.name)
            .unwrap()
            .for_envelope(&format!("env-{i}"))
            .unwrap();
        assert!(!remote.is_development());
        let sealed = seal_with(&pki, &remote, false);
        println!("ours  keyd   {:<22} {}", case.name, ours(&pki, &sealed));
        outputs.push((format!("keyd-pkcs11-{}-bb.pdf", case.name), sealed));
    }
    let (lines, _) = oplog::verify(&keyd.oplog).unwrap();
    assert_eq!(lines, 8, "one chain and one sign line per case");
    let log = std::fs::read_to_string(&keyd.oplog).unwrap();
    println!("keyd operation log:\n{log}");

    let validators = dir.join("validators");
    std::fs::create_dir_all(&validators).unwrap();
    write_validator_dir(&pki, &validators, &outputs);
    pyhanko(&validators);
}
