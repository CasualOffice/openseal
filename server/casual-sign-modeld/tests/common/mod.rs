//! Test-only throwaway TLS PKI (rcgen, keys in memory), bundles in scratch directories,
//! and a modeld started on a loopback port. Adapted from keyd's `tests/common/mod.rs`
//! (stage 2E). Never use outside tests.
// Not every test binary uses every helper.
#![allow(dead_code)]
// Test code: a panic is the failure report.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    missing_docs
)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use casual_sign_modeld::{
    AllowList, Bundle, Call, Endpoint, Manifest, ModelClient, ModelService, Modeld, ModeldLimits,
    OpLog, client_tls, fingerprint, server_tls,
};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyIdMethod, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
    SerialNumber,
};

fn dn(cn: &str) -> DistinguishedName {
    let mut d = DistinguishedName::new();
    d.push(DnType::CommonName, cn);
    d.push(
        DnType::OrganizationName,
        "OpenSeal ML-09 throwaway test PKI",
    );
    d
}

fn ca(cn: &str, serial: u64) -> CertifiedIssuer<'static, KeyPair> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name = dn(cn);
    p.not_before = rcgen::date_time_ymd(2026, 1, 1);
    p.not_after = rcgen::date_time_ymd(2046, 1, 1);
    p.serial_number = Some(SerialNumber::from(serial));
    p.key_identifier_method = KeyIdMethod::Sha256;
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    CertifiedIssuer::self_signed(p, key).unwrap()
}

/// The TLS CA modeld trusts and a rogue one it does not.
pub struct Pki {
    pub tls_ca: CertifiedIssuer<'static, KeyPair>,
    pub rogue_ca: CertifiedIssuer<'static, KeyPair>,
    serial: std::sync::atomic::AtomicU64,
}

/// (certificate PEM, key PEM, fingerprint).
pub type Identity = (String, String, String);

impl Pki {
    pub fn new() -> Self {
        Self {
            tls_ca: ca("ML-09 modeld TLS Root", 2),
            rogue_ca: ca("ML-09 Rogue Root", 3),
            serial: std::sync::atomic::AtomicU64::new(100),
        }
    }

    fn tls_entity(
        &self,
        issuer: &CertifiedIssuer<'static, KeyPair>,
        cn: &str,
        server: bool,
    ) -> Identity {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut p = if server {
            CertificateParams::new(vec!["localhost".to_owned()]).unwrap()
        } else {
            CertificateParams::new(Vec::<String>::new()).unwrap()
        };
        p.distinguished_name = dn(cn);
        p.not_before = rcgen::date_time_ymd(2026, 1, 1);
        p.not_after = rcgen::date_time_ymd(2046, 1, 1);
        p.serial_number = Some(SerialNumber::from(
            self.serial
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst),
        ));
        p.is_ca = IsCa::ExplicitNoCa;
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![if server {
            ExtendedKeyUsagePurpose::ServerAuth
        } else {
            ExtendedKeyUsagePurpose::ClientAuth
        }];
        p.use_authority_key_identifier_extension = true;
        let cert = p.signed_by(&key, issuer).unwrap();
        (cert.pem(), key.serialize_pem(), fingerprint(cert.der()))
    }

    pub fn server_identity(&self) -> Identity {
        self.tls_entity(&self.tls_ca, "modeld.test", true)
    }

    pub fn rogue_server_identity(&self) -> Identity {
        self.tls_entity(&self.rogue_ca, "modeld.test", true)
    }

    pub fn client_identity(&self, cn: &str) -> Identity {
        self.tls_entity(&self.tls_ca, cn, false)
    }

    pub fn rogue_client_identity(&self, cn: &str) -> Identity {
        self.tls_entity(&self.rogue_ca, cn, false)
    }
}

/// A scratch directory under this test binary's `target/` tmp dir, emptied.
pub fn scratch(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// Lowercase hex SHA-256 (the certificate fingerprint function hashes any bytes).
pub fn sha_hex(b: &[u8]) -> String {
    fingerprint(b)
}

/// Synthetic "model" files (no real weights): `(id, profile, path, bytes)`. Writes each
/// under `dir` and returns the manifest text listing them.
pub fn bundle(dir: &Path, files: &[(&str, &str, &str, &[u8])]) -> String {
    let mut manifest = String::from("# test bundle\n");
    for (id, profile, path, bytes) in files {
        let file = dir.join(path);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, bytes).unwrap();
        manifest.push_str(&format!(
            "{id}\t{profile}\t{}\t{}\tApache-2.0\t{path}\n",
            sha_hex(bytes),
            bytes.len()
        ));
    }
    manifest
}

/// The synthetic two-file bundle the mTLS tests serve.
pub fn test_bundle(name: &str) -> Bundle {
    let dir = scratch(name);
    let text = bundle(
        &dir,
        &[
            ("det", "ocr", "ocr/det.onnx", b"synthetic detector bytes"),
            ("rec", "ocr", "ocr/rec.onnx", b"synthetic recogniser bytes"),
        ],
    );
    Bundle::verify(&dir, &Manifest::parse(&text).unwrap(), &["ocr".into()]).unwrap()
}

/// A modeld on a loopback port.
pub struct RunningModeld {
    pub addr: String,
    pub oplog: PathBuf,
    pub bundle_id: String,
}

pub fn start_modeld(
    pki: &Pki,
    server: &Identity,
    allowed: &[&str],
    limits: ModeldLimits,
    name: &str,
) -> RunningModeld {
    let bundle = test_bundle(&format!("{name}-bundle"));
    start_modeld_with(pki, server, allowed, limits, name, bundle)
}

/// A modeld on a loopback port serving `bundle`.
pub fn start_modeld_with(
    pki: &Pki,
    server: &Identity,
    allowed: &[&str],
    limits: ModeldLimits,
    name: &str,
    bundle: Bundle,
) -> RunningModeld {
    let dir = scratch(&format!("{name}-run"));
    let (cert, key, _) = server;
    let tls = server_tls(cert.as_bytes(), key.as_bytes(), pki.tls_ca.pem().as_bytes()).unwrap();
    let mut allow = AllowList::new();
    for fp in allowed {
        allow.allow(fp, "test");
    }
    let oplog = dir.join("modeld-oplog.tsv");
    let bundle_id = bundle.id.clone();
    let service = ModelService::new(bundle, allow, OpLog::open(&oplog).unwrap(), limits);
    let modeld = Modeld::bind("127.0.0.1:0", tls, service).unwrap();
    let addr = modeld.local_addr().unwrap().to_string();
    std::thread::spawn(move || modeld.serve());
    RunningModeld {
        addr,
        oplog,
        bundle_id,
    }
}

/// A client of `modeld` trusting `trust_ca_pem`, with the given identity (`None`: no
/// certificate).
pub fn client(trust_ca_pem: &str, modeld: &RunningModeld, id: Option<&Identity>) -> ModelClient {
    let tls = client_tls(
        trust_ca_pem.as_bytes(),
        id.map(|(c, k, _)| (c.as_bytes(), k.as_bytes())),
    )
    .unwrap();
    ModelClient::new(Endpoint {
        addr: modeld.addr.clone(),
        server_name: "localhost".into(),
        tls,
        connect_timeout: Duration::from_secs(10),
    })
}

/// The real-weights bundle the model tests read (`OPENSEAL_MODELD_TEST_BUNDLE`), verified
/// against a manifest listing every file under it, with `known` paths under their
/// manifest ids; `None` (and a SKIPPED message) when the variable is unset.
pub fn real_bundle(known: &[(&str, &str)]) -> Option<Bundle> {
    let Some(dir) = std::env::var_os("OPENSEAL_MODELD_TEST_BUNDLE").map(PathBuf::from) else {
        eprintln!(
            "SKIPPED: OPENSEAL_MODELD_TEST_BUNDLE is not set. Fetch a bundle with \
             `python3 -I tools/ml/fetch-models.py --profile templates --dest DIR` and set it to DIR."
        );
        return None;
    };
    let mut text = String::new();
    let mut stack = vec![PathBuf::new()];
    let mut n = 0;
    while let Some(rel) = stack.pop() {
        for item in std::fs::read_dir(dir.join(&rel)).unwrap() {
            let item = item.unwrap();
            let r = rel.join(item.file_name());
            if item.file_type().unwrap().is_dir() {
                stack.push(r);
                continue;
            }
            let path = r.to_string_lossy().into_owned();
            let id = known.iter().find(|(p, _)| *p == path).map_or_else(
                || {
                    n += 1;
                    format!("extra-{n}")
                },
                |(_, id)| (*id).to_owned(),
            );
            let bytes = std::fs::read(dir.join(&r)).unwrap();
            text.push_str(&format!(
                "{id}\ttemplates\t{}\t{}\tMIT\t{path}\n",
                sha_hex(&bytes),
                bytes.len()
            ));
        }
    }
    Some(Bundle::verify(&dir, &Manifest::parse(&text).unwrap(), &[]).unwrap())
}

pub fn call() -> Call {
    Call {
        account: "acc-0001".into(),
        job: "job-0001".into(),
        deadline: Duration::from_secs(20),
    }
}
