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
    start_modeld_with(pki, server, allowed, limits, name, |s| s)
}

/// As [`start_modeld`], with the service configured by `configure` (a raster child, the
/// OCR models).
pub fn start_modeld_with(
    pki: &Pki,
    server: &Identity,
    allowed: &[&str],
    limits: ModeldLimits,
    name: &str,
    configure: impl FnOnce(ModelService) -> ModelService,
) -> RunningModeld {
    let dir = scratch(&format!("{name}-run"));
    let (cert, key, _) = server;
    let tls = server_tls(cert.as_bytes(), key.as_bytes(), pki.tls_ca.pem().as_bytes()).unwrap();
    let mut allow = AllowList::new();
    for fp in allowed {
        allow.allow(fp, "test");
    }
    let oplog = dir.join("modeld-oplog.tsv");
    let bundle = test_bundle(&format!("{name}-bundle"));
    let bundle_id = bundle.id.clone();
    let service = configure(ModelService::new(
        bundle,
        allow,
        OpLog::open(&oplog).unwrap(),
        limits,
    ));
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

pub fn call() -> Call {
    Call {
        account: "acc-0001".into(),
        job: "job-0001".into(),
        deadline: Duration::from_secs(20),
    }
}

/// A scratch directory deleted when dropped, so a test leaves nothing behind.
#[derive(Debug)]
pub struct ScratchDir(pub PathBuf);

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The model bundle named by `OPENSEAL_MODELD_TEST_BUNDLE` (a directory fetched by
/// `tools/ml/fetch-models.py`), with only the files its `bundle.json` lists hard-linked
/// (copied only where a link cannot be made) into a scratch directory, and verified
/// against a manifest built from that `bundle.json`. The directory is deleted when the
/// returned [`ScratchDir`] drops, so no copy of the weights outlives the test (rules 34,
/// 35). `None`, with a message, when the variable is unset: tests that need real weights
/// are skipped then, never passed.
pub fn real_bundle(name: &str, profiles: &[&str]) -> Option<(Bundle, ScratchDir)> {
    let Some(src) = std::env::var_os("OPENSEAL_MODELD_TEST_BUNDLE") else {
        eprintln!("SKIPPED: OPENSEAL_MODELD_TEST_BUNDLE is unset; no model weights to run");
        return None;
    };
    let src = PathBuf::from(src);
    let info: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(src.join("bundle.json")).unwrap()).unwrap();
    let dir = ScratchDir(scratch(name));
    let mut manifest = String::from("# test bundle from bundle.json\n");
    for f in info["files"].as_array().unwrap() {
        let s = |k: &str| f[k].as_str().unwrap().to_owned();
        let (dest, bytes) = (s("dest"), f["bytes"].as_u64().unwrap());
        let to = dir.0.join(&dest);
        std::fs::create_dir_all(to.parent().unwrap()).unwrap();
        if std::fs::hard_link(src.join(&dest), &to).is_err() {
            std::fs::copy(src.join(&dest), &to).unwrap();
        }
        manifest.push_str(&format!(
            "{}\t{}\t{}\t{bytes}\t{}\t{dest}\n",
            s("id"),
            s("profile"),
            s("sha256"),
            s("licence").split_whitespace().next().unwrap()
        ));
    }
    let profiles: Vec<String> = profiles.iter().map(|p| (*p).to_owned()).collect();
    let bundle = Bundle::verify(&dir.0, &Manifest::parse(&manifest).unwrap(), &profiles).unwrap();
    Some((bundle, dir))
}
