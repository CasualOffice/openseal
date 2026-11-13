//! Test-only throwaway PKI (rcgen, keys in memory), a one-page PDF, a keyd started on a
//! loopback port, and the independent-validator directory (`tools/verify-sealed.py`).
//! Never use outside tests.
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
use std::sync::Arc;
use std::time::Duration;

use casual_sign_crypto::Certificate;
use casual_sign_keyd::{
    AllowList, DigestSigner, Endpoint, KeyService, Keyd, KeydLimits, OpLog, client_tls,
    fingerprint, server_tls,
};
use casual_sign_seal::{NoRevocation, NoTimestamps, Profile, SealRequest, TrustStore, seal};
use casual_sign_verify::{Check, Indication, SubIndication, VerifyOptions, verify};
use der::{Decode, Encode};
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyIdMethod, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
    PublicKeyData, SerialNumber,
};

/// 2026-11-01T12:00:00Z.
pub const SIGNING_TIME: Duration = Duration::from_secs(1_793_534_400);
/// 2026-12-01T00:00:00Z.
pub const VALIDATION_TIME: Duration = Duration::from_secs(1_796_083_200);

fn dn(cn: &str) -> DistinguishedName {
    let mut d = DistinguishedName::new();
    d.push(DnType::CommonName, cn);
    d.push(DnType::OrganizationName, "OpenSeal T-2E throwaway test PKI");
    d
}

fn params(cn: &str, serial: u64) -> CertificateParams {
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name = dn(cn);
    p.not_before = rcgen::date_time_ymd(2026, 1, 1);
    p.not_after = rcgen::date_time_ymd(2046, 1, 1);
    p.serial_number = Some(SerialNumber::from(serial));
    p.key_identifier_method = KeyIdMethod::Sha256;
    p
}

fn ca(cn: &str, serial: u64) -> CertifiedIssuer<'static, KeyPair> {
    let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
    let mut p = params(cn, serial);
    p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    CertifiedIssuer::self_signed(p, key).unwrap()
}

/// A public key held elsewhere (an HSM), for rcgen to certify.
pub struct ExternalPublicKey {
    /// The SPKI `subjectPublicKey` bytes: the uncompressed point, or `RSAPublicKey` DER.
    pub raw: Vec<u8>,
    /// rcgen's algorithm naming the key type (`PKCS_ECDSA_P256_SHA256`, ...).
    pub alg: &'static rcgen::SignatureAlgorithm,
}

impl PublicKeyData for ExternalPublicKey {
    fn der_bytes(&self) -> &[u8] {
        &self.raw
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        self.alg
    }
}

/// The seal CA, which certifies signer keys, and the TLS CAs.
pub struct Pki {
    pub seal_ca: CertifiedIssuer<'static, KeyPair>,
    pub tls_ca: CertifiedIssuer<'static, KeyPair>,
    pub rogue_ca: CertifiedIssuer<'static, KeyPair>,
    serial: std::sync::atomic::AtomicU64,
}

impl Pki {
    pub fn new() -> Self {
        Self {
            seal_ca: ca("T-2E Seal Root", 1),
            tls_ca: ca("T-2E keyd TLS Root", 2),
            rogue_ca: ca("T-2E Rogue Root", 3),
            serial: std::sync::atomic::AtomicU64::new(100),
        }
    }

    fn next_serial(&self) -> u64 {
        self.serial
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
    }

    /// A signer certificate for `key` under the seal CA, as the seal expects (digital
    /// signature and non-repudiation).
    pub fn signer(&self, cn: &str, key: &impl PublicKeyData) -> Certificate {
        let mut p = params(cn, self.next_serial());
        p.is_ca = IsCa::ExplicitNoCa;
        p.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::ContentCommitment,
        ];
        p.use_authority_key_identifier_extension = true;
        let cert = p.signed_by(key, &self.seal_ca).unwrap();
        Certificate::from_der(cert.der()).unwrap()
    }

    pub fn seal_root(&self) -> Certificate {
        Certificate::from_der(self.seal_ca.der()).unwrap()
    }

    pub fn seal_root_pem(&self) -> String {
        self.seal_ca.pem()
    }

    pub fn trust(&self) -> TrustStore {
        let mut t = TrustStore::new();
        t.add_anchor(self.seal_ca.der()).unwrap();
        t
    }

    /// (certificate PEM, key PEM, fingerprint) of a TLS end entity under `issuer`.
    fn tls_entity(
        &self,
        issuer: &CertifiedIssuer<'static, KeyPair>,
        cn: &str,
        server: bool,
    ) -> (String, String, String) {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut p = if server {
            CertificateParams::new(vec!["localhost".to_owned()]).unwrap()
        } else {
            CertificateParams::new(Vec::<String>::new()).unwrap()
        };
        p.distinguished_name = dn(cn);
        p.not_before = rcgen::date_time_ymd(2026, 1, 1);
        p.not_after = rcgen::date_time_ymd(2046, 1, 1);
        p.serial_number = Some(SerialNumber::from(self.next_serial()));
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

    pub fn server_identity(&self) -> (String, String, String) {
        self.tls_entity(&self.tls_ca, "keyd.test", true)
    }

    pub fn client_identity(&self, cn: &str) -> (String, String, String) {
        self.tls_entity(&self.tls_ca, cn, false)
    }

    pub fn rogue_client_identity(&self, cn: &str) -> (String, String, String) {
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

/// A keyd on a loopback port, serving `keys`, answering the clients in `allowed`.
pub struct RunningKeyd {
    pub addr: String,
    pub oplog: PathBuf,
}

pub fn start_keyd(
    pki: &Pki,
    keys: Vec<(&str, Arc<dyn DigestSigner>)>,
    allowed: &[&str],
    limits: KeydLimits,
    dir: &Path,
) -> RunningKeyd {
    start_keyd_with_admin(pki, keys, allowed, &[], limits, dir)
}

/// As [`start_keyd`], with `admins` on the admin allow-list (CON-06).
pub fn start_keyd_with_admin(
    pki: &Pki,
    keys: Vec<(&str, Arc<dyn DigestSigner>)>,
    allowed: &[&str],
    admins: &[&str],
    limits: KeydLimits,
    dir: &Path,
) -> RunningKeyd {
    let (cert, key, _) = pki.server_identity();
    let tls = server_tls(cert.as_bytes(), key.as_bytes(), pki.tls_ca.pem().as_bytes()).unwrap();
    let mut allow = AllowList::new();
    for fp in allowed {
        allow.allow(fp, "test");
    }
    let mut admin = AllowList::new();
    for fp in admins {
        admin.allow(fp, "console");
    }
    let oplog = dir.join("keyd-oplog.tsv");
    let mut service = KeyService::new(allow, OpLog::open(&oplog).unwrap(), limits)
        .with_admin(admin)
        .unwrap();
    for (alias, key) in keys {
        service.add_key(alias, key).unwrap();
    }
    let keyd = Keyd::bind("127.0.0.1:0", tls, service).unwrap();
    let addr = keyd.local_addr().unwrap().to_string();
    std::thread::spawn(move || keyd.serve());
    RunningKeyd { addr, oplog }
}

/// An endpoint for `keyd` with the given client identity (`None`: no certificate).
pub fn endpoint(
    pki: &Pki,
    keyd: &RunningKeyd,
    client: Option<&(String, String, String)>,
) -> Endpoint {
    let tls = client_tls(
        pki.tls_ca.pem().as_bytes(),
        client.map(|(c, k, _)| (c.as_bytes(), k.as_bytes())),
    )
    .unwrap();
    Endpoint {
        addr: keyd.addr.clone(),
        server_name: "localhost".into(),
        tls,
        timeout: Duration::from_secs(10),
    }
}

// ---------------------------------------------------------------- PDFs

/// A classic-xref PDF from object bodies (object 1 is the catalog). As
/// casual-sign-seal's test helper of the same name.
pub fn classic_pdf(objects: &[Vec<u8>]) -> Vec<u8> {
    let mut out = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n".to_vec();
    let mut offsets = Vec::new();
    for (i, body) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    }
    let xref = out.len();
    out.extend_from_slice(
        format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).as_bytes(),
    );
    for o in offsets {
        out.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    out
}

/// A one-page agreement.
pub fn one_page(text: &str) -> Vec<u8> {
    let content = format!("BT /F1 24 Tf 72 720 Td ({text}) Tj ET");
    let mut stream = format!("<< /Length {} >>\nstream\n", content.len()).into_bytes();
    stream.extend_from_slice(content.as_bytes());
    stream.extend_from_slice(b"\nendstream");
    classic_pdf(&[
        b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>".to_vec(),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_vec(),
        stream,
    ])
}

// ---------------------------------------------------------------- sealing

/// Seal a one-page PDF at PAdES B-B through `key`, with the development reason when the
/// key is a development key (docs/31 §5).
pub fn seal_with(
    pki: &Pki,
    key: &dyn casual_sign_crypto::KeyProvider,
    development: bool,
) -> Vec<u8> {
    let input = one_page("Agreement sealed through keyd");
    let mut r = SealRequest::new(Profile::BaselineB, "Seal1", SIGNING_TIME);
    r.name = Some("OpenSeal test platform".into());
    r.reason = Some(if development {
        casual_sign_keyd::DEV_REASON.to_owned()
    } else {
        "Agreement completed".to_owned()
    });
    r.trust = pki.trust();
    let sealed = seal(&input, &r, key, &NoTimestamps, &NoRevocation).unwrap();
    assert!(sealed.bytes.starts_with(&input), "the input is a prefix");
    sealed.bytes
}

/// Our verifier: integrity, the CMS signature and the chain to the seal root all pass;
/// at B-B the only open question is revocation (`INDETERMINATE/TRY_LATER`), as for
/// casual-sign-seal's own B-B fixtures. Returns a one-line summary.
pub fn ours(pki: &Pki, bytes: &[u8]) -> String {
    let report = verify(bytes, &pki.trust(), &VerifyOptions::at(VALIDATION_TIME));
    assert!(report.error.is_none(), "{:?}", report.error);
    assert_eq!(report.signatures.len(), 1);
    assert!(report.covered_by_last_signature);
    let s = &report.signatures[0];
    assert_eq!(s.checks.byte_range, Check::Passed, "byte range");
    assert_eq!(s.checks.digest, Check::Passed, "digest");
    assert_eq!(s.checks.signature, Check::Passed, "signature");
    assert_eq!(s.checks.chain, Check::Passed, "chain");
    match s.indication {
        Indication::Indeterminate(r) => assert_eq!(r.sub, SubIndication::TryLater),
        Indication::TotalPassed => {}
        other => panic!("our verifier: {other:?}"),
    }
    format!(
        "byte_range=Passed digest=Passed signature=Passed chain=Passed indication={:?}",
        s.indication
    )
}

/// Write `files` and a `manifest.tsv` (`level` B-B) with `trust-root.pem`, for
/// `tools/verify-sealed.py`.
pub fn write_validator_dir(pki: &Pki, dir: &Path, files: &[(String, Vec<u8>)]) {
    let mut manifest = String::from("file\texpect\twhy\tlevel\n");
    for (name, bytes) in files {
        std::fs::write(dir.join(name), bytes).unwrap();
        manifest.push_str(&format!("{name}\tintact\tT-2E keyd seal\tB-B\n"));
    }
    std::fs::write(dir.join("manifest.tsv"), manifest).unwrap();
    std::fs::write(dir.join("trust-root.pem"), pki.seal_root_pem()).unwrap();
}

/// Run pyHanko over `dir` through `tools/verify-sealed.py` when
/// `OPENSEAL_VERIFY_PYTHON` names a Python with pyHanko; print a note otherwise. The
/// gate runs it (docs/31 §Verification ladder, rule 26).
pub fn pyhanko(dir: &Path) {
    let Ok(python) = std::env::var("OPENSEAL_VERIFY_PYTHON") else {
        eprintln!(
            "NOTE: OPENSEAL_VERIFY_PYTHON is not set; pyHanko not run over {}",
            dir.display()
        );
        return;
    };
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/verify-sealed.py");
    let out = std::process::Command::new(python)
        .arg("-I")
        .arg(script)
        .arg(dir)
        .output()
        .unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    eprintln!(
        "pyHanko (tools/verify-sealed.py {}):\n{text}",
        dir.display()
    );
    assert!(out.status.success(), "pyHanko disagreed:\n{text}");
}

pub fn der(c: &Certificate) -> Vec<u8> {
    c.to_der().unwrap()
}
