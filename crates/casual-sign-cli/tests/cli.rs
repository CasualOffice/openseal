//! `openseal` end to end (`T-1J`): each command run as a process, its exit code and its
//! output checked. A throwaway PKI is written to a temporary directory; the TSA is
//! casual-sign-seal's in-process test TSA served over HTTP on 127.0.0.1, so `seal
//! --tsa` goes through the real HTTP path.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    missing_docs
)]

#[path = "../../casual-sign-seal/tests/common/mod.rs"]
mod common;

use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use casual_sign_seal::TimestampSource;
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, CertifiedIssuer,
    DistinguishedName, DnType, IsCa, KeyIdMethod, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
    SerialNumber,
};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_openseal")
}

fn run(args: &[&str]) -> Output {
    Command::new(bin()).args(args).output().unwrap()
}

fn code(o: &Output) -> i32 {
    o.status.code().unwrap()
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn json(o: &Output) -> serde_json::Value {
    serde_json::from_slice(&o.stdout).unwrap_or_else(|e| panic!("{e}: {}", stdout(o)))
}

/// A directory under target/ for this test binary, emptied once.
fn dir() -> &'static Path {
    static D: OnceLock<PathBuf> = OnceLock::new();
    D.get_or_init(|| {
        let d = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("openseal-cli");
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    })
}

fn path(name: &str) -> String {
    dir().join(name).to_str().unwrap().to_owned()
}

/// The signer's PKI, written as PEM: root (self-signed) -> seal certificate, and a CRL
/// from the root. Also the seal test PKI's root (the TSA's) and its CRLs.
struct Files {
    key: String,
    chain: String,
    root: String,
    crl: String,
    tsa_root: String,
    tsa_crls: [String; 2],
}

fn files() -> &'static Files {
    static F: OnceLock<Files> = OnceLock::new();
    F.get_or_init(|| {
        let params = |cn: &str, serial: u64| {
            let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
            let mut d = DistinguishedName::new();
            d.push(DnType::CommonName, cn);
            d.push(DnType::OrganizationName, "OpenSeal CLI throwaway test PKI");
            p.distinguished_name = d;
            p.not_before = rcgen::date_time_ymd(2026, 1, 1);
            p.not_after = rcgen::date_time_ymd(2046, 1, 1);
            p.serial_number = Some(SerialNumber::from(serial));
            p.key_identifier_method = KeyIdMethod::Sha256;
            p
        };
        let root_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut rp = params("CLI Test Root", 1);
        rp.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        rp.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let root = CertifiedIssuer::self_signed(rp, root_key).unwrap();
        let leaf_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut lp = params("CLI Test Seal", 2);
        lp.is_ca = IsCa::ExplicitNoCa;
        lp.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::ContentCommitment,
        ];
        lp.use_authority_key_identifier_extension = true;
        let leaf = lp.signed_by(&leaf_key, &root).unwrap();
        let crl = CertificateRevocationListParams {
            this_update: rcgen::date_time_ymd(2026, 1, 2),
            next_update: rcgen::date_time_ymd(2046, 1, 1),
            crl_number: SerialNumber::from(1u64),
            issuing_distribution_point: None,
            revoked_certs: Vec::new(),
            key_identifier_method: KeyIdMethod::Sha256,
        }
        .signed_by(&root)
        .unwrap();
        let f = Files {
            key: path("key.pem"),
            chain: path("chain.pem"),
            root: path("root.pem"),
            crl: path("root.crl"),
            tsa_root: path("tsa-root.pem"),
            tsa_crls: [path("tsa-root.crl"), path("tsa-inter.crl")],
        };
        std::fs::write(&f.key, leaf_key.serialize_pem()).unwrap();
        std::fs::write(&f.chain, format!("{}{}", leaf.pem(), root.pem())).unwrap();
        std::fs::write(&f.root, root.pem()).unwrap();
        std::fs::write(&f.crl, crl.der()).unwrap();
        std::fs::write(&f.tsa_root, common::root_pem()).unwrap();
        std::fs::write(&f.tsa_crls[0], &common::pki().root_crl).unwrap();
        std::fs::write(&f.tsa_crls[1], &common::pki().inter_crl).unwrap();
        f
    })
}

fn now() -> Duration {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap()
}

/// An RFC 3161 TSA over HTTP on 127.0.0.1: the test TSA answering each POST.
fn tsa_url() -> &'static str {
    static U: OnceLock<String> = OnceLock::new();
    U.get_or_init(|| {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let start = now();
        std::thread::spawn(move || {
            let tsa = common::TestTsa::new(start);
            for stream in listener.incoming() {
                let Ok(mut s) = stream else { continue };
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                let (head_end, length) = loop {
                    let n = s.read(&mut chunk).unwrap_or(0);
                    if n == 0 {
                        break (None, 0);
                    }
                    buf.extend_from_slice(&chunk[..n]);
                    if let Some(at) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                        let head = String::from_utf8_lossy(&buf[..at]).to_ascii_lowercase();
                        let len = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        break (Some(at + 4), len);
                    }
                };
                let Some(start) = head_end else { continue };
                while buf.len() < start + length {
                    let n = s.read(&mut chunk).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&chunk[..n]);
                }
                let body = &buf[start..(start + length).min(buf.len())];
                let (status, answer) = match tsa.timestamp(body) {
                    Ok(a) => ("200 OK", a),
                    Err(_) => ("500 Internal Server Error", Vec::new()),
                };
                let _ = write!(
                    s,
                    "HTTP/1.1 {status}\r\nContent-Type: application/timestamp-reply\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    answer.len()
                );
                let _ = s.write_all(&answer);
            }
        });
        format!("http://127.0.0.1:{port}/tsa")
    })
}

/// A one-page document with an AcroForm text field `Name` and a checkbox `Agree`.
fn form_pdf() -> Vec<u8> {
    common::classic_pdf(&[
        b"<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [4 0 R 5 0 R] >> >>".to_vec(),
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots [4 0 R 5 0 R] >>".to_vec(),
        b"<< /FT /Tx /T (Name) /Type /Annot /Subtype /Widget /Rect [72 700 320 720] /P 3 0 R /F 4 >>".to_vec(),
        b"<< /FT /Btn /T (Agree) /Type /Annot /Subtype /Widget /Rect [72 660 90 678] /P 3 0 R /F 4 /AP << /N << /Yes 6 0 R /Off 6 0 R >> >> >>".to_vec(),
        b"<< /Type /XObject /Subtype /Form /BBox [0 0 18 18] /Length 0 >>\nstream\n\nendstream".to_vec(),
    ])
}

fn write(name: &str, bytes: &[u8]) -> String {
    let p = path(name);
    std::fs::write(&p, bytes).unwrap();
    p
}

/// A normalized one-page document, made with the CLI.
fn normalized(name: &str) -> String {
    let input = write(&format!("{name}.in.pdf"), &common::one_page("Agreement"));
    let out = path(&format!("{name}.pdf"));
    let o = run(&["normalize", &input, &out]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    out
}

fn seal_args<'a>(input: &'a str, out: &'a str, f: &'a Files) -> Vec<&'a str> {
    vec![
        "seal",
        input,
        out,
        "--key",
        &f.key,
        "--cert",
        &f.chain,
        "--insecure-file-key",
        "--trust",
        &f.root,
        "--trust",
        &f.tsa_root,
    ]
}

#[test]
fn help_lists_exit_codes_and_json() {
    let o = run(&["help"]);
    assert_eq!(code(&o), 0);
    assert!(stdout(&o).contains("EXIT CODES"));
    assert!(stdout(&o).contains("JSON"));
    assert_eq!(code(&run(&[])), 2);
    assert_eq!(code(&run(&["frobnicate"])), 2);
    assert_eq!(code(&run(&["admit", "--nope", "x.pdf"])), 2);
    assert_eq!(code(&run(&["admit", "/nonexistent/x.pdf"])), 2);
}

#[test]
fn admit_reports_and_refuses_with_a_code() {
    let good = write("admit.pdf", &common::one_page("Hello"));
    let o = run(&["admit", &good, "--json"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let v = json(&o);
    assert_eq!(v["admitted"], true);
    assert_eq!(v["pages"], 1);
    assert_eq!(v["signed"], false);
    let bad = write("garbage.pdf", b"this is not a PDF at all");
    let o = run(&["admit", &bad, "--json"]);
    assert_eq!(code(&o), 3);
    let v = json(&o);
    assert_eq!(v["admitted"], false);
    assert!(v["code"].as_str().unwrap().starts_with("CS-PDF-"));
}

#[test]
fn normalize_writes_the_delivered_document() {
    let input = write("norm.in.pdf", &common::one_page("Hello"));
    let out = path("norm.pdf");
    let o = run(&["normalize", &input, &out, "--json"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let v = json(&o);
    assert_eq!(v["sha256"].as_str().unwrap().len(), 64);
    assert!(std::fs::read(&out).unwrap().starts_with(b"%PDF-"));
}

#[test]
fn fill_converts_fills_and_flattens() {
    let input = write("form.in.pdf", &form_pdf());
    let delivered = path("form.pdf");
    assert_eq!(code(&run(&["normalize", &input, &delivered])), 0);
    let values = write("values.json", br#"{"Name": "Ada Lovelace", "Agree": true}"#);
    let out = path("form.filled.pdf");
    let o = run(&["fill", &delivered, &out, "--values", &values, "--json"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let v = json(&o);
    assert_eq!(v["converted"], 2);
    assert_eq!(v["drawn"], 2);
    let filled = std::fs::read(&out).unwrap();
    assert!(filled.starts_with(&std::fs::read(&delivered).unwrap()));
    // A name the document does not have, and a value of the wrong kind, are refused.
    let unknown = write("unknown.json", br#"{"Nmae": "x"}"#);
    let o = run(&["fill", &delivered, &out, "--values", &unknown]);
    assert_eq!(code(&o), 2);
    assert!(stderr(&o).contains("Nmae"));
    let wrong = write("wrong.json", br#"{"Agree": "yes"}"#);
    assert_eq!(
        code(&run(&["fill", &delivered, &out, "--values", &wrong])),
        2
    );
    let wrong = write("wrong2.json", br#"{"Name": true}"#);
    assert_eq!(
        code(&run(&["fill", &delivered, &out, "--values", &wrong])),
        2
    );
    // A required field left empty: refused by the engine with its code when complete
    // values are required.
    let fields = write(
        "fields.json",
        br#"[{"id": "extra", "document_id": "doc", "type": "text", "required": true,
             "placement": {"page": 1, "x": "72", "y": "200", "width": "200", "height": "20"}}]"#,
    );
    let o = run(&[
        "fill",
        &delivered,
        &out,
        "--values",
        &values,
        "--fields",
        &fields,
        "--require-complete",
    ]);
    assert_eq!(code(&o), 3, "{}", stderr(&o));
    assert!(stderr(&o).contains("CS-FLD-0001"), "{}", stderr(&o));
}

#[test]
fn seal_refuses_a_key_file_without_the_flag() {
    let f = files();
    let input = normalized("refuse");
    let out = path("refuse.sealed.pdf");
    let o = run(&[
        "seal",
        &input,
        &out,
        "--key",
        &f.key,
        "--cert",
        &f.chain,
        "--profile",
        "b-b",
    ]);
    assert_eq!(code(&o), 2);
    assert!(stderr(&o).contains("--insecure-file-key"));
    assert!(!Path::new(&out).exists());
    // No --reason with a file key, and b-t needs a TSA.
    let mut a = seal_args(&input, &out, f);
    a.extend(["--profile", "b-b", "--reason", "mine"]);
    assert_eq!(code(&run(&a)), 2);
    let mut a = seal_args(&input, &out, f);
    a.extend(["--profile", "b-t"]);
    assert_eq!(code(&run(&a)), 2);
}

#[test]
fn normalize_prints_a_certified_document_to_new() {
    let f = files();
    let input = normalized("p2n");
    let certified = path("p2n.certified.pdf");
    let mut a = seal_args(&input, &certified, f);
    a.extend([
        "--profile",
        "b-b",
        "--certify",
        "p1",
        "--field",
        "Certifier",
    ]);
    let o = run(&a);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let out = path("p2n.printed.pdf");
    let o = run(&["normalize", &certified, &out, "--json"]);
    assert_eq!(code(&o), 3, "signed input is refused without the flag");
    assert_eq!(json(&o)["error"]["code"], "CS-PDF-0014");
    let o = run(&["normalize", &certified, &out, "--print-to-new", "--json"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let v = json(&o);
    assert_eq!(v["printed"]["docmdp"], 1);
    assert_eq!(v["printed"]["signatures"][0]["field_name"], "Certifier");
    assert_eq!(v["printed"]["signatures"][0]["kind"], "certification");
    assert_eq!(v["printed"]["original_sha256"].as_str().unwrap().len(), 64);
    let o = run(&["admit", &out, "--json"]);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let v = json(&o);
    assert_eq!(v["signed"], false);
    assert_eq!(v["fields"], 0);
    assert_eq!(v["revisions"], 1);
    // The new document seals like any other.
    let sealed = path("p2n.sealed.pdf");
    let mut a = seal_args(&out, &sealed, f);
    a.extend(["--profile", "b-b"]);
    let o = run(&a);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
}

#[test]
fn seal_b_b_then_verify_indeterminate_without_revocation() {
    let f = files();
    let input = normalized("bb");
    let out = path("bb.sealed.pdf");
    let mut a = seal_args(&input, &out, f);
    a.extend(["--profile", "b-b", "--json"]);
    let o = run(&a);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(json(&o)["profile"], "PAdES-BASELINE-B");
    let sealed = std::fs::read(&out).unwrap();
    assert!(sealed.starts_with(&std::fs::read(&input).unwrap()));
    // /Reason is the development reason, a UTF-16BE text string written in hex.
    let reason: String = std::iter::once("<FEFF".to_owned())
        .chain(
            "Development key \u{2014} not for production"
                .encode_utf16()
                .map(|u| format!("{u:04X}")),
        )
        .chain(std::iter::once(">".to_owned()))
        .collect();
    let at = sealed
        .windows(7)
        .position(|w| w == b"/Reason")
        .expect("a /Reason");
    assert!(
        sealed[at + 7..]
            .trim_ascii_start()
            .starts_with(reason.as_bytes()),
        "{}",
        String::from_utf8_lossy(&sealed[at..at + 120])
    );
    let o = run(&["verify", &out, "--trust", &f.root, "--json"]);
    assert_eq!(code(&o), 4, "{}", stdout(&o));
    let v = json(&o);
    assert_eq!(v["outcome"], "indeterminate");
    assert_eq!(v["signatures"][0]["verdict"]["subindication"], "TRY_LATER");
    // With the root's CRL supplied it passes.
    let o = run(&["verify", &out, "--trust", &f.root, "--crl", &f.crl]);
    assert_eq!(code(&o), 0, "{}", stdout(&o));
    // Without the trust root the chain is not found.
    let o = run(&["verify", &out, "--json"]);
    assert_eq!(code(&o), 4);
}

#[test]
fn seal_b_t_over_http_tsa_then_verify_and_detect_tamper() {
    let f = files();
    let input = normalized("bt");
    let out = path("bt.sealed.pdf");
    let mut a = seal_args(&input, &out, f);
    let url = tsa_url();
    a.extend([
        "--tsa",
        "http://127.0.0.1:9/unreachable",
        "--tsa",
        url,
        "--json",
    ]);
    let o = run(&a);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    let v = json(&o);
    assert_eq!(v["profile"], "PAdES-BASELINE-T");
    assert!(v["signature_timestamp"].as_u64().is_some());
    // The first TSA failed and the second answered.
    assert!(stderr(&o).contains("unreachable"));
    let o = run(&[
        "verify",
        &out,
        "--trust",
        &f.root,
        "--trust",
        &f.tsa_root,
        "--crl",
        &f.crl,
        "--crl",
        &f.tsa_crls[0],
        "--crl",
        &f.tsa_crls[1],
        "--json",
    ]);
    assert_eq!(code(&o), 0, "{}", stdout(&o));
    let v = json(&o);
    assert_eq!(v["outcome"], "passed");
    assert_eq!(v["signatures"][0]["checks"]["timestamp"], "passed");
    assert_eq!(v["covered_by_last_signature"], true);
    // A byte flipped inside the signed range: failed.
    let mut bytes = std::fs::read(&out).unwrap();
    let at = std::fs::read(&input).unwrap().len() / 2;
    bytes[at] ^= 0x01;
    let bad = write("bt.flipped.pdf", &bytes);
    let o = run(&["verify", &bad, "--trust", &f.root, "--trust", &f.tsa_root]);
    assert_eq!(code(&o), 1, "{}", stdout(&o));
    // Sealing again appends a second signature in a new field.
    let twice = path("bt.twice.pdf");
    let mut a = seal_args(&out, &twice, f);
    a.extend(["--tsa", url, "--json"]);
    let o = run(&a);
    assert_eq!(code(&o), 0, "{}", stderr(&o));
    assert_eq!(json(&o)["field"], "OpenSeal1");
}

#[test]
fn audit_verify_detects_an_edit() {
    use casual_sign_sdk::evidence::{Actor, Chain, Context, EventData, Timestamp};
    use casual_sign_sdk::model::Id;
    let mut c = Chain::new(Id::new("env-1").unwrap());
    for (i, data) in [
        EventData::EnvelopeCreated {
            subject_hash: casual_sign_sdk::Hash256::digest(b"s"),
        },
        EventData::EnvelopeCompleting {},
    ]
    .into_iter()
    .enumerate()
    {
        let e = c.next(
            Timestamp::from_unix_millis(1_794_301_200_000 + i as i64 * 1000).unwrap(),
            Actor::system(),
            Context::default(),
            data,
        );
        c.append(e).unwrap();
    }
    let trail = c.to_trail_json().unwrap();
    let good = write("trail.json", &trail);
    let o = run(&["audit", "verify", &good, "--json"]);
    assert_eq!(code(&o), 0, "{}", stdout(&o));
    assert_eq!(json(&o)["events"], 2);
    let head = c.head().unwrap().hex();
    assert_eq!(code(&run(&["audit", "verify", &good, "--head", &head])), 0);
    let edited = String::from_utf8(trail)
        .unwrap()
        .replacen("env-1", "env-2", 1);
    let bad = write("trail-edited.json", edited.as_bytes());
    let o = run(&["audit", "verify", &bad]);
    assert_eq!(code(&o), 1, "{}", stdout(&o));
    assert_eq!(code(&run(&["audit", "frob", &good])), 2);
}
