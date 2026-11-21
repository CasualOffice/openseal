//! Write `fixtures/sealed`: PDFs sealed by `casual-sign-seal` at every PAdES baseline
//! level, with P-256 and RSA-3072 keys, approval and certification (P1, P2, P3)
//! signatures, two sequential signatures, visible and invisible widgets, an existing
//! form field, normalized hostile `valid*.pdf` inputs, an augmentation and a renewal.
//!
//! ```sh
//! python3 -I fixtures/sealed/gen.py    # runs this with the valid*.pdf inputs
//! cargo run -p casual-sign-seal --example gen_sealed -- <inputs dir> <out dir>
//! ```
//!
//! The PKI, TSA and OCSP responder are in-process and thrown away (`tests/common`): no
//! private key is written. Writes each PDF, `manifest.tsv` (file, expect, why, level,
//! ours) and `trust-root.pem`/`.der`, and prints our verifier's verdict per signature.

// A tool, not product code: a failure stops it with the reason.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    missing_docs
)]

#[path = "../tests/common/mod.rs"]
mod common;
#[path = "../tests/common/remote.rs"]
mod remote;

use std::path::{Path, PathBuf};

use casual_sign_crypto::KeyProvider;
use casual_sign_pdf::{Limits, NormalizeOptions, OutputXref, admit, normalize};
use casual_sign_seal::{
    Appearance, ArchiveOptions, DocMdp, NoRevocation, NoTimestamps, Profile, Rect, SealKind,
    SealRequest, Visible, augment, renew_lta, seal,
};
use casual_sign_verify::{Indication, VerifyOptions, verify};
use common::*;

fn never() -> bool {
    false
}

fn level(p: Profile) -> &'static str {
    match p {
        Profile::BaselineB => "B-B",
        Profile::BaselineT => "B-T",
        Profile::BaselineLt => "B-LT",
        Profile::BaselineLta => "B-LTA",
    }
}

fn expected_ours(p: Profile) -> &'static str {
    if p >= Profile::BaselineLt {
        "TOTAL_PASSED"
    } else {
        "INDETERMINATE:TRY_LATER"
    }
}

fn request(profile: Profile, field: &str) -> SealRequest {
    let mut r = SealRequest::new(profile, field, SIGNING_TIME);
    r.name = Some("OpenSeal test platform".into());
    r.reason = Some("Agreement completed".into());
    r.location = Some("Test fixture".into());
    r.trust = trust();
    r
}

fn visible(appearance: Appearance) -> Visible {
    Visible {
        page: 0,
        rect: Rect {
            llx: 72.0,
            lly: 300.0,
            urx: 272.0,
            ury: 350.0,
        },
        appearance,
    }
}

fn normalized(path: &Path, xref: OutputXref) -> Vec<u8> {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut a = admit(&bytes, &Limits::default(), &never).unwrap();
    normalize(&mut a, &NormalizeOptions::with_xref(xref), &never)
        .unwrap()
        .bytes
}

struct Out {
    dir: PathBuf,
    rows: Vec<String>,
}

impl Out {
    fn put(&mut self, name: &str, input: &[u8], bytes: &[u8], p: Profile, why: &str) {
        assert!(bytes.starts_with(input), "{name}: input is not a prefix");
        std::fs::write(self.dir.join(name), bytes).unwrap();
        let ours = expected_ours(p);
        let report = verify(bytes, &trust(), &VerifyOptions::at(VALIDATION_TIME));
        for (i, s) in report.signatures.iter().enumerate() {
            let got = match s.indication {
                Indication::TotalPassed => "TOTAL_PASSED".to_string(),
                Indication::TotalFailed(r) | Indication::Indeterminate(r) => {
                    format!("{}:{}", s.indication.name(), r.sub.name())
                }
            };
            println!("{name}\t{i}\t{:?}\t{got}", s.kind);
            assert_eq!(got, ours, "{name} signature {i}");
        }
        self.rows
            .push(format!("{name}\tintact\t{why}\t{}\t{ours}", level(p)));
    }

    /// A B-LT file changed after signing: every validator must refuse it; ours gives
    /// the same verdict for every signature, recorded in the manifest.
    fn put_tampered(&mut self, name: &str, input: &[u8], bytes: &[u8], why: &str) {
        assert!(bytes.starts_with(input), "{name}: input is not a prefix");
        std::fs::write(self.dir.join(name), bytes).unwrap();
        let report = verify(bytes, &trust(), &VerifyOptions::at(VALIDATION_TIME));
        let mut verdict: Option<String> = None;
        for (i, s) in report.signatures.iter().enumerate() {
            let got = match s.indication {
                Indication::TotalPassed => "TOTAL_PASSED".to_string(),
                Indication::TotalFailed(r) | Indication::Indeterminate(r) => {
                    format!("{}:{}", s.indication.name(), r.sub.name())
                }
            };
            println!("{name}\t{i}\t{:?}\t{got}", s.kind);
            assert_ne!(got, "TOTAL_PASSED", "{name} signature {i}");
            assert!(verdict.as_ref().is_none_or(|v| *v == got), "{name}");
            verdict = Some(got);
        }
        let ours = verdict.expect("a signature");
        self.rows
            .push(format!("{name}\ttampered\t{why}\tB-LT\t{ours}"));
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let (inputs, out_dir) = match args.as_slice() {
        [i, o] => (Some(PathBuf::from(i)), PathBuf::from(o)),
        [o] => (None, PathBuf::from(o)),
        _ => panic!("usage: gen_sealed [<inputs dir>] <out dir>"),
    };
    std::fs::create_dir_all(&out_dir).unwrap();
    let mut out = Out {
        dir: out_dir.clone(),
        rows: Vec::new(),
    };
    let rev = TestRevocation::default();
    let page = one_page("Agreement between the parties");

    // Each profile with each key, approval, invisible.
    let keys: [(&str, Box<dyn KeyProvider>); 2] =
        [("p256", Box::new(p256())), ("rsa3072", Box::new(rsa()))];
    for (label, key) in &keys {
        for p in [
            Profile::BaselineB,
            Profile::BaselineT,
            Profile::BaselineLt,
            Profile::BaselineLta,
        ] {
            let tsa = TestTsa::new(SIGNING_TIME);
            let s = if p == Profile::BaselineB {
                seal(
                    &page,
                    &request(p, "Seal1"),
                    key.as_ref(),
                    &NoTimestamps,
                    &NoRevocation,
                )
            } else {
                seal(&page, &request(p, "Seal1"), key.as_ref(), &tsa, &rev)
            }
            .unwrap();
            let name = format!(
                "{label}-approval-{}.pdf",
                level(p).to_lowercase().replace('-', "")
            );
            out.put(
                &name,
                &page,
                &s.bytes,
                p,
                &format!("{label} approval signature, invisible, {}", level(p)),
            );
        }
    }

    // Certification at each DocMDP level.
    for (docmdp, key, keyname, p) in [
        (DocMdp::P1, &keys[0].1, "p256", Profile::BaselineLt),
        (DocMdp::P1, &keys[1].1, "rsa3072", Profile::BaselineLta),
        (DocMdp::P2, &keys[0].1, "p256", Profile::BaselineLta),
        (DocMdp::P3, &keys[1].1, "rsa3072", Profile::BaselineLt),
    ] {
        let mut r = request(p, "Certification");
        r.kind = SealKind::Certification { docmdp };
        let tsa = TestTsa::new(SIGNING_TIME);
        let s = seal(&page, &r, key.as_ref(), &tsa, &rev).unwrap();
        let n = docmdp.level();
        out.put(
            &format!(
                "{keyname}-certified-p{n}-{}.pdf",
                level(p).to_lowercase().replace('-', "")
            ),
            &page,
            &s.bytes,
            p,
            &format!("certification signature DocMDP P={n}, {}", level(p)),
        );
    }

    // Two sequential signatures: certification P=2 then an approval, each at B-LT.
    {
        let tsa = TestTsa::new(SIGNING_TIME);
        let mut r = request(Profile::BaselineLt, "Certification");
        r.kind = SealKind::Certification { docmdp: DocMdp::P2 };
        let first = seal(&page, &r, keys[0].1.as_ref(), &tsa, &rev).unwrap();
        let second = seal(
            &first.bytes,
            &request(Profile::BaselineLt, "Approval2"),
            keys[1].1.as_ref(),
            &tsa,
            &rev,
        )
        .unwrap();
        out.put(
            "two-signatures-blt.pdf",
            &page,
            &second.bytes,
            Profile::BaselineLt,
            "certification P=2 (P-256) then approval (RSA-3072), each B-LT",
        );
    }

    // Visible widget with a border; an existing form field with a drawn appearance.
    {
        let tsa = TestTsa::new(SIGNING_TIME);
        let mut r = request(Profile::BaselineLt, "Seal1");
        r.visible = Some(visible(Appearance::Border));
        let s = seal(&page, &r, keys[0].1.as_ref(), &tsa, &rev).unwrap();
        out.put(
            "p256-visible-blt.pdf",
            &page,
            &s.bytes,
            Profile::BaselineLt,
            "visible approval signature (bordered widget on page 1), B-LT",
        );
        let form = form_pdf();
        let mut r = request(Profile::BaselineLta, "Signer1");
        r.visible = Some(visible(Appearance::Content {
            content: b"q 0.9 0.95 1 rg 0 0 200 50 re f 0 0 0.6 RG 2 w 4 4 192 42 re S Q".to_vec(),
            resources: None,
        }));
        let s = seal(&form, &r, keys[0].1.as_ref(), &tsa, &rev).unwrap();
        out.put(
            "form-existing-field-blta.pdf",
            &form,
            &s.bytes,
            Profile::BaselineLta,
            "the form's own empty signature field, visible, B-LTA",
        );
    }

    // Augmentation (B-T sealed, B-LTA later) and an LTA renewal.
    {
        let tsa = TestTsa::new(SIGNING_TIME);
        let bt = seal(
            &page,
            &request(Profile::BaselineT, "Seal1"),
            keys[0].1.as_ref(),
            &tsa,
            &rev,
        )
        .unwrap();
        let options = ArchiveOptions {
            time: SIGNING_TIME,
            trust: trust(),
            limits: Limits::default(),
        };
        let lta = augment(&bt.bytes, Profile::BaselineLta, &options, &tsa, &rev).unwrap();
        out.put(
            "p256-augmented-bt-to-blta.pdf",
            &page,
            &lta.bytes,
            Profile::BaselineLta,
            "sealed at B-T, augmented to B-LTA later (docs/31 §9)",
        );
        let renewed = renew_lta(&lta.bytes, &options, &tsa, &rev).unwrap();
        out.put(
            "p256-renewed-blta.pdf",
            &page,
            &renewed.bytes,
            Profile::BaselineLta,
            "B-LTA renewed: DSS for the first document timestamp, then a second",
        );
    }

    // Normalized hostile controls.
    if let Some(dir) = inputs {
        for (file, xref, p, key) in [
            ("valid.pdf", OutputXref::Table, Profile::BaselineLta, 0usize),
            (
                "valid_xrefstream.pdf",
                OutputXref::Stream,
                Profile::BaselineLt,
                1,
            ),
        ] {
            let input = normalized(&dir.join(file), xref);
            let tsa = TestTsa::new(SIGNING_TIME);
            let s = seal(
                &input,
                &request(p, "Seal1"),
                keys[key].1.as_ref(),
                &tsa,
                &rev,
            )
            .unwrap();
            let stem = file.trim_end_matches(".pdf").replace('_', "-");
            out.put(
                &format!(
                    "{stem}-normalized-{}.pdf",
                    level(p).to_lowercase().replace('-', "")
                ),
                &input,
                &s.bytes,
                p,
                &format!(
                    "fixtures/hostile/{file} normalized ({xref:?} xref), {}",
                    level(p)
                ),
            );
        }
    }

    // Remote-provider signatures (RSP-01, ADR-046 §3.2): the lock point's form, each
    // remote signer's fill and signature through prepare/complete (the test key in the
    // provider's place), later fills, the platform seal last.
    for (name, scenario, p, why) in [
        (
            "remote-csc-simple-remote-simple-blt.pdf",
            remote::Scenario::SimpleRemoteSimple,
            Profile::BaselineLt,
            "simple signer flattened, remote signer (P-256, B-LT) over the materialized form, later simple signer filled in place, platform seal B-LT",
        ),
        (
            "remote-csc-two-remote-blta.pdf",
            remote::Scenario::TwoRemote,
            Profile::BaselineLta,
            "two remote signers (P-256, RSA-3072; each B-LT) with a simple signer filled between them, platform seal B-LTA",
        ),
        // India eSign (RSP-02, ADR-047 §3.3): the ESP's own PKCS7pdf CMS embedded.
        (
            "remote-esign-cades-blt.pdf",
            remote::Scenario::EsignCades,
            Profile::BaselineLt,
            "eSign signer (P-256): an ESP's CAdES-like CMS as ETSI.CAdES.detached, our time-stamp, DSS; platform seal B-LT",
        ),
        (
            "remote-esign-adobe-pkcs7-blt.pdf",
            remote::Scenario::EsignAdobe,
            Profile::BaselineLt,
            "eSign signer (RSA-3072): an ESP's Adobe-like CMS (signingTime, no ESS) as adbe.pkcs7.detached, our time-stamp, DSS; platform seal B-LT",
        ),
        (
            "remote-esign-esp-timestamped-blt.pdf",
            remote::Scenario::EsignTimestamped,
            Profile::BaselineLt,
            "eSign signer (P-256): an ESP's CAdES-like CMS carrying its own signature time-stamp, kept; DSS; platform seal B-LT",
        ),
    ] {
        let built = remote::build(scenario, p);
        out.put(name, &[], &built.bytes, p, why);
        if scenario == remote::Scenario::EsignAdobe {
            let changed =
                remote::page_content_change(&built.after_first_remote, &built.later_field);
            out.put_tampered(
                "remote-esign-page-changed-after-signing-blt.pdf",
                &built.after_first_remote,
                &changed,
                "a value drawn into page content after the eSign signature (B-LT): disallowed",
            );
        }
        if scenario == remote::Scenario::SimpleRemoteSimple {
            // The tampered counterpart every validator must refuse (rule 26): a later
            // signer's value drawn into page content after the remote signature.
            let changed =
                remote::page_content_change(&built.after_first_remote, &built.later_field);
            out.put_tampered(
                "remote-csc-page-changed-after-signing-blt.pdf",
                &built.after_first_remote,
                &changed,
                "a value drawn into page content after the remote signature (B-LT): disallowed",
            );
        }
    }

    let mut manifest = String::from("file\texpect\twhy\tlevel\tours\n");
    for r in &out.rows {
        manifest.push_str(r);
        manifest.push('\n');
    }
    std::fs::write(out_dir.join("manifest.tsv"), manifest).unwrap();
    std::fs::write(out_dir.join("trust-root.pem"), root_pem()).unwrap();
    std::fs::write(out_dir.join("trust-root.der"), der_of(&pki().root)).unwrap();
    println!(
        "gen_sealed: {} files in {}",
        out.rows.len(),
        out_dir.display()
    );
}
