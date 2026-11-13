//! modeld over mTLS (ML-09; `SEC-I12`): who is refused, what INFO answers, what the op log
//! records (counts and ids, never text), busy slots, and ops not yet built. The refusal
//! tests are keyd's (`server/casual-sign-keyd/tests/mtls.rs`), plus a wrong server
//! certificate.
#![cfg(feature = "server")]
// Test code: a panic is the failure report.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use casual_sign_modeld::wire::{EmbedKind, SpanRequest};
use casual_sign_modeld::{ModeldError, ModeldLimits, oplog};
use common::*;

fn setup(name: &str) -> (Pki, RunningModeld, Identity) {
    let pki = Pki::new();
    let worker = pki.client_identity("worker");
    let modeld = start_modeld(
        &pki,
        &pki.server_identity(),
        &[&worker.2],
        ModeldLimits::default(),
        name,
    );
    (pki, modeld, worker)
}

/// **INFO returns the bundle id** and each installed model's hash, and the op log
/// records the call by caller, account and job.
#[test]
fn info_returns_the_bundle_id() {
    let (pki, modeld, worker) = setup("modeld-info");
    let c = client(&pki.tls_ca.pem(), &modeld, Some(&worker));
    let info = c.info(&call()).unwrap();
    assert_eq!(info.bundle_id, modeld.bundle_id);
    assert_eq!(info.bundle_id.len(), 64);
    assert_eq!(info.runtime, "none");
    let ids: Vec<&str> = info.models.iter().map(|(id, _)| id.as_str()).collect();
    assert_eq!(ids, ["det", "rec"]);
    let det = sha_hex(b"synthetic detector bytes");
    assert_eq!(casual_sign_modeld::oplog::hex(&info.models[0].1), det);

    let log = std::fs::read_to_string(&modeld.oplog).unwrap();
    let f: Vec<&str> = log.lines().next().unwrap().split('\t').collect();
    assert_eq!(f[2], worker.2, "caller fingerprint");
    assert_eq!(&f[3..6], ["info", "acc-0001", "job-0001"]);
    assert_eq!(f[9], "ok");
    assert_eq!(f[10], modeld.bundle_id);
    assert_eq!(oplog::verify(&modeld.oplog).unwrap().0, 1);
}

/// **A client without a certificate never completes the handshake.**
#[test]
fn a_client_without_a_certificate_is_refused() {
    let (pki, modeld, _) = setup("modeld-nocert");
    let err = client(&pki.tls_ca.pem(), &modeld, None)
        .info(&call())
        .unwrap_err();
    assert_eq!(err.code(), "CS-ML-0008", "{err}");
}

/// **A client certificate from another CA never completes the handshake.**
#[test]
fn a_client_with_an_untrusted_certificate_is_refused() {
    let (pki, modeld, _) = setup("modeld-rogue-client");
    let rogue = pki.rogue_client_identity("worker");
    let err = client(&pki.tls_ca.pem(), &modeld, Some(&rogue))
        .info(&call())
        .unwrap_err();
    assert_eq!(err.code(), "CS-ML-0008", "{err}");
}

/// **A server certificate the worker does not trust is refused by the worker**: nothing
/// is sent to an impostor modeld.
#[test]
fn a_server_with_an_untrusted_certificate_is_refused() {
    let pki = Pki::new();
    let worker = pki.client_identity("worker");
    let modeld = start_modeld(
        &pki,
        &pki.rogue_server_identity(),
        &[&worker.2],
        ModeldLimits::default(),
        "modeld-rogue-server",
    );
    let err = client(&pki.tls_ca.pem(), &modeld, Some(&worker))
        .info(&call())
        .unwrap_err();
    assert_eq!(err.code(), "CS-ML-0008", "{err}");
    let log = std::fs::read_to_string(&modeld.oplog).unwrap_or_default();
    assert!(log.is_empty(), "nothing reached the service: {log}");
}

/// **A certificate from the right CA but not on the allow list is refused and
/// recorded.**
#[test]
fn a_client_not_on_the_allow_list_is_refused_and_logged() {
    let (pki, modeld, _) = setup("modeld-notlisted");
    let stranger = pki.client_identity("stranger");
    let err = client(&pki.tls_ca.pem(), &modeld, Some(&stranger))
        .info(&call())
        .unwrap_err();
    assert_eq!(err, ModeldError::NotAuthorized, "{err}");
    let log = std::fs::read_to_string(&modeld.oplog).unwrap();
    assert!(
        log.contains(&format!(
            "\t{}\tconnect\t-\t-\t0\t0\t0\tCS-ML-0015\t",
            stranger.2
        )),
        "{log}"
    );
}

/// Every op whose model is not installed (here: no raster child, no models) answers `CS-ML-0010`, and the op log records
/// it by code. **No text sent reaches the log** (a first, narrow `SEC-I05` check; piece M
/// runs it over every output stream).
#[test]
fn ops_not_built_answer_not_installed_and_log_no_text() {
    let (pki, modeld, worker) = setup("modeld-notinstalled");
    let c = client(&pki.tls_ca.pem(), &modeld, Some(&worker));
    let marker = "ZQXMARKER-Ana-Synthetic-Person";
    let span = || SpanRequest {
        text: format!("Agreement with {marker}."),
        labels: vec!["ZQXLABEL party".into()],
        threshold: 5_000,
    };
    let pdf = b"%PDF-1.7 ZQXMARKER".to_vec();
    let results = [
        c.session()
            .and_then(|mut s| s.open_document(&call(), pdf.clone()))
            .map(|_| ()),
        c.embed(&call(), EmbedKind::Passage, vec![marker.into()])
            .map(|_| ()),
        c.entities(&call(), span()).map(|_| ()),
        c.personal(&call(), span()).map(|_| ()),
    ];
    for r in results {
        assert_eq!(r.unwrap_err(), ModeldError::NotInstalled);
    }
    // HASH needs no model (piece I): a PDF that does not open is refused as a raster
    // failure, never a crash, and its bytes are not logged either.
    assert_eq!(
        c.hash(&call(), pdf, vec![0]).unwrap_err().code(),
        "CS-ML-0006"
    );
    let log = std::fs::read_to_string(&modeld.oplog).unwrap();
    assert_eq!(log.lines().count(), 5, "{log}");
    assert!(
        log.lines().take(4).all(|l| l.contains("\tCS-ML-0010\t")),
        "{log}"
    );
    assert!(
        log.lines().nth(4).unwrap().contains("\tCS-ML-0006\t"),
        "{log}"
    );
    assert!(
        log.lines()
            .next()
            .unwrap()
            .contains("\tdoc_open\tacc-0001\tjob-0001\t0\t0\t")
    );
    assert!(!log.contains("ZQXMARKER"), "{log}");
    assert!(!log.contains("ZQXLABEL"), "labels are not logged: {log}");
}

/// **HASH over the wire** (piece I, `ML-05`): the same page gives the same hashes on
/// every call, each page asked for is answered in order, and the op log records the page
/// count, never a hash.
#[test]
fn hash_answers_each_page_and_logs_no_hash() {
    let (pki, modeld, worker) = setup("modeld-hash");
    let c = client(&pki.tls_ca.pem(), &modeld, Some(&worker));
    let pdf = std::fs::read(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/ml/vector/latin-services.pdf"),
    )
    .unwrap();
    let a = c.hash(&call(), pdf.clone(), vec![1, 0]).unwrap();
    let b = c.hash(&call(), pdf, vec![1, 0]).unwrap();
    assert_eq!(a, b);
    assert_eq!(a.iter().map(|h| h.page).collect::<Vec<_>>(), [1, 0]);
    assert_ne!(a[0], a[1], "two different pages");
    let log = std::fs::read_to_string(&modeld.oplog).unwrap();
    assert!(
        log.lines()
            .all(|l| l.contains("\thash\t") && l.contains("\tok\t")),
        "{log}"
    );
    for h in &a {
        assert!(!log.contains(&format!("{:016x}", h.dhash)), "{log}");
        assert!(!log.contains(&h.dhash.to_string()), "{log}");
    }
}

/// **EMBED over the wire** (piece I, `ML-05`), with real weights
/// (`OPENSEAL_MODELD_TEST_BUNDLE`; skipped when unset): one unit vector of 384 per text,
/// in order, equal to the Python reference within 1e-3 cosine, the same bits on a second
/// call, and the op log holds the count, never the text.
#[test]
fn embed_over_the_wire_equals_the_reference_and_logs_no_text() {
    let Some(bundle) = real_bundle(&[
        ("runtime/libonnxruntime.so", "onnxruntime-x86_64"),
        ("templates/e5-small/model.onnx", "e5-small"),
        ("templates/e5-small/model.fp16.onnx", "e5-small-fp16"),
        ("templates/e5-small/tokenizer.json", "e5-small-tokenizer"),
    ]) else {
        return;
    };
    let pki = Pki::new();
    let worker = pki.client_identity("worker");
    let modeld = start_modeld_with(
        &pki,
        &pki.server_identity(),
        &[&worker.2],
        ModeldLimits::default(),
        "modeld-embed",
        bundle,
        |s| s,
    );
    let c = client(&pki.tls_ca.pem(), &modeld, Some(&worker));
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/ml/e5-golden");
    let texts: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join("texts.json")).unwrap()).unwrap();
    let golden: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(root.join("e5-small.json")).unwrap())
            .unwrap();
    let ids = ["en-nda", "en-query", "de-vertrag", "ar-application"];
    let text_of = |id: &str| -> String {
        texts
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["id"] == id)
            .unwrap()["text"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let mut kinds = Vec::new();
    for id in ids {
        let rec = golden["texts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == id)
            .unwrap();
        kinds.push(rec["kind"].as_str().unwrap().to_owned());
    }
    // One call per kind present, so each text gets the prefix the reference used.
    for kind in ["query", "passage"] {
        let chosen: Vec<&str> = ids
            .iter()
            .zip(&kinds)
            .filter(|(_, k)| *k == kind)
            .map(|(id, _)| *id)
            .collect();
        if chosen.is_empty() {
            continue;
        }
        let ek = if kind == "query" {
            EmbedKind::Query
        } else {
            EmbedKind::Passage
        };
        let input: Vec<String> = chosen.iter().map(|id| text_of(id)).collect();
        let mut long = call();
        long.deadline = std::time::Duration::from_secs(120);
        let a = c.embed(&long, ek, input.clone()).unwrap();
        let b = c.embed(&long, ek, input).unwrap();
        assert_eq!(a, b, "the same input gives the same bits");
        assert_eq!(a.len(), chosen.len());
        for (v, id) in a.iter().zip(&chosen) {
            assert_eq!(v.len(), 384);
            let want: Vec<f64> = golden["texts"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["id"] == *id)
                .unwrap()["vector"]
                .as_array()
                .unwrap()
                .iter()
                .map(|x| x.as_f64().unwrap())
                .collect();
            let dot: f64 = v.iter().zip(&want).map(|(x, y)| f64::from(*x) * y).sum();
            let nv = v.iter().map(|x| f64::from(*x).powi(2)).sum::<f64>().sqrt();
            let nw = want.iter().map(|y| y * y).sum::<f64>().sqrt();
            assert!((nv - 1.0).abs() < 1e-5, "{id}: not a unit vector ({nv})");
            assert!(
                1.0 - dot / (nv * nw) <= 1e-3,
                "{id}: cosine {}",
                dot / (nv * nw)
            );
        }
    }
    let log = std::fs::read_to_string(&modeld.oplog).unwrap();
    assert!(
        log.lines()
            .all(|l| l.contains("\tembed\t") && l.contains("\tok\t")),
        "{log}"
    );
    for id in ids {
        let t = text_of(id);
        let word = t.split_whitespace().next().unwrap();
        assert!(!log.contains(word), "text reached the op log: {log}");
    }
}

/// When every slot is taken, an op is answered busy (`CS-ML-0009`, transient); INFO
/// takes no slot.
#[test]
fn ops_are_refused_busy_when_no_slot_is_free() {
    let pki = Pki::new();
    let worker = pki.client_identity("worker");
    let modeld = start_modeld(
        &pki,
        &pki.server_identity(),
        &[&worker.2],
        ModeldLimits {
            slots: 0,
            ..ModeldLimits::default()
        },
        "modeld-busy",
    );
    let c = client(&pki.tls_ca.pem(), &modeld, Some(&worker));
    let err = c
        .embed(&call(), EmbedKind::Query, vec!["q".into()])
        .unwrap_err();
    assert_eq!(err, ModeldError::Busy);
    assert!(err.is_transient());
    assert!(c.info(&call()).is_ok());
}

/// A request over a bound is refused by the client before anything is sent.
#[test]
fn a_request_over_a_bound_is_never_sent() {
    let (pki, modeld, worker) = setup("modeld-bounds");
    let c = client(&pki.tls_ca.pem(), &modeld, Some(&worker));
    let err = c
        .embed(&call(), EmbedKind::Query, vec!["q".into(); 65])
        .unwrap_err();
    assert_eq!(err.code(), "CS-ML-0004");
    let mut bad = call();
    bad.account = "acc 1".into();
    assert_eq!(c.info(&bad).unwrap_err().code(), "CS-ML-0004");
    let log = std::fs::read_to_string(&modeld.oplog).unwrap();
    assert!(log.is_empty(), "nothing was sent: {log}");
}

/// **A document handle lives on its connection only** (docs/33 §3.1, `SEC-I06`): one
/// document open per connection, a handle unknown to another connection, closed once,
/// and the raster child gone with the connection. Runs without model weights: OCR on an
/// open document answers `CS-ML-0010`, after the handle is checked. Linux only: the raster
/// child runs nowhere else (docs/33 §3.3; tests/raster.rs covers the refusal off Linux).
#[test]
#[cfg(target_os = "linux")]
fn a_document_handle_lives_on_its_connection_only() {
    let pki = Pki::new();
    let worker = pki.client_identity("worker");
    let exe = std::path::PathBuf::from(env!("CARGO_BIN_EXE_casual-sign-modeld"));
    let modeld = start_modeld_with(
        &pki,
        &pki.server_identity(),
        &[&worker.2],
        ModeldLimits::default(),
        "modeld-doc-handles",
        common::test_bundle("modeld-doc-handles-bundle"),
        |s| s.with_raster(&exe, casual_sign_modeld::raster::RasterLimits::default()),
    );
    let c = client(&pki.tls_ca.pem(), &modeld, Some(&worker));
    let pdf = b"%PDF-1.7\n1 0 obj\n<</Type/Catalog/Pages 2 0 R>>\nendobj\n2 0 obj\n<</Type/Pages/Kids[3 0 R]/Count 1>>\nendobj\n3 0 obj\n<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 200]>>\nendobj\ntrailer\n<</Root 1 0 R>>\n%%EOF\n".to_vec();
    let mut a = c.session().unwrap();
    let (doc, pages) = a.open_document(&call(), pdf.clone()).unwrap();
    assert_eq!(pages, 1);
    // One open document per connection.
    assert_eq!(
        a.open_document(&call(), pdf.clone()).unwrap_err().code(),
        "CS-ML-0004"
    );
    // The handle checks before the model: a wrong one is malformed, the right one finds
    // no OCR model installed here.
    assert_eq!(
        a.ocr(&call(), doc + 1, 0, 150, vec![]).unwrap_err().code(),
        "CS-ML-0004"
    );
    assert_eq!(
        a.ocr(&call(), doc, 0, 150, vec![]).unwrap_err(),
        ModeldError::NotInstalled
    );
    // Another connection does not know the handle.
    let mut b = c.session().unwrap();
    assert_eq!(
        b.ocr(&call(), doc, 0, 150, vec![]).unwrap_err().code(),
        "CS-ML-0004"
    );
    assert_eq!(
        b.close_document(&call(), doc).unwrap_err().code(),
        "CS-ML-0004"
    );
    b.close();
    a.close_document(&call(), doc).unwrap();
    assert_eq!(
        a.close_document(&call(), doc).unwrap_err().code(),
        "CS-ML-0004"
    );
    // After a close, the connection may open again.
    let (again, _) = a.open_document(&call(), pdf).unwrap();
    assert_ne!(again, 0);
    a.close();
    let log = std::fs::read_to_string(&modeld.oplog).unwrap();
    assert!(
        log.contains("\tdoc_open\tacc-0001\tjob-0001\t0\t1\t"),
        "{log}"
    );
    assert!(!log.contains("%PDF"), "{log}");
}
