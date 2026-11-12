//! GLiNER parity (piece K; `ML-07`, `ML-08`; docs/33 §5.3): our Rust decoder on the fp16
//! exports (owner instruction 34) against the Python `gliner` 0.2.29 golden spans in
//! `fixtures/ml/gliner-golden/`, made with ONNX Runtime on the very same files.
//!
//! The weights are not in the repository. These tests read the bundle directory named by
//! `OPENSEAL_MODELD_TEST_BUNDLE`, laid out as modeld's bundle (`runtime/libonnxruntime.so`
//! from `tools/ml/fetch-models.py --profile runtime`, and per model
//! `<dir>/{model.onnx,tokenizer.json,gliner_config.json}` from `tools/ml/export-gliner.py`),
//! and are skipped, saying so, when it is unset. Each file's SHA-256 is checked against
//! the golden file's record before anything runs, so a parity result always names the
//! exact weights it was measured on.
#![cfg(feature = "server")]
// Test code: a panic is the failure report.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    clippy::cast_possible_truncation,
    clippy::cast_precision_loss,
    missing_docs
)]

mod common;

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use casual_sign_modeld::wire::{Op, Request, Response, Span, SpanRequest};
use casual_sign_modeld::{
    AllowList, Bundle, Gliner, Manifest, ModelService, ModeldLimits, OpLog, RUNTIME_PATH,
    SpanModels, split_words,
};
use serde_json::Value;

/// Largest score difference accepted against the reference. The acceptance is on spans
/// (offsets and labels after the threshold), which must be equal; scores move a little
/// because the reference ran ONNX Runtime 1.31.1 where modeld links 1.28.3, and fp16
/// kernels differ between releases. Measured 2026-11-12: multi 0.0029, small 0.0004,
/// PII 0.0004.
const SCORE_TOLERANCE: f64 = 5e-3;

fn bundle_dir() -> Option<PathBuf> {
    match std::env::var_os("OPENSEAL_MODELD_TEST_BUNDLE") {
        Some(d) if !d.is_empty() => Some(PathBuf::from(d)),
        _ => {
            eprintln!(
                "SKIPPED: OPENSEAL_MODELD_TEST_BUNDLE is not set; GLiNER parity needs the \
                 fp16 exports and ONNX Runtime (see this file's docs)"
            );
            None
        }
    }
}

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/ml/gliner-golden")
}

fn json(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn sha_file(path: &Path) -> String {
    common::sha_hex(&std::fs::read(path).unwrap())
}

/// Golden model name → its directory in the bundle.
const MODELS: [(&str, &str); 3] = [
    ("gliner_multi-v2.1", "extraction/gliner-multi"),
    ("gliner_small-v2.1", "extraction/gliner-small"),
    ("gliner-pii-base-v1.0", "personal_data/gliner-pii-base"),
];

fn load(root: &Path, golden: &Value, dir: &str) -> Gliner {
    let model_dir = root.join(dir);
    let model = golden["model"].as_str().unwrap();
    let want = golden["onnx"][format!("{model}.fp16.onnx")]
        .as_str()
        .unwrap();
    assert_eq!(
        sha_file(&model_dir.join("model.onnx")),
        want,
        "{model}: not the fp16 export the golden ran"
    );
    assert_eq!(
        sha_file(&model_dir.join("tokenizer.json")),
        golden["tokenizer_json_sha256"].as_str().unwrap(),
        "{model}: not the golden run's tokenizer.json"
    );
    Gliner::load(&root.join(RUNTIME_PATH), &model_dir).unwrap()
}

fn byte_offset(text: &str, cp: usize) -> usize {
    text.char_indices().nth(cp).map_or(text.len(), |(b, _)| b)
}

fn ints(v: &Value) -> Vec<i64> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|x| x.as_i64().unwrap())
        .collect()
}

struct Outcome {
    texts: usize,
    spans: usize,
    max_score_diff: f64,
}

fn parity(model: &str, dir: &str) -> Option<Outcome> {
    let root = bundle_dir()?;
    let golden = json(&fixtures().join(format!("{model}.json")));
    let texts = json(&fixtures().join("texts.json"));
    let gliner = load(&root, &golden, dir);
    let labels: Vec<String> = golden["labels"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l.as_str().unwrap().to_owned())
        .collect();
    let threshold = (golden["threshold"].as_f64().unwrap() * 10_000.0).round() as u16;
    let records = golden["records"].as_array().unwrap();
    assert_eq!(records.len(), 50);
    let mut out = Outcome {
        texts: 0,
        spans: 0,
        max_score_diff: 0.0,
    };
    let mut failures = Vec::new();
    for rec in records {
        let id = rec["id"].as_str().unwrap();
        let text = texts["texts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|t| t["id"] == rec["id"])
            .unwrap()["text"]
            .as_str()
            .unwrap()
            .to_owned();

        // Words: gliner's splitter, its code-point offsets turned into bytes.
        let want_words: Vec<(usize, usize)> = rec["words"]
            .as_array()
            .unwrap()
            .iter()
            .map(|w| {
                (
                    byte_offset(&text, w[1].as_u64().unwrap() as usize),
                    byte_offset(&text, w[2].as_u64().unwrap() as usize),
                )
            })
            .collect();
        assert_eq!(
            split_words(&text).unwrap(),
            want_words,
            "{model} {id}: words"
        );

        // Feeds: exactly the reference's.
        let feeds = gliner.feeds(&text, &labels).unwrap();
        assert_eq!(feeds.len(), 1, "{model} {id}: one window");
        let inputs = &rec["onnx_inputs"];
        assert_eq!(
            feeds[0].input_ids,
            ints(&inputs["input_ids"]),
            "{model} {id}: input_ids"
        );
        assert_eq!(
            feeds[0].words_mask,
            ints(&inputs["words_mask"]),
            "{model} {id}: words_mask"
        );
        assert_eq!(
            feeds[0].words as i64,
            inputs["text_lengths"].as_i64().unwrap(),
            "{model} {id}: text_lengths"
        );

        // Spans after the threshold.
        let req = SpanRequest {
            text: text.clone(),
            labels: labels.clone(),
            threshold,
        };
        let deadline = Instant::now() + Duration::from_secs(120);
        let got = gliner.spans(&req, deadline).unwrap();
        let again = gliner.spans(&req, deadline).unwrap();
        assert_eq!(got, again, "{model} {id}: not deterministic");
        let want: Vec<(u32, u32, u8, f64)> = rec["spans"]["onnx_fp16"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| {
                let label = labels
                    .iter()
                    .position(|l| l == s["label"].as_str().unwrap())
                    .unwrap();
                (
                    s["start_byte"].as_u64().unwrap() as u32,
                    s["end_byte"].as_u64().unwrap() as u32,
                    label as u8,
                    s["score"].as_f64().unwrap(),
                )
            })
            .collect();
        let got_keys: Vec<(u32, u32, u8)> = got.iter().map(|s| (s.start, s.end, s.label)).collect();
        let want_keys: Vec<(u32, u32, u8)> = want.iter().map(|w| (w.0, w.1, w.2)).collect();
        if got_keys != want_keys {
            failures.push(format!("{id}: got {got_keys:?}, want {want_keys:?}"));
            continue;
        }
        for (g, w) in got.iter().zip(&want) {
            let diff = (f64::from(g.score) / 10_000.0 - w.3).abs();
            out.max_score_diff = out.max_score_diff.max(diff);
            assert!(
                text.is_char_boundary(g.start as usize) && text.is_char_boundary(g.end as usize)
            );
        }
        out.texts += 1;
        out.spans += got.len();
    }
    assert!(
        failures.is_empty(),
        "{model}: {} texts differ:\n{}",
        failures.len(),
        failures.join("\n")
    );
    assert!(
        out.max_score_diff <= SCORE_TOLERANCE,
        "{model}: score differs by {} from the reference",
        out.max_score_diff
    );
    eprintln!(
        "{model}: {} of 50 texts equal, {} spans, max score difference {:.6}",
        out.texts, out.spans, out.max_score_diff
    );
    Some(out)
}

#[test]
fn gliner_multi_spans_equal_the_golden_fp16_spans_on_all_50_texts() {
    if let Some(o) = parity(MODELS[0].0, MODELS[0].1) {
        assert_eq!((o.texts, o.spans), (50, 185));
    }
}

#[test]
fn gliner_small_spans_equal_the_golden_fp16_spans_on_all_50_texts() {
    if let Some(o) = parity(MODELS[1].0, MODELS[1].1) {
        assert_eq!((o.texts, o.spans), (50, 159));
    }
}

#[test]
fn gliner_pii_spans_equal_the_golden_fp16_spans_on_all_50_texts() {
    if let Some(o) = parity(MODELS[2].0, MODELS[2].1) {
        assert_eq!((o.texts, o.spans), (50, 57));
    }
}

/// A text longer than one window is read in overlapping windows, deterministically, and
/// a span found in a short text is still found when that text sits inside a long one.
#[test]
fn long_texts_are_windowed_deterministically_and_keep_their_spans() {
    let Some(root) = bundle_dir() else { return };
    let golden = json(&fixtures().join("gliner_small-v2.1.json"));
    let gliner = load(&root, &golden, MODELS[1].1);
    let labels: Vec<String> = ["party organization", "date", "monetary amount"]
        .map(str::to_owned)
        .to_vec();
    let filler = "The parties agree to the terms set out below in this schedule. ".repeat(80);
    let core = "This Agreement is made on 3 March 2025 between Quillfern Systems Ltd and \
                Marrowgate Holdings LLC for a fee of USD 12,500.";
    let text = format!("{filler}{core} {filler}{core}");
    let feeds = gliner.feeds(&text, &labels).unwrap();
    assert!(feeds.len() >= 3, "{} windows", feeds.len());
    for pair in feeds.windows(2) {
        let (a, b) = (&pair[0], &pair[1]);
        assert!(a.words <= gliner.max_len());
        assert_eq!(b.first_word, a.first_word + a.words - 64, "stride");
    }
    let req = SpanRequest {
        text: text.clone(),
        labels: labels.clone(),
        threshold: 5000,
    };
    let deadline = Instant::now() + Duration::from_secs(300);
    let long = gliner.spans(&req, deadline).unwrap();
    assert_eq!(
        long,
        gliner.spans(&req, deadline).unwrap(),
        "not deterministic"
    );
    let short = gliner
        .spans(
            &SpanRequest {
                text: core.to_owned(),
                labels,
                threshold: 5000,
            },
            deadline,
        )
        .unwrap();
    assert!(!short.is_empty());
    for (base, n) in [(filler.len(), 0), (filler.len() * 2 + core.len() + 1, 1)] {
        for s in &short {
            let moved = (s.start as usize + base, s.end as usize + base, s.label);
            assert!(
                long.iter()
                    .any(|l| (l.start as usize, l.end as usize, l.label) == moved),
                "copy {n}: span {:?} lost in the long text",
                (s.start, s.end, s.label)
            );
        }
    }
}

/// Text not in NFC, a label holding a prompt token and a passed deadline are refused
/// with their codes; nothing is decoded.
#[test]
fn bad_requests_are_refused_with_their_codes() {
    let Some(root) = bundle_dir() else { return };
    let golden = json(&fixtures().join("gliner-pii-base-v1.0.json"));
    let gliner = load(&root, &golden, MODELS[2].1);
    let later = Instant::now() + Duration::from_secs(60);
    let req = |text: &str, label: &str| SpanRequest {
        text: text.to_owned(),
        labels: vec![label.to_owned()],
        threshold: 5000,
    };
    let not_nfc = gliner
        .spans(&req("Cafe\u{301} Ltd", "name"), later)
        .unwrap_err();
    assert_eq!(not_nfc.code(), "CS-ML-0004");
    let injected = gliner
        .spans(&req("Ann Lee", "name <<SEP>> x"), later)
        .unwrap_err();
    assert_eq!(injected.code(), "CS-ML-0004");
    let past = Instant::now();
    let late = gliner
        .spans(&req("Ann Lee lives in Leeds.", "name"), past)
        .unwrap_err();
    assert_eq!(late.code(), "CS-ML-0007");
    assert!(gliner.spans(&req("   ", "name"), later).unwrap().is_empty());

    // ML-17: 32 labels of 64 bytes of punctuation tokenize to nearly one token a byte,
    // and their prompt leaves no room for the text. Before the fix every word was
    // skipped and the call answered no spans, as if nothing had matched.
    let heavy: Vec<String> = (0..32)
        .map(|i| {
            let mut s = format!("{i}");
            while s.len() < 64 {
                s.push_str(".,");
            }
            s.truncate(64);
            s
        })
        .collect();
    let crowded = SpanRequest {
        text: "Ann Lee lives in Leeds.".to_owned(),
        labels: heavy,
        threshold: 5000,
    };
    assert_eq!(
        gliner.spans(&crowded, later).unwrap_err().code(),
        "CS-ML-0005"
    );
    assert_eq!(
        gliner
            .feeds(&crowded.text, &crowded.labels)
            .unwrap_err()
            .code(),
        "CS-ML-0005"
    );
}

/// Hard-link (or copy) `files` of the test bundle into a scratch bundle.
fn scratch_bundle(root: &Path, name: &str, files: &[&str]) -> PathBuf {
    let dir = common::scratch(name);
    for f in files {
        let to = dir.join(f);
        std::fs::create_dir_all(to.parent().unwrap()).unwrap();
        if std::fs::hard_link(root.join(f), &to).is_err() {
            std::fs::copy(root.join(f), &to).unwrap();
        }
    }
    dir
}

/// ENTITIES and PERSONAL through the service: the op log records counts and ids, never
/// the text, the labels or what matched (`SEC-I05`); an op whose model is absent
/// answers `CS-ML-0010`.
#[test]
fn personal_spans_through_the_service_log_no_text() {
    let Some(root) = bundle_dir() else { return };
    let files = [
        RUNTIME_PATH,
        "personal_data/gliner-pii-base/model.onnx",
        "personal_data/gliner-pii-base/tokenizer.json",
        "personal_data/gliner-pii-base/gliner_config.json",
    ];
    let dir = scratch_bundle(&root, "gliner-service-bundle", &files);
    let ids = [
        "ort",
        "gliner-pii-base",
        "gliner-pii-base-tokenizer",
        "gliner-pii-base-config",
    ];
    let mut manifest = String::new();
    for (id, f) in ids.iter().zip(files) {
        let bytes = std::fs::read(dir.join(f)).unwrap();
        // The runtime's own licence is a compound one; this test manifest is not the
        // shipped one and lists it as MIT.
        manifest.push_str(&format!(
            "{id}\tpersonal_data\t{}\t{}\tMIT\t{f}\n",
            common::sha_hex(&bytes),
            bytes.len()
        ));
    }
    let bundle = Bundle::verify(
        &dir,
        &Manifest::parse(&manifest).unwrap(),
        &["personal_data".into()],
    )
    .unwrap();
    let spans = SpanModels::load(&bundle).unwrap();
    assert!(spans.has_personal() && !spans.has_entities());
    let run = common::scratch("gliner-service-run");
    let oplog = run.join("oplog.tsv");
    let service = ModelService::new(
        bundle,
        AllowList::new(),
        OpLog::open(&oplog).unwrap(),
        ModeldLimits::default(),
    )
    .with_span_models(spans);

    let marker = "Zorbleworth";
    let text = format!("Please send the signed copy to {marker} Quanticle at 14 Elm Row, Leeds.");
    let req = |op| Request {
        deadline_ms: 60_000,
        account: "acc-k".into(),
        job: "job-k".into(),
        op,
    };
    let span_req = SpanRequest {
        text: text.clone(),
        labels: vec!["name".into(), "location address".into()],
        threshold: 5000,
    };
    let Response::Spans(found) = service.answer("caller-k", &req(Op::Personal(span_req.clone())))
    else {
        panic!("PERSONAL did not answer spans");
    };
    let named: Vec<&str> = found
        .iter()
        .map(|s: &Span| &text[s.start as usize..s.end as usize])
        .collect();
    assert!(named.iter().any(|n| n.contains(marker)), "{named:?}");
    assert_eq!(
        service.answer("caller-k", &req(Op::Entities(span_req))),
        Response::Error(10)
    );
    let Response::Info(info) = service.answer("caller-k", &req(Op::Info)) else {
        panic!()
    };
    // Microsoft's 1.28.3 build names its commit, not its release.
    assert_eq!(info.runtime, "onnxruntime-git-0d68ff6");

    let log = std::fs::read_to_string(&oplog).unwrap();
    assert!(
        log.contains("personal") && log.contains("entities"),
        "{log}"
    );
    for secret in [marker, "Quanticle", "Leeds", "location address", "Elm"] {
        assert!(!log.contains(secret), "op log holds {secret}");
    }
}
