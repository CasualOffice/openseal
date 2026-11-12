//! The log scrubber (`SEC-I05`, docs/33 §3.4, review defect 3): every op runs with
//! `RUST_LOG` asking for trace everywhere, on a page whose text is a marker string, and
//! the output of modeld's one subscriber must hold neither the marker nor any
//! third-party event below the fixed caps (WARN; ERROR for ONNX Runtime). Needs the OCR
//! weights (`OPENSEAL_MODELD_TEST_BUNDLE`, see tests/ocr.rs) so the marker really passes
//! through `oar-ocr` and ONNX Runtime; skipped with a message without them.
//!
//! One test in this binary: it installs the process-wide subscriber, so third-party
//! threads (ONNX Runtime's) log into it too.
// Test code: a panic is the failure report.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};

use casual_sign_modeld::raster::RasterLimits;
use casual_sign_modeld::wire::{EmbedKind, Op, Request, Response, SpanRequest};
use casual_sign_modeld::{AllowList, ConnectionState, ModelService, ModeldLimits, OpLog, logging};

const EXE: &str = env!("CARGO_BIN_EXE_casual-sign-modeld");
const MARKER: &str = "ZQXMARKER";

/// A writer into a shared buffer.
#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);

impl Write for Captured {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Captured {
    type Writer = Captured;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

/// A one-page PDF whose only text is the marker, large, in Helvetica.
fn marker_pdf() -> Vec<u8> {
    let content = format!("BT /F1 28 Tf 72 600 Td ({MARKER}) Tj ET 0 g 72 540 m 400 540 l S");
    let objs = [
        "<</Type/Catalog/Pages 2 0 R>>".to_owned(),
        "<</Type/Pages/Kids[3 0 R]/Count 1>>".to_owned(),
        "<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]/Resources<</Font<</F1 5 0 R>>>>/Contents 4 0 R>>".to_owned(),
        format!("<</Length {}>>\nstream\n{content}\nendstream", content.len()),
        "<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>".to_owned(),
    ];
    let mut out = b"%PDF-1.7\n".to_vec();
    let mut offsets = Vec::new();
    for (i, o) in objs.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n{o}\nendobj\n", i + 1).as_bytes());
    }
    let xref = out.len();
    out.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", objs.len() + 1).as_bytes());
    for off in offsets {
        out.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<</Size {}/Root 1 0 R>>\nstartxref\n{xref}\n%%EOF\n",
            objs.len() + 1
        )
        .as_bytes(),
    );
    out
}

fn request(op: Op) -> Request {
    Request {
        deadline_ms: 120_000,
        account: "acc-scrub".into(),
        job: "job-scrub".into(),
        op,
    }
}

/// Whether a formatted line is a third-party event below its cap: `LEVEL target: ...`.
fn third_party_below_cap(line: &str) -> bool {
    let mut words = line.split_whitespace();
    let level = words.find(|w| matches!(*w, "TRACE" | "DEBUG" | "INFO" | "WARN" | "ERROR"));
    let Some(level) = level else {
        return false;
    };
    let target = words.next().unwrap_or_default().trim_end_matches(':');
    let ort = target == "ort" || target.starts_with("ort::");
    let third = ort
        || ["oar_ocr", "hayro", "tokenizers", "image", "vello"]
            .iter()
            .any(|p| target.starts_with(p));
    match level {
        "TRACE" | "DEBUG" | "INFO" => third,
        "WARN" => ort,
        _ => false,
    }
}

#[test]
fn no_op_at_trace_level_writes_document_text_or_a_third_party_event_below_its_cap() {
    let Some(bundle) = common::real_bundle("scrub-bundle", &["ocr", "runtime"]) else {
        return;
    };
    let out = Captured::default();
    tracing::subscriber::set_global_default(logging::subscriber(
        out.clone(),
        Some("trace,oar_ocr=trace,oar_ocr_core=trace,ort=trace,hayro=trace,hayro_interpret=trace,tokenizers=trace"),
    ))
    .unwrap();
    // modeld's own target is at trace, so the capture is live.
    tracing::trace!(target: "casual_sign_modeld::scrub", "scrubber capture is live");

    let dir = common::scratch("scrub-run");
    let s = ModelService::new(
        bundle,
        AllowList::new(),
        OpLog::open(&dir.join("oplog.tsv")).unwrap(),
        ModeldLimits::default(),
    )
    .with_raster(Path::new(EXE), RasterLimits::default())
    .with_ocr()
    .unwrap();
    let mut conn = ConnectionState::default();
    let mut answer = |op| s.answer("t", &request(op), &mut conn);
    assert!(matches!(answer(Op::Info), Response::Info(_)));
    let Response::Opened { doc, .. } = answer(Op::DocOpen { pdf: marker_pdf() }) else {
        panic!("DOC_OPEN");
    };
    let Response::Ocr(page) = answer(Op::Ocr {
        doc,
        page: 0,
        dpi: 150,
        scripts: vec![],
    }) else {
        panic!("OCR");
    };
    // The marker really went through the pipeline: OCR read it.
    assert!(
        page.words.iter().any(|w| w.text.contains(MARKER)),
        "OCR did not read the marker ({} words)",
        page.words.len()
    );
    assert_eq!(answer(Op::DocClose { doc }), Response::Closed);
    let span = SpanRequest {
        text: format!("Agreement with {MARKER}."),
        labels: vec!["party".into()],
        threshold: 5_000,
    };
    for op in [
        Op::Hash {
            pdf: marker_pdf(),
            pages: vec![0],
        },
        Op::Embed {
            kind: EmbedKind::Passage,
            texts: vec![MARKER.into()],
        },
        Op::Entities(span.clone()),
        Op::Personal(span),
    ] {
        let _ = answer(op);
    }

    let text = String::from_utf8(out.0.lock().unwrap().clone()).unwrap();
    assert!(text.contains("scrubber capture is live"), "{text}");
    assert!(!text.contains(MARKER), "the marker reached the log");
    let below: Vec<&str> = text.lines().filter(|l| third_party_below_cap(l)).collect();
    assert!(
        below.is_empty(),
        "{} third-party events below their cap, first: {:?}",
        below.len(),
        below.first()
    );
    let oplog = std::fs::read_to_string(dir.join("oplog.tsv")).unwrap();
    assert!(!oplog.contains(MARKER), "the marker reached the op log");
    eprintln!(
        "SEC-I05 scrubber: {} log lines at trace, none with the marker or a third-party event below its cap",
        text.lines().count()
    );
}
