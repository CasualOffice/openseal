//! The whole corpus through optional content and annotation flattening (`FLT-03`):
//! every file that admits and normalizes is flattened with no fields, and must come
//! out as an incremental update that admits again, with no `/OCProperties` left.
//!
//! Runs only with `OPENSEAL_CORPUS_SWEEP=1` (it reads every corpus file); the corpus
//! is at `OPENSEAL_CORPUS_DIR`, else `fixtures/corpus/files`. With `FLATTEN_DUMP_DIR`,
//! files with optional content or flattened annotations are written there with a
//! `layers-corpus.json` for `tools/check_layers.py` (PDFium draws input and output
//! alike).

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use std::collections::BTreeMap;
use std::path::PathBuf;

use casual_sign_flatten::{FlattenInput, FlattenOptions, FontSet, FormMode, flatten};
use casual_sign_pdf::{Limits, NormalizeOptions, Object, OutputXref, admit, normalize};
use common::*;

fn corpus_dir() -> PathBuf {
    std::env::var_os("OPENSEAL_CORPUS_DIR").map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/corpus/files"),
        PathBuf::from,
    )
}

#[test]
fn every_corpus_file_flattens_its_layers_and_annotations() {
    if std::env::var_os("OPENSEAL_CORPUS_SWEEP").is_none() {
        eprintln!("skipped: set OPENSEAL_CORPUS_SWEEP=1 to sweep the corpus");
        return;
    }
    let mut names: Vec<_> = std::fs::read_dir(corpus_dir())
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "pdf"))
        .collect();
    names.sort();
    let (mut files, mut not_admitted, mut with_oc, mut with_annots) = (0, 0, 0, 0);
    let (mut flattened, mut removed, mut kept, mut sections) = (0, 0, 0, 0);
    let mut failures = Vec::new();
    let mut manifest = Vec::new();
    for path in &names {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let raw = std::fs::read(path).unwrap();
        files += 1;
        // As on delivery; a file the reader refuses never reaches flattening.
        let Ok(mut a) = admit(&raw, &Limits::default(), &never) else {
            not_admitted += 1;
            continue;
        };
        let Ok(n) = normalize(
            &mut a,
            &NormalizeOptions::with_xref(OutputXref::Stream),
            &never,
        ) else {
            not_admitted += 1;
            continue;
        };
        let base = n.bytes;
        let mut a = admit(&base, &Limits::default(), &never).unwrap();
        let root = a.document.trailer().get(b"Root").and_then(Object::as_ref);
        let has_oc = root
            .and_then(|r| a.document.object(r.num, &never).ok())
            .is_some_and(|c| c.get(b"OCProperties").is_some());
        let values = BTreeMap::new();
        let caps = BTreeMap::new();
        let input = FlattenInput {
            fields: &[],
            values: &values,
            captures: &caps,
            envelope_id: None,
            acroform: None,
        };
        let out = match flatten(
            &mut a,
            &input,
            &FontSet::bundled(),
            &FlattenOptions::default(),
            &never,
        ) {
            Ok(o) => o,
            Err(e) => {
                failures.push(format!("{name}: {e}"));
                continue;
            }
        };
        // Filled in place (no field values): the form stays as it is, so the PDFium
        // comparison sees only what FLT-03 changed, not how widgets are flattened.
        let mut options = FlattenOptions::default();
        options.mode = FormMode::FillInPlace;
        let mut b = admit(&base, &Limits::default(), &never).unwrap();
        let in_place = match flatten(&mut b, &input, &FontSet::bundled(), &options, &never) {
            Ok(o) => o,
            Err(e) => {
                failures.push(format!("{name}: in place: {e}"));
                continue;
            }
        };
        let r = &out.report;
        if !out.bytes.starts_with(&base) {
            failures.push(format!("{name}: not an incremental update"));
        }
        match admit(&out.bytes, &Limits::default(), &never) {
            Ok(mut b) => {
                let root = b.document.trailer().get(b"Root").and_then(Object::as_ref);
                if root
                    .and_then(|r| b.document.object(r.num, &never).ok())
                    .is_some_and(|c| c.get(b"OCProperties").is_some())
                {
                    failures.push(format!("{name}: /OCProperties left"));
                }
            }
            Err(e) => failures.push(format!("{name}: output does not admit: {e}")),
        }
        let annots = r.annotations_flattened + r.annotations_removed + r.annotations_kept;
        with_oc += usize::from(has_oc);
        with_annots += usize::from(annots > 0);
        flattened += r.annotations_flattened;
        removed += r.annotations_removed;
        kept += r.annotations_kept;
        sections += r.hidden_sections;
        if has_oc || annots > 0 {
            eprintln!(
                "{name}: oc {has_oc}, {} hidden sections, {} operators; annotations {} drawn, {} removed, {} kept",
                r.hidden_sections,
                r.hidden_operators,
                r.annotations_flattened,
                r.annotations_removed,
                r.annotations_kept
            );
        }
        if (has_oc || r.annotations_flattened + r.annotations_removed > 0) && dump_dir().is_some() {
            let stem = name.trim_end_matches(".pdf");
            dump(&format!("corpus-{stem}.in.pdf"), &base);
            dump(&format!("corpus-{stem}.out.pdf"), &in_place.bytes);
            // An annotation drawn as page content may anti-alias its edge a pixel
            // differently: two pixels per annotation drawn are tolerated.
            manifest.push(format!(
                "{{\"in\":{},\"out\":{},\"shown\":[],\"hidden\":[],\"pages\":3,\"tolerance\":{}}}",
                js(&format!("corpus-{stem}.in.pdf")),
                js(&format!("corpus-{stem}.out.pdf")),
                40 + 2 * in_place.report.annotations_flattened
            ));
        }
    }
    if dump_dir().is_some() {
        dump(
            "layers-corpus.json",
            format!("[\n{}\n]\n", manifest.join(",\n")).as_bytes(),
        );
    }
    eprintln!(
        "{files} files, {not_admitted} not admitted or normalized; {with_oc} with optional content \
         ({sections} hidden sections), {with_annots} with non-widget annotations \
         ({flattened} drawn, {removed} removed, {kept} kept); {} failures",
        failures.len()
    );
    assert!(failures.is_empty(), "{failures:#?}");
}
