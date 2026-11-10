//! Real forms from the corpus (`FLD-RADIO-NAME`, `FLD-RADIO-NOOPT`, `P1-GATE-01`):
//! normalized as on delivery, converted, every field given a value (an on-state for
//! each radio group), validated, then flattened and filled in place.
//!
//! The corpus is not in the repository (`fixtures/corpus/fetch.py` downloads it). The
//! test reads `OPENSEAL_CORPUS_DIR`, else `fixtures/corpus/files` at the workspace
//! root, and passes with a note when a file is absent; the constructs these files
//! exercise have synthetic tests in `tests/acroform.rs` that always run.

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

use casual_sign_fields::{convert_acroform, evaluate_envelope};
use casual_sign_flatten::{Art, Capture, FlattenInput, FlattenOptions, FontSet, FormMode, flatten};
use casual_sign_model::{Field, FieldType, FieldValue, Id, Text, Validation, ValidationRule};
use casual_sign_pdf::{Limits, admit};
use common::*;

/// The files the Phase 1 corpus gate failed on.
const FILES: [&str; 2] = ["ed-fafsa-2324.pdf", "ed-fafsa-2425.pdf"];

/// A value of each field's type, as the pipeline gate gives them: text cut to its
/// maximum length, the check box checked, the first option of a choice (an on-state of
/// a radio group), the drawn capture for a signature; read-only and locked fields keep
/// their own value.
fn sample_values(fields: &[Field]) -> (BTreeMap<Id, FieldValue>, BTreeMap<Id, Capture>) {
    let mut out = BTreeMap::new();
    for f in fields {
        if f.read_only || f.locked {
            continue;
        }
        let v = match f.field_type {
            FieldType::Checkbox => FieldValue::Checked(true),
            FieldType::RadioGroup | FieldType::Dropdown => match f.options.as_slice().first() {
                Some(o) => FieldValue::Choice(o.clone()),
                None => continue,
            },
            FieldType::Signature | FieldType::Initials | FieldType::Stamp => {
                FieldValue::Signature(id("cap"))
            }
            _ => {
                let max = match &f.validation {
                    Some(Validation {
                        rule: ValidationRule::Length(r),
                        ..
                    }) => r.max().map_or(usize::MAX, |m| m as usize),
                    _ => usize::MAX,
                };
                if max == 0 {
                    continue;
                }
                let text: String = "Sample 42".chars().take(max).collect();
                FieldValue::Text(Text::new(text).unwrap())
            }
        };
        out.insert(f.id.clone(), v);
    }
    let caps = BTreeMap::from([(id("cap"), capture(Art::Drawn(ink(120))))]);
    (out, caps)
}

fn corpus_dir() -> PathBuf {
    std::env::var_os("OPENSEAL_CORPUS_DIR").map_or_else(
        || PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/corpus/files"),
        PathBuf::from,
    )
}

#[test]
fn the_fafsa_forms_convert_fill_and_flatten() {
    for name in FILES {
        let path = corpus_dir().join(name);
        let Ok(raw) = std::fs::read(&path) else {
            eprintln!("skipped {name}: not at {}", path.display());
            continue;
        };
        let base = delivered(&raw);
        let mut a = admit(&base, &Limits::default(), &never).unwrap();
        let report = a.report.clone();
        let conv =
            convert_acroform(&mut a.document, &report, &id("doc"), &mut minter(), &never).unwrap();
        let fields: Vec<_> = conv.fields.iter().map(|c| c.field.clone()).collect();
        // Every radio group has an on-state to choose.
        let empty: Vec<_> = fields
            .iter()
            .filter(|f| f.field_type == FieldType::RadioGroup && f.options.is_empty())
            .map(|f| f.id.as_str().to_owned())
            .collect();
        assert!(
            empty.is_empty(),
            "{name}: radio groups without options: {empty:?}"
        );
        let (values, caps) = sample_values(&fields);
        let outcome = evaluate_envelope(&fields, &values);
        let invalid: Vec<_> = outcome
            .issues
            .iter()
            .filter(|i| i.code() != "CS-FLD-0001" && i.code() != "CS-FLD-0003")
            .map(|i| format!("{} {}", i.code(), i.field_id.as_str()))
            .collect();
        assert!(invalid.is_empty(), "{name}: {invalid:?}");
        let input = FlattenInput {
            fields: &fields,
            values: &values,
            captures: &caps,
            envelope_id: Some("ENV-CORPUS"),
            acroform: Some(&conv),
        };
        let fonts = FontSet::bundled();
        let flat = flatten(&mut a, &input, &fonts, &FlattenOptions::default(), &never)
            .unwrap_or_else(|e| panic!("{name}: flatten: {e}"));
        assert!(flat.bytes.starts_with(&base), "{name}");
        let mut a = admit(&base, &Limits::default(), &never).unwrap();
        let mut options = FlattenOptions::default();
        options.mode = FormMode::FillInPlace;
        let filled = flatten(&mut a, &input, &fonts, &options, &never)
            .unwrap_or_else(|e| panic!("{name}: fill: {e}"));
        assert!(filled.bytes.starts_with(&base), "{name}");
        let b = admit(&flat.bytes, &Limits::default(), &never).unwrap();
        assert!(
            b.report.fields.is_empty(),
            "{name}: live fields after flattening"
        );
        eprintln!(
            "ok {name}: {} fields converted, {} drawn, {} filled in place",
            fields.len(),
            flat.report.drawn.len(),
            filled.report.filled.len()
        );
    }
}
