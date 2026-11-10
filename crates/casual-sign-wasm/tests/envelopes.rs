//! `parity/envelopes.json` is the envelope half of the field-rule case table of
//! casual-sign-fields (`tests/parity/cases.rs`) written as the JSON the `evaluate_envelope`
//! export takes. Each case, read back from that JSON, must give exactly the `envelope`
//! line of `tests/parity/expected.txt`, so the JSON is the table and not an approximation.

// Tests may unwrap and index their own fixtures (CLAUDE.md).
#![allow(clippy::unwrap_used, clippy::indexing_slicing)]

use std::collections::BTreeMap;

use casual_sign_fields::{Values, evaluate_envelope};
use casual_sign_model::Field;
use serde_json::Value;

const ENVELOPES: &str = include_str!("../parity/envelopes.json");
const EXPECTED: &str = include_str!("../../casual-sign-fields/tests/parity/expected.txt");

#[test]
fn every_json_envelope_reproduces_its_line_of_the_case_table() {
    let cases: Vec<Value> = serde_json::from_str(ENVELOPES).unwrap();
    let want: BTreeMap<&str, &str> = EXPECTED
        .lines()
        .filter_map(|l| l.split_once(" envelope "))
        .map(|(_, rest)| rest.split_once(' ').unwrap())
        .collect();
    assert_eq!(
        cases.len(),
        want.len(),
        "every envelope case is in the JSON"
    );
    for case in &cases {
        let name = case["name"].as_str().unwrap();
        let fields: Vec<Field> = serde_json::from_value(case["fields"].clone()).unwrap();
        let values: Values = serde_json::from_value(case["values"].clone()).unwrap();
        let o = evaluate_envelope(&fields, &values);
        let issues: Vec<String> = o
            .issues
            .iter()
            .map(|i| format!("{}:{}", i.field_id, i.code()))
            .collect();
        let got = format!(
            "issues={issues:?} computed={:?} dropped={:?} hidden={:?}",
            o.computed, o.dropped, o.hidden
        );
        assert_eq!(got, want[name], "{name}");
    }
}

#[test]
fn the_export_answers_each_envelope_canonically() {
    let cases: Vec<Value> = serde_json::from_str(ENVELOPES).unwrap();
    for case in &cases {
        let out = casual_sign_wasm::api::evaluate(
            &case["fields"].to_string(),
            &case["values"].to_string(),
        );
        let v: Value = serde_json::from_str(&out).unwrap();
        assert!(v.get("ok").is_some(), "{out}");
    }
    let bad = casual_sign_wasm::api::evaluate("[", "{}");
    assert!(
        bad.starts_with(r#"{"error":{"code":"CS-API-0001""#),
        "{bad}"
    );
}
