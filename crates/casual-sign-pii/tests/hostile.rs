//! Bounds and hostile input: the size limit and its code, truncation reports, no text
//! in any error or report, and no panic on any input (CLAUDE.md: untrusted input never
//! panics).

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

use casual_sign_pii::{
    Detection, Kind, MAX_SCORE, MAX_TEXT_BYTES, Options, PiiError, Truncation, detect,
};
use proptest::prelude::*;

/// A string that must never appear in an error, a report or a span's `Debug`.
const MARKER: &str = "MARKER-7f3a-jane.roe@example.com";

#[test]
fn text_over_the_limit_is_refused_with_its_code_and_no_text() {
    let options = Options {
        max_text_bytes: 64,
        ..Options::default()
    };
    let text = format!("{MARKER} {MARKER} {MARKER}");
    let e = detect(&text, &options).unwrap_err();
    assert_eq!(e.code(), "CS-PII-0001");
    assert_eq!(
        e,
        PiiError::TextTooLarge {
            bytes: text.len(),
            limit: 64
        }
    );
    for shown in [e.to_string(), format!("{e:?}")] {
        assert!(
            !shown.contains("MARKER") && !shown.contains("example"),
            "{shown}"
        );
        assert!(shown.contains(&text.len().to_string()), "{shown}");
    }
}

#[test]
fn text_at_the_limit_is_read() {
    let text = "a".repeat(MAX_TEXT_BYTES);
    assert!(detect(&text, &Options::default()).is_ok());
    let over = "a".repeat(MAX_TEXT_BYTES + 1);
    assert_eq!(
        detect(&over, &Options::default()).unwrap_err().code(),
        "CS-PII-0001"
    );
}

#[test]
fn spans_past_the_limit_are_dropped_and_reported_without_text() {
    let text = (0..10)
        .map(|i| format!("markerq{i}@example.com "))
        .collect::<String>();
    let options = Options {
        max_spans: 3,
        ..Options::default()
    };
    let d = detect(&text, &options).unwrap();
    assert_eq!(d.spans.len(), 3);
    assert_eq!(d.truncated, [Truncation::Spans { limit: 3 }]);
    let shown = format!("{d:?}");
    assert!(
        !shown.contains("markerq") && !shown.contains("example"),
        "{shown}"
    );
}

#[test]
fn candidates_past_the_limit_are_not_examined_and_reported() {
    let text = "192.0.2.1 ".repeat(50);
    let options = Options {
        max_candidates: 10,
        ..Options::default()
    };
    let d = detect(&text, &options).unwrap();
    assert!(
        d.truncated.contains(&Truncation::Candidates {
            kind: Kind::IpAddress,
            limit: 10
        }),
        "{:?}",
        d.truncated
    );
    assert_eq!(
        d.spans.iter().filter(|s| s.kind == Kind::IpAddress).count(),
        10
    );
}

#[test]
fn min_score_filters() {
    let text = "ref 536228726";
    assert!(!detect(text, &Options::default()).unwrap().spans.is_empty());
    let d = detect(
        text,
        &Options {
            min_score: 51,
            ..Options::default()
        },
    )
    .unwrap();
    assert!(d.spans.iter().all(|s| s.score >= 51), "{d:?}");
}

#[test]
fn a_large_hostile_text_finishes_bounded() {
    // Dense digit groups: every recogniser has candidates everywhere.
    let unit = "4111 1111 1111 1111 +44 20 7946 0958 536-22-8726 DE89 3704 0044 0532 0130 00 ";
    let text = unit.repeat(1024 * 1024 / unit.len());
    let d = detect(&text, &Options::default()).unwrap();
    assert!(d.spans.len() <= 5_000);
    assert!(!d.truncated.is_empty());
}

fn check(text: &str, d: &Detection) {
    let mut last = (0, 0);
    for s in &d.spans {
        assert!(s.start < s.end && s.end <= text.len());
        assert!(text.is_char_boundary(s.start) && text.is_char_boundary(s.end));
        assert!((1..=MAX_SCORE).contains(&s.score));
        assert!((s.start, s.end) >= last);
        last = (s.start, s.end);
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    #[test]
    fn any_text_never_panics(text in "\\PC{0,200}") {
        let d = detect(&text, &Options::default()).unwrap();
        check(&text, &d);
    }

    #[test]
    fn number_like_text_never_panics(text in "[0-9 +().:/\\-A-Za-z@#]{0,80}") {
        let d = detect(&text, &Options::default()).unwrap();
        check(&text, &d);
    }

    #[test]
    fn same_text_same_spans(text in "[0-9 +().:\\-]{0,60}") {
        let a = detect(&text, &Options::default()).unwrap();
        let b = detect(&text, &Options::default()).unwrap();
        prop_assert_eq!(a, b);
    }
}
