//! Native half of the native = WASM check (ADR-022): the fixed case table must produce
//! exactly `parity/expected.txt`. The WASM half runs the same `parity/cases.rs`.
//!
//! To regenerate after an intended change: `PARITY_BLESS=1 cargo test -p
//! casual-sign-fields --test parity`, then review the diff.

#[path = "parity/cases.rs"]
mod cases;

#[test]
fn case_table_matches_the_recorded_output() {
    let got = cases::run();
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/parity/expected.txt");
    if std::env::var_os("PARITY_BLESS").is_some() {
        std::fs::write(path, &got).ok();
    }
    // Normalized: a Windows checkout may turn the file's line endings into CRLF (docs/04 #16).
    let want = include_str!("parity/expected.txt").replace("\r\n", "\n");
    assert!(
        got.lines().count() >= 200,
        "the table holds {} cases",
        got.lines().count()
    );
    for (g, w) in got.lines().zip(want.lines()) {
        assert_eq!(g, w);
    }
    assert_eq!(got, want);
}
