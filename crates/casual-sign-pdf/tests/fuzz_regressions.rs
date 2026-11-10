//! Inputs the fuzz targets found (`FUZZ-01`), kept so each finding stays fixed. Each file
//! is a fuzzer's own output, with no personal data.
#![allow(clippy::unwrap_used, clippy::panic)]

use casual_sign_pdf::{Credentials, Limits, admit_strict_with, admit_with};

/// The `admit` target's invariant: strict reading never opens a file the default
/// refuses. Run 42890029431 found a signed file whose xref the default rebuilds (and
/// so refuses, `CS-PDF-0014`) while strict reading corrected an entry offset and opened
/// it, reporting `repaired`.
#[test]
fn strict_never_opens_what_the_default_refuses() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fuzz-regressions");
    let limits = Limits {
        max_stream_bytes: 8 << 20,
        max_total_decoded_bytes: 32 << 20,
        objstm_cache_bytes: 8 << 20,
        ..Limits::default()
    };
    let credentials = Credentials::new()
        .with_password("openseal-user")
        .with_password("user");
    let never = || false;
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let data = std::fs::read(&path).unwrap();
        let lenient = admit_with(&data, &limits, &credentials, &never);
        let strict = admit_strict_with(&data, &limits, &credentials, &never);
        if let Ok(s) = &strict {
            assert!(
                lenient.is_ok(),
                "{}: strict opened what the default refused",
                path.display()
            );
            assert!(
                !s.report.repaired,
                "{}: strict reading repaired",
                path.display()
            );
        }
    }
}
