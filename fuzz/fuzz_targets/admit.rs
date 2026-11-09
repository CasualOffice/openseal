//! Bytes into both admission entry points (`T-1A`, `F-007`). Any panic, hang or
//! out-of-memory is a finding; so is strict reading opening a file the recovering
//! reader refuses, or an error without a `CS-PDF-` code.
#![no_main]

use casual_sign_pdf::{Limits, admit, admit_strict};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Smaller decode caps than the defaults keep each run fast; the caps themselves are
    // what is exercised, not their size.
    let limits = Limits {
        max_stream_bytes: 8 << 20,
        max_total_decoded_bytes: 32 << 20,
        objstm_cache_bytes: 8 << 20,
        ..Limits::default()
    };
    let never = || false;
    let lenient = admit(data, &limits, &never).map(|a| a.report);
    let strict = admit_strict(data, &limits, &never).map(|a| a.report);
    if let Err(e) = &lenient {
        assert!(e.code().starts_with("CS-PDF-"));
    }
    if strict.is_ok() {
        assert!(lenient.is_ok(), "strict opened what the default refused");
    }
});
