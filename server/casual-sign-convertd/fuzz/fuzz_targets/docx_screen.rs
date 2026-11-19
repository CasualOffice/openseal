//! Bytes into convertd's own parsing (VS-06C, docs/07 `SEC-P13`): the archive screen a
//! `.docx` passes before the converter reads it, and the wire frames the daemon, its
//! child and the API server read from each other. Any panic, hang or out-of-memory is a
//! finding.
//!
//!   cd server/casual-sign-convertd/fuzz && cargo +nightly fuzz run docx_screen ../../../fixtures/hostile/docx -- -max_total_time=600
#![no_main]

use casual_sign_convertd::screen;
use casual_sign_convertd::wire::{read_answer, read_request};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(found) = screen(data) {
        assert!(found.pages_estimate >= 1);
    }
    let _ = read_request(&mut &data[..]);
    let _ = read_answer(&mut &data[..]);
});
