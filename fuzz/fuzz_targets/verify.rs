//! Bytes into the verifier (`T-1H`, `F-007`), seeded with `fixtures/signed/`. Any panic,
//! hang or out-of-memory is a finding; so is a report that names a signature without a
//! docs/20 code on its failure.
//!
//!   cargo +nightly fuzz run verify fixtures/signed -- -max_total_time=600 -dict=fuzz/pdf.dict
#![no_main]

use casual_sign_verify::{Limits, TrustStore, VerifyOptions, verify};
use libfuzzer_sys::fuzz_target;
use std::time::Duration;

fuzz_target!(|data: &[u8]| {
    let mut options = VerifyOptions::at(Duration::from_secs(1_796_083_200));
    options.limits = Limits {
        max_stream_bytes: 8 << 20,
        max_total_decoded_bytes: 32 << 20,
        objstm_cache_bytes: 8 << 20,
        ..Limits::default()
    };
    let report = verify(data, &TrustStore::new(), &options);
    for s in &report.signatures {
        if let Some(r) = s.indication.reason() {
            assert!(r.code.starts_with("CS-"));
        }
    }
});
