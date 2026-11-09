//! Peak heap allocation while admitting hostile fixtures stays bounded: the oversized
//! and many-object files are refused before any large allocation (`SEC-P01`, `-P02`).
//!
//! The whole test binary runs under a counting global allocator, so this file holds a
//! single test: other tests running beside it would disturb the counts.
// Test code: a panic is the failure report.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod common;

use casual_sign_pdf::{Limits, admit, admit_strict};
use peak_alloc::PeakAlloc;

#[global_allocator]
static ALLOC: PeakAlloc = PeakAlloc;

const KIB: usize = 1024;
const MIB: usize = 1024 * KIB;

/// Peak bytes allocated beyond what was live before, over both modes.
fn peak_over_baseline(bytes: &[u8], limits: &Limits) -> usize {
    let before = ALLOC.current_usage();
    ALLOC.reset_peak_usage();
    let s = admit_strict(bytes, limits, &common::never).map(|_| ());
    let d = admit(bytes, limits, &common::never).map(|_| ());
    drop((s, d));
    ALLOC.peak_usage().saturating_sub(before)
}

#[test]
fn peak_allocation_is_bounded_on_hostile_fixtures() {
    // Built here, not a fixture: 20 million numbers in one array, a 40 MB file that
    // would parse to well over 600 MB of objects without the per-object value cap.
    let mut objs = common::pages(1);
    let mut big = b"[".to_vec();
    big.extend(std::iter::repeat_n(b"0 ".as_slice(), 20_000_000).flatten());
    big.push(b']');
    objs.push((9, big));
    let wide = common::classic(&objs, "");
    let peak = peak_over_baseline(&wide, &Limits::default());
    println!(
        "{:26} peak {:>10} bytes (bound {})",
        "array_20m (built)",
        peak,
        96 * MIB
    );
    assert!(peak <= 96 * MIB, "array of 2*10^7 values: peak {peak}");
    drop(wide);

    if !common::ensure_hostile() {
        return;
    }
    // (file, bound on the peak above the input itself). Inputs are read first, so the
    // file's own bytes are in the baseline.
    let cases: &[(&str, usize)] = &[
        // Refused on its length before a single byte is parsed.
        ("too_large.pdf", 4 * KIB),
        // 10^6 xref entries are refused at the cap: the entries read so far, never a
        // table sized from /Size. lopdf peaked at 485 MiB RSS here (SPK-01).
        ("many_objects.pdf", 96 * MIB),
        ("xref_size_2g_table.pdf", 256 * KIB),
        ("xref_size_2g_stream.pdf", 256 * KIB),
        ("revisions_1001.pdf", 4 * MIB),
        ("nesting_100k_arrays.pdf", MIB),
        ("nesting_100k_dicts.pdf", MIB),
        ("pages_5001.pdf", 16 * MIB),
        // A 16 MiB string is scanned, never stored past the cap.
        ("string_16mib_plus.pdf", 40 * MIB),
        // Bombs stop at the 256 MiB per-stream cap: at most the cap plus one growth step, and
        // never two decoded object streams at once (the cache evicts before the next decode).
        ("flate_bomb_content.pdf", 512 * MIB + MIB),
        ("flate_bomb_objstm.pdf", 512 * MIB + MIB),
        ("flate_bomb_many.pdf", 512 * MIB + MIB),
        ("flate_double.pdf", 4 * MIB),
    ];
    let mut report = Vec::new();
    for (file, bound) in cases {
        let bytes = std::fs::read(common::hostile_dir().join(file)).unwrap();
        let limits = Limits::default();
        let peak = peak_over_baseline(&bytes, &limits);
        report.push(format!("{file:26} peak {:>10} bytes (bound {bound})", peak));
        assert!(
            peak <= *bound,
            "{file}: peak {peak} bytes over bound {bound}\n{}",
            report.join("\n")
        );
    }
    println!("{}", report.join("\n"));
}
