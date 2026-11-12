//! Text into the personal-data recognisers (`ML-08`). Any panic or hang is a finding;
//! every span must lie on character boundaries inside the text, in order, with a score
//! from 1 to 1000, and an oversized text must be refused with its code.
#![no_main]

use casual_sign_pii::{MAX_SCORE, Options, detect};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    // A small bound too, so the limit path is exercised as often as the scan.
    for options in [
        Options::default(),
        Options {
            max_text_bytes: 256,
            max_spans: 8,
            max_candidates: 16,
            min_score: 1,
        },
    ] {
        match detect(&text, &options) {
            Ok(d) => {
                assert!(d.spans.len() <= options.max_spans);
                let mut last = (0, 0);
                for s in &d.spans {
                    assert!(s.start < s.end && s.end <= text.len());
                    assert!(text.is_char_boundary(s.start) && text.is_char_boundary(s.end));
                    assert!((1..=MAX_SCORE).contains(&s.score));
                    assert!((s.start, s.end) >= last);
                    last = (s.start, s.end);
                }
            }
            Err(e) => {
                assert_eq!(e.code(), "CS-PII-0001");
                assert!(text.len() > options.max_text_bytes);
            }
        }
    }
});
