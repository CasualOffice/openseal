//! Admitted bytes through normalization and an incremental update (`T-1B`, `F-007`).
//! Any panic, hang or out-of-memory is a finding; so is an output our own strict
//! reader refuses for anything but a stream's content (copied as it is), an update
//! that does not start with the normalized bytes, or a changed page count.
#![no_main]

use casual_sign_pdf::{
    Change, Dictionary, IncrementalUpdate, Limits, NormalizeOptions, Object, OutputXref, admit,
    admit_strict, normalize,
};
use libfuzzer_sys::fuzz_target;

/// Strict refusals about one stream's data, which normalization copies as stored.
const CONTENT_CODES: &[&str] = &["CS-PDF-0003", "CS-PDF-0011", "CS-PDF-0013"];

fuzz_target!(|data: &[u8]| {
    let limits = Limits {
        max_stream_bytes: 8 << 20,
        max_total_decoded_bytes: 32 << 20,
        objstm_cache_bytes: 8 << 20,
        ..Limits::default()
    };
    let never = || false;
    let Ok(mut admitted) = admit(data, &limits, &never) else {
        return;
    };
    let pages = admitted.report.page_count;
    let form = if data.len() % 2 == 0 {
        OutputXref::Stream
    } else {
        OutputXref::Table
    };
    let normalized = match normalize(&mut admitted, &NormalizeOptions::with_xref(form), &never) {
        Ok(n) => n,
        Err(e) => {
            // Signed input, or a document-wide limit met while loading objects.
            assert!(e.code().starts_with("CS-PDF-"), "{e}");
            return;
        }
    };
    let bytes = normalized.bytes;
    let again = match admit_strict(&bytes, &limits, &never) {
        Ok(a) => a,
        Err(e) => {
            assert!(CONTENT_CODES.contains(&e.code()), "normalized output refused: {e}");
            match admit(&bytes, &limits, &never) {
                Ok(a) => a,
                // The decode budget is shared by the whole read; the output is read
                // once more than the input, so only that limit may be met here.
                Err(e) if e.code() == "CS-PDF-0003" => return,
                Err(e) => panic!("normalized output refused by default: {e}"),
            }
        }
    };
    assert!(!again.report.repaired, "normalized output needed repair");
    assert_eq!(again.report.page_count, pages, "page count changed");
    let mut update = IncrementalUpdate::new(&again, Change::FillAndSign).expect("appendable");
    let mut info = Dictionary::new();
    info.insert(b"Producer", Object::String(b"fuzz".to_vec()));
    let r = update.add(Object::Dictionary(info)).expect("number available");
    update.set_info(r);
    let appended = update.finish().expect("update written");
    assert!(appended.starts_with(&bytes), "update rewrote earlier bytes");
    let after = admit(&appended, &limits, &never);
    if let Ok(a) = &after {
        assert_eq!(a.report.page_count, pages, "page count changed after update");
        assert!(!a.report.repaired);
    } else if let Err(e) = after {
        assert_eq!(e.code(), "CS-PDF-0003", "update refused: {e}");
    }
});
