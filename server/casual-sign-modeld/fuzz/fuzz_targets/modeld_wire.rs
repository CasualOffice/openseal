//! Bytes into modeld's frame decoders (ML-09, `SEC-I12`): requests as modeld reads them,
//! and responses as the worker reads them against each kind of request. Any panic, hang
//! or out-of-memory is a finding; so is a request that decodes but does not encode back
//! to the same bytes.
//!
//!   cd server/casual-sign-modeld/fuzz && cargo +nightly fuzz run modeld_wire -- -max_total_time=300
#![no_main]

use casual_sign_modeld::wire::{EmbedKind, Op, Request, Response, SpanRequest, read_frame};
use libfuzzer_sys::fuzz_target;

fn requests() -> Vec<Request> {
    let span = SpanRequest {
        text: "Agreement between Ana and Bob. شروط".into(),
        labels: vec!["person".into(), "date".into()],
        threshold: 5_000,
    };
    [
        Op::Info,
        Op::DocOpen { pdf: vec![] },
        Op::DocClose { doc: 1 },
        Op::Ocr {
            doc: 1,
            page: 0,
            dpi: 150,
            scripts: vec![],
        },
        Op::Hash {
            pdf: vec![],
            pages: vec![0],
        },
        Op::Embed {
            kind: EmbedKind::Query,
            texts: vec!["a".into(), "b".into()],
        },
        Op::Entities(span.clone()),
        Op::Personal(span),
    ]
    .into_iter()
    .map(|op| Request {
        deadline_ms: 1000,
        account: "a".into(),
        job: "j".into(),
        op,
    })
    .collect()
}

fuzz_target!(|data: &[u8]| {
    if let Ok(req) = Request::decode(data) {
        let again = req.encode().expect("a decoded request encodes");
        assert_eq!(again, data, "decode then encode is the identity");
    }
    for req in requests() {
        if let Ok(resp) = Response::decode(data, &req) {
            let again = resp.encode().expect("a decoded response encodes");
            assert_eq!(again, data, "decode then encode is the identity");
        }
    }
    let mut stream = data;
    let _ = read_frame(&mut stream);
});
