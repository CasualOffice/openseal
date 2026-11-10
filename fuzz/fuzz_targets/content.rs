//! Bytes into the content-stream tokenizer (`PDF-API-01`, `F-007`). Any panic or hang
//! is a finding; the token stream must end, and every error must carry a code.
#![no_main]

use casual_sign_pdf::{ContentLexer, ContentToken, Limits};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = Limits::default();
    let mut tokens: usize = 0;
    let mut last = 0usize;
    let mut lexer = ContentLexer::new(data, &limits);
    while let Some(t) = lexer.next() {
        tokens += 1;
        // Every token consumes input: at most one token per byte, plus one.
        assert!(tokens <= data.len() + 1, "more tokens than bytes");
        match t {
            Ok(ContentToken::InlineImage { data: d, .. }) => assert!(d.len() <= data.len()),
            Ok(_) => {}
            Err(e) => assert!(e.code().starts_with("CS-PDF-")),
        }
        let pos = lexer.position();
        assert!(pos >= last && pos <= data.len());
        last = pos;
    }
});
