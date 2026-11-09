//! A deterministic mutation loop over valid documents: no input may panic, hang or
//! give different answers on two runs. The fuzz target (`fuzz/`) does the same with
//! coverage guidance; this runs in every `cargo test`.
// Test code: a panic is the failure report.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects
)]

mod common;

use casual_sign_pdf::{Limits, admit, admit_strict};
use common::{classic, never, pages, stream, xref_stream_file, zlib};

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

const TOKENS: &[&[u8]] = &[
    b"<<",
    b">>",
    b"[",
    b"]",
    b"(",
    b")",
    b"<",
    b">",
    b"/",
    b"%",
    b"\\",
    b" 0 R",
    b" 1 0 R",
    b"999999999 0 R",
    b"stream\n",
    b"endstream",
    b"endobj",
    b" 1 0 obj ",
    b"xref\n0 1\n",
    b"trailer",
    b"startxref\n0\n",
    b"%%EOF",
    b"/Length 99999999",
    b"/Length 1 0 R",
    b"/Filter/FlateDecode",
    b"/Prev 0",
    b"/Kids[2 0 R]",
    b"/Type/ObjStm",
    b"/N 2147483647",
    b"/W[8 8 8]",
    b"/Size 2147483648",
    b"-0.5",
    b"1e309",
    b"#00",
    b"\x00",
    b"\xff",
];

fn mutate(base: &[u8], rng: &mut Rng) -> Vec<u8> {
    let mut v = base.to_vec();
    for _ in 0..1 + rng.below(4) {
        let at = rng.below(v.len() + 1);
        match rng.below(7) {
            0 if !v.is_empty() => {
                let i = rng.below(v.len());
                v[i] ^= 1 << rng.below(8);
            }
            1 if !v.is_empty() => {
                let i = rng.below(v.len());
                v[i] = rng.next() as u8;
            }
            2 => {
                let t = TOKENS[rng.below(TOKENS.len())];
                v.splice(at..at, t.iter().copied());
            }
            3 => {
                let end = (at + rng.below(64)).min(v.len());
                v.drain(at..end);
            }
            4 => v.truncate(at),
            5 => {
                let end = (at + rng.below(256)).min(v.len());
                let chunk = v[at..end].to_vec();
                let to = rng.below(v.len() + 1);
                v.splice(to..to, chunk);
            }
            _ => {
                // Replace a digit run with a large number.
                if let Some(p) = v.iter().skip(at).position(u8::is_ascii_digit) {
                    let p = at + p;
                    v.splice(p..p + 1, b"4294967296".iter().copied());
                }
            }
        }
    }
    v
}

fn bases() -> Vec<Vec<u8>> {
    let mut objs = pages(2);
    objs[0].1 = b"<</Type/Catalog/Pages 2 0 R/AcroForm<</Fields[9 0 R]>>/OpenAction<</S/JavaScript/JS(1)>>>>".to_vec();
    objs.push((9, b"<</FT/Tx/T(a)/Rect[0 0 10 10]>>".to_vec()));
    let objs2 = vec![
        (1, b"<</Type/Catalog/Pages 2 0 R>>".to_vec()),
        (4, stream("/Filter/FlateDecode", &zlib(b"BT (x) Tj ET"))),
    ];
    let comp = vec![
        (
            2,
            b"<</Type/Pages/Kids[3 0 R]/MediaBox[0 0 10 10]>>".to_vec(),
        ),
        (3, b"<</Type/Page/Parent 2 0 R/Contents 4 0 R>>".to_vec()),
    ];
    let base = classic(&pages(1), "");
    vec![
        classic(&pages(3), ""),
        classic(&objs, ""),
        xref_stream_file(&objs2, &comp, 5),
        common::append_update(
            &base,
            &[(1, b"<</Type/Catalog/Pages 2 0 R/V 1>>".to_vec())],
            5,
        ),
    ]
}

#[test]
fn mutated_documents_never_panic_and_answer_deterministically() {
    let limits = Limits {
        max_stream_bytes: 1 << 20,
        max_total_decoded_bytes: 4 << 20,
        max_objects: 10_000,
        ..Limits::default()
    };
    let iterations = std::env::var("MUTATION_ITERATIONS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4000);
    let mut rng = Rng(0x0123_4567_89ab_cdef);
    let mut outcomes = [0usize; 2];
    for base in bases() {
        assert!(
            admit_strict(&base, &Limits::default(), &never).is_ok(),
            "bases are valid"
        );
        for i in 0..iterations {
            let input = mutate(&base, &mut rng);
            let a = admit(&input, &limits, &never).map(|x| x.report);
            let s = admit_strict(&input, &limits, &never).map(|x| x.report);
            outcomes[usize::from(a.is_ok())] += 1;
            if i % 16 == 0 {
                // Same bytes, same answer.
                assert_eq!(a, admit(&input, &limits, &never).map(|x| x.report));
                assert_eq!(s, admit_strict(&input, &limits, &never).map(|x| x.report));
            }
            // Strict success implies default success.
            if s.is_ok() {
                assert!(
                    a.is_ok(),
                    "strict opened what default refused: {:?}",
                    a.err()
                );
            }
        }
    }
    println!("refused {}, opened {}", outcomes[0], outcomes[1]);
    assert!(outcomes[1] > 0 && outcomes[0] > 0);
}
