//! Lay out the XFA form of each PDF given and write the static PDF beside it
//! (`XFA-01` corpus run).
//!
//! ```sh
//! cargo run -p casual-sign-xfa --example xfa_corpus -- OUT_DIR FILE.pdf...
//! ```
//!
//! Prints one tab-separated line per file: name, outcome (`laid-out`, `no-xfa`, or the
//! refusal code), pages, widgets, fields by kind, draws, images drawn and skipped,
//! scripts ignored, missing glyphs, symbol characters, overflowed objects.
// A developer tool: a panic is the failure report.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::print_stdout)]

use std::path::Path;

use casual_sign_pdf::{Credentials, Limits, xfa_packets};
use casual_sign_xfa::{Faces, XfaLimits, lay_out};

fn main() {
    let mut args = std::env::args().skip(1);
    let out = args.next().expect("OUT_DIR FILE.pdf...");
    std::fs::create_dir_all(&out).unwrap();
    let faces = Faces::bundled();
    println!(
        "file\toutcome\tpages\twidgets\ttext\tnumeric\tdate\tcheck\tchoice\tsignature\tdraws\timages\timages_skipped\tscripts_ignored\tinert\tmissing_glyphs\tsymbol_chars\toverflowed\tscreen_only\tms"
    );
    for f in args {
        let name = Path::new(&f)
            .file_name()
            .unwrap()
            .to_string_lossy()
            .to_string();
        let bytes = std::fs::read(&f).unwrap();
        let start = std::time::Instant::now();
        let packets =
            match xfa_packets(&bytes, &Limits::default(), &Credentials::default(), &|| {
                false
            }) {
                Ok(Some(p)) => p,
                Ok(None) => {
                    println!("{name}\tno-xfa");
                    continue;
                }
                Err(e) => {
                    println!("{name}\t{}", e.code());
                    continue;
                }
            };
        match lay_out(&packets, &faces, &XfaLimits::default(), &|| false) {
            Ok(laid) => {
                let r = &laid.report;
                std::fs::write(Path::new(&out).join(&name), &laid.pdf).unwrap();
                println!(
                    "{name}\tlaid-out\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    r.pages,
                    r.widgets,
                    r.fields.text,
                    r.fields.numeric,
                    r.fields.date,
                    r.fields.check,
                    r.fields.choice,
                    r.fields.signature,
                    r.draws,
                    r.images,
                    r.images_skipped,
                    r.scripts_ignored,
                    r.inert_fields,
                    r.missing_glyphs,
                    r.symbol_chars,
                    r.overflowed,
                    r.screen_only,
                    start.elapsed().as_millis()
                );
            }
            Err(e) => println!("{name}\t{}", e.code()),
        }
    }
}
