//! Extract the text of every PDF in a directory: the stage 1C corpus run.
//!
//! ```sh
//! cargo run --release -p casual-sign-fields --example extract_dir -- <dir> [<text-out-dir>]
//! ```
//!
//! Prints one line per file (pages, characters, findings, milliseconds) and a summary:
//! files, refused at admission, panics, files with any text, mean time, slowest file.
//! With a second argument, writes `<name>.txt` there (pages joined by form feeds) for
//! the pypdf comparison in `tools/compare_pypdf.py`.

// An example run by hand: a panic here is the tool failing, which is what it reports.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::time::Instant;

use casual_sign_fields::extract_text;
use casual_sign_pdf::{Limits, admit};

fn never() -> bool {
    false
}

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = PathBuf::from(args.next().expect("usage: extract_dir <dir> [<text-out>]"));
    let out = args.next().map(PathBuf::from);
    if let Some(o) = &out {
        std::fs::create_dir_all(o).unwrap();
    }
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_file())
        .collect();
    files.sort();
    let (mut n, mut refused, mut panics, mut with_text) = (0u32, 0u32, 0u32, 0u32);
    let mut total_ms = 0.0f64;
    let mut slowest = (0.0f64, String::new());
    for path in &files {
        let Ok(bytes) = std::fs::read(path) else {
            continue;
        };
        n += 1;
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let start = Instant::now();
        let r = catch_unwind(AssertUnwindSafe(|| {
            let mut a = admit(&bytes, &Limits::default(), &never).map_err(|e| e.code())?;
            let pages = a.report.pages.clone();
            extract_text(&mut a.document, &pages, &never).map_err(|e| e.code())
        }));
        let ms = start.elapsed().as_secs_f64() * 1000.0;
        total_ms += ms;
        if ms > slowest.0 {
            slowest = (ms, name.clone());
        }
        match r {
            Err(_) => {
                panics += 1;
                println!("{name}\tPANIC\t{ms:.1} ms");
            }
            Ok(Err(code)) => {
                refused += 1;
                println!("{name}\trefused {code}\t{ms:.1} ms");
            }
            Ok(Ok(pages)) => {
                let texts: Vec<String> = pages.iter().map(|p| p.text()).collect();
                let chars: usize = texts.iter().map(|t| t.chars().count()).sum();
                if chars > 0 {
                    with_text += 1;
                }
                let mut codes: Vec<String> = pages
                    .iter()
                    .flat_map(|p| {
                        p.findings
                            .iter()
                            .map(|f| format!("{}:{:?}", f.code, f.issue))
                    })
                    .collect();
                codes.sort();
                codes.dedup();
                println!(
                    "{name}\t{} pages\t{chars} chars\t{ms:.1} ms\t{}",
                    pages.len(),
                    codes.join(",")
                );
                if let Some(o) = &out {
                    std::fs::write(o.join(format!("{name}.txt")), texts.join("\u{c}")).unwrap();
                }
            }
        }
    }
    let mean = if n > 0 { total_ms / f64::from(n) } else { 0.0 };
    println!(
        "SUMMARY files {n} refused {refused} panics {panics} with_text {with_text} mean_ms {mean:.1} slowest {} ({:.1} ms)",
        slowest.1, slowest.0
    );
}
