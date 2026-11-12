//! The dependency gates of ADR-029 (`SEC-I09`; review defects 2, 4 and 5), read from
//! `cargo tree` over the committed lock file:
//!
//! - **A caller links no inference stack.** With `--no-default-features` (how the worker
//!   depends on modeld) the tree holds no ONNX Runtime binding, OCR pipeline, rasteriser,
//!   tokenizer or image decoder.
//! - **Nothing downloads at build time.** With every feature on, `ort`, `oar-ocr` and
//!   `tokenizers` carry none of their download or network features.
// Test code: a panic is the failure report.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;

/// Crates that only the daemon (the `server` feature) may bring in.
const SERVER_ONLY: &[&str] = &[
    "ort",
    "ort-sys",
    "oar-ocr",
    "oar-ocr-core",
    "hayro",
    "hayro-syntax",
    "hayro-jbig2",
    "hayro-jpeg2000",
    "hayro-ccitt",
    "tokenizers",
    "onig",
    "onig_sys",
    "esaxx-rs",
    "image_hasher",
    "imageproc",
    "image",
    "pdfium-render",
];

/// `(crate, feature)` pairs that fetch something at build or run time.
const FETCHING_FEATURES: &[(&str, &str)] = &[
    ("ort", "download-binaries"),
    ("ort", "tls-native"),
    ("ort", "tls-rustls"),
    ("ort-sys", "download-binaries"),
    ("oar-ocr", "download-binaries"),
    ("oar-ocr", "auto-download"),
    ("oar-ocr-core", "download-binaries"),
    ("oar-ocr-core", "auto-download"),
    ("tokenizers", "http"),
    ("tokenizers", "esaxx_fast"),
];

/// The crate names in `cargo tree --prefix none` output.
fn crate_names(tree: &str) -> Vec<&str> {
    tree.lines()
        .filter_map(|l| l.split_whitespace().next())
        .collect()
}

/// The server-only crates present in `tree`.
fn server_only_present(tree: &str) -> Vec<String> {
    let names = crate_names(tree);
    SERVER_ONLY
        .iter()
        .filter(|c| names.contains(c))
        .map(|c| (*c).to_owned())
        .collect()
}

/// The fetching features present in `cargo tree -e features --prefix none` output, whose
/// feature lines read `name feature "feat"`.
fn fetching_present(tree: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in tree.lines() {
        let mut words = line.split_whitespace();
        let (Some(name), Some("feature"), Some(feat)) = (words.next(), words.next(), words.next())
        else {
            continue;
        };
        let feat = feat.trim_matches('"');
        if FETCHING_FEATURES.contains(&(name, feat)) {
            out.push(format!("{name}/{feat}"));
        }
    }
    out.sort();
    out.dedup();
    out
}

fn cargo_tree(args: &[&str]) -> String {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let out = Command::new(cargo)
        .args(["tree", "-p", "casual-sign-modeld", "--locked", "--offline"])
        .args(["--prefix", "none", "--target", "all"])
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo runs");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "cargo tree {args:?} failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The listing is real: the client's own TLS stack is in it.
    assert!(crate_names(&text).contains(&"rustls"), "{text}");
    text
}

/// **The worker's view of modeld holds no inference dependency** (review defect 4).
#[test]
fn the_client_only_tree_has_no_inference_stack() {
    let tree = cargo_tree(&["--no-default-features", "-e", "normal,build"]);
    let found = server_only_present(&tree);
    assert!(found.is_empty(), "client-only tree links {found:?}");
}

/// **The worker links no inference stack** (`SEC-I14`): whatever it depends on, the
/// secret-holding worker's own tree holds no ONNX Runtime binding, OCR pipeline,
/// rasteriser, tokenizer or image decoder.
#[test]
fn the_worker_links_no_inference_stack() {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let out = Command::new(cargo)
        .args(["tree", "-p", "casual-sign-worker", "--locked", "--offline"])
        .args(["--prefix", "none", "--target", "all", "-e", "normal,build"])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo runs");
    let tree = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "cargo tree -p casual-sign-worker failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(crate_names(&tree).contains(&"casual-sign-worker"), "{tree}");
    let found = server_only_present(&tree);
    assert!(found.is_empty(), "the worker links {found:?}");
}

/// **No dependency downloads binaries or models** (review defect 2, `SEC-I09`).
#[test]
fn no_dependency_has_a_fetching_feature() {
    let tree = cargo_tree(&["--all-features", "-e", "features,normal,build"]);
    let found = fetching_present(&tree);
    assert!(found.is_empty(), "fetching features on: {found:?}");
}

/// The two readers find what they look for (so the gates above cannot pass by misreading
/// cargo's output).
#[test]
fn the_tree_readers_find_forbidden_entries() {
    let tree = "casual-sign-modeld v0.0.1 (/x)\nrustls v0.23.46\nort v2.0.0-rc.13\n\
                ort feature \"default\"\nort feature \"download-binaries\"\n\
                oar-ocr feature \"auto-download\"\ntokenizers feature \"onig\"\n";
    // A feature line names its crate too: a crate with a feature on is in the tree.
    assert_eq!(server_only_present(tree), ["ort", "oar-ocr", "tokenizers"]);
    assert_eq!(
        fetching_present(tree),
        ["oar-ocr/auto-download", "ort/download-binaries"]
    );
    assert!(server_only_present("rustls v0.23.46\nimage-webp v1\n").is_empty());
}
