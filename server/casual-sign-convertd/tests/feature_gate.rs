//! The dependency gate of ADR-042 (docs/07 `SEC-P13`), read from `cargo tree` over the
//! committed lock file, as modeld's `tests/feature_gate.rs`: **the API server links no
//! DOCX parser, image decoder or font code.** It depends on convertd with
//! `default-features = false` (the client and the wire code only); the converter runs in
//! convertd's own container.
// Test code: a panic is the failure report.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::process::Command;

/// Crates only the daemon (the `server` feature) may bring in.
/// (`png` is not listed: the server decodes signature images with it itself.)
const SERVER_ONLY: &[&str] = &[
    "docxide-pdf",
    "zip",
    "roxmltree",
    "image",
    "tiff",
    "ttf-parser",
    "subsetter",
    "pdf-writer",
    "memmap2",
];

fn crate_names(tree: &str) -> Vec<&str> {
    tree.lines()
        .filter_map(|l| l.split_whitespace().next())
        .collect()
}

fn server_only_present(tree: &str) -> Vec<String> {
    let names = crate_names(tree);
    SERVER_ONLY
        .iter()
        .filter(|c| names.contains(c))
        .map(|c| (*c).to_owned())
        .collect()
}

fn tree(package: &str, extra: &[&str]) -> String {
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let out = Command::new(cargo)
        .args(["tree", "-p", package, "--locked", "--offline"])
        .args(["--prefix", "none", "--target", "all", "-e", "normal,build"])
        .args(extra)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo runs");
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    assert!(
        out.status.success(),
        "cargo tree -p {package} failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    // The listing is real: the client's own runtime is in it.
    assert!(crate_names(&text).contains(&"tokio"), "{text}");
    text
}

#[test]
fn the_client_only_tree_has_no_converter() {
    let found = server_only_present(&tree("casual-sign-convertd", &["--no-default-features"]));
    assert!(found.is_empty(), "client-only tree links {found:?}");
}

#[test]
fn the_api_server_links_no_converter() {
    let t = tree("casual-sign-server", &[]);
    assert!(crate_names(&t).contains(&"casual-sign-convertd"), "{t}");
    let found = server_only_present(&t);
    assert!(found.is_empty(), "the API server links {found:?}");
}

#[test]
fn the_daemon_tree_does_hold_the_converter() {
    // So the gates above cannot pass by misreading cargo's output.
    let found = server_only_present(&tree("casual-sign-convertd", &[]));
    assert!(found.contains(&"docxide-pdf".to_owned()), "{found:?}");
}
