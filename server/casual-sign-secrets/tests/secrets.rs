//! What a deployment gets wrong, and what it must be told. Copied from OpenCalc's
//! `casual-calc-secrets` tests (PROVENANCE.md), with OpenSeal names, a scratch directory
//! under `target/`, and a test that a secret never prints.
// Test code: a panic is the failure report.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write as _;
use std::path::PathBuf;

use casual_sign_secrets::{Secret, SecretError, resolve, unknown_secret_files};

/// A file with `body` in it, in this test binary's scratch directory under `target/`.
fn secret_file(name: &str, body: &[u8]) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("openseal-secrets-{name}"));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let path = dir.join("secret");
    let mut f = std::fs::File::create(&path).expect("create");
    f.write_all(body).expect("write");
    path
}

fn some(v: &str) -> Result<Option<Secret>, SecretError> {
    Ok(Some(Secret::new(v.to_owned())))
}

/// **The point of the crate: a mounted secret file is read.**
#[test]
fn a_mounted_file_is_read() {
    let path = secret_file("read", b"123456");
    let got = resolve(
        "OPENSEAL_KEYD_PKCS11_PIN",
        None,
        Some(path.display().to_string()),
    );
    assert_eq!(got, some("123456"));
}

/// Every way of writing a file adds a newline, and no secret ends in one.
#[test]
fn a_trailing_newline_is_not_part_of_the_secret() {
    for (label, body) in [("lf", "key\n"), ("crlf", "key\r\n")] {
        let path = secret_file(label, body.as_bytes());
        assert_eq!(
            resolve("X", None, Some(path.display().to_string())),
            some("key"),
            "{label}"
        );
    }
}

/// Only *one* trailing newline, and nothing else is touched.
#[test]
fn nothing_but_the_final_newline_is_stripped() {
    let path = secret_file("inner", b"  spaced key \n\n");
    assert_eq!(
        resolve("X", None, Some(path.display().to_string())),
        some("  spaced key \n")
    );
}

/// An empty file is a mount that did not happen.
#[test]
fn an_empty_file_is_refused_rather_than_treated_as_unset() {
    let path = secret_file("empty", b"\n");
    let err = resolve(
        "OPENSEAL_KEYD_PKCS11_PIN",
        None,
        Some(path.display().to_string()),
    )
    .unwrap_err();
    assert!(matches!(err, SecretError::Empty { .. }));
    assert_eq!(err.code(), "CS-KEY-0005");
}

/// A misspelled path must stop the server, not fall back to the environment.
#[test]
fn an_unreadable_file_is_refused() {
    let why = resolve(
        "OPENSEAL_KEYD_PKCS11_PIN",
        None,
        Some("/nowhere/at/all".into()),
    )
    .expect_err("a path that does not exist");
    assert!(matches!(why, SecretError::Unreadable { .. }));
    assert!(
        why.to_string().contains("/nowhere/at/all"),
        "the operator is not told which path: {why}"
    );
}

/// **Both set is an error, not a precedence rule.**
#[test]
fn setting_both_is_refused() {
    let path = secret_file("both", b"from-the-file");
    let why = resolve(
        "OPENSEAL_KEYD_PKCS11_PIN",
        Some("from-the-environment".into()),
        Some(path.display().to_string()),
    )
    .expect_err("both forms set");
    assert_eq!(
        why,
        SecretError::Ambiguous {
            name: "OPENSEAL_KEYD_PKCS11_PIN".to_owned()
        }
    );
    assert!(
        why.to_string().contains("docker inspect"),
        "the operator is not told which one to keep: {why}"
    );
}

/// The environment still works.
#[test]
fn the_environment_variable_still_works() {
    assert_eq!(resolve("X", Some("plain".into()), None), some("plain"));
    assert_eq!(resolve("X", None, None), Ok(None));
}

/// A secret never prints: not in `Debug`, not inside an error's `Debug`.
#[test]
fn a_secret_never_prints() {
    let s = Secret::new("987654".to_owned());
    assert_eq!(format!("{s:?}"), "Secret(..)");
    assert_eq!(format!("{:?}", Some(s.clone())), "Some(Secret(..))");
    assert_eq!(s.expose(), "987654");
}

/// A misspelled secret file is a mount that is present, correct and ignored.
#[test]
fn a_misspelled_secret_file_is_named() {
    let known = ["OPENSEAL_KEYD_PKCS11_PIN_FILE"];
    let present = [
        "OPENSEAL_KEYD_PKCS11_PIN_FILE",  // read
        "OPENSEAL_KEYD_PKCS11_PINS_FILE", // the plural typo, read by nothing
        "OPENSEAL_KEYD_LISTEN",           // not a file
        "PATH",                           // not ours
    ];
    assert_eq!(
        unknown_secret_files(present.iter(), &known),
        vec!["OPENSEAL_KEYD_PKCS11_PINS_FILE".to_owned()]
    );
}

/// And a correctly-spelled environment says nothing.
#[test]
fn a_correct_environment_produces_no_complaint() {
    let known = ["OPENSEAL_KEYD_PKCS11_PIN_FILE"];
    assert!(
        unknown_secret_files(["OPENSEAL_KEYD_PKCS11_PIN_FILE", "HOME"].iter(), &known).is_empty()
    );
}
