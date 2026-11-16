//! `casual-sign-keyd verify-oplog <path>` (ASVS-14): a backup's copy of the operation
//! log is checked before it is restored, without starting the daemon. An intact log
//! answers its line count and head; an edited or cut line is named.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

use std::path::PathBuf;
use std::process::{Command, Output};

use casual_sign_keyd::{OpLog, OpRecord};

fn scratch(test: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join("verify-oplog")
        .join(format!("{test}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn verify(path: &std::path::Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_casual-sign-keyd"))
        .env_clear()
        .arg("verify-oplog")
        .arg(path)
        .output()
        .unwrap()
}

#[test]
fn an_intact_log_verifies_and_an_edited_or_cut_one_is_refused() {
    let dir = scratch("log");
    let path = dir.join("oplog");
    let mut log = OpLog::open(&path).unwrap();
    for i in 0..3u64 {
        log.append(&OpRecord {
            time: 1_700_000_000 + i,
            caller: "ab".repeat(32),
            op: "sign",
            alias: "platform".into(),
            alg: "ecdsa-p256-sha256".into(),
            digest: format!("{i:064x}"),
            envelope: "0190a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b".into(),
            outcome: "ok",
        })
        .unwrap();
    }
    drop(log);
    let (lines, head) = casual_sign_keyd::oplog::verify(&path).unwrap();
    let o = verify(&path);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(
        String::from_utf8_lossy(&o.stdout).trim(),
        format!("oplog verified: lines={lines} head={head}")
    );
    assert_eq!(lines, 3);

    // A digest edited on line 2.
    let text = std::fs::read_to_string(&path).unwrap();
    let edited = text.replacen(&format!("{:064x}", 1), &format!("{:064x}", 9), 1);
    let bad = dir.join("edited");
    std::fs::write(&bad, edited).unwrap();
    let o = verify(&bad);
    assert!(!o.status.success());
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains("CS-KEY-0009") && err.contains("line 2"),
        "{err}"
    );

    // The last line cut short, as a copy taken mid-write would be.
    let cut = dir.join("cut");
    std::fs::write(&cut, &text[..text.len() - 10]).unwrap();
    let o = verify(&cut);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("line 3"));

    let o = Command::new(env!("CARGO_BIN_EXE_casual-sign-keyd"))
        .env_clear()
        .arg("verify-oplog")
        .output()
        .unwrap();
    assert!(!o.status.success());
}
