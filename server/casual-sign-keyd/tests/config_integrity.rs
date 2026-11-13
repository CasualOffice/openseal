//! keyd's security configuration is hashed at start and checked against the operator's
//! manifest before anything else is read (ASVS 14.1.5, `ASVS-24`, `HRD-06`).

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(clippy::unwrap_used, clippy::panic)]

use std::path::PathBuf;
use std::process::{Command, Output};

const KEYD: &str = env!("CARGO_BIN_EXE_casual-sign-keyd");

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("openseal-keyd-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// keyd with only the settings this test cares about; nothing from the caller's shell.
fn keyd(dir: &std::path::Path, args: &[&str], manifest: Option<&std::path::Path>) -> Output {
    let mut c = Command::new(KEYD);
    c.args(args)
        .env_clear()
        .env("OPENSEAL_KEYD_ALLOW_LIST", dir.join("allow"))
        .env("OPENSEAL_KEYD_CLIENT_CA", dir.join("ca.pem"))
        .env("OPENSEAL_KEYD_ALIAS", "platform");
    if let Some(m) = manifest {
        c.env("OPENSEAL_CONFIG_MANIFEST", m);
    }
    c.output().unwrap()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[test]
fn a_changed_allow_list_stops_keyd_before_it_starts() {
    let dir = scratch("changed");
    std::fs::write(dir.join("allow"), "ab12 worker\n").unwrap();
    std::fs::write(dir.join("ca.pem"), "not really a CA\n").unwrap();

    let printed = keyd(&dir, &["config-manifest"], None);
    assert!(printed.status.success(), "{}", stderr(&printed));
    let manifest = String::from_utf8(printed.stdout).unwrap();
    for name in [
        "OPENSEAL_KEYD_ALLOW_LIST",
        "OPENSEAL_KEYD_CLIENT_CA",
        "OPENSEAL_KEYD_ALIAS",
    ] {
        assert!(manifest.contains(&format!("  {name}\n")), "{manifest}");
    }
    let path = dir.join("manifest");
    std::fs::write(&path, &manifest).unwrap();

    // Unchanged: the check passes and keyd goes on to fail on its (absent) TLS identity.
    let same = keyd(&dir, &[], Some(&path));
    let err = stderr(&same);
    assert!(
        err.contains("keyd: config OPENSEAL_KEYD_ALLOW_LIST sha256:"),
        "{err}"
    );
    assert!(
        err.contains("keyd: security configuration sha256:"),
        "{err}"
    );
    assert!(err.contains("matches OPENSEAL_CONFIG_MANIFEST"), "{err}");
    assert!(!err.contains("CS-KEY-0013"), "{err}");

    // A caller added to the allow list without a new manifest: refused, by name.
    std::fs::write(dir.join("allow"), "ab12 worker\ncd34 intruder\n").unwrap();
    let changed = keyd(&dir, &[], Some(&path));
    let err = stderr(&changed);
    assert!(!changed.status.success());
    assert!(
        err.contains("CS-KEY-0013: OPENSEAL_KEYD_ALLOW_LIST differs"),
        "{err}"
    );
    assert!(!err.contains("intruder"), "a value reached the log: {err}");

    // An admin list switched on without a new manifest: refused too.
    std::fs::write(dir.join("allow"), "ab12 worker\n").unwrap();
    std::fs::write(dir.join("admin"), "ef56 console\n").unwrap();
    let added = Command::new(KEYD)
        .env_clear()
        .env("OPENSEAL_KEYD_ALLOW_LIST", dir.join("allow"))
        .env("OPENSEAL_KEYD_CLIENT_CA", dir.join("ca.pem"))
        .env("OPENSEAL_KEYD_ALIAS", "platform")
        .env("OPENSEAL_KEYD_ADMIN_ALLOW_LIST", dir.join("admin"))
        .env("OPENSEAL_CONFIG_MANIFEST", &path)
        .output()
        .unwrap();
    assert!(!added.status.success());
    assert!(
        stderr(&added).contains("CS-KEY-0013: OPENSEAL_KEYD_ADMIN_ALLOW_LIST is set but not"),
        "{}",
        stderr(&added)
    );

    // The signature operations log moved elsewhere without a new manifest: refused, as
    // the log is the record of every signature keyd makes (HRD-06 review).
    let moved = Command::new(KEYD)
        .env_clear()
        .env("OPENSEAL_KEYD_ALLOW_LIST", dir.join("allow"))
        .env("OPENSEAL_KEYD_CLIENT_CA", dir.join("ca.pem"))
        .env("OPENSEAL_KEYD_ALIAS", "platform")
        .env("OPENSEAL_KEYD_OPLOG", dir.join("elsewhere.log"))
        .env("OPENSEAL_CONFIG_MANIFEST", &path)
        .output()
        .unwrap();
    assert!(!moved.status.success());
    assert!(
        stderr(&moved).contains("CS-KEY-0013: OPENSEAL_KEYD_OPLOG is set but not"),
        "{}",
        stderr(&moved)
    );

    // A manifest that cannot be read is a refusal, not a skipped check.
    let missing = keyd(&dir, &[], Some(&dir.join("absent")));
    assert!(!missing.status.success());
    assert!(stderr(&missing).contains("CS-KEY-0013: OPENSEAL_CONFIG_MANIFEST could not be read"));
    std::fs::remove_dir_all(&dir).unwrap();
}
