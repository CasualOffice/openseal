//! Crash points for the process crash tests (Phase 2 exit item 2, `P2-CRASH`).
//!
//! With the `crash-points` feature, [`point`] kills this process with `SIGKILL` when
//! `OPENSEAL_CRASH_AT` names the point it is called at: no destructor runs, no
//! transaction commits, no response is written, exactly as when an operator or the
//! kernel kills the server or worker. Without the feature (every release and every
//! deployed build) each function here is empty and the variable is never read.
//!
//! A point is `<kind>:<subject>`; `OPENSEAL_CRASH_AT=<kind>:<suffix>` fires at the first
//! point of that kind whose subject ends with `suffix` (for example
//! `before_commit:Send`, `after_commit:/finish`, `worker:EmailSent:send_invitation`).
//! `OPENSEAL_CRASH_AT=startup` fires at [`startup`], so a test can tell a binary built
//! with the feature from one built without it. [`hold`] (`OPENSEAL_HOLD_AT`, `HRD-01`)
//! parks the process at a point instead, so a chaos test can stop it, cut a dependency
//! or race a second worker while it stands mid-job.

/// Kill this process if `OPENSEAL_CRASH_AT` names `kind` and a suffix of `subject`.
#[cfg(feature = "crash-points")]
pub fn point(kind: &str, subject: &str) {
    let Ok(at) = std::env::var("OPENSEAL_CRASH_AT") else {
        return;
    };
    let Some((k, suffix)) = at.split_once(':') else {
        return;
    };
    if k == kind && subject.ends_with(suffix) {
        die();
    }
}

/// Without the feature: nothing.
#[cfg(not(feature = "crash-points"))]
#[inline(always)]
pub fn point(_kind: &str, _subject: &str) {}

/// The `before_commit` point of a command: its subject is the command's variant name
/// (`Send`, `Finish`, ...), compared and never logged.
#[cfg(feature = "crash-points")]
pub fn before_commit<T: core::fmt::Debug>(command: &T) {
    let debug = format!("{command:?}");
    let name: String = debug
        .chars()
        .take_while(char::is_ascii_alphanumeric)
        .collect();
    point("before_commit", &name);
}

/// Without the feature: nothing.
#[cfg(not(feature = "crash-points"))]
#[inline(always)]
pub fn before_commit<T: core::fmt::Debug>(_command: &T) {}

/// Hold this thread at a point (`HRD-01` chaos tests): when `OPENSEAL_HOLD_AT` names
/// `kind` and a suffix of `subject` (as `OPENSEAL_CRASH_AT` does), the first time only,
/// create `<OPENSEAL_HOLD_DIR>/reached` and wait until `<OPENSEAL_HOLD_DIR>/release`
/// exists. The test then stops, starves or races the process while it stands mid-job,
/// and releases it.
#[cfg(feature = "crash-points")]
pub fn hold(kind: &str, subject: &str) {
    use std::sync::atomic::{AtomicBool, Ordering};
    static HELD: AtomicBool = AtomicBool::new(false);
    let (Ok(at), Ok(dir)) = (
        std::env::var("OPENSEAL_HOLD_AT"),
        std::env::var("OPENSEAL_HOLD_DIR"),
    ) else {
        return;
    };
    let Some((k, suffix)) = at.split_once(':') else {
        return;
    };
    if k != kind || !subject.ends_with(suffix) || HELD.swap(true, Ordering::SeqCst) {
        return;
    }
    let dir = std::path::PathBuf::from(dir);
    let _ = std::fs::write(dir.join("reached"), b"");
    while !dir.join("release").exists() {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
}

/// Without the feature: nothing.
#[cfg(not(feature = "crash-points"))]
#[inline(always)]
pub fn hold(_kind: &str, _subject: &str) {}

/// Kill this process if `OPENSEAL_CRASH_AT=startup` (the feature probe).
#[cfg(feature = "crash-points")]
pub fn startup() {
    if std::env::var("OPENSEAL_CRASH_AT").as_deref() == Ok("startup") {
        die();
    }
}

/// Without the feature: nothing.
#[cfg(not(feature = "crash-points"))]
#[inline(always)]
pub fn startup() {}

/// `SIGKILL` to ourselves through `kill(1)` (no `unsafe`, no crash report); `abort` if
/// that is not possible. Never returns.
#[cfg(feature = "crash-points")]
pub fn die() -> ! {
    eprintln!("crash point reached: SIGKILL");
    let _ = std::process::Command::new("kill")
        .arg("-KILL")
        .arg(std::process::id().to_string())
        .status();
    std::thread::sleep(std::time::Duration::from_secs(5));
    std::process::abort()
}
