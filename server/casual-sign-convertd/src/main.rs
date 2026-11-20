//! `casual-sign-convertd`: the conversion daemon (ADR-042). Configured by environment; it
//! reads no secret and needs no network.
//!
//! | Variable | Meaning |
//! | --- | --- |
//! | `OPENSEAL_CONVERTD_SOCKET` | The Unix socket to listen on (default `/run/convertd/convertd.sock`); a stale file there is replaced, and the socket is made readable and writable by its owner only |
//! | `OPENSEAL_CONVERTD_FONTS` | A font directory searched before the system's (default none) |
//! | `OPENSEAL_CONVERTD_SLOTS` | Jobs at once, 1 to 64 (default 2); a request beyond them is answered `CS-CNV-0005 busy` |
//! | `OPENSEAL_CONVERTD_JOB_SECONDS` | Wall-clock seconds per job before its child is killed, 1 to 600 (default 60) |
//! | `OPENSEAL_CONVERTD_MEMORY` | The child's address-space limit in MiB, 256 to 16384 (default 2048; Linux) |
//!
//! `casual-sign-convertd health` pings the socket and exits 0 when the daemon answers
//! (the container's health check); `casual-sign-convertd convert-child …` is the per-job
//! child, started by the daemon only.

use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use casual_sign_convertd::child::{CHILD_ARG, child_main};
use casual_sign_convertd::daemon::{Daemon, Limits, ping};

const DEFAULT_SOCKET: &str = "/run/convertd/convertd.sock";

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.trim().is_empty())
}

fn num(name: &'static str, lo: u64, hi: u64, default: u64) -> Result<u64, &'static str> {
    match var(name) {
        None => Ok(default),
        Some(v) => v
            .trim()
            .parse::<u64>()
            .ok()
            .filter(|n| (lo..=hi).contains(n))
            .ok_or(name),
    }
}

fn fail(what: &str) -> ExitCode {
    eprintln!(
        r#"{{"level":"error","target":"convertd","msg":"convertd does not start","setting":"{what}"}}"#
    );
    ExitCode::from(1)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some(CHILD_ARG) {
        return child_main(args.get(1..).unwrap_or_default());
    }
    let socket =
        PathBuf::from(var("OPENSEAL_CONVERTD_SOCKET").unwrap_or_else(|| DEFAULT_SOCKET.into()));
    if args.first().map(String::as_str) == Some("health") {
        return if ping(&socket, Duration::from_secs(3)) {
            ExitCode::SUCCESS
        } else {
            ExitCode::from(1)
        };
    }
    if !args.is_empty() {
        return fail("arguments");
    }
    let limits = match (
        num("OPENSEAL_CONVERTD_SLOTS", 1, 64, 2),
        num("OPENSEAL_CONVERTD_JOB_SECONDS", 1, 600, 60),
        num("OPENSEAL_CONVERTD_MEMORY", 256, 16_384, 2_048),
    ) {
        (Ok(slots), Ok(secs), Ok(mib)) => Limits {
            job_time: Duration::from_secs(secs),
            address_space: mib.saturating_mul(1 << 20),
            cpu_seconds: secs,
            slots: usize::try_from(slots).unwrap_or(1),
        },
        (Err(n), _, _) | (_, Err(n), _) | (_, _, Err(n)) => return fail(n),
    };
    let Ok(exe) = std::env::current_exe() else {
        return fail("current_exe");
    };
    let fonts = var("OPENSEAL_CONVERTD_FONTS").map(PathBuf::from);
    let _ = std::fs::remove_file(&socket);
    let listener = match UnixListener::bind(&socket) {
        Ok(l) => l,
        Err(_) => return fail("OPENSEAL_CONVERTD_SOCKET"),
    };
    if std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600)).is_err() {
        return fail("OPENSEAL_CONVERTD_SOCKET");
    }
    eprintln!(
        r#"{{"level":"info","target":"convertd","msg":"listening","slots":{},"job_seconds":{},"memory_mib":{},"converter":"{}"}}"#,
        limits.slots,
        limits.job_time.as_secs(),
        limits.address_space >> 20,
        casual_sign_convertd::CONVERTER
    );
    let daemon = Daemon::new(exe, fonts, limits);
    match daemon.serve(&listener) {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => fail("accept"),
    }
}
