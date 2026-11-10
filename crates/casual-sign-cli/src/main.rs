//! `openseal`: the OpenSeal engine on the command line (stage 1J, `T-1J`, docs/06 M1).
//!
//! A host over `casual-sign-sdk` (docs/19): it reads and writes files, reads the system
//! clock, reaches a time-stamping authority and revocation responders over HTTP, and signs
//! with a development file key. The engine it drives does none of that. `openseal help`
//! lists the commands, their exit codes and their JSON output.
//!
//! The binary is native-only. The workspace's wasm32 check builds this crate too, so on
//! `wasm32` it compiles to a stub with no dependencies of its own; the main session is to
//! give that check `--exclude casual-sign-cli` instead (reported in `T-1J`).

#[cfg(not(target_arch = "wasm32"))]
mod app;
#[cfg(not(target_arch = "wasm32"))]
mod args;
#[cfg(not(target_arch = "wasm32"))]
mod key;
#[cfg(not(target_arch = "wasm32"))]
mod net;
#[cfg(not(target_arch = "wasm32"))]
mod output;

#[cfg(not(target_arch = "wasm32"))]
fn main() -> std::process::ExitCode {
    std::process::ExitCode::from(app::run(std::env::args().skip(1).collect()))
}

/// No CLI in a browser: `casual-sign-wasm` is the engine's binding there.
#[cfg(target_arch = "wasm32")]
fn main() {}
