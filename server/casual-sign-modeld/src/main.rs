//! `casual-sign-modeld`: the model daemon (ADR-029, docs/33). Configured by environment;
//! adapted from keyd's `main.rs`. It reads no secret other than its own TLS key, and
//! refuses to start unless the bundle directory matches the manifest compiled into it.
//!
//! | Variable | Meaning |
//! | --- | --- |
//! | `OPENSEAL_MODELD_LISTEN` | Address to bind (default `127.0.0.1:7444`) |
//! | `OPENSEAL_MODELD_TLS_CERT`, `OPENSEAL_MODELD_TLS_KEY` | Server certificate chain and key (PEM paths) |
//! | `OPENSEAL_MODELD_CLIENT_CA` | CA a client certificate must chain to (PEM path) |
//! | `OPENSEAL_MODELD_ALLOW_LIST` | Allowed callers: `sha256-fingerprint [name]` per line |
//! | `OPENSEAL_MODELD_OPLOG` | The operation log (append-only, hash-chained; counts and ids only) |
//! | `OPENSEAL_MODELD_BUNDLE` | The bundle directory, read-only (default `/opt/openseal/models`) |
//! | `OPENSEAL_MODELD_PROFILES` | Comma-separated profiles that must be complete (`ocr,templates,...`; default none) |
//! | `OPENSEAL_MODELD_SLOTS` | Operations at once (default: half the cores, at least 1) |

use std::path::Path;
use std::process::ExitCode;

use casual_sign_modeld::{
    AllowList, Bundle, Manifest, ModelService, Modeld, ModeldError, ModeldLimits, OpLog, server_tls,
};

fn var(name: &'static str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

fn need(name: &'static str) -> Result<String, ModeldError> {
    var(name).ok_or(ModeldError::Setting(name))
}

fn read(name: &'static str, path: &str) -> Result<Vec<u8>, ModeldError> {
    std::fs::read(Path::new(path)).map_err(|_| ModeldError::Setting(name))
}

fn run() -> Result<(), ModeldError> {
    // The bundle first: a tampered or incomplete bundle stops modeld before it listens.
    let manifest = Manifest::embedded()?;
    let dir = var("OPENSEAL_MODELD_BUNDLE").unwrap_or_else(|| "/opt/openseal/models".into());
    let profiles: Vec<String> = var("OPENSEAL_MODELD_PROFILES")
        .map(|p| {
            p.split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let bundle = Bundle::verify(Path::new(&dir), &manifest, &profiles)?;

    let tls = server_tls(
        &read(
            "OPENSEAL_MODELD_TLS_CERT",
            &need("OPENSEAL_MODELD_TLS_CERT")?,
        )?,
        &read("OPENSEAL_MODELD_TLS_KEY", &need("OPENSEAL_MODELD_TLS_KEY")?)?,
        &read(
            "OPENSEAL_MODELD_CLIENT_CA",
            &need("OPENSEAL_MODELD_CLIENT_CA")?,
        )?,
    )?;
    let allow_text = read(
        "OPENSEAL_MODELD_ALLOW_LIST",
        &need("OPENSEAL_MODELD_ALLOW_LIST")?,
    )?;
    let allow = AllowList::parse(
        core::str::from_utf8(&allow_text)
            .map_err(|_| ModeldError::Setting("OPENSEAL_MODELD_ALLOW_LIST"))?,
    )?;
    if allow.is_empty() {
        return Err(ModeldError::Setting("OPENSEAL_MODELD_ALLOW_LIST (empty)"));
    }
    let log = OpLog::open(Path::new(&need("OPENSEAL_MODELD_OPLOG")?))?;
    let cores = std::thread::available_parallelism().map_or(2, std::num::NonZeroUsize::get);
    let mut limits = ModeldLimits {
        slots: (cores / 2).max(1),
        ..ModeldLimits::default()
    };
    if let Some(n) = var("OPENSEAL_MODELD_SLOTS") {
        limits.slots = n
            .parse()
            .ok()
            .filter(|n| *n > 0)
            .ok_or(ModeldError::Setting("OPENSEAL_MODELD_SLOTS"))?;
    }
    let installed = bundle.installed.len();
    let id = bundle.id.clone();
    let service = ModelService::new(bundle, allow, log, limits);
    let listen = var("OPENSEAL_MODELD_LISTEN").unwrap_or_else(|| "127.0.0.1:7444".into());
    let modeld = Modeld::bind(&listen, tls, service)?;
    eprintln!(
        "modeld: bundle {id} ({installed} files), {} slots, on {}",
        limits.slots,
        modeld.local_addr()?
    );
    modeld.serve();
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("modeld: {e}");
            ExitCode::FAILURE
        }
    }
}
