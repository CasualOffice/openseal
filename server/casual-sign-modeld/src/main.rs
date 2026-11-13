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
//! | `OPENSEAL_MODELD_MEMORY_LIMIT` | modeld's memory limit: bytes, or `KiB`/`MiB`/`GiB` (default: the cgroup's `memory.max`, else 4 GiB) |
//! | `RUST_LOG` | modeld's own log level only; third-party targets stay at WARN (ONNX Runtime at ERROR) whatever it says (`SEC-I05`) |
//! | `OPENSEAL_MODELD_SLOTS` | Operations at once (default: half the cores, at least 1, but no more than `(memory limit - resident memory after loading) / 512 MiB`; a value above that bound, or a bound of zero, stops modeld) |

use std::path::Path;
use std::process::ExitCode;

use casual_sign_modeld::raster::{CHILD_ARG, RasterLimits, child_main};
use casual_sign_modeld::{
    AllowList, Bundle, Manifest, ModelService, Modeld, ModeldError, ModeldLimits, OpLog,
    SlotSettings, SpanModels, configured_slots, logging, resident_bytes, server_tls,
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
    logging::init();
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
    // Inference sessions load before modeld listens, and before resident memory is read
    // for the slot bound (docs/33 §3.3).
    let spans = SpanModels::load(&bundle)?;

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
    // The raster child is this binary; the models load before resident memory is read.
    let exe = std::env::current_exe().map_err(|_| ModeldError::Setting("current_exe"))?;
    let service = ModelService::new(bundle, allow, log, ModeldLimits::default())
        .with_raster(&exe, RasterLimits::default())
        .with_ocr()?
        .with_span_models(spans);
    // Slots are bounded by memory as well as cores (docs/33 §3.3). Resident memory is read
    // once the bundle is verified and the inference sessions are loaded.
    let cores = std::thread::available_parallelism().map_or(2, std::num::NonZeroUsize::get);
    let slots_setting = var("OPENSEAL_MODELD_SLOTS");
    let memory_setting = var("OPENSEAL_MODELD_MEMORY_LIMIT");
    let cgroup = std::fs::read_to_string("/sys/fs/cgroup/memory.max").ok();
    let model_rss = std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| resident_bytes(&s))
        .unwrap_or(0);
    let limits = ModeldLimits {
        slots: configured_slots(&SlotSettings {
            cores,
            slots: slots_setting.as_deref(),
            memory_limit: memory_setting.as_deref(),
            cgroup_memory_max: cgroup.as_deref(),
            model_rss,
        })?,
        ..ModeldLimits::default()
    };
    let installed = service.bundle().installed.len();
    let id = service.bundle().id.clone();
    let service = service.with_limits(limits);
    let listen = var("OPENSEAL_MODELD_LISTEN").unwrap_or_else(|| "127.0.0.1:7444".into());
    let modeld = Modeld::bind(&listen, tls, service)?;
    let mut m = serde_json::Map::new();
    m.insert("bundle".into(), id.into());
    m.insert("files".into(), installed.into());
    m.insert("slots".into(), limits.slots.into());
    m.insert("listen".into(), modeld.local_addr()?.to_string().into());
    casual_sign_seclog::write(
        casual_sign_seclog::Service::Modeld,
        casual_sign_seclog::Level::Info,
        "serving",
        m,
    );
    modeld.serve();
    Ok(())
}

fn main() -> ExitCode {
    // A raster child (src/raster.rs) does nothing else: no settings, no bundle, no log.
    let args: Vec<String> = std::env::args().skip(1).collect();
    if let Some((first, rest)) = args.split_first()
        && first == CHILD_ARG
    {
        return child_main(rest);
    }
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let mut m = serde_json::Map::new();
            m.insert("code".into(), e.code().into());
            m.insert("error".into(), e.to_string().into());
            casual_sign_seclog::write(
                casual_sign_seclog::Service::Modeld,
                casual_sign_seclog::Level::Error,
                "start_failed",
                m,
            );
            ExitCode::FAILURE
        }
    }
}
