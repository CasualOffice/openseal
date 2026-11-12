//! The ONNX Runtime library (piece I; docs/33 §5.5): `ort` with `load-dynamic` loads the
//! bundle's own pinned `runtime/libonnxruntime.so`, verified by SHA-256 with the rest of
//! the bundle, once per process. Nothing is downloaded and no system copy is used.
//!
//! Shared by every op that runs a model (EMBED here; OCR, ENTITIES and PERSONAL when
//! their pieces land). The settings that make output repeatable are here too (docs/33
//! §5.5 "Determinism"): CPU only, one intra-op and one inter-op thread, sequential
//! execution, and a fixed graph optimisation level. ONNX Runtime's own log is set to
//! `error` whatever `ORT_LOG` says, so no input reaches it.

use std::path::Path;
use std::sync::OnceLock;

use ort::environment::Environment;
use ort::logging::LogLevel;
use ort::session::Session;
use ort::session::builder::GraphOptimizationLevel;

use crate::error::ModeldError;
use crate::manifest::Bundle;

/// Where the runtime library sits in a bundle (tools/ml/models.toml, `dest`).
pub(crate) const RUNTIME_PATH: &str = "runtime/libonnxruntime.so";

static LOADED: OnceLock<Result<(), ModeldError>> = OnceLock::new();

/// Load the bundle's ONNX Runtime library, once.
///
/// # Errors
/// `CS-ML-0010` if the bundle holds no runtime library; `CS-ML-0013` if it does not
/// load. The first outcome is kept: a process whose runtime failed to load does not try
/// again.
pub(crate) fn ensure(bundle: &Bundle) -> Result<(), ModeldError> {
    if !bundle.installed.iter().any(|e| e.path == RUNTIME_PATH) {
        return Err(ModeldError::NotInstalled);
    }
    LOADED
        .get_or_init(|| load(&bundle.dir.join(RUNTIME_PATH)))
        .clone()
}

fn load(path: &Path) -> Result<(), ModeldError> {
    let builder = ort::init_from(path).map_err(|_| ModeldError::Inference)?;
    // `false` means an environment already existed; it was made by this function, so the
    // settings below still hold.
    let _ = builder.with_name("casual-sign-modeld").commit();
    Environment::current()
        .map_err(|_| ModeldError::Inference)?
        .set_log_level(LogLevel::Error);
    Ok(())
}

/// A CPU session on `model`, with the deterministic settings.
///
/// # Errors
/// `CS-ML-0013` if the session cannot be built (the runtime's text is dropped).
pub(crate) fn session(model: &Path) -> Result<Session, ModeldError> {
    let fail = |_| ModeldError::Inference;
    Session::builder()
        .map_err(|_| ModeldError::Inference)?
        .with_intra_threads(1)
        .map_err(fail)?
        .with_inter_threads(1)
        .map_err(fail)?
        .with_parallel_execution(false)
        .map_err(fail)?
        .with_optimization_level(GraphOptimizationLevel::All)
        .map_err(fail)?
        .with_log_level(LogLevel::Error)
        .map_err(fail)?
        .commit_from_file(model)
        .map_err(|_| ModeldError::Inference)
}
