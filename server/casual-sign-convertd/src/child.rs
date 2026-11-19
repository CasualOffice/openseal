//! The per-job child: the convertd binary run with the fixed argument [`CHILD_ARG`], an
//! empty environment, no inherited descriptor besides its three standard streams, stderr
//! discarded. It sets its own limits before it reads a byte of the document (pattern
//! copied from modeld's raster child, `server/casual-sign-modeld/src/raster.rs`):
//!
//! - `RLIMIT_AS` (Linux only: macOS accepts and ignores it, so off Linux the child runs
//!   without a memory cap; convertd ships in a Linux container and the cap is proven by a
//!   Linux-only test),
//! - `RLIMIT_CPU`, a backstop behind the daemon's wall-clock kill,
//! - `RLIMIT_FSIZE` 0: the child writes no file (the converter's font cache is off),
//! - `RLIMIT_CORE` 0 and `RLIMIT_NOFILE` small.
//!
//! Then it reads one request from stdin, screens the archive ([`crate::screen()`]),
//! converts it with `docxide-pdf`, and writes one answer to stdout. A panic in the
//! converter answers `CS-CNV-0001 failed`; the panic message is suppressed, since it
//! could carry document text.

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use crate::error::{ConvertError, Reason};
use crate::screen::screen;
use crate::wire::{Converted, MAX_OUTPUT, Request, read_request, write_answer};

/// The argument that makes the convertd binary run as a job's child.
pub const CHILD_ARG: &str = "convert-child";

/// File descriptors the child may hold: its three standard streams, font files opened
/// one at a time, and a few spare.
#[cfg(unix)]
const CHILD_FILES: u64 = 64;

#[cfg(unix)]
fn set_limit(resource: rustix::process::Resource, value: u64) -> bool {
    rustix::process::setrlimit(
        resource,
        rustix::process::Rlimit {
            current: Some(value),
            maximum: Some(value),
        },
    )
    .is_ok()
}

/// Set the child's limits on itself; false when any cannot be set.
#[cfg(unix)]
fn set_limits(address_space: u64, cpu: u64) -> bool {
    use rustix::process::Resource;
    let common = set_limit(Resource::Core, 0)
        && set_limit(Resource::Nofile, CHILD_FILES)
        && set_limit(Resource::Fsize, 0)
        && set_limit(Resource::Cpu, cpu);
    #[cfg(target_os = "linux")]
    let common = common && set_limit(Resource::As, address_space);
    #[cfg(not(target_os = "linux"))]
    let _ = address_space;
    common
}

#[cfg(not(unix))]
fn set_limits(_address_space: u64, _cpu: u64) -> bool {
    false
}

/// Convert an admitted-by-the-screen `.docx`: the screen, then the converter, a panic
/// caught. Runs inside the child; exposed for the fuzz target and tests, which must not
/// rely on it for containment.
///
/// # Errors
/// The screen's refusals; `CS-CNV-0001` (`malformed`, `failed`) from the converter;
/// `CS-CNV-0003 output` for a PDF over [`MAX_OUTPUT`].
pub fn convert_here(docx: &[u8], font_dir: Option<PathBuf>) -> Result<Converted, ConvertError> {
    let screened = screen(docx)?;
    let mut options = docxide_pdf::ConvertOptions::new().font_cache(false);
    if let Some(dir) = font_dir {
        options = options.font_dirs([dir]);
    }
    let done = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        docxide_pdf::convert_docx_bytes_to_pdf_bytes_with(docx, &options)
    }));
    let pdf = match done {
        Ok(Ok(pdf)) => pdf,
        Ok(Err(
            docxide_pdf::Error::InvalidDocx(_)
            | docxide_pdf::Error::Zip(_)
            | docxide_pdf::Error::Xml(_),
        )) => {
            return Err(ConvertError::Failed(Reason::Malformed));
        }
        Ok(Err(_)) | Err(_) => return Err(ConvertError::Failed(Reason::Failed)),
    };
    if pdf.len() > MAX_OUTPUT {
        return Err(ConvertError::OverLimit(Reason::Output));
    }
    if !pdf.starts_with(b"%PDF-") {
        return Err(ConvertError::Failed(Reason::Failed));
    }
    Ok(Converted {
        pdf,
        external_refs: screened.external_refs,
    })
}

/// The child's main: `casual-sign-convertd convert-child <address-space> <cpu-s>
/// <font-dir|->`. Sets its limits, reads one request from stdin, answers on stdout.
#[must_use]
pub fn child_main(args: &[String]) -> ExitCode {
    let (Some(Ok(address_space)), Some(Ok(cpu)), Some(fonts)) = (
        args.first().map(|a| a.parse::<u64>()),
        args.get(1).map(|a| a.parse::<u64>()),
        args.get(2),
    ) else {
        return ExitCode::from(2);
    };
    if !set_limits(address_space, cpu) {
        return ExitCode::from(3);
    }
    // Nothing the converter prints may reach a log: stderr is discarded by the parent,
    // and the panic message is suppressed here too.
    std::panic::set_hook(Box::new(|_| {}));
    let font_dir = (fonts != "-").then(|| PathBuf::from(fonts));
    let answer = match read_request(&mut std::io::stdin().lock()) {
        Ok(Request::Convert(docx)) => convert_here(&docx, font_dir),
        Ok(Request::Ping) => Err(ConvertError::Unavailable(Reason::Protocol)),
        Err(e) => Err(e),
    };
    let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    if write_answer(&mut out, &answer)
        .and_then(|()| out.flush())
        .is_err()
    {
        return ExitCode::from(5);
    }
    ExitCode::SUCCESS
}
