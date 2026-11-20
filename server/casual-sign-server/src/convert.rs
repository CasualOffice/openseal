//! Word uploads converted to PDF (ADR-042, owner instruction 76; docs/30 §3, docs/07
//! `SEC-P13`; row `VS-06C`).
//!
//! An upload whose bytes are a ZIP archive is a Word document (`.docx`): it is malware-
//! scanned as uploaded, then sent to the conversion daemon (`casual-sign-convertd`, its
//! own container, no network) over its Unix socket, and the PDF that comes back goes
//! through admission and normalization like any upload. **Nothing of the document is
//! parsed in this process**: the server moves bytes and reads the daemon's answer as
//! hostile (lengths bounded, a PDF must start as one).
//!
//! - **Synchronous, with a deadline.** A conversion takes well under a second for an
//!   ordinary agreement; the server waits at most [`casual_sign_convertd::DEFAULT_TIMEOUT`]
//!   (90 s, `OPENSEAL_CONVERTD_TIMEOUT`) without holding a database connection or a row
//!   lock, as the malware scan does. The client gets the admitted document in the same
//!   answer, so the API stays one call and the data model needs no "converting" state.
//! - **The evidence.** The `.docx` is the document's `original` version (its SHA-256 is
//!   the `upload_hash` of `document.added`); the admission report of the `normalized`
//!   version says `"converted": {"from": "docx", "converter", "pdf_sha256",
//!   "external_references"}`, and the chain binds that report's hash.
//! - **Off by default.** Without `OPENSEAL_CONVERTD_SOCKET` a Word upload is refused
//!   `415 CS-CNV-0002` (`conversion_off`); a PDF is unaffected.

use std::path::PathBuf;
use std::time::Duration;

use casual_sign_convertd::{Client, ConvertError, Converted, Reason};

use crate::error::ApiError;
use crate::state::AppState;

/// The media type of a Word document (`.docx`).
pub const DOCX_MEDIA_TYPE: &str =
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document";

/// The converter's configuration from `OPENSEAL_CONVERTD_SOCKET` and
/// `OPENSEAL_CONVERTD_TIMEOUT` (seconds, 1 to 600), read through `var` (an unset or empty
/// variable is `None`): `None` when no socket is set.
///
/// # Errors
/// A message naming the variable that is not valid.
pub fn converter_from_vars(var: impl Fn(&str) -> Option<String>) -> Result<Option<Client>, String> {
    let get = |n: &str| var(n).filter(|v| !v.trim().is_empty());
    let Some(socket) = get("OPENSEAL_CONVERTD_SOCKET") else {
        return Ok(None);
    };
    let mut c = Client::new(PathBuf::from(socket.trim()));
    if let Some(t) = get("OPENSEAL_CONVERTD_TIMEOUT") {
        let secs = t
            .trim()
            .parse::<u64>()
            .ok()
            .filter(|s| (1..=600).contains(s))
            .ok_or("OPENSEAL_CONVERTD_TIMEOUT: not 1 to 600 seconds")?;
        c = c.with_timeout(Duration::from_secs(secs));
    }
    Ok(Some(c))
}

/// Whether an upload is a ZIP archive, so a Word document to convert, rather than a PDF.
#[must_use]
pub fn is_word(bytes: &[u8]) -> bool {
    bytes.starts_with(b"PK\x03\x04")
}

/// Convert `bytes` when they are a Word document; `None` for anything else (a PDF, or
/// bytes admission will refuse).
///
/// # Errors
/// The daemon's refusal as `CS-CNV-*` (docs/20), or `415 CS-CNV-0002 conversion_off`
/// when no converter is configured.
pub(crate) async fn convert_upload(
    st: &AppState,
    bytes: &[u8],
) -> Result<Option<Converted>, ApiError> {
    if !is_word(bytes) {
        return Ok(None);
    }
    let Some(client) = st.converter() else {
        return Err(ApiError::conversion(ConvertError::Unsupported(
            Reason::ConversionOff,
        )));
    };
    match client.convert(bytes).await {
        Ok(c) => Ok(Some(c)),
        Err(e) => {
            tracing::info!(
                code = e.code(),
                reason = e.reason().as_str(),
                request_id = %crate::error::request_id().unwrap_or_default(),
                "Word upload not converted"
            );
            Err(ApiError::conversion(e))
        }
    }
}

/// The admission report's `converted` member for a converted upload.
pub(crate) fn report_entry(c: &Converted) -> serde_json::Value {
    let sha = casual_sign_audit::Hash256::digest(&c.pdf);
    serde_json::json!({
        "from": "docx",
        "converter": casual_sign_convertd::CONVERTER,
        "pdf_sha256": sha.hex(),
        "external_references": c.external_refs,
    })
}
