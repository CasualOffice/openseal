//! Bounded PDF reading for OpenSeal (stage 1A, docs/30 §2).
//!
//! Every uploaded PDF is hostile (docs/07). This crate admits a PDF within the limits
//! of docs/21 and classifies what it contains into an [`AdmissionReport`]. It performs
//! no I/O, reads no clock and holds no key: the host supplies bytes, [`Limits`] and a
//! cancellation predicate, checked in every loop the file can lengthen
//! (`CS-PDF-0013`).
//!
//! Two entry points:
//!
//! - [`admit`] (the default) recovers what readers commonly recover: an xref rebuilt by
//!   scanning, a `/Prev` loop broken, an over-long value dropped, a stream that cannot
//!   be decoded within its caps skipped; each is a [`Finding`] in the report. Limits on
//!   the document as a whole (size, objects, revisions, pages, nesting, the decode
//!   budget, cancellation) refuse in both modes.
//! - [`admit_strict`] refuses with the code instead of repairing. It still corrects
//!   xref offsets that point a few bytes from the object or section they name, which
//!   it reports as `CS-PDF-0101` (such a file is not structurally sound for appending).
//!
//! A signed document (see [`AdmissionReport::is_signed`]) is never repaired: one that
//! needs repair is refused with `CS-PDF-0014`.
//!
//! An encrypted document is opened with the standard security handler (revisions 2
//! to 6: RC4, AES-128, AES-256) when the empty user password or a password the host
//! supplies in [`Credentials`] ([`admit_with`], [`admit_strict_with`]) opens it;
//! otherwise it is refused with `CS-PDF-0009`. Other handlers, the public-key one
//! among them, are refused with `CS-PDF-0010`. Strings and streams are decrypted as
//! they are read, within the decode budget; [`normalize`] writes the document
//! unencrypted.
//!
//! Nothing here is executed or followed: actions, JavaScript, embedded files and
//! external streams are only reported.
//!
//! Writing (stage 1B, docs/30 §3 and §9):
//!
//! - [`normalize`] writes an admitted, unsigned document as a fresh file: reachable
//!   objects renumbered from 1, active content, embedded files, RichMedia, 3D, XFA
//!   and external data removed, each listed in a [`NormalizationReport`].
//! - [`IncrementalUpdate`] appends new and replaced objects to an admitted,
//!   structurally sound document. The input is always a prefix of the output
//!   (`CS-WRT-0001`).

mod classify;
mod crypt;
mod document;
mod error;
mod filters;
mod lexer;
mod limits;
mod normalize;
mod object;
mod pages;
mod parser;
mod report;
mod serialize;
mod text;
mod writer;
mod xref;

pub use crypt::{Cipher, Credentials, EncryptionInfo, MAX_PASSWORDS, PasswordKind};
pub use document::Document;
pub use error::PdfError;
pub use limits::Limits;
pub use normalize::{
    NormalizationReport, NormalizeOptions, Normalized, OutputXref, Removal, normalize,
};
pub use object::{Dictionary, ObjRef, Object, Stream};
pub use report::{
    ActionInfo, ActionKind, AdmissionReport, FieldType, Finding, FindingKind, FormField,
    MAX_FINDINGS, PageInfo, PdfVersion, Rect, Revision, SignatureInfo, SignatureKind, Widget,
};
pub use writer::{Change, IncrementalUpdate, WriteError};
pub use xref::XrefKind;

/// The host's cancellation predicate: return `true` to stop the read (`CS-PDF-0013`).
pub type Cancel<'a> = &'a dyn Fn() -> bool;

/// An admitted document: the report, and the parsed document for later stages.
#[derive(Debug)]
pub struct Admitted<'a> {
    /// What was found.
    pub report: AdmissionReport,
    /// The parsed document, for reading objects and streams after admission.
    pub document: Document<'a>,
}

/// Admit a PDF, recovering from damage where readers commonly do (the default).
///
/// # Errors
///
/// A [`PdfError`] whose [`PdfError::code`] is the docs/20 code of the limit crossed or
/// the reason the file cannot be read.
pub fn admit<'a>(
    bytes: &'a [u8],
    limits: &Limits,
    cancel: Cancel<'_>,
) -> Result<Admitted<'a>, PdfError> {
    run(bytes, limits, &Credentials::default(), cancel, false)
}

/// [`admit`], opening an encrypted document with the host's passwords as well as the
/// empty user password.
///
/// # Errors
///
/// As [`admit`]; `CS-PDF-0009` when the document is encrypted and no password opens it.
pub fn admit_with<'a>(
    bytes: &'a [u8],
    limits: &Limits,
    credentials: &Credentials,
    cancel: Cancel<'_>,
) -> Result<Admitted<'a>, PdfError> {
    run(bytes, limits, credentials, cancel, false)
}

/// Admit a PDF strictly: refuse with the code instead of repairing.
///
/// # Errors
///
/// As [`admit`], and also for any damage the default mode would repair.
pub fn admit_strict<'a>(
    bytes: &'a [u8],
    limits: &Limits,
    cancel: Cancel<'_>,
) -> Result<Admitted<'a>, PdfError> {
    run(bytes, limits, &Credentials::default(), cancel, true)
}

/// [`admit_strict`], opening an encrypted document with the host's passwords as well
/// as the empty user password.
///
/// # Errors
///
/// As [`admit_strict`]; `CS-PDF-0009` when the document is encrypted and no password
/// opens it.
pub fn admit_strict_with<'a>(
    bytes: &'a [u8],
    limits: &Limits,
    credentials: &Credentials,
    cancel: Cancel<'_>,
) -> Result<Admitted<'a>, PdfError> {
    run(bytes, limits, credentials, cancel, true)
}

fn run<'a>(
    bytes: &'a [u8],
    limits: &Limits,
    credentials: &Credentials,
    cancel: Cancel<'_>,
    strict: bool,
) -> Result<Admitted<'a>, PdfError> {
    let mut document = Document::open(bytes, limits, strict, cancel, false, credentials)?;
    match classify::classify(&mut document, strict, cancel) {
        Ok(report) => Ok(Admitted { report, document }),
        // The xref read cleanly but does not lead to a catalog and pages: rebuild once.
        Err(PdfError::NotPdf { .. } | PdfError::Malformed { .. })
            if !strict && !document.is_rebuilt() =>
        {
            let mut document = Document::open(bytes, limits, strict, cancel, true, credentials)?;
            let report = classify::classify(&mut document, strict, cancel)?;
            Ok(Admitted { report, document })
        }
        Err(e) => Err(e),
    }
}
