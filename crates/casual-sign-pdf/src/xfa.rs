//! The XFA packets of a form, for laying out a dynamic-only XFA form (`XFA-01`,
//! docs/30 §3): admission refuses such a document (`CS-PDF-0012`), since it has no
//! static content, and the host hands these bytes to `casual-sign-xfa`, which lays the
//! form out into a new static PDF.

use crate::Cancel;
use crate::crypt::Credentials;
use crate::document::Document;
use crate::error::PdfError;
use crate::limits::Limits;
use crate::object::Object;

/// The `/AcroForm /XFA` packets of `bytes`, concatenated in order (one XDP document),
/// or `None` when the form has no XFA. The file is read with the same limits and
/// recovery as [`crate::admit_with`], and an encrypted file is opened with the
/// host's `credentials`; each stream is decoded within the decode budget.
///
/// Nothing in the packets is parsed or run here.
///
/// # Errors
///
/// A [`PdfError`] whose code is in docs/20 when the file cannot be read within the
/// limits, or `CS-PDF-0005` when `/XFA` is neither a stream nor an array of names and
/// streams.
pub fn xfa_packets(
    bytes: &[u8],
    limits: &Limits,
    credentials: &Credentials,
    cancel: Cancel<'_>,
) -> Result<Option<Vec<u8>>, PdfError> {
    match read(bytes, limits, credentials, cancel, false) {
        Err(PdfError::NotPdf { .. } | PdfError::Malformed { .. }) => {
            read(bytes, limits, credentials, cancel, true)
        }
        other => other,
    }
}

fn read(
    bytes: &[u8],
    limits: &Limits,
    credentials: &Credentials,
    cancel: Cancel<'_>,
    rebuild: bool,
) -> Result<Option<Vec<u8>>, PdfError> {
    let mut doc = Document::open(bytes, limits, false, cancel, rebuild, credentials)?;
    let root = doc.trailer().get(b"Root").cloned().unwrap_or(Object::Null);
    let catalog = doc.resolve(&root, cancel)?;
    let Some(form) = catalog.get(b"AcroForm").cloned() else {
        return Ok(None);
    };
    let form = doc.resolve(&form, cancel)?;
    let Some(xfa) = form.get(b"XFA").cloned() else {
        return Ok(None);
    };
    let bad = |object: Option<u32>| PdfError::Malformed { object, offset: 0 };
    let mut out = Vec::new();
    let mut add = |doc: &mut Document<'_>, v: &Object| -> Result<(), PdfError> {
        let r = v.as_ref().ok_or_else(|| bad(None))?;
        let data = doc.decode_stream(r.num, cancel)?;
        out.extend_from_slice(&data);
        Ok(())
    };
    match &xfa {
        Object::Reference(_) => match doc.resolve(&xfa, cancel)? {
            Object::Stream(_) => add(&mut doc, &xfa)?,
            Object::Array(items) => {
                for v in items.iter().skip(1).step_by(2) {
                    add(&mut doc, v)?;
                }
            }
            _ => return Err(bad(xfa.as_ref().map(|r| r.num))),
        },
        Object::Array(items) => {
            for v in items.iter().skip(1).step_by(2) {
                add(&mut doc, v)?;
            }
        }
        _ => return Err(bad(None)),
    }
    Ok(Some(out))
}
