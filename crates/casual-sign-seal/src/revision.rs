//! One signature revision (docs/31 §4 steps 1–3 and 7): the field and the signature
//! dictionary with a fixed-width `/ByteRange` and a zero `/Contents` placeholder, the
//! ByteRange filled in place, and the DER written into the placeholder.
//!
//! The placeholder is sized by the caller's computation; DER larger than it is
//! [`SealError::Overflow`] (`CS-SEAL-0003`) and is never truncated. [`write_with_retry`]
//! retries once with the measured size (docs/31 §9).

use core::ops::Range;

use casual_sign_pdf::{Admitted, Change, Dictionary, IncrementalUpdate, Limits, Object, admit};

use crate::error::{LayoutProblem, SealError};
use crate::form::{self, FieldSpec, never};

/// The ByteRange placeholder: four values, each of the last three written in ten
/// digits, so any file under 10^10 bytes fits (docs/66 pitfall 5).
const BR_PLACEHOLDER: &[u8] = b"[0 9999999999 9999999999 9999999999]";
const BR_FILLER: i64 = 9_999_999_999;
/// Largest value a ByteRange field of ten digits holds.
const BR_MAX: usize = 9_999_999_999;

/// Bytes added to a measured DER length for the retry, and to a computed bound.
pub(crate) const MARGIN: usize = 64;

/// Largest `/Contents` placeholder: the crypto crate's CMS bound (`MAX_CMS_LEN`).
const MAX_PLACEHOLDER: usize = casual_sign_crypto::cms::MAX_CMS_LEN;

/// A written signature revision.
#[derive(Debug, Clone)]
pub(crate) struct Written {
    /// The whole file: input and the update.
    pub(crate) bytes: Vec<u8>,
    /// The `/Contents` value as a reader decodes it: the DER and its zero padding (the
    /// bytes a VRI key hashes).
    pub(crate) contents: Vec<u8>,
    /// `[0, a, b, c]`.
    pub(crate) byte_range: [u64; 4],
    /// Bytes reserved.
    pub(crate) placeholder: usize,
    /// Bytes of DER written.
    pub(crate) der_len: usize,
    /// 1, or 2 after a retry.
    pub(crate) attempts: u8,
}

/// What a revision is for.
pub(crate) struct RevisionSpec<'r> {
    pub(crate) limits: &'r Limits,
    pub(crate) field: FieldSpec<'r>,
    /// Entries of the signature dictionary before `/ByteRange` and `/Contents`.
    pub(crate) head: Dictionary,
    /// Add `/Perms /DocMDP` to the catalog.
    pub(crate) certification: bool,
    /// Ignore the document's DocMDP level when appending (a DSS or document timestamp,
    /// which every level permits: ISO 32000-2 §12.8.2.2.2).
    pub(crate) archival: bool,
}

/// The signed bytes and their ranges, handed to the content builder.
pub(crate) struct ToSign<'b> {
    pub(crate) bytes: &'b [u8],
    pub(crate) ranges: [Range<usize>; 2],
}

/// Admit `input` for an update, refusing nothing the writer would accept.
pub(crate) fn admit_for_update<'a>(
    input: &'a [u8],
    limits: &Limits,
    archival: bool,
) -> Result<Admitted<'a>, SealError> {
    let mut admitted = admit(input, limits, &never)?;
    if archival {
        // casual-sign-pdf's `Change` has no archival kind yet, so a DocMDP P=1 document
        // would refuse a DSS or a document timestamp, which every level permits. The
        // report is ours to adjust; the writer's other checks (soundness, numbering, the
        // prefix) still run. Reported in T-1G.
        admitted.report.docmdp = None;
    }
    Ok(admitted)
}

/// The position of `needle` in `hay`, if it occurs exactly once; else how many times.
fn find_once(hay: &[u8], needle: &[u8]) -> Result<usize, usize> {
    let mut found = None;
    let mut count = 0usize;
    if needle.is_empty() || hay.len() < needle.len() {
        return Err(0);
    }
    let first = needle.first().copied().unwrap_or(0);
    let last_start = hay.len().saturating_sub(needle.len());
    let mut i = 0usize;
    while i <= last_start {
        match hay
            .get(i..)
            .and_then(|h| h.iter().position(|&b| b == first))
        {
            None => break,
            Some(p) => {
                let at = i.saturating_add(p);
                if at > last_start {
                    break;
                }
                if hay.get(at..at.saturating_add(needle.len())) == Some(needle) {
                    count = count.saturating_add(1);
                    found = Some(at);
                }
                i = at.saturating_add(1);
            }
        }
    }
    match (count, found) {
        (1, Some(at)) => Ok(at),
        (n, _) => Err(n),
    }
}

/// Write `[0 a b c]` over the placeholder at `at`, padded with spaces before `]` to the
/// placeholder's width, so no offset in the file moves.
pub(crate) fn fill_byte_range(
    out: &mut [u8],
    at: usize,
    values: [usize; 3],
) -> Result<(), SealError> {
    if values.iter().any(|&v| v > BR_MAX) {
        return Err(SealError::Layout(LayoutProblem::ByteRangeWidth));
    }
    let mut text = format!("[0 {} {} {}", values[0], values[1], values[2]).into_bytes();
    if text.len() >= BR_PLACEHOLDER.len() {
        return Err(SealError::Layout(LayoutProblem::ByteRangeWidth));
    }
    text.resize(BR_PLACEHOLDER.len().saturating_sub(1), b' ');
    text.push(b']');
    let slot = out
        .get_mut(at..at.saturating_add(BR_PLACEHOLDER.len()))
        .ok_or(SealError::Layout(LayoutProblem::ByteRangeWidth))?;
    if slot != BR_PLACEHOLDER {
        return Err(SealError::Layout(LayoutProblem::Placeholder(0)));
    }
    slot.copy_from_slice(&text);
    Ok(())
}

/// Write one revision with a `/Contents` placeholder of `placeholder` bytes, and fill it
/// with the DER `content` returns for the signed bytes.
fn write_once(
    input: &[u8],
    spec: &RevisionSpec<'_>,
    placeholder: usize,
    content: &mut dyn FnMut(ToSign<'_>) -> Result<Vec<u8>, SealError>,
) -> Result<Written, SealError> {
    let mut admitted = admit_for_update(input, spec.limits, spec.archival)?;
    let plan = form::plan(&mut admitted, spec.field)?;
    let mut u = IncrementalUpdate::new(&admitted, Change::FillAndSign)?;
    let mut dict = spec.head.clone();
    dict.insert(
        b"ByteRange",
        Object::Array(vec![
            Object::Integer(0),
            Object::Integer(BR_FILLER),
            Object::Integer(BR_FILLER),
            Object::Integer(BR_FILLER),
        ]),
    );
    dict.insert(b"Contents", Object::String(vec![0u8; placeholder]));
    let value = u.add(Object::Dictionary(dict))?;
    form::apply(&mut u, plan, value, spec.certification)?;
    let mut out = u.finish()?;

    // Find the placeholder in the update only: `/ByteRange [...]/Contents <00…>` as the
    // serializer writes it, exactly once.
    let hex_len = placeholder.saturating_mul(2);
    let mut needle = Vec::with_capacity(hex_len.saturating_add(64));
    needle.extend_from_slice(b"/ByteRange ");
    needle.extend_from_slice(BR_PLACEHOLDER);
    needle.extend_from_slice(b"/Contents <");
    needle.resize(needle.len().saturating_add(hex_len), b'0');
    needle.push(b'>');
    let update = out.get(input.len()..).unwrap_or_default();
    let rel =
        find_once(update, &needle).map_err(|n| SealError::Layout(LayoutProblem::Placeholder(n)))?;
    let br_at = input
        .len()
        .saturating_add(rel)
        .saturating_add(b"/ByteRange ".len());
    let a = br_at
        .saturating_add(BR_PLACEHOLDER.len())
        .saturating_add(b"/Contents ".len());
    let b = a.saturating_add(hex_len).saturating_add(2);
    let c = out.len().saturating_sub(b);
    fill_byte_range(&mut out, br_at, [a, b, c])?;

    let der = content(ToSign {
        bytes: &out,
        ranges: [0..a, b..out.len()],
    })?;
    if der.len() > placeholder {
        return Err(SealError::Overflow {
            reserved: placeholder,
            needed: der.len(),
        });
    }
    let hex = crate::text::hex_upper(&der);
    let slot = out
        .get_mut(a.saturating_add(1)..a.saturating_add(1).saturating_add(hex.len()))
        .ok_or(SealError::Layout(LayoutProblem::Placeholder(0)))?;
    slot.copy_from_slice(hex.as_bytes());
    let mut contents = der.clone();
    contents.resize(placeholder, 0);
    let to_u64 = |v: usize| u64::try_from(v).unwrap_or(u64::MAX);
    Ok(Written {
        bytes: out,
        contents,
        byte_range: [0, to_u64(a), to_u64(b), to_u64(c)],
        placeholder,
        der_len: der.len(),
        attempts: 1,
    })
}

/// [`write_once`], and on overflow once more with the measured size plus [`MARGIN`]
/// (docs/31 §9). A second overflow is returned.
pub(crate) fn write_with_retry(
    input: &[u8],
    spec: &RevisionSpec<'_>,
    placeholder: usize,
    content: &mut dyn FnMut(ToSign<'_>) -> Result<Vec<u8>, SealError>,
) -> Result<Written, SealError> {
    let first = placeholder.min(MAX_PLACEHOLDER);
    match write_once(input, spec, first, content) {
        Err(SealError::Overflow { needed, .. }) => {
            let second = needed.saturating_add(MARGIN).min(MAX_PLACEHOLDER);
            let mut w = write_once(input, spec, second, content)?;
            w.attempts = 2;
            Ok(w)
        }
        r => r,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_once_counts() {
        assert_eq!(find_once(b"abcabc", b"bc"), Err(2));
        assert_eq!(find_once(b"abcabd", b"bc"), Ok(1));
        assert_eq!(find_once(b"ab", b"abc"), Err(0));
        assert_eq!(find_once(b"xxab", b"ab"), Ok(2));
    }

    #[test]
    fn byte_range_keeps_its_width() {
        let mut buf = b"x[0 9999999999 9999999999 9999999999]y".to_vec();
        let before = buf.len();
        fill_byte_range(&mut buf, 1, [1234, 5678, 90]).ok();
        assert_eq!(buf.len(), before);
        assert_eq!(&buf, b"x[0 1234 5678 90                    ]y");
    }

    #[test]
    fn byte_range_wider_than_its_placeholder_is_refused() {
        let mut buf = BR_PLACEHOLDER.to_vec();
        assert_eq!(
            fill_byte_range(&mut buf, 0, [BR_MAX + 1, 1, 1]),
            Err(SealError::Layout(LayoutProblem::ByteRangeWidth))
        );
        assert_eq!(buf, BR_PLACEHOLDER, "nothing written on refusal");
        // The widest values that fit.
        assert!(fill_byte_range(&mut buf, 0, [BR_MAX, BR_MAX, BR_MAX]).is_ok());
        assert_eq!(buf.len(), BR_PLACEHOLDER.len());
    }
}
