//! The incremental writer (docs/30 §9, ISO 32000-2 §7.5.6).
//!
//! An update appends new and replaced objects, a cross-reference section in the same
//! form as the file's last one (a classic table, or an xref stream with `/W` chosen to
//! fit), and a trailer with `/Prev`, `/Size`, `/Root`, `/Info` and `/ID`. The input is
//! never rewritten: the output starts with it, byte for byte, and the writer checks
//! that before returning (`CS-WRT-0001`). Same input and same objects give the same
//! bytes.

use core::fmt;
use std::borrow::Cow;
use std::collections::BTreeMap;

use crate::Admitted;
use crate::document::Document;
use crate::error::PdfError;
use crate::object::{Dictionary, ObjRef, Object};
use crate::report::AdmissionReport;
use crate::serialize::{Body, write_indirect, write_value};
use crate::xref::XrefKind;

/// The highest object number a file may use (ISO 32000-1 Annex C; the same bound as
/// the reader's `/Size` check, docs/21).
pub(crate) const MAX_OBJECT_NUMBER: u32 = 8_388_607;

/// Why an update or a normalization was not written. [`WriteError::code`] gives the
/// stable code.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WriteError {
    /// The output would not start with the input (`CS-WRT-0001`, the invariant).
    PrefixViolated,
    /// A new object would be numbered above 8,388,607 (`CS-WRT-0002`).
    ObjectNumbersExhausted,
    /// The file is not structurally sound for appending: its xref needed repair
    /// (`CS-PDF-0101`) or was rebuilt (docs/30 §2) (`CS-WRT-0003`, proposed).
    NotSound,
    /// A certification signature's DocMDP permissions forbid this kind of change
    /// (`CS-WRT-0004`, proposed).
    ChangeForbidden {
        /// The DocMDP level (1, 2 or 3).
        docmdp: u8,
    },
    /// The update replaces an object the file does not have, or gives a stream whose
    /// data is not in the file (`CS-WRT-0005`, proposed).
    InvalidObject {
        /// The object number.
        object: u32,
    },
    /// The document is signed: normalizing would break its signatures
    /// (`CS-PDF-0014`). "Print to a new PDF" is not built yet.
    Signed,
    /// The document is encrypted: an update would have to be encrypted with its key,
    /// and OpenSeal never encrypts what it writes (ADR-006). Normalize it first, which
    /// writes it unencrypted (`CS-WRT-0006`, proposed).
    Encrypted,
    /// Reading an object of the input failed (that error's `CS-PDF-*` code).
    Read(PdfError),
}

impl WriteError {
    /// The stable code (docs/20).
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::PrefixViolated => "CS-WRT-0001",
            Self::ObjectNumbersExhausted => "CS-WRT-0002",
            Self::NotSound => "CS-WRT-0003",
            Self::ChangeForbidden { .. } => "CS-WRT-0004",
            Self::InvalidObject { .. } => "CS-WRT-0005",
            Self::Signed => "CS-PDF-0014",
            Self::Encrypted => "CS-WRT-0006",
            Self::Read(e) => e.code(),
        }
    }
}

impl fmt::Display for WriteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = self.code();
        match self {
            Self::PrefixViolated => write!(f, "{code}: output would modify earlier bytes"),
            Self::ObjectNumbersExhausted => {
                write!(f, "{code}: no object number left below 8388608")
            }
            Self::NotSound => write!(
                f,
                "{code}: cross-reference needed repair; normalize before appending"
            ),
            Self::ChangeForbidden { docmdp } => {
                write!(f, "{code}: DocMDP level {docmdp} forbids this change")
            }
            Self::InvalidObject { object } => {
                write!(f, "{code}: object {object} is not in the file")
            }
            Self::Signed => write!(f, "{code}: signed document cannot be rewritten"),
            Self::Encrypted => write!(
                f,
                "{code}: encrypted document; normalize it before appending"
            ),
            Self::Read(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for WriteError {}

impl From<PdfError> for WriteError {
    fn from(e: PdfError) -> Self {
        Self::Read(e)
    }
}

/// What an update changes, checked against a certification signature's DocMDP level
/// (ISO 32000-2 §12.8.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Change {
    /// Filling form fields and signing: permitted by DocMDP levels 2 and 3.
    FillAndSign,
    /// Adding or changing annotations, with filling and signing: level 3 only.
    Annotate,
    /// Anything else (new page content, flattening): no DocMDP level permits it.
    Other,
}

fn permitted(change: Change, docmdp: u8) -> bool {
    match change {
        Change::FillAndSign => docmdp >= 2,
        Change::Annotate => docmdp >= 3,
        Change::Other => false,
    }
}

/// Refuse a file that is not structurally sound, or whose DocMDP forbids `change`.
fn check_appendable(
    report: &AdmissionReport,
    doc: &Document<'_>,
    change: Change,
) -> Result<(), WriteError> {
    let sound = !report.repaired
        && !doc.is_repaired()
        && doc
            .revisions()
            .iter()
            .all(|r| r.xref_offset.is_some() && r.kind != XrefKind::Rebuilt);
    if !sound || doc.revisions().is_empty() {
        return Err(WriteError::NotSound);
    }
    if let Some(level) = report.docmdp
        && !permitted(change, level)
    {
        return Err(WriteError::ChangeForbidden { docmdp: level });
    }
    Ok(())
}

/// Bytes needed to hold `v` big-endian (at least one).
pub(crate) fn width(v: u64) -> u8 {
    let mut w: u8 = 1;
    let mut x = v >> 8;
    while x > 0 {
        w = w.saturating_add(1);
        x >>= 8;
    }
    w
}

/// Append `v` big-endian in `w` bytes.
pub(crate) fn push_be(out: &mut Vec<u8>, v: u64, w: u8) {
    for i in (0..w).rev() {
        let shift = u32::from(i).saturating_mul(8);
        let byte = v.checked_shr(shift).unwrap_or(0) & 0xff;
        out.push(u8::try_from(byte).unwrap_or(0));
    }
}

/// Runs of consecutive numbers: (first, count).
fn runs(nums: impl Iterator<Item = u32>) -> Vec<(u32, u32)> {
    let mut out: Vec<(u32, u32)> = Vec::new();
    for n in nums {
        match out.last_mut() {
            Some((first, count)) if first.checked_add(*count) == Some(n) => {
                *count = count.saturating_add(1);
            }
            _ => out.push((n, 1)),
        }
    }
    out
}

fn int(v: impl TryInto<i64>) -> Object {
    Object::Integer(v.try_into().unwrap_or(i64::MAX))
}

/// One xref row: (object number, generation, offset).
type Row = (u32, u16, usize);

/// A classic xref table for `rows` (sorted by number), `xref` keyword to the end of
/// the last entry.
pub(crate) fn write_table(out: &mut Vec<u8>, rows: &[Row], with_free_head: bool) {
    out.extend_from_slice(b"xref\n");
    let mut list: Vec<(u32, Option<(u16, usize)>)> =
        Vec::with_capacity(rows.len().saturating_add(1));
    if with_free_head {
        list.push((0, None));
    }
    list.extend(rows.iter().map(|&(n, g, o)| (n, Some((g, o)))));
    let mut i: usize = 0;
    for (first, count) in runs(list.iter().map(|(n, _)| *n)) {
        out.extend_from_slice(format!("{first} {count}\n").as_bytes());
        let count = usize::try_from(count).unwrap_or(0);
        for (_, entry) in list.iter().skip(i).take(count) {
            match entry {
                Some((g, o)) => out.extend_from_slice(format!("{o:010} {g:05} n\r\n").as_bytes()),
                None => out.extend_from_slice(b"0000000000 65535 f\r\n"),
            }
        }
        i = i.saturating_add(count);
    }
}

/// `startxref`, the offset and `%%EOF`.
pub(crate) fn write_tail(out: &mut Vec<u8>, xref_pos: usize) {
    out.extend_from_slice(format!("startxref\n{xref_pos}\n%%EOF\n").as_bytes());
}

/// An incremental update being built over an admitted document (docs/30 §9).
///
/// New objects are numbered from max(`/Size`, highest object number read + 1);
/// replaced objects keep their number and generation. [`IncrementalUpdate::finish`]
/// writes the input followed by the update.
#[derive(Debug)]
pub struct IncrementalUpdate<'d> {
    doc: &'d Document<'d>,
    form: XrefKind,
    prev: u64,
    size: u32,
    next: u32,
    objects: BTreeMap<u32, (u16, Body<'d>)>,
    info: Option<Object>,
}

impl<'d> IncrementalUpdate<'d> {
    /// Start an update to `admitted` making a change of kind `change`.
    ///
    /// # Errors
    ///
    /// `CS-WRT-0003` when the file needed any xref repair (normalize it first),
    /// `CS-WRT-0004` when a certification signature's DocMDP forbids `change`,
    /// `CS-WRT-0002` when no object number is left.
    pub fn new(admitted: &'d Admitted<'d>, change: Change) -> Result<Self, WriteError> {
        let doc = &admitted.document;
        if doc.encryption().is_some() {
            return Err(WriteError::Encrypted);
        }
        check_appendable(&admitted.report, doc, change)?;
        let last = doc.revisions().last().ok_or(WriteError::NotSound)?;
        let prev = last.xref_offset.ok_or(WriteError::NotSound)?;
        let form = match last.kind {
            XrefKind::Stream => XrefKind::Stream,
            // A hybrid file's newest section is a table; its /XRefStm stays reachable
            // through /Prev.
            _ => XrefKind::Table,
        };
        let declared = doc
            .trailer()
            .get(b"Size")
            .and_then(Object::as_i64)
            .and_then(|s| u32::try_from(s).ok())
            .unwrap_or(0);
        let after_max = doc.max_object_number().saturating_add(1);
        let next = declared.max(after_max).max(1);
        if next > MAX_OBJECT_NUMBER.saturating_add(1) {
            return Err(WriteError::ObjectNumbersExhausted);
        }
        Ok(Self {
            doc,
            form,
            prev,
            size: next,
            next,
            objects: BTreeMap::new(),
            info: None,
        })
    }

    fn allocate(&mut self) -> Result<ObjRef, WriteError> {
        let num = self.next;
        if num > MAX_OBJECT_NUMBER {
            return Err(WriteError::ObjectNumbersExhausted);
        }
        self.next = num.saturating_add(1);
        Ok(ObjRef { num, generation: 0 })
    }

    fn body(&self, value: Object, num: u32) -> Result<Body<'d>, WriteError> {
        match value {
            Object::Stream(s) => {
                let data = self
                    .doc
                    .bytes()
                    .get(s.data.clone())
                    .ok_or(WriteError::InvalidObject { object: num })?;
                Ok(Body::Stream {
                    dict: s.dict,
                    data: Cow::Borrowed(data),
                })
            }
            v => Ok(Body::Value(v)),
        }
    }

    /// Add a new object; returns its reference. A [`Object::Stream`] must be one read
    /// from this file (its data is copied from the input); new stream data goes
    /// through [`IncrementalUpdate::add_stream`].
    ///
    /// # Errors
    ///
    /// `CS-WRT-0002` when the number would pass 8,388,607; `CS-WRT-0005` for a stream
    /// whose data is not in the file.
    pub fn add(&mut self, value: Object) -> Result<ObjRef, WriteError> {
        let r = self.allocate()?;
        let body = self.body(value, r.num)?;
        self.objects.insert(r.num, (r.generation, body));
        Ok(r)
    }

    /// Add a new stream with `data` as its encoded bytes (`/Length` is set from it).
    ///
    /// # Errors
    ///
    /// `CS-WRT-0002` when the number would pass 8,388,607.
    pub fn add_stream(&mut self, dict: Dictionary, data: Vec<u8>) -> Result<ObjRef, WriteError> {
        let r = self.allocate()?;
        let body = Body::Stream {
            dict,
            data: Cow::Owned(data),
        };
        self.objects.insert(r.num, (r.generation, body));
        Ok(r)
    }

    fn generation_of(&self, num: u32) -> Result<u16, WriteError> {
        if let Some((g, _)) = self.objects.get(&num) {
            return Ok(*g);
        }
        self.doc
            .generation(num)
            .ok_or(WriteError::InvalidObject { object: num })
    }

    /// Replace object `num`, keeping its generation.
    ///
    /// # Errors
    ///
    /// `CS-WRT-0005` when the file has no object `num` in use (and this update did not
    /// add it), or for a stream whose data is not in the file.
    pub fn replace(&mut self, num: u32, value: Object) -> Result<(), WriteError> {
        let generation = self.generation_of(num)?;
        let body = self.body(value, num)?;
        self.objects.insert(num, (generation, body));
        Ok(())
    }

    /// Replace object `num` with a stream holding `data`.
    ///
    /// # Errors
    ///
    /// As [`IncrementalUpdate::replace`].
    pub fn replace_stream(
        &mut self,
        num: u32,
        dict: Dictionary,
        data: Vec<u8>,
    ) -> Result<(), WriteError> {
        let generation = self.generation_of(num)?;
        let body = Body::Stream {
            dict,
            data: Cow::Owned(data),
        };
        self.objects.insert(num, (generation, body));
        Ok(())
    }

    /// Point the trailer's `/Info` at `info`.
    pub fn set_info(&mut self, info: ObjRef) {
        self.info = Some(Object::Reference(info));
    }

    /// The trailer entries carried into the new section.
    fn trailer(&self, size: u32) -> Dictionary {
        let t = self.doc.trailer();
        let mut d = Dictionary::new();
        d.insert(b"Size", int(size));
        if let Some(root) = t.get(b"Root") {
            d.insert(b"Root", root.clone());
        }
        match (&self.info, t.get(b"Info")) {
            (Some(i), _) | (None, Some(i)) => d.insert(b"Info", i.clone()),
            (None, None) => {}
        }
        if let Some(id) = t.get(b"ID") {
            d.insert(b"ID", id.clone());
        }
        d.insert(b"Prev", int(self.prev));
        d
    }

    /// Write the input followed by the update.
    ///
    /// # Errors
    ///
    /// `CS-WRT-0002` when the xref stream's own number would pass 8,388,607;
    /// `CS-WRT-0001` if the output would not start with the input.
    pub fn finish(mut self) -> Result<Vec<u8>, WriteError> {
        let input = self.doc.bytes();
        let mut out = Vec::with_capacity(input.len().saturating_add(4096));
        out.extend_from_slice(input);
        if !matches!(input.last(), Some(b'\n' | b'\r')) {
            out.push(b'\n');
        }
        let mut rows: Vec<Row> = Vec::with_capacity(self.objects.len().saturating_add(1));
        for (&num, (generation, body)) in &self.objects {
            rows.push((num, *generation, out.len()));
            write_indirect(
                &mut out,
                ObjRef {
                    num,
                    generation: *generation,
                },
                body,
            );
        }
        let highest = self
            .objects
            .keys()
            .next_back()
            .map_or(0, |n| n.saturating_add(1));
        match self.form {
            XrefKind::Stream => {
                let own = self.allocate()?;
                let size = self.size.max(highest).max(own.num.saturating_add(1));
                let xref_pos = out.len();
                rows.push((own.num, 0, xref_pos));
                let max_off = rows.iter().map(|r| r.2).max().unwrap_or(0);
                let max_gen = rows.iter().map(|r| r.1).max().unwrap_or(0);
                let w2 = width(u64::try_from(max_off).unwrap_or(u64::MAX));
                let w3 = width(u64::from(max_gen));
                let mut data = Vec::new();
                for &(_, g, o) in &rows {
                    data.push(1);
                    push_be(&mut data, u64::try_from(o).unwrap_or(u64::MAX), w2);
                    push_be(&mut data, u64::from(g), w3);
                }
                let mut dict = Dictionary::new();
                dict.insert(b"Type", Object::Name(b"XRef".to_vec()));
                for (k, v) in self.trailer(size).iter() {
                    dict.insert(k, v.clone());
                }
                dict.insert(b"W", Object::Array(vec![int(1), int(w2), int(w3)]));
                let index: Vec<Object> = runs(rows.iter().map(|r| r.0))
                    .into_iter()
                    .flat_map(|(f, c)| [int(f), int(c)])
                    .collect();
                dict.insert(b"Index", Object::Array(index));
                let body = Body::Stream {
                    dict,
                    data: Cow::Owned(data),
                };
                write_indirect(&mut out, own, &body);
                write_tail(&mut out, xref_pos);
            }
            _ => {
                let size = self.size.max(highest);
                let xref_pos = out.len();
                write_table(&mut out, &rows, false);
                out.extend_from_slice(b"trailer\n");
                write_value(&mut out, &Object::Dictionary(self.trailer(size)));
                out.push(b'\n');
                write_tail(&mut out, xref_pos);
            }
        }
        if !out.starts_with(input) {
            return Err(WriteError::PrefixViolated);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn widths_fit() {
        assert_eq!(width(0), 1);
        assert_eq!(width(255), 1);
        assert_eq!(width(256), 2);
        assert_eq!(width(u64::MAX), 8);
        let mut v = Vec::new();
        push_be(&mut v, 0x01_0203, 3);
        assert_eq!(v, [1, 2, 3]);
    }

    #[test]
    fn runs_group_consecutive_numbers() {
        assert_eq!(
            runs([1, 2, 3, 7, 9, 10].into_iter()),
            vec![(1, 3), (7, 1), (9, 2)]
        );
    }

    #[test]
    fn docmdp_levels() {
        assert!(!permitted(Change::FillAndSign, 1));
        assert!(permitted(Change::FillAndSign, 2));
        assert!(!permitted(Change::Annotate, 2));
        assert!(permitted(Change::Annotate, 3));
        assert!(!permitted(Change::Other, 3));
    }
}
