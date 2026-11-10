//! Cross-reference sections: classic tables, xref streams, hybrid files, and the byte
//! scans used to correct offsets and to rebuild a broken xref (ISO 32000-2 §7.5).
//!
//! No count read from the file sizes an allocation: a subsection's count is believed
//! only as far as the bytes present, and every section is capped by
//! `Limits::max_objects`.

use crate::error::{PdfError, off};
use crate::lexer::{Lexer, is_regular, is_ws};
use crate::limits::MAX_XREF_SIZE;
use crate::object::{Dictionary, Object};
use crate::parser::{Warnings, parse_object};

/// Where an object lives, from the xref.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Entry {
    /// Free or absent: references to it read as `null`.
    Free,
    /// At a byte offset in the file.
    Offset { offset: usize, generation: u16 },
    /// Inside an object stream.
    Compressed { stream: u32, index: u32 },
}

/// The form of one revision's cross-reference section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum XrefKind {
    /// A classic `xref` table.
    Table,
    /// A cross-reference stream.
    Stream,
    /// A classic table with an `/XRefStm` stream beside it.
    Hybrid,
    /// No usable xref: objects were found by scanning (`CS-PDF-0101`).
    Rebuilt,
}

/// One section as read.
pub(crate) struct Section {
    pub(crate) entries: Vec<(u32, Entry)>,
    pub(crate) trailer: Dictionary,
    pub(crate) kind: XrefKind,
    /// Byte position just after the section (after `trailer <<…>>` or `endobj`).
    pub(crate) end: usize,
}

/// Why a section could not be read.
pub(crate) enum SectionError {
    /// Ends the whole read in every mode.
    Fatal(PdfError),
    /// Damage: strict reading refuses with this error, lenient reading rebuilds.
    Damage(PdfError),
}

impl From<PdfError> for SectionError {
    fn from(e: PdfError) -> Self {
        if e.is_document_wide() {
            Self::Fatal(e)
        } else {
            Self::Damage(e)
        }
    }
}

pub(crate) type SectionResult<T> = core::result::Result<T, SectionError>;

fn damage(at: usize) -> SectionError {
    SectionError::Damage(PdfError::NotPdf {
        offset: Some(off(at)),
    })
}

/// Find `needle` in `hay` at or after `from`.
pub(crate) fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    let first = *needle.first()?;
    let mut i = from;
    while let Some(rest) = hay.get(i..) {
        let p = rest.iter().position(|&c| c == first)?;
        let at = i.checked_add(p)?;
        if hay.get(at..at.checked_add(needle.len())?) == Some(needle) {
            return Some(at);
        }
        i = at.checked_add(1)?;
    }
    None
}

/// Find the last `needle` in `hay`.
pub(crate) fn rfind(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).rposition(|w| w == needle)
}

/// True when position `p` starts a token (start of input or after a non-regular byte).
pub(crate) fn token_start(b: &[u8], p: usize) -> bool {
    p == 0
        || p.checked_sub(1)
            .and_then(|q| b.get(q))
            .is_none_or(|&c| !is_regular(c))
}

/// `num gen obj` at `pos`: the numbers, and the position after `obj`.
pub(crate) fn header_at(b: &[u8], pos: usize) -> Option<(u32, u16, usize)> {
    if !token_start(b, pos) {
        return None;
    }
    let mut lx = Lexer::new(b, pos, 0, 0, true);
    if lx.peek().is_none_or(|c| !c.is_ascii_digit()) {
        return None;
    }
    let num = u32::try_from(lx.uint()?).ok()?;
    let generation = u16::try_from(lx.uint()?).ok()?;
    lx.keyword(b"obj").then_some((num, generation, lx.pos))
}

/// Search `±window` bytes around `pos`, nearest first, for the header of `num`.
pub(crate) fn correct_header(b: &[u8], pos: usize, num: u32, window: usize) -> Option<usize> {
    (0..=window).find_map(|d| {
        [pos.checked_add(d), pos.checked_sub(d)]
            .into_iter()
            .flatten()
            .find(|&p| header_at(b, p).is_some_and(|(n, _, _)| n == num))
    })
}

/// End of the revision whose xref starts at `from`: just after the next `%%EOF` and its
/// end-of-line, or the end of input.
pub(crate) fn revision_end(b: &[u8], from: usize) -> usize {
    let Some(p) = find(b, b"%%EOF", from) else {
        return b.len();
    };
    let mut e = p.saturating_add(5);
    if b.get(e) == Some(&b'\r') {
        e = e.saturating_add(1);
    }
    if b.get(e) == Some(&b'\n') {
        e = e.saturating_add(1);
    }
    e.min(b.len())
}

/// What a section reader needs from the document: lexer caps, mode, and a way to
/// decode an xref stream within the document's budgets.
pub(crate) struct SectionCtx<'x> {
    pub(crate) max_objects: u32,
    pub(crate) max_depth: usize,
    pub(crate) max_string: usize,
    pub(crate) max_name: usize,
    pub(crate) lenient: bool,
    pub(crate) max_values: usize,
    pub(crate) cancel: crate::Cancel<'x>,
}

impl SectionCtx<'_> {
    fn lexer<'a>(&self, b: &'a [u8], pos: usize) -> Lexer<'a> {
        Lexer::new(b, pos, self.max_string, self.max_name, self.lenient)
            .with_max_values(self.max_values)
    }

    fn entry_cap(&self) -> usize {
        usize::try_from(self.max_objects)
            .unwrap_or(usize::MAX)
            .saturating_add(1)
    }

    fn cancelled(&self) -> SectionResult<()> {
        if (self.cancel)() {
            Err(SectionError::Fatal(PdfError::Cancelled))
        } else {
            Ok(())
        }
    }
}

/// Check `/Size` against the architectural limit.
pub(crate) fn check_size(trailer: &Dictionary, at: usize) -> SectionResult<()> {
    match trailer.get(b"Size") {
        Some(Object::Integer(s)) if u64::try_from(*s).is_ok_and(|s| s > MAX_XREF_SIZE) => {
            Err(SectionError::Damage(PdfError::XrefSizeAbsurd {
                offset: off(at),
            }))
        }
        Some(Object::Real(_)) => Err(SectionError::Damage(PdfError::XrefSizeAbsurd {
            offset: off(at),
        })),
        _ => Ok(()),
    }
}

/// Read a classic table at `pos` (which holds the `xref` keyword).
pub(crate) fn table_at(b: &[u8], pos: usize, cx: &SectionCtx<'_>) -> SectionResult<Section> {
    let mut lx = cx.lexer(b, pos);
    if !lx.keyword(b"xref") {
        return Err(damage(pos));
    }
    let mut entries: Vec<(u32, Entry)> = Vec::new();
    loop {
        cx.cancelled()?;
        if lx.keyword(b"trailer") {
            break;
        }
        let at = lx.pos;
        let first = lx.uint().ok_or_else(|| damage(at))?;
        let count = lx.uint().ok_or_else(|| damage(at))?;
        // A count is believed only as far as the bytes present (an entry is at least
        // 18 bytes): never an allocation size.
        let room = u64::try_from(b.len().saturating_sub(lx.pos) / 18).unwrap_or(u64::MAX);
        if count > room {
            return Err(damage(at));
        }
        let mut k: u64 = 0;
        while k < count {
            if k.is_multiple_of(4096) {
                cx.cancelled()?;
            }
            let at = lx.pos;
            let offset = lx.uint().ok_or_else(|| damage(at))?;
            let generation = lx.uint().ok_or_else(|| damage(at))?;
            lx.skip_ws();
            let kind = lx.peek();
            lx.pos = lx.pos.saturating_add(1);
            let num = first
                .checked_add(k)
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| damage(at))?;
            // A generation above 65,535 cannot name an object (§7.5.4). iText writes
            // `0000000000 65536 n` for numbers it never used (`PDF-REAL-01`, the GPO
            // certified files): such an entry is a free one, not damage.
            let generation = u16::try_from(generation).ok();
            let entry = match (kind, generation) {
                (Some(b'n' | b'f'), None) => Entry::Free,
                (Some(b'n'), Some(generation)) if offset > 0 => Entry::Offset {
                    offset: usize::try_from(offset).map_err(|_| damage(at))?,
                    generation,
                },
                (Some(b'n' | b'f'), Some(_)) => Entry::Free,
                _ => return Err(damage(at)),
            };
            if entries.len() >= cx.entry_cap() {
                return Err(SectionError::Fatal(PdfError::TooManyObjects {
                    limit: cx.max_objects,
                }));
            }
            entries.push((num, entry));
            k = k.saturating_add(1);
        }
    }
    let at = lx.pos;
    let trailer = match parse_object(&mut lx, cx.max_depth, &mut Warnings::default())? {
        Object::Dictionary(d) => d,
        _ => return Err(damage(at)),
    };
    check_size(&trailer, pos)?;
    let kind = if trailer.contains(b"XRefStm") {
        XrefKind::Hybrid
    } else {
        XrefKind::Table
    };
    Ok(Section {
        entries,
        trailer,
        kind,
        end: lx.pos,
    })
}

/// The dictionary and data range of a stream object whose header is at `pos`, using
/// a direct `/Length` or, failing that, the `endstream` keyword.
pub(crate) fn raw_stream_at(
    b: &[u8],
    pos: usize,
    cx: &SectionCtx<'_>,
) -> SectionResult<(u32, Dictionary, core::ops::Range<usize>, usize)> {
    let (num, _, after) = header_at(b, pos).ok_or_else(|| damage(pos))?;
    let mut lx = cx.lexer(b, after);
    let dict = match parse_object(&mut lx, cx.max_depth, &mut Warnings::default())? {
        Object::Dictionary(d) => d,
        _ => return Err(damage(pos)),
    };
    if !lx.keyword(b"stream") {
        return Err(damage(pos));
    }
    let start = stream_data_start(b, lx.pos);
    let direct = dict
        .get(b"Length")
        .and_then(Object::as_i64)
        .and_then(|l| usize::try_from(l).ok());
    let range = direct
        .and_then(|len| length_fits(b, start, len))
        .or_else(|| endstream_search(b, start))
        .ok_or_else(|| damage(pos))?;
    Ok((num, dict, range.clone(), range.end))
}

/// Skip the end-of-line after the `stream` keyword: CRLF or LF (a lone CR leniently).
pub(crate) fn stream_data_start(b: &[u8], mut p: usize) -> usize {
    if b.get(p) == Some(&b'\r') {
        p = p.saturating_add(1);
    }
    if b.get(p) == Some(&b'\n') {
        p = p.saturating_add(1);
    }
    p
}

/// `start..start+len` if the data fits and `endstream` follows it.
pub(crate) fn length_fits(b: &[u8], start: usize, len: usize) -> Option<core::ops::Range<usize>> {
    let end = start.checked_add(len)?;
    if end > b.len() {
        return None;
    }
    let mut lx = Lexer::new(b, end, 0, 0, true);
    lx.keyword(b"endstream").then_some(start..end)
}

/// Data range ending before the next `endstream` (one end-of-line stripped).
pub(crate) fn endstream_search(b: &[u8], start: usize) -> Option<core::ops::Range<usize>> {
    let p = find(b, b"endstream", start)?;
    Some(start..strip_eol(b, start, p))
}

/// Strip one trailing end-of-line before `end`.
pub(crate) fn strip_eol(b: &[u8], start: usize, mut end: usize) -> usize {
    if end > start && end.checked_sub(1).and_then(|i| b.get(i)) == Some(&b'\n') {
        end = end.saturating_sub(1);
    }
    if end > start && end.checked_sub(1).and_then(|i| b.get(i)) == Some(&b'\r') {
        end = end.saturating_sub(1);
    }
    end
}

/// Parse the decoded rows of an xref stream into entries.
pub(crate) fn xref_stream_entries(
    dict: &Dictionary,
    rows: &[u8],
    pos: usize,
    cx: &SectionCtx<'_>,
) -> SectionResult<Vec<(u32, Entry)>> {
    let w: Vec<usize> = match dict.get(b"W") {
        Some(Object::Array(a)) if a.len() == 3 => a
            .iter()
            .map(|o| {
                o.as_i64()
                    .and_then(|v| usize::try_from(v).ok())
                    .filter(|v| *v <= 8)
            })
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| damage(pos))?,
        _ => return Err(damage(pos)),
    };
    let (w0, w1, w2) = match w.as_slice() {
        [a, b, c] => (*a, *b, *c),
        _ => return Err(damage(pos)),
    };
    let width = w0.saturating_add(w1).saturating_add(w2);
    if width == 0 {
        return Err(damage(pos));
    }
    let size = dict
        .get(b"Size")
        .and_then(Object::as_i64)
        .ok_or_else(|| damage(pos))?;
    let index: Vec<(u64, u64)> = match dict.get(b"Index") {
        None => vec![(0, u64::try_from(size).map_err(|_| damage(pos))?)],
        Some(Object::Array(a)) => {
            let nums: Vec<u64> = a
                .iter()
                .map(|o| o.as_i64().and_then(|v| u64::try_from(v).ok()))
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| damage(pos))?;
            nums.chunks(2)
                .filter_map(|c| if let [f, n] = c { Some((*f, *n)) } else { None })
                .collect()
        }
        Some(_) => return Err(damage(pos)),
    };
    let mut rows_iter = rows.chunks_exact(width);
    let mut entries = Vec::new();
    'sub: for (first, count) in index {
        let mut k: u64 = 0;
        while k < count {
            if k.is_multiple_of(4096) {
                cx.cancelled()?;
            }
            // Rows are believed only as far as the decoded data reaches.
            let Some(row) = rows_iter.next() else {
                break 'sub;
            };
            let (f0, rest) = row.split_at(w0);
            let (f1, f2) = rest.split_at(w1);
            let kind = if w0 == 0 { 1 } else { be(f0) };
            let num = first
                .checked_add(k)
                .and_then(|n| u32::try_from(n).ok())
                .ok_or_else(|| damage(pos))?;
            let entry = match kind {
                0 => Entry::Free,
                // Offset 0 is the file header, never an object: LiveCycle's hybrid
                // updates list their own xref stream there (`PDF-REAL-02`). A classic
                // `n` entry at 0 is read the same way.
                1 if be(f1) == 0 => Entry::Free,
                1 => Entry::Offset {
                    offset: usize::try_from(be(f1)).map_err(|_| damage(pos))?,
                    generation: u16::try_from(be(f2)).unwrap_or(u16::MAX),
                },
                2 => Entry::Compressed {
                    stream: u32::try_from(be(f1)).map_err(|_| damage(pos))?,
                    index: u32::try_from(be(f2)).map_err(|_| damage(pos))?,
                },
                // Unknown types are references to null (§7.5.8.3).
                _ => Entry::Free,
            };
            if entries.len() >= cx.entry_cap() {
                return Err(SectionError::Fatal(PdfError::TooManyObjects {
                    limit: cx.max_objects,
                }));
            }
            entries.push((num, entry));
            k = k.saturating_add(1);
        }
    }
    Ok(entries)
}

/// Big-endian unsigned value of up to 8 bytes.
fn be(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b))
}

/// Every `n g obj` header in the file: (object number, offset of the header), in file
/// order. Used to rebuild a broken xref.
pub(crate) fn scan_headers(b: &[u8], cx: &SectionCtx<'_>) -> SectionResult<Vec<(u32, usize)>> {
    let mut found = Vec::new();
    let mut from = 0usize;
    let mut since_check = 0usize;
    while let Some(p) = find(b, b"obj", from) {
        from = p.saturating_add(3);
        since_check = since_check.saturating_add(1);
        if since_check >= 4096 {
            since_check = 0;
            cx.cancelled()?;
        }
        if b.get(from).is_some_and(|&c| is_regular(c)) || !token_start(b, p) {
            continue;
        }
        if let Some(start) = header_start_before(b, p)
            && let Some((num, _, _)) = header_at(b, start)
        {
            if found.len() >= cx.entry_cap() {
                return Err(SectionError::Fatal(PdfError::TooManyObjects {
                    limit: cx.max_objects,
                }));
            }
            found.push((num, start));
        }
    }
    Ok(found)
}

/// Walk back from an `obj` keyword over `gen` and `num` to where the header starts.
fn header_start_before(b: &[u8], obj: usize) -> Option<usize> {
    let mut p = obj;
    for _ in 0..2 {
        let ws_end = p;
        while p > 0 && b.get(p.checked_sub(1)?).is_some_and(|&c| is_ws(c)) {
            p = p.checked_sub(1)?;
        }
        if p == ws_end {
            return None;
        }
        let digits_end = p;
        while p > 0 && b.get(p.checked_sub(1)?).is_some_and(u8::is_ascii_digit) {
            p = p.checked_sub(1)?;
        }
        if p == digits_end || digits_end.saturating_sub(p) > 10 {
            return None;
        }
    }
    Some(p)
}

/// Offsets of every `trailer` keyword, in file order.
pub(crate) fn scan_trailers(b: &[u8]) -> Vec<usize> {
    let mut v = Vec::new();
    let mut from = 0usize;
    while let Some(p) = find(b, b"trailer", from) {
        from = p.saturating_add(7);
        if token_start(b, p) && !b.get(from).is_some_and(|&c| is_regular(c)) {
            v.push(from);
        }
    }
    v
}

#[cfg(test)]
mod tests {
    // Tests index and unwrap freely: a panic is the failure report.
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
    use super::*;

    fn never() -> bool {
        false
    }

    fn cx() -> SectionCtx<'static> {
        SectionCtx {
            max_objects: 10,
            max_depth: 16,
            max_string: 64,
            max_name: 64,
            lenient: false,
            max_values: 1000,
            cancel: &never,
        }
    }

    #[test]
    fn finds_headers_and_corrects_offsets() {
        let b = b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n12 0 obj 5 endobj";
        assert_eq!(header_at(b, 9), Some((1, 0, 16)));
        assert_eq!(correct_header(b, 14, 1, 16), Some(9));
        let found: Vec<u32> = scan_headers(b, &cx())
            .ok()
            .unwrap()
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert_eq!(found, vec![1, 12]);
    }

    #[test]
    fn table_count_is_believed_only_as_far_as_bytes_present() {
        let b = b"xref\n0 4000000000\n0000000000 65535 f \ntrailer\n<<>>";
        assert!(matches!(
            table_at(b, 0, &cx()),
            Err(SectionError::Damage(_))
        ));
    }

    #[test]
    fn table_entries_over_the_cap_are_fatal() {
        let mut b = b"xref\n0 12\n".to_vec();
        for _ in 0..12 {
            b.extend_from_slice(b"0000000000 65535 f \n");
        }
        b.extend_from_slice(b"trailer\n<<>>");
        assert!(matches!(
            table_at(&b, 0, &cx()),
            Err(SectionError::Fatal(PdfError::TooManyObjects { .. }))
        ));
    }

    #[test]
    fn zero_width_xref_stream_rows_are_damage() {
        let mut d = Dictionary::new();
        d.push(
            b"W".to_vec(),
            Object::Array(vec![
                Object::Integer(0),
                Object::Integer(0),
                Object::Integer(0),
            ]),
        );
        d.push(b"Size".to_vec(), Object::Integer(3));
        assert!(matches!(
            xref_stream_entries(&d, b"", 0, &cx()),
            Err(SectionError::Damage(_))
        ));
    }

    #[test]
    fn revision_end_includes_the_eol() {
        let b = b"xref ... %%EOF\r\nmore";
        assert_eq!(revision_end(b, 0), 16);
    }
}
