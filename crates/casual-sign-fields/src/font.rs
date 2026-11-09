//! Fonts for text extraction: how a shown string splits into codes, each code's width
//! and its Unicode text (ISO 32000-2 §9.2–9.10). No glyph is ever rendered.

use casual_sign_pdf::{Dictionary, Document, Object, PdfError};

use crate::cmap::CMap;
use crate::tables;

/// Width used for every glyph of a simple font that has no `/Widths` and is not one of
/// the standard 14 we carry metrics for, in 1/1000 em. The page is flagged.
pub const FALLBACK_WIDTH: f64 = 500.0;

/// Default ascent and descent, in em, when a font gives none we can trust.
const DEFAULT_ASCENT: f64 = 0.8;
const DEFAULT_DESCENT: f64 = -0.2;

/// Errors that end the whole extraction: the document's budgets and the host's
/// cancellation. Everything else damages only one font or stream, which is skipped.
pub(crate) fn is_fatal(e: &PdfError) -> bool {
    matches!(
        e,
        PdfError::DecodeBudget { .. } | PdfError::Cancelled | PdfError::OutOfMemory
    )
}

/// `Ok(None)` for a local failure, `Err` for a fatal one.
pub(crate) fn local<T>(r: Result<T, PdfError>) -> Result<Option<T>, PdfError> {
    match r {
        Ok(v) => Ok(Some(v)),
        Err(e) if is_fatal(&e) => Err(e),
        Err(_) => Ok(None),
    }
}

/// The Unicode character a glyph name stands for: the Adobe Glyph List subset we carry,
/// then `uniXXXX` and `uXXXX[XX]`; a suffix after `.` is ignored (`a.sc` is `a`).
pub(crate) fn glyph_unicode(name: &[u8]) -> Option<char> {
    let name = core::str::from_utf8(name).ok()?;
    let base = name.split('.').next().unwrap_or(name);
    if let Ok(i) = tables::GLYPH_NAMES.binary_search_by(|(n, _)| (*n).cmp(base)) {
        return tables::GLYPH_NAMES
            .get(i)
            .and_then(|(_, c)| char::from_u32(u32::from(*c)));
    }
    let hex = |s: &str| u32::from_str_radix(s, 16).ok().and_then(char::from_u32);
    if let Some(h) = base.strip_prefix("uni") {
        return h.get(..4).and_then(hex);
    }
    if let Some(h) = base.strip_prefix('u')
        && (4..=6).contains(&h.len())
        && h.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return hex(h);
    }
    None
}

#[derive(Debug, Clone)]
enum Kind {
    Simple {
        /// Width per code, in glyph units (× `scale` gives em).
        widths: Vec<f64>,
        /// Unicode per code from the encoding.
        unicode: Vec<Option<char>>,
    },
    Composite {
        encoding: CidEncoding,
        /// `(first CID, last CID, width)` sorted by first CID, 1/1000 em.
        widths: Vec<(u32, u32, f64)>,
        default_width: f64,
        /// Codes are UTF-16 (`Uni…-UCS2-…`, `Uni…-UTF16-…`), usable without `ToUnicode`.
        ucs2: bool,
    },
}

#[derive(Debug, Clone)]
enum CidEncoding {
    /// Two-byte codes, CID = code. Identity, and predefined CMaps we carry no data for.
    TwoByte,
    /// An embedded CMap.
    Embedded(CMap),
}

/// A font, reduced to what text extraction needs.
#[derive(Debug, Clone)]
pub(crate) struct Font {
    kind: Kind,
    to_unicode: Option<CMap>,
    /// Glyph-space units to em: 0.001, or `/FontMatrix` a for a Type 3 font.
    scale: f64,
    /// Ascent above the baseline, in em.
    pub(crate) ascent: f64,
    /// Descent below the baseline, in em (negative).
    pub(crate) descent: f64,
    /// Widths were guessed ([`FALLBACK_WIDTH`]).
    pub(crate) fallback_widths: bool,
    /// A predefined CMap we carry no data for: codes are read as two bytes.
    pub(crate) unsupported_cmap: bool,
    /// Vertical writing; positioned as horizontal text.
    pub(crate) vertical: bool,
}

/// One code read from a shown string.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Code {
    pub(crate) code: u32,
    pub(crate) len: u8,
}

impl Font {
    /// A font that knows nothing: used when `Tf` names no loadable font.
    pub(crate) fn unknown() -> Self {
        Self {
            kind: Kind::Simple {
                widths: vec![FALLBACK_WIDTH; 256],
                unicode: (0u8..=255).map(latin1).collect(),
            },
            to_unicode: None,
            scale: 0.001,
            ascent: DEFAULT_ASCENT,
            descent: DEFAULT_DESCENT,
            fallback_widths: true,
            unsupported_cmap: false,
            vertical: false,
        }
    }

    /// Split a shown string into codes.
    pub(crate) fn codes(&self, s: &[u8]) -> Vec<Code> {
        match &self.kind {
            Kind::Simple { .. } => s
                .iter()
                .map(|&b| Code {
                    code: u32::from(b),
                    len: 1,
                })
                .collect(),
            Kind::Composite { encoding, .. } => {
                let mut out = Vec::new();
                let mut rest = s;
                while !rest.is_empty() {
                    let n = match encoding {
                        CidEncoding::TwoByte => 2,
                        CidEncoding::Embedded(c) if c.has_code_spaces() => c.code_len(rest),
                        CidEncoding::Embedded(_) => 2,
                    }
                    .min(rest.len())
                    .max(1);
                    let (head, tail) = rest.split_at(n);
                    let code = head
                        .iter()
                        .fold(0u32, |a, &b| a.wrapping_shl(8) | u32::from(b));
                    out.push(Code {
                        code,
                        len: u8::try_from(n).unwrap_or(4),
                    });
                    rest = tail;
                }
                out
            }
        }
    }

    /// Advance width of a code, in em.
    pub(crate) fn width(&self, c: Code) -> f64 {
        match &self.kind {
            Kind::Simple { widths, .. } => {
                let w = usize::try_from(c.code)
                    .ok()
                    .and_then(|i| widths.get(i))
                    .copied()
                    .unwrap_or(0.0);
                w * self.scale
            }
            Kind::Composite {
                encoding,
                widths,
                default_width,
                ..
            } => {
                let cid = match encoding {
                    CidEncoding::TwoByte => Some(c.code),
                    CidEncoding::Embedded(m) => m.cid(c.len, c.code),
                }
                .unwrap_or(0);
                let i = widths.partition_point(|(lo, _, _)| *lo <= cid);
                let w = match i.checked_sub(1).and_then(|i| widths.get(i)) {
                    Some((_, hi, w)) if cid <= *hi => *w,
                    _ => *default_width,
                };
                w * 0.001
            }
        }
    }

    /// The Unicode text of a code; empty when nothing maps it.
    pub(crate) fn text(&self, c: Code) -> String {
        if let Some(t) = self
            .to_unicode
            .as_ref()
            .and_then(|m| m.unicode(c.len, c.code))
        {
            return t;
        }
        match &self.kind {
            Kind::Simple { unicode, .. } => usize::try_from(c.code)
                .ok()
                .and_then(|i| unicode.get(i))
                .copied()
                .flatten()
                .map(String::from)
                .unwrap_or_default(),
            Kind::Composite { ucs2: true, .. } => u16::try_from(c.code)
                .ok()
                .and_then(|u| char::from_u32(u32::from(u)))
                .map(String::from)
                .unwrap_or_default(),
            Kind::Composite { .. } => String::new(),
        }
    }
}

fn latin1(b: u8) -> Option<char> {
    (b >= 0x20 && b != 0x7f).then_some(char::from(b))
}

fn num(doc: &mut Document<'_>, o: Option<&Object>, cancel: &dyn Fn() -> bool) -> Option<f64> {
    let o = o?;
    let v = doc.resolve(o, cancel).ok()?;
    v.as_f64().filter(|v| v.is_finite())
}

fn resolved(
    doc: &mut Document<'_>,
    o: Option<&Object>,
    cancel: &dyn Fn() -> bool,
) -> Result<Option<Object>, PdfError> {
    match o {
        None => Ok(None),
        Some(o) => local(doc.resolve(o, cancel)),
    }
}

fn stream_cmap(
    doc: &mut Document<'_>,
    o: Option<&Object>,
    cancel: &dyn Fn() -> bool,
) -> Result<Option<CMap>, PdfError> {
    match o.and_then(Object::as_ref) {
        Some(r) => Ok(local(doc.decode_stream(r.num, cancel))?.map(|d| CMap::parse(&d))),
        None => Ok(None),
    }
}

/// The standard-14 family whose metrics stand in for `base`, with subset prefixes and
/// the common Windows names (`Arial`, `TimesNewRoman`, `CourierNew`) understood.
fn standard(base: &[u8]) -> Option<(&'static [u16; 224], &'static str)> {
    let name = core::str::from_utf8(base).ok()?;
    let name = match name.split_once('+') {
        Some((tag, rest)) if tag.len() == 6 => rest,
        _ => name,
    };
    let lower = name.to_ascii_lowercase();
    let bold = lower.contains("bold");
    let italic = lower.contains("italic") || lower.contains("oblique");
    if lower.starts_with("courier") {
        return Some((&COURIER, "Courier"));
    }
    if lower.starts_with("helvetica") || lower.starts_with("arial") {
        return Some(if bold {
            (&tables::HELVETICA_BOLD, "Helvetica-Bold")
        } else {
            (&tables::HELVETICA, "Helvetica")
        });
    }
    if lower.starts_with("times") {
        return Some(match (bold, italic) {
            (true, true) => (&tables::TIMES_BOLDITALIC, "Times-BoldItalic"),
            (true, false) => (&tables::TIMES_BOLD, "Times-Bold"),
            (false, true) => (&tables::TIMES_ITALIC, "Times-Italic"),
            (false, false) => (&tables::TIMES_ROMAN, "Times-Roman"),
        });
    }
    None
}

static COURIER: [u16; 224] = [600; 224];

fn ascent_descent(family: &str) -> Option<(f64, f64)> {
    tables::ASCENT_DESCENT
        .iter()
        .find(|(n, _, _)| *n == family)
        .map(|(_, a, d)| (f64::from(*a) / 1000.0, f64::from(*d) / 1000.0))
}

fn base_encoding(name: &[u8]) -> Option<&'static [u16; 256]> {
    match name {
        b"WinAnsiEncoding" => Some(&tables::WIN_ANSI),
        b"MacRomanEncoding" => Some(&tables::MAC_ROMAN),
        b"StandardEncoding" | b"MacExpertEncoding" => Some(&tables::STANDARD),
        _ => None,
    }
}

/// Load the font `obj` (a font dictionary, or a reference to one).
pub(crate) fn load(
    doc: &mut Document<'_>,
    obj: &Object,
    cancel: &dyn Fn() -> bool,
) -> Result<Font, PdfError> {
    let Some(o) = local(doc.resolve(obj, cancel))? else {
        return Ok(Font::unknown());
    };
    let Some(d) = o.dict().cloned() else {
        return Ok(Font::unknown());
    };
    let to_unicode = stream_cmap(doc, d.get(b"ToUnicode"), cancel)?;
    let mut font = if d.name(b"Subtype") == Some(b"Type0") {
        composite(doc, &d, cancel)?
    } else {
        simple(doc, &d, cancel)?
    };
    font.to_unicode = to_unicode;
    Ok(font)
}

/// Ascent and descent (em) and `/MissingWidth` from a font descriptor.
type Metrics = (Option<f64>, Option<f64>, Option<f64>);

fn descriptor_metrics(
    doc: &mut Document<'_>,
    d: &Dictionary,
    cancel: &dyn Fn() -> bool,
) -> Result<Metrics, PdfError> {
    let Some(fd) = resolved(doc, d.get(b"FontDescriptor"), cancel)? else {
        return Ok((None, None, None));
    };
    let Some(fd) = fd.dict() else {
        return Ok((None, None, None));
    };
    let ascent = num(doc, fd.get(b"Ascent"), cancel).filter(|a| *a > 0.0 && *a <= 2000.0);
    let descent = num(doc, fd.get(b"Descent"), cancel).filter(|d| *d < 0.0 && *d >= -1000.0);
    let missing = num(doc, fd.get(b"MissingWidth"), cancel);
    Ok((
        ascent.map(|a| a / 1000.0),
        descent.map(|d| d / 1000.0),
        missing,
    ))
}

fn simple(
    doc: &mut Document<'_>,
    d: &Dictionary,
    cancel: &dyn Fn() -> bool,
) -> Result<Font, PdfError> {
    let subtype = d.name(b"Subtype").unwrap_or_default().to_vec();
    let base_font = d.name(b"BaseFont").unwrap_or_default().to_vec();
    let std = standard(&base_font);
    let type3 = subtype == b"Type3";

    // Encoding: base table, then /Differences.
    let enc = resolved(doc, d.get(b"Encoding"), cancel)?;
    let default_base = if subtype == b"TrueType" {
        &tables::WIN_ANSI
    } else {
        &tables::STANDARD
    };
    let mut base = default_base;
    let mut diffs: Vec<(usize, char)> = Vec::new();
    match &enc {
        Some(Object::Name(n)) => base = base_encoding(n).unwrap_or(default_base),
        Some(o @ Object::Dictionary(_)) => {
            if let Some(b) = o.get(b"BaseEncoding").and_then(Object::as_name) {
                base = base_encoding(b).unwrap_or(default_base);
            }
            if let Some(Object::Array(a)) = resolved(doc, o.get(b"Differences"), cancel)? {
                let mut code: Option<usize> = None;
                for item in &a {
                    match item {
                        Object::Integer(i) => code = usize::try_from(*i).ok(),
                        Object::Name(n) => {
                            if let Some(c) = code {
                                if let Some(ch) = glyph_unicode(n) {
                                    diffs.push((c, ch));
                                }
                                code = c.checked_add(1);
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
        _ => {}
    }
    let mut unicode: Vec<Option<char>> = base
        .iter()
        .enumerate()
        .map(|(i, &u)| {
            if u == 0 {
                u8::try_from(i).ok().and_then(latin1)
            } else {
                char::from_u32(u32::from(u))
            }
        })
        .collect();
    for (c, ch) in diffs {
        if let Some(slot) = unicode.get_mut(c) {
            *slot = Some(ch);
        }
    }

    let (fd_ascent, fd_descent, missing) = descriptor_metrics(doc, d, cancel)?;
    let mut fallback_widths = false;
    let widths_obj = resolved(doc, d.get(b"Widths"), cancel)?;
    let widths: Vec<f64> = if let Some(Object::Array(ws)) = widths_obj {
        let first = num(doc, d.get(b"FirstChar"), cancel).unwrap_or(0.0);
        let first = if (0.0..=255.0).contains(&first) {
            first as usize
        } else {
            0
        };
        let mut v = vec![missing.unwrap_or(0.0); 256];
        for (i, w) in ws.iter().take(256).enumerate() {
            let w = num(doc, Some(w), cancel).unwrap_or(0.0);
            if let Some(slot) = first.checked_add(i).and_then(|c| v.get_mut(c)) {
                *slot = w;
            }
        }
        v
    } else if let Some((table, _)) = std {
        unicode
            .iter()
            .enumerate()
            .map(|(code, u)| {
                // The tables are indexed by WinAnsi code; find this glyph there.
                let ch = u.map(u32::from);
                let idx = ch.and_then(|ch| {
                    tables::WIN_ANSI
                        .iter()
                        .skip(32)
                        .position(|&w| u32::from(w) == ch)
                });
                let idx = idx.or_else(|| code.checked_sub(32));
                idx.and_then(|i| table.get(i))
                    .map_or(0.0, |w| f64::from(*w))
            })
            .collect()
    } else {
        fallback_widths = true;
        vec![FALLBACK_WIDTH; 256]
    };

    let mut scale = 0.001;
    if type3
        && let Some(Object::Array(m)) = resolved(doc, d.get(b"FontMatrix"), cancel)?
        && let Some(a) = m.first().and_then(Object::as_f64).filter(|a| a.is_finite())
    {
        scale = a;
    }
    let std_metrics = std.and_then(|(_, fam)| ascent_descent(fam));
    let (ascent, descent) = if type3 {
        (DEFAULT_ASCENT, DEFAULT_DESCENT)
    } else {
        (
            fd_ascent
                .or(std_metrics.map(|m| m.0))
                .unwrap_or(DEFAULT_ASCENT),
            fd_descent
                .or(std_metrics.map(|m| m.1))
                .unwrap_or(DEFAULT_DESCENT),
        )
    };
    Ok(Font {
        kind: Kind::Simple { widths, unicode },
        to_unicode: None,
        scale,
        ascent,
        descent,
        fallback_widths,
        unsupported_cmap: false,
        vertical: false,
    })
}

fn composite(
    doc: &mut Document<'_>,
    d: &Dictionary,
    cancel: &dyn Fn() -> bool,
) -> Result<Font, PdfError> {
    let mut unsupported_cmap = false;
    let mut vertical = false;
    let mut ucs2 = false;
    let encoding = match d.get(b"Encoding") {
        Some(Object::Name(n)) => {
            vertical = n.ends_with(b"-V");
            if n != b"Identity-H" && n != b"Identity-V" {
                unsupported_cmap = true;
                ucs2 = n.starts_with(b"Uni")
                    && (n.windows(4).any(|w| w == b"UCS2") || n.windows(5).any(|w| w == b"UTF16"));
            }
            CidEncoding::TwoByte
        }
        other => match stream_cmap(doc, other, cancel)? {
            Some(m) => CidEncoding::Embedded(m),
            None => CidEncoding::TwoByte,
        },
    };
    let mut widths: Vec<(u32, u32, f64)> = Vec::new();
    let mut default_width = 1000.0;
    let (mut ascent, mut descent) = (None, None);
    let desc = resolved(doc, d.get(b"DescendantFonts"), cancel)?;
    let cid_font = match desc {
        Some(Object::Array(a)) => match a.first() {
            Some(f) => resolved(doc, Some(f), cancel)?,
            None => None,
        },
        _ => None,
    };
    if let Some(cf) = cid_font.as_ref().and_then(Object::dict) {
        if let Some(dw) = num(doc, cf.get(b"DW"), cancel) {
            default_width = dw;
        }
        (ascent, descent, _) = descriptor_metrics(doc, cf, cancel)?;
        if let Some(Object::Array(w)) = resolved(doc, cf.get(b"W"), cancel)? {
            parse_w(doc, &w, &mut widths, cancel);
        }
    }
    widths.sort_by_key(|(lo, _, _)| *lo);
    Ok(Font {
        kind: Kind::Composite {
            encoding,
            widths,
            default_width,
            ucs2,
        },
        to_unicode: None,
        scale: 0.001,
        ascent: ascent.unwrap_or(DEFAULT_ASCENT),
        descent: descent.unwrap_or(DEFAULT_DESCENT),
        fallback_widths: false,
        unsupported_cmap,
        vertical,
    })
}

/// `/W`: `c [w1 w2 …]` and `c_first c_last w` entries (§9.7.4.3).
fn parse_w(
    doc: &mut Document<'_>,
    w: &[Object],
    out: &mut Vec<(u32, u32, f64)>,
    cancel: &dyn Fn() -> bool,
) {
    let cid = |o: &Object| {
        o.as_i64().and_then(|i| u32::try_from(i).ok()).or_else(|| {
            o.as_f64()
                .filter(|f| *f >= 0.0 && *f < 4.0e9)
                .map(|f| f as u32)
        })
    };
    let mut i = 0usize;
    while let Some(first) = w.get(i).and_then(cid) {
        match w.get(i.saturating_add(1)) {
            Some(arr @ (Object::Array(_) | Object::Reference(_))) => {
                if let Ok(Object::Array(list)) = doc.resolve(arr, cancel) {
                    let mut c = first;
                    for v in &list {
                        if let Some(width) = v.as_f64() {
                            out.push((c, c, width));
                        }
                        c = c.saturating_add(1);
                    }
                }
                i = i.saturating_add(2);
            }
            Some(last) => {
                let (Some(last), Some(width)) = (
                    cid(last),
                    w.get(i.saturating_add(2)).and_then(Object::as_f64),
                ) else {
                    break;
                };
                if last >= first {
                    out.push((first, last, width));
                }
                i = i.saturating_add(3);
            }
            None => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glyph_names_resolve() {
        assert_eq!(glyph_unicode(b"A"), Some('A'));
        assert_eq!(glyph_unicode(b"eacute"), Some('é'));
        assert_eq!(glyph_unicode(b"uni20AC"), Some('€'));
        assert_eq!(glyph_unicode(b"u1F600"), Some('\u{1F600}'));
        assert_eq!(glyph_unicode(b"a.sc"), Some('a'));
        assert_eq!(glyph_unicode(b"g123"), None);
    }

    #[test]
    fn standard_names_are_recognized() {
        assert_eq!(
            standard(b"ABCDEF+Arial,Bold").map(|s| s.1),
            Some("Helvetica-Bold")
        );
        assert_eq!(
            standard(b"TimesNewRomanPS-BoldItalicMT").map(|s| s.1),
            Some("Times-BoldItalic")
        );
        assert_eq!(standard(b"Courier-Oblique").map(|s| s.1), Some("Courier"));
        assert_eq!(standard(b"Symbol"), None);
    }

    #[test]
    fn helvetica_widths_are_the_afm_values() {
        // A, a, space from Adobe's Helvetica AFM.
        assert_eq!(tables::HELVETICA.get(65 - 32), Some(&667));
        assert_eq!(tables::HELVETICA.get(97 - 32), Some(&556));
        assert_eq!(tables::HELVETICA.first(), Some(&278));
    }
}
