//! The screen a `.docx` passes before the converter reads it (docs/21 §DOCX conversion,
//! docs/07 `SEC-P13`). It runs inside the per-job child, under the child's limits, and
//! reads the archive's central directory and three kinds of small part only:
//!
//! - **The archive.** At most [`MAX_ENTRIES`] entries; no encrypted entry; every entry's
//!   declared expanded size at most [`MAX_PART`], all of them together at most
//!   [`MAX_EXPANDED`], and above [`RATIO_FLOOR`] no entry expanding more than
//!   [`MAX_RATIO`] times (a zip bomb). Declared sizes can lie: a part read here is read
//!   through a cap one byte above its declared size, and the child's address-space limit
//!   bounds what the converter reads after.
//! - **`[Content_Types].xml`.** The package must declare a Word document's main part.
//!   A macro-enabled document (`.docm`, `macroEnabled` content types, a VBA project or
//!   VBA data part anywhere) is refused, `CS-CNV-0004`: macros never run and are never
//!   kept. A template (`.dotx`) is refused as unsupported.
//! - **Relationships (`*.rels`).** Targets with `TargetMode="External"` (linked pictures,
//!   hyperlinks, attached templates) are counted. None is ever fetched: the converter
//!   reads the archive only and convertd has no network.
//! - **The main part.** Explicit page breaks and sections are counted; an estimate over
//!   [`MAX_PAGES`] is refused before rendering. Admission counts the converted PDF's
//!   pages again (docs/21 `CS-PDF-0007`).
//!
//! Nothing here reads text into an error or a log line: errors are a code and a reason.

use std::io::{Cursor, Read};

use zip::ZipArchive;

use crate::error::{ConvertError, Reason};

/// Archive entries at most.
pub const MAX_ENTRIES: usize = 4_096;
/// One part's declared expanded size at most, bytes.
pub const MAX_PART: u64 = 64 << 20;
/// All parts' declared expanded sizes together at most, bytes.
pub const MAX_EXPANDED: u64 = 256 << 20;
/// Expansion ratio at most, for an entry whose expanded size is above [`RATIO_FLOOR`].
pub const MAX_RATIO: u64 = 1_000;
/// Entries expanding to at most this many bytes are not ratio-checked (small XML parts
/// legitimately compress very well).
pub const RATIO_FLOOR: u64 = 1 << 20;
/// Pages at most, estimated from the main part (as `CS-PDF-0007`).
pub const MAX_PAGES: u64 = 5_000;
/// A relationships part read at most, bytes.
const MAX_RELS: u64 = 4 << 20;
/// Relationships parts read at most.
const MAX_RELS_PARTS: usize = 1_024;

const MAIN_DOCUMENT: &str =
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml";
const MAIN_TEMPLATE: &str =
    "application/vnd.openxmlformats-officedocument.wordprocessingml.template.main+xml";

/// What the screen found in an admitted archive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Screened {
    /// Relationships with `TargetMode="External"` (never fetched).
    pub external_refs: u32,
    /// The page estimate from the main part.
    pub pages_estimate: u64,
}

const MALFORMED: ConvertError = ConvertError::Failed(Reason::Malformed);

/// Screen `docx` (see the module notes).
///
/// # Errors
/// `CS-CNV-0002` (`not_zip`, `not_word`, `template`, `encrypted`); `CS-CNV-0004` for
/// macros; `CS-CNV-0003` (`entries`, `part`, `expanded`, `ratio`, `pages`);
/// `CS-CNV-0001 malformed` for a part that does not read as declared.
pub fn screen(docx: &[u8]) -> Result<Screened, ConvertError> {
    if !docx.starts_with(b"PK\x03\x04") {
        return Err(ConvertError::Unsupported(Reason::NotZip));
    }
    let mut zip = ZipArchive::new(Cursor::new(docx))
        .map_err(|_| ConvertError::Unsupported(Reason::NotZip))?;
    if zip.len() > MAX_ENTRIES {
        return Err(ConvertError::OverLimit(Reason::Entries));
    }
    let mut total: u64 = 0;
    let mut rels = Vec::new();
    let mut has_types = false;
    for i in 0..zip.len() {
        let f = zip.by_index_raw(i).map_err(|_| MALFORMED)?;
        if f.encrypted() {
            return Err(ConvertError::Unsupported(Reason::Encrypted));
        }
        let size = f.size();
        if size > MAX_PART {
            return Err(ConvertError::OverLimit(Reason::Part));
        }
        total = total.saturating_add(size);
        if total > MAX_EXPANDED {
            return Err(ConvertError::OverLimit(Reason::Expanded));
        }
        if size > RATIO_FLOOR
            && size.checked_div(f.compressed_size()).unwrap_or(u64::MAX) > MAX_RATIO
        {
            return Err(ConvertError::OverLimit(Reason::Ratio));
        }
        let name = f.name().map_err(|_| MALFORMED)?.to_ascii_lowercase();
        if name.ends_with("vbaproject.bin") || name.ends_with("vbadata.xml") {
            return Err(ConvertError::Macros);
        }
        if name == "[content_types].xml" {
            has_types = true;
        } else if name.ends_with(".rels") && rels.len() < MAX_RELS_PARTS {
            rels.push(i);
        }
    }
    if !has_types {
        return Err(ConvertError::Unsupported(Reason::NotWord));
    }
    let types = read_part(&mut zip, "[Content_Types].xml", MAX_RELS)?;
    let main = main_part(&types)?;
    let mut external: u32 = 0;
    for i in rels {
        let text = read_index(&mut zip, i, MAX_RELS)?;
        let n = count(&text, "TargetMode=\"External\"")
            .saturating_add(count(&text, "TargetMode='External'"));
        external = external.saturating_add(u32::try_from(n).unwrap_or(u32::MAX));
    }
    let body = read_part(&mut zip, main.trim_start_matches('/'), MAX_PART)?;
    let pages = estimate_pages(&body);
    if pages > MAX_PAGES {
        return Err(ConvertError::OverLimit(Reason::Pages));
    }
    Ok(Screened {
        external_refs: external,
        pages_estimate: pages,
    })
}

/// The main part's name from `[Content_Types].xml`, after the macro and template checks.
fn main_part(types: &str) -> Result<String, ConvertError> {
    let lower = types.to_ascii_lowercase();
    if lower.contains("macroenabled") || lower.contains("vbaproject") {
        return Err(ConvertError::Macros);
    }
    let mut found = None;
    let mut template = false;
    for el in types.split('<').filter(|e| e.starts_with("Override")) {
        let ct = attr(el, "ContentType");
        if ct == Some(MAIN_TEMPLATE) {
            template = true;
        }
        if ct == Some(MAIN_DOCUMENT) {
            found = attr(el, "PartName").map(str::to_owned);
        }
    }
    match found {
        Some(p) if !p.is_empty() => Ok(p),
        _ if template => Err(ConvertError::Unsupported(Reason::Template)),
        _ => Err(ConvertError::Unsupported(Reason::NotWord)),
    }
}

/// An attribute's value in one element's text (`name="v"` or `name='v'`).
fn attr<'a>(el: &'a str, name: &str) -> Option<&'a str> {
    let mut rest = el;
    while let Some(at) = rest.find(name) {
        let after = rest.get(at.saturating_add(name.len())..)?;
        let before_ok = at == 0
            || rest
                .get(..at)
                .and_then(|b| b.chars().last())
                .is_some_and(char::is_whitespace);
        let after = after.trim_start();
        if before_ok && let Some(v) = after.strip_prefix('=') {
            let v = v.trim_start();
            let quote = v.chars().next()?;
            if quote == '"' || quote == '\'' {
                let v = v.get(1..)?;
                return v.find(quote).and_then(|end| v.get(..end));
            }
        }
        rest = rest.get(at.saturating_add(name.len())..)?;
    }
    None
}

fn count(text: &str, needle: &str) -> usize {
    text.matches(needle).count()
}

/// One page, plus one per explicit page break, page-break-before paragraph and section
/// break (the last section's properties end the body and add none). Namespace prefixes
/// vary, so the local names are matched.
fn estimate_pages(body: &str) -> u64 {
    let breaks = count(body, "type=\"page\"").saturating_add(count(body, "type='page'"));
    let before = count(body, "pageBreakBefore");
    // An opening and a closing tag each name `sectPr`.
    let sections = body.matches("sectPr").count().checked_div(2).unwrap_or(0);
    let n = breaks
        .saturating_add(before)
        .saturating_add(sections.saturating_sub(1));
    u64::try_from(n).unwrap_or(u64::MAX).saturating_add(1)
}

fn read_part(
    zip: &mut ZipArchive<Cursor<&[u8]>>,
    name: &str,
    cap: u64,
) -> Result<String, ConvertError> {
    let i = zip
        .index_for_name(name)
        .ok_or(ConvertError::Unsupported(Reason::NotWord))?;
    read_index(zip, i, cap)
}

/// An entry's text, read through a cap of `min(declared, cap) + 1` bytes: an entry that
/// expands past its declared size is malformed.
fn read_index(
    zip: &mut ZipArchive<Cursor<&[u8]>>,
    i: usize,
    cap: u64,
) -> Result<String, ConvertError> {
    let f = zip.by_index(i).map_err(|_| MALFORMED)?;
    let declared = f.size();
    if declared > cap {
        return Err(ConvertError::OverLimit(Reason::Part));
    }
    let mut out = Vec::new();
    f.take(declared.saturating_add(1))
        .read_to_end(&mut out)
        .map_err(|_| MALFORMED)?;
    if u64::try_from(out.len()).unwrap_or(u64::MAX) > declared {
        return Err(MALFORMED);
    }
    String::from_utf8(out).map_err(|_| MALFORMED)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attributes_are_found_in_either_quote_and_not_inside_other_names() {
        let el = r#"Override XPartName="/x" PartName='/word/document.xml' ContentType="a""#;
        assert_eq!(attr(el, "PartName"), Some("/word/document.xml"));
        assert_eq!(attr(el, "ContentType"), Some("a"));
        assert_eq!(attr(el, "Missing"), None);
        assert_eq!(attr("Override PartName=", "PartName"), None);
    }

    #[test]
    fn the_page_estimate_counts_breaks_and_sections() {
        assert_eq!(estimate_pages("<w:body><w:p/></w:body>"), 1);
        let body = r#"<w:br w:type="page"/><w:pageBreakBefore/><w:sectPr></w:sectPr><w:sectPr></w:sectPr>"#;
        assert_eq!(estimate_pages(body), 4);
    }

    #[test]
    fn a_macro_content_type_or_template_is_refused() {
        let docm = r#"<Types><Override PartName="/word/document.xml" ContentType="application/vnd.ms-word.document.macroEnabled.main+xml"/></Types>"#;
        assert_eq!(main_part(docm), Err(ConvertError::Macros));
        let dotx = format!(
            r#"<Types><Override PartName="/word/document.xml" ContentType="{MAIN_TEMPLATE}"/></Types>"#
        );
        assert_eq!(
            main_part(&dotx),
            Err(ConvertError::Unsupported(Reason::Template))
        );
        let docx = format!(
            r#"<Types><Override PartName="/word/document.xml" ContentType="{MAIN_DOCUMENT}"/></Types>"#
        );
        assert_eq!(main_part(&docx).as_deref(), Ok("/word/document.xml"));
    }

    #[test]
    fn bytes_that_are_not_a_zip_are_unsupported() {
        assert_eq!(
            screen(b"%PDF-1.7"),
            Err(ConvertError::Unsupported(Reason::NotZip))
        );
        assert_eq!(
            screen(b"PK\x03\x04garbage"),
            Err(ConvertError::Unsupported(Reason::NotZip))
        );
    }
}
