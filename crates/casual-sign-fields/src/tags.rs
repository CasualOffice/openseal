//! Text tags (docs/30 §5, docs/40 §3, docs/49 §2): SignNow-style tags written in a
//! document's text become fields where they stand.
//!
//! # Grammar
//!
//! Tags are read from the page text after NFKC (so full-width braces count) with
//! whitespace inferred from glyph positions; **whitespace inside a tag is ignored**.
//!
//! ```text
//! tag       = "{{" type ":" recipient [ ":" required ] [ ":" label ] [ ":" size ] "}}"
//! type      = one of TYPES below, ASCII case-insensitive
//! recipient = 1*64( ALPHA / DIGIT / "_" / "-" )        ; a recipient or role reference
//! required  = "req" / "required"                        ; ASCII case-insensitive
//! label     = 1*255 bytes, no ":" "{" "}", no control   ; the data label (NFC later)
//! size      = number ( "x" / "X" ) number               ; width x height, points
//! number    = 1*DIGIT [ "." 1*DIGIT ]                   ; > 0 and <= 14400
//! ```
//!
//! The optional parts keep their order; a part that parses as a `size` is the size,
//! so a label may not look like `12x30`. The tag's text is at most
//! [`MAX_TAG_CHARS`] characters between the braces; a `{{` with no `}}` in that span,
//! or with another `{{` first, is unterminated. At most [`MAX_TAGS`] tags per document.
//!
//! The field takes the tag's rectangle (the bounding box of its glyphs, braces
//! included), or the tag's top-left corner and the given size. The tag's rectangle is
//! reported so normalization can cover the tag text. Errors carry the page and the
//! tag's position, never its text (`CS-FLD-0011`).

use casual_sign_model::{DataLabel, FieldType, Id, Placement};

use crate::error::{PlaceError, TagProblem};
use crate::geometry::DisplayRect;
use crate::text::{PageText, char_stream};

/// Most characters between `{{` and `}}`.
pub const MAX_TAG_CHARS: usize = 512;
/// Most tags per document: docs/21's fields per envelope.
pub const MAX_TAGS: usize = 3_000;

/// Type names a tag may use, with SignNow's one-letter forms. Types that need more
/// than a tag can say (options, a formula, a URL, a payment) are not taggable.
pub const TYPES: &[(&str, FieldType)] = &[
    ("signature", FieldType::Signature),
    ("s", FieldType::Signature),
    ("initials", FieldType::Initials),
    ("i", FieldType::Initials),
    ("stamp", FieldType::Stamp),
    ("date_signed", FieldType::DateSigned),
    ("name", FieldType::Name),
    ("first_name", FieldType::FirstName),
    ("last_name", FieldType::LastName),
    ("email", FieldType::Email),
    ("company", FieldType::Company),
    ("title", FieldType::Title),
    ("envelope_id", FieldType::EnvelopeId),
    ("text", FieldType::Text),
    ("t", FieldType::Text),
    ("number", FieldType::Number),
    ("date", FieldType::Date),
    ("d", FieldType::Date),
    ("email_address", FieldType::EmailAddress),
    ("phone", FieldType::Phone),
    ("ssn", FieldType::Ssn),
    ("zip", FieldType::Zip),
    ("checkbox", FieldType::Checkbox),
    ("c", FieldType::Checkbox),
    ("attachment", FieldType::Attachment),
    ("a", FieldType::Attachment),
    ("approve", FieldType::Approve),
    ("decline", FieldType::Decline),
];

/// A field read from a tag.
#[derive(Debug, Clone, PartialEq)]
pub struct TextTag {
    /// The field's type.
    pub field_type: FieldType,
    /// The recipient (or role) reference as written.
    pub recipient: Id,
    /// The tag said `req` or `required`.
    pub required: bool,
    /// The data label, when given.
    pub label: Option<DataLabel>,
    /// Where the field goes.
    pub placement: Placement,
    /// The tag text's rectangle, for normalization to cover.
    pub tag_rect: DisplayRect,
}

/// Every tag found, and every malformed one.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TagScan {
    /// Well-formed tags, in page then content order.
    pub tags: Vec<TextTag>,
    /// Malformed tags and other refusals, in the same order.
    pub errors: Vec<PlaceError>,
}

struct Parsed {
    field_type: FieldType,
    recipient: Id,
    required: bool,
    label: Option<DataLabel>,
    size: Option<(f64, f64)>,
}

fn size_part(s: &str) -> Option<Result<(f64, f64), TagProblem>> {
    let (w, h) = s.split_once(['x', 'X'])?;
    let num = |t: &str| {
        let (int, frac) = t.split_once('.').unwrap_or((t, "0"));
        let ok = !int.is_empty()
            && !frac.is_empty()
            && int.bytes().all(|b| b.is_ascii_digit())
            && frac.bytes().all(|b| b.is_ascii_digit())
            && t.len() <= 16;
        ok.then(|| t.parse::<f64>().ok()).flatten()
    };
    let (Some(w), Some(h)) = (num(w), num(h)) else {
        // Digits on one side only: meant as a size, but wrong.
        let looks = w.bytes().any(|b| b.is_ascii_digit()) && h.bytes().any(|b| b.is_ascii_digit());
        return looks.then_some(Err(TagProblem::Size));
    };
    let valid = |v: f64| v > 0.0 && v <= 14_400.0;
    Some(if valid(w) && valid(h) {
        Ok((w, h))
    } else {
        Err(TagProblem::Size)
    })
}

fn parse(body: &str) -> Result<Parsed, TagProblem> {
    let parts: Vec<&str> = body.split(':').collect();
    let (Some(ty), Some(rcpt)) = (parts.first(), parts.get(1)) else {
        return Err(TagProblem::MissingParts);
    };
    let field_type = TYPES
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(ty))
        .map(|(_, t)| *t)
        .ok_or(TagProblem::UnknownType)?;
    let recipient = Id::new(*rcpt).map_err(|_| TagProblem::Recipient)?;
    let mut rest = parts.get(2..).unwrap_or_default().iter().peekable();
    let mut required = false;
    if rest
        .peek()
        .is_some_and(|p| p.eq_ignore_ascii_case("req") || p.eq_ignore_ascii_case("required"))
    {
        required = true;
        rest.next();
    }
    let mut label = None;
    let mut size = None;
    if let Some(p) = rest.next() {
        match size_part(p) {
            Some(s) => size = Some(s?),
            None => {
                if p.contains(['{', '}']) {
                    return Err(TagProblem::Label);
                }
                label = Some(DataLabel::new(*p).map_err(|_| TagProblem::Label)?);
                if let Some(p) = rest.next() {
                    size = Some(size_part(p).ok_or(TagProblem::TooManyParts)??);
                }
            }
        }
    }
    if rest.next().is_some() {
        return Err(TagProblem::TooManyParts);
    }
    Ok(Parsed {
        field_type,
        recipient,
        required,
        label,
        size,
    })
}

fn find(chars: &[char], from: usize, pat: [char; 2]) -> Option<usize> {
    let mut i = from;
    while let (Some(a), Some(b)) = (chars.get(i), chars.get(i.saturating_add(1))) {
        if *a == pat[0] && *b == pat[1] {
            return Some(i);
        }
        i = i.saturating_add(1);
    }
    None
}

/// Find every text tag in the document.
#[must_use]
pub fn scan_tags(pages: &[PageText]) -> TagScan {
    let mut scan = TagScan::default();
    for page in pages {
        let chars = char_stream(page, false);
        let cs = &chars.chars;
        let mut i = 0usize;
        while let Some(open) = find(cs, i, ['{', '{']) {
            let at = |to: usize| chars.rect(page, open, to).unwrap_or_default();
            let malformed = |problem, rect: DisplayRect| PlaceError::TagMalformed {
                page: page.page,
                x: rect.x,
                y: rect.y,
                problem,
            };
            let body_start = open.saturating_add(2);
            let limit = body_start.saturating_add(MAX_TAG_CHARS);
            let close = find(cs, body_start, ['}', '}']).filter(|c| *c <= limit);
            let reopen = find(cs, body_start, ['{', '{']);
            let close = match (close, reopen) {
                (Some(c), Some(r)) if r < c => None,
                (c, _) => c,
            };
            let Some(close) = close else {
                scan.errors
                    .push(malformed(TagProblem::Unterminated, at(body_start)));
                i = reopen.unwrap_or(body_start);
                continue;
            };
            let end = close.saturating_add(2);
            i = end;
            if scan.tags.len().saturating_add(scan.errors.len()) >= MAX_TAGS {
                scan.errors
                    .push(PlaceError::TooManyTags { limit: MAX_TAGS });
                return scan;
            }
            let rect = at(end);
            let body: String = cs
                .get(body_start..close)
                .unwrap_or_default()
                .iter()
                .filter(|c| !c.is_whitespace())
                .collect();
            let parsed = match parse(&body) {
                Ok(p) => p,
                Err(problem) => {
                    scan.errors.push(malformed(problem, rect));
                    continue;
                }
            };
            let field = match parsed.size {
                Some((w, h)) => DisplayRect {
                    width: w,
                    height: h,
                    ..rect
                },
                None => rect,
            };
            let placement = if page.geometry.contains(&field, 0.01) {
                field.to_placement(page.page).ok()
            } else {
                None
            };
            let Some(placement) = placement else {
                scan.errors
                    .push(PlaceError::OutsidePage { page: page.page });
                continue;
            };
            scan.tags.push(TextTag {
                field_type: parsed.field_type,
                recipient: parsed.recipient,
                required: parsed.required,
                label: parsed.label,
                placement,
                tag_rect: rect,
            });
        }
    }
    scan
}

#[cfg(test)]
mod tests {
    // Tests may unwrap (CLAUDE.md): a failure here is the test failing.
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn grammar_accepts_each_optional_part_in_order() {
        let p = parse("signature:client").ok().unwrap();
        assert_eq!(p.field_type, FieldType::Signature);
        assert!(!p.required && p.label.is_none() && p.size.is_none());
        let p = parse("text:client:req:company_name").ok().unwrap();
        assert!(p.required);
        assert_eq!(p.label.unwrap().as_str(), "company_name");
        let p = parse("T:ceo:Required:120x30.5").ok().unwrap();
        assert_eq!(p.field_type, FieldType::Text);
        assert_eq!(p.size, Some((120.0, 30.5)));
        let p = parse("d:ceo:due:80X20").ok().unwrap();
        assert_eq!(p.size, Some((80.0, 20.0)));
    }

    #[test]
    fn grammar_refuses_each_malformation() {
        assert_eq!(parse("signature").err(), Some(TagProblem::MissingParts));
        assert_eq!(parse("dropdown:a").err(), Some(TagProblem::UnknownType));
        assert_eq!(parse("s:bad.ref").err(), Some(TagProblem::Recipient));
        assert_eq!(parse("s:a::").err(), Some(TagProblem::Label));
        assert_eq!(parse("s:a:0x30").err(), Some(TagProblem::Size));
        assert_eq!(parse("s:a:1x99999").err(), Some(TagProblem::Size));
        assert_eq!(parse("s:a:lbl:big").err(), Some(TagProblem::TooManyParts));
        assert_eq!(
            parse("s:a:lbl:10x10:x").err(),
            Some(TagProblem::TooManyParts)
        );
        assert_eq!(parse("s:a:10x10:lbl").err(), Some(TagProblem::TooManyParts));
    }
}
