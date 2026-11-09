//! Anchor text (docs/30 §5, docs/48 §5): place a field relative to each occurrence of a
//! string in the document, DocuSign's auto-place.
//!
//! Matching runs on the page text as [`crate::text::PageText::text`] gives it: NFKC per
//! glyph, whitespace inferred from glyph positions and collapsed, so a string split
//! across show operators, lines of a content stream or kerning still matches. The
//! anchor string is normalized the same way. The field's top-left corner is the
//! match's top-left corner moved by the offsets.

use casual_sign_model::{Placement, Points};
use rust_decimal::Decimal;
use unicode_normalization::UnicodeNormalization;

use crate::error::PlaceError;
use crate::geometry::DisplayRect;
use crate::text::{Chars, PageText, char_stream};

/// Most matches one anchor string may have (docs/21, `CS-FLD-0010`).
pub const MAX_ANCHOR_MATCHES: usize = 500;
/// Longest anchor string, in characters after normalization. A decision of `T-1C`:
/// DocuSign documents none; a sentence is enough to anchor on.
pub const MAX_ANCHOR_CHARS: usize = 256;

/// The unit of an anchor's offsets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum AnchorUnits {
    /// Points (1/72 inch).
    #[default]
    Points,
    /// Inches.
    Inches,
    /// Millimetres.
    Millimetres,
    /// Centimetres.
    Centimetres,
    /// CSS pixels at 96 per inch (DocuSign's `pixels`).
    Pixels,
}

impl AnchorUnits {
    /// Points per unit.
    #[must_use]
    pub fn points(self) -> f64 {
        match self {
            Self::Points => 1.0,
            Self::Inches => 72.0,
            Self::Millimetres => 72.0 / 25.4,
            Self::Centimetres => 72.0 / 2.54,
            Self::Pixels => 0.75,
        }
    }
}

/// Which occurrences place a field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum AnchorMatch {
    /// The first occurrence in page order, then content order.
    First,
    /// Every occurrence (at most [`MAX_ANCHOR_MATCHES`]).
    #[default]
    All,
}

/// An anchor: where to look and how to place the field (docs/22 §6 `anchor`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnchorSpec {
    /// The string to find.
    pub text: String,
    /// Horizontal offset from the match's left edge, positive to the right.
    pub offset_x: Decimal,
    /// Vertical offset from the match's top edge, positive downwards.
    pub offset_y: Decimal,
    /// Unit of the offsets.
    pub units: AnchorUnits,
    /// No match is not an error.
    pub ignore_if_absent: bool,
    /// Letter case must match.
    pub case_sensitive: bool,
    /// The match must not be part of a longer word.
    pub whole_word: bool,
    /// First or every occurrence.
    pub matching: AnchorMatch,
    /// The placed field's width.
    pub width: Points,
    /// The placed field's height.
    pub height: Points,
}

/// One placed field.
#[derive(Debug, Clone, PartialEq)]
pub struct AnchorPlacement {
    /// Where the field goes.
    pub placement: Placement,
    /// The matched text's rectangle, displayed page space.
    pub text_rect: DisplayRect,
}

/// Normalize like the page text: NFKC, whitespace collapsed and trimmed, optionally
/// lower-cased.
pub(crate) fn normalize(s: &str, fold_case: bool) -> Vec<char> {
    let mut out: Vec<char> = Vec::new();
    for c in s.nfkc() {
        if c.is_whitespace() {
            if out.last().is_some_and(|l| *l != ' ') {
                out.push(' ');
            }
        } else if fold_case {
            out.extend(c.to_lowercase());
        } else {
            out.push(c);
        }
    }
    if out.last() == Some(&' ') {
        out.pop();
    }
    out
}

/// Knuth–Morris–Pratt failure table.
fn kmp_table(p: &[char]) -> Vec<usize> {
    let mut t = vec![0usize; p.len()];
    let mut k = 0usize;
    for i in 1..p.len() {
        while k > 0 && p.get(i) != p.get(k) {
            k = t.get(k.saturating_sub(1)).copied().unwrap_or(0);
        }
        if p.get(i) == p.get(k) {
            k = k.saturating_add(1);
        }
        if let Some(slot) = t.get_mut(i) {
            *slot = k;
        }
    }
    t
}

/// Start indexes of non-overlapping occurrences of `p` in `s`, stopping after `cap`.
fn find_all(s: &[char], p: &[char], cap: usize, whole_word: bool) -> Vec<usize> {
    let t = kmp_table(p);
    let mut out = Vec::new();
    let mut k = 0usize;
    let mut i = 0usize;
    while let Some(c) = s.get(i) {
        while k > 0 && Some(c) != p.get(k) {
            k = t.get(k.saturating_sub(1)).copied().unwrap_or(0);
        }
        if Some(c) == p.get(k) {
            k = k.saturating_add(1);
        }
        if k == p.len() {
            let start = i.saturating_add(1).saturating_sub(p.len());
            let before = start.checked_sub(1).and_then(|b| s.get(b));
            let after = s.get(i.saturating_add(1));
            let word = |c: Option<&char>| c.is_some_and(|c| c.is_alphanumeric());
            if !whole_word || (!word(before) && !word(after)) {
                out.push(start);
                if out.len() >= cap {
                    return out;
                }
                k = 0;
            } else {
                k = t.get(k.saturating_sub(1)).copied().unwrap_or(0);
            }
        }
        i = i.saturating_add(1);
    }
    out
}

/// Place the fields of anchor `index` (its position in the request, for errors).
///
/// # Errors
///
/// - [`PlaceError::AnchorText`] (`CS-FLD-0002`): the string is empty or too long.
/// - [`PlaceError::AnchorNotFound`] (`CS-FLD-0010`): no match and not ignorable.
/// - [`PlaceError::TooManyMatches`] (`CS-FLD-0010`): more than
///   [`MAX_ANCHOR_MATCHES`] matches.
/// - [`PlaceError::OutsidePage`] (`CS-FLD-0004`): an offset puts a field off its page.
pub fn place_anchor(
    pages: &[PageText],
    spec: &AnchorSpec,
    index: usize,
) -> Result<Vec<AnchorPlacement>, PlaceError> {
    let fold = !spec.case_sensitive;
    let needle = normalize(&spec.text, fold);
    if needle.is_empty() || needle.len() > MAX_ANCHOR_CHARS {
        return Err(PlaceError::AnchorText { anchor: index });
    }
    let unit = spec.units.points();
    let dx = f64::try_from(spec.offset_x).unwrap_or(0.0) * unit;
    let dy = f64::try_from(spec.offset_y).unwrap_or(0.0) * unit;
    let width = f64::try_from(spec.width.get()).unwrap_or(0.0);
    let height = f64::try_from(spec.height.get()).unwrap_or(0.0);
    let cap = match spec.matching {
        AnchorMatch::First => 1,
        // One more than allowed, to know the cap was crossed.
        AnchorMatch::All => MAX_ANCHOR_MATCHES.saturating_add(1),
    };
    let mut out = Vec::new();
    for page in pages {
        let chars: Chars = char_stream(page, fold);
        let left = cap.saturating_sub(out.len());
        for start in find_all(&chars.chars, &needle, left, spec.whole_word) {
            let Some(text_rect) = chars.rect(page, start, start.saturating_add(needle.len()))
            else {
                continue;
            };
            let field = DisplayRect {
                x: text_rect.x + dx,
                y: text_rect.y + dy,
                width,
                height,
            };
            if !page.geometry.contains(&field, 0.01) {
                return Err(PlaceError::OutsidePage { page: page.page });
            }
            let placement = field
                .to_placement(page.page)
                .map_err(|_| PlaceError::OutsidePage { page: page.page })?;
            out.push(AnchorPlacement {
                placement,
                text_rect,
            });
        }
        if out.len() >= cap {
            break;
        }
    }
    if out.len() > MAX_ANCHOR_MATCHES {
        return Err(PlaceError::TooManyMatches {
            anchor: index,
            limit: MAX_ANCHOR_MATCHES,
        });
    }
    if out.is_empty() && !spec.ignore_if_absent {
        return Err(PlaceError::AnchorNotFound { anchor: index });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chars(s: &str) -> Vec<char> {
        s.chars().collect()
    }

    #[test]
    fn finds_non_overlapping_and_whole_words() {
        let s = chars("aaaa sign signer sign");
        assert_eq!(find_all(&s, &chars("aa"), 10, false), vec![0, 2]);
        assert_eq!(find_all(&s, &chars("sign"), 10, false), vec![5, 10, 17]);
        assert_eq!(find_all(&s, &chars("sign"), 10, true), vec![5, 17]);
        assert_eq!(find_all(&s, &chars("sign"), 2, false), vec![5, 10]);
    }

    #[test]
    fn normalization_collapses_whitespace_and_compatibility_forms() {
        assert_eq!(
            normalize("  ﬁ\tＳign \n here ", false),
            chars("fi Sign here")
        );
        assert_eq!(normalize("Sign", true), chars("sign"));
    }

    #[test]
    fn units_convert_to_points() {
        assert!((AnchorUnits::Millimetres.points() * 25.4 - 72.0).abs() < 1e-9);
        assert!((AnchorUnits::Pixels.points() * 96.0 - 72.0).abs() < 1e-9);
    }
}
