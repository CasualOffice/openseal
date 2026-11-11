//! Field auto-detection (docs/30 §5, `WEB-06`): suggest where a sender's fields go from
//! what a page already shows, as SignNow's and DocuSign's "detect fields" do.
//!
//! Cues, from the text with positions ([`PageText`]) and painted shapes
//! ([`crate::text::Shape`]):
//!
//! - **Underscore runs** (`____`, four or more) are lines to write on.
//! - **Painted rules and boxes** (horizontal lines, thin bars, rectangles 2.5–100 pt
//!   tall, at least half an inch wide) are lines or boxes, but only when a label names
//!   them: a page draws many rules (table borders, separators) that are not fields.
//! - **Labels** ("Signature", "Sign here", "Signed", "Initials", "Date", "Name",
//!   "Print name", "Title", "Company", any case, colon or not) set the kind of the line
//!   they sit beside: left of it on the same line first, then just under it, then just
//!   above. A label ending in a colon with blank space to its right and no line is a
//!   field in that space.
//! - **Existing form fields** ([`Converted`], from [`crate::convert_acroform`]) are
//!   suggested as they are, and a text cue overlapping one is dropped.
//!
//! Everything is pure and bounded: at most [`MAX_DETECTED_FIELDS`] suggestions,
//! [`MAX_DETECT_WORDS`] words and [`MAX_DETECT_SLOTS`] lines per page, and
//! [`MAX_DETECT_STEPS`] comparisons for the whole document; crossing a bound stops
//! detection with [`Detection::truncated`] set, never an error. Suggestions only:
//! nothing here changes an envelope.

use casual_sign_model::{FieldType, Placement};

use crate::acroform::Converted;
use crate::geometry::DisplayRect;
use crate::text::{PageText, ShapeKind, char_stream};

/// Most suggestions returned for one document (docs/21).
pub const MAX_DETECTED_FIELDS: usize = 500;
/// Most words read per page; later words are not considered (docs/21).
pub const MAX_DETECT_WORDS: usize = 20_000;
/// Most lines and boxes considered per page (docs/21).
pub const MAX_DETECT_SLOTS: usize = 2_000;
/// Most word-to-line comparisons for one document (docs/21).
pub const MAX_DETECT_STEPS: u64 = 50_000_000;
/// Longest label cue returned, in characters.
pub const MAX_CUE_CHARS: usize = 64;

/// Fewest underscores read as a line.
const MIN_UNDERSCORES: usize = 4;
/// How far left of a line a same-line label may sit, in points.
const LABEL_REACH: f64 = 300.0;
/// How far under or over a line a label may sit, in points.
const LABEL_GAP: f64 = 20.0;
/// The widest gap between words of one label phrase, in points.
const WORD_GAP: f64 = 18.0;
/// Blank space after a colon label needed for a field there, in points.
const MIN_BLANK: f64 = 72.0;

/// What a suggestion was found from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DetectedSource {
    /// A run of underscores or a painted rule.
    Underline,
    /// A label with blank space after it.
    Label,
    /// A painted rectangle.
    Box,
    /// A form field already in the PDF.
    AcroForm,
}

impl DetectedSource {
    /// The wire name: `underline`, `label`, `box`, `acroform`.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Underline => "underline",
            Self::Label => "label",
            Self::Box => "box",
            Self::AcroForm => "acroform",
        }
    }
}

/// One suggested field.
#[derive(Debug, Clone, PartialEq)]
pub struct DetectedField {
    /// Signature, initials, date signed, name, title, company or text; any type for an
    /// existing form field.
    pub field_type: FieldType,
    /// Page and rectangle, displayed page space (ADR-019).
    pub placement: Placement,
    /// What it was found from.
    pub source: DetectedSource,
    /// The label text that set its kind (at most [`MAX_CUE_CHARS`]), or the form
    /// field's data label.
    pub label: Option<String>,
    /// 0–100: 100 for a form field, 90 a line with a label beside it, 80 under or over
    /// it, 70 a labelled painted rule or box, 60 a colon label, 40 an unlabelled line.
    pub confidence: u8,
}

/// The suggestions for a document.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Detection {
    /// In page order, then top to bottom, then left to right.
    pub fields: Vec<DetectedField>,
    /// A bound stopped detection early, or a page's text was cut short.
    pub truncated: bool,
}

#[derive(Debug, Clone)]
struct Word {
    text: String,
    rect: DisplayRect,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum SlotKind {
    Underscores,
    Rule,
    Box,
}

#[derive(Debug, Clone)]
struct Slot {
    kind: SlotKind,
    rect: DisplayRect,
}

/// The field kind a label phrase names, in priority order: "Date signed" is a date,
/// "Company name" a company.
fn classify(phrase: &[&str]) -> Option<FieldType> {
    let has = |keys: &[&str]| phrase.iter().any(|w| keys.contains(w));
    if has(&["date", "dated"]) {
        Some(FieldType::DateSigned)
    } else if has(&["initials", "initial"]) {
        Some(FieldType::Initials)
    } else if has(&["signature", "signed", "sign", "signer"]) {
        Some(FieldType::Signature)
    } else if has(&["company", "organization", "organisation"]) {
        Some(FieldType::Company)
    } else if has(&["title"]) {
        Some(FieldType::Title)
    } else if has(&["name"]) {
        Some(FieldType::Name)
    } else {
        None
    }
}

/// A word as compared: lower case, trailing punctuation dropped.
fn key(word: &str) -> String {
    word.trim_matches(|c: char| !c.is_alphanumeric())
        .to_lowercase()
}

fn cue(words: &[&Word]) -> String {
    let joined: Vec<&str> = words.iter().map(|w| w.text.as_str()).collect();
    joined.join(" ").chars().take(MAX_CUE_CHARS).collect()
}

/// Words and underscore runs of a page, in content order.
fn words_and_lines(page: &PageText, truncated: &mut bool) -> (Vec<Word>, Vec<Slot>) {
    let chars = char_stream(page, false);
    let mut words = Vec::new();
    let mut slots = Vec::new();
    let mut i = 0usize;
    let n = chars.chars.len();
    while i < n {
        let c = chars.chars.get(i).copied().unwrap_or(' ');
        if c == ' ' {
            i = i.saturating_add(1);
            continue;
        }
        let start = i;
        let under = c == '_';
        while let Some(&d) = chars.chars.get(i) {
            if d == ' ' || (d == '_') != under {
                break;
            }
            i = i.saturating_add(1);
        }
        let len = i.saturating_sub(start);
        let Some(rect) = chars.rect(page, start, i) else {
            continue;
        };
        if under {
            if len >= MIN_UNDERSCORES {
                if slots.len() >= MAX_DETECT_SLOTS {
                    *truncated = true;
                } else {
                    slots.push(Slot {
                        kind: SlotKind::Underscores,
                        rect,
                    });
                }
            }
        } else if words.len() >= MAX_DETECT_WORDS {
            *truncated = true;
        } else {
            let text: String = chars
                .chars
                .get(start..i)
                .unwrap_or_default()
                .iter()
                .collect();
            words.push(Word { text, rect });
        }
    }
    (words, merge(slots))
}

/// Joins underscore runs on one line separated by an inferred space (`___ ___`).
fn merge(slots: Vec<Slot>) -> Vec<Slot> {
    let mut out: Vec<Slot> = Vec::with_capacity(slots.len());
    for s in slots {
        if let Some(last) = out.last_mut()
            && same_line(&last.rect, &s.rect)
            && s.rect.x >= last.rect.x
            && s.rect.x - last.rect.right() <= 6.0
        {
            last.rect = last.rect.union(&s.rect);
            continue;
        }
        out.push(s);
    }
    out
}

fn mid_y(r: &DisplayRect) -> f64 {
    r.y + r.height / 2.0
}

/// Whether `b`'s middle lies within `a`'s height (widened a little), or the reverse.
fn same_line(a: &DisplayRect, b: &DisplayRect) -> bool {
    let within = |r: &DisplayRect, y: f64| y >= r.y - 2.0 && y <= r.bottom() + 2.0;
    within(a, mid_y(b)) || within(b, mid_y(a))
}

fn overlaps_x(a: &DisplayRect, b: &DisplayRect) -> bool {
    a.x < b.right() && b.x < a.right()
}

fn intersects(a: &DisplayRect, b: &DisplayRect) -> bool {
    overlaps_x(a, b) && a.y < b.bottom() && b.y < a.bottom()
}

struct Budget {
    steps: u64,
    out: bool,
}

impl Budget {
    /// Spend `n` steps; false once the document's budget is gone.
    fn spend(&mut self, n: usize) -> bool {
        self.steps = self
            .steps
            .saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        if self.steps > MAX_DETECT_STEPS {
            self.out = true;
        }
        !self.out
    }
}

/// A label found for a line: its kind, cue, how it sat (0 beside, 1 under or over),
/// and the indexes of its words.
type Label = (FieldType, String, u8, Vec<usize>);

/// The label of `slot`: same line to its left, else just under, else just over.
///
/// Beside, the phrase is the nearest words going left, at most four, stopping at a gap
/// wider than [`WORD_GAP`] (a column break: "Signature of Treasurer    Date ____" is
/// a date).
fn label_of(slot: &DisplayRect, words: &[Word]) -> Option<Label> {
    let mut beside: Vec<usize> = (0..words.len())
        .filter(|&i| {
            words.get(i).is_some_and(|w| {
                same_line(&w.rect, slot)
                    && w.rect.right() <= slot.x + 1.0
                    && slot.x - w.rect.right() <= LABEL_REACH
            })
        })
        .collect();
    let x_of = |i: &usize| words.get(*i).map_or(0.0, |w| w.rect.x);
    beside.sort_by(|a, b| x_of(b).total_cmp(&x_of(a)));
    let mut phrase: Vec<usize> = Vec::new();
    let mut left = slot.x;
    for i in beside {
        let Some(w) = words.get(i) else { break };
        if phrase.len() >= 4 || (!phrase.is_empty() && left - w.rect.right() > WORD_GAP) {
            break;
        }
        left = w.rect.x;
        phrase.push(i);
    }
    phrase.reverse();
    if let Some(l) = labelled(&phrase, words, 0) {
        return Some(l);
    }
    // Under, then over: the words whose middle is within the line's width.
    for under in [true, false] {
        let near: Vec<usize> = (0..words.len())
            .filter(|&i| {
                words.get(i).is_some_and(|w| {
                    let gap = if under {
                        w.rect.y - slot.bottom()
                    } else {
                        slot.y - w.rect.bottom()
                    };
                    let centre = w.rect.x + w.rect.width / 2.0;
                    (-2.0..=LABEL_GAP).contains(&gap) && (slot.x..=slot.right()).contains(&centre)
                })
            })
            .collect();
        if let Some(l) = labelled(&near, words, 1) {
            return Some(l);
        }
    }
    None
}

fn labelled(phrase: &[usize], words: &[Word], how: u8) -> Option<Label> {
    let ws: Vec<&Word> = phrase.iter().filter_map(|&i| words.get(i)).collect();
    let keys: Vec<String> = ws.iter().map(|w| key(&w.text)).collect();
    let refs: Vec<&str> = keys.iter().map(String::as_str).collect();
    classify(&refs).map(|t| (t, cue(&ws), how, phrase.to_vec()))
}

/// The suggested rectangle for a field of `ty` on a line or in a box `slot`.
fn rect_for(ty: FieldType, slot: &DisplayRect, boxed: bool) -> DisplayRect {
    let (w, h) = match ty {
        FieldType::Signature => (slot.width, 30.0),
        FieldType::Initials => (slot.width.min(60.0), 30.0),
        FieldType::DateSigned => (slot.width.min(100.0), 18.0),
        _ => (slot.width, 18.0),
    };
    if boxed {
        // Inside the box, as tall as it allows.
        DisplayRect {
            x: slot.x,
            y: slot.y,
            width: w,
            height: slot.height,
        }
    } else {
        // Sitting on the line.
        DisplayRect {
            x: slot.x,
            y: slot.bottom() - h,
            width: w,
            height: h,
        }
    }
}

/// `r` moved and cut to lie on a page of `size`, or `None` when nothing is left.
fn clamp(r: DisplayRect, size: (f64, f64)) -> Option<DisplayRect> {
    let x = r.x.max(0.0);
    let y = r.y.max(0.0);
    let right = r.right().min(size.0);
    let bottom = r.bottom().min(size.1);
    let (width, height) = (right - x, bottom - y);
    (width >= 1.0 && height >= 1.0 && width.is_finite() && height.is_finite()).then_some(
        DisplayRect {
            x,
            y,
            width,
            height,
        },
    )
}

/// Suggest fields for a document from its pages' text and shapes and its converted
/// form fields (`acroform`, empty when it has none).
///
/// Never fails: a bound crossed ends detection with [`Detection::truncated`] set.
#[must_use]
pub fn detect_fields(pages: &[PageText], acroform: &[Converted]) -> Detection {
    let mut out = Detection::default();
    let mut budget = Budget {
        steps: 0,
        out: false,
    };
    let mut found: Vec<(u32, DisplayRect, DetectedField)> = Vec::new();
    for c in acroform {
        let f = &c.field;
        let rect = DisplayRect::from_placement(&f.placement);
        found.push((
            f.placement.page(),
            rect,
            DetectedField {
                field_type: f.field_type,
                placement: f.placement,
                source: DetectedSource::AcroForm,
                label: f
                    .label
                    .as_ref()
                    .map(|l| l.as_str().chars().take(MAX_CUE_CHARS).collect()),
                confidence: 100,
            },
        ));
    }
    let forms: Vec<(u32, DisplayRect)> = found.iter().map(|(p, r, _)| (*p, *r)).collect();
    for page in pages {
        if budget.out {
            break;
        }
        if page.truncated() {
            out.truncated = true;
        }
        let size = page.geometry.displayed_size();
        let (words, mut slots) = words_and_lines(page, &mut out.truncated);
        let lines_from_text = slots.len();
        for s in &page.shapes {
            if slots.len() >= MAX_DETECT_SLOTS {
                out.truncated = true;
                break;
            }
            let kind = match s.kind {
                ShapeKind::Rule => SlotKind::Rule,
                ShapeKind::Box => SlotKind::Box,
            };
            slots.push(Slot { kind, rect: s.rect });
        }
        let mut taken: Vec<DisplayRect> = Vec::new();
        // Words already the label of a line are not colon labels of their own.
        let mut used: Vec<bool> = vec![false; words.len()];
        for slot in &slots {
            if !budget.spend(words.len().saturating_add(taken.len())) {
                break;
            }
            // A painted rule under underscores, or under text (underlined words), is
            // not a line of its own.
            if slot.kind == SlotKind::Rule
                && (slots
                    .get(..lines_from_text)
                    .unwrap_or_default()
                    .iter()
                    .any(|u| {
                        overlaps_x(&u.rect, &slot.rect)
                            && (u.rect.bottom() - slot.rect.y).abs() <= 4.0
                    })
                    || words.iter().any(|w| {
                        overlaps_x(&w.rect, &slot.rect)
                            && (-1.0..=4.0).contains(&(slot.rect.y - w.rect.bottom()))
                    }))
            {
                continue;
            }
            // A box with text inside is not empty.
            if slot.kind == SlotKind::Box && words.iter().any(|w| intersects(&w.rect, &slot.rect)) {
                continue;
            }
            let label = label_of(&slot.rect, &words);
            if let Some((_, _, _, idx)) = &label {
                for &i in idx {
                    if let Some(u) = used.get_mut(i) {
                        *u = true;
                    }
                }
            }
            let label = label.map(|(t, c, how, _)| (t, c, how));
            let (ty, cue, confidence, source) = match (slot.kind, label) {
                (SlotKind::Underscores, Some((t, c, 0))) => {
                    (t, Some(c), 90, DetectedSource::Underline)
                }
                (SlotKind::Underscores, Some((t, c, _))) => {
                    (t, Some(c), 80, DetectedSource::Underline)
                }
                (SlotKind::Underscores, None) => {
                    (FieldType::Text, None, 40, DetectedSource::Underline)
                }
                (SlotKind::Rule, Some((t, c, _))) => (t, Some(c), 70, DetectedSource::Underline),
                (SlotKind::Box, Some((t, c, _))) => (t, Some(c), 70, DetectedSource::Box),
                (_, None) => continue,
            };
            let Some(rect) = clamp(rect_for(ty, &slot.rect, slot.kind == SlotKind::Box), size)
            else {
                continue;
            };
            if taken.iter().any(|t| intersects(t, &rect)) {
                continue;
            }
            taken.push(rect);
            push(&mut found, page.page, rect, ty, source, cue, confidence);
        }
        // Colon labels with blank space after them and no line.
        for (wi, w) in words.iter().enumerate() {
            if used.get(wi).copied().unwrap_or(false) {
                continue;
            }
            if !budget.spend(words.len().saturating_add(taken.len())) {
                break;
            }
            if !w.text.ends_with(':') {
                continue;
            }
            let k = key(&w.text);
            let Some(ty) = classify(&[k.as_str()]) else {
                continue;
            };
            let next = words
                .iter()
                .filter(|o| same_line(&o.rect, &w.rect) && o.rect.x >= w.rect.right())
                .map(|o| o.rect.x)
                .fold(size.0, f64::min);
            let blank = next - w.rect.right();
            if blank < MIN_BLANK {
                continue;
            }
            let width = (blank - 8.0).min(match ty {
                FieldType::Initials => 60.0,
                FieldType::DateSigned => 100.0,
                _ => 200.0,
            });
            let h = if ty == FieldType::Signature || ty == FieldType::Initials {
                30.0
            } else {
                18.0
            };
            let r = DisplayRect {
                x: w.rect.right() + 4.0,
                y: w.rect.bottom() - h,
                width,
                height: h,
            };
            let Some(rect) = clamp(r, size) else {
                continue;
            };
            if taken.iter().any(|t| intersects(t, &rect)) {
                continue;
            }
            taken.push(rect);
            push(
                &mut found,
                page.page,
                rect,
                ty,
                DetectedSource::Label,
                Some(cue(&[w])),
                60,
            );
        }
    }
    if budget.out {
        out.truncated = true;
    }
    // A text cue on an existing form field is that field.
    found.retain(|(p, r, f)| {
        f.source == DetectedSource::AcroForm
            || !forms.iter().any(|(fp, fr)| fp == p && intersects(fr, r))
    });
    found.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then(a.1.y.total_cmp(&b.1.y))
            .then(a.1.x.total_cmp(&b.1.x))
    });
    if found.len() > MAX_DETECTED_FIELDS {
        found.truncate(MAX_DETECTED_FIELDS);
        out.truncated = true;
    }
    out.fields = found.into_iter().map(|(_, _, f)| f).collect();
    out
}

fn push(
    found: &mut Vec<(u32, DisplayRect, DetectedField)>,
    page: u32,
    rect: DisplayRect,
    field_type: FieldType,
    source: DetectedSource,
    label: Option<String>,
    confidence: u8,
) {
    let Ok(placement) = rect.to_placement(page) else {
        return;
    };
    // Bounded before sorting: the cap plus one is enough to know it was crossed.
    if found.len() > MAX_DETECTED_FIELDS.saturating_mul(4) {
        return;
    }
    found.push((
        page,
        rect,
        DetectedField {
            field_type,
            placement,
            source,
            label,
            confidence,
        },
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_classify_in_priority_order() {
        assert_eq!(classify(&["date", "signed"]), Some(FieldType::DateSigned));
        assert_eq!(classify(&["company", "name"]), Some(FieldType::Company));
        assert_eq!(classify(&["print", "name"]), Some(FieldType::Name));
        assert_eq!(classify(&["sign", "here"]), Some(FieldType::Signature));
        assert_eq!(classify(&["initials"]), Some(FieldType::Initials));
        assert_eq!(classify(&["title"]), Some(FieldType::Title));
        assert_eq!(classify(&["address"]), None);
        assert_eq!(key("Signature:"), "signature");
    }

    #[test]
    fn clamp_keeps_a_rectangle_on_its_page() {
        let r = DisplayRect {
            x: -10.0,
            y: -5.0,
            width: 700.0,
            height: 30.0,
        };
        let c = clamp(r, (612.0, 792.0)).unwrap_or_default();
        assert!(c.x == 0.0 && c.y == 0.0 && c.width == 612.0 && c.height == 25.0);
        let off = DisplayRect {
            x: 700.0,
            y: 0.0,
            width: 10.0,
            height: 10.0,
        };
        assert!(clamp(off, (612.0, 792.0)).is_none());
    }
}
