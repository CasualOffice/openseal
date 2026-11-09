//! Converting existing AcroForm fields into OpenSeal fields (docs/30 §3: "convert to
//! OpenSeal fields (name, type, rect, options mapped)"; DocuSign's
//! `transformPdfFields`, docs/48 §5).
//!
//! Input is the admission report's inventory and the document it came from; output is
//! one [`Field`] per widget (one per group for radio buttons), placed in displayed page
//! space through [`crate::geometry`]. What cannot be mapped is listed with a reason;
//! what maps with a loss (a dropped label, options cut or merged, multi-select) is
//! listed too. Nothing is executed and the document is not changed.

use casual_sign_model::{
    DataLabel, Field, FieldOptions, FieldType, Id, LengthRule, Text, Validation, ValidationRule,
};
use casual_sign_pdf::{AdmissionReport, Document, FieldType as PdfFieldType, Object, PdfError};

use crate::font::local;
use crate::geometry::{DisplayRect, PageGeometry};

/// `/Ff` bits (ISO 32000-2 Tables 226, 229, 231).
const FF_READ_ONLY: i64 = 1;
const FF_REQUIRED: i64 = 1 << 1;
const FF_COMBO: i64 = 1 << 17;
const FF_EDIT: i64 = 1 << 18;
const FF_MULTI_SELECT: i64 = 1 << 21;
/// Most `/Parent` hops read for inherited attributes.
const MAX_PARENT_HOPS: usize = 32;

/// Why an existing field, or part of one, did not convert.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Unmapped {
    /// A push button: it holds no value.
    PushButton,
    /// No `/FT`, or one we do not know.
    UnknownType,
    /// The field has no widgets.
    NoWidget,
    /// The widget names no page of the document.
    NoPage,
    /// The widget's rectangle is empty or entirely off its page.
    NoArea,
    /// A radio group whose buttons are on several pages.
    RadioAcrossPages,
    /// The field name is not a valid data label; the field has no label.
    Label,
    /// Options over 500, repeated or over 4,000 bytes were dropped.
    Options,
    /// A multi-select list became a single-choice dropdown.
    MultiSelect,
    /// A choice field with no usable options became a text field.
    NoOptions,
}

/// One thing not converted, or converted with a loss.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Skipped {
    /// The PDF field's object number, when indirect.
    pub object: Option<u32>,
    /// The widget's object number, when it concerns one widget.
    pub widget: Option<u32>,
    /// What happened.
    pub reason: Unmapped,
}

/// A converted field and where it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Converted {
    /// The field.
    pub field: Field,
    /// The PDF field's object number, when indirect.
    pub object: Option<u32>,
}

/// The result of a conversion.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Conversion {
    /// Fields made, in the report's order.
    pub fields: Vec<Converted>,
    /// Fields or widgets not converted.
    pub skipped: Vec<Skipped>,
    /// Fields converted with a loss.
    pub lossy: Vec<Skipped>,
}

#[derive(Debug, Default)]
struct Attrs {
    flags: i64,
    max_len: Option<u32>,
    options: Option<Vec<Object>>,
}

/// Read `/Ff`, `/MaxLen` and `/Opt`, inherited through `/Parent`.
fn attrs(
    doc: &mut Document<'_>,
    object: Option<u32>,
    cancel: &dyn Fn() -> bool,
) -> Result<Attrs, PdfError> {
    let mut out = Attrs::default();
    let (mut flags, mut max_len, mut options) = (None, None, None);
    let mut cur = match object {
        Some(n) => local(doc.object(n, cancel))?,
        None => None,
    };
    let mut seen: Vec<u32> = object.into_iter().collect();
    for _ in 0..MAX_PARENT_HOPS {
        let Some(d) = cur.as_ref().and_then(Object::dict).cloned() else {
            break;
        };
        if flags.is_none() {
            flags = d.get(b"Ff").and_then(Object::as_i64);
        }
        if max_len.is_none() {
            max_len = d
                .get(b"MaxLen")
                .and_then(Object::as_i64)
                .and_then(|v| u32::try_from(v).ok())
                .filter(|v| *v > 0);
        }
        if options.is_none()
            && let Some(o) = d.get(b"Opt")
            && let Some(Object::Array(a)) = local(doc.resolve(o, cancel))?
        {
            options = Some(a);
        }
        let Some(parent) = d.get(b"Parent").and_then(Object::as_ref) else {
            break;
        };
        if seen.contains(&parent.num) {
            break;
        }
        seen.push(parent.num);
        cur = local(doc.object(parent.num, cancel))?;
    }
    out.flags = flags.unwrap_or(0);
    out.max_len = max_len;
    out.options = options;
    Ok(out)
}

/// A PDF text string (ISO 32000-2 §7.9.2.2), as `casual-sign-pdf` decodes field names:
/// UTF-16BE or UTF-8 with a byte-order mark, else PDFDocEncoding (Latin-1 for the
/// characters that matter in option lists).
fn text_string(b: &[u8]) -> String {
    if let Some(rest) = b.strip_prefix(&[0xFE, 0xFF]) {
        let units = rest.chunks(2).map(|c| match c {
            [h, l] => u16::from_be_bytes([*h, *l]),
            _ => 0xFFFD,
        });
        return char::decode_utf16(units)
            .map(|r| r.unwrap_or('\u{FFFD}'))
            .collect();
    }
    if let Some(rest) = b.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        return String::from_utf8_lossy(rest).into_owned();
    }
    b.iter().map(|&c| char::from(c)).collect()
}

/// The option texts: a string, or the display text of an `[export display]` pair.
fn option_texts(
    doc: &mut Document<'_>,
    opts: &[Object],
    cancel: &dyn Fn() -> bool,
) -> Result<Vec<String>, PdfError> {
    let mut out = Vec::new();
    for o in opts.iter().take(1_000) {
        let o = local(doc.resolve(o, cancel))?;
        let s = match &o {
            Some(Object::String(s)) => Some(s.clone()),
            Some(Object::Array(pair)) => match pair.get(1).or_else(|| pair.first()) {
                Some(Object::String(s)) => Some(s.clone()),
                _ => None,
            },
            _ => None,
        };
        if let Some(s) = s {
            out.push(text_string(&s));
        }
    }
    Ok(out)
}

/// Options for the model: repeats and over-long ones dropped, at most 500. True when
/// anything was dropped.
fn to_options(texts: Vec<String>) -> (FieldOptions, bool) {
    let total = texts.len();
    let mut kept: Vec<Text> = Vec::new();
    for t in texts {
        if kept.len() >= casual_sign_model::limits::MAX_OPTIONS {
            break;
        }
        if kept.iter().any(|k| k.as_str() == t) {
            continue;
        }
        if let Ok(t) = Text::new(t) {
            kept.push(t);
        }
    }
    let lost = kept.len() != total;
    (FieldOptions::new(kept).unwrap_or_default(), lost)
}

/// Radio export names: each widget's `/AP /N` keys other than `/Off`.
fn radio_states(
    doc: &mut Document<'_>,
    widget: Option<u32>,
    cancel: &dyn Fn() -> bool,
) -> Result<Vec<String>, PdfError> {
    let Some(w) = widget else {
        return Ok(Vec::new());
    };
    let Some(wd) = local(doc.object(w, cancel))? else {
        return Ok(Vec::new());
    };
    let Some(ap) = wd.get(b"AP").cloned() else {
        return Ok(Vec::new());
    };
    let Some(ap) = local(doc.resolve(&ap, cancel))? else {
        return Ok(Vec::new());
    };
    let Some(n) = ap.get(b"N").cloned() else {
        return Ok(Vec::new());
    };
    let Some(Object::Dictionary(n)) = local(doc.resolve(&n, cancel))? else {
        return Ok(Vec::new());
    };
    Ok(n.iter()
        .filter(|(k, _)| *k != b"Off")
        .map(|(k, _)| String::from_utf8_lossy(k).into_owned())
        .collect())
}

/// The widget's rectangle on its page, clipped to the page; `None` when nothing is left.
fn place(report: &AdmissionReport, page: u32, rect: &casual_sign_pdf::Rect) -> Option<DisplayRect> {
    let info = report.pages.get(usize::try_from(page).ok()?)?;
    let g = PageGeometry::from_page(info);
    let r = g.rect_to_displayed(rect);
    let (w, h) = g.displayed_size();
    let x0 = r.x.max(0.0);
    let y0 = r.y.max(0.0);
    let x1 = r.right().min(w);
    let y1 = r.bottom().min(h);
    (x1 > x0 && y1 > y0).then_some(DisplayRect {
        x: x0,
        y: y0,
        width: x1 - x0,
        height: y1 - y0,
    })
}

/// Convert the existing form fields of an admitted document.
///
/// `next_id` mints each field's id (the engine never makes ids, docs/22 §2); fields
/// are bound to no recipient, for the sender to assign.
///
/// # Errors
///
/// Only what ends the whole document: the decode budget, memory and cancellation.
pub fn convert_acroform(
    doc: &mut Document<'_>,
    report: &AdmissionReport,
    document_id: &Id,
    next_id: &mut dyn FnMut() -> Id,
    cancel: &dyn Fn() -> bool,
) -> Result<Conversion, PdfError> {
    let mut out = Conversion::default();
    for f in &report.fields {
        let skip = |reason, widget| Skipped {
            object: f.object,
            widget,
            reason,
        };
        let field_type = match f.field_type {
            PdfFieldType::Text => FieldType::Text,
            PdfFieldType::CheckBox => FieldType::Checkbox,
            PdfFieldType::Radio => FieldType::RadioGroup,
            PdfFieldType::Choice => FieldType::Dropdown,
            PdfFieldType::Signature => FieldType::Signature,
            PdfFieldType::PushButton => {
                out.skipped.push(skip(Unmapped::PushButton, None));
                continue;
            }
            _ => {
                out.skipped.push(skip(Unmapped::UnknownType, None));
                continue;
            }
        };
        if f.widgets.is_empty() {
            out.skipped.push(skip(Unmapped::NoWidget, None));
            continue;
        }
        let a = attrs(doc, f.object, cancel)?;
        let label = DataLabel::new(f.name.clone()).ok();
        if label.is_none() {
            out.lossy.push(skip(Unmapped::Label, None));
        }
        let mut field_type = field_type;
        let mut options = FieldOptions::default();
        let mut allow_custom = false;
        if field_type == FieldType::Dropdown {
            let texts = match &a.options {
                Some(o) => option_texts(doc, o, cancel)?,
                None => Vec::new(),
            };
            let (opts, lost) = to_options(texts);
            if lost {
                out.lossy.push(skip(Unmapped::Options, None));
            }
            if opts.is_empty() {
                field_type = FieldType::Text;
                out.lossy.push(skip(Unmapped::NoOptions, None));
            }
            options = opts;
            allow_custom = a.flags & FF_COMBO != 0 && a.flags & FF_EDIT != 0;
            if a.flags & FF_MULTI_SELECT != 0 {
                out.lossy.push(skip(Unmapped::MultiSelect, None));
            }
        }
        let validation = match (field_type, a.max_len) {
            (FieldType::Text, Some(max)) => {
                LengthRule::new(None, Some(max)).ok().map(|r| Validation {
                    rule: ValidationRule::Length(r),
                    message: None,
                })
            }
            _ => None,
        };
        let make = |placement: casual_sign_model::Placement,
                    options: FieldOptions,
                    next_id: &mut dyn FnMut() -> Id| {
            let mut field = Field::new(next_id(), document_id.clone(), field_type, placement);
            field.required = a.flags & FF_REQUIRED != 0;
            field.read_only = a.flags & FF_READ_ONLY != 0;
            field.label = label.clone();
            field.validation = validation.clone();
            field.options = options;
            field.allow_custom = allow_custom;
            Converted {
                field,
                object: f.object,
            }
        };

        if field_type == FieldType::RadioGroup {
            // One field for the group: the buttons' bounding box, their states as options.
            let pages: Vec<Option<u32>> = f.widgets.iter().map(|w| w.page).collect();
            let Some(Some(page)) = pages.first().copied() else {
                out.skipped.push(skip(Unmapped::NoPage, None));
                continue;
            };
            if pages.iter().any(|p| *p != Some(page)) {
                out.skipped.push(skip(Unmapped::RadioAcrossPages, None));
                continue;
            }
            let mut rect: Option<DisplayRect> = None;
            let mut states = Vec::new();
            for w in &f.widgets {
                if let Some(r) = place(report, page, &w.rect) {
                    rect = Some(rect.map_or(r, |o| o.union(&r)));
                }
                states.extend(radio_states(doc, w.object, cancel)?);
            }
            let Some(rect) = rect else {
                out.skipped.push(skip(Unmapped::NoArea, None));
                continue;
            };
            let Ok(placement) = rect.to_placement(page.saturating_add(1)) else {
                out.skipped.push(skip(Unmapped::NoArea, None));
                continue;
            };
            let (opts, lost) = to_options(states);
            if lost {
                out.lossy.push(skip(Unmapped::Options, None));
            }
            out.fields.push(make(placement, opts, next_id));
            continue;
        }

        for w in &f.widgets {
            let Some(page) = w.page else {
                out.skipped.push(skip(Unmapped::NoPage, w.object));
                continue;
            };
            let placement = place(report, page, &w.rect)
                .and_then(|r| r.to_placement(page.saturating_add(1)).ok());
            let Some(placement) = placement else {
                out.skipped.push(skip(Unmapped::NoArea, w.object));
                continue;
            };
            out.fields.push(make(placement, options.clone(), next_id));
        }
    }
    Ok(out)
}
