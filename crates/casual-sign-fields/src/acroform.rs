//! Converting existing AcroForm fields into OpenSeal fields (docs/30 §3: "convert to
//! OpenSeal fields (name, type, rect, options mapped)"; DocuSign's
//! `transformPdfFields`, docs/48 §5).
//!
//! Input is the admission report's inventory and the document it came from; output is
//! one [`Field`] per widget (one per page for a radio group), placed in displayed page
//! space through [`crate::geometry`]. What cannot be mapped is listed with a reason;
//! what maps with a loss (a dropped label, options cut or merged, multi-select) is
//! listed too. Nothing is executed and the document is not changed.

use std::collections::BTreeMap;

use casual_sign_model::{
    DataLabel, Field, FieldOptions, FieldType, Id, LengthRule, Text, Validation, ValidationRule,
};
use casual_sign_pdf::{
    AdmissionReport, Document, FieldType as PdfFieldType, Object, PdfError, decode_text_string,
};

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
    /// A radio group whose buttons are on several pages, with no label to link a field
    /// on each page by: it became one field on its first page (its other buttons still
    /// turn on when chosen).
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
            out.push(decode_text_string(&s));
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

/// The text of a PDF name (ISO 32000-2 §7.3.5): its bytes as UTF-8 when they are,
/// else as PDFDocEncoding, the encoding Acrobat writes non-ASCII state names in
/// (`/First#20bachelor#90s#20degree` is "First bachelor’s degree").
#[must_use]
pub fn name_text(name: &[u8]) -> String {
    match std::str::from_utf8(name) {
        Ok(s) => s.to_owned(),
        Err(_) => decode_text_string(name),
    }
}

/// One widget of a radio group, as a choice turns it on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RadioWidget {
    /// The widget annotation's object number.
    pub widget: u32,
    /// The on-state name written to `/V` and `/AS`, as its bytes.
    pub state: Vec<u8>,
    /// Whether `/AP /N` has an appearance for the state. When it has not (a button
    /// with no on appearance, or a state minted here), whoever turns the widget on
    /// draws one.
    pub has_appearance: bool,
}

/// One choice of a radio group: the option text a signer picks and the widgets it
/// turns on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RadioChoice {
    /// The option's text: the first widget's `/Opt` entry when the field has one, else
    /// its on-state name as text ([`name_text`]). Unique within the group.
    pub text: String,
    /// The widgets turned on, all with the same state.
    pub widgets: Vec<RadioWidget>,
}

/// Most widgets read for one radio group.
const MAX_RADIO_WIDGETS: usize = 1_000;

/// A widget's on-state: the first `/AP /N` key other than `/Off` (flag true), else the
/// first such `/AP /D` key, else a `/AS` other than `/Off` (flag false).
fn widget_state(
    doc: &mut Document<'_>,
    widget: u32,
    cancel: &dyn Fn() -> bool,
) -> Result<Option<(Vec<u8>, bool)>, PdfError> {
    let Some(wd) = local(doc.object(widget, cancel))? else {
        return Ok(None);
    };
    let ap = match wd.get(b"AP").cloned() {
        Some(ap) => local(doc.resolve(&ap, cancel))?,
        None => None,
    };
    for (key, normal) in [(&b"N"[..], true), (b"D", false)] {
        let Some(states) = ap.as_ref().and_then(|a| a.get(key)).cloned() else {
            continue;
        };
        let Some(Object::Dictionary(states)) = local(doc.resolve(&states, cancel))? else {
            continue;
        };
        if let Some((k, _)) = states.iter().find(|(k, _)| *k != b"Off") {
            return Ok(Some((k.to_vec(), normal)));
        }
    }
    Ok(wd
        .dict()
        .and_then(|d| d.name(b"AS"))
        .filter(|s| *s != b"Off")
        .map(|s| (s.to_vec(), false)))
}

/// The choices of a radio group (ISO 32000-2 §12.7.5.2.4), in widget order.
///
/// A widget's on-state is the name of its `/AP /N` appearance other than `/Off` (then
/// `/AP /D`, then `/AS`). A widget with none at all (no `/AP`, or an `/N` holding only
/// `/Off`) can never be turned on as written; it gets a minted state, its position
/// among the widgets as a decimal number (as `/Opt` groups name theirs), made unique,
/// and whoever turns it on draws its appearance. Widgets with the same state are one
/// choice: `/V` names a state, so they turn on together. A choice's text is the first
/// widget's `/Opt` entry, else the state as text, else "Option n"; a text already taken
/// gets " (2)", " (3)" … so each choice is distinct.
///
/// [`convert_acroform`] makes a radio group's options from these texts, and flattening
/// and filling in place map the chosen text back through this same function, so the
/// state written is the document's own bytes, whatever their encoding.
///
/// # Errors
///
/// Only what ends the whole document: the decode budget, memory and cancellation.
pub fn radio_choices(
    doc: &mut Document<'_>,
    field: &casual_sign_pdf::FormField,
    cancel: &dyn Fn() -> bool,
) -> Result<Vec<RadioChoice>, PdfError> {
    let opt = attrs(doc, field.object, cancel)?
        .options
        .unwrap_or_default();
    // (position, widget, state if any, `/Opt` text)
    let mut read = Vec::new();
    for (i, w) in field.widgets.iter().enumerate().take(MAX_RADIO_WIDGETS) {
        let Some(obj) = w.object else { continue };
        let state = widget_state(doc, obj, cancel)?;
        let opt_text = match opt.get(i) {
            Some(o) => match local(doc.resolve(o, cancel))? {
                Some(Object::String(s)) => Some(decode_text_string(&s)),
                _ => None,
            },
            None => None,
        };
        read.push((i, obj, state, opt_text));
    }
    let mut taken: Vec<Vec<u8>> = read
        .iter()
        .filter_map(|(_, _, s, _)| s.as_ref().map(|(n, _)| n.clone()))
        .collect();
    let mut choices: Vec<RadioChoice> = Vec::new();
    for (i, obj, state, opt_text) in read {
        let (state, has_appearance) = match state {
            Some(s) => s,
            None => {
                let mut k = i;
                let mut name = k.to_string().into_bytes();
                while taken.contains(&name) {
                    k = k.saturating_add(1);
                    name = k.to_string().into_bytes();
                }
                taken.push(name.clone());
                (name, false)
            }
        };
        let rw = RadioWidget {
            widget: obj,
            state: state.clone(),
            has_appearance,
        };
        if let Some(c) = choices
            .iter_mut()
            .find(|c| c.widgets.first().is_some_and(|w| w.state == state))
        {
            c.widgets.push(rw);
            continue;
        }
        let base = opt_text
            .filter(|t| !t.trim().is_empty())
            .or_else(|| Some(name_text(&state)).filter(|t| !t.trim().is_empty()))
            .unwrap_or_else(|| format!("Option {}", i.saturating_add(1)));
        let mut text = base.clone();
        let mut n: usize = 1;
        while choices.iter().any(|c| c.text == text) {
            n = n.saturating_add(1);
            text = format!("{base} ({n})");
        }
        choices.push(RadioChoice {
            text,
            widgets: vec![rw],
        });
    }
    Ok(choices)
}

/// Most `/Annots` entries read per page to find a widget's page (docs/21); further
/// entries are not indexed, and a widget only they list is reported `NoPage`.
pub const MAX_ANNOTS_INDEXED: usize = 10_000;

/// Which page lists each annotation in its `/Annots`, by annotation object number:
/// zero-based page index, the first page when several list one (`PDF-WID-01`).
///
/// A widget's `/P` is optional (ISO 32000-2 Table 166) and forms written before PDF 1.3
/// (irs-f1040-1997) never carry it; viewers place such a widget on the page whose
/// `/Annots` holds it, and so does conversion. Read once per document, at most
/// [`MAX_ANNOTS_INDEXED`] entries a page; a page or array that cannot be read
/// contributes nothing.
///
/// # Errors
///
/// Only what ends the whole document: the decode budget, memory and cancellation.
pub fn annotation_pages(
    doc: &mut Document<'_>,
    report: &AdmissionReport,
    cancel: &dyn Fn() -> bool,
) -> Result<BTreeMap<u32, u32>, PdfError> {
    let mut out = BTreeMap::new();
    for (index, info) in report.pages.iter().enumerate() {
        let Ok(index) = u32::try_from(index) else {
            break;
        };
        let Some(page) = local(doc.object(info.object, cancel))? else {
            continue;
        };
        let Some(annots) = page.dict().and_then(|d| d.get(b"Annots")).cloned() else {
            continue;
        };
        let Some(Object::Array(items)) = local(doc.resolve(&annots, cancel))? else {
            continue;
        };
        for r in items
            .iter()
            .take(MAX_ANNOTS_INDEXED)
            .filter_map(Object::as_ref)
        {
            out.entry(r.num).or_insert(index);
        }
    }
    Ok(out)
}

/// Each widget's page: its `/P` when that names a page, else the page whose `/Annots`
/// lists it (`PDF-WID-01`).
struct WidgetPages {
    by_annots: Option<BTreeMap<u32, u32>>,
}

impl WidgetPages {
    /// The index is read only when some widget lacks a page from `/P`.
    fn new(
        doc: &mut Document<'_>,
        report: &AdmissionReport,
        cancel: &dyn Fn() -> bool,
    ) -> Result<Self, PdfError> {
        let needed = report
            .fields
            .iter()
            .flat_map(|f| &f.widgets)
            .any(|w| w.page.is_none() && w.object.is_some());
        let by_annots = if needed {
            Some(annotation_pages(doc, report, cancel)?)
        } else {
            None
        };
        Ok(Self { by_annots })
    }

    fn page(&self, w: &casual_sign_pdf::Widget) -> Option<u32> {
        w.page.or_else(|| {
            let obj = w.object?;
            self.by_annots.as_ref()?.get(&obj).copied()
        })
    }
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
    let widget_pages = WidgetPages::new(doc, report, cancel)?;
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
            // One group: on each page holding its buttons, a field over that page's
            // buttons with every choice as options. The fields share the group's label,
            // so they hold one value (linked fields, docs/22 §6) and the group stays
            // exclusive across pages; a choice turns on its buttons wherever they are.
            let mut per_page: BTreeMap<u32, Option<DisplayRect>> = BTreeMap::new();
            for w in &f.widgets {
                let Some(page) = widget_pages.page(w) else {
                    out.skipped.push(skip(Unmapped::NoPage, w.object));
                    continue;
                };
                let slot = per_page.entry(page).or_insert(None);
                if let Some(r) = place(report, page, &w.rect) {
                    *slot = Some(slot.map_or(r, |o| o.union(&r)));
                }
            }
            if per_page.is_empty() {
                continue;
            }
            let mut placements = Vec::new();
            for (page, rect) in per_page {
                if let Some(p) = rect.and_then(|r| r.to_placement(page.saturating_add(1)).ok()) {
                    placements.push(p);
                }
            }
            if placements.is_empty() {
                out.skipped.push(skip(Unmapped::NoArea, None));
                continue;
            }
            // Without a label nothing links the fields: one field, on the first page.
            if label.is_none() && placements.len() > 1 {
                placements.truncate(1);
                out.lossy.push(skip(Unmapped::RadioAcrossPages, None));
            }
            let states: Vec<String> = radio_choices(doc, f, cancel)?
                .into_iter()
                .map(|c| c.text)
                .collect();
            let (opts, lost) = to_options(states);
            if lost {
                out.lossy.push(skip(Unmapped::Options, None));
            }
            for placement in placements {
                out.fields.push(make(placement, opts.clone(), next_id));
            }
            continue;
        }

        for w in &f.widgets {
            let Some(page) = widget_pages.page(w) else {
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
