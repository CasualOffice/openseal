//! The orchestration of one flattening: read what is needed, draw every field, then
//! write one incremental update (docs/30 §7).

use std::collections::{BTreeMap, BTreeSet};

use casual_sign_fields::{DisplayRect, PageGeometry, Point, RadioChoice, radio_choices};
use casual_sign_model::{FieldType, FieldValue, Id, Text};
use casual_sign_pdf::{
    Admitted, Cancel, Change, Dictionary, FieldType as PdfFieldType, IncrementalUpdate, ObjRef,
    Object, PageInfo, Rect,
};

use crate::canvas::{Canvas, Color, GlyphUse, num, num_fine};
use crate::draw::{self, Ctx, Drawing, Drawn};
use crate::error::FlattenError;
use crate::fill::{self, FillPlan, FillValue, Target};
use crate::fonts::FontSet;
use crate::limits::MAX_FIELDS_PER_PAGE;
use crate::optional::{self, OptionalContent, Pass};
use crate::read::{self, MAX_ANNOTS, WidgetInfo};
use crate::write;
use crate::{FlattenInput, FlattenOptions, FlattenReport, Flattened, FormMode, NotDrawn};

/// The matrix taking a field's own coordinates (points, origin bottom-left of the box
/// as displayed, y up) to the page's user space.
pub(crate) fn field_matrix(g: &PageGeometry, r: &DisplayRect) -> [f64; 6] {
    let o = g.to_user(Point::new(r.x, r.bottom()));
    let ux = g.to_user(Point::new(r.x + 1.0, r.bottom()));
    let vy = g.to_user(Point::new(r.x, r.bottom() - 1.0));
    [ux.x - o.x, ux.y - o.y, vy.x - o.x, vy.y - o.y, o.x, o.y]
}

fn cm(m: [f64; 6]) -> String {
    let [a, b, c, d, e, f] = m;
    format!(
        "{} {} {} {} {} {} cm",
        num_fine(a),
        num_fine(b),
        num_fine(c),
        num_fine(d),
        num(e),
        num(f)
    )
}

/// A box of marks to place on a page.
#[derive(Debug)]
struct Placed {
    page: usize,
    w: f64,
    h: f64,
    matrix: [f64; 6],
    drawing: Drawing,
}

/// An existing appearance stream drawn into a page.
#[derive(Debug)]
struct Kept {
    page: usize,
    stream: ObjRef,
    matrix: [f64; 6],
}

/// A widget of the document's form, with its field.
#[derive(Debug)]
struct FormWidget {
    field_object: Option<u32>,
    kind: PdfFieldType,
    info: WidgetInfo,
}

/// The cm mapping a form XObject's transformed `/BBox` onto `rect` (ISO 32000-2
/// §12.5.5); the XObject's own `/Matrix` is applied by `Do`.
fn appearance_matrix(bbox: &Rect, m: [f64; 6], rect: &Rect) -> Option<[f64; 6]> {
    let [a, b, c, d, e, f] = m;
    let corners = [
        (bbox.llx, bbox.lly),
        (bbox.urx, bbox.lly),
        (bbox.llx, bbox.ury),
        (bbox.urx, bbox.ury),
    ];
    let (mut x0, mut y0, mut x1, mut y1) = (f64::MAX, f64::MAX, f64::MIN, f64::MIN);
    for (x, y) in corners {
        let (tx, ty) = (a * x + c * y + e, b * x + d * y + f);
        x0 = x0.min(tx);
        y0 = y0.min(ty);
        x1 = x1.max(tx);
        y1 = y1.max(ty);
    }
    let (tw, th) = (x1 - x0, y1 - y0);
    if tw <= 1e-9 || th <= 1e-9 || !tw.is_finite() || !th.is_finite() {
        return None;
    }
    let sx = (rect.urx - rect.llx) / tw;
    let sy = (rect.ury - rect.lly) / th;
    Some([sx, 0.0, 0.0, sy, rect.llx - x0 * sx, rect.lly - y0 * sy])
}

/// A value for filling from a model value.
fn fill_value(v: &FieldValue) -> Option<FillValue> {
    match v {
        FieldValue::Text(t) => Some(FillValue::Text(t.as_str().to_owned())),
        FieldValue::Choice(t) => Some(FillValue::Choice(t.as_str().to_owned())),
        FieldValue::Checked(c) => Some(FillValue::Checked(*c)),
        _ => None,
    }
}

fn page_geometry(pages: &[PageInfo], index: usize) -> Option<PageGeometry> {
    pages.get(index).map(PageGeometry::from_page)
}

/// `first` then `then`, as PDF concatenates matrices (row vectors).
fn concat(first: [f64; 6], then: [f64; 6]) -> [f64; 6] {
    let [a, b, c, d, e, f] = first;
    let [a2, b2, c2, d2, e2, f2] = then;
    [
        a * a2 + b * c2,
        a * b2 + b * d2,
        c * a2 + d * c2,
        c * b2 + d * d2,
        e * a2 + f * c2 + e2,
        e * b2 + f * d2 + f2,
    ]
}

/// Where an annotation's appearance goes on the page (ISO 32000-2 §12.5.5): onto its
/// rectangle; with NoRotate (`/F` bit 5) on a rotated page, upright on screen with
/// the rectangle's upper-left corner fixed, as viewers show it (§12.5.3). NoZoom needs
/// nothing: at 100 % the annotation is its own size.
fn annotation_matrix(
    g: &PageGeometry,
    bbox: &Rect,
    m: [f64; 6],
    rect: &Rect,
    no_rotate: bool,
) -> Option<[f64; 6]> {
    if !no_rotate || g.rotate() == 0 {
        return appearance_matrix(bbox, m, rect);
    }
    let shown = g.rect_to_displayed(rect);
    let (w, h) = if g.rotate().is_multiple_of(180) {
        (shown.width, shown.height)
    } else {
        (shown.height, shown.width)
    };
    let corner = g.to_displayed(Point::new(rect.llx, rect.ury));
    let upright = DisplayRect {
        x: corner.x,
        y: corner.y,
        width: w,
        height: h,
    };
    let unit = g.user_unit();
    let local = Rect {
        llx: 0.0,
        lly: 0.0,
        urx: w / unit,
        ury: h / unit,
    };
    let inner = appearance_matrix(bbox, m, &local)?;
    // The field matrix maps display points; `local` is in user units.
    let scale = [unit, 0.0, 0.0, unit, 0.0, 0.0];
    Some(concat(concat(inner, scale), field_matrix(g, &upright)))
}

/// The on-state appearance of the widget a converted checkbox came from: among the
/// field's widgets on `page`, the one nearest the field's box (the sender may have
/// moved it), its first normal-appearance state other than `/Off`.
fn own_on_appearance(
    widgets: &[&FormWidget],
    page: usize,
    g: &PageGeometry,
    rect: &DisplayRect,
) -> Option<ObjRef> {
    let centre = |r: &DisplayRect| (r.x + r.width / 2.0, r.y + r.height / 2.0);
    let (cx, cy) = centre(rect);
    let w = widgets
        .iter()
        .filter(|w| w.info.page.and_then(|p| usize::try_from(p).ok()) == Some(page))
        .map(|w| {
            let (x, y) = centre(&g.rect_to_displayed(&w.info.rect));
            ((x - cx).hypot(y - cy), w)
        })
        .filter(|(d, _)| d.is_finite())
        .min_by(|a, b| a.0.total_cmp(&b.0))?
        .1;
    let Some(Object::Dictionary(states)) = &w.info.ap_n else {
        return None;
    };
    w.info
        .on_states
        .iter()
        .find_map(|s| states.get(s).and_then(Object::as_ref))
}

/// Whether `d`'s `/OC` is hidden under the default configuration.
fn oc_hidden(
    doc: &mut casual_sign_pdf::Document<'_>,
    oc: &mut Option<OptionalContent>,
    d: &Dictionary,
    cancel: Cancel<'_>,
) -> Result<bool, FlattenError> {
    match (oc.as_mut(), d.get(b"OC")) {
        (Some(oc), Some(v)) => Ok(!oc.visible(doc, v, cancel)?),
        _ => Ok(false),
    }
}

/// `/F` bits that keep an annotation off the screen: Hidden (2) and NoView (6). The
/// sealed page shows what the signer saw on screen, so these decide and Print does
/// not (docs/30 §7).
const OFF_SCREEN: i64 = (1 << 1) | (1 << 5);
/// `/F` NoRotate (bit 5).
const NO_ROTATE: i64 = 1 << 4;

/// Flatten `input` into the admitted, normalized document.
///
/// The document is read through `admitted` (hence `&mut`: reading objects updates its
/// caches and decode budget) and then written as one incremental update; the input
/// bytes are a prefix of the output (`CS-WRT-0001` otherwise). `cancel` is checked in
/// every read.
///
/// # Errors
///
/// [`FlattenError`], with its code: `CS-FLT-0001` for a character no face draws,
/// `CS-FLT-0002`/`0003` for images, `CS-FLD-*` for values over their bounds or not
/// suiting their field, and the reader's or writer's code when the document cannot be
/// read or appended to.
pub fn flatten(
    admitted: &mut Admitted<'_>,
    input: &FlattenInput<'_>,
    fonts: &FontSet,
    options: &FlattenOptions,
    cancel: Cancel<'_>,
) -> Result<Flattened, FlattenError> {
    let mut report = FlattenReport::default();

    // Bounds before any work.
    let mut per_page: BTreeMap<u32, usize> = BTreeMap::new();
    for f in input.fields {
        let n = per_page.entry(f.placement.page()).or_insert(0);
        *n = n.saturating_add(1);
        if *n > MAX_FIELDS_PER_PAGE {
            return Err(FlattenError::TooManyFields {
                page: f.placement.page(),
                fields: *n,
            });
        }
    }

    let pages = admitted.report.pages.clone();
    let pdf_fields = admitted.report.fields.clone();
    // A certified document filled in place keeps its certification: its DocMDP permits
    // filling and signing at most, never new page content, so its optional content and
    // annotations are left as the certifier signed them (the review renders them with
    // the default configuration). Flattening such a document is refused by the writer.
    let keep_as_certified =
        admitted.report.docmdp.is_some() && options.mode == FormMode::FillInPlace;
    report.layers_kept_as_certified = keep_as_certified;
    let doc = &mut admitted.document;

    // The fields the conversion made, by id, and the PDF fields they came from.
    let mut source: BTreeMap<&Id, u32> = BTreeMap::new();
    let mut converted: BTreeSet<u32> = BTreeSet::new();
    if let Some(c) = input.acroform {
        for cf in &c.fields {
            if let Some(obj) = cf.object {
                source.insert(&cf.field.id, obj);
                converted.insert(obj);
            }
        }
    }

    let catalog = read::catalog(doc, cancel)?;
    let acroform_ref = catalog
        .as_ref()
        .and_then(|(_, c)| c.get(b"AcroForm").cloned());
    let has_form = acroform_ref.is_some();
    let remove_form = has_form && options.mode == FormMode::Flatten;
    // The default configuration of optional content, when the document has any.
    let mut oc = match &catalog {
        Some((_, c)) if !keep_as_certified => OptionalContent::read(doc, c, cancel)?,
        _ => None,
    };

    // Which page holds each annotation: a widget without `/P` is found by the page whose
    // `/Annots` lists it, as viewers find it.
    let mut annot_page: BTreeMap<u32, u32> = BTreeMap::new();
    if has_form {
        for (index, info) in pages.iter().enumerate() {
            let Some(page) = read::object_dict(doc, info.object, cancel)? else {
                continue;
            };
            let Some(a) = page.get(b"Annots").cloned() else {
                continue;
            };
            if let Some(Object::Array(items)) = read::local(doc.resolve(&a, cancel))? {
                for r in items.iter().take(MAX_ANNOTS).filter_map(Object::as_ref) {
                    if let Ok(i) = u32::try_from(index) {
                        annot_page.entry(r.num).or_insert(i);
                    }
                }
            }
        }
    }

    // Every widget of the form, read once.
    let mut widgets: Vec<FormWidget> = Vec::new();
    if has_form {
        for f in &pdf_fields {
            for w in &f.widgets {
                let Some(obj) = w.object else { continue };
                let page = w.page.or_else(|| annot_page.get(&obj).copied());
                if let Some(mut info) = read::widget(doc, obj, w.rect, page, cancel)? {
                    // A widget in hidden optional content is not seen either.
                    if oc_hidden(doc, &mut oc, &info.dict, cancel)? {
                        info.hidden = true;
                    }
                    widgets.push(FormWidget {
                        field_object: f.object,
                        kind: f.field_type,
                        info,
                    });
                }
            }
        }
    }
    // Each radio group's choices: the option texts conversion offered and the states
    // they write, in the document's own bytes (FLD-RADIO-NAME, FLD-RADIO-NOOPT).
    let mut radio: BTreeMap<u32, Vec<RadioChoice>> = BTreeMap::new();
    if has_form {
        for f in &pdf_fields {
            if f.field_type == PdfFieldType::Radio
                && let Some(obj) = f.object
            {
                radio.insert(obj, radio_choices(doc, f, cancel)?);
            }
        }
    }
    let widgets_of = |obj: u32| -> Vec<&FormWidget> {
        widgets
            .iter()
            .filter(|w| w.field_object == Some(obj))
            .collect()
    };

    let mut uses = GlyphUse::default();
    let mut placed: Vec<Placed> = Vec::new();
    let mut kept: Vec<Kept> = Vec::new();

    // Frames of converted widgets go under the values.
    if remove_form && options.widget_frames {
        for w in &widgets {
            let Some(fo) = w.field_object else { continue };
            if !converted.contains(&fo) || w.info.hidden {
                continue;
            }
            let Some(page) = w.info.page.and_then(|p| usize::try_from(p).ok()) else {
                continue;
            };
            let Some(g) = page_geometry(&pages, page) else {
                continue;
            };
            let r = g.rect_to_displayed(&w.info.rect);
            let mut canvas = Canvas::default();
            fill::draw_frame(
                &mut canvas,
                &w.info,
                r.width,
                r.height,
                w.kind == PdfFieldType::Radio,
            );
            if canvas.ops.is_empty() {
                continue;
            }
            placed.push(Placed {
                page,
                w: r.width,
                h: r.height,
                matrix: field_matrix(&g, &r),
                drawing: Drawing {
                    canvas,
                    images: Vec::new(),
                },
            });
        }
    }

    // Appearances of widgets that were not converted, kept as they look.
    if remove_form && options.keep_unconverted_appearances {
        for w in &widgets {
            if w.field_object.is_some_and(|fo| converted.contains(&fo)) || w.info.hidden {
                continue;
            }
            let Some(page) = w.info.page.and_then(|p| usize::try_from(p).ok()) else {
                continue;
            };
            let Some(stream) = read::current_appearance(&w.info) else {
                // No appearance: keep the border and background a viewer draws from
                // `/MK`, as for converted widgets.
                let Some(g) = page_geometry(&pages, page) else {
                    continue;
                };
                let r = g.rect_to_displayed(&w.info.rect);
                let mut canvas = Canvas::default();
                fill::draw_frame(
                    &mut canvas,
                    &w.info,
                    r.width,
                    r.height,
                    w.kind == PdfFieldType::Radio,
                );
                if !canvas.ops.is_empty() {
                    placed.push(Placed {
                        page,
                        w: r.width,
                        h: r.height,
                        matrix: field_matrix(&g, &r),
                        drawing: Drawing {
                            canvas,
                            images: Vec::new(),
                        },
                    });
                    report.appearances_kept = report.appearances_kept.saturating_add(1);
                }
                continue;
            };
            let Some((bbox, m)) = read::form_box(doc, stream, cancel)? else {
                continue;
            };
            if let Some(matrix) = appearance_matrix(&bbox, m, &w.info.rect) {
                kept.push(Kept {
                    page,
                    stream,
                    matrix,
                });
                report.appearances_kept = report.appearances_kept.saturating_add(1);
            }
        }
    }

    // Fill targets (FILL-01): converted fields of a fillable kind, first value wins.
    let mut targets: BTreeMap<u32, (FillValue, Vec<Id>)> = BTreeMap::new();
    let fill_kind = |obj: u32| -> Option<PdfFieldType> {
        pdf_fields
            .iter()
            .find(|f| f.object == Some(obj))
            .map(|f| f.field_type)
            .filter(|k| {
                matches!(
                    k,
                    PdfFieldType::Text
                        | PdfFieldType::CheckBox
                        | PdfFieldType::Radio
                        | PdfFieldType::Choice
                )
            })
    };

    let envelope_value = input
        .envelope_id
        .and_then(|e| Text::new(e).ok())
        .map(FieldValue::Text);
    // Radio groups whose chosen buttons are drawn.
    let mut radio_drawn: BTreeSet<u32> = BTreeSet::new();
    let mut ctx = Ctx {
        fonts,
        uses: &mut uses,
        options,
        envelope_id: input.envelope_id,
        captures: input.captures,
    };
    for field in input.fields {
        let value = input.values.get(&field.id).or_else(|| {
            (field.field_type == FieldType::EnvelopeId)
                .then_some(envelope_value.as_ref())
                .flatten()
        });
        let Some(value) = value else {
            report.not_drawn.push((field.id.clone(), NotDrawn::NoValue));
            continue;
        };
        let src = source.get(&field.id).copied();
        if options.mode == FormMode::FillInPlace
            && let Some(obj) = src
            && fill_kind(obj).is_some()
        {
            let Some(v) = fill_value(value) else {
                return Err(FlattenError::ValueMismatch {
                    field: field.id.clone(),
                });
            };
            let entry = targets
                .entry(obj)
                .or_insert_with(|| (v.clone(), Vec::new()));
            if matches!(&entry.0, FillValue::Text(t) | FillValue::Choice(t) if t.is_empty()) {
                entry.0 = v;
            }
            entry.1.push(field.id.clone());
            continue;
        }
        let page = usize::try_from(field.placement.page())
            .ok()
            .and_then(|p| p.checked_sub(1));
        let Some((page, g)) = page.and_then(|p| page_geometry(&pages, p).map(|g| (p, g))) else {
            return Err(FlattenError::OffPage {
                field: field.id.clone(),
            });
        };
        let rect = DisplayRect::from_placement(&field.placement);
        if !g.contains(&rect, 1.0) {
            return Err(FlattenError::OffPage {
                field: field.id.clone(),
            });
        }

        // A converted radio group: the chosen buttons as the document draws them on (their
        // own on appearance), or a dot in their box when they have none. Never the
        // option's text: a group's value is a button, not words.
        if field.field_type == FieldType::RadioGroup
            && let Some(obj) = src
            && let Some(choices) = radio.get(&obj)
            && let FieldValue::Choice(chosen) | FieldValue::Text(chosen) = value
        {
            if chosen.is_empty() {
                report.not_drawn.push((field.id.clone(), NotDrawn::NoValue));
                continue;
            }
            let Some(choice) = choices.iter().find(|c| c.text == chosen.as_str()) else {
                return Err(FlattenError::ValueMismatch {
                    field: field.id.clone(),
                });
            };
            // A group across pages is a linked field on each page (ACRO-02): its
            // buttons are drawn once, by the first of them.
            if !radio_drawn.insert(obj) {
                report.drawn.push(field.id.clone());
                continue;
            }
            let color = field
                .format
                .as_ref()
                .and_then(|f| f.color)
                .map_or(Color::BLACK, |c| Color::from_rgb(c.0));
            for rw in &choice.widgets {
                let Some(b) = widgets_of(obj)
                    .into_iter()
                    .find(|w| w.info.object == rw.widget)
                else {
                    continue;
                };
                let Some(bp) = b.info.page.and_then(|p| usize::try_from(p).ok()) else {
                    continue;
                };
                let own = match (&b.info.ap_n, rw.has_appearance) {
                    (Some(Object::Dictionary(states)), true) => {
                        states.get(&rw.state).and_then(Object::as_ref)
                    }
                    _ => None,
                };
                if let Some(stream) = own
                    && let Some((bbox, m)) = read::form_box(doc, stream, cancel)?
                    && let Some(matrix) = appearance_matrix(&bbox, m, &b.info.rect)
                {
                    kept.push(Kept {
                        page: bp,
                        stream,
                        matrix,
                    });
                    continue;
                }
                let Some(bg) = page_geometry(&pages, bp) else {
                    continue;
                };
                let r = bg.rect_to_displayed(&b.info.rect);
                let mut canvas = Canvas::default();
                draw::dot(&mut canvas, r.width, r.height, color);
                placed.push(Placed {
                    page: bp,
                    w: r.width,
                    h: r.height,
                    matrix: field_matrix(&bg, &r),
                    drawing: Drawing {
                        canvas,
                        images: Vec::new(),
                    },
                });
            }
            report.drawn.push(field.id.clone());
            continue;
        }

        // A converted checkbox, checked: its widget's own on appearance (a cross, a
        // filled square, a styled check) in the field's box, as the document draws it
        // on; our checkmark only when it has none (FLT-04).
        if field.field_type == FieldType::Checkbox
            && matches!(value, FieldValue::Checked(true))
            && let Some(obj) = src
            && let Some(stream) = own_on_appearance(&widgets_of(obj), page, &g, &rect)
            && let Some((bbox, m)) = read::form_box(doc, stream, cancel)?
            && let Some(matrix) = appearance_matrix(&bbox, m, &g.rect_to_user(&rect))
        {
            kept.push(Kept {
                page,
                stream,
                matrix,
            });
            report.drawn.push(field.id.clone());
            continue;
        }

        match draw::field(&mut ctx, field, value, rect.width, rect.height)? {
            Drawn::Skip(why) => report.not_drawn.push((field.id.clone(), why)),
            Drawn::Marks(drawing, fit) => {
                if fit.shrunk {
                    report.shrunk.push(field.id.clone());
                }
                if fit.overflow {
                    report.overflow.push(field.id.clone());
                }
                report.drawn.push(field.id.clone());
                placed.push(Placed {
                    page,
                    w: rect.width,
                    h: rect.height,
                    matrix: field_matrix(&g, &rect),
                    drawing,
                });
            }
        }
    }

    // Annotations, page by page (FLT-03): widgets go with the form; non-widget
    // annotations the signer could not see go; those with an appearance are drawn into
    // the page and go, with their pop-ups; links and annotations without an appearance
    // stay. `appearances` collects the streams of whatever stays, for the optional
    // content pass.
    let mut new_annots: BTreeMap<usize, Vec<Object>> = BTreeMap::new();
    let mut appearances: Vec<u32> = Vec::new();
    // Annotations that stay and carry `/OC`, and whether it hides them.
    let mut hide: Vec<(u32, bool)> = Vec::new();
    let mut page_dicts: Vec<(usize, u32, Dictionary)> = Vec::with_capacity(pages.len());
    for (index, info) in pages.iter().enumerate() {
        let Some(page_dict) = read::object_dict(doc, info.object, cancel)? else {
            continue;
        };
        page_dicts.push((index, info.object, page_dict.clone()));
        let Some(a) = page_dict.get(b"Annots").cloned() else {
            continue;
        };
        let Some(Object::Array(items)) = read::local(doc.resolve(&a, cancel))? else {
            continue;
        };
        let g = page_geometry(&pages, index);
        let mut changed = false;
        // (item, the parent it pops up for)
        let mut out: Vec<(Object, Option<u32>)> = Vec::with_capacity(items.len());
        let mut gone: BTreeSet<u32> = BTreeSet::new();
        for (i, item) in items.into_iter().enumerate() {
            if i >= MAX_ANNOTS {
                out.push((item, None));
                continue;
            }
            let Some(d) = read::dict(doc, &item, cancel)? else {
                out.push((item, None));
                continue;
            };
            let num = item.as_ref().map(|r| r.num);
            match d.name(b"Subtype") {
                Some(b"Widget") => {
                    if remove_form {
                        report.widgets_removed = report.widgets_removed.saturating_add(1);
                        changed = true;
                        continue;
                    }
                    if oc.is_some()
                        && d.contains(b"OC")
                        && let Some(n) = num
                    {
                        hide.push((n, oc_hidden(doc, &mut oc, &d, cancel)?));
                    }
                    appearances.extend(optional::appearance_streams(doc, &d, cancel)?);
                    out.push((item, None));
                    continue;
                }
                Some(b"Popup") => {
                    let parent = d.get(b"Parent").and_then(Object::as_ref).map(|r| r.num);
                    out.push((item, parent));
                    continue;
                }
                _ => {}
            }
            if keep_as_certified {
                out.push((item, None));
                continue;
            }
            let flags = d.get(b"F").and_then(Object::as_i64).unwrap_or(0);
            if flags & OFF_SCREEN != 0 || oc_hidden(doc, &mut oc, &d, cancel)? {
                report.annotations_removed = report.annotations_removed.saturating_add(1);
                changed = true;
                gone.extend(num);
                continue;
            }
            let drawn = if d.name(b"Subtype") == Some(b"Link") {
                None
            } else {
                match (
                    read::annotation_appearance(doc, &d, cancel)?,
                    read::rect(d.get(b"Rect")),
                    g.as_ref(),
                ) {
                    (Some(stream), Some(rect), Some(g)) => read::form_box(doc, stream, cancel)?
                        .and_then(|(bbox, m)| {
                            annotation_matrix(g, &bbox, m, &rect, flags & NO_ROTATE != 0)
                        })
                        .map(|matrix| Kept {
                            page: index,
                            stream,
                            matrix,
                        }),
                    _ => None,
                }
            };
            match drawn {
                Some(k) => {
                    kept.push(k);
                    report.annotations_flattened = report.annotations_flattened.saturating_add(1);
                    changed = true;
                    gone.extend(num);
                }
                None => {
                    report.annotations_kept = report.annotations_kept.saturating_add(1);
                    appearances.extend(optional::appearance_streams(doc, &d, cancel)?);
                    if oc.is_some() && d.contains(b"OC") {
                        match num {
                            Some(n) => hide.push((n, false)),
                            None => {
                                let mut d = d.clone();
                                d.remove(b"OC");
                                out.push((Object::Dictionary(d), None));
                                changed = true;
                                continue;
                            }
                        }
                    }
                    out.push((item, None));
                }
            }
        }
        // A pop-up goes with the annotation it belongs to.
        let before = out.len();
        out.retain(|(_, parent)| !parent.is_some_and(|p| gone.contains(&p)));
        let popped = before.saturating_sub(out.len());
        if popped > 0 {
            report.annotations_removed = report.annotations_removed.saturating_add(popped);
            changed = true;
        }
        if changed {
            new_annots.insert(index, out.into_iter().map(|(o, _)| o).collect());
        }
    }

    // Optional content (FLT-03): what the default configuration hides is not drawn by
    // anything kept, and is removed from every content stream that stays.
    let mut pass = Pass::default();
    if let Some(oc) = oc.as_mut() {
        let mut visible = Vec::with_capacity(kept.len());
        for k in kept.drain(..) {
            if !pass.stream_hidden(doc, oc, k.stream.num, cancel)? {
                visible.push(k);
            }
        }
        kept = visible;
        appearances.extend(kept.iter().map(|k| k.stream.num));
        pass.run(doc, oc, &page_dicts, &appearances, cancel)?;
        report.optional_content_flattened = true;
        report.hidden_sections = pass.stats.sections;
        report.hidden_operators = pass.stats.operators;
    }

    // Plan the fills.
    let mut plan = FillPlan::default();
    let mut acroform_edit: Option<(Option<u32>, Dictionary)> = None;
    if options.mode == FormMode::FillInPlace && has_form {
        let form = match &acroform_ref {
            Some(Object::Reference(r)) => {
                read::object_dict(doc, r.num, cancel)?.map(|d| (Some(r.num), d))
            }
            Some(Object::Dictionary(d)) => Some((None, d.clone())),
            _ => None,
        };
        let default_da = form.as_ref().and_then(|(_, d)| match d.get(b"DA") {
            Some(Object::String(s)) => Some(s.clone()),
            _ => None,
        });
        for (obj, (value, ids)) in &targets {
            let Some(kind) = fill_kind(*obj) else {
                continue;
            };
            let infos: Vec<WidgetInfo> = widgets_of(*obj).iter().map(|w| w.info.clone()).collect();
            let Some(first) = ids.first() else { continue };
            fill::plan_field(
                doc,
                &mut plan,
                ctx.uses,
                fonts,
                default_da.as_deref(),
                &Target {
                    object: *obj,
                    kind,
                    value,
                    widgets: &infos,
                    choices: radio.get(obj).map_or(&[], Vec::as_slice),
                    field_id: first,
                },
                cancel,
            )?;
            report.filled.extend(ids.iter().cloned());
        }
        if let Some((num, mut d)) = form {
            d.insert(b"NeedAppearances", Object::Bool(false));
            acroform_edit = Some((num, d));
        }
    }

    // Annotations that stay lose `/OC`, since no configuration is left to read it;
    // those it hid (widgets of a kept form) are marked Hidden instead, as the signer
    // did not see them.
    for (n, hidden) in hide {
        let d = match plan.edits.remove(&n) {
            Some(d) => Some(d),
            None => read::object_dict(doc, n, cancel)?,
        };
        if let Some(mut d) = d {
            if hidden {
                let flags = d.get(b"F").and_then(Object::as_i64).unwrap_or(0);
                d.insert(b"F", Object::Integer(flags | (1 << 1)));
            }
            d.remove(b"OC");
            plan.edits.insert(n, d);
        }
    }

    // Pages to rewrite: those drawn on, those whose annotations changed, and those
    // whose content held hidden optional content.
    let drawn_pages: BTreeSet<usize> = placed
        .iter()
        .map(|p| p.page)
        .chain(kept.iter().map(|k| k.page))
        .collect();
    let mut touched = drawn_pages.clone();
    touched.extend(new_annots.keys().copied());
    touched.extend(pass.pages.keys().copied());
    struct PageEdit {
        object: u32,
        dict: Dictionary,
        resources: Dictionary,
        contents: Vec<Object>,
        draws: bool,
        rewritten: Option<Vec<u8>>,
    }
    let mut edits: BTreeMap<usize, PageEdit> = BTreeMap::new();
    for &index in &touched {
        let Some(info) = pages.get(index) else {
            continue;
        };
        let Some(mut dict) = read::object_dict(doc, info.object, cancel)? else {
            continue;
        };
        if let Some(items) = new_annots.remove(&index) {
            if items.is_empty() {
                dict.remove(b"Annots");
            } else {
                dict.insert(b"Annots", Object::Array(items));
            }
        }
        let draws = drawn_pages.contains(&index);
        let resources = if draws {
            read::resources(doc, &dict, cancel)?
        } else {
            Dictionary::new()
        };
        let contents = read::contents(doc, &dict, cancel)?;
        edits.insert(
            index,
            PageEdit {
                object: info.object,
                dict,
                resources,
                contents,
                draws,
                rewritten: pass.pages.remove(&index),
            },
        );
    }

    // ---- write ----------------------------------------------------------------------
    let change =
        if placed.is_empty() && kept.is_empty() && !remove_form && oc.is_none() && edits.is_empty()
        {
            Change::FillAndSign
        } else {
            Change::Other
        };
    let admitted_ref: &Admitted<'_> = admitted;
    let mut u = IncrementalUpdate::new(admitted_ref, change)?;
    let font_refs = write::fonts(&mut u, fonts, &uses, &mut report.fonts)?;

    // Per page: (XObject reference, cm).
    let mut invocations: BTreeMap<usize, Vec<(ObjRef, [f64; 6])>> = BTreeMap::new();
    for p in &placed {
        let mut image_refs = Vec::with_capacity(p.drawing.images.len());
        for img in &p.drawing.images {
            image_refs.push(write::image(&mut u, img)?);
            report.images = report.images.saturating_add(1);
        }
        let form = write::form(
            &mut u,
            &p.drawing.canvas,
            p.w,
            p.h,
            None,
            &font_refs,
            &image_refs,
        )?;
        invocations
            .entry(p.page)
            .or_default()
            .push((form, p.matrix));
    }
    for k in &kept {
        invocations
            .entry(k.page)
            .or_default()
            .push((k.stream, k.matrix));
    }
    let opener = if invocations.is_empty() {
        None
    } else {
        Some(write::content(&mut u, "q\n")?)
    };
    for (index, edit) in &mut edits {
        let mut dict = edit.dict.clone();
        // Content cleared of hidden optional content replaces the page's streams.
        if let Some(data) = edit.rewritten.take() {
            let r = write::content_bytes(&mut u, &data)?;
            edit.contents = vec![Object::Reference(r)];
            dict.insert(b"Contents", Object::Array(edit.contents.clone()));
        }
        if edit.draws
            && let Some(list) = invocations.get(index)
        {
            let mut resources = edit.resources.clone();
            let mut xobjects = match resources.get(b"XObject") {
                Some(Object::Dictionary(d)) => d.clone(),
                _ => Dictionary::new(),
            };
            let mut ops = String::new();
            if !edit.contents.is_empty() {
                ops.push_str("Q\n");
            }
            let mut n: usize = 0;
            for (r, m) in list {
                let mut key = format!("OSF{n}");
                while xobjects.contains(key.as_bytes()) {
                    n = n.saturating_add(1);
                    key = format!("OSF{n}");
                }
                n = n.saturating_add(1);
                xobjects.insert(key.as_bytes(), Object::Reference(*r));
                ops.push_str(&format!("q\n{}\n/{key} Do\nQ\n", cm(*m)));
            }
            resources.insert(b"XObject", Object::Dictionary(xobjects));
            let closer = write::content(&mut u, &ops)?;
            let mut contents = Vec::with_capacity(edit.contents.len().saturating_add(2));
            if !edit.contents.is_empty()
                && let Some(o) = opener
            {
                contents.push(Object::Reference(o));
                contents.extend(edit.contents.iter().cloned());
            }
            contents.push(Object::Reference(closer));
            dict.insert(b"Contents", Object::Array(contents));
            dict.insert(b"Resources", Object::Dictionary(resources));
        }
        u.replace(edit.object, Object::Dictionary(dict))?;
    }
    // Forms and patterns cleared of hidden optional content, in place.
    for s in &pass.streams {
        write::replace_stream(&mut u, s.num, s.dict.clone(), &s.data)?;
    }
    for (num, stream) in &pass.stripped {
        u.replace(*num, stream.clone())?;
    }

    // Fills: appearance streams, then the changed dictionaries.
    for a in &plan.appearances {
        let stream = write::form(&mut u, &a.canvas, a.w, a.h, a.matrix, &font_refs, &[])?;
        let mut ap = Dictionary::new();
        match &a.on_state {
            Some(state) => {
                let off = write::form(
                    &mut u,
                    &Canvas::default(),
                    a.w,
                    a.h,
                    a.matrix,
                    &font_refs,
                    &[],
                )?;
                let mut n = Dictionary::new();
                n.insert(state, Object::Reference(stream));
                n.insert(b"Off", Object::Reference(off));
                ap.insert(b"N", Object::Dictionary(n));
            }
            None => ap.insert(b"N", Object::Reference(stream)),
        }
        if let Some(d) = plan.edits.get_mut(&a.widget) {
            d.insert(b"AP", Object::Dictionary(ap));
        }
    }
    for (num, d) in &plan.edits {
        u.replace(*num, Object::Dictionary(d.clone()))?;
    }

    // The catalog: the form removed, or told to use our appearances; optional content
    // gone, so every viewer draws what remains.
    if let Some((root, mut cat)) = catalog {
        let mut changed = false;
        if oc.is_some() {
            cat.remove(b"OCProperties");
            changed = true;
        }
        if remove_form {
            cat.remove(b"AcroForm");
            changed = true;
            report.acroform_removed = true;
        } else if let Some((num, form)) = acroform_edit {
            match num {
                Some(n) => u.replace(n, Object::Dictionary(form))?,
                None => {
                    cat.insert(b"AcroForm", Object::Dictionary(form));
                    changed = true;
                }
            }
        }
        if changed {
            u.replace(root, Object::Dictionary(cat))?;
        }
    }
    let bytes = u.finish()?;
    Ok(Flattened { bytes, report })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn geom(rotate: i64) -> PageGeometry {
        PageGeometry::new(
            Rect {
                llx: 10.0,
                lly: 20.0,
                urx: 210.0,
                ury: 320.0,
            },
            rotate,
            2.0,
        )
    }

    #[test]
    fn the_field_matrix_maps_the_box_corners_to_the_user_space_rectangle() {
        let r = DisplayRect {
            x: 40.0,
            y: 60.0,
            width: 100.0,
            height: 30.0,
        };
        for rot in [0, 90, 180, 270] {
            let g = geom(rot);
            let m = field_matrix(&g, &r);
            let apply = |u: f64, v: f64| (m[0] * u + m[2] * v + m[4], m[1] * u + m[3] * v + m[5]);
            let want = g.rect_to_user(&r);
            let corners = [apply(0.0, 0.0), apply(100.0, 30.0)];
            for (x, y) in corners {
                assert!(x >= want.llx - 1e-9 && x <= want.urx + 1e-9, "{rot}");
                assert!(y >= want.lly - 1e-9 && y <= want.ury + 1e-9, "{rot}");
            }
            // Top-left of the box (0, h) lands on the displayed top-left.
            let tl = apply(0.0, 30.0);
            let d = g.to_displayed(Point::new(tl.0, tl.1));
            assert!(
                (d.x - 40.0).abs() < 1e-9 && (d.y - 60.0).abs() < 1e-9,
                "{rot}"
            );
        }
    }

    #[test]
    fn an_appearance_fills_its_rectangle() {
        let bbox = Rect {
            llx: 0.0,
            lly: 0.0,
            urx: 50.0,
            ury: 10.0,
        };
        let rect = Rect {
            llx: 100.0,
            lly: 200.0,
            urx: 200.0,
            ury: 220.0,
        };
        let m = appearance_matrix(&bbox, [1.0, 0.0, 0.0, 1.0, 0.0, 0.0], &rect).unwrap_or_default();
        assert_eq!(m, [2.0, 0.0, 0.0, 2.0, 100.0, 200.0]);
        assert!(appearance_matrix(&bbox, [0.0; 6], &rect).is_none());
    }

    #[test]
    fn a_no_rotate_annotation_stays_upright_at_its_upper_left_corner() {
        let bbox = Rect {
            llx: 0.0,
            lly: 0.0,
            urx: 40.0,
            ury: 10.0,
        };
        let rect = Rect {
            llx: 50.0,
            lly: 100.0,
            urx: 90.0,
            ury: 110.0,
        };
        let id = [1.0, 0.0, 0.0, 1.0, 0.0, 0.0];
        for rot in [0, 90, 180, 270] {
            for uu in [1.0, 2.0] {
                let g = geom(rot);
                let g = PageGeometry::new(g.crop_box(), rot, uu);
                let m = annotation_matrix(&g, &bbox, id, &rect, true).unwrap_or_default();
                let shown = |x: f64, y: f64| {
                    let (ux, uy) = (m[0] * x + m[2] * y + m[4], m[1] * x + m[3] * y + m[5]);
                    g.to_displayed(Point::new(ux, uy))
                };
                // The appearance's top-left is the rectangle's upper-left corner as
                // displayed, and its width runs right, its height down, unscaled.
                let corner = g.to_displayed(Point::new(rect.llx, rect.ury));
                let tl = shown(0.0, 10.0);
                let tr = shown(40.0, 10.0);
                let bl = shown(0.0, 0.0);
                let near = |a: f64, b: f64| (a - b).abs() < 1e-6;
                assert!(near(tl.x, corner.x) && near(tl.y, corner.y), "{rot} {uu}");
                assert!(
                    near(tr.x - tl.x, 40.0 * uu) && near(tr.y, tl.y),
                    "{rot} {uu}"
                );
                assert!(
                    near(bl.y - tl.y, 10.0 * uu) && near(bl.x, tl.x),
                    "{rot} {uu}"
                );
                if rot == 0 {
                    assert_eq!(Some(m), appearance_matrix(&bbox, id, &rect));
                }
            }
        }
    }
}
