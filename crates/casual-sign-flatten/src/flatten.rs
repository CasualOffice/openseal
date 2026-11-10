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
                if let Some(info) = read::widget(doc, obj, w.rect, page, cancel)? {
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

    // Pages to rewrite: those drawn on, and every page with widgets when the form goes.
    let mut touched: BTreeSet<usize> = placed.iter().map(|p| p.page).collect();
    touched.extend(kept.iter().map(|k| k.page));
    if remove_form {
        touched.extend(0..pages.len());
    }
    struct PageEdit {
        object: u32,
        dict: Dictionary,
        resources: Dictionary,
        contents: Vec<Object>,
        draws: bool,
        annots_changed: bool,
    }
    let drawn_pages: BTreeSet<usize> = placed
        .iter()
        .map(|p| p.page)
        .chain(kept.iter().map(|k| k.page))
        .collect();
    let mut edits: BTreeMap<usize, PageEdit> = BTreeMap::new();
    for &index in &touched {
        let Some(info) = pages.get(index) else {
            continue;
        };
        let Some(mut dict) = read::object_dict(doc, info.object, cancel)? else {
            continue;
        };
        let draws = drawn_pages.contains(&index);
        let mut annots_changed = false;
        if remove_form && let Some(a) = dict.get(b"Annots").cloned() {
            let items = match read::local(doc.resolve(&a, cancel))? {
                Some(Object::Array(items)) => items,
                _ => Vec::new(),
            };
            let mut kept_items = Vec::with_capacity(items.len());
            for (i, item) in items.into_iter().enumerate() {
                if i >= MAX_ANNOTS {
                    kept_items.push(item);
                    continue;
                }
                let is_widget = read::dict(doc, &item, cancel)?
                    .is_some_and(|d| d.name(b"Subtype") == Some(b"Widget"));
                if is_widget {
                    report.widgets_removed = report.widgets_removed.saturating_add(1);
                    annots_changed = true;
                } else {
                    kept_items.push(item);
                }
            }
            if annots_changed {
                if kept_items.is_empty() {
                    dict.remove(b"Annots");
                } else {
                    dict.insert(b"Annots", Object::Array(kept_items));
                }
            }
        }
        if !draws && !annots_changed {
            continue;
        }
        let (resources, contents) = if draws {
            (
                read::resources(doc, &dict, cancel)?,
                read::contents(doc, &dict, cancel)?,
            )
        } else {
            (Dictionary::new(), Vec::new())
        };
        edits.insert(
            index,
            PageEdit {
                object: info.object,
                dict,
                resources,
                contents,
                draws,
                annots_changed,
            },
        );
    }

    // ---- write ----------------------------------------------------------------------
    let change = if placed.is_empty() && kept.is_empty() && !remove_form {
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
        } else if !edit.annots_changed {
            continue;
        }
        u.replace(edit.object, Object::Dictionary(dict))?;
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

    // The catalog: the form removed, or told to use our appearances.
    if let Some((root, mut cat)) = catalog {
        if remove_form {
            cat.remove(b"AcroForm");
            u.replace(root, Object::Dictionary(cat))?;
            report.acroform_removed = true;
        } else if let Some((num, form)) = acroform_edit {
            match num {
                Some(n) => u.replace(n, Object::Dictionary(form))?,
                None => {
                    cat.insert(b"AcroForm", Object::Dictionary(form));
                    u.replace(root, Object::Dictionary(cat))?;
                }
            }
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
}
