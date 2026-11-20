//! Remote-provider signatures (ADR-046 §3.2): the form a document carries after its lock
//! point, and filling it in place.
//!
//! A remote signature covers every byte before it, and after it only form filling,
//! further signatures and DSS data are changes validators accept; drawing a later
//! signer's values into page content would read as a modified document. So at the lock
//! point, once every value already final is flattened ([`crate::flatten`]),
//! [`materialize`] gives every field still to be filled its own **AcroForm text field**
//! (read-only, printed, with an empty appearance, at the field's rectangle), and each
//! remote signer an **unsigned signature field** at their first signature field's
//! rectangle. Later, [`fill_materialized`] writes values into those fields in place: `/V`
//! and a new normal appearance drawing exactly what flattening would have drawn there
//! (text, a checkmark, the adopted mark), and, for a remote signer about to sign, the
//! appearance of their signature widget (their mark, their name as sent, and "Digitally
//! signed, see the signature panel"). Validators classify both as form filling.
//!
//! Every materialized field is a text field (`/FT /Tx`), whatever it shows: its value is
//! its appearance, and a text field's `/V` and `/AP` changing is form filling to every
//! validator; a checkbox's `/V` is `Yes` or `Off`, a mark's `signed`.

use std::collections::BTreeMap;

use casual_sign_fields::{DisplayRect, PageGeometry};
use casual_sign_model::{Field, FieldValue, Id};
use casual_sign_pdf::{Admitted, Cancel, Change, Dictionary, IncrementalUpdate, Object, Rect};

use crate::canvas::GlyphUse;
use crate::draw::{self, Ctx, Drawing, Drawn};
use crate::error::FlattenError;
use crate::fill::text_string;
use crate::fonts::FontSet;
use crate::read;
use crate::write::{self, name, real};
use crate::{Capture, FlattenOptions, FlattenReport, NotDrawn};

/// Annotation flags: Print (4).
const PRINT: i64 = 4;
/// Field flags: ReadOnly (1).
const READ_ONLY: i64 = 1;

/// The AcroForm name of the field materialized for model field `id`.
#[must_use]
pub fn materialized_name(id: &Id) -> String {
    format!("os_{}", id.as_str())
}

/// An unsigned signature field to create for a remote signer.
#[derive(Debug, Clone)]
pub struct SignatureSlot<'a> {
    /// Its name (no period).
    pub name: &'a str,
    /// Where it shows: the signer's first signature field, or `None` for an invisible
    /// widget on the first page.
    pub at: Option<&'a Field>,
}

fn structure(object: u32) -> FlattenError {
    FlattenError::RemoteForm { object }
}

/// The page index, geometry and user-space rectangle of `field`.
fn place(
    admitted: &Admitted<'_>,
    field: &Field,
) -> Result<(usize, PageGeometry, DisplayRect, Rect), FlattenError> {
    let off = || FlattenError::OffPage {
        field: field.id.clone(),
    };
    let index = usize::try_from(field.placement.page())
        .ok()
        .and_then(|p| p.checked_sub(1))
        .ok_or_else(off)?;
    let info = admitted.report.pages.get(index).ok_or_else(off)?;
    let g = PageGeometry::from_page(info);
    let r = DisplayRect::from_placement(&field.placement);
    if !g.contains(&r, 1.0) {
        return Err(off());
    }
    let user = g.rect_to_user(&r);
    Ok((index, g, r, user))
}

fn rect_object(r: &Rect) -> Object {
    Object::Array(vec![real(r.llx), real(r.lly), real(r.urx), real(r.ury)])
}

/// An unsigned signature field's empty appearance, written as the signature revision
/// will write its widget's (`casual-sign-seal`: no filter, the `/Rect`'s size), so
/// signing changes only its content and resources.
fn empty_slot_appearance(
    u: &mut IncrementalUpdate<'_>,
    rect: &Rect,
) -> Result<Object, FlattenError> {
    let mut d = Dictionary::new();
    d.insert(b"Type", name(b"XObject"));
    d.insert(b"Subtype", name(b"Form"));
    d.insert(
        b"BBox",
        Object::Array(vec![
            real(0.0),
            real(0.0),
            real(rect.urx - rect.llx),
            real(rect.ury - rect.lly),
        ]),
    );
    d.insert(b"Resources", Object::Dictionary(Dictionary::new()));
    Ok(Object::Reference(u.add_stream(d, Vec::new())?))
}

/// The orientation an appearance needs so it reads upright on a rotated page.
fn orientation(g: &PageGeometry, r: &DisplayRect) -> Option<[f64; 6]> {
    let [a, b, c, d, _, _] = crate::flatten::field_matrix(g, r);
    let upright =
        (a - 1.0).abs() < 1e-9 && b.abs() < 1e-9 && c.abs() < 1e-9 && (d - 1.0).abs() < 1e-9;
    (!upright).then_some([a, b, c, d, 0.0, 0.0])
}

/// An empty appearance of `w` × `h`, written as a fill's appearance will be (the same
/// keys, Flate-compressed), so filling changes only its content and resources: EU DSS
/// counts a filter appearing on an appearance stream as an undefined change.
fn empty_appearance(
    u: &mut IncrementalUpdate<'_>,
    w: f64,
    h: f64,
    matrix: Option<[f64; 6]>,
) -> Result<Object, FlattenError> {
    let empty = crate::canvas::Canvas::default();
    Ok(Object::Reference(write::form(
        u,
        &empty,
        w.max(0.0),
        h.max(0.0),
        matrix,
        &BTreeMap::new(),
        &[],
    )?))
}

/// R0's form (ADR-046 §3.2): a read-only text field for each of `fields` and an unsigned
/// signature field for each of `slots`, in one incremental update of `admitted` (whose
/// final values are already flattened). Answers the whole file.
///
/// # Errors
/// `CS-FLD-0004` a field off its page; `CS-FLT-0007` a catalog, form or page that is not
/// the kind of object ISO 32000-2 requires; the writer's `CS-WRT-*` code.
pub fn materialize(
    admitted: &mut Admitted<'_>,
    fields: &[Field],
    slots: &[SignatureSlot<'_>],
    cancel: Cancel<'_>,
) -> Result<Vec<u8>, FlattenError> {
    struct New {
        page: usize,
        dict: Dictionary,
        w: f64,
        h: f64,
        matrix: Option<[f64; 6]>,
        /// A signature slot's widget rectangle.
        slot: Option<Rect>,
    }
    let mut news: Vec<New> = Vec::with_capacity(fields.len().saturating_add(slots.len()));
    for f in fields {
        let (page, g, r, user) = place(admitted, f)?;
        let mut d = Dictionary::new();
        d.insert(b"Type", name(b"Annot"));
        d.insert(b"Subtype", name(b"Widget"));
        d.insert(b"FT", name(b"Tx"));
        d.insert(b"T", Object::String(text_string(&materialized_name(&f.id))));
        d.insert(b"Rect", rect_object(&user));
        d.insert(b"F", Object::Integer(PRINT));
        d.insert(b"Ff", Object::Integer(READ_ONLY));
        d.insert(b"DA", Object::String(b"/Helv 0 Tf 0 g".to_vec()));
        news.push(New {
            page,
            dict: d,
            w: r.width,
            h: r.height,
            matrix: orientation(&g, &r),
            slot: None,
        });
    }
    for s in slots {
        if s.name.is_empty() || s.name.contains('.') || s.name.len() > 255 {
            return Err(structure(0));
        }
        let (page, rect, w, h, matrix) = match s.at {
            Some(f) => {
                let (page, g, r, user) = place(admitted, f)?;
                (page, user, r.width, r.height, orientation(&g, &r))
            }
            None => (
                0,
                Rect {
                    llx: 0.0,
                    lly: 0.0,
                    urx: 0.0,
                    ury: 0.0,
                },
                0.0,
                0.0,
                None,
            ),
        };
        let mut d = Dictionary::new();
        d.insert(b"Type", name(b"Annot"));
        d.insert(b"Subtype", name(b"Widget"));
        d.insert(b"FT", name(b"Sig"));
        d.insert(b"T", Object::String(text_string(s.name)));
        d.insert(b"Rect", rect_object(&rect));
        d.insert(b"F", Object::Integer(PRINT));
        news.push(New {
            page,
            dict: d,
            w,
            h,
            matrix,
            slot: Some(rect),
        });
    }
    let pages = admitted.report.pages.clone();
    if pages.is_empty() {
        return Err(structure(0));
    }
    let doc = &mut admitted.document;
    let (catalog_num, mut catalog) = read::catalog(doc, cancel)?.ok_or_else(|| structure(0))?;
    // The form, kept or new; its fields array resolved.
    let (form_num, mut form) = match catalog.get(b"AcroForm").cloned() {
        None => (None, Dictionary::new()),
        Some(Object::Reference(r)) => (
            Some(r.num),
            read::object_dict(doc, r.num, cancel)?.ok_or_else(|| structure(r.num))?,
        ),
        Some(Object::Dictionary(d)) => (None, d),
        Some(_) => return Err(structure(catalog_num)),
    };
    let (fields_num, mut field_list) = match form.get(b"Fields").cloned() {
        None => (None, Vec::new()),
        Some(Object::Reference(r)) => match read::local(doc.object(r.num, cancel))? {
            Some(Object::Array(a)) => (Some(r.num), a),
            _ => return Err(structure(r.num)),
        },
        Some(Object::Array(a)) => (None, a),
        Some(_) => return Err(structure(form_num.unwrap_or(catalog_num))),
    };
    let mut page_dicts: BTreeMap<usize, (u32, Dictionary, Vec<Object>, Option<u32>)> =
        BTreeMap::new();
    for n in &news {
        if page_dicts.contains_key(&n.page) {
            continue;
        }
        let info = pages.get(n.page).ok_or_else(|| structure(0))?;
        let dict =
            read::object_dict(doc, info.object, cancel)?.ok_or_else(|| structure(info.object))?;
        let (annots, annots_num) = match dict.get(b"Annots").cloned() {
            None => (Vec::new(), None),
            Some(Object::Array(a)) => (a, None),
            Some(Object::Reference(r)) => match read::local(doc.object(r.num, cancel))? {
                Some(Object::Array(a)) => (a, Some(r.num)),
                _ => return Err(structure(r.num)),
            },
            Some(_) => return Err(structure(info.object)),
        };
        page_dicts.insert(n.page, (info.object, dict, annots, annots_num));
    }

    let admitted_ref: &Admitted<'_> = admitted;
    let mut u = IncrementalUpdate::new(admitted_ref, Change::Other)?;
    for n in news {
        let Some((page_num, _, annots, _)) = page_dicts.get_mut(&n.page) else {
            continue;
        };
        let mut d = n.dict;
        d.insert(
            b"P",
            Object::Reference(casual_sign_pdf::ObjRef {
                num: *page_num,
                generation: 0,
            }),
        );
        let mut ap = Dictionary::new();
        let empty = match &n.slot {
            Some(rect) => empty_slot_appearance(&mut u, rect)?,
            None => empty_appearance(&mut u, n.w, n.h, n.matrix)?,
        };
        ap.insert(b"N", empty);
        d.insert(b"AP", Object::Dictionary(ap));
        let r = u.add(Object::Dictionary(d))?;
        annots.push(Object::Reference(r));
        field_list.push(Object::Reference(r));
    }
    for (page_num, mut dict, annots, annots_num) in page_dicts.into_values() {
        match annots_num {
            Some(n) => u.replace(n, Object::Array(annots))?,
            None => {
                dict.insert(b"Annots", Object::Array(annots));
                u.replace(page_num, Object::Dictionary(dict))?;
            }
        }
    }
    match fields_num {
        Some(n) => u.replace(n, Object::Array(field_list))?,
        None => {
            form.insert(b"Fields", Object::Array(field_list));
        }
    }
    // The text fields' default appearance names Helvetica; the form's resources hold it.
    if !form.contains(b"DR") {
        let mut helv = Dictionary::new();
        helv.insert(b"Type", name(b"Font"));
        helv.insert(b"Subtype", name(b"Type1"));
        helv.insert(b"BaseFont", name(b"Helvetica"));
        helv.insert(b"Encoding", name(b"WinAnsiEncoding"));
        let mut fonts = Dictionary::new();
        fonts.insert(b"Helv", Object::Dictionary(helv));
        let mut dr = Dictionary::new();
        dr.insert(b"Font", Object::Dictionary(fonts));
        form.insert(b"DR", Object::Dictionary(dr));
    }
    if !form.contains(b"DA") {
        form.insert(b"DA", Object::String(b"/Helv 0 Tf 0 g".to_vec()));
    }
    match form_num {
        Some(n) => u.replace(n, Object::Dictionary(form))?,
        None => {
            catalog.insert(b"AcroForm", Object::Dictionary(form));
            u.replace(catalog_num, Object::Dictionary(catalog))?;
        }
    }
    Ok(u.finish()?)
}

/// What [`fill_materialized`] draws.
#[derive(Debug, Clone, Copy)]
pub struct FillMaterialized<'a> {
    /// The fields to fill (each materialized at the lock point), with their values.
    pub fields: &'a [Field],
    /// Their values.
    pub values: &'a BTreeMap<Id, FieldValue>,
    /// The captures signature values name.
    pub captures: &'a BTreeMap<Id, Capture>,
    /// The envelope id, for captions.
    pub envelope_id: Option<&'a str>,
    /// A remote signer about to sign: their widget's appearance is drawn in this
    /// revision as an XObject nothing references yet, and the signature revision
    /// attaches it ([`Filled::signature`]), since pyHanko counts an unsigned signature
    /// field's appearance changing in a revision of its own as more than form filling.
    pub signature: Option<SignatureAppearance<'a>>,
}

/// What [`fill_materialized`] wrote.
#[derive(Debug, Clone)]
pub struct Filled {
    /// The input followed by the fill.
    pub bytes: Vec<u8>,
    /// What was filled.
    pub report: FlattenReport,
    /// The remote signer's widget appearance, for their signature revision.
    pub signature: Option<SlotAppearance>,
}

/// A remote signer's widget appearance, written and not yet referenced: the signature
/// revision's widget draws it with `cm` (`q {cm} cm /OsMark Do Q`) in a box of the
/// widget's `/Rect` size.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct SlotAppearance {
    /// The form XObject's object number.
    pub object: u32,
    /// Its generation.
    pub generation: u16,
    /// The matrix placing it in the widget's box.
    pub cm: [f64; 6],
}

impl SlotAppearance {
    /// The widget's content stream: the XObject named `/OsMark`, placed.
    #[must_use]
    pub fn content(&self) -> Vec<u8> {
        let [a, b, c, d, e, f] = self.cm;
        format!("q {a:.6} {b:.6} {c:.6} {d:.6} {e:.4} {f:.4} cm /OsMark Do Q\n").into_bytes()
    }

    /// The widget's resources: `/XObject << /OsMark n g R >>`.
    #[must_use]
    pub fn resources(&self) -> Dictionary {
        let mut x = Dictionary::new();
        x.insert(
            b"OsMark",
            Object::Reference(casual_sign_pdf::ObjRef {
                num: self.object,
                generation: self.generation,
            }),
        );
        let mut r = Dictionary::new();
        r.insert(b"XObject", Object::Dictionary(x));
        r
    }
}

/// The appearance of a remote signer's signature widget (ADR-046 §3.2).
#[derive(Debug, Clone, Copy)]
pub struct SignatureAppearance<'a> {
    /// The unsigned signature field's name.
    pub slot: &'a str,
    /// The signer's first signature field (its rectangle and style).
    pub field: &'a Field,
    /// The adopted mark's capture id (a key of `captures`).
    pub capture: &'a Id,
}

/// The text drawn under a remote signer's mark (fixed wording, ADR-046 §3.2; docs/09
/// §2a: it states a fact and claims no legal status).
pub const REMOTE_CAPTION: &str = "Digitally signed, see the signature panel";

/// The field object of the form field named `name` and its widget's rectangle.
fn find_field(admitted: &mut Admitted<'_>, name_wanted: &str) -> Option<(u32, Rect)> {
    admitted
        .report
        .fields
        .iter()
        .find(|f| f.name == name_wanted)
        .and_then(|f| {
            let rect = f.widgets.first().map(|w| w.rect)?;
            f.object.map(|o| (o, rect))
        })
}

/// Rk's fill (ADR-046 §3.2): each field of `input` with a value gets `/V` and a normal
/// appearance in its materialized form field; the signature slot, when given, gets the
/// signer's mark. One incremental update that changes nothing but form fields, so it
/// classifies as form filling. Answers the whole file and what was filled.
///
/// # Errors
/// `CS-FLT-0007` a field that was not materialized; the drawing's codes (`CS-FLT-0001`
/// a missing glyph, `CS-FLD-0002`, `CS-FLD-0005`); the writer's `CS-WRT-*` code.
pub fn fill_materialized(
    admitted: &mut Admitted<'_>,
    input: &FillMaterialized<'_>,
    fonts: &FontSet,
    options: &FlattenOptions,
    cancel: Cancel<'_>,
) -> Result<Filled, FlattenError> {
    struct Planned {
        object: u32,
        dict: Dictionary,
        drawing: Option<Drawing>,
        w: f64,
        h: f64,
        matrix: Option<[f64; 6]>,
        value: Vec<u8>,
        sets_value: bool,
        /// The widget's user-space size, for a remote signer's slot.
        slot: Option<Rect>,
    }
    let mut report = FlattenReport::default();
    let mut uses = GlyphUse::default();
    let mut planned: Vec<Planned> = Vec::new();
    let mut todo: Vec<(&Field, String, Option<&FieldValue>, Option<&Id>)> = Vec::new();
    for f in input.fields {
        let Some(v) = input.values.get(&f.id) else {
            report.not_drawn.push((f.id.clone(), NotDrawn::NoValue));
            continue;
        };
        todo.push((f, materialized_name(&f.id), Some(v), None));
    }
    if let Some(s) = &input.signature {
        todo.push((s.field, s.slot.to_owned(), None, Some(s.capture)));
    }
    for (f, field_name, value, mark) in todo {
        let (object, widget_rect) =
            find_field(admitted, &field_name).ok_or_else(|| structure(0))?;
        let (_, g, r, _) = place(admitted, f)?;
        let dict = read::object_dict(&mut admitted.document, object, cancel)?
            .ok_or_else(|| structure(object))?;
        let mut ctx = Ctx {
            fonts,
            uses: &mut uses,
            options,
            envelope_id: input.envelope_id,
            captures: input.captures,
        };
        let (drawn, value_text, sets_value) = match (value, mark) {
            (Some(v), _) => {
                let text = match v {
                    FieldValue::Text(t) | FieldValue::Choice(t) => t.as_str().to_owned(),
                    FieldValue::Checked(true) => "Yes".to_owned(),
                    FieldValue::Checked(false) => "Off".to_owned(),
                    FieldValue::Choices(c) => c
                        .as_slice()
                        .iter()
                        .map(|t| t.as_str())
                        .collect::<Vec<_>>()
                        .join("\n"),
                    _ => "signed".to_owned(),
                };
                (draw::field(&mut ctx, f, v, r.width, r.height)?, text, true)
            }
            (None, Some(capture)) => {
                let d = draw::remote_mark(&mut ctx, f, capture, REMOTE_CAPTION, r.width, r.height)?;
                (d, String::new(), false)
            }
            (None, None) => continue,
        };
        let drawing = match drawn {
            Drawn::Marks(d, fit) => {
                if fit.shrunk {
                    report.shrunk.push(f.id.clone());
                }
                if fit.overflow {
                    report.overflow.push(f.id.clone());
                }
                Some(d)
            }
            Drawn::Skip(why) => {
                report.not_drawn.push((f.id.clone(), why));
                None
            }
        };
        if sets_value {
            report.filled.push(f.id.clone());
        } else {
            report.drawn.push(f.id.clone());
        }
        planned.push(Planned {
            object,
            dict,
            drawing,
            w: r.width,
            h: r.height,
            matrix: orientation(&g, &r),
            value: text_string(&value_text),
            sets_value,
            slot: mark.map(|_| widget_rect),
        });
    }
    let admitted_ref: &Admitted<'_> = admitted;
    let mut u = IncrementalUpdate::new(admitted_ref, Change::FillAndSign)?;
    let font_refs = write::fonts(&mut u, fonts, &uses, &mut report.fonts)?;
    let mut signature = None;
    for p in planned {
        let mut d = p.dict;
        let ap = match &p.drawing {
            Some(drawing) => {
                let mut image_refs = Vec::with_capacity(drawing.images.len());
                for img in &drawing.images {
                    image_refs.push(write::image(&mut u, img)?);
                    report.images = report.images.saturating_add(1);
                }
                write::form(
                    &mut u,
                    &drawing.canvas,
                    p.w,
                    p.h,
                    p.matrix,
                    &font_refs,
                    &image_refs,
                )?
            }
            None => {
                let empty = crate::canvas::Canvas::default();
                write::form(&mut u, &empty, p.w, p.h, p.matrix, &font_refs, &[])?
            }
        };
        if let Some(rect) = p.slot {
            // The signature revision attaches it; nothing references it until then.
            let bbox = Rect {
                llx: 0.0,
                lly: 0.0,
                urx: p.w,
                ury: p.h,
            };
            let to = Rect {
                llx: 0.0,
                lly: 0.0,
                urx: rect.urx - rect.llx,
                ury: rect.ury - rect.lly,
            };
            let m = p.matrix.unwrap_or([1.0, 0.0, 0.0, 1.0, 0.0, 0.0]);
            let cm = crate::flatten::appearance_matrix(&bbox, m, &to)
                .ok_or_else(|| structure(p.object))?;
            signature = Some(SlotAppearance {
                object: ap.num,
                generation: ap.generation,
                cm,
            });
            continue;
        }
        let mut apd = Dictionary::new();
        apd.insert(b"N", Object::Reference(ap));
        d.insert(b"AP", Object::Dictionary(apd));
        if p.sets_value {
            d.insert(b"V", Object::String(p.value));
        }
        u.replace(p.object, Object::Dictionary(d))?;
    }
    let bytes = u.finish()?;
    Ok(Filled {
        bytes,
        report,
        signature,
    })
}
