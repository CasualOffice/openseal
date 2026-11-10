//! The signature field and its widget (docs/31 §4 step 1; ISO 32000-2 §12.7.5.5,
//! §12.8.1): read what the update must change, then write it.
//!
//! Reading needs the document mutably and the incremental writer borrows it, so a
//! [`Plan`] holds owned copies of every object the update replaces (catalog, AcroForm,
//! field array, page or annotation array, an existing field and its widget); [`apply`]
//! then edits those copies with the new objects' references and replaces them.

use casual_sign_pdf::{
    Admitted, Dictionary, Document, FieldType, IncrementalUpdate, ObjRef, Object, Rect,
};

use crate::error::{RequestProblem, SealError};
use crate::text::{num, text_string};
use crate::{Appearance, Visible};

/// Longest field name accepted, in bytes.
const MAX_FIELD_NAME: usize = 255;
/// Widget flags: Print (4) and Locked (128) (ISO 32000-2 Table 167).
const WIDGET_FLAGS: i64 = 132;
/// AcroForm `/SigFlags`: SignaturesExist (1) and AppendOnly (2).
const SIG_FLAGS: i64 = 3;

pub(crate) fn never() -> bool {
    false
}

/// Where a dictionary or array lives.
#[derive(Debug)]
pub(crate) enum Holder<T> {
    /// Not present.
    Absent,
    /// Inside its parent.
    Direct(T),
    /// Its own object.
    Indirect(u32, T),
}

/// What the new field is.
#[derive(Debug, Clone, Copy)]
pub(crate) struct FieldSpec<'r> {
    /// The partial (and full) name of a new field, or the full name of an existing one.
    pub(crate) name: &'r str,
    /// Where and how to draw it; `None` for an invisible widget on the first page.
    pub(crate) visible: Option<&'r Visible>,
}

#[derive(Debug)]
enum Target {
    New {
        name: Vec<u8>,
        page_num: u32,
        page: Dictionary,
        annots: Holder<Vec<Object>>,
        rect: Rect,
        appearance: Option<Appearance>,
    },
    Existing {
        field_num: u32,
        field: Dictionary,
        /// A separate widget (the first kid) to receive the appearance.
        widget: Option<(u32, Dictionary)>,
        rect: Rect,
        appearance: Option<Appearance>,
    },
}

/// Owned copies of everything the update changes.
#[derive(Debug)]
pub(crate) struct Plan {
    catalog_num: u32,
    catalog: Dictionary,
    acroform: Holder<Dictionary>,
    fields: Holder<Vec<Object>>,
    target: Target,
}

fn structure(num: u32) -> SealError {
    SealError::Request(RequestProblem::Structure(num))
}

/// The dictionary object `num`.
pub(crate) fn dict_object(doc: &mut Document<'_>, num: u32) -> Result<Dictionary, SealError> {
    match doc.object(num, &never)? {
        Object::Dictionary(d) => Ok(d),
        _ => Err(structure(num)),
    }
}

fn dict_holder(
    doc: &mut Document<'_>,
    value: Option<&Object>,
) -> Result<Holder<Dictionary>, SealError> {
    match value {
        None | Some(Object::Null) => Ok(Holder::Absent),
        Some(Object::Dictionary(d)) => Ok(Holder::Direct(d.clone())),
        Some(Object::Reference(r)) => match doc.object(r.num, &never)? {
            Object::Dictionary(d) => Ok(Holder::Indirect(r.num, d)),
            Object::Null => Ok(Holder::Absent),
            _ => Err(structure(r.num)),
        },
        Some(_) => Err(structure(0)),
    }
}

pub(crate) fn array_holder(
    doc: &mut Document<'_>,
    value: Option<&Object>,
) -> Result<Holder<Vec<Object>>, SealError> {
    match value {
        None | Some(Object::Null) => Ok(Holder::Absent),
        Some(Object::Array(a)) => Ok(Holder::Direct(a.clone())),
        Some(Object::Reference(r)) => match doc.object(r.num, &never)? {
            Object::Array(a) => Ok(Holder::Indirect(r.num, a)),
            Object::Null => Ok(Holder::Absent),
            _ => Err(structure(r.num)),
        },
        Some(_) => Err(structure(0)),
    }
}

/// The catalog's object number and dictionary.
pub(crate) fn catalog(doc: &mut Document<'_>) -> Result<(u32, Dictionary), SealError> {
    let root = doc
        .trailer()
        .get(b"Root")
        .and_then(Object::as_ref)
        .ok_or_else(|| structure(0))?;
    Ok((root.num, dict_object(doc, root.num)?))
}

fn rect_ok(r: &Rect) -> bool {
    [r.llx, r.lly, r.urx, r.ury].iter().all(|v| v.is_finite()) && r.urx >= r.llx && r.ury >= r.lly
}

fn read_rect(d: &Dictionary) -> Rect {
    let n = |i: usize| -> f64 {
        match d.get(b"Rect") {
            Some(Object::Array(a)) => a.get(i).and_then(Object::as_f64).unwrap_or(0.0),
            _ => 0.0,
        }
    };
    let (a, b, c, e) = (n(0), n(1), n(2), n(3));
    Rect {
        llx: a.min(c),
        lly: b.min(e),
        urx: a.max(c),
        ury: b.max(e),
    }
}

/// Read what a new signature field (or the signing of an existing one) changes.
pub(crate) fn plan(admitted: &mut Admitted<'_>, spec: FieldSpec<'_>) -> Result<Plan, SealError> {
    let existing = admitted
        .report
        .fields
        .iter()
        .find(|f| f.name == spec.name)
        .cloned();
    let pages: Vec<u32> = admitted.report.pages.iter().map(|p| p.object).collect();
    let doc = &mut admitted.document;
    let (catalog_num, catalog) = catalog(doc)?;
    let acroform = dict_holder(doc, catalog.get(b"AcroForm"))?;
    let fields = match &acroform {
        Holder::Direct(d) | Holder::Indirect(_, d) => array_holder(doc, d.get(b"Fields"))?,
        Holder::Absent => Holder::Absent,
    };
    let appearance = spec.visible.map(|v| v.appearance.clone());

    let target = if let Some(field) = existing {
        if field.field_type != FieldType::Signature {
            return Err(SealError::Request(RequestProblem::FieldNotSignature));
        }
        let field_num = field
            .object
            .ok_or(SealError::Request(RequestProblem::FieldUnsupported))?;
        let dict = dict_object(doc, field_num)?;
        if !matches!(dict.get(b"V"), None | Some(Object::Null)) {
            return Err(SealError::Request(RequestProblem::FieldAlreadySigned));
        }
        let (widget, rect) = if dict.name(b"Subtype") == Some(b"Widget") {
            (None, read_rect(&dict))
        } else {
            let kid = match dict.get(b"Kids") {
                Some(Object::Array(k)) => k.first().and_then(Object::as_ref),
                _ => None,
            }
            .ok_or(SealError::Request(RequestProblem::FieldUnsupported))?;
            let w = dict_object(doc, kid.num)?;
            let rect = read_rect(&w);
            (Some((kid.num, w)), rect)
        };
        Target::Existing {
            field_num,
            field: dict,
            widget,
            rect,
            appearance,
        }
    } else {
        if spec.name.is_empty() || spec.name.len() > MAX_FIELD_NAME || spec.name.contains('.') {
            return Err(SealError::Request(RequestProblem::FieldName));
        }
        let name = text_string(spec.name).map_err(SealError::Request)?;
        let (index, rect) = match spec.visible {
            Some(v) => {
                if !rect_ok(&v.rect) {
                    return Err(SealError::Request(RequestProblem::Rect));
                }
                (v.page, v.rect)
            }
            None => (
                0,
                Rect {
                    llx: 0.0,
                    lly: 0.0,
                    urx: 0.0,
                    ury: 0.0,
                },
            ),
        };
        let page_num = match usize::try_from(index).ok().and_then(|i| pages.get(i)) {
            Some(&n) => n,
            None if pages.is_empty() => return Err(SealError::Request(RequestProblem::NoPages)),
            None => return Err(SealError::Request(RequestProblem::PageOutOfRange)),
        };
        let page = dict_object(doc, page_num)?;
        let annots = array_holder(doc, page.get(b"Annots"))?;
        Target::New {
            name,
            page_num,
            page,
            annots,
            rect,
            appearance,
        }
    };
    Ok(Plan {
        catalog_num,
        catalog,
        acroform,
        fields,
        target,
    })
}

fn name(n: &[u8]) -> Object {
    Object::Name(n.to_vec())
}

fn real(v: f64) -> Object {
    // Whole values as integers; others through `num` so no exponent is ever written.
    let s = num(v);
    match s.parse::<i64>() {
        Ok(i) => Object::Integer(i),
        Err(_) => Object::Real(s.parse().unwrap_or(0.0)),
    }
}

fn rect_array(r: &Rect) -> Object {
    Object::Array(vec![real(r.llx), real(r.lly), real(r.urx), real(r.ury)])
}

/// The normal appearance: a form XObject the size of the widget.
fn appearance_stream(
    u: &mut IncrementalUpdate<'_>,
    rect: &Rect,
    appearance: Option<&Appearance>,
) -> Result<ObjRef, SealError> {
    let (w, h) = (rect.urx - rect.llx, rect.ury - rect.lly);
    let mut d = Dictionary::new();
    d.insert(b"Type", name(b"XObject"));
    d.insert(b"Subtype", name(b"Form"));
    d.insert(
        b"BBox",
        Object::Array(vec![real(0.0), real(0.0), real(w), real(h)]),
    );
    let (resources, content) = match appearance {
        None => (Dictionary::new(), Vec::new()),
        Some(Appearance::Border) => (
            Dictionary::new(),
            format!(
                "q 0 0 0 RG 1 w 0.5 0.5 {} {} re S Q\n",
                num((w - 1.0).max(0.0)),
                num((h - 1.0).max(0.0))
            )
            .into_bytes(),
        ),
        Some(Appearance::Content { content, resources }) => {
            (resources.clone().unwrap_or_default(), content.clone())
        }
    };
    d.insert(b"Resources", Object::Dictionary(resources));
    Ok(u.add_stream(d, content)?)
}

/// Write the field, its widget and appearance, and every object they change, with `/V`
/// pointing at `value`. `perms` adds `/Perms /DocMDP` to the catalog (a certification
/// signature).
pub(crate) fn apply(
    u: &mut IncrementalUpdate<'_>,
    plan: Plan,
    value: ObjRef,
    perms: bool,
) -> Result<(), SealError> {
    let Plan {
        catalog_num,
        mut catalog,
        acroform,
        fields,
        target,
    } = plan;
    let mut catalog_dirty = false;

    let new_field = match target {
        Target::New {
            name: field_name,
            page_num,
            mut page,
            annots,
            rect,
            appearance,
        } => {
            // An invisible widget (zero-size /Rect, no appearance asked for) carries no
            // /AP (ISO 32000-2 §12.5.5 exempts it): a new appearance stream would read
            // as form filling to validators, which DocMDP P=1 forbids (pyHanko 0.38.1
            // does; found with a P=1 B-LTA fixture).
            let invisible = appearance.is_none() && rect.urx <= rect.llx && rect.ury <= rect.lly;
            let ap = if invisible {
                None
            } else {
                Some(appearance_stream(u, &rect, appearance.as_ref())?)
            };
            let mut f = Dictionary::new();
            f.insert(b"Type", name(b"Annot"));
            f.insert(b"Subtype", name(b"Widget"));
            f.insert(b"FT", name(b"Sig"));
            f.insert(b"T", Object::String(field_name));
            f.insert(b"V", Object::Reference(value));
            f.insert(b"F", Object::Integer(WIDGET_FLAGS));
            f.insert(b"Rect", rect_array(&rect));
            f.insert(
                b"P",
                Object::Reference(ObjRef {
                    num: page_num,
                    generation: 0,
                }),
            );
            if let Some(ap) = ap {
                let mut apd = Dictionary::new();
                apd.insert(b"N", Object::Reference(ap));
                f.insert(b"AP", Object::Dictionary(apd));
            }
            let field_ref = u.add(Object::Dictionary(f))?;
            match annots {
                Holder::Absent => {
                    page.insert(b"Annots", Object::Array(vec![Object::Reference(field_ref)]));
                    u.replace(page_num, Object::Dictionary(page))?;
                }
                Holder::Direct(mut a) => {
                    a.push(Object::Reference(field_ref));
                    page.insert(b"Annots", Object::Array(a));
                    u.replace(page_num, Object::Dictionary(page))?;
                }
                Holder::Indirect(n, mut a) => {
                    a.push(Object::Reference(field_ref));
                    u.replace(n, Object::Array(a))?;
                }
            }
            Some(field_ref)
        }
        Target::Existing {
            field_num,
            mut field,
            widget,
            rect,
            appearance,
        } => {
            let ap = match &appearance {
                Some(a) => Some(appearance_stream(u, &rect, Some(a))?),
                None => None,
            };
            field.insert(b"V", Object::Reference(value));
            let set_ap = |d: &mut Dictionary, ap: ObjRef| {
                let mut apd = Dictionary::new();
                apd.insert(b"N", Object::Reference(ap));
                d.insert(b"AP", Object::Dictionary(apd));
            };
            match (widget, ap) {
                (Some((wn, mut w)), Some(ap)) => {
                    set_ap(&mut w, ap);
                    u.replace(wn, Object::Dictionary(w))?;
                }
                (None, Some(ap)) => set_ap(&mut field, ap),
                (_, None) => {}
            }
            u.replace(field_num, Object::Dictionary(field))?;
            None
        }
    };

    // The AcroForm: /Fields gains the new field; /SigFlags gets SignaturesExist and
    // AppendOnly.
    let mut form = match &acroform {
        Holder::Absent => Dictionary::new(),
        Holder::Direct(d) | Holder::Indirect(_, d) => d.clone(),
    };
    let mut form_dirty = matches!(acroform, Holder::Absent);
    if let Some(field_ref) = new_field {
        match fields {
            Holder::Indirect(n, mut a) => {
                a.push(Object::Reference(field_ref));
                u.replace(n, Object::Array(a))?;
            }
            Holder::Direct(mut a) => {
                a.push(Object::Reference(field_ref));
                form.insert(b"Fields", Object::Array(a));
                form_dirty = true;
            }
            Holder::Absent => {
                form.insert(b"Fields", Object::Array(vec![Object::Reference(field_ref)]));
                form_dirty = true;
            }
        }
    }
    let flags = form.get(b"SigFlags").and_then(Object::as_i64).unwrap_or(0);
    if flags & SIG_FLAGS != SIG_FLAGS {
        form.insert(b"SigFlags", Object::Integer(flags | SIG_FLAGS));
        form_dirty = true;
    }
    if form_dirty {
        match acroform {
            Holder::Indirect(n, _) => u.replace(n, Object::Dictionary(form))?,
            Holder::Absent => {
                let r = u.add(Object::Dictionary(form))?;
                catalog.insert(b"AcroForm", Object::Reference(r));
                catalog_dirty = true;
            }
            Holder::Direct(_) => {
                catalog.insert(b"AcroForm", Object::Dictionary(form));
                catalog_dirty = true;
            }
        }
    }

    if perms {
        let mut p = match catalog.get(b"Perms") {
            Some(Object::Dictionary(d)) => d.clone(),
            _ => Dictionary::new(),
        };
        p.insert(b"DocMDP", Object::Reference(value));
        catalog.insert(b"Perms", Object::Dictionary(p));
        catalog_dirty = true;
    }
    if catalog_dirty {
        u.replace(catalog_num, Object::Dictionary(catalog))?;
    }
    Ok(())
}

/// A field name not used by any field of the document: `base` followed by the first
/// free number.
pub(crate) fn free_name(admitted: &Admitted<'_>, base: &str) -> String {
    let mut i: u32 = 1;
    loop {
        let candidate = format!("{base}{i}");
        if !admitted.report.fields.iter().any(|f| f.name == candidate) || i == u32::MAX {
            return candidate;
        }
        i = i.saturating_add(1);
    }
}
