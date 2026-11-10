//! What flattening reads from the document before it writes: pages, resources,
//! annotations, the AcroForm and its widgets. A local failure (one damaged object) is
//! treated as absent; the budget, memory and cancellation end the whole run.

use casual_sign_pdf::{Cancel, Dictionary, Document, ObjRef, Object, PdfError, Rect};

/// Most `/Parent` hops followed for inherited attributes.
const MAX_PARENT_HOPS: usize = 32;
/// Most annotations read from one page. A decision of `T-1E`; more are kept as they
/// are, unread.
pub(crate) const MAX_ANNOTS: usize = 10_000;

fn fatal(e: &PdfError) -> bool {
    matches!(
        e,
        PdfError::DecodeBudget { .. } | PdfError::Cancelled | PdfError::OutOfMemory
    )
}

/// `Ok(None)` for a local failure, `Err` for a fatal one.
pub(crate) fn local<T>(r: Result<T, PdfError>) -> Result<Option<T>, PdfError> {
    match r {
        Ok(v) => Ok(Some(v)),
        Err(e) if fatal(&e) => Err(e),
        Err(_) => Ok(None),
    }
}

/// Resolve `value` to a dictionary (a stream's dictionary counts).
pub(crate) fn dict(
    doc: &mut Document<'_>,
    value: &Object,
    cancel: Cancel<'_>,
) -> Result<Option<Dictionary>, PdfError> {
    Ok(local(doc.resolve(value, cancel))?.and_then(|o| o.dict().cloned()))
}

/// Object `num` as a dictionary.
pub(crate) fn object_dict(
    doc: &mut Document<'_>,
    num: u32,
    cancel: Cancel<'_>,
) -> Result<Option<Dictionary>, PdfError> {
    Ok(local(doc.object(num, cancel))?.and_then(|o| o.dict().cloned()))
}

/// The catalog's object number and dictionary.
pub(crate) fn catalog(
    doc: &mut Document<'_>,
    cancel: Cancel<'_>,
) -> Result<Option<(u32, Dictionary)>, PdfError> {
    let Some(root) = doc.trailer().get(b"Root").and_then(Object::as_ref) else {
        return Ok(None);
    };
    Ok(object_dict(doc, root.num, cancel)?.map(|d| (root.num, d)))
}

/// A page's resources, inherited through `/Parent` when the page has none, with the
/// `/XObject` and `/Font` subdictionaries resolved to direct ones.
pub(crate) fn resources(
    doc: &mut Document<'_>,
    page: &Dictionary,
    cancel: Cancel<'_>,
) -> Result<Dictionary, PdfError> {
    let mut cur = page.clone();
    let mut found = None;
    for _ in 0..MAX_PARENT_HOPS {
        if let Some(r) = cur.get(b"Resources").cloned() {
            found = dict(doc, &r, cancel)?;
            break;
        }
        let Some(parent) = cur.get(b"Parent").cloned() else {
            break;
        };
        match dict(doc, &parent, cancel)? {
            Some(p) => cur = p,
            None => break,
        }
    }
    let mut res = found.unwrap_or_default();
    for key in [&b"XObject"[..], b"Font", b"ExtGState"] {
        if let Some(v) = res.get(key).cloned() {
            let d = dict(doc, &v, cancel)?.unwrap_or_default();
            res.insert(key, Object::Dictionary(d));
        }
    }
    Ok(res)
}

/// A page's `/Contents` as a list of references (direct streams cannot occur).
pub(crate) fn contents(
    doc: &mut Document<'_>,
    page: &Dictionary,
    cancel: Cancel<'_>,
) -> Result<Vec<Object>, PdfError> {
    Ok(match page.get(b"Contents") {
        Some(Object::Reference(r)) => match local(doc.object(r.num, cancel))? {
            // An indirect array of streams.
            Some(Object::Array(a)) => a,
            _ => vec![Object::Reference(*r)],
        },
        Some(Object::Array(a)) => a.clone(),
        _ => Vec::new(),
    })
}

/// A rectangle from a four-number array, normalized.
pub(crate) fn rect(value: Option<&Object>) -> Option<Rect> {
    let Some(Object::Array(a)) = value else {
        return None;
    };
    let n: Vec<f64> = a.iter().filter_map(Object::as_f64).collect();
    let [x0, y0, x1, y1] = n.as_slice() else {
        return None;
    };
    let r = Rect {
        llx: x0.min(*x1),
        lly: y0.min(*y1),
        urx: x0.max(*x1),
        ury: y0.max(*y1),
    };
    [r.llx, r.lly, r.urx, r.ury]
        .iter()
        .all(|v| v.is_finite())
        .then_some(r)
}

/// A colour array from `/MK` (`/BG`, `/BC`): gray, RGB or CMYK, as RGB fractions.
pub(crate) fn mk_color(value: Option<&Object>) -> Option<[f64; 3]> {
    let Some(Object::Array(a)) = value else {
        return None;
    };
    let n: Vec<f64> = a
        .iter()
        .filter_map(Object::as_f64)
        .map(|v| v.clamp(0.0, 1.0))
        .collect();
    match n.as_slice() {
        [g] => Some([*g, *g, *g]),
        [r, g, b] => Some([*r, *g, *b]),
        [c, m, y, k] => Some([
            (1.0 - c) * (1.0 - k),
            (1.0 - m) * (1.0 - k),
            (1.0 - y) * (1.0 - k),
        ]),
        _ => None,
    }
}

/// Field attributes, inherited through `/Parent` (ISO 32000-2 §12.7.4).
#[derive(Debug, Clone, Default)]
pub(crate) struct FieldAttrs {
    pub ft: Option<Vec<u8>>,
    pub ff: i64,
    pub da: Option<Vec<u8>>,
    pub q: Option<i64>,
    pub max_len: Option<u32>,
    pub opt: Option<Vec<Object>>,
}

/// Read inherited attributes starting from `start` (a field or a merged widget).
pub(crate) fn field_attrs(
    doc: &mut Document<'_>,
    start: &Dictionary,
    cancel: Cancel<'_>,
) -> Result<FieldAttrs, PdfError> {
    let mut out = FieldAttrs::default();
    let mut ff = None;
    let mut cur = Some(start.clone());
    let mut seen: Vec<u32> = Vec::new();
    for _ in 0..MAX_PARENT_HOPS {
        let Some(d) = cur.take() else { break };
        if out.ft.is_none() {
            out.ft = d.name(b"FT").map(<[u8]>::to_vec);
        }
        if ff.is_none() {
            ff = d.get(b"Ff").and_then(Object::as_i64);
        }
        if out.da.is_none()
            && let Some(Object::String(s)) = d.get(b"DA")
        {
            out.da = Some(s.clone());
        }
        if out.q.is_none() {
            out.q = d.get(b"Q").and_then(Object::as_i64);
        }
        if out.max_len.is_none() {
            out.max_len = d
                .get(b"MaxLen")
                .and_then(Object::as_i64)
                .and_then(|v| u32::try_from(v).ok())
                .filter(|v| *v > 0 && *v <= 1_000);
        }
        if out.opt.is_none()
            && let Some(o) = d.get(b"Opt").cloned()
            && let Some(Object::Array(a)) = local(doc.resolve(&o, cancel))?
        {
            out.opt = Some(a);
        }
        let Some(parent) = d.get(b"Parent").and_then(Object::as_ref) else {
            break;
        };
        if seen.contains(&parent.num) {
            break;
        }
        seen.push(parent.num);
        cur = object_dict(doc, parent.num, cancel)?;
    }
    out.ff = ff.unwrap_or(0);
    Ok(out)
}

/// What flattening and filling need of one widget.
#[derive(Debug, Clone)]
pub(crate) struct WidgetInfo {
    pub object: u32,
    pub dict: Dictionary,
    pub rect: Rect,
    /// Zero-based page index.
    pub page: Option<u32>,
    /// The normal appearance: a stream reference, or a dictionary of states.
    pub ap_n: Option<Object>,
    /// State names of the normal appearance, other than `Off`.
    pub on_states: Vec<Vec<u8>>,
    pub hidden: bool,
}

/// Read a widget.
pub(crate) fn widget(
    doc: &mut Document<'_>,
    object: u32,
    rect: Rect,
    page: Option<u32>,
    cancel: Cancel<'_>,
) -> Result<Option<WidgetInfo>, PdfError> {
    let Some(d) = object_dict(doc, object, cancel)? else {
        return Ok(None);
    };
    let flags = d.get(b"F").and_then(Object::as_i64).unwrap_or(0);
    // Hidden (bit 2) and NoView (bit 6).
    let hidden = flags & (1 << 1) != 0 || flags & (1 << 5) != 0;
    let mut ap_n = None;
    let mut on_states = Vec::new();
    if let Some(ap) = d.get(b"AP").cloned()
        && let Some(ap) = dict(doc, &ap, cancel)?
        && let Some(n) = ap.get(b"N").cloned()
    {
        match &n {
            Object::Reference(r) => match local(doc.object(r.num, cancel))? {
                Some(Object::Stream(_)) => ap_n = Some(n.clone()),
                Some(Object::Dictionary(states)) => {
                    on_states = states
                        .iter()
                        .filter(|(k, _)| *k != b"Off")
                        .map(|(k, _)| k.to_vec())
                        .collect();
                    ap_n = Some(Object::Dictionary(states));
                }
                _ => {}
            },
            Object::Dictionary(states) => {
                on_states = states
                    .iter()
                    .filter(|(k, _)| *k != b"Off")
                    .map(|(k, _)| k.to_vec())
                    .collect();
                ap_n = Some(n.clone());
            }
            _ => {}
        }
    }
    Ok(Some(WidgetInfo {
        object,
        dict: d,
        rect,
        page,
        ap_n,
        on_states,
        hidden,
    }))
}

/// The appearance stream a widget shows now: `/AP /N`, or its `/AS` state.
pub(crate) fn current_appearance(w: &WidgetInfo) -> Option<ObjRef> {
    match &w.ap_n {
        Some(Object::Reference(r)) => Some(*r),
        Some(Object::Dictionary(states)) => {
            let state = w.dict.name(b"AS")?;
            states.get(state).and_then(Object::as_ref)
        }
        _ => None,
    }
}

/// The appearance stream an annotation shows now: its `/AP /N` stream, or the entry of
/// its `/AP /N` state dictionary that `/AS` names.
pub(crate) fn annotation_appearance(
    doc: &mut Document<'_>,
    d: &Dictionary,
    cancel: Cancel<'_>,
) -> Result<Option<ObjRef>, PdfError> {
    let Some(ap) = d.get(b"AP").cloned() else {
        return Ok(None);
    };
    let Some(n) = dict(doc, &ap, cancel)?.and_then(|ap| ap.get(b"N").cloned()) else {
        return Ok(None);
    };
    let states = match &n {
        Object::Reference(r) => match local(doc.object(r.num, cancel))? {
            Some(Object::Stream(_)) => return Ok(Some(*r)),
            Some(Object::Dictionary(states)) => states,
            _ => return Ok(None),
        },
        Object::Dictionary(states) => states.clone(),
        _ => return Ok(None),
    };
    Ok(d.name(b"AS")
        .and_then(|s| states.get(s))
        .and_then(Object::as_ref))
}

/// `/BBox` and `/Matrix` of a form XObject.
pub(crate) fn form_box(
    doc: &mut Document<'_>,
    r: ObjRef,
    cancel: Cancel<'_>,
) -> Result<Option<(Rect, [f64; 6])>, PdfError> {
    let Some(Object::Stream(s)) = local(doc.object(r.num, cancel))? else {
        return Ok(None);
    };
    let Some(bbox) = rect(s.dict.get(b"BBox")) else {
        return Ok(None);
    };
    let mut m = [1.0, 0.0, 0.0, 1.0, 0.0, 0.0];
    if let Some(Object::Array(a)) = s.dict.get(b"Matrix") {
        let v: Vec<f64> = a.iter().filter_map(Object::as_f64).collect();
        if let [a, b, c, d, e, f] = v.as_slice()
            && v.iter().all(|x| x.is_finite())
        {
            m = [*a, *b, *c, *d, *e, *f];
        }
    }
    Ok(Some((bbox, m)))
}
