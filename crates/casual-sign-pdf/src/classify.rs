//! Classification: one pass over every object for active content and carriers, the
//! page walk, content-stream operator counts, AcroForm fields, signatures, and the
//! admission report (docs/30 §2).

use std::collections::{BTreeMap, BTreeSet};

use crate::Cancel;
use crate::document::Document;
use crate::error::{PdfError, Result};
use crate::lexer::{Lexer, Tok};
use crate::object::{Dictionary, Object};
use crate::pages::{self, Page};
use crate::report::{
    ActionInfo, ActionKind, AdmissionReport, ChoiceOption, FieldType, Finding, FindingKind,
    FormField, MAX_FIELD_OPTIONS, PdfVersion, SignatureInfo, SignatureKind, Widget,
    counts_as_signed,
};
use crate::text;

/// What the object pass collects.
#[derive(Debug, Default)]
struct Inventory {
    actions: Vec<ActionInfo>,
    /// Objects referenced from `/OpenAction` or an `/AA` dictionary.
    automatic: BTreeSet<u32>,
    embedded: BTreeSet<u32>,
    rich_media: BTreeSet<u32>,
    external_streams: BTreeSet<u32>,
    /// Signature dictionaries (`/Type /Sig` or `/DocTimeStamp` with `/ByteRange`).
    sig_values: BTreeSet<u32>,
}

pub(crate) fn action_kind(s: &[u8]) -> Option<ActionKind> {
    Some(match s {
        b"JavaScript" => ActionKind::JavaScript,
        b"Launch" => ActionKind::Launch,
        b"GoToR" => ActionKind::GoToR,
        b"GoToE" => ActionKind::GoToE,
        b"URI" => ActionKind::Uri,
        b"SubmitForm" => ActionKind::SubmitForm,
        b"ImportData" => ActionKind::ImportData,
        b"Rendition" | b"Movie" | b"Sound" | b"RichMediaExecute" => ActionKind::Multimedia,
        _ => return None,
    })
}

/// True when an `/EF` value is a file specification's embedded-file dictionary
/// (§7.11.4). Usage-rights transform parameters also have an `/EF` key, an array of
/// rights names (§12.8.2.3), which carries no file (`PDF-REAL-02`).
pub(crate) fn is_file_ef(v: &Object) -> bool {
    matches!(v, Object::Dictionary(_) | Object::Reference(_))
}

/// Inspect one object's value tree (already depth-capped by the parser).
fn inspect(obj: &Object, num: u32, inv: &mut Inventory) {
    if let Object::Stream(s) = obj
        && s.dict.contains(b"F")
    {
        inv.external_streams.insert(num);
    }
    let mut stack: Vec<(&Object, bool)> = vec![(obj, false)];
    while let Some((value, auto)) = stack.pop() {
        let dict: &Dictionary = match value {
            Object::Dictionary(d) => d,
            Object::Stream(s) => &s.dict,
            Object::Array(a) => {
                stack.extend(a.iter().map(|v| (v, auto)));
                continue;
            }
            Object::Reference(r) => {
                if auto {
                    inv.automatic.insert(r.num);
                }
                continue;
            }
            _ => continue,
        };
        let kind = dict
            .name(b"S")
            .and_then(action_kind)
            .or_else(|| dict.contains(b"JS").then_some(ActionKind::JavaScript));
        if let Some(kind) = kind {
            inv.actions.push(ActionInfo {
                object: num,
                kind,
                automatic: auto,
            });
        }
        if dict.contains(b"JavaScript") {
            // The document-level JavaScript name tree (§7.7.4).
            inv.actions.push(ActionInfo {
                object: num,
                kind: ActionKind::JavaScript,
                automatic: true,
            });
        }
        let ty = dict.name(b"Type");
        let subtype = dict.name(b"Subtype");
        if ty == Some(b"EmbeddedFile")
            || dict.get(b"EF").is_some_and(is_file_ef)
            || dict.contains(b"EmbeddedFiles")
        {
            inv.embedded.insert(num);
        }
        if matches!(subtype, Some(b"RichMedia" | b"3D"))
            || matches!(ty, Some(b"3D" | b"RichMediaContent"))
        {
            inv.rich_media.insert(num);
        }
        if matches!(ty, Some(b"Sig" | b"DocTimeStamp")) && dict.contains(b"ByteRange") {
            inv.sig_values.insert(num);
        }
        for (k, v) in dict.iter() {
            let child_auto = auto || k == b"AA" || k == b"OpenAction";
            stack.push((v, child_auto));
        }
    }
}

/// Handle an error local to one object: a finding when lenient, else the error.
fn local(
    doc: &mut Document<'_>,
    e: PdfError,
    object: Option<u32>,
    page: Option<u32>,
    strict: bool,
) -> Result<()> {
    if strict || e.is_document_wide() {
        return Err(e);
    }
    doc.findings.push(Finding::limit(&e, object, page));
    Ok(())
}

/// Every in-use object, parsed once, inspected, then dropped.
fn object_pass(doc: &mut Document<'_>, strict: bool, cancel: Cancel<'_>) -> Result<Inventory> {
    let mut inv = Inventory::default();
    let nums: Vec<u32> = doc.object_numbers().collect();
    for num in nums {
        let obj = match doc.object(num, cancel) {
            Ok(o) => o,
            // Here a stream is decoded only to read an object stream: one that cannot be
            // decoded within the limits loses objects the document may need.
            Err(
                e @ (PdfError::StreamTooLarge { .. }
                | PdfError::DecodeRatio { .. }
                | PdfError::UnsupportedFilter { .. }
                | PdfError::FilterChainTooLong { .. }),
            ) => return Err(e),
            Err(e) => {
                local(doc, e, Some(num), None, strict)?;
                continue;
            }
        };
        // A bare reference: the chain from this object is what may be too long.
        if let Object::Reference(_) = obj
            && let Err(e) = doc.resolve(&obj, cancel)
        {
            let e = match e {
                PdfError::ReferenceTooDeep { .. } => PdfError::ReferenceTooDeep { object: num },
                other => other,
            };
            local(doc, e, Some(num), None, strict)?;
        }
        inspect(&obj, num, &mut inv);
    }
    let auto = inv.automatic.clone();
    for a in &mut inv.actions {
        if auto.contains(&a.object) {
            a.automatic = true;
        }
    }
    Ok(inv)
}

/// Count content-stream operators, skipping inline image data.
fn count_ops(data: &[u8], limit: u32, max_string: usize, cancel: Cancel<'_>) -> Result<u32> {
    let mut lx = Lexer::new(data, 0, max_string, usize::MAX, true);
    let mut ops: u32 = 0;
    let mut steps: u32 = 0;
    loop {
        steps = steps.wrapping_add(1);
        if steps.is_multiple_of(65_536) && cancel() {
            return Err(PdfError::Cancelled);
        }
        let at = lx.pos;
        match lx.next_tok() {
            Ok(None) => break,
            Ok(Some(Tok::Kw(k))) => {
                if matches!(k, b"true" | b"false" | b"null") {
                    continue;
                }
                ops = ops.saturating_add(1);
                if ops > limit {
                    return Ok(ops);
                }
                if k == b"ID" {
                    skip_inline_image(&mut lx);
                }
            }
            Ok(Some(_)) => {}
            Err(_) => lx.pos = lx.pos.max(at.saturating_add(1)),
        }
    }
    Ok(ops)
}

/// After `ID`: skip to the `EI` that ends the image, as [`crate::ContentLexer`] does.
fn skip_inline_image(lx: &mut Lexer<'_>) {
    lx.pos = crate::content::inline_image_end(lx.b, lx.pos.saturating_add(1)).1;
}

/// Operator counts per page; each content stream decoded once.
fn content_pass(
    doc: &mut Document<'_>,
    pages: &[Page],
    strict: bool,
    cancel: Cancel<'_>,
) -> Result<()> {
    let limits = *doc.limits();
    let max_string = usize::try_from(limits.max_string_bytes).unwrap_or(usize::MAX);
    let mut counted: BTreeMap<u32, Option<u32>> = BTreeMap::new();
    for (index, page) in pages.iter().enumerate() {
        let page_no = u32::try_from(index).unwrap_or(u32::MAX);
        let refs: Vec<u32> = match &page.contents {
            Some(Object::Reference(r)) => match doc.object(r.num, cancel) {
                Ok(Object::Array(a)) => {
                    a.iter().filter_map(Object::as_ref).map(|r| r.num).collect()
                }
                _ => vec![r.num],
            },
            Some(Object::Array(a)) => a.iter().filter_map(Object::as_ref).map(|r| r.num).collect(),
            _ => Vec::new(),
        };
        let mut total: u32 = 0;
        for num in refs {
            let ops = match counted.get(&num) {
                Some(c) => *c,
                None => {
                    let c = match doc.decode_stream(num, cancel) {
                        Ok(data) => Some(count_ops(
                            &data,
                            limits.max_content_ops,
                            max_string,
                            cancel,
                        )?),
                        Err(e) => {
                            local(doc, e, Some(num), Some(page_no), strict)?;
                            None
                        }
                    };
                    counted.insert(num, c);
                    c
                }
            };
            total = total.saturating_add(ops.unwrap_or(0));
        }
        if total > limits.max_content_ops {
            local(
                doc,
                PdfError::TooManyContentOps { page: page_no },
                None,
                Some(page_no),
                strict,
            )?;
        }
    }
    Ok(())
}

/// A field still to visit: the field, its parent's full name, the inherited `/FT` and
/// `/Ff`, and its depth.
type FieldFrame = (Object, String, Inherit, usize);

/// What a field inherits from its ancestors (ISO 32000-2 §12.7.4.1).
#[derive(Debug, Clone, Default)]
struct Inherit {
    ft: Option<Vec<u8>>,
    ff: i64,
    max_len: Option<u32>,
    opt: Option<Vec<Object>>,
}

/// A choice field's `/Opt` entries: a text string, or an `[export display]` pair. At
/// most [`MAX_FIELD_OPTIONS`].
fn choice_options(
    doc: &mut Document<'_>,
    opt: &[Object],
    cancel: Cancel<'_>,
) -> Result<Vec<ChoiceOption>> {
    let mut out = Vec::new();
    for o in opt.iter().take(MAX_FIELD_OPTIONS) {
        let o = match doc.resolve(o, cancel) {
            Ok(o) => o,
            Err(e) if e.is_document_wide() => return Err(e),
            Err(_) => continue,
        };
        let text = |doc: &mut Document<'_>, v: Option<&Object>| -> Result<Option<String>> {
            Ok(match v.map(|v| doc.resolve(v, cancel)) {
                Some(Ok(Object::String(s))) => Some(text::decode(&s)),
                Some(Err(e)) if e.is_document_wide() => return Err(e),
                _ => None,
            })
        };
        let pair = match &o {
            Object::String(s) => {
                let t = text::decode(s);
                Some((t.clone(), t))
            }
            Object::Array(p) => match (text(doc, p.first())?, text(doc, p.get(1))?) {
                (Some(e), Some(d)) => Some((e, d)),
                (Some(e), None) => Some((e.clone(), e)),
                _ => None,
            },
            _ => None,
        };
        if let Some((export, display)) = pair {
            out.push(ChoiceOption { export, display });
        }
    }
    Ok(out)
}

/// Fields under the AcroForm, terminal fields only.
fn form_fields(
    doc: &mut Document<'_>,
    acroform: &Dictionary,
    page_index: &BTreeMap<u32, u32>,
    strict: bool,
    cancel: Cancel<'_>,
) -> Result<(Vec<FormField>, Vec<SignatureInfo>)> {
    let mut fields = Vec::new();
    let mut sigs = Vec::new();
    let roots = match acroform.get(b"Fields") {
        Some(f) => match doc.resolve(f, cancel) {
            Ok(Object::Array(a)) => a,
            Ok(_) => Vec::new(),
            Err(e) => {
                local(doc, e, None, None, strict)?;
                Vec::new()
            }
        },
        None => Vec::new(),
    };
    let max_depth = usize::from(doc.limits().max_depth);
    let mut visited: BTreeSet<u32> = BTreeSet::new();
    let mut stack: Vec<FieldFrame> = roots
        .into_iter()
        .rev()
        .map(|o| (o, String::new(), Inherit::default(), 0))
        .collect();
    while let Some((node, parent, inherit, depth)) = stack.pop() {
        if cancel() {
            return Err(PdfError::Cancelled);
        }
        let num = node.as_ref().map(|r| r.num);
        if let Some(n) = num
            && !visited.insert(n)
        {
            continue;
        }
        if depth > max_depth {
            local(doc, PdfError::TooDeep { offset: 0 }, num, None, strict)?;
            continue;
        }
        let dict = match doc.resolve(&node, cancel) {
            Ok(Object::Dictionary(d)) => d,
            Ok(_) => continue,
            Err(e) => {
                local(doc, e, num, None, strict)?;
                continue;
            }
        };
        let name = match dict.get(b"T") {
            Some(Object::String(t)) => {
                let part = text::decode(t);
                if parent.is_empty() {
                    part
                } else {
                    format!("{parent}.{part}")
                }
            }
            _ => parent.clone(),
        };
        let ft = dict.name(b"FT").map(<[u8]>::to_vec).or(inherit.ft);
        let int = |doc: &mut Document<'_>, key: &[u8]| {
            dict.get(key)
                .and_then(|v| doc.resolve(v, cancel).ok())
                .and_then(|o| o.as_i64())
        };
        let ff = int(doc, b"Ff").unwrap_or(inherit.ff);
        let max_len = int(doc, b"MaxLen")
            .and_then(|v| u32::try_from(v).ok())
            .filter(|v| *v > 0)
            .or(inherit.max_len);
        let opt = match dict.get(b"Opt").map(|o| doc.resolve(o, cancel)) {
            Some(Ok(Object::Array(a))) => Some(a),
            _ => inherit.opt,
        };
        let kids = match dict.get(b"Kids") {
            Some(k) => match doc.resolve(k, cancel) {
                Ok(Object::Array(a)) => a,
                _ => Vec::new(),
            },
            None => Vec::new(),
        };
        // Kids with /T are child fields; kids without are this field's widgets.
        let mut widgets = Vec::new();
        let mut child_fields = Vec::new();
        for k in kids {
            let kd = match doc.resolve(&k, cancel) {
                Ok(Object::Dictionary(d)) => d,
                Ok(_) => continue,
                Err(e) => {
                    local(doc, e, k.as_ref().map(|r| r.num), None, strict)?;
                    continue;
                }
            };
            if kd.contains(b"T") || kd.contains(b"Kids") {
                child_fields.push(k);
            } else if let Some(w) = widget(doc, k.as_ref().map(|r| r.num), &kd, page_index, cancel)?
            {
                widgets.push(w);
            }
        }
        if !child_fields.is_empty() {
            let next = depth.saturating_add(1);
            let inherit = Inherit {
                ft,
                ff,
                max_len,
                opt,
            };
            for k in child_fields.into_iter().rev() {
                stack.push((k, name.clone(), inherit.clone(), next));
            }
            continue;
        }
        if dict.contains(b"Rect")
            && let Some(w) = widget(doc, num, &dict, page_index, cancel)?
        {
            widgets.push(w);
        }
        let field_type = match ft.as_deref() {
            Some(b"Tx") => FieldType::Text,
            Some(b"Ch") => FieldType::Choice,
            Some(b"Sig") => FieldType::Signature,
            Some(b"Btn") if ff & (1 << 16) != 0 => FieldType::PushButton,
            Some(b"Btn") if ff & (1 << 15) != 0 => FieldType::Radio,
            Some(b"Btn") => FieldType::CheckBox,
            _ => FieldType::Unknown,
        };
        if field_type == FieldType::Signature
            && let Some(v) = dict.get(b"V")
        {
            let value = v.as_ref().map(|r| r.num);
            let (sub_filter, kind) = match doc.resolve(v, cancel) {
                Ok(Object::Dictionary(d)) => (
                    d.name(b"SubFilter")
                        .map(|s| String::from_utf8_lossy(s).into_owned()),
                    value_kind(&d),
                ),
                _ => (None, SignatureKind::Approval),
            };
            if *v != Object::Null {
                sigs.push(SignatureInfo {
                    field: num,
                    value,
                    sub_filter,
                    kind,
                });
            }
        }
        let options = match &opt {
            Some(o) => choice_options(doc, o, cancel)?,
            None => Vec::new(),
        };
        fields.push(FormField {
            object: num,
            name,
            field_type,
            widgets,
            flags: u32::try_from(ff & 0xFFFF_FFFF).unwrap_or(0),
            max_len,
            options,
        });
    }
    Ok((fields, sigs))
}

fn widget(
    doc: &mut Document<'_>,
    object: Option<u32>,
    d: &Dictionary,
    page_index: &BTreeMap<u32, u32>,
    cancel: Cancel<'_>,
) -> Result<Option<Widget>> {
    let Some(r) = d.get(b"Rect") else {
        return Ok(None);
    };
    let rect = match pages::rect(doc, r, cancel) {
        Ok(Some(rect)) => rect,
        Ok(None) => return Ok(None),
        Err(e) if e.is_document_wide() => return Err(e),
        Err(_) => return Ok(None),
    };
    let page = d
        .get(b"P")
        .and_then(Object::as_ref)
        .and_then(|p| page_index.get(&p.num).copied());
    let appearance_states = appearance_states(doc, d, cancel)?;
    Ok(Some(Widget {
        object,
        rect,
        page,
        appearance_states,
    }))
}

/// The names of a widget's normal appearances other than `/Off` (`/AP /N`, ISO
/// 32000-2 §12.5.5): a check box's or radio button's on state. At most
/// [`MAX_FIELD_OPTIONS`].
fn appearance_states(
    doc: &mut Document<'_>,
    widget: &Dictionary,
    cancel: Cancel<'_>,
) -> Result<Vec<String>> {
    let resolve = |doc: &mut Document<'_>, o: Option<&Object>| -> Result<Option<Object>> {
        match o.map(|o| doc.resolve(o, cancel)) {
            Some(Ok(v)) => Ok(Some(v)),
            Some(Err(e)) if e.is_document_wide() => Err(e),
            _ => Ok(None),
        }
    };
    let Some(ap) = resolve(doc, widget.get(b"AP"))? else {
        return Ok(Vec::new());
    };
    let Some(Object::Dictionary(n)) = resolve(doc, ap.get(b"N"))? else {
        return Ok(Vec::new());
    };
    Ok(n.iter()
        .filter(|(k, _)| *k != b"Off")
        .take(MAX_FIELD_OPTIONS)
        .map(|(k, _)| String::from_utf8_lossy(k).into_owned())
        .collect())
}

/// Approval or document timestamp, from a signature dictionary's `/Type`; whether
/// it is a certification or usage-rights signature is decided by `/Perms`.
fn value_kind(d: &Dictionary) -> SignatureKind {
    if d.name(b"Type") == Some(b"DocTimeStamp") {
        SignatureKind::DocTimeStamp
    } else {
        SignatureKind::Approval
    }
}

/// DocMDP level from `/Perms /DocMDP` (§12.8.2.2), default 2 when unstated.
fn docmdp(doc: &mut Document<'_>, perms: &Dictionary, cancel: Cancel<'_>) -> Option<u8> {
    let sig = doc.resolve(perms.get(b"DocMDP")?, cancel).ok()?;
    let refs = match sig.get(b"Reference").map(|r| doc.resolve(r, cancel)) {
        Some(Ok(Object::Array(a))) => a,
        _ => return Some(2),
    };
    for r in refs {
        let Ok(Object::Dictionary(sr)) = doc.resolve(&r, cancel) else {
            continue;
        };
        if sr.name(b"TransformMethod") != Some(b"DocMDP") {
            continue;
        }
        let p = match sr.get(b"TransformParams").map(|t| doc.resolve(t, cancel)) {
            Some(Ok(Object::Dictionary(tp))) => tp.get(b"P").and_then(Object::as_i64),
            _ => None,
        };
        return Some(match p {
            Some(1) => 1,
            Some(3) => 3,
            _ => 2,
        });
    }
    Some(2)
}

fn catalog_version(cat: &Dictionary) -> Option<PdfVersion> {
    match cat.name(b"Version")? {
        [ma @ b'0'..=b'9', b'.', mi @ b'0'..=b'9'] => Some(PdfVersion {
            major: ma.saturating_sub(b'0'),
            minor: mi.saturating_sub(b'0'),
        }),
        _ => None,
    }
}

/// Classify an opened document into a report.
pub(crate) fn classify(
    doc: &mut Document<'_>,
    strict: bool,
    cancel: Cancel<'_>,
) -> Result<AdmissionReport> {
    let inv = object_pass(doc, strict, cancel)?;

    let root = doc
        .trailer()
        .get(b"Root")
        .cloned()
        .ok_or(PdfError::NotPdf { offset: None })?;
    let catalog = match doc.resolve(&root, cancel)? {
        Object::Dictionary(d) => d,
        _ => return Err(PdfError::NotPdf { offset: None }),
    };
    // Document metadata (XMP) that cannot be read is reported, never a refusal
    // (`PDF-REAL-03`).
    if let Some(Object::Reference(m)) = catalog.get(b"Metadata") {
        match doc.object(m.num, cancel) {
            Ok(Object::Stream(_)) => {}
            Err(e) if e.is_document_wide() => return Err(e),
            Err(e) if strict => return Err(e),
            _ => doc.findings.push(Finding::new(
                "CS-PDF-0102",
                FindingKind::ObjectUnreadable,
                Some(m.num),
            )),
        }
    }
    let pages_root = catalog.get(b"Pages").cloned();
    let walked = match &pages_root {
        Some(r) => pages::walk(doc, r, strict, cancel),
        None => Err(PdfError::NotPdf { offset: None }),
    };
    let pages = match walked {
        Ok(p) if !p.is_empty() => p,
        Err(e) if strict || e.is_document_wide() => return Err(e),
        // The tree's root is unreadable or holds no page. Once the xref has been rebuilt
        // (the first attempt returns the error, and the caller rebuilds), the pages are
        // taken from the page objects themselves, as common readers do (`PDF-REAL-03`).
        other if !strict && doc.is_rebuilt() => {
            let found = pages::orphans(doc, cancel)?;
            if found.is_empty() {
                return Err(other.err().unwrap_or(PdfError::NotPdf { offset: None }));
            }
            doc.findings.push(Finding::new(
                "CS-PDF-0101",
                FindingKind::PageTreeRebuilt,
                pages_root.as_ref().and_then(Object::as_ref).map(|r| r.num),
            ));
            found
        }
        Ok(_) => return Err(PdfError::NotPdf { offset: None }),
        Err(e) => return Err(e),
    };
    content_pass(doc, &pages, strict, cancel)?;
    let page_index: BTreeMap<u32, u32> = pages
        .iter()
        .enumerate()
        .map(|(i, p)| (p.info.object, u32::try_from(i).unwrap_or(u32::MAX)))
        .collect();

    // AcroForm, XFA, signatures.
    let acroform = match catalog.get(b"AcroForm").map(|a| doc.resolve(a, cancel)) {
        Some(Ok(Object::Dictionary(d))) => Some(d),
        Some(Err(e)) => {
            local(doc, e, None, None, strict)?;
            None
        }
        _ => None,
    };
    let has_xfa = acroform.as_ref().is_some_and(|a| a.contains(b"XFA"));
    if has_xfa && matches!(catalog.get(b"NeedsRendering"), Some(Object::Bool(true))) {
        return Err(PdfError::DynamicXfa);
    }
    let (fields, mut signatures) = match &acroform {
        Some(a) => form_fields(doc, a, &page_index, strict, cancel)?,
        None => (Vec::new(), Vec::new()),
    };
    let perms = match catalog.get(b"Perms").map(|p| doc.resolve(p, cancel)) {
        Some(Ok(Object::Dictionary(d))) => Some(d),
        _ => None,
    };
    let has_perms = perms.is_some();
    let docmdp = match &perms {
        Some(p) => docmdp(doc, p, cancel),
        None => None,
    };
    // Which signature dictionaries `/Perms` names (§12.8.4): the certification and the
    // usage-rights signatures.
    let perm_ref = |key: &[u8]| {
        perms
            .as_ref()
            .and_then(|p| p.get(key))
            .and_then(Object::as_ref)
            .map(|r| r.num)
    };
    let certification = perm_ref(b"DocMDP");
    let usage_rights: BTreeSet<u32> = [perm_ref(b"UR3"), perm_ref(b"UR")]
        .into_iter()
        .flatten()
        .collect();
    let catalog_num = root.as_ref().map(|r| r.num);
    // Signature dictionaries no field points at still count as signatures.
    let in_fields: BTreeSet<u32> = signatures.iter().filter_map(|s| s.value).collect();
    for v in &inv.sig_values {
        // A usage-rights signature written directly in `/Perms` is inside the catalog;
        // it is listed below, not the catalog itself.
        if in_fields.contains(v) || Some(*v) == catalog_num {
            continue;
        }
        let (sub_filter, kind) = match doc.object(*v, cancel) {
            Ok(Object::Dictionary(d)) => (
                d.name(b"SubFilter")
                    .map(|s| String::from_utf8_lossy(s).into_owned()),
                value_kind(&d),
            ),
            _ => (None, SignatureKind::Approval),
        };
        signatures.push(SignatureInfo {
            field: None,
            value: Some(*v),
            sub_filter,
            kind,
        });
    }
    for key in [&b"UR3"[..], b"UR"] {
        if let Some(Object::Dictionary(d)) = perms.as_ref().and_then(|p| p.get(key))
            && matches!(d.name(b"Type"), Some(b"Sig"))
        {
            signatures.push(SignatureInfo {
                field: None,
                value: None,
                sub_filter: d
                    .name(b"SubFilter")
                    .map(|s| String::from_utf8_lossy(s).into_owned()),
                kind: SignatureKind::UsageRights,
            });
        }
    }
    for s in &mut signatures {
        if s.value.is_some_and(|v| usage_rights.contains(&v)) {
            s.kind = SignatureKind::UsageRights;
        } else if s.value.is_some() && s.value == certification {
            s.kind = SignatureKind::Certification;
        }
    }
    let has_optional_content = catalog.contains(b"OCProperties");

    // A signed document must not need repair (docs/30 §2, `CS-PDF-0014`). Usage-rights
    // signatures alone do not make it signed (`PDF-REAL-02`).
    if counts_as_signed(docmdp, &signatures) && doc.is_repaired() {
        return Err(PdfError::DamagedSigned);
    }

    // Findings for what was found.
    for a in &inv.actions {
        let f = match a.kind {
            ActionKind::GoToR | ActionKind::GoToE => Finding::new(
                "CS-PDF-0105",
                FindingKind::ExternalReference(a.kind),
                Some(a.object),
            ),
            ActionKind::Uri if a.automatic => Finding::new(
                "CS-PDF-0105",
                FindingKind::ExternalReference(a.kind),
                Some(a.object),
            ),
            ActionKind::Uri => continue,
            kind => Finding::new("CS-PDF-0103", FindingKind::Action(kind), Some(a.object)),
        };
        doc.findings.push(f);
    }
    if has_xfa {
        doc.findings.push(Finding::new(
            "CS-PDF-0103",
            FindingKind::Xfa,
            root.as_ref().map(|r| r.num),
        ));
    }
    for &n in &inv.embedded {
        doc.findings.push(Finding::new(
            "CS-PDF-0104",
            FindingKind::EmbeddedFile,
            Some(n),
        ));
    }
    for &n in &inv.rich_media {
        doc.findings
            .push(Finding::new("CS-PDF-0104", FindingKind::RichMedia, Some(n)));
    }
    for &n in &inv.external_streams {
        doc.findings.push(Finding::new(
            "CS-PDF-0105",
            FindingKind::ExternalStream,
            Some(n),
        ));
    }
    if !fields.is_empty() {
        doc.findings
            .push(Finding::new("CS-PDF-0106", FindingKind::FormFields, None));
    }
    if counts_as_signed(docmdp, &signatures) {
        doc.findings
            .push(Finding::new("CS-PDF-0107", FindingKind::Signatures, None));
    }
    for s in &signatures {
        if s.kind == SignatureKind::UsageRights {
            doc.findings.push(Finding::new(
                "CS-PDF-0107",
                FindingKind::UsageRights,
                s.value.or(catalog_num),
            ));
        }
    }
    if doc.encryption().is_some() {
        let object = doc
            .trailer()
            .get(b"Encrypt")
            .and_then(Object::as_ref)
            .map(|r| r.num);
        doc.findings
            .push(Finding::new("CS-PDF-0109", FindingKind::Encrypted, object));
    }
    if has_optional_content {
        doc.findings.push(Finding::new(
            "CS-PDF-0108",
            FindingKind::OptionalContent,
            None,
        ));
    }

    let version = match (doc.header_version(), catalog_version(&catalog)) {
        (Some(h), Some(c)) => Some(h.max(c)),
        (h, c) => h.or(c),
    };
    let page_infos: Vec<_> = pages.iter().map(|p| p.info).collect();
    Ok(AdmissionReport {
        version,
        page_count: u32::try_from(page_infos.len()).unwrap_or(u32::MAX),
        pages: page_infos,
        revisions: doc.revisions().to_vec(),
        object_count: u32::try_from(doc.object_numbers().count()).unwrap_or(u32::MAX),
        repaired: doc.is_repaired(),
        stream_lengths_corrected: u32::try_from(doc.lengths_corrected.len()).unwrap_or(u32::MAX),
        fields,
        signatures,
        has_perms,
        docmdp,
        actions: inv.actions,
        embedded_files: inv.embedded.into_iter().collect(),
        rich_media: inv.rich_media.into_iter().collect(),
        external_streams: inv.external_streams.into_iter().collect(),
        has_xfa,
        has_optional_content,
        encryption: doc.encryption(),
        decoded_bytes: doc.decoded_bytes(),
        findings: doc.findings.list.clone(),
        findings_dropped: doc.findings.dropped,
    })
}
