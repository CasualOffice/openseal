//! Classification: one pass over every object for active content and carriers, the
//! page walk, content-stream operator counts, AcroForm fields, signatures, and the
//! admission report (docs/30 §2).

use std::collections::{BTreeMap, BTreeSet};

use crate::Cancel;
use crate::document::Document;
use crate::error::{PdfError, Result};
use crate::lexer::{Lexer, Tok, is_ws};
use crate::object::{Dictionary, Object};
use crate::pages::{self, Page};
use crate::report::{
    ActionInfo, ActionKind, AdmissionReport, FieldType, Finding, FindingKind, FormField,
    PdfVersion, SignatureInfo, Widget,
};
use crate::text;
use crate::xref::find;

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

/// After `ID`: skip to the `EI` that ends the image (white space, `EI`, then a
/// delimiter, white space or the end).
fn skip_inline_image(lx: &mut Lexer<'_>) {
    let b = lx.b;
    let mut from = lx.pos.saturating_add(1);
    while let Some(p) = find(b, b"EI", from) {
        let before = p
            .checked_sub(1)
            .and_then(|i| b.get(i))
            .is_some_and(|&c| is_ws(c));
        let after = b
            .get(p.saturating_add(2))
            .is_none_or(|&c| !crate::lexer::is_regular(c));
        if before && after {
            lx.pos = p.saturating_add(2);
            return;
        }
        from = p.saturating_add(2);
    }
    lx.pos = b.len();
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
type FieldFrame = (Object, String, Option<Vec<u8>>, i64, usize);

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
        .map(|o| (o, String::new(), None, 0, 0))
        .collect();
    while let Some((node, parent, ft, ff, depth)) = stack.pop() {
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
        let ft = dict.name(b"FT").map(<[u8]>::to_vec).or(ft);
        let ff = match dict.get(b"Ff") {
            Some(v) => doc
                .resolve(v, cancel)
                .ok()
                .and_then(|o| o.as_i64())
                .unwrap_or(ff),
            None => ff,
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
            for k in child_fields.into_iter().rev() {
                stack.push((k, name.clone(), ft.clone(), ff, next));
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
            let sub_filter = match doc.resolve(v, cancel) {
                Ok(Object::Dictionary(d)) => d
                    .name(b"SubFilter")
                    .map(|s| String::from_utf8_lossy(s).into_owned()),
                _ => None,
            };
            if *v != Object::Null {
                sigs.push(SignatureInfo {
                    field: num,
                    value,
                    sub_filter,
                });
            }
        }
        fields.push(FormField {
            object: num,
            name,
            field_type,
            widgets,
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
    Ok(Some(Widget { object, rect, page }))
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
    let pages_root = catalog
        .get(b"Pages")
        .cloned()
        .ok_or(PdfError::NotPdf { offset: None })?;
    let pages = pages::walk(doc, &pages_root, strict, cancel)?;
    if pages.is_empty() {
        return Err(PdfError::NotPdf { offset: None });
    }
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
    // Signature dictionaries no field points at still count as signatures.
    let in_fields: BTreeSet<u32> = signatures.iter().filter_map(|s| s.value).collect();
    for v in &inv.sig_values {
        if !in_fields.contains(v) {
            let sub_filter = match doc.object(*v, cancel) {
                Ok(o) => o
                    .get(b"SubFilter")
                    .and_then(Object::as_name)
                    .map(|s| String::from_utf8_lossy(s).into_owned()),
                Err(_) => None,
            };
            signatures.push(SignatureInfo {
                field: None,
                value: Some(*v),
                sub_filter,
            });
        }
    }
    let perms = match catalog.get(b"Perms").map(|p| doc.resolve(p, cancel)) {
        Some(Ok(Object::Dictionary(d))) => Some(d),
        _ => None,
    };
    let has_perms = perms.is_some();
    let docmdp = match &perms {
        Some(p) => docmdp(doc, p, cancel),
        None => None,
    };
    let has_optional_content = catalog.contains(b"OCProperties");

    // A signed document must not need repair (docs/30 §2, `CS-PDF-0014`).
    if (!signatures.is_empty() || has_perms) && doc.is_repaired() {
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
    if !signatures.is_empty() || has_perms {
        doc.findings
            .push(Finding::new("CS-PDF-0107", FindingKind::Signatures, None));
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
        decoded_bytes: doc.decoded_bytes(),
        findings: doc.findings.list.clone(),
        findings_dropped: doc.findings.dropped,
    })
}
