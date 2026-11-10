//! From a [`Plan`] to PDF bytes, and the audit trail as an associated file.
//!
//! 1. [`draw`]: a blank file with the plan's pages and their rules, written here in a
//!    few fixed objects, then admitted and given to the flattener with one text field per
//!    line and one signature field per picture. The flattener sets the text in subset
//!    embedded faces with `ToUnicode` maps (so it extracts and searches) and checks and
//!    draws the signature art, exactly as on signed documents.
//! 2. [`attach`]: the trail as an embedded file stream (`/Type /EmbeddedFile`,
//!    `/Subtype /application#2Fjson`, `/Params` with size, MD5 `/CheckSum` and dates),
//!    its file specification (`/AFRelationship /Supplement`), the catalog's `/AF` array
//!    and its `/Names /EmbeddedFiles` tree (ISO 32000-2 §7.11.4, §14.13).
//! 3. [`copy_pages`]: a drawn page and everything it reaches, renumbered into another
//!    document's update, for appending the certificate to the document it certifies.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use casual_sign_audit::{Hash256, TRAIL_FILE_NAME, Timestamp};
use casual_sign_flatten::{Capture, FlattenInput, FlattenOptions, FontSet, flatten};
use casual_sign_model::{
    Field, FieldType, FieldValue, FontFamily, Format, Id, Placement, Points, Text,
};
use casual_sign_pdf::{
    Admitted, Dictionary, Document, IncrementalUpdate, Limits, ObjRef, Object, admit,
};
use md5::Digest as _;
use rust_decimal::Decimal;

use crate::error::CertificateError;
use crate::layout::Plan;
use crate::text::Face;

/// Most objects copied from a drawn certificate into a document. A decision of `T-1I`:
/// a 500-page certificate with every font and image stays far below it.
const MAX_COPIED_OBJECTS: usize = 200_000;

pub(crate) fn never() -> bool {
    false
}

fn pts(v: f64) -> Result<Points, CertificateError> {
    let d = Decimal::try_from(v)
        .map_err(|_| CertificateError::Input { what: "placement" })?
        .round_dp(2);
    Points::new(d.max(Decimal::ZERO)).map_err(|_| CertificateError::Input { what: "placement" })
}

fn id(s: String) -> Result<Id, CertificateError> {
    Id::new(s).map_err(|_| CertificateError::Input { what: "field id" })
}

/// The blank pages: catalog, page tree, each page with its rules as content.
fn skeleton(plan: &Plan, file_id: &[u8]) -> Vec<u8> {
    let mut out = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n".to_vec();
    let mut offsets: Vec<usize> = Vec::new();
    let obj = |out: &mut Vec<u8>, offsets: &mut Vec<usize>, body: &[u8]| {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n", offsets.len()).as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    };
    let (w, h) = (plan.width, plan.height);
    let count = plan.pages.len();
    let kids: Vec<String> = (0..count)
        .map(|i| format!("{} 0 R", i.saturating_mul(2).saturating_add(3)))
        .collect();
    obj(&mut out, &mut offsets, b"<</Type/Catalog/Pages 2 0 R>>");
    obj(
        &mut out,
        &mut offsets,
        format!("<</Type/Pages/Kids[{}]/Count {count}>>", kids.join(" ")).as_bytes(),
    );
    for (i, page) in plan.pages.iter().enumerate() {
        let contents = i.saturating_mul(2).saturating_add(4);
        // Every inheritable attribute is set, so a page appended under another
        // document's page tree inherits nothing from it.
        obj(
            &mut out,
            &mut offsets,
            format!(
                "<</Type/Page/Parent 2 0 R/MediaBox[0 0 {w} {h}]/CropBox[0 0 {w} {h}]/Rotate 0/Resources<<>>/Contents {contents} 0 R>>"
            )
            .as_bytes(),
        );
        let data = page.ops.as_bytes();
        let mut body = format!("<</Length {}>>\nstream\n", data.len()).into_bytes();
        body.extend_from_slice(data);
        body.extend_from_slice(b"\nendstream");
        obj(&mut out, &mut offsets, &body);
    }
    let size = offsets.len().saturating_add(1);
    let xref = out.len();
    out.extend_from_slice(format!("xref\n0 {size}\n0000000000 65535 f\r\n").as_bytes());
    for o in &offsets {
        out.extend_from_slice(format!("{o:010} 00000 n\r\n").as_bytes());
    }
    let hex: String = file_id.iter().map(|b| format!("{b:02x}")).collect();
    out.extend_from_slice(
        format!(
            "trailer\n<</Size {size}/Root 1 0 R/ID[<{hex}><{hex}>]>>\nstartxref\n{xref}\n%%EOF\n"
        )
        .as_bytes(),
    );
    out
}

/// The plan drawn: the blank pages and one update from the flattener; and how many
/// lines the flattener set smaller than asked to fit their boxes.
pub(crate) fn draw(
    plan: &Plan,
    fonts: &FontSet,
    file_id: &[u8],
) -> Result<(Vec<u8>, usize), CertificateError> {
    let blank = skeleton(plan, file_id);
    let mut admitted = admit(&blank, &Limits::default(), &never)?;
    let doc_id = id("certificate".to_owned())?;
    let mut fields: Vec<Field> = Vec::new();
    let mut values: BTreeMap<Id, FieldValue> = BTreeMap::new();
    let mut captures: BTreeMap<Id, Capture> = BTreeMap::new();
    for (p, page) in plan.pages.iter().enumerate() {
        let page_no = u32::try_from(p.saturating_add(1))
            .map_err(|_| CertificateError::Input { what: "pages" })?;
        for (j, r) in page.runs.iter().enumerate() {
            if r.text.trim().is_empty() {
                continue;
            }
            let fid = id(format!("p{p}t{j}"))?;
            let placement = Placement::new(page_no, pts(r.x)?, pts(r.top)?, pts(r.w)?, pts(r.h)?)
                .map_err(|_| CertificateError::Input { what: "placement" })?;
            let mut f = Field::new(fid.clone(), doc_id.clone(), FieldType::Text, placement);
            f.format = Some(Format {
                font_family: Some(match r.face {
                    Face::Mono => FontFamily::Courier,
                    Face::Sans => FontFamily::Helvetica,
                }),
                font_size: Some(pts(r.size)?),
                color: Some(r.color),
                align: Some(r.align),
                date_format: None,
                mask: false,
            });
            let text =
                Text::new(r.text.clone()).map_err(|_| CertificateError::Input { what: "text" })?;
            values.insert(fid, FieldValue::Text(text));
            fields.push(f);
        }
        for (j, pic) in page.pictures.iter().enumerate() {
            let fid = id(format!("p{p}s{j}"))?;
            let cid = id(format!("p{p}c{j}"))?;
            let placement = Placement::new(
                page_no,
                pts(pic.x)?,
                pts(pic.top)?,
                pts(pic.w)?,
                pts(pic.h)?,
            )
            .map_err(|_| CertificateError::Input { what: "placement" })?;
            fields.push(Field::new(
                fid.clone(),
                doc_id.clone(),
                FieldType::Signature,
                placement,
            ));
            values.insert(fid, FieldValue::Signature(cid.clone()));
            captures.insert(
                cid,
                Capture {
                    art: pic.art.clone(),
                    signed_by: None,
                    reason: None,
                },
            );
        }
    }
    let mut options = FlattenOptions::default();
    options.signed_by_line = false;
    let input = FlattenInput {
        fields: &fields,
        values: &values,
        captures: &captures,
        envelope_id: None,
        acroform: None,
    };
    let out = flatten(&mut admitted, &input, fonts, &options, &never)?;
    if !out.report.overflow.is_empty() {
        return Err(CertificateError::TextOverflow {
            lines: out.report.overflow.len(),
        });
    }
    // Text runs only (`p{page}t{n}`): a typed signature is meant to shrink to its box.
    let shrunk = out
        .report
        .shrunk
        .iter()
        .filter(|f| f.as_str().contains('t'))
        .count();
    Ok((out.bytes, shrunk))
}

/// `D:YYYYMMDDHHmmSSZ`.
pub(crate) fn pdf_date(t: Timestamp) -> String {
    match t.civil(0) {
        Some(c) => format!(
            "D:{:04}{:02}{:02}{:02}{:02}{:02}Z",
            c.year, c.month, c.day, c.hour, c.minute, c.second
        ),
        None => "D:19700101000000Z".to_owned(),
    }
}

fn name(s: &[u8]) -> Object {
    Object::Name(s.to_vec())
}

fn int(v: impl TryInto<i64>) -> Object {
    Object::Integer(v.try_into().unwrap_or(i64::MAX))
}

/// A document's catalog: its object number and dictionary.
pub(crate) fn catalog(doc: &mut Document<'_>) -> Result<(u32, Dictionary), CertificateError> {
    let root = doc
        .trailer()
        .get(b"Root")
        .and_then(Object::as_ref)
        .ok_or(CertificateError::PageTree { object: None })?;
    match doc.object(root.num, &never)? {
        Object::Dictionary(d) => Ok((root.num, d)),
        _ => Err(CertificateError::PageTree {
            object: Some(root.num),
        }),
    }
}

/// The catalog's `/Names` dictionary resolved, refusing one that already has
/// `/EmbeddedFiles`, and a catalog that already has `/AF`.
pub(crate) fn names(
    doc: &mut Document<'_>,
    catalog: &Dictionary,
) -> Result<Dictionary, CertificateError> {
    if catalog.contains(b"AF") {
        return Err(CertificateError::AlreadyAttached);
    }
    let names = match catalog.get(b"Names") {
        None => Dictionary::new(),
        Some(v) => match doc.resolve(v, &never)? {
            Object::Dictionary(d) => d,
            Object::Null => Dictionary::new(),
            _ => return Err(CertificateError::PageTree { object: None }),
        },
    };
    if names.contains(b"EmbeddedFiles") {
        return Err(CertificateError::AlreadyAttached);
    }
    Ok(names)
}

/// Add the trail as the document's associated file and replace the catalog.
pub(crate) fn attach(
    u: &mut IncrementalUpdate<'_>,
    catalog_num: u32,
    mut catalog: Dictionary,
    mut names: Dictionary,
    trail: &[u8],
    events: usize,
    made: Timestamp,
) -> Result<(), CertificateError> {
    let date = Object::String(pdf_date(made).into_bytes());
    let mut params = Dictionary::new();
    params.insert(b"Size", int(trail.len()));
    params.insert(b"CreationDate", date.clone());
    params.insert(b"ModDate", date);
    params.insert(
        b"CheckSum",
        Object::String(md5::Md5::digest(trail).to_vec()),
    );
    let mut ef = Dictionary::new();
    ef.insert(b"Type", name(b"EmbeddedFile"));
    ef.insert(b"Subtype", name(b"application/json"));
    ef.insert(b"Params", Object::Dictionary(params));
    let stream = u.add_stream(ef, trail.to_vec())?;

    let file = TRAIL_FILE_NAME.as_bytes().to_vec();
    let desc = format!(
        "OpenSeal audit trail: RFC 8785 JSON, {events} events, SHA-256 {}",
        Hash256::digest(trail).hex()
    );
    let mut efd = Dictionary::new();
    efd.insert(b"F", Object::Reference(stream));
    efd.insert(b"UF", Object::Reference(stream));
    let mut spec = Dictionary::new();
    spec.insert(b"Type", name(b"Filespec"));
    spec.insert(b"F", Object::String(file.clone()));
    spec.insert(b"UF", Object::String(file.clone()));
    spec.insert(b"Desc", Object::String(desc.into_bytes()));
    spec.insert(b"AFRelationship", name(b"Supplement"));
    spec.insert(b"EF", Object::Dictionary(efd));
    let spec = u.add(Object::Dictionary(spec))?;

    let mut tree = Dictionary::new();
    tree.insert(
        b"Names",
        Object::Array(vec![Object::String(file), Object::Reference(spec)]),
    );
    names.insert(b"EmbeddedFiles", Object::Dictionary(tree));
    catalog.insert(b"Names", Object::Dictionary(names));
    catalog.insert(b"AF", Object::Array(vec![Object::Reference(spec)]));
    u.replace(catalog_num, Object::Dictionary(catalog))?;
    Ok(())
}

/// References in `v`, skipping a page's `/Parent`.
fn refs(v: &Object, skip_parent: bool, out: &mut Vec<u32>) {
    let mut stack: Vec<(&Object, bool)> = vec![(v, skip_parent)];
    while let Some((v, skip)) = stack.pop() {
        match v {
            Object::Reference(r) => out.push(r.num),
            Object::Array(items) => stack.extend(items.iter().map(|i| (i, false))),
            Object::Dictionary(d) => {
                for (k, x) in d.iter() {
                    if !(skip && k == b"Parent") {
                        stack.push((x, false));
                    }
                }
            }
            Object::Stream(s) => {
                for (_, x) in s.dict.iter() {
                    stack.push((x, false));
                }
            }
            _ => {}
        }
    }
}

/// `v` with every reference renumbered through `map` (unknown ones become `null`).
fn remap(v: &Object, map: &BTreeMap<u32, ObjRef>) -> Object {
    match v {
        Object::Reference(r) => map
            .get(&r.num)
            .map_or(Object::Null, |n| Object::Reference(*n)),
        Object::Array(items) => Object::Array(items.iter().map(|i| remap(i, map)).collect()),
        Object::Dictionary(d) => Object::Dictionary(remap_dict(d, map)),
        other => other.clone(),
    }
}

fn remap_dict(d: &Dictionary, map: &BTreeMap<u32, ObjRef>) -> Dictionary {
    d.iter().map(|(k, x)| (k.to_vec(), remap(x, map))).collect()
}

/// Copy `pages` of `src` and everything they reach into `u`, each page's `/Parent` set
/// to `parent`. Returns the new page references, in order.
pub(crate) fn copy_pages(
    src: &mut Admitted<'_>,
    pages: &[u32],
    u: &mut IncrementalUpdate<'_>,
    parent: ObjRef,
) -> Result<Vec<ObjRef>, CertificateError> {
    let page_set: BTreeSet<u32> = pages.iter().copied().collect();
    let mut objects: BTreeMap<u32, Object> = BTreeMap::new();
    let mut queue: VecDeque<u32> = pages.iter().copied().collect();
    while let Some(num) = queue.pop_front() {
        if objects.contains_key(&num) {
            continue;
        }
        if objects.len() >= MAX_COPIED_OBJECTS {
            return Err(CertificateError::TooManyPages {
                pages: pages.len(),
                limit: crate::limits::MAX_PAGES,
            });
        }
        let v = src.document.object(num, &never)?;
        let mut found = Vec::new();
        refs(&v, page_set.contains(&num), &mut found);
        queue.extend(found.into_iter().filter(|n| !objects.contains_key(n)));
        objects.insert(num, v);
    }
    // Numbers first (pages in order, then the rest ascending), so references resolve.
    let mut map: BTreeMap<u32, ObjRef> = BTreeMap::new();
    for &p in pages {
        map.insert(p, u.add(Object::Null)?);
    }
    for &num in objects.keys() {
        if let std::collections::btree_map::Entry::Vacant(slot) = map.entry(num) {
            slot.insert(u.add(Object::Null)?);
        }
    }
    let bytes = src.document.bytes();
    for (num, v) in &objects {
        let Some(target) = map.get(num) else { continue };
        match v {
            Object::Stream(s) => {
                let data = bytes
                    .get(s.data.clone())
                    .ok_or(CertificateError::PageTree { object: Some(*num) })?
                    .to_vec();
                let mut dict = remap_dict(&s.dict, &map);
                dict.remove(b"Length");
                u.replace_stream(target.num, dict, data)?;
            }
            other => {
                let mut copied = remap(other, &map);
                if page_set.contains(num)
                    && let Object::Dictionary(d) = &mut copied
                {
                    d.insert(b"Parent", Object::Reference(parent));
                }
                u.replace(target.num, copied)?;
            }
        }
    }
    pages
        .iter()
        .map(|p| {
            map.get(p)
                .copied()
                .ok_or(CertificateError::PageTree { object: Some(*p) })
        })
        .collect()
}
