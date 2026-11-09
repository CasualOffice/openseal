//! Normalization (docs/30 §3): a fresh, unambiguous file from an admitted one.
//!
//! Every object reachable from the trailer is renumbered densely from 1 in
//! breadth-first order from the trailer (`/Root`, then `/Info`) and written once, with
//! a classic xref table or an xref stream with object streams. Linearization,
//! unreachable objects, earlier revisions and duplicate dictionary keys do not
//! survive. Removed, and listed in the [`NormalizationReport`] with their codes:
//!
//! - JavaScript and every action that runs or fetches: `/OpenAction`, `/AA`, `/JS`,
//!   the `/JavaScript` name tree, and `/Launch`, `/SubmitForm`, `/ImportData`,
//!   `/GoToR`, `/GoToE`, multimedia actions wherever they are (`CS-PDF-0103`,
//!   `CS-PDF-0105` for the ones that reach outside the file). A `/URI` action that
//!   needs a click (a link annotation's `/A`) is kept; one that runs on its own sat in
//!   `/OpenAction` or `/AA` and goes with them.
//! - Embedded files, file attachment annotations, the `/EmbeddedFiles` name tree,
//!   RichMedia and 3D (`CS-PDF-0104`).
//! - External stream data (`/F` on a stream): the stream is kept with no data
//!   (`CS-PDF-0105`).
//! - XFA (`CS-PDF-0103`); the AcroForm and its static fields stay.
//!
//! Optional content is kept as it is and reported, not flattened. A signed document
//! is refused (`CS-PDF-0014`): rewriting it would break its signatures.
//!
//! The page tree is made to say what it holds: each node's `/Kids` keeps only
//! dictionaries and its `/Count` is the number of pages actually under it, so a
//! viewer that trusts `/Count` sees the pages this reader sees (SEC-P11).
//!
//! Stream data is copied as stored, with its filters; nothing is decoded except
//! object streams the reader needs to load objects. A chain of objects whose values
//! are bare references collapses to its target.

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::classify::action_kind;
use crate::document::Document;
use crate::error::PdfError;
use crate::object::{Dictionary, ObjRef, Object};
use crate::report::{ActionKind, AdmissionReport, FindingKind, MAX_FINDINGS, PdfVersion};
use crate::serialize::{Body, write_indirect, write_value};
use crate::writer::{MAX_OBJECT_NUMBER, WriteError, push_be, width, write_table, write_tail};
use crate::{Admitted, Cancel};

/// Non-stream objects per object stream in [`OutputXref::Stream`] output.
const OBJSTM_MEMBERS: usize = 100;

/// The cross-reference form of a normalized file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum OutputXref {
    /// An xref stream, with every non-stream object in object streams (smaller).
    #[default]
    Stream,
    /// A classic xref table, every object at its own offset.
    Table,
}

/// How to normalize.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NormalizeOptions {
    /// The cross-reference form of the output.
    pub xref: OutputXref,
    /// Rewrite a signed document as a new PDF with its signatures as pictures
    /// (docs/30 §2). Not built yet: a signed document is refused either way.
    pub print_to_new: bool,
}

impl NormalizeOptions {
    /// Options with the given xref form.
    #[must_use]
    pub fn with_xref(xref: OutputXref) -> Self {
        Self {
            xref,
            print_to_new: false,
        }
    }
}

/// One thing normalization removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Removal {
    /// `CS-PDF-0103` (active content), `-0104` (embedded files, RichMedia, 3D),
    /// `-0105` (external references) or `-0102` (an object that could not be read).
    pub code: &'static str,
    /// What was removed.
    pub kind: FindingKind,
    /// The input object it was in or was, when there is one.
    pub object: Option<u32>,
    /// True when it went because nothing reachable from the trailer referred to it.
    pub unreachable: bool,
}

/// What normalization did.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[non_exhaustive]
pub struct NormalizationReport {
    /// What was removed, in the order found.
    pub removed: Vec<Removal>,
    /// Removals not listed because the list reached [`MAX_FINDINGS`].
    pub removed_dropped: u64,
    /// Objects in the output, not counting object streams and the xref stream.
    pub objects_written: u32,
    /// In-use input objects not reachable from the trailer, and so not written.
    pub unreachable_dropped: u32,
    /// Optional content is present and was kept as it is (`CS-PDF-0108`: flattening
    /// to the default visibility is not built).
    pub optional_content_kept: bool,
    /// (input object number, output object number) for every object written, in
    /// output order.
    pub renumbered: Vec<(u32, u32)>,
}

/// A normalized file and what was done to make it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Normalized {
    /// The new file.
    pub bytes: Vec<u8>,
    /// What was removed and renumbered.
    pub report: NormalizationReport,
}

/// Where a reference to an input object goes in the output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Slot {
    /// Written under this number.
    Keep(u32),
    /// Not written: free, null, unreadable or removed. References to it are dropped.
    Drop,
}

fn removal_for(kind: ActionKind) -> (&'static str, FindingKind) {
    match kind {
        ActionKind::GoToR | ActionKind::GoToE | ActionKind::Uri => {
            ("CS-PDF-0105", FindingKind::ExternalReference(kind))
        }
        k => ("CS-PDF-0103", FindingKind::Action(k)),
    }
}

/// Why a dictionary is removed wherever it appears, if it is.
fn bad_dict(d: &Dictionary) -> Option<(&'static str, FindingKind)> {
    if let Some(kind) = d.name(b"S").and_then(action_kind)
        && kind != ActionKind::Uri
    {
        return Some(removal_for(kind));
    }
    if d.contains(b"JS") {
        return Some(removal_for(ActionKind::JavaScript));
    }
    let ty = d.name(b"Type");
    let subtype = d.name(b"Subtype");
    if ty == Some(b"EmbeddedFile") || d.contains(b"EF") || subtype == Some(b"FileAttachment") {
        return Some(("CS-PDF-0104", FindingKind::EmbeddedFile));
    }
    if matches!(subtype, Some(b"RichMedia" | b"3D"))
        || matches!(ty, Some(b"3D" | b"RichMediaContent"))
    {
        return Some(("CS-PDF-0104", FindingKind::RichMedia));
    }
    None
}

/// The document structure is never removed, only cleaned.
fn structural(d: &Dictionary) -> bool {
    matches!(d.name(b"Type"), Some(b"Catalog" | b"Pages" | b"Page"))
}

/// The kind of action an `/OpenAction` or `/AA` value holds, for the report.
fn trigger_kind(d: &Dictionary) -> ActionKind {
    if d.contains(b"JS") {
        return ActionKind::JavaScript;
    }
    d.name(b"S")
        .and_then(action_kind)
        .unwrap_or(ActionKind::Other)
}

struct Norm<'d, 'a> {
    doc: &'d mut Document<'a>,
    cancel: Cancel<'d>,
    status: BTreeMap<u32, Slot>,
    queue: VecDeque<(u32, Object)>,
    next: u32,
    protected: BTreeSet<u32>,
    removed: Vec<Removal>,
    removed_seen: BTreeSet<Removal>,
    removed_dropped: u64,
    renumbered: Vec<(u32, u32)>,
    /// Objects whose value is a bare reference (collapsed to their target).
    aliases: BTreeSet<u32>,
}

impl<'a> Norm<'_, 'a> {
    fn record(&mut self, code: &'static str, kind: FindingKind, object: Option<u32>) {
        self.record_removal(Removal {
            code,
            kind,
            object,
            unreachable: false,
        });
    }

    fn record_removal(&mut self, r: Removal) {
        if self.removed_seen.contains(&r) {
            return;
        }
        if self.removed.len() >= MAX_FINDINGS {
            self.removed_dropped = self.removed_dropped.saturating_add(1);
            return;
        }
        self.removed_seen.insert(r);
        self.removed.push(r);
    }

    fn check_cancel(&self) -> Result<(), WriteError> {
        if (self.cancel)() {
            Err(WriteError::Read(PdfError::Cancelled))
        } else {
            Ok(())
        }
    }

    /// Load an object; an error local to it makes it unreadable (`CS-PDF-0102`).
    fn load(&mut self, num: u32) -> Result<Option<Object>, WriteError> {
        match self.doc.object(num, self.cancel) {
            Ok(o) => Ok(Some(o)),
            Err(e) if e.is_document_wide() => Err(e.into()),
            Err(_) => {
                self.record("CS-PDF-0102", FindingKind::ObjectUnreadable, Some(num));
                Ok(None)
            }
        }
    }

    /// Where input object `num` goes, loading and queueing it the first time.
    fn target(&mut self, num: u32) -> Result<Slot, WriteError> {
        if let Some(s) = self.status.get(&num) {
            return Ok(*s);
        }
        let max_hops = usize::from(self.doc.limits().max_ref_depth);
        let mut chain: Vec<u32> = Vec::new();
        let mut cur = num;
        let result = loop {
            if let Some(s) = self.status.get(&cur) {
                break *s;
            }
            if chain.len() > max_hops || chain.contains(&cur) {
                break Slot::Drop;
            }
            self.check_cancel()?;
            match self.load(cur)? {
                Some(Object::Reference(r)) => {
                    chain.push(cur);
                    cur = r.num;
                }
                None | Some(Object::Null) => {
                    self.status.insert(cur, Slot::Drop);
                    break Slot::Drop;
                }
                Some(o) => break self.adopt(cur, o)?,
            }
        };
        for c in chain {
            self.aliases.insert(c);
            self.status.insert(c, result);
        }
        Ok(result)
    }

    /// Decide whether a loaded object is written; number and queue it if so.
    fn adopt(&mut self, old: u32, obj: Object) -> Result<Slot, WriteError> {
        if let Object::Stream(s) = &obj
            && matches!(s.dict.name(b"Type"), Some(b"XRef" | b"ObjStm"))
        {
            // File structure, not content: the output has its own.
            self.status.insert(old, Slot::Drop);
            return Ok(Slot::Drop);
        }
        if let Some(d) = obj.dict()
            && !self.protected.contains(&old)
            && !structural(d)
            && let Some((code, kind)) = bad_dict(d)
        {
            self.record(code, kind, Some(old));
            self.status.insert(old, Slot::Drop);
            return Ok(Slot::Drop);
        }
        let new = self.next;
        if new > MAX_OBJECT_NUMBER {
            return Err(WriteError::ObjectNumbersExhausted);
        }
        self.next = new.saturating_add(1);
        self.status.insert(old, Slot::Keep(new));
        self.queue.push_back((old, obj));
        self.renumbered.push((old, new));
        Ok(Slot::Keep(new))
    }

    /// Record what an `/OpenAction` or `/AA` entry held.
    fn report_trigger(&mut self, old: u32, key: &[u8], value: &Object) -> Result<(), WriteError> {
        let resolved = match self.doc.resolve(value, self.cancel) {
            Ok(v) => v,
            Err(e) if e.is_document_wide() => return Err(e.into()),
            Err(_) => Object::Null,
        };
        let mut kinds: Vec<ActionKind> = Vec::new();
        match (key, &resolved) {
            (b"AA", Object::Dictionary(aa)) => {
                let values: Vec<Object> = aa.iter().map(|(_, v)| v.clone()).collect();
                for v in values {
                    let kind = match self.doc.resolve(&v, self.cancel) {
                        Ok(Object::Dictionary(d)) => trigger_kind(&d),
                        Ok(_) => ActionKind::Other,
                        Err(e) if e.is_document_wide() => return Err(e.into()),
                        Err(_) => ActionKind::Other,
                    };
                    kinds.push(kind);
                }
            }
            (_, Object::Dictionary(d)) => kinds.push(trigger_kind(d)),
            _ => kinds.push(ActionKind::Other),
        }
        for kind in kinds {
            let (code, fk) = removal_for(kind);
            self.record(code, fk, Some(old));
        }
        Ok(())
    }

    /// Clean a dictionary's entries: one entry per key (the last), active keys removed.
    /// `structure` marks the catalog, the page tree and `/Info`: never removed, so a
    /// `/Type` or `/Subtype` that would remove another dictionary goes instead.
    fn clean_dict(
        &mut self,
        old: u32,
        d: Dictionary,
        structure: bool,
    ) -> Result<Dictionary, WriteError> {
        let entries = d.into_entries();
        let mut last: BTreeMap<Vec<u8>, usize> = BTreeMap::new();
        for (i, (k, _)) in entries.iter().enumerate() {
            last.insert(k.clone(), i);
        }
        let mut out = Dictionary::new();
        for (i, (k, v)) in entries.into_iter().enumerate() {
            if last.get(&k) != Some(&i) {
                continue;
            }
            match k.as_slice() {
                b"AA" | b"OpenAction" => {
                    self.report_trigger(old, &k, &v)?;
                    continue;
                }
                b"JavaScript" | b"JS" => {
                    self.record(
                        "CS-PDF-0103",
                        FindingKind::Action(ActionKind::JavaScript),
                        Some(old),
                    );
                    continue;
                }
                b"EmbeddedFiles" | b"EF" => {
                    self.record("CS-PDF-0104", FindingKind::EmbeddedFile, Some(old));
                    continue;
                }
                b"XFA" => {
                    self.record("CS-PDF-0103", FindingKind::Xfa, Some(old));
                    continue;
                }
                b"Type" | b"Subtype" if structure => {
                    let carrier = match v.as_name() {
                        Some(b"EmbeddedFile" | b"FileAttachment") => {
                            Some(FindingKind::EmbeddedFile)
                        }
                        Some(b"3D" | b"RichMedia" | b"RichMediaContent") => {
                            Some(FindingKind::RichMedia)
                        }
                        _ => None,
                    };
                    if let Some(kind) = carrier {
                        self.record("CS-PDF-0104", kind, Some(old));
                        continue;
                    }
                }
                b"Pages" | b"Kids" | b"Contents" if structure => {
                    if let Some(v) = self.clean_structure(old, v)? {
                        out.push(k, v);
                    }
                    continue;
                }
                b"S" => {
                    // Only a structural dictionary reaches here with a removable /S.
                    if let Some(kind) = v.as_name().and_then(action_kind)
                        && kind != ActionKind::Uri
                    {
                        let (code, fk) = removal_for(kind);
                        self.record(code, fk, Some(old));
                        continue;
                    }
                }
                _ => {}
            }
            if let Some(v) = self.clean(old, v)? {
                out.push(k, v);
            }
        }
        Ok(out)
    }

    /// Clean a direct value; `None` when it is removed.
    fn clean(&mut self, old: u32, value: Object) -> Result<Option<Object>, WriteError> {
        Ok(match value {
            Object::Reference(r) => match self.target(r.num)? {
                Slot::Keep(n) => Some(Object::Reference(ObjRef {
                    num: n,
                    generation: 0,
                })),
                Slot::Drop => None,
            },
            Object::Array(a) => {
                let mut out = Vec::with_capacity(a.len());
                for e in a {
                    if let Some(e) = self.clean(old, e)? {
                        out.push(e);
                    }
                }
                Some(Object::Array(out))
            }
            Object::Dictionary(d) => {
                if !structural(&d)
                    && let Some((code, kind)) = bad_dict(&d)
                {
                    self.record(code, kind, Some(old));
                    return Ok(None);
                }
                let structure = structural(&d);
                Some(Object::Dictionary(self.clean_dict(old, d, structure)?))
            }
            // A stream is never a direct value; the parser does not produce one.
            Object::Stream(_) => None,
            v => Some(v),
        })
    }

    /// Clean the value of `/Pages`, `/Kids` or `/Contents` in the structure: a direct
    /// dictionary there is a page-tree node or page, cleaned but never removed. The
    /// reader takes these references one hop only, so one to an object whose value is
    /// itself a reference was unreadable to it and is dropped, not collapsed.
    fn clean_structure(&mut self, old: u32, value: Object) -> Result<Option<Object>, WriteError> {
        match value {
            Object::Reference(r) => {
                self.target(r.num)?;
                if self.aliases.contains(&r.num) {
                    self.record("CS-PDF-0102", FindingKind::ObjectUnreadable, Some(r.num));
                    return Ok(None);
                }
                self.clean(old, Object::Reference(r))
            }
            Object::Array(a) => {
                let mut out = Vec::with_capacity(a.len());
                for e in a {
                    if let Some(e) = self.clean_structure(old, e)? {
                        out.push(e);
                    }
                }
                Ok(Some(Object::Array(out)))
            }
            Object::Dictionary(d) => Ok(Some(Object::Dictionary(self.clean_dict(old, d, true)?))),
            other => self.clean(old, other),
        }
    }

    /// Clean an object taken from the queue into the body to write.
    fn clean_top(&mut self, old: u32, obj: Object) -> Result<Body<'a>, WriteError> {
        match obj {
            Object::Stream(s) => {
                let mut dict = self.clean_dict(old, s.dict, false)?;
                dict.remove(b"Length");
                let data: Cow<'a, [u8]> = if dict.contains(b"F") {
                    // External data is never fetched (SEC-P07): the stream stays, empty.
                    for k in [
                        &b"F"[..],
                        b"FFilter",
                        b"FDecodeParms",
                        b"Filter",
                        b"DecodeParms",
                        b"DL",
                    ] {
                        dict.remove(k);
                    }
                    self.record("CS-PDF-0105", FindingKind::ExternalStream, Some(old));
                    Cow::Borrowed(&[])
                } else {
                    let bytes: &'a [u8] = self.doc.bytes();
                    Cow::Borrowed(bytes.get(s.data).unwrap_or_default())
                };
                Ok(Body::Stream { dict, data })
            }
            Object::Dictionary(d) => {
                let structure = self.protected.contains(&old) || structural(&d);
                Ok(Body::Value(Object::Dictionary(
                    self.clean_dict(old, d, structure)?,
                )))
            }
            other => Ok(Body::Value(self.clean(old, other)?.unwrap_or(Object::Null))),
        }
    }

    /// A trailer value (`/Root`, `/Info`): its output reference.
    fn trailer_ref(&mut self, value: Option<Object>) -> Result<Option<ObjRef>, WriteError> {
        let slot = match value {
            Some(Object::Reference(r)) => self.target(r.num)?,
            // A direct dictionary in the trailer becomes an object of its own.
            Some(o @ Object::Dictionary(_)) => self.adopt(0, o)?,
            _ => Slot::Drop,
        };
        Ok(match slot {
            Slot::Keep(num) => Some(ObjRef { num, generation: 0 }),
            Slot::Drop => None,
        })
    }
}

/// Write `bodies` (output objects 1..=n) with a classic table.
fn write_classic(out: &mut Vec<u8>, bodies: &[Body<'_>], trailer: Dictionary) {
    let mut rows = Vec::with_capacity(bodies.len());
    for (num, body) in (1u32..).zip(bodies) {
        rows.push((num, 0u16, out.len()));
        write_indirect(out, ObjRef { num, generation: 0 }, body);
    }
    let xref_pos = out.len();
    write_table(out, &rows, true);
    out.extend_from_slice(b"trailer\n");
    write_value(out, &Object::Dictionary(trailer));
    out.push(b'\n');
    write_tail(out, xref_pos);
}

fn int(v: impl TryInto<i64>) -> Object {
    Object::Integer(v.try_into().unwrap_or(i64::MAX))
}

fn flate(data: &[u8]) -> Vec<u8> {
    miniz_oxide::deflate::compress_to_vec_zlib(data, 6)
}

/// Write `bodies` with an xref stream, non-stream objects in object streams.
fn write_streamed(
    out: &mut Vec<u8>,
    bodies: &[Body<'_>],
    trailer: Dictionary,
) -> Result<(), WriteError> {
    // (type, field 2, field 3) per object number, from 0.
    let mut rows: BTreeMap<u32, (u8, u64, u64)> = BTreeMap::new();
    rows.insert(0, (0, 0, 65_535));
    let mut members: Vec<(u32, &Object)> = Vec::new();
    for (num, body) in (1u32..).zip(bodies) {
        match body {
            Body::Value(v) => members.push((num, v)),
            Body::Stream { .. } => {
                rows.insert(num, (1, u64::try_from(out.len()).unwrap_or(u64::MAX), 0));
                write_indirect(out, ObjRef { num, generation: 0 }, body);
            }
        }
    }
    let count = u32::try_from(bodies.len()).map_err(|_| WriteError::ObjectNumbersExhausted)?;
    let mut next = count
        .checked_add(1)
        .ok_or(WriteError::ObjectNumbersExhausted)?;
    for chunk in members.chunks(OBJSTM_MEMBERS) {
        let stm = next;
        next = next
            .checked_add(1)
            .ok_or(WriteError::ObjectNumbersExhausted)?;
        let mut header = Vec::new();
        let mut body = Vec::new();
        for (index, (num, v)) in (0u64..).zip(chunk) {
            if !body.is_empty() {
                body.push(b'\n');
            }
            header.extend_from_slice(format!("{num} {} ", body.len()).as_bytes());
            write_value(&mut body, v);
            rows.insert(*num, (2, u64::from(stm), index));
        }
        let first = header.len();
        header.extend_from_slice(&body);
        let mut dict = Dictionary::new();
        dict.insert(b"Type", Object::Name(b"ObjStm".to_vec()));
        dict.insert(b"N", int(chunk.len()));
        dict.insert(b"First", int(first));
        dict.insert(b"Filter", Object::Name(b"FlateDecode".to_vec()));
        rows.insert(stm, (1, u64::try_from(out.len()).unwrap_or(u64::MAX), 0));
        let b = Body::Stream {
            dict,
            data: Cow::Owned(flate(&header)),
        };
        write_indirect(
            out,
            ObjRef {
                num: stm,
                generation: 0,
            },
            &b,
        );
    }
    let own = next;
    if own > MAX_OBJECT_NUMBER {
        return Err(WriteError::ObjectNumbersExhausted);
    }
    let xref_pos = out.len();
    rows.insert(own, (1, u64::try_from(xref_pos).unwrap_or(u64::MAX), 0));
    let max2 = rows.values().map(|r| r.1).max().unwrap_or(0);
    let w2 = width(max2);
    let mut data = Vec::with_capacity(rows.len().saturating_mul(usize::from(w2).saturating_add(3)));
    for (t, f2, f3) in rows.values() {
        data.push(*t);
        push_be(&mut data, *f2, w2);
        push_be(&mut data, *f3, 2);
    }
    let mut dict = Dictionary::new();
    dict.insert(b"Type", Object::Name(b"XRef".to_vec()));
    for (k, v) in trailer.iter() {
        dict.insert(k, v.clone());
    }
    dict.insert(b"Size", int(own.saturating_add(1)));
    dict.insert(b"W", Object::Array(vec![int(1), int(w2), int(2)]));
    dict.insert(b"Filter", Object::Name(b"FlateDecode".to_vec()));
    let b = Body::Stream {
        dict,
        data: Cow::Owned(flate(&data)),
    };
    write_indirect(
        out,
        ObjRef {
            num: own,
            generation: 0,
        },
        &b,
    );
    write_tail(out, xref_pos);
    Ok(())
}

fn header(version: PdfVersion) -> Vec<u8> {
    let mut h = format!("%PDF-{}.{}\n", version.major, version.minor).into_bytes();
    h.extend_from_slice(b"%\xE2\xE3\xCF\xD3\n");
    h
}

/// Index in the output bodies of output object `num` (numbered from 1).
fn body_index(num: u32) -> Option<usize> {
    usize::try_from(num).ok()?.checked_sub(1)
}

/// As the reader's page walk decides: a node has `/Type /Pages`, or no `/Type /Page`
/// and `/Kids`.
fn is_node(d: &Dictionary) -> bool {
    match d.name(b"Type") {
        Some(b"Pages") => true,
        Some(b"Page") => false,
        _ => d.contains(b"Kids"),
    }
}

/// Deepest page tree walked when fixing counts; the reader refuses deeper trees.
const MAX_TREE_DEPTH: usize = 4096;

/// Makes the output's page tree say what it holds (SEC-P11): each node's `/Kids` keeps
/// only dictionaries and its `/Count` is the number of pages actually under it; each
/// page's `/Contents` keeps only streams that admission could read.
struct TreeFix<'b, 'a> {
    bodies: &'b mut [Body<'a>],
    visited: BTreeSet<u32>,
    /// Output numbers of content streams admission reported unreadable.
    bad_content: BTreeSet<u32>,
    /// Output numbers of content entries dropped.
    dropped: Vec<u32>,
}

impl TreeFix<'_, '_> {
    fn body(&self, num: u32) -> Option<&Body<'_>> {
        self.bodies.get(body_index(num)?)
    }

    /// Whether a kid is a node (`Some(true)`), a page (`Some(false)`) or not a
    /// dictionary at all (`None`).
    fn kid_kind(&self, kid: &Object) -> Option<bool> {
        match kid {
            Object::Reference(r) => match self.body(r.num)? {
                Body::Value(Object::Dictionary(d)) => Some(is_node(d)),
                _ => None,
            },
            Object::Dictionary(d) => Some(is_node(d)),
            _ => None,
        }
    }

    fn readable_stream(&self, o: &Object) -> bool {
        match o {
            Object::Reference(r) => {
                matches!(self.body(r.num), Some(Body::Stream { .. }))
                    && !self.bad_content.contains(&r.num)
            }
            _ => false,
        }
    }

    /// Keep only readable content streams in a page's `/Contents`.
    fn fix_page_dict(&mut self, d: &mut Dictionary) {
        let (entries, single) = match d.get(b"Contents") {
            None => return,
            Some(o @ Object::Reference(r)) => match self.body(r.num) {
                Some(Body::Value(Object::Array(a))) => (a.clone(), false),
                _ => (vec![o.clone()], true),
            },
            Some(Object::Array(a)) => (a.clone(), false),
            Some(_) => (Vec::new(), false),
        };
        let total = entries.len();
        let mut kept = Vec::with_capacity(total);
        for e in entries {
            if self.readable_stream(&e) {
                kept.push(e);
            } else if let Object::Reference(r) = e {
                self.dropped.push(r.num);
            }
        }
        if kept.len() == total && total > 0 {
            return;
        }
        match kept.len() {
            0 => {
                d.remove(b"Contents");
            }
            1 if single => {}
            _ => d.insert(b"Contents", Object::Array(kept)),
        }
    }

    fn fix_page(&mut self, num: u32) {
        if !self.visited.insert(num) {
            return;
        }
        let Some(i) = body_index(num) else {
            return;
        };
        let mut d = match self.bodies.get_mut(i) {
            Some(Body::Value(Object::Dictionary(d))) => core::mem::take(d),
            _ => return,
        };
        self.fix_page_dict(&mut d);
        if let Some(Body::Value(Object::Dictionary(slot))) = self.bodies.get_mut(i) {
            *slot = d;
        }
    }

    /// Rewrite one node's `/Kids` and `/Count`; its page count.
    fn fix_node_dict(&mut self, d: &mut Dictionary, depth: usize) -> u64 {
        let kids = match d.get(b"Kids") {
            Some(Object::Array(a)) => a.clone(),
            Some(Object::Reference(r)) => match self.body(r.num) {
                Some(Body::Value(Object::Array(a))) => a.clone(),
                _ => Vec::new(),
            },
            _ => Vec::new(),
        };
        let mut kept = Vec::with_capacity(kids.len());
        let mut total: u64 = 0;
        for kid in kids {
            match (self.kid_kind(&kid), kid) {
                (Some(true), Object::Reference(r)) => {
                    total = total.saturating_add(self.fix_node(r.num, depth));
                    kept.push(Object::Reference(r));
                }
                (Some(true), Object::Dictionary(mut kd)) => {
                    if depth < MAX_TREE_DEPTH {
                        let next = depth.saturating_add(1);
                        total = total.saturating_add(self.fix_node_dict(&mut kd, next));
                    }
                    kept.push(Object::Dictionary(kd));
                }
                (Some(false), Object::Reference(r)) => {
                    self.fix_page(r.num);
                    total = total.saturating_add(1);
                    kept.push(Object::Reference(r));
                }
                (Some(false), Object::Dictionary(mut kd)) => {
                    self.fix_page_dict(&mut kd);
                    total = total.saturating_add(1);
                    kept.push(Object::Dictionary(kd));
                }
                _ => {}
            }
        }
        d.insert(b"Kids", Object::Array(kept));
        d.insert(b"Count", int(total));
        total
    }

    /// [`TreeFix::fix_node_dict`] for the indirect node `num`.
    fn fix_node(&mut self, num: u32, depth: usize) -> u64 {
        if depth >= MAX_TREE_DEPTH || !self.visited.insert(num) {
            return 0;
        }
        let Some(i) = body_index(num) else {
            return 0;
        };
        let mut d = match self.bodies.get_mut(i) {
            Some(Body::Value(Object::Dictionary(d))) => core::mem::take(d),
            _ => return 0,
        };
        let total = self.fix_node_dict(&mut d, depth.saturating_add(1));
        if let Some(Body::Value(Object::Dictionary(slot))) = self.bodies.get_mut(i) {
            *slot = d;
        }
        total
    }

    /// Fix the whole tree under the catalog `root`.
    fn run(&mut self, root: u32) {
        let Some(i) = body_index(root) else {
            return;
        };
        let pages = match self.bodies.get(i) {
            Some(Body::Value(Object::Dictionary(c))) => c.get(b"Pages").cloned(),
            _ => None,
        };
        match pages {
            Some(Object::Reference(r)) => match self.kid_kind(&Object::Reference(r)) {
                Some(true) => {
                    self.fix_node(r.num, 0);
                }
                Some(false) => self.fix_page(r.num),
                None => {}
            },
            Some(Object::Dictionary(mut d)) => {
                if is_node(&d) {
                    self.fix_node_dict(&mut d, 1);
                } else {
                    self.fix_page_dict(&mut d);
                }
                if let Some(Body::Value(Object::Dictionary(c))) = self.bodies.get_mut(i) {
                    c.insert(b"Pages", Object::Dictionary(d));
                }
            }
            _ => {}
        }
    }
}

/// Every object of the input's page tree (nodes and pages), as the reader walks it:
/// the structure is cleaned, never removed, whatever keys it carries.
fn page_tree_objects(
    doc: &mut Document<'_>,
    trailer: &Dictionary,
    cancel: Cancel<'_>,
) -> Result<BTreeSet<u32>, WriteError> {
    let resolve = |doc: &mut Document<'_>, o: &Object| match doc.resolve(o, cancel) {
        Ok(v) => Ok(Some(v)),
        Err(e) if e.is_document_wide() => Err(WriteError::Read(e)),
        Err(_) => Ok(None),
    };
    let mut found = BTreeSet::new();
    let Some(root) = trailer.get(b"Root") else {
        return Ok(found);
    };
    let pages = match resolve(doc, root)? {
        Some(Object::Dictionary(c)) => c.get(b"Pages").cloned(),
        _ => None,
    };
    let mut stack: Vec<Object> = pages.into_iter().collect();
    while let Some(node) = stack.pop() {
        if cancel() {
            return Err(WriteError::Read(PdfError::Cancelled));
        }
        if let Object::Reference(r) = &node
            && !found.insert(r.num)
        {
            continue;
        }
        let Some(Object::Dictionary(d)) = resolve(doc, &node)? else {
            continue;
        };
        if is_node(&d)
            && let Some(k) = d.get(b"Kids")
            && let Some(Object::Array(kids)) = resolve(doc, k)?
        {
            stack.extend(kids);
        }
    }
    Ok(found)
}

fn signed(report: &AdmissionReport) -> bool {
    !report.signatures.is_empty() || report.has_perms
}

/// Normalize an admitted document into a fresh file (docs/30 §3).
///
/// # Errors
///
/// `CS-PDF-0014` for a signed document (or `print_to_new`, not built yet);
/// `CS-PDF-0005` when the catalog cannot be reached; a reader's code when loading an
/// object crosses a document-wide limit or `cancel` returns true.
pub fn normalize(
    admitted: &mut Admitted<'_>,
    options: &NormalizeOptions,
    cancel: Cancel<'_>,
) -> Result<Normalized, WriteError> {
    if signed(&admitted.report) || options.print_to_new {
        return Err(WriteError::Signed);
    }
    let input_findings = admitted.report.findings.clone();
    let optional_content = admitted.report.has_optional_content;
    let version = admitted
        .report
        .version
        .unwrap_or(PdfVersion { major: 1, minor: 4 });
    let doc = &mut admitted.document;
    let trailer = doc.trailer().clone();
    // 0 stands for a direct dictionary in the trailer.
    let mut protected = BTreeSet::from([0]);
    for key in [&b"Root"[..], b"Info"] {
        if let Some(r) = trailer.get(key).and_then(Object::as_ref) {
            protected.insert(r.num);
        }
    }
    protected.extend(page_tree_objects(doc, &trailer, cancel)?);
    let in_use: Vec<u32> = doc.object_numbers().collect();
    let mut n = Norm {
        doc,
        cancel,
        status: BTreeMap::new(),
        queue: VecDeque::new(),
        next: 1,
        protected,
        removed: Vec::new(),
        removed_seen: BTreeSet::new(),
        removed_dropped: 0,
        renumbered: Vec::new(),
        aliases: BTreeSet::new(),
    };
    let root = n
        .trailer_ref(trailer.get(b"Root").cloned())?
        .ok_or(WriteError::Read(PdfError::NotPdf { offset: None }))?;
    let info = n.trailer_ref(trailer.get(b"Info").cloned())?;
    let mut bodies: Vec<Body<'_>> = Vec::new();
    while let Some((old, obj)) = n.queue.pop_front() {
        n.check_cancel()?;
        let body = n.clean_top(old, obj)?;
        bodies.push(body);
    }
    // Content streams admission could not read (`CS-PDF-0102` on a page) are dropped
    // from the pages that use them.
    let new_of: BTreeMap<u32, u32> = n.renumbered.iter().copied().collect();
    let bad_content: BTreeSet<u32> = input_findings
        .iter()
        .filter(|f| f.code == "CS-PDF-0102" && f.page.is_some())
        .filter_map(|f| new_of.get(&f.object?).copied())
        .collect();
    let mut fix = TreeFix {
        bodies: &mut bodies,
        visited: BTreeSet::new(),
        bad_content,
        dropped: Vec::new(),
    };
    fix.run(root.num);
    let dropped = fix.dropped;
    for new in dropped {
        let old = body_index(new)
            .and_then(|i| n.renumbered.get(i))
            .map(|(o, _)| *o);
        n.record("CS-PDF-0102", FindingKind::ObjectUnreadable, old);
    }
    // Active content in objects nothing reachable refers to went with them.
    for f in &input_findings {
        if matches!(f.code, "CS-PDF-0103" | "CS-PDF-0104" | "CS-PDF-0105")
            && let Some(o) = f.object
            && !n.status.contains_key(&o)
        {
            n.record_removal(Removal {
                code: f.code,
                kind: f.kind,
                object: Some(o),
                unreachable: true,
            });
        }
    }
    let unreachable = in_use.iter().filter(|o| !n.status.contains_key(o)).count();

    let mut t = Dictionary::new();
    t.insert(b"Size", int(bodies.len().saturating_add(1)));
    t.insert(b"Root", Object::Reference(root));
    if let Some(i) = info {
        t.insert(b"Info", Object::Reference(i));
    }
    if let Some(Object::Array(id)) = trailer.get(b"ID")
        && id.len() == 2
        && id.iter().all(|s| matches!(s, Object::String(_)))
    {
        t.insert(b"ID", Object::Array(id.clone()));
    }

    let mut out;
    match options.xref {
        OutputXref::Table => {
            out = header(version);
            write_classic(&mut out, &bodies, t);
        }
        OutputXref::Stream => {
            out = header(version.max(PdfVersion { major: 1, minor: 5 }));
            write_streamed(&mut out, &bodies, t)?;
        }
    }
    Ok(Normalized {
        bytes: out,
        report: NormalizationReport {
            removed: n.removed,
            removed_dropped: n.removed_dropped,
            objects_written: u32::try_from(bodies.len()).unwrap_or(u32::MAX),
            unreachable_dropped: u32::try_from(unreachable).unwrap_or(u32::MAX),
            optional_content_kept: optional_content,
            renumbered: n.renumbered,
        },
    })
}
