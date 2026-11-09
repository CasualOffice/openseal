//! A parsed document: the merged xref of every revision, the trailer, and lazy access
//! to objects, object streams and decoded stream data under the document's budgets.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crate::Cancel;
use crate::error::{PdfError, Result, off};
use crate::filters::{self, Budget, Filter};
use crate::lexer::Lexer;
use crate::limits::Limits;
use crate::object::{Dictionary, Object, Stream};
use crate::parser::{Warnings, parse_object};
use crate::report::{Finding, FindingKind, Findings, PdfVersion, Revision};
use crate::xref::{
    self, Entry, Section, SectionCtx, SectionError, SectionResult, XrefKind, correct_header,
    endstream_search, find, header_at, length_fits, revision_end, rfind, stream_data_start,
    strip_eol, token_start,
};

/// How far around a stated offset a misplaced header or section is looked for.
const CORRECTION_WINDOW: usize = 1024;
/// Nested loads (a `/Length` in an object stream, …) never go deeper than this.
const MAX_LOAD_NESTING: usize = 16;

/// A decoded object stream: its data and the (number, offset) pairs of its header.
#[derive(Debug)]
struct ObjStm {
    data: Vec<u8>,
    first: usize,
    members: Vec<(u32, usize)>,
}

#[derive(Debug, Default)]
struct ObjStmCache {
    map: BTreeMap<u32, ObjStm>,
    order: VecDeque<u32>,
    bytes: u64,
}

/// A PDF read within limits. Objects are parsed when asked for; streams are decoded
/// when asked for, and every decode is charged to the document's budget.
#[derive(Debug)]
pub struct Document<'a> {
    bytes: &'a [u8],
    limits: Limits,
    lenient: bool,
    xref: BTreeMap<u32, Entry>,
    trailer: Dictionary,
    revisions: Vec<Revision>,
    repaired: bool,
    header_version: Option<PdfVersion>,
    budget: Budget,
    cache: ObjStmCache,
    loading: Vec<u32>,
    endstream_memo: Option<(usize, usize)>,
    pub(crate) findings: Findings,
    /// Streams whose `/Length` was wrong, found by `endstream` instead.
    pub(crate) lengths_corrected: BTreeSet<u32>,
}

fn with_object(e: PdfError, num: u32) -> PdfError {
    match e {
        PdfError::Malformed {
            object: None,
            offset,
        } => PdfError::Malformed {
            object: Some(num),
            offset,
        },
        other => other,
    }
}

fn check(cancel: Cancel<'_>) -> Result<()> {
    if cancel() {
        Err(PdfError::Cancelled)
    } else {
        Ok(())
    }
}

/// `%PDF-x.y` within the first 1024 bytes.
fn header_version(b: &[u8]) -> Option<PdfVersion> {
    let head = b.get(..b.len().min(1024))?;
    let p = find(head, b"%PDF-", 0)?;
    let v = b.get(p.saturating_add(5)..p.saturating_add(8))?;
    match v {
        [ma @ b'0'..=b'9', b'.', mi @ b'0'..=b'9'] => Some(PdfVersion {
            major: ma.saturating_sub(b'0'),
            minor: mi.saturating_sub(b'0'),
        }),
        _ => None,
    }
}

impl<'a> Document<'a> {
    /// Read the structure: header, xref chain (or a rebuild), trailer, encryption check.
    pub(crate) fn open(
        bytes: &'a [u8],
        limits: &Limits,
        strict: bool,
        cancel: Cancel<'_>,
        rebuild: bool,
    ) -> Result<Self> {
        let size = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if size > limits.max_input_bytes {
            return Err(PdfError::TooLarge {
                size,
                limit: limits.max_input_bytes,
            });
        }
        let header_version = header_version(bytes);
        if header_version.is_none() && strict {
            return Err(PdfError::NotPdf { offset: None });
        }
        let mut doc = Self {
            bytes,
            limits: *limits,
            lenient: !strict,
            xref: BTreeMap::new(),
            trailer: Dictionary::new(),
            revisions: Vec::new(),
            repaired: false,
            header_version,
            budget: Budget::default(),
            cache: ObjStmCache::default(),
            loading: Vec::new(),
            endstream_memo: None,
            findings: Findings::default(),
            lengths_corrected: BTreeSet::new(),
        };
        if rebuild {
            doc.rebuild(cancel)?;
        } else {
            match doc.read_chain(strict, cancel) {
                Ok(()) => {}
                Err(SectionError::Fatal(e)) => return Err(e),
                Err(SectionError::Damage(e)) => {
                    if strict {
                        return Err(e);
                    }
                    if !matches!(e, PdfError::NotPdf { .. } | PdfError::Malformed { .. }) {
                        doc.findings.push(Finding::limit(&e, None, None));
                    }
                    doc.rebuild(cancel)?;
                }
            }
        }
        doc.check_encryption(cancel)?;
        Ok(doc)
    }

    fn section_ctx<'c>(&self, cancel: Cancel<'c>) -> SectionCtx<'c> {
        SectionCtx {
            max_objects: self.limits.max_objects,
            max_depth: usize::from(self.limits.max_depth),
            max_string: usize::try_from(self.limits.max_string_bytes).unwrap_or(usize::MAX),
            max_name: usize::from(self.limits.max_name_bytes),
            lenient: self.lenient,
            cancel,
        }
    }

    fn lexer(&self, data: &'a [u8], pos: usize) -> Lexer<'a> {
        Lexer::new(
            data,
            pos,
            usize::try_from(self.limits.max_string_bytes).unwrap_or(usize::MAX),
            usize::from(self.limits.max_name_bytes),
            self.lenient,
        )
    }

    fn object_cap(&self) -> usize {
        usize::try_from(self.limits.max_objects)
            .unwrap_or(usize::MAX)
            .saturating_add(1)
    }

    // ----- xref chain -------------------------------------------------------------

    fn read_chain(&mut self, strict: bool, cancel: Cancel<'_>) -> SectionResult<()> {
        let b = self.bytes;
        let no_pdf = |at: Option<usize>| {
            SectionError::Damage(PdfError::NotPdf {
                offset: at.map(off),
            })
        };
        let sx = rfind(b, b"startxref").ok_or_else(|| no_pdf(None))?;
        let mut lx = Lexer::new(b, sx.saturating_add(9), 0, 0, true);
        let start = lx
            .uint()
            .and_then(|v| usize::try_from(v).ok())
            .ok_or_else(|| no_pdf(Some(sx)))?;
        let mut next = Some(start);
        let mut visited: BTreeSet<usize> = BTreeSet::new();
        let mut corrected = false;
        let mut count: u16 = 0;
        while let Some(pos) = next {
            if cancel() {
                return Err(SectionError::Fatal(PdfError::Cancelled));
            }
            if visited.contains(&pos) {
                let e = PdfError::PrevLoop { offset: off(pos) };
                if strict {
                    return Err(SectionError::Damage(e));
                }
                self.findings.push(Finding::limit(&e, None, None));
                self.findings.push(Finding::new(
                    "CS-PDF-0101",
                    FindingKind::XrefCorrected,
                    None,
                ));
                break;
            }
            if count >= self.limits.max_revisions {
                return Err(SectionError::Fatal(PdfError::TooManyRevisions {
                    limit: self.limits.max_revisions,
                }));
            }
            count = count.saturating_add(1);
            visited.insert(pos);
            let (pos, section) = match self.section_at(pos, cancel) {
                Ok(s) => (pos, s),
                Err(SectionError::Fatal(e)) => return Err(SectionError::Fatal(e)),
                Err(SectionError::Damage(e)) => match self.correct_section(pos, cancel)? {
                    Some((p, s)) => {
                        corrected = true;
                        visited.insert(p);
                        (p, s)
                    }
                    None => return Err(SectionError::Damage(e)),
                },
            };
            let stm = match section.trailer.get(b"XRefStm").and_then(Object::as_i64) {
                Some(p) => {
                    let p = usize::try_from(p).map_err(|_| no_pdf(Some(pos)))?;
                    Some(self.xref_stream_at(p, cancel)?.entries)
                }
                None => None,
            };
            next = section
                .trailer
                .get(b"Prev")
                .and_then(Object::as_i64)
                .and_then(|p| usize::try_from(p).ok());
            self.merge(&section, stm)?;
            self.revisions.push(Revision {
                xref_offset: Some(off(pos)),
                end_offset: off(revision_end(b, section.end)),
                kind: section.kind,
            });
        }
        self.revisions.reverse();
        corrected |= self.verify_entries(cancel)?;
        if corrected {
            self.findings.push(Finding::new(
                "CS-PDF-0101",
                FindingKind::XrefCorrected,
                None,
            ));
        }
        if !self.trailer.contains(b"Root") {
            return Err(no_pdf(None));
        }
        Ok(())
    }

    fn section_at(&mut self, pos: usize, cancel: Cancel<'_>) -> SectionResult<Section> {
        let b = self.bytes;
        let mut lx = Lexer::new(b, pos, 0, 0, true);
        lx.skip_ws();
        let p = lx.pos;
        if b.get(p..).is_some_and(|r| r.starts_with(b"xref")) {
            xref::table_at(b, p, &self.section_ctx(cancel))
        } else {
            self.xref_stream_at(p, cancel)
        }
    }

    fn xref_stream_at(&mut self, pos: usize, cancel: Cancel<'_>) -> SectionResult<Section> {
        let b = self.bytes;
        let cx = self.section_ctx(cancel);
        let (num, dict, range, end) = xref::raw_stream_at(b, pos, &cx)?;
        let damage = || {
            SectionError::Damage(PdfError::NotPdf {
                offset: Some(off(pos)),
            })
        };
        if dict.name(b"Type") != Some(b"XRef") {
            return Err(damage());
        }
        xref::check_size(&dict, pos)?;
        let filters = direct_filters(&dict).ok_or_else(damage)?;
        let raw = b.get(range).ok_or_else(damage)?;
        let limits = self.limits;
        let mut ctx = filters::Ctx {
            limits: &limits,
            budget: &mut self.budget,
            cancel,
            object: num,
        };
        let rows = filters::decode(raw, &filters, &mut ctx)?;
        let entries = xref::xref_stream_entries(&dict, &rows, pos, &cx)?;
        Ok(Section {
            entries,
            trailer: dict,
            kind: XrefKind::Stream,
            end,
        })
    }

    /// Look near a wrong section offset, then at the last `xref` keyword.
    fn correct_section(
        &mut self,
        pos: usize,
        cancel: Cancel<'_>,
    ) -> SectionResult<Option<(usize, Section)>> {
        let b = self.bytes;
        for d in 0..=CORRECTION_WINDOW {
            for p in [
                pos.checked_add(d),
                if d == 0 { None } else { pos.checked_sub(d) },
            ]
            .into_iter()
            .flatten()
            {
                let candidate = match b.get(p) {
                    Some(b'x') => {
                        token_start(b, p) && b.get(p..).is_some_and(|r| r.starts_with(b"xref"))
                    }
                    Some(c) if c.is_ascii_digit() => header_at(b, p).is_some(),
                    _ => false,
                };
                if !candidate {
                    continue;
                }
                match self.section_at(p, cancel) {
                    Ok(s) => return Ok(Some((p, s))),
                    Err(SectionError::Fatal(e)) => return Err(SectionError::Fatal(e)),
                    Err(SectionError::Damage(_)) => {}
                }
            }
        }
        let last = [rfind(b, b"\nxref"), rfind(b, b"\rxref")]
            .into_iter()
            .flatten()
            .max()
            .map(|p| p.saturating_add(1));
        if let Some(p) = last.filter(|p| *p != pos) {
            match self.section_at(p, cancel) {
                Ok(s) => return Ok(Some((p, s))),
                Err(SectionError::Fatal(e)) => return Err(SectionError::Fatal(e)),
                Err(SectionError::Damage(_)) => {}
            }
        }
        Ok(None)
    }

    /// Merge one revision's entries under the newer ones already read.
    fn merge(&mut self, section: &Section, stm: Option<Vec<(u32, Entry)>>) -> SectionResult<()> {
        let mut in_use_here: BTreeSet<u32> = BTreeSet::new();
        for &(num, entry) in &section.entries {
            if entry != Entry::Free {
                in_use_here.insert(num);
            }
            self.insert_entry(num, entry)?;
        }
        // Hybrid file: the stream supplies what the table leaves free (§7.5.8.4).
        for (num, entry) in stm.into_iter().flatten() {
            if !in_use_here.contains(&num) {
                if self.xref.get(&num) == Some(&Entry::Free) && entry != Entry::Free {
                    self.xref.insert(num, entry);
                } else {
                    self.insert_entry(num, entry)?;
                }
            }
        }
        if self.trailer.is_empty() {
            self.trailer = section.trailer.clone();
        } else {
            for key in [b"Root".as_slice(), b"Info", b"ID", b"Encrypt"] {
                if !self.trailer.contains(key)
                    && let Some(v) = section.trailer.get(key)
                {
                    self.trailer.push(key.to_vec(), v.clone());
                }
            }
        }
        Ok(())
    }

    fn insert_entry(&mut self, num: u32, entry: Entry) -> SectionResult<()> {
        if num == 0 {
            return Ok(());
        }
        if !self.xref.contains_key(&num) {
            if self.xref.len() >= self.object_cap() {
                return Err(SectionError::Fatal(PdfError::TooManyObjects {
                    limit: self.limits.max_objects,
                }));
            }
            self.xref.insert(num, entry);
        }
        Ok(())
    }

    /// Check that every offset entry points at its own header; correct small shifts.
    /// Returns whether anything was corrected.
    fn verify_entries(&mut self, cancel: Cancel<'_>) -> SectionResult<bool> {
        let b = self.bytes;
        let mut corrected = false;
        for (i, (num, entry)) in self.xref.iter_mut().enumerate() {
            if i % 4096 == 0 && cancel() {
                return Err(SectionError::Fatal(PdfError::Cancelled));
            }
            let Entry::Offset { offset, .. } = entry else {
                continue;
            };
            if header_at(b, *offset).is_some_and(|(n, _, _)| n == *num) {
                continue;
            }
            match correct_header(b, *offset, *num, CORRECTION_WINDOW) {
                Some(p) => {
                    *offset = p;
                    corrected = true;
                }
                None => {
                    return Err(SectionError::Damage(PdfError::Malformed {
                        object: Some(*num),
                        offset: off(*offset),
                    }));
                }
            }
        }
        Ok(corrected)
    }

    // ----- rebuild ----------------------------------------------------------------

    /// Rebuild the xref by scanning for `n g obj`, as every reader does (`CS-PDF-0101`).
    fn rebuild(&mut self, cancel: Cancel<'_>) -> Result<()> {
        let b = self.bytes;
        self.xref.clear();
        self.trailer = Dictionary::new();
        self.cache = ObjStmCache::default();
        self.repaired = true;
        self.revisions = vec![Revision {
            xref_offset: None,
            end_offset: off(b.len()),
            kind: XrefKind::Rebuilt,
        }];
        let cx = self.section_ctx(cancel);
        let headers = match xref::scan_headers(b, &cx) {
            Ok(h) => h,
            Err(SectionError::Fatal(e) | SectionError::Damage(e)) => return Err(e),
        };
        for &(num, pos) in &headers {
            if num == 0 {
                continue;
            }
            if !self.xref.contains_key(&num) && self.xref.len() >= self.object_cap() {
                return Err(PdfError::TooManyObjects {
                    limit: self.limits.max_objects,
                });
            }
            self.xref.insert(
                num,
                Entry::Offset {
                    offset: pos,
                    generation: 0,
                },
            );
        }
        // The last trailer (classic or xref-stream dictionary) naming a /Root.
        let mut best: Option<(usize, Dictionary)> = None;
        for t in xref::scan_trailers(b) {
            check(cancel)?;
            let mut lx = self.lexer(b, t);
            if let Ok(Object::Dictionary(d)) = parse_object(
                &mut lx,
                usize::from(self.limits.max_depth),
                &mut Warnings::default(),
            ) && d.contains(b"Root")
                && best.as_ref().is_none_or(|(p, _)| *p < t)
            {
                best = Some((t, d));
            }
        }
        let mut objstms: Vec<u32> = Vec::new();
        for &(num, pos) in &headers {
            check(cancel)?;
            let window = b
                .get(pos..pos.saturating_add(1024).min(b.len()))
                .unwrap_or_default();
            let is_xref = find(window, b"/XRef", 0).is_some();
            let is_objstm = find(window, b"/ObjStm", 0).is_some();
            if !is_xref && !is_objstm {
                continue;
            }
            let Some((_, _, after)) = header_at(b, pos) else {
                continue;
            };
            let mut lx = self.lexer(b, after);
            let Ok(Object::Dictionary(d)) = parse_object(
                &mut lx,
                usize::from(self.limits.max_depth),
                &mut Warnings::default(),
            ) else {
                continue;
            };
            if is_xref
                && d.name(b"Type") == Some(b"XRef")
                && d.contains(b"Root")
                && best.as_ref().is_none_or(|(p, _)| *p < pos)
            {
                best = Some((pos, d.clone()));
            }
            if is_objstm
                && d.name(b"Type") == Some(b"ObjStm")
                && self.xref.get(&num)
                    == Some(&Entry::Offset {
                        offset: pos,
                        generation: 0,
                    })
            {
                objstms.push(num);
            }
        }
        for s in objstms {
            match self.objstm_members(s, cancel) {
                Ok(members) => {
                    for (index, (n, _)) in members.into_iter().enumerate() {
                        let index = u32::try_from(index).unwrap_or(u32::MAX);
                        match self.xref.get(&n) {
                            Some(Entry::Offset { .. }) => {}
                            Some(_) => {
                                self.xref.insert(n, Entry::Compressed { stream: s, index });
                            }
                            None => {
                                if self.xref.len() >= self.object_cap() {
                                    return Err(PdfError::TooManyObjects {
                                        limit: self.limits.max_objects,
                                    });
                                }
                                self.xref.insert(n, Entry::Compressed { stream: s, index });
                            }
                        }
                    }
                }
                Err(e) if e.is_document_wide() => return Err(e),
                Err(e) => self.findings.push(Finding::limit(&e, Some(s), None)),
            }
        }
        if let Some((_, d)) = best {
            self.trailer = d;
        }
        let root_ok = match self.trailer.get(b"Root").cloned() {
            Some(r) => matches!(self.resolve(&r, cancel), Ok(Object::Dictionary(_))),
            None => false,
        };
        if !root_ok {
            let root = self
                .find_catalog(cancel)?
                .ok_or(PdfError::NotPdf { offset: None })?;
            let mut t = Dictionary::new();
            for (k, v) in self.trailer.iter() {
                if k != b"Root" {
                    t.push(k.to_vec(), v.clone());
                }
            }
            t.push(
                b"Root".to_vec(),
                Object::Reference(crate::object::ObjRef {
                    num: root,
                    generation: 0,
                }),
            );
            self.trailer = t;
        }
        self.findings
            .push(Finding::new("CS-PDF-0101", FindingKind::XrefRebuilt, None));
        Ok(())
    }

    /// The highest-numbered object that is a `/Type /Catalog` dictionary.
    fn find_catalog(&mut self, cancel: Cancel<'_>) -> Result<Option<u32>> {
        let nums: Vec<u32> = self.xref.keys().rev().copied().collect();
        for num in nums {
            match self.object(num, cancel) {
                Ok(Object::Dictionary(d))
                    if d.name(b"Type") == Some(b"Catalog") && d.contains(b"Pages") =>
                {
                    return Ok(Some(num));
                }
                Err(e) if e.is_document_wide() => return Err(e),
                _ => {}
            }
        }
        Ok(None)
    }

    // ----- encryption -------------------------------------------------------------

    fn check_encryption(&mut self, cancel: Cancel<'_>) -> Result<()> {
        let Some(enc) = self.trailer.get(b"Encrypt").cloned() else {
            return Ok(());
        };
        if enc == Object::Null {
            return Ok(());
        }
        let public_key = match self.resolve(&enc, cancel) {
            Ok(Object::Dictionary(d)) => {
                d.name(b"Filter") == Some(b"Adobe.PubSec")
                    || d.name(b"SubFilter")
                        .is_some_and(|s| s.starts_with(b"adbe.pkcs7"))
            }
            Err(e) if e.is_document_wide() => return Err(e),
            _ => false,
        };
        Err(if public_key {
            PdfError::PublicKeySecurity
        } else {
            PdfError::Encrypted
        })
    }

    // ----- objects ----------------------------------------------------------------

    /// The limits this document is read under.
    #[must_use]
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// The input bytes.
    #[must_use]
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// The trailer dictionary of the newest revision (with `/Root`, `/Info`, `/ID`
    /// filled from older ones when the newest lacks them).
    #[must_use]
    pub fn trailer(&self) -> &Dictionary {
        &self.trailer
    }

    /// Revisions, oldest first.
    #[must_use]
    pub fn revisions(&self) -> &[Revision] {
        &self.revisions
    }

    /// True when the xref needed any repair (`CS-PDF-0101`).
    #[must_use]
    pub fn is_repaired(&self) -> bool {
        self.repaired || self.findings.has(FindingKind::XrefCorrected)
    }

    /// The version in the file header, if any.
    #[must_use]
    pub fn header_version(&self) -> Option<PdfVersion> {
        self.header_version
    }

    /// Object numbers of every in-use object, ascending.
    pub fn object_numbers(&self) -> impl Iterator<Item = u32> + '_ {
        self.xref
            .iter()
            .filter(|(_, e)| **e != Entry::Free)
            .map(|(n, _)| *n)
    }

    /// The highest object number in the xref.
    #[must_use]
    pub fn max_object_number(&self) -> u32 {
        self.xref.keys().next_back().copied().unwrap_or(0)
    }

    /// Bytes decoded so far, charged to the document budget.
    #[must_use]
    pub fn decoded_bytes(&self) -> u64 {
        self.budget.used
    }

    /// The object `num`; `null` when it is free or absent (§7.3.10).
    pub fn object(&mut self, num: u32, cancel: Cancel<'_>) -> Result<Object> {
        if self.loading.contains(&num) {
            return Err(PdfError::ReferenceCycle { object: num });
        }
        if self.loading.len() >= MAX_LOAD_NESTING {
            return Err(PdfError::ReferenceTooDeep { object: num });
        }
        check(cancel)?;
        let entry = self.xref.get(&num).copied().unwrap_or(Entry::Free);
        self.loading.push(num);
        let r = match entry {
            Entry::Free => Ok(Object::Null),
            Entry::Offset { offset, .. } => self.parse_at(num, offset, cancel),
            Entry::Compressed { stream, index } => self.load_compressed(num, stream, index, cancel),
        };
        self.loading.pop();
        r.map_err(|e| with_object(e, num))
    }

    /// Follow references from `value` until a direct object, at most
    /// `Limits::max_ref_depth` hops (`CS-PDF-0004`).
    pub fn resolve(&mut self, value: &Object, cancel: Cancel<'_>) -> Result<Object> {
        let Object::Reference(first) = value else {
            return Ok(value.clone());
        };
        let mut cur = Object::Reference(*first);
        let mut hops: u16 = 0;
        while let Object::Reference(r) = cur {
            if hops >= self.limits.max_ref_depth {
                return Err(PdfError::ReferenceTooDeep { object: first.num });
            }
            hops = hops.saturating_add(1);
            cur = self.object(r.num, cancel)?;
        }
        Ok(cur)
    }

    fn record_warnings(&mut self, num: u32, w: Warnings) {
        for e in w.list {
            self.findings.push(Finding::limit(&e, Some(num), None));
        }
    }

    fn parse_at(&mut self, num: u32, offset: usize, cancel: Cancel<'_>) -> Result<Object> {
        let b = self.bytes;
        let malformed = PdfError::Malformed {
            object: Some(num),
            offset: off(offset),
        };
        let (n, _, after) = header_at(b, offset).ok_or_else(|| malformed.clone())?;
        if n != num {
            return Err(malformed);
        }
        let mut lx = self.lexer(b, after);
        let mut w = Warnings::default();
        let obj = parse_object(&mut lx, usize::from(self.limits.max_depth), &mut w)?;
        self.record_warnings(num, w);
        let Object::Dictionary(dict) = obj else {
            return Ok(obj);
        };
        if !lx.keyword(b"stream") {
            return Ok(Object::Dictionary(dict));
        }
        let start = stream_data_start(b, lx.pos);
        let length = match dict.get(b"Length") {
            Some(Object::Integer(l)) => Some(*l),
            Some(Object::Reference(r)) => match self.object(r.num, cancel) {
                Ok(Object::Integer(l)) => Some(l),
                Err(e) if e.is_document_wide() => return Err(e),
                _ => None,
            },
            _ => None,
        };
        let range = match length
            .and_then(|l| usize::try_from(l).ok())
            .and_then(|l| length_fits(b, start, l))
        {
            Some(r) => r,
            None => {
                self.lengths_corrected.insert(num);
                self.endstream_after(start).ok_or(malformed)?
            }
        };
        Ok(Object::Stream(Stream { dict, data: range }))
    }

    /// `endstream` search with a one-entry memo, so many streams with wrong lengths
    /// ahead of one far `endstream` cost one scan, not one each.
    fn endstream_after(&mut self, start: usize) -> Option<core::ops::Range<usize>> {
        let b = self.bytes;
        if let Some((from, found)) = self.endstream_memo
            && start >= from
            && start <= found
        {
            return Some(start..strip_eol(b, start, found));
        }
        let r = endstream_search(b, start)?;
        let found = find(b, b"endstream", start)?;
        self.endstream_memo = Some((start, found));
        Some(r)
    }

    fn load_compressed(
        &mut self,
        num: u32,
        stream: u32,
        index: u32,
        cancel: Cancel<'_>,
    ) -> Result<Object> {
        self.ensure_objstm(stream, cancel)?;
        let max_depth = usize::from(self.limits.max_depth);
        let max_string = usize::try_from(self.limits.max_string_bytes).unwrap_or(usize::MAX);
        let max_name = usize::from(self.limits.max_name_bytes);
        let lenient = self.lenient;
        let malformed = PdfError::Malformed {
            object: Some(num),
            offset: 0,
        };
        let Some(stm) = self.cache.map.get(&stream) else {
            return Err(malformed);
        };
        let at = usize::try_from(index)
            .ok()
            .and_then(|i| stm.members.get(i))
            .filter(|(n, _)| *n == num)
            .or_else(|| stm.members.iter().find(|(n, _)| *n == num))
            .map(|(_, o)| *o);
        let Some(rel) = at else {
            return Ok(Object::Null);
        };
        let pos = stm
            .first
            .checked_add(rel)
            .filter(|p| *p <= stm.data.len())
            .ok_or(malformed)?;
        let mut lx = Lexer::new(&stm.data, pos, max_string, max_name, lenient);
        let mut w = Warnings::default();
        let obj = parse_object(&mut lx, max_depth, &mut w);
        self.record_warnings(num, w);
        obj
    }

    /// The members of object stream `stream`, in header order.
    fn objstm_members(&mut self, stream: u32, cancel: Cancel<'_>) -> Result<Vec<(u32, usize)>> {
        self.ensure_objstm(stream, cancel)?;
        Ok(self
            .cache
            .map
            .get(&stream)
            .map(|s| s.members.clone())
            .unwrap_or_default())
    }

    fn ensure_objstm(&mut self, stream: u32, cancel: Cancel<'_>) -> Result<()> {
        if self.cache.map.contains_key(&stream) {
            return Ok(());
        }
        match self.xref.get(&stream) {
            Some(Entry::Offset { .. }) => {}
            // An object stream inside an object stream (or inside itself) (§7.5.7).
            Some(Entry::Compressed { .. }) => {
                return Err(PdfError::ReferenceCycle { object: stream });
            }
            _ => {
                return Err(PdfError::Malformed {
                    object: Some(stream),
                    offset: 0,
                });
            }
        }
        let malformed = PdfError::Malformed {
            object: Some(stream),
            offset: 0,
        };
        let Object::Stream(s) = self.object(stream, cancel)? else {
            return Err(malformed);
        };
        let data = self.decode(&s, stream, cancel)?;
        let n = s
            .dict
            .get(b"N")
            .and_then(Object::as_i64)
            .and_then(|v| u64::try_from(v).ok())
            .ok_or(malformed.clone())?;
        if n > u64::from(self.limits.max_objects) {
            return Err(PdfError::TooManyObjects {
                limit: self.limits.max_objects,
            });
        }
        let first = s
            .dict
            .get(b"First")
            .and_then(Object::as_i64)
            .and_then(|v| usize::try_from(v).ok())
            .filter(|f| *f <= data.len())
            .ok_or(malformed)?;
        let mut members = Vec::new();
        {
            let head = data.get(..first).unwrap_or_default();
            let mut lx = Lexer::new(head, 0, 0, 0, true);
            let mut k: u64 = 0;
            while k < n {
                if k.is_multiple_of(4096) {
                    check(cancel)?;
                }
                let (Some(num), Some(o)) = (lx.uint(), lx.uint()) else {
                    break;
                };
                let (Ok(num), Ok(o)) = (u32::try_from(num), usize::try_from(o)) else {
                    break;
                };
                members.push((num, o));
                k = k.saturating_add(1);
            }
        }
        let size = u64::try_from(data.len()).unwrap_or(u64::MAX);
        while self.cache.bytes.saturating_add(size) > self.limits.objstm_cache_bytes {
            let Some(old) = self.cache.order.pop_front() else {
                break;
            };
            if let Some(o) = self.cache.map.remove(&old) {
                self.cache.bytes = self
                    .cache
                    .bytes
                    .saturating_sub(u64::try_from(o.data.len()).unwrap_or(0));
            }
        }
        self.cache.bytes = self.cache.bytes.saturating_add(size);
        self.cache.order.push_back(stream);
        self.cache.map.insert(
            stream,
            ObjStm {
                data,
                first,
                members,
            },
        );
        Ok(())
    }

    // ----- streams ----------------------------------------------------------------

    /// The filters of a stream, with `/Filter` and `/DecodeParms` resolved.
    fn filters_of(&mut self, dict: &Dictionary, cancel: Cancel<'_>) -> Result<Vec<Filter>> {
        let filter = match dict.get(b"Filter") {
            Some(f) => self.resolve(f, cancel)?,
            None => Object::Null,
        };
        let parms = match dict.get(b"DecodeParms") {
            Some(p) => self.resolve(p, cancel)?,
            None => Object::Null,
        };
        let names: Vec<Object> = match filter {
            Object::Array(a) => a,
            Object::Null => Vec::new(),
            other => vec![other],
        };
        let parms: Vec<Object> = match parms {
            Object::Array(a) => a,
            other => vec![other],
        };
        let mut out = Vec::new();
        for (i, n) in names.iter().enumerate() {
            if out.len() > usize::from(self.limits.max_filter_chain) {
                break;
            }
            let name = match self.resolve(n, cancel)? {
                Object::Name(n) => n,
                _ => {
                    return Err(PdfError::Malformed {
                        object: None,
                        offset: 0,
                    });
                }
            };
            let p = match parms.get(i) {
                Some(p) => match self.resolve(p, cancel)? {
                    Object::Dictionary(d) => Some(d),
                    _ => None,
                },
                None => None,
            };
            out.push(Filter { name, parms: p });
        }
        Ok(out)
    }

    fn decode(&mut self, s: &Stream, num: u32, cancel: Cancel<'_>) -> Result<Vec<u8>> {
        if s.dict.contains(b"F") {
            // The data is in an external file, which is never fetched (SEC-P07).
            return Err(PdfError::UnsupportedFilter { object: num });
        }
        let filters = self
            .filters_of(&s.dict, cancel)
            .map_err(|e| with_object(e, num))?;
        let raw = self.bytes.get(s.data.clone()).unwrap_or_default();
        let limits = self.limits;
        let mut ctx = filters::Ctx {
            limits: &limits,
            budget: &mut self.budget,
            cancel,
            object: num,
        };
        filters::decode(raw, &filters, &mut ctx)
    }

    /// Decode the stream object `num` through its filters, charged to the budgets.
    pub fn decode_stream(&mut self, num: u32, cancel: Cancel<'_>) -> Result<Vec<u8>> {
        match self.object(num, cancel)? {
            Object::Stream(s) => self.decode(&s, num, cancel),
            _ => Err(PdfError::Malformed {
                object: Some(num),
                offset: 0,
            }),
        }
    }
}

/// `/Filter` and `/DecodeParms` that are direct (an xref stream must not need the
/// xref to be decoded).
fn direct_filters(dict: &Dictionary) -> Option<Vec<Filter>> {
    let names: Vec<&Object> = match dict.get(b"Filter") {
        None => Vec::new(),
        Some(Object::Array(a)) => a.iter().collect(),
        Some(o) => vec![o],
    };
    let parms: Vec<&Object> = match dict.get(b"DecodeParms") {
        Some(Object::Array(a)) => a.iter().collect(),
        Some(o) => vec![o],
        None => Vec::new(),
    };
    names
        .iter()
        .enumerate()
        .map(|(i, n)| {
            let name = n.as_name()?.to_vec();
            let parms = match parms.get(i) {
                Some(Object::Dictionary(d)) => Some(d.clone()),
                _ => None,
            };
            Some(Filter { name, parms })
        })
        .collect()
}
