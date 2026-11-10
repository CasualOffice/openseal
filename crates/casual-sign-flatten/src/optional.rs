//! Optional content flattened to its default visibility (ISO 32000-2 §8.11, `FLT-03`,
//! SEC-S03).
//!
//! [`OptionalContent`] decides whether an optional content group (OCG) or membership
//! dictionary (OCMD) is visible under the document's default configuration
//! (`/OCProperties /D`): `/BaseState`, then `/ON` or `/OFF`, with `/Intent` matching;
//! an OCMD by its visibility expression (`/VE`) when it has a readable one, else by its
//! policy (`/P`) over its groups. [`rewrite`] removes what is hidden from one content
//! stream: within a hidden marked-content sequence (`/OC … BDC` … `EMC`) every painting
//! operator is dropped (a path is ended with `n` so a pending clip still applies; `'`
//! and `"` keep their line moves and spacing) while every graphics-state operator is
//! kept, as a viewer processes it (§8.11.3.2); anywhere, `Do` of an XObject whose `/OC`
//! is hidden is dropped. The flattened document then carries no `/OCProperties`, so
//! every viewer draws exactly what remains, whatever its optional content support.
//!
//! Not applied: the configuration's `/AS` automatic states (usage-driven, applied by
//! some viewers and not others) and the text advance of a hidden string: a visible
//! string placed only by that advance, in the same text object, moves (`FLT-06`,
//! proposed).

use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use casual_sign_pdf::{
    Cancel, ContentLexer, ContentToken, Dictionary, Document, Limits, Object, Operand,
};

use crate::canvas::num_fine;
use crate::error::FlattenError;
use crate::read;

use crate::limits::{MAX_VE_DEPTH, MAX_VE_TERMS};

/// The default configuration's visibility of every group, with caches.
#[derive(Debug, Default)]
pub(crate) struct OptionalContent {
    /// `/BaseState` is not `/OFF`.
    base_on: bool,
    on: BTreeSet<u32>,
    off: BTreeSet<u32>,
    /// The configuration's intents; `None` for `/All`.
    intents: Option<Vec<Vec<u8>>>,
    /// Visibility by object number, for groups and membership dictionaries.
    cache: BTreeMap<u32, bool>,
}

/// Names from a name or an array of names.
fn names(
    doc: &mut Document<'_>,
    v: &Object,
    cancel: Cancel<'_>,
) -> Result<Vec<Vec<u8>>, FlattenError> {
    Ok(match read::local(doc.resolve(v, cancel))? {
        Some(Object::Name(n)) => vec![n],
        Some(Object::Array(a)) => a
            .iter()
            .filter_map(Object::as_name)
            .map(<[u8]>::to_vec)
            .collect(),
        _ => Vec::new(),
    })
}

/// Object numbers of the references in an array (resolved when indirect).
fn refs(
    doc: &mut Document<'_>,
    v: Option<&Object>,
    cancel: Cancel<'_>,
) -> Result<Vec<u32>, FlattenError> {
    let Some(v) = v else {
        return Ok(Vec::new());
    };
    if let Some(r) = v.as_ref()
        && !matches!(
            read::local(doc.object(r.num, cancel))?,
            Some(Object::Array(_))
        )
    {
        return Ok(vec![r.num]);
    }
    Ok(match read::local(doc.resolve(v, cancel))? {
        Some(Object::Array(a)) => a.iter().filter_map(Object::as_ref).map(|r| r.num).collect(),
        _ => Vec::new(),
    })
}

impl OptionalContent {
    /// The default configuration of the catalog's `/OCProperties`, or `None` when the
    /// document has none (then every `/OC` is ignored, as viewers ignore it).
    pub(crate) fn read(
        doc: &mut Document<'_>,
        catalog: &Dictionary,
        cancel: Cancel<'_>,
    ) -> Result<Option<Self>, FlattenError> {
        let Some(props) = catalog.get(b"OCProperties").cloned() else {
            return Ok(None);
        };
        let props = read::dict(doc, &props, cancel)?.unwrap_or_default();
        let config = match props.get(b"D").cloned() {
            Some(d) => read::dict(doc, &d, cancel)?.unwrap_or_default(),
            None => Dictionary::new(),
        };
        let base_on = config.name(b"BaseState") != Some(b"OFF");
        let on = refs(doc, config.get(b"ON"), cancel)?.into_iter().collect();
        let off = refs(doc, config.get(b"OFF"), cancel)?.into_iter().collect();
        // No readable intent is the default, View.
        let intents = match config.get(b"Intent").cloned() {
            Some(v) => names(doc, &v, cancel)?,
            None => Vec::new(),
        };
        let intents = if intents.is_empty() {
            vec![b"View".to_vec()]
        } else {
            intents
        };
        let intents = (!intents.iter().any(|n| n == b"All")).then_some(intents);
        Ok(Some(Self {
            base_on,
            on,
            off,
            intents,
            cache: BTreeMap::new(),
        }))
    }

    /// Whether the group `num` (dictionary `d`) is on. A group whose `/Intent` the
    /// configuration does not consider has no effect, so counts as on.
    fn group(
        &mut self,
        doc: &mut Document<'_>,
        num: u32,
        d: &Dictionary,
        cancel: Cancel<'_>,
    ) -> Result<bool, FlattenError> {
        if let Some(v) = self.cache.get(&num) {
            return Ok(*v);
        }
        let considered = match &self.intents {
            None => true,
            Some(config) => {
                let own = match d.get(b"Intent").cloned() {
                    Some(v) => names(doc, &v, cancel)?,
                    None => Vec::new(),
                };
                if own.is_empty() {
                    config.iter().any(|i| i == b"View")
                } else {
                    own.iter().any(|i| i == b"All" || config.contains(i))
                }
            }
        };
        let on = !considered
            || if self.base_on {
                !self.off.contains(&num)
            } else {
                self.on.contains(&num)
            };
        self.cache.insert(num, on);
        Ok(on)
    }

    /// Whether content whose `/OC` (or `/OC … BDC` property list) is `value` is shown.
    /// Anything that is not a group or membership dictionary has no effect.
    ///
    /// # Errors
    ///
    /// `CS-FLT-0006` for a visibility expression over its bounds; the reader's fatal
    /// errors.
    pub(crate) fn visible(
        &mut self,
        doc: &mut Document<'_>,
        value: &Object,
        cancel: Cancel<'_>,
    ) -> Result<bool, FlattenError> {
        let num = value.as_ref().map(|r| r.num);
        if let Some(n) = num
            && let Some(v) = self.cache.get(&n)
        {
            return Ok(*v);
        }
        let Some(d) = read::dict(doc, value, cancel)? else {
            return Ok(true);
        };
        let v = match (d.name(b"Type"), num) {
            (Some(b"OCG"), Some(n)) => return self.group(doc, n, &d, cancel),
            // A group must be indirect to be named by `/ON` or `/OFF`; a direct one is
            // on unless the base state says otherwise.
            (Some(b"OCG"), None) => self.base_on,
            (Some(b"OCMD"), _) => self.membership(doc, &d, num, cancel)?,
            _ => true,
        };
        if let Some(n) = num {
            self.cache.insert(n, v);
        }
        Ok(v)
    }

    /// An OCMD: its `/VE` when readable, else `/P` over `/OCGs` (ISO 32000-2
    /// §8.11.2.2). No groups means no effect.
    fn membership(
        &mut self,
        doc: &mut Document<'_>,
        d: &Dictionary,
        num: Option<u32>,
        cancel: Cancel<'_>,
    ) -> Result<bool, FlattenError> {
        if let Some(ve) = d.get(b"VE").cloned() {
            let mut terms = 0usize;
            if let Some(v) = self.expression(doc, &ve, 0, &mut terms, num, cancel)? {
                return Ok(v);
            }
        }
        let mut states = Vec::new();
        for g in refs(doc, d.get(b"OCGs"), cancel)? {
            let Some(gd) = read::object_dict(doc, g, cancel)? else {
                continue;
            };
            if gd.name(b"Type") == Some(b"OCG") {
                states.push(self.group(doc, g, &gd, cancel)?);
            }
        }
        if states.is_empty() {
            return Ok(true);
        }
        Ok(match d.name(b"P") {
            Some(b"AllOn") => states.iter().all(|s| *s),
            Some(b"AnyOff") => states.iter().any(|s| !*s),
            Some(b"AllOff") => states.iter().all(|s| !*s),
            // `/AnyOn` is the default.
            _ => states.iter().any(|s| *s),
        })
    }

    /// A visibility expression: `[/And e …]`, `[/Or e …]`, `[/Not e]`, or a group.
    /// `Ok(None)` when malformed (the policy then decides).
    fn expression(
        &mut self,
        doc: &mut Document<'_>,
        e: &Object,
        depth: usize,
        terms: &mut usize,
        owner: Option<u32>,
        cancel: Cancel<'_>,
    ) -> Result<Option<bool>, FlattenError> {
        *terms = terms.saturating_add(1);
        if depth > MAX_VE_DEPTH || *terms > MAX_VE_TERMS {
            return Err(FlattenError::OptionalContentTooComplex { object: owner });
        }
        let resolved = match read::local(doc.resolve(e, cancel))? {
            Some(o) => o,
            None => return Ok(None),
        };
        match resolved {
            Object::Dictionary(d) => match (d.name(b"Type"), e.as_ref()) {
                (Some(b"OCG"), Some(r)) => Ok(Some(self.group(doc, r.num, &d, cancel)?)),
                _ => Ok(None),
            },
            Object::Array(items) => {
                let Some((op, operands)) = items.split_first() else {
                    return Ok(None);
                };
                let mut values = Vec::with_capacity(operands.len().min(MAX_VE_TERMS));
                for o in operands {
                    match self.expression(doc, o, depth.saturating_add(1), terms, owner, cancel)? {
                        Some(v) => values.push(v),
                        None => return Ok(None),
                    }
                }
                Ok(match (op.as_name(), values.as_slice()) {
                    (Some(b"Not"), [v]) => Some(!*v),
                    (Some(b"And"), [_, ..]) => Some(values.iter().all(|v| *v)),
                    (Some(b"Or"), [_, ..]) => Some(values.iter().any(|v| *v)),
                    _ => None,
                })
            }
            _ => Ok(None),
        }
    }
}

/// What [`rewrite`] asks of its caller.
#[derive(Debug)]
pub(crate) enum Query<'a> {
    /// Is the property list named here (`/OC /name BDC`) hidden?
    Property(&'a [u8]),
    /// Is the XObject named here (`/name Do`) hidden?
    XObject(&'a [u8]),
}

/// What [`rewrite`] did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Rewritten {
    /// Hidden marked-content sequences met.
    pub sections: usize,
    /// Operators dropped or replaced.
    pub operators: usize,
    /// `/OC … BDC` markers made plain `/OC BMC`, so no viewer evaluates them again
    /// without a configuration (PDFium evaluates a membership dictionary with every
    /// group on when `/OCProperties` is gone).
    pub markers: usize,
}

/// Operators that paint a path: replaced by `n` in hidden content, which ends the path
/// as they would and still applies a pending clip.
const PATH_PAINT: [&[u8]; 9] = [b"S", b"s", b"f", b"F", b"f*", b"B", b"B*", b"b", b"b*"];

fn operand_text(o: &Operand) -> String {
    o.as_f64().map_or_else(|| "0".to_owned(), num_fine)
}

/// The content stream `data` without what the default configuration hides and with
/// its optional content markers made plain, or `None` when it has neither. `hidden`
/// answers for names; it may read the document.
///
/// # Errors
///
/// A tokenizer limit (`CS-PDF-0002`, `0004`, `0008`) as [`FlattenError::Content`] with
/// `object`; whatever `hidden` returns.
pub(crate) fn rewrite(
    data: &[u8],
    limits: &Limits,
    object: u32,
    hidden: &mut dyn FnMut(Query<'_>) -> Result<bool, FlattenError>,
) -> Result<Option<(Vec<u8>, Rewritten)>, FlattenError> {
    let mut lx = ContentLexer::new(data, limits);
    let mut out: Vec<u8> = Vec::new();
    let mut stats = Rewritten::default();
    let mut start = 0usize;
    // The last operands only: no operator this pass reads takes more than three.
    let mut operands: Vec<Operand> = Vec::new();
    let mut depth = 0usize;
    let mut hidden_from: Option<usize> = None;
    while let Some(tok) = lx.next() {
        let tok = tok.map_err(|e| FlattenError::Content {
            object,
            code: e.code(),
        })?;
        let end = lx.position().min(data.len());
        let span = data.get(start..end).unwrap_or_default();
        let replacement: Option<Vec<u8>> = match tok {
            ContentToken::Operand(o) => {
                if operands.len() >= 4 {
                    operands.remove(0);
                }
                operands.push(o);
                continue;
            }
            ContentToken::Operator(op) => match op {
                b"BMC" => {
                    depth = depth.saturating_add(1);
                    None
                }
                b"BDC" => {
                    depth = depth.saturating_add(1);
                    match operands.as_slice() {
                        [.., tag, props] if tag.as_name() == Some(b"OC") => {
                            if hidden_from.is_none()
                                && let Some(name) = props.as_name()
                                && hidden(Query::Property(name))?
                            {
                                hidden_from = Some(depth);
                                stats.sections = stats.sections.saturating_add(1);
                            }
                            stats.markers = stats.markers.saturating_add(1);
                            Some(b"/OC BMC".to_vec())
                        }
                        _ => None,
                    }
                }
                b"EMC" => {
                    if hidden_from == Some(depth) {
                        hidden_from = None;
                    }
                    depth = depth.saturating_sub(1);
                    None
                }
                b"Do" if hidden_from.is_some() => Some(Vec::new()),
                b"Do" => match operands.last().and_then(Operand::as_name) {
                    Some(name) if hidden(Query::XObject(name))? => Some(Vec::new()),
                    _ => None,
                },
                _ if hidden_from.is_none() => None,
                op if PATH_PAINT.contains(&op) => Some(b"n".to_vec()),
                b"sh" | b"Tj" | b"TJ" => Some(Vec::new()),
                b"'" => Some(b"T*".to_vec()),
                b"\"" => match operands.as_slice() {
                    [.., aw, ac, _] => Some(
                        format!("{} Tw {} Tc T*", operand_text(aw), operand_text(ac)).into_bytes(),
                    ),
                    _ => Some(b"T*".to_vec()),
                },
                _ => None,
            },
            // An inline image (or a token a later tokenizer adds): painting when hidden.
            _ => hidden_from.is_some().then(Vec::new),
        };
        operands.clear();
        match replacement {
            None => out.extend_from_slice(span),
            Some(r) => {
                if r != b"/OC BMC" {
                    stats.operators = stats.operators.saturating_add(1);
                }
                out.push(b'\n');
                out.extend_from_slice(&r);
                out.push(b'\n');
            }
        }
        start = end;
    }
    out.extend_from_slice(data.get(start..).unwrap_or_default());
    Ok((stats.operators > 0 || stats.markers > 0).then_some((out, stats)))
}

/// A form XObject or pattern whose content changed.
#[derive(Debug)]
pub(crate) struct StreamEdit {
    pub num: u32,
    pub dict: Dictionary,
    pub data: Vec<u8>,
}

/// What the pass over every reachable content stream found.
#[derive(Debug, Default)]
pub(crate) struct Pass {
    /// New decoded content of pages (by index) that had hidden content.
    pub pages: BTreeMap<usize, Vec<u8>>,
    /// Form XObjects and tiling patterns with hidden content or markers, rewritten
    /// (without `/OC`).
    pub streams: Vec<StreamEdit>,
    /// Visible XObjects whose only change is losing their `/OC`, as read (their data is
    /// copied as it is).
    pub stripped: Vec<(u32, Object)>,
    /// Totals over everything rewritten.
    pub stats: Rewritten,
    /// Whether each XObject read has a hidden `/OC`, by object number.
    hidden_xobjects: BTreeMap<u32, bool>,
    /// Streams queued once for reading.
    queued: BTreeSet<u32>,
    /// Visible XObjects that carry `/OC`.
    strip: BTreeSet<u32>,
}

/// A resource subdictionary, resolved.
fn sub(
    doc: &mut Document<'_>,
    res: &Dictionary,
    key: &[u8],
    cancel: Cancel<'_>,
) -> Result<Dictionary, FlattenError> {
    Ok(match res.get(key).cloned() {
        Some(v) => read::dict(doc, &v, cancel)?.unwrap_or_default(),
        None => Dictionary::new(),
    })
}

impl Pass {
    /// Whether stream `num` (an XObject, an appearance) carries an `/OC` that is hidden.
    pub(crate) fn stream_hidden(
        &mut self,
        doc: &mut Document<'_>,
        oc: &mut OptionalContent,
        num: u32,
        cancel: Cancel<'_>,
    ) -> Result<bool, FlattenError> {
        if let Some(h) = self.hidden_xobjects.get(&num) {
            return Ok(*h);
        }
        let hidden = match read::object_dict(doc, num, cancel)?.and_then(|d| d.get(b"OC").cloned())
        {
            Some(v) => !oc.visible(doc, &v, cancel)?,
            None => false,
        };
        self.hidden_xobjects.insert(num, hidden);
        Ok(hidden)
    }

    /// Rewrite `data` read with resources `res`; queue the forms and patterns it can
    /// draw.
    #[allow(clippy::too_many_arguments)] // One call site; the pieces are all distinct.
    fn one(
        &mut self,
        doc: &mut Document<'_>,
        oc: &mut OptionalContent,
        data: &[u8],
        object: u32,
        res: &Rc<Dictionary>,
        queue: &mut Vec<(u32, Rc<Dictionary>)>,
        cancel: Cancel<'_>,
    ) -> Result<Option<Vec<u8>>, FlattenError> {
        let props = sub(doc, res, b"Properties", cancel)?;
        let xobjects = sub(doc, res, b"XObject", cancel)?;
        let limits = *doc.limits();
        let out = {
            let mut ask = |q: Query<'_>| -> Result<bool, FlattenError> {
                match q {
                    Query::Property(name) => match props.get(name) {
                        Some(v) => Ok(!oc.visible(doc, v, cancel)?),
                        None => Ok(false),
                    },
                    Query::XObject(name) => match xobjects.get(name).and_then(Object::as_ref) {
                        Some(r) => self.stream_hidden(doc, oc, r.num, cancel),
                        None => Ok(false),
                    },
                }
            };
            rewrite(data, &limits, object, &mut ask)?
        };
        // Everything this stream can draw, whether or not it changed.
        for (_, v) in xobjects.iter() {
            let Some(r) = v.as_ref() else { continue };
            if self.queued.contains(&r.num) || self.stream_hidden(doc, oc, r.num, cancel)? {
                continue;
            }
            let Some(d) = read::object_dict(doc, r.num, cancel)? else {
                continue;
            };
            if d.contains(b"OC") {
                self.strip.insert(r.num);
            }
            if d.name(b"Subtype") == Some(b"Form") {
                self.queued.insert(r.num);
                queue.push((r.num, Rc::clone(res)));
            }
        }
        let patterns = sub(doc, res, b"Pattern", cancel)?;
        for (_, v) in patterns.iter() {
            let Some(r) = v.as_ref() else { continue };
            if !self.queued.contains(&r.num)
                && read::object_dict(doc, r.num, cancel)?
                    .is_some_and(|d| d.get(b"PatternType").and_then(Object::as_i64) == Some(1))
            {
                self.queued.insert(r.num);
                queue.push((r.num, Rc::clone(res)));
            }
        }
        Ok(out.map(|(bytes, s)| {
            self.stats.sections = self.stats.sections.saturating_add(s.sections);
            self.stats.operators = self.stats.operators.saturating_add(s.operators);
            self.stats.markers = self.stats.markers.saturating_add(s.markers);
            bytes
        }))
    }

    /// Every page's content, every form and pattern they reach, and the streams in
    /// `appearances` (with what they reach), rewritten where something is hidden. Each
    /// stream is read once; the document's decode budget bounds the work.
    pub(crate) fn run(
        &mut self,
        doc: &mut Document<'_>,
        oc: &mut OptionalContent,
        pages: &[(usize, u32, Dictionary)],
        appearances: &[u32],
        cancel: Cancel<'_>,
    ) -> Result<(), FlattenError> {
        let pass = self;
        let mut queue: Vec<(u32, Rc<Dictionary>)> = Vec::new();
        for (index, object, page) in pages {
            let index = *index;
            let res = Rc::new(read::resources(doc, page, cancel)?);
            let mut data = Vec::new();
            for c in read::contents(doc, page, cancel)? {
                let Some(r) = c.as_ref() else { continue };
                if let Some(bytes) = read::local(doc.decode_stream(r.num, cancel))? {
                    data.extend_from_slice(&bytes);
                    data.push(b'\n');
                }
            }
            if let Some(new) = pass.one(doc, oc, &data, *object, &res, &mut queue, cancel)? {
                pass.pages.insert(index, new);
            }
        }
        let none = Rc::new(Dictionary::new());
        for n in appearances {
            if pass.queued.insert(*n) {
                queue.push((*n, Rc::clone(&none)));
            }
        }
        while let Some((num, inherited)) = queue.pop() {
            let Some(Object::Stream(s)) = read::local(doc.object(num, cancel))? else {
                continue;
            };
            // An appearance of something that stays, hidden by its own `/OC`: emptied,
            // as no configuration will hide it any more.
            if pass.stream_hidden(doc, oc, num, cancel)? {
                let mut dict = s.dict.clone();
                dict.remove(b"OC");
                pass.streams.push(StreamEdit {
                    num,
                    dict,
                    data: Vec::new(),
                });
                continue;
            }
            let Some(data) = read::local(doc.decode_stream(num, cancel))? else {
                continue;
            };
            let res = match s.dict.get(b"Resources").cloned() {
                Some(v) => Rc::new(read::dict(doc, &v, cancel)?.unwrap_or_default()),
                None => inherited,
            };
            let mut dict = s.dict.clone();
            dict.remove(b"OC");
            if let Some(new) = pass.one(doc, oc, &data, num, &res, &mut queue, cancel)? {
                pass.streams.push(StreamEdit {
                    num,
                    dict,
                    data: new,
                });
                pass.strip.remove(&num);
            } else if s.dict.contains(b"OC") {
                pass.strip.insert(num);
            }
        }
        // Visible XObjects (images, unchanged forms, appearances) lose `/OC`: with no
        // configuration left, no viewer may decide on it again.
        for num in std::mem::take(&mut pass.strip) {
            if let Some(Object::Stream(mut s)) = read::local(doc.object(num, cancel))? {
                s.dict.remove(b"OC");
                pass.stripped.push((num, Object::Stream(s)));
            }
        }
        Ok(())
    }
}

/// Every stream of an annotation's appearance dictionary (`/N`, `/R`, `/D`, each a
/// stream or a dictionary of states).
pub(crate) fn appearance_streams(
    doc: &mut Document<'_>,
    annot: &Dictionary,
    cancel: Cancel<'_>,
) -> Result<Vec<u32>, FlattenError> {
    let mut out = Vec::new();
    let Some(ap) = annot.get(b"AP").cloned() else {
        return Ok(out);
    };
    let Some(ap) = read::dict(doc, &ap, cancel)? else {
        return Ok(out);
    };
    for key in [&b"N"[..], b"R", b"D"] {
        let Some(v) = ap.get(key) else { continue };
        let Some(r) = v.as_ref() else {
            if let Object::Dictionary(states) = v {
                out.extend(states.iter().filter_map(|(_, s)| s.as_ref()).map(|r| r.num));
            }
            continue;
        };
        match read::local(doc.object(r.num, cancel))? {
            Some(Object::Stream(_)) => out.push(r.num),
            Some(Object::Dictionary(states)) => {
                out.extend(states.iter().filter_map(|(_, s)| s.as_ref()).map(|r| r.num));
            }
            _ => {}
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(data: &[u8], hide: &[&[u8]]) -> (String, Rewritten) {
        let mut q = |q: Query<'_>| -> Result<bool, FlattenError> {
            Ok(match q {
                Query::Property(n) | Query::XObject(n) => hide.contains(&n),
            })
        };
        let r = rewrite(data, &Limits::default(), 1, &mut q).unwrap_or(None);
        match r {
            Some((b, s)) => (String::from_utf8_lossy(&b).into_owned(), s),
            None => (
                String::from_utf8_lossy(data).into_owned(),
                Rewritten::default(),
            ),
        }
    }

    #[test]
    fn hidden_painting_goes_and_graphics_state_stays() {
        let src = b"q /OC /off BDC 1 0 0 rg 0 0 10 10 re f BT /F1 9 Tf 1 2 Td (gone) Tj [(x)] TJ ET /Im Do 2 0 0 2 0 0 cm EMC BT (kept) Tj ET Q";
        let (out, s) = run(src, &[b"off"]);
        assert!(!out.contains("(gone) Tj") && !out.contains("TJ") && !out.contains("/Im Do"));
        assert!(out.contains("re\nn\n") || out.contains("re \nn\n") || out.contains("\nn\n"));
        for kept in [
            "1 0 0 rg",
            "/F1 9 Tf",
            "1 2 Td",
            "2 0 0 2 0 0 cm",
            "(kept) Tj",
            "BT",
            "ET",
            "EMC",
        ] {
            assert!(out.contains(kept), "{kept} in {out}");
        }
        assert_eq!(s.sections, 1);
        assert_eq!(s.operators, 4);
    }

    #[test]
    fn visible_content_is_left_byte_for_byte_but_for_its_markers() {
        let src = b"/Span <</MCID 0>> BDC (a) Tj EMC /X Do";
        let mut ask = |_: Query<'_>| -> Result<bool, FlattenError> { Ok(false) };
        assert_eq!(
            rewrite(src, &Limits::default(), 1, &mut ask).ok(),
            Some(None)
        );
        let (out, s) = run(b"/OC /on BDC (a) Tj EMC /X Do", &[]);
        assert_eq!(out, "\n/OC BMC\n (a) Tj EMC /X Do");
        assert_eq!((s.markers, s.operators, s.sections), (1, 0, 0));
    }

    #[test]
    fn nested_sections_end_with_the_hidden_one() {
        let src = b"/OC /on BDC /OC /off BDC /Span BMC (a) Tj EMC (b) Tj EMC (c) Tj EMC (d) Tj";
        let (out, _) = run(src, &[b"off"]);
        assert!(!out.contains("(a) Tj") && !out.contains("(b) Tj"), "{out}");
        assert!(out.contains("(c) Tj") && out.contains("(d) Tj"), "{out}");
    }

    #[test]
    fn line_moving_text_operators_keep_their_moves() {
        let src = b"/OC /off BDC BT (a) ' 2 1.5 (b) \" ET EMC";
        let (out, _) = run(src, &[b"off"]);
        assert!(
            out.contains("T*") && out.contains("2 Tw 1.5 Tc T*"),
            "{out}"
        );
        assert!(!out.contains("(a)") && !out.contains("(b)"), "{out}");
    }

    #[test]
    fn a_hidden_xobject_is_not_invoked_and_inline_images_in_hidden_content_go() {
        let (out, _) = run(b"/A Do /B Do", &[b"B"]);
        assert!(out.contains("/A Do") && !out.contains("/B Do"));
        let (out, _) = run(
            b"/OC /off BDC BI /W 1 /H 1 /BPC 8 /CS /G ID \x00 EI EMC",
            &[b"off"],
        );
        assert!(!out.contains("BI"), "{out}");
    }

    #[test]
    fn an_unclosed_hidden_section_hides_to_the_end() {
        let (out, _) = run(b"/OC /off BDC (a) Tj", &[b"off"]);
        assert!(!out.contains("(a) Tj"));
    }
}
