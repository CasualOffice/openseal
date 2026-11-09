//! Text with positions (docs/30 §5): a bounded content-stream interpreter for the text
//! operators only. Nothing is rendered; each shown glyph becomes a quadrilateral in
//! displayed page space with its Unicode text, which is what anchors and text tags need.
//!
//! Operators read: `BT ET Tf Tm Td TD T* TL Tc Tw Tz Ts Tj TJ ' "`, `q Q cm`, and `Do`
//! for Form XObjects (nested at most [`MAX_XOBJECT_DEPTH`] deep, cycle-safe). Every
//! operator a page runs, in its own streams or in forms, counts against
//! `Limits::max_content_ops` (docs/21, `CS-PDF-0013`); glyphs kept per page are capped
//! at [`MAX_GLYPHS_PER_PAGE`]. Streams are decoded through the reader, so its decode
//! budget bounds the work (`CS-PDF-0003`). A limit crossed on one page stops that page
//! with a [`TextFinding`]; only the document's budgets and cancellation end the call.

use std::collections::{BTreeMap, VecDeque};
use std::rc::Rc;

use casual_sign_pdf::{Dictionary, Document, Object, PageInfo, PdfError};
use unicode_normalization::UnicodeNormalization;

use crate::content::{Lexer, Operand, Token};
use crate::font::{self, Code, Font, local};
use crate::geometry::{DisplayRect, PageGeometry, Point};

/// Deepest nesting of Form XObjects (`Do` inside a form inside a form …).
pub const MAX_XOBJECT_DEPTH: usize = 8;
/// Most glyphs kept per page. A decision of `T-1C`: docs/21 names no such limit; a
/// dense page holds about 5,000.
pub const MAX_GLYPHS_PER_PAGE: usize = 500_000;
/// Deepest `q` nesting tracked; deeper `q`/`Q` pairs are counted, not stored.
const MAX_GS_DEPTH: usize = 256;
/// Operands kept on the stack; older ones are dropped (no operator takes more than 6).
const MAX_OPERANDS: usize = 64;
/// Decoded Form XObject bytes kept per page for reuse.
const FORM_CACHE_BYTES: usize = 32 * 1024 * 1024;
/// Operators between cancellation checks.
const CANCEL_EVERY: u32 = 4_096;

/// Four corners of a glyph or run in displayed page space, in the text's own
/// orientation: lower-left, lower-right, upper-right, upper-left.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Quad {
    /// Start of the text, at the descent line.
    pub ll: Point,
    /// End of the text, at the descent line.
    pub lr: Point,
    /// End of the text, at the ascent line.
    pub ur: Point,
    /// Start of the text, at the ascent line.
    pub ul: Point,
}

impl Quad {
    /// The axis-aligned rectangle holding the quad.
    #[must_use]
    pub fn bounds(&self) -> DisplayRect {
        DisplayRect::bounding([self.ll, self.lr, self.ur, self.ul]).unwrap_or_default()
    }
}

/// One shown glyph.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Glyph {
    /// Byte range of its text within [`TextRun::text`] (empty when nothing maps it).
    pub text: (usize, usize),
    /// Where it is drawn: advance width by ascent and descent.
    pub quad: Quad,
    /// Its origin on the baseline.
    pub origin: Point,
    /// The end of its advance on the baseline (where the next glyph would start without
    /// spacing).
    pub end: Point,
}

/// The glyphs of one show operator (`Tj`, `TJ`, `'`, `"`).
#[derive(Debug, Clone, PartialEq)]
pub struct TextRun {
    /// Unicode text of the glyphs, in order, with no inferred spaces.
    pub text: String,
    /// The glyphs.
    pub glyphs: Vec<Glyph>,
    /// From the first glyph's start to the last glyph's end.
    pub quad: Quad,
    /// The em size in displayed points.
    pub size: f64,
}

/// What stopped or degraded extraction on a page.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum TextIssue {
    /// The page ran more than `Limits::max_content_ops` operators; the rest of the page
    /// was not read (`CS-PDF-0013`).
    ContentOps,
    /// The page showed more than [`MAX_GLYPHS_PER_PAGE`] glyphs; the rest were not
    /// kept (`CS-PDF-0013`).
    Glyphs,
    /// A Form XObject nested deeper than [`MAX_XOBJECT_DEPTH`] was skipped (`CS-PDF-0004`).
    XObjectDepth,
    /// A Form XObject that invokes itself was skipped (`CS-PDF-0004`).
    XObjectCycle,
    /// A content stream or form could not be decoded and was skipped (its reader code).
    StreamUnreadable,
    /// A content stream nested too deep or held too many values; the rest of it was
    /// skipped (`CS-PDF-0004`, `CS-PDF-0002`).
    Tokenizer,
    /// A font had no widths and no standard-14 metrics: positions use a fixed width
    /// (`CS-PDF-0102`).
    FallbackWidths,
    /// A font used a predefined CMap we carry no data for; codes were read as two bytes
    /// (`CS-PDF-0102`).
    UnsupportedCMap,
    /// A font writes vertically; its glyphs were placed as horizontal text (`CS-PDF-0102`).
    VerticalText,
}

/// One issue, with its docs/20 code and the object it concerns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TextFinding {
    /// The docs/20 code.
    pub code: &'static str,
    /// What happened.
    pub issue: TextIssue,
    /// The object, when one is to blame.
    pub object: Option<u32>,
}

/// The text of one page.
#[derive(Debug, Clone, PartialEq)]
pub struct PageText {
    /// 1-based page number.
    pub page: u32,
    /// The page's geometry.
    pub geometry: PageGeometry,
    /// Runs in content order.
    pub runs: Vec<TextRun>,
    /// What was skipped or guessed, de-duplicated.
    pub findings: Vec<TextFinding>,
    /// Operators counted.
    pub operators: u32,
}

impl PageText {
    /// True when any glyph's width was guessed.
    #[must_use]
    pub fn fallback_widths(&self) -> bool {
        self.findings
            .iter()
            .any(|f| f.issue == TextIssue::FallbackWidths)
    }

    /// True when a limit stopped extraction early on this page.
    #[must_use]
    pub fn truncated(&self) -> bool {
        self.findings
            .iter()
            .any(|f| matches!(f.issue, TextIssue::ContentOps | TextIssue::Glyphs))
    }

    /// The page's text in content order, NFKC-normalized, with whitespace inferred from
    /// glyph positions and collapsed to single spaces.
    #[must_use]
    pub fn text(&self) -> String {
        char_stream(self, false).chars.into_iter().collect()
    }
}

/// The text of a page as matched by anchors and tags: one entry per character, each
/// pointing at the glyph it came from (`None` for an inferred space).
#[derive(Debug, Clone, Default)]
pub(crate) struct Chars {
    pub(crate) chars: Vec<char>,
    pub(crate) src: Vec<Option<(usize, usize)>>,
}

impl Chars {
    fn push(&mut self, c: char, src: Option<(usize, usize)>) {
        if c.is_whitespace() {
            if self.chars.last().is_some_and(|l| *l != ' ') {
                self.chars.push(' ');
                self.src.push(None);
            }
        } else {
            self.chars.push(c);
            self.src.push(src);
        }
    }

    /// The bounding rectangle of the glyphs behind `chars[from..to]`.
    pub(crate) fn rect(&self, page: &PageText, from: usize, to: usize) -> Option<DisplayRect> {
        let mut out: Option<DisplayRect> = None;
        for (r, g) in self.src.get(from..to)?.iter().flatten() {
            let q = page.runs.get(*r)?.glyphs.get(*g)?.quad.bounds();
            out = Some(out.map_or(q, |o| o.union(&q)));
        }
        out
    }
}

fn sub(a: Point, b: Point) -> Point {
    Point::new(a.x - b.x, a.y - b.y)
}

fn dot(a: Point, b: Point) -> f64 {
    a.x * b.x + a.y * b.y
}

/// True when the gap from glyph `p` (in a run of em size `size`) to `n` reads as
/// whitespace: another line, a gap of a fifth of an em or more, or a jump backwards.
fn gap(p: &Glyph, n: &Glyph, size: f64) -> bool {
    let d = sub(p.end, p.origin);
    let len = dot(d, d).sqrt();
    let u = if len > 1e-9 {
        Point::new(d.x / len, d.y / len)
    } else {
        Point::new(1.0, 0.0)
    };
    let v = Point::new(-u.y, u.x);
    let delta = sub(n.origin, p.end);
    let along = dot(delta, u);
    let across = dot(delta, v);
    let size = size.abs().max(1e-6);
    across.abs() > 0.5 * size || along > 0.2 * size || along < -0.8 * size
}

/// Build the matching text of a page: NFKC per glyph, whitespace inferred and collapsed,
/// optionally lower-cased.
pub(crate) fn char_stream(page: &PageText, fold_case: bool) -> Chars {
    let mut out = Chars::default();
    let mut prev: Option<(Glyph, f64)> = None;
    for (ri, run) in page.runs.iter().enumerate() {
        for (gi, g) in run.glyphs.iter().enumerate() {
            let text = run.text.get(g.text.0..g.text.1).unwrap_or_default();
            if let Some((p, size)) = &prev
                && gap(p, g, *size)
            {
                out.push(' ', None);
            }
            for c in text.nfkc() {
                if fold_case {
                    for l in c.to_lowercase() {
                        out.push(l, Some((ri, gi)));
                    }
                } else {
                    out.push(c, Some((ri, gi)));
                }
            }
            prev = Some((*g, run.size));
        }
    }
    if out.chars.last() == Some(&' ') {
        out.chars.pop();
        out.src.pop();
    }
    out
}

/// An affine matrix `[a b c d e f]` (§8.3.3), applied to row vectors.
#[derive(Debug, Clone, Copy, PartialEq)]
struct M {
    a: f64,
    b: f64,
    c: f64,
    d: f64,
    e: f64,
    f: f64,
}

impl M {
    const ID: Self = Self {
        a: 1.0,
        b: 0.0,
        c: 0.0,
        d: 1.0,
        e: 0.0,
        f: 0.0,
    };

    fn from(v: &[f64]) -> Option<Self> {
        match v {
            [a, b, c, d, e, f] if v.iter().all(|x| x.is_finite()) => Some(Self {
                a: *a,
                b: *b,
                c: *c,
                d: *d,
                e: *e,
                f: *f,
            }),
            _ => None,
        }
    }

    fn translate(x: f64, y: f64) -> Self {
        Self {
            e: x,
            f: y,
            ..Self::ID
        }
    }

    /// `self × o`: apply `self`, then `o`.
    fn then(&self, o: &Self) -> Self {
        Self {
            a: self.a * o.a + self.b * o.c,
            b: self.a * o.b + self.b * o.d,
            c: self.c * o.a + self.d * o.c,
            d: self.c * o.b + self.d * o.d,
            e: self.e * o.a + self.f * o.c + o.e,
            f: self.e * o.b + self.f * o.d + o.f,
        }
    }

    fn apply(&self, x: f64, y: f64) -> Point {
        Point::new(
            x * self.a + y * self.c + self.e,
            x * self.b + y * self.d + self.f,
        )
    }
}

#[derive(Debug, Clone)]
struct Gs {
    ctm: M,
    font: Option<Rc<Font>>,
    size: f64,
    tc: f64,
    tw: f64,
    th: f64,
    tl: f64,
    rise: f64,
}

impl Gs {
    fn new(ctm: M) -> Self {
        Self {
            ctm,
            font: None,
            size: 0.0,
            tc: 0.0,
            tw: 0.0,
            th: 1.0,
            tl: 0.0,
            rise: 0.0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum FontKey {
    Object(u32),
    Direct(u32, Vec<u8>),
}

/// Why a page stopped early (not an error: the page keeps what it read).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Stop;

struct Interp<'d, 'a, 'c> {
    doc: &'d mut Document<'a>,
    geom: PageGeometry,
    cancel: &'c dyn Fn() -> bool,
    ops: u32,
    max_ops: u32,
    glyphs: usize,
    runs: Vec<TextRun>,
    findings: Vec<TextFinding>,
    fonts: BTreeMap<FontKey, Rc<Font>>,
    forms: BTreeMap<u32, Rc<Vec<u8>>>,
    form_bytes: usize,
    xobjects: Vec<u32>,
    gs: Gs,
    stack: Vec<Gs>,
    deep_q: u32,
    tm: M,
    tlm: M,
}

type Flow = Result<Result<(), Stop>, PdfError>;

impl Interp<'_, '_, '_> {
    fn finding(&mut self, code: &'static str, issue: TextIssue, object: Option<u32>) {
        let f = TextFinding {
            code,
            issue,
            object,
        };
        if !self.findings.contains(&f) && self.findings.len() < 1_000 {
            self.findings.push(f);
        }
    }

    fn resolve(&mut self, o: Option<&Object>) -> Result<Option<Object>, PdfError> {
        match o {
            Some(o) => local(self.doc.resolve(o, self.cancel)),
            None => Ok(None),
        }
    }

    /// Entry `name` of resource category `cat` (`Font`, `XObject`).
    fn resource(
        &mut self,
        res: &Dictionary,
        cat: &[u8],
        name: &[u8],
    ) -> Result<Option<Object>, PdfError> {
        let Some(d) = self.resolve(res.get(cat))? else {
            return Ok(None);
        };
        Ok(d.get(name).cloned())
    }

    fn run(&mut self, data: &[u8], res: &Dictionary, owner: u32) -> Flow {
        let mut lx = Lexer::new(data);
        let mut operands: VecDeque<Operand> = VecDeque::new();
        while let Some(t) = lx.next_token() {
            let t = match t {
                Ok(t) => t,
                Err(e) => {
                    self.finding(e.code(), TextIssue::Tokenizer, Some(owner));
                    return Ok(Ok(()));
                }
            };
            match t {
                Token::Operand(o) => {
                    if operands.len() >= MAX_OPERANDS {
                        operands.pop_front();
                    }
                    operands.push_back(o);
                }
                Token::Op(op) => {
                    self.ops = self.ops.saturating_add(1);
                    if self.ops > self.max_ops {
                        self.finding("CS-PDF-0013", TextIssue::ContentOps, None);
                        return Ok(Err(Stop));
                    }
                    if self.ops.is_multiple_of(CANCEL_EVERY) && (self.cancel)() {
                        return Err(PdfError::Cancelled);
                    }
                    let ops = operands.make_contiguous();
                    if let Err(stop) = self.op(op, ops, res, owner)? {
                        return Ok(Err(stop));
                    }
                    operands.clear();
                }
            }
        }
        Ok(Ok(()))
    }

    fn nums<const N: usize>(ops: &[Operand]) -> Option<[f64; N]> {
        let start = ops.len().checked_sub(N)?;
        let mut out = [0.0; N];
        for (slot, o) in out.iter_mut().zip(ops.get(start..)?) {
            *slot = o.num().filter(|v| v.is_finite())?;
        }
        Some(out)
    }

    fn op(&mut self, op: &[u8], ops: &[Operand], res: &Dictionary, owner: u32) -> Flow {
        match op {
            b"q" => {
                if self.stack.len() < MAX_GS_DEPTH {
                    self.stack.push(self.gs.clone());
                } else {
                    self.deep_q = self.deep_q.saturating_add(1);
                }
            }
            b"Q" => {
                if self.deep_q > 0 {
                    self.deep_q = self.deep_q.saturating_sub(1);
                } else if let Some(g) = self.stack.pop() {
                    self.gs = g;
                }
            }
            b"cm" => {
                if let Some(m) = Self::nums::<6>(ops).and_then(|v| M::from(&v)) {
                    self.gs.ctm = m.then(&self.gs.ctm);
                }
            }
            b"BT" => {
                self.tm = M::ID;
                self.tlm = M::ID;
            }
            b"Tc" => {
                if let Some([v]) = Self::nums::<1>(ops) {
                    self.gs.tc = v;
                }
            }
            b"Tw" => {
                if let Some([v]) = Self::nums::<1>(ops) {
                    self.gs.tw = v;
                }
            }
            b"Tz" => {
                if let Some([v]) = Self::nums::<1>(ops) {
                    self.gs.th = v / 100.0;
                }
            }
            b"TL" => {
                if let Some([v]) = Self::nums::<1>(ops) {
                    self.gs.tl = v;
                }
            }
            b"Ts" => {
                if let Some([v]) = Self::nums::<1>(ops) {
                    self.gs.rise = v;
                }
            }
            b"Tf" => {
                if let [.., Operand::Name(name), Operand::Num(size)] = ops {
                    if size.is_finite() {
                        self.gs.size = *size;
                    }
                    let font = self.font(res, owner, name)?;
                    self.gs.font = Some(font);
                }
            }
            b"Td" => {
                if let Some([x, y]) = Self::nums::<2>(ops) {
                    self.td(x, y);
                }
            }
            b"TD" => {
                if let Some([x, y]) = Self::nums::<2>(ops) {
                    self.gs.tl = -y;
                    self.td(x, y);
                }
            }
            b"Tm" => {
                if let Some(m) = Self::nums::<6>(ops).and_then(|v| M::from(&v)) {
                    self.tm = m;
                    self.tlm = m;
                }
            }
            b"T*" => self.td(0.0, -self.gs.tl),
            b"Tj" => {
                if let Some(Operand::Str(s)) = ops.last() {
                    return Ok(self.show(&[Operand::Str(s.clone())]));
                }
            }
            b"'" => {
                self.td(0.0, -self.gs.tl);
                if let Some(Operand::Str(s)) = ops.last() {
                    return Ok(self.show(&[Operand::Str(s.clone())]));
                }
            }
            b"\"" => {
                if let [.., Operand::Num(aw), Operand::Num(ac), Operand::Str(s)] = ops {
                    if aw.is_finite() && ac.is_finite() {
                        self.gs.tw = *aw;
                        self.gs.tc = *ac;
                    }
                    self.td(0.0, -self.gs.tl);
                    return Ok(self.show(&[Operand::Str(s.clone())]));
                }
            }
            b"TJ" => {
                if let Some(Operand::Array(a)) = ops.last() {
                    let a = a.clone();
                    return Ok(self.show(&a));
                }
            }
            b"Do" => {
                if let Some(Operand::Name(name)) = ops.last() {
                    return self.form(res, name);
                }
            }
            _ => {}
        }
        Ok(Ok(()))
    }

    fn td(&mut self, x: f64, y: f64) {
        self.tlm = M::translate(x, y).then(&self.tlm);
        self.tm = self.tlm;
    }

    fn font(&mut self, res: &Dictionary, owner: u32, name: &[u8]) -> Result<Rc<Font>, PdfError> {
        let Some(obj) = self.resource(res, b"Font", name)? else {
            self.finding("CS-PDF-0102", TextIssue::FallbackWidths, Some(owner));
            return Ok(Rc::new(Font::unknown()));
        };
        let key = match obj.as_ref() {
            Some(r) => FontKey::Object(r.num),
            None => FontKey::Direct(owner, name.to_vec()),
        };
        if let Some(f) = self.fonts.get(&key) {
            return Ok(Rc::clone(f));
        }
        let f = font::load(self.doc, &obj, self.cancel)?;
        let obj_num = obj.as_ref().map(|r| r.num);
        if f.fallback_widths {
            self.finding("CS-PDF-0102", TextIssue::FallbackWidths, obj_num);
        }
        if f.unsupported_cmap {
            self.finding("CS-PDF-0102", TextIssue::UnsupportedCMap, obj_num);
        }
        if f.vertical {
            self.finding("CS-PDF-0102", TextIssue::VerticalText, obj_num);
        }
        let f = Rc::new(f);
        // Fonts are few per page; the cache is bounded by the operator count anyway.
        self.fonts.insert(key, Rc::clone(&f));
        Ok(f)
    }

    fn display(&self, p: Point) -> Point {
        self.geom.to_displayed(p)
    }

    fn show(&mut self, items: &[Operand]) -> Result<(), Stop> {
        let font = self
            .gs
            .font
            .clone()
            .unwrap_or_else(|| Rc::new(Font::unknown()));
        let gs = self.gs.clone();
        let mut run = TextRun {
            text: String::new(),
            glyphs: Vec::new(),
            quad: Quad::default(),
            size: 0.0,
        };
        for item in items {
            match item {
                Operand::Num(n) => {
                    let tx = -n / 1000.0 * gs.size * gs.th;
                    if tx.is_finite() {
                        self.tm = M::translate(tx, 0.0).then(&self.tm);
                    }
                }
                Operand::Str(s) => {
                    for code in font.codes(s) {
                        if self.glyphs >= MAX_GLYPHS_PER_PAGE {
                            self.finding("CS-PDF-0013", TextIssue::Glyphs, None);
                            self.finish(run);
                            return Err(Stop);
                        }
                        self.glyphs = self.glyphs.saturating_add(1);
                        self.glyph(&font, &gs, code, &mut run);
                    }
                }
                _ => {}
            }
        }
        self.finish(run);
        Ok(())
    }

    fn glyph(&mut self, font: &Font, gs: &Gs, code: Code, run: &mut TextRun) {
        let w0 = font.width(code);
        // Glyph space (em) to user space: [size·Th 0 0 size 0 rise] × Tm × CTM.
        let trm = M {
            a: gs.size * gs.th,
            b: 0.0,
            c: 0.0,
            d: gs.size,
            e: 0.0,
            f: gs.rise,
        }
        .then(&self.tm)
        .then(&gs.ctm);
        let ll = self.display(trm.apply(0.0, font.descent));
        let lr = self.display(trm.apply(w0, font.descent));
        let ur = self.display(trm.apply(w0, font.ascent));
        let ul = self.display(trm.apply(0.0, font.ascent));
        let origin = self.display(trm.apply(0.0, 0.0));
        let end = self.display(trm.apply(w0, 0.0));
        if run.glyphs.is_empty() {
            let top = self.display(trm.apply(0.0, 1.0));
            let d = sub(top, origin);
            run.size = dot(d, d).sqrt();
        }
        let start = run.text.len();
        run.text.push_str(&font.text(code));
        run.glyphs.push(Glyph {
            text: (start, run.text.len()),
            quad: Quad { ll, lr, ur, ul },
            origin,
            end,
        });
        let space = if code.len == 1 && code.code == 32 {
            gs.tw
        } else {
            0.0
        };
        let tx = (w0 * gs.size + gs.tc + space) * gs.th;
        if tx.is_finite() {
            self.tm = M::translate(tx, 0.0).then(&self.tm);
        }
    }

    fn finish(&mut self, mut run: TextRun) {
        let (Some(first), Some(last)) = (run.glyphs.first(), run.glyphs.last()) else {
            return;
        };
        run.quad = Quad {
            ll: first.quad.ll,
            lr: last.quad.lr,
            ur: last.quad.ur,
            ul: first.quad.ul,
        };
        self.runs.push(run);
    }

    fn form(&mut self, res: &Dictionary, name: &[u8]) -> Flow {
        let Some(obj) = self.resource(res, b"XObject", name)? else {
            return Ok(Ok(()));
        };
        // A form is a stream, so always an indirect object.
        let Some(r) = obj.as_ref() else {
            return Ok(Ok(()));
        };
        let Some(Object::Stream(s)) = local(self.doc.object(r.num, self.cancel))? else {
            return Ok(Ok(()));
        };
        if s.dict.name(b"Subtype") != Some(b"Form") {
            return Ok(Ok(()));
        }
        if self.xobjects.contains(&r.num) {
            self.finding("CS-PDF-0004", TextIssue::XObjectCycle, Some(r.num));
            return Ok(Ok(()));
        }
        if self.xobjects.len() >= MAX_XOBJECT_DEPTH {
            self.finding("CS-PDF-0004", TextIssue::XObjectDepth, Some(r.num));
            return Ok(Ok(()));
        }
        let data = match self.forms.get(&r.num) {
            Some(d) => Rc::clone(d),
            None => match self.doc.decode_stream(r.num, self.cancel) {
                Ok(d) => {
                    let d = Rc::new(d);
                    if self.form_bytes.saturating_add(d.len()) <= FORM_CACHE_BYTES {
                        self.form_bytes = self.form_bytes.saturating_add(d.len());
                        self.forms.insert(r.num, Rc::clone(&d));
                    }
                    d
                }
                Err(e) if font::is_fatal(&e) => return Err(e),
                Err(e) => {
                    self.finding(e.code(), TextIssue::StreamUnreadable, Some(r.num));
                    return Ok(Ok(()));
                }
            },
        };
        let matrix = match self.resolve(s.dict.get(b"Matrix"))? {
            Some(Object::Array(a)) => {
                let v: Vec<f64> = a.iter().filter_map(Object::as_f64).collect();
                M::from(&v).unwrap_or(M::ID)
            }
            _ => M::ID,
        };
        let own = match self.resolve(s.dict.get(b"Resources"))? {
            Some(Object::Dictionary(d)) => Some(d),
            _ => None,
        };
        let saved = (
            self.gs.clone(),
            self.stack.len(),
            self.deep_q,
            self.tm,
            self.tlm,
        );
        self.gs.ctm = matrix.then(&self.gs.ctm);
        self.xobjects.push(r.num);
        let flow = self.run(&data, own.as_ref().unwrap_or(res), r.num);
        self.xobjects.pop();
        let (gs, depth, deep_q, tm, tlm) = saved;
        self.gs = gs;
        self.stack.truncate(depth);
        self.deep_q = deep_q;
        self.tm = tm;
        self.tlm = tlm;
        flow
    }
}

/// The page's `/Resources`, inherited through `/Parent` when absent (§7.7.3.4).
fn page_resources(
    doc: &mut Document<'_>,
    page: &Dictionary,
    cancel: &dyn Fn() -> bool,
) -> Result<Dictionary, PdfError> {
    let mut cur = page.clone();
    // The reader already refused a page tree deeper or more cyclic than its limits;
    // this bound only keeps this walk finite on its own.
    for _ in 0..64 {
        if let Some(r) = cur.get(b"Resources") {
            return Ok(match local(doc.resolve(r, cancel))? {
                Some(Object::Dictionary(d)) => d,
                _ => Dictionary::new(),
            });
        }
        let Some(parent) = cur.get(b"Parent").cloned() else {
            break;
        };
        match local(doc.resolve(&parent, cancel))? {
            Some(Object::Dictionary(d)) => cur = d,
            _ => break,
        }
    }
    Ok(Dictionary::new())
}

/// Extract the text of one page with positions.
///
/// `number` is the 1-based page number recorded in the result. A limit crossed on this
/// page ends the page early and is recorded in [`PageText::findings`].
///
/// # Errors
///
/// Only what ends the whole document: the decode budget (`CS-PDF-0003`), memory, and
/// the host's cancellation (`CS-PDF-0013`).
pub fn extract_page(
    doc: &mut Document<'_>,
    page: &PageInfo,
    number: u32,
    cancel: &dyn Fn() -> bool,
) -> Result<PageText, PdfError> {
    let geom = PageGeometry::from_page(page);
    let max_ops = doc.limits().max_content_ops;
    let mut it = Interp {
        doc,
        geom,
        cancel,
        ops: 0,
        max_ops,
        glyphs: 0,
        runs: Vec::new(),
        findings: Vec::new(),
        fonts: BTreeMap::new(),
        forms: BTreeMap::new(),
        form_bytes: 0,
        xobjects: Vec::new(),
        gs: Gs::new(M::ID),
        stack: Vec::new(),
        deep_q: 0,
        tm: M::ID,
        tlm: M::ID,
    };
    let page_obj = local(it.doc.object(page.object, cancel))?;
    let Some(pd) = page_obj.as_ref().and_then(Object::dict).cloned() else {
        return Ok(it.into_page(number));
    };
    let res = page_resources(it.doc, &pd, cancel)?;
    let contents: Vec<u32> = match pd.get(b"Contents") {
        Some(Object::Reference(r)) => match local(it.doc.object(r.num, cancel))? {
            Some(Object::Array(a)) => a.iter().filter_map(Object::as_ref).map(|r| r.num).collect(),
            Some(Object::Stream(_)) => vec![r.num],
            _ => Vec::new(),
        },
        Some(Object::Array(a)) => a.iter().filter_map(Object::as_ref).map(|r| r.num).collect(),
        _ => Vec::new(),
    };
    // The streams of one page are one content stream split anywhere (§7.8.2).
    let mut data = Vec::new();
    for num in contents {
        match it.doc.decode_stream(num, cancel) {
            Ok(d) => {
                data.extend_from_slice(&d);
                data.push(b'\n');
            }
            Err(e) if font::is_fatal(&e) => return Err(e),
            Err(e) => it.finding(e.code(), TextIssue::StreamUnreadable, Some(num)),
        }
    }
    // A stop leaves what was read; only fatal errors propagate.
    let _ = it.run(&data, &res, page.object)?;
    Ok(it.into_page(number))
}

impl Interp<'_, '_, '_> {
    fn into_page(self, number: u32) -> PageText {
        PageText {
            page: number,
            geometry: self.geom,
            runs: self.runs,
            findings: self.findings,
            operators: self.ops,
        }
    }
}

/// Extract the text of every page, in order.
///
/// # Errors
///
/// As [`extract_page`].
pub fn extract_text(
    doc: &mut Document<'_>,
    pages: &[PageInfo],
    cancel: &dyn Fn() -> bool,
) -> Result<Vec<PageText>, PdfError> {
    let mut out = Vec::with_capacity(pages.len());
    for (i, p) in pages.iter().enumerate() {
        let n = u32::try_from(i).unwrap_or(u32::MAX).saturating_add(1);
        out.push(extract_page(doc, p, n, cancel)?);
    }
    Ok(out)
}
