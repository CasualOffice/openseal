//! The laid-out form as a PDF: pages with their content, faces embedded as TrueType
//! subsets (`CIDFontType2`, Identity-H, with `/W` and `ToUnicode`), images, and an
//! AcroForm whose fields carry the XFA field names (`form1[0].page1[0].Name[0]`, as
//! Acrobat names a static XFA form's fields), so a values file written for Acrobat
//! fills the same fields.
//!
//! Text fields, choice lists and signature fields get one widget each; check buttons
//! get on and off appearances drawn as vector marks (no font); an exclusion group is one
//! radio field with a widget per member. The form's `/DA` names Helvetica for viewers
//! that regenerate an appearance; every appearance written here uses the embedded
//! faces. Output is deterministic: same input, same bytes.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::fonts::Fonts;
use crate::image::Filter;
use crate::layout::{Doc, Mark, WKind, Widget};
use crate::props::{Border, Color, Edge};
use crate::text::Block;

/// A number as PDF writes it: at most four decimals, no exponent, `0` for anything
/// not finite.
fn num(v: f64) -> String {
    if !v.is_finite() {
        return "0".to_owned();
    }
    let v = (v * 10_000.0).round() / 10_000.0;
    let mut s = format!("{v:.4}");
    while s.ends_with('0') {
        s.pop();
    }
    if s.ends_with('.') {
        s.pop();
    }
    if s == "-0" { "0".to_owned() } else { s }
}

/// A PDF text string: a literal for printable ASCII, else UTF-16BE with a BOM in hex.
fn text_string(s: &str) -> String {
    if s.chars().all(|c| (' '..='~').contains(&c)) {
        let mut out = String::from("(");
        for c in s.chars() {
            if matches!(c, '(' | ')' | '\\') {
                out.push('\\');
            }
            out.push(c);
        }
        out.push(')');
        out
    } else {
        let mut out = String::from("<FEFF");
        for u in s.encode_utf16() {
            let _ = write!(out, "{u:04X}");
        }
        out.push('>');
        out
    }
}

/// A PDF name from any text: regular characters as they are, the rest `#xx` per byte.
fn pdf_name(s: &str) -> String {
    let mut out = String::from("/");
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'+') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "#{b:02X}");
        }
    }
    if out.len() == 1 {
        out.push_str("Off#20");
    }
    out
}

fn color_fill(c: Color) -> String {
    format!("{} {} {} rg", num(c.0), num(c.1), num(c.2))
}

fn color_stroke(c: Color) -> String {
    format!("{} {} {} RG", num(c.0), num(c.1), num(c.2))
}

/// Glyphs used per face, with the text each stands for.
type Usage = BTreeMap<usize, BTreeMap<u16, (char, f64)>>;

/// Content-stream writer for one page or appearance, in a frame whose y axis points
/// down from `top` (the page height, or a form's height).
struct Canvas<'u> {
    out: String,
    top: f64,
    usage: &'u mut Usage,
    images: &'u mut Vec<usize>,
}

impl Canvas<'_> {
    fn y(&self, y: f64) -> f64 {
        self.top - y
    }

    fn edge(&mut self, e: &Edge) {
        let _ = writeln!(self.out, "{} {} w", color_stroke(e.color), num(e.thickness));
        match e.dash {
            Some((on, off)) => {
                let _ = writeln!(self.out, "[{} {}] 0 d", num(on), num(off));
            }
            None => self.out.push_str("[] 0 d\n"),
        }
    }

    fn rect_path(&mut self, x: f64, y: f64, w: f64, h: f64, r: f64) {
        let (x0, y0) = (x, self.y(y + h));
        if r <= 0.0 {
            let _ = writeln!(self.out, "{} {} {} {} re", num(x0), num(y0), num(w), num(h));
            return;
        }
        let r = r.min(w / 2.0).min(h / 2.0);
        let k = 0.552_284_75 * r;
        let (x1, y1) = (x0 + w, y0 + h);
        let p = |o: &mut String, a: f64, b: f64, op: &str| {
            let _ = write!(o, "{} {} {op}", num(a), num(b));
        };
        p(&mut self.out, x0 + r, y0, "m ");
        p(&mut self.out, x1 - r, y0, "l ");
        let _ = write!(
            self.out,
            "{} {} {} {} {} {} c ",
            num(x1 - r + k),
            num(y0),
            num(x1),
            num(y0 + r - k),
            num(x1),
            num(y0 + r)
        );
        p(&mut self.out, x1, y1 - r, "l ");
        let _ = write!(
            self.out,
            "{} {} {} {} {} {} c ",
            num(x1),
            num(y1 - r + k),
            num(x1 - r + k),
            num(y1),
            num(x1 - r),
            num(y1)
        );
        p(&mut self.out, x0 + r, y1, "l ");
        let _ = write!(
            self.out,
            "{} {} {} {} {} {} c ",
            num(x0 + r - k),
            num(y1),
            num(x0),
            num(y1 - r + k),
            num(x0),
            num(y1 - r)
        );
        p(&mut self.out, x0, y0 + r, "l ");
        let _ = writeln!(
            self.out,
            "{} {} {} {} {} {} c h",
            num(x0),
            num(y0 + r - k),
            num(x0 + r - k),
            num(y0),
            num(x0 + r),
            num(y0)
        );
    }

    fn frame(&mut self, x: f64, y: f64, w: f64, h: f64, b: &Border) {
        let [top, right, bottom, left] = b.edges;
        let same = b.edges.iter().all(|e| *e == top);
        if same {
            if top.visible && top.thickness > 0.0 {
                self.out.push_str("q\n");
                self.edge(&top);
                self.rect_path(x, y, w, h, b.radius);
                self.out.push_str("S\nQ\n");
            }
            return;
        }
        let sides = [
            (top, x, y, x + w, y),
            (right, x + w, y, x + w, y + h),
            (bottom, x, y + h, x + w, y + h),
            (left, x, y, x, y + h),
        ];
        for (e, x1, y1, x2, y2) in sides {
            self.line(x1, y1, x2, y2, &e);
        }
    }

    fn line(&mut self, x1: f64, y1: f64, x2: f64, y2: f64, e: &Edge) {
        if !e.visible || e.thickness <= 0.0 {
            return;
        }
        self.out.push_str("q\n");
        self.edge(e);
        let _ = writeln!(
            self.out,
            "{} {} m {} {} l S\nQ",
            num(x1),
            num(self.y(y1)),
            num(x2),
            num(self.y(y2))
        );
    }

    // The ellipse's box, its two angles, its edge and its fill.
    #[allow(clippy::too_many_arguments)]
    fn arc(
        &mut self,
        x: f64,
        y: f64,
        w: f64,
        h: f64,
        start: f64,
        sweep: f64,
        e: &Edge,
        fill: Option<Color>,
    ) {
        let (rx, ry) = (w / 2.0, h / 2.0);
        if rx <= 0.0 || ry <= 0.0 {
            return;
        }
        let (cx, cy) = (x + rx, self.y(y + ry));
        let full = sweep.abs() >= 360.0;
        let segs = ((sweep.abs() / 90.0).ceil()).clamp(1.0, 4.0);
        let step = sweep.to_radians() / segs;
        let mut a = start.to_radians();
        let pt = |t: f64| (cx + rx * t.cos(), cy + ry * t.sin());
        let (sx, sy) = pt(a);
        let mut path = format!("{} {} m ", num(sx), num(sy));
        let k = 4.0 / 3.0 * (step / 4.0).tan();
        // `segs` is at most 4: a short, bounded loop.
        let mut i = 0.0;
        while i < segs {
            let b = a + step;
            let (x0, y0) = pt(a);
            let (x3, y3) = pt(b);
            let (x1, y1) = (x0 - k * rx * a.sin(), y0 + k * ry * a.cos());
            let (x2, y2) = (x3 + k * rx * b.sin(), y3 - k * ry * b.cos());
            let _ = write!(
                path,
                "{} {} {} {} {} {} c ",
                num(x1),
                num(y1),
                num(x2),
                num(y2),
                num(x3),
                num(y3)
            );
            a = b;
            i += 1.0;
        }
        if full {
            path.push_str("h ");
        }
        self.out.push_str("q\n");
        if let Some(c) = fill {
            let _ = writeln!(self.out, "{}\n{path}f", color_fill(c));
        }
        if e.visible && e.thickness > 0.0 {
            self.edge(e);
            let _ = writeln!(self.out, "{path}S");
        }
        self.out.push_str("Q\n");
    }

    fn text(&mut self, x: f64, y: f64, block: &Block) {
        for p in &block.pieces {
            let Some(first) = p.glyphs.first() else {
                continue;
            };
            let face = first.0.face;
            let used = self.usage.entry(face).or_default();
            let mut hex = String::with_capacity(p.glyphs.len().saturating_mul(4));
            for (g, ch) in &p.glyphs {
                used.entry(g.gid).or_insert((*ch, g.adv));
                let _ = write!(hex, "{:04X}", g.gid);
            }
            let f = &p.font;
            let bx = x + p.x;
            let by = self.y(y + p.baseline);
            self.out.push_str("BT\n");
            let _ = writeln!(self.out, "/F{face} {} Tf", num(f.size));
            let _ = writeln!(self.out, "{}", color_fill(f.color));
            if f.bold {
                let _ = writeln!(
                    self.out,
                    "2 Tr {} {} w",
                    color_stroke(f.color),
                    num(f.size * 0.03)
                );
            } else {
                self.out.push_str("0 Tr\n");
            }
            let shear = if f.italic { 0.2126 } else { 0.0 };
            let _ = writeln!(self.out, "1 0 {} 1 {} {} Tm", num(shear), num(bx), num(by));
            let _ = writeln!(self.out, "<{hex}> Tj\nET");
            if f.underline {
                let t = f.size * 0.05;
                let uy = by - f.size * 0.12;
                let _ = writeln!(
                    self.out,
                    "q {} {} w [] 0 d {} {} m {} {} l S Q",
                    color_stroke(f.color),
                    num(t),
                    num(bx),
                    num(uy),
                    num(bx + p.width),
                    num(uy)
                );
            }
        }
    }

    fn marks(&mut self, marks: &[Mark]) {
        for m in marks {
            match m {
                Mark::Fill {
                    x,
                    y,
                    w,
                    h,
                    color,
                    radius,
                } => {
                    let _ = writeln!(self.out, "q {}", color_fill(*color));
                    self.rect_path(*x, *y, *w, *h, *radius);
                    self.out.push_str("f\nQ\n");
                }
                Mark::Frame { x, y, w, h, border } => self.frame(*x, *y, *w, *h, border),
                Mark::Line {
                    x1,
                    y1,
                    x2,
                    y2,
                    edge,
                } => self.line(*x1, *y1, *x2, *y2, edge),
                Mark::Arc {
                    x,
                    y,
                    w,
                    h,
                    start,
                    sweep,
                    edge,
                    fill,
                } => self.arc(*x, *y, *w, *h, *start, *sweep, edge, *fill),
                Mark::Text { x, y, block } => self.text(*x, *y, block),
                Mark::Image { x, y, w, h, index } => {
                    let _ = writeln!(
                        self.out,
                        "q {} 0 0 {} {} {} cm /Im{index} Do Q",
                        num(*w),
                        num(*h),
                        num(*x),
                        num(self.y(y + h))
                    );
                    if !self.images.contains(index) {
                        self.images.push(*index);
                    }
                }
                Mark::Rotated {
                    ox,
                    oy,
                    angle,
                    marks,
                } => {
                    let (s, c) = match angle {
                        90 => (1.0, 0.0),
                        180 => (0.0, -1.0),
                        270 => (-1.0, 0.0),
                        _ => (0.0, 1.0),
                    };
                    let _ = writeln!(
                        self.out,
                        "q {} {} {} {} {} {} cm",
                        num(c),
                        num(s),
                        num(-s),
                        num(c),
                        num(*ox),
                        num(self.y(*oy))
                    );
                    let top = self.top;
                    self.top = 0.0;
                    self.marks(marks);
                    self.top = top;
                    self.out.push_str("Q\n");
                }
                Mark::Widget(_) => {}
            }
        }
    }
}

fn deflate(data: &[u8]) -> Vec<u8> {
    miniz_oxide::deflate::compress_to_vec_zlib(data, 6)
}

/// The object table.
#[derive(Default)]
struct Objects {
    bodies: Vec<Vec<u8>>,
}

impl Objects {
    fn reserve(&mut self) -> usize {
        self.bodies.push(b"null".to_vec());
        self.bodies.len()
    }

    fn set(&mut self, n: usize, body: Vec<u8>) {
        if let Some(slot) = n.checked_sub(1).and_then(|i| self.bodies.get_mut(i)) {
            *slot = body;
        }
    }

    fn add(&mut self, body: impl Into<Vec<u8>>) -> usize {
        self.bodies.push(body.into());
        self.bodies.len()
    }

    fn stream(dict: &str, data: &[u8]) -> Vec<u8> {
        let mut out = format!("<<{dict}/Length {}>>\nstream\n", data.len()).into_bytes();
        out.extend_from_slice(data);
        out.extend_from_slice(b"\nendstream");
        out
    }

    fn add_stream(&mut self, dict: &str, data: &[u8]) -> usize {
        self.add(Self::stream(dict, data))
    }

    fn add_flate(&mut self, dict: &str, data: &[u8]) -> usize {
        let z = deflate(data);
        self.add_stream(&format!("{dict}/Filter/FlateDecode"), &z)
    }

    fn finish(self, root: usize, info: usize) -> Vec<u8> {
        let mut out = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n".to_vec();
        let mut offsets = Vec::with_capacity(self.bodies.len());
        for (i, b) in self.bodies.iter().enumerate() {
            offsets.push(out.len());
            let _ = writeln!(Sink(&mut out), "{} 0 obj", i.saturating_add(1));
            out.extend_from_slice(b);
            out.extend_from_slice(b"\nendobj\n");
        }
        let xref = out.len();
        let size = self.bodies.len().saturating_add(1);
        let _ = write!(Sink(&mut out), "xref\n0 {size}\n0000000000 65535 f \n");
        for o in offsets {
            let _ = writeln!(Sink(&mut out), "{o:010} 00000 n ");
        }
        let _ = write!(
            Sink(&mut out),
            "trailer\n<</Size {size}/Root {root} 0 R/Info {info} 0 R>>\nstartxref\n{xref}\n%%EOF\n"
        );
        out
    }
}

/// `fmt::Write` into a byte vector.
struct Sink<'a>(&'a mut Vec<u8>);

impl std::fmt::Write for Sink<'_> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.0.extend_from_slice(s.as_bytes());
        Ok(())
    }
}

/// A deterministic six-letter subset tag (FNV-1a over the face and its glyphs).
fn tag(face: usize, gids: impl Iterator<Item = u16>) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut eat = |b: u8| {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    };
    for b in face.to_be_bytes() {
        eat(b);
    }
    for g in gids {
        for b in g.to_be_bytes() {
            eat(b);
        }
    }
    let mut s = String::with_capacity(6);
    for _ in 0..6 {
        let letter = u8::try_from(h % 26).unwrap_or(0);
        s.push(char::from(b'A'.saturating_add(letter)));
        h /= 26;
    }
    s
}

fn to_unicode(used: &BTreeMap<u16, (char, f64)>) -> String {
    let mut out = String::from(
        "/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n\
         /CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n\
         /CMapName /Adobe-Identity-UCS def\n/CMapType 2 def\n\
         1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n",
    );
    let entries: Vec<(u16, char)> = used.iter().map(|(g, (c, _))| (*g, *c)).collect();
    for chunk in entries.chunks(100) {
        let _ = writeln!(out, "{} beginbfchar", chunk.len());
        for (gid, ch) in chunk {
            let mut utf16 = String::new();
            let mut buf = [0u16; 2];
            for unit in ch.encode_utf16(&mut buf) {
                let _ = write!(utf16, "{unit:04X}");
            }
            let _ = writeln!(out, "<{gid:04X}> <{utf16}>");
        }
        out.push_str("endbfchar\n");
    }
    out.push_str("endcmap\nCMapName currentdict /CMap defineresource pop\nend\nend\n");
    out
}

/// A check mark as a vector path in a `s` × `s` box (PDF coordinates, origin
/// bottom-left), filled or stroked.
fn check_mark(mark: char, s: f64) -> String {
    let p = |v: f64| num(v * s);
    match mark {
        // circle
        'l' => {
            let r = s * 0.3;
            let c = s / 2.0;
            let k = 0.552_284_75 * r;
            format!(
                "{} {} m {} {} {} {} {} {} c {} {} {} {} {} {} c {} {} {} {} {} {} c {} {} {} {} {} {} c f",
                num(c + r),
                num(c),
                num(c + r),
                num(c + k),
                num(c + k),
                num(c + r),
                num(c),
                num(c + r),
                num(c - k),
                num(c + r),
                num(c - r),
                num(c + k),
                num(c - r),
                num(c),
                num(c - r),
                num(c - k),
                num(c - k),
                num(c - r),
                num(c),
                num(c - r),
                num(c + k),
                num(c - r),
                num(c + r),
                num(c - k),
                num(c + r),
                num(c),
            )
        }
        // cross
        '8' => format!(
            "{} w {} {} m {} {} l {} {} m {} {} l S",
            num(s * 0.1),
            p(0.2),
            p(0.2),
            p(0.8),
            p(0.8),
            p(0.2),
            p(0.8),
            p(0.8),
            p(0.2)
        ),
        // diamond
        'u' => format!(
            "{} {} m {} {} l {} {} l {} {} l h f",
            p(0.5),
            p(0.15),
            p(0.85),
            p(0.5),
            p(0.5),
            p(0.85),
            p(0.15),
            p(0.5)
        ),
        // square
        'n' => format!("{} {} {} {} re f", p(0.2), p(0.2), p(0.6), p(0.6)),
        // star: a five-pointed star
        'H' => {
            let c = s / 2.0;
            let mut out = String::new();
            for i in 0..10u8 {
                let r = if i % 2 == 0 { s * 0.4 } else { s * 0.16 };
                let a = std::f64::consts::FRAC_PI_2 + f64::from(i) * std::f64::consts::PI / 5.0;
                let op = if i == 0 { "m" } else { "l" };
                let _ = write!(
                    out,
                    "{} {} {op} ",
                    num(c + r * a.cos()),
                    num(c + r * a.sin())
                );
            }
            out.push_str("h f");
            out
        }
        // check
        _ => format!(
            "{} w 1 J 1 j {} {} m {} {} l {} {} l S",
            num(s * 0.12),
            p(0.2),
            p(0.52),
            p(0.42),
            p(0.25),
            p(0.82),
            p(0.8)
        ),
    }
}

/// One terminal field: its widgets and kind.
struct FieldEntry<'d> {
    widgets: Vec<(usize, &'d Widget)>,
}

#[derive(Default)]
struct Trie {
    kids: BTreeMap<String, Trie>,
    order: Vec<String>,
    field: Option<usize>,
}

impl Trie {
    fn insert(&mut self, path: &[String], field: usize) {
        let mut at = self;
        for seg in path {
            if !at.kids.contains_key(seg) {
                at.order.push(seg.clone());
            }
            at = at.kids.entry(seg.clone()).or_default();
        }
        at.field = Some(field);
    }
}

/// Write `doc` as a PDF.
pub(crate) fn write(doc: &Doc, fonts: &Fonts<'_>) -> Vec<u8> {
    let mut objs = Objects::default();
    let catalog = objs.reserve();
    let pages_obj = objs.reserve();
    let resources = objs.reserve();
    let mut usage: Usage = BTreeMap::new();
    let mut used_images: Vec<usize> = Vec::new();

    // Pages and their content.
    let mut page_objs = Vec::new();
    let mut widgets: Vec<(usize, &Widget)> = Vec::new();
    for (pi, page) in doc.pages.iter().enumerate() {
        let mut c = Canvas {
            out: String::new(),
            top: page.h,
            usage: &mut usage,
            images: &mut used_images,
        };
        c.marks(&page.marks);
        let content = objs.add_flate("", c.out.as_bytes());
        let pobj = objs.reserve();
        page_objs.push((pobj, content));
        collect_widgets(&page.marks, pi, &mut widgets);
    }

    // Fields: group widgets by full name; radio groups share one.
    let mut fields: Vec<FieldEntry<'_>> = Vec::new();
    let mut by_name: BTreeMap<Vec<String>, usize> = BTreeMap::new();
    let mut trie = Trie::default();
    for (pi, w) in widgets {
        let radio = matches!(w.kind, WKind::Check { radio: true, .. });
        let mut path = w.path.clone();
        if path.is_empty() {
            path.push("field[0]".to_owned());
        }
        if let Some(&i) = by_name.get(&path) {
            if radio {
                if let Some(f) = fields.get_mut(i) {
                    f.widgets.push((pi, w));
                }
                continue;
            }
            // The same name twice: keep both, apart.
            let mut k = 2u32;
            let last = path.last().cloned().unwrap_or_default();
            while by_name.contains_key(&path) {
                if let Some(l) = path.last_mut() {
                    *l = format!("{last}#{k}");
                }
                k = k.saturating_add(1);
            }
        }
        let i = fields.len();
        fields.push(FieldEntry {
            widgets: vec![(pi, w)],
        });
        by_name.insert(path.clone(), i);
        trie.insert(&path, i);
    }

    let mut annots: Vec<Vec<usize>> = vec![Vec::new(); doc.pages.len()];
    let field_objs: Vec<usize> = fields.iter().map(|_| objs.reserve()).collect();
    // The name hierarchy: one object per inner node, in pre-order.
    let mut terminal_parent: BTreeMap<usize, (Option<usize>, String)> = BTreeMap::new();
    let mut top: Vec<usize> = Vec::new();
    let mut ordered: Vec<(usize, Option<usize>, String, Vec<usize>)> = Vec::new();
    walk_ordered(
        &trie,
        &mut objs,
        &field_objs,
        &mut ordered,
        &mut terminal_parent,
        &mut top,
    );
    for (o, parent, name, kids) in &ordered {
        let mut d = format!("<</T{}", text_string(name));
        if let Some(p) = parent {
            let _ = write!(d, "/Parent {p} 0 R");
        }
        d.push_str("/Kids[");
        for k in kids {
            let _ = write!(d, "{k} 0 R ");
        }
        d.push_str("]>>");
        objs.set(*o, d.into_bytes());
    }

    for (fi, f) in fields.iter().enumerate() {
        let Some(&fobj) = field_objs.get(fi) else {
            continue;
        };
        let Some(&(_, first)) = f.widgets.first() else {
            continue;
        };
        let (parent, seg) = terminal_parent
            .get(&fi)
            .cloned()
            .unwrap_or((None, "field".to_owned()));
        let mut d = format!("<</T{}", text_string(&seg));
        if let Some(p) = parent {
            let _ = write!(d, "/Parent {p} 0 R");
        }
        if let Some(tt) = &first.tooltip {
            let _ = write!(d, "/TU{}", text_string(tt));
        }
        let size = first.font_size.clamp(1.0, 100.0);
        match &first.kind {
            WKind::Text {
                multiline,
                max_len,
                comb,
                password,
            } => {
                let mut ff: u32 = 0;
                if *multiline {
                    ff |= 1 << 12;
                }
                if *password {
                    ff |= 1 << 13;
                }
                if *comb && max_len.is_some() {
                    ff |= 1 << 24;
                }
                let _ = write!(d, "/FT/Tx/Ff {ff}/DA(/Helv {} Tf 0 g)", num(size));
                if let Some(m) = max_len {
                    let _ = write!(d, "/MaxLen {m}");
                }
                if let Some(v) = &first.value {
                    let _ = write!(d, "/V{}", text_string(v));
                }
            }
            WKind::Choice {
                options,
                combo,
                edit,
                multi,
            } => {
                let mut ff: u32 = 0;
                if *combo {
                    ff |= 1 << 17;
                }
                if *edit && *combo {
                    ff |= 1 << 18;
                }
                if *multi {
                    ff |= 1 << 21;
                }
                let _ = write!(d, "/FT/Ch/Ff {ff}/DA(/Helv {} Tf 0 g)/Opt[", num(size));
                for (export, display) in options {
                    if export == display {
                        d.push_str(&text_string(display));
                    } else {
                        let _ = write!(d, "[{}{}]", text_string(export), text_string(display));
                    }
                }
                d.push(']');
                if let Some(v) = &first.value {
                    let _ = write!(d, "/V{}", text_string(v));
                }
            }
            WKind::Signature => d.push_str("/FT/Sig"),
            WKind::Check { radio, .. } => {
                if *radio {
                    d.push_str("/FT/Btn/Ff 49152");
                } else {
                    d.push_str("/FT/Btn/Ff 0");
                }
                let on = f.widgets.iter().find_map(|(_, w)| match &w.kind {
                    WKind::Check {
                        on, on_now: true, ..
                    } => Some(on.clone()),
                    _ => None,
                });
                match on {
                    Some(v) => {
                        let _ = write!(d, "/V{}", pdf_name(&v));
                    }
                    None => d.push_str("/V/Off"),
                }
            }
        }
        // One widget: merged into the field. Several (a radio group): kids.
        let merged = f.widgets.len() == 1;
        let mut widget_objs = Vec::new();
        for (pi, w) in &f.widgets {
            let wobj = if merged { fobj } else { objs.reserve() };
            let Some(page) = doc.pages.get(*pi) else {
                continue;
            };
            let Some((pobj, _)) = page_objs.get(*pi) else {
                continue;
            };
            let rect = format!(
                "[{} {} {} {}]",
                num(w.x),
                num(page.h - w.y - w.h),
                num(w.x + w.w),
                num(page.h - w.y)
            );
            let mut wd = format!("/Type/Annot/Subtype/Widget/F 4/P {pobj} 0 R/Rect{rect}");
            let ap = appearance(&mut objs, w, resources, &mut usage, &mut used_images);
            wd.push_str(&ap);
            if let Some(a) = annots.get_mut(*pi) {
                a.push(wobj);
            }
            if merged {
                d.push_str(&wd);
            } else {
                let body = format!("<<{wd}/Parent {fobj} 0 R>>");
                objs.set(wobj, body.into_bytes());
                widget_objs.push(wobj);
            }
        }
        if !merged {
            d.push_str("/Kids[");
            for w in &widget_objs {
                let _ = write!(d, "{w} 0 R ");
            }
            d.push(']');
        }
        d.push_str(">>");
        objs.set(fobj, d.into_bytes());
    }

    // Images.
    let mut image_objs: BTreeMap<usize, usize> = BTreeMap::new();
    used_images.sort_unstable();
    for &i in &used_images {
        let Some(img) = doc.images.get(i) else {
            continue;
        };
        let cs = match (img.colors, &img.palette) {
            (_, Some(p)) => {
                let n = (p.len() / 3).max(1).saturating_sub(1);
                let mut hex = String::with_capacity(p.len().saturating_mul(2));
                for b in p.iter().take(768) {
                    let _ = write!(hex, "{b:02X}");
                }
                format!("[/Indexed/DeviceRGB {n} <{hex}>]")
            }
            (1, None) => "/DeviceGray".to_owned(),
            (4, None) => "/DeviceCMYK".to_owned(),
            _ => "/DeviceRGB".to_owned(),
        };
        let mut dict = format!(
            "/Type/XObject/Subtype/Image/Width {}/Height {}/ColorSpace{cs}/BitsPerComponent 8",
            img.width, img.height
        );
        match img.filter {
            Filter::Dct => {
                dict.push_str("/Filter/DCTDecode");
                if img.invert_cmyk {
                    dict.push_str("/Decode[1 0 1 0 1 0 1 0]");
                }
            }
            Filter::PngFlate => {
                let colors = if img.palette.is_some() { 1 } else { img.colors };
                let _ = write!(
                    dict,
                    "/Filter/FlateDecode/DecodeParms<</Predictor 15/Colors {colors}/BitsPerComponent 8/Columns {}>>",
                    img.width
                );
            }
        }
        let o = objs.add_stream(&dict, &img.data);
        image_objs.insert(i, o);
    }

    // Fonts.
    let mut font_objs: BTreeMap<usize, usize> = BTreeMap::new();
    for (&index, used) in &usage {
        let Some(face) = fonts.faces.get(index) else {
            continue;
        };
        let program = crate::subset::subset(face.bytes, used.keys().map(|g| u32::from(*g)))
            .unwrap_or_else(|| face.bytes.to_vec());
        let base = format!("{}+{}", tag(index, used.keys().copied()), face.name);
        let file = objs.add_flate(&format!("/Length1 {}", program.len()), &program);
        let m = face.metrics;
        let mut flags: u32 = 4;
        if m.monospace {
            flags |= 1;
        }
        let desc = objs.add(format!(
            "<</Type/FontDescriptor/FontName/{base}/Flags {flags}/FontBBox[{} {} {} {}]/ItalicAngle {}/Ascent {}/Descent {}/CapHeight {}/StemV 80/FontFile2 {file} 0 R>>",
            num(m.bbox[0]), num(m.bbox[1]), num(m.bbox[2]), num(m.bbox[3]),
            num(m.italic_angle), num(m.ascent), num(m.descent), num(m.cap_height)
        ));
        let mut widths = String::new();
        for (gid, (_, adv)) in used {
            let _ = write!(widths, "{gid}[{}]", num(*adv));
        }
        let cid = objs.add(format!(
            "<</Type/Font/Subtype/CIDFontType2/BaseFont/{base}/CIDSystemInfo<</Registry(Adobe)/Ordering(Identity)/Supplement 0>>/FontDescriptor {desc} 0 R/CIDToGIDMap/Identity/DW 0/W[{widths}]>>"
        ));
        let cmap = objs.add_flate("", to_unicode(used).as_bytes());
        let t0 = objs.add(format!(
            "<</Type/Font/Subtype/Type0/BaseFont/{base}/Encoding/Identity-H/DescendantFonts[{cid} 0 R]/ToUnicode {cmap} 0 R>>"
        ));
        font_objs.insert(index, t0);
    }
    let helv = objs.add("<</Type/Font/Subtype/Type1/BaseFont/Helvetica/Encoding/WinAnsiEncoding>>");
    let mut res = String::from("<</Font<<");
    for (i, o) in &font_objs {
        let _ = write!(res, "/F{i} {o} 0 R");
    }
    let _ = write!(res, "/Helv {helv} 0 R>>/XObject<<");
    for (i, o) in &image_objs {
        let _ = write!(res, "/Im{i} {o} 0 R");
    }
    res.push_str(">>>>");
    objs.set(resources, res.into_bytes());

    // Page objects.
    for (pi, (pobj, content)) in page_objs.iter().enumerate() {
        let Some(page) = doc.pages.get(pi) else {
            continue;
        };
        let mut d = format!(
            "<</Type/Page/Parent {pages_obj} 0 R/MediaBox[0 0 {} {}]/Resources {resources} 0 R/Contents {content} 0 R",
            num(page.w),
            num(page.h)
        );
        if let Some(a) = annots.get(pi).filter(|a| !a.is_empty()) {
            d.push_str("/Annots[");
            for o in a {
                let _ = write!(d, "{o} 0 R ");
            }
            d.push(']');
        }
        d.push_str(">>");
        objs.set(*pobj, d.into_bytes());
    }
    let mut kids = String::new();
    for (pobj, _) in &page_objs {
        let _ = write!(kids, "{pobj} 0 R ");
    }
    objs.set(
        pages_obj,
        format!("<</Type/Pages/Kids[{kids}]/Count {}>>", page_objs.len()).into_bytes(),
    );
    let mut cat = format!("<</Type/Catalog/Pages {pages_obj} 0 R");
    if !top.is_empty() {
        cat.push_str("/AcroForm<</Fields[");
        for t in &top {
            let _ = write!(cat, "{t} 0 R ");
        }
        let _ = write!(
            cat,
            "]/DR<</Font<</Helv {helv} 0 R>>>>/DA(/Helv 0 Tf 0 g)/NeedAppearances false>>"
        );
    }
    cat.push_str(">>");
    objs.set(catalog, cat.into_bytes());
    let info = objs.add("<</Producer(OpenSeal casual-sign-xfa: XFA laid out to static pages)>>");
    objs.finish(catalog, info)
}

/// Inner field nodes in pre-order with their parents and kids.
fn walk_ordered(
    t: &Trie,
    objs: &mut Objects,
    field_objs: &[usize],
    out: &mut Vec<(usize, Option<usize>, String, Vec<usize>)>,
    terminal_parent: &mut BTreeMap<usize, (Option<usize>, String)>,
    top: &mut Vec<usize>,
) {
    // Explicit stack: (trie node, parent object, own object and name).
    struct Frame<'t> {
        node: &'t Trie,
        me: Option<usize>,
        slot: Option<usize>,
    }
    let mut stack: Vec<Frame<'_>> = vec![Frame {
        node: t,
        me: None,
        slot: None,
    }];
    while let Some(fr) = stack.pop() {
        let mut kids = Vec::new();
        let mut pending: Vec<Frame<'_>> = Vec::new();
        for seg in &fr.node.order {
            let Some(k) = fr.node.kids.get(seg) else {
                continue;
            };
            if let Some(fi) = k.field
                && let Some(&o) = field_objs.get(fi)
            {
                let name = if k.kids.is_empty() {
                    seg.clone()
                } else {
                    format!("{seg}#field")
                };
                terminal_parent.insert(fi, (fr.me, name));
                kids.push(o);
            }
            if !k.kids.is_empty() {
                let o = objs.reserve();
                out.push((o, fr.me, seg.clone(), Vec::new()));
                kids.push(o);
                pending.push(Frame {
                    node: k,
                    me: Some(o),
                    slot: Some(out.len().saturating_sub(1)),
                });
            }
        }
        match fr.slot.and_then(|s| out.get_mut(s)) {
            Some(entry) => entry.3 = kids,
            None => top.extend(kids),
        }
        for p in pending.into_iter().rev() {
            stack.push(p);
        }
    }
}

fn collect_widgets<'d>(marks: &'d [Mark], page: usize, out: &mut Vec<(usize, &'d Widget)>) {
    for m in marks {
        match m {
            Mark::Widget(w) => out.push((page, w)),
            Mark::Rotated { marks, .. } => collect_widgets(marks, page, out),
            _ => {}
        }
    }
}

/// The widget's `/AP` (and `/AS`, `/MK`) entries.
fn appearance(
    objs: &mut Objects,
    w: &Widget,
    resources: usize,
    usage: &mut Usage,
    images: &mut Vec<usize>,
) -> String {
    let bbox = format!("[0 0 {} {}]", num(w.w), num(w.h));
    match &w.kind {
        WKind::Check {
            on, on_now, mark, ..
        } => {
            let s = w.w.min(w.h);
            let on_stream = objs.add_stream(
                &format!("/Type/XObject/Subtype/Form/BBox{bbox}/Resources {resources} 0 R"),
                format!("q 0 g 0 G {} Q", check_mark(*mark, s)).as_bytes(),
            );
            let off_stream = objs.add_stream(
                &format!("/Type/XObject/Subtype/Form/BBox{bbox}/Resources {resources} 0 R"),
                b"",
            );
            let state = if *on_now {
                pdf_name(on)
            } else {
                "/Off".to_owned()
            };
            format!(
                "/AP<</N<<{} {on_stream} 0 R/Off {off_stream} 0 R>>>>/AS{state}/MK<</CA({})>>",
                pdf_name(on),
                mark
            )
        }
        _ => {
            let mut c = Canvas {
                out: String::new(),
                top: w.h,
                usage,
                images,
            };
            if let Some((dx, dy, block)) = &w.appearance {
                c.text(*dx, *dy, block);
            }
            let body = if c.out.is_empty() {
                String::new()
            } else {
                format!("/Tx BMC q\n{}Q EMC", c.out)
            };
            let n = objs.add_stream(
                &format!("/Type/XObject/Subtype/Form/BBox{bbox}/Resources {resources} 0 R"),
                body.as_bytes(),
            );
            format!("/AP<</N {n} 0 R>>")
        }
    }
}
