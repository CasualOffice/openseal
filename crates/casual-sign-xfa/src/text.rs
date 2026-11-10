//! Text: plain and rich (XHTML in `exData`) content as styled runs, and line layout.
//!
//! Lines break at spaces, a word wider than the line breaks between characters, and
//! hard breaks (`\n`, `<br/>`, paragraph ends) start a new line. No shaping, kerning or
//! bidirectional reordering (`FLT-01` covers shaping for flattening too). Justified
//! paragraphs are set flush left (`XFA-01` gap).

use crate::fonts::{Fonts, Glyph};
use crate::props::{self, Color, Font, HAlign, Para};
use crate::xml::{Dom, NodeId};

/// A run of text in one style. `keep_spaces` is XHTML's `xfa-spacerun:yes`.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Run {
    pub font: Font,
    pub text: String,
}

/// A paragraph: its properties and runs.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct RPara {
    pub para: Para,
    pub runs: Vec<Run>,
    /// The style an empty paragraph's line takes its height from.
    pub base: Font,
}

/// Rich or plain text.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct Rich {
    pub paras: Vec<RPara>,
}

impl Rich {
    /// Plain text in one style: one paragraph, line breaks kept.
    pub(crate) fn plain(text: &str, font: &Font, para: &Para) -> Self {
        let text = text.replace("\r\n", "\n").replace('\r', "\n");
        Self {
            paras: vec![RPara {
                para: *para,
                runs: vec![Run {
                    font: font.clone(),
                    text,
                }],
                base: font.clone(),
            }],
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.paras
            .iter()
            .all(|p| p.runs.iter().all(|r| r.text.trim().is_empty()))
    }

    /// Characters of every run, for the report.
    pub(crate) fn symbolic_chars(&self) -> usize {
        self.paras
            .iter()
            .flat_map(|p| &p.runs)
            .filter(|r| r.font.symbolic)
            .map(|r| r.text.chars().filter(|c| !c.is_whitespace()).count())
            .fold(0usize, usize::saturating_add)
    }
}

fn css_color(v: &str) -> Option<Color> {
    let v = v.trim();
    if let Some(h) = v.strip_prefix('#') {
        let n = u32::from_str_radix(h, 16).ok()?;
        let (r, g, b) = match h.len() {
            6 => ((n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff),
            3 => (
                ((n >> 8) & 0xf).saturating_mul(17),
                ((n >> 4) & 0xf).saturating_mul(17),
                (n & 0xf).saturating_mul(17),
            ),
            _ => return None,
        };
        let k = |c: u32| f64::from(c) / 255.0;
        return Some(Color(k(r), k(g), k(b)));
    }
    if let Some(inner) = v.strip_prefix("rgb(").and_then(|s| s.strip_suffix(')')) {
        let mut it = inner.split(',').map(|p| p.trim().parse::<f64>().ok());
        let k = |c: f64| (c / 255.0).clamp(0.0, 1.0);
        return Some(Color(k(it.next()??), k(it.next()??), k(it.next()??)));
    }
    match v {
        "black" => Some(Color::BLACK),
        "white" => Some(Color::WHITE),
        "red" => Some(Color(1.0, 0.0, 0.0)),
        "blue" => Some(Color(0.0, 0.0, 1.0)),
        _ => None,
    }
}

/// Inline state while walking XHTML.
#[derive(Debug, Clone)]
struct Inline {
    font: Font,
    spacerun: bool,
}

/// Apply a CSS `style` attribute: font and paragraph properties.
fn apply_style(style: &str, font: &mut Font, para: &mut Para, spacerun: &mut bool) {
    for decl in style.split(';') {
        let Some((k, v)) = decl.split_once(':') else {
            continue;
        };
        let (k, v) = (k.trim(), v.trim());
        let pt = |v: &str| props::measure(v, 1.0);
        match k {
            "font-family" => {
                let first = v
                    .split(',')
                    .next()
                    .unwrap_or(v)
                    .trim_matches(|c| c == '\'' || c == '"' || c == ' ');
                font.family = props::family(first);
                font.symbolic = props::typeface_symbolic(first);
                if props::typeface_bold(first) {
                    font.bold = true;
                }
            }
            "font-size" => {
                if let Some(s) = pt(v).filter(|s| *s > 0.0) {
                    font.size = s.clamp(1.0, 1_000.0);
                }
            }
            "font-weight" => font.bold = v == "bold" || v.parse::<u32>().is_ok_and(|w| w >= 600),
            "font-style" => font.italic = v == "italic" || v == "oblique",
            "text-decoration" => font.underline = v.contains("underline"),
            "color" => {
                if let Some(c) = css_color(v) {
                    font.color = c;
                }
            }
            "text-align" => {
                if let Some(h) = props::halign(v) {
                    para.h = h;
                }
            }
            "margin-top" => para.space_above = pt(v).unwrap_or(0.0).max(0.0),
            "margin-bottom" => para.space_below = pt(v).unwrap_or(0.0).max(0.0),
            "margin-left" => para.margin_left = pt(v).unwrap_or(0.0).max(0.0),
            "margin-right" => para.margin_right = pt(v).unwrap_or(0.0).max(0.0),
            "text-indent" => para.indent = pt(v).unwrap_or(0.0),
            "line-height" => para.line_height = pt(v).filter(|l| *l > 0.0),
            "xfa-spacerun" => *spacerun = v == "yes",
            "vertical-align" => match v {
                "super" => {
                    font.shift = font.size * 0.33;
                    font.size *= 0.66;
                }
                "sub" => {
                    font.shift = -font.size * 0.15;
                    font.size *= 0.66;
                }
                _ => {}
            },
            _ => {}
        }
    }
}

fn is_block(name: &str) -> bool {
    matches!(
        name,
        "p" | "div" | "li" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | "body" | "ol" | "ul"
    )
}

struct RichBuilder<'d> {
    dom: &'d Dom,
    out: Rich,
    para_base: Para,
}

impl RichBuilder<'_> {
    fn current(&mut self) -> Option<&mut RPara> {
        if self.out.paras.is_empty() {
            self.out.paras.push(RPara {
                para: self.para_base,
                ..RPara::default()
            });
        }
        self.out.paras.last_mut()
    }

    fn text(&mut self, raw: &str, st: &Inline) {
        let text = if st.spacerun {
            raw.replace(['\r', '\n'], " ")
        } else {
            let mut s = String::with_capacity(raw.len());
            let mut space = false;
            for c in raw.chars() {
                if c.is_whitespace() {
                    space = true;
                } else {
                    if space {
                        s.push(' ');
                    }
                    space = false;
                    s.push(c);
                }
            }
            if space {
                s.push(' ');
            }
            s
        };
        if text.is_empty() {
            return;
        }
        let Some(p) = self.current() else {
            return;
        };
        // Collapse a space at a paragraph's start or after a space.
        let text = if !st.spacerun
            && p.runs
                .last()
                .is_none_or(|r| r.text.ends_with(' ') || r.text.ends_with('\n'))
        {
            text.trim_start().to_owned()
        } else {
            text
        };
        if text.is_empty() {
            return;
        }
        if let Some(last) = p.runs.last_mut().filter(|r| r.font == st.font) {
            last.text.push_str(&text);
        } else {
            p.runs.push(Run {
                font: st.font.clone(),
                text,
            });
        }
    }

    fn new_para(&mut self, para: Para, base: &Font) {
        let fresh = self.out.paras.last().is_some_and(|p| p.runs.is_empty());
        if fresh {
            if let Some(p) = self.out.paras.last_mut() {
                p.para = para;
                p.base = base.clone();
            }
        } else {
            self.out.paras.push(RPara {
                para,
                runs: Vec::new(),
                base: base.clone(),
            });
        }
    }

    /// Walk the XHTML iteratively (depth comes from the file).
    fn walk(&mut self, root: NodeId, font: &Font, para: &Para) {
        enum Step {
            Enter(NodeId, Inline, Para),
            Leave(bool, Para, Font),
        }
        let mut stack = vec![Step::Enter(
            root,
            Inline {
                font: font.clone(),
                spacerun: false,
            },
            *para,
        )];
        let mut list_counter: Vec<(bool, u32)> = Vec::new();
        while let Some(step) = stack.pop() {
            match step {
                Step::Leave(block, para, base) => {
                    if block {
                        self.new_para(para, &base);
                    }
                }
                Step::Enter(id, mut st, mut para) => {
                    let (parent_para, parent_font) = (para, st.font.clone());
                    let node = self.dom.node(id);
                    if node.is_text() {
                        let text = node.text.clone();
                        self.text(&text, &st);
                        continue;
                    }
                    let name = node.name.as_str();
                    match name {
                        "b" | "strong" => st.font.bold = true,
                        "i" | "em" => st.font.italic = true,
                        "u" => st.font.underline = true,
                        "sup" => {
                            st.font.shift = st.font.size * 0.33;
                            st.font.size *= 0.66;
                        }
                        "sub" => {
                            st.font.shift = -st.font.size * 0.15;
                            st.font.size *= 0.66;
                        }
                        _ => {}
                    }
                    if let Some(style) = self.dom.attr(id, "style") {
                        let mut spacerun = st.spacerun;
                        apply_style(style, &mut st.font, &mut para, &mut spacerun);
                        st.spacerun = spacerun;
                    }
                    if name == "br" {
                        if let Some(p) = self.current() {
                            match p.runs.last_mut().filter(|r| r.font == st.font) {
                                Some(last) => last.text.push('\n'),
                                None => p.runs.push(Run {
                                    font: st.font.clone(),
                                    text: "\n".to_owned(),
                                }),
                            }
                        }
                        continue;
                    }
                    let block = is_block(name);
                    if block {
                        self.new_para(para, &st.font);
                    }
                    if name == "ol" || name == "ul" {
                        list_counter.push((name == "ol", 0));
                    }
                    if name == "li" {
                        let marker = match list_counter.last_mut() {
                            Some((true, n)) => {
                                *n = n.saturating_add(1);
                                format!("{n}. ")
                            }
                            _ => "\u{2022} ".to_owned(),
                        };
                        if let Some(p) = self.current() {
                            p.runs.push(Run {
                                font: st.font.clone(),
                                text: marker,
                            });
                        }
                    }
                    stack.push(Step::Leave(block, parent_para, parent_font));
                    for c in node.children.iter().rev() {
                        stack.push(Step::Enter(*c, st.clone(), para));
                    }
                }
            }
        }
        // Drop trailing empty paragraphs the walk opened.
        while self.out.paras.len() > 1 && self.out.paras.last().is_some_and(|p| p.runs.is_empty()) {
            self.out.paras.pop();
        }
    }
}

/// Rich text from an `exData` element holding XHTML (`<body>…</body>`).
pub(crate) fn rich(dom: &Dom, ex_data: NodeId, font: &Font, para: &Para) -> Rich {
    let mut b = RichBuilder {
        dom,
        out: Rich::default(),
        para_base: *para,
    };
    let root = dom.find(ex_data, "body").unwrap_or(ex_data);
    b.walk(root, font, para);
    let mut out = b.out;
    for p in &mut out.paras {
        // A trailing space at a paragraph's end is not drawn.
        if let Some(last) = p.runs.last_mut() {
            let t = last.text.trim_end_matches(' ').len();
            last.text.truncate(t);
        }
    }
    out
}

/// A placed piece of a line in one style and face run.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Piece {
    /// Left edge from the block's left, in points.
    pub x: f64,
    /// Baseline from the block's top, in points (downwards).
    pub baseline: f64,
    pub font: Font,
    pub glyphs: Vec<(Glyph, char)>,
    pub width: f64,
}

/// Laid-out text.
#[derive(Debug, Clone, PartialEq, Default)]
pub(crate) struct Block {
    pub pieces: Vec<Piece>,
    /// Widest line, margins included.
    pub width: f64,
    pub height: f64,
    /// Characters no face could draw.
    pub missing: usize,
    pub lines: usize,
}

#[derive(Debug, Clone)]
struct Atom {
    run: usize,
    ch: char,
    glyph: Option<Glyph>,
    adv: f64,
}

fn line_metrics(fonts: &Fonts<'_>, font: &Font, face: usize) -> (f64, f64, f64) {
    let m = fonts.metrics(face);
    let k = font.size / 1000.0;
    (m.ascent * k, -m.descent * k, m.gap * k)
}

/// Lay out `rich` in a box `width` wide; lines wrap when `wrap`.
pub(crate) fn layout(rich: &Rich, width: f64, wrap: bool, fonts: &mut Fonts<'_>) -> Block {
    let mut out = Block::default();
    let mut y = 0.0;
    for p in &rich.paras {
        y += p.para.space_above;
        let left = p.para.margin_left;
        let avail_all = (width - left - p.para.margin_right).max(0.0);
        // Atoms, with a hard break as '\n'.
        let mut atoms: Vec<Atom> = Vec::new();
        for (ri, r) in p.runs.iter().enumerate() {
            let face = fonts.preferred(r.font.family);
            for ch in r.text.chars() {
                let ch = if ch == '\t' { ' ' } else { ch };
                if ch == '\n' {
                    atoms.push(Atom {
                        run: ri,
                        ch,
                        glyph: None,
                        adv: 0.0,
                    });
                    continue;
                }
                if ch.is_control() {
                    continue;
                }
                let g = fonts.glyph(face, ch);
                if g.is_none() && !ch.is_whitespace() {
                    out.missing = out.missing.saturating_add(1);
                }
                let adv = g.map_or(0.0, |g| g.adv) * r.font.size / 1000.0;
                atoms.push(Atom {
                    run: ri,
                    ch,
                    glyph: g,
                    adv,
                });
            }
        }
        // Greedy breaking.
        let mut lines: Vec<Vec<Atom>> = Vec::new();
        let mut cur: Vec<Atom> = Vec::new();
        let mut cur_w = 0.0;
        let mut last_break: Option<usize> = None;
        for a in atoms {
            if a.ch == '\n' {
                lines.push(std::mem::take(&mut cur));
                cur_w = 0.0;
                last_break = None;
                continue;
            }
            let avail = if lines.is_empty() {
                avail_all - p.para.indent
            } else {
                avail_all
            };
            let is_space = a.ch == ' ';
            cur_w += a.adv;
            cur.push(a);
            if wrap && !is_space && cur_w > avail + 0.01 {
                if let Some(b) = last_break.filter(|b| *b > 0 && *b < cur.len()) {
                    let rest = cur.split_off(b);
                    lines.push(std::mem::take(&mut cur));
                    cur = rest;
                } else if cur.len() > 1 {
                    let keep = cur.pop();
                    lines.push(std::mem::take(&mut cur));
                    cur.extend(keep);
                }
                last_break = None;
                cur_w = cur.iter().map(|a| a.adv).sum();
            }
            if is_space {
                last_break = Some(cur.len());
            }
        }
        lines.push(cur);
        // Place lines.
        let base_face = fonts.preferred(p.base.family);
        for (li, mut line) in lines.into_iter().enumerate() {
            // Wrapped lines lose their trailing spaces, and leading ones after a wrap.
            while line.last().is_some_and(|a| a.ch == ' ') {
                line.pop();
            }
            let (mut asc, mut desc, mut gap) = line_metrics(fonts, &p.base, base_face);
            if let Some(first) = p.runs.first() {
                let f = fonts.preferred(first.font.family);
                let m = line_metrics(fonts, &first.font, f);
                if line.is_empty() {
                    (asc, desc, gap) = m;
                }
            }
            for a in &line {
                if let Some(r) = p.runs.get(a.run) {
                    let face = a
                        .glyph
                        .map_or_else(|| fonts.preferred(r.font.family), |g| g.face);
                    let (aa, dd, gg) = line_metrics(fonts, &r.font, face);
                    asc = f64::max(asc, aa + r.font.shift.max(0.0));
                    desc = f64::max(desc, dd - r.font.shift.min(0.0));
                    gap = f64::max(gap, gg);
                }
            }
            let natural = asc + desc + gap;
            let height = p.para.line_height.unwrap_or(natural);
            let w: f64 = line.iter().map(|a| a.adv).sum();
            let indent = if li == 0 { p.para.indent } else { 0.0 };
            let avail = (avail_all - indent).max(0.0);
            let dx = match p.para.h {
                HAlign::Center => ((avail - w) / 2.0).max(if wrap { 0.0 } else { f64::MIN }),
                HAlign::Right => (avail - w).max(if wrap { 0.0 } else { f64::MIN }),
                HAlign::Left | HAlign::Justify => 0.0,
            };
            let dx = if dx.is_finite() { dx } else { 0.0 };
            let baseline = y + asc + (height - natural).max(0.0) / 2.0;
            let mut x = left + indent + dx;
            let mut piece: Option<Piece> = None;
            for a in line {
                let Some(r) = p.runs.get(a.run) else {
                    continue;
                };
                let face = a.glyph.map(|g| g.face);
                let same = piece.as_ref().is_some_and(|pc| {
                    pc.font == r.font && pc.glyphs.first().map(|g| g.0.face) == face
                });
                if !same {
                    if let Some(pc) = piece.take() {
                        x = pc.x + pc.width;
                        if !pc.glyphs.is_empty() {
                            out.pieces.push(pc);
                        }
                    }
                    piece = Some(Piece {
                        x,
                        baseline: baseline - r.font.shift,
                        font: r.font.clone(),
                        glyphs: Vec::new(),
                        width: 0.0,
                    });
                }
                if let Some(pc) = piece.as_mut() {
                    pc.width += a.adv;
                    if let Some(g) = a.glyph {
                        pc.glyphs.push((g, a.ch));
                    }
                }
            }
            if let Some(pc) = piece.take()
                && !pc.glyphs.is_empty()
            {
                out.pieces.push(pc);
            }
            out.width = f64::max(out.width, left + indent + w + p.para.margin_right);
            out.lines = out.lines.saturating_add(1);
            y += height;
        }
        y += p.para.space_below;
    }
    out.height = y;
    out
}

#[cfg(all(test, feature = "bundled-fonts"))]
mod tests {
    // Test code: a panic is the failure report (CLAUDE.md).
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use crate::fonts::Faces;
    use crate::props::Family;
    use crate::xml::{XmlLimits, parse};

    fn sans(size: f64) -> Font {
        Font {
            family: Family::Sans,
            size,
            ..Font::default()
        }
    }

    const LIM: XmlLimits = XmlLimits {
        max_depth: 64,
        max_nodes: 10_000,
        max_attributes: 64,
    };

    #[test]
    fn plain_text_wraps_at_spaces_within_the_width() {
        let set = Faces::bundled();
        let mut fonts = Fonts::new(&set).unwrap();
        let r = Rich::plain("alpha beta gamma delta", &sans(10.0), &Para::default());
        let one = layout(&r, 1000.0, true, &mut fonts);
        assert_eq!(one.lines, 1);
        // "alpha beta" is 49.5 pt in Liberation Sans 10 pt, "gamma delta" 57.8 pt.
        let narrow = layout(&r, 45.0, true, &mut fonts);
        assert_eq!(narrow.lines, 4);
        assert!(narrow.pieces.iter().all(|p| p.x + p.width <= 45.0 + 0.01));
        assert!(narrow.height > one.height * 2.5);
    }

    #[test]
    fn a_long_word_breaks_between_characters() {
        let set = Faces::bundled();
        let mut fonts = Fonts::new(&set).unwrap();
        let r = Rich::plain("WWWWWWWWWWWWWWWWWWWW", &sans(10.0), &Para::default());
        let b = layout(&r, 30.0, true, &mut fonts);
        assert!(b.lines >= 6);
        assert!(b.pieces.iter().all(|p| p.width <= 30.01));
    }

    #[test]
    fn alignment_moves_lines_inside_the_box() {
        let set = Faces::bundled();
        let mut fonts = Fonts::new(&set).unwrap();
        let mut para = Para {
            h: HAlign::Right,
            ..Para::default()
        };
        let r = Rich::plain("x", &sans(10.0), &para);
        let b = layout(&r, 100.0, true, &mut fonts);
        assert!((b.pieces[0].x + b.pieces[0].width - 100.0).abs() < 0.01);
        para.h = HAlign::Center;
        let r = Rich::plain("x", &sans(10.0), &para);
        let b = layout(&r, 100.0, true, &mut fonts);
        assert!((b.pieces[0].x + b.pieces[0].width / 2.0 - 50.0).abs() < 0.01);
    }

    #[test]
    fn xhtml_runs_carry_their_styles_and_paragraphs() {
        let xml = br#"<exData><body xmlns="http://www.w3.org/1999/xhtml"><p style="font-size:12pt;text-align:center">One <span style="font-weight:bold">two</span></p><p style="margin-top:6pt">three<br/>four</p></body></exData>"#;
        let dom = parse(xml, LIM, &|| false).unwrap();
        let ex = dom.find(0, "exData").unwrap();
        let r = rich(&dom, ex, &sans(9.0), &Para::default());
        assert_eq!(r.paras.len(), 2, "{r:?}");
        assert_eq!(r.paras[0].para.h, HAlign::Center);
        assert_eq!(r.paras[0].runs.len(), 2);
        assert_eq!(r.paras[0].runs[0].text, "One ");
        assert!(r.paras[0].runs[1].font.bold);
        assert!((r.paras[0].runs[1].font.size - 12.0).abs() < 1e-9);
        assert!((r.paras[1].para.space_above - 6.0).abs() < 1e-9);
        assert_eq!(r.paras[1].runs[0].text, "three\nfour");
        let set = Faces::bundled();
        let mut fonts = Fonts::new(&set).unwrap();
        assert_eq!(layout(&r, 500.0, true, &mut fonts).lines, 3);
    }

    #[test]
    fn whitespace_collapses_unless_spacerun() {
        let xml = b"<body><p>a   \n  b<span style=\"xfa-spacerun:yes\">  c</span></p></body>";
        let dom = parse(xml, LIM, &|| false).unwrap();
        let r = rich(&dom, 0, &sans(9.0), &Para::default());
        let text: String = r.paras[0].runs.iter().map(|r| r.text.as_str()).collect();
        assert_eq!(text, "a b  c");
    }
}
