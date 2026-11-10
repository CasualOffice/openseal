//! Layout (XFA 3.3 "Layout for Growable Objects" and "Flowing Layout"): the merged
//! form to boxes, and boxes to pages.
//!
//! Each container is laid out once into a box of fixed size whose children sit at
//! offsets inside it: `position` layout puts them at their `x`/`y` after `anchorType`;
//! `tb` stacks them; `lr-tb` and `rl-tb` fill lines and wrap; `table` sizes `row`
//! subforms' cells to `columnWidths` (with `colSpan`) and stretches each row's cells to
//! the tallest. A box without `w` or `h` grows to its content within `minW`/`maxW`,
//! `minH`/`maxH`. Fields place their caption (`left`, `right`, `top`, `bottom`, with
//! `reserve` or the caption's own size) and their widget; draws hold text (plain or
//! XHTML), lines, rectangles, arcs and images. `rotate` turns fields and draws by
//! multiples of 90 degrees.
//!
//! Pagination then flows the root subform's children through the content areas of
//! the page set: a box that does not fit moves to the next content area or page; a
//! flowed subform without a fixed height and not kept intact splits between its rows
//! (lines, stacked children, table rows), recursively; `breakBefore`/`breakAfter`
//! (and XFA 2's `break`) start a new page on a named page area or a new content area;
//! `overflow` names the page area that overflowing content continues on. Each page
//! carries its page area's own content. The output is the printed form:
//! `relevant="-print"` objects are left out.
//!
//! Not built (`XFA-01`): `keep` `next`/`previous`, overflow leaders and trailers,
//! bookend leaders and trailers, `pageArea` selection by `pagePosition` and
//! `oddOrEven`, `occur` limits on page areas other than `max`, splitting text inside
//! one field or draw, and `hAlign` on flowed subforms.

use std::collections::BTreeMap;

use crate::XfaLimits;
use crate::XfaReport;
use crate::error::XfaError;
use crate::fonts::Fonts;
use crate::form::{FNode, Kind, Merge, occur};
use crate::image::{self, ImageData};
use crate::props::{
    self, Border, Color, Edge, Font, HAlign, Margin, Para, VAlign, attr_len, measure,
};
use crate::text::{self, Block, Rich};
use crate::xml::{Dom, NodeId};

/// Slack for floating-point comparisons, in points.
const EPS: f64 = 0.01;

/// What a widget is.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum WKind {
    Text {
        multiline: bool,
        max_len: Option<u32>,
        comb: bool,
        password: bool,
    },
    Check {
        /// The on value (the first `items` entry, `1` by default).
        on: String,
        on_now: bool,
        round: bool,
        mark: char,
        /// A member of an exclusion group: a radio button.
        radio: bool,
    },
    Choice {
        options: Vec<(String, String)>,
        combo: bool,
        edit: bool,
        multi: bool,
    },
    Signature,
}

/// An interactive field's widget.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Widget {
    pub x: f64,
    pub y: f64,
    pub w: f64,
    pub h: f64,
    /// The AcroForm full name's segments (`form1[0]`, `page1[0]`, `Name[0]`).
    pub path: Vec<String>,
    pub kind: WKind,
    /// The value as stored (`/V`).
    pub value: Option<String>,
    pub tooltip: Option<String>,
    pub font_size: f64,
    /// The value drawn as the widget's appearance, positioned in the widget.
    pub appearance: Option<(f64, f64, Block)>,
}

/// Something drawn. Coordinates are points from the top-left (y downwards) of the
/// box that holds it, and of the page once placed.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum Mark {
    Fill {
        x: f64,
        y: f64,
        w: f64,
        h: f64,
        color: Color,
        radius: f64,
    },
    Frame {
        x: f64,
        y: f64,
        w: f64,
        h: f64,
        border: Border,
    },
    Line {
        x1: f64,
        y1: f64,
        x2: f64,
        y2: f64,
        edge: Edge,
    },
    Arc {
        x: f64,
        y: f64,
        w: f64,
        h: f64,
        start: f64,
        sweep: f64,
        edge: Edge,
        fill: Option<Color>,
    },
    Text {
        x: f64,
        y: f64,
        block: Block,
    },
    Image {
        x: f64,
        y: f64,
        w: f64,
        h: f64,
        index: usize,
    },
    /// Marks drawn in a frame turned `angle` degrees counter-clockwise about
    /// (`ox`, `oy`); the inner marks' coordinates are in the unturned frame.
    Rotated {
        ox: f64,
        oy: f64,
        angle: i32,
        marks: Vec<Mark>,
    },
    /// A check box's or radio button's static look: the box itself.
    Widget(Box<Widget>),
}

fn translate(m: &mut Mark, dx: f64, dy: f64) {
    match m {
        Mark::Fill { x, y, .. }
        | Mark::Frame { x, y, .. }
        | Mark::Arc { x, y, .. }
        | Mark::Text { x, y, .. }
        | Mark::Image { x, y, .. } => {
            *x += dx;
            *y += dy;
        }
        Mark::Line { x1, y1, x2, y2, .. } => {
            *x1 += dx;
            *x2 += dx;
            *y1 += dy;
            *y2 += dy;
        }
        Mark::Rotated { ox, oy, .. } => {
            *ox += dx;
            *oy += dy;
        }
        Mark::Widget(w) => {
            w.x += dx;
            w.y += dy;
        }
    }
}

/// A break request.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct Brk {
    /// True for a page area (or `auto` with a page target), false for a content area.
    pub page: bool,
    pub target: Option<String>,
    pub start_new: bool,
}

/// A laid-out container or object.
#[derive(Debug, Clone, Default)]
pub(crate) struct LBox {
    pub w: f64,
    pub h: f64,
    /// The container's own border and fill, drawn per fragment when it splits.
    pub frame: Option<Border>,
    pub marks: Vec<Mark>,
    pub kids: Vec<(f64, f64, LBox)>,
    /// Rows for splitting: (top, height, kid indices). Empty when the box cannot split.
    pub rows: Vec<(f64, f64, Vec<usize>)>,
    pub before: Option<Brk>,
    pub after: Option<Brk>,
    pub overflow: Option<String>,
    pub inset_top: f64,
    pub inset_bottom: f64,
}

/// A laid-out page.
#[derive(Debug, Clone, Default)]
pub(crate) struct Page {
    pub w: f64,
    pub h: f64,
    pub marks: Vec<Mark>,
}

/// The laid-out document.
#[derive(Debug, Clone, Default)]
pub(crate) struct Doc {
    pub pages: Vec<Page>,
    pub images: Vec<ImageData>,
    pub report: XfaReport,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Presence {
    Visible,
    Invisible,
    Hidden,
}

struct Ctx<'a, 'f> {
    dom: &'a Dom,
    fonts: &'a mut Fonts<'f>,
    limits: &'a XfaLimits,
    cancel: &'a dyn Fn() -> bool,
    report: XfaReport,
    images: Vec<ImageData>,
    items: usize,
}

/// Geometry attributes of a container.
#[derive(Debug, Clone, Copy, Default)]
struct Geom {
    x: f64,
    y: f64,
    w: Option<f64>,
    h: Option<f64>,
    min_w: f64,
    max_w: f64,
    min_h: f64,
    max_h: f64,
    anchor: (f64, f64),
}

fn geom(dom: &Dom, id: NodeId) -> Geom {
    let l = |n: &str| attr_len(dom, id, n);
    let anchor = match dom.attr(id, "anchorType") {
        Some("topCenter") => (0.5, 0.0),
        Some("topRight") => (1.0, 0.0),
        Some("middleLeft") => (0.0, 0.5),
        Some("middleCenter") => (0.5, 0.5),
        Some("middleRight") => (1.0, 0.5),
        Some("bottomLeft") => (0.0, 1.0),
        Some("bottomCenter") => (0.5, 1.0),
        Some("bottomRight") => (1.0, 1.0),
        _ => (0.0, 0.0),
    };
    Geom {
        x: l("x").unwrap_or(0.0),
        y: l("y").unwrap_or(0.0),
        w: l("w").map(|v| v.max(0.0)),
        h: l("h").map(|v| v.max(0.0)),
        min_w: l("minW").unwrap_or(0.0).max(0.0),
        max_w: l("maxW").filter(|v| *v > 0.0).unwrap_or(f64::INFINITY),
        min_h: l("minH").unwrap_or(0.0).max(0.0),
        max_h: l("maxH").filter(|v| *v > 0.0).unwrap_or(f64::INFINITY),
        anchor,
    }
}

fn clamp(v: f64, lo: f64, hi: f64) -> f64 {
    v.max(lo).min(hi.max(lo))
}

/// The value of a `<value>` content element by kind.
enum Content {
    None,
    Text(String),
    Rich(NodeId),
    Image(NodeId),
    Rect(NodeId),
    Line(NodeId),
    Arc(NodeId),
}

fn content(dom: &Dom, owner: NodeId) -> Content {
    let Some(v) = dom.child(owner, "value") else {
        return Content::None;
    };
    let Some(c) = dom.elements(v).next() else {
        return Content::None;
    };
    match dom.name(c) {
        "exData" => {
            if dom
                .attr(c, "contentType")
                .is_some_and(|t| t.contains("html"))
            {
                Content::Rich(c)
            } else {
                Content::Text(dom.text(c))
            }
        }
        "image" => Content::Image(c),
        "rectangle" => Content::Rect(c),
        "line" => Content::Line(c),
        "arc" => Content::Arc(c),
        _ => Content::Text(dom.text(c)),
    }
}

fn scripts_in(dom: &Dom, id: NodeId) -> usize {
    dom.elements(id)
        .map(|c| match dom.name(c) {
            "event" | "calculate" => 1usize,
            "validate" => usize::from(dom.child(c, "script").is_some()),
            _ => 0,
        })
        .fold(0usize, usize::saturating_add)
}

fn brk_of(dom: &Dom, id: NodeId, before: bool) -> Option<Brk> {
    let tag = if before { "breakBefore" } else { "breakAfter" };
    if let Some(b) = dom.child(id, tag) {
        let tt = dom.attr(b, "targetType").unwrap_or("auto");
        let target = dom
            .attr(b, "target")
            .map(|t| t.trim().trim_start_matches('#').to_owned())
            .filter(|t| !t.is_empty());
        let start_new = dom.attr(b, "startNew") == Some("1");
        return match tt {
            "pageArea" => Some(Brk {
                page: true,
                target,
                start_new,
            }),
            "contentArea" => Some(Brk {
                page: false,
                target,
                start_new,
            }),
            _ => None,
        };
    }
    // XFA 2.x: <break before="pageArea" beforeTarget="#id"/>.
    let b = dom.child(id, "break")?;
    let (kind, target) = if before {
        (dom.attr(b, "before"), dom.attr(b, "beforeTarget"))
    } else {
        (dom.attr(b, "after"), dom.attr(b, "afterTarget"))
    };
    let target = target
        .map(|t| t.trim().trim_start_matches('#').to_owned())
        .filter(|t| !t.is_empty());
    let start_new = dom.attr(b, "startNew") == Some("1");
    match kind {
        Some("pageArea" | "pageEven" | "pageOdd") => Some(Brk {
            page: true,
            target,
            start_new,
        }),
        Some("contentArea") => Some(Brk {
            page: false,
            target,
            start_new,
        }),
        _ => None,
    }
}

/// The SOM segment of each node among its siblings (`name[i]`, `#subform[i]` when
/// unnamed), as Acrobat names fields.
fn names_for(nodes: &[FNode]) -> Vec<String> {
    let mut counters: BTreeMap<String, usize> = BTreeMap::new();
    let mut out = Vec::new();
    for n in nodes {
        let base = if n.name.is_empty() {
            match n.kind {
                Kind::Subform => "#subform".to_owned(),
                Kind::ExclGroup => "#exclGroup".to_owned(),
                Kind::Field => "#field".to_owned(),
                Kind::Draw => "#draw".to_owned(),
                Kind::Area => "#area".to_owned(),
                Kind::SubformSet => "#subformSet".to_owned(),
            }
        } else {
            n.name.clone()
        };
        let i = counters.entry(base.clone()).or_insert(0);
        out.push(format!("{base}[{i}]"));
        *i = i.saturating_add(1);
    }
    out
}

impl Ctx<'_, '_> {
    fn tick(&mut self) -> Result<(), XfaError> {
        self.items = self.items.saturating_add(1);
        if self.items > self.limits.max_form_nodes.saturating_mul(4) {
            return Err(XfaError::TooManyItems {
                limit: self.limits.max_form_nodes.saturating_mul(4),
            });
        }
        if self.items.is_multiple_of(512) && (self.cancel)() {
            return Err(XfaError::Cancelled);
        }
        Ok(())
    }

    fn presence(&mut self, id: NodeId) -> Presence {
        if self
            .dom
            .attr(id, "relevant")
            .is_some_and(|r| r.split_whitespace().any(|t| t == "-print"))
        {
            self.report.screen_only = self.report.screen_only.saturating_add(1);
            return Presence::Hidden;
        }
        match self.dom.attr(id, "presence") {
            Some("hidden" | "inactive") => Presence::Hidden,
            Some("invisible") => Presence::Invisible,
            _ => Presence::Visible,
        }
    }

    fn font_of(&self, owner: NodeId, base: &Font) -> Font {
        self.dom
            .child(owner, "font")
            .map_or_else(|| base.clone(), |f| props::font(self.dom, f, base))
    }

    fn para_of(&self, owner: NodeId, base: &Para) -> Para {
        self.dom
            .child(owner, "para")
            .map_or(*base, |p| props::para(self.dom, p, base))
    }

    fn rich_of(&mut self, c: &Content, font: &Font, para: &Para) -> Option<Rich> {
        match c {
            Content::Text(t) => Some(Rich::plain(t, font, para)),
            Content::Rich(id) => Some(text::rich(self.dom, *id, font, para)),
            _ => None,
        }
    }

    fn text_block(&mut self, rich: &Rich, width: f64, wrap: bool) -> Block {
        self.report.symbol_chars = self
            .report
            .symbol_chars
            .saturating_add(rich.symbolic_chars());
        let b = text::layout(rich, width, wrap, self.fonts);
        self.report.missing_glyphs = self.report.missing_glyphs.saturating_add(b.missing);
        b
    }

    /// Lay out one form node. `None` when it takes no space.
    fn node(
        &mut self,
        n: &FNode,
        path: &[String],
        force_w: Option<f64>,
        force_h: Option<f64>,
    ) -> Result<Option<LBox>, XfaError> {
        self.tick()?;
        let presence = self.presence(n.tpl);
        if presence == Presence::Hidden {
            return Ok(None);
        }
        self.report.scripts_ignored = self
            .report
            .scripts_ignored
            .saturating_add(scripts_in(self.dom, n.tpl));
        let mut b = match n.kind {
            Kind::Subform | Kind::Area | Kind::SubformSet => {
                self.container(n, path, force_w, force_h)?
            }
            Kind::ExclGroup => self.container(n, path, force_w, force_h)?,
            Kind::Field => self.field(n, path, force_w, force_h, None),
            Kind::Draw => self.draw(n, force_w, force_h),
        };
        if presence == Presence::Invisible {
            b.marks.clear();
            b.kids.clear();
            b.rows.clear();
            b.frame = None;
        }
        if matches!(n.kind, Kind::Field | Kind::Draw) {
            let angle = self
                .dom
                .attr(n.tpl, "rotate")
                .and_then(|r| r.trim().parse::<i32>().ok())
                .map_or(0, |a| a.rem_euclid(360));
            if matches!(angle, 90 | 180 | 270) {
                b = rotate(b, angle);
            }
        }
        Ok(Some(b))
    }

    fn container(
        &mut self,
        n: &FNode,
        path: &[String],
        force_w: Option<f64>,
        force_h: Option<f64>,
    ) -> Result<LBox, XfaError> {
        let dom = self.dom;
        let t = n.tpl;
        let g = geom(dom, t);
        let margin = Margin::of(dom, t);
        let frame = dom
            .child(t, "border")
            .map(|b| props::border(dom, b))
            .filter(|b| b.paints);
        let layout = match n.kind {
            Kind::SubformSet => "tb",
            Kind::Area | Kind::ExclGroup => dom.attr(t, "layout").unwrap_or("position"),
            _ => dom.attr(t, "layout").unwrap_or("position"),
        };
        let fixed_w = force_w.or(g.w);
        let fixed_h = force_h.or(g.h);
        let inner_w = fixed_w.map(|w| (w - margin.h()).max(0.0));
        let names = names_for(&n.children);
        // An exclusion group's members are widgets of the group's field.
        let group = n.kind == Kind::ExclGroup;
        let mut out = LBox {
            frame,
            inset_top: margin.top,
            inset_bottom: margin.bottom,
            before: brk_of(dom, t, true),
            after: brk_of(dom, t, false),
            overflow: dom
                .child(t, "overflow")
                .and_then(|o| dom.attr(o, "target"))
                .map(|s| s.trim().trim_start_matches('#').to_owned())
                .filter(|s| !s.is_empty()),
            ..LBox::default()
        };
        let lay_kid = |ctx: &mut Self, i: usize, c: &FNode, fw: Option<f64>, fh: Option<f64>| {
            if group && c.kind == Kind::Field {
                // Members are widgets of the group's field: they take its name.
                return ctx.field_in_group(c, path, n, fw, fh);
            }
            if matches!(c.kind, Kind::Area | Kind::SubformSet) {
                // Transparent: no segment of their own (Acrobat's naming).
                return ctx.node(c, path, fw, fh);
            }
            let mut p: Vec<String> = path.to_vec();
            if let Some(s) = names.get(i) {
                p.push(s.clone());
            }
            ctx.node(c, &p, fw, fh)
        };
        let (mut ext_w, mut ext_h) = (0.0f64, 0.0f64);
        match layout {
            "tb" => {
                let mut y = margin.top;
                for (i, c) in n.children.iter().enumerate() {
                    let Some(kb) = lay_kid(self, i, c, None, None)? else {
                        continue;
                    };
                    let k = out.kids.len();
                    out.rows.push((y, kb.h, vec![k]));
                    ext_w = ext_w.max(kb.w);
                    y += kb.h;
                    out.kids.push((margin.left, y - kb.h, kb));
                }
                ext_h = y - margin.top;
            }
            "lr-tb" | "rl-tb" | "row" => {
                let wrap = layout != "row";
                let avail = inner_w.unwrap_or(f64::INFINITY);
                let rtl = layout == "rl-tb";
                let mut y = margin.top;
                let mut x = 0.0f64;
                let mut line: Vec<usize> = Vec::new();
                let mut line_h = 0.0f64;
                let flush =
                    |out: &mut LBox, line: &mut Vec<usize>, y: &mut f64, line_h: &mut f64| {
                        if !line.is_empty() {
                            out.rows.push((*y, *line_h, std::mem::take(line)));
                            *y += *line_h;
                        }
                        *line_h = 0.0;
                    };
                for (i, c) in n.children.iter().enumerate() {
                    let Some(kb) = lay_kid(self, i, c, None, None)? else {
                        continue;
                    };
                    if wrap && !line.is_empty() && x + kb.w > avail + EPS {
                        flush(&mut out, &mut line, &mut y, &mut line_h);
                        x = 0.0;
                    }
                    let kx = if rtl && avail.is_finite() {
                        margin.left + avail - x - kb.w
                    } else {
                        margin.left + x
                    };
                    x += kb.w;
                    ext_w = ext_w.max(x);
                    line_h = line_h.max(kb.h);
                    line.push(out.kids.len());
                    out.kids.push((kx, y, kb));
                }
                flush(&mut out, &mut line, &mut y, &mut line_h);
                ext_h = y - margin.top;
            }
            "table" => {
                let cols: Vec<Option<f64>> = dom
                    .attr(t, "columnWidths")
                    .unwrap_or("")
                    .split_whitespace()
                    .map(|c| measure(c, 72.0).filter(|w| *w >= 0.0))
                    .collect();
                let mut y = margin.top;
                for (i, c) in n.children.iter().enumerate() {
                    let row_like =
                        c.kind == Kind::Subform && dom.attr(c.tpl, "layout") == Some("row");
                    let kb = if row_like {
                        let mut p: Vec<String> = path.to_vec();
                        if let Some(s) = names.get(i) {
                            p.push(s.clone());
                        }
                        self.table_row(c, &p, &cols)?
                    } else {
                        lay_kid(self, i, c, None, None)?
                    };
                    let Some(kb) = kb else {
                        continue;
                    };
                    let k = out.kids.len();
                    out.rows.push((y, kb.h, vec![k]));
                    ext_w = ext_w.max(kb.w);
                    out.kids.push((margin.left, y, kb));
                    y += out.kids.last().map_or(0.0, |k| k.2.h);
                }
                ext_h = y - margin.top;
            }
            _ => {
                // position
                for (i, c) in n.children.iter().enumerate() {
                    let Some(kb) = lay_kid(self, i, c, None, None)? else {
                        continue;
                    };
                    let cg = geom(dom, c.tpl);
                    let mut kx = cg.x - cg.anchor.0 * kb.w;
                    let mut ky = cg.y - cg.anchor.1 * kb.h;
                    if let Some((dx, dy)) = rotation_offset(dom, c, &kb) {
                        kx += dx;
                        ky += dy;
                    }
                    ext_w = ext_w.max(kx + kb.w);
                    ext_h = ext_h.max(ky + kb.h);
                    out.kids.push((margin.left + kx, margin.top + ky, kb));
                }
            }
        }
        out.w = fixed_w.unwrap_or_else(|| clamp(ext_w + margin.h(), g.min_w, g.max_w));
        out.h = fixed_h.unwrap_or_else(|| clamp(ext_h + margin.v(), g.min_h, g.max_h));
        let keep = dom
            .child(t, "keep")
            .and_then(|k| dom.attr(k, "intact"))
            .unwrap_or("none");
        let splittable = matches!(layout, "tb" | "lr-tb" | "rl-tb" | "table")
            && fixed_h.is_none()
            && keep == "none";
        if !splittable {
            out.rows.clear();
        }
        Ok(out)
    }

    fn table_row(
        &mut self,
        row: &FNode,
        path: &[String],
        cols: &[Option<f64>],
    ) -> Result<Option<LBox>, XfaError> {
        self.tick()?;
        if self.presence(row.tpl) == Presence::Hidden {
            return Ok(None);
        }
        let dom = self.dom;
        let names = names_for(&row.children);
        let mut col = 0usize;
        let mut cells: Vec<(f64, &FNode, String, f64)> = Vec::new();
        for (i, c) in row.children.iter().enumerate() {
            if self.presence(c.tpl) == Presence::Hidden {
                continue;
            }
            let span = dom
                .attr(c.tpl, "colSpan")
                .and_then(|s| s.trim().parse::<i64>().ok())
                .unwrap_or(1);
            let take = if span < 0 {
                cols.len().saturating_sub(col).max(1)
            } else {
                usize::try_from(span).unwrap_or(1).max(1)
            };
            let width: f64 = (col..col.saturating_add(take))
                .map(|k| cols.get(k).copied().flatten().unwrap_or(0.0))
                .sum();
            let x: f64 = (0..col)
                .map(|k| cols.get(k).copied().flatten().unwrap_or(0.0))
                .sum();
            col = col.saturating_add(take);
            cells.push((x, c, names.get(i).cloned().unwrap_or_default(), width));
        }
        // First pass for the row height, second to stretch every cell to it.
        let mut h = geom(dom, row.tpl).min_h;
        for (_, c, seg, w) in &cells {
            let mut p = path.to_vec();
            p.push(seg.clone());
            let fw = (*w > 0.0).then_some(*w);
            if let Some(b) = self.node(c, &p, fw, None)? {
                h = h.max(b.h);
            }
        }
        let mut out = LBox::default();
        let mut wsum = 0.0f64;
        for (x, c, seg, w) in &cells {
            let mut p = path.to_vec();
            p.push(seg.clone());
            let fw = (*w > 0.0).then_some(*w);
            if let Some(b) = self.node(c, &p, fw, Some(h))? {
                wsum = wsum.max(x + b.w);
                out.kids.push((*x, 0.0, b));
            }
        }
        out.w = wsum;
        out.h = h;
        out.frame = dom
            .child(row.tpl, "border")
            .map(|b| props::border(dom, b))
            .filter(|b| b.paints);
        Ok(Some(out))
    }

    fn field_in_group(
        &mut self,
        c: &FNode,
        path: &[String],
        group: &FNode,
        fw: Option<f64>,
        fh: Option<f64>,
    ) -> Result<Option<LBox>, XfaError> {
        self.tick()?;
        let presence = self.presence(c.tpl);
        if presence == Presence::Hidden {
            return Ok(None);
        }
        let mut b = self.field(c, path, fw, fh, Some(group));
        if presence == Presence::Invisible {
            b.marks.clear();
        }
        Ok(Some(b))
    }

    /// A field: caption, widget border and the widget.
    fn field(
        &mut self,
        n: &FNode,
        path: &[String],
        force_w: Option<f64>,
        force_h: Option<f64>,
        group: Option<&FNode>,
    ) -> LBox {
        let dom = self.dom;
        let t = n.tpl;
        let g = geom(dom, t);
        let font = self.font_of(t, &Font::default());
        let para = self.para_of(t, &Para::default());
        let margin = Margin::of(dom, t);
        let ui = dom.child(t, "ui").and_then(|u| dom.elements(u).next());
        let ui_name = ui.map_or("textEdit", |u| dom.name(u));
        let ui_name = if ui_name == "defaultUi" {
            "textEdit"
        } else {
            ui_name
        };

        // Caption.
        let cap = dom.child(t, "caption").filter(|c| {
            !matches!(
                dom.attr(*c, "presence"),
                Some("hidden" | "invisible" | "inactive")
            )
        });
        let (cap_rich, cap_place, cap_reserve, cap_margin, cap_para) = match cap {
            Some(c) => {
                let cf = self.font_of(c, &font);
                let cp = self.para_of(c, &Para::default());
                let rich = {
                    let ct = content(dom, c);
                    self.rich_of(&ct, &cf, &cp)
                };
                (
                    rich.filter(|r| !r.is_empty()),
                    dom.attr(c, "placement").unwrap_or("left"),
                    attr_len(dom, c, "reserve").filter(|r| *r > 0.0),
                    Margin::of(dom, c),
                    cp,
                )
            }
            None => (None, "left", None, Margin::default(), Para::default()),
        };
        let cap_place = if cap_rich.is_none() {
            "none"
        } else {
            cap_place
        };

        // The value as shown.
        let items: Vec<Vec<String>> = dom
            .children_named(t, "items")
            .map(|it| dom.elements(it).map(|e| dom.text(e)).collect())
            .collect();
        let saved_items = dom
            .children_named(t, "items")
            .position(|it| dom.attr(it, "save") == Some("1"));
        let value = n.value.clone();
        let check_size = ui
            .filter(|_| ui_name == "checkButton")
            .and_then(|u| attr_len(dom, u, "size"))
            .unwrap_or(10.0);

        // Natural size.
        let inner_w_fixed = force_w.or(g.w).map(|w| (w - margin.h()).max(0.0));
        let (cap_w_nat, cap_h_nat) = match &cap_rich {
            Some(r) => {
                let wrap_w = match (cap_place, inner_w_fixed) {
                    ("top" | "bottom", Some(w)) => Some(w - cap_margin.h()),
                    _ => None,
                };
                let b = self.text_block(r, wrap_w.unwrap_or(10_000.0), wrap_w.is_some());
                (b.width + cap_margin.h(), b.height + cap_margin.v())
            }
            None => (0.0, 0.0),
        };
        let reserve_h = matches!(cap_place, "left" | "right");
        let reserve = cap_reserve.unwrap_or(if reserve_h { cap_w_nat } else { cap_h_nat });
        let reserve = if cap_place == "none" || cap_place == "inline" {
            0.0
        } else {
            reserve
        };
        let value_nat = match ui_name {
            "checkButton" => (check_size, check_size),
            _ => {
                let lh = font.size * 1.15;
                let w = value
                    .as_ref()
                    .map(|v| {
                        self.text_block(&Rich::plain(v, &font, &para), 10_000.0, false)
                            .width
                    })
                    .unwrap_or(0.0);
                (w, lh)
            }
        };
        let nat_w = margin.h()
            + if reserve_h {
                reserve + value_nat.0
            } else {
                cap_w_nat.max(value_nat.0)
            };
        let nat_h = margin.v()
            + if reserve_h {
                cap_h_nat.max(value_nat.1)
            } else {
                reserve + value_nat.1
            };
        let w = force_w
            .or(g.w)
            .unwrap_or_else(|| clamp(nat_w, g.min_w, g.max_w));
        let h = force_h
            .or(g.h)
            .unwrap_or_else(|| clamp(nat_h, g.min_h, g.max_h));

        let mut out = LBox {
            w,
            h,
            ..LBox::default()
        };
        if let Some(b) = dom.child(t, "border").map(|b| props::border(dom, b)) {
            push_frame(&mut out.marks, 0.0, 0.0, w, h, &b);
        }
        let (cx, cy) = (margin.left, margin.top);
        let (cw, ch) = ((w - margin.h()).max(0.0), (h - margin.v()).max(0.0));
        let (cap_rect, wid) = match cap_place {
            "left" => (
                (cx, cy, reserve, ch),
                (cx + reserve, cy, (cw - reserve).max(0.0), ch),
            ),
            "right" => (
                ((cx + cw - reserve), cy, reserve, ch),
                (cx, cy, (cw - reserve).max(0.0), ch),
            ),
            "top" => (
                (cx, cy, cw, reserve),
                (cx, cy + reserve, cw, (ch - reserve).max(0.0)),
            ),
            "bottom" => (
                (cx, cy + ch - reserve, cw, reserve),
                (cx, cy, cw, (ch - reserve).max(0.0)),
            ),
            _ => ((cx, cy, cw, ch), (cx, cy, cw, ch)),
        };
        if let Some(r) = &cap_rich {
            let (x, y, cw2, ch2) = cap_rect;
            let iw = (cw2 - cap_margin.h()).max(0.0);
            let block = self.text_block(r, iw, true);
            let ih = (ch2 - cap_margin.v()).max(0.0);
            let dy = valign(cap_para.v, ih, block.height);
            out.marks.push(Mark::Text {
                x: x + cap_margin.left,
                y: y + cap_margin.top + dy,
                block,
            });
        }
        let (wx, wy, ww, wh) = wid;
        // The widget's own border and margin.
        let ui_margin = ui.map_or_else(Margin::default, |u| Margin::of(dom, u));
        let ui_border = ui
            .and_then(|u| dom.child(u, "border"))
            .map(|b| props::border(dom, b));
        let tooltip = dom
            .path(t, &["assist", "toolTip"])
            .map(|tt| dom.text(tt))
            .filter(|s| !s.trim().is_empty());
        match ui_name {
            "checkButton" => {
                self.report.fields.check = self.report.fields.check.saturating_add(1);
                let s = check_size.min(ww.max(0.0)).min(wh.max(0.0)).max(1.0);
                let bx = wx
                    + match para.h {
                        HAlign::Center => (ww - s) / 2.0,
                        HAlign::Right => ww - s,
                        _ => 0.0,
                    };
                let by = wy + valign(para.v, wh, s);
                let round = ui.and_then(|u| dom.attr(u, "shape")) == Some("round");
                match &ui_border {
                    Some(b) => push_frame_shape(&mut out.marks, bx, by, s, s, b, round),
                    None => push_frame_shape(
                        &mut out.marks,
                        bx,
                        by,
                        s,
                        s,
                        &Border {
                            edges: [Edge::default(); 4],
                            paints: true,
                            ..Border::default()
                        },
                        round,
                    ),
                }
                let on = items
                    .first()
                    .and_then(|i| i.first().cloned())
                    .unwrap_or_else(|| "1".to_owned());
                let (radio, group_value) = match group {
                    Some(gn) => (true, gn.value.clone()),
                    None => (false, value.clone()),
                };
                let on_now = group_value.as_deref() == Some(on.as_str());
                let mark = match ui.and_then(|u| dom.attr(u, "mark")) {
                    Some("circle") => 'l',
                    Some("cross") => '8',
                    Some("diamond") => 'u',
                    Some("square") => 'n',
                    Some("star") => 'H',
                    Some("check") => '4',
                    _ if round => 'l',
                    _ => '4',
                };
                out.marks.push(Mark::Widget(Box::new(Widget {
                    x: bx,
                    y: by,
                    w: s,
                    h: s,
                    path: path.to_vec(),
                    kind: WKind::Check {
                        on,
                        on_now,
                        round,
                        mark,
                        radio,
                    },
                    value: None,
                    tooltip,
                    font_size: font.size,
                    appearance: None,
                })));
            }
            "button" | "barcode" | "imageEdit" => {
                self.report.inert_fields = self.report.inert_fields.saturating_add(1);
                if let Some(b) = &ui_border {
                    push_frame(&mut out.marks, wx, wy, ww, wh, b);
                }
            }
            _ => {
                if let Some(b) = &ui_border {
                    push_frame(&mut out.marks, wx, wy, ww, wh, b);
                }
                let kind = match ui_name {
                    "choiceList" => {
                        self.report.fields.choice = self.report.fields.choice.saturating_add(1);
                        let display = items.first().cloned().unwrap_or_default();
                        let saved = saved_items
                            .and_then(|i| items.get(i).cloned())
                            .unwrap_or_else(|| display.clone());
                        let options = display
                            .iter()
                            .enumerate()
                            .map(|(i, d)| {
                                (
                                    saved.get(i).cloned().unwrap_or_else(|| d.clone()),
                                    d.clone(),
                                )
                            })
                            .collect();
                        let open = ui.and_then(|u| dom.attr(u, "open")).unwrap_or("userInput");
                        WKind::Choice {
                            options,
                            combo: open != "always" && open != "multiSelect",
                            edit: ui.and_then(|u| dom.attr(u, "textEntry")) == Some("1"),
                            multi: open == "multiSelect",
                        }
                    }
                    "signature" => {
                        self.report.fields.signature =
                            self.report.fields.signature.saturating_add(1);
                        WKind::Signature
                    }
                    other => {
                        match other {
                            "numericEdit" => {
                                self.report.fields.numeric =
                                    self.report.fields.numeric.saturating_add(1);
                            }
                            "dateTimeEdit" => {
                                self.report.fields.date = self.report.fields.date.saturating_add(1);
                            }
                            _ => {
                                self.report.fields.text = self.report.fields.text.saturating_add(1)
                            }
                        }
                        let max_len = dom
                            .path(t, &["value", "text"])
                            .and_then(|v| dom.attr(v, "maxChars"))
                            .and_then(|m| m.trim().parse::<u32>().ok())
                            .filter(|m| *m > 0);
                        let comb = ui.and_then(|u| dom.child(u, "comb"));
                        let comb_cells = comb
                            .and_then(|c| dom.attr(c, "numberOfCells"))
                            .and_then(|m| m.trim().parse::<u32>().ok())
                            .filter(|m| *m > 0);
                        WKind::Text {
                            multiline: ui.and_then(|u| dom.attr(u, "multiLine")) == Some("1"),
                            max_len: comb_cells.or(max_len),
                            comb: comb_cells.is_some(),
                            password: other == "passwordEdit",
                        }
                    }
                };
                let shown = match (&kind, &value) {
                    (WKind::Choice { options, .. }, Some(v)) => options
                        .iter()
                        .find(|(s, _)| s == v)
                        .map(|(_, d)| d.clone())
                        .or_else(|| Some(v.clone())),
                    (WKind::Signature, _) => None,
                    (WKind::Text { password: true, .. }, _) => None,
                    (_, v) => v.clone(),
                };
                let (ix, iy) = (wx + ui_margin.left, wy + ui_margin.top);
                let (iw, ih) = ((ww - ui_margin.h()).max(0.0), (wh - ui_margin.v()).max(0.0));
                let appearance = shown.filter(|s| !s.is_empty()).map(|s| {
                    let multiline = matches!(
                        kind,
                        WKind::Text {
                            multiline: true,
                            ..
                        }
                    );
                    let block = self.text_block(&Rich::plain(&s, &font, &para), iw, multiline);
                    let dy = valign(para.v, ih, block.height);
                    (ix - wx, iy - wy + dy, block)
                });
                let stored = match (&kind, &value) {
                    (WKind::Signature, _) => None,
                    (_, v) => v.clone(),
                };
                out.marks.push(Mark::Widget(Box::new(Widget {
                    x: wx,
                    y: wy,
                    w: ww,
                    h: wh,
                    path: path.to_vec(),
                    kind,
                    value: stored,
                    tooltip,
                    font_size: font.size,
                    appearance,
                })));
            }
        }
        out
    }

    /// A draw: text, a line, a rectangle, an arc or an image.
    fn draw(&mut self, n: &FNode, force_w: Option<f64>, force_h: Option<f64>) -> LBox {
        let dom = self.dom;
        let t = n.tpl;
        self.report.draws = self.report.draws.saturating_add(1);
        let g = geom(dom, t);
        let font = self.font_of(t, &Font::default());
        let para = self.para_of(t, &Para::default());
        let margin = Margin::of(dom, t);
        let c = content(dom, t);
        let fixed_w = force_w.or(g.w);
        let fixed_h = force_h.or(g.h);
        let rich = self.rich_of(&c, &font, &para);
        let (w, h, block) = match &rich {
            Some(r) => {
                let wrap_w = fixed_w.map(|w| (w - margin.h()).max(0.0));
                let block = self.text_block(r, wrap_w.unwrap_or(0.0), wrap_w.is_some());
                let w =
                    fixed_w.unwrap_or_else(|| clamp(block.width + margin.h(), g.min_w, g.max_w));
                let h =
                    fixed_h.unwrap_or_else(|| clamp(block.height + margin.v(), g.min_h, g.max_h));
                // Unwrapped text laid out at width 0 must be aligned again in its box.
                let block = if wrap_w.is_none() {
                    self.text_block(r, (w - margin.h()).max(0.0), false)
                } else {
                    block
                };
                (w, h, Some(block))
            }
            None => (fixed_w.unwrap_or(g.min_w), fixed_h.unwrap_or(g.min_h), None),
        };
        let mut out = LBox {
            w,
            h,
            ..LBox::default()
        };
        if let Some(b) = dom.child(t, "border").map(|b| props::border(dom, b)) {
            push_frame(&mut out.marks, 0.0, 0.0, w, h, &b);
        }
        let (cx, cy) = (margin.left, margin.top);
        let (cw, ch) = ((w - margin.h()).max(0.0), (h - margin.v()).max(0.0));
        match c {
            Content::Text(_) | Content::Rich(_) => {
                if let Some(block) = block {
                    let dy = valign(para.v, ch, block.height);
                    out.marks.push(Mark::Text {
                        x: cx,
                        y: cy + dy,
                        block,
                    });
                }
            }
            Content::Rect(r) => {
                let b = props::border(dom, r);
                push_frame(&mut out.marks, cx, cy, cw, ch, &b);
            }
            Content::Line(l) => {
                let e = dom
                    .child(l, "edge")
                    .map_or_else(Edge::default, |e| props::edge(dom, e));
                if e.visible {
                    let (x1, y1, x2, y2) = if dom.attr(l, "slope") == Some("/") {
                        (cx, cy + ch, cx + cw, cy)
                    } else {
                        (cx, cy, cx + cw, cy + ch)
                    };
                    out.marks.push(Mark::Line {
                        x1,
                        y1,
                        x2,
                        y2,
                        edge: e,
                    });
                }
            }
            Content::Arc(a) => {
                let e = dom
                    .child(a, "edge")
                    .map_or_else(Edge::default, |e| props::edge(dom, e));
                let fill = dom.child(a, "fill").and_then(|f| props::fill_color(dom, f));
                let num = |k: &str, d: f64| {
                    dom.attr(a, k)
                        .and_then(|v| v.trim().parse::<f64>().ok())
                        .filter(|v| v.is_finite())
                        .unwrap_or(d)
                };
                let circular = dom.attr(a, "circular") == Some("1");
                let (mut aw, mut ah) = (cw, ch);
                if circular {
                    let d = aw.min(ah);
                    aw = d;
                    ah = d;
                }
                out.marks.push(Mark::Arc {
                    x: cx + (cw - aw) / 2.0,
                    y: cy + (ch - ah) / 2.0,
                    w: aw,
                    h: ah,
                    start: num("startAngle", 0.0),
                    sweep: num("sweepAngle", 360.0).clamp(-360.0, 360.0),
                    edge: e,
                    fill,
                });
            }
            Content::Image(i) => self.image(&mut out, i, (cx, cy, cw, ch)),
            Content::None => {}
        }
        out
    }

    fn image(&mut self, out: &mut LBox, i: NodeId, (cx, cy, cw, ch): (f64, f64, f64, f64)) {
        let dom = self.dom;
        let text = dom.text(i);
        let parsed = if text.trim().is_empty() {
            None
        } else {
            image::base64(&text, self.limits.max_image_bytes)
                .and_then(|b| image::parse(&b, self.limits.max_image_side))
        };
        let Some(img) = parsed else {
            self.report.images_skipped = self.report.images_skipped.saturating_add(1);
            return;
        };
        let (iw, ih) = (f64::from(img.width), f64::from(img.height));
        // Pixels at 72 dpi for `actual`; otherwise fit the box.
        let (dw, dh) = match dom.attr(i, "aspect").unwrap_or("fit") {
            "none" => (cw, ch),
            "actual" => (iw * 0.75, ih * 0.75),
            "width" => (cw, cw * ih / iw),
            "height" => (ch * iw / ih, ch),
            _ => {
                let k = (cw / iw).min(ch / ih);
                (iw * k, ih * k)
            }
        };
        if !(dw.is_finite() && dh.is_finite()) || dw <= 0.0 || dh <= 0.0 {
            self.report.images_skipped = self.report.images_skipped.saturating_add(1);
            return;
        }
        self.report.images = self.report.images.saturating_add(1);
        let index = self.images.len();
        self.images.push(img);
        out.marks.push(Mark::Image {
            x: cx + (cw - dw) / 2.0,
            y: cy + (ch - dh) / 2.0,
            w: dw,
            h: dh,
            index,
        });
    }
}

fn valign(v: VAlign, room: f64, used: f64) -> f64 {
    match v {
        VAlign::Top => 0.0,
        VAlign::Middle => (room - used) / 2.0,
        VAlign::Bottom => room - used,
    }
}

fn push_frame(marks: &mut Vec<Mark>, x: f64, y: f64, w: f64, h: f64, b: &Border) {
    push_frame_shape(marks, x, y, w, h, b, false);
}

fn push_frame_shape(
    marks: &mut Vec<Mark>,
    x: f64,
    y: f64,
    w: f64,
    h: f64,
    b: &Border,
    round: bool,
) {
    if !b.paints {
        return;
    }
    if round {
        let e = b.edges.first().copied().unwrap_or_default();
        marks.push(Mark::Arc {
            x,
            y,
            w,
            h,
            start: 0.0,
            sweep: 360.0,
            edge: e,
            fill: b.fill,
        });
        return;
    }
    if let Some(color) = b.fill {
        marks.push(Mark::Fill {
            x,
            y,
            w,
            h,
            color,
            radius: b.radius,
        });
    }
    if b.edges.iter().any(|e| e.visible && e.thickness > 0.0) {
        marks.push(Mark::Frame {
            x,
            y,
            w,
            h,
            border: *b,
        });
    }
}

/// Where a rotated child's box sits relative to its anchor (`x`, `y`) in positioned
/// layout: rotation turns the object about its anchor.
fn rotation_offset(dom: &Dom, c: &FNode, kb: &LBox) -> Option<(f64, f64)> {
    let angle = dom
        .attr(c.tpl, "rotate")?
        .trim()
        .parse::<i32>()
        .ok()?
        .rem_euclid(360);
    // `kb` is already turned: its w and h are the turned extent.
    match angle {
        90 => Some((0.0, -kb.h)),
        180 => Some((-kb.w, -kb.h)),
        270 => Some((-kb.w, 0.0)),
        _ => None,
    }
}

/// Turn a laid-out object `angle` degrees counter-clockwise.
fn rotate(b: LBox, angle: i32) -> LBox {
    let (w, h) = (b.w, b.h);
    let (nw, nh, ox, oy) = match angle {
        90 => (h, w, 0.0, w),
        180 => (w, h, w, h),
        _ => (h, w, h, 0.0),
    };
    let (s, c) = match angle {
        90 => (1.0, 0.0),
        180 => (0.0, -1.0),
        _ => (-1.0, 0.0),
    };
    let map = |u: f64, v: f64| (ox + u * c + v * s, oy - u * s + v * c);
    let mut outer = Vec::new();
    let mut inner = Vec::new();
    for m in b.marks {
        match m {
            Mark::Widget(mut wd) => {
                let (x1, y1) = map(wd.x, wd.y);
                let (x2, y2) = map(wd.x + wd.w, wd.y + wd.h);
                wd.x = x1.min(x2);
                wd.y = y1.min(y2);
                wd.w = (x2 - x1).abs();
                wd.h = (y2 - y1).abs();
                // The appearance of a turned widget is not turned (`/MK /R` is not
                // written): it is dropped and the viewer draws the value.
                wd.appearance = None;
                outer.push(Mark::Widget(wd));
            }
            other => inner.push(other),
        }
    }
    let mut marks = vec![Mark::Rotated {
        ox,
        oy,
        angle,
        marks: inner,
    }];
    marks.extend(outer);
    LBox {
        w: nw,
        h: nh,
        marks,
        ..LBox::default()
    }
}

/// A page area: its size, content areas, and its own content laid out once.
struct PageArea {
    name: String,
    id: String,
    w: f64,
    h: f64,
    areas: Vec<(f64, f64, f64, f64)>,
    max: Option<usize>,
    node: NodeId,
}

fn page_areas(dom: &Dom, page_set: NodeId, out: &mut Vec<PageArea>) {
    for pa in dom.elements(page_set) {
        match dom.name(pa) {
            "pageArea" => {
                let (mut w, mut h) = (612.0, 792.0);
                if let Some(m) = dom.child(pa, "medium") {
                    let short = attr_len(dom, m, "short").unwrap_or(612.0);
                    let long = attr_len(dom, m, "long").unwrap_or(792.0);
                    if dom.attr(m, "orientation") == Some("landscape") {
                        (w, h) = (long, short);
                    } else {
                        (w, h) = (short, long);
                    }
                }
                let areas = dom
                    .children_named(pa, "contentArea")
                    .map(|ca| {
                        let l = |n: &str| attr_len(dom, ca, n);
                        (
                            l("x").unwrap_or(0.0),
                            l("y").unwrap_or(0.0),
                            l("w").unwrap_or(w).max(1.0),
                            l("h").unwrap_or(h).max(1.0),
                        )
                    })
                    .collect::<Vec<_>>();
                let max = dom.child(pa, "occur").and_then(|_| {
                    let (_, max, _) = occur(dom, pa);
                    max
                });
                out.push(PageArea {
                    name: dom.attr(pa, "name").unwrap_or("").to_owned(),
                    id: dom.attr(pa, "id").unwrap_or("").to_owned(),
                    w: w.max(1.0),
                    h: h.max(1.0),
                    areas: if areas.is_empty() {
                        vec![(0.0, 0.0, w, h)]
                    } else {
                        areas
                    },
                    max,
                    node: pa,
                });
            }
            "pageSet" => page_areas(dom, pa, out),
            _ => {}
        }
    }
}

struct Pager<'p> {
    areas: &'p [PageArea],
    pages: Vec<(usize, Page)>,
    used: Vec<usize>,
    cur_area: usize,
    ca: usize,
    y: f64,
    /// The page area the next page takes.
    next_pa: usize,
    started: bool,
    max_pages: usize,
    overflowed: usize,
    overflow_targets: Vec<String>,
    open: Vec<OpenFrame>,
}

impl Pager<'_> {
    fn find(&self, target: &str) -> Option<usize> {
        self.areas
            .iter()
            .position(|a| a.name == target || a.id == target)
    }

    fn content_area(&self) -> (f64, f64, f64, f64) {
        self.areas
            .get(self.cur_area)
            .and_then(|a| a.areas.get(self.ca).copied())
            .unwrap_or((0.0, 0.0, 612.0, 792.0))
    }

    fn new_page(&mut self, pa: usize) -> Result<(), XfaError> {
        if self.pages.len() >= self.max_pages {
            return Err(XfaError::TooManyPages {
                limit: self.max_pages,
            });
        }
        let pa = pa.min(self.areas.len().saturating_sub(1));
        let (w, h) = self.areas.get(pa).map_or((612.0, 792.0), |a| (a.w, a.h));
        self.pages.push((
            pa,
            Page {
                w,
                h,
                marks: Vec::new(),
            },
        ));
        if let Some(u) = self.used.get_mut(pa) {
            *u = u.saturating_add(1);
        }
        self.cur_area = pa;
        self.ca = 0;
        self.y = 0.0;
        self.started = true;
        Ok(())
    }

    fn ensure(&mut self) -> Result<(), XfaError> {
        if !self.started {
            self.new_page(self.next_pa)?;
        }
        Ok(())
    }

    /// The page area that continues the current one when content overflows.
    fn continuation(&self) -> usize {
        if let Some(t) = self.overflow_targets.last()
            && let Some(i) = self.find(t)
        {
            return i;
        }
        let cur = self.cur_area;
        let full = self
            .areas
            .get(cur)
            .and_then(|a| a.max)
            .is_some_and(|m| self.used.get(cur).copied().unwrap_or(0) >= m);
        if full && cur.saturating_add(1) < self.areas.len() {
            cur.saturating_add(1)
        } else {
            cur
        }
    }

    /// Move to the next content area, or a new page. The frames of boxes being split
    /// close on the area left and open again at the top of the next.
    fn advance(&mut self) -> Result<(), XfaError> {
        self.ensure()?;
        self.close_frames();
        let n = self.areas.get(self.cur_area).map_or(1, |a| a.areas.len());
        if self.ca.saturating_add(1) < n {
            self.ca = self.ca.saturating_add(1);
            self.y = 0.0;
        } else {
            let next = self.continuation();
            self.new_page(next)?;
        }
        let at = self.pages.last().map_or(0, |(_, p)| p.marks.len());
        for f in &mut self.open {
            f.top = self.y;
            f.at = at;
        }
        Ok(())
    }

    /// Draw each open frame from its top to here, behind what it holds.
    fn close_frames(&mut self) {
        let (cx, cy, _, _) = self.content_area();
        let y = self.y;
        let Some((_, page)) = self.pages.last_mut() else {
            return;
        };
        // Innermost first, so an outer frame inserted at the same place lands before it.
        for f in self.open.iter().rev() {
            let mut ms = Vec::new();
            push_frame(
                &mut ms,
                cx + f.x,
                cy + f.top,
                f.w,
                (y - f.top).max(0.0),
                &f.border,
            );
            let at = f.at.min(page.marks.len());
            page.marks.splice(at..at, ms);
        }
    }

    fn fresh(&self) -> bool {
        !self.started || (self.y <= EPS && self.ca == 0)
    }

    fn apply_break(&mut self, b: &Brk) -> Result<(), XfaError> {
        if b.page {
            let target = b.target.as_deref().and_then(|t| self.find(t));
            if !self.started {
                if let Some(t) = target {
                    self.next_pa = t;
                }
                return self.ensure();
            }
            let same = target.is_none_or(|t| t == self.cur_area);
            if self.fresh() && same && !b.start_new {
                return Ok(());
            }
            if self.fresh()
                && !same
                && self.open.is_empty()
                && self.pages.last().is_some_and(|(_, p)| p.marks.is_empty())
            {
                // Nothing on this page yet: it becomes the target page area.
                self.pages.pop();
                if let Some(u) = self.used.get_mut(self.cur_area) {
                    *u = u.saturating_sub(1);
                }
                return self.new_page(target.unwrap_or(self.cur_area));
            }
            match target {
                Some(t) => {
                    // A page break inside a split box ends its frame here.
                    self.close_frames();
                    self.new_page(t)?;
                    let at = self.pages.last().map_or(0, |(_, p)| p.marks.len());
                    for f in &mut self.open {
                        f.top = 0.0;
                        f.at = at;
                    }
                    Ok(())
                }
                None => {
                    // To the next page, wherever the content area is.
                    self.advance()?;
                    while self.ca != 0 {
                        self.advance()?;
                    }
                    Ok(())
                }
            }
        } else {
            self.ensure()?;
            if self.fresh() && !b.start_new {
                return Ok(());
            }
            self.advance()
        }
    }

    fn emit(&mut self, b: &LBox, px: f64, py: f64) {
        let Some((_, page)) = self.pages.last_mut() else {
            return;
        };
        emit_box(&mut page.marks, b, px, py);
    }

    /// Flow one box into the current content area: its break before, the box (moved
    /// on or split when it does not fit), its break after.
    fn flow(&mut self, b: &LBox, x: f64) -> Result<(), XfaError> {
        if let Some(br) = &b.before {
            self.apply_break(br)?;
        }
        self.ensure()?;
        let pushed = b.overflow.is_some();
        if let Some(t) = &b.overflow {
            self.overflow_targets.push(t.clone());
        }
        self.place(b, x)?;
        if pushed {
            self.overflow_targets.pop();
        }
        if let Some(br) = &b.after {
            self.apply_break(br)?;
        }
        Ok(())
    }

    fn place(&mut self, b: &LBox, x: f64) -> Result<(), XfaError> {
        loop {
            let (cx, cy, _, chh) = self.content_area();
            let room = chh - self.y;
            if b.h <= room + EPS {
                self.emit(b, cx + x, cy + self.y);
                self.y += b.h;
                return Ok(());
            }
            if !b.rows.is_empty() {
                return self.split(b, x);
            }
            if self.fresh() {
                // Larger than a whole content area and unsplittable: placed
                // overflowing it.
                self.overflowed = self.overflowed.saturating_add(1);
                self.emit(b, cx + x, cy + self.y);
                self.y += b.h;
                return Ok(());
            }
            self.advance()?;
        }
    }

    /// Place a splittable box row by row; a row of one child flows as that child
    /// (its breaks apply and it splits in turn).
    fn split(&mut self, b: &LBox, x: f64) -> Result<(), XfaError> {
        if b.rows.first().is_some_and(|r| r.2.len() != 1) {
            self.ensure()?;
        }
        if let Some(border) = b.frame {
            let at = self.pages.last().map_or(0, |(_, p)| p.marks.len());
            self.open.push(OpenFrame {
                x,
                w: b.w,
                border,
                top: self.y,
                at,
            });
        }
        self.y += b.inset_top;
        for (row_y, row_h, idx) in &b.rows {
            if let [only] = idx.as_slice()
                && let Some((kx, ky, kb)) = b.kids.get(*only)
            {
                let dy = (ky - row_y).max(0.0);
                self.y += dy;
                self.flow(kb, x + kx)?;
                self.y += (row_h - dy - kb.h).max(0.0);
                continue;
            }
            loop {
                let (cx, cy, _, chh) = self.content_area();
                let room = chh - self.y;
                if *row_h <= room + EPS || self.fresh() {
                    if *row_h > room + EPS {
                        self.overflowed = self.overflowed.saturating_add(1);
                    }
                    let base = cy + self.y - row_y;
                    for i in idx {
                        if let Some((kx, ky, kb)) = b.kids.get(*i) {
                            self.emit(kb, cx + x + kx, base + ky);
                        }
                    }
                    self.y += row_h;
                    break;
                }
                self.advance()?;
            }
        }
        self.y += b.inset_bottom;
        if b.frame.is_some() {
            let (cx, cy, _, _) = self.content_area();
            if let Some(f) = self.open.pop() {
                let y = self.y;
                if let Some((_, page)) = self.pages.last_mut() {
                    let mut ms = Vec::new();
                    push_frame(
                        &mut ms,
                        cx + f.x,
                        cy + f.top,
                        f.w,
                        (y - f.top).max(0.0),
                        &f.border,
                    );
                    let at = f.at.min(page.marks.len());
                    page.marks.splice(at..at, ms);
                }
            }
        }
        Ok(())
    }
}

/// The frame of a box being split, drawn per fragment.
#[derive(Debug, Clone, Copy)]
struct OpenFrame {
    x: f64,
    w: f64,
    border: Border,
    top: f64,
    at: usize,
}

/// Emit a box's marks and its children's at (`px`, `py`).
fn emit_box(out: &mut Vec<Mark>, b: &LBox, px: f64, py: f64) {
    // Iterative: boxes nest as deep as the template.
    let mut stack: Vec<(&LBox, f64, f64)> = vec![(b, px, py)];
    while let Some((bx, x, y)) = stack.pop() {
        if let Some(fr) = &bx.frame {
            push_frame(out, x, y, bx.w, bx.h, fr);
        }
        for m in &bx.marks {
            let mut m = m.clone();
            translate(&mut m, x, y);
            out.push(m);
        }
        for (kx, ky, kb) in bx.kids.iter().rev() {
            stack.push((kb, x + kx, y + ky));
        }
    }
}

/// The template's root subform and the data's root element: packets are the XDP
/// root's children (or the document's own root when it is a bare template).
fn packets(dom: &Dom) -> Option<(NodeId, Option<NodeId>)> {
    let top = dom.elements(0).next()?;
    let template = if dom.name(top) == "template" {
        Some(top)
    } else {
        dom.children_named(top, "template")
            .find(|t| dom.child(*t, "subform").is_some())
    }?;
    let root = dom.child(template, "subform")?;
    let data_root = dom
        .children_named(top, "datasets")
        .next()
        .and_then(|d| dom.child(d, "data"))
        .and_then(|d| dom.elements(d).next());
    Some((root, data_root))
}

/// Lay out the form in `dom` (an XDP document).
pub(crate) fn run(
    dom: &Dom,
    fonts: &mut Fonts<'_>,
    limits: &XfaLimits,
    cancel: &dyn Fn() -> bool,
) -> Result<Doc, XfaError> {
    let (root, data_root) = packets(dom).ok_or(XfaError::NoTemplate)?;
    let mut merge = Merge::new(dom, Some(dom), data_root, limits.max_form_nodes, cancel);
    let children = merge.children(root, data_root)?;
    let form = FNode {
        tpl: root,
        kind: Kind::Subform,
        name: dom.attr(root, "name").unwrap_or("").to_owned(),
        children,
        value: None,
    };
    let mut areas = Vec::new();
    for ps in dom.children_named(root, "pageSet") {
        page_areas(dom, ps, &mut areas);
    }
    if areas.is_empty() {
        areas.push(PageArea {
            name: String::new(),
            id: String::new(),
            w: 612.0,
            h: 792.0,
            areas: vec![(0.0, 0.0, 612.0, 792.0)],
            max: None,
            node: root,
        });
    }
    let mut ctx = Ctx {
        dom,
        fonts,
        limits,
        cancel,
        report: XfaReport::default(),
        images: Vec::new(),
        items: merge.nodes,
    };
    let root_seg = format!(
        "{}[0]",
        if form.name.is_empty() {
            "#subform"
        } else {
            &form.name
        }
    );
    let root_box = ctx.container(&form, std::slice::from_ref(&root_seg), None, None)?;
    let mut pager = Pager {
        areas: &areas,
        pages: Vec::new(),
        used: vec![0; areas.len()],
        cur_area: 0,
        ca: 0,
        y: 0.0,
        next_pa: 0,
        started: false,
        max_pages: limits.max_pages,
        overflowed: 0,
        overflow_targets: Vec::new(),
        open: Vec::new(),
    };
    let root_layout = dom.attr(root, "layout").unwrap_or("position");
    if root_layout == "position" {
        pager.ensure()?;
        let (cx, cy, _, _) = pager.content_area();
        for (kx, ky, kb) in &root_box.kids {
            pager.emit(kb, cx + kx, cy + ky);
        }
    } else {
        if (cancel)() {
            return Err(XfaError::Cancelled);
        }
        if root_box.rows.is_empty() {
            for (kx, _, kb) in &root_box.kids {
                pager.flow(kb, *kx)?;
            }
        } else {
            pager.split(&root_box, 0.0)?;
        }
    }
    pager.ensure()?;
    // Each page's own page-area content, behind the flowed content.
    let mut pages = Vec::new();
    let mut per_area: BTreeMap<usize, usize> = BTreeMap::new();
    let page_list = std::mem::take(&mut pager.pages);
    for (pa, mut page) in page_list {
        let Some(area) = areas.get(pa) else {
            pages.push(page);
            continue;
        };
        let nth = per_area.entry(pa).or_insert(0);
        let seg = format!(
            "{}[{}]",
            if area.name.is_empty() {
                "#pageArea"
            } else {
                &area.name
            },
            nth
        );
        *nth = nth.saturating_add(1);
        let page_path = vec![root_seg.clone(), "#pageSet[0]".to_owned(), seg];
        let master = merge_master(dom, area.node, cancel, limits)?;
        let mut master_box = LBox::default();
        let names = names_for(&master);
        for (i, c) in master.iter().enumerate() {
            let mut p = page_path.clone();
            if let Some(s) = names.get(i) {
                p.push(s.clone());
            }
            if let Some(kb) = ctx.node(c, &p, None, None)? {
                let cg = geom(dom, c.tpl);
                let mut kx = cg.x - cg.anchor.0 * kb.w;
                let mut ky = cg.y - cg.anchor.1 * kb.h;
                if let Some((dx, dy)) = rotation_offset(dom, c, &kb) {
                    kx += dx;
                    ky += dy;
                }
                master_box.kids.push((kx, ky, kb));
            }
        }
        let mut marks = Vec::new();
        emit_box(&mut marks, &master_box, 0.0, 0.0);
        marks.append(&mut page.marks);
        page.marks = marks;
        pages.push(page);
    }
    let mut report = ctx.report;
    report.pages = pages.len();
    report.widgets = pages
        .iter()
        .flat_map(|p| &p.marks)
        .filter(|m| matches!(m, Mark::Widget(_)))
        .count();
    report.overflowed = pager.overflowed;
    report.unsupported = count_unsupported(dom, root);
    let images = ctx.images;
    Ok(Doc {
        pages,
        images,
        report,
    })
}

/// A page area's own containers, merged without data (they bind nothing in practice;
/// `match="global"` fields still find their value).
fn merge_master(
    dom: &Dom,
    area: NodeId,
    cancel: &dyn Fn() -> bool,
    limits: &XfaLimits,
) -> Result<Vec<FNode>, XfaError> {
    let data_root = packets(dom).and_then(|(_, d)| d);
    let mut m = Merge::new(dom, Some(dom), data_root, limits.max_form_nodes, cancel);
    m.children(area, None)
}

/// Template elements layout does not handle and that would have drawn something.
fn count_unsupported(dom: &Dom, root: NodeId) -> usize {
    let mut n = 0usize;
    let mut stack = vec![root];
    while let Some(id) = stack.pop() {
        // Barcodes are not drawn; prototypes referenced by `use`/`usehref` are not
        // applied.
        if dom.name(id) == "barcode"
            || dom.attr(id, "use").is_some()
            || dom.attr(id, "usehref").is_some()
        {
            n = n.saturating_add(1);
        }
        stack.extend(dom.elements(id));
    }
    n
}

#[cfg(all(test, feature = "bundled-fonts"))]
mod tests {
    // Test code: a panic is the failure report (CLAUDE.md).
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
    use super::*;
    use crate::fonts::Faces;
    use crate::xml::{XmlLimits, parse};

    const LIM: XmlLimits = XmlLimits {
        max_depth: 128,
        max_nodes: 100_000,
        max_attributes: 64,
    };

    fn doc(template_body: &str, data: &str) -> Doc {
        let xdp = format!(
            r#"<xdp:xdp xmlns:xdp="http://ns.adobe.com/xdp/"><template xmlns="http://www.xfa.org/schema/xfa-template/3.3/">{template_body}</template><xfa:datasets xmlns:xfa="http://www.xfa.org/schema/xfa-data/1.0/"><xfa:data>{data}</xfa:data></xfa:datasets></xdp:xdp>"#
        );
        let dom = parse(xdp.as_bytes(), LIM, &|| false).unwrap();
        let set = Faces::bundled();
        let mut fonts = Fonts::new(&set).unwrap();
        run(&dom, &mut fonts, &XfaLimits::default(), &|| false).unwrap()
    }

    const PAGESET: &str = r#"<pageSet><pageArea name="P1"><contentArea x="0.5in" y="0.5in" w="7.5in" h="10in"/><medium short="8.5in" long="11in"/></pageArea><pageArea name="P2"><contentArea x="1in" y="1in" w="6.5in" h="9in"/><medium short="8.5in" long="11in" orientation="landscape"/></pageArea></pageSet>"#;

    fn widgets(p: &Page) -> Vec<&Widget> {
        p.marks
            .iter()
            .filter_map(|m| match m {
                Mark::Widget(w) => Some(&**w),
                _ => None,
            })
            .collect()
    }

    fn texts(p: &Page) -> Vec<(f64, f64)> {
        p.marks
            .iter()
            .filter_map(|m| match m {
                Mark::Text { x, y, .. } => Some((*x, *y)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn positioned_children_sit_at_their_coordinates_in_the_content_area() {
        let d = doc(
            &format!(
                r#"<subform name="f" layout="position">{PAGESET}<field name="a" x="1in" y="2in" w="2in" h="0.25in"><ui><textEdit/></ui></field><field name="b" x="3in" y="2in" w="1in" h="1in" anchorType="bottomRight"><ui><textEdit/></ui></field></subform>"#
            ),
            "<f/>",
        );
        assert_eq!(d.pages.len(), 1);
        let w = widgets(&d.pages[0]);
        assert_eq!(w.len(), 2);
        assert!((w[0].x - 108.0).abs() < 1e-6 && (w[0].y - 180.0).abs() < 1e-6);
        assert!((w[1].x - (36.0 + 216.0 - 72.0)).abs() < 1e-6);
        assert!((w[1].y - (36.0 + 144.0 - 72.0)).abs() < 1e-6);
        assert_eq!(w[0].path, vec!["f[0]", "a[0]"]);
    }

    #[test]
    fn tb_stacks_and_lr_tb_wraps() {
        let d = doc(
            &format!(
                r#"<subform name="f" layout="tb">{PAGESET}<subform name="s" layout="lr-tb" w="3in"><field name="a" w="2in" h="0.5in"/><field name="b" w="2in" h="0.25in"/><field name="c" w="1in" h="0.25in"/></subform><field name="d" w="1in" h="0.5in"/></subform>"#
            ),
            "<f/>",
        );
        let w = widgets(&d.pages[0]);
        let pos: Vec<(f64, f64)> = w.iter().map(|w| (w.x, w.y)).collect();
        // a at the top-left; b wraps under a; c fits beside b; d below the subform.
        assert_eq!(pos[0], (36.0, 36.0));
        assert_eq!(pos[1], (36.0, 72.0));
        assert_eq!(pos[2], (36.0 + 144.0, 72.0));
        assert_eq!(pos[3], (36.0, 90.0));
    }

    #[test]
    fn rl_tb_fills_from_the_right() {
        let d = doc(
            &format!(
                r#"<subform name="f" layout="tb">{PAGESET}<subform layout="rl-tb" w="3in"><field name="a" w="1in" h="0.5in"/><field name="b" w="1in" h="0.5in"/></subform></subform>"#
            ),
            "<f/>",
        );
        let w = widgets(&d.pages[0]);
        assert!((w[0].x - (36.0 + 144.0)).abs() < 1e-6);
        assert!((w[1].x - (36.0 + 72.0)).abs() < 1e-6);
    }

    #[test]
    fn growable_subforms_take_their_content_height_within_min_h() {
        let d = doc(
            &format!(
                r#"<subform name="f" layout="tb">{PAGESET}<subform name="s" layout="tb" w="3in" minH="2in"><field name="a" w="1in" h="0.5in"/></subform><field name="b" w="1in" h="0.5in"/><subform name="t" layout="tb" w="3in" minH="0.1in"><field name="c" w="1in" h="0.5in"/></subform><field name="d" w="1in" h="0.5in"/></subform>"#
            ),
            "<f/>",
        );
        let w = widgets(&d.pages[0]);
        assert!((w[1].y - (36.0 + 144.0)).abs() < 1e-6);
        assert!((w[3].y - (36.0 + 144.0 + 36.0 + 36.0)).abs() < 1e-6);
    }

    #[test]
    fn content_flows_to_new_pages_and_splits_between_rows() {
        let rows = r#"<field name="r" w="1in" h="1in"/>"#.repeat(25);
        let d = doc(
            &format!(
                r#"<subform name="f" layout="tb">{PAGESET}<subform name="s" layout="tb" w="3in">{rows}</subform></subform>"#
            ),
            "<f/>",
        );
        // 10in content area: 10 rows a page.
        assert_eq!(d.pages.len(), 3);
        assert_eq!(widgets(&d.pages[0]).len(), 10);
        assert_eq!(widgets(&d.pages[2]).len(), 5);
        let w = widgets(&d.pages[1]);
        assert!((w[0].y - 36.0).abs() < 1e-6);
        // Names continue across pages.
        assert_eq!(w[0].path.last().unwrap(), "r[10]");
    }

    #[test]
    fn a_kept_subform_moves_whole_to_the_next_page() {
        let d = doc(
            &format!(
                r#"<subform name="f" layout="tb">{PAGESET}<field name="a" w="1in" h="9in"/><subform name="k" layout="tb" w="3in"><keep intact="contentArea"/><field name="b" w="1in" h="0.6in"/><field name="c" w="1in" h="0.6in"/></subform></subform>"#
            ),
            "<f/>",
        );
        assert_eq!(d.pages.len(), 2);
        assert_eq!(widgets(&d.pages[1]).len(), 2);
    }

    #[test]
    fn break_before_selects_the_page_area() {
        let d = doc(
            &format!(
                r#"<subform name="f" layout="tb">{PAGESET}<subform name="p1" layout="tb" w="3in"><field name="a" w="1in" h="1in"/></subform><subform name="p2" layout="tb" w="3in"><breakBefore targetType="pageArea" target="P2"/><field name="b" w="1in" h="1in"/></subform></subform>"#
            ),
            "<f/>",
        );
        assert_eq!(d.pages.len(), 2);
        // P2 is landscape with its content area at 1in.
        assert!((d.pages[1].w - 792.0).abs() < 1e-6);
        let w = widgets(&d.pages[1]);
        assert!((w[0].x - 72.0).abs() < 1e-6 && (w[0].y - 72.0).abs() < 1e-6);
    }

    #[test]
    fn a_first_break_chooses_the_first_page_area_without_a_blank_page() {
        let d = doc(
            &format!(
                r#"<subform name="f" layout="tb">{PAGESET}<subform name="p" layout="tb" w="3in"><breakBefore targetType="pageArea" target="P2"/><field name="b" w="1in" h="1in"/></subform></subform>"#
            ),
            "<f/>",
        );
        assert_eq!(d.pages.len(), 1);
        assert!((d.pages[0].w - 792.0).abs() < 1e-6);
    }

    #[test]
    fn overflow_continues_on_the_target_page_area() {
        let rows = r#"<field name="r" w="1in" h="1in"/>"#.repeat(12);
        let d = doc(
            &format!(
                r#"<subform name="f" layout="tb">{PAGESET}<subform name="s" layout="tb" w="3in"><overflow target="P2"/>{rows}</subform></subform>"#
            ),
            "<f/>",
        );
        assert_eq!(d.pages.len(), 2);
        assert!((d.pages[1].w - 792.0).abs() < 1e-6);
    }

    #[test]
    fn table_rows_size_cells_to_columns_and_the_tallest_cell() {
        let d = doc(
            &format!(
                r#"<subform name="f" layout="tb">{PAGESET}<subform name="t" layout="table" columnWidths="1in 2in 1in"><subform name="row" layout="row"><field name="a" h="0.25in"/><field name="b" h="0.75in"/><field name="c" h="0.25in"/></subform><subform name="row" layout="row"><field name="d" colSpan="2" h="0.25in"/><field name="e" h="0.25in"/></subform></subform></subform>"#
            ),
            "<f/>",
        );
        let w = widgets(&d.pages[0]);
        assert!((w[1].x - 108.0).abs() < 1e-6);
        assert!((w[1].w - 144.0).abs() < 1e-6);
        // Row one is as tall as its tallest cell.
        assert!((w[0].h - 54.0).abs() < 1e-6);
        // Row two starts below it; d spans two columns.
        assert!((w[3].y - (36.0 + 54.0)).abs() < 1e-6);
        assert!((w[3].w - 216.0).abs() < 1e-6);
        assert!((w[4].x - (36.0 + 216.0)).abs() < 1e-6);
    }

    #[test]
    fn captions_take_their_reserve_and_the_widget_the_rest() {
        let d = doc(
            &format!(
                r#"<subform name="f" layout="position">{PAGESET}<field name="a" w="3in" h="0.5in"><caption reserve="1in"><value><text>Name</text></value></caption></field><field name="b" y="1in" w="3in" h="0.5in"><caption placement="top" reserve="0.25in"><value><text>Top</text></value></caption></field><field name="c" y="2in" w="3in" h="0.5in"><ui><checkButton size="10pt"/></ui><caption placement="right" reserve="2in"><value><text>Tick</text></value></caption></field></subform>"#
            ),
            "<f/>",
        );
        let w = widgets(&d.pages[0]);
        assert!((w[0].x - (36.0 + 72.0)).abs() < 1e-6 && (w[0].w - 144.0).abs() < 1e-6);
        assert!((w[1].y - (36.0 + 72.0 + 18.0)).abs() < 1e-6 && (w[1].h - 18.0).abs() < 1e-6);
        assert!(matches!(w[2].kind, WKind::Check { .. }));
        assert!((w[2].w - 10.0).abs() < 1e-6);
        assert_eq!(texts(&d.pages[0]).len(), 3);
    }

    #[test]
    fn exclusion_groups_make_radio_widgets_of_one_field() {
        let d = doc(
            &format!(
                r#"<subform name="f" layout="tb">{PAGESET}<exclGroup name="g" layout="lr-tb" w="4in"><field name="y" w="1in" h="0.25in"><ui><checkButton shape="round"/></ui><items><text>yes</text></items></field><field name="n" w="1in" h="0.25in"><ui><checkButton shape="round"/></ui><items><text>no</text></items></field></exclGroup></subform>"#
            ),
            "<f><g>no</g></f>",
        );
        let w = widgets(&d.pages[0]);
        assert_eq!(w.len(), 2);
        assert_eq!(w[0].path, w[1].path);
        assert_eq!(w[0].path.last().unwrap(), "g[0]");
        match (&w[0].kind, &w[1].kind) {
            (
                WKind::Check {
                    on_now: false,
                    radio: true,
                    ..
                },
                WKind::Check {
                    on_now: true, on, ..
                },
            ) => {
                assert_eq!(on, "no");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn hidden_and_screen_only_objects_take_no_space_invisible_ones_do() {
        let d = doc(
            &format!(
                r#"<subform name="f" layout="tb">{PAGESET}<field name="a" w="1in" h="1in" presence="hidden"/><field name="b" w="1in" h="1in" relevant="-print"/><field name="c" w="1in" h="1in" presence="invisible"/><field name="d" w="1in" h="1in"/></subform>"#
            ),
            "<f/>",
        );
        let w = widgets(&d.pages[0]);
        assert_eq!(w.len(), 1);
        assert!((w[0].y - (36.0 + 72.0)).abs() < 1e-6);
        assert_eq!(d.report.screen_only, 1);
    }

    #[test]
    fn page_area_content_is_drawn_on_every_page() {
        let ps = r#"<pageSet><pageArea name="P"><contentArea x="0" y="1in" w="8.5in" h="9in"/><draw name="hdr" x="1in" y="0.25in" w="3in" h="0.5in"><value><text>Header</text></value><font typeface="Arial"/></draw><field name="note" x="5in" y="0.25in" w="2in" h="0.3in"/><medium short="8.5in" long="11in"/></pageArea></pageSet>"#;
        let rows = r#"<field name="r" w="1in" h="1in"/>"#.repeat(12);
        let d = doc(
            &format!(
                r#"<subform name="f" layout="tb">{ps}<subform layout="tb" w="3in">{rows}</subform></subform>"#
            ),
            "<f/>",
        );
        assert_eq!(d.pages.len(), 2);
        for p in &d.pages {
            assert!(
                texts(p)
                    .iter()
                    .any(|(x, y)| (*x - 72.0).abs() < 1e-6 && (*y - 18.0).abs() < 1e-6)
            );
        }
        let w0 = widgets(&d.pages[0]);
        let w1 = widgets(&d.pages[1]);
        assert_eq!(w0[0].path, vec!["f[0]", "#pageSet[0]", "P[0]", "note[0]"]);
        assert_eq!(w1[0].path, vec!["f[0]", "#pageSet[0]", "P[1]", "note[0]"]);
    }

    #[test]
    fn draws_grow_to_their_text_and_rotate() {
        let d = doc(
            &format!(
                r#"<subform name="f" layout="position">{PAGESET}<draw name="t" x="1in" y="1in" w="2in" minH="0.1in"><value><text>one two three four five six seven eight nine ten eleven twelve</text></value><font typeface="Arial" size="10pt"/></draw><draw name="r" x="1in" y="5in" w="2in" h="0.5in" rotate="90"><value><text>Up</text></value><font typeface="Arial"/></draw></subform>"#
            ),
            "<f/>",
        );
        let p = &d.pages[0];
        let block = p.marks.iter().find_map(|m| match m {
            Mark::Text { block, .. } => Some(block),
            _ => None,
        });
        assert!(block.unwrap().lines >= 2);
        assert!(
            p.marks
                .iter()
                .any(|m| matches!(m, Mark::Rotated { angle: 90, .. }))
        );
    }

    #[test]
    fn lines_and_rectangles_are_drawn_in_their_boxes() {
        let d = doc(
            &format!(
                r#"<subform name="f" layout="position">{PAGESET}<draw name="l" x="1in" y="1in" w="2in" h="0"><value><line><edge thickness="1pt"/></line></value></draw><draw name="b" x="1in" y="2in" w="2in" h="1in"><value><rectangle><edge/><fill><color value="200,200,200"/></fill></rectangle></value></draw></subform>"#
            ),
            "<f/>",
        );
        let p = &d.pages[0];
        assert!(p.marks.iter().any(|m| matches!(m, Mark::Line { x1, y1, x2, y2, .. } if (*x1 - 108.0).abs() < 1e-6 && (*y1 - 108.0).abs() < 1e-6 && (*x2 - 252.0).abs() < 1e-6 && (*y2 - 108.0).abs() < 1e-6)));
        assert!(p.marks.iter().any(|m| matches!(m, Mark::Fill { .. })));
        assert!(p.marks.iter().any(|m| matches!(m, Mark::Frame { .. })));
    }

    #[test]
    fn the_page_limit_holds() {
        let rows = r#"<field name="r" w="1in" h="5in"/>"#.repeat(50);
        let xdp = format!(
            r#"<xdp><template><subform name="f" layout="tb">{PAGESET}{rows}</subform></template></xdp>"#
        );
        let dom = parse(xdp.as_bytes(), LIM, &|| false).unwrap();
        let set = Faces::bundled();
        let mut fonts = Fonts::new(&set).unwrap();
        let limits = XfaLimits {
            max_pages: 10,
            ..XfaLimits::default()
        };
        assert_eq!(
            run(&dom, &mut fonts, &limits, &|| false).unwrap_err(),
            XfaError::TooManyPages { limit: 10 }
        );
    }
}
