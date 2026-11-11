//! Template properties: measurements, fonts, paragraphs, margins, borders and colours
//! (XFA 3.3 chapter 2 and the template grammar).

use crate::xml::{Dom, NodeId};

/// Largest measurement accepted, in points (about 14 m). A larger or non-finite value
/// is treated as absent: geometry from a file never reaches a PDF as `inf` or `NaN`.
const MAX_MEASURE: f64 = 40_000.0;

/// Parse an XFA measurement into points. The default unit is the inch for geometry and
/// the point for font sizes (`default_unit`).
pub(crate) fn measure(raw: &str, default_unit: f64) -> Option<f64> {
    let s = raw.trim();
    let split = s
        .find(|c: char| !(c.is_ascii_digit() || matches!(c, '.' | '-' | '+')))
        .unwrap_or(s.len());
    let (num, unit) = (s.get(..split)?, s.get(split..)?.trim());
    let v: f64 = num.parse().ok()?;
    let k = match unit {
        "" => default_unit,
        "in" => 72.0,
        "pt" => 1.0,
        "mm" => 72.0 / 25.4,
        "cm" => 72.0 / 2.54,
        "mp" => 0.001,
        "pc" => 12.0,
        "px" => 0.75,
        _ => return None,
    };
    let out = v * k;
    (out.is_finite() && out.abs() <= MAX_MEASURE).then_some(out)
}

/// A measurement attribute in points (inches when unitless).
pub(crate) fn attr_len(dom: &Dom, id: NodeId, name: &str) -> Option<f64> {
    dom.attr(id, name).and_then(|v| measure(v, 72.0))
}

/// An RGB colour, components 0 to 1.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Color(pub f64, pub f64, pub f64);

impl Color {
    pub(crate) const BLACK: Self = Self(0.0, 0.0, 0.0);
    pub(crate) const WHITE: Self = Self(1.0, 1.0, 1.0);
}

/// `<color value="r,g,b"/>`.
pub(crate) fn color(dom: &Dom, color_node: NodeId) -> Option<Color> {
    let v = dom.attr(color_node, "value")?;
    let mut parts = v.split(',').map(|p| p.trim().parse::<f64>().ok());
    let r = parts.next()??;
    let g = parts.next()??;
    let b = parts.next()??;
    let k = |c: f64| (c / 255.0).clamp(0.0, 1.0);
    Some(Color(k(r), k(g), k(b)))
}

/// A `<fill>` element's colour: its `<color>` (white by default), or `None` when the
/// fill is hidden. Patterns (`linear`, `radial`, `pattern`, `stipple`) paint the
/// fill's colour flat (the second colour of a gradient is not drawn, `XFA-01` gap).
pub(crate) fn fill_color(dom: &Dom, fill: NodeId) -> Option<Color> {
    if matches!(
        dom.attr(fill, "presence"),
        Some("hidden" | "invisible" | "inactive")
    ) {
        return None;
    }
    Some(
        dom.child(fill, "color")
            .and_then(|c| color(dom, c))
            .unwrap_or(Color::WHITE),
    )
}

/// Insets from a `<margin>` element.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub(crate) struct Margin {
    pub top: f64,
    pub right: f64,
    pub bottom: f64,
    pub left: f64,
}

impl Margin {
    pub(crate) fn of(dom: &Dom, owner: NodeId) -> Self {
        dom.child(owner, "margin")
            .map_or_else(Self::default, |m| Self::from_node(dom, m))
    }

    pub(crate) fn from_node(dom: &Dom, m: NodeId) -> Self {
        let g = |n: &str| attr_len(dom, m, n).unwrap_or(0.0).max(0.0);
        Self {
            top: g("topInset"),
            right: g("rightInset"),
            bottom: g("bottomInset"),
            left: g("leftInset"),
        }
    }

    pub(crate) fn h(&self) -> f64 {
        self.left + self.right
    }

    pub(crate) fn v(&self) -> f64 {
        self.top + self.bottom
    }
}

/// One edge of a border or a line.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Edge {
    pub visible: bool,
    pub thickness: f64,
    pub color: Color,
    /// `dashed`, `dotted` and the like as a dash pattern (on, off).
    pub dash: Option<(f64, f64)>,
}

impl Default for Edge {
    fn default() -> Self {
        Self {
            visible: true,
            thickness: 0.5,
            color: Color::BLACK,
            dash: None,
        }
    }
}

pub(crate) fn edge(dom: &Dom, e: NodeId) -> Edge {
    let visible = !matches!(
        dom.attr(e, "presence"),
        Some("hidden" | "invisible" | "inactive")
    );
    let thickness = attr_len(dom, e, "thickness").unwrap_or(0.5).max(0.0);
    let color = dom
        .child(e, "color")
        .and_then(|c| color(dom, c))
        .unwrap_or(Color::BLACK);
    let dash = match dom.attr(e, "stroke") {
        Some("dashed") => Some((3.0 * thickness.max(1.0), 3.0 * thickness.max(1.0))),
        Some("dotted") => Some((thickness.max(0.5), 2.0 * thickness.max(0.5))),
        Some("dashDot" | "dashDotDot") => {
            Some((4.0 * thickness.max(1.0), 2.0 * thickness.max(1.0)))
        }
        _ => None,
    };
    Edge {
        visible,
        thickness,
        color,
        dash,
    }
}

/// A box's border: four edges (top, right, bottom, left), corner radius and fill.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub(crate) struct Border {
    pub edges: [Edge; 4],
    pub radius: f64,
    pub fill: Option<Color>,
    /// Whether any edge or the fill paints.
    pub paints: bool,
}

/// The edges of a `<border>` or `<rectangle>`: up to four `<edge>` children, the last
/// repeating for the missing ones (XFA 3.3 "border"); none means one default edge.
pub(crate) fn border(dom: &Dom, b: NodeId) -> Border {
    let hidden = matches!(
        dom.attr(b, "presence"),
        Some("hidden" | "invisible" | "inactive")
    );
    let found: Vec<Edge> = dom
        .children_named(b, "edge")
        .map(|e| edge(dom, e))
        .collect();
    let mut edges = [Edge::default(); 4];
    let mut last = Edge::default();
    for (i, slot) in edges.iter_mut().enumerate() {
        if let Some(e) = found.get(i) {
            last = *e;
        }
        *slot = last;
    }
    let radius = dom
        .child(b, "corner")
        .and_then(|c| attr_len(dom, c, "radius"))
        .unwrap_or(0.0)
        .max(0.0);
    let fill = dom.child(b, "fill").and_then(|f| fill_color(dom, f));
    if hidden {
        return Border::default();
    }
    let paints = fill.is_some() || edges.iter().any(|e| e.visible && e.thickness > 0.0);
    Border {
        edges,
        radius,
        fill,
        paints,
    }
}

/// The face family a typeface name maps onto in the bundled set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub(crate) enum Family {
    #[default]
    Sans,
    Serif,
    Mono,
}

/// Map a typeface name onto a bundled family: Liberation Sans for Arial, Helvetica,
/// Myriad and every unknown sans; Liberation Serif for Times and other serif faces;
/// Liberation Mono for Courier and OCR faces.
pub(crate) fn family(typeface: &str) -> Family {
    let t = typeface.to_ascii_lowercase();
    let serif = [
        "times",
        "serif",
        "roman",
        "garamond",
        "georgia",
        "minion",
        "bell mt",
        "trajan",
        "century",
        "bodoni",
        "palatino",
        "book antiqua",
        "cambria",
    ];
    if t.contains("sans") {
        return Family::Sans;
    }
    if ["courier", "mono", "ocr", "consolas", "lucida console"]
        .iter()
        .any(|k| t.contains(k))
    {
        return Family::Mono;
    }
    if serif.iter().any(|k| t.contains(k)) {
        return Family::Serif;
    }
    Family::Sans
}

/// Whether a typeface name says bold (`Arial Bold`, `HelveticaNeueLT Std Blk`).
pub(crate) fn typeface_bold(typeface: &str) -> bool {
    let t = typeface.to_ascii_lowercase();
    ["bold", "blk", "black", "heavy", "demi"]
        .iter()
        .any(|k| t.contains(k))
}

/// A symbol typeface whose characters are not their Unicode meaning (Pi fonts,
/// Dingbats, Wingdings): text in it is drawn as the characters it encodes, which is
/// wrong, and is counted in the report (`XFA-01` gap).
pub(crate) fn typeface_symbolic(typeface: &str) -> bool {
    let t = typeface.to_ascii_lowercase();
    [
        "pi std", "comm pi", "dingbat", "wingding", "symbol", "commpi",
    ]
    .iter()
    .any(|k| t.contains(k))
}

/// Text style.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Font {
    pub family: Family,
    pub size: f64,
    pub bold: bool,
    pub italic: bool,
    pub underline: bool,
    pub color: Color,
    pub symbolic: bool,
    /// Baseline shift upwards, in points.
    pub shift: f64,
}

impl Default for Font {
    /// XFA 3.3 defaults: Courier 10 pt; Designer always names a face, so a missing
    /// one is rare.
    fn default() -> Self {
        Self {
            family: Family::Mono,
            size: 10.0,
            bold: false,
            italic: false,
            underline: false,
            color: Color::BLACK,
            symbolic: false,
            shift: 0.0,
        }
    }
}

/// Apply a `<font>` element over `base`.
pub(crate) fn font(dom: &Dom, f: NodeId, base: &Font) -> Font {
    let mut out = base.clone();
    if let Some(t) = dom.attr(f, "typeface") {
        out.family = family(t);
        out.bold = typeface_bold(t);
        out.symbolic = typeface_symbolic(t);
    }
    if let Some(s) = dom.attr(f, "size").and_then(|s| measure(s, 1.0))
        && s > 0.0
    {
        out.size = s.clamp(1.0, 1_000.0);
    }
    match dom.attr(f, "weight") {
        Some("bold") => out.bold = true,
        Some("normal") if !dom.attr(f, "typeface").is_some_and(typeface_bold) => {
            out.bold = false;
        }
        _ => {}
    }
    match dom.attr(f, "posture") {
        Some("italic") => out.italic = true,
        Some("normal") => out.italic = false,
        _ => {}
    }
    if let Some(u) = dom.attr(f, "underline") {
        out.underline = u != "0";
    }
    if let Some(s) = dom.attr(f, "baselineShift").and_then(|s| measure(s, 1.0)) {
        out.shift = -s;
    }
    if let Some(c) = dom.path(f, &["fill", "color"]).and_then(|c| color(dom, c)) {
        out.color = c;
    }
    out
}

/// Horizontal alignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum HAlign {
    #[default]
    Left,
    Center,
    Right,
    Justify,
}

/// Vertical alignment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum VAlign {
    #[default]
    Top,
    Middle,
    Bottom,
}

/// Paragraph properties.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub(crate) struct Para {
    pub h: HAlign,
    pub v: VAlign,
    pub space_above: f64,
    pub space_below: f64,
    pub margin_left: f64,
    pub margin_right: f64,
    pub indent: f64,
    pub line_height: Option<f64>,
}

pub(crate) fn halign(v: &str) -> Option<HAlign> {
    Some(match v {
        "left" | "radix" => HAlign::Left,
        "center" => HAlign::Center,
        "right" => HAlign::Right,
        "justify" | "justifyAll" => HAlign::Justify,
        _ => return None,
    })
}

/// Apply a `<para>` element over `base`.
pub(crate) fn para(dom: &Dom, p: NodeId, base: &Para) -> Para {
    let mut out = *base;
    if let Some(h) = dom.attr(p, "hAlign").and_then(halign) {
        out.h = h;
    }
    match dom.attr(p, "vAlign") {
        Some("middle") => out.v = VAlign::Middle,
        Some("bottom") => out.v = VAlign::Bottom,
        Some("top") => out.v = VAlign::Top,
        _ => {}
    }
    let pt = |n: &str| dom.attr(p, n).and_then(|v| measure(v, 72.0));
    if let Some(v) = pt("spaceAbove") {
        out.space_above = v.max(0.0);
    }
    if let Some(v) = pt("spaceBelow") {
        out.space_below = v.max(0.0);
    }
    if let Some(v) = pt("marginLeft") {
        out.margin_left = v.max(0.0);
    }
    if let Some(v) = pt("marginRight") {
        out.margin_right = v.max(0.0);
    }
    if let Some(v) = pt("textIndent") {
        out.indent = v;
    }
    if let Some(v) = pt("lineHeight") {
        out.line_height = (v > 0.0).then_some(v);
    }
    out
}

#[cfg(test)]
mod tests {
    // Test code: a panic is the failure report (CLAUDE.md).
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn measurements_convert_to_points() {
        assert!((measure("25.4mm", 72.0).unwrap() - 72.0).abs() < 1e-9);
        assert!((measure("1in", 72.0).unwrap() - 72.0).abs() < 1e-9);
        assert!((measure("2", 72.0).unwrap() - 144.0).abs() < 1e-9);
        assert!((measure("10pt", 72.0).unwrap() - 10.0).abs() < 1e-9);
        assert!((measure("2.54cm", 72.0).unwrap() - 72.0).abs() < 1e-9);
        assert!((measure("-0.5in", 72.0).unwrap() + 36.0).abs() < 1e-9);
        assert_eq!(measure("12furlongs", 72.0), None);
        assert_eq!(measure("1e309in", 72.0), None);
        assert_eq!(measure("99999in", 72.0), None);
        assert_eq!(measure("", 72.0), None);
    }

    #[test]
    fn typefaces_map_to_bundled_families() {
        assert_eq!(family("Arial"), Family::Sans);
        assert_eq!(family("Myriad Pro"), Family::Sans);
        assert_eq!(family("Times New Roman"), Family::Serif);
        assert_eq!(family("Courier New"), Family::Mono);
        assert_eq!(family("Noto Sans CJK TC Regular"), Family::Sans);
        assert!(typeface_bold("HelveticaNeueLT Std Blk Cn"));
        assert!(!typeface_bold("Arial"));
        assert!(typeface_symbolic("Adobe Pi Std"));
    }
}
