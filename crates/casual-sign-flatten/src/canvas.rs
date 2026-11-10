//! A content stream being written, and what it uses: fonts (with the glyphs drawn from
//! each, for the subset, `/W` and `ToUnicode`) and images.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;

/// A number a PDF parser accepts: fixed point, at most four places, never an exponent,
/// `NaN` or `inf` (from OpenPresent's `pdf.rs`, `num`).
pub(crate) fn num(value: f64) -> String {
    if !value.is_finite() {
        return "0".to_owned();
    }
    let mut s = format!("{value:.4}");
    if s.contains('.') {
        while s.ends_with('0') {
            s.pop();
        }
        if s.ends_with('.') {
            s.pop();
        }
    }
    if s == "-0" { "0".to_owned() } else { s }
}

/// A finer number, for matrix scale terms.
pub(crate) fn num_fine(value: f64) -> String {
    if !value.is_finite() {
        return "0".to_owned();
    }
    let s = format!("{value:.8}");
    let s = s.trim_end_matches('0').trim_end_matches('.');
    if s == "-0" || s.is_empty() {
        "0".to_owned()
    } else {
        s.to_owned()
    }
}

/// The glyphs drawn from each face: glyph id to the text it stands for.
#[derive(Debug, Default, Clone)]
pub(crate) struct GlyphUse {
    pub faces: BTreeMap<usize, BTreeMap<u16, String>>,
}

impl GlyphUse {
    pub(crate) fn note(&mut self, face: usize, gid: u16, c: char) {
        let entry = self.faces.entry(face).or_default().entry(gid).or_default();
        if entry.is_empty() {
            entry.push(c);
        }
    }
}

/// An sRGB colour as three fractions.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Color(pub [f64; 3]);

impl Color {
    pub(crate) const BLACK: Self = Self([0.0, 0.0, 0.0]);

    pub(crate) fn from_rgb(rgb: [u8; 3]) -> Self {
        let [r, g, b] = rgb;
        Self([
            f64::from(r) / 255.0,
            f64::from(g) / 255.0,
            f64::from(b) / 255.0,
        ])
    }

    fn ops(self, op: &str) -> String {
        let [r, g, b] = self.0;
        format!("{} {} {} {op}", num(r), num(g), num(b))
    }
}

/// A content stream and its resources.
#[derive(Debug, Default)]
pub(crate) struct Canvas {
    pub ops: String,
    /// Faces used, by index in the [`crate::FontSet`]: resource `/F{index}`.
    pub fonts: BTreeSet<usize>,
    /// Images used, by index in the drawing's image list: resource `/Im{index}`.
    pub images: BTreeSet<usize>,
}

impl Canvas {
    pub(crate) fn line(&mut self, s: &str) {
        self.ops.push_str(s);
        self.ops.push('\n');
    }

    pub(crate) fn fill_color(&mut self, c: Color) {
        let s = c.ops("rg");
        self.line(&s);
    }

    pub(crate) fn stroke_color(&mut self, c: Color) {
        let s = c.ops("RG");
        self.line(&s);
    }

    pub(crate) fn rect(&mut self, x: f64, y: f64, w: f64, h: f64, op: &str) {
        let s = format!("{} {} {} {} re {op}", num(x), num(y), num(w), num(h));
        self.line(&s);
    }

    pub(crate) fn move_to(&mut self, x: f64, y: f64) {
        let _ = writeln!(self.ops, "{} {} m", num(x), num(y));
    }

    pub(crate) fn line_to(&mut self, x: f64, y: f64) {
        let _ = writeln!(self.ops, "{} {} l", num(x), num(y));
    }

    pub(crate) fn curve_to(&mut self, c: [f64; 6]) {
        let [a, b, cc, d, e, f] = c;
        let _ = writeln!(
            self.ops,
            "{} {} {} {} {} {} c",
            num(a),
            num(b),
            num(cc),
            num(d),
            num(e),
            num(f)
        );
    }

    /// A quadratic from the current point `p0` through control `c` to `p`, as the
    /// cubic PDF has.
    pub(crate) fn quad_to(&mut self, p0: (f64, f64), c: (f64, f64), p: (f64, f64)) {
        let c1 = (
            p0.0 + 2.0 / 3.0 * (c.0 - p0.0),
            p0.1 + 2.0 / 3.0 * (c.1 - p0.1),
        );
        let c2 = (p.0 + 2.0 / 3.0 * (c.0 - p.0), p.1 + 2.0 / 3.0 * (c.1 - p.1));
        self.curve_to([c1.0, c1.1, c2.0, c2.1, p.0, p.1]);
    }

    /// A circle of radius `r` at `(cx, cy)`, four cubic arcs.
    pub(crate) fn circle(&mut self, cx: f64, cy: f64, r: f64) {
        const K: f64 = 0.552_284_75;
        let k = K * r;
        self.move_to(cx + r, cy);
        self.curve_to([cx + r, cy + k, cx + k, cy + r, cx, cy + r]);
        self.curve_to([cx - k, cy + r, cx - r, cy + k, cx - r, cy]);
        self.curve_to([cx - r, cy - k, cx - k, cy - r, cx, cy - r]);
        self.curve_to([cx + k, cy - r, cx + r, cy - k, cx + r, cy]);
        self.line("h");
    }

    /// A text-showing operand: glyph ids, two bytes each, as hex (Identity-H).
    pub(crate) fn glyph_hex(gids: &[u16]) -> String {
        let mut s = String::with_capacity(gids.len().saturating_mul(4).saturating_add(2));
        s.push('<');
        for g in gids {
            let _ = write!(s, "{g:04X}");
        }
        s.push('>');
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_never_carry_an_exponent_or_nan() {
        assert_eq!(num(1e-9), "0");
        assert_eq!(num(-0.00001), "0");
        assert_eq!(num(f64::NAN), "0");
        assert_eq!(num(12.5), "12.5");
        assert_eq!(num(1e20), "100000000000000000000");
        assert_eq!(num_fine(0.123_456_789), "0.12345679");
    }
}
