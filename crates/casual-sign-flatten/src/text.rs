//! Shaping-free text layout: characters to glyphs through the face's `cmap`, advances
//! from `hmtx`, lines broken at whitespace (a word wider than the box breaks between
//! glyphs), sizes shrunk until the text fits (docs/30 §7).
//!
//! No kerning, ligatures or bidirectional reordering: what a script needs shaping for is
//! a gap (`TXT-SHAPE`, recorded in the report of `T-1E`).

use casual_sign_model::Align;
use unicode_normalization::UnicodeNormalization;

use crate::canvas::{Canvas, Color, GlyphUse, num};
use crate::fonts::FontSet;

/// Smallest size auto-shrink goes to, in points.
pub(crate) const MIN_SIZE: f64 = 4.0;
/// The size an automatic field starts from, in points.
pub(crate) const AUTO_SIZE: f64 = 12.0;
/// Shrink steps tried, at most.
const SHRINK_STEPS: usize = 64;

/// A glyph to draw: the face, its id, its advance in thousandths of an em.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Glyph {
    pub face: usize,
    pub gid: u16,
    pub adv: f64,
    pub ch: char,
}

/// A run of text mapped to glyphs, with hard breaks kept as `None`.
#[derive(Debug, Clone, Default)]
pub(crate) struct Mapped {
    pub items: Vec<Option<Glyph>>,
}

/// Map text to glyphs. Whitespace other than a line break draws as a space; other
/// control characters are dropped. `Err(())` when a character is in no face.
pub(crate) fn map(fonts: &FontSet, preferred: usize, text: &str) -> Result<Mapped, ()> {
    let mut out = Mapped::default();
    let normalized: String = text.nfc().collect();
    let mut chars = normalized.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\r' {
            if chars.peek() == Some(&'\n') {
                chars.next();
            }
            out.items.push(None);
            continue;
        }
        if matches!(c, '\n' | '\u{2028}' | '\u{2029}' | '\u{85}') {
            out.items.push(None);
            continue;
        }
        let c = if c.is_whitespace() { ' ' } else { c };
        if c.is_control() || matches!(c, '\u{200B}'..='\u{200F}' | '\u{FEFF}') {
            continue;
        }
        let (face, gid, adv) = fonts.resolve(preferred, c).ok_or(())?;
        out.items.push(Some(Glyph {
            face,
            gid,
            adv,
            ch: c,
        }));
    }
    Ok(out)
}

/// One laid-out line, its width in thousandths of an em.
#[derive(Debug, Clone, Default)]
pub(crate) struct Line {
    pub glyphs: Vec<Glyph>,
    pub width: f64,
}

fn width(glyphs: &[Glyph]) -> f64 {
    glyphs.iter().map(|g| g.adv).sum()
}

fn trim_end(mut glyphs: Vec<Glyph>) -> Line {
    while glyphs.last().is_some_and(|g| g.ch == ' ') {
        glyphs.pop();
    }
    let w = width(&glyphs);
    Line { glyphs, width: w }
}

/// Break into lines no wider than `max` (thousandths of an em). With `wrap` false,
/// hard breaks still break and nothing else does.
pub(crate) fn lines(mapped: &Mapped, max: f64, wrap: bool) -> Vec<Line> {
    let mut out = Vec::new();
    for para in mapped.items.split(Option::is_none) {
        let glyphs: Vec<Glyph> = para.iter().flatten().copied().collect();
        if !wrap {
            out.push(trim_end(glyphs));
            continue;
        }
        let mut line: Vec<Glyph> = Vec::new();
        let mut i = 0;
        // Words: a run of non-spaces with the spaces that follow it.
        while i < glyphs.len() {
            let start = i;
            while glyphs.get(i).is_some_and(|g| g.ch != ' ') {
                i = i.saturating_add(1);
            }
            let word_end = i;
            while glyphs.get(i).is_some_and(|g| g.ch == ' ') {
                i = i.saturating_add(1);
            }
            let word = glyphs.get(start..word_end).unwrap_or(&[]);
            let spaces = glyphs.get(word_end..i).unwrap_or(&[]);
            if !line.is_empty() && width(&line) + width(word) > max {
                out.push(trim_end(core::mem::take(&mut line)));
            }
            if width(word) > max {
                // Hard-break a word wider than the line.
                for g in word {
                    if !line.is_empty() && width(&line) + g.adv > max {
                        out.push(trim_end(core::mem::take(&mut line)));
                    }
                    line.push(*g);
                }
            } else {
                line.extend_from_slice(word);
            }
            line.extend_from_slice(spaces);
        }
        out.push(trim_end(line));
    }
    out
}

/// How a block of text is set in a box.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Setting {
    /// The preferred face.
    pub face: usize,
    /// A fixed size, or `None` for automatic.
    pub size: Option<f64>,
    /// May a fixed size shrink to fit?
    pub shrink: bool,
    /// May lines wrap?
    pub wrap: bool,
    pub align: Align,
    pub color: Color,
    /// Inner padding, points.
    pub padding: f64,
    /// Comb cells (a `/Comb` field's `/MaxLen`), when set.
    pub comb: Option<u32>,
}

/// The outcome of setting text.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct SetResult {
    pub size: f64,
    /// The size was reduced from the requested or automatic one.
    pub shrunk: bool,
    /// Even at the smallest size the text did not fit and is clipped by the box.
    pub overflow: bool,
}

/// Lay out `mapped` in a `w` × `h` box and write it to `canvas`.
pub(crate) fn set(
    canvas: &mut Canvas,
    uses: &mut GlyphUse,
    fonts: &FontSet,
    mapped: &Mapped,
    w: f64,
    h: f64,
    s: &Setting,
) -> SetResult {
    let pad = s.padding.min(w / 4.0).min(h / 4.0).max(0.0);
    let (aw, ah) = ((w - 2.0 * pad).max(0.1), (h - 2.0 * pad).max(0.1));
    let metrics = fonts
        .face(s.face)
        .map_or((905.0, -212.0), |f| (f.metrics.ascent, f.metrics.descent));
    let (asc, desc) = (metrics.0.max(1.0), metrics.1.min(0.0));
    let line_em = (asc - desc) / 1000.0;
    let start = match s.size {
        Some(v) => v,
        None => AUTO_SIZE.min(ah / line_em).max(MIN_SIZE),
    };
    let can_shrink = s.size.is_none() || s.shrink;
    let fits = |size: f64| -> (Vec<Line>, bool) {
        let max = aw / size * 1000.0;
        let ls = lines(mapped, max, s.wrap);
        let tall = ls.len() as f64 * line_em * size;
        let ok = tall <= ah + 1e-6 && ls.iter().all(|l| l.width <= max + 1e-6);
        (ls, ok)
    };
    let mut size = start;
    let (mut ls, mut ok) = fits(size);
    if s.comb.is_none() && can_shrink {
        let mut steps = 0;
        while !ok && size > MIN_SIZE && steps < SHRINK_STEPS {
            size = (size * 0.92).max(MIN_SIZE);
            (ls, ok) = fits(size);
            steps = steps.saturating_add(1);
        }
    }
    let result = SetResult {
        size,
        shrunk: size < start,
        overflow: !ok,
    };
    if ls.iter().all(|l| l.glyphs.is_empty()) {
        return result;
    }
    canvas.line("BT");
    canvas.fill_color(s.color);
    let em = size / 1000.0;
    // A single line sits in the vertical middle; several start at the top.
    let first_baseline = if ls.len() <= 1 {
        (h - (asc - desc) * em) / 2.0 - desc * em
    } else {
        h - pad - asc * em
    };
    let mut current: Option<usize> = None;
    for (i, line) in ls.iter().enumerate() {
        let y = first_baseline - i as f64 * line_em * size;
        if let Some(cells) = s.comb.filter(|c| *c > 0) {
            let cell = w / f64::from(cells);
            for (k, g) in line.glyphs.iter().enumerate() {
                let x = cell * k as f64 + (cell - g.adv * em) / 2.0;
                show(
                    canvas,
                    uses,
                    &mut current,
                    size,
                    x,
                    y,
                    std::slice::from_ref(g),
                );
            }
            continue;
        }
        let lw = line.width * em;
        let x = match s.align {
            Align::Center => (w - lw) / 2.0,
            Align::Right => w - pad - lw,
            _ => pad,
        };
        show(canvas, uses, &mut current, size, x, y, &line.glyphs);
    }
    canvas.line("ET");
    result
}

/// Show glyphs from `(x, y)`, switching face where the run changes face.
fn show(
    canvas: &mut Canvas,
    uses: &mut GlyphUse,
    current: &mut Option<usize>,
    size: f64,
    x: f64,
    y: f64,
    glyphs: &[Glyph],
) {
    canvas.line(&format!("1 0 0 1 {} {} Tm", num(x), num(y)));
    for run in glyphs.chunk_by(|a, b| a.face == b.face) {
        let Some(first) = run.first() else { continue };
        if *current != Some(first.face) {
            canvas.line(&format!("/F{} {} Tf", first.face, num(size)));
            canvas.fonts.insert(first.face);
            *current = Some(first.face);
        }
        let gids: Vec<u16> = run.iter().map(|g| g.gid).collect();
        for g in run {
            uses.note(g.face, g.gid, g.ch);
        }
        canvas.line(&format!("{} Tj", Canvas::glyph_hex(&gids)));
    }
}

#[cfg(all(test, feature = "bundled-fonts"))]
mod tests {
    // Test code: a panic is the failure report (CLAUDE.md).
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    fn mapped(t: &str) -> Mapped {
        map(&FontSet::bundled(), 2, t).unwrap()
    }

    #[test]
    fn wraps_at_spaces_and_hard_breaks_long_words() {
        // Liberation Mono: every advance is 600.
        let m = mapped("aaa bbb cccccccc");
        let ls = lines(&m, 600.0 * 4.0, true);
        let text: Vec<String> = ls
            .iter()
            .map(|l| l.glyphs.iter().map(|g| g.ch).collect())
            .collect();
        assert_eq!(text, ["aaa", "bbb", "cccc", "cccc"]);
    }

    #[test]
    fn hard_breaks_split_even_without_wrapping() {
        let m = mapped("a\r\nb\nc");
        assert_eq!(lines(&m, 1.0, false).len(), 3);
    }

    #[test]
    fn auto_size_shrinks_until_the_text_fits() {
        let fonts = FontSet::bundled();
        let m = map(&fonts, 0, "A long sentence that must shrink").unwrap();
        let mut c = Canvas::default();
        let mut u = GlyphUse::default();
        let s = Setting {
            face: 0,
            size: None,
            shrink: true,
            wrap: false,
            align: Align::Left,
            color: Color::BLACK,
            padding: 2.0,
            comb: None,
        };
        let r = set(&mut c, &mut u, &fonts, &m, 80.0, 20.0, &s);
        assert!(r.shrunk && !r.overflow && r.size < 12.0, "{r:?}");
        assert!(c.ops.contains("Tj"));
    }
}
