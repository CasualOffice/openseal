//! Rule and box finder on rasters (piece C; `ML-02B`): a scan has no drawn lines in its
//! content stream, so signature rules, underscore runs and check boxes are found in the
//! image by classic image processing, no model (docs/33 §5.1):
//!
//! 1. Binarise with Otsu's threshold.
//! 2. Collect horizontal (and, by columns, vertical) runs of ink, bridging one-pixel
//!    gaps: runs at least [`RULE_RUN_PT`] long for rules (so a rule that typed text or a
//!    signature touches is not merged with the letters), and runs a box's short side long
//!    for boxes.
//! 3. Join runs in neighbouring rows that overlap into one stroke, so a line skewed by a
//!    couple of degrees (a scan) stays one stroke.
//! 4. A stroke thin for its length is a line. A horizontal line at least [`RULE_MIN_PT`]
//!    long is a **rule**; two horizontal and two vertical lines that close a rectangle
//!    [`BOX_MIN_PT`] to [`BOX_MAX_PT`] tall are a **box** (the `Shape` definition in
//!    `casual-sign-fields`), and its edges are not also reported as rules.
//!
//! Results are rectangles in raster pixels; the worker maps them to page space with the
//! page's geometry ([`crate::wire::OcrPage::to_user`]). Work is bounded: at most
//! [`MAX_RUNS`] runs per direction and [`MAX_ITEMS`] results of each kind.

use crate::raster::Raster;
use crate::wire::{MAX_PAGE_ITEMS, Rect};

/// A rule is at least this long, in points (docs/33 §5.1).
pub const RULE_MIN_PT: f32 = 36.0;
/// A run counted toward a rule is at least this long, in points: longer than any stroke
/// of a letter, short enough that a line skewed by 2 degrees still yields runs.
pub const RULE_RUN_PT: f32 = 8.0;
/// A box is at least this tall and wide, in points.
pub const BOX_MIN_PT: f32 = 2.5;
/// A box is at most this tall, in points.
pub const BOX_MAX_PT: f32 = 100.0;
/// A line is at most this thick, in points (thicker strokes are bars or blocks).
pub const LINE_MAX_THICK_PT: f32 = 3.0;
/// Runs collected per direction; more are not examined.
pub const MAX_RUNS: usize = 400_000;
/// Rules, and boxes, returned per page.
pub const MAX_ITEMS: usize = MAX_PAGE_ITEMS;

/// Rules and boxes found on one raster.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Found {
    /// Rules: `x0, y0, x1, y1` in pixels.
    pub rules: Vec<Rect>,
    /// Boxes: `x0, y0, x1, y1` in pixels.
    pub boxes: Vec<Rect>,
}

/// A run of ink along one row (or column): `[start, end)` on `line`.
#[derive(Debug, Clone, Copy)]
struct Run {
    line: u32,
    start: u32,
    end: u32,
}

/// A joined stroke, in the scan direction's coordinates: `along` is x for a horizontal
/// stroke, `across` is y.
#[derive(Debug, Clone, Copy, PartialEq)]
struct Stroke {
    along0: u32,
    along1: u32,
    across0: u32,
    across1: u32,
    ink: u64,
}

impl Stroke {
    fn length(&self) -> u32 {
        self.along1.saturating_sub(self.along0)
    }

    /// Mean thickness: ink over length.
    fn thickness(&self) -> f32 {
        self.ink as f32 / self.length().max(1) as f32
    }

    /// Mean position across the stroke.
    fn middle(&self) -> f32 {
        (self.across0 as f32 + self.across1 as f32) / 2.0
    }
}

/// Otsu's threshold over a grey histogram; pixels below it are ink.
fn otsu(grey: &[u8]) -> u8 {
    let mut hist = [0u64; 256];
    for &g in grey {
        if let Some(h) = hist.get_mut(usize::from(g)) {
            *h = h.saturating_add(1);
        }
    }
    let total = grey.len() as f64;
    let sum_all: f64 = hist
        .iter()
        .enumerate()
        .map(|(i, &n)| i as f64 * n as f64)
        .sum();
    let (mut w_b, mut sum_b, mut best, mut best_t) = (0f64, 0f64, -1f64, 128u8);
    for (t, &n) in hist.iter().enumerate() {
        w_b += n as f64;
        if w_b == 0.0 {
            continue;
        }
        let w_f = total - w_b;
        if w_f == 0.0 {
            break;
        }
        sum_b += t as f64 * n as f64;
        let m_b = sum_b / w_b;
        let m_f = (sum_all - sum_b) / w_f;
        let between = w_b * w_f * (m_b - m_f) * (m_b - m_f);
        if between > best {
            best = between;
            best_t = u8::try_from(t).unwrap_or(128);
        }
    }
    // A blank page has one mode; never call paper ink.
    best_t.clamp(32, 200)
}

/// Runs of ink at least `min` long along each of `lines` lines of `len` pixels, where
/// `ink(line, i)` says whether a pixel is ink; gaps of one pixel are bridged.
fn runs(lines: u32, len: u32, min: u32, ink: impl Fn(u32, u32) -> bool) -> Vec<Run> {
    let mut out = Vec::new();
    for line in 0..lines {
        let mut i = 0u32;
        while i < len {
            if !ink(line, i) {
                i = i.saturating_add(1);
                continue;
            }
            let start = i;
            let mut end = i.saturating_add(1);
            loop {
                if end < len && ink(line, end) {
                    end = end.saturating_add(1);
                } else if end.saturating_add(1) < len && ink(line, end.saturating_add(1)) {
                    end = end.saturating_add(2);
                } else {
                    break;
                }
            }
            if end.saturating_sub(start) >= min {
                if out.len() >= MAX_RUNS {
                    return out;
                }
                out.push(Run { line, start, end });
            }
            i = end;
        }
    }
    out
}

/// Union-find root with path halving.
fn root(parent: &mut [usize], mut i: usize) -> usize {
    while let Some(&p) = parent.get(i) {
        if p == i {
            break;
        }
        let grand = parent.get(p).copied().unwrap_or(p);
        if let Some(slot) = parent.get_mut(i) {
            *slot = grand;
        }
        i = grand;
    }
    i
}

/// Join runs (sorted by line, then start) whose lines differ by at most two and whose
/// spans overlap or nearly touch, into strokes.
fn strokes(runs: &[Run]) -> Vec<Stroke> {
    let mut parent: Vec<usize> = (0..runs.len()).collect();
    // `window` holds indexes of runs on the previous two lines.
    let mut window_start = 0usize;
    for (i, r) in runs.iter().enumerate() {
        while runs
            .get(window_start)
            .is_some_and(|w| w.line.saturating_add(2) < r.line)
        {
            window_start = window_start.saturating_add(1);
        }
        for j in window_start..i {
            let Some(o) = runs.get(j) else { continue };
            if o.line == r.line {
                continue;
            }
            if o.start <= r.end.saturating_add(2) && r.start <= o.end.saturating_add(2) {
                let (a, b) = (root(&mut parent, i), root(&mut parent, j));
                if a != b
                    && let Some(slot) = parent.get_mut(a)
                {
                    *slot = b;
                }
            }
        }
    }
    let mut by_root: std::collections::BTreeMap<usize, Stroke> = std::collections::BTreeMap::new();
    for (i, r) in runs.iter().enumerate() {
        let k = root(&mut parent, i);
        let ink = u64::from(r.end.saturating_sub(r.start));
        by_root
            .entry(k)
            .and_modify(|s| {
                s.along0 = s.along0.min(r.start);
                s.along1 = s.along1.max(r.end);
                s.across0 = s.across0.min(r.line);
                s.across1 = s.across1.max(r.line.saturating_add(1));
                s.ink = s.ink.saturating_add(ink);
            })
            .or_insert(Stroke {
                along0: r.start,
                along1: r.end,
                across0: r.line,
                across1: r.line.saturating_add(1),
                ink,
            });
    }
    by_root.into_values().collect()
}

/// Strokes thin for their length: lines, allowing a skew of about three degrees.
fn lines(strokes: Vec<Stroke>, min_len: u32, max_thick: f32) -> Vec<Stroke> {
    strokes
        .into_iter()
        .filter(|s| {
            let len = s.length();
            let spread = s.across1.saturating_sub(s.across0) as f32;
            len >= min_len
                && s.thickness() <= max_thick
                && spread <= max_thick + 2.0 + len as f32 * 0.055
        })
        .collect()
}

/// Find rules and boxes on `raster`.
#[must_use]
pub fn find(raster: &Raster) -> Found {
    let (w, h) = (u32::from(raster.width), u32::from(raster.height));
    let grey = &raster.grey;
    if grey.len() as u64 != u64::from(w).saturating_mul(u64::from(h)) || w == 0 || h == 0 {
        return Found::default();
    }
    let px_per_pt = f32::from(raster.dpi) / 72.0;
    let px = |pt: f32| (pt * px_per_pt).round().max(1.0) as u32;
    let t = otsu(grey);
    let ink = |x: u32, y: u32| {
        let i = u64::from(y)
            .saturating_mul(u64::from(w))
            .saturating_add(u64::from(x));
        usize::try_from(i)
            .ok()
            .and_then(|i| grey.get(i))
            .is_some_and(|&g| g < t)
    };
    let short = px(BOX_MIN_PT * 0.8);
    let max_thick = LINE_MAX_THICK_PT * px_per_pt;
    let horizontal = lines(
        strokes(&runs(h, w, short, |y, x| ink(x, y))),
        short,
        max_thick,
    );
    let vertical = lines(strokes(&runs(w, h, short, ink)), short, max_thick);

    // Boxes: a top and a bottom line of matching extent, closed by a left and a right line.
    let (box_min, box_max) = (px(BOX_MIN_PT), px(BOX_MAX_PT));
    let mut hs: Vec<&Stroke> = horizontal.iter().collect();
    hs.sort_by(|a, b| a.middle().total_cmp(&b.middle()));
    let mut boxes = Vec::new();
    let mut edges: Vec<Stroke> = Vec::new();
    let mut checks = 0usize;
    'top: for (i, top) in hs.iter().enumerate() {
        for bottom in hs.iter().skip(i.saturating_add(1)) {
            let height = bottom.middle() - top.middle();
            if height < box_min as f32 {
                continue;
            }
            if height > box_max as f32 {
                break;
            }
            checks = checks.saturating_add(1);
            if checks > MAX_RUNS || boxes.len() >= MAX_ITEMS {
                break 'top;
            }
            let tol = 3.0 + 0.06 * height;
            let x0 = top.along0.min(bottom.along0) as f32;
            let x1 = top.along1.max(bottom.along1) as f32;
            if (top.along0 as f32 - bottom.along0 as f32).abs() > tol
                || (top.along1 as f32 - bottom.along1 as f32).abs() > tol
                || x1 - x0 < box_min as f32
            {
                continue;
            }
            // A skewed edge spans several rows: the corners lie within its band.
            let closes = |x: f32| {
                vertical.iter().any(|v| {
                    (v.middle() - x).abs() <= tol
                        && v.along0 as f32 <= top.across1 as f32 + tol
                        && v.along1 as f32 >= bottom.across0 as f32 - tol
                })
            };
            if closes(x0) && closes(x1) {
                boxes.push([x0, top.across0 as f32, x1, bottom.across1 as f32]);
                edges.push(**top);
                edges.push(**bottom);
            }
        }
    }
    let rule_min = px(RULE_MIN_PT);
    let long = lines(
        strokes(&runs(h, w, px(RULE_RUN_PT), |y, x| ink(x, y))),
        rule_min,
        max_thick,
    );
    // A box edge found again by the long-run pass is the box's, not a rule.
    let is_edge = |s: &Stroke| {
        edges.iter().any(|e| {
            let overlap = s
                .along1
                .min(e.along1)
                .saturating_sub(s.along0.max(e.along0));
            overlap.saturating_mul(2) >= s.length() && (s.middle() - e.middle()).abs() <= max_thick
        })
    };
    let rules = long
        .iter()
        .filter(|s| !is_edge(s))
        .take(MAX_ITEMS)
        .map(|s| {
            [
                s.along0 as f32,
                s.across0 as f32,
                s.along1 as f32,
                s.across1 as f32,
            ]
        })
        .collect();
    Found { rules, boxes }
}

#[cfg(test)]
mod tests {
    // Test code: a panic is the failure report.
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    use super::*;

    /// A white raster at 144 DPI (2 px per pt) with dark rectangles drawn on it.
    fn raster(w: u16, h: u16, ink: &[(u32, u32, u32, u32)]) -> Raster {
        let mut grey = vec![240u8; usize::from(w) * usize::from(h)];
        for &(x0, y0, x1, y1) in ink {
            for y in y0..y1 {
                for x in x0..x1 {
                    grey[y as usize * usize::from(w) + x as usize] = 30;
                }
            }
        }
        Raster {
            width: w,
            height: h,
            dpi: 144,
            rotate: 0,
            crop: [0.0, 0.0, f32::from(w) / 2.0, f32::from(h) / 2.0],
            grey,
        }
    }

    #[test]
    fn a_long_thin_line_is_a_rule_and_a_short_one_is_not() {
        // 150 pt rule, 1.5 pt thick; a 20 pt dash; a thick 150 pt bar.
        let r = raster(
            800,
            600,
            &[
                (100, 100, 400, 103),
                (100, 200, 140, 203),
                (100, 300, 400, 340),
            ],
        );
        let f = find(&r);
        assert_eq!(f.rules, vec![[100.0, 100.0, 400.0, 103.0]]);
        assert!(f.boxes.is_empty());
    }

    #[test]
    fn a_closed_rectangle_is_a_box_not_two_rules() {
        // A 12 pt check box (24 px) with a 1 pt (2 px) border, and a 100 pt wide entry
        // cell 20 pt tall; both are boxes and their edges are not rules.
        let mut ink = vec![
            (100, 100, 124, 102),
            (100, 122, 124, 124),
            (100, 100, 102, 124),
            (122, 100, 124, 124),
        ];
        ink.extend([
            (200, 200, 400, 202),
            (200, 238, 400, 240),
            (200, 200, 202, 240),
            (398, 200, 400, 240),
        ]);
        let f = find(&raster(600, 400, &ink));
        assert_eq!(f.boxes.len(), 2, "{f:?}");
        assert!(f.rules.is_empty(), "{f:?}");
    }

    #[test]
    fn a_skewed_rule_stays_one_rule() {
        // 200 pt long (400 px), rising 2 px every 60 px: about 1.9 degrees.
        let mut ink = Vec::new();
        for k in 0..20u32 {
            ink.push((
                100 + k * 20,
                300 - k * 2 / 3,
                100 + k * 20 + 21,
                303 - k * 2 / 3,
            ));
        }
        let f = find(&raster(700, 400, &ink));
        assert_eq!(f.rules.len(), 1, "{f:?}");
        let [x0, _, x1, _] = f.rules[0];
        assert!(x0 <= 101.0 && x1 >= 499.0, "{f:?}");
    }

    #[test]
    fn a_blank_or_inconsistent_raster_finds_nothing() {
        assert_eq!(find(&raster(300, 300, &[])), Found::default());
        let mut r = raster(300, 300, &[(10, 10, 290, 12)]);
        r.grey.pop();
        assert_eq!(find(&r), Found::default());
    }
}
