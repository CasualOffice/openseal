//! Pad strokes as PDF paths: the ink's bounding box fitted into the area, each stroke
//! smoothed by quadratic curves through the midpoints of its points (each point is the
//! control of the curve between its neighbours' midpoints), round caps and joins.

use crate::canvas::{Canvas, Color, num};
use crate::{Ink, InkPoint};

/// Count the points, refusing a non-finite one: `None` when any point is not finite.
pub(crate) fn count(ink: &Ink) -> Option<usize> {
    let mut n: usize = 0;
    for s in &ink.strokes {
        for p in s {
            if !p.x.is_finite() || !p.y.is_finite() {
                return None;
            }
        }
        n = n.saturating_add(s.len());
    }
    Some(n)
}

/// Draw `ink` fitted into the `w` × `h` area at `(x0, y0)` (bottom-left, y up).
pub(crate) fn draw(canvas: &mut Canvas, ink: &Ink, x0: f64, y0: f64, w: f64, h: f64) {
    let pts = ink.strokes.iter().flatten();
    let (mut minx, mut miny, mut maxx, mut maxy) = (f64::MAX, f64::MAX, f64::MIN, f64::MIN);
    for p in pts {
        minx = minx.min(p.x);
        miny = miny.min(p.y);
        maxx = maxx.max(p.x);
        maxy = maxy.max(p.y);
    }
    if minx > maxx || w <= 0.0 || h <= 0.0 {
        return;
    }
    let lw = (h * 0.04).clamp(0.6, 2.5);
    let (aw, ah) = ((w - 2.0 * lw).max(0.1), (h - 2.0 * lw).max(0.1));
    let (iw, ih) = ((maxx - minx).max(1e-9), (maxy - miny).max(1e-9));
    // One scale for both axes, so the signature keeps its shape; a dot or a straight
    // line fits by its other axis.
    let scale = match (maxx - minx > 1e-9, maxy - miny > 1e-9) {
        (true, true) => (aw / iw).min(ah / ih),
        (true, false) => aw / iw,
        (false, true) => ah / ih,
        (false, false) => 1.0,
    };
    let (dw, dh) = ((maxx - minx) * scale, (maxy - miny) * scale);
    let ox = x0 + (w - dw) / 2.0;
    let oy = y0 + (h - dh) / 2.0;
    // Pad y runs down; PDF y runs up.
    let map = |p: &InkPoint| (ox + (p.x - minx) * scale, oy + dh - (p.y - miny) * scale);
    canvas.line("q");
    canvas.stroke_color(ink.color.map_or(Color::BLACK, |c| Color::from_rgb(c.0)));
    canvas.line(&format!("{} w 1 J 1 j", num(lw)));
    for stroke in &ink.strokes {
        let mapped: Vec<(f64, f64)> = stroke.iter().map(map).collect();
        path(canvas, &mapped);
    }
    canvas.line("S");
    canvas.line("Q");
}

fn mid(a: (f64, f64), b: (f64, f64)) -> (f64, f64) {
    ((a.0 + b.0) / 2.0, (a.1 + b.1) / 2.0)
}

/// One stroke: a dot for a single point, a line for two, curves through midpoints for
/// more.
fn path(canvas: &mut Canvas, p: &[(f64, f64)]) {
    match p {
        [] => {}
        [a] => {
            // A zero-length segment with a round cap draws a dot.
            canvas.move_to(a.0, a.1);
            canvas.line_to(a.0, a.1);
        }
        [a, b] => {
            canvas.move_to(a.0, a.1);
            canvas.line_to(b.0, b.1);
        }
        [first, rest @ ..] => {
            canvas.move_to(first.0, first.1);
            let mut current = *first;
            for pair in p.windows(2).skip(1) {
                if let [c, next] = pair {
                    let end = mid(*c, *next);
                    canvas.quad_to(current, *c, end);
                    current = end;
                }
            }
            if let Some(last) = rest.last() {
                canvas.line_to(last.0, last.1);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    // Test code: a panic is the failure report (CLAUDE.md).
    #![allow(clippy::unwrap_used)]
    use super::*;

    fn ink(points: &[(f64, f64)]) -> Ink {
        Ink {
            strokes: vec![points.iter().map(|&(x, y)| InkPoint { x, y }).collect()],
            color: None,
        }
    }

    #[test]
    fn three_points_make_curves_and_end_on_the_last_point() {
        let mut c = Canvas::default();
        draw(
            &mut c,
            &ink(&[(0.0, 0.0), (10.0, 10.0), (20.0, 0.0)]),
            0.0,
            0.0,
            100.0,
            50.0,
        );
        assert!(c.ops.contains(" c\n"), "{}", c.ops);
        assert!(c.ops.contains(" w 1 J 1 j"));
        assert!(c.ops.trim_end().ends_with("S\nQ"));
    }

    #[test]
    fn a_non_finite_point_is_refused() {
        assert_eq!(count(&ink(&[(0.0, f64::NAN)])), None);
        assert_eq!(count(&ink(&[(0.0, 1.0), (2.0, 3.0)])), Some(2));
    }

    #[test]
    fn a_single_point_still_draws_a_dot() {
        let mut c = Canvas::default();
        draw(&mut c, &ink(&[(5.0, 5.0)]), 0.0, 0.0, 10.0, 10.0);
        assert!(c.ops.contains(" m\n") && c.ops.contains(" l\n"));
    }
}
