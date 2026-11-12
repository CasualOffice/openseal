//! OpenSeal's stand-in for the `clipper2-rust` crate (ML-02, ML-02C).
//!
//! `oar-ocr-core` (the PaddleOCR pipeline modeld runs, ADR-029) uses five items of
//! `clipper2-rust` to "unclip" a detected text region: push its outline outward by a
//! distance derived from its area and perimeter, with round corners. That crate is
//! BSL-1.0, which owner instruction 32 allows only inside the ONNX Runtime binary, so the
//! workspace manifest replaces it with this one through `[patch.crates-io]`.
//!
//! This is our own code, written from the call `oar-ocr-core` makes, not from Clipper2's
//! source. It does exactly what that call needs and no more:
//! - [`clipper::inflate_paths_d`] offsets each closed path outward with round joins. It
//!   offsets the path's **convex hull**, which is the same result for the convex
//!   rectangles modeld's detector produces (the quad box mode) and a convex superset for
//!   any other outline. Each output path is convex and counter-clockwise (y up). Other
//!   join or end types, a negative delta, and a degenerate path give no output path, which
//!   `oar-ocr-core` treats as "no box".
//! - [`core::area`] is the signed shoelace area.
//!
//! Every input is untrusted: non-finite coordinates drop the path, the arc step count is
//! bounded, and nothing panics.

/// Points, paths and the area of a path.
pub mod core {
    /// A point in the plane.
    #[derive(Debug, Clone, Copy, PartialEq, Default)]
    pub struct Point<T> {
        /// Horizontal coordinate.
        pub x: T,
        /// Vertical coordinate.
        pub y: T,
    }

    /// A point with `f64` coordinates.
    pub type PointD = Point<f64>;
    /// A closed path: its last point joins its first.
    pub type Path<T> = Vec<Point<T>>;
    /// A path of `f64` points.
    pub type PathD = Path<f64>;
    /// Several paths.
    pub type Paths<T> = Vec<Path<T>>;
    /// Several `f64` paths.
    pub type PathsD = Paths<f64>;

    /// The signed area of a closed path by the shoelace formula: positive when its points
    /// run counter-clockwise with y up. Fewer than three points have no area.
    #[must_use]
    pub fn area(path: &PathD) -> f64 {
        if path.len() < 3 {
            return 0.0;
        }
        let mut twice = 0.0;
        let mut prev = path.last().copied().unwrap_or_default();
        for p in path {
            twice += prev.x * p.y - p.x * prev.y;
            prev = *p;
        }
        twice / 2.0
    }
}

/// The join and end kinds an offset may ask for.
pub mod offset {
    /// How an offset path turns a corner. Only [`JoinType::Round`] is supported.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum JoinType {
        /// Squared-off corners (unsupported here).
        Square,
        /// Cut corners (unsupported here).
        Bevel,
        /// Arcs around each corner.
        Round,
        /// Pointed corners (unsupported here).
        Miter,
    }

    /// How an offset treats a path's ends. Only [`EndType::Polygon`] (closed) is supported.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum EndType {
        /// The path is a closed polygon.
        Polygon,
        /// An open path offset on both sides and joined (unsupported here).
        Joined,
        /// An open path with flat ends (unsupported here).
        Butt,
        /// An open path with square ends (unsupported here).
        Square,
        /// An open path with round ends (unsupported here).
        Round,
    }
}

/// The offset itself.
pub mod clipper {
    use core::f64::consts::{PI, TAU};

    use crate::core::{PathD, PathsD, PointD};
    use crate::offset::{EndType, JoinType};

    /// The arc tolerance used when the caller gives none, as a fraction of the delta.
    const DEFAULT_ARC_FRACTION: f64 = 0.002;
    /// The most arc points one corner may add, whatever the delta and tolerance say.
    const MAX_ARC_STEPS: f64 = 64.0;

    /// Push each closed path in `paths` outward by `delta` with round corners.
    ///
    /// Each path is replaced by its convex hull first (see the crate notes); `miter_limit`
    /// is unused by round joins. `precision` (clamped to -8..=8) is the number of decimal
    /// places the output is rounded to. `arc_tolerance` is the furthest an arc's chord may
    /// fall inside the true arc; zero or less means `delta * 0.002`. Returns one path per
    /// input path that could be offset; the outputs are not merged with each other.
    #[must_use]
    pub fn inflate_paths_d(
        paths: &PathsD,
        delta: f64,
        jt: JoinType,
        et: EndType,
        miter_limit: f64,
        precision: i32,
        arc_tolerance: f64,
    ) -> PathsD {
        let _ = miter_limit;
        if delta == 0.0 {
            return paths.clone();
        }
        if jt != JoinType::Round
            || et != EndType::Polygon
            || delta.partial_cmp(&0.0) != Some(core::cmp::Ordering::Greater)
            || !delta.is_finite()
        {
            return PathsD::new();
        }
        let tolerance = if arc_tolerance > 0.0 {
            arc_tolerance.min(delta)
        } else {
            delta * DEFAULT_ARC_FRACTION
        };
        let per_turn = (PI / (1.0 - tolerance / delta).acos()).clamp(1.0, MAX_ARC_STEPS);
        let steps_per_rad = per_turn / TAU;
        let scale = 10f64.powi(precision.clamp(-8, 8));
        paths
            .iter()
            .filter_map(|p| inflate_one(p, delta, steps_per_rad, scale))
            .collect()
    }

    fn inflate_one(path: &PathD, delta: f64, steps_per_rad: f64, scale: f64) -> Option<PathD> {
        if path.iter().any(|p| !p.x.is_finite() || !p.y.is_finite()) {
            return None;
        }
        let hull = convex_hull(path);
        if hull.len() < 3 {
            return None;
        }
        // Outward unit normal of each edge i -> i+1 of the counter-clockwise hull.
        let mut normals = Vec::with_capacity(hull.len());
        let mut prev = hull.last().copied()?;
        for p in &hull {
            let (dx, dy) = (p.x - prev.x, p.y - prev.y);
            let len = dx.hypot(dy);
            if len.partial_cmp(&0.0) != Some(core::cmp::Ordering::Greater) {
                return None;
            }
            normals.push((dy / len, -dx / len));
            prev = *p;
        }
        let round = |v: f64| (v * scale).round() / scale;
        let mut out = PathD::with_capacity(hull.len().saturating_mul(8));
        let mut push = |x: f64, y: f64| {
            let q = PointD {
                x: round(x),
                y: round(y),
            };
            if out.last() != Some(&q) {
                out.push(q);
            }
        };
        // normals[i] belongs to the edge ending at hull[i]; normals[i + 1] to the one
        // leaving it.
        for (i, p) in hull.iter().enumerate() {
            let a = normals.get(i).copied()?;
            let b = normals
                .get(i.saturating_add(1))
                .or(normals.first())
                .copied()?;
            let start = a.1.atan2(a.0);
            let mut turn = b.1.atan2(b.0) - start;
            if turn < 0.0 {
                turn += TAU;
            }
            push(p.x + a.0 * delta, p.y + a.1 * delta);
            // Bounded: steps_per_rad <= 64 / TAU and turn < TAU.
            let steps = (steps_per_rad * turn).ceil().clamp(1.0, MAX_ARC_STEPS);
            let mut k = 1.0;
            while k < steps {
                let t = start + turn * k / steps;
                push(p.x + t.cos() * delta, p.y + t.sin() * delta);
                k += 1.0;
            }
            push(p.x + b.0 * delta, p.y + b.1 * delta);
        }
        if out.len() > 1 && out.first() == out.last() {
            out.pop();
        }
        (out.len() >= 3).then_some(out)
    }

    /// The convex hull, counter-clockwise (y up), without collinear points (Andrew's
    /// monotone chain).
    fn convex_hull(path: &PathD) -> PathD {
        let mut pts = path.clone();
        pts.sort_by(|a, b| a.x.total_cmp(&b.x).then(a.y.total_cmp(&b.y)));
        pts.dedup();
        if pts.len() < 3 {
            return pts;
        }
        let cross =
            |o: PointD, a: PointD, b: PointD| (a.x - o.x) * (b.y - o.y) - (a.y - o.y) * (b.x - o.x);
        let mut hull: PathD = Vec::with_capacity(pts.len().saturating_mul(2));
        for pass in [pts.clone(), pts.into_iter().rev().collect::<PathD>()] {
            let floor = hull.len();
            for p in pass {
                while hull.len() >= floor.saturating_add(2) {
                    let n = hull.len();
                    let (Some(&o), Some(&a)) =
                        (hull.get(n.saturating_sub(2)), hull.get(n.saturating_sub(1)))
                    else {
                        break;
                    };
                    if cross(o, a, p) > 0.0 {
                        break;
                    }
                    hull.pop();
                }
                hull.push(p);
            }
            // The last point of each chain is the first of the next.
            hull.pop();
        }
        hull
    }
}

#[cfg(test)]
mod tests {
    // Tests may index and unwrap (CLAUDE.md): a failure is a test failure.
    #![allow(clippy::indexing_slicing, clippy::unwrap_used)]

    use super::clipper::inflate_paths_d;
    use super::core::{PathD, PointD, area};
    use super::offset::{EndType, JoinType};

    fn path(pts: &[(f64, f64)]) -> PathD {
        pts.iter().map(|&(x, y)| PointD { x, y }).collect()
    }

    fn inflate(p: PathD, delta: f64) -> Vec<PathD> {
        inflate_paths_d(
            &vec![p],
            delta,
            JoinType::Round,
            EndType::Polygon,
            2.0,
            2,
            0.0,
        )
    }

    fn bounds(p: &PathD) -> (f64, f64, f64, f64) {
        p.iter().fold(
            (f64::MAX, f64::MAX, f64::MIN, f64::MIN),
            |(a, b, c, d), q| (a.min(q.x), b.min(q.y), c.max(q.x), d.max(q.y)),
        )
    }

    #[test]
    fn area_is_signed_by_orientation() {
        let ccw = path(&[(0.0, 0.0), (4.0, 0.0), (4.0, 2.0), (0.0, 2.0)]);
        let cw: PathD = ccw.iter().rev().copied().collect();
        assert!((area(&ccw) - 8.0).abs() < 1e-12);
        assert!((area(&cw) + 8.0).abs() < 1e-12);
        assert_eq!(area(&path(&[(0.0, 0.0), (1.0, 1.0)])), 0.0);
    }

    #[test]
    fn a_rectangle_grows_by_delta_on_every_side_with_round_corners() {
        // Either orientation, as the detector's boxes come in both.
        for p in [
            path(&[(10.0, 10.0), (50.0, 10.0), (50.0, 20.0), (10.0, 20.0)]),
            path(&[(10.0, 10.0), (10.0, 20.0), (50.0, 20.0), (50.0, 10.0)]),
        ] {
            let out = inflate(p, 3.0);
            assert_eq!(out.len(), 1);
            let o = &out[0];
            assert_eq!(bounds(o), (7.0, 7.0, 53.0, 23.0));
            // Every point lies at distance delta from the rectangle (round corners), to
            // the 0.01 rounding.
            for q in o {
                let dx = (10.0 - q.x).max(q.x - 50.0).max(0.0);
                let dy = (10.0 - q.y).max(q.y - 20.0).max(0.0);
                assert!((dx.hypot(dy) - 3.0).abs() < 0.01, "{q:?}");
            }
            // Corners are arcs, not single points.
            assert!(o.len() > 12, "{}", o.len());
            assert!(area(o) > 0.0, "counter-clockwise");
            // The area is the rectangle's plus its perimeter times delta plus the circle.
            let want = 400.0 + 100.0 * 3.0 + std::f64::consts::PI * 9.0;
            assert!((area(o) - want).abs() < 0.5, "{}", area(o));
        }
    }

    #[test]
    fn a_rotated_box_keeps_its_shape() {
        let s = std::f64::consts::FRAC_1_SQRT_2;
        let p = path(&[
            (0.0, 0.0),
            (10.0 * s, 10.0 * s),
            (10.0 * s - 2.0 * s, 10.0 * s + 2.0 * s),
            (-2.0 * s, 2.0 * s),
        ]);
        let o = &inflate(p, 1.0)[0];
        let want = 20.0 + 24.0 + std::f64::consts::PI;
        assert!((area(o) - want).abs() < 0.3, "{}", area(o));
    }

    #[test]
    fn a_concave_outline_is_offset_as_its_hull() {
        let l = path(&[
            (0.0, 0.0),
            (10.0, 0.0),
            (10.0, 2.0),
            (2.0, 2.0),
            (2.0, 10.0),
            (0.0, 10.0),
        ]);
        let o = &inflate(l, 1.0)[0];
        assert_eq!(bounds(o), (-1.0, -1.0, 11.0, 11.0));
    }

    #[test]
    fn unsupported_or_hostile_input_gives_no_path_and_no_panic() {
        let sq = path(&[(0.0, 0.0), (1.0, 0.0), (1.0, 1.0), (0.0, 1.0)]);
        assert!(inflate(sq.clone(), -1.0).is_empty());
        assert!(inflate(sq.clone(), f64::NAN).is_empty());
        assert!(inflate(sq.clone(), f64::INFINITY).is_empty());
        assert_eq!(inflate(sq.clone(), 0.0), vec![sq.clone()]);
        let miter = inflate_paths_d(
            &vec![sq.clone()],
            1.0,
            JoinType::Miter,
            EndType::Polygon,
            2.0,
            2,
            0.0,
        );
        assert!(miter.is_empty());
        let open = inflate_paths_d(&vec![sq], 1.0, JoinType::Round, EndType::Butt, 2.0, 2, 0.0);
        assert!(open.is_empty());
        assert!(inflate(path(&[(0.0, 0.0), (f64::NAN, 1.0), (1.0, 1.0)]), 1.0).is_empty());
        assert!(inflate(path(&[(0.0, 0.0), (1.0, 1.0), (2.0, 2.0)]), 1.0).is_empty());
        assert!(inflate(path(&[(3.0, 3.0); 5]), 1.0).is_empty());
        assert!(inflate(PathD::new(), 1.0).is_empty());
        // Huge and tiny deltas stay bounded.
        let big = &inflate(path(&[(0.0, 0.0), (1.0, 0.0), (1.0, 1.0), (0.0, 1.0)]), 1e9)[0];
        assert!(big.len() <= 4 * 66);
        let tiny = inflate(
            path(&[(0.0, 0.0), (1.0, 0.0), (1.0, 1.0), (0.0, 1.0)]),
            1e-9,
        );
        assert!(tiny.iter().all(|p| p.len() <= 4 * 66));
    }
}
