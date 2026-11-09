//! Field geometry (docs/30 §4, ADR-019): every rotation × crop origin × UserUnit, read
//! from tiny PDFs through the reader, and a round-trip property.

// Tests may unwrap, index and panic (CLAUDE.md): a failure here is the test failing.
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::expect_used,
    clippy::panic
)]

mod pdf;

use casual_sign_fields::{DisplayRect, PageGeometry, Point};
use casual_sign_pdf::{Limits, Rect, admit};
use pdf::{never, one_page};
use proptest::prelude::*;

const ROTATIONS: [u16; 4] = [0, 90, 180, 270];
const CROPS: [(f64, f64); 3] = [(0.0, 0.0), (30.0, 45.0), (-20.5, 12.25)];
const UNITS: [f64; 3] = [1.0, 2.5, 0.75];

fn page(rotate: u16, crop: (f64, f64), unit: f64) -> PageGeometry {
    let bytes = one_page(
        "",
        &format!(
            "/Rotate {rotate}/UserUnit {unit}/CropBox[{} {} {} {}]/MediaBox[-100 -100 900 900]",
            crop.0,
            crop.1,
            crop.0 + 400.0,
            crop.1 + 500.0
        ),
        "",
        b"",
        vec![],
    );
    let a = admit(&bytes, &Limits::default(), &never).unwrap();
    let info = a.report.pages[0];
    assert_eq!(info.rotate, rotate);
    assert_eq!(info.user_unit, unit);
    PageGeometry::from_page(&info)
}

#[track_caller]
fn near(a: Point, b: Point) {
    assert!(
        (a.x - b.x).abs() < 1e-9 && (a.y - b.y).abs() < 1e-9,
        "{a:?} != {b:?}"
    );
}

#[test]
fn every_rotation_crop_origin_and_user_unit_maps_corners_and_axes() {
    for rot in ROTATIONS {
        for crop in CROPS {
            for unit in UNITS {
                let g = page(rot, crop, unit);
                let (w, h) = (400.0 * unit, 500.0 * unit);
                let size = if rot % 180 == 0 { (w, h) } else { (h, w) };
                assert_eq!(
                    g.displayed_size(),
                    size,
                    "rot {rot} crop {crop:?} unit {unit}"
                );
                let (x0, y0, x1, y1) = (crop.0, crop.1, crop.0 + 400.0, crop.1 + 500.0);
                // The user-space corner shown at the top-left after a clockwise turn,
                // and the one diagonally opposite at the bottom-right.
                let (tl, br) = match rot {
                    0 => ((x0, y1), (x1, y0)),
                    90 => ((x0, y0), (x1, y1)),
                    180 => ((x1, y0), (x0, y1)),
                    _ => ((x1, y1), (x0, y0)),
                };
                near(g.to_displayed(Point::new(tl.0, tl.1)), Point::new(0.0, 0.0));
                near(
                    g.to_displayed(Point::new(br.0, br.1)),
                    Point::new(size.0, size.1),
                );
                near(g.to_user(Point::new(0.0, 0.0)), Point::new(tl.0, tl.1));
                // Where one user unit along +x and +y goes on the displayed page.
                let (ux, uy) = match rot {
                    0 => ((1.0, 0.0), (0.0, -1.0)),
                    90 => ((0.0, 1.0), (1.0, 0.0)),
                    180 => ((-1.0, 0.0), (0.0, 1.0)),
                    _ => ((0.0, -1.0), (-1.0, 0.0)),
                };
                let o = g.to_displayed(Point::new(x0 + 10.0, y0 + 10.0));
                let px = g.to_displayed(Point::new(x0 + 11.0, y0 + 10.0));
                let py = g.to_displayed(Point::new(x0 + 10.0, y0 + 11.0));
                near(
                    Point::new(px.x - o.x, px.y - o.y),
                    Point::new(ux.0 * unit, ux.1 * unit),
                );
                near(
                    Point::new(py.x - o.x, py.y - o.y),
                    Point::new(uy.0 * unit, uy.1 * unit),
                );
                // A rectangle maps to one covering the same area, and back.
                let r = DisplayRect {
                    x: 12.5,
                    y: 30.0,
                    width: 100.0,
                    height: 20.0,
                };
                let u = g.rect_to_user(&r);
                assert!(((u.urx - u.llx) * (u.ury - u.lly) * unit * unit - 2000.0).abs() < 1e-6);
                let back = g.rect_to_displayed(&u);
                assert!((back.x - r.x).abs() < 1e-9 && (back.height - r.height).abs() < 1e-9);
            }
        }
    }
}

#[test]
fn a_box_given_upside_down_is_put_in_order() {
    let g = PageGeometry::new(
        Rect {
            llx: 100.0,
            lly: 200.0,
            urx: 0.0,
            ury: 0.0,
        },
        -270,
        f64::NAN,
    );
    assert_eq!(g.rotate(), 90);
    assert_eq!(g.user_unit(), 1.0);
    assert_eq!(g.displayed_size(), (200.0, 100.0));
}

fn geometry() -> impl Strategy<Value = PageGeometry> {
    (
        0usize..4,
        -1000.0f64..1000.0,
        -1000.0f64..1000.0,
        1.0f64..1440.0,
        1.0f64..1440.0,
        prop::sample::select(vec![1.0, 0.5, 2.0, 2.5, 7.2, 10.0]),
    )
        .prop_map(|(r, x, y, w, h, u)| {
            PageGeometry::new(
                Rect {
                    llx: x,
                    lly: y,
                    urx: x + w,
                    ury: y + h,
                },
                i64::from(ROTATIONS[r]),
                u,
            )
        })
}

/// A decimal with at most four places, as a placement holds.
fn decimal(max: f64) -> impl Strategy<Value = f64> {
    (0u64..=((max * 10_000.0) as u64)).prop_map(|v| v as f64 / 10_000.0)
}

proptest! {
    #[test]
    fn displayed_to_user_and_back_is_exact_within_a_millionth_of_a_point(
        g in geometry(), fx in 0.0f64..=1.0, fy in 0.0f64..=1.0, x in decimal(14_400.0), y in decimal(14_400.0)
    ) {
        let (w, h) = g.displayed_size();
        // A point on the page, and a decimal one anywhere in the field range.
        for p in [Point::new(fx * w, fy * h), Point::new(x, y)] {
            let back = g.to_displayed(g.to_user(p));
            prop_assert!((back.x - p.x).abs() <= 1e-6 && (back.y - p.y).abs() <= 1e-6, "{p:?} -> {back:?}");
        }
    }

    #[test]
    fn rectangles_round_trip(g in geometry(), x in decimal(1000.0), y in decimal(1000.0), w in decimal(500.0), h in decimal(500.0)) {
        let r = DisplayRect { x, y, width: w, height: h };
        let back = g.rect_to_displayed(&g.rect_to_user(&r));
        prop_assert!((back.x - r.x).abs() <= 1e-6 && (back.y - r.y).abs() <= 1e-6);
        prop_assert!((back.width - r.width).abs() <= 1e-6 && (back.height - r.height).abs() <= 1e-6);
        if w > 0.0 && h > 0.0 && x + w <= 14_400.0 && y + h <= 14_400.0 {
            let p = back.to_placement(1).unwrap();
            let q = DisplayRect::from_placement(&p);
            prop_assert!((q.x - r.x).abs() <= 1e-9 && (q.width - r.width).abs() <= 1e-9);
            prop_assert!((q.y - r.y).abs() <= 1e-9 && (q.height - r.height).abs() <= 1e-9);
        }
    }
}
