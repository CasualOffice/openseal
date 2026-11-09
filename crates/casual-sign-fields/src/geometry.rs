//! Field geometry (docs/30 §4, ADR-019): displayed page space and PDF user space.
//!
//! Fields are stored in **displayed page space**: points, origin at the top-left of the
//! page as a viewer shows it, after the crop box clips it and `/Rotate` turns it
//! (docs/22 §6). Flattening needs PDF **user space**: origin at the bottom-left of the
//! unrotated media, y up, in units of `/UserUnit` / 72 inch. [`PageGeometry::to_user`]
//! and [`PageGeometry::to_displayed`] are that conversion and its inverse; the browser
//! runs the same code compiled to WASM, so the editor and the flattener cannot disagree.
//!
//! ```text
//! displayed (x, y) ─▶ ÷ UserUnit ─▶ undo /Rotate ─▶ flip y within the crop box ─▶ + crop origin
//! ```
//!
//! All arithmetic is `f64`: a round trip returns its input within 1e-6 pt for every
//! page up to the 14,400-point limit.

use casual_sign_model::{ModelError, Placement, Points};
use casual_sign_pdf::{PageInfo, Rect};
use rust_decimal::Decimal;

/// Decimal places a placement keeps when built from a computed rectangle (0.0001 pt).
pub const PLACEMENT_DECIMALS: u32 = 4;

/// A point, in whichever space the function that takes or returns it names.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct Point {
    /// Horizontal coordinate.
    pub x: f64,
    /// Vertical coordinate.
    pub y: f64,
}

impl Point {
    /// A point at `(x, y)`.
    #[must_use]
    pub const fn new(x: f64, y: f64) -> Self {
        Self { x, y }
    }
}

/// A rectangle in displayed page space: points, origin top-left, y down.
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub struct DisplayRect {
    /// Left edge.
    pub x: f64,
    /// Top edge.
    pub y: f64,
    /// Width, never negative.
    pub width: f64,
    /// Height, never negative.
    pub height: f64,
}

impl DisplayRect {
    /// The smallest rectangle holding every point; `None` when there are none or any is
    /// not finite.
    #[must_use]
    pub fn bounding(points: impl IntoIterator<Item = Point>) -> Option<Self> {
        let mut it = points.into_iter();
        let first = it.next()?;
        let (mut x0, mut y0, mut x1, mut y1) = (first.x, first.y, first.x, first.y);
        for p in it {
            x0 = x0.min(p.x);
            y0 = y0.min(p.y);
            x1 = x1.max(p.x);
            y1 = y1.max(p.y);
        }
        let r = Self {
            x: x0,
            y: y0,
            width: x1 - x0,
            height: y1 - y0,
        };
        r.is_finite().then_some(r)
    }

    /// The smallest rectangle holding both.
    #[must_use]
    pub fn union(&self, other: &Self) -> Self {
        let x0 = self.x.min(other.x);
        let y0 = self.y.min(other.y);
        let x1 = self.right().max(other.right());
        let y1 = self.bottom().max(other.bottom());
        Self {
            x: x0,
            y: y0,
            width: x1 - x0,
            height: y1 - y0,
        }
    }

    /// Right edge.
    #[must_use]
    pub fn right(&self) -> f64 {
        self.x + self.width
    }

    /// Bottom edge.
    #[must_use]
    pub fn bottom(&self) -> f64 {
        self.y + self.height
    }

    fn is_finite(&self) -> bool {
        self.x.is_finite()
            && self.y.is_finite()
            && self.width.is_finite()
            && self.height.is_finite()
    }

    /// A placement on 1-based `page`, each value rounded to [`PLACEMENT_DECIMALS`]
    /// places (`CS-FLD-0004` when it is negative, empty or beyond 14,400 points).
    ///
    /// # Errors
    ///
    /// [`ModelError::PlacementOutOfRange`] as [`Placement::new`].
    pub fn to_placement(&self, page: u32) -> Result<Placement, ModelError> {
        Placement::new(
            page,
            points(self.x)?,
            points(self.y)?,
            points(self.width)?,
            points(self.height)?,
        )
    }

    /// The rectangle of a placement.
    #[must_use]
    pub fn from_placement(p: &Placement) -> Self {
        Self {
            x: to_f64(p.x().get()),
            y: to_f64(p.y().get()),
            width: to_f64(p.width().get()),
            height: to_f64(p.height().get()),
        }
    }
}

fn points(v: f64) -> Result<Points, ModelError> {
    let d = Decimal::try_from(v)
        .map_err(|_| ModelError::PlacementOutOfRange)?
        .round_dp(PLACEMENT_DECIMALS);
    // -0.0001 rounds to "-0", which is zero.
    Points::new(if d.is_zero() { Decimal::ZERO } else { d })
}

fn to_f64(d: Decimal) -> f64 {
    // A `Points` value is within 0..=14,400 with at most 28 digits: always representable.
    f64::try_from(d).unwrap_or(0.0)
}

/// What the conversion needs to know about a page: its crop box (in user space), its
/// rotation and its user unit.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PageGeometry {
    crop: Rect,
    rotate: u16,
    user_unit: f64,
}

impl PageGeometry {
    /// Geometry from a crop box, `/Rotate` and `/UserUnit`. The rotation is normalized
    /// to 0, 90, 180 or 270 (a value that is not a multiple of 90 counts as 0, as
    /// viewers do); a user unit that is not a positive finite number counts as 1; the
    /// box's corners are put in order.
    #[must_use]
    pub fn new(crop_box: Rect, rotate: i64, user_unit: f64) -> Self {
        let r = rotate.rem_euclid(360);
        let rotate = match r {
            90 => 90,
            180 => 180,
            270 => 270,
            _ => 0,
        };
        let user_unit = if user_unit.is_finite() && user_unit > 0.0 {
            user_unit
        } else {
            1.0
        };
        let crop = Rect {
            llx: crop_box.llx.min(crop_box.urx),
            lly: crop_box.lly.min(crop_box.ury),
            urx: crop_box.llx.max(crop_box.urx),
            ury: crop_box.lly.max(crop_box.ury),
        };
        Self {
            crop,
            rotate,
            user_unit,
        }
    }

    /// The geometry of an admitted page.
    #[must_use]
    pub fn from_page(page: &PageInfo) -> Self {
        Self::new(page.crop_box, i64::from(page.rotate), page.user_unit)
    }

    /// The crop box, in user space.
    #[must_use]
    pub fn crop_box(&self) -> Rect {
        self.crop
    }

    /// `/Rotate`: 0, 90, 180 or 270.
    #[must_use]
    pub fn rotate(&self) -> u16 {
        self.rotate
    }

    /// `/UserUnit`.
    #[must_use]
    pub fn user_unit(&self) -> f64 {
        self.user_unit
    }

    /// Width and height of the page as displayed, in points.
    #[must_use]
    pub fn displayed_size(&self) -> (f64, f64) {
        let w = (self.crop.urx - self.crop.llx) * self.user_unit;
        let h = (self.crop.ury - self.crop.lly) * self.user_unit;
        if self.rotate == 90 || self.rotate == 270 {
            (h, w)
        } else {
            (w, h)
        }
    }

    /// A point in displayed page space (points, top-left origin) to PDF user space.
    #[must_use]
    pub fn to_user(&self, p: Point) -> Point {
        let w = self.crop.urx - self.crop.llx;
        let h = self.crop.ury - self.crop.lly;
        // Back to user units, still displayed orientation.
        let dx = p.x / self.user_unit;
        let dy = p.y / self.user_unit;
        // Undo the clockwise rotation: (px, py) is top-left based, y down, unrotated.
        let (px, py) = match self.rotate {
            90 => (dy, h - dx),
            180 => (w - dx, h - dy),
            270 => (w - dy, dx),
            _ => (dx, dy),
        };
        Point::new(self.crop.llx + px, self.crop.ury - py)
    }

    /// A point in PDF user space to displayed page space (points, top-left origin).
    #[must_use]
    pub fn to_displayed(&self, p: Point) -> Point {
        let w = self.crop.urx - self.crop.llx;
        let h = self.crop.ury - self.crop.lly;
        let px = p.x - self.crop.llx;
        let py = self.crop.ury - p.y;
        // Rotate clockwise by `/Rotate` within the crop box.
        let (dx, dy) = match self.rotate {
            90 => (h - py, px),
            180 => (w - px, h - py),
            270 => (py, w - px),
            _ => (px, py),
        };
        Point::new(dx * self.user_unit, dy * self.user_unit)
    }

    /// A displayed rectangle to the user-space rectangle that covers the same area.
    #[must_use]
    pub fn rect_to_user(&self, r: &DisplayRect) -> Rect {
        let a = self.to_user(Point::new(r.x, r.y));
        let b = self.to_user(Point::new(r.right(), r.bottom()));
        Rect {
            llx: a.x.min(b.x),
            lly: a.y.min(b.y),
            urx: a.x.max(b.x),
            ury: a.y.max(b.y),
        }
    }

    /// A user-space rectangle to the displayed rectangle that covers the same area.
    #[must_use]
    pub fn rect_to_displayed(&self, r: &Rect) -> DisplayRect {
        let a = self.to_displayed(Point::new(r.llx, r.lly));
        let b = self.to_displayed(Point::new(r.urx, r.ury));
        let x = a.x.min(b.x);
        let y = a.y.min(b.y);
        DisplayRect {
            x,
            y,
            width: a.x.max(b.x) - x,
            height: a.y.max(b.y) - y,
        }
    }

    /// True when the rectangle lies on the displayed page, allowing `slack` points.
    #[must_use]
    pub fn contains(&self, r: &DisplayRect, slack: f64) -> bool {
        let (w, h) = self.displayed_size();
        r.x >= -slack && r.y >= -slack && r.right() <= w + slack && r.bottom() <= h + slack
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn geom(rotate: i64) -> PageGeometry {
        PageGeometry::new(
            Rect {
                llx: 10.0,
                lly: 20.0,
                urx: 210.0,
                ury: 320.0,
            },
            rotate,
            2.0,
        )
    }

    #[test]
    fn top_left_of_the_displayed_page_is_the_right_crop_corner_for_each_rotation() {
        // Displayed (0, 0) is the corner that ends top-left after a clockwise turn.
        let cases = [
            (0, Point::new(10.0, 320.0)),
            (90, Point::new(10.0, 20.0)),
            (180, Point::new(210.0, 20.0)),
            (270, Point::new(210.0, 320.0)),
        ];
        for (rot, want) in cases {
            assert_eq!(
                geom(rot).to_user(Point::new(0.0, 0.0)),
                want,
                "rotate {rot}"
            );
        }
    }

    #[test]
    fn displayed_size_swaps_on_quarter_turns_and_scales_by_user_unit() {
        assert_eq!(geom(0).displayed_size(), (400.0, 600.0));
        assert_eq!(geom(90).displayed_size(), (600.0, 400.0));
        assert_eq!(geom(-90).rotate(), 270);
        assert_eq!(geom(45).rotate(), 0);
    }

    #[test]
    fn placement_rounds_and_refuses_negative() {
        let r = DisplayRect {
            x: 1.000_04,
            y: 2.0,
            width: 3.0,
            height: 4.0,
        };
        let p = r.to_placement(1).ok();
        assert_eq!(p.map(|p| p.x().get().to_string()), Some("1".to_string()));
        let bad = DisplayRect { x: -1.0, ..r };
        assert!(bad.to_placement(1).is_err());
        let nan = DisplayRect { x: f64::NAN, ..r };
        assert!(nan.to_placement(1).is_err());
    }
}
