//! The faces text is measured and drawn with: supplied bytes only, never a system font
//! (the `openseal-pdf` rule). XFA typefaces map onto three families (Sans, Serif,
//! Mono, [`crate::props::family`]); bold is drawn by stroking the glyph outline and
//! italic by shearing, since only regular faces are bundled.

use std::borrow::Cow;
use std::collections::BTreeMap;

use skrifa::instance::{LocationRef, Size};
use skrifa::metrics::GlyphMetrics;
use skrifa::{FontRef, MetadataProvider};

use crate::error::XfaError;
use crate::props::Family;

/// Which family a supplied face serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum FaceRole {
    /// Sans-serif: Arial, Helvetica, Myriad and unknown faces (Liberation Sans).
    Sans,
    /// Serif: Times and other serif faces (Liberation Serif).
    Serif,
    /// Monospaced: Courier and OCR faces (Liberation Mono).
    Mono,
}

/// The faces a layout draws with, as TrueType bytes (outlines in `glyf`).
#[derive(Debug, Clone, Default)]
pub struct Faces {
    faces: Vec<(FaceRole, String, Cow<'static, [u8]>)>,
}

impl Faces {
    /// No faces.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a face for `role`. `name` becomes its `/BaseFont` after the subset tag,
    /// reduced to ASCII letters, digits and hyphens.
    ///
    /// # Errors
    ///
    /// `CS-XFA-0010` when the bytes are not a TrueType face with outlines in `glyf`.
    pub fn add(
        &mut self,
        role: FaceRole,
        name: &str,
        bytes: impl Into<Cow<'static, [u8]>>,
    ) -> Result<(), XfaError> {
        let bytes = bytes.into();
        if FontRef::new(&bytes).is_err() || crate::subset::subset(&bytes, [0]).is_none() {
            return Err(XfaError::NoFont);
        }
        let name: String = name
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
            .take(48)
            .collect();
        self.faces.push((role, name, bytes));
        Ok(())
    }

    /// Liberation Sans, Serif and Mono (SIL OFL 1.1), the faces casual-sign-flatten
    /// bundles, compiled in from that crate's `fonts/` folder.
    #[cfg(feature = "bundled-fonts")]
    #[must_use]
    pub fn bundled() -> Self {
        let mut set = Self::new();
        let faces: [(FaceRole, &str, &'static [u8]); 3] = [
            (
                FaceRole::Sans,
                "LiberationSans",
                include_bytes!(
                    "../../casual-sign-flatten/fonts/liberation/LiberationSans-Regular.ttf"
                ),
            ),
            (
                FaceRole::Serif,
                "LiberationSerif",
                include_bytes!(
                    "../../casual-sign-flatten/fonts/liberation/LiberationSerif-Regular.ttf"
                ),
            ),
            (
                FaceRole::Mono,
                "LiberationMono",
                include_bytes!(
                    "../../casual-sign-flatten/fonts/liberation/LiberationMono-Regular.ttf"
                ),
            ),
        ];
        for (role, name, bytes) in faces {
            // A test checks the bundled faces load; one that did not would only be
            // missing, and its text would fall back to another face.
            let _ = set.add(role, name, bytes);
        }
        set
    }

    /// Number of faces.
    #[must_use]
    pub fn len(&self) -> usize {
        self.faces.len()
    }

    /// True when there is no face.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.faces.is_empty()
    }
}

/// A glyph: face index, glyph id, advance in thousandths of an em.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct Glyph {
    pub face: usize,
    pub gid: u16,
    pub adv: f64,
}

/// Vertical metrics in thousandths of an em.
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct VMetrics {
    pub ascent: f64,
    pub descent: f64,
    pub gap: f64,
    pub cap_height: f64,
    pub bbox: [f64; 4],
    pub italic_angle: f64,
    pub monospace: bool,
}

pub(crate) struct Face<'a> {
    pub role: FaceRole,
    pub name: &'a str,
    pub bytes: &'a [u8],
    pub metrics: VMetrics,
    font: FontRef<'a>,
    glyph_metrics: GlyphMetrics<'a>,
    upem: f64,
}

/// Prepared faces with a glyph cache.
pub(crate) struct Fonts<'a> {
    pub faces: Vec<Face<'a>>,
    cache: BTreeMap<(usize, char), Option<Glyph>>,
}

impl std::fmt::Debug for Fonts<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Fonts")
            .field("faces", &self.faces.len())
            .finish()
    }
}

impl<'a> Fonts<'a> {
    pub(crate) fn new(set: &'a Faces) -> Result<Self, XfaError> {
        let mut faces = Vec::new();
        for (role, name, bytes) in &set.faces {
            let Ok(font) = FontRef::new(bytes) else {
                continue;
            };
            let m = font.metrics(Size::unscaled(), LocationRef::default());
            let upem = f64::from(m.units_per_em);
            if upem <= 0.0 {
                continue;
            }
            let k = |v: f32| (f64::from(v) * 1000.0 / upem).round();
            let bbox = m.bounds.map_or([0.0, -250.0, 1000.0, 950.0], |b| {
                [k(b.x_min), k(b.y_min), k(b.x_max), k(b.y_max)]
            });
            faces.push(Face {
                role: *role,
                name,
                bytes,
                metrics: VMetrics {
                    ascent: k(m.ascent),
                    descent: k(m.descent),
                    gap: k(m.leading).max(0.0),
                    cap_height: k(m.cap_height.unwrap_or(m.ascent)),
                    bbox,
                    italic_angle: f64::from(m.italic_angle),
                    monospace: m.is_monospace,
                },
                glyph_metrics: font.glyph_metrics(Size::unscaled(), LocationRef::default()),
                font,
                upem,
            });
        }
        if faces.is_empty() {
            return Err(XfaError::NoFont);
        }
        Ok(Self {
            faces,
            cache: BTreeMap::new(),
        })
    }

    /// The face for a family: the first face of its role, else the first face.
    pub(crate) fn preferred(&self, family: Family) -> usize {
        let role = match family {
            Family::Sans => FaceRole::Sans,
            Family::Serif => FaceRole::Serif,
            Family::Mono => FaceRole::Mono,
        };
        self.faces.iter().position(|f| f.role == role).unwrap_or(0)
    }

    pub(crate) fn metrics(&self, face: usize) -> VMetrics {
        self.faces.get(face).map_or(
            VMetrics {
                ascent: 800.0,
                descent: -200.0,
                gap: 0.0,
                cap_height: 700.0,
                bbox: [0.0, -200.0, 1000.0, 800.0],
                italic_angle: 0.0,
                monospace: false,
            },
            |f| f.metrics,
        )
    }

    fn lookup(&mut self, face: usize, c: char) -> Option<Glyph> {
        if let Some(g) = self.cache.get(&(face, c)) {
            return *g;
        }
        let g = self.faces.get(face).and_then(|f| {
            let gid = f.font.charmap().map(c)?;
            let id = u16::try_from(gid.to_u32()).ok().filter(|i| *i != 0)?;
            let adv = f.glyph_metrics.advance_width(gid).unwrap_or(0.0);
            Some(Glyph {
                face,
                gid: id,
                adv: (f64::from(adv) * 1000.0 / f.upem).round(),
            })
        });
        self.cache.insert((face, c), g);
        g
    }

    /// The glyph for `c` in the preferred face, else in another, else `None`.
    pub(crate) fn glyph(&mut self, preferred: usize, c: char) -> Option<Glyph> {
        if let Some(g) = self.lookup(preferred, c) {
            return Some(g);
        }
        for i in 0..self.faces.len() {
            if i != preferred
                && let Some(g) = self.lookup(i, c)
            {
                return Some(g);
            }
        }
        None
    }
}

#[cfg(all(test, feature = "bundled-fonts"))]
mod tests {
    // Test code: a panic is the failure report (CLAUDE.md).
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn bundled_faces_load_and_measure() {
        let set = Faces::bundled();
        assert_eq!(set.len(), 3);
        let mut fonts = Fonts::new(&set).unwrap();
        let sans = fonts.preferred(Family::Sans);
        // Liberation Sans is metric-compatible with Arial: "A" advances 667/1000.
        assert_eq!(fonts.glyph(sans, 'A').unwrap().adv, 667.0);
        let mono = fonts.preferred(Family::Mono);
        assert_eq!(fonts.glyph(mono, 'i').unwrap().adv, 600.0);
        assert!(fonts.glyph(sans, '\u{10FFFD}').is_none());
    }

    #[test]
    fn a_face_that_is_not_truetype_is_refused() {
        let mut set = Faces::new();
        assert_eq!(
            set.add(FaceRole::Sans, "x", b"not a font".to_vec())
                .unwrap_err(),
            XfaError::NoFont
        );
        assert!(Fonts::new(&set).is_err());
    }
}
