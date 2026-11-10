//! The faces text is drawn in: supplied bytes only, never a system font (docs/30 §7,
//! the `openseal-pdf` rule "no reference to a system font").
//!
//! A [`FontSet`] holds TrueType faces by role. A field's family picks the first face of
//! its role; a character that face lacks falls back to the other text faces in the
//! order they were added, and a character no face has is `CS-FLT-0001`.

use std::borrow::Cow;

use casual_sign_model::FontFamily;
use skrifa::instance::{LocationRef, Size};
use skrifa::{FontRef, MetadataProvider};

use crate::error::FlattenError;

/// What a face is used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Role {
    /// Sans-serif text (Helvetica's metric twin: Liberation Sans).
    Sans,
    /// Serif text (Times: Liberation Serif).
    Serif,
    /// Monospaced text (Courier: Liberation Mono).
    Mono,
    /// A handwriting face for typed signatures and initials.
    Script,
}

/// Metrics of a face, in thousandths of an em (PDF glyph space).
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct FaceMetrics {
    pub ascent: f64,
    pub descent: f64,
    pub cap_height: f64,
    pub bbox: [f64; 4],
    pub italic_angle: f64,
    pub monospace: bool,
}

/// One face: its role, a PostScript-safe name and its bytes.
#[derive(Debug, Clone)]
pub(crate) struct Face {
    pub role: Role,
    pub name: String,
    pub bytes: Cow<'static, [u8]>,
    pub metrics: FaceMetrics,
    upem: f64,
}

impl Face {
    /// The glyph for `c` and its advance in thousandths of an em, rounded as `/W`
    /// writes it, or `None` when the face has no glyph for it.
    pub(crate) fn glyph(&self, c: char) -> Option<(u16, f64)> {
        let font = FontRef::new(&self.bytes).ok()?;
        let gid = font.charmap().map(c)?;
        let id = u16::try_from(gid.to_u32()).ok()?;
        if id == 0 {
            return None;
        }
        let adv = font
            .glyph_metrics(Size::unscaled(), LocationRef::default())
            .advance_width(gid)
            .unwrap_or(0.0);
        Some((id, (f64::from(adv) * 1000.0 / self.upem).round()))
    }
}

/// The faces available to flattening, by role (docs/30 §7).
///
/// Faces are supplied as bytes, so the crate builds for `wasm32-unknown-unknown` and
/// never looks up a font on the host. [`FontSet::bundled`] gives the faces in this
/// crate's `fonts/` folder.
#[derive(Debug, Clone, Default)]
pub struct FontSet {
    faces: Vec<Face>,
}

/// A name usable after `/` in a PDF: ASCII letters, digits and hyphens.
fn ps_name(name: &str) -> String {
    let s: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .take(48)
        .collect();
    if s.is_empty() { "Face".to_owned() } else { s }
}

impl FontSet {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a face. `name` becomes the font's `/BaseFont` (after the subset tag), reduced
    /// to ASCII letters, digits and hyphens. Returns the face's index.
    ///
    /// # Errors
    ///
    /// `CS-FLT-0005` when the bytes are not a TrueType-flavoured face with outlines in
    /// `glyf` (the only kind this crate subsets and embeds as `/FontFile2`).
    pub fn add(
        &mut self,
        role: Role,
        name: &str,
        bytes: impl Into<Cow<'static, [u8]>>,
    ) -> Result<usize, FlattenError> {
        let bytes = bytes.into();
        let index = self.faces.len();
        let bad = FlattenError::FontUnreadable { face: index };
        if crate::subset::subset(&bytes, [0]).is_none() {
            return Err(bad);
        }
        let font = FontRef::new(&bytes).map_err(|_| bad.clone())?;
        let m = font.metrics(Size::unscaled(), LocationRef::default());
        let upem = f64::from(m.units_per_em);
        if upem <= 0.0 {
            return Err(bad);
        }
        let k = |v: f32| (f64::from(v) * 1000.0 / upem).round();
        let bounds = m.bounds.map_or([0.0, -250.0, 1000.0, 950.0], |b| {
            [k(b.x_min), k(b.y_min), k(b.x_max), k(b.y_max)]
        });
        let metrics = FaceMetrics {
            ascent: k(m.ascent),
            descent: k(m.descent),
            cap_height: k(m.cap_height.unwrap_or(m.ascent)),
            bbox: bounds,
            italic_angle: f64::from(m.italic_angle),
            monospace: m.is_monospace,
        };
        self.faces.push(Face {
            role,
            name: ps_name(name),
            bytes,
            metrics,
            upem,
        });
        Ok(index)
    }

    /// The faces bundled in this crate: Liberation Sans, Serif and Mono (Helvetica,
    /// Times and Courier metrics) and the script faces Great Vibes and Allura, all
    /// SIL OFL 1.1 (fonts/PROVENANCE.md).
    #[cfg(feature = "bundled-fonts")]
    #[must_use]
    pub fn bundled() -> Self {
        let mut set = Self::new();
        let faces: [(Role, &str, &'static [u8]); 5] = [
            (
                Role::Sans,
                "LiberationSans",
                include_bytes!("../fonts/liberation/LiberationSans-Regular.ttf"),
            ),
            (
                Role::Serif,
                "LiberationSerif",
                include_bytes!("../fonts/liberation/LiberationSerif-Regular.ttf"),
            ),
            (
                Role::Mono,
                "LiberationMono",
                include_bytes!("../fonts/liberation/LiberationMono-Regular.ttf"),
            ),
            (
                Role::Script,
                "GreatVibes-Regular",
                include_bytes!("../fonts/script/GreatVibes-Regular.ttf"),
            ),
            (
                Role::Script,
                "Allura-Regular",
                include_bytes!("../fonts/script/Allura-Regular.ttf"),
            ),
        ];
        for (role, name, bytes) in faces {
            // The bundled faces are checked by a test; one that failed would only be
            // missing from the set, and its text would fall back or be CS-FLT-0001.
            let _ = set.add(role, name, bytes);
        }
        set
    }

    /// Number of faces.
    #[must_use]
    pub fn len(&self) -> usize {
        self.faces.len()
    }

    /// True when the set has no face.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.faces.is_empty()
    }

    /// Number of script faces (typed-signature styles).
    #[must_use]
    pub fn script_styles(&self) -> usize {
        self.faces.iter().filter(|f| f.role == Role::Script).count()
    }

    pub(crate) fn face(&self, index: usize) -> Option<&Face> {
        self.faces.get(index)
    }

    /// The index of the first face of `role`.
    fn first(&self, role: Role) -> Option<usize> {
        self.faces.iter().position(|f| f.role == role)
    }

    /// The face a family draws in: Helvetica → Sans, Times → Serif, Courier → Mono,
    /// else the first text face.
    pub(crate) fn for_family(&self, family: FontFamily) -> Option<usize> {
        let role = match family {
            FontFamily::Times => Role::Serif,
            FontFamily::Courier => Role::Mono,
            _ => Role::Sans,
        };
        self.first(role).or_else(|| self.text_faces().next())
    }

    /// The `n`th script face (wrapping), or the first text face when there is none.
    pub(crate) fn script(&self, n: usize) -> Option<usize> {
        let scripts: Vec<usize> = self
            .faces
            .iter()
            .enumerate()
            .filter(|(_, f)| f.role == Role::Script)
            .map(|(i, _)| i)
            .collect();
        match scripts.len() {
            0 => self.text_faces().next(),
            len => scripts.get(n.checked_rem(len).unwrap_or(0)).copied(),
        }
    }

    fn text_faces(&self) -> impl Iterator<Item = usize> + '_ {
        self.faces
            .iter()
            .enumerate()
            .filter(|(_, f)| f.role != Role::Script)
            .map(|(i, _)| i)
    }

    /// The face that draws `c`, preferring `preferred`, then the text faces in order;
    /// with its glyph id and advance.
    pub(crate) fn resolve(&self, preferred: usize, c: char) -> Option<(usize, u16, f64)> {
        let first = self
            .faces
            .get(preferred)
            .and_then(|f| f.glyph(c))
            .map(|(g, a)| (preferred, g, a));
        first.or_else(|| {
            self.text_faces()
                .filter(|&i| i != preferred)
                .find_map(|i| self.faces.get(i)?.glyph(c).map(|(g, a)| (i, g, a)))
        })
    }
}

#[cfg(all(test, feature = "bundled-fonts"))]
mod tests {
    // Test code: a panic is the failure report (CLAUDE.md).
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn every_bundled_face_loads_and_maps_latin() {
        let set = FontSet::bundled();
        assert_eq!(set.len(), 5);
        assert_eq!(set.script_styles(), 2);
        for i in 0..set.len() {
            let f = set.face(i).unwrap();
            assert!(f.glyph('A').is_some(), "{}", f.name);
        }
    }

    #[test]
    fn families_map_to_their_liberation_twins_and_fall_back() {
        let set = FontSet::bundled();
        let sans = set.for_family(FontFamily::Helvetica).unwrap();
        let mono = set.for_family(FontFamily::Courier).unwrap();
        assert_eq!(set.face(sans).unwrap().name, "LiberationSans");
        assert_eq!(set.face(mono).unwrap().name, "LiberationMono");
        // Courier's advances are all 600.
        assert_eq!(set.resolve(mono, 'i').unwrap().2, 600.0);
        // No bundled face draws a CJK ideograph.
        assert!(set.resolve(sans, '漢').is_none());
    }

    #[test]
    fn a_face_that_is_not_truetype_is_refused() {
        let mut set = FontSet::new();
        let e = set.add(Role::Sans, "x", &b"OTTO0000"[..]).unwrap_err();
        assert_eq!(e.code(), "CS-FLT-0005");
    }
}
