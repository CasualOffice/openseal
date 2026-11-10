//! Objects the update adds: embedded subset fonts, images and form XObjects.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use casual_sign_pdf::{Dictionary, IncrementalUpdate, ObjRef, Object, WriteError};

use crate::EmbeddedFont;
use crate::canvas::{Canvas, GlyphUse, num};
use crate::fonts::FontSet;
use crate::image::{Image, deflate};

pub(crate) fn name(s: &[u8]) -> Object {
    Object::Name(s.to_vec())
}

pub(crate) fn int(v: impl TryInto<i64>) -> Object {
    Object::Integer(v.try_into().unwrap_or(0))
}

pub(crate) fn real(v: f64) -> Object {
    // Written through `num` so the serializer never sees an exponent.
    let s = num(v);
    match s.parse::<i64>() {
        Ok(i) => Object::Integer(i),
        Err(_) => Object::Real(s.parse().unwrap_or(0.0)),
    }
}

fn reference(r: ObjRef) -> Object {
    Object::Reference(r)
}

/// A deterministic six-letter subset tag from the face and its glyph ids (FNV-1a), so
/// two subsets of one face in one file carry different names (ISO 32000-2 §9.9.2).
fn tag(face: usize, gids: impl Iterator<Item = u16>) -> String {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    let mut eat = |b: u8| {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    };
    for b in face.to_be_bytes() {
        eat(b);
    }
    for g in gids {
        for b in g.to_be_bytes() {
            eat(b);
        }
    }
    let mut s = String::with_capacity(6);
    for _ in 0..6 {
        let letter = u8::try_from(h % 26).unwrap_or(0);
        s.push(char::from(b'A'.saturating_add(letter)));
        h /= 26;
    }
    s
}

/// The `ToUnicode` CMap: what each glyph id means (from OpenPresent's `pdf.rs`).
fn to_unicode(used: &BTreeMap<u16, String>) -> String {
    let mut out = String::from(
        "/CIDInit /ProcSet findresource begin\n12 dict begin\nbegincmap\n\
         /CIDSystemInfo << /Registry (Adobe) /Ordering (UCS) /Supplement 0 >> def\n\
         /CMapName /Adobe-Identity-UCS def\n/CMapType 2 def\n\
         1 begincodespacerange\n<0000> <FFFF>\nendcodespacerange\n",
    );
    let entries: Vec<(u16, &str)> = used
        .iter()
        .filter(|(_, t)| !t.is_empty())
        .map(|(&g, t)| (g, t.as_str()))
        .collect();
    // `bfchar` blocks hold at most 100 entries.
    for chunk in entries.chunks(100) {
        let _ = writeln!(out, "{} beginbfchar", chunk.len());
        for (gid, text) in chunk {
            let mut utf16 = String::new();
            for unit in text.encode_utf16() {
                let _ = write!(utf16, "{unit:04X}");
            }
            let _ = writeln!(out, "<{gid:04X}> <{utf16}>");
        }
        out.push_str("endbfchar\n");
    }
    out.push_str("endcmap\nCMapName currentdict /CMap defineresource pop\nend\nend\n");
    out
}

fn flate_stream(
    u: &mut IncrementalUpdate<'_>,
    mut dict: Dictionary,
    data: &[u8],
) -> Result<ObjRef, WriteError> {
    dict.insert(b"Filter", name(b"FlateDecode"));
    u.add_stream(dict, deflate(data))
}

/// Embed each face that drew a glyph as a Type0 font over a TrueType subset.
pub(crate) fn fonts(
    u: &mut IncrementalUpdate<'_>,
    set: &FontSet,
    uses: &GlyphUse,
    report: &mut Vec<EmbeddedFont>,
) -> Result<BTreeMap<usize, ObjRef>, WriteError> {
    let mut out = BTreeMap::new();
    for (&index, used) in &uses.faces {
        let Some(face) = set.face(index) else {
            continue;
        };
        let program = crate::subset::subset(&face.bytes, used.keys().map(|g| u32::from(*g)))
            .unwrap_or_else(|| face.bytes.to_vec());
        let base = format!("{}+{}", tag(index, used.keys().copied()), face.name);
        let mut fd = Dictionary::new();
        fd.insert(b"Length1", int(program.len()));
        let file = flate_stream(u, fd, &program)?;
        let m = face.metrics;
        let mut flags: i64 = 4;
        if m.monospace {
            flags |= 1;
        }
        if m.italic_angle != 0.0 {
            flags |= 64;
        }
        let mut desc = Dictionary::new();
        desc.insert(b"Type", name(b"FontDescriptor"));
        desc.insert(b"FontName", name(base.as_bytes()));
        desc.insert(b"Flags", int(flags));
        desc.insert(
            b"FontBBox",
            Object::Array(m.bbox.iter().map(|v| real(*v)).collect()),
        );
        desc.insert(b"ItalicAngle", real(m.italic_angle));
        desc.insert(b"Ascent", real(m.ascent));
        desc.insert(b"Descent", real(m.descent));
        desc.insert(b"CapHeight", real(m.cap_height));
        desc.insert(b"StemV", int(80));
        desc.insert(b"FontFile2", reference(file));
        let desc = u.add(Object::Dictionary(desc))?;
        let mut widths = Vec::new();
        for (&gid, text) in used {
            let adv = text
                .chars()
                .next()
                .and_then(|c| face.glyph(c))
                .map_or(0.0, |(_, a)| a);
            widths.push(int(gid));
            widths.push(Object::Array(vec![real(adv)]));
        }
        let mut cid = Dictionary::new();
        cid.insert(b"Type", name(b"Font"));
        cid.insert(b"Subtype", name(b"CIDFontType2"));
        cid.insert(b"BaseFont", name(base.as_bytes()));
        let mut info = Dictionary::new();
        info.insert(b"Registry", Object::String(b"Adobe".to_vec()));
        info.insert(b"Ordering", Object::String(b"Identity".to_vec()));
        info.insert(b"Supplement", int(0));
        cid.insert(b"CIDSystemInfo", Object::Dictionary(info));
        cid.insert(b"FontDescriptor", reference(desc));
        cid.insert(b"CIDToGIDMap", name(b"Identity"));
        cid.insert(b"DW", int(0));
        cid.insert(b"W", Object::Array(widths));
        let cid = u.add(Object::Dictionary(cid))?;
        let cmap = flate_stream(u, Dictionary::new(), to_unicode(used).as_bytes())?;
        let mut t0 = Dictionary::new();
        t0.insert(b"Type", name(b"Font"));
        t0.insert(b"Subtype", name(b"Type0"));
        t0.insert(b"BaseFont", name(base.as_bytes()));
        t0.insert(b"Encoding", name(b"Identity-H"));
        t0.insert(b"DescendantFonts", Object::Array(vec![reference(cid)]));
        t0.insert(b"ToUnicode", reference(cmap));
        let r = u.add(Object::Dictionary(t0))?;
        report.push(EmbeddedFont {
            base_font: base,
            glyphs: used.len(),
        });
        out.insert(index, r);
    }
    Ok(out)
}

/// An image XObject, with its soft mask.
pub(crate) fn image(u: &mut IncrementalUpdate<'_>, img: &Image) -> Result<ObjRef, WriteError> {
    let mut d = Dictionary::new();
    d.insert(b"Type", name(b"XObject"));
    d.insert(b"Subtype", name(b"Image"));
    d.insert(b"Width", int(img.width));
    d.insert(b"Height", int(img.height));
    d.insert(b"ColorSpace", name(img.space.name()));
    d.insert(b"BitsPerComponent", int(8));
    if img.inverted {
        d.insert(
            b"Decode",
            Object::Array([1, 0, 1, 0, 1, 0, 1, 0].iter().map(|v| int(*v)).collect()),
        );
    }
    if let Some(mask) = &img.smask {
        let mut m = Dictionary::new();
        m.insert(b"Type", name(b"XObject"));
        m.insert(b"Subtype", name(b"Image"));
        m.insert(b"Width", int(img.width));
        m.insert(b"Height", int(img.height));
        m.insert(b"ColorSpace", name(b"DeviceGray"));
        m.insert(b"BitsPerComponent", int(8));
        m.insert(b"Filter", name(b"FlateDecode"));
        let m = u.add_stream(m, mask.clone())?;
        d.insert(b"SMask", reference(m));
    }
    d.insert(
        b"Filter",
        name(if img.dct {
            b"DCTDecode"
        } else {
            b"FlateDecode"
        }),
    );
    u.add_stream(d, img.data.clone())
}

/// A form XObject of `w` × `h` drawing `canvas`, its fonts and images given.
pub(crate) fn form(
    u: &mut IncrementalUpdate<'_>,
    canvas: &Canvas,
    w: f64,
    h: f64,
    matrix: Option<[f64; 6]>,
    font_refs: &BTreeMap<usize, ObjRef>,
    image_refs: &[ObjRef],
) -> Result<ObjRef, WriteError> {
    let mut d = Dictionary::new();
    d.insert(b"Type", name(b"XObject"));
    d.insert(b"Subtype", name(b"Form"));
    d.insert(
        b"BBox",
        Object::Array(vec![int(0), int(0), real(w), real(h)]),
    );
    if let Some(m) = matrix {
        d.insert(
            b"Matrix",
            Object::Array(m.iter().map(|v| real(*v)).collect()),
        );
    }
    d.insert(
        b"Resources",
        Object::Dictionary(resources(canvas, font_refs, image_refs)),
    );
    flate_stream(u, d, canvas.ops.as_bytes())
}

/// The resources a canvas names.
pub(crate) fn resources(
    canvas: &Canvas,
    font_refs: &BTreeMap<usize, ObjRef>,
    image_refs: &[ObjRef],
) -> Dictionary {
    let mut res = Dictionary::new();
    if !canvas.fonts.is_empty() {
        let mut f = Dictionary::new();
        for i in &canvas.fonts {
            if let Some(r) = font_refs.get(i) {
                f.insert(format!("F{i}").as_bytes(), reference(*r));
            }
        }
        res.insert(b"Font", Object::Dictionary(f));
    }
    if !canvas.images.is_empty() {
        let mut x = Dictionary::new();
        for i in &canvas.images {
            if let Some(r) = image_refs.get(*i) {
                x.insert(format!("Im{i}").as_bytes(), reference(*r));
            }
        }
        res.insert(b"XObject", Object::Dictionary(x));
    }
    res
}

/// A content stream, Flate-compressed.
pub(crate) fn content(u: &mut IncrementalUpdate<'_>, ops: &str) -> Result<ObjRef, WriteError> {
    flate_stream(u, Dictionary::new(), ops.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subset_tags_are_six_capitals_and_differ_by_glyph_set() {
        let a = tag(0, [1u16, 2].into_iter());
        let b = tag(0, [1u16, 3].into_iter());
        assert_eq!(a.len(), 6);
        assert!(a.chars().all(|c| c.is_ascii_uppercase()));
        assert_ne!(a, b);
        assert_eq!(a, tag(0, [1u16, 2].into_iter()));
    }

    #[test]
    fn to_unicode_maps_each_glyph_to_utf16() {
        let mut m = BTreeMap::new();
        m.insert(3u16, "é".to_owned());
        m.insert(4u16, "😀".to_owned());
        let s = to_unicode(&m);
        assert!(s.contains("<0003> <00E9>"));
        assert!(s.contains("<0004> <D83DDE00>"));
    }
}
