//! A TrueType subsetter for PDF embedding: keep the drawn glyphs, empty the rest.
//!
//! Copied unchanged from crates/casual-sign-flatten/src/subset.rs at 8e053b6 (this
//! repository), itself copied from OpenPresent's crates/casual-slide-render/src/subset.rs
//! at e61277d and OpenCalc's casual-calc-render/src/subset.rs at b23c67c
//! (crates/casual-sign-flatten/PROVENANCE.md). A copy rather than a shared module because
//! flatten keeps it crate-private; XFA-01 proposes moving it to one place.
//!
//! # Why this shape of subset
//!
//! A `CIDFontType2` with `/CIDToGIDMap /Identity` addresses glyphs by their id in the
//! embedded program, and the content streams, `/W` and `ToUnicode` are written in those
//! ids. So the cheapest correct subset **keeps every glyph id where it is** and empties
//! the outlines of the ones not drawn: `glyf` shrinks to what the page uses, `loca` is
//! rewritten to point at it, and nothing else is renumbered. Composite glyphs pull in
//! their components, transitively.
//!
//! Only the tables a PDF consumer reads from an embedded TrueType program are kept
//! (ISO 32000-2 §9.9: `head`, `hhea`, `loca`, `maxp`, `cvt `, `prep`, `glyf`, `hmtx`,
//! `fpgm`), plus `OS/2` and `post`, which some viewers consult when repairing a font.

use std::collections::{BTreeMap, BTreeSet};

const KEEP: [&[u8; 4]; 11] = [
    b"OS/2", b"cvt ", b"fpgm", b"glyf", b"head", b"hhea", b"hmtx", b"loca", b"maxp", b"post",
    b"prep",
];

fn at(base: usize, off: usize) -> Option<usize> {
    base.checked_add(off)
}

fn u16_at(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(at(i, 1)?)?]))
}

fn u32_at(b: &[u8], i: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *b.get(i)?,
        *b.get(at(i, 1)?)?,
        *b.get(at(i, 2)?)?,
        *b.get(at(i, 3)?)?,
    ]))
}

fn usize_of(v: u32) -> Option<usize> {
    usize::try_from(v).ok()
}

/// The tables of an sfnt, by tag; `None` unless it is TrueType-flavoured.
fn tables(font: &[u8]) -> Option<BTreeMap<[u8; 4], &[u8]>> {
    let version = u32_at(font, 0)?;
    if version != 0x0001_0000 && version != u32::from_be_bytes(*b"true") {
        return None;
    }
    let n = usize::from(u16_at(font, 4)?);
    let mut out = BTreeMap::new();
    for i in 0..n {
        let rec = at(12, i.checked_mul(16)?)?;
        let tag: [u8; 4] = font.get(rec..at(rec, 4)?)?.try_into().ok()?;
        let offset = usize_of(u32_at(font, at(rec, 8)?)?)?;
        let length = usize_of(u32_at(font, at(rec, 12)?)?)?;
        out.insert(tag, font.get(offset..offset.checked_add(length)?)?);
    }
    Some(out)
}

/// The glyph ids a composite glyph's components name.
fn components(glyph: &[u8]) -> Vec<u16> {
    let mut out = Vec::new();
    let contours = match (glyph.first(), glyph.get(1)) {
        (Some(&a), Some(&b)) if glyph.len() >= 10 => i16::from_be_bytes([a, b]),
        _ => return out,
    };
    if contours >= 0 {
        return out;
    }
    let mut i: usize = 10;
    // A composite of more components than bytes is malformed; the bound is the glyph's
    // own length, and each step advances at least four bytes.
    while let (Some(flags), Some(gid)) = (u16_at(glyph, i), at(i, 2).and_then(|j| u16_at(glyph, j)))
    {
        out.push(gid);
        let mut step: usize = 4;
        step = step.saturating_add(if flags & 0x0001 != 0 { 4 } else { 2 });
        if flags & 0x0008 != 0 {
            step = step.saturating_add(2);
        } else if flags & 0x0040 != 0 {
            step = step.saturating_add(4);
        } else if flags & 0x0080 != 0 {
            step = step.saturating_add(8);
        }
        i = i.saturating_add(step);
        if flags & 0x0020 == 0 || i >= glyph.len() {
            break;
        }
    }
    out
}

/// `font` with every glyph outside `used` (and their components) emptied, or `None`
/// when the face is not one this can subset (CFF, a collection, a damaged face).
#[must_use]
pub(crate) fn subset(font: &[u8], used: impl IntoIterator<Item = u32>) -> Option<Vec<u8>> {
    let t = tables(font)?;
    let head = *t.get(b"head")?;
    let maxp = *t.get(b"maxp")?;
    let loca = *t.get(b"loca")?;
    let glyf = *t.get(b"glyf")?;
    t.get(b"hhea")?;
    t.get(b"hmtx")?;
    let long = i16::from_be_bytes([*head.get(50)?, *head.get(51)?]) != 0;
    let num_glyphs = usize::from(u16_at(maxp, 4)?);
    let span = |gid: usize| -> Option<&[u8]> {
        let (a, b) = if long {
            let i = gid.checked_mul(4)?;
            (
                usize_of(u32_at(loca, i)?)?,
                usize_of(u32_at(loca, at(i, 4)?)?)?,
            )
        } else {
            let i = gid.checked_mul(2)?;
            (
                usize::from(u16_at(loca, i)?).checked_mul(2)?,
                usize::from(u16_at(loca, at(i, 2)?)?).checked_mul(2)?,
            )
        };
        if a > b {
            return None;
        }
        glyf.get(a..b)
    };

    // The closure over composites: a worklist with a visited set, so a cycle in a
    // malformed face terminates.
    let mut keep: BTreeSet<usize> = BTreeSet::from([0]);
    let mut work: Vec<usize> = used
        .into_iter()
        .filter_map(|g| usize::try_from(g).ok())
        .filter(|&g| g < num_glyphs)
        .collect();
    work.push(0);
    let mut seen: BTreeSet<usize> = BTreeSet::new();
    while let Some(gid) = work.pop() {
        if !seen.insert(gid) {
            continue;
        }
        keep.insert(gid);
        for c in components(span(gid)?) {
            let c = usize::from(c);
            if c < num_glyphs && !seen.contains(&c) {
                work.push(c);
            }
        }
    }

    let mut new_glyf = Vec::new();
    let mut new_loca = Vec::with_capacity(num_glyphs.saturating_add(1).saturating_mul(4));
    for gid in 0..num_glyphs {
        new_loca.extend_from_slice(&u32::try_from(new_glyf.len()).ok()?.to_be_bytes());
        if keep.contains(&gid) {
            new_glyf.extend_from_slice(span(gid)?);
            while new_glyf.len() % 4 != 0 {
                new_glyf.push(0);
            }
        }
    }
    new_loca.extend_from_slice(&u32::try_from(new_glyf.len()).ok()?.to_be_bytes());
    let mut new_head = head.to_vec();
    new_head
        .get_mut(50..52)?
        .copy_from_slice(&1i16.to_be_bytes());
    // The checksum adjustment is recomputed over the whole new file below.
    new_head.get_mut(8..12)?.copy_from_slice(&[0; 4]);

    let mut out_tables: Vec<([u8; 4], Vec<u8>)> = Vec::new();
    for tag in KEEP {
        let data = match tag {
            b"glyf" => new_glyf.clone(),
            b"loca" => new_loca.clone(),
            b"head" => new_head.clone(),
            _ => match t.get(tag) {
                Some(d) => d.to_vec(),
                None => continue,
            },
        };
        out_tables.push((*tag, data));
    }
    assemble(&out_tables)
}

fn checksum(data: &[u8]) -> u32 {
    data.chunks(4).fold(0u32, |sum, chunk| {
        let mut word = [0u8; 4];
        for (w, c) in word.iter_mut().zip(chunk) {
            *w = *c;
        }
        sum.wrapping_add(u32::from_be_bytes(word))
    })
}

/// An sfnt from tables already in tag order.
fn assemble(tables: &[([u8; 4], Vec<u8>)]) -> Option<Vec<u8>> {
    let n = u16::try_from(tables.len()).ok()?;
    let header = usize::from(n).checked_mul(16)?.checked_add(12)?;
    // n is at most 11, so these fit in u16.
    let mut entry_selector: u16 = 0;
    while (1u16 << entry_selector.saturating_add(1)) <= n {
        entry_selector = entry_selector.saturating_add(1);
    }
    let search_range = (1u16 << entry_selector).checked_mul(16)?;
    let range_shift = n.checked_mul(16)?.checked_sub(search_range)?;
    let mut out = Vec::new();
    out.extend_from_slice(&0x0001_0000u32.to_be_bytes());
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(&search_range.to_be_bytes());
    out.extend_from_slice(&entry_selector.to_be_bytes());
    out.extend_from_slice(&range_shift.to_be_bytes());
    let mut body = Vec::new();
    let mut head_at = None;
    for (tag, data) in tables {
        let offset = header.checked_add(body.len())?;
        if tag == b"head" {
            head_at = Some(offset);
        }
        out.extend_from_slice(tag);
        out.extend_from_slice(&checksum(data).to_be_bytes());
        out.extend_from_slice(&u32::try_from(offset).ok()?.to_be_bytes());
        out.extend_from_slice(&u32::try_from(data.len()).ok()?.to_be_bytes());
        body.extend_from_slice(data);
        while body.len() % 4 != 0 {
            body.push(0);
        }
    }
    out.extend_from_slice(&body);
    if let Some(h) = head_at {
        let slot = at(h, 8)?..at(h, 12)?;
        let adjust = 0xB1B0_AFBAu32.wrapping_sub(checksum(&out));
        out.get_mut(slot)?.copy_from_slice(&adjust.to_be_bytes());
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    // Test code: a panic is the failure report (CLAUDE.md).
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn hostile_input_is_refused_not_panicked_on() {
        assert!(subset(b"", [1]).is_none());
        assert!(subset(b"OTTO\0\0\0\0\0\0\0\0", [1]).is_none());
        let mut bad = vec![0, 1, 0, 0, 0, 200];
        bad.resize(64, 0xFF);
        assert!(subset(&bad, [1]).is_none());
        // A composite naming itself terminates.
        assert_eq!(
            components(&[0xFF, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x20, 0, 5]).len(),
            1
        );
    }

    #[test]
    fn table_directory_fields_match_the_spec() {
        let t = vec![(*b"head", vec![0u8; 54]), (*b"maxp", vec![0u8; 6])];
        let out = assemble(&t).unwrap();
        // numTables 2, searchRange 32, entrySelector 1, rangeShift 0.
        assert_eq!(&out[4..12], &[0, 2, 0, 32, 0, 1, 0, 0]);
    }
}
