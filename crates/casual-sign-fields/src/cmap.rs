//! CMaps (ISO 32000-2 §9.7.5, §9.10.3): code space ranges, code-to-CID maps of an
//! embedded Type 0 encoding, and `ToUnicode` maps. Ranges are kept as ranges, never
//! expanded, so `<0000> <FFFF>` costs one entry.

use std::collections::BTreeMap;

use crate::content::{Lexer, Operand, Token};

/// Most mappings kept from one CMap; further ones are ignored and flagged.
pub(crate) const MAX_CMAP_ENTRIES: usize = 100_000;
/// Longest Unicode string one code maps to, in UTF-16 units.
const MAX_DST_UNITS: usize = 64;

/// A code space range: codes of `len` bytes from `lo` to `hi`, byte by byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CodeSpace {
    len: u8,
    lo: [u8; 4],
    hi: [u8; 4],
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Dst {
    /// The first code's string; later codes increment its last UTF-16 unit.
    Base(Vec<u16>),
    /// One string per code.
    List(Vec<Vec<u16>>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct UniRange {
    len: u8,
    lo: u32,
    hi: u32,
    dst: Dst,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CidRange {
    len: u8,
    lo: u32,
    hi: u32,
    cid: u32,
}

/// A parsed CMap. One type serves both uses; a `ToUnicode` map has no CID entries and
/// an encoding has no Unicode ones.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CMap {
    spaces: Vec<CodeSpace>,
    uni_single: BTreeMap<(u8, u32), Vec<u16>>,
    uni_ranges: Vec<UniRange>,
    cid_single: BTreeMap<(u8, u32), u32>,
    cid_ranges: Vec<CidRange>,
    /// Entries beyond [`MAX_CMAP_ENTRIES`] were ignored.
    pub(crate) truncated: bool,
}

fn code_of(b: &[u8]) -> Option<(u8, u32)> {
    if b.is_empty() || b.len() > 4 {
        return None;
    }
    let v = b
        .iter()
        .fold(0u32, |acc, &x| acc.wrapping_shl(8) | u32::from(x));
    Some((u8::try_from(b.len()).ok()?, v))
}

fn utf16(b: &[u8]) -> Vec<u16> {
    b.chunks(2)
        .take(MAX_DST_UNITS)
        .map(|c| match c {
            [h, l] => u16::from_be_bytes([*h, *l]),
            [h] => u16::from(*h),
            _ => 0xFFFD,
        })
        .collect()
}

impl CMap {
    /// Parse a CMap stream. Unknown content is skipped; nothing fails.
    pub(crate) fn parse(data: &[u8]) -> Self {
        let mut map = Self::default();
        let mut lx = Lexer::new(data);
        let mut stack: Vec<Operand> = Vec::new();
        let mut section: Option<&'static [u8]> = None;
        let mut entries: usize = 0;
        while let Some(t) = lx.next_token() {
            let Ok(t) = t else { break };
            match t {
                Token::Operand(o) => {
                    if section.is_some() {
                        stack.push(o);
                        if map.take(section, &stack, &mut entries) {
                            stack.clear();
                        }
                    }
                }
                Token::Op(op) => {
                    section = match op {
                        b"begincodespacerange" => Some(b"cs"),
                        b"beginbfchar" => Some(b"bfc"),
                        b"beginbfrange" => Some(b"bfr"),
                        b"begincidchar" => Some(b"cidc"),
                        b"begincidrange" => Some(b"cidr"),
                        _ => None,
                    };
                    stack.clear();
                }
            }
        }
        map.uni_ranges.sort_by_key(|r| (r.len, r.lo));
        map.cid_ranges.sort_by_key(|r| (r.len, r.lo));
        map
    }

    /// Consume a complete entry from `stack` when it has one; true when consumed.
    fn take(
        &mut self,
        section: Option<&'static [u8]>,
        stack: &[Operand],
        entries: &mut usize,
    ) -> bool {
        let need = match section {
            Some(b"cs" | b"bfc" | b"cidc") => 2,
            Some(b"bfr" | b"cidr") => 3,
            _ => return true,
        };
        if stack.len() < need {
            return false;
        }
        if *entries >= MAX_CMAP_ENTRIES {
            self.truncated = true;
            return true;
        }
        *entries = entries.saturating_add(1);
        match (section, stack) {
            (Some(b"cs"), [Operand::Str(lo), Operand::Str(hi)]) => {
                if lo.len() == hi.len()
                    && let Some((len, _)) = code_of(lo)
                {
                    let mut l = [0u8; 4];
                    let mut h = [0u8; 4];
                    for (i, (a, b)) in lo.iter().zip(hi.iter()).enumerate() {
                        if let (Some(x), Some(y)) = (l.get_mut(i), h.get_mut(i)) {
                            *x = *a;
                            *y = *b;
                        }
                    }
                    self.spaces.push(CodeSpace { len, lo: l, hi: h });
                }
            }
            (Some(b"bfc"), [Operand::Str(src), dst]) => {
                if let Some(k) = code_of(src) {
                    let d = match dst {
                        Operand::Str(s) => Some(utf16(s)),
                        Operand::Name(n) => crate::font::glyph_unicode(n)
                            .map(|c| c.encode_utf16(&mut [0; 2]).to_vec()),
                        _ => None,
                    };
                    if let Some(d) = d {
                        self.uni_single.insert(k, d);
                    }
                }
            }
            (Some(b"bfr"), [Operand::Str(lo), Operand::Str(hi), dst]) => {
                if let (Some((len, lo)), Some((hl, hi))) = (code_of(lo), code_of(hi))
                    && len == hl
                    && lo <= hi
                {
                    let dst = match dst {
                        Operand::Str(s) => Some(Dst::Base(utf16(s))),
                        Operand::Array(a) => Some(Dst::List(
                            a.iter()
                                .map(|o| match o {
                                    Operand::Str(s) => utf16(s),
                                    _ => Vec::new(),
                                })
                                .collect(),
                        )),
                        _ => None,
                    };
                    if let Some(dst) = dst {
                        self.uni_ranges.push(UniRange { len, lo, hi, dst });
                    }
                }
            }
            (Some(b"cidc"), [Operand::Str(src), Operand::Num(cid)]) => {
                if let (Some(k), Some(cid)) = (code_of(src), as_u32(*cid)) {
                    self.cid_single.insert(k, cid);
                }
            }
            (Some(b"cidr"), [Operand::Str(lo), Operand::Str(hi), Operand::Num(cid)]) => {
                if let (Some((len, lo)), Some((hl, hi)), Some(cid)) =
                    (code_of(lo), code_of(hi), as_u32(*cid))
                    && len == hl
                    && lo <= hi
                {
                    self.cid_ranges.push(CidRange { len, lo, hi, cid });
                }
            }
            _ => {}
        }
        true
    }

    /// True when the map declares code space ranges.
    pub(crate) fn has_code_spaces(&self) -> bool {
        !self.spaces.is_empty()
    }

    /// Length of the code at the start of `b`, by the code space ranges (§9.7.6.2):
    /// the shortest range that matches; when none does, the shortest range length that
    /// fits (and at least 1).
    pub(crate) fn code_len(&self, b: &[u8]) -> usize {
        let mut fallback: Option<usize> = None;
        for len in 1..=4usize {
            let Some(code) = b.get(..len) else { break };
            for s in self.spaces.iter().filter(|s| usize::from(s.len) == len) {
                let inside = code.iter().enumerate().all(|(i, c)| {
                    matches!((s.lo.get(i), s.hi.get(i)), (Some(l), Some(h)) if l <= c && c <= h)
                });
                if inside {
                    return len;
                }
                fallback.get_or_insert(len);
            }
        }
        fallback.unwrap_or(1).min(b.len()).max(1)
    }

    /// The Unicode text of a code, if the map has one.
    pub(crate) fn unicode(&self, len: u8, code: u32) -> Option<String> {
        if let Some(d) = self.uni_single.get(&(len, code)) {
            return Some(from_utf16(d));
        }
        let i = self
            .uni_ranges
            .partition_point(|r| (r.len, r.lo) <= (len, code));
        let r = self.uni_ranges.get(i.checked_sub(1)?)?;
        if r.len != len || code > r.hi {
            return None;
        }
        let off = code.checked_sub(r.lo)?;
        match &r.dst {
            Dst::Base(base) => {
                let mut v = base.clone();
                let last = v.last_mut()?;
                let bumped = u32::from(*last).checked_add(off)?;
                *last = u16::try_from(bumped).ok()?;
                Some(from_utf16(&v))
            }
            Dst::List(list) => list.get(usize::try_from(off).ok()?).map(|d| from_utf16(d)),
        }
    }

    /// The CID of a code under an embedded encoding CMap.
    pub(crate) fn cid(&self, len: u8, code: u32) -> Option<u32> {
        if let Some(c) = self.cid_single.get(&(len, code)) {
            return Some(*c);
        }
        let i = self
            .cid_ranges
            .partition_point(|r| (r.len, r.lo) <= (len, code));
        let r = self.cid_ranges.get(i.checked_sub(1)?)?;
        if r.len != len || code > r.hi {
            return None;
        }
        r.cid.checked_add(code.checked_sub(r.lo)?)
    }
}

fn as_u32(n: f64) -> Option<u32> {
    (n >= 0.0 && n <= f64::from(u32::MAX) && n.fract() == 0.0).then_some(n as u32)
}

fn from_utf16(units: &[u16]) -> String {
    char::decode_utf16(units.iter().copied())
        .map(|r| r.unwrap_or('\u{FFFD}'))
        .filter(|c| *c != '\0')
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &[u8] = b"/CIDInit /ProcSet findresource begin 12 dict begin begincmap
1 begincodespacerange <0000> <FFFF> endcodespacerange
2 beginbfchar <0003> <0020> <0011> <00660069> endbfchar
2 beginbfrange <0024> <0026> <0041> <0030> <0031> [<0078> <D83DDE00>] endbfrange
1 begincidrange <0000> <00FF> 100 endcidrange
endcmap CMapName currentdict /CMap defineresource pop end end";

    #[test]
    fn maps_singles_ranges_and_arrays() {
        let m = CMap::parse(SAMPLE);
        assert_eq!(m.unicode(2, 3).as_deref(), Some(" "));
        assert_eq!(m.unicode(2, 0x11).as_deref(), Some("fi"));
        assert_eq!(m.unicode(2, 0x25).as_deref(), Some("B"));
        assert_eq!(m.unicode(2, 0x26).as_deref(), Some("C"));
        assert_eq!(m.unicode(2, 0x27), None);
        assert_eq!(m.unicode(2, 0x31).as_deref(), Some("\u{1F600}"));
        assert_eq!(m.unicode(1, 0x25), None);
        assert_eq!(m.cid(2, 5), Some(105));
        assert_eq!(m.code_len(&[0, 5]), 2);
    }

    #[test]
    fn mixed_code_lengths_follow_the_code_space() {
        let m = CMap::parse(b"2 begincodespacerange <00> <80> <8140> <9FFC> endcodespacerange");
        assert_eq!(m.code_len(&[0x41, 0x81]), 1);
        assert_eq!(m.code_len(&[0x81, 0x40]), 2);
    }
}
