//! `/ByteRange` rules (docs/31 §7; SEC-S02): exactly `[0 b c d]`, the one gap is exactly
//! the signature dictionary's `/Contents` hex string, no gap, overlap or byte outside the
//! file, and the end is the end of a revision.

use core::ops::Range;

use casual_sign_pdf::{Object, Revision};

/// A ByteRange that passed every rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Checked {
    /// The two signed ranges.
    pub(crate) ranges: [Range<usize>; 2],
    /// Where the signed bytes end (`c + d`).
    pub(crate) end: usize,
    /// The revision that ends there (index, oldest first).
    pub(crate) revision: usize,
    /// True when only whitespace follows the end.
    pub(crate) whole_file: bool,
}

/// Why a ByteRange is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Problem {
    /// Not an array of four non-negative integers.
    Shape,
    /// The first range does not start at 0.
    NotAtStart,
    /// A range lies outside the file, or the ranges overlap or are out of order.
    OutOfBounds,
    /// The gap is not exactly the `/Contents` hex string of this signature.
    GapNotContents,
    /// The signed bytes do not end where a revision ends.
    NotRevisionEnd,
}

/// The four integers of `/ByteRange`.
pub(crate) fn read(o: Option<&Object>) -> Result<[u64; 4], Problem> {
    let Some(Object::Array(a)) = o else {
        return Err(Problem::Shape);
    };
    let [p, q, r, s] = a.as_slice() else {
        return Err(Problem::Shape);
    };
    let n = |o: &Object| o.as_i64().and_then(|i| u64::try_from(i).ok());
    match (n(p), n(q), n(r), n(s)) {
        (Some(p), Some(q), Some(r), Some(s)) => Ok([p, q, r, s]),
        _ => Err(Problem::Shape),
    }
}

fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n' | b'\x0c' | b'\0')
}

fn hex_value(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b.wrapping_sub(b'0')),
        b'a'..=b'f' => Some(b.wrapping_sub(b'a').wrapping_add(10)),
        b'A'..=b'F' => Some(b.wrapping_sub(b'A').wrapping_add(10)),
        _ => None,
    }
}

/// Decode `<...>` (ISO 32000-2 §7.3.4.3); `None` for anything else.
fn hex_string(gap: &[u8]) -> Option<Vec<u8>> {
    let inner = gap.strip_prefix(b"<")?.strip_suffix(b">")?;
    let mut out = Vec::with_capacity(inner.len().div_ceil(2));
    let mut high: Option<u8> = None;
    for &b in inner {
        if is_ws(b) {
            continue;
        }
        let v = hex_value(b)?;
        match high.take() {
            None => high = Some(v),
            Some(h) => out.push(h.wrapping_shl(4) | v),
        }
    }
    if let Some(h) = high {
        out.push(h.wrapping_shl(4));
    }
    Some(out)
}

/// Check `br` against the file `bytes`, the signature's decoded `/Contents`, and the
/// revisions the reader found.
pub(crate) fn check(
    br: [u64; 4],
    bytes: &[u8],
    contents: &[u8],
    revisions: &[Revision],
) -> Result<Checked, Problem> {
    let to = |v: u64| usize::try_from(v).map_err(|_| Problem::OutOfBounds);
    let [a, b, c, d] = [to(br[0])?, to(br[1])?, to(br[2])?, to(br[3])?];
    if a != 0 {
        return Err(Problem::NotAtStart);
    }
    let first_end = b;
    let end = c.checked_add(d).ok_or(Problem::OutOfBounds)?;
    if first_end == 0 || c <= first_end || end > bytes.len() {
        return Err(Problem::OutOfBounds);
    }
    let gap = bytes.get(first_end..c).ok_or(Problem::OutOfBounds)?;
    if hex_string(gap).as_deref() != Some(contents) {
        return Err(Problem::GapNotContents);
    }
    // The gap must be the value of `/Contents`: the token before it is that key.
    let before = bytes.get(..first_end).ok_or(Problem::OutOfBounds)?;
    let key_end = before
        .iter()
        .rposition(|&x| !is_ws(x))
        .and_then(|p| p.checked_add(1))
        .ok_or(Problem::GapNotContents)?;
    if !before
        .get(..key_end)
        .is_some_and(|k| k.ends_with(b"/Contents"))
    {
        return Err(Problem::GapNotContents);
    }
    let revision = revisions
        .iter()
        .position(|r| {
            let Ok(r_end) = usize::try_from(r.end_offset) else {
                return false;
            };
            let (lo, hi) = if r_end <= end {
                (r_end, end)
            } else {
                (end, r_end)
            };
            bytes
                .get(lo..hi)
                .is_some_and(|between| between.iter().all(|&x| x == b'\r' || x == b'\n'))
        })
        .ok_or(Problem::NotRevisionEnd)?;
    let whole_file = bytes
        .get(end..)
        .is_some_and(|rest| rest.iter().all(|&x| is_ws(x)));
    Ok(Checked {
        ranges: [0..first_end, c..end],
        end,
        revision,
        whole_file,
    })
}

// Tests may unwrap, index and panic (CLAUDE.md).
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;
    use casual_sign_pdf::XrefKind;

    fn rev(end: u64) -> Revision {
        Revision {
            xref_offset: Some(0),
            end_offset: end,
            kind: XrefKind::Table,
        }
    }

    // "AAAA/Contents <0102>BBBB%%EOF\n": gap at 14..20, file length 29.
    const FILE: &[u8] = b"AAAA/Contents <0102>BBBB%%EOF\n";

    #[test]
    fn accepts_a_well_formed_range() {
        let c = check([0, 14, 20, 10], FILE, &[1, 2], &[rev(30)]).unwrap();
        assert_eq!(c.ranges, [0..14, 20..30]);
        assert!(c.whole_file);
        assert_eq!(c.revision, 0);
    }

    #[test]
    fn refuses_each_malformation() {
        let revs = [rev(30)];
        assert_eq!(
            check([1, 13, 20, 10], FILE, &[1, 2], &revs),
            Err(Problem::NotAtStart)
        );
        // A gap wider than /Contents.
        assert_eq!(
            check([0, 13, 20, 10], FILE, &[1, 2], &revs),
            Err(Problem::GapNotContents)
        );
        // A gap of other bytes.
        assert_eq!(
            check([0, 4, 20, 10], FILE, &[1, 2], &revs),
            Err(Problem::GapNotContents)
        );
        // Past the end.
        assert_eq!(
            check([0, 14, 20, 11], FILE, &[1, 2], &revs),
            Err(Problem::OutOfBounds)
        );
        // Overlap.
        assert_eq!(
            check([0, 20, 14, 16], FILE, &[1, 2], &revs),
            Err(Problem::OutOfBounds)
        );
        // Not the whole revision.
        assert_eq!(
            check([0, 14, 20, 4], FILE, &[1, 2], &revs),
            Err(Problem::NotRevisionEnd)
        );
        // Contents differ from the dictionary's.
        assert_eq!(
            check([0, 14, 20, 10], FILE, &[1, 3], &revs),
            Err(Problem::GapNotContents)
        );
    }

    #[test]
    fn reads_only_four_non_negative_integers() {
        let ints = |v: &[i64]| Object::Array(v.iter().map(|&i| Object::Integer(i)).collect());
        assert_eq!(read(Some(&ints(&[0, 1, 2, 3]))), Ok([0, 1, 2, 3]));
        assert_eq!(read(Some(&ints(&[0, 1, 2]))), Err(Problem::Shape));
        assert_eq!(read(Some(&ints(&[0, -1, 2, 3]))), Err(Problem::Shape));
        assert_eq!(read(None), Err(Problem::Shape));
    }
}
