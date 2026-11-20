//! A ZIP archive of stored (uncompressed) entries, for the evidence package
//! (`VS-06D`, docs/32 §6). PKWARE APPNOTE 6.3.10 §4.3: a local header and the bytes per
//! entry, then the central directory and its end record. Store only: the entries are
//! PDFs and JSON, already compact or small, and every unzip tool reads method 0. No
//! ZIP64: an archive whose entries or offsets would pass 4 GiB, or that would hold more
//! than 65,535 entries, is refused. Names are UTF-8 (general purpose bit 11). Every
//! entry carries the same fixed DOS time (1980-01-01 00:00), so the same entries give
//! the same bytes; the manifest inside says when the package was made.
//!
//! Why written here rather than the `zip` crate: writing stored entries is the three
//! fixed records below, while `zip` adds deflate, ZIP64, encryption and a reader to
//! the server for a format we only write (and had four advisories in 2026, cleared in
//! 9.0.5). The CRC-32 comes from `crc32fast` (already in the tree); nothing here is
//! cryptographic, the integrity of each entry is the manifest's SHA-256.

/// Local file header signature.
const LOCAL: u32 = 0x0403_4b50;
/// Central directory file header signature.
const CENTRAL: u32 = 0x0201_4b50;
/// End of central directory record signature.
const END: u32 = 0x0605_4b50;
/// Version needed to extract: 1.0 (stored entries, no ZIP64).
const NEEDED: u16 = 10;
/// Version made by: 2.0, MS-DOS attributes (none set).
const MADE_BY: u16 = 20;
/// General purpose flags: bit 11, names are UTF-8.
const UTF8: u16 = 0x0800;
/// 1980-01-01 in MS-DOS date form (year 0 = 1980, month 1, day 1); time 00:00:00.
const DOS_DATE: u16 = (1 << 5) | 1;

/// Why an archive could not be written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ZipError {
    /// More than 65,535 entries, an entry, a name or an offset past `u32`/`u16`.
    TooLarge,
    /// A name that is empty, absolute, holds `..`, a backslash or a control character.
    BadName,
}

struct Central {
    name: Vec<u8>,
    crc: u32,
    size: u32,
    offset: u32,
}

/// An archive being written in memory.
pub(crate) struct StoreZip {
    out: Vec<u8>,
    entries: Vec<Central>,
}

fn u16_of(n: usize) -> Result<u16, ZipError> {
    u16::try_from(n).map_err(|_| ZipError::TooLarge)
}

fn u32_of(n: usize) -> Result<u32, ZipError> {
    u32::try_from(n).map_err(|_| ZipError::TooLarge)
}

fn name_ok(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with('/')
        && !name.contains('\\')
        && !name.chars().any(char::is_control)
        && name
            .split('/')
            .all(|p| !p.is_empty() && p != "." && p != "..")
}

impl StoreZip {
    pub(crate) fn new() -> Self {
        Self {
            out: Vec::new(),
            entries: Vec::new(),
        }
    }

    /// Add `bytes` as `name` (a relative path with `/` separators).
    pub(crate) fn add(&mut self, name: &str, bytes: &[u8]) -> Result<(), ZipError> {
        if !name_ok(name) {
            return Err(ZipError::BadName);
        }
        if self.entries.len() >= usize::from(u16::MAX) {
            return Err(ZipError::TooLarge);
        }
        let n = name.as_bytes();
        let name_len = u16_of(n.len())?;
        let size = u32_of(bytes.len())?;
        let offset = u32_of(self.out.len())?;
        let crc = crc32fast::hash(bytes);
        let o = &mut self.out;
        o.extend_from_slice(&LOCAL.to_le_bytes());
        o.extend_from_slice(&NEEDED.to_le_bytes());
        o.extend_from_slice(&UTF8.to_le_bytes());
        o.extend_from_slice(&0u16.to_le_bytes()); // method: stored
        o.extend_from_slice(&0u16.to_le_bytes()); // time
        o.extend_from_slice(&DOS_DATE.to_le_bytes());
        o.extend_from_slice(&crc.to_le_bytes());
        o.extend_from_slice(&size.to_le_bytes()); // compressed
        o.extend_from_slice(&size.to_le_bytes()); // uncompressed
        o.extend_from_slice(&name_len.to_le_bytes());
        o.extend_from_slice(&0u16.to_le_bytes()); // extra
        o.extend_from_slice(n);
        o.extend_from_slice(bytes);
        // The next offset must still fit.
        u32_of(self.out.len())?;
        self.entries.push(Central {
            name: n.to_vec(),
            crc,
            size,
            offset,
        });
        Ok(())
    }

    /// The archive's bytes: the entries, the central directory and its end record.
    pub(crate) fn finish(mut self) -> Result<Vec<u8>, ZipError> {
        let start = u32_of(self.out.len())?;
        let count = u16_of(self.entries.len())?;
        for e in &self.entries {
            let o = &mut self.out;
            o.extend_from_slice(&CENTRAL.to_le_bytes());
            o.extend_from_slice(&MADE_BY.to_le_bytes());
            o.extend_from_slice(&NEEDED.to_le_bytes());
            o.extend_from_slice(&UTF8.to_le_bytes());
            o.extend_from_slice(&0u16.to_le_bytes()); // method
            o.extend_from_slice(&0u16.to_le_bytes()); // time
            o.extend_from_slice(&DOS_DATE.to_le_bytes());
            o.extend_from_slice(&e.crc.to_le_bytes());
            o.extend_from_slice(&e.size.to_le_bytes());
            o.extend_from_slice(&e.size.to_le_bytes());
            o.extend_from_slice(&u16_of(e.name.len())?.to_le_bytes());
            o.extend_from_slice(&0u16.to_le_bytes()); // extra
            o.extend_from_slice(&0u16.to_le_bytes()); // comment
            o.extend_from_slice(&0u16.to_le_bytes()); // disk
            o.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
            o.extend_from_slice(&0u32.to_le_bytes()); // external attributes
            o.extend_from_slice(&e.offset.to_le_bytes());
            o.extend_from_slice(&e.name);
        }
        let end = u32_of(self.out.len())?;
        let size = end.checked_sub(start).ok_or(ZipError::TooLarge)?;
        let o = &mut self.out;
        o.extend_from_slice(&END.to_le_bytes());
        o.extend_from_slice(&0u16.to_le_bytes()); // this disk
        o.extend_from_slice(&0u16.to_le_bytes()); // disk with the directory
        o.extend_from_slice(&count.to_le_bytes());
        o.extend_from_slice(&count.to_le_bytes());
        o.extend_from_slice(&size.to_le_bytes());
        o.extend_from_slice(&start.to_le_bytes());
        o.extend_from_slice(&0u16.to_le_bytes()); // comment
        Ok(self.out)
    }
}

#[cfg(test)]
// Tests may unwrap and index (CLAUDE.md).
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
mod tests {
    use super::{StoreZip, ZipError};

    #[test]
    fn the_same_entries_give_the_same_bytes_and_bad_names_are_refused() {
        let make = || {
            let mut z = StoreZip::new();
            z.add("manifest.json", b"{}").unwrap();
            z.add("documents/01-a.pdf", b"%PDF-1.7").unwrap();
            z.finish().unwrap()
        };
        let a = make();
        assert_eq!(a, make());
        assert_eq!(&a[..4], b"PK\x03\x04");
        // End record: two entries.
        let end = a.len() - 22;
        assert_eq!(&a[end..end + 4], b"PK\x05\x06");
        assert_eq!(&a[end + 8..end + 10], &2u16.to_le_bytes());
        let mut z = StoreZip::new();
        for bad in ["", "/abs", "a/../b", "a\\b", "a//b", "x\ny"] {
            assert_eq!(z.add(bad, b""), Err(ZipError::BadName), "{bad:?}");
        }
    }
}
