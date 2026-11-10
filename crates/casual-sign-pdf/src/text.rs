//! PDF text strings (ISO 32000-2 §7.9.2.2): UTF-16BE or UTF-8 with a byte-order mark,
//! otherwise PDFDocEncoding.

/// PDFDocEncoding code points that differ from Latin-1 (Annex D.3).
pub(crate) fn pdfdoc(b: u8) -> char {
    let cp: u32 = match b {
        0x18 => 0x02D8,
        0x19 => 0x02C7,
        0x1A => 0x02C6,
        0x1B => 0x02D9,
        0x1C => 0x02DD,
        0x1D => 0x02DB,
        0x1E => 0x02DA,
        0x1F => 0x02DC,
        0x80 => 0x2022,
        0x81 => 0x2020,
        0x82 => 0x2021,
        0x83 => 0x2026,
        0x84 => 0x2014,
        0x85 => 0x2013,
        0x86 => 0x0192,
        0x87 => 0x2044,
        0x88 => 0x2039,
        0x89 => 0x203A,
        0x8A => 0x2212,
        0x8B => 0x2030,
        0x8C => 0x201E,
        0x8D => 0x201C,
        0x8E => 0x201D,
        0x8F => 0x2018,
        0x90 => 0x2019,
        0x91 => 0x201A,
        0x92 => 0x2122,
        0x93 => 0xFB01,
        0x94 => 0xFB02,
        0x95 => 0x0141,
        0x96 => 0x0152,
        0x97 => 0x0160,
        0x98 => 0x0178,
        0x99 => 0x017D,
        0x9A => 0x0131,
        0x9B => 0x0142,
        0x9C => 0x0153,
        0x9D => 0x0161,
        0x9E => 0x017E,
        0x9F | 0xAD => 0xFFFD,
        0xA0 => 0x20AC,
        other => u32::from(other),
    };
    char::from_u32(cp).unwrap_or('\u{FFFD}')
}

/// Decode a text string; invalid sequences become U+FFFD.
pub(crate) fn decode(bytes: &[u8]) -> String {
    if let Some(rest) = bytes.strip_prefix(&[0xFE, 0xFF]) {
        let units = rest.chunks(2).map(|c| match c {
            [h, l] => u16::from_be_bytes([*h, *l]),
            _ => 0xFFFD,
        });
        return char::decode_utf16(units)
            .map(|r| r.unwrap_or('\u{FFFD}'))
            .collect();
    }
    if let Some(rest) = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        return String::from_utf8_lossy(rest).into_owned();
    }
    bytes.iter().map(|&b| pdfdoc(b)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_each_encoding() {
        assert_eq!(decode(b"Name\x80"), "Name\u{2022}");
        assert_eq!(decode(&[0xFE, 0xFF, 0x00, 0x41, 0x04, 0x14]), "A\u{0414}");
        assert_eq!(decode(&[0xEF, 0xBB, 0xBF, b'o', b'k']), "ok");
    }
}
