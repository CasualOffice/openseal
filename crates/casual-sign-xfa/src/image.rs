//! Images embedded in the template (`<image>` with base64 content): JPEG passes through
//! as `DCTDecode`; 8-bit, non-interlaced PNG without alpha passes its compressed data
//! through as `FlateDecode` with the PNG predictor. Anything else, an external `href`
//! (never fetched), or an image over the limits is not drawn and is counted.
//!
//! Only headers are parsed here; nothing is decoded to pixels, so no allocation is
//! sized by a dimension from the file.

/// An image ready to embed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ImageData {
    pub width: u32,
    pub height: u32,
    /// `/DeviceGray`, `/DeviceRGB` or `/DeviceCMYK`; for a palette image, the base
    /// space of `/Indexed`.
    pub colors: u8,
    pub filter: Filter,
    pub data: Vec<u8>,
    /// PNG palette (RGB triples) for an indexed image.
    pub palette: Option<Vec<u8>>,
    /// Adobe-inverted CMYK JPEG (`/Decode [1 0 1 0 1 0 1 0]`).
    pub invert_cmyk: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Filter {
    Dct,
    /// PNG data: `/FlateDecode` with `/Predictor 15`.
    PngFlate,
}

/// Decode base64, ignoring whitespace; `None` on any other invalid character or when
/// the output would exceed `max`.
pub(crate) fn base64(text: &str, max: usize) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len().min(max).saturating_mul(3) / 4);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for c in text.bytes() {
        let v = match c {
            b'A'..=b'Z' => c.wrapping_sub(b'A'),
            b'a'..=b'z' => c.wrapping_sub(b'a').wrapping_add(26),
            b'0'..=b'9' => c.wrapping_sub(b'0').wrapping_add(52),
            b'+' | b'-' => 62,
            b'/' | b'_' => 63,
            b'=' => break,
            c if c.is_ascii_whitespace() => continue,
            _ => return None,
        };
        acc = (acc << 6) | u32::from(v);
        bits = bits.wrapping_add(6);
        if bits >= 8 {
            bits = bits.wrapping_sub(8);
            out.push(u8::try_from((acc >> bits) & 0xff).unwrap_or(0));
            if out.len() > max {
                return None;
            }
        }
        acc &= 0xff_ff;
    }
    Some(out)
}

fn be16(b: &[u8], at: usize) -> Option<u16> {
    let s = b.get(at..at.checked_add(2)?)?;
    Some(u16::from_be_bytes([*s.first()?, *s.get(1)?]))
}

fn be32(b: &[u8], at: usize) -> Option<u32> {
    let s = b.get(at..at.checked_add(4)?)?;
    Some(u32::from_be_bytes([
        *s.first()?,
        *s.get(1)?,
        *s.get(2)?,
        *s.get(3)?,
    ]))
}

fn jpeg(b: &[u8]) -> Option<ImageData> {
    if !b.starts_with(&[0xff, 0xd8]) {
        return None;
    }
    let mut at = 2usize;
    let mut adobe = false;
    loop {
        if *b.get(at)? != 0xff {
            return None;
        }
        let marker = *b.get(at.checked_add(1)?)?;
        if marker == 0xff {
            at = at.checked_add(1)?;
            continue;
        }
        let len = usize::from(be16(b, at.checked_add(2)?)?);
        if marker == 0xee {
            adobe = b.get(at.checked_add(4)?..at.checked_add(9)?) == Some(b"Adobe");
        }
        if matches!(marker, 0xc0..=0xcf) && !matches!(marker, 0xc4 | 0xc8 | 0xcc) {
            let height = u32::from(be16(b, at.checked_add(5)?)?);
            let width = u32::from(be16(b, at.checked_add(7)?)?);
            let colors = *b.get(at.checked_add(9)?)?;
            if !matches!(colors, 1 | 3 | 4) || width == 0 || height == 0 {
                return None;
            }
            return Some(ImageData {
                width,
                height,
                colors,
                filter: Filter::Dct,
                data: b.to_vec(),
                palette: None,
                invert_cmyk: colors == 4 && adobe,
            });
        }
        at = at.checked_add(2)?.checked_add(len)?;
    }
}

fn png(b: &[u8]) -> Option<ImageData> {
    if !b.starts_with(b"\x89PNG\r\n\x1a\n") {
        return None;
    }
    let mut at = 8usize;
    let mut idat = Vec::new();
    let (mut width, mut height, mut ctype) = (0u32, 0u32, 0u8);
    let mut palette = None;
    loop {
        let len = usize::try_from(be32(b, at)?).ok()?;
        let kind = b.get(at.checked_add(4)?..at.checked_add(8)?)?;
        let body = b.get(at.checked_add(8)?..at.checked_add(8)?.checked_add(len)?)?;
        match kind {
            b"IHDR" => {
                width = be32(body, 0)?;
                height = be32(body, 4)?;
                let depth = *body.get(8)?;
                ctype = *body.get(9)?;
                let interlace = *body.get(12)?;
                if depth != 8 || interlace != 0 || !matches!(ctype, 0 | 2 | 3) {
                    return None;
                }
            }
            b"PLTE" => palette = Some(body.to_vec()),
            b"IDAT" => idat.extend_from_slice(body),
            b"IEND" => break,
            _ => {}
        }
        at = at.checked_add(12)?.checked_add(len)?;
    }
    if width == 0 || height == 0 || idat.is_empty() || (ctype == 3 && palette.is_none()) {
        return None;
    }
    Some(ImageData {
        width,
        height,
        colors: if ctype == 2 { 3 } else { 1 },
        filter: Filter::PngFlate,
        data: idat,
        palette: if ctype == 3 { palette } else { None },
        invert_cmyk: false,
    })
}

/// Parse an embedded image, within `max_side` pixels a side.
pub(crate) fn parse(bytes: &[u8], max_side: u32) -> Option<ImageData> {
    let img = jpeg(bytes).or_else(|| png(bytes))?;
    (img.width <= max_side && img.height <= max_side).then_some(img)
}

#[cfg(test)]
mod tests {
    // Test code: a panic is the failure report (CLAUDE.md).
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn base64_decodes_and_is_bounded() {
        assert_eq!(base64("aGVs\nbG8=", 100).unwrap(), b"hello");
        assert_eq!(base64("aGVsbG8", 100).unwrap(), b"hello");
        assert!(base64("aGVsbG8=", 3).is_none());
        assert!(base64("a*b", 100).is_none());
    }

    #[test]
    fn jpeg_and_png_headers_are_read_and_limited() {
        // A minimal JPEG header: SOI, SOF0 for 3x2 RGB.
        let j = [
            0xff, 0xd8, 0xff, 0xc0, 0x00, 0x11, 0x08, 0x00, 0x02, 0x00, 0x03, 0x03, 1, 0x11, 0, 2,
            0x11, 0, 3, 0x11, 0,
        ];
        let img = parse(&j, 100).unwrap();
        assert_eq!((img.width, img.height, img.colors), (3, 2, 3));
        assert!(parse(&j, 2).is_none());
        // A truncated JPEG never panics.
        for n in 0..j.len() {
            let _ = parse(j.get(..n).unwrap(), 100);
        }
        assert!(parse(b"GIF89a", 100).is_none());
    }
}
