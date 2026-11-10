//! Signature and stamp images: PNG and JPEG only, dimension-checked before any pixel
//! buffer exists, decoded in a bounded decoder, and re-encoded (docs/21 §Images,
//! `SEC-P09`).
//!
//! - **PNG** is decoded to 8-bit samples and written as a Flate image, with its alpha as
//!   a soft mask (`/SMask`) when any pixel is not opaque.
//! - **JPEG** is checked marker by marker (baseline or progressive Huffman, 8-bit, one,
//!   three or four components), decoded once in full to prove it decodes, and its DCT
//!   data passes through rebuilt from the segments a decoder needs: EXIF, XMP, ICC and
//!   comments are dropped, so no camera metadata (location, device) reaches the sealed
//!   document. EXIF orientation is applied by the placement, not lost.

use std::io::Cursor;

use crate::limits::{MAX_IMAGE_BYTES, MAX_IMAGE_SIDE};

/// Why an image was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ImageError {
    /// Over the size or dimension cap (`CS-FLT-0002`).
    TooLarge,
    /// Not PNG or JPEG, or does not decode (`CS-FLT-0003`).
    Undecodable,
}

/// The colour space of image samples.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Space {
    Gray,
    Rgb,
    Cmyk,
}

impl Space {
    pub(crate) fn name(self) -> &'static [u8] {
        match self {
            Self::Gray => b"DeviceGray",
            Self::Rgb => b"DeviceRGB",
            Self::Cmyk => b"DeviceCMYK",
        }
    }
}

/// An image ready to write as an XObject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Image {
    pub width: u32,
    pub height: u32,
    pub space: Space,
    /// Encoded sample data.
    pub data: Vec<u8>,
    /// `true` for `/DCTDecode`, `false` for `/FlateDecode`.
    pub dct: bool,
    /// A CMYK JPEG written by Adobe software stores inverted samples.
    pub inverted: bool,
    /// Flate-encoded 8-bit alpha, when some pixel is not opaque.
    pub smask: Option<Vec<u8>>,
    /// EXIF orientation, 1 to 8 (1 when absent).
    pub orientation: u8,
}

pub(crate) fn deflate(data: &[u8]) -> Vec<u8> {
    miniz_oxide::deflate::compress_to_vec_zlib(data, 6)
}

/// Decode and re-encode `bytes`.
pub(crate) fn load(bytes: &[u8]) -> Result<Image, ImageError> {
    if bytes.len() > MAX_IMAGE_BYTES {
        return Err(ImageError::TooLarge);
    }
    if bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
        png_image(bytes)
    } else if bytes.starts_with(&[0xFF, 0xD8]) {
        jpeg_image(bytes)
    } else {
        Err(ImageError::Undecodable)
    }
}

fn side_ok(w: u32, h: u32) -> Result<(), ImageError> {
    if w == 0 || h == 0 {
        return Err(ImageError::Undecodable);
    }
    if w > MAX_IMAGE_SIDE || h > MAX_IMAGE_SIDE {
        return Err(ImageError::TooLarge);
    }
    Ok(())
}

fn png_image(bytes: &[u8]) -> Result<Image, ImageError> {
    use png::{ColorType, Transformations};
    let side = usize::try_from(MAX_IMAGE_SIDE).map_err(|_| ImageError::TooLarge)?;
    // The decoder's own working memory: rows and the 16-bit stripping, never the image.
    let limits = png::Limits {
        bytes: side.saturating_mul(side).saturating_mul(8),
    };
    let mut decoder = png::Decoder::new_with_limits(Cursor::new(bytes), limits);
    let header = decoder
        .read_header_info()
        .map_err(|_| ImageError::Undecodable)?;
    side_ok(header.width, header.height)?;
    decoder.set_transformations(Transformations::normalize_to_color8());
    let mut reader = decoder.read_info().map_err(|_| ImageError::Undecodable)?;
    let size = reader.output_buffer_size().ok_or(ImageError::TooLarge)?;
    let mut buf = vec![0u8; size];
    let info = reader
        .next_frame(&mut buf)
        .map_err(|_| ImageError::Undecodable)?;
    let (w, h) = (info.width, info.height);
    side_ok(w, h)?;
    let pixels = usize::try_from(w)
        .ok()
        .and_then(|w| usize::try_from(h).ok().and_then(|h| w.checked_mul(h)))
        .ok_or(ImageError::TooLarge)?;
    let (space, channels, alpha) = match info.color_type {
        ColorType::Grayscale => (Space::Gray, 1usize, false),
        ColorType::GrayscaleAlpha => (Space::Gray, 2, true),
        ColorType::Rgb => (Space::Rgb, 3, false),
        ColorType::Rgba => (Space::Rgb, 4, true),
        ColorType::Indexed => return Err(ImageError::Undecodable),
    };
    let row = usize::try_from(w)
        .ok()
        .and_then(|w| w.checked_mul(channels))
        .ok_or(ImageError::TooLarge)?;
    let used = row
        .checked_mul(usize::try_from(h).map_err(|_| ImageError::TooLarge)?)
        .ok_or(ImageError::TooLarge)?;
    let data = buf.get(..used).ok_or(ImageError::Undecodable)?;
    let color_channels = if space == Space::Gray { 1 } else { 3 };
    let mut color = Vec::with_capacity(pixels.saturating_mul(color_channels));
    let mut mask = Vec::new();
    if alpha {
        mask.reserve(pixels);
        for px in data.chunks_exact(channels) {
            let (c, a) = px.split_at(color_channels);
            color.extend_from_slice(c);
            mask.extend_from_slice(a);
        }
    } else {
        color.extend_from_slice(data);
    }
    let smask = (alpha && mask.iter().any(|&a| a != 255)).then(|| deflate(&mask));
    Ok(Image {
        width: w,
        height: h,
        space,
        data: deflate(&color),
        dct: false,
        inverted: false,
        smask,
        orientation: 1,
    })
}

fn be16(b: &[u8], i: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*b.get(i)?, *b.get(i.checked_add(1)?)?]))
}

/// What the JPEG walk found.
#[derive(Debug, Default)]
struct JpegHeader {
    width: u32,
    height: u32,
    components: u8,
    adobe: bool,
    orientation: u8,
    /// The rebuilt file.
    out: Vec<u8>,
}

fn jpeg_walk(bytes: &[u8]) -> Result<JpegHeader, ImageError> {
    let bad = ImageError::Undecodable;
    let mut h = JpegHeader {
        orientation: 1,
        ..JpegHeader::default()
    };
    h.out.extend_from_slice(&[0xFF, 0xD8]);
    let mut i: usize = 2;
    let mut frame = false;
    loop {
        if bytes.get(i) != Some(&0xFF) {
            return Err(bad);
        }
        while bytes.get(i) == Some(&0xFF) {
            i = i.checked_add(1).ok_or(bad)?;
        }
        let marker = *bytes.get(i).ok_or(bad)?;
        let seg = i.checked_add(1).ok_or(bad)?;
        match marker {
            0xD0..=0xD7 | 0x01 => {
                i = seg;
                continue;
            }
            0xD9 => return Err(bad),
            _ => {}
        }
        let len = usize::from(be16(bytes, seg).ok_or(bad)?);
        if len < 2 {
            return Err(bad);
        }
        let end = seg.checked_add(len).ok_or(bad)?;
        let body = bytes.get(seg.checked_add(2).ok_or(bad)?..end).ok_or(bad)?;
        let whole = bytes.get(i.checked_sub(1).ok_or(bad)?..end).ok_or(bad)?;
        match marker {
            // Huffman baseline, extended and progressive frames.
            0xC0..=0xC2 => {
                if frame {
                    return Err(bad);
                }
                frame = true;
                let precision = *body.first().ok_or(bad)?;
                h.height = u32::from(be16(body, 1).ok_or(bad)?);
                h.width = u32::from(be16(body, 3).ok_or(bad)?);
                h.components = *body.get(5).ok_or(bad)?;
                if precision != 8 || !matches!(h.components, 1 | 3 | 4) {
                    return Err(bad);
                }
                side_ok(h.width, h.height)?;
                h.out.extend_from_slice(whole);
            }
            // Lossless, hierarchical and arithmetic-coded frames: DCTDecode has no use
            // for them.
            0xC3 | 0xC5..=0xC7 | 0xC8..=0xCB | 0xCD..=0xCF => return Err(bad),
            // Tables and restart interval.
            0xC4 | 0xDB | 0xDD | 0xCC => h.out.extend_from_slice(whole),
            0xEE => {
                if body.starts_with(b"Adobe") {
                    h.adobe = true;
                    h.out.extend_from_slice(whole);
                }
            }
            0xE1 => {
                if let Some(rest) = body.strip_prefix(b"Exif\0\0") {
                    h.orientation = exif_orientation(rest).unwrap_or(1);
                }
            }
            0xDA => {
                if !frame {
                    return Err(bad);
                }
                // The scans and everything after them, up to the last EOI.
                let rest = bytes.get(i.checked_sub(1).ok_or(bad)?..).ok_or(bad)?;
                let eoi = rest
                    .windows(2)
                    .rposition(|w| w == [0xFF, 0xD9])
                    .ok_or(bad)?;
                let upto = eoi.checked_add(2).ok_or(bad)?;
                h.out.extend_from_slice(rest.get(..upto).ok_or(bad)?);
                return Ok(h);
            }
            // APPn, COM and anything else: dropped.
            _ => {}
        }
        i = end;
    }
}

/// The orientation tag (0x0112) of IFD0 in an EXIF TIFF block.
fn exif_orientation(tiff: &[u8]) -> Option<u8> {
    let le = match tiff.get(..2)? {
        b"II" => true,
        b"MM" => false,
        _ => return None,
    };
    let r16 = |i: usize| -> Option<u16> {
        let b = [*tiff.get(i)?, *tiff.get(i.checked_add(1)?)?];
        Some(if le {
            u16::from_le_bytes(b)
        } else {
            u16::from_be_bytes(b)
        })
    };
    let r32 = |i: usize| -> Option<u32> {
        let b = [
            *tiff.get(i)?,
            *tiff.get(i.checked_add(1)?)?,
            *tiff.get(i.checked_add(2)?)?,
            *tiff.get(i.checked_add(3)?)?,
        ];
        Some(if le {
            u32::from_le_bytes(b)
        } else {
            u32::from_be_bytes(b)
        })
    };
    let ifd = usize::try_from(r32(4)?).ok()?;
    let n = usize::from(r16(ifd)?).min(512);
    for k in 0..n {
        let e = ifd.checked_add(2)?.checked_add(k.checked_mul(12)?)?;
        if r16(e)? == 0x0112 {
            let v = r16(e.checked_add(8)?)?;
            return u8::try_from(v).ok().filter(|v| (1..=8).contains(v));
        }
    }
    None
}

fn jpeg_image(bytes: &[u8]) -> Result<Image, ImageError> {
    use zune_jpeg::zune_core::options::DecoderOptions;
    let h = jpeg_walk(bytes)?;
    let side = usize::try_from(MAX_IMAGE_SIDE).map_err(|_| ImageError::TooLarge)?;
    let options = DecoderOptions::new_safe()
        .set_max_width(side)
        .set_max_height(side)
        .set_strict_mode(true);
    let mut decoder = zune_jpeg::JpegDecoder::new_with_options(Cursor::new(&h.out), options);
    decoder.decode().map_err(|_| ImageError::Undecodable)?;
    let space = match h.components {
        1 => Space::Gray,
        3 => Space::Rgb,
        _ => Space::Cmyk,
    };
    Ok(Image {
        width: h.width,
        height: h.height,
        space,
        inverted: space == Space::Cmyk && h.adobe,
        data: h.out,
        dct: true,
        smask: None,
        orientation: h.orientation,
    })
}

#[cfg(test)]
mod tests {
    // Test code: a panic is the failure report (CLAUDE.md).
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn exif_orientation_reads_both_byte_orders() {
        let mut mm = b"MM\0\x2a\0\0\0\x08\0\x01".to_vec();
        mm.extend_from_slice(&[0x01, 0x12, 0, 3, 0, 0, 0, 1, 0, 6, 0, 0]);
        assert_eq!(exif_orientation(&mm), Some(6));
        let mut ii = b"II\x2a\0\x08\0\0\0\x01\0".to_vec();
        ii.extend_from_slice(&[0x12, 0x01, 3, 0, 1, 0, 0, 0, 8, 0, 0, 0]);
        assert_eq!(exif_orientation(&ii), Some(8));
        assert_eq!(exif_orientation(b"II"), None);
    }

    #[test]
    fn junk_is_undecodable_not_a_panic() {
        assert_eq!(load(b"GIF89a").unwrap_err(), ImageError::Undecodable);
        assert_eq!(load(&[0xFF, 0xD8]).unwrap_err(), ImageError::Undecodable);
        assert_eq!(
            load(&[0xFF, 0xD8, 0xFF, 0xC0, 0, 1]).unwrap_err(),
            ImageError::Undecodable
        );
        assert_eq!(
            load(b"\x89PNG\r\n\x1a\n\0\0").unwrap_err(),
            ImageError::Undecodable
        );
    }
}
