//! Page hashes (piece I; `ML-05`, docs/33 §5.2): the first, model-free stage of template
//! matching. Each page is rendered at 72 DPI in grey, then hashed twice with
//! `image_hasher` 3.1.1: a 64-bit difference hash (dHash: `Gradient` over a 9×8 resize)
//! and a 64-bit DCT perceptual hash (pHash: `Median` over the 8×8 low frequencies of a
//! 16×16 DCT). The worker stores both as `BIGINT` and compares them by Hamming distance.
//!
//! **Rendering.** `raster.rs` (piece C) is still a stub, so this module renders with
//! `hayro` directly, in process, behind the same caps: the page box is checked against
//! [`MAX_RASTER_SIDE`] before anything is allocated, an encrypted or unreadable PDF and a
//! page outside the document are refused (`CS-ML-0006`), and a panic inside the
//! rasteriser is caught and reported as `CS-ML-0006`, never passed on. What it does not
//! have yet is piece C's killable child process (the per-page time cap, `RLIMIT_AS`):
//! when piece C lands, [`render_grey`] is replaced by its raster call and the hashing
//! below stays as it is. Recorded for the merge.
//!
//! Hashes are of the rendered pixels only; no text is read, and nothing here is logged.

use std::panic::{AssertUnwindSafe, catch_unwind};

use hayro::hayro_interpret::InterpreterSettings;
use hayro::hayro_syntax::Pdf;
use hayro::vello_cpu::color::palette::css::WHITE;
use hayro::{PixmapSettings, RenderCache, RenderSettings};
use image::GrayImage;
use image_hasher::{HashAlg, HasherConfig};

use crate::error::ModeldError;
use crate::manifest::Bundle;
use crate::wire::{MAX_PAGES, MAX_RASTER_SIDE, Op, PageHash, Request};

/// Resolution the hashes are taken at (docs/33 §5.2): coarse enough that a scan and its
/// vector original agree, and cheap.
pub(crate) const HASH_DPI: f32 = 72.0;

/// A page rendered in 8-bit grey, row-major, `width × height` bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct GreyPage {
    /// Width in pixels.
    pub(crate) width: u32,
    /// Height in pixels.
    pub(crate) height: u32,
    /// The pixels.
    pub(crate) pixels: Vec<u8>,
}

/// Hash the pages of `request` (a HASH request). Needs no model, so it answers whatever
/// the bundle holds.
///
/// # Errors
/// `CS-ML-0004` if `request` is not a HASH request or names more than [`MAX_PAGES`]
/// pages; `CS-ML-0006` for a PDF that does not open, is encrypted, or lacks a page asked
/// for, or a page the rasteriser fails on; `CS-ML-0005` for a page whose raster would
/// exceed [`MAX_RASTER_SIDE`] pixels on a side.
pub(crate) fn run(bundle: &Bundle, request: &Request) -> Result<Vec<PageHash>, ModeldError> {
    let _ = bundle;
    let Op::Hash { pdf, pages } = &request.op else {
        return Err(ModeldError::Malformed("not a HASH request"));
    };
    page_hashes(pdf, pages)
}

/// The dHash and pHash of each of `pages` (zero-based) of `pdf`, in the order asked.
pub(crate) fn page_hashes(pdf: &[u8], pages: &[u16]) -> Result<Vec<PageHash>, ModeldError> {
    if pages.len() > MAX_PAGES {
        return Err(ModeldError::Malformed("too many pages"));
    }
    let rendered = render_grey(pdf, pages, HASH_DPI)?;
    pages
        .iter()
        .zip(rendered)
        .map(|(&page, grey)| {
            let (dhash, phash) = hash_grey(&grey)?;
            Ok(PageHash { page, dhash, phash })
        })
        .collect()
}

/// dHash and pHash of one grey raster.
///
/// # Errors
/// `CS-ML-0006` if the pixel buffer does not match its dimensions (cannot happen for a
/// raster from [`render_grey`]; checked rather than assumed).
pub(crate) fn hash_grey(page: &GreyPage) -> Result<(u64, u64), ModeldError> {
    let img = GrayImage::from_raw(page.width, page.height, page.pixels.clone())
        .ok_or(ModeldError::Raster("raster size"))?;
    let dhash = HasherConfig::with_bytes_type::<[u8; 8]>()
        .hash_size(8, 8)
        .hash_alg(HashAlg::Gradient)
        .to_hasher()
        .hash_image(&img);
    let phash = HasherConfig::with_bytes_type::<[u8; 8]>()
        .hash_size(8, 8)
        .hash_alg(HashAlg::Median)
        .preproc_dct()
        .to_hasher()
        .hash_image(&img);
    Ok((
        u64::from_be_bytes(dhash.into_inner()),
        u64::from_be_bytes(phash.into_inner()),
    ))
}

/// Render `pages` of `pdf` at `dpi` to grey on white.
///
/// Stand-in for piece C's raster child (see the module docs); the caps are the same.
pub(crate) fn render_grey(
    pdf: &[u8],
    pages: &[u16],
    dpi: f32,
) -> Result<Vec<GreyPage>, ModeldError> {
    let scale = dpi / 72.0;
    if !scale.is_finite() || scale <= 0.0 {
        return Err(ModeldError::Malformed("resolution"));
    }
    // hayro is not documented to never panic on hostile input; a panic is a refusal of
    // this document, never a crash of modeld.
    catch_unwind(AssertUnwindSafe(|| render_inner(pdf, pages, scale)))
        .unwrap_or(Err(ModeldError::Raster("rasteriser failed")))
}

fn render_inner(pdf: &[u8], pages: &[u16], scale: f32) -> Result<Vec<GreyPage>, ModeldError> {
    let doc = Pdf::new(pdf.to_vec()).map_err(|e| match e {
        hayro::hayro_syntax::LoadPdfError::Decryption(_) => ModeldError::Raster("encrypted"),
        _ => ModeldError::Raster("unreadable"),
    })?;
    let all = doc.pages();
    let cache = RenderCache::new();
    let settings = InterpreterSettings::default();
    let mut out = Vec::with_capacity(pages.len());
    for &index in pages {
        let page = all
            .get(usize::from(index))
            .ok_or(ModeldError::Raster("page not in document"))?;
        // The pixel cap is checked from the page box before anything is allocated
        // (hayro would otherwise saturate a huge box to 65,535 pixels a side).
        let (w, h) = page.render_dimensions();
        let (pw, ph) = (w * scale, h * scale);
        let side = f32::from(MAX_RASTER_SIDE);
        if !(pw.is_finite() && ph.is_finite()) || pw < 1.0 || ph < 1.0 {
            return Err(ModeldError::Raster("page box"));
        }
        if pw > side || ph > side {
            return Err(ModeldError::OverBound("page pixels"));
        }
        let pixmap = hayro::render(
            page,
            &cache,
            &settings,
            &RenderSettings::default(),
            &PixmapSettings {
                x_scale: scale,
                y_scale: scale,
                bg_color: WHITE,
            },
        );
        let width = u32::from(pixmap.width());
        let height = u32::from(pixmap.height());
        // Premultiplied RGBA over an opaque white background: alpha is 255, so the
        // colour channels are the colour. Rec. 601 luma, rounded.
        let pixels: Vec<u8> = pixmap
            .data_as_u8_slice()
            .chunks_exact(4)
            .map(|px| match *px {
                [r, g, b, _] => {
                    let y = 0.299 * f32::from(r) + 0.587 * f32::from(g) + 0.114 * f32::from(b);
                    // `as` saturates a float to the u8 range; `y` is in 0..=255 anyway.
                    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                    let v = y.round() as u8;
                    v
                }
                _ => 255,
            })
            .collect();
        out.push(GreyPage {
            width,
            height,
            pixels,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    // Test code: a panic is the failure report.
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::arithmetic_side_effects
    )]
    use super::*;
    use std::path::PathBuf;

    fn fixture(rel: &str) -> Vec<u8> {
        let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/ml")
            .join(rel);
        std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
    }

    fn dist(a: u64, b: u64) -> u32 {
        (a ^ b).count_ones()
    }

    #[test]
    fn the_same_page_gives_the_same_hashes() {
        let pdf = fixture("vector/latin-consent.pdf");
        let a = page_hashes(&pdf, &[0]).unwrap();
        let b = page_hashes(&pdf, &[0]).unwrap();
        assert_eq!(a, b);
        assert_eq!(a[0].page, 0);
        // A blank-looking hash would make every page match every other.
        assert_ne!(a[0].dhash, 0);
        assert_ne!(a[0].phash, 0);
    }

    /// The acceptance pair: a degraded scan (200 DPI, JPEG q75, skewed +0.6°) of a form
    /// is within Hamming distance 10 of its vector original on both hashes, and a
    /// different form is not.
    #[test]
    fn a_scan_is_near_its_vector_original_and_far_from_another_form() {
        let vector = page_hashes(&fixture("vector/latin-consent.pdf"), &[0]).unwrap()[0];
        let scan = page_hashes(
            &fixture("scans/latin-consent--200dpi-q75-skew+0.6.pdf"),
            &[0],
        )
        .unwrap()[0];
        let other = page_hashes(&fixture("vector/latin-acroform.pdf"), &[0]).unwrap()[0];
        let (dd, dp) = (
            dist(vector.dhash, scan.dhash),
            dist(vector.phash, scan.phash),
        );
        assert!(dd <= 10 && dp <= 10, "scan: dhash {dd}, phash {dp}");
        let (od, op) = (
            dist(vector.dhash, other.dhash),
            dist(vector.phash, other.phash),
        );
        assert!(od > 10 || op > 10, "another form: dhash {od}, phash {op}");
    }

    /// Distances for every upright scan in fixtures/ml, printed for the record
    /// (`--nocapture`); asserted only for the acceptance pair above.
    #[test]
    fn distances_over_the_scan_fixtures_are_reported() {
        let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/ml/scans");
        let mut names: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        for name in names {
            let Some((form, _)) = name.split_once("--") else {
                continue;
            };
            let scan = page_hashes(&fixture(&format!("scans/{name}")), &[0]).unwrap()[0];
            let vector = page_hashes(&fixture(&format!("vector/{form}.pdf")), &[0]).unwrap()[0];
            println!(
                "{name}: dhash {} phash {}",
                dist(vector.dhash, scan.dhash),
                dist(vector.phash, scan.phash)
            );
        }
    }

    #[test]
    fn hostile_input_is_refused_not_panicked() {
        assert_eq!(
            page_hashes(b"%PDF-1.7 not a pdf", &[0]).unwrap_err().code(),
            "CS-ML-0006"
        );
        let pdf = fixture("vector/latin-consent.pdf");
        assert_eq!(
            page_hashes(&pdf, &[999]).unwrap_err(),
            ModeldError::Raster("page not in document")
        );
        let many = vec![0u16; MAX_PAGES + 1];
        assert_eq!(page_hashes(&pdf, &many).unwrap_err().code(), "CS-ML-0004");
    }

    #[test]
    fn a_page_over_the_pixel_cap_is_refused_before_rendering() {
        // 4,097 pt wide: 4,097 px at 72 DPI, one over the cap (and small to render, so the
        // test stays cheap if the check is ever removed). 4,096 is allowed.
        let pdf = minimal_pdf("0 0 4097 100");
        assert_eq!(
            page_hashes(&pdf, &[0]).unwrap_err(),
            ModeldError::OverBound("page pixels")
        );
        let ok = minimal_pdf("0 0 4096 100");
        assert_eq!(page_hashes(&ok, &[0]).unwrap().len(), 1);
    }

    /// A one-page PDF with an empty content stream and this media box, offsets computed.
    fn minimal_pdf(media_box: &str) -> Vec<u8> {
        let objs = [
            "<< /Type /Catalog /Pages 2 0 R >>".to_owned(),
            "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_owned(),
            format!(
                "<< /Type /Page /Parent 2 0 R /MediaBox [{media_box}] /Contents 4 0 R /Resources << >> >>"
            ),
            "<< /Length 0 >>\nstream\n\nendstream".to_owned(),
        ];
        let mut out = b"%PDF-1.7\n".to_vec();
        let mut offsets = Vec::new();
        for (i, o) in objs.iter().enumerate() {
            offsets.push(out.len());
            out.extend_from_slice(format!("{} 0 obj\n{o}\nendobj\n", i + 1).as_bytes());
        }
        let xref = out.len();
        out.extend_from_slice(
            format!("xref\n0 {}\n0000000000 65535 f \n", objs.len() + 1).as_bytes(),
        );
        for off in offsets {
            out.extend_from_slice(format!("{off:010} 00000 n \n").as_bytes());
        }
        out.extend_from_slice(
            format!(
                "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
                objs.len() + 1
            )
            .as_bytes(),
        );
        out
    }
}
