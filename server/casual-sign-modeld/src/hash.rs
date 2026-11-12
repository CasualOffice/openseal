//! Page hashes (piece I; `ML-05`, docs/33 §5.2): the first, model-free stage of template
//! matching. Each page is rendered at 72 DPI in grey, then hashed twice with
//! `image_hasher` 3.1.1: a 64-bit difference hash (dHash: `Gradient` over a 9×8 resize)
//! and a 64-bit DCT perceptual hash (pHash: `Median` over the 8×8 low frequencies of a
//! 16×16 DCT). The worker stores both as `BIGINT` and compares them by Hamming distance.
//!
//! **Rendering.** `raster.rs` (piece C) is still a stub, so this module renders with
//! `hayro` directly, in process: the page box is checked against [`MAX_RASTER_SIDE`]
//! before anything is allocated (a larger page renders at a lower resolution, docs/21
//! §ML), an encrypted or unreadable PDF and a page outside the document are refused
//! (`CS-ML-0006`), and a panic inside the rasteriser is caught and reported as
//! `CS-ML-0006`, never passed on. **What it does not have yet** is piece C's killable
//! child process: no per-page time cap, no decoded-image budget, no `RLIMIT_AS`
//! (`SEC-I01`). When piece C lands, [`render_each`] is replaced by its raster call and
//! the hashing below stays as it is. Recorded for the merge.
//!
//! **Memory.** Pages are rendered one at a time and each is hashed, and its raster
//! dropped, before the next is rendered: a request holds one page raster at once (at most
//! 16 MiB of grey plus its 64 MiB colour buffer), never all of its up to [`MAX_PAGES`].
//! The request's deadline is checked before every page (`CS-ML-0007`).
//!
//! Hashes are of the rendered pixels only; no text is read, and nothing here is logged.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::time::{Duration, Instant};

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
///
/// Not `Clone`: a page raster can be 16 MiB, and the tests count the live ones
/// ([`live_rasters`]) to prove a request holds at most one at a time.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct GreyPage {
    /// Width in pixels.
    pub(crate) width: u32,
    /// Height in pixels.
    pub(crate) height: u32,
    /// The pixels.
    pub(crate) pixels: Vec<u8>,
}

impl GreyPage {
    fn new(width: u32, height: u32, pixels: Vec<u8>) -> Self {
        #[cfg(test)]
        live_rasters::up();
        Self {
            width,
            height,
            pixels,
        }
    }
}

#[cfg(test)]
impl Drop for GreyPage {
    fn drop(&mut self) {
        live_rasters::down();
    }
}

/// Test-only count of the [`GreyPage`]s alive on this thread, and its high-water mark.
#[cfg(test)]
pub(crate) mod live_rasters {
    use std::cell::Cell;

    thread_local! {
        static LIVE: Cell<usize> = const { Cell::new(0) };
        static PEAK: Cell<usize> = const { Cell::new(0) };
    }

    pub(super) fn up() {
        let n = LIVE.get().saturating_add(1);
        LIVE.set(n);
        PEAK.set(PEAK.get().max(n));
    }

    pub(super) fn down() {
        LIVE.set(LIVE.get().saturating_sub(1));
    }

    /// Reset the high-water mark to the live count; returns nothing.
    pub(crate) fn reset_peak() {
        PEAK.set(LIVE.get());
    }

    /// The most rasters alive at once since [`reset_peak`].
    pub(crate) fn peak() -> usize {
        PEAK.get()
    }
}

/// Hash the pages of `request` (a HASH request). Needs no model, so it answers whatever
/// the bundle holds.
///
/// # Errors
/// `CS-ML-0004` if `request` is not a HASH request or names more than [`MAX_PAGES`]
/// pages; `CS-ML-0007` once the request's deadline passes between pages; `CS-ML-0006` for a PDF that does not open, is encrypted, or lacks a page asked
/// for, a page box under one pixel, or a page the rasteriser fails on. A page over
/// [`MAX_RASTER_SIDE`] pixels on a side is rendered smaller, not refused.
pub(crate) fn run(bundle: &Bundle, request: &Request) -> Result<Vec<PageHash>, ModeldError> {
    let started = Instant::now();
    let _ = bundle;
    let Op::Hash { pdf, pages } = &request.op else {
        return Err(ModeldError::Malformed("not a HASH request"));
    };
    let deadline = Duration::from_millis(u64::from(request.deadline_ms));
    page_hashes(pdf, pages, || started.elapsed() > deadline)
}

/// The dHash and pHash of each of `pages` (zero-based) of `pdf`, in the order asked.
///
/// Each page is hashed as soon as it is rendered and its raster dropped before the next
/// is rendered, so a request holds one page raster at a time, never all of them (up to
/// [`MAX_PAGES`] × 16 MiB). `expired` is asked before each page; once it answers true
/// the request stops with `CS-ML-0007`.
pub(crate) fn page_hashes(
    pdf: &[u8],
    pages: &[u16],
    expired: impl Fn() -> bool,
) -> Result<Vec<PageHash>, ModeldError> {
    if pages.len() > MAX_PAGES {
        return Err(ModeldError::Malformed("too many pages"));
    }
    let mut out = Vec::with_capacity(pages.len());
    render_each(pdf, pages, HASH_DPI, expired, |page, grey| {
        let (dhash, phash) = hash_grey(grey)?;
        out.push(PageHash { page, dhash, phash });
        Ok(())
    })?;
    Ok(out)
}

/// dHash and pHash of one grey raster.
///
/// # Errors
/// `CS-ML-0006` if the pixel buffer does not match its dimensions (cannot happen for a
/// raster from [`render_each`]; checked rather than assumed). Takes the page by value so
/// its pixels move into the image instead of being copied.
pub(crate) fn hash_grey(mut page: GreyPage) -> Result<(u64, u64), ModeldError> {
    let pixels = std::mem::take(&mut page.pixels);
    let img = GrayImage::from_raw(page.width, page.height, pixels)
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

/// Render `pages` of `pdf` at `dpi` to grey on white, one at a time, handing each page
/// (its index and raster) to `sink` before the next is rendered. `expired` is asked
/// before each page.
///
/// Stand-in for piece C's raster child (see the module docs); the caps are the same.
///
/// # Errors
/// `CS-ML-0007` once `expired` answers true; `CS-ML-0006` as [`page_hashes`]; any error
/// `sink` returns.
pub(crate) fn render_each(
    pdf: &[u8],
    pages: &[u16],
    dpi: f32,
    expired: impl Fn() -> bool,
    mut sink: impl FnMut(u16, GreyPage) -> Result<(), ModeldError>,
) -> Result<(), ModeldError> {
    let scale = dpi / 72.0;
    if !scale.is_finite() || scale <= 0.0 {
        return Err(ModeldError::Malformed("resolution"));
    }
    // hayro is not documented to never panic on hostile input; a panic is a refusal of
    // this document, never a crash of modeld.
    catch_unwind(AssertUnwindSafe(|| {
        render_inner(pdf, pages, scale, &expired, &mut sink)
    }))
    .unwrap_or(Err(ModeldError::Raster("rasteriser failed")))
}

fn render_inner(
    pdf: &[u8],
    pages: &[u16],
    scale: f32,
    expired: &dyn Fn() -> bool,
    sink: &mut dyn FnMut(u16, GreyPage) -> Result<(), ModeldError>,
) -> Result<(), ModeldError> {
    let doc = Pdf::new(pdf.to_vec()).map_err(|e| match e {
        hayro::hayro_syntax::LoadPdfError::Decryption(_) => ModeldError::Raster("encrypted"),
        _ => ModeldError::Raster("unreadable"),
    })?;
    let all = doc.pages();
    let cache = RenderCache::new();
    let settings = InterpreterSettings::default();
    for &index in pages {
        if expired() {
            return Err(ModeldError::Deadline);
        }
        let page = all
            .get(usize::from(index))
            .ok_or(ModeldError::Raster("page not in document"))?;
        // The pixel cap is checked from the page box before anything is allocated
        // (hayro would otherwise saturate a huge box to 65,535 pixels a side). A page
        // over it renders at a lower resolution (docs/21 §ML), which a hash does not
        // notice: it is taken over a 9×8 or 16×16 resize anyway.
        let scale = fit_scale(page.render_dimensions(), scale)?;
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
        // The colour buffer is dropped here, before the sink sees the grey page.
        drop(pixmap);
        sink(index, GreyPage::new(width, height, pixels))?;
    }
    Ok(())
}

/// The scale to render a page box of `(w, h)` points at: `scale`, lowered so neither
/// side exceeds [`MAX_RASTER_SIDE`] pixels.
///
/// # Errors
/// `CS-ML-0006` for a page box that is not finite or would be under one pixel.
fn fit_scale((w, h): (f32, f32), scale: f32) -> Result<f32, ModeldError> {
    let side = f32::from(MAX_RASTER_SIDE);
    let long = w.max(h) * scale;
    // One pixel of margin, so a rasteriser rounding up still stays within the cap.
    let scale = if long > side {
        scale * (side - 1.0) / long
    } else {
        scale
    };
    let (pw, ph) = (w * scale, h * scale);
    if !(pw.is_finite() && ph.is_finite()) || pw < 1.0 || ph < 1.0 {
        return Err(ModeldError::Raster("page box"));
    }
    Ok(scale)
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

    fn never() -> bool {
        false
    }

    /// All the requested pages' rasters, for the tests that look at them.
    fn render_grey(pdf: &[u8], pages: &[u16], dpi: f32) -> Result<Vec<GreyPage>, ModeldError> {
        let mut out = Vec::new();
        render_each(pdf, pages, dpi, never, |_, g| {
            out.push(g);
            Ok(())
        })?;
        Ok(out)
    }

    fn dist(a: u64, b: u64) -> u32 {
        (a ^ b).count_ones()
    }

    #[test]
    fn the_same_page_gives_the_same_hashes() {
        let pdf = fixture("vector/latin-consent.pdf");
        let a = page_hashes(&pdf, &[0], never).unwrap();
        let b = page_hashes(&pdf, &[0], never).unwrap();
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
        let vector = page_hashes(&fixture("vector/latin-consent.pdf"), &[0], never).unwrap()[0];
        let scan = page_hashes(
            &fixture("scans/latin-consent--200dpi-q75-skew+0.6.pdf"),
            &[0],
            never,
        )
        .unwrap()[0];
        let other = page_hashes(&fixture("vector/latin-acroform.pdf"), &[0], never).unwrap()[0];
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
            let scan = page_hashes(&fixture(&format!("scans/{name}")), &[0], never).unwrap()[0];
            let vector =
                page_hashes(&fixture(&format!("vector/{form}.pdf")), &[0], never).unwrap()[0];
            println!(
                "{name}: dhash {} phash {}",
                dist(vector.dhash, scan.dhash),
                dist(vector.phash, scan.phash)
            );
        }
    }

    /// A hostile request of many large pages must not hold every page raster at once
    /// (200 pages × 16 MiB is 3.2 GiB, past the 512 MiB slot budget, docs/33 §3.3): each
    /// page is hashed as soon as it is rendered, and its raster dropped.
    #[test]
    fn hashing_holds_at_most_one_page_raster_at_a_time() {
        let pdf = minimal_pdf("0 0 600 800");
        let pages = [0u16; 8];
        live_rasters::reset_peak();
        let hashes = page_hashes(&pdf, &pages, never).unwrap();
        assert_eq!(hashes.len(), pages.len());
        assert_eq!(live_rasters::peak(), 1, "page rasters held at once");
    }

    /// The deadline is checked before every page, not only after the last.
    #[test]
    fn a_passed_deadline_stops_between_pages() {
        use std::cell::Cell;
        let pdf = minimal_pdf("0 0 600 800");
        let asked = Cell::new(0u32);
        let err = page_hashes(&pdf, &[0, 0, 0, 0], || {
            asked.set(asked.get() + 1);
            asked.get() > 2
        })
        .unwrap_err();
        assert_eq!(err, ModeldError::Deadline);
        assert_eq!(
            asked.get(),
            3,
            "asked before pages 0, 1 and 2; page 2 never renders"
        );
    }

    #[test]
    fn hostile_input_is_refused_not_panicked() {
        assert_eq!(
            page_hashes(b"%PDF-1.7 not a pdf", &[0], never)
                .unwrap_err()
                .code(),
            "CS-ML-0006"
        );
        let pdf = fixture("vector/latin-consent.pdf");
        assert_eq!(
            page_hashes(&pdf, &[999], never).unwrap_err(),
            ModeldError::Raster("page not in document")
        );
        let many = vec![0u16; MAX_PAGES + 1];
        assert_eq!(
            page_hashes(&pdf, &many, never).unwrap_err().code(),
            "CS-ML-0004"
        );
    }

    #[test]
    fn a_page_over_the_pixel_cap_renders_smaller_never_larger() {
        // 4,097 pt wide is 4,097 px at 72 DPI, one over the cap: it renders at 4,096 or
        // fewer. 4,096 renders as is. A page box of 200,000 pt a side (far past hayro's
        // own 65,535-pixel saturation) renders within the cap too.
        for (media_box, max_w) in [
            ("0 0 4097 100", 4096),
            ("0 0 4096 100", 4096),
            ("0 0 200000 200000", 4096),
            ("0 0 600 800", 600),
        ] {
            let pdf = minimal_pdf(media_box);
            let g = render_grey(&pdf, &[0], HASH_DPI).unwrap();
            assert!(
                g[0].width <= max_w && g[0].height <= 4096,
                "{media_box}: {}x{}",
                g[0].width,
                g[0].height
            );
            assert_eq!(g[0].pixels.len(), (g[0].width * g[0].height) as usize);
            assert_eq!(page_hashes(&pdf, &[0], never).unwrap().len(), 1);
        }
        assert!(
            render_grey(&minimal_pdf("0 0 4097 100"), &[0], HASH_DPI).unwrap()[0].width >= 4090
        );
        assert_eq!(
            fit_scale((f32::INFINITY, 10.0), 1.0).unwrap_err(),
            ModeldError::Raster("page box")
        );
        assert_eq!(
            fit_scale((1e9, 1.0), 1.0).unwrap_err(),
            ModeldError::Raster("page box")
        );
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
