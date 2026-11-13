//! Page rasteriser (piece C of ADR-029's build plan; `ML-02`, `PDF-REN-01`): `hayro` 0.8.0
//! renders a page of an opened PDF to a grey raster for OCR and the rule finder.
//!
//! **Rasterising never runs in the daemon.** A [`Document`] starts one child process per
//! opened PDF (the modeld binary with the fixed argument [`CHILD_ARG`], an empty
//! environment, no inherited descriptor besides its three standard streams, stderr
//! discarded), which sets its own `RLIMIT_AS`, `RLIMIT_CPU`, `RLIMIT_CORE` (0) and
//! `RLIMIT_NOFILE` before it reads a byte of the PDF. `hayro` cannot cancel a render, so
//! the per-page time cap is enforced by killing that child alone; the next page starts a
//! fresh one, and after [`MAX_KILLS`] kills or deaths in one document the remaining pages
//! are not rendered (docs/33 §3.3, review defect 11, `SEC-I01`, `SEC-I02`).
//!
//! **Linux only.** The child's limits are the containment, and only Linux enforces
//! `RLIMIT_AS` (macOS accepts it and ignores it; Windows has no `setrlimit`). modeld ships
//! in a Linux container, so on any other platform [`Document::open`] starts no child and
//! answers `CS-ML-0014`, and a child started there by hand exits before reading a byte.
//!
//! Inside the child, before anything is allocated for a page ([`render_page`]):
//!
//! - **Pixel cap:** the raster size is computed from the page box. A page larger than
//!   [`MAX_LONG_SIDE`] px on its long side or [`MAX_PIXELS`] in all renders at a lower
//!   resolution, down to [`MIN_FIT_DPI`]; below that it is refused (`CS-ML-0005`).
//! - **Decoded image budget:** the image XObjects the page can draw (through its Form
//!   XObjects, at most [`MAX_FORM_DEPTH`] deep and [`MAX_XOBJECTS`] visited) are summed by
//!   their declared decoded size (width × height × components × bits); over
//!   [`MAX_DECODED`] the page is refused (`CS-ML-0005`). Inline images are not counted;
//!   the child's address-space limit bounds them.
//! - Annotations are not rendered: OCR reads the page content a scanner produced.
//!
//! The parent reads the child's answers as hostile input: every size is checked against
//! the same caps before a buffer is allocated.

use std::collections::HashSet;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, ExitCode, Stdio};
use std::sync::Arc;
use std::sync::mpsc;
use std::time::Duration;

use hayro::hayro_interpret::InterpreterSettings;
use hayro::hayro_syntax::Pdf;
use hayro::hayro_syntax::object::{Array, Dict, Name, Stream};
use hayro::hayro_syntax::page::{Page, Rotation};
use hayro::vello_cpu::color::palette::css::WHITE;
use hayro::{PixmapSettings, RenderCache, RenderSettings};

use crate::error::ModeldError;
use crate::wire::{MAX_PDF, Rect};

/// The argument that makes the modeld binary run as a raster child.
pub const CHILD_ARG: &str = "raster-child";
/// Raster pixels on the long side, at most (docs/33 §4).
pub const MAX_LONG_SIDE: u32 = 4096;
/// Raster pixels in all, at most (16.8 MP, docs/33 §4).
pub const MAX_PIXELS: u64 = 16_800_000;
/// The lowest resolution a large page is rendered at to fit the caps; a page that does
/// not fit at this resolution is refused (`CS-ML-0005`): text is unreadable below it.
pub const MIN_FIT_DPI: u16 = 50;
/// Declared decoded image data a page may draw (256 MiB, as `SEC-P01`).
pub const MAX_DECODED: u64 = 256 << 20;
/// Form XObjects nested deeper than this are refused (`CS-ML-0005`).
pub const MAX_FORM_DEPTH: usize = 32;
/// XObjects visited per page while summing the image budget.
pub const MAX_XOBJECTS: usize = 10_000;
/// Rasterise time per page, enforced by killing the child (docs/33 §4).
pub const PAGE_TIME: Duration = Duration::from_secs(10);
/// The child's address-space limit (provisional, docs/33 §3.3).
pub const ADDRESS_SPACE: u64 = 1 << 30;
/// The child's CPU-time limit in seconds: a backstop behind the per-page wall-clock kill.
pub const CPU_SECONDS: u64 = 30 * 60;
/// Child kills or deaths per document after which later pages are not rendered.
pub const MAX_KILLS: u8 = 3;
/// File descriptors the child may hold (its three standard streams and a few spare).
#[cfg(target_os = "linux")]
const CHILD_FILES: u64 = 16;

/// A rendered page: grey pixels, row by row, top left first, and the geometry the
/// rasteriser used (see [`crate::wire::OcrPage::to_user`]).
#[derive(Clone, PartialEq)]
pub struct Raster {
    /// Width in pixels.
    pub width: u16,
    /// Height in pixels.
    pub height: u16,
    /// The resolution rendered at.
    pub dpi: u16,
    /// The page's `/Rotate`: 0, 90, 180 or 270.
    pub rotate: u16,
    /// The page's crop box intersected with its media box, PDF user space.
    pub crop: Rect,
    /// `width × height` grey levels (0 black, 255 white).
    pub grey: Vec<u8>,
}

impl core::fmt::Debug for Raster {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Never the pixels: they are document content.
        f.debug_struct("Raster")
            .field("width", &self.width)
            .field("height", &self.height)
            .field("dpi", &self.dpi)
            .field("rotate", &self.rotate)
            .finish_non_exhaustive()
    }
}

/// Bounds a [`Document`]'s child runs under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RasterLimits {
    /// Wall-clock time per page (and to open the PDF) before the child is killed.
    pub page_time: Duration,
    /// The child's `RLIMIT_AS`, bytes.
    pub address_space: u64,
    /// The child's `RLIMIT_CPU`, seconds.
    pub cpu_seconds: u64,
    /// Kills or deaths per document before later pages are not rendered.
    pub max_kills: u8,
}

impl Default for RasterLimits {
    fn default() -> Self {
        Self {
            page_time: PAGE_TIME,
            address_space: ADDRESS_SPACE,
            cpu_seconds: CPU_SECONDS,
            max_kills: MAX_KILLS,
        }
    }
}

fn raster_error(why: &'static str) -> ModeldError {
    ModeldError::Raster(why)
}

/// The pixel size of a `w_pt × h_pt` page at `dpi`, computed as `hayro` sizes its pixmap.
fn pixels_at(w_pt: f32, h_pt: f32, dpi: u16) -> (u32, u32) {
    let s = f32::from(dpi) / 72.0;
    // Float to integer `as` saturates and floors: the same arithmetic hayro uses.
    ((w_pt * s) as u32, (h_pt * s) as u32)
}

/// The resolution a `w_pt × h_pt` page (as displayed) renders at when `dpi` is asked:
/// `dpi`, or the highest lower one at which the raster fits [`MAX_LONG_SIDE`] and
/// [`MAX_PIXELS`], not below [`MIN_FIT_DPI`].
///
/// # Errors
/// `CS-ML-0005` when the page does not fit even at [`MIN_FIT_DPI`]; `CS-ML-0006` for a
/// page box that is not a positive finite size.
pub fn fit_dpi(w_pt: f32, h_pt: f32, dpi: u16) -> Result<u16, ModeldError> {
    if !(w_pt.is_finite() && h_pt.is_finite() && w_pt > 0.0 && h_pt > 0.0) {
        return Err(raster_error("page box"));
    }
    let mut d = dpi;
    while d >= MIN_FIT_DPI {
        let (w, h) = pixels_at(w_pt, h_pt, d);
        if w >= 1
            && h >= 1
            && w.max(h) <= MAX_LONG_SIDE
            && u64::from(w).saturating_mul(u64::from(h)) <= MAX_PIXELS
        {
            return Ok(d);
        }
        d = d.saturating_sub(1);
    }
    Err(ModeldError::OverBound("page pixels"))
}

/// Components per pixel of an image's colour space, conservatively 4 when unknown.
fn components(d: &Dict<'_>) -> u64 {
    let name_components = |n: &[u8]| match n {
        b"DeviceGray" | b"G" | b"CalGray" | b"Indexed" | b"I" => 1,
        b"DeviceRGB" | b"RGB" | b"CalRGB" | b"Lab" => 3,
        _ => 4,
    };
    if let Some(n) = d.get::<Name<'_>>(b"ColorSpace").or_else(|| d.get(b"CS")) {
        return name_components(n.as_ref());
    }
    if let Some(a) = d.get::<Array<'_>>(b"ColorSpace").or_else(|| d.get(b"CS")) {
        let mut items = a.iter::<hayro::hayro_syntax::object::Object<'_>>();
        let family = items.next().and_then(|o| o.into_name());
        return match family.as_ref().map(AsRef::as_ref) {
            Some(b"Indexed" | b"I") => 1,
            Some(b"ICCBased") => items
                .next()
                .and_then(|o| o.into_stream())
                .and_then(|s| s.dict().get::<i64>(b"N"))
                .and_then(|n| u64::try_from(n).ok())
                .filter(|n| (1..=4).contains(n))
                .unwrap_or(4),
            Some(other) => name_components(other),
            None => 4,
        };
    }
    4
}

/// The declared decoded size of an image XObject, bytes.
fn image_bytes(d: &Dict<'_>) -> u64 {
    let num = |a: &[u8], b: &[u8]| {
        d.get::<i64>(a)
            .or_else(|| d.get::<i64>(b))
            .and_then(|n| u64::try_from(n).ok())
            .unwrap_or(0)
    };
    let w = num(b"Width", b"W");
    let h = num(b"Height", b"H");
    let mask = d.get::<bool>(b"ImageMask").unwrap_or(false);
    let (comps, bpc) = if mask {
        (1, 1)
    } else {
        (components(d), num(b"BitsPerComponent", b"BPC").clamp(1, 16))
    };
    let bits_per_row = w.saturating_mul(comps).saturating_mul(bpc);
    bits_per_row.div_ceil(8).saturating_mul(h)
}

/// Running totals of the decoded-image walk.
#[derive(Default)]
struct Budget {
    seen: HashSet<(i32, i32)>,
    visits: usize,
    total: u64,
}

impl Budget {
    fn count(&mut self, stream: &Stream<'_>) -> Result<bool, ModeldError> {
        self.visits = self.visits.saturating_add(1);
        if self.visits > MAX_XOBJECTS {
            return Err(ModeldError::OverBound("XObjects drawn by one page"));
        }
        let id = stream.obj_id();
        Ok(self.seen.insert((id.obj_number, id.gen_number)))
    }

    fn add(&mut self, bytes: u64) -> Result<(), ModeldError> {
        self.total = self.total.saturating_add(bytes);
        if self.total > MAX_DECODED {
            return Err(ModeldError::OverBound("decoded image data"));
        }
        Ok(())
    }

    fn walk(&mut self, xobjects: &Dict<'_>, depth: usize) -> Result<(), ModeldError> {
        if depth > MAX_FORM_DEPTH {
            return Err(ModeldError::OverBound("Form XObject nesting"));
        }
        for key in xobjects.keys() {
            let Some(stream) = xobjects.get::<Stream<'_>>(key.as_ref()) else {
                continue;
            };
            if !self.count(&stream)? {
                continue;
            }
            let d = stream.dict();
            match d.get::<Name<'_>>(b"Subtype").as_ref().map(AsRef::as_ref) {
                Some(b"Image") => {
                    self.add(image_bytes(d))?;
                    if let Some(smask) = d.get::<Stream<'_>>(b"SMask")
                        && self.count(&smask)?
                    {
                        self.add(image_bytes(smask.dict()))?;
                    }
                }
                Some(b"Form") => {
                    if let Some(inner) = d
                        .get::<Dict<'_>>(b"Resources")
                        .and_then(|r| r.get::<Dict<'_>>(b"XObject"))
                    {
                        self.walk(&inner, depth.saturating_add(1))?;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// Check the decoded image data `page` can draw against [`MAX_DECODED`].
///
/// # Errors
/// `CS-ML-0005` when it is over the budget, nests Form XObjects deeper than
/// [`MAX_FORM_DEPTH`] or draws more than [`MAX_XOBJECTS`].
pub fn check_image_budget(page: &Page<'_>) -> Result<u64, ModeldError> {
    let mut b = Budget::default();
    b.walk(&page.resources().x_objects, 0)?;
    Ok(b.total)
}

/// Render page `index` of `pdf` at `dpi` (lowered to fit the caps) in this process.
/// Only the raster child calls this on a hostile PDF; the fuzz target and tests call it
/// directly.
///
/// # Errors
/// `CS-ML-0005` over the pixel cap or the decoded image budget; `CS-ML-0006` for a page
/// that does not exist or a page box that is not a size.
pub fn render_page(pdf: &Pdf, index: usize, dpi: u16) -> Result<Raster, ModeldError> {
    let pages = pdf.pages();
    let page = pages.get(index).ok_or(raster_error("no such page"))?;
    let (w_pt, h_pt) = page.render_dimensions();
    let dpi = fit_dpi(w_pt, h_pt, dpi)?;
    check_image_budget(page)?;
    let (want_w, want_h) = pixels_at(w_pt, h_pt, dpi);
    let s = f32::from(dpi) / 72.0;
    let settings = InterpreterSettings {
        render_annotations: false,
        ..InterpreterSettings::default()
    };
    let pixmap = hayro::render(
        page,
        &RenderCache::new(),
        &settings,
        &RenderSettings::default(),
        &PixmapSettings {
            x_scale: s,
            y_scale: s,
            bg_color: WHITE,
        },
    );
    let (width, height) = (pixmap.width(), pixmap.height());
    if u32::from(width) != want_w || u32::from(height) != want_h {
        return Err(raster_error("raster size"));
    }
    let grey: Vec<u8> = pixmap
        .data_as_u8_slice()
        .chunks_exact(4)
        .map(|p| match p {
            // Opaque over a white background: premultiplied equals straight.
            [r, g, b, _] => {
                // At most 1000 × 255: no overflow.
                let y = (299 * u32::from(*r))
                    .saturating_add(587 * u32::from(*g))
                    .saturating_add(114 * u32::from(*b));
                u8::try_from(y / 1000).unwrap_or(u8::MAX)
            }
            _ => u8::MAX,
        })
        .collect();
    let c = page.intersected_crop_box();
    let crop = if c.width() > 0.0 && c.height() > 0.0 {
        [c.x0 as f32, c.y0 as f32, c.x1 as f32, c.y1 as f32]
    } else {
        // hayro renders a zero-area page as A4; report the area it rendered.
        let (bw, bh) = page.base_dimensions();
        [0.0, 0.0, bw, bh]
    };
    let rotate = match page.rotation() {
        Rotation::None => 0,
        Rotation::Horizontal => 90,
        Rotation::Flipped => 180,
        Rotation::FlippedHorizontal => 270,
    };
    Ok(Raster {
        width,
        height,
        dpi,
        rotate,
        crop,
        grey,
    })
}

/// Open `pdf` and render page `index` at `dpi`, in this process: what the raster child
/// does for one page. For the fuzz target and tests; the daemon never calls it.
///
/// # Errors
/// As [`render_page`]; `CS-ML-0006` when the PDF does not open.
pub fn render_bytes(pdf: &[u8], index: usize, dpi: u16) -> Result<Raster, ModeldError> {
    let pdf = Pdf::new(pdf.to_vec()).map_err(|_| raster_error("the PDF does not open"))?;
    render_page(&pdf, index, dpi)
}

// ---- the child's side -------------------------------------------------------------

#[cfg(target_os = "linux")]
fn set_limit(resource: rustix::process::Resource, value: u64) -> bool {
    rustix::process::setrlimit(
        resource,
        rustix::process::Rlimit {
            current: Some(value),
            maximum: Some(value),
        },
    )
    .is_ok()
}

fn read_u16(r: &mut impl Read) -> Option<u16> {
    let mut b = [0u8; 2];
    r.read_exact(&mut b).ok()?;
    Some(u16::from_be_bytes(b))
}

fn read_u32(r: &mut impl Read) -> Option<u32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b).ok()?;
    Some(u32::from_be_bytes(b))
}

fn write_error(w: &mut impl Write, e: &ModeldError) -> std::io::Result<()> {
    w.write_all(&[1])?;
    w.write_all(&e.number().to_be_bytes())?;
    w.flush()
}

fn write_raster(w: &mut impl Write, r: &Raster) -> std::io::Result<()> {
    w.write_all(&[0])?;
    for v in [r.width, r.height, r.dpi, r.rotate] {
        w.write_all(&v.to_be_bytes())?;
    }
    for v in r.crop {
        w.write_all(&v.to_be_bytes())?;
    }
    w.write_all(&r.grey)?;
    w.flush()
}

/// Set the child's limits on itself; false when any cannot be set.
#[cfg(target_os = "linux")]
fn set_limits(address_space: u64, cpu: u64) -> bool {
    use rustix::process::Resource;
    set_limit(Resource::Core, 0)
        && set_limit(Resource::Nofile, CHILD_FILES)
        && set_limit(Resource::Cpu, cpu)
        && set_limit(Resource::As, address_space)
}

/// Off Linux the limits cannot be enforced (see the module notes), so the child refuses
/// to run at all.
#[cfg(not(target_os = "linux"))]
fn set_limits(_address_space: u64, _cpu: u64) -> bool {
    false
}

/// Whether this platform can run the raster child: only Linux enforces its limits.
pub const CHILD_SUPPORTED: bool = cfg!(target_os = "linux");

/// The raster child's main: `casual-sign-modeld raster-child <address-space> <cpu-s>`.
/// Sets its limits, reads the PDF from stdin (`len:u32be bytes`), answers `0 pages:u32be`
/// or `1 code:u16be`, then renders each `page:u16be dpi:u16be` asked for until stdin
/// closes. A panic inside the renderer answers `CS-ML-0006` for that page.
#[must_use]
pub fn child_main(args: &[String]) -> ExitCode {
    let mut nums = args.iter().map(|a| a.parse::<u64>().ok());
    let (Some(Some(address_space)), Some(Some(cpu))) = (nums.next(), nums.next()) else {
        return ExitCode::from(2);
    };
    if !set_limits(address_space, cpu) {
        return ExitCode::from(3);
    }
    // Nothing a renderer prints may reach a log: stderr is discarded by the parent, and
    // the panic message is suppressed here too.
    std::panic::set_hook(Box::new(|_| {}));
    let mut input = std::io::stdin().lock();
    let mut output = std::io::BufWriter::new(std::io::stdout().lock());
    let Some(len) = read_u32(&mut input) else {
        return ExitCode::from(4);
    };
    let Ok(len) = usize::try_from(len) else {
        return ExitCode::from(4);
    };
    if len > MAX_PDF {
        return ExitCode::from(4);
    }
    let mut bytes = vec![0u8; len];
    if input.read_exact(&mut bytes).is_err() {
        return ExitCode::from(4);
    }
    let opened = std::panic::catch_unwind(move || Pdf::new(bytes).ok())
        .ok()
        .flatten();
    let Some(pdf) = opened else {
        let _ = write_error(&mut output, &raster_error("the PDF does not open"));
        return ExitCode::SUCCESS;
    };
    let count = u32::try_from(pdf.pages().len()).unwrap_or(u32::MAX);
    if output
        .write_all(&[0])
        .and_then(|()| output.write_all(&count.to_be_bytes()))
        .and_then(|()| output.flush())
        .is_err()
    {
        return ExitCode::from(5);
    }
    while let (Some(page), Some(dpi)) = (read_u16(&mut input), read_u16(&mut input)) {
        let rendered = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            render_page(&pdf, usize::from(page), dpi)
        }))
        .unwrap_or(Err(raster_error("the renderer failed")));
        let sent = match rendered {
            Ok(r) => write_raster(&mut output, &r),
            Err(e) => write_error(&mut output, &e),
        };
        if sent.is_err() {
            return ExitCode::from(5);
        }
    }
    ExitCode::SUCCESS
}

// ---- the parent's side ------------------------------------------------------------

/// A running child: its process and pipes.
struct Running {
    child: Child,
    stdin: ChildStdin,
    stdout: Option<ChildStdout>,
}

impl Running {
    fn end(mut self) {
        drop(self.stdin);
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// What a child answered within its time, or why not.
enum Answer<T> {
    Done(T),
    TimedOut,
    Died,
}

/// A PDF opened for rasterising, with its child process. Dropping it ends the child.
pub struct Document {
    exe: PathBuf,
    pdf: Arc<Vec<u8>>,
    limits: RasterLimits,
    running: Option<Running>,
    pages: u32,
    kills: u8,
}

impl core::fmt::Debug for Document {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Document")
            .field("pages", &self.pages)
            .field("kills", &self.kills)
            .finish_non_exhaustive()
    }
}

impl Drop for Document {
    fn drop(&mut self) {
        if let Some(r) = self.running.take() {
            r.end();
        }
    }
}

/// Read a raster answer, checking every size before allocating (the child is hostile
/// once it has parsed the PDF).
fn read_answer(r: &mut impl Read, asked_dpi: u16) -> Option<Result<Raster, ModeldError>> {
    let mut status = [0u8; 1];
    r.read_exact(&mut status).ok()?;
    match status {
        [1] => {
            let n = read_u16(r)?;
            Some(Err(match ModeldError::from_number(n) {
                e @ (ModeldError::OverBound(_) | ModeldError::Raster(_)) => e,
                _ => ModeldError::RasterChild,
            }))
        }
        [0] => {
            let width = read_u16(r)?;
            let height = read_u16(r)?;
            let dpi = read_u16(r)?;
            let rotate = read_u16(r)?;
            let mut crop = [0f32; 4];
            for v in &mut crop {
                let mut b = [0u8; 4];
                r.read_exact(&mut b).ok()?;
                *v = f32::from_be_bytes(b);
            }
            let pixels = u64::from(width).saturating_mul(u64::from(height));
            if width == 0
                || height == 0
                || u32::from(width.max(height)) > MAX_LONG_SIDE
                || pixels > MAX_PIXELS
                || dpi == 0
                || dpi > asked_dpi
                || !matches!(rotate, 0 | 90 | 180 | 270)
                || !crop.iter().all(|v| v.is_finite())
            {
                return Some(Err(ModeldError::RasterChild));
            }
            let mut grey = vec![0u8; usize::try_from(pixels).ok()?];
            r.read_exact(&mut grey).ok()?;
            Some(Ok(Raster {
                width,
                height,
                dpi,
                rotate,
                crop,
                grey,
            }))
        }
        _ => Some(Err(ModeldError::RasterChild)),
    }
}

impl Document {
    /// Open `pdf` in a new raster child started from `exe` (the modeld binary).
    ///
    /// # Errors
    /// `CS-ML-0006` when the PDF does not open (or opening it outlasts the page time),
    /// `CS-ML-0014` when the child cannot start or dies, and always off Linux, where the
    /// child's limits cannot be enforced (no child is started there).
    pub fn open(exe: &Path, pdf: Vec<u8>, limits: RasterLimits) -> Result<Self, ModeldError> {
        let mut doc = Self {
            exe: exe.to_owned(),
            pdf: Arc::new(pdf),
            limits,
            running: None,
            pages: 0,
            kills: 0,
        };
        doc.pages = doc.start()?;
        if doc.pages == 0 {
            return Err(raster_error("the PDF has no pages"));
        }
        Ok(doc)
    }

    /// Pages in the document.
    #[must_use]
    pub fn pages(&self) -> u32 {
        self.pages
    }

    /// Child kills and deaths so far.
    #[must_use]
    pub fn kills(&self) -> u8 {
        self.kills
    }

    /// Start a child and hand it the PDF; its page count.
    fn start(&mut self) -> Result<u32, ModeldError> {
        if !CHILD_SUPPORTED {
            return Err(ModeldError::RasterChild);
        }
        let mut child = Command::new(&self.exe)
            .arg(CHILD_ARG)
            .arg(self.limits.address_space.to_string())
            .arg(self.limits.cpu_seconds.to_string())
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| ModeldError::RasterChild)?;
        let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(ModeldError::RasterChild);
        };
        self.running = Some(Running {
            child,
            stdin,
            stdout: Some(stdout),
        });
        let pdf = Arc::clone(&self.pdf);
        let answer = self.exchange(
            move |w| {
                let n = u32::try_from(pdf.len()).map_err(|_| ())?;
                w.write_all(&n.to_be_bytes()).map_err(|_| ())?;
                w.write_all(&pdf).map_err(|_| ())?;
                w.flush().map_err(|_| ())
            },
            |r| {
                let mut status = [0u8; 1];
                r.read_exact(&mut status).ok()?;
                match status {
                    [0] => read_u32(r).map(Ok),
                    [1] => read_u16(r).map(|_| Err(raster_error("the PDF does not open"))),
                    _ => Some(Err(ModeldError::RasterChild)),
                }
            },
        );
        match answer {
            Answer::Done(r) => r,
            Answer::TimedOut => Err(raster_error("opening the PDF took too long")),
            Answer::Died => Err(ModeldError::RasterChild),
        }
    }

    /// Write a request to the running child and read its answer within the page time.
    /// The child is killed and dropped when it overruns or dies; the write happens on a
    /// helper thread too, so a child that stops reading cannot block the daemon.
    fn exchange<T: Send + 'static>(
        &mut self,
        send: impl FnOnce(&mut ChildStdin) -> Result<(), ()> + Send + 'static,
        read: impl FnOnce(&mut ChildStdout) -> Option<T> + Send + 'static,
    ) -> Answer<T> {
        let Some(mut running) = self.running.take() else {
            return Answer::Died;
        };
        let Some(stdout) = running.stdout.take() else {
            running.end();
            return Answer::Died;
        };
        self.exchange_owned(running, stdout, send, read)
    }

    fn exchange_owned<T: Send + 'static>(
        &mut self,
        running: Running,
        stdout: ChildStdout,
        send: impl FnOnce(&mut ChildStdin) -> Result<(), ()> + Send + 'static,
        read: impl FnOnce(&mut ChildStdout) -> Option<T> + Send + 'static,
    ) -> Answer<T> {
        let Running {
            mut child,
            mut stdin,
            ..
        } = running;
        let mut stdout = stdout;
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let answer = match send(&mut stdin) {
                Ok(()) => read(&mut stdout),
                Err(()) => None,
            };
            // The receiver may have given up; then the pipes are simply dropped.
            let _ = tx.send((stdin, stdout, answer));
        });
        match rx.recv_timeout(self.limits.page_time) {
            Ok((stdin, stdout, Some(answer))) => {
                self.running = Some(Running {
                    child,
                    stdin,
                    stdout: Some(stdout),
                });
                Answer::Done(answer)
            }
            Ok((stdin, stdout, None)) => {
                drop((stdin, stdout));
                let _ = child.kill();
                let _ = child.wait();
                self.kills = self.kills.saturating_add(1);
                Answer::Died
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                // The helper sees end of stream and ends; its pipes drop with it.
                let _ = rx.recv();
                self.kills = self.kills.saturating_add(1);
                Answer::TimedOut
            }
        }
    }

    /// Render page `page` (zero-based) at `dpi`.
    ///
    /// # Errors
    /// `CS-ML-0005` over the pixel cap or image budget; `CS-ML-0006` for a page that does
    /// not exist, does not render, overruns its time (the child is killed), or comes after
    /// [`RasterLimits::max_kills`] kills; `CS-ML-0014` when the child dies otherwise.
    pub fn render(&mut self, page: u16, dpi: u16) -> Result<Raster, ModeldError> {
        if u32::from(page) >= self.pages {
            return Err(raster_error("no such page"));
        }
        if self.kills >= self.limits.max_kills {
            return Err(raster_error(
                "too many raster children killed for this document",
            ));
        }
        if self.running.is_none() {
            self.start()?;
        }
        let answer = self.exchange(
            move |w| {
                w.write_all(&page.to_be_bytes()).map_err(|_| ())?;
                w.write_all(&dpi.to_be_bytes()).map_err(|_| ())?;
                w.flush().map_err(|_| ())
            },
            move |r| read_answer(r, dpi),
        );
        match answer {
            Answer::Done(r) => r,
            Answer::TimedOut => Err(raster_error("rasterising took too long")),
            Answer::Died => Err(ModeldError::RasterChild),
        }
    }
}

#[cfg(test)]
mod tests {
    // Tests may unwrap (CLAUDE.md, Rust standards): a failure is the test failing.
    #![allow(clippy::unwrap_used)]
    use super::*;

    /// A raster header as a lying child would write it, with no pixels after it: a
    /// header the parent accepted would make it allocate and then fail to read them.
    fn header(width: u16, height: u16, dpi: u16, rotate: u16, crop: [f32; 4]) -> Vec<u8> {
        let mut b = vec![0u8];
        for v in [width, height, dpi, rotate] {
            b.extend_from_slice(&v.to_be_bytes());
        }
        for v in crop {
            b.extend_from_slice(&v.to_be_bytes());
        }
        b
    }

    const CROP: [f32; 4] = [0.0, 0.0, 612.0, 792.0];

    /// Feeds `bytes` to the parent and returns the code it answered, after checking it
    /// read nothing past the header (it refused before allocating the pixels).
    fn refused(bytes: &[u8]) -> Option<&'static str> {
        let mut r = std::io::Cursor::new(bytes);
        let answer = read_answer(&mut r, 150)?;
        assert_eq!(r.position(), u64::try_from(bytes.len()).unwrap());
        answer.err().map(|e| e.code())
    }

    #[test]
    fn parent_refuses_a_lying_childs_header_before_allocating() {
        let long = u16::try_from(MAX_LONG_SIDE + 1).unwrap();
        let cases: [(&str, Vec<u8>); 9] = [
            ("zero width", header(0, 100, 150, 0, CROP)),
            ("zero height", header(100, 0, 150, 0, CROP)),
            ("long side over the cap", header(long, 10, 150, 0, CROP)),
            ("zero dpi", header(100, 100, 0, 0, CROP)),
            (
                "dpi above the one asked for",
                header(100, 100, 151, 0, CROP),
            ),
            (
                "rotation not a quarter turn",
                header(100, 100, 150, 45, CROP),
            ),
            (
                "NaN crop",
                header(100, 100, 150, 0, [f32::NAN, 0.0, 1.0, 1.0]),
            ),
            (
                "infinite crop",
                header(100, 100, 150, 0, [0.0, 0.0, f32::INFINITY, 1.0]),
            ),
            ("unknown status byte", vec![7]),
        ];
        for (why, bytes) in cases {
            assert_eq!(refused(&bytes), Some("CS-ML-0014"), "{why}");
        }
    }

    #[test]
    fn the_side_cap_implies_the_pixel_cap() {
        // 4096 × 4096 = 16.78 MP is under 16.8 MP, so a header within the side cap is
        // within the pixel cap too: the `pixels > MAX_PIXELS` check in `read_answer` is
        // a second guard that no header can reach while the caps stay as they are. If
        // either cap changes, this fails and a pixel-cap case belongs in the test above.
        assert!(u64::from(MAX_LONG_SIDE) * u64::from(MAX_LONG_SIDE) <= MAX_PIXELS);
    }

    #[test]
    fn parent_accepts_an_honest_header_and_reads_its_pixels() {
        let mut bytes = header(3, 2, 150, 90, CROP);
        bytes.extend_from_slice(&[0, 64, 128, 192, 255, 1]);
        let mut r = std::io::Cursor::new(bytes);
        let raster = read_answer(&mut r, 150).unwrap().unwrap();
        assert_eq!(
            (raster.width, raster.height, raster.dpi, raster.rotate),
            (3, 2, 150, 90)
        );
        assert_eq!(raster.grey, [0, 64, 128, 192, 255, 1]);
    }

    #[test]
    fn a_childs_error_code_outside_the_raster_set_becomes_raster_child() {
        let mut b = vec![1u8];
        b.extend_from_slice(&ModeldError::RasterChild.number().to_be_bytes());
        assert_eq!(refused(&b), Some("CS-ML-0014"));
        let mut b = vec![1u8];
        b.extend_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(refused(&b), Some("CS-ML-0014"));
    }
}
