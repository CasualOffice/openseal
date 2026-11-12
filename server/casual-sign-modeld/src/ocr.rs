//! OCR (piece D; `ML-02`): words, their quads and confidences on a page raster, read by the
//! PaddleOCR pipeline through `oar-ocr` 0.10.2 (`default-features = false`: no download,
//! local files only) on ONNX Runtime loaded from the verified bundle (`ort` rc.13,
//! `load-dynamic`).
//!
//! - **Models** (docs/33 §5.1): PP-OCRv6 small detection and recognition always; the
//!   PP-LCNet text-line orientation classifier when the bundle holds it; PP-OCRv5 script
//!   packs (`arabic`, `devanagari`, ...) when the bundle holds them and a request names
//!   them. The recogniser's character dictionary is read from its `inference.yml` (the
//!   `PostProcess.character_dict` list), so nothing but the pinned files is used.
//! - **Determinism:** CPU only, one intra-op and one inter-op thread per session, a fixed
//!   graph optimisation level.
//! - **Words:** each recognised line is split at spaces; a word's quad is interpolated
//!   along the line's quad from the recogniser's per-character boxes (`return_word_box`).
//! - **Text leaves modeld in NFC**, and a right-to-left word in logical order (the
//!   recogniser reads it in visual order), with a line's words in reading order (docs/33
//!   §3.2, §5.1).
//!
//! Nothing here logs: a word, a box or a score is document content (`SEC-I05`).

use std::path::Path;
use std::sync::OnceLock;

use oar_ocr::core::config::{OrtExecutionProvider, OrtGraphOptimizationLevel, OrtSessionConfig};
use oar_ocr::oarocr::{OAROCR, OAROCRBuilder};
use oar_ocr::processors::BoundingBox;
use unicode_normalization::UnicodeNormalization;

use crate::error::{BundleProblem, ModeldError};
use crate::manifest::Bundle;
use crate::raster::Raster;
use crate::wire::{MAX_PAGE_ITEMS, MAX_WORD, Quad, SCORE_SCALE, Word};

/// Manifest ids of the default OCR models.
const DET: &str = "ppocrv6-small-det";
const REC: &str = "ppocrv6-small-rec";
const REC_CONFIG: &str = "ppocrv6-small-rec-config";
const ORIENTATION: &str = "pplcnet-textline-ori";

/// The ONNX Runtime library entry for this machine.
#[cfg(target_arch = "aarch64")]
const RUNTIME: &str = "onnxruntime-aarch64";
#[cfg(not(target_arch = "aarch64"))]
const RUNTIME: &str = "onnxruntime-x86_64";

/// Script packs: request id → manifest ids of the recogniser and its config.
const PACKS: &[(&str, &str, &str)] = &[
    ("arabic", "ppocrv5-arabic-rec", "ppocrv5-arabic-rec-config"),
    (
        "devanagari",
        "ppocrv5-devanagari-rec",
        "ppocrv5-devanagari-rec-config",
    ),
];

/// The ONNX Runtime library loaded into this process, once (by path), and its version.
static RUNTIME_LOADED: OnceLock<Result<String, ()>> = OnceLock::new();

/// Load ONNX Runtime from `lib` (once per process) with its own logging routed to the
/// fixed `tracing` filter (`SEC-I05`). Its version, as INFO reports it.
fn load_runtime(lib: &Path) -> Result<String, ModeldError> {
    RUNTIME_LOADED
        .get_or_init(|| {
            let builder = ort::init_from(lib).map_err(|_| ())?;
            let _ = builder.with_name("casual-sign-modeld").commit();
            Ok(runtime_version(ort::info()))
        })
        .clone()
        .map_err(|()| ModeldError::Inference)
}

/// `onnxruntime-1.28.3` from ONNX Runtime's build string (`... git-branch=rel-1.28.3,
/// ...`), or `onnxruntime` when it does not say.
fn runtime_version(info: &str) -> String {
    let version = info
        .split(|c: char| c == ',' || c.is_whitespace())
        .find_map(|w| w.strip_prefix("git-branch=rel-"))
        .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit() || b == b'.'));
    match version {
        Some(v) => format!("onnxruntime-{v}"),
        None => "onnxruntime".into(),
    }
}

/// One YAML scalar of a block list (`- x`, `- 'x'`, `- "x"`), as Paddle's exporter writes
/// them.
fn yaml_scalar(raw: &str) -> Option<String> {
    if let Some(inner) = raw.strip_prefix('\'') {
        return Some(inner.strip_suffix('\'')?.replace("''", "'"));
    }
    if let Some(inner) = raw.strip_prefix('"') {
        let inner = inner.strip_suffix('"')?;
        let mut out = String::new();
        let mut chars = inner.chars();
        while let Some(c) = chars.next() {
            if c != '\\' {
                out.push(c);
                continue;
            }
            match chars.next()? {
                '\\' => out.push('\\'),
                '"' => out.push('"'),
                '/' => out.push('/'),
                't' => out.push('\t'),
                ' ' => out.push(' '),
                'u' => {
                    let hex: String = chars.by_ref().take(4).collect();
                    out.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
                }
                'U' => {
                    let hex: String = chars.by_ref().take(8).collect();
                    out.push(char::from_u32(u32::from_str_radix(&hex, 16).ok()?)?);
                }
                _ => return None,
            }
        }
        return Some(out);
    }
    (!raw.is_empty()).then(|| raw.to_owned())
}

/// The recogniser's character dictionary from its Paddle `inference.yml`: the
/// `character_dict` list under `PostProcess`, one character per line, as `oar-ocr`
/// takes it.
///
/// # Errors
/// `CS-ML-0002` naming the file when the list is missing, empty or not parseable.
pub(crate) fn dictionary(yml: &str, file: &str) -> Result<String, ModeldError> {
    let bad = || ModeldError::Bundle(BundleProblem::Unreadable(format!("{file}: character_dict")));
    let mut lines = yml
        .lines()
        .skip_while(|l| l.trim_end() != "  character_dict:");
    lines.next().ok_or_else(bad)?;
    let mut out = Vec::new();
    for line in lines {
        let Some(item) = line.strip_prefix("  - ") else {
            break;
        };
        out.push(yaml_scalar(item).ok_or_else(bad)?);
    }
    if out.is_empty() || out.iter().any(|c| c.contains('\n')) {
        return Err(bad());
    }
    Ok(out.join("\n"))
}

/// Whether `c` belongs to a right-to-left script.
fn is_rtl(c: char) -> bool {
    matches!(u32::from(c),
        0x0590..=0x08FF | 0xFB1D..=0xFDFF | 0xFE70..=0xFEFF | 0x10800..=0x10FFF | 0x1E800..=0x1EFFF)
}

/// A recognised word as it leaves modeld: logical order, NFC, at most [`MAX_WORD`] bytes.
fn finish(visual: &str) -> Option<String> {
    let logical: String = if visual.chars().any(is_rtl) {
        let bidi = unicode_bidi::BidiInfo::new(visual, None);
        match bidi.paragraphs.first() {
            Some(para) => bidi.reorder_line(para, para.range.clone()).into_owned(),
            None => visual.to_owned(),
        }
    } else {
        visual.to_owned()
    };
    let mut nfc: String = logical.nfc().collect();
    if nfc.len() > MAX_WORD {
        let mut cut = MAX_WORD;
        while !nfc.is_char_boundary(cut) {
            cut = cut.saturating_sub(1);
        }
        nfc.truncate(cut);
    }
    (!nfc.trim().is_empty()).then_some(nfc)
}

/// A line's quad from its polygon: the four points clockwise from top left, or the
/// polygon's bounding rectangle when it is not four points.
fn line_quad(b: &BoundingBox) -> Quad {
    match b.points.as_slice() {
        [a, c, d, e] => [(a.x, a.y), (c.x, c.y), (d.x, d.y), (e.x, e.y)],
        _ => {
            let (x0, y0, x1, y1) = (b.x_min(), b.y_min(), b.x_max(), b.y_max());
            [(x0, y0), (x1, y0), (x1, y1), (x0, y1)]
        }
    }
}

/// The part of `line` between fractions `t0` and `t1` of its length.
fn sub_quad(line: &Quad, t0: f32, t1: f32) -> Quad {
    let lerp =
        |a: (f32, f32), b: (f32, f32), t: f32| (a.0 + (b.0 - a.0) * t, a.1 + (b.1 - a.1) * t);
    let [tl, tr, br, bl] = *line;
    [
        lerp(tl, tr, t0),
        lerp(tl, tr, t1),
        lerp(bl, br, t1),
        lerp(bl, br, t0),
    ]
}

/// Split one recognised line into words with quads. `boxes` are the recogniser's
/// per-character boxes (in the line's direction), when it gave one per character.
pub(crate) fn words_of_line(
    text: &str,
    conf: f32,
    line: &Quad,
    boxes: Option<&[BoundingBox]>,
) -> Vec<Word> {
    let chars: Vec<char> = text.chars().collect();
    let n = chars.len();
    if n == 0 {
        return Vec::new();
    }
    let (x_min, x_max) = boxes
        .and_then(|b| Some((b.first()?.x_min(), b.last()?.x_max())))
        .unwrap_or((0.0, 0.0));
    let span = x_max - x_min;
    let per_char = boxes.filter(|b| b.len() == n && span > 0.0);
    let frac = |i: usize, end: bool| -> f32 {
        match per_char.and_then(|b| b.get(i)) {
            Some(b) => ((if end { b.x_max() } else { b.x_min() }) - x_min) / span,
            None => (i as f32 + if end { 1.0 } else { 0.0 }) / n as f32,
        }
    };
    let conf = (conf.clamp(0.0, 1.0) * f32::from(SCORE_SCALE)).round();
    let conf = (conf as u16).min(SCORE_SCALE);
    let mut out = Vec::new();
    let mut i = 0;
    while i < n {
        if chars.get(i).is_some_and(|c| c.is_whitespace()) {
            i = i.saturating_add(1);
            continue;
        }
        let start = i;
        while chars.get(i).is_some_and(|c| !c.is_whitespace()) {
            i = i.saturating_add(1);
        }
        let visual: String = chars.get(start..i).unwrap_or_default().iter().collect();
        if let Some(text) = finish(&visual) {
            let last = i.saturating_sub(1);
            out.push(Word {
                text,
                quad: sub_quad(
                    line,
                    frac(start, false).clamp(0.0, 1.0),
                    frac(last, true).clamp(0.0, 1.0),
                ),
                conf,
            });
        }
    }
    // A right-to-left line was read left to right; its words go out in reading order.
    if text.chars().any(is_rtl) {
        out.reverse();
    }
    out
}

/// One recognised line: text, confidence, quad and per-character boxes.
type Line = (String, f32, Quad, Option<Vec<BoundingBox>>);

/// One page read: its words and its line quads.
#[derive(Debug, Default)]
pub(crate) struct Reading {
    pub words: Vec<Word>,
    pub lines: Vec<Quad>,
}

/// The loaded OCR pipelines.
pub(crate) struct OcrEngine {
    default: OAROCR,
    packs: Vec<(&'static str, OAROCR)>,
    runtime: String,
}

impl core::fmt::Debug for OcrEngine {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OcrEngine")
            .field(
                "packs",
                &self.packs.iter().map(|(s, _)| *s).collect::<Vec<_>>(),
            )
            .field("runtime", &self.runtime)
            .finish_non_exhaustive()
    }
}

fn session_config() -> OrtSessionConfig {
    OrtSessionConfig::new()
        .with_execution_providers(vec![OrtExecutionProvider::CPU])
        .with_intra_threads(1)
        .with_inter_threads(1)
        .with_parallel_execution(false)
        .with_optimization_level(OrtGraphOptimizationLevel::Level1)
}

impl OcrEngine {
    /// Load the OCR pipelines from `bundle`, or `None` when it holds no OCR models (OCR
    /// then answers `CS-ML-0010`).
    ///
    /// # Errors
    /// `CS-ML-0002` for an unreadable dictionary, `CS-ML-0013` when ONNX Runtime or a
    /// model does not load (its own message is never passed on).
    pub(crate) fn load(bundle: &Bundle) -> Result<Option<Self>, ModeldError> {
        let path = |id: &str| bundle.model(id).map(|e| bundle.dir.join(&e.path));
        let (Some(det), Some(rec), Some(rec_config), Some(lib)) =
            (path(DET), path(REC), path(REC_CONFIG), path(RUNTIME))
        else {
            return Ok(None);
        };
        let runtime = load_runtime(&lib)?;
        let orientation = path(ORIENTATION);
        let build = |rec: &Path, config: &Path, name: &str| -> Result<OAROCR, ModeldError> {
            let yml = std::fs::read_to_string(config).map_err(|e| {
                ModeldError::Bundle(BundleProblem::Unreadable(format!("{name}: {}", e.kind())))
            })?;
            let mut b = OAROCRBuilder::new(det.as_path(), rec, "unused-dictionary-path")
                .character_dict_content(dictionary(&yml, name)?)
                .ort_session(session_config())
                .return_word_box(true)
                .image_batch_size(1)
                .region_batch_size(8);
            if let Some(o) = &orientation {
                b = b.with_text_line_orientation_classification(o.as_path());
            }
            b.build().map_err(|_| ModeldError::Inference)
        };
        let default = build(&rec, &rec_config, REC_CONFIG)?;
        let mut packs = Vec::new();
        for (script, rec_id, config_id) in PACKS {
            if let (Some(r), Some(c)) = (path(rec_id), path(config_id)) {
                packs.push((*script, build(&r, &c, config_id)?));
            }
        }
        Ok(Some(Self {
            default,
            packs,
            runtime,
        }))
    }

    /// The ONNX Runtime version, for INFO.
    pub(crate) fn runtime(&self) -> &str {
        &self.runtime
    }

    /// Read `raster` with the default recogniser and the named script packs. Each line the
    /// detector finds is taken from whichever recogniser is most confident on it.
    ///
    /// # Errors
    /// `CS-ML-0010` for a script pack not installed, `CS-ML-0013` when inference fails.
    pub(crate) fn read(&self, raster: &Raster, scripts: &[String]) -> Result<Reading, ModeldError> {
        let mut engines = vec![&self.default];
        for s in scripts {
            let pack = self
                .packs
                .iter()
                .find(|(id, _)| id == s)
                .ok_or(ModeldError::NotInstalled)?;
            engines.push(&pack.1);
        }
        let (w, h) = (u32::from(raster.width), u32::from(raster.height));
        let rgb: Vec<u8> = raster.grey.iter().flat_map(|&g| [g, g, g]).collect();
        let upright = image::RgbImage::from_raw(w, h, rgb).ok_or(ModeldError::Inference)?;
        let lines = Self::lines(&engines, &upright)?;
        // A page scanned upside down reads as noise at low confidence; then the page is
        // read turned half round too, and the more confident reading is kept (no model:
        // PP-LCNet line orientation, when installed, handles single lines).
        if median_confidence(&lines).is_some_and(|m| m < UPSIDE_DOWN_BELOW) {
            let turned = image::imageops::rotate180(&upright);
            let turned_lines = Self::lines(&engines, &turned)?;
            if total_confidence(&turned_lines) > total_confidence(&lines) {
                let (wf, hf) = (f32::from(raster.width), f32::from(raster.height));
                return Ok(reading_of(turned_lines, |q| half_turn(q, wf, hf)));
            }
        }
        Ok(reading_of(lines, |q| q))
    }

    /// Detect once and recognise with each of `engines`; per detected line the most
    /// confident recognition. The detector is the same model on the same image for every
    /// recogniser, so its lines come back in the same order.
    fn lines(engines: &[&OAROCR], image: &image::RgbImage) -> Result<Vec<Line>, ModeldError> {
        let mut best: Vec<Option<Line>> = Vec::new();
        for engine in engines {
            let results = engine
                .predict(vec![image.clone()])
                .map_err(|_| ModeldError::Inference)?;
            let Some(result) = results.into_iter().next() else {
                return Err(ModeldError::Inference);
            };
            if best.is_empty() {
                best.resize(result.text_regions.len(), None);
            }
            for (slot, region) in best.iter_mut().zip(result.text_regions) {
                let (Some(text), Some(conf)) = (region.text, region.confidence) else {
                    continue;
                };
                if slot.as_ref().is_none_or(|(_, c, _, _)| conf > *c) {
                    *slot = Some((
                        text.to_string(),
                        conf,
                        line_quad(&region.bounding_box),
                        region.word_boxes,
                    ));
                }
            }
        }
        Ok(best.into_iter().flatten().collect())
    }
}

/// Below this median line confidence a page is also read turned half round.
const UPSIDE_DOWN_BELOW: f32 = 0.75;

fn median_confidence(lines: &[Line]) -> Option<f32> {
    let mut c: Vec<f32> = lines.iter().map(|l| l.1).collect();
    c.sort_by(f32::total_cmp);
    c.get(c.len() / 2).copied()
}

fn total_confidence(lines: &[Line]) -> f32 {
    lines.iter().map(|l| l.1).sum()
}

/// A quad read on the page turned half round, back on the page: each point turned, and
/// the corners renamed so the first is again top left.
fn half_turn(q: Quad, w: f32, h: f32) -> Quad {
    let t = |(x, y): (f32, f32)| (w - x, h - y);
    let [a, b, c, d] = q;
    [t(c), t(d), t(a), t(b)]
}

/// Words and line quads from recognised lines, each quad passed through `place`.
fn reading_of(lines: Vec<Line>, place: impl Fn(Quad) -> Quad) -> Reading {
    let mut reading = Reading::default();
    for (text, conf, quad, boxes) in lines {
        if reading.words.len() >= MAX_PAGE_ITEMS {
            break;
        }
        let words = words_of_line(&text, conf, &quad, boxes.as_deref());
        if words.is_empty() {
            continue;
        }
        reading.lines.push(place(quad));
        let room = MAX_PAGE_ITEMS.saturating_sub(reading.words.len());
        reading
            .words
            .extend(words.into_iter().take(room).map(|w| Word {
                quad: place(w.quad),
                ..w
            }));
    }
    reading
}

#[cfg(test)]
mod tests {
    // Test code: a panic is the failure report.
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;
    use oar_ocr::processors::Point;

    #[test]
    fn the_dictionary_is_read_from_the_paddle_config() {
        let yml = "Global:\n  model_name: x\nPostProcess:\n  name: CTCLabelDecode\n  character_dict:\n  - '!'\n  - ''''\n  - $\n  - \"\\u00e9\"\n  - 'a''b'\n  - 中\nPreProcess:\n  x: 1\n";
        assert_eq!(dictionary(yml, "f").unwrap(), "!\n'\n$\né\na'b\n中");
        for bad in [
            "Global:\n  x: 1\n",
            "PostProcess:\n  character_dict:\n",
            "PostProcess:\n  character_dict:\n  - 'open\n",
        ] {
            assert_eq!(
                dictionary(bad, "f").unwrap_err().code(),
                "CS-ML-0002",
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_quad_read_upside_down_comes_back_upright_from_top_left() {
        // A word at the top left of a 100 x 50 page turned half round is at its bottom
        // right; turned back, its first corner is its top left again.
        let q: Quad = [(80.0, 40.0), (90.0, 40.0), (90.0, 45.0), (80.0, 45.0)];
        assert_eq!(
            half_turn(q, 100.0, 50.0),
            [(10.0, 5.0), (20.0, 5.0), (20.0, 10.0), (10.0, 10.0)]
        );
    }

    #[test]
    fn the_runtime_version_is_read_from_its_build_string() {
        assert_eq!(
            runtime_version(
                "ORT Build Info: git-branch=rel-1.28.3, git-commit-id=abc, build type=Release"
            ),
            "onnxruntime-1.28.3"
        );
        assert_eq!(runtime_version("something else"), "onnxruntime");
    }

    fn bbox(x0: f32, x1: f32) -> BoundingBox {
        BoundingBox::new(vec![
            Point::new(x0, 0.0),
            Point::new(x1, 0.0),
            Point::new(x1, 10.0),
            Point::new(x0, 10.0),
        ])
    }

    #[test]
    fn a_line_splits_into_words_with_quads_along_it() {
        // "ab cd" over x 0..50, one box per character, 10 px each.
        let line: Quad = [(0.0, 0.0), (50.0, 0.0), (50.0, 10.0), (0.0, 10.0)];
        let boxes: Vec<_> = (0..5)
            .map(|i| bbox(i as f32 * 10.0, i as f32 * 10.0 + 10.0))
            .collect();
        let w = words_of_line("ab cd", 0.97, &line, Some(&boxes));
        assert_eq!(w.len(), 2);
        assert_eq!(w[0].text, "ab");
        assert_eq!(
            w[0].quad,
            [(0.0, 0.0), (20.0, 0.0), (20.0, 10.0), (0.0, 10.0)]
        );
        assert_eq!(w[1].text, "cd");
        let near =
            |p: (f32, f32), q: (f32, f32)| (p.0 - q.0).abs() < 1e-3 && (p.1 - q.1).abs() < 1e-3;
        assert!(near(w[1].quad[0], (30.0, 0.0)), "{:?}", w[1].quad);
        assert_eq!(w[1].conf, 9_700);
        // Without per-character boxes the line is shared out by character.
        let w = words_of_line("ab cd", 1.5, &line, None);
        assert!(near(w[1].quad[0], (30.0, 0.0)), "{:?}", w[1].quad);
        assert_eq!(w[1].conf, SCORE_SCALE);
    }

    #[test]
    fn text_leaves_in_nfc_and_right_to_left_words_in_logical_order() {
        // "e" + combining acute becomes the precomposed é.
        assert_eq!(finish("cafe\u{301}").unwrap(), "caf\u{e9}");
        // سلام read in visual order (reversed) comes back in logical order.
        let visual: String = "سلام".chars().rev().collect();
        assert_eq!(finish(&visual).unwrap(), "سلام");
        // A right-to-left line's words come out right to left.
        let line: Quad = [(0.0, 0.0), (90.0, 0.0), (90.0, 10.0), (0.0, 10.0)];
        let text = format!("{} {}", "مرحبا".chars().rev().collect::<String>(), visual);
        let w = words_of_line(&text, 0.9, &line, None);
        assert_eq!(
            w.iter().map(|w| w.text.as_str()).collect::<Vec<_>>(),
            ["سلام", "مرحبا"]
        );
        // Whitespace only is no word; an over-long word is cut on a character boundary.
        assert!(finish("  ").is_none());
        let long = "é".repeat(MAX_WORD);
        let cut = finish(&long).unwrap();
        assert!(cut.len() <= MAX_WORD && cut.chars().all(|c| c == 'é'));
    }
}
