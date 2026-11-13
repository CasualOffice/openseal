//! Document analysis (WEB-19, ML-01; docs/33 §2): the advisory `analyze_document` and
//! `fingerprint_template` jobs, run against the model service through the
//! [`Inference`] seam.
//!
//! - **Seam.** [`Modeld`] is the production [`Inference`]: `casual-sign-modeld`'s client
//!   over mTLS, linked with `default-features = false`, so no inference runtime,
//!   rasteriser or tokenizer enters this process, which holds the database, SMTP and
//!   keyd secrets (`SEC-I14`). Tests supply a fake.
//! - **Advisory.** [`analyse`] reads the stored, normalized PDF and answers OCR words,
//!   page hashes and suggestions; the worker writes them in one transaction with the
//!   run's end and the job's completion. Nothing here touches an envelope's state, its
//!   audit chain or a document version (docs/33 invariant 2).
//! - **Offsets, never text.** A suggestion stores its page and the UTF-8 byte offsets of
//!   its span in the text it was found in ([`casual_sign_host::ml::page_text`]); the
//!   server rebuilds that text to show it. Nothing is logged but ids, counts and codes.

use std::collections::BTreeMap;

use casual_sign_host::ml::page_text;
use casual_sign_modeld::wire::{
    EmbedKind, Info, MAX_EMBED_TEXT, MAX_EMBED_TEXTS, MAX_PAGES, MAX_SPAN_TEXT, OcrPage, PageHash,
    SCORE_SCALE, Span, SpanRequest,
};
use casual_sign_modeld::{Call, ModelClient, ModeldError};
use casual_sign_sdk::Engine;
use casual_sign_store::TemplateId;
use casual_sign_store::repo::ml::{Fingerprint, SuggestionKind};
use serde_json::{Value, json};

use crate::error::{Result, WorkerError};

/// The resolution pages are read at (docs/33 §4: 150 DPI by default).
pub const OCR_DPI: u16 = 150;
/// Entity spans kept per document (docs/33 §4).
pub const MAX_ENTITIES: usize = 2_000;
/// Personal-data spans kept per document (docs/33 §4).
pub const MAX_PERSONAL: usize = 5_000;
/// Lowest model score kept, in ten-thousandths.
pub const THRESHOLD: u16 = 5_000;
/// A template page matches when both its hashes are within this Hamming distance.
pub const MAX_HAMMING: u32 = 10;
/// ... and at least this share of the template's pages match (docs/33 §5.2: 80 %).
pub const MIN_PAGE_SHARE: f32 = 0.8;
/// ... and the matched pages' texts have at least this mean cosine (docs/33 §5.2).
pub const MIN_COSINE: f32 = 0.9;

/// Agreement details asked of the entity model, with the label people see.
pub const ENTITY_LABELS: [(&str, &str); 7] = [
    ("party", "Party"),
    ("date", "Date"),
    ("monetary amount", "Amount"),
    ("duration", "Duration"),
    ("address", "Address"),
    ("governing law", "Governing law"),
    ("notice period", "Notice period"),
];

/// Personal data asked of the personal-data model (docs/33 §5.4 layer 2).
pub const PERSONAL_LABELS: [(&str, &str); 5] = [
    ("person", "Person name"),
    ("address", "Home address"),
    ("date of birth", "Date of birth"),
    ("phone number", "Phone number"),
    ("email", "Email address"),
];

/// The model service, as the worker uses it. Blocking; called on the blocking pool.
pub trait Inference: Send + Sync + core::fmt::Debug {
    /// The installed bundle.
    ///
    /// # Errors
    /// A `CS-ML-*` error.
    fn info(&self, call: &Call) -> core::result::Result<Info, ModeldError>;
    /// OCR of `pages` (zero-based) of `pdf`, which crosses the wire once.
    ///
    /// # Errors
    /// A `CS-ML-*` error.
    fn ocr(
        &self,
        call: &Call,
        pdf: &[u8],
        pages: &[u16],
        dpi: u16,
        scripts: &[String],
    ) -> core::result::Result<Vec<OcrPage>, ModeldError>;
    /// Page hashes of `pages` (zero-based) of `pdf`.
    ///
    /// # Errors
    /// A `CS-ML-*` error.
    fn hash(
        &self,
        call: &Call,
        pdf: &[u8],
        pages: Vec<u16>,
    ) -> core::result::Result<Vec<PageHash>, ModeldError>;
    /// Passage embeddings of `texts`.
    ///
    /// # Errors
    /// A `CS-ML-*` error.
    fn embed(
        &self,
        call: &Call,
        texts: Vec<String>,
    ) -> core::result::Result<Vec<Vec<f32>>, ModeldError>;
    /// Entity spans of `req.text`.
    ///
    /// # Errors
    /// A `CS-ML-*` error.
    fn entities(
        &self,
        call: &Call,
        req: SpanRequest,
    ) -> core::result::Result<Vec<Span>, ModeldError>;
    /// Personal-data spans of `req.text`.
    ///
    /// # Errors
    /// A `CS-ML-*` error.
    fn personal(
        &self,
        call: &Call,
        req: SpanRequest,
    ) -> core::result::Result<Vec<Span>, ModeldError>;
}

/// `casual-sign-modeld` over mTLS: the production [`Inference`].
#[derive(Debug, Clone)]
pub struct Modeld {
    client: ModelClient,
}

impl Modeld {
    /// A seam over `client`.
    #[must_use]
    pub fn new(client: ModelClient) -> Self {
        Self { client }
    }
}

impl Inference for Modeld {
    fn info(&self, call: &Call) -> core::result::Result<Info, ModeldError> {
        self.client.info(call)
    }

    fn ocr(
        &self,
        call: &Call,
        pdf: &[u8],
        pages: &[u16],
        dpi: u16,
        scripts: &[String],
    ) -> core::result::Result<Vec<OcrPage>, ModeldError> {
        let mut session = self.client.session()?;
        let out = (|| {
            let (doc, _) = session.open_document(call, pdf.to_vec())?;
            let mut out = Vec::with_capacity(pages.len());
            for p in pages {
                out.push(session.ocr(call, doc, *p, dpi, scripts.to_vec())?);
            }
            session.close_document(call, doc)?;
            Ok(out)
        })();
        session.close();
        out
    }

    fn hash(
        &self,
        call: &Call,
        pdf: &[u8],
        pages: Vec<u16>,
    ) -> core::result::Result<Vec<PageHash>, ModeldError> {
        self.client.hash(call, pdf.to_vec(), pages)
    }

    fn embed(
        &self,
        call: &Call,
        texts: Vec<String>,
    ) -> core::result::Result<Vec<Vec<f32>>, ModeldError> {
        self.client.embed(call, EmbedKind::Passage, texts)
    }

    fn entities(
        &self,
        call: &Call,
        req: SpanRequest,
    ) -> core::result::Result<Vec<Span>, ModeldError> {
        self.client.entities(call, req)
    }

    fn personal(
        &self,
        call: &Call,
        req: SpanRequest,
    ) -> core::result::Result<Vec<Span>, ModeldError> {
        self.client.personal(call, req)
    }
}

/// What a job asks [`analyse`] for.
#[derive(Debug, Clone)]
pub struct Input {
    /// The stored, normalized PDF.
    pub pdf: Vec<u8>,
    /// `ocr`, `template`, `entities`, `personal_data`.
    pub uses: Vec<String>,
    /// OCR script packs besides the default recogniser.
    pub scripts: Vec<String>,
    /// The account's template page hashes (template matching).
    pub fingerprints: Vec<Fingerprint>,
    /// A `fingerprint_template` job: hash and embed the document's own pages.
    pub fingerprint: bool,
}

/// One suggestion before it has an id.
#[derive(Debug, Clone, PartialEq)]
pub struct Draft {
    /// What.
    pub kind: SuggestionKind,
    /// 1-based page.
    pub page: i32,
    /// The label people see (a template suggestion's is filled from its name later).
    pub label: String,
    /// UTF-8 byte offsets into the page's analysed text.
    pub span: Option<(i32, i32)>,
    /// The template, pages matched and its pages.
    pub template: Option<(TemplateId, i32, i32)>,
    /// From 0 to 1.
    pub score: f32,
    /// The model (manifest id) and its SHA-256.
    pub model: (String, [u8; 32]),
}

/// A page's hashes and embedding, for a `fingerprint_template` job.
#[derive(Debug, Clone, PartialEq)]
pub struct PagePrint {
    /// 1-based page.
    pub page: i32,
    /// Difference hash, as stored.
    pub dhash: i64,
    /// Perceptual hash, as stored.
    pub phash: i64,
    /// Passage embedding as little-endian `f32`s.
    pub embedding: Option<Vec<u8>>,
}

/// What [`analyse`] found.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Output {
    /// The bundle that ran it.
    pub bundle: String,
    /// The runtime's version.
    pub runtime: String,
    /// OCR words by 1-based page (`[{text, conf, x, y, width, height}]`, displayed points).
    pub ocr: Vec<(i32, Value)>,
    /// Whether a bound cut it short.
    pub truncated: bool,
    /// Suggestions.
    pub suggestions: Vec<Draft>,
    /// Page prints (a `fingerprint_template` job).
    pub prints: Vec<PagePrint>,
}

/// The id and SHA-256 recorded for page hashing, which is an algorithm, not a model.
pub const PAGE_HASH_MODEL: &str = "page-hash-v1";
/// The id recorded for the deterministic personal-data recognisers.
pub const PII_RULES_MODEL: &str = "casual-sign-pii";

/// SHA-256 of `s` (an id standing in for weights the method does not have).
#[must_use]
pub fn id_hash(s: &str) -> [u8; 32] {
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, s.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// The installed model whose id matches `want`, or a stand-in named `fallback`.
fn model(info: &Info, want: impl Fn(&str) -> bool, fallback: &str) -> (String, [u8; 32]) {
    info.models
        .iter()
        .find(|(id, _)| want(&id.to_ascii_lowercase()))
        .map_or_else(
            || (fallback.to_owned(), id_hash(fallback)),
            |(id, sha)| (id.clone(), *sha),
        )
}

/// `text` cut into pieces of at most `max` bytes, at whitespace when one is near, always
/// on a character boundary: `(byte offset, piece)`.
#[must_use]
pub fn chunks(text: &str, max: usize) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut start = 0usize;
    let max = max.max(4);
    while start < text.len() {
        let rest = text.get(start..).unwrap_or_default();
        if rest.len() <= max {
            out.push((start, rest));
            break;
        }
        let mut cut = max;
        while cut > 0 && !rest.is_char_boundary(cut) {
            cut = cut.saturating_sub(1);
        }
        if let Some(ws) = rest.get(..cut).and_then(|h| h.rfind(' '))
            && ws > cut / 2
        {
            cut = ws.saturating_add(1);
        }
        if cut == 0 {
            break;
        }
        out.push((start, rest.get(..cut).unwrap_or_default()));
        start = start.saturating_add(cut);
    }
    out
}

/// The OCR words of a page as stored: each word's box in displayed points.
fn words_json(p: &OcrPage) -> Value {
    let words: Vec<Value> = p
        .words
        .iter()
        .map(|w| {
            let pts: Vec<(f32, f32)> = w.quad.iter().map(|c| p.to_displayed(*c)).collect();
            let (mut x0, mut y0, mut x1, mut y1) = (f32::MAX, f32::MAX, f32::MIN, f32::MIN);
            for (x, y) in pts {
                x0 = x0.min(x);
                y0 = y0.min(y);
                x1 = x1.max(x);
                y1 = y1.max(y);
            }
            json!({
                "text": w.text,
                "conf": f32::from(w.conf) / f32::from(SCORE_SCALE),
                "x": x0, "y": y0, "width": (x1 - x0).max(0.0), "height": (y1 - y0).max(0.0),
            })
        })
        .collect();
    Value::Array(words)
}

fn to_i32(v: usize) -> i32 {
    i32::try_from(v).unwrap_or(i32::MAX)
}

fn score(s: u16) -> f32 {
    (f32::from(s) / f32::from(SCORE_SCALE)).clamp(0.0, 1.0)
}

/// Passage embeddings of each page's text (`None` for a page with no text), in batches
/// within modeld's bounds. An embedding model that is not installed gives `None` for
/// every page.
fn embed_pages(
    inf: &dyn Inference,
    call: &Call,
    texts: &[String],
) -> Result<Vec<Option<Vec<f32>>>> {
    let mut out: Vec<Option<Vec<f32>>> = vec![None; texts.len()];
    let asked: Vec<(usize, String)> = texts
        .iter()
        .enumerate()
        .filter(|(_, t)| !t.trim().is_empty())
        .map(|(i, t)| {
            let piece = chunks(t, MAX_EMBED_TEXT)
                .first()
                .map_or("", |c| c.1)
                .to_owned();
            (i, piece)
        })
        .collect();
    for batch in asked.chunks(MAX_EMBED_TEXTS) {
        let vecs = match inf.embed(call, batch.iter().map(|b| b.1.clone()).collect()) {
            Ok(v) => v,
            Err(ModeldError::NotInstalled) => return Ok(vec![None; texts.len()]),
            Err(e) => return Err(e.into()),
        };
        for ((i, _), v) in batch.iter().zip(vecs) {
            if let Some(slot) = out.get_mut(*i) {
                *slot = Some(v);
            }
        }
    }
    Ok(out)
}

fn vec_bytes(v: &[f32]) -> Vec<u8> {
    v.iter().flat_map(|f| f.to_le_bytes()).collect()
}

fn bytes_vec(b: &[u8]) -> Vec<f32> {
    b.chunks_exact(4)
        .filter_map(|c| <[u8; 4]>::try_from(c).ok().map(f32::from_le_bytes))
        .collect()
}

fn cosine(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    a.iter().zip(b).map(|(x, y)| x * y).sum()
}

#[allow(clippy::cast_possible_wrap)] // The hash's 64 bits, stored as BIGINT.
fn stored(h: u64) -> i64 {
    h as i64
}

#[allow(clippy::cast_sign_loss)] // Back to the hash's 64 bits.
fn hamming(a: i64, b: i64) -> u32 {
    ((a ^ b) as u64).count_ones()
}

/// Analyse one stored document (docs/33 §2 steps 1 to 5). Blocking.
///
/// # Errors
/// [`WorkerError::Model`] with the model service's code; [`WorkerError::Pipeline`]
/// when the stored document cannot be read.
#[allow(clippy::too_many_lines)] // One step per docs/33 §2 item, in order.
pub fn analyse(inf: &dyn Inference, engine: &Engine, call: &Call, input: &Input) -> Result<Output> {
    let info = inf.info(call)?;
    let layers = engine
        .page_texts(&input.pdf)
        .map_err(|e| WorkerError::Pipeline { code: e.code() })?;
    let mut out = Output {
        bundle: info.bundle_id.clone(),
        runtime: info.runtime.clone(),
        ..Output::default()
    };
    let n = layers.len().min(MAX_PAGES);
    out.truncated = layers.len() > MAX_PAGES;
    let all_pages: Vec<u16> = (0..n).filter_map(|i| u16::try_from(i).ok()).collect();
    let uses = |u: &str| input.uses.iter().any(|x| x == u);

    if input.fingerprint {
        let hashes = inf.hash(call, &input.pdf, all_pages)?;
        let vecs = embed_pages(inf, call, layers.get(..n).unwrap_or_default())?;
        for h in hashes {
            let i = usize::from(h.page);
            out.prints.push(PagePrint {
                page: to_i32(i).saturating_add(1),
                dhash: stored(h.dhash),
                phash: stored(h.phash),
                embedding: vecs.get(i).cloned().flatten().map(|v| vec_bytes(&v)),
            });
        }
        return Ok(out);
    }

    // OCR: pages with no text layer, up to the page cap (docs/33 §2 step 2).
    let mut ocr: BTreeMap<usize, Value> = BTreeMap::new();
    if uses("ocr") {
        let blank: Vec<u16> = all_pages
            .iter()
            .copied()
            .filter(|p| {
                layers
                    .get(usize::from(*p))
                    .is_some_and(|t| t.trim().is_empty())
            })
            .collect();
        if !blank.is_empty() {
            for p in inf.ocr(call, &input.pdf, &blank, OCR_DPI, &input.scripts)? {
                if p.status != 0 || !blank.contains(&p.page) {
                    continue;
                }
                let w = words_json(&p);
                ocr.insert(usize::from(p.page), w.clone());
                out.ocr
                    .push((to_i32(usize::from(p.page)).saturating_add(1), w));
            }
        }
    }
    let texts: Vec<String> = layers
        .iter()
        .take(n)
        .enumerate()
        .map(|(i, l)| page_text(l, ocr.get(&i)))
        .collect();

    // Agreement details (step 5, entities).
    if uses("entities") {
        let m = model(
            &info,
            |id| id.contains("gliner") && !id.contains("pii"),
            "gliner",
        );
        let labels: Vec<String> = ENTITY_LABELS.iter().map(|l| l.0.to_owned()).collect();
        let mut kept = 0usize;
        'pages: for (i, text) in texts.iter().enumerate() {
            for (off, piece) in chunks(text, MAX_SPAN_TEXT) {
                if piece.trim().is_empty() {
                    continue;
                }
                let spans = inf.entities(
                    call,
                    SpanRequest {
                        text: piece.to_owned(),
                        labels: labels.clone(),
                        threshold: THRESHOLD,
                    },
                )?;
                for s in spans {
                    if kept >= MAX_ENTITIES {
                        out.truncated = true;
                        break 'pages;
                    }
                    let Some((_, shown)) = ENTITY_LABELS.get(usize::from(s.label)) else {
                        continue;
                    };
                    out.suggestions.push(Draft {
                        kind: SuggestionKind::Entity,
                        page: to_i32(i).saturating_add(1),
                        label: (*shown).to_owned(),
                        span: Some((
                            to_i32(off.saturating_add(s.start as usize)),
                            to_i32(off.saturating_add(s.end as usize)),
                        )),
                        template: None,
                        score: score(s.score),
                        model: m.clone(),
                    });
                    kept = kept.saturating_add(1);
                }
            }
        }
    }

    // Personal data (step 5): the deterministic recognisers, then the model's spans that
    // do not overlap them. A personal-data model that is not installed adds nothing.
    if uses("personal_data") {
        let rules = (PII_RULES_MODEL.to_owned(), id_hash(PII_RULES_MODEL));
        let m = model(&info, |id| id.contains("pii"), "gliner-pii");
        let labels: Vec<String> = PERSONAL_LABELS.iter().map(|l| l.0.to_owned()).collect();
        let mut kept = 0usize;
        let mut model_on = true;
        'pii: for (i, text) in texts.iter().enumerate() {
            let page = to_i32(i).saturating_add(1);
            let mut found: Vec<(usize, usize)> = Vec::new();
            for (off, piece) in chunks(text, casual_sign_pii::MAX_TEXT_BYTES) {
                let d = casual_sign_pii::detect(
                    piece,
                    &casual_sign_pii::Options {
                        min_score: 500,
                        ..casual_sign_pii::Options::default()
                    },
                )
                .map_err(|_| WorkerError::Pipeline {
                    code: "CS-PII-0001",
                })?;
                out.truncated |= !d.truncated.is_empty();
                for s in d.spans {
                    if kept >= MAX_PERSONAL {
                        out.truncated = true;
                        break 'pii;
                    }
                    let (a, b) = (off.saturating_add(s.start), off.saturating_add(s.end));
                    found.push((a, b));
                    out.suggestions.push(Draft {
                        kind: SuggestionKind::PersonalData,
                        page,
                        label: human(s.kind.label()),
                        span: Some((to_i32(a), to_i32(b))),
                        template: None,
                        score: (f32::from(s.score) / f32::from(casual_sign_pii::MAX_SCORE))
                            .clamp(0.0, 1.0),
                        model: rules.clone(),
                    });
                    kept = kept.saturating_add(1);
                }
            }
            if !model_on {
                continue;
            }
            for (off, piece) in chunks(text, MAX_SPAN_TEXT) {
                if piece.trim().is_empty() {
                    continue;
                }
                let spans = match inf.personal(
                    call,
                    SpanRequest {
                        text: piece.to_owned(),
                        labels: labels.clone(),
                        threshold: THRESHOLD,
                    },
                ) {
                    Ok(s) => s,
                    Err(ModeldError::NotInstalled) => {
                        model_on = false;
                        break;
                    }
                    Err(e) => return Err(e.into()),
                };
                for s in spans {
                    let (a, b) = (
                        off.saturating_add(s.start as usize),
                        off.saturating_add(s.end as usize),
                    );
                    if found.iter().any(|(x, y)| a < *y && *x < b) {
                        continue;
                    }
                    let Some((_, shown)) = PERSONAL_LABELS.get(usize::from(s.label)) else {
                        continue;
                    };
                    if kept >= MAX_PERSONAL {
                        out.truncated = true;
                        break 'pii;
                    }
                    out.suggestions.push(Draft {
                        kind: SuggestionKind::PersonalData,
                        page,
                        label: (*shown).to_owned(),
                        span: Some((to_i32(a), to_i32(b))),
                        template: None,
                        score: score(s.score),
                        model: m.clone(),
                    });
                    kept = kept.saturating_add(1);
                }
            }
        }
    }

    // Template matching (step 4, docs/33 §5.2): both hashes within MAX_HAMMING on at
    // least MIN_PAGE_SHARE of a template document's pages, and the matched pages' texts
    // at a mean cosine of at least MIN_COSINE.
    if uses("template") && !input.fingerprints.is_empty() && n > 0 {
        let hashes = inf.hash(call, &input.pdf, all_pages)?;
        let vecs = embed_pages(inf, call, &texts)?;
        let mut groups: BTreeMap<(TemplateId, uuid::Uuid), Vec<&Fingerprint>> = BTreeMap::new();
        for f in &input.fingerprints {
            groups
                .entry((f.template_id, f.document_id.0))
                .or_default()
                .push(f);
        }
        let mut best: BTreeMap<TemplateId, Draft> = BTreeMap::new();
        for ((t, _), pages) in groups {
            let total = pages.len();
            let mut matched = 0usize;
            let mut cos = Vec::new();
            for f in &pages {
                let Some(i) = usize::try_from(f.page.saturating_sub(1)).ok() else {
                    continue;
                };
                let Some(h) = hashes.iter().find(|h| usize::from(h.page) == i) else {
                    continue;
                };
                if hamming(stored(h.dhash), f.dhash) > MAX_HAMMING
                    || hamming(stored(h.phash), f.phash) > MAX_HAMMING
                {
                    continue;
                }
                matched = matched.saturating_add(1);
                if let (Some(Some(v)), Some(e)) = (vecs.get(i), f.embedding.as_deref()) {
                    cos.push(cosine(v, &bytes_vec(e)));
                }
            }
            #[allow(clippy::cast_precision_loss)] // Page counts are at most 200.
            let share = matched as f32 / total.max(1) as f32;
            if matched == 0 || share < MIN_PAGE_SHARE || cos.is_empty() {
                continue;
            }
            #[allow(clippy::cast_precision_loss)]
            let mean = cos.iter().sum::<f32>() / cos.len() as f32;
            if mean < MIN_COSINE {
                continue;
            }
            let d = Draft {
                kind: SuggestionKind::Template,
                page: 1,
                label: String::new(),
                span: None,
                template: Some((t, to_i32(matched), to_i32(total))),
                score: (share * mean).clamp(0.0, 1.0),
                model: model(
                    &info,
                    |id| id.contains("e5") || id.contains("minilm"),
                    PAGE_HASH_MODEL,
                ),
            };
            if best.get(&t).is_none_or(|b| b.score < d.score) {
                best.insert(t, d);
            }
        }
        out.suggestions.extend(best.into_values());
    }
    Ok(out)
}

/// `EMAIL_ADDRESS` → `Email address`.
fn human(label: &str) -> String {
    let lower = label.replace('_', " ").to_lowercase();
    let mut c = lower.chars();
    c.next()
        .map(|f| f.to_uppercase().chain(c).collect())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunks_cover_the_text_on_character_boundaries() {
        let t = "déjà vu ".repeat(40);
        let parts = chunks(&t, 37);
        let mut joined = String::new();
        for (off, p) in &parts {
            assert_eq!(*off, joined.len());
            assert!(p.len() <= 37);
            joined.push_str(p);
        }
        assert_eq!(joined, t);
        assert_eq!(chunks("", 10), Vec::<(usize, &str)>::new());
    }

    #[test]
    fn labels_read_as_people_write_them() {
        assert_eq!(human("EMAIL_ADDRESS"), "Email address");
        assert_eq!(human("IBAN_CODE"), "Iban code");
    }

    #[test]
    fn hashes_round_trip_through_bigint_and_embeddings_through_bytes() {
        let h = u64::MAX - 5;
        assert_eq!(hamming(stored(h), stored(h)), 0);
        assert_eq!(hamming(stored(h), stored(h ^ 0b101)), 2);
        let v = vec![0.5_f32, -0.25, 1.0];
        assert_eq!(bytes_vec(&vec_bytes(&v)), v);
        assert!((cosine(&v, &v) - 1.3125).abs() < 1e-6);
    }
}
