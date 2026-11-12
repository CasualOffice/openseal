//! modeld's protocol inside the mutually authenticated TLS stream (docs/33 §3):
//! length-prefixed binary frames, every field bounded, every read checked. Framing and
//! the reader are copied from keyd's `wire.rs` (`server/casual-sign-keyd/src/wire.rs`,
//! stage 2E) and extended with modeld's operations.
//!
//! A frame from the network is hostile input, in both directions: nothing here indexes,
//! unwraps or does unchecked arithmetic on it. A response is decoded against the request
//! it answers, so a span outside the text sent, a page not asked for or a vector of the
//! wrong count is refused (`CS-ML-0004`), never handed to the worker.
//!
//! ```text
//! frame    = len:u32be body                          (len <= MAX_FRAME)
//! request  = 0x01 op:u8 deadline_ms:u32be account:id8 job:id8 body
//!   0x01 INFO      (no body)
//!   0x02 OCR       pdf:bytes32 pages:list16(u16) dpi:u16 scripts:list8(id8)
//!   0x03 HASH      pdf:bytes32 pages:list16(u16)
//!   0x04 EMBED     kind:u8 (0 query | 1 passage) texts:list8(text32)
//!   0x05 ENTITIES  text:text32 labels:list8(text8) threshold:u16
//!   0x06 PERSONAL  as ENTITIES
//! response = 0x01 0x00 ok-body | 0x01 0x01 code:u16be
//!   INFO     bundle:id8 runtime:id8 models:list16(id:id8 sha256:32B)
//!   OCR      list16(page:u16 status:u16 width:u16 height:u16
//!                   words:list16(text:text16 quad conf:u16)
//!                   lines:list16(quad) rules:list16(rect) boxes:list16(rect))
//!   HASH     list16(page:u16 dhash:u64be phash:u64be)
//!   EMBED    dim:u16 list8(f32be × dim)
//!   SPANS    list16(start:u32be end:u32be label:u8 score:u16)    (ENTITIES, PERSONAL)
//! quad     = 4 × (x:f32be y:f32be)        rect = x0 y0 x1 y1 : f32be
//! id8      = len:u8 [A-Za-z0-9._-]{1,64}  textN = lenN UTF-8 (checked, never logged)
//! listN(x) = count:uN x{count}
//! ```
//!
//! Span offsets are **UTF-8 byte offsets into exactly the text the worker sent** (which
//! the worker has put in NFC); review defect 19 of ADR-029. Scores and confidences are in
//! ten-thousandths ([`SCORE_SCALE`]). Pixel coordinates are in the raster's space, top
//! left, at the request's DPI; the worker maps them to page space (docs/33 §2 step 3).

use std::io::{Read, Write};

use crate::error::ModeldError;

/// Protocol version.
pub const VERSION: u8 = 1;
/// Largest frame either side reads: a 50 MiB upload plus headers (docs/33 §4,
/// `CS-ML-0004`).
pub const MAX_FRAME: usize = 64 << 20;
/// Largest PDF in an OCR or HASH request: the upload cap.
pub const MAX_PDF: usize = 50 << 20;
/// Longest identifier (account, job, script, model, bundle, runtime version).
pub const MAX_ID: usize = 64;
/// Most pages in one OCR or HASH request (the per-document OCR cap).
pub const MAX_PAGES: usize = 200;
/// Lowest render resolution a request may ask for.
pub const MIN_DPI: u16 = 100;
/// Highest render resolution a request may ask for.
pub const MAX_DPI: u16 = 200;
/// Most OCR script packs named in one request.
pub const MAX_SCRIPTS: usize = 16;
/// Longest deadline a request may set: the per-job OCR deadline, 15 minutes.
pub const MAX_DEADLINE_MS: u32 = 15 * 60 * 1000;
/// Most texts in one EMBED request.
pub const MAX_EMBED_TEXTS: usize = 64;
/// Longest text in an EMBED request.
pub const MAX_EMBED_TEXT: usize = 8 * 1024;
/// Longest text in an ENTITIES or PERSONAL request.
pub const MAX_SPAN_TEXT: usize = 64 * 1024;
/// Most labels in an ENTITIES or PERSONAL request.
pub const MAX_LABELS: usize = 32;
/// Longest label.
pub const MAX_LABEL: usize = 64;
/// Most spans in one answer (the per-document personal-data cap).
pub const MAX_SPANS: usize = 5_000;
/// Most words, lines, rules or boxes on one OCR page (`MAX_DETECT_WORDS`).
pub const MAX_PAGE_ITEMS: usize = 20_000;
/// Longest OCR word.
pub const MAX_WORD: usize = 1024;
/// Largest raster side in pixels (docs/33 §4).
pub const MAX_RASTER_SIDE: u16 = 4096;
/// Largest embedding dimension.
pub const MAX_DIM: usize = 4096;
/// Most models INFO may list.
pub const MAX_MODELS: usize = 64;
/// Scores, confidences and thresholds are in ten-thousandths.
pub const SCORE_SCALE: u16 = 10_000;

const OP_INFO: u8 = 1;
const OP_OCR: u8 = 2;
const OP_HASH: u8 = 3;
const OP_EMBED: u8 = 4;
const OP_ENTITIES: u8 = 5;
const OP_PERSONAL: u8 = 6;

/// Which embedding prefix the model is given (e5's `query:` and `passage:`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmbedKind {
    /// A search query.
    Query,
    /// A page or document passage.
    Passage,
}

/// A request to modeld: who asks (for the op log), how long it may take, and the op.
#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    /// Milliseconds modeld may spend before answering `CS-ML-0007`.
    pub deadline_ms: u32,
    /// The account the work is for, recorded in the op log.
    pub account: String,
    /// The job the work is for, recorded in the op log.
    pub job: String,
    /// What to do.
    pub op: Op,
}

/// An operation.
#[derive(Debug, Clone, PartialEq)]
pub enum Op {
    /// The installed bundle: its id, the runtime version and each model's hash.
    Info,
    /// Rasterise and read pages.
    Ocr {
        /// The stored, normalized PDF.
        pdf: Vec<u8>,
        /// Zero-based page indexes.
        pages: Vec<u16>,
        /// Render resolution.
        dpi: u16,
        /// OCR script packs to use (installed pack ids).
        scripts: Vec<String>,
    },
    /// Perceptual hashes of pages.
    Hash {
        /// The stored, normalized PDF.
        pdf: Vec<u8>,
        /// Zero-based page indexes.
        pages: Vec<u16>,
    },
    /// Sentence embeddings.
    Embed {
        /// Query or passage.
        kind: EmbedKind,
        /// The texts.
        texts: Vec<String>,
    },
    /// Named entities (parties, dates, amounts, ...).
    Entities(SpanRequest),
    /// Personal-data spans (the model layer of ML-08).
    Personal(SpanRequest),
}

/// The body of an ENTITIES or PERSONAL request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpanRequest {
    /// The text, in NFC; span offsets index its UTF-8 bytes.
    pub text: String,
    /// The labels asked for; a span's `label` indexes this list.
    pub labels: Vec<String>,
    /// Lowest score returned, in ten-thousandths.
    pub threshold: u16,
}

/// modeld's answer.
#[derive(Debug, Clone, PartialEq)]
pub enum Response {
    /// INFO.
    Info(Info),
    /// OCR, one entry per page asked for, in order.
    Ocr(Vec<OcrPage>),
    /// HASH, one entry per page asked for, in order.
    Hash(Vec<PageHash>),
    /// EMBED, one vector per text, in order.
    Embed(Vec<Vec<f32>>),
    /// ENTITIES or PERSONAL.
    Spans(Vec<Span>),
    /// Refused or failed, with the `CS-ML-` number.
    Error(u16),
}

/// The installed bundle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Info {
    /// The bundle id (hex SHA-256 of the installed manifest entries).
    pub bundle_id: String,
    /// The inference runtime's version (`none` until one is linked).
    pub runtime: String,
    /// Each installed model file: manifest id and SHA-256.
    pub models: Vec<(String, [u8; 32])>,
}

/// Four corners, clockwise from top left, in raster pixels.
pub type Quad = [(f32, f32); 4];
/// `x0, y0, x1, y1` in raster pixels.
pub type Rect = [f32; 4];

/// One OCR'd page.
#[derive(Debug, Clone, PartialEq)]
pub struct OcrPage {
    /// The page index asked for.
    pub page: u16,
    /// `0`, or the `CS-ML-` number this page failed with (5 or 6); then nothing else is
    /// filled in.
    pub status: u16,
    /// Raster width in pixels.
    pub width: u16,
    /// Raster height in pixels.
    pub height: u16,
    /// Words read.
    pub words: Vec<Word>,
    /// Text lines found.
    pub lines: Vec<Quad>,
    /// Drawn rules (signature lines, underscores) found in the image.
    pub rules: Vec<Rect>,
    /// Drawn boxes (check boxes, entry cells) found in the image.
    pub boxes: Vec<Rect>,
}

/// One OCR'd word.
#[derive(Debug, Clone, PartialEq)]
pub struct Word {
    /// The word, UTF-8.
    pub text: String,
    /// Where it is.
    pub quad: Quad,
    /// Recognition confidence, in ten-thousandths.
    pub conf: u16,
}

/// A page's perceptual hashes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PageHash {
    /// The page index asked for.
    pub page: u16,
    /// Difference hash.
    pub dhash: u64,
    /// DCT perceptual hash.
    pub phash: u64,
}

/// A span of the text sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    /// UTF-8 byte offset of the first byte.
    pub start: u32,
    /// UTF-8 byte offset one past the last byte.
    pub end: u32,
    /// Index into the request's labels.
    pub label: u8,
    /// Score, in ten-thousandths.
    pub score: u16,
}

impl Op {
    /// The op's name in the op log.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Ocr { .. } => "ocr",
            Self::Hash { .. } => "hash",
            Self::Embed { .. } => "embed",
            Self::Entities(_) => "entities",
            Self::Personal(_) => "personal",
        }
    }
}

fn malformed(why: &'static str) -> ModeldError {
    ModeldError::Malformed(why)
}

/// Whether `s` is a valid identifier: `[A-Za-z0-9._-]{1,64}`.
#[must_use]
pub fn valid_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_ID
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Whether `s` is a usable label: 1 to [`MAX_LABEL`] bytes, no control characters.
fn valid_label(s: &str) -> bool {
    !s.is_empty() && s.len() <= MAX_LABEL && !s.chars().any(char::is_control)
}

/// A cursor over a frame body (keyd's `Reader`, extended).
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ModeldError> {
        if n > self.0.len() {
            return Err(malformed("truncated"));
        }
        let (head, tail) = self.0.split_at(n);
        self.0 = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ModeldError> {
        self.take(N)?.try_into().map_err(|_| malformed("truncated"))
    }

    fn u8(&mut self) -> Result<u8, ModeldError> {
        Ok(u8::from_be_bytes(self.array()?))
    }

    fn u16(&mut self) -> Result<u16, ModeldError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, ModeldError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, ModeldError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn f32(&mut self) -> Result<f32, ModeldError> {
        let v = f32::from_be_bytes(self.array()?);
        if v.is_finite() {
            Ok(v)
        } else {
            Err(malformed("number is not finite"))
        }
    }

    fn len32(&mut self, max: usize) -> Result<usize, ModeldError> {
        let n = usize::try_from(self.u32()?).map_err(|_| malformed("length"))?;
        if n > max {
            return Err(malformed("field over its bound"));
        }
        Ok(n)
    }

    fn count8(&mut self, max: usize) -> Result<usize, ModeldError> {
        let n = usize::from(self.u8()?);
        if n > max {
            return Err(malformed("count over its bound"));
        }
        Ok(n)
    }

    fn count16(&mut self, max: usize) -> Result<usize, ModeldError> {
        let n = usize::from(self.u16()?);
        if n > max {
            return Err(malformed("count over its bound"));
        }
        Ok(n)
    }

    fn utf8(raw: &[u8]) -> Result<String, ModeldError> {
        core::str::from_utf8(raw)
            .map(str::to_owned)
            .map_err(|_| malformed("text is not UTF-8"))
    }

    fn id(&mut self) -> Result<String, ModeldError> {
        let n = usize::from(self.u8()?);
        let s = Self::utf8(self.take(n)?)?;
        if !valid_id(&s) {
            return Err(malformed(
                "identifier empty, too long or outside [A-Za-z0-9._-]",
            ));
        }
        Ok(s)
    }

    fn label(&mut self) -> Result<String, ModeldError> {
        let n = usize::from(self.u8()?);
        let s = Self::utf8(self.take(n)?)?;
        if !valid_label(&s) {
            return Err(malformed(
                "label empty, too long or with a control character",
            ));
        }
        Ok(s)
    }

    fn text16(&mut self, max: usize) -> Result<String, ModeldError> {
        let n = usize::from(self.u16()?);
        if n > max {
            return Err(malformed("text over its bound"));
        }
        Self::utf8(self.take(n)?)
    }

    fn text32(&mut self, max: usize) -> Result<String, ModeldError> {
        let n = self.len32(max)?;
        Self::utf8(self.take(n)?)
    }

    fn pages(&mut self) -> Result<Vec<u16>, ModeldError> {
        let n = self.count16(MAX_PAGES)?;
        if n == 0 {
            return Err(malformed("no pages"));
        }
        (0..n).map(|_| self.u16()).collect()
    }

    fn quad(&mut self) -> Result<Quad, ModeldError> {
        Ok([
            (self.f32()?, self.f32()?),
            (self.f32()?, self.f32()?),
            (self.f32()?, self.f32()?),
            (self.f32()?, self.f32()?),
        ])
    }

    fn rect(&mut self) -> Result<Rect, ModeldError> {
        Ok([self.f32()?, self.f32()?, self.f32()?, self.f32()?])
    }

    fn list16<T>(
        &mut self,
        max: usize,
        mut each: impl FnMut(&mut Self) -> Result<T, ModeldError>,
    ) -> Result<Vec<T>, ModeldError> {
        let n = self.count16(max)?;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(each(self)?);
        }
        Ok(out)
    }

    fn span_request(&mut self) -> Result<SpanRequest, ModeldError> {
        let text = self.text32(MAX_SPAN_TEXT)?;
        let n = self.count8(MAX_LABELS)?;
        if n == 0 {
            return Err(malformed("no labels"));
        }
        let labels = (0..n)
            .map(|_| self.label())
            .collect::<Result<Vec<_>, _>>()?;
        let threshold = self.u16()?;
        if threshold > SCORE_SCALE {
            return Err(malformed("threshold over 10000"));
        }
        Ok(SpanRequest {
            text,
            labels,
            threshold,
        })
    }

    fn end(&self) -> Result<(), ModeldError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(malformed("trailing bytes"))
        }
    }
}

/// A frame body being written: every length checked against its field's width.
struct Writer(Vec<u8>);

impl Writer {
    fn u8(&mut self, v: u8) {
        self.0.push(v);
    }

    fn u16(&mut self, v: u16) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }

    fn u32(&mut self, v: u32) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }

    fn u64(&mut self, v: u64) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }

    fn f32(&mut self, v: f32) {
        self.0.extend_from_slice(&v.to_be_bytes());
    }

    fn count8(&mut self, n: usize) -> Result<(), ModeldError> {
        self.u8(u8::try_from(n).map_err(|_| malformed("count over 255"))?);
        Ok(())
    }

    fn count16(&mut self, n: usize) -> Result<(), ModeldError> {
        self.u16(u16::try_from(n).map_err(|_| malformed("count over 65535"))?);
        Ok(())
    }

    fn bytes8(&mut self, b: &[u8]) -> Result<(), ModeldError> {
        self.count8(b.len())?;
        self.0.extend_from_slice(b);
        Ok(())
    }

    fn bytes16(&mut self, b: &[u8]) -> Result<(), ModeldError> {
        self.count16(b.len())?;
        self.0.extend_from_slice(b);
        Ok(())
    }

    fn bytes32(&mut self, b: &[u8]) -> Result<(), ModeldError> {
        self.u32(u32::try_from(b.len()).map_err(|_| malformed("field over 4 GiB"))?);
        self.0.extend_from_slice(b);
        Ok(())
    }

    fn quad(&mut self, q: &Quad) {
        for (x, y) in q {
            self.f32(*x);
            self.f32(*y);
        }
    }

    fn rect(&mut self, r: &Rect) {
        for v in r {
            self.f32(*v);
        }
    }

    fn pages(&mut self, pages: &[u16]) -> Result<(), ModeldError> {
        self.count16(pages.len())?;
        for p in pages {
            self.u16(*p);
        }
        Ok(())
    }

    fn span_request(&mut self, r: &SpanRequest) -> Result<(), ModeldError> {
        self.bytes32(r.text.as_bytes())?;
        self.count8(r.labels.len())?;
        for l in &r.labels {
            self.bytes8(l.as_bytes())?;
        }
        self.u16(r.threshold);
        Ok(())
    }
}

impl Request {
    /// Encode. The encoder writes what it is given; [`Request::decode`] is where bounds
    /// are enforced, on both sides (the client decodes its own request before sending).
    ///
    /// # Errors
    /// `CS-ML-0004` when a field does not fit its width.
    pub fn encode(&self) -> Result<Vec<u8>, ModeldError> {
        let mut w = Writer(vec![VERSION]);
        w.u8(match &self.op {
            Op::Info => OP_INFO,
            Op::Ocr { .. } => OP_OCR,
            Op::Hash { .. } => OP_HASH,
            Op::Embed { .. } => OP_EMBED,
            Op::Entities(_) => OP_ENTITIES,
            Op::Personal(_) => OP_PERSONAL,
        });
        w.u32(self.deadline_ms);
        w.bytes8(self.account.as_bytes())?;
        w.bytes8(self.job.as_bytes())?;
        match &self.op {
            Op::Info => {}
            Op::Ocr {
                pdf,
                pages,
                dpi,
                scripts,
            } => {
                w.bytes32(pdf)?;
                w.pages(pages)?;
                w.u16(*dpi);
                w.count8(scripts.len())?;
                for s in scripts {
                    w.bytes8(s.as_bytes())?;
                }
            }
            Op::Hash { pdf, pages } => {
                w.bytes32(pdf)?;
                w.pages(pages)?;
            }
            Op::Embed { kind, texts } => {
                w.u8(match kind {
                    EmbedKind::Query => 0,
                    EmbedKind::Passage => 1,
                });
                w.count8(texts.len())?;
                for t in texts {
                    w.bytes32(t.as_bytes())?;
                }
            }
            Op::Entities(r) | Op::Personal(r) => w.span_request(r)?,
        }
        Ok(w.0)
    }

    /// Decode a frame body, enforcing every bound.
    ///
    /// # Errors
    /// `CS-ML-0004` for anything malformed or over a bound.
    pub fn decode(body: &[u8]) -> Result<Self, ModeldError> {
        let mut r = Reader(body);
        if r.u8()? != VERSION {
            return Err(malformed("unknown protocol version"));
        }
        let op = r.u8()?;
        let deadline_ms = r.u32()?;
        if deadline_ms == 0 || deadline_ms > MAX_DEADLINE_MS {
            return Err(malformed("deadline outside 1 ms to 15 minutes"));
        }
        let account = r.id()?;
        let job = r.id()?;
        let op = match op {
            OP_INFO => Op::Info,
            OP_OCR => {
                let n = r.len32(MAX_PDF)?;
                let pdf = r.take(n)?.to_vec();
                let pages = r.pages()?;
                let dpi = r.u16()?;
                if !(MIN_DPI..=MAX_DPI).contains(&dpi) {
                    return Err(malformed("resolution outside 100 to 200 DPI"));
                }
                let k = r.count8(MAX_SCRIPTS)?;
                let scripts = (0..k).map(|_| r.id()).collect::<Result<Vec<_>, _>>()?;
                Op::Ocr {
                    pdf,
                    pages,
                    dpi,
                    scripts,
                }
            }
            OP_HASH => {
                let n = r.len32(MAX_PDF)?;
                let pdf = r.take(n)?.to_vec();
                let pages = r.pages()?;
                Op::Hash { pdf, pages }
            }
            OP_EMBED => {
                let kind = match r.u8()? {
                    0 => EmbedKind::Query,
                    1 => EmbedKind::Passage,
                    _ => return Err(malformed("embedding kind")),
                };
                let n = r.count8(MAX_EMBED_TEXTS)?;
                if n == 0 {
                    return Err(malformed("no texts"));
                }
                let texts = (0..n)
                    .map(|_| r.text32(MAX_EMBED_TEXT))
                    .collect::<Result<Vec<_>, _>>()?;
                Op::Embed { kind, texts }
            }
            OP_ENTITIES => Op::Entities(r.span_request()?),
            OP_PERSONAL => Op::Personal(r.span_request()?),
            _ => return Err(malformed("unknown operation")),
        };
        r.end()?;
        Ok(Self {
            deadline_ms,
            account,
            job,
            op,
        })
    }
}

impl Response {
    /// Encode.
    ///
    /// # Errors
    /// `CS-ML-0004` when a field does not fit its width.
    pub fn encode(&self) -> Result<Vec<u8>, ModeldError> {
        let mut w = Writer(vec![VERSION]);
        if let Self::Error(code) = self {
            w.u8(1);
            w.u16(*code);
            return Ok(w.0);
        }
        w.u8(0);
        match self {
            Self::Error(_) => {}
            Self::Info(info) => {
                w.bytes8(info.bundle_id.as_bytes())?;
                w.bytes8(info.runtime.as_bytes())?;
                w.count16(info.models.len())?;
                for (id, sha) in &info.models {
                    w.bytes8(id.as_bytes())?;
                    w.0.extend_from_slice(sha);
                }
            }
            Self::Ocr(pages) => {
                w.count16(pages.len())?;
                for p in pages {
                    w.u16(p.page);
                    w.u16(p.status);
                    w.u16(p.width);
                    w.u16(p.height);
                    w.count16(p.words.len())?;
                    for word in &p.words {
                        w.bytes16(word.text.as_bytes())?;
                        w.quad(&word.quad);
                        w.u16(word.conf);
                    }
                    w.count16(p.lines.len())?;
                    for q in &p.lines {
                        w.quad(q);
                    }
                    w.count16(p.rules.len())?;
                    for r in &p.rules {
                        w.rect(r);
                    }
                    w.count16(p.boxes.len())?;
                    for r in &p.boxes {
                        w.rect(r);
                    }
                }
            }
            Self::Hash(pages) => {
                w.count16(pages.len())?;
                for h in pages {
                    w.u16(h.page);
                    w.u64(h.dhash);
                    w.u64(h.phash);
                }
            }
            Self::Embed(vectors) => {
                let dim = vectors.first().map_or(0, Vec::len);
                w.count16(dim)?;
                w.count8(vectors.len())?;
                for v in vectors {
                    if v.len() != dim {
                        return Err(malformed("vectors of different dimensions"));
                    }
                    for x in v {
                        w.f32(*x);
                    }
                }
            }
            Self::Spans(spans) => {
                w.count16(spans.len())?;
                for s in spans {
                    w.u32(s.start);
                    w.u32(s.end);
                    w.u8(s.label);
                    w.u16(s.score);
                }
            }
        }
        Ok(w.0)
    }

    /// Decode a frame body answering `request`, checking that it answers exactly that
    /// request: the pages asked for in order, one vector per text, spans inside the text
    /// sent and on character boundaries, labels that were asked for.
    ///
    /// # Errors
    /// `CS-ML-0004` for anything malformed, over a bound or not answering `request`.
    pub fn decode(body: &[u8], request: &Request) -> Result<Self, ModeldError> {
        let mut r = Reader(body);
        if r.u8()? != VERSION {
            return Err(malformed("unknown protocol version"));
        }
        let resp = match r.u8()? {
            1 => Self::Error(r.u16()?),
            0 => match &request.op {
                Op::Info => Self::Info(decode_info(&mut r)?),
                Op::Ocr { pages, .. } => Self::Ocr(decode_ocr(&mut r, pages)?),
                Op::Hash { pages, .. } => Self::Hash(decode_hash(&mut r, pages)?),
                Op::Embed { texts, .. } => Self::Embed(decode_embed(&mut r, texts.len())?),
                Op::Entities(req) | Op::Personal(req) => Self::Spans(decode_spans(&mut r, req)?),
            },
            _ => return Err(malformed("unknown status")),
        };
        r.end()?;
        Ok(resp)
    }
}

fn decode_info(r: &mut Reader<'_>) -> Result<Info, ModeldError> {
    let bundle_id = r.id()?;
    let runtime = r.id()?;
    let models = r.list16(MAX_MODELS, |r| Ok((r.id()?, r.array::<32>()?)))?;
    Ok(Info {
        bundle_id,
        runtime,
        models,
    })
}

fn decode_ocr(r: &mut Reader<'_>, asked: &[u16]) -> Result<Vec<OcrPage>, ModeldError> {
    let n = r.count16(MAX_PAGES)?;
    if n != asked.len() {
        return Err(malformed("OCR answer is not one entry per page asked for"));
    }
    let mut out = Vec::with_capacity(n);
    for want in asked {
        let page = r.u16()?;
        if page != *want {
            return Err(malformed("OCR answer pages are not those asked for"));
        }
        let status = r.u16()?;
        let width = r.u16()?;
        let height = r.u16()?;
        if width > MAX_RASTER_SIDE || height > MAX_RASTER_SIDE {
            return Err(malformed("raster side over its bound"));
        }
        let words = r.list16(MAX_PAGE_ITEMS, |r| {
            let text = r.text16(MAX_WORD)?;
            let quad = r.quad()?;
            let conf = r.u16()?;
            if conf > SCORE_SCALE {
                return Err(malformed("confidence over 10000"));
            }
            Ok(Word { text, quad, conf })
        })?;
        let lines = r.list16(MAX_PAGE_ITEMS, Reader::quad)?;
        let rules = r.list16(MAX_PAGE_ITEMS, Reader::rect)?;
        let boxes = r.list16(MAX_PAGE_ITEMS, Reader::rect)?;
        if status != 0
            && (!words.is_empty() || !lines.is_empty() || !rules.is_empty() || !boxes.is_empty())
        {
            return Err(malformed("a failed page carries results"));
        }
        out.push(OcrPage {
            page,
            status,
            width,
            height,
            words,
            lines,
            rules,
            boxes,
        });
    }
    Ok(out)
}

fn decode_hash(r: &mut Reader<'_>, asked: &[u16]) -> Result<Vec<PageHash>, ModeldError> {
    let n = r.count16(MAX_PAGES)?;
    if n != asked.len() {
        return Err(malformed("HASH answer is not one entry per page asked for"));
    }
    asked
        .iter()
        .map(|want| {
            let page = r.u16()?;
            if page != *want {
                return Err(malformed("HASH answer pages are not those asked for"));
            }
            Ok(PageHash {
                page,
                dhash: r.u64()?,
                phash: r.u64()?,
            })
        })
        .collect()
}

fn decode_embed(r: &mut Reader<'_>, asked: usize) -> Result<Vec<Vec<f32>>, ModeldError> {
    let dim = r.count16(MAX_DIM)?;
    let n = r.count8(MAX_EMBED_TEXTS)?;
    if n != asked || dim == 0 {
        return Err(malformed("EMBED answer is not one vector per text"));
    }
    (0..n)
        .map(|_| (0..dim).map(|_| r.f32()).collect())
        .collect()
}

fn decode_spans(r: &mut Reader<'_>, req: &SpanRequest) -> Result<Vec<Span>, ModeldError> {
    r.list16(MAX_SPANS, |r| {
        let s = Span {
            start: r.u32()?,
            end: r.u32()?,
            label: r.u8()?,
            score: r.u16()?,
        };
        let (Ok(start), Ok(end)) = (usize::try_from(s.start), usize::try_from(s.end)) else {
            return Err(malformed("span offset"));
        };
        if start >= end
            || !req.text.is_char_boundary(start)
            || !req.text.is_char_boundary(end)
            || end > req.text.len()
        {
            return Err(malformed(
                "span outside the text or off a character boundary",
            ));
        }
        if usize::from(s.label) >= req.labels.len() {
            return Err(malformed("span label was not asked for"));
        }
        if s.score > SCORE_SCALE || s.score < req.threshold {
            return Err(malformed("span score outside the threshold and 10000"));
        }
        Ok(s)
    })
}

/// Read one frame. `Ok(None)` at a clean end of stream before a frame starts. A length
/// over [`MAX_FRAME`] is refused before anything is allocated. (keyd's `read_frame`.)
///
/// # Errors
/// `CS-ML-0004` for a truncated or oversized frame, `CS-ML-0008` for a transport error.
pub fn read_frame(stream: &mut impl Read) -> Result<Option<Vec<u8>>, ModeldError> {
    let Some(n) = read_frame_length(stream)? else {
        return Ok(None);
    };
    let mut body = vec![0u8; n];
    stream
        .read_exact(&mut body)
        .map_err(|e| ModeldError::Transport(e.kind().to_string()))?;
    Ok(Some(body))
}

/// Read one frame's length prefix only, checked against [`MAX_FRAME`]. `Ok(None)` at a
/// clean end of stream. The server reads a refused caller's frame this way, so nothing
/// the size of the frame is allocated before a caller is admitted.
pub(crate) fn read_frame_length(stream: &mut impl Read) -> Result<Option<usize>, ModeldError> {
    let mut len = [0u8; 4];
    let mut got = 0usize;
    while got < len.len() {
        let slot = len.get_mut(got..).ok_or(malformed("truncated"))?;
        match stream.read(slot) {
            Ok(0) if got == 0 => return Ok(None),
            Ok(0) => return Err(malformed("truncated frame length")),
            Ok(n) => got = got.saturating_add(n),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(ModeldError::Transport(e.kind().to_string())),
        }
    }
    let n = usize::try_from(u32::from_be_bytes(len)).map_err(|_| malformed("frame length"))?;
    if n > MAX_FRAME {
        return Err(malformed("frame over the limit"));
    }
    Ok(Some(n))
}

/// Write one frame.
///
/// # Errors
/// `CS-ML-0004` for a body over [`MAX_FRAME`], `CS-ML-0008` for a transport error.
pub fn write_frame(stream: &mut impl Write, body: &[u8]) -> Result<(), ModeldError> {
    if body.len() > MAX_FRAME {
        return Err(malformed("frame over the limit"));
    }
    let n = u32::try_from(body.len()).map_err(|_| malformed("frame length"))?;
    let io = |e: std::io::Error| ModeldError::Transport(e.kind().to_string());
    stream.write_all(&n.to_be_bytes()).map_err(io)?;
    stream.write_all(body).map_err(io)?;
    stream.flush().map_err(io)
}

#[cfg(test)]
mod tests {
    // Test code: a panic is the failure report.
    #![allow(
        clippy::unwrap_used,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects
    )]
    use super::*;

    fn req(op: Op) -> Request {
        Request {
            deadline_ms: 20_000,
            account: "acc_01J9".into(),
            job: "job-7".into(),
            op,
        }
    }

    fn span_req() -> SpanRequest {
        SpanRequest {
            text: "Agreement between Ana and Bob, 1 May 2026. شروط".into(),
            labels: vec!["person".into(), "date".into()],
            threshold: 5_000,
        }
    }

    fn every_request() -> Vec<Request> {
        vec![
            req(Op::Info),
            req(Op::Ocr {
                pdf: b"%PDF-1.7 synthetic".to_vec(),
                pages: vec![0, 2],
                dpi: 150,
                scripts: vec!["latin".into(), "arabic".into()],
            }),
            req(Op::Hash {
                pdf: b"%PDF-1.7".to_vec(),
                pages: vec![1],
            }),
            req(Op::Embed {
                kind: EmbedKind::Passage,
                texts: vec!["page one".into(), "page two".into()],
            }),
            req(Op::Entities(span_req())),
            req(Op::Personal(span_req())),
        ]
    }

    fn quad(v: f32) -> Quad {
        [(v, v), (v + 1.0, v), (v + 1.0, v + 1.0), (v, v + 1.0)]
    }

    /// One valid answer for each request of [`every_request`], in order.
    fn every_response() -> Vec<Response> {
        vec![
            Response::Info(Info {
                bundle_id: "ab".repeat(32),
                runtime: "none".into(),
                models: vec![("pp-ocrv6-det".into(), [7; 32])],
            }),
            Response::Ocr(vec![
                OcrPage {
                    page: 0,
                    status: 0,
                    width: 1275,
                    height: 1650,
                    words: vec![Word {
                        text: "Signature".into(),
                        quad: quad(10.0),
                        conf: 9_731,
                    }],
                    lines: vec![quad(9.0)],
                    rules: vec![[100.0, 700.0, 400.0, 701.5]],
                    boxes: vec![[50.0, 50.0, 62.0, 62.0]],
                },
                OcrPage {
                    page: 2,
                    status: 6,
                    width: 0,
                    height: 0,
                    words: vec![],
                    lines: vec![],
                    rules: vec![],
                    boxes: vec![],
                },
            ]),
            Response::Hash(vec![PageHash {
                page: 1,
                dhash: u64::MAX,
                phash: 3,
            }]),
            Response::Embed(vec![vec![0.5; 384], vec![-0.25; 384]]),
            Response::Spans(vec![Span {
                start: 18,
                end: 21,
                label: 0,
                score: 9_100,
            }]),
            Response::Spans(vec![]),
        ]
    }

    #[test]
    fn every_request_and_response_round_trips() {
        for (rq, rs) in every_request().into_iter().zip(every_response()) {
            assert_eq!(Request::decode(&rq.encode().unwrap()).unwrap(), rq);
            assert_eq!(Response::decode(&rs.encode().unwrap(), &rq).unwrap(), rs);
            let err = Response::Error(9);
            assert_eq!(Response::decode(&err.encode().unwrap(), &rq).unwrap(), err);
        }
    }

    /// Every truncation and every extension of a valid frame is refused, not panicked on.
    #[test]
    fn truncated_or_extended_frames_are_refused() {
        for (rq, rs) in every_request().into_iter().zip(every_response()) {
            let body = rq.encode().unwrap();
            for n in 0..body.len() {
                assert!(
                    Request::decode(&body[..n]).is_err(),
                    "{} prefix {n}",
                    rq.op.name()
                );
            }
            let mut longer = body.clone();
            longer.push(0);
            assert!(Request::decode(&longer).is_err());
            let resp = rs.encode().unwrap();
            for n in 0..resp.len() {
                assert!(Response::decode(&resp[..n], &rq).is_err(), "prefix {n}");
            }
            let mut longer = resp.clone();
            longer.push(0);
            assert!(Response::decode(&longer, &rq).is_err());
        }
    }

    #[test]
    fn identifiers_outside_the_alphabet_are_refused() {
        for bad in ["", "a b", "a\nb", "ünï", "a/b", "a\tb"] {
            let mut r = req(Op::Info);
            r.account = bad.into();
            let e = Request::decode(&r.encode().unwrap()).unwrap_err();
            assert_eq!(e.code(), "CS-ML-0004", "{bad:?}");
            let mut r = req(Op::Info);
            r.job = bad.into();
            assert!(Request::decode(&r.encode().unwrap()).is_err(), "{bad:?}");
        }
        let mut r = req(Op::Info);
        r.account = "a".repeat(MAX_ID + 1);
        assert!(Request::decode(&r.encode().unwrap()).is_err());
        let mut r = req(Op::Info);
        r.account = "a".repeat(MAX_ID);
        assert!(Request::decode(&r.encode().unwrap()).is_ok());
    }

    #[test]
    fn text_that_is_not_utf8_is_refused() {
        let body = req(Op::Entities(span_req())).encode().unwrap();
        // The text starts after version, op, deadline, account and job, and its length.
        let at = 1 + 1 + 4 + 1 + "acc_01J9".len() + 1 + "job-7".len() + 4;
        let mut bad = body.clone();
        bad[at] = 0xff;
        assert_eq!(Request::decode(&bad).unwrap_err().code(), "CS-ML-0004");
        assert!(Request::decode(&body).is_ok());
    }

    #[test]
    fn requests_over_a_bound_are_refused() {
        let over = |op: Op| Request::decode(&req(op).encode().unwrap()).unwrap_err();
        let sr = |text: String, labels: Vec<String>, threshold| SpanRequest {
            text,
            labels,
            threshold,
        };
        let cases: Vec<(&str, Op)> = vec![
            (
                "text",
                Op::Entities(sr("a".repeat(MAX_SPAN_TEXT + 1), vec!["x".into()], 0)),
            ),
            (
                "labels",
                Op::Personal(sr("a".into(), vec!["x".into(); MAX_LABELS + 1], 0)),
            ),
            ("no labels", Op::Personal(sr("a".into(), vec![], 0))),
            (
                "label length",
                Op::Entities(sr("a".into(), vec!["x".repeat(MAX_LABEL + 1)], 0)),
            ),
            (
                "label control",
                Op::Entities(sr("a".into(), vec!["a\u{0}b".into()], 0)),
            ),
            (
                "threshold",
                Op::Entities(sr("a".into(), vec!["x".into()], SCORE_SCALE + 1)),
            ),
            (
                "texts",
                Op::Embed {
                    kind: EmbedKind::Query,
                    texts: vec!["t".into(); MAX_EMBED_TEXTS + 1],
                },
            ),
            (
                "no texts",
                Op::Embed {
                    kind: EmbedKind::Query,
                    texts: vec![],
                },
            ),
            (
                "text size",
                Op::Embed {
                    kind: EmbedKind::Query,
                    texts: vec!["t".repeat(MAX_EMBED_TEXT + 1)],
                },
            ),
            (
                "pages",
                Op::Hash {
                    pdf: vec![],
                    pages: vec![0; MAX_PAGES + 1],
                },
            ),
            (
                "no pages",
                Op::Hash {
                    pdf: vec![],
                    pages: vec![],
                },
            ),
            (
                "dpi low",
                Op::Ocr {
                    pdf: vec![],
                    pages: vec![0],
                    dpi: MIN_DPI - 1,
                    scripts: vec![],
                },
            ),
            (
                "dpi high",
                Op::Ocr {
                    pdf: vec![],
                    pages: vec![0],
                    dpi: MAX_DPI + 1,
                    scripts: vec![],
                },
            ),
            (
                "scripts",
                Op::Ocr {
                    pdf: vec![],
                    pages: vec![0],
                    dpi: 150,
                    scripts: vec!["l".into(); MAX_SCRIPTS + 1],
                },
            ),
            (
                "script id",
                Op::Ocr {
                    pdf: vec![],
                    pages: vec![0],
                    dpi: 150,
                    scripts: vec!["a b".into()],
                },
            ),
        ];
        for (what, op) in cases {
            assert_eq!(over(op).code(), "CS-ML-0004", "{what}");
        }
        for deadline_ms in [0, MAX_DEADLINE_MS + 1] {
            let mut r = req(Op::Info);
            r.deadline_ms = deadline_ms;
            assert!(
                Request::decode(&r.encode().unwrap()).is_err(),
                "{deadline_ms}"
            );
        }
    }

    /// A PDF length over the cap is refused from its length field, before the bytes.
    #[test]
    fn a_pdf_over_the_cap_is_refused_from_its_length() {
        let mut body = vec![VERSION, OP_HASH];
        body.extend_from_slice(&1000u32.to_be_bytes());
        for id in ["a", "j"] {
            body.push(1);
            body.extend_from_slice(id.as_bytes());
        }
        body.extend_from_slice(&(u32::try_from(MAX_PDF).unwrap() + 1).to_be_bytes());
        let e = Request::decode(&body).unwrap_err();
        assert_eq!(e, ModeldError::Malformed("field over its bound"));
    }

    /// A response that does not answer the request it is read against is refused: the
    /// worker never sees a span outside its text or a page it did not ask for.
    #[test]
    fn responses_that_do_not_answer_the_request_are_refused() {
        let rq = req(Op::Entities(span_req()));
        let text_len = u32::try_from(span_req().text.len()).unwrap();
        let bad_spans = [
            (
                "past the end",
                Span {
                    start: 0,
                    end: text_len + 1,
                    label: 0,
                    score: 9_000,
                },
            ),
            (
                "empty",
                Span {
                    start: 4,
                    end: 4,
                    label: 0,
                    score: 9_000,
                },
            ),
            (
                "reversed",
                Span {
                    start: 5,
                    end: 4,
                    label: 0,
                    score: 9_000,
                },
            ),
            // The Arabic word's letters are two bytes each; offset 1 inside one is not a
            // character boundary.
            (
                "mid-character",
                Span {
                    start: text_len - 1,
                    end: text_len,
                    label: 0,
                    score: 9_000,
                },
            ),
            (
                "label",
                Span {
                    start: 0,
                    end: 4,
                    label: 2,
                    score: 9_000,
                },
            ),
            (
                "below threshold",
                Span {
                    start: 0,
                    end: 4,
                    label: 0,
                    score: 4_999,
                },
            ),
            (
                "score",
                Span {
                    start: 0,
                    end: 4,
                    label: 0,
                    score: SCORE_SCALE + 1,
                },
            ),
        ];
        for (what, s) in bad_spans {
            let body = Response::Spans(vec![s]).encode().unwrap();
            assert_eq!(
                Response::decode(&body, &rq).unwrap_err().code(),
                "CS-ML-0004",
                "{what}"
            );
        }
        let arabic = span_req().text.find('ش').unwrap();
        let ok = Span {
            start: u32::try_from(arabic).unwrap(),
            end: text_len,
            label: 1,
            score: 5_000,
        };
        let body = Response::Spans(vec![ok]).encode().unwrap();
        assert!(Response::decode(&body, &rq).is_ok());

        let ocr = every_request().remove(1);
        let mut pages = match every_response().remove(1) {
            Response::Ocr(p) => p,
            _ => unreachable!(),
        };
        pages.swap(0, 1);
        let body = Response::Ocr(pages.clone()).encode().unwrap();
        assert!(Response::decode(&body, &ocr).is_err(), "pages out of order");
        pages.truncate(1);
        let body = Response::Ocr(pages).encode().unwrap();
        assert!(Response::decode(&body, &ocr).is_err(), "a page missing");

        let embed = every_request().remove(3);
        let body = Response::Embed(vec![vec![0.0; 384]]).encode().unwrap();
        assert!(
            Response::decode(&body, &embed).is_err(),
            "one vector for two texts"
        );
        let body = Response::Embed(vec![vec![f32::NAN; 4], vec![0.0; 4]])
            .encode()
            .unwrap();
        assert!(Response::decode(&body, &embed).is_err(), "not finite");

        let failed_with_words = Response::Ocr(vec![
            OcrPage {
                page: 0,
                status: 5,
                width: 0,
                height: 0,
                words: vec![Word {
                    text: "x".into(),
                    quad: quad(0.0),
                    conf: 1,
                }],
                lines: vec![],
                rules: vec![],
                boxes: vec![],
            },
            OcrPage {
                page: 2,
                status: 0,
                width: 1,
                height: 1,
                words: vec![],
                lines: vec![],
                rules: vec![],
                boxes: vec![],
            },
        ]);
        let body = failed_with_words.encode().unwrap();
        assert!(
            Response::decode(&body, &ocr).is_err(),
            "a failed page with words"
        );
    }

    #[test]
    fn an_oversized_frame_is_refused_before_it_is_read() {
        let mut stream: &[u8] = &[0xff, 0xff, 0xff, 0xff, 0, 0];
        assert_eq!(read_frame(&mut stream).unwrap_err().code(), "CS-ML-0004");
        let n = u32::try_from(MAX_FRAME + 1).unwrap().to_be_bytes();
        let mut stream: &[u8] = &n;
        assert_eq!(read_frame(&mut stream).unwrap_err().code(), "CS-ML-0004");
        let mut empty: &[u8] = &[];
        assert_eq!(read_frame(&mut empty).unwrap(), None);
        let mut short: &[u8] = &[0, 0];
        assert!(read_frame(&mut short).is_err());
        let mut out = Vec::new();
        assert!(write_frame(&mut out, &vec![0; MAX_FRAME + 1]).is_err());
        assert!(out.is_empty());
    }

    #[test]
    fn frames_round_trip_through_a_stream() {
        let body = every_request()[1].encode().unwrap();
        let mut out = Vec::new();
        write_frame(&mut out, &body).unwrap();
        let mut s: &[u8] = &out;
        assert_eq!(read_frame(&mut s).unwrap().unwrap(), body);
        assert_eq!(read_frame(&mut s).unwrap(), None);
    }

    /// Bytes from a deterministic generator never panic either decoder.
    #[test]
    fn arbitrary_bytes_never_panic() {
        let mut x: u32 = 0x1234_5678;
        let requests = every_request();
        for len in 0..400usize {
            let body: Vec<u8> = (0..len)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 17;
                    x ^= x << 5;
                    x.to_le_bytes()[0]
                })
                .collect();
            let _ = Request::decode(&body);
            for rq in &requests {
                let _ = Response::decode(&body, rq);
            }
        }
    }
}
