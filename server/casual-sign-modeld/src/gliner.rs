//! GLiNER span decoding (piece K; rows `ML-07`, `ML-08`): our own code on the one `ort`
//! version (ADR-029 D3, docs/33 §5.3). `gline-rs` 1.1.0 is the reference for the span
//! logic, not a dependency; the behaviour reproduced exactly is the Python `gliner` 0.2.29
//! pipeline the golden spans in `fixtures/ml/gliner-golden/` were made with:
//!
//! 1. **Words.** The text is split with gliner's whitespace splitter,
//!    `\w+(?:[-_]\w+)*|\S`, with Python's meaning of `\w` (a letter, a number or `_`; a
//!    combining mark is *not* a word character, so it stands alone) and of `\s` (which
//!    also counts U+001C..U+001F). Word positions are kept as UTF-8 byte offsets into the
//!    exact text sent, which must already be NFC (docs/33 §3.2, review defect 19).
//! 2. **Prompt.** `<<ENT>> label₁ <<ENT>> label₂ … <<SEP>>` followed by the words, encoded
//!    by the model's `tokenizer.json` as pre-split words, with no truncation or padding.
//!    `words_mask` marks the first sub-token of each text word with its 1-based number
//!    (counting words the tokenizer actually emitted tokens for, as gliner does).
//! 3. **Spans.** Every start word and width `0..max_width`; `span_mask` is false past the
//!    end. The graph returns logits `[1, words, max_width, labels]`; a span is a candidate
//!    when `sigmoid(logit) > threshold`.
//! 4. **Flat decoding.** Candidates in `(start, width, label)` order are sorted by score,
//!    highest first (a stable sort, so ties keep that order), and taken greedily when they
//!    share no word with a span already taken. The result is ordered by start.
//!
//! **Windows.** A text longer than one window is read in windows of at most the model's
//! `max_len` words and [`MAX_WINDOW_TOKENS`] tokens (prompt and special tokens included).
//! The label prompt may take at most [`MAX_PROMPT_TOKENS`] of them; a larger one is
//! refused, so the text always has half a window.
//! Each next window starts [`WINDOW_OVERLAP`] words (at most half the previous window)
//! before the previous one ended. A word whose tokens alone overflow a window is skipped
//! (no window reads it and no span covers it). At most [`MAX_WINDOWS`] windows are read;
//! later words are not (truncated). Candidates from all windows are pooled, a span seen
//! in two windows keeps its higher score, and step 4 runs once over the pool, so the
//! result depends only on the text, the labels and the threshold. A text that fits one
//! window is decoded exactly as gliner decodes it.
//!
//! Inference runs on the CPU, one intra-op thread, graph optimisation `ORT_ENABLE_ALL`
//! (the golden runs' settings). ONNX Runtime is cancelled at the caller's deadline through
//! its run-terminate flag. Nothing here logs: ONNX Runtime's own logger is replaced by
//! one that reports only the level and category of an error, never its message.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use ort::logging::LogLevel;
use ort::session::builder::GraphOptimizationLevel;
use ort::session::{RunOptions, Session};
use ort::value::Tensor;
use regex::Regex;
use tokenizers::{EncodeInput, Encoding, InputSequence, Tokenizer};

use crate::error::{BundleProblem, ModeldError};
use crate::manifest::Bundle;
use crate::wire::{MAX_LABELS, MAX_SPAN_TEXT, MAX_SPANS, SCORE_SCALE, Span, SpanRequest};

/// Words shared by consecutive windows (docs/33 §4: "stride 64").
pub const WINDOW_OVERLAP: usize = 64;
/// Most tokens in one window, prompt and special tokens included (docs/33 §4).
pub const MAX_WINDOW_TOKENS: usize = 2048;
/// Most windows read from one text; later words are not read (docs/33 §4).
pub const MAX_WINDOWS: usize = 2000;
/// Most tokens the label prompt (with the special tokens) may take of a window, so at
/// least half of every window is left for the text (`ML-17`). A prompt over it is
/// refused (`CS-ML-0005`) rather than leaving the text unread and answering no spans.
pub const MAX_PROMPT_TOKENS: usize = MAX_WINDOW_TOKENS / 2;
/// Largest `gliner_config.json` read.
const MAX_CONFIG: u64 = 64 * 1024;
/// Widest span a config may ask for.
const MAX_WIDTH: usize = 32;
/// Most words per window a config may ask for.
const MAX_LEN: usize = 4096;
/// The ONNX Runtime library's path in a bundle.
pub const RUNTIME_PATH: &str = "runtime/libonnxruntime.so";

/// The inputs an exported GLiNER span graph takes, in the order gliner exports them.
const INPUTS: [&str; 6] = [
    "input_ids",
    "attention_mask",
    "words_mask",
    "text_lengths",
    "span_idx",
    "span_mask",
];

fn refused(why: &'static str) -> ModeldError {
    ModeldError::Bundle(BundleProblem::Unreadable(why.into()))
}

/// gliner's `WhitespaceTokenSplitter`. `\p{L}\p{N}_` is Python's `\w` (letters, numbers,
/// underscore; combining marks excluded); the second branch is Python's `\S`, whose
/// whitespace also holds the information separators U+001C..U+001F.
const WORD_PATTERN: &str = r"[\p{L}\p{N}_]+(?:[-_][\p{L}\p{N}_]+)*|[^\s\x1C-\x1F]";

fn word_regex() -> Result<&'static Regex, ModeldError> {
    static WORDS: OnceLock<Option<Regex>> = OnceLock::new();
    WORDS
        .get_or_init(|| Regex::new(WORD_PATTERN).ok())
        .as_ref()
        .ok_or(ModeldError::Inference)
}

/// The words of `text` as UTF-8 byte ranges `(start, end)`, in order.
///
/// # Errors
/// `CS-ML-0013` if the splitter does not build (it is a constant; never in practice).
pub fn split_words(text: &str) -> Result<Vec<(usize, usize)>, ModeldError> {
    Ok(word_regex()?
        .find_iter(text)
        .map(|m| (m.start(), m.end()))
        .collect())
}

/// Load ONNX Runtime from `lib` once per process. Later calls return the first result.
///
/// # Errors
/// `CS-ML-0001` when the library does not load.
pub fn init_runtime(lib: &Path) -> Result<(), ModeldError> {
    static RUNTIME: OnceLock<bool> = OnceLock::new();
    let ok = *RUNTIME.get_or_init(|| match ort::init_from(lib) {
        Ok(env) => {
            // `commit` is false only when an environment already exists, which this
            // OnceLock rules out; either way the library is loaded.
            let _ = env
                .with_name("modeld")
                .with_telemetry(false)
                .with_logger(Arc::new(ort_log))
                .commit();
            true
        }
        Err(_) => false,
    });
    if ok {
        Ok(())
    } else {
        Err(ModeldError::Setting(
            "OPENSEAL_MODELD_BUNDLE (runtime library does not load)",
        ))
    }
}

/// The loaded ONNX Runtime, for INFO and every suggestion's provenance (docs/33 §5.5):
/// `onnxruntime-<release>` when its build string names a release branch, else
/// `onnxruntime-git-<commit>` (Microsoft's 1.28.3 binaries say `git-branch=HEAD,
/// git-commit-id=0d68ff6`). The library itself is pinned by SHA-256 in the bundle. Call
/// only after [`init_runtime`] succeeded.
pub(crate) fn runtime_version() -> String {
    let info = ort::info();
    let field = |key: &str| {
        info.split([',', ' '])
            .find_map(|f| f.strip_prefix(key))
            .filter(|v| {
                !v.is_empty()
                    && v.len() <= 40
                    && v.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.')
            })
    };
    if let Some(release) = field("git-branch=rel-") {
        format!("onnxruntime-{release}")
    } else if let Some(commit) = field("git-commit-id=") {
        format!("onnxruntime-git-{commit}")
    } else {
        "onnxruntime".to_owned()
    }
}

/// ONNX Runtime's logger: errors are reported by level and category only. Its messages
/// can name tensors and shapes of the request; they are never written (docs/33 §3.4).
fn ort_log(level: LogLevel, category: &str, _id: &str, _location: &str, _message: &str) {
    let level = match level {
        LogLevel::Error => "error",
        LogLevel::Fatal => "fatal",
        LogLevel::Verbose | LogLevel::Info | LogLevel::Warning => return,
    };
    // A category is a fixed ONNX Runtime name ("onnxruntime", "Session", ...), never data.
    let category: String = category
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .take(32)
        .collect();
    let mut m = serde_json::Map::new();
    m.insert("severity".into(), level.into());
    m.insert("category".into(), category.into());
    casual_sign_seclog::write(
        casual_sign_seclog::Service::Modeld,
        casual_sign_seclog::Level::Error,
        "onnxruntime",
        m,
    );
}

/// What `gliner_config.json` decides for decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Config {
    max_len: usize,
    max_width: usize,
    ent_token: String,
    sep_token: String,
}

impl Config {
    /// Parse a config, refusing one this decoder does not implement: a span mode other
    /// than `markerV0`, a splitter other than `whitespace`, pooling other than `first`.
    fn parse(text: &str) -> Result<Self, ModeldError> {
        let v: serde_json::Value =
            serde_json::from_str(text).map_err(|_| refused("gliner_config.json does not parse"))?;
        let field = |name: &str| v.get(name);
        let size = |name: &str, default: usize, max: usize| -> Result<usize, ModeldError> {
            match field(name) {
                None => Ok(default),
                Some(n) => n
                    .as_u64()
                    .and_then(|n| usize::try_from(n).ok())
                    .filter(|n| (1..=max).contains(n))
                    .ok_or_else(|| {
                        refused("gliner_config.json: max_len or max_width out of range")
                    }),
            }
        };
        let text_field = |name: &str, default: &str| -> Result<String, ModeldError> {
            match field(name) {
                None | Some(serde_json::Value::Null) => Ok(default.to_owned()),
                Some(serde_json::Value::String(s)) if !s.is_empty() && s.len() <= 64 => {
                    Ok(s.clone())
                }
                Some(_) => Err(refused(
                    "gliner_config.json: a token or mode is not a short string",
                )),
            }
        };
        if text_field("span_mode", "markerV0")? != "markerV0"
            || text_field("words_splitter_type", "whitespace")? != "whitespace"
            || text_field("subtoken_pooling", "first")? != "first"
        {
            return Err(refused(
                "gliner_config.json: span mode, splitter or pooling not supported",
            ));
        }
        Ok(Self {
            max_len: size("max_len", 384, MAX_LEN)?,
            max_width: size("max_width", 12, MAX_WIDTH)?,
            ent_token: text_field("ent_token", "<<ENT>>")?,
            sep_token: text_field("sep_token", "<<SEP>>")?,
        })
    }
}

/// One window's exact ONNX feeds, as gliner builds them. Public so the parity tests can
/// compare them with the reference's recorded feeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowFeeds {
    /// Index of the window's first word in the whole text.
    pub first_word: usize,
    /// Words in the window (`text_lengths`).
    pub words: usize,
    /// Token ids, prompt included.
    pub input_ids: Vec<i64>,
    /// 1-based word number on each word's first sub-token, else 0.
    pub words_mask: Vec<i64>,
}

/// The labels of a request, deduplicated as gliner does (first occurrence wins), with
/// each one's index in the request.
struct Labels {
    names: Vec<String>,
    index: Vec<u8>,
}

/// A loaded GLiNER model: graph, tokenizer and config.
pub struct Gliner {
    session: Mutex<Session>,
    tokenizer: Tokenizer,
    config: Config,
    /// Added-token texts a label may not contain: a label holding `<<SEP>>` or `[CLS]`
    /// would rewrite the prompt.
    reserved: Vec<String>,
}

impl core::fmt::Debug for Gliner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Gliner")
            .field("max_len", &self.config.max_len)
            .field("max_width", &self.config.max_width)
            .finish_non_exhaustive()
    }
}

fn i64_of(n: usize) -> Result<i64, ModeldError> {
    i64::try_from(n).map_err(|_| ModeldError::OverBound("count too large"))
}

fn sigmoid(x: f32) -> f32 {
    1.0 / (1.0 + (-x).exp())
}

impl Gliner {
    /// Load the model in `dir` (`model.onnx`, `tokenizer.json`, `gliner_config.json`) on
    /// the ONNX Runtime library `runtime`. The caller has verified every file's SHA-256
    /// (the bundle); this checks that they are a GLiNER span model this decoder supports.
    ///
    /// # Errors
    /// `CS-ML-0001` when the runtime does not load; `CS-ML-0002` when a file is missing,
    /// unreadable or not what this decoder supports; `CS-ML-0013` when ONNX Runtime
    /// refuses the graph.
    pub fn load(runtime: &Path, dir: &Path) -> Result<Self, ModeldError> {
        init_runtime(runtime)?;
        let config_path = dir.join("gliner_config.json");
        let meta = std::fs::metadata(&config_path).map_err(|_| {
            ModeldError::Bundle(BundleProblem::Missing("gliner_config.json".into()))
        })?;
        if meta.len() > MAX_CONFIG {
            return Err(refused("gliner_config.json too large"));
        }
        let config_text = std::fs::read_to_string(&config_path)
            .map_err(|_| refused("gliner_config.json unreadable"))?;
        let config = Config::parse(&config_text)?;

        let mut tokenizer = Tokenizer::from_file(dir.join("tokenizer.json"))
            .map_err(|_| refused("tokenizer.json does not load"))?;
        // gliner tokenizes with truncation to an effectively unbounded length and no
        // padding for one text; whatever tokenizer.json says is overridden the same way.
        tokenizer
            .with_truncation(None)
            .map_err(|_| refused("tokenizer.json truncation"))?;
        tokenizer.with_padding(None);
        for t in [&config.ent_token, &config.sep_token] {
            if tokenizer.token_to_id(t).is_none() {
                return Err(refused("tokenizer.json lacks the prompt tokens"));
            }
        }
        let mut reserved: Vec<String> = tokenizer
            .get_added_tokens_decoder()
            .into_values()
            .map(|t| t.content)
            .filter(|c| !c.is_empty())
            .collect();
        reserved.sort();
        reserved.dedup();

        let inf = |_| ModeldError::Inference;
        let session = Session::builder()
            .map_err(inf)?
            .with_optimization_level(GraphOptimizationLevel::All)
            .map_err(|_| ModeldError::Inference)?
            .with_intra_threads(1)
            .map_err(|_| ModeldError::Inference)?
            .with_inter_threads(1)
            .map_err(|_| ModeldError::Inference)?
            .with_parallel_execution(false)
            .map_err(|_| ModeldError::Inference)?
            .with_log_level(LogLevel::Error)
            .map_err(|_| ModeldError::Inference)?
            .commit_from_file(dir.join("model.onnx"))
            .map_err(|_| ModeldError::Inference)?;
        let names: Vec<&str> = session.inputs().iter().map(|i| i.name()).collect();
        if INPUTS.iter().any(|i| !names.contains(i))
            || !session.outputs().iter().any(|o| o.name() == "logits")
        {
            return Err(refused("model.onnx is not a GLiNER span graph"));
        }
        Ok(Self {
            session: Mutex::new(session),
            tokenizer,
            config,
            reserved,
        })
    }

    /// The model's `max_len` (words per window).
    #[must_use]
    pub fn max_len(&self) -> usize {
        self.config.max_len
    }

    fn labels(&self, labels: &[String]) -> Result<Labels, ModeldError> {
        if labels.is_empty() {
            return Err(ModeldError::Malformed("no labels"));
        }
        if labels.len() > MAX_LABELS {
            return Err(ModeldError::Malformed("too many labels"));
        }
        let mut names: Vec<String> = Vec::new();
        let mut index = Vec::new();
        for (i, l) in labels.iter().enumerate() {
            if l.trim().is_empty() || self.reserved.iter().any(|r| l.contains(r.as_str())) {
                return Err(ModeldError::Malformed(
                    "label empty or holding a reserved token",
                ));
            }
            if names.contains(l) {
                continue;
            }
            names.push(l.clone());
            index.push(u8::try_from(i).map_err(|_| ModeldError::Malformed("too many labels"))?);
        }
        Ok(Labels { names, index })
    }

    fn prompt<'a>(&'a self, labels: &'a Labels) -> Vec<&'a str> {
        let mut p = Vec::with_capacity(labels.names.len().saturating_mul(2).saturating_add(1));
        for l in &labels.names {
            p.push(self.config.ent_token.as_str());
            p.push(l.as_str());
        }
        p.push(self.config.sep_token.as_str());
        p
    }

    fn encode(&self, words: Vec<&str>) -> Result<Encoding, ModeldError> {
        let input = EncodeInput::Single(InputSequence::PreTokenized(Cow::Owned(words)));
        self.tokenizer
            .encode(input, true)
            .map_err(|_| ModeldError::Inference)
    }

    /// The windows of `text` for `labels` and their exact feeds, as gliner builds them
    /// for a text that fits one window.
    ///
    /// # Errors
    /// `CS-ML-0004` for a text not in NFC or a bad label; `CS-ML-0005` for a text over
    /// [`MAX_SPAN_TEXT`] or labels whose prompt is over [`MAX_PROMPT_TOKENS`];
    /// `CS-ML-0013` when the tokenizer fails.
    pub fn feeds(&self, text: &str, labels: &[String]) -> Result<Vec<WindowFeeds>, ModeldError> {
        let labels = self.labels(labels)?;
        let words = self.checked_words(text)?;
        self.window_feeds(text, &words, &labels)
    }

    fn checked_words(&self, text: &str) -> Result<Vec<(usize, usize)>, ModeldError> {
        if text.len() > MAX_SPAN_TEXT {
            return Err(ModeldError::OverBound("span text"));
        }
        if !unicode_normalization::is_nfc(text) {
            return Err(ModeldError::Malformed("span text is not NFC"));
        }
        split_words(text)
    }

    fn window_feeds(
        &self,
        text: &str,
        words: &[(usize, usize)],
        labels: &Labels,
    ) -> Result<Vec<WindowFeeds>, ModeldError> {
        if words.is_empty() {
            return Ok(Vec::new());
        }
        let word_text = |&(s, e): &(usize, usize)| text.get(s..e).unwrap_or_default();
        let prompt = self.prompt(labels);
        let prompt_len = prompt.len();

        // Tokens per word, from one encoding of the prompt and every word: a pre-split
        // word is tokenized on its own, so its count is the same in every window.
        let mut all = prompt.clone();
        all.extend(words.iter().map(word_text));
        let whole = self.encode(all)?;
        let total = prompt_len.saturating_add(words.len());
        let mut counts = vec![0usize; total];
        let mut specials = 0usize;
        for w in whole.get_word_ids() {
            match w.and_then(|w| usize::try_from(w).ok()) {
                Some(w) => {
                    if let Some(c) = counts.get_mut(w) {
                        *c = c.saturating_add(1);
                    }
                }
                None => specials = specials.saturating_add(1),
            }
        }
        let fixed = counts
            .get(..prompt_len)
            .unwrap_or_default()
            .iter()
            .fold(specials, |a, c| a.saturating_add(*c));
        if fixed > MAX_PROMPT_TOKENS {
            return Err(ModeldError::OverBound("label prompt tokens"));
        }
        let budget = MAX_WINDOW_TOKENS.saturating_sub(fixed);
        let word_counts = counts.get(prompt_len..).unwrap_or_default();

        let mut out = Vec::new();
        for (first, end) in plan_windows(word_counts, budget, self.config.max_len) {
            let mut seq = prompt.clone();
            seq.extend(
                words
                    .get(first..end)
                    .unwrap_or_default()
                    .iter()
                    .map(word_text),
            );
            let enc = self.encode(seq)?;
            if enc.get_ids().len() > MAX_WINDOW_TOKENS {
                return Err(ModeldError::Inference);
            }
            out.push(WindowFeeds {
                first_word: first,
                words: end.saturating_sub(first),
                input_ids: enc.get_ids().iter().map(|&i| i64::from(i)).collect(),
                words_mask: words_mask(enc.get_word_ids(), prompt_len),
            });
        }
        Ok(out)
    }

    /// Spans of `request`: UTF-8 byte offsets into its text, each with the index of its
    /// label in the request and its score in ten-thousandths, ordered by start.
    ///
    /// # Errors
    /// As [`Gliner::feeds`]; `CS-ML-0007` when `deadline` passes; `CS-ML-0013` when
    /// inference fails or the graph answers in a shape it should not.
    pub fn spans(
        &self,
        request: &SpanRequest,
        deadline: Instant,
    ) -> Result<Vec<Span>, ModeldError> {
        if request.threshold > SCORE_SCALE {
            return Err(ModeldError::Malformed("threshold over 10000"));
        }
        let labels = self.labels(&request.labels)?;
        let text = request.text.as_str();
        let words = self.checked_words(text)?;
        let windows = self.window_feeds(text, &words, &labels)?;
        let threshold = f32::from(request.threshold) / f32::from(SCORE_SCALE);
        let classes = labels.names.len();
        let width = self.config.max_width;

        // (start word, width, label) → best score.
        let mut pool: BTreeMap<(usize, usize, usize), f32> = BTreeMap::new();
        for w in &windows {
            let logits = self.run(w, width, classes, deadline)?;
            let mut at = 0usize;
            for s in 0..w.words {
                for k in 0..width {
                    for c in 0..classes {
                        let logit = logits.get(at).copied().ok_or(ModeldError::Inference)?;
                        at = at.saturating_add(1);
                        // gliner: a span must end inside the text.
                        if s.saturating_add(k) >= w.words {
                            continue;
                        }
                        let p = sigmoid(logit);
                        if p > threshold {
                            let key = (w.first_word.saturating_add(s), k, c);
                            let best = pool.entry(key).or_insert(p);
                            if p > *best {
                                *best = p;
                            }
                        }
                    }
                }
            }
        }

        let mut candidates: Vec<((usize, usize, usize), f32)> = pool.into_iter().collect();
        // Stable: equal scores keep (start, width, label) order, as Python's `sorted`.
        candidates.sort_by(|a, b| b.1.total_cmp(&a.1));
        let mut taken = vec![false; words.len()];
        let mut chosen: Vec<(usize, usize, usize, f32)> = Vec::new();
        for ((start, k, c), p) in candidates {
            let end = start.saturating_add(k);
            let Some(slots) = taken.get_mut(start..=end) else {
                continue;
            };
            if slots.iter().any(|t| *t) {
                continue;
            }
            slots.iter_mut().for_each(|t| *t = true);
            chosen.push((start, end, c, p));
        }
        chosen.sort_by_key(|s| s.0);
        chosen.truncate(MAX_SPANS);

        chosen
            .into_iter()
            .map(|(start, end, c, p)| {
                let (b0, _) = words.get(start).copied().ok_or(ModeldError::Inference)?;
                let (_, b1) = words.get(end).copied().ok_or(ModeldError::Inference)?;
                if !text.is_char_boundary(b0) || !text.is_char_boundary(b1) {
                    return Err(ModeldError::Inference);
                }
                let scaled = (p * f32::from(SCORE_SCALE)).round();
                Ok(Span {
                    start: u32::try_from(b0).map_err(|_| ModeldError::Inference)?,
                    end: u32::try_from(b1).map_err(|_| ModeldError::Inference)?,
                    label: labels.index.get(c).copied().ok_or(ModeldError::Inference)?,
                    // In (0, 1] by construction; the cast saturates.
                    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                    score: (scaled as u16).min(SCORE_SCALE),
                })
            })
            .collect()
    }

    /// Run one window; the logits, flattened `[words, max_width, labels]`.
    fn run(
        &self,
        w: &WindowFeeds,
        width: usize,
        classes: usize,
        deadline: Instant,
    ) -> Result<Vec<f32>, ModeldError> {
        let tokens = w.input_ids.len();
        let spans = w.words.checked_mul(width).ok_or(ModeldError::Inference)?;
        let mut span_idx = Vec::with_capacity(spans.saturating_mul(2));
        let mut span_mask = Vec::with_capacity(spans);
        for s in 0..w.words {
            for k in 0..width {
                let e = s.saturating_add(k);
                span_idx.push(i64_of(s)?);
                span_idx.push(i64_of(e)?);
                span_mask.push(e < w.words);
            }
        }
        let inf = |_| ModeldError::Inference;
        let inputs = ort::inputs! {
            "input_ids" => Tensor::from_array(([1usize, tokens], w.input_ids.clone())).map_err(inf)?,
            "attention_mask" => Tensor::from_array(([1usize, tokens], vec![1i64; tokens])).map_err(inf)?,
            "words_mask" => Tensor::from_array(([1usize, tokens], w.words_mask.clone())).map_err(inf)?,
            "text_lengths" => Tensor::from_array(([1usize, 1], vec![i64_of(w.words)?])).map_err(inf)?,
            "span_idx" => Tensor::from_array(([1usize, spans, 2], span_idx)).map_err(inf)?,
            "span_mask" => Tensor::from_array(([1usize, spans], span_mask)).map_err(inf)?,
        };
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ModeldError::Deadline);
        }
        let options = RunOptions::new().map_err(inf)?;
        let mut session = self.session.lock().map_err(|_| ModeldError::Inference)?;
        let (stop, stopped) = mpsc::channel::<()>();
        let result = std::thread::scope(|scope| {
            // The watchdog: at the deadline, ONNX Runtime's terminate flag ends the run.
            let watched = &options;
            scope.spawn(move || {
                if let Err(RecvTimeoutError::Timeout) = stopped.recv_timeout(remaining) {
                    let _ = watched.terminate();
                }
            });
            let outcome = session
                .run_with_options(inputs, &options)
                .map_err(|_| ModeldError::Inference)
                .and_then(|out| {
                    let value = out.get("logits").ok_or(ModeldError::Inference)?;
                    let (shape, data) = value
                        .try_extract_tensor::<f32>()
                        .map_err(|_| ModeldError::Inference)?;
                    let want = [1, i64_of(w.words)?, i64_of(width)?, i64_of(classes)?];
                    if **shape != want {
                        return Err(ModeldError::Inference);
                    }
                    Ok(data.to_vec())
                });
            drop(stop);
            outcome
        });
        match result {
            Err(_) if Instant::now() >= deadline => Err(ModeldError::Deadline),
            r => r,
        }
    }
}

/// gliner's `prepare_word_mask` with `first` pooling: each word's first sub-token gets
/// the word's 1-based number among the words that produced tokens; prompt words, special
/// tokens and later sub-tokens get 0.
fn words_mask(word_ids: &[Option<u32>], prompt_len: usize) -> Vec<i64> {
    let mut mask = Vec::with_capacity(word_ids.len());
    let mut prev: Option<u32> = None;
    let mut seen = 0usize;
    for wid in word_ids {
        match wid {
            None => mask.push(0),
            Some(w) => {
                let first = Some(*w) != prev;
                if first {
                    seen = seen.saturating_add(1);
                }
                if seen <= prompt_len || !first {
                    mask.push(0);
                } else {
                    mask.push(i64::try_from(seen.saturating_sub(prompt_len)).unwrap_or(i64::MAX));
                }
            }
        }
        prev = *wid;
    }
    mask
}

/// Windows `[first, end)` over words with `counts` tokens each, at most `max_words`
/// words and `budget` tokens each (see the module docs).
fn plan_windows(counts: &[usize], budget: usize, max_words: usize) -> Vec<(usize, usize)> {
    let n = counts.len();
    let mut out = Vec::new();
    let mut start = 0usize;
    while start < n && out.len() < MAX_WINDOWS {
        if counts.get(start).is_none_or(|c| *c > budget) {
            start = start.saturating_add(1);
            continue;
        }
        let mut end = start;
        let mut tokens = 0usize;
        while end < n && end.saturating_sub(start) < max_words {
            let c = counts.get(end).copied().unwrap_or(usize::MAX);
            if tokens.saturating_add(c) > budget {
                break;
            }
            tokens = tokens.saturating_add(c);
            end = end.saturating_add(1);
        }
        out.push((start, end));
        if end >= n {
            break;
        }
        if counts.get(end).is_some_and(|c| *c > budget) {
            // The next word is skipped; no span can cross it, so no overlap is needed.
            start = end;
        } else {
            let len = end.saturating_sub(start);
            start = end.saturating_sub(WINDOW_OVERLAP.min(len / 2));
        }
    }
    out
}

/// The span models of a bundle: the entity model (GLiNER multi, else GLiNER small) and
/// the personal-data model (GLiNER-PII), each loaded when its profile is installed.
#[derive(Debug, Default)]
pub struct SpanModels {
    pub(crate) entities: Option<Gliner>,
    pub(crate) personal: Option<Gliner>,
}

/// Bundle ids of the span models, by preference. Each has `<id>-tokenizer` and
/// `<id>-config` beside it in the manifest (`tools/ml/models.toml`).
const ENTITY_MODELS: [&str; 2] = ["gliner-multi", "gliner-small"];
const PERSONAL_MODELS: [&str; 1] = ["gliner-pii-base"];

impl SpanModels {
    /// Load the span models `bundle` holds. None installed is not an error: ENTITIES and
    /// PERSONAL then answer `CS-ML-0010`.
    ///
    /// # Errors
    /// `CS-ML-0002` when a model is installed without its tokenizer, config or the ONNX
    /// Runtime library; otherwise as [`Gliner::load`].
    pub fn load(bundle: &Bundle) -> Result<Self, ModeldError> {
        Ok(Self {
            entities: load_first(bundle, &ENTITY_MODELS)?,
            personal: load_first(bundle, &PERSONAL_MODELS)?,
        })
    }

    /// Whether an entity model is loaded.
    #[must_use]
    pub fn has_entities(&self) -> bool {
        self.entities.is_some()
    }

    /// Whether a personal-data model is loaded.
    #[must_use]
    pub fn has_personal(&self) -> bool {
        self.personal.is_some()
    }
}

fn load_first(bundle: &Bundle, ids: &[&str]) -> Result<Option<Gliner>, ModeldError> {
    let Some(model) = ids.iter().find_map(|id| bundle.model(id)) else {
        return Ok(None);
    };
    let dir = model
        .path
        .rsplit_once('/')
        .map(|(d, _)| d)
        .ok_or_else(|| refused("span model not in its own directory"))?;
    for (suffix, file) in [
        ("", "model.onnx"),
        ("-tokenizer", "tokenizer.json"),
        ("-config", "gliner_config.json"),
    ] {
        let path = format!("{dir}/{file}");
        let id = format!("{}{suffix}", model.id);
        if bundle.model(&id).is_none_or(|e| e.path != path) {
            return Err(ModeldError::Bundle(BundleProblem::Missing(path)));
        }
    }
    if !bundle.installed.iter().any(|e| e.path == RUNTIME_PATH) {
        return Err(ModeldError::Bundle(BundleProblem::Missing(
            RUNTIME_PATH.into(),
        )));
    }
    let root: PathBuf = bundle.dir.clone();
    Gliner::load(&root.join(RUNTIME_PATH), &root.join(dir)).map(Some)
}

#[cfg(test)]
mod tests {
    // Test code: a panic is the failure report.
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    fn words(text: &str) -> Vec<&str> {
        split_words(text)
            .unwrap()
            .into_iter()
            .map(|(s, e)| &text[s..e])
            .collect()
    }

    /// Python's `\w+(?:[-_]\w+)*|\S`: hyphenated words hold together, punctuation stands
    /// alone, a trailing hyphen is its own word.
    #[test]
    fn the_splitter_matches_gliners_word_rule() {
        assert_eq!(
            words("Non-Disclosure (the \"Agreement\") ends 31-12-2026, x_y- z."),
            [
                "Non-Disclosure",
                "(",
                "the",
                "\"",
                "Agreement",
                "\"",
                ")",
                "ends",
                "31-12-2026",
                ",",
                "x_y",
                "-",
                "z",
                "."
            ]
        );
    }

    /// A combining mark is not a word character in Python, so Devanagari vowel signs
    /// split a word; U+001C..U+001F are whitespace to Python and never a word.
    #[test]
    fn combining_marks_and_information_separators_follow_python() {
        assert_eq!(words("हिंदी"), ["ह", "ि", "ं", "द", "ी"]);
        assert_eq!(words("a\u{1c}b\u{1f}c"), ["a", "b", "c"]);
        assert_eq!(words("café №5 ²"), ["café", "№", "5", "²"]);
    }

    /// Offsets are UTF-8 byte offsets into the text as sent.
    #[test]
    fn word_offsets_are_utf8_bytes() {
        let text = "Ünïcode — ok";
        let w = split_words(text).unwrap();
        assert_eq!(w, [(0, 9), (10, 13), (14, 16)]);
    }

    #[test]
    fn the_word_mask_marks_each_first_sub_token_after_the_prompt() {
        // [CLS] ENT label SEP | w0 w0 w1 | [SEP]; prompt is 3 words.
        let ids = [
            None,
            Some(0),
            Some(1),
            Some(2),
            Some(3),
            Some(3),
            Some(4),
            None,
        ];
        assert_eq!(words_mask(&ids, 3), [0, 0, 0, 0, 1, 0, 2, 0]);
        // A word with no tokens (id 4 missing) is not counted, as gliner's seen_words.
        let ids = [None, Some(0), Some(1), Some(3), Some(5), None];
        assert_eq!(words_mask(&ids, 1), [0, 0, 1, 2, 3, 0]);
    }

    /// Windows are deterministic, overlap by 64 words (at most half a window), respect
    /// both caps, skip a word too long for any window, and stop at MAX_WINDOWS.
    #[test]
    fn windows_overlap_by_a_fixed_stride_and_respect_both_caps() {
        let counts = vec![1usize; 1000];
        let w = plan_windows(&counts, 10_000, 384);
        assert_eq!(w, [(0, 384), (320, 704), (640, 1000)]);
        assert_eq!(plan_windows(&counts, 10_000, 384), w);
        let w = plan_windows(&counts, 100, 384);
        assert!(w.iter().all(|(s, e)| e - s <= 100));
        assert_eq!(w[0], (0, 100));
        assert_eq!(w[1], (50, 150));
        assert_eq!(w.last().unwrap().1, 1000);
        let mut long = vec![1usize; 10];
        long[4] = 500;
        assert_eq!(plan_windows(&long, 100, 384), [(0, 4), (5, 10)]);
        assert!(plan_windows(&[], 100, 384).is_empty());
        let many = vec![1usize; 10_000];
        assert_eq!(plan_windows(&many, 2, 384).len(), MAX_WINDOWS);
        // Every word of an ordinary text is read by some window.
        let w = plan_windows(&counts, 10_000, 100);
        for i in 0..1000 {
            assert!(w.iter().any(|(s, e)| (*s..*e).contains(&i)), "{i}");
        }
    }

    #[test]
    fn configs_this_decoder_cannot_follow_are_refused() {
        let c =
            Config::parse(r#"{"max_len": 384, "max_width": 12, "span_mode": "markerV0"}"#).unwrap();
        assert_eq!(c.ent_token, "<<ENT>>");
        assert_eq!(c.sep_token, "<<SEP>>");
        for bad in [
            r#"{"span_mode": "token_level"}"#,
            r#"{"words_splitter_type": "spacy"}"#,
            r#"{"subtoken_pooling": "mean"}"#,
            r#"{"max_width": 0}"#,
            r#"{"max_len": 100000}"#,
            r#"{"ent_token": 5}"#,
            "not json",
        ] {
            assert_eq!(
                Config::parse(bad).unwrap_err().code(),
                "CS-ML-0002",
                "{bad}"
            );
        }
    }
}
