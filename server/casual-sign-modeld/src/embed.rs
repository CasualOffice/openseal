//! Sentence embeddings (piece I; `ML-05` template matching, and `ML-07` search):
//! intfloat/multilingual-e5-small through `tokenizers` (`default-features = false`) and
//! ONNX Runtime, mean-pooled over the tokens and L2-normalised: the sentence-transformers
//! pipeline the checkpoint declares (docs/33 §5.2).
//!
//! - **Prefix.** e5 is trained with `query: ` and `passage: `; modeld adds the one the
//!   request's [`EmbedKind`] names, so the worker sends plain text.
//! - **Truncation.** 512 tokens, `<s>` and `</s>` included (the model's window); a longer
//!   text is cut deterministically at the end. No padding: each text runs alone, so a
//!   vector never depends on the other texts in the call.
//! - **Which file.** The fp16 export (`e5-small-fp16`) when the bundle holds it, else the
//!   fp32 file (`e5-small`). Owner instruction 34 allows fp16 only where it equals the
//!   reference; it does on the golden texts (lowest cosine 0.9999999 against the fp32
//!   PyTorch reference, fixtures/ml/e5-golden), and the same test runs on whichever file
//!   is installed. Until the fp16 file is hosted (`ML-15`) bundles carry fp32.
//! - **Equality with the reference** is tested on 24 synthetic texts in 15 languages:
//!   token ids exactly equal, cosine within 1e-3 (fixtures/ml/e5-golden, written by
//!   tools/ml/export-e5.py).
//!
//! Texts and vectors are never logged; errors carry no runtime text.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ort::session::{Session, SessionInputValue};
use ort::value::Tensor;
use tokenizers::{Tokenizer, TruncationParams};

use crate::error::ModeldError;
use crate::manifest::Bundle;
use crate::runtime;
use crate::wire::{EmbedKind, MAX_EMBED_TEXT, MAX_EMBED_TEXTS, Op, Request};

/// The embedding width of multilingual-e5-small.
pub(crate) const DIM: usize = 384;
/// The model's window, in tokens, `<s>` and `</s>` included.
pub(crate) const MAX_TOKENS: usize = 512;
/// Manifest id of the fp16 export, preferred when installed.
pub(crate) const MODEL_FP16: &str = "e5-small-fp16";
/// Manifest id of the fp32 model.
pub(crate) const MODEL_FP32: &str = "e5-small";
/// Manifest id of the tokenizer.
pub(crate) const TOKENIZER: &str = "e5-small-tokenizer";

/// A loaded model: tokenizer and session. Built once per process and model file.
pub(crate) struct Embedder {
    tokenizer: Tokenizer,
    session: Mutex<Session>,
    token_types: bool,
}

impl core::fmt::Debug for Embedder {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Embedder")
            .field("token_types", &self.token_types)
            .finish_non_exhaustive()
    }
}

/// The loaded embedder and the model file it was loaded from (its SHA-256).
static LOADED: Mutex<Option<([u8; 32], Arc<Embedder>)>> = Mutex::new(None);

/// Embed the texts of `request` (an EMBED request), one vector of [`DIM`] per text, in
/// order.
///
/// # Errors
/// `CS-ML-0010` if the bundle holds no e5 model, tokenizer or runtime; `CS-ML-0004` for a
/// request that is not EMBED or is over the wire bounds; `CS-ML-0007` once the deadline
/// passes between texts; `CS-ML-0013` if the runtime fails or returns a malformed output.
pub(crate) fn run(bundle: &Bundle, request: &Request) -> Result<Vec<Vec<f32>>, ModeldError> {
    let started = Instant::now();
    let Op::Embed { kind, texts } = &request.op else {
        return Err(ModeldError::Malformed("not an EMBED request"));
    };
    let embedder = load(bundle)?;
    let deadline = Duration::from_millis(u64::from(request.deadline_ms));
    embedder.embed_all(*kind, texts, || started.elapsed() > deadline)
}

fn load(bundle: &Bundle) -> Result<Arc<Embedder>, ModeldError> {
    let model = bundle
        .model(MODEL_FP16)
        .or_else(|| bundle.model(MODEL_FP32))
        .ok_or(ModeldError::NotInstalled)?;
    let tokenizer = bundle.model(TOKENIZER).ok_or(ModeldError::NotInstalled)?;
    runtime::ensure(bundle)?;
    let mut slot = LOADED.lock().map_err(|_| ModeldError::Inference)?;
    if let Some((sha, e)) = slot.as_ref()
        && *sha == model.sha256
    {
        return Ok(Arc::clone(e));
    }
    let e = Arc::new(Embedder::load(
        &bundle.dir.join(&model.path),
        &bundle.dir.join(&tokenizer.path),
    )?);
    *slot = Some((model.sha256, Arc::clone(&e)));
    Ok(e)
}

impl Embedder {
    /// Load `model` (ONNX) and `tokenizer` (tokenizer.json). The runtime must be loaded.
    ///
    /// # Errors
    /// `CS-ML-0013` if either does not load.
    pub(crate) fn load(model: &Path, tokenizer: &Path) -> Result<Self, ModeldError> {
        let mut tokenizer = Tokenizer::from_file(tokenizer).map_err(|_| ModeldError::Inference)?;
        tokenizer
            .with_truncation(Some(TruncationParams {
                max_length: MAX_TOKENS,
                ..TruncationParams::default()
            }))
            .map_err(|_| ModeldError::Inference)?;
        tokenizer.with_padding(None);
        let session = runtime::session(model)?;
        let names: Vec<&str> = session.inputs().iter().map(|i| i.name()).collect();
        if !names.contains(&"input_ids") || !names.contains(&"attention_mask") {
            return Err(ModeldError::Inference);
        }
        let token_types = names.contains(&"token_type_ids");
        Ok(Self {
            tokenizer,
            session: Mutex::new(session),
            token_types,
        })
    }

    /// The token ids e5 sees for `text` (prefix added, truncated, `<s>` and `</s>`).
    ///
    /// # Errors
    /// `CS-ML-0013` if the tokenizer fails.
    pub(crate) fn token_ids(&self, kind: EmbedKind, text: &str) -> Result<Vec<i64>, ModeldError> {
        let prefix = match kind {
            EmbedKind::Query => "query: ",
            EmbedKind::Passage => "passage: ",
        };
        let enc = self
            .tokenizer
            .encode(format!("{prefix}{text}"), true)
            .map_err(|_| ModeldError::Inference)?;
        Ok(enc.get_ids().iter().map(|&i| i64::from(i)).collect())
    }

    /// Embed every text, checking `expired` before each.
    pub(crate) fn embed_all(
        &self,
        kind: EmbedKind,
        texts: &[String],
        expired: impl Fn() -> bool,
    ) -> Result<Vec<Vec<f32>>, ModeldError> {
        if texts.len() > MAX_EMBED_TEXTS || texts.iter().any(|t| t.len() > MAX_EMBED_TEXT) {
            return Err(ModeldError::Malformed("embed bounds"));
        }
        let mut out = Vec::with_capacity(texts.len());
        for t in texts {
            if expired() {
                return Err(ModeldError::Deadline);
            }
            out.push(self.embed(kind, t)?);
        }
        Ok(out)
    }

    /// One text's vector: mean of the last hidden states, L2-normalised.
    ///
    /// # Errors
    /// `CS-ML-0013` if the runtime fails or its output is not `[1, tokens, 384]` of
    /// finite values.
    pub(crate) fn embed(&self, kind: EmbedKind, text: &str) -> Result<Vec<f32>, ModeldError> {
        let ids = self.token_ids(kind, text)?;
        let n = ids.len();
        if n == 0 || n > MAX_TOKENS {
            return Err(ModeldError::Inference);
        }
        let fail = |_| ModeldError::Inference;
        let tensor = |v: Vec<i64>| -> Result<SessionInputValue<'static>, ModeldError> {
            Ok(Tensor::from_array(([1usize, n], v)).map_err(fail)?.into())
        };
        let mut inputs: Vec<(&str, SessionInputValue<'static>)> = vec![
            ("input_ids", tensor(ids)?),
            ("attention_mask", tensor(vec![1; n])?),
        ];
        if self.token_types {
            inputs.push(("token_type_ids", tensor(vec![0; n])?));
        }
        let mut session = self.session.lock().map_err(|_| ModeldError::Inference)?;
        let outputs = session.run(inputs).map_err(fail)?;
        let (shape, hidden) = outputs
            .get("last_hidden_state")
            .ok_or(ModeldError::Inference)?
            .try_extract_tensor::<f32>()
            .map_err(fail)?;
        let want = [
            1,
            i64::try_from(n).map_err(|_| ModeldError::Inference)?,
            384,
        ];
        if shape.as_ref() != want.as_slice() || hidden.len() != n.saturating_mul(DIM) {
            return Err(ModeldError::Inference);
        }
        mean_normalised(hidden, n)
    }
}

/// The mean of `tokens` rows of [`DIM`] floats, divided by its L2 norm.
fn mean_normalised(hidden: &[f32], tokens: usize) -> Result<Vec<f32>, ModeldError> {
    let mut sum = vec![0.0f64; DIM];
    for row in hidden.chunks_exact(DIM) {
        for (s, &x) in sum.iter_mut().zip(row) {
            *s += f64::from(x);
        }
    }
    #[allow(clippy::cast_precision_loss)] // tokens <= 512
    let n = tokens as f64;
    let mean: Vec<f64> = sum.iter().map(|s| s / n).collect();
    let norm = mean.iter().map(|x| x * x).sum::<f64>().sqrt();
    if !norm.is_finite() || norm <= 0.0 {
        return Err(ModeldError::Inference);
    }
    #[allow(clippy::cast_possible_truncation)] // a unit vector's components fit f32
    Ok(mean.iter().map(|x| (x / norm) as f32).collect())
}

#[cfg(test)]
mod tests {
    // Test code: a panic is the failure report.
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::cast_possible_truncation,
        clippy::arithmetic_side_effects
    )]
    use super::*;
    use crate::manifest::Manifest;
    use std::path::PathBuf;

    const BUNDLE_ENV: &str = "OPENSEAL_MODELD_TEST_BUNDLE";
    const TOLERANCE: f64 = 1e-3;

    fn golden() -> serde_json::Value {
        let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/ml/e5-golden/e5-small.json");
        serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap()
    }

    fn texts() -> std::collections::HashMap<String, String> {
        let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../fixtures/ml/e5-golden/texts.json");
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
        v.as_array()
            .unwrap()
            .iter()
            .map(|t| {
                (
                    t["id"].as_str().unwrap().to_owned(),
                    t["text"].as_str().unwrap().to_owned(),
                )
            })
            .collect()
    }

    /// The bundle directory to test with, or `None` (and a message) when unset.
    fn bundle_dir() -> Option<PathBuf> {
        let dir = std::env::var_os(BUNDLE_ENV).map(PathBuf::from);
        if dir.is_none() {
            eprintln!(
                "SKIPPED: {BUNDLE_ENV} is not set. Fetch a bundle with \
                 `python3 -I tools/ml/fetch-models.py --profile templates --dest DIR` and set it to DIR."
            );
        }
        dir
    }

    fn sha_hex(path: &Path) -> (String, u64) {
        let data = std::fs::read(path).unwrap();
        let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &data);
        let hex: String = d.as_ref().iter().map(|b| format!("{b:02x}")).collect();
        (hex, data.len() as u64)
    }

    /// A manifest for whatever the test bundle holds, so [`Bundle::verify`] accepts it:
    /// the known files under their manifest ids, anything else (bundle.json, notices)
    /// under `extra-N`.
    fn manifest_for(dir: &Path) -> Manifest {
        let known = [
            (runtime::RUNTIME_PATH, "onnxruntime-x86_64"),
            ("templates/e5-small/model.onnx", MODEL_FP32),
            ("templates/e5-small/model.fp16.onnx", MODEL_FP16),
            ("templates/e5-small/tokenizer.json", TOKENIZER),
        ];
        let mut lines = String::new();
        let mut stack = vec![PathBuf::new()];
        let mut n = 0;
        while let Some(rel) = stack.pop() {
            for item in std::fs::read_dir(dir.join(&rel)).unwrap() {
                let item = item.unwrap();
                let r = rel.join(item.file_name());
                if item.file_type().unwrap().is_dir() {
                    stack.push(r);
                    continue;
                }
                let path = r.to_string_lossy().into_owned();
                let id = known.iter().find(|(p, _)| *p == path).map_or_else(
                    || {
                        n += 1;
                        format!("extra-{n}")
                    },
                    |(_, id)| (*id).to_owned(),
                );
                let (sha, bytes) = sha_hex(&dir.join(&r));
                lines.push_str(&format!("{id}\ttemplates\t{sha}\t{bytes}\tMIT\t{path}\n"));
            }
        }
        Manifest::parse(&lines).unwrap()
    }

    fn cosine(a: &[f32], b: &[f64]) -> f64 {
        let dot: f64 = a.iter().zip(b).map(|(x, y)| f64::from(*x) * y).sum();
        let na = a.iter().map(|x| f64::from(*x).powi(2)).sum::<f64>().sqrt();
        let nb = b.iter().map(|y| y * y).sum::<f64>().sqrt();
        dot / (na * nb)
    }

    /// Compare one model file against the golden reference: token ids exactly, vectors
    /// within 1e-3 cosine. Returns the lowest cosine.
    fn check_against_golden(e: &Embedder, label: &str) -> f64 {
        let g = golden();
        let texts = texts();
        let mut lowest = 1.0f64;
        for rec in g["texts"].as_array().unwrap() {
            let id = rec["id"].as_str().unwrap();
            let kind = match rec["kind"].as_str().unwrap() {
                "query" => EmbedKind::Query,
                _ => EmbedKind::Passage,
            };
            let want_ids: Vec<i64> = rec["input_ids"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_i64().unwrap())
                .collect();
            assert_eq!(
                e.token_ids(kind, &texts[id]).unwrap(),
                want_ids,
                "{label} {id}: token ids"
            );
            let want: Vec<f64> = rec["vector"]
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v.as_f64().unwrap())
                .collect();
            let got = e.embed(kind, &texts[id]).unwrap();
            assert_eq!(got.len(), DIM);
            let c = cosine(&got, &want);
            assert!(1.0 - c <= TOLERANCE, "{label} {id}: cosine {c}");
            lowest = lowest.min(c);
        }
        println!(
            "{label}: {} texts, lowest cosine {lowest:.7}",
            g["texts"].as_array().unwrap().len()
        );
        lowest
    }

    #[test]
    fn mean_pooling_normalises_and_refuses_a_zero_vector() {
        let mut hidden = vec![0.0f32; DIM * 2];
        hidden[0] = 3.0;
        hidden[DIM] = 1.0;
        hidden[1] = 4.0;
        hidden[DIM + 1] = 4.0;
        let v = mean_normalised(&hidden, 2).unwrap();
        // mean (2, 4) normalised = (0.4472, 0.8944)
        assert!((v[0] - 0.447_213_6).abs() < 1e-6 && (v[1] - 0.894_427_2).abs() < 1e-6);
        assert_eq!(
            mean_normalised(&vec![0.0; DIM], 1).unwrap_err(),
            ModeldError::Inference
        );
        let mut nan = vec![0.0f32; DIM];
        nan[0] = f32::NAN;
        assert_eq!(
            mean_normalised(&nan, 1).unwrap_err(),
            ModeldError::Inference
        );
    }

    #[test]
    fn a_bundle_without_e5_answers_not_installed() {
        let dir = std::env::temp_dir().join(format!("modeld-embed-empty-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bundle = Bundle::verify(&dir, &Manifest::parse("").unwrap(), &[]).unwrap();
        let req = Request {
            deadline_ms: 1000,
            account: "acc".into(),
            job: "job".into(),
            op: Op::Embed {
                kind: EmbedKind::Passage,
                texts: vec!["x".into()],
            },
        };
        assert_eq!(run(&bundle, &req).unwrap_err(), ModeldError::NotInstalled);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The acceptance test: every model file in the test bundle equals the Python
    /// reference within 1e-3 cosine, with identical token ids; and `run` (the EMBED op,
    /// through the verified bundle) gives the same vectors as the model it prefers.
    #[test]
    fn embeddings_equal_the_python_reference() {
        let Some(dir) = bundle_dir() else { return };
        let bundle = Bundle::verify(&dir, &manifest_for(&dir), &[]).unwrap();
        runtime::ensure(&bundle).unwrap();
        let tok = dir.join("templates/e5-small/tokenizer.json");
        let mut tried = 0;
        for (id, file) in [(MODEL_FP32, "model.onnx"), (MODEL_FP16, "model.fp16.onnx")] {
            let path = dir.join("templates/e5-small").join(file);
            if path.is_file() {
                let e = Embedder::load(&path, &tok).unwrap();
                check_against_golden(&e, id);
                tried += 1;
            }
        }
        assert!(tried > 0, "the test bundle holds no e5 model");

        let texts = texts();
        let req = Request {
            deadline_ms: 60_000,
            account: "acc".into(),
            job: "job".into(),
            op: Op::Embed {
                kind: EmbedKind::Passage,
                texts: vec![texts["en-nda"].clone(), texts["ar-application"].clone()],
            },
        };
        let a = run(&bundle, &req).unwrap();
        let b = run(&bundle, &req).unwrap();
        assert_eq!(a, b, "the same input gives the same bits");
        assert_eq!(a.len(), 2);
        let g = golden();
        let want: Vec<f64> = g["texts"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == "en-nda")
            .unwrap()["vector"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_f64().unwrap())
            .collect();
        assert!(1.0 - cosine(&a[0], &want) <= TOLERANCE);
    }

    #[test]
    fn a_passed_deadline_stops_between_texts() {
        let Some(dir) = bundle_dir() else { return };
        let bundle = Bundle::verify(&dir, &manifest_for(&dir), &[]).unwrap();
        let e = load(&bundle).unwrap();
        let texts = vec!["one".to_owned(), "two".to_owned()];
        assert_eq!(
            e.embed_all(EmbedKind::Query, &texts, || true).unwrap_err(),
            ModeldError::Deadline
        );
        let over = vec!["x".to_owned(); MAX_EMBED_TEXTS + 1];
        assert_eq!(
            e.embed_all(EmbedKind::Query, &over, || false)
                .unwrap_err()
                .code(),
            "CS-ML-0004"
        );
    }
}
