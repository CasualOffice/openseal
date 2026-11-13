//! Document analysis as the server and the worker both see it (WEB-19, ML-01; docs/33
//! §2, §6, §7): which features are in effect, the two advisory job kinds and their
//! idempotency keys, and the text a run analyses, which the server rebuilds to show a
//! span.
//!
//! **Enablement** (docs/33 §7): a feature is in effect only when the operator deployed
//! a model service (the server knows its bundle id), the plan entitles the workspace
//! (`ml.*` entitlements) **and** the workspace's administrator turned it on. Off by
//! default at every level; with nothing in effect no job is enqueued (`ML-01`).
//!
//! **Keys** (`SEC-I06`): both keys name the account and the document, so no run is ever
//! shared across accounts or documents, even for identical bytes.
//!
//! These jobs are advisory (ADR-012 beside the effect jobs of ADR-011): they touch no
//! envelope state, no audit chain and no document version, and a dead one means only
//! "no suggestions".

use casual_sign_store::repo::jobs::NewJob;
use casual_sign_store::repo::ml::MlSettings;
use casual_sign_store::{AccountId, EnvelopeId, JobId};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// `analyze_document`: OCR, template matching, details and personal data for a draft
/// envelope's document.
pub const ANALYZE_DOCUMENT: &str = "analyze_document";
/// `fingerprint_template`: a template document's page hashes, for matching uploads.
pub const FINGERPRINT_TEMPLATE: &str = "fingerprint_template";
/// Attempts before an analysis job is dead (docs/33 §2).
pub const MAX_ATTEMPTS: i32 = 3;

/// One of the four features of docs/33 §7.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Feature {
    /// OCR of scanned pages (`ml.ocr`).
    Ocr,
    /// Template matching (`ml.template_matching`).
    TemplateMatching,
    /// Agreement details (`ml.extraction`).
    Extraction,
    /// Personal data (`ml.personal_data`).
    PersonalData,
}

impl Feature {
    /// All four, in the settings' order.
    pub const ALL: [Self; 4] = [
        Self::Ocr,
        Self::TemplateMatching,
        Self::Extraction,
        Self::PersonalData,
    ];

    /// The settings' member name (`ocr`, `template_matching`, ...).
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Ocr => "ocr",
            Self::TemplateMatching => "template_matching",
            Self::Extraction => "extraction",
            Self::PersonalData => "personal_data",
        }
    }

    /// The plan entitlement (`ml.ocr`, ...).
    #[must_use]
    pub const fn entitlement(self) -> &'static str {
        match self {
            Self::Ocr => "ml.ocr",
            Self::TemplateMatching => "ml.template_matching",
            Self::Extraction => "ml.extraction",
            Self::PersonalData => "ml.personal_data",
        }
    }

    /// What a run does for it (`ocr`, `template`, `entities`, `personal_data`).
    #[must_use]
    pub const fn use_name(self) -> &'static str {
        match self {
            Self::Ocr => "ocr",
            Self::TemplateMatching => "template",
            Self::Extraction => "entities",
            Self::PersonalData => "personal_data",
        }
    }

    /// Whether the workspace's administrator turned it on.
    #[must_use]
    pub const fn on_in(self, s: &MlSettings) -> bool {
        match self {
            Self::Ocr => s.ocr,
            Self::TemplateMatching => s.template_matching,
            Self::Extraction => s.extraction,
            Self::PersonalData => s.personal_data,
        }
    }
}

/// Whether the plan entitles the workspace to `f`.
#[must_use]
pub fn entitled(f: Feature, entitlements: &[String]) -> bool {
    entitlements.iter().any(|e| e == f.entitlement())
}

/// The features in effect: deployed (`installed`) ∧ entitled ∧ turned on, in order.
#[must_use]
pub fn effective(settings: &MlSettings, entitlements: &[String], installed: bool) -> Vec<Feature> {
    if !installed {
        return Vec::new();
    }
    Feature::ALL
        .into_iter()
        .filter(|f| f.on_in(settings) && entitled(*f, entitlements))
        .collect()
}

/// The `uses` of a run for `features`, in the fixed order of docs/33 §2.
#[must_use]
pub fn uses_of(features: &[Feature]) -> Vec<String> {
    Feature::ALL
        .into_iter()
        .filter(|f| features.contains(f))
        .map(|f| f.use_name().to_owned())
        .collect()
}

/// Lower-case hex of a SHA-256.
#[must_use]
pub fn hex(sha: &[u8; 32]) -> String {
    use core::fmt::Write as _;
    let mut s = String::with_capacity(64);
    for b in sha {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// `analyze:{account}:{document}:{document_sha256}:{uses}:{bundle_id}` (docs/33 §2).
#[must_use]
pub fn analyze_key(
    account: AccountId,
    document: Uuid,
    sha: &[u8; 32],
    uses: &[String],
    bundle: &str,
) -> String {
    format!(
        "analyze:{}:{}:{}:{}:{bundle}",
        account.0.hyphenated(),
        document.hyphenated(),
        hex(sha),
        uses.join(",")
    )
}

/// `fingerprint:{account}:{template}:{document}:{document_sha256}:{bundle_id}` (docs/33
/// §2).
#[must_use]
pub fn fingerprint_key(
    account: AccountId,
    template: Uuid,
    document: Uuid,
    sha: &[u8; 32],
    bundle: &str,
) -> String {
    format!(
        "fingerprint:{}:{}:{}:{}:{bundle}",
        account.0.hyphenated(),
        template.hyphenated(),
        document.hyphenated(),
        hex(sha)
    )
}

/// The key prefix of a retry (`ML-24`): asking again after a run of this document ended
/// `failed` or `unavailable` starts a new run keyed this prefix followed by the failed
/// run's hyphenated id, `analyze:{account}:{document}:retry:{run}` or
/// `fingerprint:{account}:{template}:{document}:retry:{run}`. It names the account and
/// the document (`SEC-I06`) and, unlike the first key, stays within the 255 characters
/// of a job key; asking twice after the same failure finds the same retry.
#[must_use]
pub fn retry_prefix(account: AccountId, template: Option<Uuid>, document: Uuid) -> String {
    match template {
        Some(t) => format!(
            "fingerprint:{}:{}:{}:retry:",
            account.0.hyphenated(),
            t.hyphenated(),
            document.hyphenated()
        ),
        None => format!(
            "analyze:{}:{}:retry:",
            account.0.hyphenated(),
            document.hyphenated()
        ),
    }
}

/// The key of the run that retries `failed` (see [`retry_prefix`]).
#[must_use]
pub fn retry_key(prefix: &str, failed: Uuid) -> String {
    format!("{prefix}{}", failed.hyphenated())
}

/// The payload of both analysis jobs: ids only, never document content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalysisJob {
    /// The run (`analysis_runs.id`) the job fills.
    pub run_id: Uuid,
    /// The account (also the job's own; checked to agree).
    pub account_id: Uuid,
    /// The document (`documents.id` or `template_documents.id`).
    pub document_id: Uuid,
    /// The draft envelope, for `analyze_document`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub envelope_id: Option<Uuid>,
    /// The template, for `fingerprint_template`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub template_id: Option<Uuid>,
    /// `ocr`, `template`, `entities`, `personal_data`, in that order.
    pub uses: Vec<String>,
    /// The stored, normalized PDF's SHA-256, hex.
    pub document_sha256: String,
}

/// The job of kind `kind` that fills a run, keyed `key`, due `now`.
#[must_use]
pub fn analysis_job(
    id: JobId,
    kind: &'static str,
    payload: &AnalysisJob,
    key: String,
    now: time::OffsetDateTime,
) -> NewJob {
    NewJob {
        id,
        envelope_id: payload.envelope_id.map(EnvelopeId),
        kind: kind.to_owned(),
        idempotency_key: key,
        payload: serde_json::to_value(payload).unwrap_or(serde_json::Value::Null),
        run_at: now,
        max_attempts: MAX_ATTEMPTS,
    }
}

/// The text a run analyses for one page: the OCR words when the page was read by OCR
/// (joined by single spaces, as modeld returns them in NFC), else the page's text layer
/// as the engine extracts it (NFKC, whitespace collapsed). Span offsets are UTF-8 byte
/// offsets into exactly this text (docs/33 §3.2), so the server, rebuilding it from the
/// stored document and the stored words, shows the span the model found.
#[must_use]
pub fn page_text(layer: &str, ocr_words: Option<&serde_json::Value>) -> String {
    match ocr_words.and_then(serde_json::Value::as_array) {
        Some(words) => {
            let mut out = String::new();
            for w in words {
                let Some(t) = w.get("text").and_then(serde_json::Value::as_str) else {
                    continue;
                };
                let t = t.trim();
                if t.is_empty() {
                    continue;
                }
                if !out.is_empty() {
                    out.push(' ');
                }
                out.push_str(t);
            }
            out
        }
        None => layer.to_owned(),
    }
}

/// The text of `text[start..end]`, when both ends are in range and on character
/// boundaries; `None` otherwise (the stored document changed, or a bad offset).
#[must_use]
pub fn span_text(text: &str, start: i32, end: i32) -> Option<&str> {
    let s = usize::try_from(start).ok()?;
    let e = usize::try_from(end).ok()?;
    text.get(s..e)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn on() -> MlSettings {
        MlSettings {
            ocr: true,
            template_matching: true,
            extraction: true,
            personal_data: true,
            ..MlSettings::default()
        }
    }

    #[test]
    fn a_feature_is_in_effect_only_when_deployed_entitled_and_turned_on() {
        let all: Vec<String> = Feature::ALL
            .iter()
            .map(|f| f.entitlement().to_owned())
            .collect();
        assert_eq!(effective(&on(), &all, true), Feature::ALL.to_vec());
        assert!(effective(&on(), &all, false).is_empty(), "not installed");
        assert!(
            effective(&MlSettings::default(), &all, true).is_empty(),
            "off"
        );
        assert!(effective(&on(), &[], true).is_empty(), "not in plan");
        let one = vec!["ml.extraction".to_owned()];
        assert_eq!(effective(&on(), &one, true), vec![Feature::Extraction]);
    }

    #[test]
    fn uses_are_in_the_fixed_order() {
        assert_eq!(
            uses_of(&[Feature::PersonalData, Feature::Ocr, Feature::Extraction]),
            ["ocr", "entities", "personal_data"]
        );
    }

    #[test]
    fn keys_name_the_account_and_the_document() {
        let a = AccountId(Uuid::from_u128(1));
        let b = AccountId(Uuid::from_u128(2));
        let d = Uuid::from_u128(3);
        let sha = [7u8; 32];
        let uses = vec!["ocr".to_owned()];
        let ka = analyze_key(a, d, &sha, &uses, "b1");
        assert_ne!(ka, analyze_key(b, d, &sha, &uses, "b1"));
        assert_ne!(ka, analyze_key(a, Uuid::from_u128(4), &sha, &uses, "b1"));
        assert!(ka.starts_with("analyze:00000000-0000-0000-0000-000000000001:"));
        assert!(ka.len() <= 255);
        let kf = fingerprint_key(a, d, d, &sha, "b1");
        assert!(kf.starts_with("fingerprint:00000000-0000-0000-0000-000000000001:"));
        let r = retry_key(&retry_prefix(a, None, d), Uuid::from_u128(5));
        assert!(r.starts_with("analyze:00000000-0000-0000-0000-000000000001:"));
        let rf = retry_key(&retry_prefix(a, Some(d), d), Uuid::from_u128(u128::MAX));
        assert!(rf.starts_with("fingerprint:00000000-0000-0000-0000-000000000001:"));
        assert!(r.len() <= 255 && rf.len() <= 255);
    }

    #[test]
    fn page_text_prefers_ocr_words_and_spans_respect_char_boundaries() {
        let words = serde_json::json!([{"text": "Start"}, {"text": " "}, {"text": "1 déc."}]);
        assert_eq!(page_text("layer", Some(&words)), "Start 1 déc.");
        assert_eq!(page_text("layer", None), "layer");
        let t = "1 déc.";
        assert_eq!(span_text(t, 2, 5), Some("dé"));
        assert_eq!(span_text(t, 2, 4), None, "inside é");
        assert_eq!(span_text(t, -1, 2), None);
        assert_eq!(span_text(t, 0, 99), None);
    }
}
