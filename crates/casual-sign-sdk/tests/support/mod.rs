//! The whole pipeline over one document through the facade, as the Phase 1 gate runs it
//! (`P1-GATE-01`, docs/06 Phase 1 exit item 2): admit; normalize (or keep signed input
//! as it is); convert the AcroForm and fill every field with a value of its type, or
//! place one text field by geometry; flatten; append the certificate of completion with
//! a small audit chain; seal at PAdES B-T with the throwaway test PKI and in-process TSA;
//! verify. The prefix invariant is checked after every step. Shared by the facade's
//! tests and `examples/pipeline_corpus.rs`.

// Not every user calls every helper.
#![allow(dead_code)]
// Test and tool code: a panic is the failure report, and the corpus run catches it.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    missing_docs
)]

use std::collections::BTreeMap;
use std::time::Duration;

use casual_sign_sdk::evidence::{
    Actor, ActorKind, AdoptionMethod, AuthMethod, Chain, Channel, Context, DocumentHash,
    DocumentRow, EnvelopeSummary, EventData, Mark, MarkKind, Outcome as RowOutcome, Party,
    RecipientRow, Role, SealInfo, Timestamp,
};
use casual_sign_sdk::model::{
    Field, FieldType, FieldValue, Id, PageGeometry, Placement, Points, Text, Validation,
    ValidationRule,
};
use casual_sign_sdk::{
    AdmissionReport, Art, Capture, CertificateInput, CertificateOptions, Conversion, Credentials,
    Delivered, Engine, Fill, FlattenOptions, Hash256, Indication, Ink, InkPoint, NoRevocation,
    Profile, TrailOptions, TrustStore, VerificationReport,
};
use rust_decimal::Decimal;

use crate::common::{SIGNING_TIME, TestTsa, VALIDATION_TIME, p256, pki, trust};

/// The passwords the corpus's encrypted files publish (fixtures/corpus/README.md).
pub const PASSWORDS: [&str; 5] = ["user", "usersecret", "openpassword", "view", " "];

pub const ENVELOPE: &str = "0193a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";

/// Text every text field is filled with, cut to the field's `/MaxLen`.
pub const SAMPLE: &str = "Sample 42";

pub fn credentials() -> Credentials {
    PASSWORDS
        .iter()
        .fold(Credentials::new(), |c, p| c.with_password(p))
}

fn id(s: &str) -> Id {
    Id::new(s).unwrap()
}

fn pts(v: f64) -> Points {
    Points::new(Decimal::from_f64_retain(v.floor()).unwrap()).unwrap()
}

/// A wavy drawn signature.
pub fn ink() -> Ink {
    let pts = (0..80)
        .map(|i| {
            let t = f64::from(i) / 80.0;
            InkPoint {
                x: t * 300.0,
                y: 60.0 + 30.0 * (t * 12.0).sin(),
            }
        })
        .collect();
    Ink {
        strokes: vec![pts],
        color: None,
    }
}

pub fn captures() -> BTreeMap<Id, Capture> {
    BTreeMap::from([(
        id("cap"),
        Capture {
            art: Art::Drawn(ink()),
            signed_by: Some("Sample Signer".to_owned()),
            reason: None,
        },
    )])
}

/// A value of each field's type: text cut to its maximum length, the checkbox checked,
/// the first option of a choice, the drawn capture for a signature.
pub fn sample_values(fields: &[Field]) -> BTreeMap<Id, FieldValue> {
    let mut out = BTreeMap::new();
    for f in fields {
        // A read-only or locked field keeps the sender's value: a signer's differs
        // (`CS-FLD-0022`).
        if f.read_only || f.locked {
            continue;
        }
        let v = match f.field_type {
            FieldType::Checkbox => FieldValue::Checked(true),
            FieldType::RadioGroup | FieldType::Dropdown => match f.options.as_slice().first() {
                Some(o) => FieldValue::Choice(o.clone()),
                None => continue,
            },
            FieldType::Signature | FieldType::Initials | FieldType::Stamp => {
                FieldValue::Signature(id("cap"))
            }
            _ => {
                let max = match &f.validation {
                    Some(Validation {
                        rule: ValidationRule::Length(r),
                        ..
                    }) => r.max().map_or(usize::MAX, |m| m as usize),
                    _ => usize::MAX,
                };
                if max == 0 {
                    continue;
                }
                let text: String = SAMPLE.chars().take(max).collect();
                FieldValue::Text(Text::new(text).unwrap())
            }
        };
        out.insert(f.id.clone(), v);
    }
    out
}

/// One text field on page 1, 36 points in from the top-left corner as displayed, as
/// wide as the page allows up to 300 by 20 points.
pub fn geometry_field(report: &AdmissionReport) -> Field {
    let (w, h) = report.pages.first().map_or((612.0, 792.0), |p| {
        PageGeometry::from_page(p).displayed_size()
    });
    let margin = (w.min(h) / 10.0).clamp(0.0, 36.0);
    let width = (w - 2.0 * margin).clamp(1.0, 300.0);
    let height = (h - 2.0 * margin).clamp(1.0, 20.0);
    Field::new(
        id("note"),
        id("doc"),
        FieldType::Text,
        Placement::new(1, pts(margin), pts(margin), pts(width), pts(height)).unwrap(),
    )
}

pub fn t(ms_before_signing: i64) -> Timestamp {
    let s = i64::try_from(SIGNING_TIME.as_millis()).unwrap();
    Timestamp::from_unix_millis(s - ms_before_signing).unwrap()
}

/// A one-signer envelope's chain up to `envelope.completing`.
pub fn chain(delivered: Hash256, pages: u32) -> Chain {
    let mut c = Chain::new(id(ENVELOPE));
    let mut at = 600_000;
    let rid = id("rcp-1");
    let signer = Actor {
        kind: ActorKind::Recipient,
        id: Some(rid.clone()),
        name: Some(casual_sign_sdk::evidence::Personal("Sample Signer".into())),
        email: Some(casual_sign_sdk::evidence::Personal(
            "signer@example.org".into(),
        )),
    };
    let sender = Actor {
        kind: ActorKind::Sender,
        id: Some(id("u-1")),
        name: None,
        email: None,
    };
    let doc = DocumentHash {
        document_id: id("doc"),
        hash: delivered,
    };
    let events = vec![
        (
            sender.clone(),
            EventData::EnvelopeCreated {
                subject_hash: Hash256::digest(b"Corpus pipeline"),
            },
        ),
        (
            Actor::system(),
            EventData::DocumentFixed {
                document_id: id("doc"),
                delivered_hash: delivered,
                pages,
            },
        ),
        (
            sender,
            EventData::EnvelopeSent {
                recipients: 1,
                documents: 1,
            },
        ),
        (
            Actor::system(),
            EventData::InvitationSent {
                recipient_id: rid.clone(),
                channel: Channel::Email,
            },
        ),
        (
            signer.clone(),
            EventData::RecipientViewedDocument {
                recipient_id: rid.clone(),
                document: doc.clone(),
                pages_seen: vec![1],
            },
        ),
        (
            signer.clone(),
            EventData::RecipientSignatureAdopted {
                recipient_id: rid.clone(),
                mark: MarkKind::Signature,
                method: AdoptionMethod::Draw,
                image_hash: Hash256::digest(b"ink"),
            },
        ),
        (
            signer,
            EventData::RecipientSigned {
                recipient_id: rid,
                documents: vec![doc],
                field_value_hashes: BTreeMap::new(),
            },
        ),
        (Actor::system(), EventData::EnvelopeCompleting {}),
    ];
    for (actor, data) in events {
        at -= 60_000;
        let ctx = Context {
            auth: vec![AuthMethod::EmailLink],
            ..Context::default()
        };
        let e = c.next(t(at), actor, ctx, data);
        c.append(e).unwrap();
    }
    c
}

pub fn certificate_input<'a>(
    chain: &'a Chain,
    name: &str,
    delivered: Hash256,
    pages: u32,
) -> CertificateInput<'a> {
    let name: String = name.chars().take(200).collect();
    CertificateInput {
        envelope: EnvelopeSummary {
            id: ENVELOPE.into(),
            subject: format!("Corpus pipeline: {name}"),
            status: "Completed".into(),
            sender: Party {
                name: "Sam Sender".into(),
                email: "sam.sender@example.org".into(),
            },
            account: "OpenSeal gate run".into(),
            created: t(540_000),
            sent: Some(t(420_000)),
            completed: None,
            seal_profile: "PAdES-B-T".into(),
        },
        documents: vec![DocumentRow {
            name,
            pages,
            delivered,
            sealed: None,
        }],
        recipients: vec![RecipientRow {
            routing_order: 1,
            party: Party {
                name: "Sample Signer".into(),
                email: "signer@example.org".into(),
            },
            role: Role::Signer,
            auth: Vec::new(),
            ip: Some("203.0.113.7".into()),
            user_agent: Some("openseal-gate".into()),
            location: None,
            signature: Some(Mark {
                art: Art::Drawn(ink()),
                method: AdoptionMethod::Draw,
            }),
            initials: None,
            sent: Some(t(360_000)),
            viewed: Some(t(300_000)),
            outcome: RowOutcome::Signed(t(120_000)),
            consent: None,
        }],
        copies: Vec::new(),
        disclosure: None,
        seal: SealInfo::Pending,
        verify_url: None,
        chain,
        generated: t(30_000),
    }
}

/// The class of a document for the gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    /// Has AcroForm fields: converted and filled.
    Form,
    /// No fields: one placed by geometry.
    Plain,
    /// Signed input: kept as it is, sealed by appending a second signature.
    Signed,
}

impl Class {
    pub fn name(self) -> &'static str {
        match self {
            Self::Form => "form",
            Self::Plain => "plain",
            Self::Signed => "signed",
        }
    }
}

/// How far a document got, and what came out.
#[derive(Debug, Default)]
pub struct Run {
    pub class: Option<Class>,
    /// Steps completed, in order.
    pub steps: Vec<&'static str>,
    /// Converted fields and fields given a value.
    pub fields: (usize, usize),
    /// The delivered bytes.
    pub delivered: Vec<u8>,
    /// The sealed bytes.
    pub sealed: Option<Vec<u8>>,
    /// Our verdict offline (no revocation data: B-T is INDETERMINATE/TRY_LATER) and with
    /// the test PKI's CRLs supplied.
    pub offline: Option<VerificationReport>,
    pub online: Option<VerificationReport>,
    /// The failing step's code or cause.
    pub failure: Option<String>,
    /// Every prefix check held.
    pub prefix: bool,
}

/// Every signature passed every check with revocation answers supplied, the last one
/// covers the whole file, and no revision is a disallowed change.
pub fn passes(report: &VerificationReport) -> bool {
    report.all_passed()
}

/// For signed input: our new (last) signature passed; earlier ones are judged only on
/// what our revision did to them: no disallowed change after them, and each still
/// verifies as far as it did before.
pub fn passes_appended(before: &VerificationReport, after: &VerificationReport) -> bool {
    let Some(ours) = after.signatures.last() else {
        return false;
    };
    if after.error.is_some()
        || ours.indication != Indication::TotalPassed
        || !after.covered_by_last_signature
        || after.signatures.len() != before.signatures.len() + 1
    {
        return false;
    }
    before
        .signatures
        .iter()
        .zip(&after.signatures)
        .all(|(b, a)| {
            a.checks.byte_range == b.checks.byte_range
                && a.checks.digest == b.checks.digest
                && a.checks.signature == b.checks.signature
                && a.modifications_after.iter().all(|m| {
                    m.allowed()
                        || b.modifications_after
                            .iter()
                            .any(|x| x.revision == m.revision)
                })
        })
}

/// The test PKI's CRLs: revocation answers for every certificate below the root.
pub fn crls() -> Vec<Vec<u8>> {
    vec![pki().root_crl.clone(), pki().inter_crl.clone()]
}

pub fn trust_store() -> TrustStore {
    trust()
}

/// Run the pipeline over one file. Never panics on a refusal: each step's failure is
/// recorded with its code.
pub fn run(engine: &Engine, name: &str, bytes: &[u8]) -> Run {
    let mut r = Run {
        prefix: true,
        ..Run::default()
    };
    let admission = match engine.admit(bytes, &credentials()) {
        Ok(a) => a,
        Err(e) => {
            r.failure = Some(format!("admit {}", e.code()));
            return r;
        }
    };
    r.steps.push("admit");
    if admission.is_signed() {
        r.class = Some(Class::Signed);
        return run_signed(engine, bytes, r);
    }
    let delivered = match engine.prepare(bytes, &credentials()) {
        Ok(d) => d,
        Err(e) => {
            r.failure = Some(format!("normalize {}", e.code()));
            return r;
        }
    };
    r.steps.push("normalize");
    r.delivered = delivered.bytes.clone();
    let mut n = 0u32;
    let mut next = || {
        n += 1;
        id(&format!("f{n}"))
    };
    let conversion = match engine.convert_form(&delivered.bytes, &id("doc"), &mut next) {
        Ok(c) => c,
        Err(e) => {
            r.failure = Some(format!("convert {}", e.code()));
            return r;
        }
    };
    let fields: Vec<Field> = conversion.fields.iter().map(|c| c.field.clone()).collect();
    let (fields, acroform): (Vec<Field>, Option<&Conversion>) = if fields.is_empty() {
        r.class = Some(Class::Plain);
        (vec![geometry_field(&delivered.admission)], None)
    } else {
        r.class = Some(Class::Form);
        (fields, Some(&conversion))
    };
    let values = sample_values(&fields);
    r.fields = (fields.len(), values.len());
    r.steps.push("fill");
    let caps = captures();
    let fill = Fill {
        fields: &fields,
        values: &values,
        captures: &caps,
        envelope_id: Some(ENVELOPE),
        acroform,
        require_complete: false,
    };
    let flat = match engine.fill_and_flatten(&delivered.bytes, &fill, &FlattenOptions::default()) {
        Ok(f) => f,
        Err(e) => {
            r.failure = Some(format!("flatten {}: {e}", e.code()));
            return r;
        }
    };
    r.prefix &= flat.bytes.starts_with(&delivered.bytes);
    r.steps.push("flatten");
    let pages = u32::try_from(delivered.admission.pages.len()).unwrap_or(u32::MAX);
    let chain = chain(delivered.hash, pages);
    let input = certificate_input(&chain, name, delivered.hash, pages);
    let completed = match engine.complete(&flat.bytes, &input, &CertificateOptions::default()) {
        Ok(c) => c,
        Err(e) => {
            r.failure = Some(format!("certificate {}", e.code()));
            return r;
        }
    };
    r.prefix &=
        completed.bytes.starts_with(&flat.bytes) && completed.bytes.starts_with(&delivered.bytes);
    if !engine
        .verify_trail(&completed.trail, &TrailOptions::default())
        .is_valid()
    {
        r.failure = Some("certificate trail does not verify".into());
        return r;
    }
    r.steps.push("certificate");
    seal_and_verify(engine, &completed.bytes, &delivered, None, r)
}

fn run_signed(engine: &Engine, bytes: &[u8], mut r: Run) -> Run {
    let delivered = match engine.keep_signed(bytes) {
        Ok(d) => d,
        Err(e) => {
            r.failure = Some(format!("keep-signed {}", e.code()));
            return r;
        }
    };
    r.steps.push("keep");
    r.delivered = delivered.bytes.clone();
    let before = engine.verify(bytes, &trust(), &with_crls(engine));
    seal_and_verify(engine, bytes, &delivered, Some(before), r)
}

fn with_crls(engine: &Engine) -> casual_sign_sdk::VerifyOptions {
    let mut o = engine.verify_options(VALIDATION_TIME);
    o.crls = crls();
    o
}

fn seal_and_verify(
    engine: &Engine,
    input: &[u8],
    delivered: &Delivered,
    before: Option<VerificationReport>,
    mut r: Run,
) -> Run {
    let field = match engine.free_field_name(input, "OpenSealGate") {
        Ok(f) => f,
        Err(e) => {
            r.failure = Some(format!("seal {}", e.code()));
            return r;
        }
    };
    let mut request = engine.seal_request(Profile::BaselineT, &field, SIGNING_TIME);
    request.reason = Some("Phase 1 gate run".into());
    request.trust = trust();
    let tsa = TestTsa::new(SIGNING_TIME + Duration::from_secs(1));
    let sealed = match engine.seal(input, &request, &p256(), &tsa, &NoRevocation) {
        Ok(s) => s,
        Err(e) => {
            r.failure = Some(format!("seal {}", e.code()));
            return r;
        }
    };
    r.prefix &= sealed.bytes.starts_with(input) && sealed.bytes.starts_with(&delivered.bytes);
    r.steps.push("seal");
    let offline = engine.verify(
        &sealed.bytes,
        &trust(),
        &engine.verify_options(VALIDATION_TIME),
    );
    let online = engine.verify(&sealed.bytes, &trust(), &with_crls(engine));
    let ok = match &before {
        Some(b) => passes_appended(b, &online),
        None => passes(&online),
    };
    if ok {
        r.steps.push("verify");
    } else {
        r.failure = Some(format!(
            "verify {}",
            online
                .signatures
                .last()
                .map_or("no signature".to_owned(), |s| s.indication.to_string())
        ));
    }
    r.sealed = Some(sealed.bytes);
    r.offline = Some(offline);
    r.online = Some(online);
    r
}
