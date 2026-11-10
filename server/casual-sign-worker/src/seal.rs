//! The seal job's pipeline (docs/24 `SealEnvelope`, docs/30 §1, docs/31): for each
//! document, fill and flatten the signers' values into the delivered bytes, append the
//! certificate of completion with the audit trail, seal at the envelope's PAdES profile
//! with the platform key, and verify the stored result independently. Blocking (the
//! keyd and TSA calls are synchronous): run on a blocking thread.
//!
//! **What "verified" means here.** After sealing, the worker reads the sealed bytes back
//! as stored and runs `casual-sign-verify` over them, separately from the seal's own
//! in-process self-check, against the operator's trust anchors at the current time.
//! Every signature's byte range, digest, CMS signature and certificate chain must pass,
//! the timestamp too at B-T and above, no revision after a signature may be a
//! disallowed change, and the last signature must cover the whole file. Revocation may
//! be unknown at B-T (`INDETERMINATE/TRY_LATER`, as EU DSS says offline); at B-LT and
//! B-LTA it must pass from the embedded data. Only then is `verified: true` reported to
//! the engine, which refuses `completed` otherwise. pyHanko and EU DSS run over sealed
//! output in the gates (docs/31 §Verification ladder), not inside the worker.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use casual_sign_audit::{AuthMethod, Chain, EventData, Hash256, Timestamp};
use casual_sign_keyd::{DEV_REASON, DigestSigner, RemoteKey};
use casual_sign_model::{EnvelopeStatus, Field, FieldValue, Id, RecipientType, SealProfile};
use casual_sign_sdk::evidence::{
    AuthStep, Consent, CopyKind, CopyRow, DocumentRow, EnvelopeSummary, Mark, Outcome, Party,
    RecipientRow, Role, SealInfo,
};
use casual_sign_sdk::verify::{Check, Indication, SubIndication};
use casual_sign_sdk::{
    Capture, CertificateInput, CertificateOptions, Engine, Fill, FlattenOptions, KeyProvider,
    Profile, RevocationSource, TimestampSource, TrustStore, VerificationReport,
};
use casual_sign_workflow::{EnvelopeState, SealedDocument};

use crate::error::{Result, WorkerError};

/// Makes a timestamp source for one seal (sources may keep per-use state).
pub type TsaFactory = Arc<dyn Fn() -> Box<dyn TimestampSource> + Send + Sync>;
/// Makes a revocation source for one seal.
pub type RevocationFactory = Arc<dyn Fn() -> Box<dyn RevocationSource> + Send + Sync>;
/// Makes a key provider for one seal, in process (development and tests).
pub type KeyFactory = Arc<dyn Fn() -> Box<dyn KeyProvider> + Send + Sync>;

/// The platform key.
#[derive(Clone)]
pub enum SealKey {
    /// The key in keyd, over mTLS (production). keyd says whether it is a development
    /// key; when it is, every seal carries the development `/Reason` (docs/31 §5).
    Remote(RemoteKey),
    /// A key in this process: development only (a `FileKey` behind
    /// `OPENSEAL_DEV_INSECURE_KEY=1`) or tests. `development` must be true for a file key.
    Local {
        /// Makes the provider.
        provider: KeyFactory,
        /// Whether seals must carry the development `/Reason`.
        development: bool,
    },
}

impl core::fmt::Debug for SealKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Remote(r) => f.debug_tuple("Remote").field(r).finish(),
            Self::Local { development, .. } => f
                .debug_struct("Local")
                .field("development", development)
                .finish_non_exhaustive(),
        }
    }
}

/// Everything sealing needs besides the envelope.
#[derive(Clone)]
pub struct SealServices {
    /// The SDK facade with its limits and faces.
    pub engine: Engine,
    /// The platform key.
    pub key: SealKey,
    /// RFC 3161 time-stamping (B-T and above).
    pub timestamps: TsaFactory,
    /// OCSP and CRL fetching (B-LT and above).
    pub revocation: RevocationFactory,
    /// Trust anchors for the seal's self-check and the independent verification.
    pub trust: TrustStore,
    /// CRLs given to the verifier (optional: B-T passes without them).
    pub crls: Vec<Vec<u8>>,
    /// `/Name` of the seal (the operator's organisation).
    pub name: Option<String>,
    /// `/Reason` (replaced by the development reason for a development key).
    pub reason: Option<String>,
    /// `/Location`.
    pub location: Option<String>,
    /// The certificate's layout.
    pub certificate: CertificateOptions,
    /// Where readers can verify online, printed on the certificate.
    pub verify_url: Option<String>,
}

impl core::fmt::Debug for SealServices {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SealServices")
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

/// What the job gathered for one envelope.
pub struct SealInput {
    /// The state at `completing`.
    pub state: EnvelopeState,
    /// The chain as stored.
    pub chain: Chain,
    /// The account's name.
    pub account_name: String,
    /// The sender's name and email (personal data).
    pub sender: Party,
    /// Each document's delivered bytes, in the state's order.
    pub delivered: Vec<Vec<u8>>,
    /// Captures by id (the field values' and the adoptions' hashes).
    pub captures: BTreeMap<String, casual_sign_sdk::Art>,
    /// The sealing time.
    pub now: Timestamp,
}

impl core::fmt::Debug for SealInput {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SealInput")
            .field("documents", &self.delivered.len())
            .field("events", &self.chain.len())
            .finish_non_exhaustive()
    }
}

/// One sealed document: the engine's record of it and the bytes to store.
#[derive(Clone)]
pub struct SealedOut {
    /// For `SealSucceeded` (`verified` still false: set after re-verification).
    pub record: SealedDocument,
    /// The sealed bytes.
    pub bytes: Vec<u8>,
    /// Pages of the sealed document (delivered plus the certificate's).
    pub pages: u32,
}

impl core::fmt::Debug for SealedOut {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SealedOut")
            .field("document", &self.record.document_id)
            .field("bytes", &self.bytes.len())
            .finish()
    }
}

/// The SDK profile of an envelope's seal profile.
#[must_use]
pub fn profile(p: SealProfile) -> Profile {
    match p {
        SealProfile::PadesBLt => Profile::BaselineLt,
        SealProfile::PadesBLta => Profile::BaselineLta,
        _ => Profile::BaselineT,
    }
}

fn duration(t: Timestamp) -> Duration {
    Duration::from_millis(u64::try_from(t.unix_millis()).unwrap_or(0))
}

fn pipeline(code: &'static str) -> WorkerError {
    WorkerError::Pipeline { code }
}

/// Whether `report` proves an intact, trusted seal at `profile` (module docs).
///
/// # Errors
///
/// `CS-WRK-0012` naming the first check that failed.
pub fn check_verified(report: &VerificationReport, profile: Profile) -> Result<()> {
    let fail = |check| Err(WorkerError::NotVerified { check });
    if report.error.is_some() {
        return fail("document");
    }
    if report.signatures.is_empty() {
        return fail("no signature");
    }
    if !report.covered_by_last_signature {
        return fail("coverage");
    }
    let long_term = matches!(profile, Profile::BaselineLt | Profile::BaselineLta);
    for s in &report.signatures {
        let c = &s.checks;
        if !c.byte_range.passed() {
            return fail("byte_range");
        }
        if !c.digest.passed() {
            return fail("digest");
        }
        if !c.signature.passed() {
            return fail("signature");
        }
        if !c.chain.passed() {
            return fail("chain");
        }
        if profile != Profile::BaselineB && !c.timestamp.passed() {
            return fail("timestamp");
        }
        if matches!(c.modifications, Check::Failed(_)) {
            return fail("modifications");
        }
        if long_term && !c.revocation.passed() {
            return fail("revocation");
        }
        match s.indication {
            Indication::TotalPassed => {}
            Indication::Indeterminate(r) if r.sub == SubIndication::TryLater && !long_term => {}
            _ => return fail("indication"),
        }
    }
    Ok(())
}

fn party(name: &str, email: &str) -> Party {
    Party {
        name: name.to_owned(),
        email: email.to_owned(),
    }
}

/// The certificate's rows, from the state and the chain (docs/32 §6).
fn certificate_input<'a>(input: &'a SealInput) -> CertificateInput<'a> {
    let s = &input.state;
    let mut rows: Vec<RecipientRow> = Vec::new();
    let mut copies: Vec<CopyRow> = Vec::new();
    let events = input.chain.events();
    for r in &s.recipients {
        let rid = r.id();
        let about = |e: &EventData| -> bool {
            match e {
                EventData::InvitationSent { recipient_id, .. }
                | EventData::RecipientDelivered { recipient_id }
                | EventData::RecipientViewedDocument { recipient_id, .. }
                | EventData::RecipientAuthPassed { recipient_id, .. }
                | EventData::RecipientAuthFailed { recipient_id, .. }
                | EventData::RecipientConsented { recipient_id, .. }
                | EventData::RecipientSignatureAdopted { recipient_id, .. }
                | EventData::RecipientSigned { recipient_id, .. }
                | EventData::RecipientApproved { recipient_id, .. }
                | EventData::RecipientCompleted { recipient_id }
                | EventData::RecipientDeclined { recipient_id, .. } => recipient_id == rid,
                _ => false,
            }
        };
        let mine: Vec<_> = events.iter().filter(|c| about(&c.event.data)).collect();
        let first = |pred: &dyn Fn(&EventData) -> bool| {
            mine.iter()
                .find(|c| pred(&c.event.data))
                .map(|c| c.event.at)
        };
        let sent = first(&|d| matches!(d, EventData::InvitationSent { .. }));
        let p = party(r.spec.name.get().as_str(), r.spec.email.get().as_str());
        let role = match r.spec.rtype {
            RecipientType::Signer | RecipientType::Seal | RecipientType::Notary => Role::Signer,
            RecipientType::InPersonSigner => Role::InPersonSigner,
            RecipientType::Approver => Role::Approver,
            RecipientType::Witness => Role::Witness,
            RecipientType::Cc => {
                copies.push(CopyRow {
                    party: p,
                    kind: CopyKind::CarbonCopy,
                    delivered: sent,
                });
                continue;
            }
            RecipientType::Viewer => {
                copies.push(CopyRow {
                    party: p,
                    kind: CopyKind::Viewer,
                    delivered: first(&|d| matches!(d, EventData::RecipientCompleted { .. })),
                });
                continue;
            }
            // Editors, agents and intermediaries have no role on the certificate
            // (WRK-CERT row): their acts are in the embedded trail.
            _ => continue,
        };
        let mut auth = Vec::new();
        let mut marks: BTreeMap<&'static str, Mark> = BTreeMap::new();
        let mut outcome = Outcome::Pending;
        let mut consent = None;
        let mut acted_context = None;
        for c in &mine {
            let e = &c.event;
            match &e.data {
                EventData::RecipientAuthPassed { method, .. } => auth.push(AuthStep {
                    method: *method,
                    passed: true,
                    at: Some(e.at),
                }),
                EventData::RecipientAuthFailed { method, .. } => auth.push(AuthStep {
                    method: *method,
                    passed: false,
                    at: Some(e.at),
                }),
                EventData::RecipientConsented {
                    ersd_version,
                    ersd_hash,
                    ..
                } => {
                    consent = Some(Consent {
                        version: ersd_version.clone(),
                        hash: *ersd_hash,
                        accepted: e.at,
                    });
                }
                EventData::RecipientSignatureAdopted {
                    mark,
                    method,
                    image_hash,
                    ..
                } => {
                    if let Some(art) = input.captures.get(&image_hash.hex()) {
                        let which = match mark {
                            casual_sign_audit::MarkKind::Initials => "initials",
                            _ => "signature",
                        };
                        marks.insert(
                            which,
                            Mark {
                                art: art.clone(),
                                method: *method,
                            },
                        );
                    }
                }
                EventData::RecipientSigned { .. } => {
                    outcome = Outcome::Signed(e.at);
                    acted_context = Some(&e.context);
                }
                EventData::RecipientApproved { .. } => {
                    outcome = Outcome::Approved(e.at);
                    acted_context = Some(&e.context);
                }
                EventData::RecipientDeclined { reason, .. } => {
                    outcome = Outcome::Declined {
                        at: e.at,
                        reason: reason.as_ref().map(|x| x.get().clone()),
                    };
                    acted_context = Some(&e.context);
                }
                _ => {}
            }
        }
        // Authentication by email link is what every recipient passed by opening it.
        if auth.is_empty() && sent.is_some() {
            auth.push(AuthStep {
                method: AuthMethod::EmailLink,
                passed: true,
                at: first(&|d| matches!(d, EventData::RecipientDelivered { .. })),
            });
        }
        rows.push(RecipientRow {
            routing_order: r.spec.routing_order.get(),
            party: p,
            role,
            auth,
            ip: acted_context.and_then(|c| c.ip.as_ref().map(|v| v.get().clone())),
            user_agent: acted_context.and_then(|c| c.user_agent.as_ref().map(|v| v.get().clone())),
            signature: marks.remove("signature"),
            initials: marks.remove("initials"),
            sent,
            viewed: first(&|d| {
                matches!(
                    d,
                    EventData::RecipientDelivered { .. }
                        | EventData::RecipientViewedDocument { .. }
                )
            }),
            outcome,
            consent,
        });
    }
    rows.sort_by_key(|r| r.routing_order);
    CertificateInput {
        envelope: EnvelopeSummary {
            id: s.id.as_str().to_owned(),
            subject: s.subject.get().as_str().to_owned(),
            status: if s.status == EnvelopeStatus::Completing {
                "Completed".into()
            } else {
                format!("{:?}", s.status)
            },
            sender: input.sender.clone(),
            account: input.account_name.clone(),
            created: s.created_at,
            sent: s.sent_at,
            completed: None,
            seal_profile: s.seal_profile.as_str().to_owned(),
        },
        documents: s
            .documents
            .iter()
            .map(|d| DocumentRow {
                name: d.spec.name.get().as_str().to_owned(),
                pages: d.spec.pages,
                delivered: d.spec.delivered_hash,
                sealed: None,
            })
            .collect(),
        recipients: rows,
        copies,
        disclosure: None,
        seal: SealInfo::Pending,
        verify_url: None,
        chain: &input.chain,
        generated: input.now,
    }
}

/// The fields of one document, and the captures their signature values name.
fn fill_parts(
    fields: &[Field],
    document: &Id,
    state: &EnvelopeState,
    captures: &BTreeMap<String, casual_sign_sdk::Art>,
) -> Result<(Vec<Field>, BTreeMap<Id, Capture>)> {
    let mine: Vec<Field> = fields
        .iter()
        .filter(|f| &f.document_id == document)
        .cloned()
        .collect();
    let mut caps = BTreeMap::new();
    for f in &mine {
        if let Some(FieldValue::Signature(cap)) = &f.value {
            let art = captures
                .get(cap.as_str())
                .ok_or(WorkerError::SealInput { what: "capture" })?;
            let signed_by = f
                .recipient_id
                .as_ref()
                .and_then(|r| state.recipient(r))
                .map(|r| r.spec.name.get().as_str().to_owned());
            caps.insert(
                cap.clone(),
                Capture {
                    art: art.clone(),
                    signed_by,
                    reason: None,
                },
            );
        }
    }
    Ok((mine, caps))
}

/// Seal every document of `input` (blocking). The records' `verified` is false: the
/// caller stores the bytes, reads them back and calls [`verify_stored`].
///
/// # Errors
///
/// The failing step's code (`CS-FLD-*`, `CS-FLT-*`, `CS-AUD-*`, `CS-SEAL-*`,
/// `CS-KEY-*`, ...), or `CS-WRK-0011` for a missing input.
pub fn seal_all(services: &SealServices, input: &SealInput) -> Result<Vec<SealedOut>> {
    let s = &input.state;
    if input.delivered.len() != s.documents.len() {
        return Err(WorkerError::SealInput { what: "document" });
    }
    let (provider, development): (Box<dyn KeyProvider>, bool) = match &services.key {
        SealKey::Remote(r) => {
            let r = r
                .for_envelope(s.id.as_str())
                .map_err(|e| pipeline(e.code()))?;
            let dev = DigestSigner::is_development(&r);
            (Box::new(r), dev)
        }
        SealKey::Local {
            provider,
            development,
        } => (provider(), *development),
    };
    let fingerprint = provider
        .certificate_chain()
        .first()
        .and_then(|c| der::Encode::to_der(c).ok())
        .map(|d| Hash256::digest(&d))
        .ok_or(WorkerError::SealInput {
            what: "certificate",
        })?;
    let cert_input = certificate_input(input);
    let target = profile(s.seal_profile);
    let mut out = Vec::with_capacity(s.documents.len());
    for (doc, delivered) in s.documents.iter().zip(&input.delivered) {
        if Hash256::digest(delivered) != doc.spec.delivered_hash {
            return Err(WorkerError::SealInput { what: "document" });
        }
        let (fields, captures) = fill_parts(&s.fields.0, doc.id(), s, &input.captures)?;
        let values = BTreeMap::new();
        let fill = Fill {
            fields: &fields,
            values: &values,
            captures: &captures,
            envelope_id: Some(s.id.as_str()),
            acroform: None,
            require_complete: false,
        };
        let e = &services.engine;
        let flat = e
            .fill_and_flatten(delivered, &fill, &FlattenOptions::default())
            .map_err(|x| pipeline(x.code()))?;
        let flattened_hash = Hash256::digest(&flat.bytes);
        let completed = e
            .complete(&flat.bytes, &cert_input, &services.certificate)
            .map_err(|x| pipeline(x.code()))?;
        let field = e
            .free_field_name(&completed.bytes, "OpenSealSeal")
            .map_err(|x| pipeline(x.code()))?;
        let mut request = e.seal_request(target, &field, duration(input.now));
        request.trust = services.trust.clone();
        request.name.clone_from(&services.name);
        request.location.clone_from(&services.location);
        request.reason = if development {
            Some(DEV_REASON.to_owned())
        } else {
            services.reason.clone()
        };
        let tsa = (services.timestamps)();
        let revocation = (services.revocation)();
        let sealed = e
            .seal(
                &completed.bytes,
                &request,
                provider.as_ref(),
                tsa.as_ref(),
                revocation.as_ref(),
            )
            .map_err(|x| pipeline(x.code()))?;
        let tsa_time = sealed
            .report
            .signature_timestamp
            .and_then(|d| i64::try_from(d.as_millis()).ok())
            .and_then(Timestamp::from_unix_millis);
        let pages = doc
            .spec
            .pages
            .saturating_add(u32::try_from(completed.pages_added).unwrap_or(u32::MAX));
        out.push(SealedOut {
            record: SealedDocument {
                document_id: doc.id().clone(),
                delivered_hash: doc.spec.delivered_hash,
                flattened_hash,
                sealed_hash: Hash256::digest(&sealed.bytes),
                profile: s.seal_profile,
                certificate_fingerprint: fingerprint,
                tsa_time,
                verified: false,
            },
            bytes: sealed.bytes,
            pages,
        });
    }
    Ok(out)
}

/// Verify sealed bytes as read back from storage (module docs).
///
/// # Errors
///
/// `CS-WRK-0012` naming the failing check.
pub fn verify_stored(
    services: &SealServices,
    bytes: &[u8],
    profile_of: SealProfile,
    now: Timestamp,
) -> Result<()> {
    let mut options = services.engine.verify_options(duration(now));
    options.crls.clone_from(&services.crls);
    let report = services.engine.verify(bytes, &services.trust, &options);
    check_verified(&report, profile(profile_of))
}

/// The capture ids an envelope's seal needs: signature values and adoptions.
#[must_use]
pub fn capture_ids(state: &EnvelopeState, chain: &Chain) -> Vec<String> {
    let mut ids: Vec<String> = state
        .fields
        .0
        .iter()
        .filter_map(|f| match &f.value {
            Some(FieldValue::Signature(id)) => Some(id.as_str().to_owned()),
            _ => None,
        })
        .collect();
    for c in chain.events() {
        if let EventData::RecipientSignatureAdopted { image_hash, .. } = &c.event.data {
            ids.push(image_hash.hex());
        }
    }
    ids.sort();
    ids.dedup();
    ids
}
