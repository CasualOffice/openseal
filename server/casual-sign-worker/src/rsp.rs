//! The worker's half of a remote signing session (`RSP-01`, ADR-046 §3.4 to §3.6): a
//! `remote_signing` job the server queues when the provider sends the signer back.
//!
//! - **`preparing`**: exchange the code (scope `service`), list the signer's credentials
//!   and take the first the account accepts (`credentials/info`: enabled, valid, an
//!   algorithm we accept, the qualifier the account requires; none: `no_eligible_credential`),
//!   then, for each document the signer sees, from its current bytes: at the lock point
//!   (the document's first remote signature) R0, the final values flattened and the rest
//!   materialized with an unsigned signature field per remote signer; the fill of every
//!   materialized value now final, the signer's own included; and `prepare` with the
//!   signer's widget. The prepared bytes are stored first, then `RemoteSigningPrepared`
//!   records their hashes and the session waits for the signer to authorize them.
//! - **`signing`**: exchange the code (scope `credential`, bound to the hashes), call
//!   `signatures/signHash` once with every hash, then `complete` each document (the value
//!   checked under the certificate, our time-stamp, the DSS at once) and store it;
//!   `CompleteRemoteSigning` records it and the signer completes.
//!
//! Any provider failure fails the session (`FailRemoteSigning`) with its reason and the
//! provider's own code; the signer may start again. Tokens and codes live only in this
//! job's memory; the code and verifier sealed in the session row are taken once.

use std::collections::{BTreeMap, BTreeSet};
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use casual_sign_audit::{
    Hash256, NameMatch, PreparedDocument, RemoteCertificate, RemoteFailure, RemoteProvider,
    RemoteSignedDocument, Timestamp,
};
use casual_sign_csc::client::{Client, SHA256_OID};
use casual_sign_csc::{Catalogue, CscError, ProviderSecretsKey, Transport};
use casual_sign_model::{Field, FieldType, FieldValue, Id, RecipientStatus};
use casual_sign_sdk::remote::{
    Appearance, CompleteOptions, ExternalSigner, FillMaterialized, Prepared, Rect,
    SignatureAppearance, SignatureSlot, Visible, admit, fill_materialized, materialize,
};
use casual_sign_sdk::{
    Capture, Certificate, Fill, FlattenOptions, Limits, Profile, SealKind, SealRequest,
    SignatureAlgorithm, TrustStore,
};
use casual_sign_store::EnvelopeId;
use casual_sign_store::blob::{BlobKey, BlobStore};
use casual_sign_store::repo::signing::{RemoteSession, SessionStatus};
use casual_sign_workflow::{Command, EnvelopeState};
use der::Decode as _;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::Worker;
use crate::apply::{apply_in, job_command_id, load_state, system_context, ts};
use crate::error::{Result, WorkerError};
use crate::seal::SealServices;
use crate::webhook::SsrfPolicy;

/// What remote signing needs: the operator's catalogue, the key that seals provider
/// secrets, and the address policy every provider request passes (`SEC-W01`).
pub struct RemoteSigning {
    /// The operator's providers.
    pub catalogue: Arc<Catalogue>,
    /// Opens an account's own client secret and a session's code.
    pub key: Arc<ProviderSecretsKey>,
    /// Addresses a provider may be reached at, besides public ones.
    pub policy: SsrfPolicy,
    /// What signs India eSign requests (`RSP-02`): keyd's ASP key; `None` fails eSign
    /// sessions `provider_unavailable`.
    pub asp: Option<Arc<dyn super::esign::AspSigner>>,
}

impl core::fmt::Debug for RemoteSigning {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RemoteSigning(..)")
    }
}

/// The HTTPS transport to a provider: no redirect, 30-second timeout, answers bounded,
/// every resolved address checked against the policy before each request; plain HTTP
/// only to a loopback host (the catalogue allows nothing else).
struct Http {
    agent: ureq::Agent,
    policy: SsrfPolicy,
}

fn authority(url: &str) -> Option<(String, u16, bool)> {
    let (rest, port, https) = if let Some(r) = url.strip_prefix("https://") {
        (r, 443, true)
    } else {
        (url.strip_prefix("http://")?, 80, false)
    };
    let auth = rest.split(['/', '?', '#']).next()?;
    if auth.contains('@') || auth.is_empty() {
        return None;
    }
    let (host, port) = match auth.rsplit_once(':') {
        Some((h, p)) if !h.ends_with(']') || h.starts_with('[') => {
            (h.trim_matches(['[', ']']).to_owned(), p.parse().ok()?)
        }
        _ => (auth.trim_matches(['[', ']']).to_owned(), port),
    };
    Some((host, port, https))
}

impl Transport for Http {
    fn post(
        &self,
        url: &str,
        content_type: &str,
        bearer: Option<&str>,
        body: &[u8],
    ) -> core::result::Result<(u16, Vec<u8>), CscError> {
        let (host, port, https) = authority(url).ok_or(CscError::AddressRefused)?;
        let loopback = casual_sign_csc::catalogue::is_loopback_host(&host);
        if !https && !loopback {
            return Err(CscError::AddressRefused);
        }
        if !loopback {
            let addrs: Vec<_> = (host.as_str(), port)
                .to_socket_addrs()
                .map_err(|_| CscError::Unavailable)?
                .take(16)
                .collect();
            if addrs.is_empty() || !addrs.iter().all(|a| self.policy.permits(a.ip())) {
                return Err(CscError::AddressRefused);
            }
        }
        let mut req = self.agent.post(url).header("Content-Type", content_type);
        if let Some(t) = bearer {
            req = req.header("Authorization", &format!("Bearer {t}"));
        }
        match req.send(body) {
            Ok(mut r) => {
                let status = r.status().as_u16();
                let bytes = r
                    .body_mut()
                    .with_config()
                    .limit(casual_sign_csc::client::MAX_ANSWER)
                    .read_to_vec()
                    .map_err(|_| CscError::Invalid { what: "answer" })?;
                Ok((status, bytes))
            }
            Err(_) => Err(CscError::Unavailable),
        }
    }
}

fn http(policy: &SsrfPolicy) -> Http {
    let native = rustls_native_certs::load_native_certs();
    let roots: Vec<ureq::tls::Certificate<'static>> = native
        .certs
        .iter()
        .map(|c| ureq::tls::Certificate::from_der(c.as_ref()).to_owned())
        .collect();
    let tls = ureq::tls::TlsConfig::builder()
        .provider(ureq::tls::TlsProvider::Rustls)
        .root_certs(ureq::tls::RootCerts::new_with_certs(&roots))
        .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .build();
    let agent = ureq::Agent::config_builder()
        .tls_config(tls)
        .timeout_global(Some(Duration::from_secs(30)))
        .max_redirects(0)
        .http_status_as_error(false)
        .user_agent("openseal-worker")
        .build()
        .into();
    Http {
        agent,
        policy: policy.clone(),
    }
}

/// One document as a session prepared and, once completed, embedded it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PreparedDoc {
    pub(crate) document_id: String,
    /// The blob the revisions were made from.
    pub(crate) base: String,
    /// The prepared bytes' blob.
    pub(crate) prepared: String,
    pub(crate) byte_range: [u64; 4],
    pub(crate) placeholder_len: usize,
    pub(crate) byte_range_digest: String,
    pub(crate) signed_attributes: String,
    pub(crate) to_be_signed: String,
    pub(crate) first_new_revision: usize,
    /// Field ids materialized at the lock point.
    pub(crate) materialized: Vec<String>,
    /// Of those, the ones filled so far.
    pub(crate) filled: Vec<String>,
    /// The signed revision's blob, once completed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) signed: Option<String>,
    /// eSign (ADR-047): this document's transaction id, `{session}.{n}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) txn: Option<String>,
    /// eSign: the signed request XML's blob, kept with the evidence (§3.6).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) request: Option<String>,
    /// eSign: the ESP's answer's blob, once it arrived and verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) response: Option<String>,
    /// eSign: the `/SubFilter` written at preparation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) format: Option<String>,
}

/// A prepared document's record and its bytes.
pub(crate) type PreparedBytes = (PreparedDoc, Vec<u8>);

/// How a session's documents are prepared: for a CSC credential whose chain is known,
/// or for an ESP's own CMS (ADR-047 §3.2), under the `/SubFilter` the catalogue says.
pub(crate) enum How<'a> {
    /// CSC: our CAdES signed attributes over the credential's chain.
    Csc(&'a ExternalSigner),
    /// eSign: the placeholder planned and the format.
    Esign {
        /// CAdES-conformant (`ETSI.CAdES.detached`) or not (`adbe.pkcs7.detached`).
        cades: bool,
        /// Bytes planned for the ESP's CMS and our time-stamp.
        placeholder: usize,
    },
}

/// A session's `prepared` record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PreparedSession {
    pub(crate) credential_id: String,
    pub(crate) chain: Vec<String>,
    pub(crate) algorithm: String,
    pub(crate) signing_time_ms: i64,
    pub(crate) documents: Vec<PreparedDoc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) qualifier: Option<String>,
}

/// The current state of each document locked so far: the newest completed session that
/// names it.
pub(crate) fn current_revisions(completed: &[RemoteSession]) -> BTreeMap<String, PreparedDoc> {
    let mut out = BTreeMap::new();
    for s in completed {
        let Some(p) = s
            .prepared
            .clone()
            .and_then(|v| serde_json::from_value::<PreparedSession>(v).ok())
        else {
            continue;
        };
        for d in p.documents {
            if d.signed.is_some() {
                out.entry(d.document_id.clone()).or_insert(d);
            }
        }
    }
    out
}

fn algorithm_name(a: SignatureAlgorithm) -> &'static str {
    match a {
        SignatureAlgorithm::EcdsaP256Sha256 => "ecdsa-p256-sha256",
        _ => "rsa-pkcs1-sha256",
    }
}

fn algorithm_from(name: &str) -> SignatureAlgorithm {
    if name == "ecdsa-p256-sha256" {
        SignatureAlgorithm::EcdsaP256Sha256
    } else {
        SignatureAlgorithm::RsaPkcs1Sha256
    }
}

fn sign_algorithm_oid(a: SignatureAlgorithm) -> &'static str {
    match a {
        SignatureAlgorithm::EcdsaP256Sha256 => "1.2.840.10045.4.3.2",
        _ => "1.2.840.113549.1.1.11",
    }
}

/// The algorithm the signer's key signs with: P-256 ECDSA or RSA PKCS#1 v1.5 with
/// SHA-256 (the hashes the session records are SHA-256).
fn algorithm_of(cert: &Certificate) -> Option<(SignatureAlgorithm, String)> {
    let spki = cert.tbs_certificate().subject_public_key_info();
    let oid = spki.algorithm.oid.to_string();
    if oid == "1.2.840.113549.1.1.1" {
        let bits = spki.subject_public_key.raw_bytes().len().saturating_mul(8);
        return Some((
            SignatureAlgorithm::RsaPkcs1Sha256,
            format!("rsa-{}", bits.saturating_sub(bits % 1024).max(2048)),
        ));
    }
    if oid == "1.2.840.10045.2.1" {
        let curve = spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.decode_as::<der::asn1::ObjectIdentifier>().ok())?;
        if curve.to_string() == "1.2.840.10045.3.1.7" {
            return Some((SignatureAlgorithm::EcdsaP256Sha256, "ec-p256".to_owned()));
        }
    }
    None
}

fn common_name(name: &x509_cert::name::Name) -> String {
    for atv in name.iter() {
        if atv.oid.to_string() == "2.5.4.3" {
            if let Ok(s) = atv.value.decode_as::<String>() {
                return s;
            }
            if let Ok(s) = atv.value.decode_as::<der::asn1::PrintableStringRef<'_>>() {
                return s.to_string();
            }
        }
    }
    String::new()
}

fn unix_ts(t: x509_cert::time::Time) -> Option<Timestamp> {
    i64::try_from(t.to_unix_duration().as_millis())
        .ok()
        .and_then(Timestamp::from_unix_millis)
}

/// The key's name as the audit trail records it (`rsa-2048`, `ec-p256`), or empty.
pub(crate) fn key_name(cert: &Certificate) -> String {
    algorithm_of(cert).map(|(_, k)| k).unwrap_or_default()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// What the certificate says, as found (ADR-046 §3.7).
pub(crate) fn certificate_facts(
    cert: &Certificate,
    der: &[u8],
    key: &str,
    qualifier: Option<&str>,
) -> Option<RemoteCertificate> {
    let tbs = cert.tbs_certificate();
    let validity = tbs.validity();
    Some(RemoteCertificate {
        sha256: Hash256::digest(der),
        issuer: tbs.issuer().to_string(),
        serial: hex(tbs.serial_number().as_bytes()),
        not_before: unix_ts(validity.not_before)?,
        not_after: unix_ts(validity.not_after)?,
        subject_cn: casual_sign_audit::Personal(common_name(tbs.subject())),
        key: key.to_owned(),
        qualifier: qualifier.map(str::to_owned),
        qc_statements: Vec::new(),
    })
}

fn fold(s: &str) -> String {
    s.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

/// The certificate's name against the recipient's as sent.
pub(crate) fn name_match(cn: &str, recipient: &str) -> NameMatch {
    if cn.trim() == recipient.trim() {
        NameMatch::Exact
    } else if fold(cn) == fold(recipient) {
        NameMatch::Normalized
    } else {
        NameMatch::Differs
    }
}

pub(crate) fn pem_anchors(pem: &[u8]) -> Vec<Vec<u8>> {
    let text = String::from_utf8_lossy(pem);
    let mut out = Vec::new();
    for block in text.split("-----BEGIN CERTIFICATE-----").skip(1) {
        let Some((body, _)) = block.split_once("-----END CERTIFICATE-----") else {
            continue;
        };
        let b64: String = body.chars().filter(|c| !c.is_whitespace()).collect();
        if let Ok(der) = STANDARD.decode(b64) {
            out.push(der);
        }
    }
    out
}

/// The slot (unsigned signature field) of remote signer `recipient`.
pub(crate) fn slot_name(recipient: &Id) -> String {
    format!("Remote_{}", recipient.as_str())
}

/// The first signature field of `recipient` on `document`.
fn first_signature<'a>(fields: &'a [Field], recipient: &Id, document: &Id) -> Option<&'a Field> {
    fields.iter().find(|f| {
        f.document_id == *document
            && f.recipient_id.as_ref() == Some(recipient)
            && f.field_type == FieldType::Signature
    })
}

/// Captures for the signature values of `fields`, captioned with their signer's name.
fn captures_for(
    fields: &[Field],
    state: &EnvelopeState,
    arts: &BTreeMap<String, casual_sign_sdk::Art>,
) -> BTreeMap<Id, Capture> {
    let mut caps = BTreeMap::new();
    for f in fields {
        if let Some(FieldValue::Signature(cap)) = &f.value
            && let Some(art) = arts.get(cap.as_str())
        {
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
    caps
}

/// One document to prepare, with its current bytes.
pub(crate) struct DocIn {
    pub(crate) id: Id,
    pub(crate) bytes: Vec<u8>,
    pub(crate) current: Option<PreparedDoc>,
}

/// The failure a pipeline step ends the session with.
fn invalid(code: &'static str) -> (RemoteFailure, String) {
    (RemoteFailure::ResponseInvalid, code.to_owned())
}

/// Prepare every document (blocking): the revisions of ADR-046 §3.2 and `prepare`.
#[allow(clippy::too_many_lines)]
// One pass per document, in the ADR's order.
pub(crate) fn prepare_documents(
    services: &SealServices,
    state: &EnvelopeState,
    signer_id: &Id,
    how: &How<'_>,
    docs: Vec<DocIn>,
    arts: &BTreeMap<String, casual_sign_sdk::Art>,
    signing_time: Duration,
) -> core::result::Result<Vec<PreparedBytes>, (RemoteFailure, String)> {
    let never = || false;
    let fields = &state.fields.0;
    let caps = captures_for(fields, state, arts);
    let completed: BTreeSet<&Id> = state
        .recipients
        .iter()
        .filter(|r| r.status == RecipientStatus::Completed)
        .map(|r| r.id())
        .collect();
    let remote_signers: Vec<&Id> = state
        .recipients
        .iter()
        .filter(|r| !r.spec.signature.is_simple())
        .map(|r| r.id())
        .collect();
    let mut options = FlattenOptions::default();
    options.envelope_id_stamp = state.options.stamp_envelope_id;
    let bound = (services.timestamps)().token_len_bound();
    let mut out = Vec::with_capacity(docs.len());
    for d in docs {
        let on_doc: Vec<Field> = fields
            .iter()
            .filter(|f| f.document_id == d.id)
            .cloned()
            .collect();
        let widget_of = |r: &Id| first_signature(&on_doc, r, &d.id).map(|f| f.id.clone());
        let widgets: BTreeSet<Id> = remote_signers.iter().filter_map(|r| widget_of(r)).collect();
        let (base, materialized, mut filled) = match &d.current {
            Some(c) => (d.bytes.clone(), c.materialized.clone(), c.filled.clone()),
            None => {
                // R0: what is final now is flattened; the rest materialized.
                let is_final = |f: &Field| match &f.recipient_id {
                    None => true,
                    Some(r) => completed.contains(r) || r == signer_id,
                };
                let final_fields: Vec<Field> = on_doc
                    .iter()
                    .filter(|f| is_final(f) && !widgets.contains(&f.id))
                    .cloned()
                    .collect();
                let unfinished: Vec<Field> = on_doc
                    .iter()
                    .filter(|f| !is_final(f) && !widgets.contains(&f.id))
                    .cloned()
                    .collect();
                let values = BTreeMap::new();
                let flat = services
                    .engine
                    .fill_and_flatten(
                        &d.bytes,
                        &Fill {
                            fields: &final_fields,
                            values: &values,
                            captures: &caps,
                            envelope_id: Some(state.id.as_str()),
                            acroform: None,
                            require_complete: false,
                        },
                        &options,
                    )
                    .map_err(|e| invalid(e.code()))?
                    .bytes;
                let slot_names: Vec<(String, Option<Field>)> = remote_signers
                    .iter()
                    .filter(|r| state.recipient(r).is_some_and(|x| x.spec.sees(&d.id)))
                    .map(|r| (slot_name(r), first_signature(&on_doc, r, &d.id).cloned()))
                    .collect();
                let slots: Vec<SignatureSlot<'_>> = slot_names
                    .iter()
                    .map(|(n, f)| SignatureSlot {
                        name: n,
                        at: f.as_ref(),
                    })
                    .collect();
                let mut a =
                    admit(&flat, &Limits::default(), &never).map_err(|e| invalid(e.code()))?;
                let r0 = materialize(&mut a, &unfinished, &slots, &never)
                    .map_err(|e| invalid(e.code()))?;
                (
                    r0,
                    unfinished
                        .iter()
                        .map(|f| f.id.as_str().to_owned())
                        .collect::<Vec<_>>(),
                    Vec::new(),
                )
            }
        };
        // Rk: every materialized value now final, the signer's own included.
        let to_fill: Vec<Field> = on_doc
            .iter()
            .filter(|f| {
                materialized.iter().any(|m| m == f.id.as_str())
                    && !filled.iter().any(|x| x == f.id.as_str())
                    && f.value.is_some()
                    && f.recipient_id
                        .as_ref()
                        .is_some_and(|r| completed.contains(r) || r == signer_id)
            })
            .cloned()
            .collect();
        let values: BTreeMap<Id, FieldValue> = to_fill
            .iter()
            .filter_map(|f| f.value.clone().map(|v| (f.id.clone(), v)))
            .collect();
        let own = first_signature(&on_doc, signer_id, &d.id).cloned();
        let slot = slot_name(signer_id);
        let capture = own.as_ref().and_then(|f| match &f.value {
            Some(FieldValue::Signature(c)) => Some(c.clone()),
            _ => None,
        });
        let appearance = match (&own, &capture) {
            (Some(f), Some(c)) => Some(SignatureAppearance {
                slot: &slot,
                field: f,
                capture: c,
            }),
            _ => None,
        };
        let mut a = admit(&base, &Limits::default(), &never).map_err(|e| invalid(e.code()))?;
        let filled_doc = fill_materialized(
            &mut a,
            &FillMaterialized {
                fields: &to_fill,
                values: &values,
                captures: &caps,
                envelope_id: Some(state.id.as_str()),
                signature: appearance,
            },
            &services.fonts,
            &options,
            &never,
        )
        .map_err(|e| invalid(e.code()))?;
        filled.extend(to_fill.iter().map(|f| f.id.as_str().to_owned()));
        let mut request = SealRequest::new(Profile::BaselineLt, &slot, signing_time);
        request.kind = SealKind::Approval;
        request.trust = services.trust.clone();
        request.name = state
            .recipient(signer_id)
            .map(|r| r.spec.name.get().as_str().to_owned());
        request.visible = filled_doc.signature.map(|s| Visible {
            page: 0,
            rect: Rect {
                llx: 0.0,
                lly: 0.0,
                urx: 0.0,
                ury: 0.0,
            },
            appearance: Appearance::Content {
                content: s.content(),
                resources: Some(s.resources()),
            },
        });
        let doc = |bytes: &[u8],
                   byte_range: [u64; 4],
                   placeholder_len: usize,
                   digest: &[u8],
                   attrs: &[u8],
                   tbs: &[u8],
                   first: usize,
                   format: Option<String>| PreparedDoc {
            document_id: d.id.as_str().to_owned(),
            base: BlobKey::of(&d.bytes).hex(),
            prepared: BlobKey::of(bytes).hex(),
            byte_range,
            placeholder_len,
            byte_range_digest: STANDARD.encode(digest),
            signed_attributes: STANDARD.encode(attrs),
            to_be_signed: STANDARD.encode(tbs),
            first_new_revision: first,
            materialized: materialized.clone(),
            filled: filled.clone(),
            signed: None,
            txn: None,
            request: None,
            response: None,
            format,
        };
        match how {
            How::Csc(signer) => {
                let p =
                    casual_sign_sdk::remote::prepare(&filled_doc.bytes, &request, signer, bound)
                        .map_err(|e| invalid(e.code()))?;
                let record = doc(
                    &p.bytes,
                    p.byte_range,
                    p.placeholder_len,
                    &p.byte_range_digest,
                    &p.signed_attributes,
                    &p.to_be_signed,
                    p.first_new_revision,
                    None,
                );
                out.push((record, p.bytes));
            }
            How::Esign { cades, placeholder } => {
                let format = if *cades {
                    casual_sign_sdk::remote::CmsFormat::Cades
                } else {
                    casual_sign_sdk::remote::CmsFormat::Pkcs7
                };
                let p = casual_sign_sdk::remote::prepare_for_cms(
                    &filled_doc.bytes,
                    &request,
                    format,
                    *placeholder,
                )
                .map_err(|e| invalid(e.code()))?;
                let record = doc(
                    &p.bytes,
                    p.byte_range,
                    p.placeholder_len,
                    &p.byte_range_digest,
                    &[],
                    &p.byte_range_digest,
                    p.first_new_revision,
                    Some(format.sub_filter().to_owned()),
                );
                out.push((record, p.bytes));
            }
        }
    }
    Ok(out)
}

/// The audit trail's record of one prepared document.
pub(crate) fn prepared_document(doc: &PreparedDoc, bytes: &[u8], rid: &Id) -> PreparedDocument {
    PreparedDocument {
        document_id: Id::new(doc.document_id.clone()).unwrap_or_else(|_| rid.clone()),
        base_hash: Hash256(BlobKey::parse(&doc.base).map(|k| k.0).unwrap_or_default()),
        prepared_hash: Hash256::digest(bytes),
        byte_range: doc.byte_range,
        byte_range_digest: hash32(&doc.byte_range_digest).unwrap_or_default(),
        to_be_signed: hash32(&doc.to_be_signed).unwrap_or_default(),
        lock_point: false,
        txn: doc.txn.clone(),
    }
}

pub(crate) fn hash32(b64: &str) -> Option<Hash256> {
    let v = STANDARD.decode(b64).ok()?;
    <[u8; 32]>::try_from(v.as_slice()).ok().map(Hash256)
}

/// What a finished phase leaves for the database.
pub(crate) enum Outcome {
    /// Prepared: blobs to store, the session record and the engine's command.
    Prepared {
        blobs: Vec<Vec<u8>>,
        record: PreparedSession,
        command: Command,
    },
    /// Signed: blobs, the record with each signed revision, the engine's command.
    Signed {
        blobs: Vec<Vec<u8>>,
        record: PreparedSession,
        command: Command,
    },
    /// The session fails.
    Failed(RemoteFailure, Option<String>),
}

impl<B: BlobStore + 'static> Worker<B> {
    /// Offer remote signing through `rsp` (`RSP-01`).
    #[must_use]
    pub fn with_remote_signing(mut self, rsp: Arc<RemoteSigning>) -> Self {
        self.rsp = Some(rsp);
        self
    }

    /// A `remote_signing` job.
    pub(super) async fn remote_signing(
        &self,
        job: &casual_sign_store::ClaimedJob,
        lease: Uuid,
    ) -> Result<()> {
        let bad = || WorkerError::BadJob {
            kind: job.kind.clone(),
        };
        let p: casual_sign_host::jobs::RemoteSigningJob =
            serde_json::from_value(job.payload.clone()).map_err(|_| bad())?;
        let envelope = EnvelopeId(p.envelope_id);
        if job.envelope_id != Some(envelope) {
            return Err(bad());
        }
        let mut tx = self.store.for_account(job.account_id).begin().await?;
        let session = tx.signing().session(p.session).await?;
        let state = load_state(&mut tx, envelope).await?;
        let (Some(session), Some(state)) = (session, state) else {
            return self.close_job(tx, job, lease).await;
        };
        if session.closed_at.is_some()
            || !matches!(
                session.status,
                SessionStatus::Preparing | SessionStatus::Signing
            )
        {
            return self.close_job(tx, job, lease).await;
        }
        let row = tx.signing().provider(&session.provider_id).await?;
        let completed = tx.signing().completed_for(envelope).await?;
        let code = tx.signing().take_code(session.id, session.status).await?;
        tx.commit().await?;
        let rid = Id::new(session.recipient_id.0.to_string()).map_err(|_| bad())?;
        let outcome = match self
            .run_phase(
                job.account_id,
                envelope,
                &session,
                &state,
                &rid,
                row.as_ref(),
                &completed,
                code,
            )
            .await
        {
            Ok(o) => o,
            Err(WorkerError::Store(e)) => return Err(WorkerError::Store(e)),
            Err(e) => Outcome::Failed(RemoteFailure::ProviderUnavailable, Some(e.code().into())),
        };
        let now = self.now();
        let cid = job_command_id(job.id)?;
        let c = system_context(cid, ts(now)?, self.config.policy.clone());
        let mut tx = self.store.for_account(job.account_id).begin().await?;
        let session_id = Id::new(session.id.to_string()).map_err(|_| bad())?;
        match outcome {
            Outcome::Prepared {
                blobs,
                record,
                command,
            } => {
                for b in &blobs {
                    self.blobs.put(b).await?;
                }
                let value = serde_json::to_value(&record).map_err(|_| bad())?;
                match apply_in(&mut tx, envelope, &command, &c).await {
                    Ok(_) => {
                        // An eSign session has no credential (the ESP issues it).
                        let credential =
                            Some(record.credential_id.as_str()).filter(|c| !c.is_empty());
                        tx.signing()
                            .advance(
                                session.id,
                                SessionStatus::Prepared,
                                None,
                                None,
                                credential,
                                None,
                                Some(&value),
                            )
                            .await?;
                    }
                    Err(WorkerError::Workflow { code }) => {
                        drop(tx);
                        tx = self.store.for_account(job.account_id).begin().await?;
                        tx.signing()
                            .close(session.id, Some("response_invalid"), Some(code), now)
                            .await?;
                    }
                    Err(e) => return Err(e),
                }
            }
            Outcome::Signed {
                blobs,
                record,
                command,
            } => {
                for b in &blobs {
                    self.blobs.put(b).await?;
                }
                let value = serde_json::to_value(&record).map_err(|_| bad())?;
                match apply_in(&mut tx, envelope, &command, &c).await {
                    Ok(_) => {
                        tx.signing().complete(session.id, &value, now).await?;
                    }
                    Err(WorkerError::Workflow { code }) => {
                        drop(tx);
                        tx = self.store.for_account(job.account_id).begin().await?;
                        tx.signing()
                            .close(session.id, Some("response_invalid"), Some(code), now)
                            .await?;
                    }
                    Err(e) => return Err(e),
                }
            }
            Outcome::Failed(reason, provider_code) => {
                let reason_text = serde_json::to_value(reason)
                    .ok()
                    .and_then(|v| v.as_str().map(str::to_owned))
                    .unwrap_or_else(|| "provider_unavailable".into());
                let cmd = Command::FailRemoteSigning {
                    recipient: rid.clone(),
                    session: session_id,
                    reason,
                    provider_code: provider_code.clone(),
                };
                crate::log(
                    "INFO",
                    "remote_signing_failed",
                    &[
                        ("session", session.id.to_string()),
                        ("reason", reason_text.clone()),
                        // The check that ended it: a docs/20 code or the provider's
                        // own short code, never a message (RSP-02).
                        ("code", provider_code.clone().unwrap_or_default()),
                    ],
                );
                match apply_in(&mut tx, envelope, &cmd, &c).await {
                    Ok(_) | Err(WorkerError::Workflow { .. }) => {}
                    Err(e) => return Err(e),
                }
                let code = provider_code
                    .filter(|c| {
                        c.bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
                    })
                    .map(|c| c.chars().take(64).collect::<String>());
                tx.signing()
                    .close(session.id, Some(&reason_text), code.as_deref(), now)
                    .await?;
            }
        }
        self.close_job(tx, job, lease).await
    }

    #[allow(clippy::too_many_arguments, clippy::too_many_lines)]
    // One phase of the session; its inputs read once above.
    async fn run_phase(
        &self,
        account: casual_sign_store::AccountId,
        envelope: EnvelopeId,
        session: &RemoteSession,
        state: &EnvelopeState,
        rid: &Id,
        row: Option<&casual_sign_store::repo::signing::AccountProvider>,
        completed: &[RemoteSession],
        code: Option<Vec<u8>>,
    ) -> Result<Outcome> {
        let Some(rsp) = self.rsp.clone() else {
            return Ok(Outcome::Failed(RemoteFailure::ProviderUnavailable, None));
        };
        let Some(provider) = rsp.catalogue.get(&session.provider_id) else {
            return Ok(Outcome::Failed(RemoteFailure::ProviderRefused, None));
        };
        let Some(row) = row.filter(|r| r.enabled) else {
            return Ok(Outcome::Failed(RemoteFailure::ProviderRefused, None));
        };
        // India eSign (RSP-02): no OAuth code; the ESP's answers are stored blobs.
        if provider.esign.is_some() {
            return self
                .esign_phase(account, envelope, session, state, rid, completed)
                .await;
        }
        let acct = account.0;
        let sid = session.id;
        // The code and PKCE verifier, sealed by the server, opened once.
        let Some(sealed) = code else {
            return Ok(Outcome::Failed(RemoteFailure::Expired, None));
        };
        let opened = rsp
            .key
            .open(
                &sealed,
                &casual_sign_csc::sealing::session_binding(acct.as_bytes(), sid.as_bytes(), "code"),
            )
            .map_err(|_| WorkerError::Pipeline {
                code: "CS-RSP-0009",
            })?;
        #[derive(Deserialize)]
        struct CodeIn {
            code: String,
            verifier: String,
        }
        let c: CodeIn = serde_json::from_slice(&opened).map_err(|_| WorkerError::Pipeline {
            code: "CS-RSP-0009",
        })?;
        let secret = match &row.client_secret_sealed {
            Some(s) => String::from_utf8(
                rsp.key
                    .open(
                        s,
                        &casual_sign_csc::sealing::client_secret_binding(
                            acct.as_bytes(),
                            &provider.id,
                        ),
                    )
                    .map_err(|_| WorkerError::Pipeline {
                        code: "CS-RSP-0009",
                    })?,
            )
            .map_err(|_| WorkerError::Pipeline {
                code: "CS-RSP-0009",
            })?,
            None => provider.client_secret.expose().to_owned(),
        };
        let provider_ref = RemoteProvider {
            id: Id::new(provider.id.clone()).map_err(|_| WorkerError::StateUnreadable)?,
            kind: provider.kind.as_str().to_owned(),
            name: provider.name.clone(),
        };
        let session_id = Id::new(sid.to_string()).map_err(|_| WorkerError::StateUnreadable)?;
        let services = self.seal.clone();
        let anchors = provider.trust_anchors_pem.clone();
        let policy = rsp.policy.clone();
        let catalogue = Arc::clone(&rsp.catalogue);
        let provider_id = provider.id.clone();
        match session.status {
            SessionStatus::Preparing => {
                // Inputs read now; the provider and the PDF work run blocking.
                let input = self.gather(account, envelope, state.clone(), true).await?;
                let current = current_revisions(completed);
                let visible: Vec<(Id, Vec<u8>, Option<PreparedDoc>)> = {
                    let mut v = Vec::new();
                    let me = state.recipient(rid).ok_or(WorkerError::StateUnreadable)?;
                    for (d, delivered) in state.documents.iter().zip(&input.delivered) {
                        if !me.spec.sees(d.id()) {
                            continue;
                        }
                        let cur = current.get(d.id().as_str()).cloned();
                        let bytes = match &cur {
                            Some(c) => {
                                let key = BlobKey::parse(c.signed.as_deref().unwrap_or(""))
                                    .map_err(|_| WorkerError::StateUnreadable)?;
                                self.blob_or(&key, "document").await?
                            }
                            None => delivered.clone(),
                        };
                        v.push((d.id().clone(), bytes, cur));
                    }
                    v
                };
                let required = row.required_qualifiers.clone();
                let state = state.clone();
                let rid = rid.clone();
                let now = self.now();
                let signing_time =
                    Duration::from_millis(u64::try_from(ts(now)?.unix_millis()).unwrap_or(0));
                let signing_ms = ts(now)?.unix_millis();
                let arts = input.captures.clone();
                let result = tokio::task::spawn_blocking(move || {
                    let Some(provider) = catalogue.get(&provider_id) else {
                        return Outcome::Failed(RemoteFailure::ProviderRefused, None);
                    };
                    let t = http(&policy);
                    let client = Client::new(provider, &secret, &t);
                    let fail = |e: CscError| {
                        let reason = match e.session_failure() {
                            "cancelled" => RemoteFailure::Cancelled,
                            "expired" => RemoteFailure::Expired,
                            "provider_refused" => RemoteFailure::ProviderRefused,
                            "response_invalid" => RemoteFailure::ResponseInvalid,
                            "no_eligible_credential" => RemoteFailure::NoEligibleCredential,
                            _ => RemoteFailure::ProviderUnavailable,
                        };
                        Outcome::Failed(reason, e.provider_code().map(str::to_owned))
                    };
                    let token = match client.token(&c.code, &c.verifier) {
                        Ok(t) => t,
                        Err(e) => return fail(e),
                    };
                    let ids = match client.credentials(&token) {
                        Ok(i) => i,
                        Err(e) => return fail(e),
                    };
                    let mut chosen = None;
                    for id in ids {
                        let info = match client.info(&token, &id) {
                            Ok(i) => i,
                            Err(e) => return fail(e),
                        };
                        if !info.eligible(&required) {
                            continue;
                        }
                        let Some(leaf) = info.chain.first() else {
                            continue;
                        };
                        let Ok(cert) = Certificate::from_der(leaf) else {
                            continue;
                        };
                        if let Some((alg, _)) = algorithm_of(&cert) {
                            chosen = Some((info, alg));
                            break;
                        }
                    }
                    let Some((info, alg)) = chosen else {
                        return Outcome::Failed(RemoteFailure::NoEligibleCredential, None);
                    };
                    let Ok(chain) = info
                        .chain
                        .iter()
                        .map(|d| Certificate::from_der(d))
                        .collect::<core::result::Result<Vec<_>, _>>()
                    else {
                        return Outcome::Failed(RemoteFailure::ResponseInvalid, None);
                    };
                    let signer = ExternalSigner {
                        chain,
                        algorithm: alg,
                    };
                    let docs: Vec<DocIn> = visible
                        .into_iter()
                        .map(|(id, bytes, current)| DocIn { id, bytes, current })
                        .collect();
                    let bases: Vec<Vec<u8>> = docs.iter().map(|d| d.bytes.clone()).collect();
                    let prepared = match prepare_documents(
                        &services,
                        &state,
                        &rid,
                        &How::Csc(&signer),
                        docs,
                        &arts,
                        signing_time,
                    ) {
                        Ok(p) => p,
                        Err((reason, code)) => return Outcome::Failed(reason, Some(code)),
                    };
                    let mut blobs = bases;
                    let mut documents = Vec::new();
                    let mut records = Vec::new();
                    for (doc, bytes) in prepared {
                        documents.push(prepared_document(&doc, &bytes, &rid));
                        blobs.push(bytes);
                        records.push(doc);
                    }
                    let leaf_der = info.chain.first().cloned().unwrap_or_default();
                    Outcome::Prepared {
                        blobs,
                        record: PreparedSession {
                            credential_id: info.id.clone(),
                            chain: info.chain.iter().map(|c| STANDARD.encode(c)).collect(),
                            algorithm: algorithm_name(alg).to_owned(),
                            signing_time_ms: signing_ms,
                            documents: records,
                            qualifier: info.signature_qualifier.clone(),
                        },
                        command: Command::RemoteSigningPrepared {
                            recipient: rid.clone(),
                            session: session_id,
                            documents,
                            certificate_sha256: Some(Hash256::digest(&leaf_der)),
                        },
                    }
                })
                .await
                .map_err(|_| WorkerError::Pipeline {
                    code: "CS-RSP-0002",
                })?;
                Ok(result)
            }
            SessionStatus::Signing => {
                let record: PreparedSession = session
                    .prepared
                    .clone()
                    .and_then(|v| serde_json::from_value(v).ok())
                    .ok_or(WorkerError::StateUnreadable)?;
                let mut prepared_bytes = Vec::new();
                for d in &record.documents {
                    let key =
                        BlobKey::parse(&d.prepared).map_err(|_| WorkerError::StateUnreadable)?;
                    prepared_bytes.push(self.blob_or(&key, "document").await?);
                }
                let name = state
                    .recipient(rid)
                    .map(|r| r.spec.name.get().as_str().to_owned())
                    .unwrap_or_default();
                let rid = rid.clone();
                let result = tokio::task::spawn_blocking(move || {
                    sign_phase(
                        &catalogue,
                        &provider_id,
                        &secret,
                        &policy,
                        &services,
                        &anchors,
                        &c.code,
                        &c.verifier,
                        record,
                        prepared_bytes,
                        &rid,
                        &session_id,
                        &provider_ref,
                        &name,
                    )
                })
                .await
                .map_err(|_| WorkerError::Pipeline {
                    code: "CS-RSP-0002",
                })?;
                Ok(result)
            }
            _ => Ok(Outcome::Failed(RemoteFailure::ResponseInvalid, None)),
        }
    }
}

/// The signing phase (blocking): `signHash` over every prepared hash, then `complete`.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
// The phase's inputs, gathered by the caller.
fn sign_phase(
    catalogue: &Catalogue,
    provider_id: &str,
    secret: &str,
    policy: &SsrfPolicy,
    services: &SealServices,
    anchors_pem: &[u8],
    code: &str,
    verifier: &str,
    mut record: PreparedSession,
    prepared_bytes: Vec<Vec<u8>>,
    rid: &Id,
    session_id: &Id,
    provider: &RemoteProvider,
    recipient_name: &str,
) -> Outcome {
    let Some(p) = catalogue.get(provider_id) else {
        return Outcome::Failed(RemoteFailure::ProviderRefused, None);
    };
    let t = http(policy);
    let client = Client::new(p, secret, &t);
    let fail = |e: CscError| {
        let reason = match e.session_failure() {
            "cancelled" => RemoteFailure::Cancelled,
            "expired" => RemoteFailure::Expired,
            "provider_refused" => RemoteFailure::ProviderRefused,
            "response_invalid" => RemoteFailure::ResponseInvalid,
            _ => RemoteFailure::ProviderUnavailable,
        };
        Outcome::Failed(reason, e.provider_code().map(str::to_owned))
    };
    let token = match client.token(code, verifier) {
        Ok(t) => t,
        Err(e) => return fail(e),
    };
    let alg = algorithm_from(&record.algorithm);
    let Some(hashes) = record
        .documents
        .iter()
        .map(|d| STANDARD.decode(&d.to_be_signed).ok())
        .collect::<Option<Vec<_>>>()
    else {
        return Outcome::Failed(RemoteFailure::ResponseInvalid, None);
    };
    let values = match client.sign_hash(
        &token,
        &record.credential_id,
        &hashes,
        SHA256_OID,
        sign_algorithm_oid(alg),
    ) {
        Ok(v) => v,
        Err(e) => return fail(e),
    };
    let Some(chain_der) = record
        .chain
        .iter()
        .map(|c| STANDARD.decode(c).ok())
        .collect::<Option<Vec<_>>>()
    else {
        return Outcome::Failed(RemoteFailure::ResponseInvalid, None);
    };
    let Ok(chain) = chain_der
        .iter()
        .map(|d| Certificate::from_der(d))
        .collect::<core::result::Result<Vec<_>, _>>()
    else {
        return Outcome::Failed(RemoteFailure::ResponseInvalid, None);
    };
    let mut trust: TrustStore = services.trust.clone();
    for a in pem_anchors(anchors_pem) {
        let _ = trust.add_anchor(&a);
    }
    for c in chain_der.iter().skip(1) {
        let _ = trust.add_intermediate(c);
    }
    let options = CompleteOptions {
        trust,
        limits: Limits::default(),
    };
    let signing_time = Duration::from_millis(u64::try_from(record.signing_time_ms).unwrap_or(0));
    let mut blobs = Vec::new();
    let mut signed_docs = Vec::new();
    for ((doc, bytes), value) in record.documents.iter_mut().zip(prepared_bytes).zip(values) {
        let decode = |s: &str| STANDARD.decode(s).unwrap_or_default();
        let prepared = Prepared {
            bytes,
            byte_range: doc.byte_range,
            placeholder_len: doc.placeholder_len,
            byte_range_digest: decode(&doc.byte_range_digest),
            signed_attributes: decode(&doc.signed_attributes),
            to_be_signed: decode(&doc.to_be_signed),
            signer: ExternalSigner {
                chain: chain.clone(),
                algorithm: alg,
            },
            profile: Profile::BaselineLt,
            kind: SealKind::Approval,
            signing_time,
            first_new_revision: doc.first_new_revision,
        };
        let tsa = (services.timestamps)();
        let revocation = (services.revocation)();
        let sealed = match casual_sign_sdk::remote::complete(
            &prepared,
            &value,
            tsa.as_ref(),
            revocation.as_ref(),
            &options,
        ) {
            Ok(s) => s,
            Err(e) => {
                let reason = match e.code() {
                    "CS-RSP-0005" => RemoteFailure::PlaceholderOverflow,
                    "CS-SEAL-0002" | "CS-SEAL-0004" => RemoteFailure::ProviderUnavailable,
                    _ => RemoteFailure::ResponseInvalid,
                };
                return Outcome::Failed(reason, Some(e.code().to_owned()));
            }
        };
        let a = prepared.byte_range[1];
        let b = prepared.byte_range[2];
        let cms = usize::try_from(a)
            .ok()
            .zip(usize::try_from(b).ok())
            .and_then(|(a, b)| sealed.bytes.get(a.saturating_add(1)..b.saturating_sub(1)))
            .map(Hash256::digest)
            .unwrap_or_default();
        let key = BlobKey::of(&sealed.bytes);
        doc.signed = Some(key.hex());
        signed_docs.push(RemoteSignedDocument {
            document_id: Id::new(doc.document_id.clone()).unwrap_or_else(|_| rid.clone()),
            revision_hash: Hash256::digest(&sealed.bytes),
            signature_sha256: cms,
            timestamp_time: sealed
                .report
                .signature_timestamp
                .and_then(|d| i64::try_from(d.as_millis()).ok())
                .and_then(Timestamp::from_unix_millis),
            certificate_sha256: None,
            request_sha256: None,
            response_sha256: None,
            signature_format: None,
        });
        blobs.push(sealed.bytes);
    }
    let Some((leaf, leaf_der)) = chain.first().zip(chain_der.first()) else {
        return Outcome::Failed(RemoteFailure::ResponseInvalid, None);
    };
    let key_name = algorithm_of(leaf).map(|(_, k)| k).unwrap_or_default();
    let Some(certificate) =
        certificate_facts(leaf, leaf_der, &key_name, record.qualifier.as_deref())
    else {
        return Outcome::Failed(RemoteFailure::ResponseInvalid, None);
    };
    let matched = name_match(certificate.subject_cn.get(), recipient_name);
    Outcome::Signed {
        blobs,
        command: Command::CompleteRemoteSigning {
            recipient: rid.clone(),
            session: session_id.clone(),
            provider: provider.clone(),
            provider_reference: None,
            certificate: Box::new(certificate),
            name_match: matched,
            documents: signed_docs,
            esign: None,
        },
        record,
    }
}

#[cfg(test)]
// Tests may unwrap (CLAUDE.md).
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn names_match_exactly_after_folding_or_not_at_all() {
        assert_eq!(name_match("Ann Lee", "Ann Lee"), NameMatch::Exact);
        assert_eq!(name_match("ANN  lee", "Ann Lee"), NameMatch::Normalized);
        assert_eq!(name_match("Bob Lee", "Ann Lee"), NameMatch::Differs);
    }

    #[test]
    fn authorities_are_read_and_credentials_refused() {
        assert_eq!(
            authority("http://127.0.0.1:8091/csc/v2"),
            Some(("127.0.0.1".into(), 8091, false))
        );
        assert_eq!(
            authority("https://csc.example.test/x"),
            Some(("csc.example.test".into(), 443, true))
        );
        assert_eq!(authority("https://u@csc.example.test/"), None);
        assert_eq!(authority("ftp://x/"), None);
    }
}
