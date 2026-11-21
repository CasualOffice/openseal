//! The worker's half of an India eSign session (`RSP-02`, ADR-047), OpenSeal the ASP.
//!
//! - **`prepare`**: the documents the signer sees are prepared as for CSC (the lock
//!   point, the fills), each laid out for the ESP's own CMS under the `/SubFilter` the
//!   catalogue says (`prepare_for_cms`); then one v2.1 request per document
//!   (`txn` = `{session}.{n}`, the SHA-256 ByteRange digest as `InputHash`, no Aadhaar
//!   data), signed by the ASP key in keyd with the database's ASP token for this open
//!   session. The prepared bytes and the signed requests are stored (the requests are
//!   evidence, §3.6), `RemoteSigningPrepared` records the hashes and `txn`s, and the
//!   page hands each request to the ESP in turn.
//! - **`sign`**: every document answered; each answer is read again and verified under
//!   the ESP's configured certificate, its errors mapped to the session's result
//!   (§3.9), and each CMS checked and embedded (`complete_cms`: our time-stamp unless it
//!   has one that verifies, the DSS at once); `CompleteRemoteSigning` records the ESP's
//!   `resCode`, the request and response hashes and the format.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use casual_sign_audit::{
    EsignSigned, Hash256, RemoteFailure, RemoteProvider, RemoteSignedDocument, Timestamp,
};
use casual_sign_csc::catalogue::Esign;
use casual_sign_esign::{Algorithm, AuthMode, EsignError, Request, Status, VerifyingKey};
use casual_sign_model::Id;
use casual_sign_sdk::remote::{CmsFormat, CompleteOptions, PreparedForCms};
use casual_sign_sdk::{Certificate, Limits, Profile, SealKind, TrustStore};
use casual_sign_store::blob::BlobKey;
use casual_sign_workflow::{Command, EnvelopeState};
use der::Decode as _;

use super::rsp::{
    DocIn, How, Outcome, PreparedSession, certificate_facts, name_match, pem_anchors,
    prepare_documents, prepared_document,
};
use crate::seal::SealServices;

/// What signs an ASP request: keyd's ASP key (alias `asp-*`) for the session, with the
/// database's ASP token (ADR-047 §3.5). Tests give a local key.
pub trait AspSigner: Send + Sync {
    /// The algorithm of the key `alias`.
    ///
    /// # Errors
    /// keyd's code, or `CS-RSP-0010` for a key the profile does not take.
    fn algorithm(&self, alias: &str) -> Result<Algorithm, &'static str>;

    /// Sign `digest` (SHA-256) with `alias` for `session`, presenting `token`; the value,
    /// the key's algorithm and the certificate (DER) to put in `KeyInfo`.
    ///
    /// # Errors
    /// keyd's code (`CS-KEY-0015` without a valid ASP token).
    fn sign(
        &self,
        alias: &str,
        session: &str,
        token: Option<casual_sign_keyd::SealToken>,
        digest: &[u8],
    ) -> Result<(Vec<u8>, Algorithm, Vec<u8>), &'static str>;
}

/// keyd as the [`AspSigner`].
#[derive(Debug)]
pub struct KeydAsp {
    /// keyd's address and this worker's mTLS identity.
    pub endpoint: casual_sign_keyd::Endpoint,
}

fn profile_algorithm(a: casual_sign_sdk::SignatureAlgorithm) -> Result<Algorithm, &'static str> {
    match a {
        casual_sign_sdk::SignatureAlgorithm::EcdsaP256Sha256 => Ok(Algorithm::EcdsaP256Sha256),
        casual_sign_sdk::SignatureAlgorithm::RsaPkcs1Sha256 => Ok(Algorithm::RsaSha256),
        _ => Err("CS-RSP-0010"),
    }
}

impl AspSigner for KeydAsp {
    fn algorithm(&self, alias: &str) -> Result<Algorithm, &'static str> {
        use casual_sign_keyd::DigestSigner as _;
        let r = crate::seal::connect_keyd(self.endpoint.clone(), alias).map_err(|e| e.code())?;
        profile_algorithm(r.algorithm())
    }

    fn sign(
        &self,
        alias: &str,
        session: &str,
        token: Option<casual_sign_keyd::SealToken>,
        digest: &[u8],
    ) -> Result<(Vec<u8>, Algorithm, Vec<u8>), &'static str> {
        use casual_sign_keyd::DigestSigner as _;
        let r = crate::seal::connect_keyd(self.endpoint.clone(), alias)
            .and_then(|r| r.for_envelope(session))
            .map_err(|e| e.code())?;
        let r = match token {
            Some(t) => r.with_seal_token(t),
            None => r,
        };
        let alg = profile_algorithm(r.algorithm())?;
        let cert = r
            .certificate_chain()
            .first()
            .and_then(|c| der::Encode::to_der(c).ok())
            .ok_or("CS-RSP-0010")?;
        let value = r.sign_digest(digest).map_err(|e| e.code())?;
        Ok((value, alg, cert))
    }
}

/// The transaction id of document `n` (1-based) of `session` (ADR-047 §3.1: unique per
/// ASP and ESP, a UUIDv7 session id with the document's place).
#[must_use]
pub fn txn_of(session: &str, n: usize) -> String {
    format!("{session}.{n}")
}

/// The session and document a `txn` names.
#[must_use]
pub fn parse_txn(txn: &str) -> Option<(uuid::Uuid, usize)> {
    let (s, n) = txn.rsplit_once('.')?;
    let n: usize = n.parse().ok().filter(|n| (1..=64).contains(n))?;
    Some((uuid::Uuid::parse_str(s).ok()?, n))
}

/// The state hash the response endpoint spends for document `n`: single use, one
/// answer per hand-off (ADR-047 §3.4).
#[must_use]
pub fn response_state(session: &str, n: usize) -> [u8; 32] {
    let d = aws_lc_rs::digest::digest(
        &aws_lc_rs::digest::SHA256,
        format!("openseal-esign-response-v1\n{session}\n{n}").as_bytes(),
    );
    let mut out = [0u8; 32];
    out.copy_from_slice(d.as_ref());
    out
}

/// What the start recorded about the eSign session, kept in its `prepared` record.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EsignStart {
    /// `otp`, `face`, ...
    pub auth_mode: String,
}

fn failure_of(f: casual_sign_esign::Failure) -> RemoteFailure {
    match f {
        casual_sign_esign::Failure::Cancelled => RemoteFailure::Cancelled,
        casual_sign_esign::Failure::Expired => RemoteFailure::Expired,
        casual_sign_esign::Failure::ProviderRefused => RemoteFailure::ProviderRefused,
        casual_sign_esign::Failure::ProviderUnavailable => RemoteFailure::ProviderUnavailable,
    }
}

/// Everything `prepare` needs, read before the blocking work.
pub(crate) struct PrepareIn<'a> {
    pub(crate) services: &'a SealServices,
    pub(crate) state: &'a EnvelopeState,
    pub(crate) rid: &'a Id,
    pub(crate) session: &'a str,
    pub(crate) esign: &'a Esign,
    pub(crate) docs: Vec<DocIn>,
    pub(crate) names: BTreeMap<String, String>,
    pub(crate) arts: &'a BTreeMap<String, casual_sign_sdk::Art>,
    pub(crate) signing_time: Duration,
    pub(crate) signing_ms: i64,
    pub(crate) unix_time: i64,
    pub(crate) auth_mode: AuthMode,
    pub(crate) token: Option<casual_sign_keyd::SealToken>,
    pub(crate) signer: &'a dyn AspSigner,
}

/// The `prepare` phase (blocking).
pub(crate) fn prepare(i: PrepareIn<'_>) -> Outcome {
    let how = How::Esign {
        cades: i.esign.cades,
        placeholder: i.esign.placeholder_bytes,
    };
    let bases: Vec<Vec<u8>> = i.docs.iter().map(|d| d.bytes.clone()).collect();
    let prepared = match prepare_documents(
        i.services,
        i.state,
        i.rid,
        &how,
        i.docs,
        i.arts,
        i.signing_time,
    ) {
        Ok(p) => p,
        Err((reason, code)) => return Outcome::Failed(reason, Some(code)),
    };
    let mut blobs = bases;
    let mut records = Vec::new();
    let mut documents = Vec::new();
    for (n, (mut doc, bytes)) in prepared.into_iter().enumerate() {
        let n = n.saturating_add(1);
        let txn = txn_of(i.session, n);
        let Some(digest) = STANDARD.decode(&doc.byte_range_digest).ok() else {
            return Outcome::Failed(RemoteFailure::ResponseInvalid, None);
        };
        let name = if i.esign.send_document_names {
            i.names
                .get(&doc.document_id)
                .cloned()
                .unwrap_or_else(|| "Agreement".to_owned())
        } else {
            format!("Agreement {}", i.state.id.as_str().get(..8).unwrap_or(""))
        };
        let request = Request {
            asp_id: &i.esign.asp_id,
            txn: &txn,
            unix_time: i.unix_time,
            auth_mode: i.auth_mode,
            response_url: &i.esign.response_url,
            sha256: &digest,
            doc_info: &name,
        };
        let alg = match i.signer.algorithm(&i.esign.asp_key_alias) {
            Ok(a) => a,
            Err(code) => {
                return Outcome::Failed(RemoteFailure::ProviderUnavailable, Some(code.into()));
            }
        };
        let mut refused: Option<&'static str> = None;
        let mut sign = |d: &[u8]| -> Result<Vec<u8>, EsignError> {
            i.signer
                .sign(&i.esign.asp_key_alias, i.session, i.token.clone(), d)
                .map(|(v, _, _)| v)
                .map_err(|code| {
                    refused = Some(code);
                    EsignError::Signer
                })
        };
        let signed = match request.signed(alg, None, &mut sign) {
            Ok(xml) => xml,
            Err(e) => {
                let code = refused.unwrap_or(e.code());
                return Outcome::Failed(RemoteFailure::ProviderUnavailable, Some(code.into()));
            }
        };
        let xml = signed.into_bytes();
        doc.txn = Some(txn);
        doc.request = Some(BlobKey::of(&xml).hex());
        documents.push(prepared_document(&doc, &bytes, i.rid));
        blobs.push(bytes);
        blobs.push(xml);
        records.push(doc);
    }
    let Ok(session_id) = Id::new(i.session.to_owned()) else {
        return Outcome::Failed(RemoteFailure::ResponseInvalid, None);
    };
    Outcome::Prepared {
        blobs,
        record: PreparedSession {
            credential_id: String::new(),
            chain: Vec::new(),
            algorithm: i.auth_mode.as_str().to_owned(),
            signing_time_ms: i.signing_ms,
            documents: records,
            qualifier: None,
        },
        command: Command::RemoteSigningPrepared {
            recipient: i.rid.clone(),
            session: session_id,
            documents,
            certificate_sha256: None,
        },
    }
}

/// Everything `sign` needs.
pub(crate) struct SignIn<'a> {
    pub(crate) services: &'a SealServices,
    pub(crate) esign: &'a Esign,
    pub(crate) anchors_pem: &'a [u8],
    pub(crate) record: PreparedSession,
    pub(crate) prepared: Vec<Vec<u8>>,
    pub(crate) requests: Vec<Vec<u8>>,
    /// Each document's answer, in order; `None` after an answer that ended the session.
    pub(crate) responses: Vec<Option<Vec<u8>>>,
    pub(crate) rid: &'a Id,
    pub(crate) session: &'a Id,
    pub(crate) provider: &'a RemoteProvider,
    pub(crate) recipient_name: &'a str,
}

/// Whether two one-time certificates name the same signer: the same subject, issued by
/// the same CA (ADR-047 §3.1: one request, so one certificate, per document in v2.1).
pub(crate) fn same_signer(a: &Certificate, b: &Certificate) -> bool {
    a.tbs_certificate().subject() == b.tbs_certificate().subject()
        && a.tbs_certificate().issuer() == b.tbs_certificate().issuer()
}

fn policy_oids(cert: &Certificate) -> Vec<String> {
    let Ok(Some((_, policies))) = cert
        .tbs_certificate()
        .get_extension::<x509_cert::ext::pkix::CertificatePolicies>()
    else {
        return Vec::new();
    };
    policies
        .0
        .iter()
        .map(|p| p.policy_identifier.to_string())
        .take(8)
        .collect()
}

/// The `sign` phase (blocking).
#[allow(clippy::too_many_lines)]
// One pass per document, in the ADR's order of checks.
pub(crate) fn sign(i: SignIn<'_>) -> Outcome {
    let Ok(esp) = VerifyingKey::from_certificate(&i.esign.response_certificate) else {
        return Outcome::Failed(RemoteFailure::ProviderRefused, Some("CS-RSP-0010".into()));
    };
    let mut trust: TrustStore = i.services.trust.clone();
    for a in pem_anchors(i.anchors_pem) {
        let _ = trust.add_anchor(&a);
    }
    let options = CompleteOptions {
        trust,
        limits: Limits::default(),
    };
    let signing_time = Duration::from_millis(u64::try_from(i.record.signing_time_ms).unwrap_or(0));
    let mut record = i.record;
    let mut blobs = Vec::new();
    let mut signed_docs = Vec::new();
    let mut leaf: Option<(Certificate, Vec<u8>)> = None;
    let mut reference: Option<String> = None;
    for (((doc, bytes), request), response) in record
        .documents
        .iter_mut()
        .zip(i.prepared)
        .zip(i.requests)
        .zip(i.responses)
    {
        // An answer ended the session before this document: its failure came first.
        let Some(response) = response else {
            return Outcome::Failed(RemoteFailure::ResponseInvalid, Some("CS-RSP-0004".into()));
        };
        // Read again from the stored bytes, verified under the configured certificate.
        let answer = match casual_sign_esign::response::read(&response, &esp) {
            Ok(a) => a,
            Err(e) => {
                return Outcome::Failed(RemoteFailure::ResponseInvalid, Some(e.code().into()));
            }
        };
        if Some(answer.txn.as_str()) != doc.txn.as_deref() {
            return Outcome::Failed(RemoteFailure::ResponseInvalid, Some("CS-RSP-0004".into()));
        }
        match answer.status {
            Status::Signed => {}
            Status::Failed => {
                let code = answer.err_code.clone().unwrap_or_default();
                return Outcome::Failed(
                    failure_of(casual_sign_esign::failure_for(&code)),
                    casual_sign_esign::provider_code(&code),
                );
            }
            Status::Pending => {
                return Outcome::Failed(RemoteFailure::ResponseInvalid, Some("CS-RSP-0004".into()));
            }
        }
        let [sig] = answer.signatures.as_slice() else {
            return Outcome::Failed(RemoteFailure::ResponseInvalid, Some("CS-RSP-0004".into()));
        };
        if let Some(err) = &sig.error {
            return Outcome::Failed(
                failure_of(casual_sign_esign::failure_for(err)),
                casual_sign_esign::provider_code(err),
            );
        }
        if sig.id != "1" {
            return Outcome::Failed(RemoteFailure::ResponseInvalid, Some("CS-RSP-0004".into()));
        }
        let Some(user) = answer.user_certificate.clone() else {
            return Outcome::Failed(RemoteFailure::ResponseInvalid, Some("CS-RSP-0004".into()));
        };
        let Ok(cert) = Certificate::from_der(&user) else {
            return Outcome::Failed(RemoteFailure::ResponseInvalid, Some("CS-RSP-0004".into()));
        };
        // One signer across the session's documents: v2.1 makes one request per
        // document and the ESP issues a one-time certificate for each (its key deleted
        // after one signature), so the certificates differ; their subject, the person
        // the e-KYC identified, must not.
        if leaf
            .as_ref()
            .is_some_and(|(first, _)| !same_signer(first, &cert))
        {
            return Outcome::Failed(RemoteFailure::ResponseInvalid, Some("CS-RSP-0004".into()));
        }
        let decode = |s: &str| STANDARD.decode(s).unwrap_or_default();
        let prepared = PreparedForCms {
            bytes,
            byte_range: doc.byte_range,
            placeholder_len: doc.placeholder_len,
            byte_range_digest: decode(&doc.byte_range_digest),
            format: if doc.format.as_deref() == Some("adbe.pkcs7.detached") {
                CmsFormat::Pkcs7
            } else {
                CmsFormat::Cades
            },
            profile: Profile::BaselineLt,
            signing_time,
            first_new_revision: doc.first_new_revision,
        };
        let _ = SealKind::Approval;
        let tsa = (i.services.timestamps)();
        let revocation = (i.services.revocation)();
        let (sealed, _found) = match casual_sign_sdk::remote::complete_cms(
            &prepared,
            &sig.value,
            &user,
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
        let a = usize::try_from(prepared.byte_range[1]).unwrap_or(0);
        let b = usize::try_from(prepared.byte_range[2]).unwrap_or(0);
        let cms = sealed
            .bytes
            .get(a.saturating_add(1)..b.saturating_sub(1))
            .map(Hash256::digest)
            .unwrap_or_default();
        doc.signed = Some(BlobKey::of(&sealed.bytes).hex());
        doc.response = Some(BlobKey::of(&response).hex());
        reference = reference.or(answer.res_code.clone());
        signed_docs.push(RemoteSignedDocument {
            document_id: Id::new(doc.document_id.clone()).unwrap_or_else(|_| i.rid.clone()),
            revision_hash: Hash256::digest(&sealed.bytes),
            signature_sha256: cms,
            timestamp_time: sealed
                .report
                .signature_timestamp
                .and_then(|d| i64::try_from(d.as_millis()).ok())
                .and_then(Timestamp::from_unix_millis),
            certificate_sha256: Some(Hash256::digest(&user)),
            request_sha256: Some(Hash256::digest(&request)),
            response_sha256: Some(Hash256::digest(&response)),
            signature_format: doc.format.clone(),
        });
        blobs.push(sealed.bytes);
        blobs.push(response);
        if leaf.is_none() {
            leaf = Some((cert, user));
        }
    }
    let Some((cert, der)) = leaf else {
        return Outcome::Failed(RemoteFailure::ResponseInvalid, Some("CS-RSP-0004".into()));
    };
    let key = super::rsp::key_name(&cert);
    let Some(certificate) = certificate_facts(&cert, &der, &key, None) else {
        return Outcome::Failed(RemoteFailure::ResponseInvalid, Some("CS-RSP-0004".into()));
    };
    let matched = name_match(certificate.subject_cn.get(), i.recipient_name);
    let auth_mode = record.algorithm.clone();
    Outcome::Signed {
        blobs,
        command: Command::CompleteRemoteSigning {
            recipient: i.rid.clone(),
            session: i.session.clone(),
            provider: i.provider.clone(),
            provider_reference: reference,
            certificate: Box::new(certificate),
            name_match: matched,
            documents: signed_docs,
            esign: Some(EsignSigned {
                auth_mode,
                policy_oids: policy_oids(&cert),
            }),
        },
        record,
    }
}

/// The signer for a configured worker: keyd's ASP key.
#[must_use]
pub fn keyd_signer(endpoint: casual_sign_keyd::Endpoint) -> Arc<dyn AspSigner> {
    Arc::new(KeydAsp { endpoint })
}

impl<B: casual_sign_store::blob::BlobStore + 'static> super::Worker<B> {
    /// One phase of an eSign session (`prepare` or `sign`).
    #[allow(clippy::too_many_lines)]
    // The phase's inputs, read in order, then the blocking work.
    pub(super) async fn esign_phase(
        &self,
        account: casual_sign_store::AccountId,
        envelope: casual_sign_store::EnvelopeId,
        session: &casual_sign_store::repo::signing::RemoteSession,
        state: &EnvelopeState,
        rid: &Id,
        completed: &[casual_sign_store::repo::signing::RemoteSession],
    ) -> crate::error::Result<Outcome> {
        use crate::error::WorkerError;
        use casual_sign_store::repo::signing::SessionStatus;
        let Some(rsp) = self.rsp.clone() else {
            return Ok(Outcome::Failed(RemoteFailure::ProviderUnavailable, None));
        };
        let Some(provider) = rsp.catalogue.get(&session.provider_id) else {
            return Ok(Outcome::Failed(RemoteFailure::ProviderRefused, None));
        };
        let Some(esign) = provider.esign.clone() else {
            return Ok(Outcome::Failed(RemoteFailure::ProviderRefused, None));
        };
        let Some(signer) = rsp.asp.clone() else {
            return Ok(Outcome::Failed(
                RemoteFailure::ProviderUnavailable,
                Some("CS-RSP-0002".into()),
            ));
        };
        let sid = session.id.to_string();
        let session_id = Id::new(sid.clone()).map_err(|_| WorkerError::StateUnreadable)?;
        let provider_ref = RemoteProvider {
            id: Id::new(provider.id.clone()).map_err(|_| WorkerError::StateUnreadable)?,
            kind: provider.kind.as_str().to_owned(),
            name: provider.name.clone(),
        };
        let services = self.seal.clone();
        match session.status {
            SessionStatus::Preparing => {
                let auth_mode = session
                    .prepared
                    .as_ref()
                    .and_then(|p| p.get("esign"))
                    .and_then(|e| e.get("auth_mode"))
                    .and_then(serde_json::Value::as_str)
                    .and_then(AuthMode::from_name)
                    .unwrap_or(AuthMode::Otp);
                // The database's ASP token for this open session (ADR-047 §3.5).
                let token = {
                    let mut tx = self.store.for_account(account).begin().await?;
                    let t = tx.signing().asp_token(session.id).await?;
                    tx.commit().await?;
                    t.and_then(|(expires, mac)| {
                        Some(casual_sign_keyd::SealToken {
                            expires: u64::try_from(expires).ok()?,
                            mac: mac?,
                        })
                    })
                };
                let input = self.gather(account, envelope, state.clone(), true).await?;
                let current = super::rsp::current_revisions(completed);
                let me = state.recipient(rid).ok_or(WorkerError::StateUnreadable)?;
                let mut docs = Vec::new();
                let mut names = BTreeMap::new();
                for (d, delivered) in state.documents.iter().zip(&input.delivered) {
                    if !me.spec.sees(d.id()) {
                        continue;
                    }
                    names.insert(
                        d.id().as_str().to_owned(),
                        d.spec.name.get().as_str().to_owned(),
                    );
                    let cur = current.get(d.id().as_str()).cloned();
                    let bytes = match &cur {
                        Some(c) => {
                            let key = BlobKey::parse(c.signed.as_deref().unwrap_or(""))
                                .map_err(|_| WorkerError::StateUnreadable)?;
                            self.blob_or(&key, "document").await?
                        }
                        None => delivered.clone(),
                    };
                    docs.push(DocIn {
                        id: d.id().clone(),
                        bytes,
                        current: cur,
                    });
                }
                let now = self.now();
                let signing_ms = crate::apply::ts(now)?.unix_millis();
                let unix_time = now.unix_timestamp();
                let state = state.clone();
                let rid = rid.clone();
                let arts = input.captures.clone();
                tokio::task::spawn_blocking(move || {
                    prepare(PrepareIn {
                        services: &services,
                        state: &state,
                        rid: &rid,
                        session: &sid,
                        esign: &esign,
                        docs,
                        names,
                        arts: &arts,
                        signing_time: Duration::from_millis(u64::try_from(signing_ms).unwrap_or(0)),
                        signing_ms,
                        unix_time,
                        auth_mode,
                        token,
                        signer: signer.as_ref(),
                    })
                })
                .await
                .map_err(|_| WorkerError::Pipeline {
                    code: "CS-RSP-0002",
                })
            }
            SessionStatus::Signing => {
                let record: PreparedSession = session
                    .prepared
                    .clone()
                    .and_then(|v| serde_json::from_value(v).ok())
                    .ok_or(WorkerError::StateUnreadable)?;
                let mut prepared = Vec::new();
                let mut requests = Vec::new();
                let mut responses = Vec::new();
                let key = |k: Option<&str>| BlobKey::parse(k.unwrap_or("")).ok();
                for d in &record.documents {
                    let (Some(p), Some(q)) = (key(Some(&d.prepared)), key(d.request.as_deref()))
                    else {
                        return Ok(Outcome::Failed(RemoteFailure::ResponseInvalid, None));
                    };
                    prepared.push(self.blob_or(&p, "document").await?);
                    requests.push(self.blob_or(&q, "document").await?);
                    // A document after the answer that ended the session has none.
                    responses.push(match key(d.response.as_deref()) {
                        Some(r) => Some(self.blob_or(&r, "document").await?),
                        None => None,
                    });
                }
                let name = state
                    .recipient(rid)
                    .map(|r| r.spec.name.get().as_str().to_owned())
                    .unwrap_or_default();
                let anchors = provider.trust_anchors_pem.clone();
                let rid = rid.clone();
                tokio::task::spawn_blocking(move || {
                    sign(SignIn {
                        services: &services,
                        esign: &esign,
                        anchors_pem: &anchors,
                        record,
                        prepared,
                        requests,
                        responses,
                        rid: &rid,
                        session: &session_id,
                        provider: &provider_ref,
                        recipient_name: &name,
                    })
                })
                .await
                .map_err(|_| WorkerError::Pipeline {
                    code: "CS-RSP-0002",
                })
            }
            _ => Ok(Outcome::Failed(RemoteFailure::ResponseInvalid, None)),
        }
    }
}

#[cfg(test)]
// Tests may unwrap (CLAUDE.md).
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn a_txn_names_its_session_and_document_and_nothing_else_parses() {
        let s = "0193a000-0000-7000-8000-0000000000e1";
        let t = txn_of(s, 2);
        assert_eq!(parse_txn(&t), Some((uuid::Uuid::parse_str(s).unwrap(), 2)));
        for bad in [
            "",
            s,
            &format!("{s}.0"),
            &format!("{s}.65"),
            "x.1",
            &format!("{s}.a"),
        ] {
            assert_eq!(parse_txn(bad), None, "{bad}");
        }
    }

    /// Two answers of one v2.1 session, from the CI stub ESP: two one-time certificates
    /// (each document its own key), one signer.
    #[test]
    fn one_time_certificates_of_one_signer_are_one_signer() {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../crates/casual-sign-seal/tests/fixtures/esign-stub");
        let a = std::fs::read(dir.join("cades.user.der")).unwrap();
        let b = std::fs::read(dir.join("adobe.user.der")).unwrap();
        assert_ne!(a, b, "each document has its own certificate");
        let (a, b) = (
            Certificate::from_der(&a).unwrap(),
            Certificate::from_der(&b).unwrap(),
        );
        assert!(same_signer(&a, &b));
        let root = std::fs::read(dir.join("root.der")).unwrap();
        assert!(!same_signer(&a, &Certificate::from_der(&root).unwrap()));
    }

    #[test]
    fn each_document_has_its_own_single_use_state() {
        let s = "0193a000-0000-7000-8000-0000000000e1";
        assert_ne!(response_state(s, 1), response_state(s, 2));
        assert_ne!(
            response_state(s, 1),
            response_state("0193a000-0000-7000-8000-0000000000e2", 1)
        );
    }
}
