//! Remote-provider signatures (ADR-046 §3.4, §3.7, §3.12): a remote signer's session,
//! from their start (values frozen) through preparation (the lock point) to the
//! embedded signature or a failure. The worker talks to the provider and to the PDF
//! engine; these commands record what it did, in the chain, in order.

use casual_sign_audit::{
    EventData, Hash256, NameMatch, PreparedDocument, RemoteCertificate, RemoteFailure,
    RemoteProvider, RemoteSignedDocument,
};
use casual_sign_model::{Id, RecipientType};

use crate::command::{Command, FieldEntry};
use crate::engine::{
    Out, authorize_recipient, authorize_recipient_or_system, authorize_system, gate_ready,
    not_allowed, rec, rec_mut, recipient_refused, set_signer_values, signed,
};
use crate::error::{RemoteRule, WorkflowError};
use crate::state::{EnvelopeState, RemoteSession};

fn rule(rule: RemoteRule, object: &Id) -> WorkflowError {
    WorkflowError::Remote {
        rule,
        object: Some(object.clone()),
    }
}

/// The recipient's open session, if it is `session`; else `CS-RSP-0003`.
fn open_session<'s>(
    s: &'s EnvelopeState,
    recipient: &Id,
    session: &Id,
) -> Result<(usize, &'s RemoteSession), WorkflowError> {
    let (i, r) = rec(s, recipient)?;
    match &r.remote {
        Some(x) if x.session == *session => Ok((i, x)),
        _ => Err(rule(RemoteRule::NoSession, session)),
    }
}

/// `BeginRemoteSigning`.
pub(crate) fn begin(
    s: &mut EnvelopeState,
    cmd: &Command,
    recipient: &Id,
    session: &Id,
    provider: &RemoteProvider,
    values: &[FieldEntry],
    out: &mut Out<'_>,
) -> Result<(), WorkflowError> {
    let ctx = out.ctx;
    let (i, r) = rec(s, recipient)?;
    authorize_recipient(r, cmd, ctx)?;
    gate_ready(s, r, cmd, ctx)?;
    if r.spec.rtype != RecipientType::Signer {
        return Err(recipient_refused(cmd, r));
    }
    if r.spec.signature.provider() != Some(&provider.id) {
        return Err(rule(RemoteRule::NotRemote, recipient));
    }
    // One remote session at a time in an envelope: each signature is over the bytes the
    // one before it left (ADR-046 §3.1).
    if s.recipients.iter().any(|q| q.remote.is_some()) {
        return Err(rule(RemoteRule::SessionOpen, recipient));
    }
    set_signer_values(s, i, values, out)?;
    out.event(EventData::RecipientRemoteSigningStarted {
        recipient_id: recipient.clone(),
        session: session.clone(),
        provider: provider.clone(),
    });
    let now = out.ctx.now;
    rec_mut(s, i)?.remote = Some(RemoteSession {
        session: session.clone(),
        provider_id: provider.id.clone(),
        started_at: now,
        prepared: false,
    });
    Ok(())
}

/// `RemoteSigningPrepared`.
pub(crate) fn prepared(
    s: &mut EnvelopeState,
    cmd: &Command,
    recipient: &Id,
    session: &Id,
    documents: &[PreparedDocument],
    certificate_sha256: Option<Hash256>,
    out: &mut Out<'_>,
) -> Result<(), WorkflowError> {
    authorize_system(cmd, out.ctx)?;
    if !s.status.is_in_flight() {
        return Err(not_allowed(cmd, s));
    }
    let (i, _) = open_session(s, recipient, session)?;
    let r = s
        .recipients
        .get(i)
        .ok_or_else(|| rule(RemoteRule::NoSession, session))?;
    if documents.is_empty()
        || documents
            .iter()
            .any(|d| s.document(&d.document_id).is_none() || !r.spec.sees(&d.document_id))
    {
        return Err(recipient_refused(cmd, r));
    }
    // The lock point is the engine's to say: the first preparation over a document.
    let documents: Vec<PreparedDocument> = documents
        .iter()
        .map(|d| PreparedDocument {
            lock_point: !s.locked_documents.contains(&d.document_id),
            ..d.clone()
        })
        .collect();
    for d in &documents {
        s.locked_documents.insert(d.document_id.clone());
    }
    out.event(EventData::RecipientRemoteSigningPrepared {
        recipient_id: recipient.clone(),
        session: session.clone(),
        documents,
        certificate_sha256,
    });
    if let Some(x) = rec_mut(s, i)?.remote.as_mut() {
        x.prepared = true;
    }
    Ok(())
}

/// What `CompleteRemoteSigning` carries.
pub(crate) struct Completion<'a> {
    pub(crate) recipient: &'a Id,
    pub(crate) session: &'a Id,
    pub(crate) provider: &'a RemoteProvider,
    pub(crate) provider_reference: Option<&'a str>,
    pub(crate) certificate: &'a RemoteCertificate,
    pub(crate) name_match: NameMatch,
    pub(crate) documents: &'a [RemoteSignedDocument],
}

/// `CompleteRemoteSigning`: `recipient.remote_signed`, then the signer signs and
/// completes as a finish does, and routing moves on.
pub(crate) fn complete(
    s: &mut EnvelopeState,
    cmd: &Command,
    c: &Completion<'_>,
    out: &mut Out<'_>,
) -> Result<(), WorkflowError> {
    authorize_system(cmd, out.ctx)?;
    if !s.status.is_in_flight() {
        return Err(not_allowed(cmd, s));
    }
    let (i, x) = open_session(s, c.recipient, c.session)?;
    if !x.prepared || x.provider_id != c.provider.id {
        return Err(rule(RemoteRule::NoSession, c.session));
    }
    let r = s
        .recipients
        .get(i)
        .ok_or_else(|| rule(RemoteRule::NoSession, c.session))?;
    if c.documents.is_empty()
        || c.documents
            .iter()
            .any(|d| !s.locked_documents.contains(&d.document_id) || !r.spec.sees(&d.document_id))
    {
        return Err(recipient_refused(cmd, r));
    }
    out.event(EventData::RecipientRemoteSigned {
        recipient_id: c.recipient.clone(),
        session: c.session.clone(),
        provider: c.provider.clone(),
        provider_reference: c.provider_reference.map(str::to_owned),
        certificate: Box::new(c.certificate.clone()),
        name_match: c.name_match,
        documents: c.documents.to_vec(),
    });
    rec_mut(s, i)?.remote = None;
    signed(s, i, out)
}

/// `FailRemoteSigning`: the recipient cancels, or the platform ends the session.
pub(crate) fn fail(
    s: &mut EnvelopeState,
    cmd: &Command,
    recipient: &Id,
    session: &Id,
    reason: RemoteFailure,
    provider_code: Option<&str>,
    out: &mut Out<'_>,
) -> Result<(), WorkflowError> {
    let (i, r) = rec(s, recipient)?;
    authorize_recipient_or_system(r, cmd, out.ctx)?;
    open_session(s, recipient, session)?;
    out.event(EventData::RecipientRemoteSigningFailed {
        recipient_id: recipient.clone(),
        session: session.clone(),
        reason,
        provider_code: provider_code.map(str::to_owned),
    });
    let r = rec_mut(s, i)?;
    r.remote = None;
    r.remote_failures = r.remote_failures.saturating_add(1);
    Ok(())
}

/// Close every open session `envelope_ended` (the envelope was voided, declined or
/// expired).
pub(crate) fn close_all(s: &mut EnvelopeState, out: &mut Out<'_>) {
    for r in &mut s.recipients {
        if let Some(x) = r.remote.take() {
            out.event(EventData::RecipientRemoteSigningFailed {
                recipient_id: r.id().clone(),
                session: x.session,
                reason: RemoteFailure::EnvelopeEnded,
                provider_code: None,
            });
            r.remote_failures = r.remote_failures.saturating_add(1);
        }
    }
}
