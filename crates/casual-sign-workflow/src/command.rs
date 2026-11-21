//! Commands, the context they are decided in, and the decision (docs/24 §1).

use casual_sign_audit::{Actor, Context as RequestContext, EventData};
use casual_sign_audit::{
    AdoptionMethod, AuditEvent, AuthMethod, Chain, Channel, Hash256, MarkKind, Personal, Timestamp,
};
use casual_sign_model::{
    DateFormat, Delivery, FieldValue, Id, ReminderPolicy, SealProfile, SigningOptions, Text,
};
use serde::{Deserialize, Serialize};

use crate::effect::{Effect, EffectId};
use crate::state::{DocumentSpec, EnvelopeState, RecipientSpec};

/// Who is acting, as the server authenticated them. The engine checks it against the
/// envelope on every command (deny by default).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Principal {
    /// The envelope's sender, signed in.
    Sender {
        /// Their user id.
        user_id: Id,
    },
    /// An administrator of the envelope's account.
    Admin {
        /// Their user id.
        user_id: Id,
    },
    /// A recipient, through their token or session.
    Recipient {
        /// The recipient's id.
        recipient_id: Id,
    },
    /// A staff user hosting an in-person signing, signed in.
    InPersonHost {
        /// Their user id.
        user_id: Id,
    },
    /// An embedding host application, through the API.
    Host {
        /// Its API client id.
        client_id: Id,
    },
    /// The platform: a job, a timer, the sealing service, the retention job.
    System,
}

/// The current consumer disclosure (ERSD) recipients must accept.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ersd {
    /// Its version label.
    pub version: Text,
    /// SHA-256 of its text.
    pub hash: Hash256,
}

/// The account's settings the engine applies (docs/22 §8). Count limits are capped at
/// docs/21's whatever the account says.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    /// Failed authentication attempts before a recipient is locked.
    pub max_auth_attempts: u32,
    /// Recipients per envelope (docs/21: 100).
    pub max_recipients: usize,
    /// Fields per envelope (docs/21: 3,000).
    pub max_fields: usize,
    /// Documents per envelope (stage 2A decision: 100; docs/21 names none yet).
    pub max_documents: usize,
    /// The disclosure recipients must accept, when the account requires one.
    pub ersd: Option<Ersd>,
    /// Days before expiry to warn recipients who have not acted; 0 for none.
    pub expiry_warning_days: u16,
    /// Milliseconds before a failed seal is retried.
    pub seal_retry_ms: u32,
    /// The account's date format for `date_signed`.
    pub date_format: DateFormat,
}

/// Envelope limits of docs/21, which no policy can raise.
pub mod limits {
    /// Recipients per envelope (`CS-WF-0004`).
    pub const MAX_RECIPIENTS: usize = 100;
    /// Fields per envelope (`CS-WF-0004`).
    pub const MAX_FIELDS: usize = 3_000;
    /// Documents per envelope. A decision of `T-2A`: docs/21 names none.
    pub const MAX_DOCUMENTS: usize = 100;
    /// Pages per document (docs/21's page cap).
    pub const MAX_PAGES: u32 = 5_000;
    /// Commands one envelope may apply (`CS-WF-0011`). A decision of `T-2A`: the
    /// idempotency record grows with every command, so it is bounded.
    pub const MAX_COMMANDS: usize = 100_000;
    /// Changes in one edit or correction. A decision of `T-2A`.
    pub const MAX_CHANGES: usize = 5_000;
    /// How far ahead a draft may be scheduled to send, in days (`CS-WF-0023`). A
    /// decision of `WF-02`: a year bounds the timers a draft holds.
    pub const MAX_SCHEDULE_DAYS: u16 = 365;
    /// The longest delayed routing for one recipient, in hours (`CS-WF-0023`). A
    /// decision of `WF-02`: thirty days bounds how long one routing step waits.
    pub const MAX_ROUTE_DELAY_HOURS: u16 = 720;
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            max_auth_attempts: 3,
            max_recipients: limits::MAX_RECIPIENTS,
            max_fields: limits::MAX_FIELDS,
            max_documents: limits::MAX_DOCUMENTS,
            ersd: None,
            expiry_warning_days: 0,
            seal_retry_ms: 60_000,
            date_format: DateFormat::default(),
        }
    }
}

/// Everything a decision depends on besides the state and the command: supplied, never
/// sampled (CLAUDE.md).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Context {
    /// The command's id (the API idempotency key, or the job's id): re-applying it gives
    /// the same decision.
    pub command_id: Id,
    /// The server's time.
    pub now: Timestamp,
    /// Who is acting.
    pub principal: Principal,
    /// The request's IP, user agent, session and satisfied methods, copied into events.
    pub request: RequestContext,
    /// The envelope version the client read, for commands that edit it; `None` for
    /// commands that touch one recipient (docs/24 §1).
    pub expected_version: Option<u64>,
    /// The account's settings.
    pub policy: Policy,
}

/// A field value a recipient supplies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldEntry {
    /// The field.
    pub field: Id,
    /// The value.
    pub value: Personal<FieldValue>,
}

/// The new recipient of a reassignment. Type, routing order, authentication and fields
/// carry over from the recipient who reassigns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReassignTo {
    /// The new recipient's id.
    pub id: Id,
    /// Their name.
    pub name: Personal<Text>,
    /// Their email.
    pub email: Personal<Text>,
    /// Their phone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone: Option<Personal<Text>>,
    /// How to reach them; the old recipient's when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delivery: Option<Delivery>,
}

/// One edit to an envelope: in a draft (`Edit`), a correction (`Correct`) or a
/// recipient's edit of later recipients (`RecipientEdit`). Fields travel wrapped in
/// [`Personal`] because their values and defaults are document content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Change {
    /// Add a recipient.
    AddRecipient {
        /// The recipient.
        recipient: RecipientSpec,
    },
    /// Replace a recipient's configuration (its id names it).
    UpdateRecipient {
        /// The new configuration.
        recipient: RecipientSpec,
    },
    /// Remove a recipient and their fields.
    RemoveRecipient {
        /// The recipient.
        id: Id,
    },
    /// Add a field.
    AddField {
        /// The field.
        field: Personal<casual_sign_model::Field>,
    },
    /// Replace a field (its id names it).
    UpdateField {
        /// The field.
        field: Personal<casual_sign_model::Field>,
    },
    /// Remove a field.
    RemoveField {
        /// The field.
        id: Id,
    },
    /// Add an uploaded, admitted document.
    AddDocument {
        /// The document.
        document: DocumentSpec,
    },
    /// Remove a document and its fields.
    RemoveDocument {
        /// The document.
        id: Id,
    },
    /// Replace a document's bytes (its id names it).
    ReplaceDocument {
        /// The document.
        document: DocumentSpec,
    },
    /// Set the email subject.
    SetSubject {
        /// The subject.
        subject: Personal<Text>,
    },
    /// Set the email message.
    SetMessage {
        /// The message.
        message: Personal<Text>,
    },
    /// Set or clear the expiry.
    SetExpiry {
        /// When.
        expires_at: Option<Timestamp>,
    },
    /// Set the reminders.
    SetReminders {
        /// The policy.
        reminders: ReminderPolicy,
    },
    /// Set what recipients may do.
    SetSigningOptions {
        /// The options.
        options: SigningOptions,
    },
    /// Set the PAdES level (drafts only).
    SetSealProfile {
        /// The profile.
        profile: SealProfile,
    },
}

/// One sealed document as the seal job reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedDocument {
    /// The document.
    pub document_id: Id,
    /// SHA-256 of the delivered bytes the job flattened (must be the fixed document).
    pub delivered_hash: Hash256,
    /// SHA-256 of the flattened bytes.
    pub flattened_hash: Hash256,
    /// SHA-256 of the sealed bytes.
    pub sealed_hash: Hash256,
    /// The profile applied.
    pub profile: SealProfile,
    /// SHA-256 of the sealing certificate (DER).
    pub certificate_fingerprint: Hash256,
    /// The timestamp authority's time, when one was applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tsa_time: Option<Timestamp>,
    /// The independent validator accepted the sealed bytes (docs/31 verification ladder).
    pub verified: bool,
}

/// What was accessed (docs/32 §3 Access).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "what", rename_all = "snake_case")]
pub enum Access {
    /// The sender viewed the envelope.
    SenderViewed,
    /// A document was downloaded.
    DocumentDownloaded {
        /// The document.
        document: Id,
        /// SHA-256 of the bytes served.
        hash: Hash256,
    },
    /// The certificate of completion was downloaded.
    CertificateDownloaded {
        /// SHA-256 of the bytes served.
        hash: Hash256,
    },
    /// A signer's attachment was downloaded (WEB-08): the file an attachment field's
    /// value names.
    AttachmentDownloaded {
        /// The attachment field.
        field: Id,
        /// SHA-256 of the bytes served (the value names the same hash).
        hash: Hash256,
    },
    /// An envelope's evidence package was exported (ORG-09, docs/23 §2.4, `VS-06D`): a
    /// completed one, or one that ended without completing; recorded as
    /// `envelope.exported` naming the member who exported it.
    EvidenceExported,
}

/// Every command of docs/24. Recipient commands name the recipient; the principal must
/// be that recipient, their embedding host, or their in-person host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Command {
    // Sender ---------------------------------------------------------------------------
    /// Create a draft envelope (the state must be `None`).
    Create {
        /// The new envelope's id.
        envelope_id: Id,
        /// The tenant.
        account_id: Id,
        /// The sender.
        sender_user_id: Id,
        /// Email subject.
        subject: Personal<Text>,
        /// Email message.
        message: Personal<Text>,
    },
    /// Edit a draft.
    Edit {
        /// The changes, applied in order, all or none.
        changes: Vec<Change>,
    },
    /// Send the draft: fix documents, start routing. A scheduled draft sends now and its
    /// schedule is dropped.
    Send,
    /// Schedule the draft to send itself at `at`, or cancel the schedule (`None`)
    /// (`WF-02`). The draft must be sendable now, `at` after now, within
    /// [`limits::MAX_SCHEDULE_DAYS`] and before the expiry (`CS-WF-0023`); a scheduled
    /// draft cannot be edited (`CS-WF-0022`) until the schedule is cancelled.
    ScheduleSend {
        /// When to send; `None` cancels the schedule.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        at: Option<Timestamp>,
    },
    /// Delete a draft.
    DeleteDraft,
    /// Remove an envelope that ended without completing (declined, voided, expired)
    /// from the sender's lists (WEB-08). Nothing is purged: the chain, the documents
    /// and the state stay; `envelope.deleted` records who removed it and when.
    DeleteEnded,
    /// List again an envelope removed by [`Command::DeleteEnded`] (ADR-031, `UXW-02`):
    /// only while it is deleted and not purged; `envelope.restored` records who and when.
    /// Nothing in the agreement changes.
    RestoreDeleted,
    /// Correct a sent envelope (docs/24 §6).
    Correct {
        /// The changes, applied in order, all or none.
        changes: Vec<Change>,
    },
    /// Void with a reason.
    Void {
        /// The reason.
        reason: Personal<Text>,
    },
    /// Re-send invitations (all active recipients when empty); clears a bounce and an
    /// authentication lock.
    Resend {
        /// Recipients.
        recipients: Vec<Id>,
    },
    /// Remind every active recipient who has not acted, now.
    Remind,
    /// Pass the envelope's ownership to another member of the same workspace (ORG-09,
    /// docs/23 §2.4): any envelope not purged, by an administrator principal (the
    /// server admits only a member holding `envelopes.transfer`). The server checks
    /// that `to_user` is a member of the envelope's workspace; envelopes never move
    /// between workspaces.
    Transfer {
        /// The new owner.
        to_user: Id,
    },

    // Recipient ------------------------------------------------------------------------
    /// The recipient opened their link.
    OpenLink {
        /// The recipient.
        recipient: Id,
    },
    /// The recipient was asked to authenticate.
    ChallengeAuth {
        /// The recipient.
        recipient: Id,
        /// The method.
        method: AuthMethod,
    },
    /// The server's verdict on an authentication attempt.
    AuthResult {
        /// The recipient.
        recipient: Id,
        /// The method.
        method: AuthMethod,
        /// Whether it passed.
        passed: bool,
        /// For a passed `sso`, who the identity provider said signed in (RAUTH-01); the
        /// engine refuses a pass by `sso` without it, and it with any other method.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        identity: Option<casual_sign_audit::SignInIdentity>,
    },
    /// The embedding host asserts it authenticated the recipient.
    HostAssertAuth {
        /// The recipient.
        recipient: Id,
        /// The host's statement of how.
        claim: Personal<Text>,
    },
    /// The recipient accepted the consumer disclosure.
    Consent {
        /// The recipient.
        recipient: Id,
        /// The version shown.
        ersd_version: Text,
        /// SHA-256 of the text shown.
        ersd_hash: Hash256,
    },
    /// The recipient withdrew consent; a recipient with a required action thereby
    /// declines.
    WithdrawConsent {
        /// The recipient.
        recipient: Id,
    },
    /// A staff user starts hosting an in-person signer.
    HostInPerson {
        /// The in-person signer.
        recipient: Id,
    },
    /// The recipient viewed pages of a document.
    ViewDocument {
        /// The recipient.
        recipient: Id,
        /// The document.
        document: Id,
        /// SHA-256 of the bytes shown.
        hash: Hash256,
        /// Pages seen, 1-based.
        pages_seen: Vec<u32>,
    },
    /// The recipient adopted a signature or initials.
    AdoptSignature {
        /// The recipient.
        recipient: Id,
        /// Which mark.
        mark: MarkKind,
        /// How it was made.
        method: AdoptionMethod,
        /// SHA-256 of the image or strokes.
        image_hash: Hash256,
    },
    /// The recipient set a field's value.
    CompleteField {
        /// The recipient.
        recipient: Id,
        /// The field and value.
        entry: FieldEntry,
    },
    /// Sign on paper (FG-013, ADR-043): a signer whose turn it is, authenticated and
    /// consented, on an envelope allowing it, completes with the scan of the documents
    /// they printed and signed by hand. The server admits the scan like any upload and
    /// passes it as `document`; it is added to the envelope (fixed, so the seal covers
    /// it) and `recipient.signed_on_paper` binds it to the documents printed.
    SignOnPaper {
        /// The recipient.
        recipient: Id,
        /// The admitted scan.
        document: DocumentSpec,
    },
    /// The recipient finished: signs (signer types), completes (viewer, agent,
    /// intermediary). Values given here are set first.
    Finish {
        /// The recipient.
        recipient: Id,
        /// Values to set first.
        values: Vec<FieldEntry>,
    },
    /// An approver approves.
    Approve {
        /// The recipient.
        recipient: Id,
    },
    /// The recipient declines.
    Decline {
        /// The recipient.
        recipient: Id,
        /// Their reason.
        reason: Option<Personal<Text>>,
    },
    /// The recipient hands their part to someone else.
    Reassign {
        /// The recipient.
        recipient: Id,
        /// The new recipient.
        to: ReassignTo,
        /// Their reason.
        reason: Option<Personal<Text>>,
    },
    /// The recipient will finish later.
    FinishLater {
        /// The recipient.
        recipient: Id,
    },
    /// An editor, agent or intermediary edits later recipients (and, for an editor,
    /// fields) before finishing.
    RecipientEdit {
        /// The recipient editing.
        recipient: Id,
        /// The changes.
        changes: Vec<Change>,
    },

    // System ---------------------------------------------------------------------------
    /// An invitation left (the worker's report).
    InvitationDispatched {
        /// The recipient.
        recipient: Id,
        /// How.
        channel: Channel,
    },
    /// A reminder left.
    ReminderDispatched {
        /// The recipient.
        recipient: Id,
        /// How.
        channel: Channel,
    },
    /// An invitation bounced.
    InvitationBounced {
        /// The recipient.
        recipient: Id,
        /// How it was sent.
        channel: Channel,
    },
    /// A scheduled timer fired (`RemindDue`, `Expire` and the expiry warning of docs/24
    /// §7 are this command naming their timer).
    TimerDue {
        /// The timer's effect id.
        timer: EffectId,
    },
    /// Expire the envelope if its expiry has passed (a sweep's command).
    Expire,
    /// The seal job sealed and independently verified every document.
    SealSucceeded {
        /// The seal job's effect id.
        job: EffectId,
        /// Each document.
        documents: Vec<SealedDocument>,
    },
    /// The seal job failed; it is retried.
    SealFailed {
        /// The seal job's effect id.
        job: EffectId,
        /// Its error code.
        code: Text,
    },
    /// Someone viewed or downloaded something.
    RecordAccess {
        /// What.
        access: Access,
    },
    /// Purge documents and personal data by retention policy or request.
    Purge {
        /// The policy or request.
        policy: Text,
    },

    // Remote-provider signatures (ADR-046 §3.4) ---------------------------------------
    /// A remote signer, their turn come and authenticated, starts signing with their
    /// provider: `values` are set and checked as a finish would, then frozen, and
    /// `recipient.remote_signing_started` is recorded. Refused (`CS-RSP-0007`) when they
    /// are not a remote signer of this provider or another session is open.
    BeginRemoteSigning {
        /// The recipient.
        recipient: Id,
        /// The new session's id (host-minted).
        session: Id,
        /// The provider, as the catalogue names it.
        provider: casual_sign_audit::RemoteProvider,
        /// Values set first, as in `Finish`.
        values: Vec<FieldEntry>,
        /// India eSign (ADR-047 §3.1): the consent's hash, API version and
        /// authentication; `None` for CSC.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        esign: Option<casual_sign_audit::EsignStarted>,
    },
    /// The worker prepared the session's documents (the platform): records the hashes the
    /// signature will bind; a document not yet locked reaches its lock point here.
    RemoteSigningPrepared {
        /// The recipient.
        recipient: Id,
        /// The open session.
        session: Id,
        /// Each document prepared.
        documents: Vec<casual_sign_audit::PreparedDocument>,
        /// SHA-256 of the credential's certificate, when known before signing.
        certificate_sha256: Option<Hash256>,
    },
    /// The worker checked and embedded the provider's signature in every prepared
    /// document (the platform): `recipient.remote_signed`, then the recipient signs and
    /// completes as a finish does.
    CompleteRemoteSigning {
        /// The recipient.
        recipient: Id,
        /// The open session.
        session: Id,
        /// The provider.
        provider: casual_sign_audit::RemoteProvider,
        /// The provider's transaction id, where it has one.
        provider_reference: Option<String>,
        /// The certificate the signature was made with.
        certificate: Box<casual_sign_audit::RemoteCertificate>,
        /// Its name against the recipient's.
        name_match: casual_sign_audit::NameMatch,
        /// Each document signed.
        documents: Vec<casual_sign_audit::RemoteSignedDocument>,
        /// India eSign (ADR-047 §3.8): the authentication asked, the certificate's
        /// policies; `None` for CSC.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        esign: Option<casual_sign_audit::EsignSigned>,
    },
    /// The session failed: cancelled by the signer, or ended by the platform. The
    /// signer's fields reopen; a new attempt is a new session.
    FailRemoteSigning {
        /// The recipient.
        recipient: Id,
        /// The open session.
        session: Id,
        /// Why.
        reason: casual_sign_audit::RemoteFailure,
        /// The provider's own error code.
        provider_code: Option<String>,
    },
}

impl Command {
    /// The command's name, as errors report it.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Create { .. } => "create",
            Self::Edit { .. } => "edit",
            Self::Send => "send",
            Self::ScheduleSend { .. } => "schedule_send",
            Self::DeleteDraft => "delete_draft",
            Self::DeleteEnded => "delete_ended",
            Self::RestoreDeleted => "restore_deleted",
            Self::Correct { .. } => "correct",
            Self::Void { .. } => "void",
            Self::Resend { .. } => "resend",
            Self::Remind => "remind",
            Self::Transfer { .. } => "transfer",
            Self::OpenLink { .. } => "open_link",
            Self::ChallengeAuth { .. } => "challenge_auth",
            Self::AuthResult { .. } => "auth_result",
            Self::HostAssertAuth { .. } => "host_assert_auth",
            Self::Consent { .. } => "consent",
            Self::WithdrawConsent { .. } => "withdraw_consent",
            Self::HostInPerson { .. } => "host_in_person",
            Self::ViewDocument { .. } => "view_document",
            Self::AdoptSignature { .. } => "adopt_signature",
            Self::CompleteField { .. } => "complete_field",
            Self::Finish { .. } => "finish",
            Self::SignOnPaper { .. } => "sign_on_paper",
            Self::Approve { .. } => "approve",
            Self::Decline { .. } => "decline",
            Self::Reassign { .. } => "reassign",
            Self::FinishLater { .. } => "finish_later",
            Self::RecipientEdit { .. } => "recipient_edit",
            Self::InvitationDispatched { .. } => "invitation_dispatched",
            Self::ReminderDispatched { .. } => "reminder_dispatched",
            Self::InvitationBounced { .. } => "invitation_bounced",
            Self::TimerDue { .. } => "timer_due",
            Self::Expire => "expire",
            Self::SealSucceeded { .. } => "seal_succeeded",
            Self::SealFailed { .. } => "seal_failed",
            Self::RecordAccess { .. } => "record_access",
            Self::Purge { .. } => "purge",
            Self::BeginRemoteSigning { .. } => "begin_remote_signing",
            Self::RemoteSigningPrepared { .. } => "remote_signing_prepared",
            Self::CompleteRemoteSigning { .. } => "complete_remote_signing",
            Self::FailRemoteSigning { .. } => "fail_remote_signing",
        }
    }
}

/// An audit event the decision produced, before the chain numbers it. The server
/// appends these, in order, in the same transaction as the state (ADR-010).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingEvent {
    /// The server's time.
    pub at: Timestamp,
    /// Who acted.
    pub actor: Actor,
    /// Request context.
    pub context: RequestContext,
    /// Type and data.
    pub data: EventData,
}

impl PendingEvent {
    /// The event with `v`, `envelope_id`, `seq` and `prev` taken from `chain`; append it
    /// before building the next.
    #[must_use]
    pub fn into_audit(self, chain: &Chain) -> AuditEvent {
        chain.next(self.at, self.actor, self.context, self.data)
    }
}

/// What a command decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decision {
    /// The new state, to write.
    pub state: EnvelopeState,
    /// The audit events, to append in order.
    pub events: Vec<PendingEvent>,
    /// The effects, to enqueue as jobs.
    pub effects: Vec<Effect>,
    /// The command id was applied before with this same command: nothing is written,
    /// and the server answers as it did the first time.
    pub replayed: bool,
}
