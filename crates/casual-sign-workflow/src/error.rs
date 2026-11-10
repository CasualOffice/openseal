//! The one error type of the engine, and the violations a send or correction reports.

use core::fmt;

use casual_sign_audit::MarkKind;
use casual_sign_fields::{FieldError, Issue};
use casual_sign_model::{EnvelopeStatus, Id, ModelError, RecipientStatus};

/// Which kind of object an id names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ObjectKind {
    /// The envelope.
    Envelope,
    /// A recipient.
    Recipient,
    /// A document.
    Document,
    /// A field.
    Field,
}

impl fmt::Display for ObjectKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Envelope => "envelope",
            Self::Recipient => "recipient",
            Self::Document => "document",
            Self::Field => "field",
        })
    }
}

/// Why a seal result does not prove a verified seal (`CS-WF-0009`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SealFault {
    /// The result names a seal job that is not the one pending.
    UnknownJob,
    /// A document of the envelope has no sealed result.
    MissingDocument,
    /// A result names a document twice, or one the envelope does not have.
    UnexpectedDocument,
    /// The result says independent verification did not pass.
    NotVerified,
    /// The sealed input's hash is not the document as delivered to signers.
    InputMismatch,
    /// The result's profile is not the envelope's seal profile.
    WrongProfile,
}

/// One reason an envelope cannot be sent or a correction saved (`CS-WF-0004` and the
/// field codes it carries).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Problem {
    /// No document.
    NoDocuments,
    /// No recipient with a required action (everyone is a carbon copy, or nobody).
    NoActingRecipient,
    /// Over a count limit of docs/21.
    TooMany {
        /// What is counted: `recipients`, `fields` or `documents`.
        what: &'static str,
        /// How many there are.
        count: usize,
        /// How many are allowed.
        limit: usize,
    },
    /// A recipient has no address for their delivery and no earlier agent, intermediary
    /// or editor can supply one (`CS-WF-0005`).
    MissingAddress,
    /// A field names no recipient (only templates may).
    FieldWithoutRecipient,
    /// A field names a recipient the envelope does not have (`CS-WF-0008`).
    FieldOnUnknownRecipient,
    /// A field names a document the envelope does not have (`CS-WF-0008`).
    FieldOnUnknownDocument,
    /// A field is on a page past the end of its document.
    PageOutOfRange,
    /// The recipient's type cannot hold this kind of field (a carbon copy with a text
    /// field, an approver with a signature).
    FieldNotAllowedForType,
    /// A witness names no signing recipient (`CS-WF-0008`).
    UnknownWitnessed,
    /// The expiry is not after now.
    ExpiryInPast,
    /// A document has no pages, or more than docs/21 allows.
    DocumentPages,
    /// A field rule failed (`CS-FLD-*`).
    Field(FieldError),
}

/// A [`Problem`] and the object it is on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// The recipient, field or document concerned, when there is one.
    pub object: Option<Id>,
    /// What is wrong.
    pub problem: Problem,
}

impl Violation {
    /// The stable code of this violation.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match &self.problem {
            Problem::MissingAddress => "CS-WF-0005",
            Problem::FieldOnUnknownRecipient
            | Problem::FieldOnUnknownDocument
            | Problem::UnknownWitnessed => "CS-WF-0008",
            Problem::Field(e) => e.code(),
            _ => "CS-WF-0004",
        }
    }
}

/// Why a command was refused. Each variant maps to one stable code of docs/20.
///
/// Messages carry ids, statuses and counts, never names, addresses, reasons or values
/// (`SEC-D01`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WorkflowError {
    /// The command is not allowed in the envelope's status (`CS-WF-0001`).
    NotAllowed {
        /// The command.
        command: &'static str,
        /// The envelope's status.
        status: EnvelopeStatus,
    },
    /// The command is not allowed in the recipient's status or type (`CS-WF-0001`).
    NotAllowedForRecipient {
        /// The command.
        command: &'static str,
        /// The recipient.
        recipient: Id,
        /// Their status.
        status: RecipientStatus,
    },
    /// The command was built on an older version of the envelope (`CS-WF-0002`).
    StaleVersion {
        /// The version the command read.
        expected: u64,
        /// The current version.
        actual: u64,
    },
    /// The actor may not perform the command (`CS-WF-0003`).
    NotPermitted {
        /// The command.
        command: &'static str,
    },
    /// The envelope cannot be sent, or a correction saved, as it stands (`CS-WF-0004`).
    Invalid {
        /// Every violation found.
        violations: Vec<Violation>,
    },
    /// Finishing would leave a later recipient with no address (`CS-WF-0005`).
    Unreachable {
        /// The recipient who cannot be reached.
        recipient: Id,
    },
    /// The command id was already used for a different command (`CS-WF-0006`).
    CommandIdReused,
    /// Routing has not reached the recipient (`CS-WF-0007`).
    NotYourTurn {
        /// The recipient.
        recipient: Id,
    },
    /// No such envelope, recipient, document or field (`CS-WF-0008`).
    Unknown {
        /// What kind of object.
        kind: ObjectKind,
        /// Its id, when one was given.
        id: Option<Id>,
    },
    /// The seal result does not prove a verified seal of every document (`CS-WF-0009`).
    SealNotProven {
        /// What is missing.
        fault: SealFault,
    },
    /// An id is already used in the envelope (`CS-WF-0010`).
    DuplicateId {
        /// What kind of object.
        kind: ObjectKind,
        /// The id.
        id: Id,
    },
    /// The envelope has applied as many commands as one envelope may (`CS-WF-0011`).
    CommandLogFull {
        /// The limit.
        limit: usize,
    },
    /// The envelope's signing options do not allow this (`CS-WF-0012`).
    OptionDisabled {
        /// The option: `allow_decline`, `allow_reassign` or `allow_finish_later`.
        option: &'static str,
    },
    /// A signature or initials value needs the mark adopted first (`CS-WF-0013`).
    NotAdopted {
        /// The mark.
        mark: MarkKind,
    },
    /// A viewer has not viewed every document to the end (`CS-WF-0014`).
    NotViewed {
        /// The recipient.
        recipient: Id,
    },
    /// The document viewed is not the document as fixed: another hash, or pages it does
    /// not have (`CS-WF-0015`).
    DocumentMismatch {
        /// The document.
        document: Id,
    },
    /// The recipient may not set this field (another's, read-only, locked, or no input)
    /// (`CS-WF-0016`).
    FieldNotEditable {
        /// The field.
        field: Id,
    },
    /// A computed time is outside years 0000 to 9999 (`CS-WF-0017`).
    TimeOutOfRange,
    /// A value could not be put in canonical form for hashing (`CS-WF-0018`).
    Encoding,
    /// The envelope captures location and a recipient action came without one: the
    /// server supplies the device's location or, failing that, an IP approximation with
    /// its reason (`CS-WF-0019`, GEO-01).
    LocationRequired {
        /// The recipient who acted.
        recipient: Id,
    },
    /// The request's location contradicts the envelope's setting: a device location, or
    /// a reason saying the signer was asked, when the envelope does not capture
    /// location; or `not_requested` when it does (`CS-WF-0020`, GEO-01).
    LocationInconsistent {
        /// The envelope's `capture_location`.
        capture_location: bool,
    },
    /// The recipient has not passed every authentication requirement (`CS-AUTH-0003`).
    AuthRequired {
        /// The recipient.
        recipient: Id,
    },
    /// The recipient is locked after too many failed attempts (`CS-AUTH-0004`).
    AuthLocked {
        /// The recipient.
        recipient: Id,
    },
    /// The recipient has not accepted the current consumer disclosure (`CS-AUTH-0005`).
    ConsentRequired {
        /// The recipient.
        recipient: Id,
    },
    /// Field rules failed at completion or on a value (`CS-FLD-*`, the first issue's).
    Fields {
        /// Every issue, sorted by field id then code.
        issues: Vec<Issue>,
    },
    /// A model value was out of its bounds (the model's code).
    Model(ModelError),
}

impl WorkflowError {
    /// The stable code from docs/20.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::NotAllowed { .. } | Self::NotAllowedForRecipient { .. } => "CS-WF-0001",
            Self::StaleVersion { .. } => "CS-WF-0002",
            Self::NotPermitted { .. } => "CS-WF-0003",
            Self::Invalid { .. } => "CS-WF-0004",
            Self::Unreachable { .. } => "CS-WF-0005",
            Self::CommandIdReused => "CS-WF-0006",
            Self::NotYourTurn { .. } => "CS-WF-0007",
            Self::Unknown { .. } => "CS-WF-0008",
            Self::SealNotProven { .. } => "CS-WF-0009",
            Self::DuplicateId { .. } => "CS-WF-0010",
            Self::CommandLogFull { .. } => "CS-WF-0011",
            Self::OptionDisabled { .. } => "CS-WF-0012",
            Self::NotAdopted { .. } => "CS-WF-0013",
            Self::NotViewed { .. } => "CS-WF-0014",
            Self::DocumentMismatch { .. } => "CS-WF-0015",
            Self::FieldNotEditable { .. } => "CS-WF-0016",
            Self::TimeOutOfRange => "CS-WF-0017",
            Self::Encoding => "CS-WF-0018",
            Self::LocationRequired { .. } => "CS-WF-0019",
            Self::LocationInconsistent { .. } => "CS-WF-0020",
            Self::AuthRequired { .. } => "CS-AUTH-0003",
            Self::AuthLocked { .. } => "CS-AUTH-0004",
            Self::ConsentRequired { .. } => "CS-AUTH-0005",
            Self::Fields { issues } => issues.first().map_or("CS-FLD-0002", Issue::code),
            Self::Model(e) => e.code(),
        }
    }
}

impl From<ModelError> for WorkflowError {
    fn from(value: ModelError) -> Self {
        Self::Model(value)
    }
}

impl fmt::Display for WorkflowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = self.code();
        match self {
            Self::NotAllowed { command, status } => {
                write!(f, "{code}: {command} not allowed while {status:?}")
            }
            Self::NotAllowedForRecipient {
                command,
                recipient,
                status,
            } => write!(
                f,
                "{code}: {command} not allowed for recipient {recipient} while {status:?}"
            ),
            Self::StaleVersion { expected, actual } => {
                write!(f, "{code}: read version {expected}, current {actual}")
            }
            Self::NotPermitted { command } => write!(f, "{code}: actor may not {command}"),
            Self::Invalid { violations } => {
                write!(f, "{code}: {} violation(s)", violations.len())
            }
            Self::Unreachable { recipient } => {
                write!(f, "{code}: recipient {recipient} has no address")
            }
            Self::CommandIdReused => write!(f, "{code}: command id reused for another command"),
            Self::NotYourTurn { recipient } => {
                write!(f, "{code}: routing has not reached recipient {recipient}")
            }
            Self::Unknown { kind, id } => match id {
                Some(id) => write!(f, "{code}: no {kind} {id}"),
                None => write!(f, "{code}: no {kind}"),
            },
            Self::SealNotProven { fault } => write!(f, "{code}: seal not proven ({fault:?})"),
            Self::DuplicateId { kind, id } => write!(f, "{code}: {kind} {id} already exists"),
            Self::CommandLogFull { limit } => {
                write!(f, "{code}: envelope applied {limit} commands")
            }
            Self::OptionDisabled { option } => write!(f, "{code}: {option} is off"),
            Self::NotAdopted { mark } => write!(f, "{code}: {mark:?} not adopted"),
            Self::NotViewed { recipient } => {
                write!(
                    f,
                    "{code}: recipient {recipient} has not viewed every document"
                )
            }
            Self::DocumentMismatch { document } => {
                write!(f, "{code}: view of document {document} does not match it")
            }
            Self::FieldNotEditable { field } => write!(f, "{code}: field {field} not editable"),
            Self::TimeOutOfRange => write!(f, "{code}: time out of range"),
            Self::Encoding => write!(f, "{code}: value could not be encoded"),
            Self::LocationRequired { recipient } => {
                write!(f, "{code}: recipient {recipient} acted without a location")
            }
            Self::LocationInconsistent { capture_location } => write!(
                f,
                "{code}: location does not match capture_location = {capture_location}"
            ),
            Self::AuthRequired { recipient } => {
                write!(f, "{code}: recipient {recipient} not authenticated")
            }
            Self::AuthLocked { recipient } => write!(f, "{code}: recipient {recipient} locked"),
            Self::ConsentRequired { recipient } => {
                write!(f, "{code}: recipient {recipient} has not consented")
            }
            Self::Fields { issues } => write!(f, "{code}: {} field issue(s)", issues.len()),
            Self::Model(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for WorkflowError {}
