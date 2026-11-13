//! Typed errors with stable codes (docs/20 `CS-WRK-*`; the store's, the engine's, the
//! SDK's and keyd's codes pass through unchanged).
//!
//! Messages carry codes, ids, counts and status numbers, never an address, a name, a
//! subject, a URL's path or query, or document content (`SEC-D01`).

use core::fmt;

use casual_sign_store::StoreError;
use casual_sign_workflow::WorkflowError;

/// Every error the worker returns.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum WorkerError {
    /// `CS-WRK-0001`: a setting is missing or invalid (named, never its value).
    Config {
        /// The setting.
        setting: &'static str,
    },
    /// `CS-WRK-0002`: a stored engine state does not read back as an `EnvelopeState`.
    StateUnreadable,
    /// `CS-WRK-0003`: an engine id the database keys by UUID is not one.
    NotUuid {
        /// What it names (`envelope`, `recipient`, ...).
        what: &'static str,
    },
    /// `CS-WRK-0004`: a job's payload is malformed, or its kind is unknown.
    BadJob {
        /// The job's kind as stored.
        kind: String,
    },
    /// `CS-WRK-0005`: an email address or header value was refused (`SEC-M02`).
    BadHeader {
        /// Which (`to`, `from`, `name`, `subject`).
        field: &'static str,
    },
    /// `CS-WRK-0006`: the SMTP server could not be reached or refused for now.
    SmtpTransient,
    /// `CS-WRK-0007`: the SMTP server refused the recipient permanently (a bounce).
    SmtpPermanent,
    /// `CS-WRK-0008`: a webhook URL was refused: not HTTPS, unparsable, or it resolves
    /// to a private, loopback, link-local, metadata or otherwise non-public address
    /// that is not allow-listed (`SEC-W01`).
    WebhookRefused,
    /// `CS-WRK-0009`: a webhook delivery failed: timeout, connection or TLS failure, or
    /// a status other than 2xx.
    WebhookFailed {
        /// The HTTP status, when one came back.
        status: Option<u16>,
    },
    /// `CS-WRK-0010`: a secret reference does not resolve.
    SecretMissing,
    /// `CS-WRK-0011`: something the seal job needs is missing or unusable: a delivered
    /// document's blob, a capture, a recipient's row.
    SealInput {
        /// What.
        what: &'static str,
    },
    /// `CS-WRK-0012`: a sealed document did not pass independent verification; the
    /// envelope stays `completing`.
    NotVerified {
        /// The failing check, as the verifier names it.
        check: &'static str,
    },
    /// `CS-WRK-0013`: the channel has no provider configured (SMS, WhatsApp).
    NoChannel,
    /// `CS-WRK-0014`: no payment gateway is configured (slice 13).
    NoPaymentGateway,
    /// `CS-WRK-0015`: the job's lease was lost (it lapsed and another worker took it).
    LeaseLost,
    /// `CS-WRK-0016`: a capture (signature art) is malformed or over its limits.
    BadCapture,
    /// `CS-WRK-0017`: the SMS or voice provider did not accept the message (slice 5);
    /// `status` is its HTTP status, when it answered.
    MessengerFailed {
        /// The provider's HTTP status, when it answered.
        status: Option<u16>,
    },
    /// The store's error (`CS-DB-*`, `CS-BLOB-*`).
    Store(StoreError),
    /// The engine refused the worker's command (`CS-WF-*`, `CS-FLD-*`, `CS-AUTH-*`).
    Workflow {
        /// Its code.
        code: &'static str,
    },
    /// A pipeline step failed (`CS-PDF-*`, `CS-FLT-*`, `CS-SEAL-*`, `CS-AUD-*`,
    /// `CS-KEY-*`, ...).
    Pipeline {
        /// Its code.
        code: &'static str,
    },
    /// The model service failed or refused (`CS-ML-*`, docs/33 §12); retried only when it
    /// was unreachable, busy or out of time.
    Model {
        /// Its code.
        code: &'static str,
    },
}

impl WorkerError {
    /// The stable docs/20 code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Config { .. } => "CS-WRK-0001",
            Self::StateUnreadable => "CS-WRK-0002",
            Self::NotUuid { .. } => "CS-WRK-0003",
            Self::BadJob { .. } => "CS-WRK-0004",
            Self::BadHeader { .. } => "CS-WRK-0005",
            Self::SmtpTransient => "CS-WRK-0006",
            Self::SmtpPermanent => "CS-WRK-0007",
            Self::WebhookRefused => "CS-WRK-0008",
            Self::WebhookFailed { .. } => "CS-WRK-0009",
            Self::SecretMissing => "CS-WRK-0010",
            Self::SealInput { .. } => "CS-WRK-0011",
            Self::NotVerified { .. } => "CS-WRK-0012",
            Self::NoChannel => "CS-WRK-0013",
            Self::NoPaymentGateway => "CS-WRK-0014",
            Self::LeaseLost => "CS-WRK-0015",
            Self::BadCapture => "CS-WRK-0016",
            Self::MessengerFailed { .. } => "CS-WRK-0017",
            Self::Store(e) => e.code(),
            Self::Workflow { code } | Self::Pipeline { code } | Self::Model { code } => code,
        }
    }

    /// Whether running the job again may succeed. A job whose error is not retryable is
    /// dead at once; a retryable one waits for its back-off.
    #[must_use]
    pub fn retryable(&self) -> bool {
        match self {
            Self::Config { .. }
            | Self::StateUnreadable
            | Self::NotUuid { .. }
            | Self::BadJob { .. }
            | Self::BadHeader { .. }
            | Self::SmtpPermanent
            | Self::WebhookRefused
            | Self::NoChannel
            | Self::NoPaymentGateway
            | Self::BadCapture
            | Self::Workflow { .. } => false,
            Self::Model { code } => matches!(*code, "CS-ML-0007" | "CS-ML-0008" | "CS-ML-0009"),
            Self::Store(e) => !matches!(
                e.code(),
                "CS-DB-0008" | "CS-DB-0009" | "CS-DB-0010" | "CS-BLOB-0003" | "CS-BLOB-0005"
            ),
            _ => true,
        }
    }
}

impl fmt::Display for WorkerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = self.code();
        match self {
            Self::Config { setting } => write!(f, "{code}: setting {setting} missing or invalid"),
            Self::StateUnreadable => write!(f, "{code}: stored envelope state is unreadable"),
            Self::NotUuid { what } => write!(f, "{code}: {what} id is not a UUID"),
            Self::BadJob { kind } => write!(f, "{code}: job of kind {kind:?} is malformed"),
            Self::BadHeader { field } => write!(f, "{code}: email {field} refused"),
            Self::SmtpTransient => write!(f, "{code}: SMTP delivery failed for now"),
            Self::SmtpPermanent => write!(f, "{code}: SMTP refused the recipient permanently"),
            Self::WebhookRefused => write!(f, "{code}: webhook URL refused (SSRF policy)"),
            Self::WebhookFailed { status } => match status {
                Some(s) => write!(f, "{code}: webhook answered {s}"),
                None => write!(f, "{code}: webhook delivery failed"),
            },
            Self::SecretMissing => write!(f, "{code}: secret reference does not resolve"),
            Self::SealInput { what } => write!(f, "{code}: seal input missing: {what}"),
            Self::NotVerified { check } => {
                write!(f, "{code}: sealed output failed verification: {check}")
            }
            Self::NoChannel => write!(f, "{code}: no provider for this channel"),
            Self::NoPaymentGateway => write!(f, "{code}: no payment gateway configured"),
            Self::LeaseLost => write!(f, "{code}: job lease lost"),
            Self::BadCapture => write!(f, "{code}: capture malformed or over its limits"),
            Self::MessengerFailed { status } => match status {
                Some(s) => write!(f, "{code}: the SMS or voice provider answered {s}"),
                None => write!(f, "{code}: the SMS or voice provider could not be reached"),
            },
            Self::Store(e) => write!(f, "{e}"),
            Self::Workflow { .. } => write!(f, "{code}: the engine refused the worker's command"),
            Self::Pipeline { .. } => write!(f, "{code}: a pipeline step failed"),
            Self::Model { .. } => write!(f, "{code}: the model service failed"),
        }
    }
}

impl std::error::Error for WorkerError {}

impl From<casual_sign_modeld::ModeldError> for WorkerError {
    fn from(e: casual_sign_modeld::ModeldError) -> Self {
        Self::Model { code: e.code() }
    }
}

impl From<casual_sign_host::capture::BadCapture> for WorkerError {
    fn from(_: casual_sign_host::capture::BadCapture) -> Self {
        Self::BadCapture
    }
}

impl From<StoreError> for WorkerError {
    fn from(e: StoreError) -> Self {
        Self::Store(e)
    }
}

impl From<casual_sign_host::HostError> for WorkerError {
    fn from(e: casual_sign_host::HostError) -> Self {
        use casual_sign_host::HostError as H;
        match e {
            H::Clock => Self::Config { setting: "clock" },
            H::StateUnreadable => Self::StateUnreadable,
            H::NotUuid { what } => Self::NotUuid { what },
            H::BadJob { kind } => Self::BadJob { kind },
            H::Workflow(w) => Self::Workflow { code: w.code() },
            H::Store(s) => Self::Store(s),
            other => Self::Pipeline { code: other.code() },
        }
    }
}

impl From<WorkflowError> for WorkerError {
    fn from(e: WorkflowError) -> Self {
        Self::Workflow { code: e.code() }
    }
}

/// Shorthand.
pub type Result<T, E = WorkerError> = core::result::Result<T, E>;
