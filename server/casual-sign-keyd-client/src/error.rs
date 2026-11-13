//! keyd's errors, each with a stable docs/20 `CS-KEY-*` code (and `CS-CON-0008` for an
//! admin call refused). Messages carry counts, aliases and PKCS#11 return values, never a
//! PIN, key bytes or document content.
//!
//! Moved from `casual-sign-keyd` (`CON-06`, `CON-15`): both sides of the protocol name
//! the same errors; keyd re-exports them.

use core::fmt;

/// The wire number of `CS-CON-0008` (the `CS-KEY-` numbers stay below 1000).
pub const ADMIN_REFUSED: u16 = 1008;

/// Why a key operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeydError {
    /// `CS-KEY-0001`: the caller presented no certificate, an untrusted one, or one that
    /// is not on the allow-list.
    NotAuthorized,
    /// `CS-KEY-0002`: no key has this alias.
    UnknownAlias,
    /// `CS-KEY-0003`: the HSM or KMS could not be reached, refused the login, or failed
    /// an operation. `what` names the step and the module's return value.
    Backend {
        /// The step and the PKCS#11 return value (`C_Sign: CKR_DEVICE_ERROR`, say).
        what: String,
    },
    /// `CS-KEY-0004`: a file key was offered without `OPENSEAL_DEV_INSECURE_KEY=1`.
    InsecureKeyRefused,
    /// `CS-KEY-0005`: a secret (the PIN) could not be read.
    Secret(String),
    /// `CS-KEY-0006`: the key or its certificates do not form a usable signer.
    KeyConfig(KeyConfigProblem),
    /// `CS-KEY-0007`: a request or a response does not follow the protocol.
    Malformed(&'static str),
    /// `CS-KEY-0008`: the caller exceeded its rate.
    RateLimited,
    /// `CS-KEY-0009`: the operation log cannot be opened, read back or written; no
    /// signature is released without its record.
    OperationLog(String),
    /// `CS-KEY-0010`: the TLS certificates or keys do not load.
    TlsConfig(String),
    /// `CS-KEY-0011`: keyd could not be reached, or the connection failed before TLS
    /// answered (refused, reset, timed out, closed, the name does not resolve): an
    /// outage, which a later call may not meet.
    Transport(String),
    /// `CS-KEY-0013`: the TLS handshake was refused: keyd's certificate does not chain
    /// to the configured CA or does not carry the configured name, or keyd refused this
    /// client's certificate (untrusted, expired, revoked, none). A configuration error
    /// that retrying does not cure (`HRD-01`); `what` is the TLS library's reason.
    TlsRefused(String),
    /// `CS-KEY-0012`: a daemon setting is missing or invalid (named).
    Setting(&'static str),
    /// `CS-CON-0008`: an admin call from a caller on the signing allow-list, or a signing
    /// call from a caller on the admin allow-list (docs/23 §5.4, `CON-06`).
    AdminRefused,
}

/// What is wrong with a key's configuration (`CS-KEY-0006`).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyConfigProblem {
    /// No certificate was supplied or found.
    NoCertificate,
    /// A certificate or a PEM block does not parse.
    BadCertificate,
    /// The key file holds no usable private key (or an encrypted one).
    BadKeyFile,
    /// The token has no slot with this label.
    NoToken,
    /// Neither a label nor an id names the key.
    NoSelector,
    /// No private key matches the selector.
    KeyNotFound,
    /// More than one private key matches the selector.
    KeyAmbiguous(usize),
    /// The key is not the signer certificate's.
    KeyCertificateMismatch,
    /// The key type, curve or the requested scheme is not one the seal supports.
    UnsupportedAlgorithm,
}

impl KeydError {
    /// The stable docs/20 code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::NotAuthorized => "CS-KEY-0001",
            Self::UnknownAlias => "CS-KEY-0002",
            Self::Backend { .. } => "CS-KEY-0003",
            Self::InsecureKeyRefused => "CS-KEY-0004",
            Self::Secret(_) => "CS-KEY-0005",
            Self::KeyConfig(_) => "CS-KEY-0006",
            Self::Malformed(_) => "CS-KEY-0007",
            Self::RateLimited => "CS-KEY-0008",
            Self::OperationLog(_) => "CS-KEY-0009",
            Self::TlsConfig(_) => "CS-KEY-0010",
            Self::Transport(_) => "CS-KEY-0011",
            Self::TlsRefused(_) => "CS-KEY-0013",
            Self::Setting(_) => "CS-KEY-0012",
            Self::AdminRefused => "CS-CON-0008",
        }
    }

    /// The code's number, as the wire protocol carries it: the `CS-KEY-` number, and
    /// [`ADMIN_REFUSED`] for `CS-CON-0008`.
    #[must_use]
    pub const fn number(&self) -> u16 {
        match self {
            Self::NotAuthorized => 1,
            Self::UnknownAlias => 2,
            Self::Backend { .. } => 3,
            Self::InsecureKeyRefused => 4,
            Self::Secret(_) => 5,
            Self::KeyConfig(_) => 6,
            Self::Malformed(_) => 7,
            Self::RateLimited => 8,
            Self::OperationLog(_) => 9,
            Self::TlsConfig(_) => 10,
            Self::Transport(_) => 11,
            Self::TlsRefused(_) => 13,
            Self::Setting(_) => 12,
            Self::AdminRefused => ADMIN_REFUSED,
        }
    }

    /// The error a remote keyd reported by number. Detail stays on the server, in its
    /// own log; the caller learns only the code.
    #[must_use]
    pub fn from_number(n: u16) -> Self {
        match n {
            1 => Self::NotAuthorized,
            2 => Self::UnknownAlias,
            3 => Self::Backend {
                what: "reported by keyd".into(),
            },
            4 => Self::InsecureKeyRefused,
            6 => Self::KeyConfig(KeyConfigProblem::UnsupportedAlgorithm),
            7 => Self::Malformed("refused by keyd"),
            8 => Self::RateLimited,
            9 => Self::OperationLog("reported by keyd".into()),
            ADMIN_REFUSED => Self::AdminRefused,
            _ => Self::Transport(format!("keyd answered with unknown error {n}")),
        }
    }

    /// The backend failed: `step` and the library's error.
    pub fn backend(step: &str, e: impl fmt::Display) -> Self {
        Self::Backend {
            what: format!("{step}: {e}"),
        }
    }
}

impl fmt::Display for KeyConfigProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCertificate => f.write_str("no signer certificate"),
            Self::BadCertificate => f.write_str("a certificate does not parse"),
            Self::BadKeyFile => f.write_str("the key file holds no usable unencrypted private key"),
            Self::NoToken => f.write_str("no token has the configured label"),
            Self::NoSelector => f.write_str("neither a key label nor a key id is configured"),
            Self::KeyNotFound => f.write_str("no private key matches the label or id"),
            Self::KeyAmbiguous(n) => write!(f, "{n} private keys match the label or id"),
            Self::KeyCertificateMismatch => f.write_str("the key is not the certificate's"),
            Self::UnsupportedAlgorithm => f.write_str(
                "the key is not ECDSA P-256/P-384 or RSA 2048-8192 with a supported scheme",
            ),
        }
    }
}

impl fmt::Display for KeydError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: ", self.code())?;
        match self {
            Self::NotAuthorized => f.write_str("caller not authorized"),
            Self::UnknownAlias => f.write_str("unknown key alias"),
            Self::Backend { what } => write!(f, "key backend failed ({what})"),
            Self::InsecureKeyRefused => f.write_str(
                "a file key is for development only; set OPENSEAL_DEV_INSECURE_KEY=1 to use one",
            ),
            Self::Secret(why) => write!(f, "secret unreadable: {why}"),
            Self::KeyConfig(p) => write!(f, "key configuration: {p}"),
            Self::Malformed(why) => write!(f, "malformed message: {why}"),
            Self::RateLimited => f.write_str("rate limited"),
            Self::OperationLog(why) => write!(f, "operation log: {why}"),
            Self::TlsConfig(why) => write!(f, "TLS configuration: {why}"),
            Self::Transport(why) => write!(f, "keyd unreachable: {why}"),
            Self::TlsRefused(why) => write!(f, "TLS handshake with keyd refused: {why}"),
            Self::Setting(name) => write!(f, "setting {name} is missing or invalid"),
            Self::AdminRefused => f.write_str(
                "admin call refused: a signing caller cannot administer, an admin caller cannot sign",
            ),
        }
    }
}

impl std::error::Error for KeydError {}

impl KeydError {
    /// The error for a failed read or write on keyd's connection: `CS-KEY-0013` when
    /// the TLS layer refused (the I/O error carries a `rustls::Error`: a certificate
    /// not trusted, a name mismatch, an alert from keyd), `CS-KEY-0011` otherwise.
    #[must_use]
    pub fn from_io(e: &std::io::Error) -> Self {
        match e
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        {
            Some(tls) => Self::TlsRefused(tls.to_string()),
            None => Self::Transport(e.kind().to_string()),
        }
    }
}

impl From<casual_sign_secrets::SecretError> for KeydError {
    fn from(e: casual_sign_secrets::SecretError) -> Self {
        Self::Secret(e.to_string())
    }
}
