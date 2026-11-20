//! Why a provider operation failed, with its docs/20 code. Messages name members, counts
//! and the provider's own error code, never a secret, a token, a name or a certificate.

use core::fmt;

/// A remote-provider failure.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum CscError {
    /// A secret could not be read (`CS-KEY-0005`).
    Secret(casual_sign_secrets::SecretError),
    /// The provider secrets key is missing or not a key, or a sealed value does not open
    /// under it (`CS-RSP-0009`).
    SecretsKey,
    /// The operator's provider catalogue is malformed (`CS-RSP-0010`): the provider's
    /// position and the member at fault.
    Catalogue {
        /// The provider's index, when the fault is in one.
        index: Option<usize>,
        /// The member.
        member: &'static str,
    },
    /// The provider is not in the catalogue, not offered to the account or not enabled
    /// (`CS-RSP-0001`).
    UnknownProvider,
    /// The provider could not be reached, timed out or answered 5xx (`CS-RSP-0002`).
    Unavailable,
    /// The provider's answer does not hold: oversized, malformed, a wrong count, a value
    /// or certificate that does not check (`CS-RSP-0004`).
    Invalid {
        /// What did not hold.
        what: &'static str,
    },
    /// The signer has no credential the account accepts (`CS-RSP-0006`).
    NoEligibleCredential,
    /// The provider refused the request: an OAuth or CSC error (`CS-RSP-0008` for a
    /// configuration fault such as `invalid_client`; the session fails
    /// `provider_refused`, `cancelled` or `expired` by [`CscError::session_failure`]).
    Refused {
        /// The provider's error code (`access_denied`, `invalid_request`, ...), checked
        /// to be a short token; never its description.
        code: String,
    },
    /// A target address is not allowed (`SEC-W01`): a private, loopback or link-local
    /// address that the operator did not allow (`CS-RSP-0002`).
    AddressRefused,
}

impl CscError {
    /// The stable docs/20 code.
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::Secret(e) => e.code(),
            Self::SecretsKey => "CS-RSP-0009",
            Self::Catalogue { .. } => "CS-RSP-0010",
            Self::UnknownProvider => "CS-RSP-0001",
            Self::Unavailable | Self::AddressRefused => "CS-RSP-0002",
            Self::Invalid { .. } => "CS-RSP-0004",
            Self::NoEligibleCredential => "CS-RSP-0006",
            Self::Refused { .. } => "CS-RSP-0008",
        }
    }

    /// The session's failure reason this error ends it with (ADR-046 §3.7, §3.12).
    #[must_use]
    pub fn session_failure(&self) -> &'static str {
        match self {
            Self::Refused { code } if code == "access_denied" => "cancelled",
            Self::Refused { code } if code == "invalid_grant" || code == "expired_token" => {
                "expired"
            }
            Self::Refused { .. } => "provider_refused",
            Self::Invalid { .. } => "response_invalid",
            Self::NoEligibleCredential => "no_eligible_credential",
            _ => "provider_unavailable",
        }
    }

    /// The provider's own code, for `provider_code` (never a message).
    #[must_use]
    pub fn provider_code(&self) -> Option<&str> {
        match self {
            Self::Refused { code } => Some(code),
            _ => None,
        }
    }
}

impl fmt::Display for CscError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = self.code();
        match self {
            Self::Secret(e) => write!(f, "{code}: {e}"),
            Self::SecretsKey => write!(f, "{code}: provider secrets key missing or wrong"),
            Self::Catalogue { index, member } => match index {
                Some(i) => write!(f, "{code}: signing providers: providers[{i}].{member}"),
                None => write!(f, "{code}: signing providers: {member}"),
            },
            Self::UnknownProvider => write!(f, "{code}: provider not available"),
            Self::Unavailable => write!(f, "{code}: provider unavailable"),
            Self::Invalid { what } => write!(f, "{code}: provider answer invalid ({what})"),
            Self::NoEligibleCredential => write!(f, "{code}: no eligible credential"),
            Self::Refused { code: c } => write!(f, "{code}: provider refused ({c})"),
            Self::AddressRefused => write!(f, "{code}: provider address not allowed"),
        }
    }
}

impl std::error::Error for CscError {}
