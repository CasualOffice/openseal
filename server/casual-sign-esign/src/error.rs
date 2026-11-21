//! Why an eSign operation failed, with its docs/20 code, and how an ESP's own error code
//! ends a session (ADR-047 §3.9). Messages name the profile rule or member at fault and
//! the ESP's code, never a value, a name or a certificate.

use core::fmt;

use casual_sign_xml::XmlError;

/// An eSign failure.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EsignError {
    /// The answer is not readable XML within the eSign limits (`CS-RSP-0004`; the
    /// reader's own code is kept for the log).
    Xml(XmlError),
    /// The answer's XML Signature is outside the one profile ADR-047 §3.5 accepts: no
    /// signature, two, one elsewhere than last in the root, another reference,
    /// transform, canonicalization, digest or signature method, an `Object`
    /// (`CS-RSP-0004`).
    Profile(&'static str),
    /// The reference's digest is not the document's (`CS-RSP-0004`).
    DigestMismatch,
    /// The signature value does not verify under the configured certificate
    /// (`CS-RSP-0004`).
    SignatureInvalid,
    /// The answer is signed but not an answer we can read: a member missing, repeated,
    /// out of its bounds or of the wrong form (`CS-RSP-0004`).
    Response(&'static str),
    /// The configured certificate (the ESP's, or the ASP's) cannot be used: not DER, or
    /// a key we do not verify with (`CS-RSP-0010`).
    Certificate,
    /// A request cannot be written from these values (`CS-RSP-0010`: the catalogue's
    /// `asp_id` or `response_url`, or a hash that is not SHA-256).
    Request(&'static str),
    /// The ASP key's signature could not be made (keyd refused or failed;
    /// `CS-RSP-0002`).
    Signer,
}

impl EsignError {
    /// The stable docs/20 code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Xml(_)
            | Self::Profile(_)
            | Self::DigestMismatch
            | Self::SignatureInvalid
            | Self::Response(_) => "CS-RSP-0004",
            Self::Certificate | Self::Request(_) => "CS-RSP-0010",
            Self::Signer => "CS-RSP-0002",
        }
    }
}

impl From<XmlError> for EsignError {
    fn from(e: XmlError) -> Self {
        Self::Xml(e)
    }
}

impl fmt::Display for EsignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let code = self.code();
        match self {
            Self::Xml(e) => write!(f, "{code}: eSign answer not readable ({e})"),
            Self::Profile(what) => write!(f, "{code}: XML Signature refused ({what})"),
            Self::DigestMismatch => write!(f, "{code}: XML Signature reference digest differs"),
            Self::SignatureInvalid => write!(f, "{code}: XML Signature does not verify"),
            Self::Response(what) => write!(f, "{code}: eSign answer invalid ({what})"),
            Self::Certificate => write!(f, "{code}: configured certificate unusable"),
            Self::Request(what) => write!(f, "{code}: eSign request not written ({what})"),
            Self::Signer => write!(f, "{code}: the ASP key did not sign"),
        }
    }
}

impl std::error::Error for EsignError {}

/// How a session ends for an ESP's error (ADR-047 §3.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Failure {
    /// The signer stopped or failed to authenticate at the ESP; fields reopen.
    Cancelled,
    /// The ESP's page expired.
    Expired,
    /// The ESP refused the request or the ASP: a configuration or registration problem,
    /// alerted to the operator (`CS-RSP-0008`).
    ProviderRefused,
    /// The ESP failed (`CS-RSP-0002`).
    ProviderUnavailable,
}

impl Failure {
    /// The session's `failure` value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Cancelled => "cancelled",
            Self::Expired => "expired",
            Self::ProviderRefused => "provider_refused",
            Self::ProviderUnavailable => "provider_unavailable",
        }
    }
}

/// The session result for an ESP's `errCode` (Annexure 1 of the v2.1 specification, and
/// the UIDAI authentication codes it passes through) or a document's `error` ("User
/// Rejected"). An `ESP-` code not listed is the ESP's failure; any other code is an
/// authentication failure at the ESP, which is the signer's.
#[must_use]
pub fn failure_for(code: &str) -> Failure {
    let code = code.trim();
    if code.eq_ignore_ascii_case("User Rejected") {
        return Failure::Cancelled;
    }
    let Some(n) = code
        .strip_prefix("ESP-")
        .and_then(|n| n.parse::<u16>().ok())
    else {
        return Failure::Cancelled;
    };
    match n {
        944 | 945 => Failure::Cancelled,
        946 => Failure::Expired,
        901..=911 | 922 | 992 => Failure::ProviderRefused,
        _ => Failure::ProviderUnavailable,
    }
}

/// The ESP's code as the session and the audit trail keep it: letters, digits, `-`,
/// `_`, `.` and spaces as `_`, at most 64 characters (never its message).
#[must_use]
pub fn provider_code(code: &str) -> Option<String> {
    let c: String = code
        .trim()
        .chars()
        .map(|c| if c == ' ' { '_' } else { c })
        .filter(|c| c.is_ascii_alphanumeric() || "_.-".contains(*c))
        .take(64)
        .collect();
    (!c.is_empty() && !c.eq_ignore_ascii_case("NA")).then_some(c)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_annexure_code_ends_the_session_as_adr_047_says() {
        for (code, want) in [
            ("ESP-944", Failure::Cancelled),
            ("ESP-945", Failure::Cancelled),
            ("User Rejected", Failure::Cancelled),
            ("K-100", Failure::Cancelled),
            ("300", Failure::Cancelled),
            ("ESP-946", Failure::Expired),
            ("ESP-901", Failure::ProviderRefused),
            ("ESP-911", Failure::ProviderRefused),
            ("ESP-922", Failure::ProviderRefused),
            ("ESP-992", Failure::ProviderRefused),
            ("ESP-991", Failure::ProviderUnavailable),
            ("ESP-993", Failure::ProviderUnavailable),
            ("ESP-999", Failure::ProviderUnavailable),
            ("ESP-912", Failure::ProviderUnavailable),
        ] {
            assert_eq!(failure_for(code), want, "{code}");
        }
    }

    #[test]
    fn provider_codes_are_kept_as_short_tokens() {
        assert_eq!(provider_code("ESP-944").as_deref(), Some("ESP-944"));
        assert_eq!(
            provider_code("User Rejected").as_deref(),
            Some("User_Rejected")
        );
        assert_eq!(provider_code("NA"), None);
        assert_eq!(provider_code("<x>"), Some("x".into()));
        assert_eq!(provider_code(&"9".repeat(100)).map(|c| c.len()), Some(64));
    }
}
