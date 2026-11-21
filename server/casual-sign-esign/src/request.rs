//! The ASP's request (eSign API v2.1 §3.3.1, ADR-047 §3.1): the `Esign` element with
//! one `InputHash`, written by us and signed with the ASP's key through keyd.
//!
//! What it carries (ADR-047 §3.1, §3.7): `ver="2.1"`; `sc="Y"` only because the signer
//! ticked the consent (the caller holds that proof); `ts` in Indian Standard Time;
//! `txn` the session id; `ekycId` empty and `ekycIdType="A"`, so **no Aadhaar number, VID
//! or UID token**: the signer gives those to the ESP on the ESP's page; `aspId`;
//! `AuthMode`; `responseSigType="pkcs7pdf"`; `responseUrl`; and the document's SHA-256
//! ByteRange digest in hex with `docInfo` (its name cut to 50 characters, control
//! characters removed).

use crate::dsig::{Algorithm, DigestSigner, sign_enveloped};
use crate::error::EsignError;

/// The API version written.
pub const VERSION: &str = "2.1";
/// The response signature type asked for (ADR-047 §3.2).
pub const RESPONSE_SIG_TYPE: &str = "pkcs7pdf";
/// Longest `docInfo`, in characters (ADR-047 §3.1, owner instruction 82).
pub const MAX_DOC_INFO: usize = 50;

/// How the ESP authenticates the signer (`AuthMode`, v2.1 §3.3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthMode {
    /// Aadhaar OTP (or TOTP): `1`.
    Otp,
    /// Fingerprint: `2` (assisted signing only).
    Fingerprint,
    /// Iris: `3` (assisted signing only).
    Iris,
    /// Face: `4`.
    Face,
}

impl AuthMode {
    /// The attribute value.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::Otp => "1",
            Self::Fingerprint => "2",
            Self::Iris => "3",
            Self::Face => "4",
        }
    }

    /// The name sessions, settings and audit events use.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Otp => "otp",
            Self::Fingerprint => "fingerprint",
            Self::Iris => "iris",
            Self::Face => "face",
        }
    }

    /// The mode a name (as [`AuthMode::as_str`]) names.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        [Self::Otp, Self::Fingerprint, Self::Iris, Self::Face]
            .into_iter()
            .find(|m| m.as_str() == name)
    }
}

/// One v2.1 request.
#[derive(Debug, Clone)]
pub struct Request<'a> {
    /// The ASP id the ESP registered.
    pub asp_id: &'a str,
    /// The transaction id: the session id (a UUIDv7).
    pub txn: &'a str,
    /// Unix seconds at which the request is made (written in IST).
    pub unix_time: i64,
    /// How the signer authenticates at the ESP.
    pub auth_mode: AuthMode,
    /// Where the ESP sends the answer.
    pub response_url: &'a str,
    /// The SHA-256 ByteRange digest of the prepared revision.
    pub sha256: &'a [u8],
    /// The document's name, or the account's generic label.
    pub doc_info: &'a str,
}

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

/// `docInfo` from a document name: control characters removed, white space runs made
/// one space, cut to [`MAX_DOC_INFO`] characters.
#[must_use]
pub fn doc_info(name: &str) -> String {
    name.split(|c: char| c.is_whitespace() || c.is_control())
        .filter(|p| !p.is_empty())
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(MAX_DOC_INFO)
        .collect()
}

/// `ts`: the time in Indian Standard Time (UTC+05:30), `YYYY-MM-DDThh:mm:ss`.
#[must_use]
// Clamped to years 1970 to 9999 first, so no step below can overflow an i64.
#[allow(clippy::arithmetic_side_effects, clippy::integer_division)]
pub fn ist(unix: i64) -> String {
    let t = unix.clamp(0, 253_402_300_799) + 5 * 3600 + 30 * 60;
    let days = t.div_euclid(86_400);
    let secs = t.rem_euclid(86_400);
    // Civil date from days since 1970-01-01 (H. Hinnant's algorithm).
    let z = days.saturating_add(719_468);
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

fn token(s: &str, max: usize) -> bool {
    !s.is_empty()
        && s.len() <= max
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:".contains(&b))
}

impl Request<'_> {
    /// The request without its signature.
    ///
    /// # Errors
    /// [`EsignError::Request`] for an `aspId` or `txn` that is not a short token, a
    /// `responseUrl` that is not HTTP(S), or a hash that is not 32 bytes.
    pub fn unsigned(&self) -> Result<String, EsignError> {
        if !token(self.asp_id, 64) {
            return Err(EsignError::Request("aspId"));
        }
        if !token(self.txn, 64) {
            return Err(EsignError::Request("txn"));
        }
        if !(self.response_url.starts_with("https://") || self.response_url.starts_with("http://"))
            || self.response_url.len() > 2048
        {
            return Err(EsignError::Request("responseUrl"));
        }
        if self.sha256.len() != 32 {
            return Err(EsignError::Request("hash"));
        }
        let hex: String = self.sha256.iter().map(|b| format!("{b:02x}")).collect();
        Ok(format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Esign ver=\"{VERSION}\" sc=\"Y\" ts=\"{}\" \
txn=\"{}\" ekycId=\"\" ekycIdType=\"A\" aspId=\"{}\" AuthMode=\"{}\" responseSigType=\"{RESPONSE_SIG_TYPE}\" \
responseUrl=\"{}\"><Docs><InputHash id=\"1\" hashAlgorithm=\"SHA256\" docInfo=\"{}\">{hex}</InputHash>\
</Docs></Esign>",
            ist(self.unix_time),
            escape(self.txn),
            escape(self.asp_id),
            self.auth_mode.code(),
            escape(self.response_url),
            escape(&doc_info(self.doc_info)),
        ))
    }

    /// The signed request: [`Request::unsigned`] with the enveloped XML Signature made
    /// by `sign` (keyd's `sign-digest` with the ASP key and an ASP token).
    ///
    /// # Errors
    /// As [`Request::unsigned`] and [`sign_enveloped`].
    pub fn signed(
        &self,
        algorithm: Algorithm,
        certificate: Option<&[u8]>,
        sign: &mut DigestSigner<'_>,
    ) -> Result<String, EsignError> {
        sign_enveloped(&self.unsigned()?, algorithm, certificate, sign)
    }
}

#[cfg(test)]
mod tests {
    // Test code: a panic is the failure report (CLAUDE.md).
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn ist_is_utc_plus_five_thirty() {
        assert_eq!(ist(0), "1970-01-01T05:30:00");
        // 2026-11-21T18:45:07Z
        assert_eq!(ist(1_795_286_707), "2026-11-22T00:15:07");
        assert_eq!(ist(951_782_400), "2000-02-29T05:30:00");
    }

    #[test]
    fn doc_info_is_cut_to_fifty_characters_without_controls() {
        assert_eq!(
            doc_info("Lease\u{7}  agreement\n2026.pdf"),
            "Lease agreement 2026.pdf"
        );
        let long = "ä".repeat(80);
        assert_eq!(doc_info(&long).chars().count(), 50);
    }

    #[test]
    fn the_request_carries_no_aadhaar_data_and_the_hash_in_hex() {
        let h = [0xabu8; 32];
        let r = Request {
            asp_id: "ASP-OPENSEAL",
            txn: "0192f3a4-0000-7000-8000-000000000001",
            unix_time: 0,
            auth_mode: AuthMode::Face,
            response_url: "https://sign.example.test/rsp/esign/emudhra/response",
            sha256: &h,
            doc_info: "A \"quoted\" <name> & more",
        }
        .unsigned()
        .unwrap();
        assert!(r.contains("ekycId=\"\" ekycIdType=\"A\""));
        assert!(r.contains("sc=\"Y\""));
        assert!(r.contains("AuthMode=\"4\""));
        assert!(r.contains(&"ab".repeat(32)));
        assert!(r.contains("docInfo=\"A &quot;quoted&quot; &lt;name&gt; &amp; more\""));
        assert!(!r.contains("uid") && !r.contains("Uid") && !r.contains("vid="));
    }

    #[test]
    fn a_request_refuses_values_it_cannot_write() {
        let h = [0u8; 32];
        let ok = Request {
            asp_id: "ASP",
            txn: "t1",
            unix_time: 0,
            auth_mode: AuthMode::Otp,
            response_url: "https://x.test/r",
            sha256: &h,
            doc_info: "d",
        };
        assert!(ok.unsigned().is_ok());
        let mut bad = ok.clone();
        bad.asp_id = "A\"SP";
        assert_eq!(bad.unsigned().unwrap_err(), EsignError::Request("aspId"));
        let mut bad = ok.clone();
        bad.response_url = "javascript:alert(1)";
        assert_eq!(
            bad.unsigned().unwrap_err(),
            EsignError::Request("responseUrl")
        );
        let mut bad = ok;
        bad.sha256 = &h[..20];
        assert_eq!(bad.unsigned().unwrap_err(), EsignError::Request("hash"));
    }
}
