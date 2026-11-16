//! Revocation of every certificate in a path (docs/31 §7), from the document's DSS and
//! the caller's supplied answers, through `casual-sign-crypto`'s OCSP and CRL checks. A
//! delegated OCSP responder is itself covered: by `id-pkix-ocsp-nocheck`, or by a CRL of
//! its issuer.

use core::time::Duration;

use casual_sign_crypto::revocation::{RevocationStatus, crl_status_for, ocsp_status};
use casual_sign_crypto::{CryptoError, oid};
use der::Decode;
use x509_ocsp::{BasicOcspResponse, OcspResponse, ResponderId};

use crate::chain::{Cert, OCSP_NOCHECK};

/// OCSP responses and CRLs available to the verifier.
#[derive(Clone, Debug, Default)]
pub(crate) struct RevocationData {
    pub(crate) ocsps: Vec<Vec<u8>>,
    pub(crate) crls: Vec<Vec<u8>>,
}

/// What the data says about one certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum State {
    Good,
    Revoked(Duration),
    /// No usable answer.
    Missing,
    /// Only answers in algorithms we refuse (SHA-1 CertIDs, `SEAL-14`).
    Unsupported,
}

/// The delegated responder that signed an OCSP response, if it is not the issuer.
fn delegated_responder(response: &[u8], issuer: &Cert) -> Option<Cert> {
    let outer = OcspResponse::from_der(response).ok()?;
    let bytes = outer.response_bytes?;
    if bytes.response_type != oid::OCSP_BASIC {
        return None;
    }
    let basic = BasicOcspResponse::from_der(bytes.response.as_bytes()).ok()?;
    let issuer_subject = issuer.cert.tbs_certificate().subject();
    let by_issuer = match &basic.tbs_response_data.responder_id {
        ResponderId::ByName(n) => n == issuer_subject,
        ResponderId::ByKey(_) => false,
    };
    if by_issuer {
        return None;
    }
    basic
        .certs
        .iter()
        .flatten()
        .filter_map(Cert::from_parsed)
        .find(|c| c.cert.tbs_certificate().issuer() == issuer_subject && c.issued_by(issuer))
}

/// The status of `cert` (issued by `issuer`) at `at`. Any answer of revoked wins; then
/// any answer of good.
pub(crate) fn status(cert: &Cert, issuer: &Cert, at: Duration, data: &RevocationData) -> State {
    status_inner(cert, issuer, at, data, true)
}

fn status_inner(
    cert: &Cert,
    issuer: &Cert,
    at: Duration,
    data: &RevocationData,
    allow_ocsp: bool,
) -> State {
    let serial = cert.cert.tbs_certificate().serial_number();
    let mut good = false;
    let mut unsupported = false;
    let mut note = |r: Result<RevocationStatus, CryptoError>| -> Option<Duration> {
        match r {
            Ok(RevocationStatus::Good) => good = true,
            Ok(RevocationStatus::Revoked { revoked_at }) => return Some(revoked_at),
            Err(CryptoError::UnsupportedAlgorithm) => unsupported = true,
            Ok(RevocationStatus::Unknown) | Err(_) => {}
        }
        None
    };
    if allow_ocsp {
        for o in &data.ocsps {
            let r = ocsp_status(o, serial, &issuer.cert, at);
            if matches!(r, Ok(RevocationStatus::Good))
                && let Some(responder) = delegated_responder(o, issuer)
                && !responder.has_extension(OCSP_NOCHECK)
                && status_inner(&responder, issuer, at, data, false) != State::Good
            {
                // The responder itself is not shown unrevoked: the answer is unusable.
                continue;
            }
            if let Some(t) = note(r) {
                return State::Revoked(t);
            }
        }
    }
    for c in &data.crls {
        // Scope-aware: a CRL scoped by an Issuing Distribution Point answers only for the
        // certificates its scope covers (HRD-02).
        if let Some(t) = note(crl_status_for(c, &cert.cert, &issuer.cert, at)) {
            return State::Revoked(t);
        }
    }
    if good {
        State::Good
    } else if unsupported {
        State::Unsupported
    } else {
        State::Missing
    }
}
