//! OCSP responses (RFC 6960) and CRLs (RFC 5280 §5): enough to answer "was serial S of
//! this issuer revoked at time T, according to this data, and is the data signed by the
//! issuer or a responder it authorized?". No network; the host fetches. Path building for
//! the issuer itself is the verifier's job (docs/31 §7).
//!
//! Signed parts (`tbsResponseData`, `tbsCertList`, a delegated responder's
//! `tbsCertificate`) are verified exactly as received, never re-encoded.

use core::time::Duration;

use der::Decode;
use x509_cert::Certificate;
use x509_cert::crl::CertificateList;
use x509_cert::ext::pkix::crl::IssuingDistributionPoint;
use x509_cert::ext::pkix::name::DistributionPointName;
use x509_cert::ext::pkix::{BasicConstraints, CrlDistributionPoints, ExtendedKeyUsage, KeyUsage};
use x509_cert::serial_number::SerialNumber;
use x509_ocsp::{BasicOcspResponse, CertStatus, OcspResponse, OcspResponseStatus};

use crate::der_walk;
use crate::digest::DigestAlgorithm;
use crate::error::{CryptoError, RevocationFailure, Structure};
use crate::oid;
use crate::signature::{self, Scheme, to_der};

/// Largest OCSP response parsed.
pub const MAX_OCSP_LEN: usize = 1024 * 1024;
/// Largest CRL parsed. Public CA CRLs reach tens of MB; ours and most TSAs' are small.
pub const MAX_CRL_LEN: usize = 32 * 1024 * 1024;

/// What revocation data says about one certificate at one time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RevocationStatus {
    /// Not revoked at the time asked.
    Good,
    /// Revoked at or before the time asked.
    Revoked {
        /// When it was revoked, since the Unix epoch.
        revoked_at: Duration,
    },
    /// The OCSP responder does not know the certificate.
    Unknown,
}

impl RevocationStatus {
    /// `Ok` only for [`RevocationStatus::Good`].
    ///
    /// # Errors
    /// [`CryptoError::Revoked`] (`CS-VER-0005`) for a revoked certificate;
    /// [`CryptoError::Revocation`] (`CS-SEAL-0004`) for an unknown one.
    pub const fn require_good(self) -> Result<(), CryptoError> {
        match self {
            Self::Good => Ok(()),
            Self::Revoked { .. } => Err(CryptoError::Revoked),
            Self::Unknown => Err(CryptoError::Revocation(RevocationFailure::NotCovered)),
        }
    }
}

fn fail(f: RevocationFailure) -> CryptoError {
    CryptoError::Revocation(f)
}

/// Whether data issued at `this_update`, valid to `next_update`, speaks for time `at`:
/// any earlier time, or a later one up to `next_update`.
fn in_period(at: Duration, this_update: Duration, next_update: Option<Duration>) -> bool {
    at <= this_update || next_update.is_some_and(|n| at <= n)
}

/// Verify `signature` over `tbs_raw` with `signer`'s key under `alg`.
fn verify_with(
    signer: &Certificate,
    alg: &spki::AlgorithmIdentifierOwned,
    tbs_raw: &[u8],
    signature: &der::asn1::BitString,
) -> Result<(), CryptoError> {
    let scheme = Scheme::from_algorithm_identifier(alg, None)?;
    let sig = signature.as_bytes().ok_or(CryptoError::SignatureInvalid)?;
    signature::verify(
        signer.tbs_certificate().subject_public_key_info(),
        scheme,
        tbs_raw,
        sig,
    )
}

/// The status of `serial`, issued by `issuer`, at time `at` according to the OCSP
/// response `response`.
///
/// The response must be signed by `issuer` itself or by a certificate carried in the
/// response that `issuer` signed and that has the `id-kp-OCSPSigning` key purpose and was
/// valid at `producedAt` (RFC 6960 §4.2.2.2). The matching `SingleResponse` must use a
/// SHA-2 `CertID`. A `revoked` status with a revocation time after `at` is `Good`.
///
/// # Errors
/// [`CryptoError::Revocation`] (`CS-SEAL-0004`) for an unusable response;
/// [`CryptoError::UnsupportedAlgorithm`] for a SHA-1 `CertID` or an unsupported key.
pub fn ocsp_status(
    response: &[u8],
    serial: &SerialNumber,
    issuer: &Certificate,
    at: Duration,
) -> Result<RevocationStatus, CryptoError> {
    let bad = CryptoError::Malformed(Structure::OcspResponse);
    if response.len() > MAX_OCSP_LEN {
        return Err(CryptoError::TooLarge(Structure::OcspResponse));
    }
    let tlv = der_walk::single_tlv(response).ok_or(bad)?;
    let outer = OcspResponse::from_der(tlv).map_err(|_| bad)?;
    if outer.response_status != OcspResponseStatus::Successful {
        return Err(fail(RevocationFailure::NotSuccessful));
    }
    let bytes = outer.response_bytes.ok_or(bad)?;
    if bytes.response_type != oid::OCSP_BASIC {
        return Err(fail(RevocationFailure::NotBasic));
    }
    let basic_der = der_walk::single_tlv(bytes.response.as_bytes()).ok_or(bad)?;
    let basic = BasicOcspResponse::from_der(basic_der).map_err(|_| bad)?;
    let tbs_raw = der_walk::first_child(basic_der).ok_or(bad)?;
    let produced_at = basic.tbs_response_data.produced_at.0.to_unix_duration();

    // Who signed: the issuer, or a delegated responder the issuer authorized.
    let by_issuer = verify_with(
        issuer,
        &basic.signature_algorithm,
        tbs_raw,
        &basic.signature,
    );
    if let Err(issuer_err) = by_issuer {
        // The issuer's key may not even fit the algorithm (an RSA responder under an EC
        // CA), so any issuer failure falls through to the delegated responders.
        let delegated = responder_certs(basic_der).ok_or(bad)?;
        let authorized = delegated.iter().any(|(cert, raw)| {
            verify_with(cert, &basic.signature_algorithm, tbs_raw, &basic.signature).is_ok()
                && delegated_by(cert, raw, issuer, produced_at)
        });
        if !authorized {
            return Err(match issuer_err {
                CryptoError::UnsupportedAlgorithm if delegated.is_empty() => issuer_err,
                _ => fail(RevocationFailure::UnauthorizedSigner),
            });
        }
    }

    let issuer_name = to_der(issuer.tbs_certificate().subject())?;
    let issuer_key = issuer
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .raw_bytes();
    let mut sha1_seen = false;
    let single = basic.tbs_response_data.responses.iter().find(|r| {
        let Ok(alg) = DigestAlgorithm::from_algorithm_identifier(&r.cert_id.hash_algorithm) else {
            sha1_seen = true;
            return false;
        };
        r.cert_id.serial_number == *serial
            && r.cert_id.issuer_name_hash.as_bytes() == alg.digest(&issuer_name).as_bytes()
            && r.cert_id.issuer_key_hash.as_bytes() == alg.digest(issuer_key).as_bytes()
    });
    let Some(single) = single else {
        return Err(if sha1_seen {
            CryptoError::UnsupportedAlgorithm
        } else {
            fail(RevocationFailure::NotCovered)
        });
    };

    let this_update = single.this_update.0.to_unix_duration();
    let next_update = single.next_update.map(|n| n.0.to_unix_duration());
    if !in_period(at, this_update, next_update) {
        return Err(fail(RevocationFailure::OutOfPeriod));
    }
    Ok(match &single.cert_status {
        CertStatus::Good(_) => RevocationStatus::Good,
        CertStatus::Unknown(_) => RevocationStatus::Unknown,
        CertStatus::Revoked(info) => {
            let revoked_at = info.revocation_time.0.to_unix_duration();
            if revoked_at <= at {
                RevocationStatus::Revoked { revoked_at }
            } else {
                RevocationStatus::Good
            }
        }
    })
}

/// The certificates in a `BasicOCSPResponse`'s `[0] certs`, each with its raw DER.
fn responder_certs(basic_der: &[u8]) -> Option<Vec<(Certificate, &[u8])>> {
    let items = der_walk::children(basic_der)?;
    let Some(explicit) = items.get(3) else {
        return Some(Vec::new());
    };
    let seq = der_walk::first_child(explicit)?;
    der_walk::children(seq)?
        .into_iter()
        .map(|raw| Certificate::from_der(raw).ok().map(|c| (c, raw)))
        .collect()
}

/// RFC 6960 §4.2.2.2: issued by `issuer` (name and signature over the raw
/// `tbsCertificate`), `id-kp-OCSPSigning`, and valid at `produced_at`.
fn delegated_by(
    cert: &Certificate,
    raw: &[u8],
    issuer: &Certificate,
    produced_at: Duration,
) -> bool {
    let tbs = cert.tbs_certificate();
    if tbs.issuer() != issuer.tbs_certificate().subject() {
        return false;
    }
    let Some(tbs_raw) = der_walk::first_child(raw) else {
        return false;
    };
    if verify_with(
        issuer,
        cert.signature_algorithm(),
        tbs_raw,
        cert.signature(),
    )
    .is_err()
    {
        return false;
    }
    let eku_ok = matches!(
        tbs.get_extension::<ExtendedKeyUsage>(),
        Ok(Some((_, eku))) if eku.0.contains(&oid::KP_OCSP_SIGNING)
    );
    let v = tbs.validity();
    eku_ok
        && v.not_before.to_unix_duration() <= produced_at
        && produced_at <= v.not_after.to_unix_duration()
}

/// The status of `serial`, issued by `issuer`, at time `at` according to the CRL `crl`.
///
/// The CRL must name `issuer` as its issuer, be signed by its key (with `cRLSign` if the
/// issuer has a key-usage extension), carry no critical extension other than those this
/// function understands (so indirect, delta and partitioned CRLs are refused: without the
/// certificate, a CRL's scope cannot be compared; [`crl_status_for`] can), and speak for
/// `at` (`at <= thisUpdate`, or `at <= nextUpdate`).
///
/// # Errors
/// [`CryptoError::Revocation`] (`CS-SEAL-0004`) for an unusable CRL;
/// [`CryptoError::UnsupportedAlgorithm`] for an unsupported signature.
pub fn crl_status(
    crl: &[u8],
    serial: &SerialNumber,
    issuer: &Certificate,
    at: Duration,
) -> Result<RevocationStatus, CryptoError> {
    crl_check(crl, serial, issuer, at, None)
}

/// [`crl_status`] for the certificate `subject`, which also reads a CRL scoped by an
/// Issuing Distribution Point (RFC 5280 §5.2.5, §6.3.3), as production CAs issue them
/// (HRD-02): the CRL answers only when its scope covers `subject`, that is its
/// distribution point is one `subject`'s CRL distribution points names, and its
/// user-only or CA-only restriction fits `subject`'s basic constraints. Indirect CRLs and
/// CRLs for only some reasons are still refused.
///
/// # Errors
/// As [`crl_status`]; [`RevocationFailure::NotCovered`] when the CRL's scope does not
/// include `subject`.
pub fn crl_status_for(
    crl: &[u8],
    subject: &Certificate,
    issuer: &Certificate,
    at: Duration,
) -> Result<RevocationStatus, CryptoError> {
    crl_check(
        crl,
        subject.tbs_certificate().serial_number(),
        issuer,
        at,
        Some(subject),
    )
}

/// Whether a CRL whose Issuing Distribution Point is `idp` speaks for `subject`.
/// `Err` for scopes this crate does not process (indirect, some reasons only).
fn idp_covers(idp: &IssuingDistributionPoint, subject: &Certificate) -> Result<bool, CryptoError> {
    if idp.indirect_crl || idp.only_some_reasons.is_some() {
        return Err(fail(RevocationFailure::UnsupportedCriticalExtension));
    }
    let restrictions = [
        idp.only_contains_user_certs,
        idp.only_contains_ca_certs,
        idp.only_contains_attribute_certs,
    ];
    if restrictions.iter().filter(|r| **r).count() > 1 {
        return Err(CryptoError::Malformed(Structure::Crl));
    }
    let tbs = subject.tbs_certificate();
    let is_ca = matches!(
        tbs.get_extension::<BasicConstraints>(),
        Ok(Some((_, bc))) if bc.ca
    );
    if idp.only_contains_attribute_certs
        || (idp.only_contains_user_certs && is_ca)
        || (idp.only_contains_ca_certs && !is_ca)
    {
        return Ok(false);
    }
    Ok(match &idp.distribution_point {
        None => true,
        Some(DistributionPointName::FullName(names)) => {
            let Ok(Some((_, dps))) = tbs.get_extension::<CrlDistributionPoints>() else {
                return Ok(false);
            };
            // A distribution point of the certificate's own (no cRLIssuer), for every
            // reason, that names one of the CRL's names (§6.3.3 (b)(2)(i)).
            dps.0.iter().any(|dp| {
                dp.crl_issuer.is_none()
                    && dp.reasons.is_none()
                    && matches!(
                        &dp.distribution_point,
                        Some(DistributionPointName::FullName(own))
                            if own.iter().any(|n| names.contains(n))
                    )
            })
        }
        Some(DistributionPointName::NameRelativeToCRLIssuer(_)) => false,
    })
}

fn crl_check(
    crl: &[u8],
    serial: &SerialNumber,
    issuer: &Certificate,
    at: Duration,
    subject: Option<&Certificate>,
) -> Result<RevocationStatus, CryptoError> {
    let bad = CryptoError::Malformed(Structure::Crl);
    if crl.len() > MAX_CRL_LEN {
        return Err(CryptoError::TooLarge(Structure::Crl));
    }
    let tlv = der_walk::single_tlv(crl).ok_or(bad)?;
    let list = CertificateList::from_der(tlv).map_err(|_| bad)?;
    let tbs_raw = der_walk::first_child(tlv).ok_or(bad)?;
    let tbs = &list.tbs_cert_list;
    if tbs.signature != list.signature_algorithm {
        return Err(bad);
    }
    let itbs = issuer.tbs_certificate();
    if tbs.issuer != *itbs.subject() {
        return Err(fail(RevocationFailure::UnauthorizedSigner));
    }
    if let Ok(Some((_, ku))) = itbs.get_extension::<KeyUsage>()
        && !ku.crl_sign()
    {
        return Err(fail(RevocationFailure::UnauthorizedSigner));
    }
    verify_with(issuer, &list.signature_algorithm, tbs_raw, &list.signature).map_err(
        |e| match e {
            CryptoError::SignatureInvalid => fail(RevocationFailure::UnauthorizedSigner),
            other => other,
        },
    )?;
    let mut understood = vec![oid::CE_CRL_NUMBER, oid::CE_AUTHORITY_KEY_IDENTIFIER];
    if subject.is_some() {
        understood.push(oid::CE_ISSUING_DISTRIBUTION_POINT);
    }
    if tbs
        .crl_extensions
        .iter()
        .flatten()
        .any(|e| e.critical && !understood.contains(&e.extn_id))
    {
        return Err(fail(RevocationFailure::UnsupportedCriticalExtension));
    }
    if let Some(subject) = subject {
        // Critical or not (RFC 5280 says critical; some CAs differ), a scope is a scope.
        for e in tbs
            .crl_extensions
            .iter()
            .flatten()
            .filter(|e| e.extn_id == oid::CE_ISSUING_DISTRIBUTION_POINT)
        {
            let idp = der_walk::single_tlv(e.extn_value.as_bytes())
                .and_then(|t| IssuingDistributionPoint::from_der(t).ok())
                .ok_or(bad)?;
            if !idp_covers(&idp, subject)? {
                return Err(fail(RevocationFailure::NotCovered));
            }
        }
    }

    let this_update = tbs.this_update.to_unix_duration();
    let next_update = tbs.next_update.map(|t| t.to_unix_duration());
    if !in_period(at, this_update, next_update) {
        return Err(fail(RevocationFailure::OutOfPeriod));
    }
    let entry = tbs
        .revoked_certificates
        .iter()
        .flatten()
        .find(|r| r.serial_number == *serial);
    let Some(entry) = entry else {
        return Ok(RevocationStatus::Good);
    };
    if entry
        .crl_entry_extensions
        .iter()
        .flatten()
        .any(|e| e.critical && e.extn_id != oid::CE_CRL_REASONS)
    {
        return Err(fail(RevocationFailure::UnsupportedCriticalExtension));
    }
    let revoked_at = entry.revocation_date.to_unix_duration();
    Ok(if revoked_at <= at {
        RevocationStatus::Revoked { revoked_at }
    } else {
        RevocationStatus::Good
    })
}

// Tests may unwrap, index and panic (CLAUDE.md).
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn period_rules() {
        let s = Duration::from_secs;
        assert!(in_period(s(5), s(10), None));
        assert!(in_period(s(10), s(10), None));
        assert!(!in_period(s(11), s(10), None));
        assert!(in_period(s(15), s(10), Some(s(20))));
        assert!(!in_period(s(21), s(10), Some(s(20))));
    }
}
