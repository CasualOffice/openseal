//! Certificate path building and validation (RFC 5280 §6, as far as docs/31 §7 needs):
//! from a signer or TSA certificate through supplied and embedded intermediates to a
//! supplied trust anchor; each certificate's signature, validity at the time asked, basic
//! constraints, path length, key usage, extended key usage, and critical extensions.

use core::time::Duration;

use casual_sign_crypto::{Certificate, CryptoError, oid};
use der::asn1::ObjectIdentifier;
use der::{Decode, Encode};
use x509_cert::ext::pkix::{
    AuthorityKeyIdentifier, BasicConstraints, ExtendedKeyUsage, KeyUsage, SubjectKeyIdentifier,
};

use crate::certsig;

/// Longest path built (leaf to anchor inclusive). Real PKIs use three or four.
pub(crate) const MAX_PATH: usize = 8;
/// Most issuer candidates tried in one path search, bounding the work a hostile pool of
/// same-named certificates can cause.
const MAX_TRIES: usize = 256;

/// `id-pkix-ocsp-nocheck` (RFC 6960 §4.2.2.2.1).
pub(crate) const OCSP_NOCHECK: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.5");

/// Extensions understood well enough to accept when critical.
const UNDERSTOOD: [ObjectIdentifier; 9] = [
    ObjectIdentifier::new_unwrap("2.5.29.19"), // basicConstraints
    ObjectIdentifier::new_unwrap("2.5.29.15"), // keyUsage
    ObjectIdentifier::new_unwrap("2.5.29.37"), // extKeyUsage
    ObjectIdentifier::new_unwrap("2.5.29.17"), // subjectAltName
    ObjectIdentifier::new_unwrap("2.5.29.18"), // issuerAltName
    ObjectIdentifier::new_unwrap("2.5.29.14"), // subjectKeyIdentifier
    ObjectIdentifier::new_unwrap("2.5.29.35"), // authorityKeyIdentifier
    // certificatePolicies: accepted unprocessed, as with an initial policy set of
    // anyPolicy and no explicit policy required (RFC 5280 §6.1.1).
    ObjectIdentifier::new_unwrap("2.5.29.32"),
    OCSP_NOCHECK,
];

/// A certificate with its DER.
#[derive(Clone, Debug)]
pub(crate) struct Cert {
    pub(crate) cert: Certificate,
    pub(crate) der: Vec<u8>,
}

impl Cert {
    pub(crate) fn from_der(der: &[u8]) -> Option<Self> {
        let cert = Certificate::from_der(der).ok()?;
        Some(Self {
            cert,
            der: der.to_vec(),
        })
    }

    /// From a decoded certificate (re-encoded: DER is canonical, so for a DER input the
    /// bytes are those received).
    pub(crate) fn from_parsed(cert: &Certificate) -> Option<Self> {
        Some(Self {
            der: cert.to_der().ok()?,
            cert: cert.clone(),
        })
    }

    fn same_key_and_name(&self, other: &Self) -> bool {
        let (a, b) = (self.cert.tbs_certificate(), other.cert.tbs_certificate());
        a.subject() == b.subject() && a.subject_public_key_info() == b.subject_public_key_info()
    }

    pub(crate) fn not_before(&self) -> Duration {
        self.cert
            .tbs_certificate()
            .validity()
            .not_before
            .to_unix_duration()
    }

    pub(crate) fn not_after(&self) -> Duration {
        self.cert
            .tbs_certificate()
            .validity()
            .not_after
            .to_unix_duration()
    }

    pub(crate) fn has_extension(&self, id: ObjectIdentifier) -> bool {
        self.cert
            .tbs_certificate()
            .extensions()
            .is_some_and(|e| e.iter().any(|x| x.extn_id == id))
    }

    pub(crate) fn has_eku(&self, id: ObjectIdentifier) -> bool {
        matches!(
            self.cert.tbs_certificate().get_extension::<ExtendedKeyUsage>(),
            Ok(Some((_, eku))) if eku.0.contains(&id)
        )
    }

    /// True when `issuer` signed this certificate (name, key identifiers, signature over
    /// the `tbsCertificate` as received).
    pub(crate) fn issued_by(&self, issuer: &Self) -> bool {
        let tbs = self.cert.tbs_certificate();
        let itbs = issuer.cert.tbs_certificate();
        if tbs.issuer() != itbs.subject() {
            return false;
        }
        if let (Ok(Some((_, aki))), Ok(Some((_, ski)))) = (
            tbs.get_extension::<AuthorityKeyIdentifier>(),
            itbs.get_extension::<SubjectKeyIdentifier>(),
        ) && let Some(kid) = aki.key_identifier
            && kid != ski.0
        {
            return false;
        }
        let Some(tbs_raw) = first_child(&self.der) else {
            return false;
        };
        let Some(sig) = self.cert.signature().as_bytes() else {
            return false;
        };
        certsig::verify(
            itbs.subject_public_key_info(),
            self.cert.signature_algorithm(),
            None,
            tbs_raw,
            sig,
        )
        .is_ok()
    }
}

/// The first element (header and content) inside the outer SEQUENCE of `der`.
fn first_child(der: &[u8]) -> Option<&[u8]> {
    let content = tlv_content(der)?;
    let len = tlv_len(content)?;
    content.get(..len)
}

/// Length of the whole TLV at the start of `b` (definite DER lengths only).
pub(crate) fn tlv_len(b: &[u8]) -> Option<usize> {
    let first = *b.get(1)?;
    if first < 0x80 {
        return 2usize.checked_add(usize::from(first));
    }
    let n = usize::from(first & 0x7f);
    if n == 0 || n > 4 {
        return None;
    }
    let mut len: usize = 0;
    for i in 0..n {
        let byte = *b.get(i.checked_add(2)?)?;
        len = len.checked_mul(256)?.checked_add(usize::from(byte))?;
    }
    len.checked_add(2)?.checked_add(n)
}

fn tlv_content(b: &[u8]) -> Option<&[u8]> {
    let total = tlv_len(b)?;
    let first = *b.get(1)?;
    let header = if first < 0x80 {
        2
    } else {
        2usize.checked_add(usize::from(first & 0x7f))?
    };
    b.get(header..total)
}

/// What the end certificate is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Purpose {
    /// A document signer: `digitalSignature` or `nonRepudiation` when key usage is present.
    Signer,
    /// A TSA: the `timeStamping` key purpose.
    Tsa,
}

/// Why a path fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ChainFailure {
    /// No path to an anchor.
    NoChain,
    /// A certificate (index in the path) is outside its validity at the time asked;
    /// `before` when the time is before `notBefore`.
    OutOfValidity { index: usize, before: bool },
    /// A constraint fails.
    Constraints,
}

/// Find a path from `leaf` through `pool` to one of `anchors`. The result starts with
/// `leaf` and ends with an anchor. Signatures are checked while searching.
pub(crate) fn build(leaf: &Cert, pool: &[Cert], anchors: &[Cert]) -> Option<Vec<Cert>> {
    if anchors
        .iter()
        .any(|a| a.der == leaf.der || a.same_key_and_name(leaf))
    {
        return Some(vec![leaf.clone()]);
    }
    let mut tries = 0usize;
    let mut path = vec![leaf.clone()];
    if extend(&mut path, pool, anchors, &mut tries) {
        Some(path)
    } else {
        None
    }
}

fn extend(path: &mut Vec<Cert>, pool: &[Cert], anchors: &[Cert], tries: &mut usize) -> bool {
    if path.len() >= MAX_PATH {
        return false;
    }
    let Some(cur) = path.last().cloned() else {
        return false;
    };
    for a in anchors {
        *tries = tries.saturating_add(1);
        if *tries > MAX_TRIES {
            return false;
        }
        if cur.issued_by(a) {
            path.push(a.clone());
            return true;
        }
    }
    for c in pool {
        if path.iter().any(|p| p.der == c.der) {
            continue;
        }
        *tries = tries.saturating_add(1);
        if *tries > MAX_TRIES {
            return false;
        }
        if cur.issued_by(c) {
            path.push(c.clone());
            if extend(path, pool, anchors, tries) {
                return true;
            }
            path.pop();
        }
    }
    false
}

/// Validate a built path at time `at`. The last element is the anchor: trusted as
/// supplied, so neither its validity nor its constraints are checked (RFC 5280 §6.1.1).
pub(crate) fn validate(path: &[Cert], at: Duration, purpose: Purpose) -> Result<(), ChainFailure> {
    let Some((_anchor, rest)) = path.split_last() else {
        return Err(ChainFailure::NoChain);
    };
    for (index, c) in rest.iter().enumerate() {
        if at < c.not_before() {
            return Err(ChainFailure::OutOfValidity {
                index,
                before: true,
            });
        }
        if at > c.not_after() {
            return Err(ChainFailure::OutOfValidity {
                index,
                before: false,
            });
        }
        let tbs = c.cert.tbs_certificate();
        if let Some(exts) = tbs.extensions()
            && exts
                .iter()
                .any(|e| e.critical && !UNDERSTOOD.contains(&e.extn_id))
        {
            return Err(ChainFailure::Constraints);
        }
        let ku = match tbs.get_extension::<KeyUsage>() {
            Ok(k) => k.map(|(_, k)| k),
            Err(_) => return Err(ChainFailure::Constraints),
        };
        if index == 0 {
            match purpose {
                Purpose::Signer => {
                    if ku.is_some_and(|k| !k.digital_signature() && !k.non_repudiation()) {
                        return Err(ChainFailure::Constraints);
                    }
                }
                Purpose::Tsa => {
                    if !c.has_eku(oid::KP_TIME_STAMPING) {
                        return Err(ChainFailure::Constraints);
                    }
                }
            }
        } else {
            // An intermediate CA: cA, path length (intermediates below it), keyCertSign.
            let bc = match tbs.get_extension::<BasicConstraints>() {
                Ok(Some((_, bc))) => bc,
                _ => return Err(ChainFailure::Constraints),
            };
            if !bc.ca || ku.is_some_and(|k| !k.key_cert_sign()) {
                return Err(ChainFailure::Constraints);
            }
            let below = index.saturating_sub(1);
            if bc
                .path_len_constraint
                .is_some_and(|p| usize::from(p) < below)
            {
                return Err(ChainFailure::Constraints);
            }
        }
    }
    // Path length constraints of the anchor are not enforced (trusted as supplied).
    Ok(())
}

/// Parse a DER certificate for the trust store.
///
/// # Errors
/// [`CryptoError::Malformed`] when it is not a DER certificate.
pub(crate) fn parse(der: &[u8]) -> Result<Cert, CryptoError> {
    Cert::from_der(der).ok_or(CryptoError::Malformed(
        casual_sign_crypto::Structure::Certificate,
    ))
}
