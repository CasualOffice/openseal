//! A signature provider's own CMS (ADR-047 §3.3, §3.4): an India eSign Service
//! Provider's `PKCS7pdf` answer, which we embed but never re-sign.
//!
//! [`check_foreign`] establishes, before anything is written, that the CMS is DER
//! `SignedData` with exactly one SignerInfo whose signed attributes carry our
//! ByteRange digest as `message-digest`, that its signature verifies over those
//! attributes **as received** under the certificate the SignerInfo names, that this
//! certificate is the one the provider told us (`UserX509Certificate`), and with what
//! algorithm and key size. It reports whether the signed attributes are
//! CAdES-conformant (ESS `signing-certificate-v2`, no `signingTime`) and whether a
//! signature time-stamp is already there.
//!
//! [`append_unsigned_attribute`] adds our RFC 3161 time-stamp as an unsigned attribute
//! by splicing DER: every byte the provider signed, and every other byte of its
//! structure, is kept; only the lengths of the enclosing headers change.

use der::{Decode, Header, Reader, SliceReader};

use crate::cms::ParsedCms;
use crate::digest::DigestValue;
use crate::error::{CryptoError, Structure};
use crate::oid;
use crate::signature;

/// What a provider's CMS was found to be.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForeignCms {
    /// `ETSI.CAdES.detached`-conformant signed attributes: ESS `signing-certificate-v2`
    /// present and no `signingTime`.
    pub cades: bool,
    /// A `signature-time-stamp` unsigned attribute is already there.
    pub timestamped: bool,
    /// The signature value (what a B-T time-stamp covers).
    pub signature_value: Vec<u8>,
}

fn bad() -> CryptoError {
    CryptoError::Malformed(Structure::Cms)
}

/// Whether `cms` begins as BER with an indefinite length (refused until `SEAL-13`).
#[must_use]
pub fn is_ber(cms: &[u8]) -> bool {
    matches!(cms, [0x30, 0x80, ..])
}

/// Check a provider's detached CMS over `content_digest` (our ByteRange digest) and
/// against `signer_der`, the certificate the provider said signed.
///
/// # Errors
/// [`CryptoError::Malformed`] for BER or anything not DER `SignedData` with signed
/// attributes; [`CryptoError::SignerCount`]; [`CryptoError::DigestMismatch`] when its
/// `message-digest` is another; [`CryptoError::SigningCertificateMismatch`] when the
/// signer is another certificate; [`CryptoError::SignatureInvalid`];
/// [`CryptoError::UnsupportedAlgorithm`] for a weak digest, key or algorithm (RSA under
/// 2,048 bits).
pub fn check_foreign(
    cms: &[u8],
    content_digest: &DigestValue,
    signer_der: &[u8],
) -> Result<ForeignCms, CryptoError> {
    if is_ber(cms) {
        return Err(bad());
    }
    let parsed = ParsedCms::parse(cms)?;
    let verified = parsed.verify_detached_legacy(content_digest)?;
    if parsed.signer_certificate_der()? != signer_der {
        return Err(CryptoError::SigningCertificateMismatch);
    }
    let spki = verified.certificate.tbs_certificate().subject_public_key_info();
    if signature::rsa_modulus_len(spki).is_some_and(|n| n < 256) {
        return Err(CryptoError::UnsupportedAlgorithm);
    }
    let oids = parsed.signed_attribute_oids();
    Ok(ForeignCms {
        cades: oids.contains(&oid::ID_SIGNING_CERTIFICATE_V2)
            && !oids.contains(&oid::ID_SIGNING_TIME),
        timestamped: parsed.timestamp_token()?.is_some(),
        signature_value: parsed.signature_value()?.to_vec(),
    })
}

/// The CMS's one TLV without any zero padding after it.
///
/// # Errors
/// [`CryptoError::Malformed`] when it is not one TLV followed only by zeros.
pub fn trimmed(cms: &[u8]) -> Result<Vec<u8>, CryptoError> {
    crate::der_walk::single_tlv_zero_padded(cms)
        .map(<[u8]>::to_vec)
        .ok_or_else(bad)
}

/// DER length octets.
fn length(n: usize) -> Vec<u8> {
    if n < 0x80 {
        return vec![u8::try_from(n).unwrap_or(0)];
    }
    let bytes: Vec<u8> = n
        .to_be_bytes()
        .into_iter()
        .skip_while(|b| *b == 0)
        .collect();
    let mut out = vec![0x80 | u8::try_from(bytes.len()).unwrap_or(0)];
    out.extend(bytes);
    out
}

/// One TLV split into its tag octet, header length and content.
fn split(tlv: &[u8]) -> Option<(u8, &[u8])> {
    let mut r = SliceReader::new(tlv).ok()?;
    let h = Header::decode(&mut r).ok()?;
    let content = r.read_slice(h.length()).ok()?;
    if !r.is_finished() {
        return None;
    }
    Some((*tlv.first()?, content))
}

/// `tlv` with `extra` appended to the content of the constructed TLV `path` names
/// (each step an index among the children), every enclosing length re-encoded.
fn splice(tlv: &[u8], path: &[usize], extra: &[u8]) -> Option<Vec<u8>> {
    let (tag, content) = split(tlv)?;
    let new_content = match path.split_first() {
        None => [content, extra].concat(),
        Some((&i, rest)) => {
            let kids = crate::der_walk::children(tlv)?;
            let mut out = Vec::with_capacity(content.len().saturating_add(extra.len()));
            for (k, child) in kids.iter().enumerate() {
                if k == i {
                    out.extend(splice(child, rest, extra)?);
                } else {
                    out.extend_from_slice(child);
                }
            }
            if i >= kids.len() {
                return None;
            }
            out
        }
    };
    let mut out = vec![tag];
    out.extend(length(new_content.len()));
    out.extend(new_content);
    Some(out)
}

/// Add an unsigned attribute (`attr_oid` with one DER value `value`) to the only
/// SignerInfo of `cms`, which must have none yet.
///
/// # Errors
/// [`CryptoError::Malformed`] when `cms` is not one DER `ContentInfo` with one
/// SignerInfo, already has unsigned attributes, or `value` is not one TLV;
/// [`CryptoError::Encoding`] when the attribute cannot be encoded.
pub fn append_unsigned_attribute(
    cms: &[u8],
    attr_oid: der::asn1::ObjectIdentifier,
    value: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let tlv = crate::der_walk::single_tlv_zero_padded(cms).ok_or_else(bad)?;
    crate::der_walk::single_tlv(value).ok_or_else(bad)?;
    let ci = crate::der_walk::children(tlv).ok_or_else(bad)?;
    let explicit = ci.get(1).ok_or_else(bad)?;
    let sd = crate::der_walk::first_child(explicit).ok_or_else(bad)?;
    let sd_items = crate::der_walk::children(sd).ok_or_else(bad)?;
    let last = sd_items.len().checked_sub(1).ok_or_else(bad)?;
    let infos = crate::der_walk::children(sd_items.get(last).ok_or_else(bad)?).ok_or_else(bad)?;
    let [si] = infos.as_slice() else {
        return Err(bad());
    };
    let si_items = crate::der_walk::children(si).ok_or_else(bad)?;
    if si_items.last().and_then(|t| t.first()) == Some(&0xA1) {
        return Err(bad());
    }
    // Attribute ::= SEQUENCE { attrType OID, attrValues SET OF ANY }
    let oid_der = crate::signature::to_der(&attr_oid).map_err(|_| CryptoError::Encoding)?;
    let mut set = vec![0x31];
    set.extend(length(value.len()));
    set.extend_from_slice(value);
    let body = [oid_der, set].concat();
    let mut attribute = vec![0x30];
    attribute.extend(length(body.len()));
    attribute.extend(body);
    // [1] IMPLICIT SET OF Attribute
    let mut unsigned = vec![0xA1];
    unsigned.extend(length(attribute.len()));
    unsigned.extend(attribute);
    splice(tlv, &[1, 0, last, 0], &unsigned).ok_or_else(bad)
}

#[cfg(test)]
mod tests {
    // Test code: a panic is the failure report (CLAUDE.md).
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn lengths_are_minimal_der() {
        assert_eq!(length(0x7f), vec![0x7f]);
        assert_eq!(length(0x80), vec![0x81, 0x80]);
        assert_eq!(length(0x1234), vec![0x82, 0x12, 0x34]);
    }

    #[test]
    fn splicing_reencodes_every_enclosing_length() {
        // SEQ { SEQ { INT 1 } }  -> append INT 2 inside the inner SEQ.
        let tlv = [0x30, 0x05, 0x30, 0x03, 0x02, 0x01, 0x01];
        let out = splice(&tlv, &[0], &[0x02, 0x01, 0x02]).unwrap();
        assert_eq!(out, vec![0x30, 0x08, 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02]);
        assert!(splice(&tlv, &[3], &[0x05, 0x00]).is_none());
    }

    #[test]
    fn ber_is_recognized() {
        assert!(is_ber(&[0x30, 0x80, 0x06]));
        assert!(!is_ber(&[0x30, 0x03, 0x02, 0x01, 0x00]));
    }
}
