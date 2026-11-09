//! CMS `SignedData` (RFC 5652): a builder for detached PAdES signatures (docs/31 §2 B-B,
//! §4 steps 5 and 7) and a DER-only parser and verifier.
//!
//! Signed attributes written: `content-type` (id-data), `message-digest`, ESS
//! `signing-certificate-v2` with `hashAlgorithm` omitted for SHA-256. No `signingTime`
//! (the PDF `/M` carries it). The verifier hashes the signed attributes **exactly as
//! received** and never re-encodes them.

use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{
    CertificateSet, EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo, SignerInfos,
};
use der::asn1::{Any, ObjectIdentifier, OctetString, SetOfVec};
use der::{Decode, Tag};
use x509_cert::Certificate;
use x509_cert::attr::Attribute;
use x509_cert::ext::pkix::SubjectKeyIdentifier;

use crate::der_walk;
use crate::digest::{DigestAlgorithm, DigestValue};
use crate::error::{CryptoError, KeyError, SignedAttribute, Structure};
use crate::ess::SigningCertificateV2;
use crate::key::KeyProvider;
use crate::oid;
use crate::signature::{self, Scheme, SignatureAlgorithm, to_der};

/// Largest CMS this crate parses: a PAdES `/Contents` with a chain, a timestamp token
/// and room to spare. Larger input is refused before decoding (docs/21 should list it).
pub const MAX_CMS_LEN: usize = 1024 * 1024;

/// `id-aa-signingCertificate` (v1, SHA-1 `ESSCertID`), recognized only to refuse it.
const ID_SIGNING_CERTIFICATE_V1: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.12");

/// Largest ECDSA signature value for each curve, for placeholder sizing.
const MAX_ECDSA_P256_SIG: usize = 72;
const MAX_ECDSA_P384_SIG: usize = 104;

/// A detached CMS signature made through a [`KeyProvider`], before the optional
/// timestamp token is added (docs/31 §4: sign, then timestamp the signature value, then
/// assemble).
#[derive(Clone, Debug)]
pub struct SignedCms {
    signer: Certificate,
    chain: Vec<Certificate>,
    algorithm: SignatureAlgorithm,
    signed_attrs: SetOfVec<Attribute>,
    signature: Vec<u8>,
}

impl SignedCms {
    /// The signature value; RFC 3161 timestamps its digest for PAdES B-T.
    #[must_use]
    pub fn signature_value(&self) -> &[u8] {
        &self.signature
    }

    /// The algorithm the provider signed with.
    #[must_use]
    pub const fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    /// Encode the `ContentInfo`, with `timestamp_token` (a whole RFC 3161
    /// `TimeStampToken`, as returned by [`crate::tsp::TimestampToken::as_der`]) as the
    /// `signature-time-stamp` unsigned attribute when given.
    ///
    /// # Errors
    /// [`CryptoError::Encoding`] if the DER cannot be produced;
    /// [`CryptoError::Malformed`] if the token is not one DER TLV.
    pub fn to_der(&self, timestamp_token: Option<&[u8]>) -> Result<Vec<u8>, CryptoError> {
        let unsigned = match timestamp_token {
            None => None,
            Some(tok) => {
                let any = Any::from_der(tok)
                    .map_err(|_| CryptoError::Malformed(Structure::TimestampToken))?;
                Some(set_of(vec![Attribute {
                    oid: oid::ID_SIGNATURE_TIME_STAMP_TOKEN,
                    values: set_of(vec![any])?,
                }])?)
            }
        };
        assemble(
            &self.signer,
            &self.chain,
            self.algorithm,
            self.signed_attrs.clone(),
            self.signature.clone(),
            unsigned,
        )
    }
}

fn set_of<T: der::DerOrd>(v: Vec<T>) -> Result<SetOfVec<T>, CryptoError> {
    SetOfVec::try_from(v).map_err(|_| CryptoError::Encoding)
}

fn attribute(oid: ObjectIdentifier, value: Any) -> Result<Attribute, CryptoError> {
    Ok(Attribute {
        oid,
        values: set_of(vec![value])?,
    })
}

fn signed_attributes(
    signer: &Certificate,
    content_digest: &DigestValue,
) -> Result<SetOfVec<Attribute>, CryptoError> {
    let enc = |_: der::Error| CryptoError::Encoding;
    // SetOfVec sorts on construction, so the set is in DER order (docs/66 pitfall 1).
    set_of(vec![
        attribute(
            oid::ID_CONTENT_TYPE,
            Any::encode_from(&oid::ID_DATA).map_err(enc)?,
        )?,
        attribute(
            oid::ID_MESSAGE_DIGEST,
            Any::encode_from(&OctetString::new(content_digest.as_bytes()).map_err(enc)?)
                .map_err(enc)?,
        )?,
        attribute(
            oid::ID_SIGNING_CERTIFICATE_V2,
            Any::encode_from(&SigningCertificateV2::for_certificate(signer)?).map_err(enc)?,
        )?,
    ])
}

fn max_signature_len(signer: &Certificate, alg: SignatureAlgorithm) -> Result<usize, CryptoError> {
    match alg {
        SignatureAlgorithm::EcdsaP256Sha256 => Ok(MAX_ECDSA_P256_SIG),
        SignatureAlgorithm::EcdsaP384Sha384 => Ok(MAX_ECDSA_P384_SIG),
        _ => signature::rsa_modulus_len(signer.tbs_certificate().subject_public_key_info())
            .ok_or(CryptoError::UnsupportedAlgorithm),
    }
}

fn leaf_and_chain(
    provider: &dyn KeyProvider,
) -> Result<(Certificate, Vec<Certificate>), CryptoError> {
    let chain = provider.certificate_chain();
    let (leaf, rest) = chain
        .split_first()
        .ok_or(CryptoError::UnsupportedAlgorithm)?;
    signature::key_matches(
        leaf.tbs_certificate().subject_public_key_info(),
        provider.algorithm(),
    )?;
    Ok((leaf.clone(), rest.to_vec()))
}

/// Sign a detached CMS over content whose digest is `content_digest` (docs/31 §4 steps
/// 4–5). The provider receives only the DER signed attributes.
///
/// # Errors
/// [`CryptoError::UnsupportedAlgorithm`] (`CS-SEAL-0005`) when the digest algorithm differs
/// from the provider's, the chain is empty, or the signer key does not fit the algorithm;
/// [`CryptoError::KeyProvider`] (`CS-SEAL-0001`) when the provider fails or returns a
/// signature of impossible length.
pub fn sign_detached(
    provider: &dyn KeyProvider,
    content_digest: &DigestValue,
) -> Result<SignedCms, CryptoError> {
    let algorithm = provider.algorithm();
    if content_digest.algorithm() != algorithm.digest_algorithm() {
        return Err(CryptoError::UnsupportedAlgorithm);
    }
    let (signer, chain) = leaf_and_chain(provider)?;
    let signed_attrs = signed_attributes(&signer, content_digest)?;
    let attrs_der = to_der(&signed_attrs)?;
    let sig = provider.sign(&attrs_der)?;
    let max = max_signature_len(&signer, algorithm)?;
    let len = sig.as_bytes().len();
    let len_ok = if algorithm.is_rsa() {
        len == max
    } else {
        (8..=max).contains(&len)
    };
    if !len_ok {
        return Err(KeyError::BadSignature.into());
    }
    Ok(SignedCms {
        signer,
        chain,
        algorithm,
        signed_attrs,
        signature: sig.as_bytes().to_vec(),
    })
}

/// An upper bound on the DER length [`SignedCms::to_der`] will produce for this provider,
/// with a timestamp token of at most `timestamp_token_len` bytes (0 for none), for sizing
/// the `/Contents` placeholder by computation (docs/31 §4 step 2). Calls no key.
///
/// # Errors
/// As [`sign_detached`], without the provider errors.
pub fn max_der_len(
    provider: &dyn KeyProvider,
    timestamp_token_len: usize,
) -> Result<usize, CryptoError> {
    let algorithm = provider.algorithm();
    let (signer, chain) = leaf_and_chain(provider)?;
    let d = algorithm.digest_algorithm();
    let zero = DigestValue::from_bytes(d, &vec![0u8; d.output_len()])?;
    let attrs = signed_attributes(&signer, &zero)?;
    let sig = vec![0xFFu8; max_signature_len(&signer, algorithm)?];
    let unsigned = if timestamp_token_len == 0 {
        None
    } else {
        let filler = Any::new(Tag::Sequence, vec![0u8; timestamp_token_len])
            .map_err(|_| CryptoError::Encoding)?;
        Some(set_of(vec![attribute(
            oid::ID_SIGNATURE_TIME_STAMP_TOKEN,
            filler,
        )?])?)
    };
    Ok(assemble(&signer, &chain, algorithm, attrs, sig, unsigned)?.len())
}

fn assemble(
    signer: &Certificate,
    chain: &[Certificate],
    algorithm: SignatureAlgorithm,
    signed_attrs: SetOfVec<Attribute>,
    signature: Vec<u8>,
    unsigned_attrs: Option<SetOfVec<Attribute>>,
) -> Result<Vec<u8>, CryptoError> {
    let tbs = signer.tbs_certificate();
    let digest_alg = algorithm.digest_algorithm().algorithm_identifier();
    let si = SignerInfo {
        version: CmsVersion::V1,
        sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: tbs.issuer().clone(),
            serial_number: tbs.serial_number().clone(),
        }),
        digest_alg: digest_alg.clone(),
        signed_attrs: Some(signed_attrs),
        signature_algorithm: algorithm.algorithm_identifier()?,
        signature: OctetString::new(signature).map_err(|_| CryptoError::Encoding)?,
        unsigned_attrs,
    };
    let mut certs = vec![CertificateChoices::Certificate(signer.clone())];
    certs.extend(chain.iter().cloned().map(CertificateChoices::Certificate));
    let sd = SignedData {
        version: CmsVersion::V1,
        digest_algorithms: set_of(vec![digest_alg])?,
        encap_content_info: EncapsulatedContentInfo {
            econtent_type: oid::ID_DATA,
            econtent: None,
        },
        certificates: Some(CertificateSet(set_of(certs)?)),
        crls: None,
        signer_infos: SignerInfos(set_of(vec![si])?),
    };
    to_der(&ContentInfo {
        content_type: oid::ID_SIGNED_DATA,
        content: Any::encode_from(&sd).map_err(|_| CryptoError::Encoding)?,
    })
}

/// A parsed CMS `SignedData` with exactly one SignerInfo carrying signed attributes.
#[derive(Clone, Debug)]
pub struct ParsedCms {
    signed_data: SignedData,
    signed_attrs_raw: Vec<u8>,
    digest_algorithm: DigestAlgorithm,
}

/// What a successful verification establishes.
#[derive(Clone, Debug)]
pub struct VerifiedSigner {
    /// The signer certificate, found by the SignerInfo's identifier.
    pub certificate: Certificate,
    /// The digest algorithm of the content and the signed attributes.
    pub digest_algorithm: DigestAlgorithm,
}

impl ParsedCms {
    /// Parse a DER `ContentInfo`. Reads exactly one TLV; bytes after it must be zero
    /// padding (a PDF `/Contents`). BER is refused (`SEAL-13`).
    ///
    /// # Errors
    /// [`CryptoError::TooLarge`] over [`MAX_CMS_LEN`]; [`CryptoError::Malformed`] when it is
    /// not DER `SignedData`, has no signed attributes, or uses an unsupported digest;
    /// [`CryptoError::SignerCount`] unless there is exactly one SignerInfo.
    pub fn parse(input: &[u8]) -> Result<Self, CryptoError> {
        Self::parse_as(input, Structure::Cms)
    }

    pub(crate) fn parse_as(input: &[u8], what: Structure) -> Result<Self, CryptoError> {
        if input.len() > MAX_CMS_LEN {
            return Err(CryptoError::TooLarge(what));
        }
        let bad = CryptoError::Malformed(what);
        let tlv = der_walk::single_tlv_zero_padded(input).ok_or(bad)?;
        let ci = ContentInfo::from_der(tlv).map_err(|_| bad)?;
        if ci.content_type != oid::ID_SIGNED_DATA {
            return Err(bad);
        }
        let signed_data: SignedData = ci.content.decode_as().map_err(|_| bad)?;
        let [si] = signed_data.signer_infos.0.as_slice() else {
            return Err(CryptoError::SignerCount);
        };
        if si.signed_attrs.is_none() {
            return Err(bad);
        }
        let digest_algorithm = DigestAlgorithm::from_algorithm_identifier(&si.digest_alg)?;
        let signed_attrs_raw = der_walk::signed_attrs_as_received(tlv).ok_or(bad)?;
        Ok(Self {
            signed_data,
            signed_attrs_raw,
            digest_algorithm,
        })
    }

    /// The digest algorithm the content must be hashed with before
    /// [`ParsedCms::verify_detached`].
    #[must_use]
    pub const fn digest_algorithm(&self) -> DigestAlgorithm {
        self.digest_algorithm
    }

    /// Certificates carried in the structure.
    pub fn certificates(&self) -> impl Iterator<Item = &Certificate> {
        self.signed_data
            .certificates
            .iter()
            .flat_map(|s| s.0.iter())
            .filter_map(|c| match c {
                CertificateChoices::Certificate(c) => Some(c),
                CertificateChoices::Other(_) => None,
            })
    }

    fn signer_info(&self) -> Result<&SignerInfo, CryptoError> {
        self.signed_data
            .signer_infos
            .0
            .as_slice()
            .first()
            .ok_or(CryptoError::SignerCount)
    }

    /// The signature value (what a PAdES B-T timestamp covers).
    ///
    /// # Errors
    /// Never after a successful parse.
    pub fn signature_value(&self) -> Result<&[u8], CryptoError> {
        Ok(self.signer_info()?.signature.as_bytes())
    }

    /// The raw `signature-time-stamp` unsigned attribute value (a `TimeStampToken`), if
    /// present. Verify it with [`crate::tsp::verify_timestamp_token`] over the digest of
    /// [`ParsedCms::signature_value`].
    ///
    /// # Errors
    /// [`CryptoError::Malformed`] if the attribute repeats or cannot be re-encoded.
    pub fn timestamp_token(&self) -> Result<Option<Vec<u8>>, CryptoError> {
        let si = self.signer_info()?;
        let Some(attrs) = &si.unsigned_attrs else {
            return Ok(None);
        };
        let mut found = attrs
            .iter()
            .filter(|a| a.oid == oid::ID_SIGNATURE_TIME_STAMP_TOKEN);
        let (Some(a), None) = (found.next(), found.next()) else {
            return Ok(None);
        };
        let [v] = a.values.as_slice() else {
            return Err(CryptoError::Malformed(Structure::Cms));
        };
        to_der(v)
            .map(Some)
            .map_err(|_| CryptoError::Malformed(Structure::Cms))
    }

    /// The encapsulated content, if any (an RFC 3161 token's `TSTInfo`).
    pub(crate) fn encapsulated(&self) -> (ObjectIdentifier, Option<&Any>) {
        let e = &self.signed_data.encap_content_info;
        (e.econtent_type, e.econtent.as_ref())
    }

    /// Verify a detached signature: `content_digest` must be the digest of the signed
    /// bytes (a PDF's ByteRange) under [`ParsedCms::digest_algorithm`].
    ///
    /// Checks, in order: detached `id-data`; signed attributes `content-type`,
    /// `message-digest` (against `content_digest`) and `signing-certificate-v2`, each
    /// exactly once; the signer certificate; ESS against it; the signature over the
    /// signed attributes as received.
    ///
    /// # Errors
    /// The first failing check, as a [`CryptoError`] with its docs/20 code.
    pub fn verify_detached(
        &self,
        content_digest: &DigestValue,
    ) -> Result<VerifiedSigner, CryptoError> {
        let (ty, content) = self.encapsulated();
        if ty != oid::ID_DATA || content.is_some() {
            return Err(CryptoError::ContentTypeMismatch);
        }
        self.verify_signer(ty, content_digest)
    }

    /// The checks shared by detached and encapsulated signatures.
    pub(crate) fn verify_signer(
        &self,
        content_type: ObjectIdentifier,
        content_digest: &DigestValue,
    ) -> Result<VerifiedSigner, CryptoError> {
        let si = self.signer_info()?;
        let attrs = si
            .signed_attrs
            .as_ref()
            .ok_or(CryptoError::Malformed(Structure::Cms))?;

        let ct: ObjectIdentifier =
            single_value(attrs, oid::ID_CONTENT_TYPE, SignedAttribute::ContentType)?;
        if ct != content_type {
            return Err(CryptoError::ContentTypeMismatch);
        }
        let md: OctetString = single_value(
            attrs,
            oid::ID_MESSAGE_DIGEST,
            SignedAttribute::MessageDigest,
        )?;
        if content_digest.algorithm() != self.digest_algorithm
            || md.as_bytes() != content_digest.as_bytes()
        {
            return Err(CryptoError::DigestMismatch);
        }

        let cert = self.find_signer(&si.sid)?;

        if attrs.iter().any(|a| a.oid == ID_SIGNING_CERTIFICATE_V1)
            && !attrs
                .iter()
                .any(|a| a.oid == oid::ID_SIGNING_CERTIFICATE_V2)
        {
            // SHA-1 ESSCertID only: not checkable without SHA-1, which we never accept.
            return Err(CryptoError::UnsupportedAlgorithm);
        }
        let ess: SigningCertificateV2 = single_value(
            attrs,
            oid::ID_SIGNING_CERTIFICATE_V2,
            SignedAttribute::SigningCertificateV2,
        )?;
        ess.matches(cert)?;

        let scheme = Scheme::from_algorithm_identifier(
            &si.signature_algorithm,
            Some(self.digest_algorithm),
        )?;
        if scheme.digest_algorithm() != self.digest_algorithm {
            return Err(CryptoError::UnsupportedAlgorithm);
        }
        signature::verify(
            cert.tbs_certificate().subject_public_key_info(),
            scheme,
            &self.signed_attrs_raw,
            si.signature.as_bytes(),
        )?;
        Ok(VerifiedSigner {
            certificate: cert.clone(),
            digest_algorithm: self.digest_algorithm,
        })
    }

    fn find_signer(&self, sid: &SignerIdentifier) -> Result<&Certificate, CryptoError> {
        self.certificates()
            .find(|c| {
                let tbs = c.tbs_certificate();
                match sid {
                    SignerIdentifier::IssuerAndSerialNumber(isn) => {
                        tbs.issuer() == &isn.issuer && tbs.serial_number() == &isn.serial_number
                    }
                    SignerIdentifier::SubjectKeyIdentifier(ski) => {
                        matches!(tbs.get_extension::<SubjectKeyIdentifier>(), Ok(Some((_, s))) if s == *ski)
                    }
                }
            })
            .ok_or(CryptoError::SignerCertificateNotFound)
    }
}

/// The single value of the single attribute `id` in `attrs`, decoded as `T`.
fn single_value<'a, T: der::Choice<'a> + der::DecodeValue<'a>>(
    attrs: &'a SetOfVec<Attribute>,
    id: ObjectIdentifier,
    which: SignedAttribute,
) -> Result<T, CryptoError> {
    let mut found = attrs.iter().filter(|a| a.oid == id);
    let (Some(a), None) = (found.next(), found.next()) else {
        return Err(CryptoError::MissingSignedAttribute(which));
    };
    let [v] = a.values.as_slice() else {
        return Err(CryptoError::MissingSignedAttribute(which));
    };
    v.decode_as()
        .map_err(|_| CryptoError::Malformed(Structure::Cms))
}
