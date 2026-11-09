//! One test per verification check (T-1F acceptance 2 and 3). Each was also seen failing
//! with its check removed from the code; the outputs are in the T-1F report.

// Tests may unwrap, index and panic (CLAUDE.md); the product lints target src/.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]
// Without `rsa` the RSA-signed fixtures are skipped, leaving some helpers unused.
#![cfg_attr(not(feature = "rsa"), allow(unused_imports, dead_code))]

mod common;

use ::cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use ::cms::content_info::{CmsVersion, ContentInfo};
use ::cms::signed_data::{
    CertificateSet, EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo, SignerInfos,
};
use casual_sign_crypto::cms::{self, ParsedCms};
use casual_sign_crypto::oid;
use casual_sign_crypto::revocation::{self, RevocationStatus};
use casual_sign_crypto::tsp::{self, TimestampRequest};
use casual_sign_crypto::{
    Certificate, CryptoError, DigestAlgorithm, DigestValue, KeyError, KeyProvider,
    RevocationFailure, SerialNumber, Signature, SignatureAlgorithm, SignedAttribute,
    TimestampFailure,
};
use common::{cert, fixture, pki};
use core::time::Duration;
use der::asn1::{Any, ObjectIdentifier, OctetString, SetOfVec};
use der::{Decode, Encode};
use p256::ecdsa::signature::Verifier;
use x509_cert::attr::Attribute;

const NONCE: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];

fn verify(der: &[u8], message: &[u8]) -> Result<(), CryptoError> {
    let parsed = ParsedCms::parse(der)?;
    parsed
        .verify_detached(&parsed.digest_algorithm().digest(message))
        .map(|_| ())
}

// ---- acceptance 2: signed attributes hashed as received ----

#[test]
fn out_of_order_signed_attributes_verify_as_received() {
    let message = fixture("message.bin");
    let der = fixture("cms-p256-unsorted.der");
    verify(&der, &message).unwrap();

    // What a re-encoding verifier does: decode with `der` (which sorts SET OF on decode)
    // and re-encode. The bytes differ from those signed, and the signature fails.
    let ci = ContentInfo::from_der(&der).unwrap();
    let sd: SignedData = ci.content.decode_as().unwrap();
    let si = &sd.signer_infos.0.as_slice()[0];
    let reencoded = si.signed_attrs.as_ref().unwrap().to_der().unwrap();
    let p256_cert = cert("p256.der");
    let spk = p256_cert
        .tbs_certificate()
        .subject_public_key_info()
        .subject_public_key
        .raw_bytes();
    let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(spk).unwrap();
    let sig = p256::ecdsa::Signature::from_der(si.signature.as_bytes()).unwrap();
    assert!(
        key.verify(&reencoded, &sig).is_err(),
        "a re-encoding verifier must fail on this fixture"
    );
    // The sorted fixture, by contrast, verifies either way.
    println!("re-encoding verifier on cms-p256-unsorted.der: signature invalid; ours: valid");
}

// ---- helpers: a CMS with arbitrary signed attributes, signed by the test P-256 key ----

fn attr(id: ObjectIdentifier, value: Any) -> Attribute {
    Attribute {
        oid: id,
        values: SetOfVec::try_from(vec![value]).unwrap(),
    }
}

fn ess_for(cert: &Certificate) -> Any {
    let hash = DigestAlgorithm::Sha256.digest(&cert.to_der().unwrap());
    let ess = casual_sign_crypto::ess::SigningCertificateV2 {
        certs: vec![casual_sign_crypto::ess::EssCertIdV2 {
            hash_algorithm: None,
            cert_hash: OctetString::new(hash.as_bytes()).unwrap(),
            issuer_serial: None,
        }],
        policies: None,
    };
    Any::encode_from(&ess).unwrap()
}

fn custom_cms(signer: &Certificate, attrs: Vec<Attribute>) -> Vec<u8> {
    let provider = pki().provider(SignatureAlgorithm::EcdsaP256Sha256);
    // Attribute sets with duplicates cannot be a der SetOfVec; build the SET by hand.
    let mut encoded: Vec<Vec<u8>> = attrs.iter().map(|a| a.to_der().unwrap()).collect();
    encoded.sort();
    let body: Vec<u8> = encoded.concat();
    let set = der_tlv(0x31, &body);
    let sig = provider.sign(&set).unwrap();
    let tbs = signer.tbs_certificate();
    let si = SignerInfo {
        version: CmsVersion::V1,
        sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: tbs.issuer().clone(),
            serial_number: tbs.serial_number().clone(),
        }),
        digest_alg: DigestAlgorithm::Sha256.algorithm_identifier(),
        signed_attrs: None,
        signature_algorithm: SignatureAlgorithm::EcdsaP256Sha256
            .algorithm_identifier()
            .unwrap(),
        signature: OctetString::new(sig.as_bytes()).unwrap(),
        unsigned_attrs: None,
    };
    // Splice the raw [0] set into the SignerInfo after digestAlgorithm.
    let si_der = si.to_der().unwrap();
    let si_items = children(&si_der);
    let mut si_body = Vec::new();
    for (i, item) in si_items.iter().enumerate() {
        if i == 3 {
            si_body.extend(der_tlv(0xA0, &body));
        }
        si_body.extend_from_slice(item);
    }
    let si_raw = der_tlv(0x30, &si_body);
    let sd = SignedData {
        version: CmsVersion::V1,
        digest_algorithms: SetOfVec::try_from(vec![DigestAlgorithm::Sha256.algorithm_identifier()])
            .unwrap(),
        encap_content_info: EncapsulatedContentInfo {
            econtent_type: oid::ID_DATA,
            econtent: None,
        },
        certificates: Some(CertificateSet(
            SetOfVec::try_from(vec![
                CertificateChoices::Certificate(pki().p256.clone()),
                CertificateChoices::Certificate(pki().root.clone()),
            ])
            .unwrap(),
        )),
        crls: None,
        signer_infos: SignerInfos(SetOfVec::try_from(vec![]).unwrap()),
    };
    let sd_der = sd.to_der().unwrap();
    let mut items = children(&sd_der);
    let infos = der_tlv(0x31, &si_raw);
    *items.last_mut().unwrap() = infos;
    let sd_raw = der_tlv(0x30, &items.concat());
    let mut ci_body = oid::ID_SIGNED_DATA.to_der().unwrap();
    ci_body.extend(der_tlv(0xA0, &sd_raw));
    der_tlv(0x30, &ci_body)
}

fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    let n = content.len();
    if n < 0x80 {
        v.push(n as u8);
    } else {
        let b = n.to_be_bytes();
        let first = b.iter().position(|&x| x != 0).unwrap();
        v.push(0x80 | (b.len() - first) as u8);
        v.extend_from_slice(&b[first..]);
    }
    v.extend_from_slice(content);
    v
}

fn children(tlv: &[u8]) -> Vec<Vec<u8>> {
    let mut r = der::SliceReader::new(tlv).unwrap();
    let h = <der::Header as Decode>::decode(&mut r).unwrap();
    let content = der::Reader::read_slice(&mut r, h.length()).unwrap();
    let mut cr = der::SliceReader::new(content).unwrap();
    let mut out = Vec::new();
    while !der::Reader::is_finished(&cr) {
        out.push(der::Reader::tlv_bytes(&mut cr).unwrap().to_vec());
    }
    out
}

fn standard_attrs(message: &[u8], ess_cert: &Certificate) -> Vec<Attribute> {
    vec![
        attr(
            oid::ID_CONTENT_TYPE,
            Any::encode_from(&oid::ID_DATA).unwrap(),
        ),
        attr(
            oid::ID_MESSAGE_DIGEST,
            Any::encode_from(
                &OctetString::new(DigestAlgorithm::Sha256.digest(message).as_bytes()).unwrap(),
            )
            .unwrap(),
        ),
        attr(oid::ID_SIGNING_CERTIFICATE_V2, ess_for(ess_cert)),
    ]
}

// ---- acceptance 3: each CMS check ----

#[test]
fn custom_cms_with_correct_attributes_verifies() {
    let m = b"payload";
    let p = &pki().p256;
    verify(&custom_cms(p, standard_attrs(m, p)), m).unwrap();
}

#[test]
fn digest_check_rejects_other_content() {
    let m = b"payload";
    let p = &pki().p256;
    let der = custom_cms(p, standard_attrs(m, p));
    assert_eq!(verify(&der, b"payloaD"), Err(CryptoError::DigestMismatch));
    // A digest of the right bytes but the wrong algorithm is also a mismatch.
    let parsed = ParsedCms::parse(&der).unwrap();
    let wrong_alg = DigestAlgorithm::Sha384.digest(m);
    assert_eq!(
        parsed.verify_detached(&wrong_alg).unwrap_err().code(),
        "CS-VER-0002"
    );
}

/// A provider that signs, then corrupts the signature.
struct Corrupting(common::TestProvider);

impl KeyProvider for Corrupting {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.0.algorithm()
    }
    fn certificate_chain(&self) -> &[Certificate] {
        self.0.certificate_chain()
    }
    fn sign(&self, attrs: &[u8]) -> Result<Signature, KeyError> {
        let mut s = self.0.sign(attrs)?.as_bytes().to_vec();
        let last = s.len() - 2;
        s[last] ^= 0x01;
        Ok(Signature::new(s))
    }
}

#[test]
fn signature_check_rejects_a_corrupted_signature() {
    let m = b"payload";
    for alg in [
        SignatureAlgorithm::EcdsaP256Sha256,
        SignatureAlgorithm::EcdsaP384Sha384,
        #[cfg(feature = "rsa")]
        SignatureAlgorithm::RsaPkcs1Sha256,
        #[cfg(feature = "rsa")]
        SignatureAlgorithm::RsaPssSha384,
    ] {
        let good = pki().provider(alg);
        let d = alg.digest_algorithm().digest(m);
        let ok = cms::sign_detached(&good, &d).unwrap().to_der(None).unwrap();
        verify(&ok, m).unwrap();
        let bad = Corrupting(pki().provider(alg));
        let der = cms::sign_detached(&bad, &d).unwrap().to_der(None).unwrap();
        assert_eq!(
            verify(&der, m),
            Err(CryptoError::SignatureInvalid),
            "{alg:?}"
        );
    }
}

#[test]
fn signature_check_rejects_a_key_that_is_not_the_certificates() {
    // The provider's key is not the one in its certificate: the builder refuses nothing
    // (keys are the provider's business) but verification must fail.
    let p = pki().mismatched_provider();
    let m = b"payload";
    let der = cms::sign_detached(&p, &DigestAlgorithm::Sha256.digest(m))
        .unwrap()
        .to_der(None)
        .unwrap();
    assert_eq!(verify(&der, m), Err(CryptoError::SignatureInvalid));
}

#[test]
fn content_type_check() {
    let m = b"payload";
    let p = &pki().p256;
    let mut attrs = standard_attrs(m, p);
    attrs[0] = attr(
        oid::ID_CONTENT_TYPE,
        Any::encode_from(&oid::ID_CT_TST_INFO).unwrap(),
    );
    assert_eq!(
        verify(&custom_cms(p, attrs), m),
        Err(CryptoError::ContentTypeMismatch)
    );
}

#[test]
fn each_required_attribute_must_appear_exactly_once() {
    let m = b"payload";
    let p = &pki().p256;
    for (i, which) in [
        SignedAttribute::ContentType,
        SignedAttribute::MessageDigest,
        SignedAttribute::SigningCertificateV2,
    ]
    .into_iter()
    .enumerate()
    {
        let mut missing = standard_attrs(m, p);
        missing.remove(i);
        assert_eq!(
            verify(&custom_cms(p, missing), m),
            Err(CryptoError::MissingSignedAttribute(which))
        );
        let mut twice = standard_attrs(m, p);
        twice.push(twice[i].clone());
        assert_eq!(
            verify(&custom_cms(p, twice), m),
            Err(CryptoError::MissingSignedAttribute(which))
        );
    }
}

#[test]
fn ess_check_rejects_a_signing_certificate_naming_another_certificate() {
    let m = b"payload";
    let p = &pki().p256;
    // Correctly signed, but signing-certificate-v2 names the root, not the signer.
    let der = custom_cms(p, standard_attrs(m, &pki().root));
    assert_eq!(
        verify(&der, m),
        Err(CryptoError::SigningCertificateMismatch)
    );
}

#[test]
fn builder_writes_der_ordered_attributes_without_signing_time_and_omits_sha256_ess_algorithm() {
    let p = pki().provider(SignatureAlgorithm::EcdsaP256Sha256);
    let der = cms::sign_detached(&p, &DigestAlgorithm::Sha256.digest(b"x"))
        .unwrap()
        .to_der(None)
        .unwrap();
    let ci = ContentInfo::from_der(&der).unwrap();
    let sd: SignedData = ci.content.decode_as().unwrap();
    let si = &sd.signer_infos.0.as_slice()[0];
    let attrs = si.signed_attrs.as_ref().unwrap();
    let ids: Vec<_> = attrs.iter().map(|a| a.oid).collect();
    assert_eq!(
        ids,
        [
            oid::ID_CONTENT_TYPE,
            oid::ID_MESSAGE_DIGEST,
            oid::ID_SIGNING_CERTIFICATE_V2
        ]
    );
    let signing_time = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.5");
    assert!(!ids.contains(&signing_time));
    let ess = attrs
        .iter()
        .find(|a| a.oid == oid::ID_SIGNING_CERTIFICATE_V2)
        .unwrap();
    let ess: casual_sign_crypto::ess::SigningCertificateV2 =
        ess.values.as_slice()[0].decode_as().unwrap();
    assert!(ess.certs[0].hash_algorithm.is_none());
    assert!(sd.encap_content_info.econtent.is_none(), "detached");
}

#[test]
fn builder_refuses_a_digest_of_another_algorithm_and_reports_provider_failure() {
    let p = pki().provider(SignatureAlgorithm::EcdsaP256Sha256);
    let err = cms::sign_detached(&p, &DigestAlgorithm::Sha384.digest(b"x")).unwrap_err();
    assert_eq!(err.code(), "CS-SEAL-0005");

    struct Down(common::TestProvider);
    impl KeyProvider for Down {
        fn algorithm(&self) -> SignatureAlgorithm {
            self.0.algorithm()
        }
        fn certificate_chain(&self) -> &[Certificate] {
            self.0.certificate_chain()
        }
        fn sign(&self, _: &[u8]) -> Result<Signature, KeyError> {
            Err(KeyError::Unavailable)
        }
    }
    let err = cms::sign_detached(&Down(p), &DigestAlgorithm::Sha256.digest(b"x")).unwrap_err();
    assert_eq!(err, CryptoError::KeyProvider(KeyError::Unavailable));
    assert_eq!(err.code(), "CS-SEAL-0001");
}

#[test]
fn placeholder_bound_holds_with_and_without_a_timestamp() {
    let message = fixture("message.bin");
    let tsr = fixture("tsr-granted.der");
    let imprint = DigestAlgorithm::Sha256.digest(&message);
    let req = TimestampRequest::new(&imprint, &NONCE).unwrap();
    let token = tsp::verify_timestamp_response(&tsr, &req);
    for alg in [
        SignatureAlgorithm::EcdsaP256Sha256,
        SignatureAlgorithm::EcdsaP384Sha384,
        SignatureAlgorithm::RsaPkcs1Sha256,
        SignatureAlgorithm::RsaPssSha512,
    ] {
        let p = pki().provider(alg);
        let signed = cms::sign_detached(&p, &alg.digest_algorithm().digest(&message)).unwrap();
        let plain = signed.to_der(None).unwrap();
        assert!(plain.len() <= cms::max_der_len(&p, 0).unwrap());
        if let Ok(tok) = &token {
            let with = signed.to_der(Some(tok.as_der())).unwrap();
            let bound = cms::max_der_len(&p, tok.as_der().len()).unwrap();
            assert!(with.len() <= bound, "{alg:?}: {} > {bound}", with.len());
            // The token survives the round trip as the unsigned attribute.
            let parsed = ParsedCms::parse(&with).unwrap();
            assert_eq!(
                parsed.timestamp_token().unwrap().as_deref(),
                Some(tok.as_der())
            );
        }
    }
}

// ---- RFC 3161 checks ----

fn granted() -> (Vec<u8>, DigestValue) {
    (
        fixture("tsr-granted.der"),
        DigestAlgorithm::Sha256.digest(&fixture("message.bin")),
    )
}

#[test]
#[cfg(feature = "rsa")]
fn nonce_check_rejects_a_response_to_another_request() {
    let (tsr, imprint) = granted();
    let other = TimestampRequest::new(&imprint, &[0x42; 8]).unwrap();
    assert_eq!(
        tsp::verify_timestamp_response(&tsr, &other).unwrap_err(),
        CryptoError::TimestampResponse(TimestampFailure::NonceMismatch)
    );
}

#[test]
#[cfg(feature = "rsa")]
fn imprint_check_rejects_a_token_over_other_data() {
    let (tsr, _) = granted();
    let other = DigestAlgorithm::Sha256.digest(b"other data");
    let req = TimestampRequest::new(&other, &NONCE).unwrap();
    assert_eq!(
        tsp::verify_timestamp_response(&tsr, &req).unwrap_err(),
        CryptoError::TimestampResponse(TimestampFailure::ImprintMismatch)
    );
    // The embedded-token path reports CS-VER-0006.
    let (_, imprint) = granted();
    let good =
        tsp::verify_timestamp_response(&tsr, &TimestampRequest::new(&imprint, &NONCE).unwrap())
            .unwrap();
    let err = tsp::verify_timestamp_token(good.as_der(), &other).unwrap_err();
    assert_eq!(
        err,
        CryptoError::TimestampToken(TimestampFailure::ImprintMismatch)
    );
    assert_eq!(err.code(), "CS-VER-0006");
}

#[test]
#[cfg(feature = "rsa")]
fn tsa_signature_check_rejects_a_corrupted_token_signature() {
    let (tsr, imprint) = granted();
    let req = TimestampRequest::new(&imprint, &NONCE).unwrap();
    let token = tsp::verify_timestamp_response(&tsr, &req).unwrap();
    let sig = ParsedCms::parse(token.as_der())
        .unwrap()
        .signature_value()
        .unwrap()
        .to_vec();
    let at = tsr.windows(sig.len()).position(|w| w == sig).unwrap();
    let mut bad = tsr.clone();
    bad[at + sig.len() / 2] ^= 0x01;
    assert_eq!(
        tsp::verify_timestamp_response(&bad, &req).unwrap_err(),
        CryptoError::TimestampResponse(TimestampFailure::Signature)
    );
}

#[test]
fn nonce_is_read_as_an_unsigned_integer() {
    let d = DigestAlgorithm::Sha256.digest(b"x");
    assert!(TimestampRequest::new(&d, &[]).is_err());
    assert!(TimestampRequest::new(&d, &[0, 0]).is_err());
    assert!(TimestampRequest::new(&d, &[0xFF; 33]).is_err());
    let a = TimestampRequest::new(&d, &[0x80]).unwrap();
    let b = TimestampRequest::new(&d, &[0, 0x80]).unwrap();
    assert_eq!(a.as_der(), b.as_der());
}

// ---- revocation checks ----

fn serial(n: u64) -> SerialNumber {
    let bytes = n.to_be_bytes();
    let first = bytes.iter().position(|&b| b != 0).unwrap();
    SerialNumber::new(&bytes[first..]).unwrap()
}

const JUNE_1: Duration = Duration::from_secs(1_780_272_000);

#[test]
fn ocsp_revoked_status_is_reported() {
    let st = revocation::ocsp_status(
        &fixture("ocsp-revoked-by-ca.der"),
        &serial(0x1001),
        &cert("root.der"),
        JUNE_1,
    )
    .unwrap();
    assert!(matches!(st, RevocationStatus::Revoked { .. }));
    assert_eq!(st.require_good().unwrap_err().code(), "CS-VER-0005");
}

#[test]
fn crl_revoked_status_is_reported() {
    let st = revocation::crl_status(
        &fixture("crl.der"),
        &serial(0x1001),
        &cert("root.der"),
        JUNE_1,
    )
    .unwrap();
    assert!(matches!(st, RevocationStatus::Revoked { .. }));
}

#[test]
fn ocsp_from_an_unauthorized_responder_is_refused() {
    let err = revocation::ocsp_status(
        &fixture("ocsp-good-unauthorized.der"),
        &serial(0x1002),
        &cert("root.der"),
        JUNE_1,
    )
    .unwrap_err();
    assert_eq!(
        err,
        CryptoError::Revocation(RevocationFailure::UnauthorizedSigner)
    );
    assert_eq!(err.code(), "CS-SEAL-0004");
}

#[test]
fn crl_whose_signature_does_not_verify_is_refused() {
    // A byte flipped near the end lands in the ECDSA signature value.
    let crl = fixture("crl.der");
    let mut bad = crl.clone();
    let n = bad.len();
    bad[n - 3] ^= 0x01;
    let err = revocation::crl_status(&bad, &serial(0x1001), &cert("root.der"), JUNE_1).unwrap_err();
    assert_eq!(
        err,
        CryptoError::Revocation(RevocationFailure::UnauthorizedSigner)
    );
}
