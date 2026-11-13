//! Test-only throwaway PKI (rcgen, keys in memory, never written), a key provider, an
//! in-process RFC 3161 TSA (ESSCertIDv2, ECDSA P-256) and an OCSP responder with CRLs,
//! built with the RustCrypto types `casual-sign-crypto` uses. Shared by the tests and the
//! `gen_sealed` example (`fixtures/sealed`). Never use outside tests.
//!
//! The PKI: root -> intermediate -> {P-256 signer, RSA-3072 signer, TSA, OCSP responder
//! (`id-pkix-ocsp-nocheck`)}. The responder answers for certificates the intermediate
//! issued; the root's CRL covers the intermediate. Validity 2026-01-01 to 2046-01-01.
// Not every test binary uses every helper.
#![allow(dead_code)]
// Test code: a panic is the failure report.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic,
    missing_docs
)]

use std::cell::Cell;
use std::sync::OnceLock;
use std::time::Duration;

use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};
use aws_lc_rs::rsa::KeySize;
use aws_lc_rs::signature::RsaKeyPair;
use casual_sign_crypto::ess::{EssCertIdV2, IssuerSerial, SigningCertificateV2};
use casual_sign_crypto::{
    Certificate, DigestAlgorithm, KeyError, KeyProvider, Signature, SignatureAlgorithm, oid,
};
use casual_sign_seal::{
    CrlQuery, OcspQuery, RevocationSource, SourceError, TimestampSource, TrustStore,
};
use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{
    CertificateSet, EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo, SignerInfos,
};
use der::asn1::{Any, BitString, GeneralizedTime, Int, ObjectIdentifier, OctetString, SetOfVec};
use der::{Decode, Encode, Tag};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, CertifiedIssuer,
    CrlDistributionPoint, CrlIssuingDistributionPoint, CrlScope, CustomExtension,
    DistinguishedName, DnType, IsCa, KeyIdMethod, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256,
    PKCS_RSA_SHA256, SerialNumber, SigningKey,
};
use x509_cert::attr::Attribute;
use x509_cert::ext::Extension;
use x509_cert::ext::pkix::name::GeneralName;
use x509_cert::spki::AlgorithmIdentifierOwned;
use x509_ocsp::{
    BasicOcspResponse, CertStatus, OcspRequest, OcspResponse, ResponderId, ResponseData,
    SingleResponse,
};
use x509_tsp::cmpv2::status::{PkiStatus, PkiStatusInfo};
use x509_tsp::{GeneralizedTimeNanos, TimeStampReq, TimeStampResp, TspVersion, TstInfo};

/// 2026-11-01T12:00:00Z: the signing time every fixture is sealed at.
pub const SIGNING_TIME: Duration = Duration::from_secs(1_793_534_400);
/// 2026-11-02T00:00:00Z: OCSP `producedAt`/`thisUpdate` and CRL `thisUpdate`, after the
/// signing time so validators' freshness rules hold.
pub const REVOCATION_TIME: Duration = Duration::from_secs(1_793_577_600);
/// 2026-12-01T00:00:00Z, the validation time of `fixtures/signed`.
pub const VALIDATION_TIME: Duration = Duration::from_secs(1_796_083_200);

const OCSP_NOCHECK: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 48, 1, 5];
const EKU: &[u64] = &[2, 5, 29, 37];
/// The CRL distribution points the certificates name (never fetched: the in-process
/// source answers), so a CRL scoped by an Issuing Distribution Point can match them.
const ROOT_CRL_URI: &str = "http://pki.t-1g.test/root.crl";
const INTER_CRL_URI: &str = "http://pki.t-1g.test/intermediate.crl";

/// A test policy OID under the documentation enterprise number 32473 (RFC 5612).
const TSA_POLICY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.1");
/// A private extension the TSA can pad its tokens with (overflow tests).
const PADDING_EXT: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.4.1.32473.2");

fn dn(cn: &str) -> DistinguishedName {
    let mut d = DistinguishedName::new();
    d.push(DnType::CommonName, cn);
    d.push(DnType::OrganizationName, "OpenSeal T-1G throwaway test PKI");
    d
}

fn params(cn: &str, serial: u64) -> CertificateParams {
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name = dn(cn);
    p.not_before = rcgen::date_time_ymd(2026, 1, 1);
    p.not_after = rcgen::date_time_ymd(2046, 1, 1);
    p.serial_number = Some(SerialNumber::from(serial));
    p.key_identifier_method = KeyIdMethod::Sha256;
    p
}

/// An extended key usage extension, critical (RFC 3161 §2.3 requires it for a TSA).
fn eku(purpose: &[u8]) -> CustomExtension {
    // SEQUENCE { OID } with the OID's content bytes given.
    let mut oid_tlv = vec![0x06, u8::try_from(purpose.len()).unwrap()];
    oid_tlv.extend_from_slice(purpose);
    let mut seq = vec![0x30, u8::try_from(oid_tlv.len()).unwrap()];
    seq.extend_from_slice(&oid_tlv);
    let mut e = CustomExtension::from_oid_content(EKU, seq);
    e.set_criticality(true);
    e
}

fn x509(der: &[u8]) -> Certificate {
    Certificate::from_der(der).unwrap()
}

pub struct Pki {
    pub root: Certificate,
    pub inter: Certificate,
    pub tsa: Certificate,
    pub ocsp: Certificate,
    pub p256: Certificate,
    pub rsa: Certificate,
    tsa_key: KeyPair,
    ocsp_key: KeyPair,
    p256_key: KeyPair,
    rsa_key: KeyPair,
    pub root_crl: Vec<u8>,
    pub inter_crl: Vec<u8>,
    /// The same CRLs scoped as production CAs issue them (HRD-02): a critical Issuing
    /// Distribution Point naming the certificates' distribution point, the root's for CA
    /// certificates only, the intermediate's for end entities only.
    pub root_crl_scoped: Vec<u8>,
    pub inter_crl_scoped: Vec<u8>,
    /// The root cross-certified by a CA that is in no pool and no trust store.
    pub root_cross: Certificate,
}

pub fn pki() -> &'static Pki {
    static PKI: OnceLock<Pki> = OnceLock::new();
    PKI.get_or_init(|| {
        let root_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut rp = params("T-1G Test Root", 1);
        rp.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        rp.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        // The root's subject and key cross-certified by another CA no one here holds, as
        // DigiCert's TSA tokens carry "Trusted Root G4" issued by "Assured ID Root CA".
        let other_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut op = params("T-1G Other Root", 3);
        op.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        op.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let other = CertifiedIssuer::self_signed(op, other_key).unwrap();
        let mut cp = rp.clone();
        cp.serial_number = Some(SerialNumber::from(4u64));
        cp.use_authority_key_identifier_extension = true;
        let root_cross = x509(cp.signed_by(&root_key, &other).unwrap().der());
        let root = CertifiedIssuer::self_signed(rp, root_key).unwrap();

        let inter_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ip = params("T-1G Test Intermediate", 2);
        ip.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ip.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        ip.use_authority_key_identifier_extension = true;
        ip.crl_distribution_points = vec![CrlDistributionPoint {
            uris: vec![ROOT_CRL_URI.to_owned()],
        }];
        let inter = CertifiedIssuer::signed_by(ip, inter_key, &root).unwrap();

        let leaf = |cn: &str, serial: u64, key: &KeyPair, ext: Vec<CustomExtension>, nr: bool| {
            let mut p = params(cn, serial);
            p.is_ca = IsCa::ExplicitNoCa;
            p.key_usages = if nr {
                vec![
                    KeyUsagePurpose::DigitalSignature,
                    KeyUsagePurpose::ContentCommitment,
                ]
            } else {
                vec![KeyUsagePurpose::DigitalSignature]
            };
            p.use_authority_key_identifier_extension = true;
            p.crl_distribution_points = vec![CrlDistributionPoint {
                uris: vec![INTER_CRL_URI.to_owned()],
            }];
            p.custom_extensions = ext;
            x509(p.signed_by(key, &inter).unwrap().der())
        };

        let tsa_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        // id-kp-timeStamping 1.3.6.1.5.5.7.3.8
        let tsa = leaf(
            "T-1G Test TSA",
            11,
            &tsa_key,
            vec![eku(&[0x2b, 6, 1, 5, 5, 7, 3, 8])],
            false,
        );
        let ocsp_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        // id-kp-OCSPSigning 1.3.6.1.5.5.7.3.9, and id-pkix-ocsp-nocheck (NULL).
        let ocsp = leaf(
            "T-1G Test OCSP Responder",
            12,
            &ocsp_key,
            vec![
                eku(&[0x2b, 6, 1, 5, 5, 7, 3, 9]),
                CustomExtension::from_oid_content(OCSP_NOCHECK, vec![0x05, 0x00]),
            ],
            false,
        );
        let p256_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let p256 = leaf("T-1G Test Seal P-256", 20, &p256_key, Vec::new(), true);
        let rsa = RsaKeyPair::generate(KeySize::Rsa3072).unwrap();
        let rsa_pkcs8 = AsDer::<Pkcs8V1Der>::as_der(&rsa).unwrap().as_ref().to_vec();
        let rsa_key =
            KeyPair::from_pkcs8_der_and_sign_algo(&rsa_pkcs8.as_slice().into(), &PKCS_RSA_SHA256)
                .unwrap();
        let rsa = leaf("T-1G Test Seal RSA-3072", 21, &rsa_key, Vec::new(), true);

        let crl = |issuer: &CertifiedIssuer<'static, KeyPair>,
                   idp: Option<CrlIssuingDistributionPoint>| {
            CertificateRevocationListParams {
                this_update: rcgen::date_time_ymd(2026, 11, 2),
                next_update: rcgen::date_time_ymd(2046, 1, 1),
                crl_number: SerialNumber::from(1u64),
                issuing_distribution_point: idp,
                revoked_certs: Vec::new(),
                key_identifier_method: KeyIdMethod::Sha256,
            }
            .signed_by(issuer)
            .unwrap()
            .der()
            .to_vec()
        };
        let root_crl = crl(&root, None);
        let inter_crl = crl(&inter, None);
        let scoped = |uri: &str, scope| CrlIssuingDistributionPoint {
            distribution_point: CrlDistributionPoint {
                uris: vec![uri.to_owned()],
            },
            scope: Some(scope),
        };
        let root_crl_scoped = crl(&root, Some(scoped(ROOT_CRL_URI, CrlScope::CaCertsOnly)));
        let inter_crl_scoped = crl(&inter, Some(scoped(INTER_CRL_URI, CrlScope::UserCertsOnly)));
        Pki {
            root: x509(root.der()),
            inter: x509(inter.der()),
            tsa,
            ocsp,
            p256,
            rsa,
            tsa_key,
            ocsp_key,
            p256_key,
            rsa_key,
            root_crl,
            inter_crl,
            root_crl_scoped,
            inter_crl_scoped,
            root_cross,
        }
    })
}

pub fn der_of(c: &Certificate) -> Vec<u8> {
    c.to_der().unwrap()
}

pub fn trust() -> TrustStore {
    let mut t = TrustStore::new();
    t.add_anchor(&der_of(&pki().root)).unwrap();
    t
}

pub fn root_pem() -> String {
    let b64 = base64(&der_of(&pki().root));
    let mut s = String::from("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        s.push_str(std::str::from_utf8(chunk).unwrap());
        s.push('\n');
    }
    s.push_str("-----END CERTIFICATE-----\n");
    s
}

fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(T[((n >> (18 - 6 * i)) & 63) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

// ---------------------------------------------------------------- key provider

/// Signs with an rcgen key: ECDSA P-256 (aws-lc-rs, randomized k, not RFC 6979) or RSA
/// PKCS#1 v1.5 (deterministic). One-shot hash-and-sign over the DER signed attributes.
pub struct TestProvider {
    key: &'static KeyPair,
    algorithm: SignatureAlgorithm,
    chain: Vec<Certificate>,
    /// When set, sign these bytes instead (a provider that returns a wrong signature).
    pub corrupt: bool,
}

impl KeyProvider for TestProvider {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    fn certificate_chain(&self) -> &[Certificate] {
        &self.chain
    }

    fn sign(&self, signed_attrs_der: &[u8]) -> Result<Signature, KeyError> {
        let msg: &[u8] = if self.corrupt {
            b"not the signed attributes"
        } else {
            signed_attrs_der
        };
        self.key
            .sign(msg)
            .map(Signature::new)
            .map_err(|_| KeyError::Unavailable)
    }
}

pub fn p256() -> TestProvider {
    let p = pki();
    TestProvider {
        key: &p.p256_key,
        algorithm: SignatureAlgorithm::EcdsaP256Sha256,
        chain: vec![p.p256.clone(), p.inter.clone(), p.root.clone()],
        corrupt: false,
    }
}

/// The P-256 signer with the chain a real CA hands out: the certificate and its issuing
/// CA, never the (offline) root (HRD-02).
pub fn p256_below_root() -> TestProvider {
    let p = pki();
    TestProvider {
        key: &p.p256_key,
        algorithm: SignatureAlgorithm::EcdsaP256Sha256,
        chain: vec![p.p256.clone(), p.inter.clone()],
        corrupt: false,
    }
}

pub fn rsa() -> TestProvider {
    let p = pki();
    TestProvider {
        key: &p.rsa_key,
        algorithm: SignatureAlgorithm::RsaPkcs1Sha256,
        chain: vec![p.rsa.clone(), p.inter.clone(), p.root.clone()],
        corrupt: false,
    }
}

// ---------------------------------------------------------------- TSA

fn alg(oid: ObjectIdentifier) -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid,
        parameters: None,
    }
}

fn set_of<T: der::DerOrd>(v: Vec<T>) -> SetOfVec<T> {
    SetOfVec::try_from(v).unwrap()
}

fn attribute(oid: ObjectIdentifier, value: Any) -> Attribute {
    Attribute {
        oid,
        values: set_of(vec![value]),
    }
}

/// The minimal DER INTEGER content for a positive `v`.
fn minimal(v: u64) -> Vec<u8> {
    let b = v.to_be_bytes();
    let first = b.iter().position(|&x| x != 0).unwrap_or(7);
    let mut out = b[first..].to_vec();
    if out[0] & 0x80 != 0 {
        out.insert(0, 0);
    }
    out
}

/// An in-process TSA: answers each request with a token at `time`, advancing one
/// second per token so tokens are ordered.
pub struct TestTsa {
    time: Cell<u64>,
    serial: Cell<u64>,
    nonce: Cell<u64>,
    /// Extra bytes each token carries in a private extension (grows by `grow_step` per
    /// call), to make tokens larger than [`TestTsa::bound`] says.
    pub padding: Cell<usize>,
    pub grow_step: usize,
    /// What `token_len_bound` reports; `None` for an honest bound.
    pub bound: Option<usize>,
    pub calls: Cell<usize>,
    /// Carry the root's cross-certificate in each token too.
    pub cross_certificate: bool,
}

impl TestTsa {
    pub fn new(start: Duration) -> Self {
        Self {
            time: Cell::new(start.as_secs()),
            serial: Cell::new(1000),
            nonce: Cell::new(0x0102_0304_0506_0708),
            padding: Cell::new(0),
            grow_step: 0,
            bound: None,
            calls: Cell::new(0),
            cross_certificate: false,
        }
    }

    fn token(&self, req: &TimeStampReq) -> Vec<u8> {
        let p = pki();
        let serial = self.serial.get();
        self.serial.set(serial + 1);
        let t = self.time.get();
        self.time.set(t + 1);
        let padding = self.padding.get();
        self.padding.set(padding + self.grow_step);
        let extensions = (padding > 0).then(|| {
            vec![Extension {
                extn_id: PADDING_EXT,
                critical: false,
                extn_value: OctetString::new(vec![0x5a; padding]).unwrap(),
            }]
        });
        let tst = TstInfo {
            version: TspVersion::V1,
            policy: TSA_POLICY,
            message_imprint: req.message_imprint.clone(),
            serial_number: Int::new(&minimal(serial)).unwrap(),
            gen_time: GeneralizedTimeNanos::from_unix_duration(Duration::from_secs(t)).unwrap(),
            accuracy: None,
            ordering: false,
            nonce: req.nonce.clone(),
            tsa: None,
            extensions,
        };
        let tst_der = tst.to_der().unwrap();
        let digest = DigestAlgorithm::Sha256.digest(&tst_der);
        let tsa_der = der_of(&p.tsa);
        let ess = SigningCertificateV2 {
            certs: vec![EssCertIdV2 {
                hash_algorithm: None,
                cert_hash: OctetString::new(DigestAlgorithm::Sha256.digest(&tsa_der).as_bytes())
                    .unwrap(),
                issuer_serial: Some(IssuerSerial {
                    issuer: vec![GeneralName::DirectoryName(
                        p.tsa.tbs_certificate().issuer().clone(),
                    )],
                    serial_number: p.tsa.tbs_certificate().serial_number().clone(),
                }),
            }],
            policies: None,
        };
        let attrs = set_of(vec![
            attribute(
                oid::ID_CONTENT_TYPE,
                Any::encode_from(&oid::ID_CT_TST_INFO).unwrap(),
            ),
            attribute(
                oid::ID_MESSAGE_DIGEST,
                Any::encode_from(&OctetString::new(digest.as_bytes()).unwrap()).unwrap(),
            ),
            attribute(
                oid::ID_SIGNING_CERTIFICATE_V2,
                Any::encode_from(&ess).unwrap(),
            ),
        ]);
        let sig = p.tsa_key.sign(&attrs.to_der().unwrap()).unwrap();
        let si = SignerInfo {
            version: CmsVersion::V1,
            sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
                issuer: p.tsa.tbs_certificate().issuer().clone(),
                serial_number: p.tsa.tbs_certificate().serial_number().clone(),
            }),
            digest_alg: alg(oid::ID_SHA256),
            signed_attrs: Some(attrs),
            signature_algorithm: alg(oid::ECDSA_WITH_SHA256),
            signature: OctetString::new(sig).unwrap(),
            unsigned_attrs: None,
        };
        let sd = SignedData {
            version: CmsVersion::V3,
            digest_algorithms: set_of(vec![alg(oid::ID_SHA256)]),
            encap_content_info: EncapsulatedContentInfo {
                econtent_type: oid::ID_CT_TST_INFO,
                econtent: Some(Any::new(Tag::OctetString, tst_der).unwrap()),
            },
            certificates: Some(CertificateSet(set_of(
                [p.tsa.clone(), p.inter.clone()]
                    .into_iter()
                    .chain(self.cross_certificate.then(|| p.root_cross.clone()))
                    .map(CertificateChoices::Certificate)
                    .collect(),
            ))),
            crls: None,
            signer_infos: SignerInfos(set_of(vec![si])),
        };
        let token = ContentInfo {
            content_type: oid::ID_SIGNED_DATA,
            content: Any::encode_from(&sd).unwrap(),
        };
        TimeStampResp {
            status: PkiStatusInfo {
                status: PkiStatus::Accepted,
                status_string: None,
                fail_info: None,
            },
            time_stamp_token: Some(token),
        }
        .to_der()
        .unwrap()
    }

    /// The length of one token now (a probe, as a host caches).
    pub fn probe(&self) -> usize {
        let imprint = DigestAlgorithm::Sha256.digest(b"probe");
        let req = casual_sign_crypto::tsp::TimestampRequest::new(&imprint, &[1; 16]).unwrap();
        let resp = self.timestamp(req.as_der()).unwrap();
        self.calls.set(self.calls.get() - 1);
        let token = casual_sign_crypto::tsp::verify_timestamp_response(&resp, &req).unwrap();
        token.as_der().len()
    }
}

impl TimestampSource for TestTsa {
    fn token_len_bound(&self) -> usize {
        // An honest bound: the measured token plus room for longer serials and nonces.
        self.bound
            .unwrap_or_else(|| der_of(&pki().tsa).len() + der_of(&pki().inter).len() + 1024)
    }

    fn nonce(&self) -> Vec<u8> {
        let n = self.nonce.get();
        self.nonce
            .set(n.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1));
        let mut v = n.to_be_bytes().to_vec();
        v[0] |= 0x40;
        v
    }

    fn timestamp(&self, request_der: &[u8]) -> Result<Vec<u8>, SourceError> {
        self.calls.set(self.calls.get() + 1);
        let req = TimeStampReq::from_der(request_der).map_err(|_| SourceError::Refused)?;
        Ok(self.token(&req))
    }
}

// ---------------------------------------------------------------- OCSP and CRLs

/// The OCSP responder (for certificates the intermediate issued) and the CRLs.
#[derive(Default)]
pub struct TestRevocation {
    /// Answer no OCSP request (CRLs only).
    pub no_ocsp: bool,
    /// Answer nothing at all.
    pub nothing: bool,
    /// Answer with the scoped CRLs (critical Issuing Distribution Point).
    pub scoped_crls: bool,
    /// Offer no issuer certificates (a host that fetches none, as the CLI and worker).
    pub no_issuers: bool,
    pub ocsp_calls: Cell<usize>,
    pub crl_calls: Cell<usize>,
}

impl TestRevocation {
    fn response(&self, request_der: &[u8]) -> Vec<u8> {
        let p = pki();
        let req = OcspRequest::from_der(request_der).unwrap();
        let cert_id = req.tbs_request.request_list[0].req_cert.clone();
        let at = x509_ocsp::OcspGeneralizedTime(
            GeneralizedTime::from_unix_duration(REVOCATION_TIME).unwrap(),
        );
        let next = x509_ocsp::OcspGeneralizedTime(
            GeneralizedTime::from_unix_duration(Duration::from_secs(2_398_377_600)).unwrap(),
        );
        let data = ResponseData {
            version: x509_ocsp::Version::V1,
            responder_id: ResponderId::ByName(p.ocsp.tbs_certificate().subject().clone()),
            produced_at: at,
            responses: vec![SingleResponse {
                cert_id,
                cert_status: CertStatus::good(),
                this_update: at,
                next_update: Some(next),
                single_extensions: None,
            }],
            response_extensions: None,
        };
        let sig = p.ocsp_key.sign(&data.to_der().unwrap()).unwrap();
        let basic = BasicOcspResponse {
            tbs_response_data: data,
            signature_algorithm: alg(oid::ECDSA_WITH_SHA256),
            signature: BitString::from_bytes(&sig).unwrap(),
            certs: Some(vec![p.ocsp.clone()]),
        };
        OcspResponse {
            response_status: x509_ocsp::OcspResponseStatus::Successful,
            response_bytes: Some(x509_ocsp::ResponseBytes {
                response_type: oid::OCSP_BASIC,
                response: OctetString::new(basic.to_der().unwrap()).unwrap(),
            }),
        }
        .to_der()
        .unwrap()
    }
}

impl RevocationSource for TestRevocation {
    fn certificates(&self) -> &[Certificate] {
        static CHAIN: OnceLock<Vec<Certificate>> = OnceLock::new();
        if self.no_issuers {
            return &[];
        }
        CHAIN.get_or_init(|| vec![pki().inter.clone(), pki().root.clone()])
    }

    fn ocsp(&self, query: &OcspQuery<'_>) -> Result<Option<Vec<u8>>, SourceError> {
        self.ocsp_calls.set(self.ocsp_calls.get() + 1);
        if self.no_ocsp || self.nothing || *query.issuer != pki().inter {
            return Ok(None);
        }
        Ok(Some(self.response(query.request_der)))
    }

    fn crl(&self, query: &CrlQuery<'_>) -> Result<Option<Vec<u8>>, SourceError> {
        self.crl_calls.set(self.crl_calls.get() + 1);
        if self.nothing {
            return Ok(None);
        }
        let p = pki();
        let (root_crl, inter_crl) = if self.scoped_crls {
            (&p.root_crl_scoped, &p.inter_crl_scoped)
        } else {
            (&p.root_crl, &p.inter_crl)
        };
        Ok(if *query.issuer == p.root {
            Some(root_crl.clone())
        } else if *query.issuer == p.inter {
            Some(inter_crl.clone())
        } else {
            None
        })
    }
}

// ---------------------------------------------------------------- PDFs

/// A classic-xref PDF from object bodies (object 1 is the catalog).
pub fn classic_pdf(objects: &[Vec<u8>]) -> Vec<u8> {
    let mut out = b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n".to_vec();
    let mut offsets = Vec::new();
    for (i, body) in objects.iter().enumerate() {
        offsets.push(out.len());
        out.extend_from_slice(format!("{} 0 obj\n", i + 1).as_bytes());
        out.extend_from_slice(body);
        out.extend_from_slice(b"\nendobj\n");
    }
    let xref = out.len();
    out.extend_from_slice(
        format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).as_bytes(),
    );
    for o in offsets {
        out.extend_from_slice(format!("{o:010} 00000 n \n").as_bytes());
    }
    out.extend_from_slice(
        format!(
            "trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    out
}

fn stream(dict: &str, data: &[u8]) -> Vec<u8> {
    let mut v = format!("<< {dict} /Length {} >>\nstream\n", data.len()).into_bytes();
    v.extend_from_slice(data);
    v.extend_from_slice(b"\nendstream");
    v
}

/// A one-page agreement.
pub fn one_page(text: &str) -> Vec<u8> {
    let content = format!("BT /F1 24 Tf 72 720 Td ({text}) Tj ET");
    classic_pdf(&[
        b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>".to_vec(),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_vec(),
        stream("", content.as_bytes()),
    ])
}

/// A one-page form: an empty signature field `Signer1` (visible, 200x50 at 72,100) and
/// a text field `Name`.
pub fn form_pdf() -> Vec<u8> {
    let content = b"BT /F1 18 Tf 72 720 Td (Please sign below) Tj ET";
    classic_pdf(&[
        b"<< /Type /Catalog /Pages 2 0 R /AcroForm 6 0 R >>".to_vec(),
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_vec(),
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R /Annots [7 0 R 8 0 R] >>".to_vec(),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_vec(),
        stream("", content),
        b"<< /Fields [7 0 R 8 0 R] /DA (/Helv 0 Tf 0 g) >>".to_vec(),
        b"<< /Type /Annot /Subtype /Widget /FT /Sig /T (Signer1) /Rect [72 100 272 150] /F 4 /P 3 0 R >>".to_vec(),
        b"<< /Type /Annot /Subtype /Widget /FT /Tx /T (Name) /Rect [72 200 272 220] /F 4 /P 3 0 R /V (Ada) >>".to_vec(),
    ])
}

/// Count `needle` in `hay`.
pub fn count(hay: &[u8], needle: &[u8]) -> usize {
    hay.windows(needle.len()).filter(|w| *w == needle).count()
}
