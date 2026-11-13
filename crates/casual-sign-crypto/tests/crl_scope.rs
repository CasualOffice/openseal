//! CRLs scoped by a critical Issuing Distribution Point (RFC 5280 §5.2.5, §6.3.3), as
//! production CAs issue them (HRD-02: DigiCert's timestamping CA, and partitioned CRLs
//! generally). `crl_status_for` reads the scope against the certificate asked about; the
//! plain `crl_status`, which has no certificate to compare, still refuses the extension.

// Tests may unwrap, index and panic (CLAUDE.md); the product lints target src/.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use casual_sign_crypto::oid::CE_ISSUING_DISTRIBUTION_POINT;
use casual_sign_crypto::revocation::{RevocationStatus, crl_status, crl_status_for};
use casual_sign_crypto::{Certificate, CryptoError, RevocationFailure, Structure};
use core::time::Duration;
use der::asn1::{BitString, OctetString};
use der::{Decode, Encode};
use rcgen::{
    BasicConstraints, CertificateParams, CertificateRevocationListParams, CertifiedIssuer,
    CrlDistributionPoint, CrlIssuingDistributionPoint, CrlScope, DistinguishedName, DnType, IsCa,
    KeyIdMethod, KeyPair, KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, RevocationReason,
    RevokedCertParams, SerialNumber, SigningKey,
};
use x509_cert::crl::CertificateList;
use x509_cert::ext::pkix::crl::IssuingDistributionPoint;
use x509_cert::ext::pkix::crl::dp::Reasons;

const CA_CRL: &str = "http://pki.example.test/ca.crl";
const OTHER_CRL: &str = "http://pki.example.test/partition-2.crl";
/// 2026-11-10T00:00:00Z, inside every CRL's period.
const AT: Duration = Duration::from_secs(1_794_268_800);

fn params(cn: &str, serial: u64) -> CertificateParams {
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    let mut d = DistinguishedName::new();
    d.push(DnType::CommonName, cn);
    p.distinguished_name = d;
    p.not_before = rcgen::date_time_ymd(2026, 1, 1);
    p.not_after = rcgen::date_time_ymd(2036, 1, 1);
    p.serial_number = Some(SerialNumber::from(serial));
    p.key_identifier_method = KeyIdMethod::Sha256;
    p.use_authority_key_identifier_extension = true;
    p
}

struct Pki {
    ca: CertifiedIssuer<'static, KeyPair>,
    ca_cert: Certificate,
    /// An end-entity certificate naming CA_CRL.
    leaf: Certificate,
    /// A subordinate CA certificate naming CA_CRL.
    sub: Certificate,
    /// An end-entity certificate naming no CRL distribution point.
    bare: Certificate,
}

fn pki() -> Pki {
    let mut cp = params("Scope test CA", 1);
    cp.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    cp.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    cp.use_authority_key_identifier_extension = false;
    let ca =
        CertifiedIssuer::self_signed(cp, KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap())
            .unwrap();
    let issue = |cn: &str, serial: u64, is_ca: bool, cdp: bool| {
        let mut p = params(cn, serial);
        if is_ca {
            p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        } else {
            p.is_ca = IsCa::ExplicitNoCa;
            p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        }
        if cdp {
            p.crl_distribution_points = vec![CrlDistributionPoint {
                uris: vec![CA_CRL.to_owned()],
            }];
        }
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        Certificate::from_der(p.signed_by(&key, &ca).unwrap().der()).unwrap()
    };
    let leaf = issue("Scope test leaf", 10, false, true);
    let sub = issue("Scope test sub-CA", 11, true, true);
    let bare = issue("Scope test bare leaf", 12, false, false);
    let ca_cert = Certificate::from_der(ca.der()).unwrap();
    Pki {
        ca,
        ca_cert,
        leaf,
        sub,
        bare,
    }
}

fn crl(pki: &Pki, uri: &str, scope: Option<CrlScope>, revoked: &[u64]) -> Vec<u8> {
    CertificateRevocationListParams {
        this_update: rcgen::date_time_ymd(2026, 11, 1),
        next_update: rcgen::date_time_ymd(2026, 12, 1),
        crl_number: SerialNumber::from(7u64),
        issuing_distribution_point: Some(CrlIssuingDistributionPoint {
            distribution_point: CrlDistributionPoint {
                uris: vec![uri.to_owned()],
            },
            scope,
        }),
        revoked_certs: revoked
            .iter()
            .map(|s| RevokedCertParams {
                serial_number: SerialNumber::from(*s),
                revocation_time: rcgen::date_time_ymd(2026, 6, 1),
                reason_code: Some(RevocationReason::KeyCompromise),
                invalidity_date: None,
            })
            .collect(),
        key_identifier_method: KeyIdMethod::Sha256,
    }
    .signed_by(&pki.ca)
    .unwrap()
    .der()
    .to_vec()
}

const NOT_COVERED: CryptoError = CryptoError::Revocation(RevocationFailure::NotCovered);

#[test]
fn a_crl_scoped_to_the_certificates_distribution_point_answers_for_it() {
    let p = pki();
    let all = crl(&p, CA_CRL, None, &[]);
    assert_eq!(
        crl_status_for(&all, &p.leaf, &p.ca_cert, AT),
        Ok(RevocationStatus::Good)
    );
    assert_eq!(
        crl_status_for(&all, &p.sub, &p.ca_cert, AT),
        Ok(RevocationStatus::Good)
    );
    let revoked = crl(&p, CA_CRL, Some(CrlScope::UserCertsOnly), &[10]);
    assert!(matches!(
        crl_status_for(&revoked, &p.leaf, &p.ca_cert, AT),
        Ok(RevocationStatus::Revoked { .. })
    ));
}

#[test]
fn a_crl_scoped_elsewhere_does_not_cover_the_certificate() {
    let p = pki();
    // Another partition's CRL: silent about this certificate, so never "good".
    let other = crl(&p, OTHER_CRL, None, &[]);
    assert_eq!(
        crl_status_for(&other, &p.leaf, &p.ca_cert, AT),
        Err(NOT_COVERED)
    );
    // A certificate naming no distribution point is covered only by a full CRL.
    let all = crl(&p, CA_CRL, None, &[]);
    assert_eq!(
        crl_status_for(&all, &p.bare, &p.ca_cert, AT),
        Err(NOT_COVERED)
    );
    // End-entity only, asked about a CA; CA only, asked about an end entity.
    let users = crl(&p, CA_CRL, Some(CrlScope::UserCertsOnly), &[]);
    assert_eq!(
        crl_status_for(&users, &p.sub, &p.ca_cert, AT),
        Err(NOT_COVERED)
    );
    assert_eq!(
        crl_status_for(&users, &p.leaf, &p.ca_cert, AT),
        Ok(RevocationStatus::Good)
    );
    let cas = crl(&p, CA_CRL, Some(CrlScope::CaCertsOnly), &[]);
    assert_eq!(
        crl_status_for(&cas, &p.leaf, &p.ca_cert, AT),
        Err(NOT_COVERED)
    );
    assert_eq!(
        crl_status_for(&cas, &p.sub, &p.ca_cert, AT),
        Ok(RevocationStatus::Good)
    );
}

#[test]
fn without_the_certificate_a_scoped_crl_is_still_refused() {
    let p = pki();
    let all = crl(&p, CA_CRL, None, &[]);
    assert_eq!(
        crl_status(
            &all,
            p.leaf.tbs_certificate().serial_number(),
            &p.ca_cert,
            AT
        ),
        Err(CryptoError::Revocation(
            RevocationFailure::UnsupportedCriticalExtension
        ))
    );
}

/// `crl` with its Issuing Distribution Point extension's value and criticality replaced
/// by `value` and `critical`, re-signed by the CA so that only the scope is under test.
fn with_idp(pki: &Pki, crl: &[u8], value: Vec<u8>, critical: bool) -> Vec<u8> {
    let mut list = <CertificateList>::from_der(crl).unwrap();
    let ext = list
        .tbs_cert_list
        .crl_extensions
        .iter_mut()
        .flatten()
        .find(|e| e.extn_id == CE_ISSUING_DISTRIBUTION_POINT)
        .unwrap();
    ext.extn_value = OctetString::new(value).unwrap();
    ext.critical = critical;
    let tbs = list.tbs_cert_list.to_der().unwrap();
    list.signature = BitString::from_bytes(&pki.ca.key().sign(&tbs).unwrap()).unwrap();
    list.to_der().unwrap()
}

/// The DER value of `crl`'s Issuing Distribution Point extension.
fn idp_value(crl: &[u8]) -> Vec<u8> {
    let list = <CertificateList>::from_der(crl).unwrap();
    list.tbs_cert_list
        .crl_extensions
        .iter()
        .flatten()
        .find(|e| e.extn_id == CE_ISSUING_DISTRIBUTION_POINT)
        .unwrap()
        .extn_value
        .as_bytes()
        .to_vec()
}

/// `crl` (scoped to CA_CRL) with its Issuing Distribution Point changed by `edit`.
fn edited(pki: &Pki, edit: impl FnOnce(&mut IssuingDistributionPoint)) -> Vec<u8> {
    let base = crl(pki, CA_CRL, None, &[]);
    let mut idp = IssuingDistributionPoint::from_der(&idp_value(&base)).unwrap();
    edit(&mut idp);
    with_idp(pki, &base, idp.to_der().unwrap(), true)
}

const MALFORMED: CryptoError = CryptoError::Malformed(Structure::Crl);
const UNSUPPORTED: CryptoError =
    CryptoError::Revocation(RevocationFailure::UnsupportedCriticalExtension);

#[test]
fn a_malformed_issuing_distribution_point_is_a_malformed_crl() {
    let p = pki();
    let base = crl(&p, CA_CRL, None, &[]);
    let good = idp_value(&base);
    let mut trailing = good.clone();
    trailing.push(0);
    let mut truncated = good.clone();
    truncated.pop();
    for value in [
        Vec::new(),
        vec![0x30],
        vec![0x30, 0x05, 0x01],
        vec![0x04, 0x00],
        vec![0x30, 0x03, 0x81, 0x01, 0x07],
        truncated,
        trailing,
    ] {
        for critical in [true, false] {
            let bad = with_idp(&p, &base, value.clone(), critical);
            assert_eq!(
                crl_status_for(&bad, &p.leaf, &p.ca_cert, AT),
                Err(MALFORMED),
                "value {value:02x?}, critical {critical}"
            );
        }
    }
}

#[test]
fn more_than_one_only_contains_restriction_is_a_malformed_crl() {
    let p = pki();
    let pairs: [fn(&mut IssuingDistributionPoint); 3] = [
        |i| {
            i.only_contains_user_certs = true;
            i.only_contains_ca_certs = true;
        },
        |i| {
            i.only_contains_user_certs = true;
            i.only_contains_attribute_certs = true;
        },
        |i| {
            i.only_contains_ca_certs = true;
            i.only_contains_attribute_certs = true;
        },
    ];
    for edit in pairs {
        let bad = edited(&p, edit);
        assert_eq!(
            crl_status_for(&bad, &p.leaf, &p.ca_cert, AT),
            Err(MALFORMED)
        );
        assert_eq!(crl_status_for(&bad, &p.sub, &p.ca_cert, AT), Err(MALFORMED));
    }
}

#[test]
fn indirect_and_some_reasons_only_crls_are_refused() {
    let p = pki();
    let indirect = edited(&p, |i| i.indirect_crl = true);
    assert_eq!(
        crl_status_for(&indirect, &p.leaf, &p.ca_cert, AT),
        Err(UNSUPPORTED)
    );
    let some_reasons = edited(&p, |i| {
        i.only_some_reasons = Some(Reasons::KeyCompromise.into());
    });
    assert_eq!(
        crl_status_for(&some_reasons, &p.leaf, &p.ca_cert, AT),
        Err(UNSUPPORTED)
    );
}

#[test]
fn an_attribute_certificate_crl_covers_no_public_key_certificate() {
    let p = pki();
    let attrs = edited(&p, |i| i.only_contains_attribute_certs = true);
    assert_eq!(
        crl_status_for(&attrs, &p.leaf, &p.ca_cert, AT),
        Err(NOT_COVERED)
    );
    assert_eq!(
        crl_status_for(&attrs, &p.sub, &p.ca_cert, AT),
        Err(NOT_COVERED)
    );
}

#[test]
fn a_non_critical_scope_for_another_partition_is_still_a_scope() {
    let p = pki();
    // Some CAs mark the extension non-critical; its scope binds all the same, so another
    // partition's CRL must not read as "good" for this certificate.
    let other = crl(&p, OTHER_CRL, None, &[]);
    let value = idp_value(&other);
    let non_critical = with_idp(&p, &other, value.clone(), false);
    assert_eq!(
        crl_status_for(&non_critical, &p.leaf, &p.ca_cert, AT),
        Err(NOT_COVERED)
    );
    // And our own partition, non-critical, still answers.
    let own = crl(&p, CA_CRL, None, &[10]);
    let value = idp_value(&own);
    let own = with_idp(&p, &own, value, false);
    assert!(matches!(
        crl_status_for(&own, &p.leaf, &p.ca_cert, AT),
        Ok(RevocationStatus::Revoked { .. })
    ));
}
