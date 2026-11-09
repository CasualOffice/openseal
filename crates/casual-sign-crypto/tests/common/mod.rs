//! Test-only key provider (aws-lc-rs) and throwaway PKI (rcgen), generated in memory per
//! test binary. No key touches disk. Never use outside tests.
#![allow(dead_code)] // Each test binary uses a different subset of these helpers.

use std::path::PathBuf;
use std::sync::OnceLock;

use aws_lc_rs::encoding::{AsDer, Pkcs8V1Der};
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::KeySize;
use aws_lc_rs::signature::{self as aws, EcdsaKeyPair, RsaKeyPair};
use casual_sign_crypto::{Certificate, KeyError, KeyProvider, Signature, SignatureAlgorithm};
use der::Decode;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DistinguishedName, DnType, IsCa, KeyPair,
    KeyUsagePurpose, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_RSA_SHA256, SerialNumber,
};

pub fn fixture(name: &str) -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../fixtures/crypto")
        .join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{}: {e}", p.display()))
}

pub fn cert(name: &str) -> Certificate {
    Certificate::from_der(&fixture(name)).unwrap()
}

/// Where tests write outputs for the independent check (`gen.py --verify`).
pub fn interop_out_dir() -> PathBuf {
    let d = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../target/crypto-interop");
    std::fs::create_dir_all(&d).unwrap();
    d
}

enum Key {
    Ecdsa(EcdsaKeyPair),
    Rsa(RsaKeyPair),
}

/// An in-memory `KeyProvider` for tests: aws-lc-rs signs the signed attributes with the
/// FIPS-approved one-shot `sign` (hash and sign in one call), as `keyd` will.
pub struct TestProvider {
    key: Key,
    algorithm: SignatureAlgorithm,
    chain: Vec<Certificate>,
}

impl KeyProvider for TestProvider {
    fn algorithm(&self) -> SignatureAlgorithm {
        self.algorithm
    }

    fn certificate_chain(&self) -> &[Certificate] {
        &self.chain
    }

    fn sign(&self, signed_attrs_der: &[u8]) -> Result<Signature, KeyError> {
        let rng = SystemRandom::new();
        match &self.key {
            Key::Ecdsa(k) => k
                .sign(&rng, signed_attrs_der)
                .map(|s| Signature::new(s.as_ref().to_vec()))
                .map_err(|_| KeyError::Unavailable),
            Key::Rsa(k) => {
                let pad: &'static dyn aws::RsaEncoding = match self.algorithm {
                    SignatureAlgorithm::RsaPkcs1Sha256 => &aws::RSA_PKCS1_SHA256,
                    SignatureAlgorithm::RsaPkcs1Sha384 => &aws::RSA_PKCS1_SHA384,
                    SignatureAlgorithm::RsaPkcs1Sha512 => &aws::RSA_PKCS1_SHA512,
                    SignatureAlgorithm::RsaPssSha256 => &aws::RSA_PSS_SHA256,
                    SignatureAlgorithm::RsaPssSha384 => &aws::RSA_PSS_SHA384,
                    SignatureAlgorithm::RsaPssSha512 => &aws::RSA_PSS_SHA512,
                    _ => return Err(KeyError::Refused),
                };
                let mut sig = vec![0u8; k.public_modulus_len()];
                k.sign(pad, &rng, signed_attrs_der, &mut sig)
                    .map_err(|_| KeyError::Unavailable)?;
                Ok(Signature::new(sig))
            }
        }
    }
}

pub struct Pki {
    pub root: Certificate,
    root_issuer: CertifiedIssuer<'static, KeyPair>,
    p256_pkcs8: Vec<u8>,
    p384_pkcs8: Vec<u8>,
    rsa_pkcs8: Vec<u8>,
    pub p256: Certificate,
    pub p384: Certificate,
    pub rsa: Certificate,
}

fn name(cn: &str) -> DistinguishedName {
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    dn.push(
        DnType::OrganizationName,
        "OpenSeal T-1F throwaway test PKI (Rust)",
    );
    dn
}

fn leaf(
    cn: &str,
    serial: u64,
    key: &KeyPair,
    ca: &CertifiedIssuer<'static, KeyPair>,
) -> Certificate {
    let mut p = CertificateParams::new(Vec::<String>::new()).unwrap();
    p.distinguished_name = name(cn);
    p.is_ca = IsCa::ExplicitNoCa;
    p.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::ContentCommitment,
    ];
    p.not_before = rcgen::date_time_ymd(2026, 1, 1);
    p.not_after = rcgen::date_time_ymd(2036, 1, 1);
    p.serial_number = Some(SerialNumber::from(serial));
    Certificate::from_der(p.signed_by(key, ca).unwrap().der()).unwrap()
}

pub fn pki() -> &'static Pki {
    static PKI: OnceLock<Pki> = OnceLock::new();
    PKI.get_or_init(|| {
        let ca_key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut ca_p = CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_p.distinguished_name = name("T-1F Rust test root");
        ca_p.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_p.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        ca_p.not_before = rcgen::date_time_ymd(2026, 1, 1);
        ca_p.not_after = rcgen::date_time_ymd(2036, 1, 1);
        ca_p.serial_number = Some(SerialNumber::from(1u64));
        let ca = CertifiedIssuer::self_signed(ca_p, ca_key).unwrap();
        let root = Certificate::from_der(ca.der()).unwrap();

        let rng = SystemRandom::new();
        let p256_pkcs8 = EcdsaKeyPair::generate_pkcs8(&aws::ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
            .unwrap()
            .as_ref()
            .to_vec();
        let p384_pkcs8 = EcdsaKeyPair::generate_pkcs8(&aws::ECDSA_P384_SHA384_ASN1_SIGNING, &rng)
            .unwrap()
            .as_ref()
            .to_vec();
        let rsa = RsaKeyPair::generate(KeySize::Rsa3072).unwrap();
        let rsa_pkcs8 = AsDer::<Pkcs8V1Der>::as_der(&rsa).unwrap().as_ref().to_vec();

        let p256 = leaf(
            "T-1F Rust P-256",
            2,
            &KeyPair::try_from(p256_pkcs8.as_slice()).unwrap(),
            &ca,
        );
        let p384 = leaf(
            "T-1F Rust P-384",
            3,
            &KeyPair::try_from(p384_pkcs8.as_slice()).unwrap(),
            &ca,
        );
        let rsa_rc =
            KeyPair::from_pkcs8_der_and_sign_algo(&rsa_pkcs8.as_slice().into(), &PKCS_RSA_SHA256)
                .unwrap();
        let rsa_cert = leaf("T-1F Rust RSA-3072", 4, &rsa_rc, &ca);
        let _ = &PKCS_ECDSA_P384_SHA384;
        Pki {
            root,
            root_issuer: ca,
            p256_pkcs8,
            p384_pkcs8,
            rsa_pkcs8,
            p256,
            p384,
            rsa: rsa_cert,
        }
    })
}

impl Pki {
    pub fn provider(&self, algorithm: SignatureAlgorithm) -> TestProvider {
        let (key, leaf) = match algorithm {
            SignatureAlgorithm::EcdsaP256Sha256 => (
                Key::Ecdsa(
                    EcdsaKeyPair::from_pkcs8(
                        &aws::ECDSA_P256_SHA256_ASN1_SIGNING,
                        &self.p256_pkcs8,
                    )
                    .unwrap(),
                ),
                &self.p256,
            ),
            SignatureAlgorithm::EcdsaP384Sha384 => (
                Key::Ecdsa(
                    EcdsaKeyPair::from_pkcs8(
                        &aws::ECDSA_P384_SHA384_ASN1_SIGNING,
                        &self.p384_pkcs8,
                    )
                    .unwrap(),
                ),
                &self.p384,
            ),
            _ => (
                Key::Rsa(RsaKeyPair::from_pkcs8(&self.rsa_pkcs8).unwrap()),
                &self.rsa,
            ),
        };
        TestProvider {
            key,
            algorithm,
            chain: vec![leaf.clone(), self.root.clone()],
        }
    }

    /// A provider whose certificate does not belong to its key.
    pub fn mismatched_provider(&self) -> TestProvider {
        let mut p = self.provider(SignatureAlgorithm::EcdsaP256Sha256);
        let other = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        p.chain = vec![
            leaf("T-1F Rust wrong key", 9, &other, &self.root_issuer),
            self.root.clone(),
        ];
        p
    }
}
