//! Bytes into the sealer (`T-1G`, `F-007`), seeded with `fixtures/sealed/` and
//! `fixtures/signed/`: every input is admitted, given an approval signature at PAdES B-B
//! with a throwaway P-256 key (made at start, never written) and verified by the sealer
//! itself. Any panic, hang or out-of-memory is a finding; so is an error without a
//! docs/20 code, or an output the input does not prefix.
//!
//!   cargo +nightly fuzz run seal fixtures/sealed fixtures/signed -- -max_total_time=300 -dict=fuzz/pdf.dict
#![no_main]

use std::sync::OnceLock;
use std::time::Duration;

use casual_sign_crypto::{Certificate, KeyError, KeyProvider, Signature, SignatureAlgorithm};
use casual_sign_seal::{Limits, NoRevocation, NoTimestamps, Profile, SealRequest, seal};
use der::Decode;
use libfuzzer_sys::fuzz_target;
use rcgen::{CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256, SigningKey};

struct Key {
    key: KeyPair,
    chain: Vec<Certificate>,
}

impl KeyProvider for Key {
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::EcdsaP256Sha256
    }

    fn certificate_chain(&self) -> &[Certificate] {
        &self.chain
    }

    fn sign(&self, signed_attrs_der: &[u8]) -> Result<Signature, KeyError> {
        self.key
            .sign(signed_attrs_der)
            .map(Signature::new)
            .map_err(|_| KeyError::Unavailable)
    }
}

fn key() -> &'static Key {
    static KEY: OnceLock<Key> = OnceLock::new();
    KEY.get_or_init(|| {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = CertificateParams::new(Vec::<String>::new())
            .unwrap()
            .self_signed(&key)
            .unwrap();
        let chain = vec![Certificate::from_der(cert.der()).unwrap()];
        Key { key, chain }
    })
}

fuzz_target!(|data: &[u8]| {
    let mut request = SealRequest::new(
        Profile::BaselineB,
        "FuzzSeal",
        Duration::from_secs(1_793_534_400),
    );
    request.limits = Limits {
        max_stream_bytes: 8 << 20,
        max_total_decoded_bytes: 32 << 20,
        objstm_cache_bytes: 8 << 20,
        ..Limits::default()
    };
    match seal(data, &request, key(), &NoTimestamps, &NoRevocation) {
        Ok(sealed) => assert!(sealed.bytes.starts_with(data)),
        Err(e) => assert!(e.code().starts_with("CS-")),
    }
});
