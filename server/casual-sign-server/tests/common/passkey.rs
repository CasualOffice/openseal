//! A software WebAuthn authenticator for the server's tests (CON-13): one ES256
//! credential per value, answering the options `POST /auth/mfa/passkeys/options` gives
//! the way a browser and an authenticator would (WebAuthn Level 2 §6.1 authenticator
//! data, §5.8.1 client data), with the key from `aws-lc-rs` (ADR-006). The relying
//! party's checks are written separately (`src/webauthn.rs`); the browser e2e drives
//! Chromium's own virtual authenticator against the same server code.

use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::encoding::AsDer;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, KeyPair};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};

pub fn b64(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

pub fn unb64(s: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(s).unwrap()
}

/// One credential on a software authenticator.
pub struct Soft {
    key: EcdsaKeyPair,
    pub id: Vec<u8>,
    /// The signature counter it reports next (0: an authenticator that keeps none).
    pub count: u32,
    /// The origin its "browser" reports.
    pub origin: String,
    /// The RP id it hashes into authenticator data.
    pub rp_id: String,
}

impl Soft {
    pub fn new() -> Self {
        let id: [u8; 16] = rand_id();
        Self {
            key: EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).unwrap(),
            id: id.to_vec(),
            count: 0,
            origin: "https://sign.example.test".into(),
            rp_id: "sign.example.test".into(),
        }
    }

    fn auth_data(&self, attested: bool) -> Vec<u8> {
        let mut d = digest(&SHA256, self.rp_id.as_bytes()).as_ref().to_vec();
        // UP and UV, and AT when attesting.
        d.push(0x05 | if attested { 0x40 } else { 0 });
        d.extend_from_slice(&self.count.to_be_bytes());
        if attested {
            d.extend_from_slice(&[0; 16]);
            d.extend_from_slice(&u16::try_from(self.id.len()).unwrap().to_be_bytes());
            d.extend_from_slice(&self.id);
            // The COSE key would follow; the server reads `getPublicKey()` instead.
            d.push(0xa0);
        }
        d
    }

    fn client_data(&self, ty: &str, challenge: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({"type": ty, "challenge": challenge, "origin": self.origin, "crossOrigin": false})).unwrap()
    }

    /// `POST /auth/mfa/passkeys`'s body for the registration `options` asked for.
    pub fn register(&self, options: &Value, name: &str) -> Value {
        let challenge = options["public_key"]["challenge"].as_str().unwrap();
        json!({
            "name": name,
            "credential": {
                "id": b64(&self.id),
                "client_data_json": b64(&self.client_data("webauthn.create", challenge)),
                "authenticator_data": b64(&self.auth_data(true)),
                "public_key": b64(self.key.public_key().as_der().unwrap().as_ref()),
                "public_key_algorithm": -7,
                "transports": ["internal"],
            }
        })
    }

    /// A `passkey` assertion answering the `options` asked for (`verify` or
    /// `reauthenticate`), as `{"passkey": …}` takes it.
    pub fn assert(&self, options: &Value) -> Value {
        let challenge = options["public_key"]["challenge"].as_str().unwrap();
        let cd = self.client_data("webauthn.get", challenge);
        let ad = self.auth_data(false);
        let mut msg = ad.clone();
        msg.extend_from_slice(digest(&SHA256, &cd).as_ref());
        let sig = self.key.sign(&SystemRandom::new(), &msg).unwrap();
        json!({
            "credential_id": b64(&self.id),
            "client_data_json": b64(&cd),
            "authenticator_data": b64(&ad),
            "signature": b64(sig.as_ref()),
        })
    }
}

fn rand_id() -> [u8; 16] {
    let mut b = [0u8; 16];
    aws_lc_rs::rand::fill(&mut b).unwrap();
    b
}
