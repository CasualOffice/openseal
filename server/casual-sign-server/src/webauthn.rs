//! The WebAuthn relying party for staff passkeys (CON-13, ADR-040; W3C Web
//! Authentication Level 2 §7.1 and §7.2).
//!
//! What this module checks is the protocol: the client data (type, challenge, origin),
//! the authenticator data (the RP id hash, user presence, the attested credential id,
//! the signature counter), and which key and algorithm sign. The cryptography is
//! `aws-lc-rs`'s (ADR-006): SHA-256, and the signature verified with the stored public
//! key, ES256 (`ECDSA_P256_SHA256_ASN1`), EdDSA (`ED25519`) or RS256
//! (`RSA_PKCS1_2048_8192_SHA256`).
//!
//! Registration takes the credential's public key as SubjectPublicKeyInfo DER, from the
//! browser's `AuthenticatorAttestationResponse.getPublicKey()`, which WebAuthn Level 2
//! (§5.2.1) provides so that a relying party need not decode CBOR. Attestation is
//! "none": the attestation statement is neither read nor trusted, so the key, like the
//! rest of a registration, is as good as the authenticated session that sends it; every
//! later use is proved by a signature over a fresh, single-use challenge.
//!
//! Everything here reads untrusted input: lengths are bounded and checked, nothing
//! panics, and a refusal names what failed ([`Refusal`]) without echoing any of it.

use aws_lc_rs::constant_time::verify_slices_are_equal;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_ASN1, ED25519, ParsedPublicKey, RSA_PKCS1_2048_8192_SHA256,
    UnparsedPublicKey, VerificationAlgorithm,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;

use crate::crypto::sha256;

/// COSE algorithm ES256: ECDSA on P-256 with SHA-256.
pub const ES256: i32 = -7;
/// COSE algorithm EdDSA (Ed25519).
pub const EDDSA: i32 = -8;
/// COSE algorithm RS256: RSASSA-PKCS1-v1_5 with SHA-256.
pub const RS256: i32 = -257;
/// The algorithms offered, in the order of preference given to the browser.
pub const ALGORITHMS: [i32; 3] = [ES256, EDDSA, RS256];

/// Largest `clientDataJSON` read (docs/21).
pub const MAX_CLIENT_DATA: usize = 4096;
/// Largest authenticator data read (docs/21): the fixed 37 bytes, an attested credential
/// with an RSA key, and extensions.
pub const MAX_AUTHENTICATOR_DATA: usize = 4096;
/// Largest credential id (WebAuthn Level 2 §5.8.3: at most 1023 bytes).
pub const MAX_CREDENTIAL_ID: usize = 1023;
/// Largest SubjectPublicKeyInfo kept (an RSA-8192 key is about 1.1 KB).
pub const MAX_PUBLIC_KEY: usize = 2048;
/// Largest signature read (RSA-8192: 1024 bytes).
pub const MAX_SIGNATURE: usize = 1024;
/// Largest user handle (§5.4.3: at most 64 bytes).
pub const MAX_USER_HANDLE: usize = 64;

const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;
const FLAG_BE: u8 = 0x08;
const FLAG_BS: u8 = 0x10;
const FLAG_AT: u8 = 0x40;

/// Why a registration or an assertion was refused. Each is one check of WebAuthn
/// Level 2 §7.1 or §7.2; [`Refusal::as_str`] is the word the security log records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refusal {
    /// A field is too long, or not base64url.
    Malformed,
    /// `clientDataJSON` is not the JSON object WebAuthn defines.
    ClientData,
    /// The ceremony type is not the one expected (`webauthn.create` or `webauthn.get`).
    Type,
    /// The challenge is not the one this server issued for this session and purpose.
    Challenge,
    /// The origin is not this server's.
    Origin,
    /// The ceremony ran in a cross-origin frame.
    CrossOrigin,
    /// The authenticator data is too short or inconsistent.
    AuthenticatorData,
    /// The RP id hash is not this server's.
    RpId,
    /// The user was not present (the UP flag is clear).
    UserPresence,
    /// A registration without attested credential data, or whose credential id is not
    /// the one sent.
    Credential,
    /// An algorithm this server does not accept.
    Algorithm,
    /// The public key does not parse as a key of the algorithm.
    PublicKey,
    /// The signature does not verify.
    Signature,
    /// The user handle names another user.
    UserHandle,
}

impl Refusal {
    /// The word the security log records.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Malformed => "malformed",
            Self::ClientData => "client_data",
            Self::Type => "type",
            Self::Challenge => "challenge",
            Self::Origin => "origin",
            Self::CrossOrigin => "cross_origin",
            Self::AuthenticatorData => "authenticator_data",
            Self::RpId => "rp_id",
            Self::UserPresence => "user_presence",
            Self::Credential => "credential",
            Self::Algorithm => "algorithm",
            Self::PublicKey => "public_key",
            Self::Signature => "signature",
            Self::UserHandle => "user_handle",
        }
    }
}

/// This server as a WebAuthn relying party: its RP id and the one origin ceremonies
/// must run on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelyingParty {
    id: String,
    origin: String,
    id_hash: [u8; 32],
}

impl RelyingParty {
    /// From the server's public URL (`OPENSEAL_PUBLIC_URL`): the origin is its scheme,
    /// host and port; the RP id is `rp_id` (`OPENSEAL_WEBAUTHN_RP_ID`) when given, which
    /// must be the host or a parent domain of it, else the host. `None` when the URL's
    /// host cannot be an RP id (an IP address, or no host), or `rp_id` does not fit:
    /// passkeys are then unavailable.
    #[must_use]
    pub fn from_public_url(public_url: &str, rp_id: Option<&str>) -> Option<Self> {
        let (scheme, rest) = public_url.split_once("://")?;
        let scheme = scheme.to_ascii_lowercase();
        if scheme != "https" && scheme != "http" {
            return None;
        }
        let authority = rest.split(['/', '?', '#']).next()?.to_ascii_lowercase();
        if authority.is_empty() || authority.contains('@') || authority.starts_with('[') {
            return None;
        }
        let host = authority.split(':').next()?.to_owned();
        let domain_like = !host.is_empty()
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
            && host.bytes().any(|b| b.is_ascii_alphabetic());
        if !domain_like {
            return None;
        }
        let id = match rp_id {
            Some(r) => {
                let r = r.trim().to_ascii_lowercase();
                let fits = r == host
                    || (host.ends_with(&r) && host[..host.len() - r.len()].ends_with('.'));
                if r.is_empty() || !fits {
                    return None;
                }
                r
            }
            None => host,
        };
        let id_hash = sha256(id.as_bytes());
        Some(Self {
            origin: format!("{scheme}://{authority}"),
            id,
            id_hash,
        })
    }

    /// The RP id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The origin ceremonies must run on.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }
}

/// Base64url without padding (what the browser's JSON carries), padding tolerated.
/// `None` when it is not base64url, or decodes to more than `max` bytes.
#[must_use]
pub fn unb64(s: &str, max: usize) -> Option<Vec<u8>> {
    // Four characters carry three bytes: refuse what cannot fit before decoding it.
    if s.len() > max.saturating_mul(4) / 3 + 4 {
        return None;
    }
    let v = URL_SAFE_NO_PAD.decode(s.trim_end_matches('=')).ok()?;
    (v.len() <= max).then_some(v)
}

/// Base64url without padding.
#[must_use]
pub fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

#[derive(Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    ty: String,
    challenge: String,
    origin: String,
    #[serde(rename = "crossOrigin", default)]
    cross_origin: Option<bool>,
}

/// §7.1 steps 5 to 12 / §7.2 steps 10 to 14: the client data names this ceremony, this
/// challenge and this origin.
fn check_client_data(
    rp: &RelyingParty,
    json: &[u8],
    ty: &str,
    challenge: &[u8],
) -> Result<(), Refusal> {
    if json.len() > MAX_CLIENT_DATA {
        return Err(Refusal::Malformed);
    }
    let c: ClientData = serde_json::from_slice(json).map_err(|_| Refusal::ClientData)?;
    if c.ty != ty {
        return Err(Refusal::Type);
    }
    let sent = unb64(&c.challenge, 64).ok_or(Refusal::Challenge)?;
    verify_slices_are_equal(&sent, challenge).map_err(|_| Refusal::Challenge)?;
    if c.origin != rp.origin {
        return Err(Refusal::Origin);
    }
    if c.cross_origin == Some(true) {
        return Err(Refusal::CrossOrigin);
    }
    Ok(())
}

/// The fixed part of authenticator data (§6.1), and the attested credential id when
/// the AT flag is set.
struct AuthData<'a> {
    flags: u8,
    sign_count: u32,
    credential_id: Option<&'a [u8]>,
}

fn parse_auth_data<'a>(rp: &RelyingParty, b: &'a [u8]) -> Result<AuthData<'a>, Refusal> {
    if b.len() > MAX_AUTHENTICATOR_DATA {
        return Err(Refusal::Malformed);
    }
    let hash = b.get(0..32).ok_or(Refusal::AuthenticatorData)?;
    let flags = *b.get(32).ok_or(Refusal::AuthenticatorData)?;
    let count: [u8; 4] = b
        .get(33..37)
        .and_then(|c| c.try_into().ok())
        .ok_or(Refusal::AuthenticatorData)?;
    verify_slices_are_equal(hash, &rp.id_hash).map_err(|_| Refusal::RpId)?;
    if flags & FLAG_UP == 0 {
        return Err(Refusal::UserPresence);
    }
    // A credential backed up must be one that may be (§6.1 BS, BE).
    if flags & FLAG_BS != 0 && flags & FLAG_BE == 0 {
        return Err(Refusal::AuthenticatorData);
    }
    let credential_id = if flags & FLAG_AT == 0 {
        None
    } else {
        // 16 bytes of AAGUID, a 2-byte big-endian length, the credential id.
        let len: [u8; 2] = b
            .get(53..55)
            .and_then(|l| l.try_into().ok())
            .ok_or(Refusal::AuthenticatorData)?;
        let len = usize::from(u16::from_be_bytes(len));
        if len == 0 || len > MAX_CREDENTIAL_ID {
            return Err(Refusal::AuthenticatorData);
        }
        let end = 55usize.checked_add(len).ok_or(Refusal::AuthenticatorData)?;
        Some(b.get(55..end).ok_or(Refusal::AuthenticatorData)?)
    };
    Ok(AuthData {
        flags,
        sign_count: u32::from_be_bytes(count),
        credential_id,
    })
}

fn algorithm(alg: i32) -> Result<&'static dyn VerificationAlgorithm, Refusal> {
    match alg {
        ES256 => Ok(&ECDSA_P256_SHA256_ASN1),
        EDDSA => Ok(&ED25519),
        RS256 => Ok(&RSA_PKCS1_2048_8192_SHA256),
        _ => Err(Refusal::Algorithm),
    }
}

/// A registration response, as the browser's `PublicKeyCredential` gives it (decoded).
#[derive(Debug, Clone, Copy)]
pub struct Registration<'a> {
    /// `rawId`.
    pub credential_id: &'a [u8],
    /// `response.clientDataJSON`.
    pub client_data_json: &'a [u8],
    /// `response.getAuthenticatorData()`.
    pub authenticator_data: &'a [u8],
    /// `response.getPublicKey()`: SubjectPublicKeyInfo DER.
    pub public_key: &'a [u8],
    /// `response.getPublicKeyAlgorithm()`.
    pub algorithm: i32,
}

/// A credential that passed [`verify_registration`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registered {
    /// The credential id.
    pub credential_id: Vec<u8>,
    /// The public key, SubjectPublicKeyInfo DER.
    pub public_key: Vec<u8>,
    /// The COSE algorithm.
    pub algorithm: i32,
    /// The signature counter at registration.
    pub sign_count: u32,
    /// The authenticator verified the user (PIN, biometrics).
    pub user_verified: bool,
    /// The credential may be backed up (a synced passkey).
    pub backup_eligible: bool,
}

/// Verify a registration (§7.1) against the `challenge` this server issued.
///
/// # Errors
///
/// The first check that failed.
pub fn verify_registration(
    rp: &RelyingParty,
    challenge: &[u8],
    r: &Registration<'_>,
) -> Result<Registered, Refusal> {
    if r.credential_id.is_empty() || r.credential_id.len() > MAX_CREDENTIAL_ID {
        return Err(Refusal::Malformed);
    }
    if r.public_key.len() > MAX_PUBLIC_KEY {
        return Err(Refusal::Malformed);
    }
    check_client_data(rp, r.client_data_json, "webauthn.create", challenge)?;
    let a = parse_auth_data(rp, r.authenticator_data)?;
    let attested = a.credential_id.ok_or(Refusal::Credential)?;
    verify_slices_are_equal(attested, r.credential_id).map_err(|_| Refusal::Credential)?;
    let alg = algorithm(r.algorithm)?;
    ParsedPublicKey::new(alg, r.public_key).map_err(|_| Refusal::PublicKey)?;
    Ok(Registered {
        credential_id: r.credential_id.to_vec(),
        public_key: r.public_key.to_vec(),
        algorithm: r.algorithm,
        sign_count: a.sign_count,
        user_verified: a.flags & FLAG_UV != 0,
        backup_eligible: a.flags & FLAG_BE != 0,
    })
}

/// An authentication response, as the browser's `PublicKeyCredential` gives it
/// (decoded).
#[derive(Debug, Clone, Copy)]
pub struct Assertion<'a> {
    /// `response.clientDataJSON`.
    pub client_data_json: &'a [u8],
    /// `response.authenticatorData`.
    pub authenticator_data: &'a [u8],
    /// `response.signature`.
    pub signature: &'a [u8],
    /// `response.userHandle`, when the authenticator gave one.
    pub user_handle: Option<&'a [u8]>,
}

/// What a verified assertion reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Asserted {
    /// The signature counter (the caller refuses one that did not move: a clone).
    pub sign_count: u32,
    /// The authenticator verified the user.
    pub user_verified: bool,
}

/// Verify an assertion (§7.2) by the stored credential `public_key` (SubjectPublicKeyInfo
/// DER) and `algorithm`, against the `challenge` this server issued, for the user whose
/// handle is `user_handle`.
///
/// # Errors
///
/// The first check that failed.
pub fn verify_assertion(
    rp: &RelyingParty,
    challenge: &[u8],
    public_key: &[u8],
    alg: i32,
    user_handle: &[u8],
    a: &Assertion<'_>,
) -> Result<Asserted, Refusal> {
    if a.signature.len() > MAX_SIGNATURE {
        return Err(Refusal::Malformed);
    }
    if let Some(h) = a.user_handle {
        verify_slices_are_equal(h, user_handle).map_err(|_| Refusal::UserHandle)?;
    }
    check_client_data(rp, a.client_data_json, "webauthn.get", challenge)?;
    let d = parse_auth_data(rp, a.authenticator_data)?;
    let alg = algorithm(alg)?;
    let mut signed = Vec::with_capacity(a.authenticator_data.len().saturating_add(32));
    signed.extend_from_slice(a.authenticator_data);
    signed.extend_from_slice(&sha256(a.client_data_json));
    UnparsedPublicKey::new(alg, public_key)
        .verify(&signed, a.signature)
        .map_err(|_| Refusal::Signature)?;
    Ok(Asserted {
        sign_count: d.sign_count,
        user_verified: d.flags & FLAG_UV != 0,
    })
}

#[cfg(test)]
// Tests may unwrap and index (CLAUDE.md).
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use aws_lc_rs::encoding::AsDer;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{
        ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair,
    };
    use serde_json::json;

    /// A software authenticator: one ES256 or Ed25519 credential.
    enum Key {
        Ec(EcdsaKeyPair),
        Ed(Ed25519KeyPair),
    }

    struct Soft {
        key: Key,
        id: Vec<u8>,
        count: u32,
    }

    impl Soft {
        fn es256() -> Self {
            let key = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).unwrap();
            Self {
                key: Key::Ec(key),
                id: vec![9; 16],
                count: 0,
            }
        }
        fn ed25519() -> Self {
            Self {
                key: Key::Ed(Ed25519KeyPair::generate().unwrap()),
                id: vec![8; 32],
                count: 0,
            }
        }
        fn spki(&self) -> Vec<u8> {
            match &self.key {
                Key::Ec(k) => k.public_key().as_der().unwrap().as_ref().to_vec(),
                Key::Ed(k) => k.public_key().as_der().unwrap().as_ref().to_vec(),
            }
        }
        fn alg(&self) -> i32 {
            match self.key {
                Key::Ec(_) => ES256,
                Key::Ed(_) => EDDSA,
            }
        }
        fn auth_data(&self, rp_id: &str, flags: u8, attested: bool) -> Vec<u8> {
            let mut d = sha256(rp_id.as_bytes()).to_vec();
            d.push(flags | if attested { FLAG_AT } else { 0 });
            d.extend_from_slice(&self.count.to_be_bytes());
            if attested {
                d.extend_from_slice(&[0; 16]);
                d.extend_from_slice(&u16::try_from(self.id.len()).unwrap().to_be_bytes());
                d.extend_from_slice(&self.id);
                // The COSE key would follow; the server reads `getPublicKey()` instead.
                d.extend_from_slice(&[0xa0]);
            }
            d
        }
        fn sign(&self, msg: &[u8]) -> Vec<u8> {
            match &self.key {
                Key::Ec(k) => k.sign(&SystemRandom::new(), msg).unwrap().as_ref().to_vec(),
                Key::Ed(k) => k.sign(msg).as_ref().to_vec(),
            }
        }
    }

    fn client_data(ty: &str, challenge: &[u8], origin: &str) -> Vec<u8> {
        serde_json::to_vec(&json!({"type": ty, "challenge": b64(challenge), "origin": origin, "crossOrigin": false})).unwrap()
    }

    fn rp() -> RelyingParty {
        RelyingParty::from_public_url("https://sign.example.test", None).unwrap()
    }

    #[test]
    fn the_relying_party_comes_from_the_public_url() {
        let r = RelyingParty::from_public_url("https://Sign.Example.test/app", None).unwrap();
        assert_eq!(
            (r.id(), r.origin()),
            ("sign.example.test", "https://sign.example.test")
        );
        let r = RelyingParty::from_public_url("http://localhost:8080", None).unwrap();
        assert_eq!((r.id(), r.origin()), ("localhost", "http://localhost:8080"));
        let r = RelyingParty::from_public_url("https://sign.example.test", Some("example.test"))
            .unwrap();
        assert_eq!(r.id(), "example.test");
        // Not a parent domain, an IP address, another scheme: none.
        assert!(
            RelyingParty::from_public_url("https://sign.example.test", Some("le.test")).is_none()
        );
        assert!(
            RelyingParty::from_public_url("https://sign.example.test", Some("other.test"))
                .is_none()
        );
        assert!(RelyingParty::from_public_url("http://127.0.0.1:8080", None).is_none());
        assert!(RelyingParty::from_public_url("http://[::1]:8080", None).is_none());
        assert!(RelyingParty::from_public_url("ftp://sign.example.test", None).is_none());
    }

    fn register(rp: &RelyingParty, soft: &Soft, challenge: &[u8]) -> Result<Registered, Refusal> {
        let cd = client_data("webauthn.create", challenge, rp.origin());
        let ad = soft.auth_data(rp.id(), FLAG_UP | FLAG_UV, true);
        let spki = soft.spki();
        verify_registration(
            rp,
            challenge,
            &Registration {
                credential_id: &soft.id,
                client_data_json: &cd,
                authenticator_data: &ad,
                public_key: &spki,
                algorithm: soft.alg(),
            },
        )
    }

    #[test]
    fn a_software_authenticator_registers_and_signs_in_with_es256_and_ed25519() {
        let rp = rp();
        for mut soft in [Soft::es256(), Soft::ed25519()] {
            let reg = register(&rp, &soft, &[1; 32]).unwrap();
            assert_eq!(reg.credential_id, soft.id);
            assert!(reg.user_verified && !reg.backup_eligible);
            soft.count = 7;
            let cd = client_data("webauthn.get", &[2; 32], rp.origin());
            let ad = soft.auth_data(rp.id(), FLAG_UP, false);
            let mut msg = ad.clone();
            msg.extend_from_slice(&sha256(&cd));
            let sig = soft.sign(&msg);
            let ok = |cd: &[u8], ad: &[u8], sig: &[u8], challenge: &[u8]| {
                verify_assertion(
                    &rp,
                    challenge,
                    &reg.public_key,
                    reg.algorithm,
                    b"user",
                    &Assertion {
                        client_data_json: cd,
                        authenticator_data: ad,
                        signature: sig,
                        user_handle: Some(b"user"),
                    },
                )
            };
            assert_eq!(ok(&cd, &ad, &sig, &[2; 32]).unwrap().sign_count, 7);
            // Another challenge, a changed byte of either signed part, a bad signature.
            assert_eq!(ok(&cd, &ad, &sig, &[3; 32]), Err(Refusal::Challenge));
            let mut ad2 = ad.clone();
            ad2[36] ^= 1;
            assert_eq!(ok(&cd, &ad2, &sig, &[2; 32]), Err(Refusal::Signature));
            let mut sig2 = sig.clone();
            let last = sig2.len() - 1;
            sig2[last] ^= 1;
            assert_eq!(ok(&cd, &ad, &sig2, &[2; 32]), Err(Refusal::Signature));
            // The registration's type in an assertion.
            let cd2 = client_data("webauthn.create", &[2; 32], rp.origin());
            assert_eq!(ok(&cd2, &ad, &sig, &[2; 32]), Err(Refusal::Type));
        }
    }

    #[test]
    fn a_registration_from_another_origin_rp_or_challenge_is_refused() {
        let rp = rp();
        let soft = Soft::es256();
        let spki = soft.spki();
        let try_with = |cd: Vec<u8>, ad: Vec<u8>, id: &[u8], alg: i32| {
            verify_registration(
                &rp,
                &[1; 32],
                &Registration {
                    credential_id: id,
                    client_data_json: &cd,
                    authenticator_data: &ad,
                    public_key: &spki,
                    algorithm: alg,
                },
            )
        };
        let good_ad = || soft.auth_data(rp.id(), FLAG_UP, true);
        let cd = |ty: &str, ch: &[u8], origin: &str| client_data(ty, ch, origin);
        let o = rp.origin().to_owned();
        assert!(
            try_with(
                cd("webauthn.create", &[1; 32], &o),
                good_ad(),
                &soft.id,
                ES256
            )
            .is_ok()
        );
        assert_eq!(
            try_with(
                cd("webauthn.create", &[1; 32], "https://evil.test"),
                good_ad(),
                &soft.id,
                ES256
            ),
            Err(Refusal::Origin)
        );
        assert_eq!(
            try_with(
                cd("webauthn.create", &[0; 32], &o),
                good_ad(),
                &soft.id,
                ES256
            ),
            Err(Refusal::Challenge)
        );
        assert_eq!(
            try_with(cd("webauthn.get", &[1; 32], &o), good_ad(), &soft.id, ES256),
            Err(Refusal::Type)
        );
        assert_eq!(
            try_with(
                cd("webauthn.create", &[1; 32], &o),
                soft.auth_data("evil.test", FLAG_UP, true),
                &soft.id,
                ES256
            ),
            Err(Refusal::RpId)
        );
        assert_eq!(
            try_with(
                cd("webauthn.create", &[1; 32], &o),
                soft.auth_data(rp.id(), 0, true),
                &soft.id,
                ES256
            ),
            Err(Refusal::UserPresence)
        );
        assert_eq!(
            try_with(
                cd("webauthn.create", &[1; 32], &o),
                soft.auth_data(rp.id(), FLAG_UP, false),
                &soft.id,
                ES256
            ),
            Err(Refusal::Credential)
        );
        assert_eq!(
            try_with(
                cd("webauthn.create", &[1; 32], &o),
                good_ad(),
                &[1, 2, 3],
                ES256
            ),
            Err(Refusal::Credential)
        );
        // The key is P-256: neither another algorithm nor an unknown one.
        assert_eq!(
            try_with(
                cd("webauthn.create", &[1; 32], &o),
                good_ad(),
                &soft.id,
                EDDSA
            ),
            Err(Refusal::PublicKey)
        );
        assert_eq!(
            try_with(
                cd("webauthn.create", &[1; 32], &o),
                good_ad(),
                &soft.id,
                -35
            ),
            Err(Refusal::Algorithm)
        );
        // Cross-origin frames, and client data that is not the object.
        let cross = serde_json::to_vec(&json!({"type": "webauthn.create", "challenge": b64(&[1; 32]), "origin": o, "crossOrigin": true})).unwrap();
        assert_eq!(
            try_with(cross, good_ad(), &soft.id, ES256),
            Err(Refusal::CrossOrigin)
        );
        assert_eq!(
            try_with(b"[]".to_vec(), good_ad(), &soft.id, ES256),
            Err(Refusal::ClientData)
        );
    }

    #[test]
    fn hostile_authenticator_data_is_refused_without_a_panic() {
        let rp = rp();
        let soft = Soft::es256();
        let good = soft.auth_data(rp.id(), FLAG_UP, true);
        // Every truncation, and a length that runs past the end.
        for n in 0..good.len() - 1 {
            assert!(
                parse_auth_data(&rp, &good[..n]).is_err() || n >= 55 + soft.id.len(),
                "{n}"
            );
        }
        let mut long = good.clone();
        long[53] = 0xff;
        long[54] = 0xff;
        assert_eq!(
            parse_auth_data(&rp, &long).err(),
            Some(Refusal::AuthenticatorData)
        );
        let mut zero = good.clone();
        zero[53] = 0;
        zero[54] = 0;
        assert_eq!(
            parse_auth_data(&rp, &zero).err(),
            Some(Refusal::AuthenticatorData)
        );
        // Backed up but not backup eligible.
        let bs = soft.auth_data(rp.id(), FLAG_UP | FLAG_BS, false);
        assert_eq!(
            parse_auth_data(&rp, &bs).err(),
            Some(Refusal::AuthenticatorData)
        );
        assert_eq!(
            parse_auth_data(&rp, &vec![0; MAX_AUTHENTICATOR_DATA + 1]).err(),
            Some(Refusal::Malformed)
        );
        // Base64url beyond its bound is refused before decoding.
        assert!(unb64(&"A".repeat(10_000), 64).is_none());
        assert_eq!(unb64(&b64(&[1, 2, 3]), 3), Some(vec![1, 2, 3]));
        assert_eq!(unb64("AQID==", 3), Some(vec![1, 2, 3]));
        assert!(unb64("not base64!", 64).is_none());
    }
}
