//! Secrets the server mints and checks: random tokens, their SHA-256, Argon2id password
//! and access-code hashes, and ES256 access tokens. Primitives come from `aws-lc-rs`
//! and RustCrypto's `argon2` (ADR-006, CLAUDE.md: cryptography is never hand-rolled).

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use aws_lc_rs::signature::{ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use casual_sign_audit::Hash256;
use jsonwebtoken::{Algorithm as JwtAlg, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;

/// `n` random bytes from the operating system.
pub(crate) fn random_bytes<const N: usize>() -> Result<[u8; N], ApiError> {
    let mut out = [0u8; N];
    SystemRandom::new()
        .fill(&mut out)
        .map_err(|_| ApiError::internal("random"))?;
    Ok(out)
}

/// A 256-bit random secret as base64url text (43 characters).
pub(crate) fn random_secret() -> Result<String, ApiError> {
    Ok(URL_SAFE_NO_PAD.encode(random_bytes::<32>()?))
}

/// SHA-256 of a secret's text, the only form in which secrets are stored.
pub(crate) fn sha256(text: &[u8]) -> [u8; 32] {
    *Hash256::digest(text).as_bytes()
}

/// Constant-time equality of two hashes.
pub(crate) fn same(a: &[u8; 32], b: &[u8; 32]) -> bool {
    // Constant-time from aws-lc-rs (ADR-006), never a hand-rolled loop (CLAUDE.md, ASVS-12).
    aws_lc_rs::constant_time::verify_slices_are_equal(a, b).is_ok()
}

/// Argon2id with OWASP's second recommended configuration (19 MiB, 2 passes, 1 lane).
fn argon() -> Result<Argon2<'static>, ApiError> {
    let params = Params::new(19 * 1024, 2, 1, None).map_err(|_| ApiError::internal("argon2"))?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

/// The Argon2id PHC string of a password or access code, with a fresh random salt.
pub(crate) fn hash_password(secret: &str) -> Result<String, ApiError> {
    let salt_bytes = random_bytes::<16>()?;
    let salt = SaltString::encode_b64(&salt_bytes).map_err(|_| ApiError::internal("salt"))?;
    argon()?
        .hash_password(secret.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|_| ApiError::internal("argon2"))
}

/// Whether `secret` matches the PHC string. A malformed stored string never matches.
pub(crate) fn verify_password(secret: &str, phc: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(phc) else {
        return false;
    };
    argon().is_ok_and(|a| a.verify_password(secret.as_bytes(), &parsed).is_ok())
}

/// A PHC string no password matches (a random secret's, thrown away), verified
/// against when the login is unknown so that a login takes the same time whether or not
/// the email exists (SEC-A09).
pub(crate) fn dummy_phc() -> Result<String, ApiError> {
    hash_password(&random_secret()?)
}

/// The claims of an OAuth 2.1 client-credentials access token (docs/40 §2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Claims {
    /// The issuer: this server's configured URL.
    pub iss: String,
    /// The API client's id.
    pub sub: String,
    /// The account.
    pub acct: String,
    /// The audience: always `openseal-api`.
    pub aud: String,
    /// Space-separated scopes granted.
    pub scope: String,
    /// Issued at, Unix seconds.
    pub iat: i64,
    /// Expiry, Unix seconds.
    pub exp: i64,
    /// Token id.
    pub jti: String,
}

/// The audience every access token carries.
pub(crate) const AUDIENCE: &str = "openseal-api";

/// The ES256 key that signs access tokens, and its public half for JWKS; during a
/// rotation also the previous keys' public halves, so tokens they signed keep verifying
/// until they expire (`HRD-06`, docs/65 §Rotation).
pub struct JwtKeys {
    encoding: EncodingKey,
    current: PublicJwk,
    previous: Vec<PublicJwk>,
}

/// One verifying key, by its `kid`.
struct PublicJwk {
    decoding: DecodingKey,
    kid: String,
    x: String,
    y: String,
}

impl PublicJwk {
    fn json(&self) -> serde_json::Value {
        serde_json::json!({
            "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig",
            "kid": self.kid, "x": self.x, "y": self.y
        })
    }
}

/// The public half of a P-256 PKCS#8 private key.
fn public_jwk(der: &[u8]) -> Result<PublicJwk, ApiError> {
    let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, der)
        .map_err(|_| ApiError::internal("jwt key"))?;
    let point = pair.public_key().as_ref();
    // Uncompressed SEC1 point: 0x04, x (32 bytes), y (32 bytes).
    let (Some(x), Some(y)) = (point.get(1..33), point.get(33..65)) else {
        return Err(ApiError::internal("jwt key"));
    };
    let x = URL_SAFE_NO_PAD.encode(x);
    let y = URL_SAFE_NO_PAD.encode(y);
    let kid = Hash256::digest(point).hex().chars().take(16).collect();
    let decoding =
        DecodingKey::from_ec_components(&x, &y).map_err(|_| ApiError::internal("jwt key"))?;
    Ok(PublicJwk {
        decoding,
        kid,
        x,
        y,
    })
}

impl core::fmt::Debug for JwtKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let previous: Vec<&str> = self.previous.iter().map(|p| p.kid.as_str()).collect();
        f.debug_struct("JwtKeys")
            .field("kid", &self.current.kid)
            .field("previous", &previous)
            .finish()
    }
}

impl JwtKeys {
    /// From a PKCS#8 DER P-256 private key (from the secrets store, docs/40 §2).
    ///
    /// # Errors
    ///
    /// `CS-API-0010` when the bytes are not a P-256 PKCS#8 key.
    pub fn from_pkcs8(der: &[u8]) -> Result<Self, ApiError> {
        Ok(Self {
            current: public_jwk(der)?,
            encoding: EncodingKey::from_ec_der(der),
            previous: Vec::new(),
        })
    }

    /// Also accept tokens signed by the key `der` (a P-256 PKCS#8 private key, of which
    /// only the public half is kept) and publish it in JWKS: the key this one replaced,
    /// kept for one access-token lifetime after a rotation. The same key as the current
    /// one, or one already added, changes nothing.
    ///
    /// # Errors
    ///
    /// `CS-API-0010` when the bytes are not a P-256 PKCS#8 key.
    pub fn with_previous(mut self, der: &[u8]) -> Result<Self, ApiError> {
        let key = public_jwk(der)?;
        if key.kid != self.current.kid && self.previous.iter().all(|p| p.kid != key.kid) {
            self.previous.push(key);
        }
        Ok(self)
    }

    /// The `kid` of the signing key.
    #[must_use]
    pub fn kid(&self) -> &str {
        &self.current.kid
    }

    /// A fresh key, for development and tests only.
    ///
    /// # Errors
    ///
    /// `CS-API-0010` when key generation fails.
    pub fn generate() -> Result<Self, ApiError> {
        let doc =
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .map_err(|_| ApiError::internal("jwt key"))?;
        Self::from_pkcs8(doc.as_ref())
    }

    pub(crate) fn sign(&self, claims: &Claims) -> Result<String, ApiError> {
        let mut header = Header::new(JwtAlg::ES256);
        header.kid = Some(self.current.kid.clone());
        jsonwebtoken::encode(&header, claims, &self.encoding)
            .map_err(|_| ApiError::internal("jwt sign"))
    }

    /// The claims of a token the current or a previous key signed (chosen by the
    /// token's `kid`; none, or an unknown one, is refused), for this issuer and audience.
    /// Expiry is checked by the caller against the server's clock, not the system's.
    pub(crate) fn verify(&self, token: &str, issuer: &str) -> Option<Claims> {
        let kid = jsonwebtoken::decode_header(token).ok()?.kid?;
        let key = std::iter::once(&self.current)
            .chain(&self.previous)
            .find(|k| k.kid == kid)?;
        let mut v = Validation::new(JwtAlg::ES256);
        v.validate_exp = false;
        v.required_spec_claims.clear();
        v.set_audience(&[AUDIENCE]);
        v.set_issuer(&[issuer]);
        jsonwebtoken::decode::<Claims>(token, &key.decoding, &v)
            .ok()
            .map(|d| d.claims)
    }

    pub(crate) fn jwks(&self) -> serde_json::Value {
        let keys: Vec<serde_json::Value> = std::iter::once(&self.current)
            .chain(&self.previous)
            .map(PublicJwk::json)
            .collect();
        serde_json::json!({ "keys": keys })
    }
}

#[cfg(test)]
// Tests may unwrap, index and panic (CLAUDE.md).
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn passwords_verify_only_themselves_and_the_dummy_matches_nothing() {
        let phc = hash_password("correct horse").unwrap();
        assert!(phc.starts_with("$argon2id$"));
        assert!(verify_password("correct horse", &phc));
        assert!(!verify_password("correct horsf", &phc));
        let dummy = dummy_phc().unwrap();
        assert!(!verify_password("", &dummy));
        assert!(PasswordHash::new(&dummy).is_ok());
        assert!(!verify_password("x", "not a phc"));
    }

    #[test]
    fn tokens_verify_with_their_key_issuer_and_audience_only() {
        let k = JwtKeys::generate().unwrap();
        let c = Claims {
            iss: "https://a".into(),
            sub: "client".into(),
            acct: "acct".into(),
            aud: AUDIENCE.into(),
            scope: "envelopes:read".into(),
            iat: 0,
            exp: 10,
            jti: "j".into(),
        };
        let t = k.sign(&c).unwrap();
        assert_eq!(k.verify(&t, "https://a"), Some(c.clone()));
        assert_eq!(k.verify(&t, "https://b"), None);
        assert_eq!(JwtKeys::generate().unwrap().verify(&t, "https://a"), None);
        let mut other = c;
        other.aud = "else".into();
        assert_eq!(k.verify(&k.sign(&other).unwrap(), "https://a"), None);
        // A token with `alg: none` is refused.
        let parts: Vec<&str> = t.split('.').collect();
        let none = format!(
            "{}.{}.",
            URL_SAFE_NO_PAD.encode(br#"{"alg":"none","typ":"JWT"}"#),
            parts[1]
        );
        assert_eq!(k.verify(&none, "https://a"), None);
    }

    #[test]
    fn a_rotated_key_keeps_the_previous_keys_tokens_valid_and_drops_them_after() {
        let new_key = || {
            EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &SystemRandom::new())
                .unwrap()
                .as_ref()
                .to_vec()
        };
        let (old_der, new_der) = (new_key(), new_key());
        let c = Claims {
            iss: "https://a".into(),
            sub: "client".into(),
            acct: "acct".into(),
            aud: AUDIENCE.into(),
            scope: "envelopes:read".into(),
            iat: 0,
            exp: 10,
            jti: "j".into(),
        };
        let old = JwtKeys::from_pkcs8(&old_der).unwrap();
        let issued_before = old.sign(&c).unwrap();

        // During the overlap: the new key signs, both verify, JWKS lists both.
        let rotated = JwtKeys::from_pkcs8(&new_der)
            .unwrap()
            .with_previous(&old_der)
            .unwrap()
            .with_previous(&old_der)
            .unwrap()
            .with_previous(&new_der)
            .unwrap();
        assert_eq!(rotated.verify(&issued_before, "https://a"), Some(c.clone()));
        let issued_after = rotated.sign(&c).unwrap();
        assert_eq!(rotated.verify(&issued_after, "https://a"), Some(c.clone()));
        let kids: Vec<String> = rotated.jwks()["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| k["kid"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(kids, vec![rotated.kid().to_owned(), old.kid().to_owned()]);
        assert!(format!("{rotated:?}").contains(old.kid()));

        // After the overlap: the previous key is gone and its tokens stop verifying.
        let done = JwtKeys::from_pkcs8(&new_der).unwrap();
        assert_eq!(done.verify(&issued_before, "https://a"), None);
        assert_eq!(done.verify(&issued_after, "https://a"), Some(c));
        assert_eq!(done.jwks()["keys"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn same_compares_every_byte() {
        assert!(same(&[1; 32], &[1; 32]));
        let mut b = [1; 32];
        b[31] = 2;
        assert!(!same(&[1; 32], &b));
    }
}
