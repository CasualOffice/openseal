//! Recipient sign-in through an OpenID Connect provider (`sso`, slice 5, row RAUTH-01).
//!
//! The operator lists the providers a signer may sign in with in a JSON file named by
//! `OPENSEAL_RECIPIENT_IDPS_FILE` (docs/65): for each, an id and a display name, the
//! issuer, its authorization, token and JWKS endpoints, and the client registered there.
//! A sender requires `sso` of a recipient; the signer picks one of these providers on the
//! signing page and signs in there (authorization code flow with PKCE S256, `state` and
//! `nonce`; OpenID Connect Core §3.1). The ID token passes only when it is signed by a key
//! in the provider's JWKS with an asymmetric algorithm, names the provider's issuer and
//! the client as audience, has not expired by the server's clock, carries the nonce of the
//! sign-in it answers, and asserts a verified email equal to the recipient's. The audit
//! chain then records the issuer and the SHA-256 of the subject, never the subject itself
//! or the token.
//!
//! **Why bind by email.** Any account at a trusted provider can sign in; what makes the
//! sign-in authenticate *this* recipient is the provider's statement that the account's
//! verified email is the one the sender addressed.
//!
//! **Network.** Endpoints come from the operator's file, never from a request, so this is
//! not a server-side request forgery path; they must be HTTPS, except `http` to a loopback
//! address for a provider on the same host. No redirect is followed.
//!
//! **Personal data (`SEC-D01`).** The email and subject in an ID token are personal data:
//! nothing here logs them, and refusals carry no claim values.

use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use casual_sign_audit::{Hash256, SignInIdentity};
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use serde::Deserialize;
use serde_json::{Value, json};
use time::OffsetDateTime;

use crate::crypto::sha256;
use crate::error::ApiError;

/// The longest response read from a provider (a token response or a JWKS).
const MAX_RESPONSE: u64 = 256 * 1024;

/// The most providers one server lists.
const MAX_PROVIDERS: usize = 32;

/// The signature algorithms an ID token may use: asymmetric only, so a token can never be
/// forged with the client secret (`HS256`) or left unsigned (`none`).
const ALGORITHMS: &[Algorithm] = &[
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::EdDSA,
];

/// Why the configuration file was refused, naming the provider's position and member,
/// never a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdpConfigError {
    /// The provider's index in `providers`, when the fault is in one.
    pub index: Option<usize>,
    /// The member at fault.
    pub member: &'static str,
}

impl core::fmt::Display for IdpConfigError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self.index {
            Some(i) => write!(
                f,
                "recipient identity providers: providers[{i}].{}",
                self.member
            ),
            None => write!(f, "recipient identity providers: {}", self.member),
        }
    }
}

impl std::error::Error for IdpConfigError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileIn {
    providers: Vec<ProviderIn>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderIn {
    id: String,
    name: String,
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    client_id: String,
    client_secret: String,
    #[serde(default)]
    redirect_uri: Option<String>,
}

/// One provider a signer may sign in with.
pub(crate) struct Provider {
    pub(crate) id: String,
    name: String,
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    client_id: String,
    client_secret: casual_sign_secrets::Secret,
    redirect_uri: String,
}

impl core::fmt::Debug for Provider {
    /// The id only: never the client secret.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Provider")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// The providers recipients may sign in with, and the HTTP client that reaches them.
pub struct RecipientIdps {
    providers: Vec<Provider>,
    agent: ureq::Agent,
}

impl core::fmt::Debug for RecipientIdps {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RecipientIdps")
            .field("providers", &self.providers)
            .finish_non_exhaustive()
    }
}

/// Whether `url` is one this server will call or send a browser to: HTTPS, or HTTP to a
/// loopback address.
fn endpoint(url: &str) -> bool {
    if url.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    if let Some(rest) = url.strip_prefix("https://") {
        return !rest.is_empty() && !rest.starts_with('/');
    }
    let Some(rest) = url.strip_prefix("http://") else {
        return false;
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = host.rsplit_once(':').map_or(host, |(h, _)| h);
    matches!(host, "127.0.0.1" | "[::1]" | "localhost")
}

impl RecipientIdps {
    /// The providers in `json` (the file's bytes), with `public_url` (no trailing slash)
    /// giving each provider's default redirect URI, `{public_url}/s/oidc`.
    ///
    /// # Errors
    ///
    /// [`IdpConfigError`] naming the member that is missing, malformed, duplicated or not
    /// an HTTPS endpoint.
    pub fn from_json(json: &[u8], public_url: &str) -> Result<Self, IdpConfigError> {
        let file: FileIn = serde_json::from_slice(json).map_err(|_| IdpConfigError {
            index: None,
            member: "file (not the expected JSON)",
        })?;
        if file.providers.len() > MAX_PROVIDERS {
            return Err(IdpConfigError {
                index: None,
                member: "providers (more than 32)",
            });
        }
        let mut providers = Vec::with_capacity(file.providers.len());
        for (i, p) in file.providers.into_iter().enumerate() {
            let bad = |member| IdpConfigError {
                index: Some(i),
                member,
            };
            if p.id.is_empty()
                || p.id.len() > 32
                || !p
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            {
                return Err(bad("id"));
            }
            if providers.iter().any(|q: &Provider| q.id == p.id) {
                return Err(bad("id (duplicate)"));
            }
            if p.name.trim().is_empty() || p.name.chars().count() > 64 {
                return Err(bad("name"));
            }
            if p.issuer.is_empty() || p.issuer.len() > 512 {
                return Err(bad("issuer"));
            }
            if p.client_id.is_empty() || p.client_secret.is_empty() {
                return Err(bad("client_id or client_secret"));
            }
            let redirect_uri = p
                .redirect_uri
                .unwrap_or_else(|| format!("{public_url}/s/oidc"));
            for (member, url) in [
                ("authorization_endpoint", &p.authorization_endpoint),
                ("token_endpoint", &p.token_endpoint),
                ("jwks_uri", &p.jwks_uri),
                ("redirect_uri", &redirect_uri),
            ] {
                if !endpoint(url) || url.len() > 2048 {
                    return Err(bad(member));
                }
            }
            providers.push(Provider {
                id: p.id,
                name: p.name.trim().to_owned(),
                issuer: p.issuer,
                authorization_endpoint: p.authorization_endpoint,
                token_endpoint: p.token_endpoint,
                jwks_uri: p.jwks_uri,
                client_id: p.client_id,
                client_secret: casual_sign_secrets::Secret::new(p.client_secret),
                redirect_uri,
            });
        }
        Ok(Self {
            providers,
            agent: agent(),
        })
    }

    /// The provider with `id`.
    pub(crate) fn get(&self, id: &str) -> Option<&Provider> {
        self.providers.iter().find(|p| p.id == id)
    }

    /// What the signing page shows: each provider's id and name.
    pub(crate) fn listing(&self) -> Value {
        Value::Array(
            self.providers
                .iter()
                .map(|p| json!({"id": p.id, "name": p.name}))
                .collect(),
        )
    }

    /// Exchange `code` at `p`'s token endpoint with the PKCE `verifier`, answering the ID
    /// token. Blocking: the caller runs it on the blocking pool.
    pub(crate) fn exchange(
        &self,
        p: &Provider,
        code: &str,
        verifier: &str,
    ) -> Result<Exchange, ApiError> {
        let body = form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &p.redirect_uri),
            ("client_id", &p.client_id),
            ("client_secret", p.client_secret.expose()),
            ("code_verifier", verifier),
        ]);
        let mut answer = self
            .agent
            .post(&p.token_endpoint)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .header("Accept", "application/json")
            .send(body.as_bytes())
            .map_err(|_| ApiError::idp_unavailable())?;
        let status = answer.status().as_u16();
        // RFC 6749 §5.2: a refused grant (a wrong, used or expired code) is a 400 or 401;
        // that is the signer's failure, counted like a wrong code.
        if status == 400 || status == 401 {
            return Ok(Exchange::Refused);
        }
        if status != 200 {
            return Err(ApiError::idp_unavailable());
        }
        let v: Value = read_json(&mut answer)?;
        match v.get("id_token").and_then(Value::as_str) {
            Some(t) => Ok(Exchange::IdToken(t.to_owned())),
            None => Err(ApiError::idp_unavailable()),
        }
    }

    /// `p`'s current JWKS. Blocking.
    pub(crate) fn jwks(&self, p: &Provider) -> Result<JwkSet, ApiError> {
        let mut answer = self
            .agent
            .get(&p.jwks_uri)
            .header("Accept", "application/json")
            .call()
            .map_err(|_| ApiError::idp_unavailable())?;
        if answer.status().as_u16() != 200 {
            return Err(ApiError::idp_unavailable());
        }
        read_json(&mut answer)
    }
}

/// A provider's JSON answer, at most [`MAX_RESPONSE`] bytes.
fn read_json<T: serde::de::DeserializeOwned>(
    answer: &mut ureq::http::Response<ureq::Body>,
) -> Result<T, ApiError> {
    let bytes = answer
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE)
        .read_to_vec()
        .map_err(|_| ApiError::idp_unavailable())?;
    serde_json::from_slice(&bytes).map_err(|_| ApiError::idp_unavailable())
}

/// What the token endpoint answered.
pub(crate) enum Exchange {
    /// An ID token, still to be checked.
    IdToken(String),
    /// The provider refused the code.
    Refused,
}

fn agent() -> ureq::Agent {
    let native = rustls_native_certs::load_native_certs();
    let roots: Vec<ureq::tls::Certificate<'static>> = native
        .certs
        .iter()
        .map(|c| ureq::tls::Certificate::from_der(c.as_ref()).to_owned())
        .collect();
    let tls = ureq::tls::TlsConfig::builder()
        .provider(ureq::tls::TlsProvider::Rustls)
        .root_certs(ureq::tls::RootCerts::new_with_certs(&roots))
        .unversioned_rustls_crypto_provider(Arc::new(rustls::crypto::aws_lc_rs::default_provider()))
        .build();
    ureq::Agent::config_builder()
        .tls_config(tls)
        .timeout_global(Some(Duration::from_secs(10)))
        .max_redirects(0)
        .http_status_as_error(false)
        .user_agent("openseal-server")
        .build()
        .into()
}

/// `application/x-www-form-urlencoded` (and query) encoding: every byte but the
/// unreserved set of RFC 3986 §2.3 percent-encoded.
fn encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn form(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(k, v)| format!("{}={}", encode(k), encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// The PKCE S256 challenge of `verifier` (RFC 7636 §4.2).
pub(crate) fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(sha256(verifier.as_bytes()))
}

/// Where to send the browser: `p`'s authorization endpoint with the request of
/// OpenID Connect Core §3.1.2.1.
pub(crate) fn authorization_url(p: &Provider, state: &str, nonce: &str, verifier: &str) -> String {
    let sep = if p.authorization_endpoint.contains('?') {
        '&'
    } else {
        '?'
    };
    format!(
        "{}{sep}{}",
        p.authorization_endpoint,
        form(&[
            ("response_type", "code"),
            ("client_id", &p.client_id),
            ("redirect_uri", &p.redirect_uri),
            ("scope", "openid email"),
            ("state", state),
            ("nonce", nonce),
            ("code_challenge", &challenge(verifier)),
            ("code_challenge_method", "S256"),
        ])
    )
}

#[derive(Deserialize)]
struct IdClaims {
    iss: String,
    sub: String,
    exp: i64,
    #[serde(default)]
    iat: Option<i64>,
    #[serde(default)]
    nonce: Option<String>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    email_verified: Option<Value>,
}

/// How far a provider's clock may be ahead of or behind ours.
const SKEW_SECS: i64 = 120;

/// Check `token` from `p` for the sign-in with `nonce`, for the recipient addressed at
/// `email`, at `now`: the identity it proves, or `None` when it does not pass. Every check
/// of the module comment; the reason for a refusal is not told to the caller, as for a
/// wrong code.
pub(crate) fn verify(
    p: &Provider,
    jwks: &JwkSet,
    token: &str,
    nonce: &str,
    email: &str,
    now: OffsetDateTime,
) -> Option<SignInIdentity> {
    let header = jsonwebtoken::decode_header(token).ok()?;
    if !ALGORITHMS.contains(&header.alg) {
        return None;
    }
    let jwk = match &header.kid {
        Some(kid) => jwks.find(kid)?,
        None => match jwks.keys.as_slice() {
            [only] => only,
            _ => return None,
        },
    };
    let key = DecodingKey::from_jwk(jwk).ok()?;
    let mut v = Validation::new(header.alg);
    // Expiry against the server's clock, below, not the system's.
    v.validate_exp = false;
    v.validate_nbf = false;
    v.required_spec_claims.clear();
    v.set_issuer(&[p.issuer.as_str()]);
    v.set_audience(&[p.client_id.as_str()]);
    let claims = jsonwebtoken::decode::<IdClaims>(token, &key, &v)
        .ok()?
        .claims;
    let now = now.unix_timestamp();
    if claims.exp.saturating_add(SKEW_SECS) <= now {
        return None;
    }
    if claims
        .iat
        .is_some_and(|iat| iat > now.saturating_add(SKEW_SECS))
    {
        return None;
    }
    let nonce_ok = claims
        .nonce
        .as_deref()
        .is_some_and(|n| crate::crypto::same(&sha256(n.as_bytes()), &sha256(nonce.as_bytes())));
    if !nonce_ok || claims.iss != p.issuer || claims.sub.is_empty() {
        return None;
    }
    // A verified email equal to the recipient's (some providers send the flag as a
    // string).
    let verified = matches!(claims.email_verified, Some(Value::Bool(true)))
        || matches!(&claims.email_verified, Some(Value::String(s)) if s == "true");
    let same_email = claims
        .email
        .as_deref()
        .is_some_and(|e| !email.is_empty() && e.trim().eq_ignore_ascii_case(email.trim()));
    if !verified || !same_email {
        return None;
    }
    Some(SignInIdentity {
        issuer: claims.iss,
        subject_sha256: Hash256(sha256(claims.sub.as_bytes())),
    })
}

#[cfg(test)]
// Tests may unwrap, index and panic (CLAUDE.md).
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn file(extra: &str) -> String {
        format!(
            r#"{{"providers": [{{"id": "corp", "name": "Example Corp", "issuer": "https://idp.example.test",
            "authorization_endpoint": "https://idp.example.test/authorize",
            "token_endpoint": "https://idp.example.test/token",
            "jwks_uri": "https://idp.example.test/jwks", "client_id": "openseal",
            "client_secret": "s3cret"{extra}}}]}}"#
        )
    }

    #[test]
    fn a_provider_file_is_read_and_its_secret_never_shown() {
        let idps =
            RecipientIdps::from_json(file("").as_bytes(), "https://sign.example.test").unwrap();
        let p = idps.get("corp").unwrap();
        assert_eq!(p.redirect_uri, "https://sign.example.test/s/oidc");
        assert!(!format!("{idps:?}").contains("s3cret"));
        assert_eq!(
            idps.listing(),
            json!([{"id": "corp", "name": "Example Corp"}])
        );
    }

    #[test]
    fn endpoints_must_be_https_or_loopback() {
        for bad in [
            r#", "redirect_uri": "http://sign.example.test/s/oidc""#,
            r#", "redirect_uri": "javascript:alert(1)""#,
            r#", "redirect_uri": "https:///x""#,
        ] {
            let e = RecipientIdps::from_json(file(bad).as_bytes(), "https://s").unwrap_err();
            assert_eq!(e.member, "redirect_uri", "{bad}");
        }
        assert!(endpoint("http://127.0.0.1:5000/token"));
        assert!(endpoint("http://localhost/token"));
        assert!(!endpoint("http://127.0.0.1.example.test/token"));
    }

    #[test]
    fn the_authorization_request_carries_state_nonce_and_an_s256_challenge() {
        let idps = RecipientIdps::from_json(file("").as_bytes(), "https://s.test").unwrap();
        let u = authorization_url(idps.get("corp").unwrap(), "st", "nn", "verifier");
        assert!(
            u.starts_with("https://idp.example.test/authorize?response_type=code&"),
            "{u}"
        );
        assert!(u.contains("&state=st&nonce=nn&"), "{u}");
        assert!(
            u.contains("redirect_uri=https%3A%2F%2Fs.test%2Fs%2Foidc"),
            "{u}"
        );
        assert!(
            u.contains(&format!("code_challenge={}&", challenge("verifier"))),
            "{u}"
        );
        assert!(u.ends_with("code_challenge_method=S256"), "{u}");
        // RFC 7636 appendix B.
        assert_eq!(
            challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }
}
