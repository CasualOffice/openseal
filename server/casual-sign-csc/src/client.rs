//! The Cloud Signature Consortium API v2.0.0.2 calls ADR-046 relies on (§2), over a
//! [`Transport`] the host supplies (the worker's HTTPS agent with its address policy,
//! `SEC-W01`; a fake in tests): the OAuth 2.0 authorization URL (scope `service`, then
//! scope `credential` binding the hashes, both with PKCE S256), the code exchange,
//! `credentials/list`, `credentials/info` and `signatures/signHash`.
//!
//! **Bounds.** An answer is read to at most [`MAX_ANSWER`] by the transport; this module
//! refuses more than [`MAX_CREDENTIALS`] credentials or [`MAX_CERTIFICATES`] certificates
//! in a chain, and a `signHash` answer with any other number of values than hashes sent
//! (`CS-RSP-0004`). **Errors.** A 5xx or a transport failure is `CS-RSP-0002`; an OAuth or
//! CSC error answer is `Refused` with the provider's code (checked to be a short token;
//! its description is never read); anything malformed is `CS-RSP-0004`. **Secrets.** The
//! client secret, tokens and codes are passed through and never kept or logged.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::catalogue::Provider;
use crate::error::CscError;

/// Largest answer read from a provider (docs/21).
pub const MAX_ANSWER: u64 = 1024 * 1024;
/// Most credentials a `credentials/list` answer may hold (docs/21).
pub const MAX_CREDENTIALS: usize = 32;
/// Most certificates in a credential's chain (docs/21).
pub const MAX_CERTIFICATES: usize = 16;

/// SHA-256's OID, the `hashAlgorithmOID` sent with SHA-256 hashes.
pub const SHA256_OID: &str = "2.16.840.1.101.3.4.2.1";
/// SHA-384's OID.
pub const SHA384_OID: &str = "2.16.840.1.101.3.4.2.2";

/// One HTTP exchange: a `POST` of `body` (`content_type`), with a bearer token when
/// given, answered with the status and at most [`MAX_ANSWER`] bytes of body. The
/// transport checks the target's addresses (`SEC-W01`), follows no redirect and times
/// out.
pub trait Transport {
    /// `POST url`.
    ///
    /// # Errors
    /// `CS-RSP-0002` when the provider cannot be reached, times out or its address is
    /// refused; `CS-RSP-0004` when the answer is larger than [`MAX_ANSWER`].
    fn post(
        &self,
        url: &str,
        content_type: &str,
        bearer: Option<&str>,
        body: &[u8],
    ) -> Result<(u16, Vec<u8>), CscError>;
}

/// The OAuth 2.0 scope asked for (CSC §8.4.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Scope<'a> {
    /// The signer logs in to the service.
    Service,
    /// The signer authorizes `hashes` (raw digests) with `credential_id`: at SCAL2 the
    /// authorization is bound to them.
    Credential {
        /// The credential.
        credential_id: &'a str,
        /// The digests to authorize, one per document.
        hashes: &'a [Vec<u8>],
        /// Their algorithm's OID.
        hash_algorithm_oid: &'a str,
    },
}

/// `application/x-www-form-urlencoded` escaping (RFC 3986 unreserved kept).
#[must_use]
pub fn form_escape(s: &str) -> String {
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
        .map(|(k, v)| format!("{}={}", form_escape(k), form_escape(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// A PKCE verifier from 32 random bytes (RFC 7636 §4.1: 43 characters of base64url).
///
/// # Errors
/// `CS-RSP-0009` when no randomness could be drawn.
pub fn pkce_verifier() -> Result<String, CscError> {
    let mut b = [0u8; 32];
    aws_lc_rs::rand::fill(&mut b).map_err(|_| CscError::SecretsKey)?;
    Ok(URL_SAFE_NO_PAD.encode(b))
}

/// The S256 challenge of `verifier` (RFC 7636 §4.2).
#[must_use]
pub fn pkce_challenge(verifier: &str) -> String {
    let d = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(d.as_ref())
}

/// Where the signer's browser goes (top-level, never in a frame): the provider's
/// authorization endpoint with `scope`, our redirect URI, the `state` bound to the
/// session and the PKCE challenge.
#[must_use]
pub fn authorization_url(p: &Provider, scope: &Scope<'_>, state: &str, challenge: &str) -> String {
    let mut pairs: Vec<(&str, String)> = vec![
        ("response_type", "code".to_owned()),
        ("client_id", p.client_id.clone()),
        ("redirect_uri", p.redirect_uri.clone()),
        ("state", state.to_owned()),
        ("code_challenge", challenge.to_owned()),
        ("code_challenge_method", "S256".to_owned()),
    ];
    match scope {
        Scope::Service => pairs.push(("scope", "service".to_owned())),
        Scope::Credential {
            credential_id,
            hashes,
            hash_algorithm_oid,
        } => {
            pairs.push(("scope", "credential".to_owned()));
            pairs.push(("credentialID", (*credential_id).to_owned()));
            pairs.push(("numSignatures", hashes.len().to_string()));
            pairs.push((
                "hashes",
                hashes
                    .iter()
                    .map(|h| URL_SAFE_NO_PAD.encode(h))
                    .collect::<Vec<_>>()
                    .join(","),
            ));
            pairs.push(("hashAlgorithmOID", (*hash_algorithm_oid).to_owned()));
        }
    }
    let query = pairs
        .iter()
        .map(|(k, v)| format!("{}={}", form_escape(k), form_escape(v)))
        .collect::<Vec<_>>()
        .join("&");
    let sep = if p.authorization_endpoint.contains('?') {
        '&'
    } else {
        '?'
    };
    format!("{}{sep}{query}", p.authorization_endpoint)
}

/// A provider's error code: a short token, or `invalid` when it is not one.
fn code_of(v: &Value) -> String {
    let c = v.get("error").and_then(Value::as_str).unwrap_or("invalid");
    if (1..=64).contains(&c.len())
        && c.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
    {
        c.to_owned()
    } else {
        "invalid".to_owned()
    }
}

/// The JSON of a 2xx answer; an error answer as `Refused` or `Unavailable`.
fn answer(status: u16, body: &[u8]) -> Result<Value, CscError> {
    if status >= 500 {
        return Err(CscError::Unavailable);
    }
    let v: Value = serde_json::from_slice(body).map_err(|_| CscError::Invalid { what: "json" })?;
    if (200..300).contains(&status) {
        Ok(v)
    } else {
        Err(CscError::Refused { code: code_of(&v) })
    }
}

/// A CSC client for one provider and its client secret (the operator's or the
/// account's own).
pub struct Client<'a> {
    provider: &'a Provider,
    client_secret: &'a str,
    transport: &'a dyn Transport,
}

impl core::fmt::Debug for Client<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Client")
            .field("provider", &self.provider.id)
            .finish_non_exhaustive()
    }
}

/// What `credentials/info` says of a credential, as checked (CSC §11.5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialInfo {
    /// The credential's id.
    pub id: String,
    /// `key/status`.
    pub key_status: String,
    /// `key/algo`: key algorithm OIDs.
    pub key_algorithms: Vec<String>,
    /// `key/len`, bits.
    pub key_len: u32,
    /// `cert/status`.
    pub cert_status: String,
    /// `cert/certificates`: the chain, signer first, DER.
    pub chain: Vec<Vec<u8>>,
    /// `SCAL` (`1` or `2`).
    pub scal: String,
    /// `multisign`: how many signatures one authorization covers.
    pub multisign: u32,
    /// `auth/mode`: `implicit`, `explicit` or `oauth2code`.
    pub auth_mode: String,
    /// `signatureQualifier`, as the provider states it.
    pub signature_qualifier: Option<String>,
}

#[derive(Deserialize)]
struct InfoIn {
    #[serde(default)]
    key: Option<KeyIn>,
    #[serde(default)]
    cert: Option<CertIn>,
    #[serde(default, rename = "SCAL")]
    scal: Option<String>,
    #[serde(default)]
    multisign: Option<u32>,
    #[serde(default)]
    auth: Option<AuthIn>,
    #[serde(default, rename = "signatureQualifier")]
    signature_qualifier: Option<String>,
}

#[derive(Deserialize)]
struct KeyIn {
    #[serde(default)]
    status: String,
    #[serde(default)]
    algo: Vec<String>,
    #[serde(default)]
    len: u32,
}

#[derive(Deserialize)]
struct CertIn {
    #[serde(default)]
    status: String,
    #[serde(default)]
    certificates: Vec<String>,
}

#[derive(Deserialize)]
struct AuthIn {
    #[serde(default)]
    mode: String,
}

/// RSA and EC public-key OIDs as `key/algo` names them.
const RSA_KEY: &str = "1.2.840.113549.1.1.1";
const EC_KEY: &str = "1.2.840.10045.2.1";

impl CredentialInfo {
    /// Whether the account may use it (ADR-046 §3.4, §3.6): key enabled, certificate
    /// valid, an RSA (2,048 to 8,192 bits) or EC key, authorized by OAuth (never PIN or
    /// OTP on our pages: `explicit` alone is refused), and, when the account requires
    /// qualifiers, one of them stated.
    #[must_use]
    pub fn eligible(&self, required_qualifiers: &[String]) -> bool {
        let algo_ok = self.key_algorithms.iter().any(|a| a == EC_KEY)
            || (self.key_algorithms.iter().any(|a| a == RSA_KEY)
                && (2048..=8192).contains(&self.key_len));
        let qualifier_ok = required_qualifiers.is_empty()
            || self
                .signature_qualifier
                .as_ref()
                .is_some_and(|q| required_qualifiers.iter().any(|r| r == q));
        self.key_status == "enabled"
            && self.cert_status == "valid"
            && !self.chain.is_empty()
            && algo_ok
            && self.auth_mode != "explicit"
            && qualifier_ok
    }
}

impl<'a> Client<'a> {
    /// A client of `provider` authenticating with `client_secret`.
    #[must_use]
    pub fn new(
        provider: &'a Provider,
        client_secret: &'a str,
        transport: &'a dyn Transport,
    ) -> Self {
        Self {
            provider,
            client_secret,
            transport,
        }
    }

    fn api(&self, method: &str, token: &str, body: &Value) -> Result<Value, CscError> {
        let url = format!("{}/{method}", self.provider.base_uri);
        let body = serde_json::to_vec(body).map_err(|_| CscError::Invalid { what: "request" })?;
        let (status, bytes) = self
            .transport
            .post(&url, "application/json", Some(token), &body)?;
        answer(status, &bytes)
    }

    /// Exchange an authorization code (with its PKCE verifier) for an access token
    /// (CSC §8.4.4). With scope `credential` the token authorizes `signHash`.
    ///
    /// # Errors
    /// `Refused` with the provider's code (`invalid_grant`, ...); `CS-RSP-0002`;
    /// `CS-RSP-0004` an answer without a token.
    pub fn token(&self, code: &str, verifier: &str) -> Result<String, CscError> {
        let body = form(&[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &self.provider.redirect_uri),
            ("client_id", &self.provider.client_id),
            ("client_secret", self.client_secret),
            ("code_verifier", verifier),
        ]);
        let (status, bytes) = self.transport.post(
            &self.provider.token_endpoint,
            "application/x-www-form-urlencoded",
            None,
            body.as_bytes(),
        )?;
        let v = answer(status, &bytes)?;
        v.get("access_token")
            .and_then(Value::as_str)
            .filter(|t| !t.is_empty() && t.len() <= 8192)
            .map(str::to_owned)
            .ok_or(CscError::Invalid {
                what: "access_token",
            })
    }

    /// `credentials/list` (CSC §11.4): the signer's credential ids.
    ///
    /// # Errors
    /// As [`Client::token`]; `CS-RSP-0004` over [`MAX_CREDENTIALS`].
    pub fn credentials(&self, token: &str) -> Result<Vec<String>, CscError> {
        let v = self.api("credentials/list", token, &json!({}))?;
        let ids = v
            .get("credentialIDs")
            .and_then(Value::as_array)
            .ok_or(CscError::Invalid {
                what: "credentialIDs",
            })?;
        if ids.len() > MAX_CREDENTIALS {
            return Err(CscError::Invalid {
                what: "credentials",
            });
        }
        ids.iter()
            .map(|i| {
                i.as_str()
                    .filter(|s| (1..=255).contains(&s.len()))
                    .map(str::to_owned)
                    .ok_or(CscError::Invalid {
                        what: "credentialID",
                    })
            })
            .collect()
    }

    /// `credentials/info` (CSC §11.5) for `id`, with the whole chain.
    ///
    /// # Errors
    /// As [`Client::token`]; `CS-RSP-0004` over [`MAX_CERTIFICATES`] or a certificate
    /// that is not base64.
    pub fn info(&self, token: &str, id: &str) -> Result<CredentialInfo, CscError> {
        let v = self.api(
            "credentials/info",
            token,
            &json!({"credentialID": id, "certificates": "chain", "certInfo": true, "authInfo": true}),
        )?;
        let info: InfoIn =
            serde_json::from_value(v).map_err(|_| CscError::Invalid { what: "info" })?;
        let key = info.key.ok_or(CscError::Invalid { what: "key" })?;
        let cert = info.cert.ok_or(CscError::Invalid { what: "cert" })?;
        if cert.certificates.len() > MAX_CERTIFICATES {
            return Err(CscError::Invalid {
                what: "certificates",
            });
        }
        let chain = cert
            .certificates
            .iter()
            .map(|c| {
                STANDARD.decode(c).map_err(|_| CscError::Invalid {
                    what: "certificate",
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(CredentialInfo {
            id: id.to_owned(),
            key_status: key.status,
            key_algorithms: key.algo,
            key_len: key.len,
            cert_status: cert.status,
            chain,
            scal: info.scal.unwrap_or_else(|| "1".to_owned()),
            multisign: info.multisign.unwrap_or(1).max(1),
            auth_mode: info.auth.map(|a| a.mode).unwrap_or_default(),
            signature_qualifier: info.signature_qualifier,
        })
    }

    /// `signatures/signHash` (CSC §11.10), authorized by a `credential`-scope token:
    /// one value per hash, in order, as raw bytes (DER or raw `r‖s` for ECDSA; the
    /// engine re-encodes and checks each).
    ///
    /// # Errors
    /// As [`Client::token`]; `CS-RSP-0004` for a wrong number of values or one that is
    /// not base64.
    pub fn sign_hash(
        &self,
        token: &str,
        credential_id: &str,
        hashes: &[Vec<u8>],
        hash_algorithm_oid: &str,
        sign_algorithm_oid: &str,
    ) -> Result<Vec<Vec<u8>>, CscError> {
        let v = self.api(
            "signatures/signHash",
            token,
            &json!({
                "credentialID": credential_id,
                "hashes": hashes.iter().map(|h| STANDARD.encode(h)).collect::<Vec<_>>(),
                "hashAlgorithmOID": hash_algorithm_oid,
                "signAlgo": sign_algorithm_oid,
            }),
        )?;
        let values = v
            .get("signatures")
            .and_then(Value::as_array)
            .ok_or(CscError::Invalid { what: "signatures" })?;
        if values.len() != hashes.len() {
            return Err(CscError::Invalid {
                what: "signature count",
            });
        }
        values
            .iter()
            .map(|s| {
                s.as_str()
                    .and_then(|s| STANDARD.decode(s).ok())
                    .filter(|b| !b.is_empty() && b.len() <= 1024)
                    .ok_or(CscError::Invalid { what: "signature" })
            })
            .collect()
    }
}

#[cfg(test)]
// Tests may unwrap and index (CLAUDE.md).
#[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::panic)]
mod tests {
    use std::cell::RefCell;

    use super::*;
    use crate::catalogue::Catalogue;

    struct Fake {
        answers: RefCell<Vec<(u16, Value)>>,
        seen: RefCell<Vec<(String, Option<String>, String)>>,
    }

    impl Transport for Fake {
        fn post(
            &self,
            url: &str,
            _ct: &str,
            bearer: Option<&str>,
            body: &[u8],
        ) -> Result<(u16, Vec<u8>), CscError> {
            self.seen.borrow_mut().push((
                url.to_owned(),
                bearer.map(str::to_owned),
                String::from_utf8_lossy(body).into_owned(),
            ));
            let (s, v) = self.answers.borrow_mut().remove(0);
            Ok((s, serde_json::to_vec(&v).unwrap()))
        }
    }

    fn fake(answers: Vec<(u16, Value)>) -> Fake {
        Fake {
            answers: RefCell::new(answers),
            seen: RefCell::new(Vec::new()),
        }
    }

    fn catalogue() -> Catalogue {
        let json = r#"{"providers": [{"id": "csc-ci", "kind": "csc", "name": "CI",
            "base_uri": "https://csc.example.test/csc/v2",
            "authorization_endpoint": "https://csc.example.test/oauth2/authorize",
            "token_endpoint": "https://csc.example.test/oauth2/token",
            "client_id": "openseal", "client_secret_ref": "S",
            "trust_anchors_file": "/a.pem", "accounts": ["*"]}]}"#;
        Catalogue::parse(
            json.as_bytes(),
            "https://sign.example.test",
            &|_| Ok(Some(casual_sign_secrets::Secret::new("s".into()))),
            &|_| Some(b"-----BEGIN CERTIFICATE-----\n".to_vec()),
        )
        .unwrap()
    }

    #[test]
    fn the_authorization_urls_carry_pkce_state_and_the_bound_hashes() {
        let c = catalogue();
        let p = c.get("csc-ci").unwrap();
        let v = pkce_verifier().unwrap();
        assert_eq!(v.len(), 43);
        let ch = pkce_challenge(&v);
        let url = authorization_url(p, &Scope::Service, "st/1", &ch);
        assert!(url.starts_with("https://csc.example.test/oauth2/authorize?response_type=code&"));
        assert!(url.contains("scope=service"));
        assert!(url.contains("state=st%2F1"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("redirect_uri=https%3A%2F%2Fsign.example.test%2Fs%2Frsp"));
        let hashes = vec![vec![0xFBu8; 32], vec![1u8; 32]];
        let url = authorization_url(
            p,
            &Scope::Credential {
                credential_id: "cred-1",
                hashes: &hashes,
                hash_algorithm_oid: SHA256_OID,
            },
            "s2",
            &ch,
        );
        assert!(url.contains("scope=credential") && url.contains("numSignatures=2"));
        assert!(url.contains(&format!(
            "hashes={}%2C{}",
            URL_SAFE_NO_PAD.encode(&hashes[0]),
            URL_SAFE_NO_PAD.encode(&hashes[1])
        )));
    }

    #[test]
    fn a_whole_exchange_and_its_refusals() {
        let c = catalogue();
        let p = c.get("csc-ci").unwrap();
        let cert = STANDARD.encode([0x30u8, 0x03, 0x02, 0x01, 0x01]);
        let t = fake(vec![
            (200, json!({"access_token": "tok", "token_type": "Bearer"})),
            (200, json!({"credentialIDs": ["c1"]})),
            (
                200,
                json!({"key": {"status": "enabled", "algo": [EC_KEY], "len": 256},
                "cert": {"status": "valid", "certificates": [cert]}, "SCAL": "2",
                "multisign": 2, "auth": {"mode": "oauth2code"},
                "signatureQualifier": "eu_eidas_qes"}),
            ),
            (200, json!({"signatures": [STANDARD.encode([1u8; 64])]})),
        ]);
        let client = Client::new(p, "secret", &t);
        let tok = client.token("code-1", "verifier").unwrap();
        assert_eq!(tok, "tok");
        let form_sent = t.seen.borrow()[0].2.clone();
        assert!(
            form_sent.contains("code_verifier=verifier")
                && form_sent.contains("client_secret=secret")
        );
        assert_eq!(client.credentials(&tok).unwrap(), ["c1"]);
        let info = client.info(&tok, "c1").unwrap();
        assert!(info.eligible(&[]));
        assert!(info.eligible(&["eu_eidas_qes".to_owned()]));
        assert!(!info.eligible(&["other".to_owned()]));
        assert_eq!(info.scal, "2");
        let sigs = client
            .sign_hash(
                &tok,
                "c1",
                &[vec![2u8; 32]],
                SHA256_OID,
                "1.2.840.10045.4.3.2",
            )
            .unwrap();
        assert_eq!(sigs, vec![vec![1u8; 64]]);
        assert_eq!(t.seen.borrow()[3].1.as_deref(), Some("tok"));

        // A wrong number of values; an OAuth refusal; a 5xx; garbage.
        let t = fake(vec![(200, json!({"signatures": ["AA==", "AA=="]}))]);
        let e = Client::new(p, "s", &t)
            .sign_hash("t", "c1", &[vec![2u8; 32]], SHA256_OID, "x")
            .unwrap_err();
        assert_eq!(e.code(), "CS-RSP-0004");
        let t = fake(vec![(
            400,
            json!({"error": "access_denied", "error_description": "Ann"}),
        )]);
        let e = Client::new(p, "s", &t).token("c", "v").unwrap_err();
        assert_eq!(e.session_failure(), "cancelled");
        assert_eq!(e.provider_code(), Some("access_denied"));
        assert!(!e.to_string().contains("Ann"));
        let t = fake(vec![(503, json!({}))]);
        assert_eq!(
            Client::new(p, "s", &t).token("c", "v").unwrap_err().code(),
            "CS-RSP-0002"
        );
        let t = fake(vec![(400, json!({"error": "<script>"}))]);
        assert_eq!(
            Client::new(p, "s", &t)
                .token("c", "v")
                .unwrap_err()
                .provider_code(),
            Some("invalid")
        );
        let many: Vec<String> = (0..=MAX_CREDENTIALS).map(|i| format!("c{i}")).collect();
        let t = fake(vec![(200, json!({"credentialIDs": many}))]);
        assert_eq!(
            Client::new(p, "s", &t).credentials("t").unwrap_err().code(),
            "CS-RSP-0004"
        );
    }

    #[test]
    fn explicit_only_weak_and_disabled_credentials_are_not_eligible() {
        let base = CredentialInfo {
            id: "c".into(),
            key_status: "enabled".into(),
            key_algorithms: vec![RSA_KEY.into()],
            key_len: 2048,
            cert_status: "valid".into(),
            chain: vec![vec![1]],
            scal: "1".into(),
            multisign: 1,
            auth_mode: "oauth2code".into(),
            signature_qualifier: None,
        };
        assert!(base.eligible(&[]));
        for bad in [
            CredentialInfo {
                auth_mode: "explicit".into(),
                ..base.clone()
            },
            CredentialInfo {
                key_len: 1024,
                ..base.clone()
            },
            CredentialInfo {
                key_status: "disabled".into(),
                ..base.clone()
            },
            CredentialInfo {
                cert_status: "expired".into(),
                ..base.clone()
            },
            CredentialInfo {
                chain: vec![],
                ..base.clone()
            },
        ] {
            assert!(!bad.eligible(&[]), "{bad:?}");
        }
    }
}
