//! One XML Signature profile (ADR-047 §3.5), for verifying an ESP's answer and signing
//! our request:
//!
//! - an enveloped `Signature` (namespace `http://www.w3.org/2000/09/xmldsig#`), the
//!   **last element child of the root**, and the only `Signature` in the document;
//! - `SignedInfo` with a `CanonicalizationMethod` of Canonical XML 1.0 or Exclusive
//!   Canonicalization 1.0 (never with comments, never an `InclusiveNamespaces` list), a
//!   `SignatureMethod` of RSA-SHA256 or ECDSA-SHA256 (P-256), and **one** `Reference`
//!   with `URI=""`;
//! - that reference's transforms: enveloped-signature, then optionally one of the two
//!   canonicalizations (Canonical XML 1.0 when none is named); digest SHA-256;
//! - then `SignatureValue` and at most a `KeyInfo`, which is never read: the key is the
//!   **configured** certificate's, never one from the message.
//!
//! Anything else is refused before any value is read. Every value a caller reads comes
//! from the same parsed tree whose canonical form was verified, and `URI=""` with the
//! enveloped transform covers every node outside the `Signature`, so signature wrapping
//! finds nothing to wrap. The cryptography is aws-lc-rs's (ADR-006).

use aws_lc_rs::digest;
use aws_lc_rs::signature::{self, UnparsedPublicKey};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use casual_sign_xml::{Dom, Limits, NodeId, parse};
use der::Decode as _;
use x509_cert::Certificate;

use crate::c14n::{Method, canonicalize};
use crate::error::EsignError;

/// The XML Signature namespace.
pub const DSIG_NS: &str = "http://www.w3.org/2000/09/xmldsig#";
/// The enveloped-signature transform.
pub const ENVELOPED: &str = "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
/// SHA-256.
pub const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
/// RSASSA-PKCS1-v1_5 with SHA-256.
pub const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
/// ECDSA with SHA-256.
pub const ECDSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";

const OID_RSA: &str = "1.2.840.113549.1.1.1";
const OID_EC: &str = "1.2.840.10045.2.1";
const OID_P256: &str = "1.2.840.10045.3.1.7";

/// The signature algorithm of a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// RSA PKCS#1 v1.5 with SHA-256, 2,048 bits or more.
    RsaSha256,
    /// ECDSA P-256 with SHA-256; the XML value is `r ‖ s`, 64 bytes.
    EcdsaP256Sha256,
}

impl Algorithm {
    /// The `SignatureMethod` URI.
    #[must_use]
    pub const fn uri(self) -> &'static str {
        match self {
            Self::RsaSha256 => RSA_SHA256,
            Self::EcdsaP256Sha256 => ECDSA_SHA256,
        }
    }
}

/// A verifying key, from a certificate the operator configured.
#[derive(Clone)]
pub struct VerifyingKey {
    algorithm: Algorithm,
    /// `RSAPublicKey` DER, or the uncompressed point.
    key: Vec<u8>,
}

impl core::fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VerifyingKey")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

impl VerifyingKey {
    /// The key of a DER certificate: RSA (2,048 bits or more) or P-256.
    ///
    /// # Errors
    /// [`EsignError::Certificate`] for anything else.
    pub fn from_certificate(der: &[u8]) -> Result<Self, EsignError> {
        let cert = Certificate::from_der(der).map_err(|_| EsignError::Certificate)?;
        let spki = cert.tbs_certificate().subject_public_key_info();
        let key = spki
            .subject_public_key
            .as_bytes()
            .ok_or(EsignError::Certificate)?
            .to_vec();
        let oid = spki.algorithm.oid.to_string();
        let algorithm = if oid == OID_RSA {
            // The modulus is at least 2,048 bits: the RSAPublicKey is longer than 256
            // bytes.
            if key.len() < 256 {
                return Err(EsignError::Certificate);
            }
            Algorithm::RsaSha256
        } else if oid == OID_EC {
            let curve = spki
                .algorithm
                .parameters
                .as_ref()
                .and_then(|p| p.decode_as::<der::asn1::ObjectIdentifier>().ok())
                .ok_or(EsignError::Certificate)?;
            if curve.to_string() != OID_P256 {
                return Err(EsignError::Certificate);
            }
            Algorithm::EcdsaP256Sha256
        } else {
            return Err(EsignError::Certificate);
        };
        Ok(Self { algorithm, key })
    }

    /// The key's algorithm.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    fn verify(&self, message: &[u8], value: &[u8]) -> Result<(), EsignError> {
        let alg: &dyn signature::VerificationAlgorithm = match self.algorithm {
            Algorithm::RsaSha256 => &signature::RSA_PKCS1_2048_8192_SHA256,
            Algorithm::EcdsaP256Sha256 => &signature::ECDSA_P256_SHA256_FIXED,
        };
        UnparsedPublicKey::new(alg, &self.key)
            .verify(message, value)
            .map_err(|_| EsignError::SignatureInvalid)
    }
}

fn is_dsig(dom: &Dom, id: NodeId, name: &str) -> bool {
    dom.name(id) == name && dom.element_namespace(id) == Some(DSIG_NS)
}

/// The element children of `id`, refusing any non-white-space text among them.
fn elements_only(dom: &Dom, id: NodeId) -> Result<Vec<NodeId>, EsignError> {
    let mut out = Vec::new();
    for c in &dom.node(id).children {
        let n = dom.node(*c);
        if n.is_text() {
            if !n.text.trim().is_empty() {
                return Err(EsignError::Profile("text in signature structure"));
            }
        } else {
            out.push(*c);
        }
    }
    Ok(out)
}

/// The `Algorithm` attribute of an element with no element children, and no other
/// attribute.
fn algorithm(dom: &Dom, id: NodeId) -> Result<&str, EsignError> {
    let n = dom.node(id);
    if !elements_only(dom, id)?.is_empty() {
        return Err(EsignError::Profile("parameters to an algorithm"));
    }
    match n.attributes.as_slice() {
        [a] if a.prefix.is_empty() && a.local == "Algorithm" => Ok(a.value.as_str()),
        _ => Err(EsignError::Profile("algorithm attributes")),
    }
}

fn base64_text(dom: &Dom, id: NodeId, max: usize) -> Result<Vec<u8>, EsignError> {
    if dom.elements(id).next().is_some() {
        return Err(EsignError::Profile("elements in a value"));
    }
    let text: String = dom
        .text(id)
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    if text.len() > max {
        return Err(EsignError::Profile("value too long"));
    }
    STANDARD
        .decode(text.as_bytes())
        .map_err(|_| EsignError::Profile("value not base64"))
}

/// The enveloped `Signature` element of `dom`, checked to be the only one and the last
/// element child of the root.
///
/// # Errors
/// [`EsignError::Profile`] otherwise.
pub fn signature_element(dom: &Dom) -> Result<NodeId, EsignError> {
    let root = dom.root().ok_or(EsignError::Profile("no root"))?;
    let all: Vec<NodeId> = dom
        .descendants(root)
        .into_iter()
        .filter(|n| dom.name(*n) == "Signature")
        .collect();
    let [sig] = all.as_slice() else {
        return Err(EsignError::Profile(if all.is_empty() {
            "no signature"
        } else {
            "more than one signature"
        }));
    };
    if !is_dsig(dom, *sig, "Signature") || dom.elements(root).last() != Some(*sig) {
        return Err(EsignError::Profile("signature not last in the root"));
    }
    Ok(*sig)
}

/// Verify the enveloped XML Signature of `dom` under `key`.
///
/// # Errors
/// [`EsignError::Profile`] for anything outside the profile;
/// [`EsignError::DigestMismatch`] or [`EsignError::SignatureInvalid`] when it does not
/// verify.
pub fn verify(dom: &Dom, key: &VerifyingKey) -> Result<(), EsignError> {
    let root = dom.root().ok_or(EsignError::Profile("no root"))?;
    let sig = signature_element(dom)?;
    if !dom.node(sig).attributes.iter().all(|a| a.local == "Id") {
        return Err(EsignError::Profile("signature attributes"));
    }
    let parts = elements_only(dom, sig)?;
    let (signed_info, value) = match parts.as_slice() {
        [si, sv] => (*si, *sv),
        [si, sv, ki] if is_dsig(dom, *ki, "KeyInfo") => (*si, *sv),
        _ => return Err(EsignError::Profile("signature children")),
    };
    if !is_dsig(dom, signed_info, "SignedInfo") || !is_dsig(dom, value, "SignatureValue") {
        return Err(EsignError::Profile("signature children"));
    }
    let si = elements_only(dom, signed_info)?;
    let [cm, sm, reference] = si.as_slice() else {
        return Err(EsignError::Profile("one reference"));
    };
    if !is_dsig(dom, *cm, "CanonicalizationMethod")
        || !is_dsig(dom, *sm, "SignatureMethod")
        || !is_dsig(dom, *reference, "Reference")
    {
        return Err(EsignError::Profile("signed info children"));
    }
    let si_method = Method::from_uri(algorithm(dom, *cm)?)
        .ok_or(EsignError::Profile("canonicalization method"))?;
    if algorithm(dom, *sm)? != key.algorithm().uri() {
        return Err(EsignError::Profile("signature method"));
    }
    // The reference: URI="" and nothing else, the enveloped transform, SHA-256.
    match dom.node(*reference).attributes.as_slice() {
        [a] if a.prefix.is_empty() && a.local == "URI" && a.value.is_empty() => {}
        _ => return Err(EsignError::Profile("reference URI")),
    }
    let r = elements_only(dom, *reference)?;
    let [transforms, dm, dv] = r.as_slice() else {
        return Err(EsignError::Profile("reference children"));
    };
    if !is_dsig(dom, *transforms, "Transforms")
        || !is_dsig(dom, *dm, "DigestMethod")
        || !is_dsig(dom, *dv, "DigestValue")
        || algorithm(dom, *dm)? != SHA256
    {
        return Err(EsignError::Profile("reference children"));
    }
    let t = elements_only(dom, *transforms)?;
    if !t.iter().all(|x| is_dsig(dom, *x, "Transform")) {
        return Err(EsignError::Profile("transforms"));
    }
    let ref_method = match t.as_slice() {
        [e] if algorithm(dom, *e)? == ENVELOPED => Method::Inclusive,
        [e, c] if algorithm(dom, *e)? == ENVELOPED => {
            Method::from_uri(algorithm(dom, *c)?).ok_or(EsignError::Profile("transforms"))?
        }
        _ => return Err(EsignError::Profile("transforms")),
    };
    let want = base64_text(dom, *dv, 128)?;
    let value = base64_text(dom, value, 2048)?;
    // The signature first, over SignedInfo as canonicalized; then the reference.
    let signed = canonicalize(dom, signed_info, si_method, None);
    key.verify(&signed, &value)?;
    let content = canonicalize(dom, root, ref_method, Some(sig));
    if digest::digest(&digest::SHA256, &content).as_ref() != want.as_slice() {
        return Err(EsignError::DigestMismatch);
    }
    Ok(())
}

/// Read `bytes` within the eSign limits and verify its signature under `key`: the tree
/// every value is then read from.
///
/// # Errors
/// [`EsignError::Xml`] when unreadable; as [`verify`] otherwise.
pub fn read_verified(bytes: &[u8], key: &VerifyingKey) -> Result<Dom, EsignError> {
    let dom = parse(bytes, &Limits::esign(), &|| false)?;
    verify(&dom, key)?;
    Ok(dom)
}

/// What signs for [`sign_enveloped`]: the SHA-256 digest of the canonical `SignedInfo`
/// in, the signature value out (keyd's `sign-digest`).
pub type DigestSigner<'a> = dyn FnMut(&[u8]) -> Result<Vec<u8>, EsignError> + 'a;

/// An ECDSA signature as DER `SEQUENCE { r, s }` turned into XML Signature's `r ‖ s`
/// (32 bytes each for P-256); a value of 64 bytes is returned as it is.
///
/// # Errors
/// [`EsignError::Signer`] when it is neither.
pub fn ecdsa_fixed(value: &[u8]) -> Result<Vec<u8>, EsignError> {
    if value.len() == 64 {
        return Ok(value.to_vec());
    }
    let bad = || EsignError::Signer;
    let int = |b: &[u8]| -> Result<(Vec<u8>, usize), EsignError> {
        let (&tag, rest) = b.split_first().ok_or_else(bad)?;
        let (&len, rest) = rest.split_first().ok_or_else(bad)?;
        let len = usize::from(len);
        if tag != 0x02 || len > 33 || len == 0 {
            return Err(bad());
        }
        let v = rest.get(..len).ok_or_else(bad)?;
        let v: Vec<u8> = v.iter().copied().skip_while(|x| *x == 0).collect();
        if v.len() > 32 {
            return Err(bad());
        }
        let mut out = vec![0u8; 32usize.saturating_sub(v.len())];
        out.extend_from_slice(&v);
        Ok((out, len.saturating_add(2)))
    };
    let (&tag, rest) = value.split_first().ok_or_else(bad)?;
    let (&len, rest) = rest.split_first().ok_or_else(bad)?;
    if tag != 0x30 || usize::from(len) != rest.len() {
        return Err(bad());
    }
    let (r, used) = int(rest)?;
    let (s, used2) = int(rest.get(used..).ok_or_else(bad)?)?;
    if used.saturating_add(used2) != rest.len() {
        return Err(bad());
    }
    Ok([r, s].concat())
}

/// Sign `unsigned` (a document we wrote, whose root's end tag closes it) with an
/// enveloped XML Signature of this profile: Canonical XML 1.0 for `SignedInfo` and the
/// reference, `URI=""`, SHA-256, `algorithm`; `certificate` goes into `KeyInfo` when
/// given. `sign` receives the SHA-256 digest of the canonical `SignedInfo` and returns
/// the signature value (an ECDSA value as DER or `r ‖ s`), as keyd's `sign-digest`
/// does.
///
/// # Errors
/// [`EsignError::Request`] when `unsigned` is not a document of ours;
/// [`EsignError::Signer`] when the value cannot be made.
pub fn sign_enveloped(
    unsigned: &str,
    algorithm: Algorithm,
    certificate: Option<&[u8]>,
    sign: &mut DigestSigner<'_>,
) -> Result<String, EsignError> {
    let lim = Limits::esign();
    let dom =
        parse(unsigned.as_bytes(), &lim, &|| false).map_err(|_| EsignError::Request("document"))?;
    let root = dom.root().ok_or(EsignError::Request("document"))?;
    let digest_value = digest::digest(
        &digest::SHA256,
        &canonicalize(&dom, root, Method::Inclusive, None),
    );
    let key_info = certificate.map_or_else(String::new, |c| {
        format!(
            "<KeyInfo><X509Data><X509Certificate>{}</X509Certificate></X509Data></KeyInfo>",
            STANDARD.encode(c)
        )
    });
    let c14n = Method::Inclusive.uri();
    let signature = format!(
        "<Signature xmlns=\"{DSIG_NS}\"><SignedInfo><CanonicalizationMethod Algorithm=\"{c14n}\"/>\
<SignatureMethod Algorithm=\"{}\"/><Reference URI=\"\"><Transforms>\
<Transform Algorithm=\"{ENVELOPED}\"/><Transform Algorithm=\"{c14n}\"/></Transforms>\
<DigestMethod Algorithm=\"{SHA256}\"/><DigestValue>{}</DigestValue></Reference></SignedInfo>\
<SignatureValue></SignatureValue>{key_info}</Signature>",
        algorithm.uri(),
        STANDARD.encode(digest_value.as_ref()),
    );
    let close = unsigned
        .rfind("</")
        .ok_or(EsignError::Request("document"))?;
    let mut doc = String::with_capacity(unsigned.len().saturating_add(signature.len()));
    doc.push_str(
        unsigned
            .get(..close)
            .ok_or(EsignError::Request("document"))?,
    );
    doc.push_str(&signature);
    doc.push_str(
        unsigned
            .get(close..)
            .ok_or(EsignError::Request("document"))?,
    );
    let placed =
        parse(doc.as_bytes(), &lim, &|| false).map_err(|_| EsignError::Request("document"))?;
    let sig = signature_element(&placed).map_err(|_| EsignError::Request("document"))?;
    let si = placed
        .child(sig, "SignedInfo")
        .ok_or(EsignError::Request("document"))?;
    let to_sign = digest::digest(
        &digest::SHA256,
        &canonicalize(&placed, si, Method::Inclusive, None),
    );
    let mut value = sign(to_sign.as_ref())?;
    if algorithm == Algorithm::EcdsaP256Sha256 {
        value = ecdsa_fixed(&value)?;
    }
    let marker = "<SignatureValue></SignatureValue>";
    let at = doc.rfind(marker).ok_or(EsignError::Request("document"))?;
    let filled = format!(
        "<SignatureValue>{}</SignatureValue>",
        STANDARD.encode(value)
    );
    doc.replace_range(at..at.saturating_add(marker.len()), &filled);
    Ok(doc)
}
