//! The ESP's answer (eSign API v2.1 §3.4, ADR-047 §3.4): `EsignResp` read within the
//! eSign limits, its XML Signature verified under the ESP's **configured** certificate
//! before any value is read, then its values read from that same tree.
//!
//! Bounds (docs/21): 512 KiB, depth 16, 256 elements (the reader); at most 5
//! `DocSignature`; 16 KiB of base64 certificate; 512 KiB of base64 per signature.
//! `errMsg` is never read: it may carry the signer's data, and the code is enough.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use casual_sign_xml::{Dom, NodeId};

use crate::dsig::{VerifyingKey, read_verified, signature_element};
use crate::error::EsignError;

/// Most `DocSignature` elements.
pub const MAX_DOC_SIGNATURES: usize = 5;
/// Longest base64 certificate.
pub const MAX_CERTIFICATE_B64: usize = 16 * 1024;
/// Longest base64 signature.
pub const MAX_SIGNATURE_B64: usize = 512 * 1024;

/// The answer's `status`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// `1`: signed.
    Signed,
    /// `0`: failed, with an `errCode`.
    Failed,
    /// `2`: pending (v3.3 acknowledgements and status checks).
    Pending,
}

/// One document's signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocSignature {
    /// The `InputHash` id it answers.
    pub id: String,
    /// The document's own error ("User Rejected", v3.3), as a short token.
    pub error: Option<String>,
    /// The signature: with `PKCS7pdf`, a DER CMS `ContentInfo`.
    pub value: Vec<u8>,
}

/// A verified answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    /// What happened.
    pub status: Status,
    /// The transaction id it answers (our session id).
    pub txn: String,
    /// The ESP's time stamp, as written.
    pub ts: String,
    /// The ESP's transaction reference, which the ASP keeps in its audit trail.
    pub res_code: Option<String>,
    /// The ESP's error code, as a short token (never its message).
    pub err_code: Option<String>,
    /// The signer's certificate, DER.
    pub user_certificate: Option<Vec<u8>>,
    /// The signatures, in document order.
    pub signatures: Vec<DocSignature>,
}

fn short(value: Option<&str>, max: usize) -> Result<Option<String>, EsignError> {
    match value.map(str::trim) {
        None | Some("") => Ok(None),
        Some(v)
            if v.len() <= max
                && v.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_.: ".contains(&b)) =>
        {
            Ok(Some(v.to_owned()))
        }
        Some(_) => Err(EsignError::Response("attribute form")),
    }
}

fn base64_of(dom: &Dom, id: NodeId, max: usize, what: &'static str) -> Result<Vec<u8>, EsignError> {
    if dom.elements(id).next().is_some() {
        return Err(EsignError::Response(what));
    }
    let text: String = dom
        .text(id)
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    if text.is_empty() || text.len() > max {
        return Err(EsignError::Response(what));
    }
    STANDARD
        .decode(text.as_bytes())
        .map_err(|_| EsignError::Response(what))
}

/// At most one child element of `id` named `name` (other than the signature).
fn one(dom: &Dom, id: NodeId, name: &str) -> Result<Option<NodeId>, EsignError> {
    let mut found = dom.children_named(id, name);
    let first = found.next();
    if found.next().is_some() {
        return Err(EsignError::Response("repeated element"));
    }
    Ok(first)
}

/// Read and verify an answer.
///
/// # Errors
/// [`EsignError::Xml`], [`EsignError::Profile`], [`EsignError::DigestMismatch`] or
/// [`EsignError::SignatureInvalid`] when its signature does not hold;
/// [`EsignError::Response`] when, signed, it is not an answer we can use.
pub fn read(bytes: &[u8], esp: &VerifyingKey) -> Result<Response, EsignError> {
    let dom = read_verified(bytes, esp)?;
    let root = dom.root().ok_or(EsignError::Response("root"))?;
    let sig = signature_element(&dom)?;
    if dom.name(root) != "EsignResp" || !dom.node(root).prefix.is_empty() {
        return Err(EsignError::Response("root"));
    }
    if dom.element_namespace(root).is_some() {
        return Err(EsignError::Response("root namespace"));
    }
    let status = match dom.attr(root, "status").map(str::trim) {
        Some("1") => Status::Signed,
        Some("0") => Status::Failed,
        Some("2") => Status::Pending,
        _ => return Err(EsignError::Response("status")),
    };
    let txn = short(dom.attr(root, "txn"), 64)?.ok_or(EsignError::Response("txn"))?;
    let ts = short(dom.attr(root, "ts"), 40)?.unwrap_or_default();
    let res_code = short(dom.attr(root, "resCode"), 64)?;
    let err_code = short(dom.attr(root, "errCode"), 64)?.filter(|c| !c.eq_ignore_ascii_case("NA"));
    let user_certificate = match one(&dom, root, "UserX509Certificate")? {
        Some(c) => Some(base64_of(&dom, c, MAX_CERTIFICATE_B64, "certificate")?),
        None => None,
    };
    let mut signatures = Vec::new();
    if let Some(s) = one(&dom, root, "Signatures")? {
        for d in dom.elements(s) {
            if d == sig || dom.name(d) != "DocSignature" {
                return Err(EsignError::Response("signatures"));
            }
            if signatures.len() >= MAX_DOC_SIGNATURES {
                return Err(EsignError::Response("too many signatures"));
            }
            let id = short(dom.attr(d, "id"), 8)?.ok_or(EsignError::Response("signature id"))?;
            let error = short(dom.attr(d, "error"), 64)?.filter(|c| !c.eq_ignore_ascii_case("NA"));
            let value = if error.is_some() && dom.text(d).trim().is_empty() {
                Vec::new()
            } else {
                base64_of(&dom, d, MAX_SIGNATURE_B64, "signature")?
            };
            if signatures.iter().any(|x: &DocSignature| x.id == id) {
                return Err(EsignError::Response("signature id"));
            }
            signatures.push(DocSignature { id, error, value });
        }
    }
    match status {
        Status::Signed if user_certificate.is_none() || signatures.is_empty() => {
            return Err(EsignError::Response("signed without a signature"));
        }
        Status::Failed if err_code.is_none() => return Err(EsignError::Response("errCode")),
        _ => {}
    }
    Ok(Response {
        status,
        txn,
        ts,
        res_code,
        err_code,
        user_certificate,
        signatures,
    })
}
