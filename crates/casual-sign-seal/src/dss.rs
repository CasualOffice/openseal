//! PAdES B-LT validation data (docs/31 §4 step 9; ETSI EN 319 142-1 §5.4; ISO 32000-2
//! §12.8.4.3): an incremental update with the Document Security Store.
//!
//! For each target signature (or document timestamp) the engine walks every certificate
//! the CMS carries, its signature timestamp's TSA certificates included, up to a
//! self-signed certificate, finding issuers in the CMS, in the source's
//! [`RevocationSource::certificates`] and among the request's trust anchors and
//! intermediates: a real CA's chain stops below its offline root, and so does a TSA's
//! token (HRD-02). A walk also ends at a trust anchor or a cross-certificate of one (same
//! subject and key), which needs no revocation data. For each certificate that is not self-signed it
//! asks the host for an OCSP response (a request with a SHA-256 `CertID`), falls back to
//! a CRL (docs/31 §9), and embeds an answer only after `casual-sign-crypto` shows the
//! certificate not revoked at the time asked. A delegated OCSP responder's certificate
//! goes into `/Certs`; without `id-pkix-ocsp-nocheck` its own CRL is collected too.
//!
//! The DSS keeps everything an earlier DSS held and adds `/VRI` entries keyed by the
//! upper-case hex SHA-1 of the target's `/Contents` string, padding included (PAdES's
//! identifier; `SEAL-14`: SHA-1 names, it never signs or digests content).

use core::time::Duration;
use std::collections::BTreeMap;

use casual_sign_crypto::cms::ParsedCms;
use casual_sign_crypto::revocation::{RevocationStatus, crl_status_for, ocsp_status};
use casual_sign_crypto::{Certificate, DigestAlgorithm, oid};
use casual_sign_pdf::{Change, Dictionary, IncrementalUpdate, Limits, ObjRef, Object};
use casual_sign_verify::TrustStore;
use der::asn1::{Any, Null, ObjectIdentifier, OctetString};
use der::{Decode, Encode};
use sha1::{Digest, Sha1};
use x509_cert::spki::AlgorithmIdentifierOwned;
use x509_ocsp::{BasicOcspResponse, CertId, OcspRequest, OcspResponse, Request, TbsRequest};

use crate::error::{LayoutProblem, RevocationProblem, SealError};
use crate::form::{self, Holder, never};
use crate::revision::admit_for_update;
use crate::source::{CrlQuery, OcspQuery, RevocationSource};
use crate::text::hex_upper;

/// `id-pkix-ocsp-nocheck` (RFC 6960 §4.2.2.2.1).
const OCSP_NOCHECK: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.3.6.1.5.5.7.48.1.5");
/// Most certificates, responses or CRLs one DSS update writes (the verifier's bound).
const MAX_ITEMS: usize = 4096;

/// What a DSS update added.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DssReport {
    /// Certificates written by this update (not counting ones already in the DSS).
    pub certificates: usize,
    /// OCSP responses written.
    pub ocsp_responses: usize,
    /// CRLs written.
    pub crls: usize,
    /// The `/VRI` keys added or replaced, one per target.
    pub vri_keys: Vec<String>,
}

/// The `/VRI` key for a signature whose `/Contents` string decodes to `contents`.
#[must_use]
pub fn vri_key(contents: &[u8]) -> String {
    hex_upper(&Sha1::digest(contents))
}

fn crypto(e: casual_sign_crypto::CryptoError) -> SealError {
    SealError::Crypto(e)
}

fn der_of(c: &Certificate) -> Result<Vec<u8>, SealError> {
    c.to_der()
        .map_err(|_| SealError::Layout(LayoutProblem::Encoding))
}

fn self_signed(c: &Certificate) -> bool {
    c.tbs_certificate().subject() == c.tbs_certificate().issuer()
}

fn has_nocheck(c: &Certificate) -> bool {
    c.tbs_certificate()
        .extensions()
        .is_some_and(|exts| exts.iter().any(|e| e.extn_id == OCSP_NOCHECK))
}

/// The DER `OCSPRequest` for `cert` with a SHA-256 `CertID` (RFC 6960 §4.1.1). SHA-1
/// `CertID`s are refused by `casual-sign-crypto` (`SEAL-14`), so none is asked for.
pub(crate) fn ocsp_request(cert: &Certificate, issuer: &Certificate) -> Result<Vec<u8>, SealError> {
    let enc = |_| SealError::Layout(LayoutProblem::Encoding);
    let itbs = issuer.tbs_certificate();
    let name = itbs.subject().to_der().map_err(enc)?;
    let key = itbs
        .subject_public_key_info()
        .subject_public_key
        .raw_bytes();
    let sha = DigestAlgorithm::Sha256;
    let req_cert = CertId {
        hash_algorithm: AlgorithmIdentifierOwned {
            oid: oid::ID_SHA256,
            parameters: Some(Any::encode_from(&Null).map_err(enc)?),
        },
        issuer_name_hash: OctetString::new(sha.digest(&name).as_bytes()).map_err(enc)?,
        issuer_key_hash: OctetString::new(sha.digest(key).as_bytes()).map_err(enc)?,
        serial_number: cert.tbs_certificate().serial_number().clone(),
    };
    let req = OcspRequest {
        tbs_request: TbsRequest {
            version: x509_ocsp::Version::V1,
            requestor_name: None,
            request_list: vec![Request {
                req_cert,
                single_request_extensions: None,
            }],
            request_extensions: None,
        },
        optional_signature: None,
    };
    req.to_der().map_err(enc)
}

/// Certificates carried by an OCSP response (a delegated responder and its chain).
fn responder_certificates(response: &[u8]) -> Vec<Certificate> {
    let Ok(outer) = OcspResponse::from_der(response) else {
        return Vec::new();
    };
    let Some(bytes) = outer.response_bytes else {
        return Vec::new();
    };
    BasicOcspResponse::from_der(bytes.response.as_bytes())
        .ok()
        .and_then(|b| b.certs)
        .unwrap_or_default()
}

/// The certificates a signature or document timestamp carries, its signature
/// timestamp's included.
pub(crate) fn certificates_of(contents: &[u8]) -> Result<Vec<Certificate>, SealError> {
    let cms = ParsedCms::parse(contents).map_err(crypto)?;
    let mut out: Vec<Certificate> = cms.certificates().cloned().collect();
    if let Ok(Some(token)) = cms.timestamp_token()
        && let Ok(t) = ParsedCms::parse(&token)
    {
        out.extend(t.certificates().cloned());
    }
    Ok(out)
}

/// The answer found for one certificate.
#[derive(Debug, Clone)]
struct Answer {
    ocsp: Option<usize>,
    crl: Option<usize>,
    /// Responder certificates to add to the DSS (and to the target's VRI).
    responders: Vec<Certificate>,
}

/// Validation data collected across targets, shared so no certificate is asked twice.
struct Collector<'s> {
    source: &'s dyn RevocationSource,
    at: Duration,
    /// The trust anchors: a path ends at one (or at a certificate with its subject and key).
    anchors: Vec<Certificate>,
    pool: Vec<Certificate>,
    certs: Vec<Certificate>,
    ocsps: Vec<Vec<u8>>,
    crls: Vec<Vec<u8>>,
    answers: Vec<(Certificate, Answer)>,
}

/// One target's VRI entry, as indexes into the collector's lists.
#[derive(Default)]
struct Vri {
    certs: Vec<usize>,
    ocsps: Vec<usize>,
    crls: Vec<usize>,
}

fn push_unique<T: PartialEq>(list: &mut Vec<T>, item: T) -> Result<usize, SealError> {
    if let Some(i) = list.iter().position(|x| *x == item) {
        return Ok(i);
    }
    if list.len() >= MAX_ITEMS {
        return Err(SealError::Revocation(RevocationProblem::TooMany));
    }
    list.push(item);
    Ok(list.len().saturating_sub(1))
}

fn note(v: &mut Vec<usize>, i: usize) {
    if !v.contains(&i) {
        v.push(i);
    }
}

impl Collector<'_> {
    /// Whether `cert` is a trust anchor, or a cross-certificate of one (the same subject
    /// and public key, issued by someone else): either ends the path.
    fn is_anchor(&self, cert: &Certificate) -> bool {
        let tbs = cert.tbs_certificate();
        self.anchors.iter().any(|a| {
            let atbs = a.tbs_certificate();
            atbs.subject() == tbs.subject()
                && atbs.subject_public_key_info() == tbs.subject_public_key_info()
        })
    }

    fn issuer_of(&self, cert: &Certificate) -> Option<Certificate> {
        let want = cert.tbs_certificate().issuer();
        self.pool
            .iter()
            .find(|c| c.tbs_certificate().subject() == want && *c != cert)
            .cloned()
    }

    fn index_of(&self, cert: &Certificate) -> usize {
        self.certs
            .iter()
            .position(|c| c == cert)
            .unwrap_or(self.certs.len())
    }

    fn crl_for(
        &mut self,
        cert: &Certificate,
        issuer: &Certificate,
    ) -> Result<Option<usize>, SealError> {
        let index = self.index_of(cert);
        let q = CrlQuery {
            certificate: cert,
            issuer,
        };
        let Some(crl) = self
            .source
            .crl(&q)
            .map_err(|e| SealError::Revocation(RevocationProblem::Source(e)))?
        else {
            return Ok(None);
        };
        // Scope-aware: a production CA's CRL carries a critical Issuing Distribution Point.
        match crl_status_for(&crl, cert, issuer, self.at) {
            Ok(RevocationStatus::Good) => Ok(Some(push_unique(&mut self.crls, crl)?)),
            Ok(RevocationStatus::Revoked { .. }) => {
                Err(SealError::Revocation(RevocationProblem::Revoked { index }))
            }
            _ => Ok(None),
        }
    }

    /// The answer for `cert` (issued by `issuer`), asked once.
    fn answer(&mut self, cert: &Certificate, issuer: &Certificate) -> Result<Answer, SealError> {
        if let Some((_, a)) = self.answers.iter().find(|(c, _)| c == cert) {
            return Ok(a.clone());
        }
        let index = self.index_of(cert);
        let mut answer = Answer {
            ocsp: None,
            crl: None,
            responders: Vec::new(),
        };
        let request = ocsp_request(cert, issuer)?;
        let q = OcspQuery {
            request_der: &request,
            certificate: cert,
            issuer,
        };
        let response = self
            .source
            .ocsp(&q)
            .map_err(|e| SealError::Revocation(RevocationProblem::Source(e)))?;
        if let Some(resp) = response {
            match ocsp_status(
                &resp,
                cert.tbs_certificate().serial_number(),
                issuer,
                self.at,
            ) {
                Ok(RevocationStatus::Good) => {
                    for r in responder_certificates(&resp) {
                        if r != *issuer && r != *cert {
                            answer.responders.push(r);
                        }
                    }
                    answer.ocsp = Some(push_unique(&mut self.ocsps, resp)?);
                }
                Ok(RevocationStatus::Revoked { .. }) => {
                    return Err(SealError::Revocation(RevocationProblem::Revoked { index }));
                }
                _ => {}
            }
        }
        if answer.ocsp.is_none() {
            answer.crl = self.crl_for(cert, issuer)?;
            if answer.crl.is_none() {
                return Err(SealError::Revocation(RevocationProblem::NoAnswer { index }));
            }
        }
        self.answers.push((cert.clone(), answer.clone()));
        Ok(answer)
    }

    /// Walk `start` up to a self-signed certificate, collecting into `vri`.
    fn walk(&mut self, start: Certificate, vri: &mut Vri) -> Result<(), SealError> {
        let mut cur = start;
        let mut hops = 0usize;
        loop {
            hops = hops.saturating_add(1);
            if hops > 32 {
                return Err(SealError::Revocation(RevocationProblem::TooMany));
            }
            let i = push_unique(&mut self.certs, cur.clone())?;
            note(&mut vri.certs, i);
            if self_signed(&cur) || self.is_anchor(&cur) {
                return Ok(());
            }
            let issuer = self.issuer_of(&cur).ok_or(SealError::Revocation(
                RevocationProblem::IssuerNotFound { index: i },
            ))?;
            let a = self.answer(&cur, &issuer)?;
            if let Some(o) = a.ocsp {
                note(&mut vri.ocsps, o);
            }
            if let Some(c) = a.crl {
                note(&mut vri.crls, c);
            }
            for r in a.responders {
                let ri = push_unique(&mut self.certs, r.clone())?;
                note(&mut vri.certs, ri);
                if !has_nocheck(&r) {
                    // A delegated responder without nocheck: its issuer's CRL must show it
                    // unrevoked (RFC 6960 §4.2.2.2.1).
                    let crl = self.crl_for(&r, &issuer)?.ok_or(SealError::Revocation(
                        RevocationProblem::NoAnswer { index: ri },
                    ))?;
                    note(&mut vri.crls, crl);
                }
            }
            cur = issuer;
        }
    }
}

/// An existing DSS array's references and their decoded bytes.
fn existing_items(
    doc: &mut casual_sign_pdf::Document<'_>,
    dss: &Dictionary,
    key: &[u8],
) -> Result<Vec<(ObjRef, Vec<u8>)>, SealError> {
    let mut out = Vec::new();
    let items = match form::array_holder(doc, dss.get(key))? {
        Holder::Absent => return Ok(out),
        Holder::Direct(a) | Holder::Indirect(_, a) => a,
    };
    for item in items.iter().take(MAX_ITEMS) {
        if let Some(r) = item.as_ref() {
            let bytes = doc.decode_stream(r.num, &never).unwrap_or_default();
            out.push((r, bytes));
        }
    }
    Ok(out)
}

/// Append a DSS revision to `input` with validation data for each of `targets` (the
/// decoded `/Contents` strings of signatures or document timestamps), checked at `at`.
/// Issuers are looked for in each target's CMS, the source's certificates and `trust`.
pub(crate) fn add_dss(
    input: &[u8],
    targets: &[Vec<u8>],
    at: Duration,
    source: &dyn RevocationSource,
    trust: &TrustStore,
    limits: &Limits,
) -> Result<(Vec<u8>, DssReport), SealError> {
    let mut pool: Vec<Certificate> = source.certificates().to_vec();
    for c in trust.certificates() {
        if !pool.contains(c) {
            pool.push(c.clone());
        }
    }
    let mut collector = Collector {
        source,
        at,
        anchors: trust.anchors().cloned().collect(),
        pool,
        certs: Vec::new(),
        ocsps: Vec::new(),
        crls: Vec::new(),
        answers: Vec::new(),
    };
    let mut per_target: Vec<(String, Vri)> = Vec::new();
    for contents in targets {
        let carried = certificates_of(contents)?;
        for c in &carried {
            if !collector.pool.contains(c) {
                collector.pool.push(c.clone());
            }
        }
        let mut vri = Vri::default();
        for c in carried {
            collector.walk(c, &mut vri)?;
        }
        per_target.push((vri_key(contents), vri));
    }

    let mut admitted = admit_for_update(input, limits, true)?;
    let doc = &mut admitted.document;
    let (catalog_num, mut catalog) = form::catalog(doc)?;
    let dss_holder = match catalog.get(b"DSS") {
        None | Some(Object::Null) => Holder::Absent,
        Some(Object::Dictionary(d)) => Holder::Direct(d.clone()),
        Some(Object::Reference(r)) => Holder::Indirect(r.num, form::dict_object(doc, r.num)?),
        Some(_) => {
            return Err(SealError::Request(crate::error::RequestProblem::Structure(
                catalog_num,
            )));
        }
    };
    let mut dss = match &dss_holder {
        Holder::Absent => Dictionary::new(),
        Holder::Direct(d) | Holder::Indirect(_, d) => d.clone(),
    };
    let old_certs = existing_items(doc, &dss, b"Certs")?;
    let old_ocsps = existing_items(doc, &dss, b"OCSPs")?;
    let old_crls = existing_items(doc, &dss, b"CRLs")?;
    let mut vri_dict = match dss.get(b"VRI") {
        Some(Object::Dictionary(d)) => d.clone(),
        Some(Object::Reference(r)) => match doc.object(r.num, &never)? {
            Object::Dictionary(d) => d,
            _ => Dictionary::new(),
        },
        _ => Dictionary::new(),
    };

    let mut u = IncrementalUpdate::new(&admitted, Change::FillAndSign)?;
    let mut report = DssReport::default();
    let write = |u: &mut IncrementalUpdate<'_>,
                 old: &[(ObjRef, Vec<u8>)],
                 new: &[Vec<u8>],
                 count: &mut usize|
     -> Result<(Vec<Object>, Vec<ObjRef>), SealError> {
        let mut all: Vec<Object> = old.iter().map(|(r, _)| Object::Reference(*r)).collect();
        let mut refs = Vec::with_capacity(new.len());
        for item in new {
            let r = match old.iter().find(|(_, b)| b == item) {
                Some((r, _)) => *r,
                None => {
                    let r = u.add_stream(Dictionary::new(), item.clone())?;
                    all.push(Object::Reference(r));
                    *count = count.saturating_add(1);
                    r
                }
            };
            refs.push(r);
        }
        Ok((all, refs))
    };
    let cert_ders = collector
        .certs
        .iter()
        .map(der_of)
        .collect::<Result<Vec<_>, _>>()?;
    let (certs_all, cert_refs) = write(&mut u, &old_certs, &cert_ders, &mut report.certificates)?;
    let (ocsps_all, ocsp_refs) = write(
        &mut u,
        &old_ocsps,
        &collector.ocsps,
        &mut report.ocsp_responses,
    )?;
    let (crls_all, crl_refs) = write(&mut u, &old_crls, &collector.crls, &mut report.crls)?;

    let pick = |refs: &[ObjRef], idx: &[usize]| -> Vec<Object> {
        idx.iter()
            .filter_map(|&i| refs.get(i).copied().map(Object::Reference))
            .collect()
    };
    let mut seen = BTreeMap::new();
    for (key, vri) in &per_target {
        let mut entry = Dictionary::new();
        for (k, list) in [
            (&b"Cert"[..], pick(&cert_refs, &vri.certs)),
            (b"OCSP", pick(&ocsp_refs, &vri.ocsps)),
            (b"CRL", pick(&crl_refs, &vri.crls)),
        ] {
            if !list.is_empty() {
                entry.insert(k, Object::Array(list));
            }
        }
        vri_dict.insert(key.as_bytes(), Object::Dictionary(entry));
        if seen.insert(key.clone(), ()).is_none() {
            report.vri_keys.push(key.clone());
        }
    }
    for (k, all) in [
        (&b"Certs"[..], certs_all),
        (b"OCSPs", ocsps_all),
        (b"CRLs", crls_all),
    ] {
        if !all.is_empty() {
            dss.insert(k, Object::Array(all));
        }
    }
    dss.insert(b"VRI", Object::Dictionary(vri_dict));
    match dss_holder {
        Holder::Indirect(n, _) => u.replace(n, Object::Dictionary(dss))?,
        Holder::Direct(_) | Holder::Absent => {
            let r = u.add(Object::Dictionary(dss))?;
            catalog.insert(b"DSS", Object::Reference(r));
            u.replace(catalog_num, Object::Dictionary(catalog))?;
        }
    }
    Ok((u.finish()?, report))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vri_key_is_upper_hex_sha1_of_the_whole_contents() {
        // FIPS 180-2 test vector: SHA-1("abc").
        assert_eq!(vri_key(b"abc"), "A9993E364706816ABA3E25717850C26C9CD0D89D");
        // Padding is part of the string, so it changes the key.
        assert_ne!(vri_key(b"abc\0"), vri_key(b"abc"));
    }
}
