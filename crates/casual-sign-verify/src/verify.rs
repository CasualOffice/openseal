//! The verification flow: read the document, check each signature, classify revisions,
//! and combine the checks into an ETSI EN 319 102-1 verdict (docs/31 §7).

use core::time::Duration;

use casual_sign_crypto::cms::ParsedCms;
use casual_sign_crypto::tsp::{TimestampToken, verify_timestamp_token};
use casual_sign_crypto::{CryptoError, DigestAlgorithm, SignedAttribute, TimestampFailure};
use casual_sign_pdf::{Document, Limits, Object, Revision, SignatureInfo, admit};

use crate::byterange::{self, Checked, Problem};
use crate::chain::{self, Cert, ChainFailure, Purpose};
use crate::diff::{self, Locks};
use crate::report::{
    Check, Checks, Disallowed, DocumentError, Indication, ModificationClass, Reason,
    RevisionChanges, SignatureKind, SignatureReport, SubIndication, TimeSource, TimestampInfo,
    VerificationReport,
};
use crate::revocation::{self, RevocationData, State};
use crate::{TimePolicy, TrustStore, VerifyOptions};

const BYTE_RANGE: &str = "CS-VER-0001";
const DIGEST: &str = "CS-VER-0002";
const CMS: &str = "CS-VER-0003";
const CHAIN: &str = "CS-VER-0004";
const REVOKED_OR_EXPIRED: &str = "CS-VER-0005";
const TIMESTAMP: &str = "CS-VER-0006";
const MODIFIED: &str = "CS-VER-0007";
const REVOCATION_DATA: &str = "CS-SEAL-0004";
const ALGORITHM: &str = "CS-SEAL-0005";

/// Most DSS entries read per array, bounding work on a hostile DSS.
const MAX_DSS_ITEMS: usize = 4096;

fn no_cancel() -> bool {
    false
}

const fn reason(sub: SubIndication, code: &'static str) -> Reason {
    Reason { sub, code }
}

/// One signature found in the document, before verification.
struct Candidate {
    info: SignatureInfo,
    contents: Vec<u8>,
    raw: Option<[u64; 4]>,
    br: Result<Checked, Problem>,
    kind: SignatureKind,
    sub_filter: Option<String>,
    locks: Locks,
    order: u64,
}

fn resolve(doc: &mut Document<'_>, o: Option<&Object>) -> Object {
    match o {
        Some(o) => doc.resolve(o, &no_cancel).unwrap_or(Object::Null),
        None => Object::Null,
    }
}

fn candidate(
    doc: &mut Document<'_>,
    info: &SignatureInfo,
    bytes: &[u8],
    revisions: &[Revision],
) -> Option<Candidate> {
    let field = match info.field {
        Some(n) => doc.object(n, &no_cancel).unwrap_or(Object::Null),
        None => Object::Null,
    };
    let value = match info.value {
        Some(n) => doc.object(n, &no_cancel).unwrap_or(Object::Null),
        None => field.get(b"V").cloned().unwrap_or(Object::Null),
    };
    let dict = value.dict()?.clone();
    let contents = match dict.get(b"Contents") {
        Some(Object::String(s)) => s.clone(),
        _ => Vec::new(),
    };
    let raw = byterange::read(dict.get(b"ByteRange")).ok();
    let br = match raw {
        Some(r) => byterange::check(r, bytes, &contents, revisions),
        None => Err(Problem::Shape),
    };
    let sub_filter = dict
        .name(b"SubFilter")
        .map(|s| String::from_utf8_lossy(s).into_owned());
    let mut locks = Locks::default();
    let mut docmdp = None;
    if let Object::Array(refs) = resolve(doc, dict.get(b"Reference")) {
        for r in refs.iter().take(64) {
            let r = resolve(doc, Some(r));
            let params = resolve(doc, r.get(b"TransformParams"));
            match r.get(b"TransformMethod").and_then(Object::as_name) {
                Some(b"DocMDP") => {
                    let p = params.get(b"P").and_then(Object::as_i64).unwrap_or(2);
                    docmdp = Some(u8::try_from(p.clamp(1, 3)).unwrap_or(2));
                }
                Some(b"FieldMDP") => {
                    if let Some(d) = params.dict() {
                        locks.add(d);
                    }
                }
                _ => {}
            }
        }
    }
    if let Object::Dictionary(lock) = resolve(doc, field.get(b"Lock")) {
        locks.add(&lock);
    }
    let is_doc_ts = dict.name(b"Type") == Some(b"DocTimeStamp")
        || sub_filter.as_deref() == Some("ETSI.RFC3161");
    let kind = if is_doc_ts {
        SignatureKind::DocumentTimestamp
    } else if let Some(p) = docmdp {
        SignatureKind::Certification { permissions: p }
    } else {
        SignatureKind::Approval
    };
    let order = match (&br, raw) {
        (Ok(c), _) => u64::try_from(c.end).unwrap_or(u64::MAX),
        (Err(_), Some([_, _, c, d])) => c.saturating_add(d),
        (Err(_), None) => u64::MAX,
    };
    Some(Candidate {
        info: info.clone(),
        contents,
        raw,
        br,
        kind,
        sub_filter,
        locks,
        order,
    })
}

/// Certificates and revocation data in the document's `/DSS` (ISO 32000-2 §12.8.4.3).
fn dss(doc: &mut Document<'_>) -> (Vec<Cert>, RevocationData) {
    let mut certs = Vec::new();
    let mut data = RevocationData::default();
    let trailer = doc.trailer().clone();
    let catalog = resolve(doc, trailer.get(b"Root"));
    let dss = resolve(doc, catalog.get(b"DSS"));
    let Some(dss) = dss.dict().cloned() else {
        return (certs, data);
    };
    let mut lists: Vec<(u8, Object)> = Vec::new();
    for (key, which) in [(&b"Certs"[..], 0u8), (b"OCSPs", 1), (b"CRLs", 2)] {
        lists.push((which, resolve(doc, dss.get(key))));
    }
    if let Object::Dictionary(vri) = resolve(doc, dss.get(b"VRI")) {
        for (_, entry) in vri.iter().take(MAX_DSS_ITEMS) {
            let entry = resolve(doc, Some(entry));
            for (key, which) in [(&b"Cert"[..], 0u8), (b"OCSP", 1), (b"CRL", 2)] {
                lists.push((which, resolve(doc, entry.get(key))));
            }
        }
    }
    for (which, list) in lists {
        let Object::Array(items) = list else { continue };
        for item in items.iter().take(MAX_DSS_ITEMS) {
            let Some(r) = item.as_ref() else { continue };
            let Ok(raw) = doc.decode_stream(r.num, &no_cancel) else {
                continue;
            };
            match which {
                0 => {
                    if !certs.iter().any(|c: &Cert| c.der == raw)
                        && let Some(c) = Cert::from_der(&raw)
                    {
                        certs.push(c);
                    }
                }
                1 => {
                    if !data.ocsps.contains(&raw) {
                        data.ocsps.push(raw);
                    }
                }
                _ => {
                    if !data.crls.contains(&raw) {
                        data.crls.push(raw);
                    }
                }
            }
        }
    }
    (certs, data)
}

/// The document as of the revision ending at `end`.
fn prefix<'a>(bytes: &'a [u8], end: u64, limits: &Limits) -> Option<Document<'a>> {
    let end = usize::try_from(end).ok()?;
    let b = bytes.get(..end)?;
    admit(b, limits, &no_cancel).ok().map(|a| a.document)
}

/// Classify every revision after `first` against the one before it.
fn changes(
    bytes: &[u8],
    revisions: &[Revision],
    first: usize,
    cands: &[Candidate],
    limits: &Limits,
) -> Vec<RevisionChanges> {
    let mut docs: Vec<Option<Document<'_>>> = revisions
        .iter()
        .enumerate()
        .map(|(k, r)| {
            if k < first {
                None
            } else {
                prefix(bytes, r.end_offset, limits)
            }
        })
        .collect();
    let mut out = Vec::new();
    for k in first.saturating_add(1)..revisions.len() {
        let before: Vec<&Candidate> = cands
            .iter()
            .filter(|c| c.br.as_ref().is_ok_and(|b| b.revision < k))
            .collect();
        let mut locks = Locks::default();
        for c in &before {
            if c.locks.all {
                locks.all = true;
            }
            locks.include.extend(c.locks.include.iter().cloned());
            if let Some(e) = &c.locks.exclude {
                locks.exclude = Some(match locks.exclude.take() {
                    None => e.clone(),
                    Some(prev) => prev.intersection(e).cloned().collect(),
                });
            }
        }
        let docmdp = before.iter().find_map(|c| match c.kind {
            SignatureKind::Certification { permissions } => Some(permissions),
            _ => None,
        });
        let (lo, hi) = docs.split_at_mut(k);
        let classes = match (lo.last_mut(), hi.first_mut()) {
            (Some(Some(a)), Some(Some(b))) => diff::classify(a, b, bytes, &locks),
            _ => vec![ModificationClass::Disallowed(Disallowed::Unreadable)],
        };
        out.push(RevisionChanges {
            revision: k,
            classes: diff::apply_docmdp(classes, docmdp),
        });
    }
    // Bytes after the last revision that are not a revision: unsigned and unexplained.
    let last_end = revisions
        .last()
        .and_then(|r| usize::try_from(r.end_offset).ok())
        .unwrap_or(0);
    if bytes.get(last_end..).is_some_and(|rest| {
        rest.iter()
            .any(|b| !matches!(b, b' ' | b'\t' | b'\r' | b'\n' | b'\x0c' | b'\0'))
    }) {
        out.push(RevisionChanges {
            revision: revisions.len(),
            classes: vec![ModificationClass::Disallowed(Disallowed::Unreadable)],
        });
    }
    out
}

/// Shared state for verifying each signature.
struct Ctx<'a> {
    bytes: &'a [u8],
    trust: &'a TrustStore,
    options: &'a VerifyOptions,
    pool: Vec<Cert>,
    revocation: RevocationData,
    changes: Vec<RevisionChanges>,
}

pub(crate) fn run(bytes: &[u8], trust: &TrustStore, options: &VerifyOptions) -> VerificationReport {
    let admitted = match admit(bytes, &options.limits, &no_cancel) {
        Ok(a) => a,
        Err(e) => {
            return VerificationReport {
                error: Some(DocumentError { code: e.code() }),
                revisions: 0,
                signatures: Vec::new(),
                revision_changes: Vec::new(),
                covered_by_last_signature: false,
            };
        }
    };
    let report = admitted.report;
    let mut document = admitted.document;
    let revisions = report.revisions.clone();

    let mut cands: Vec<Candidate> = Vec::new();
    for info in &report.signatures {
        if info.value.is_some() && cands.iter().any(|c| c.info.value == info.value) {
            continue;
        }
        if let Some(c) = candidate(&mut document, info, bytes, &revisions) {
            cands.push(c);
        }
    }
    cands.sort_by_key(|c| c.order);

    let (dss_certs, mut revocation) = dss(&mut document);
    revocation
        .ocsps
        .extend(options.ocsp_responses.iter().cloned());
    revocation.crls.extend(options.crls.iter().cloned());
    let mut pool = dss_certs;
    pool.extend(trust.intermediates.iter().cloned());

    let first = cands
        .iter()
        .filter_map(|c| c.br.as_ref().ok().map(|b| b.revision))
        .min();
    let changes = match first {
        Some(r) => changes(bytes, &revisions, r, &cands, &options.limits),
        None => Vec::new(),
    };
    let ctx = Ctx {
        bytes,
        trust,
        options,
        pool,
        revocation,
        changes,
    };

    // Last first, so each signature knows the earliest later document timestamp.
    let mut reports = Vec::with_capacity(cands.len());
    let mut poe: Option<Duration> = None;
    for c in cands.iter().rev() {
        let covering = match options.time_policy {
            TimePolicy::ProofOfExistence => poe,
            TimePolicy::ValidationTime => None,
        };
        let (r, own) = verify_one(&ctx, c, covering);
        if let Some(t) = own {
            poe = Some(poe.map_or(t, |p| p.min(t)));
        }
        reports.push(r);
    }
    reports.reverse();

    let covered_by_last_signature = cands
        .last()
        .is_some_and(|c| c.br.as_ref().is_ok_and(|b| b.whole_file));
    VerificationReport {
        error: None,
        revisions: revisions.len(),
        signatures: reports,
        revision_changes: ctx.changes,
        covered_by_last_signature,
    }
}

/// Verify a timestamp token over `data`, trying each digest algorithm we accept for the
/// imprint (the token names its own; the crypto crate checks it equals ours).
fn verify_token(token: &[u8], data: &[&[u8]]) -> Result<TimestampToken, CryptoError> {
    for alg in [
        DigestAlgorithm::Sha256,
        DigestAlgorithm::Sha384,
        DigestAlgorithm::Sha512,
    ] {
        let mut h = casual_sign_crypto::Hasher::new(alg);
        for d in data {
            h.update(d);
        }
        match verify_timestamp_token(token, &h.finish()) {
            Err(CryptoError::TimestampToken(TimestampFailure::ImprintMismatch)) => {}
            r => return r,
        }
    }
    Err(CryptoError::TimestampToken(
        TimestampFailure::ImprintMismatch,
    ))
}

/// The verdict builder: failures as they are found, the first total failure wins, then the
/// first indeterminate.
#[derive(Default)]
struct Verdict {
    total: Option<Reason>,
    indeterminate: Option<Reason>,
}

impl Verdict {
    fn fail(&mut self, r: Reason) -> Check {
        if self.total.is_none() {
            self.total = Some(r);
        }
        Check::Failed(r)
    }

    fn unsure(&mut self, r: Reason) -> Check {
        if self.indeterminate.is_none() {
            self.indeterminate = Some(r);
        }
        Check::Failed(r)
    }

    fn indication(&self) -> Indication {
        match (self.total, self.indeterminate) {
            (Some(r), _) => Indication::TotalFailed(r),
            (None, Some(r)) => Indication::Indeterminate(r),
            (None, None) => Indication::TotalPassed,
        }
    }
}

/// Map a chain failure: expiry or not-yet-valid at a proven time, or with nothing proven.
fn chain_failure(v: &mut Verdict, f: ChainFailure, proven: bool) -> Check {
    match f {
        ChainFailure::NoChain => v.unsure(reason(SubIndication::NoCertificateChainFound, CHAIN)),
        ChainFailure::Constraints => {
            v.unsure(reason(SubIndication::ChainConstraintsFailure, CHAIN))
        }
        ChainFailure::OutOfValidity {
            index: 0,
            before: true,
        } if proven => v.fail(reason(SubIndication::NotYetValid, REVOKED_OR_EXPIRED)),
        ChainFailure::OutOfValidity { .. } => {
            v.unsure(reason(SubIndication::OutOfBoundsNoPoe, REVOKED_OR_EXPIRED))
        }
    }
}

/// Revocation of every certificate but the anchor in `path` at `at`.
fn revocation_check(ctx: &Ctx<'_>, v: &mut Verdict, path: &[Cert], at: Duration) -> Check {
    for pair in path.windows(2) {
        let [cert, issuer] = pair else { continue };
        if cert.has_extension(chain::OCSP_NOCHECK) {
            continue;
        }
        match revocation::status(cert, issuer, at, &ctx.revocation) {
            State::Good => {}
            // ETSI EN 319 102-1 §5.5.4: a certificate revoked before the best signature
            // time stays INDETERMINATE/REVOKED_NO_POE (EU DSS agrees); a proof of existence
            // before the revocation is what passes, and then the status asked is good.
            State::Revoked(_) => {
                return v.unsure(reason(SubIndication::RevokedNoPoe, REVOKED_OR_EXPIRED));
            }
            State::Missing => return v.unsure(reason(SubIndication::TryLater, REVOCATION_DATA)),
            State::Unsupported => {
                return v.unsure(reason(SubIndication::CryptoConstraintsFailure, ALGORITHM));
            }
        }
    }
    Check::Passed
}

/// A TSA's chain: valid at `gen_time` and at `poe` (when it must still be valid), and its
/// revocation at `gen_time`. Returns (chain check, revocation check).
fn tsa_checks(
    ctx: &Ctx<'_>,
    v: &mut Verdict,
    tst: &TimestampToken,
    poe: Duration,
) -> (Check, Check) {
    let mut pool = ctx.pool.clone();
    if let Ok(p) = ParsedCms::parse(tst.as_der()) {
        pool.extend(p.certificates().filter_map(Cert::from_parsed));
    }
    let Some(tsa) = Cert::from_parsed(tst.tsa_certificate()) else {
        return (
            v.unsure(reason(SubIndication::NoCertificateChainFound, CHAIN)),
            Check::NotRun,
        );
    };
    let Some(path) = chain::build(&tsa, &pool, &ctx.trust.anchors) else {
        return (
            v.unsure(reason(SubIndication::NoCertificateChainFound, CHAIN)),
            Check::NotRun,
        );
    };
    for at in [tst.gen_time(), poe] {
        if let Err(f) = chain::validate(&path, at, Purpose::Tsa) {
            return (chain_failure(v, f, false), Check::NotRun);
        }
    }
    let rev = revocation_check(ctx, v, &path, tst.gen_time());
    (Check::Passed, rev)
}

fn verify_one(
    ctx: &Ctx<'_>,
    c: &Candidate,
    covering: Option<Duration>,
) -> (SignatureReport, Option<Duration>) {
    let mut v = Verdict::default();
    let mut checks = Checks::default();
    let mut report = SignatureReport {
        field: c.info.field,
        value: c.info.value,
        sub_filter: c.sub_filter.clone(),
        kind: c.kind,
        byte_range: c.raw,
        signed_revision: c.br.as_ref().ok().map(|b| b.revision),
        covers_whole_document: c.br.as_ref().is_ok_and(|b| b.whole_file),
        indication: Indication::TotalPassed,
        checks,
        validation_time: ctx.options.validation_time,
        time_source: TimeSource::ValidationTime,
        timestamp: None,
        modifications_after: Vec::new(),
    };
    let finish = |mut report: SignatureReport, v: &Verdict, checks: Checks| {
        report.indication = v.indication();
        report.checks = checks;
        report
    };

    let br = match &c.br {
        Ok(b) => {
            checks.byte_range = Check::Passed;
            b
        }
        Err(_) => {
            checks.byte_range = v.fail(reason(SubIndication::FormatFailure, BYTE_RANGE));
            return (finish(report, &v, checks), None);
        }
    };

    // Modifications after the signed revision (decided before the cryptography so the
    // report lists them even for a broken signature).
    report.modifications_after = ctx
        .changes
        .iter()
        .filter(|ch| ch.revision > br.revision)
        .cloned()
        .collect();
    let modified = report.modifications_after.iter().any(|ch| !ch.allowed());

    let [r0, r1] = &br.ranges;
    let (Some(part0), Some(part1)) = (ctx.bytes.get(r0.clone()), ctx.bytes.get(r1.clone())) else {
        checks.byte_range = v.fail(reason(SubIndication::FormatFailure, BYTE_RANGE));
        return (finish(report, &v, checks), None);
    };

    let validation_time = ctx.options.validation_time;
    let mut own_poe = None;
    match (c.kind, c.sub_filter.as_deref()) {
        (SignatureKind::DocumentTimestamp, Some("ETSI.RFC3161") | None) => {
            // `/Contents` is zero-padded after the token: exactly one TLV, then zeros.
            let token = chain::tlv_len(&c.contents)
                .and_then(|n| c.contents.split_at_checked(n))
                .filter(|(_, pad)| pad.iter().all(|&b| b == 0))
                .map_or(&[][..], |(t, _)| t);
            match verify_token(token, &[part0, part1]) {
                Ok(tst) => {
                    checks.digest = Check::Passed;
                    checks.signature = Check::Passed;
                    checks.timestamp = Check::Passed;
                    report.timestamp = Some(TimestampInfo {
                        gen_time: tst.gen_time(),
                    });
                    let poe = covering.unwrap_or(validation_time);
                    report.validation_time = poe;
                    report.time_source = if covering.is_some() {
                        TimeSource::DocumentTimestamp
                    } else {
                        TimeSource::ValidationTime
                    };
                    let (ch, rev) = tsa_checks(ctx, &mut v, &tst, poe);
                    checks.chain = ch;
                    checks.revocation = rev;
                    if ch.passed() {
                        own_poe = Some(tst.gen_time());
                    }
                }
                Err(e) => {
                    let (digest, sig, ts) = token_failure(&mut v, e);
                    checks.digest = digest;
                    checks.signature = sig;
                    checks.timestamp = ts;
                }
            }
        }
        (
            SignatureKind::Approval | SignatureKind::Certification { .. },
            Some("ETSI.CAdES.detached" | "adbe.pkcs7.detached"),
        ) => cms_signature(
            ctx,
            &mut v,
            &mut checks,
            &mut report,
            c,
            [part0, part1],
            covering,
        ),
        (_, Some("adbe.pkcs7.sha1" | "adbe.x509.rsa_sha1")) => {
            checks.signature = v.unsure(reason(SubIndication::CryptoConstraintsFailure, ALGORITHM));
        }
        _ => {
            checks.signature = v.unsure(reason(SubIndication::FormatFailure, CMS));
        }
    }

    // Integrity failures found above stay first: `fail` keeps the earliest.
    checks.modifications = if modified {
        v.fail(reason(SubIndication::DisallowedModification, MODIFIED))
    } else {
        Check::Passed
    };
    (finish(report, &v, checks), own_poe)
}

/// How a refused token maps to (digest, signature, timestamp) checks.
fn token_failure(v: &mut Verdict, e: CryptoError) -> (Check, Check, Check) {
    match e {
        CryptoError::TimestampToken(TimestampFailure::ImprintMismatch) => {
            let r = v.fail(reason(SubIndication::HashFailure, DIGEST));
            (r, Check::NotRun, r)
        }
        CryptoError::TimestampToken(
            TimestampFailure::Signature
            | TimestampFailure::TokenDigest
            | TimestampFailure::SigningCertificate,
        ) => {
            let r = v.fail(reason(SubIndication::SigCryptoFailure, TIMESTAMP));
            (Check::Passed, r, r)
        }
        CryptoError::TimestampToken(TimestampFailure::NotTimestampingCertificate) => {
            let r = v.unsure(reason(SubIndication::ChainConstraintsFailure, TIMESTAMP));
            (Check::Passed, Check::Passed, r)
        }
        CryptoError::UnsupportedAlgorithm => {
            let r = v.unsure(reason(SubIndication::CryptoConstraintsFailure, ALGORITHM));
            (Check::NotRun, r, r)
        }
        _ => {
            let r = v.fail(reason(SubIndication::FormatFailure, TIMESTAMP));
            (Check::NotRun, r, r)
        }
    }
}

fn cms_signature(
    ctx: &Ctx<'_>,
    v: &mut Verdict,
    checks: &mut Checks,
    report: &mut SignatureReport,
    c: &Candidate,
    parts: [&[u8]; 2],
    covering: Option<Duration>,
) {
    let cms = match ParsedCms::parse(&c.contents) {
        Ok(cms) => cms,
        Err(CryptoError::UnsupportedAlgorithm) => {
            checks.signature = v.unsure(reason(SubIndication::CryptoConstraintsFailure, ALGORITHM));
            return;
        }
        Err(_) => {
            checks.signature = v.fail(reason(SubIndication::FormatFailure, CMS));
            return;
        }
    };
    let mut h = casual_sign_crypto::Hasher::new(cms.digest_algorithm());
    for p in parts {
        h.update(p);
    }
    let digest = h.finish();
    let signer = match cms.verify_detached(&digest) {
        Ok(s) => {
            checks.digest = Check::Passed;
            checks.signature = Check::Passed;
            s.certificate
        }
        Err(CryptoError::DigestMismatch) => {
            checks.digest = v.fail(reason(SubIndication::HashFailure, DIGEST));
            return;
        }
        Err(CryptoError::SignatureInvalid) => {
            checks.digest = Check::Passed;
            checks.signature = v.fail(reason(SubIndication::SigCryptoFailure, CMS));
            return;
        }
        Err(CryptoError::SignerCertificateNotFound | CryptoError::SigningCertificateMismatch) => {
            checks.digest = Check::Passed;
            checks.signature = v.unsure(reason(SubIndication::NoSigningCertificateFound, CMS));
            return;
        }
        Err(CryptoError::MissingSignedAttribute(SignedAttribute::SigningCertificateV2)) => {
            // The digest is checked before the ESS attribute. A legacy
            // `adbe.pkcs7.detached` signer need not carry it; casual-sign-crypto cannot
            // verify such a signature yet (reported in T-1H), so it is not concluded.
            checks.digest = Check::Passed;
            checks.signature = if c.sub_filter.as_deref() == Some("adbe.pkcs7.detached") {
                v.unsure(reason(SubIndication::FormatFailure, CMS))
            } else {
                v.fail(reason(SubIndication::FormatFailure, CMS))
            };
            return;
        }
        Err(CryptoError::UnsupportedAlgorithm) => {
            checks.signature = v.unsure(reason(SubIndication::CryptoConstraintsFailure, ALGORITHM));
            return;
        }
        Err(_) => {
            checks.signature = v.fail(reason(SubIndication::FormatFailure, CMS));
            return;
        }
    };

    let mut pool: Vec<Cert> = cms.certificates().filter_map(Cert::from_parsed).collect();
    pool.extend(ctx.pool.iter().cloned());
    let validation_time = ctx.options.validation_time;
    let proof_policy = ctx.options.time_policy == TimePolicy::ProofOfExistence;

    // The signature timestamp.
    let mut tst = None;
    match cms.timestamp_token() {
        Ok(None) => {}
        Ok(Some(token)) => {
            let value = cms.signature_value().unwrap_or_default();
            match verify_token(&token, &[value]) {
                Ok(t) => {
                    checks.timestamp = Check::Passed;
                    report.timestamp = Some(TimestampInfo {
                        gen_time: t.gen_time(),
                    });
                    tst = Some(t);
                }
                Err(CryptoError::UnsupportedAlgorithm) => {
                    checks.timestamp =
                        v.unsure(reason(SubIndication::CryptoConstraintsFailure, ALGORITHM));
                }
                Err(_) => {
                    checks.timestamp =
                        v.unsure(reason(SubIndication::SigConstraintsFailure, TIMESTAMP));
                }
            }
        }
        Err(_) => {
            checks.timestamp = v.unsure(reason(SubIndication::SigConstraintsFailure, TIMESTAMP));
        }
    }

    // The time the signer is judged at.
    let mut at = validation_time;
    let mut source = TimeSource::ValidationTime;
    if proof_policy {
        if let Some(t) = &tst
            && t.gen_time() < at
        {
            at = t.gen_time();
            source = TimeSource::SignatureTimestamp;
        }
        if let Some(p) = covering
            && p < at
        {
            at = p;
            source = TimeSource::DocumentTimestamp;
        }
    }
    report.validation_time = at;
    report.time_source = source;
    let proven = source != TimeSource::ValidationTime;

    let Some(signer) = Cert::from_parsed(&signer) else {
        checks.chain = v.unsure(reason(SubIndication::NoSigningCertificateFound, CMS));
        return;
    };
    let mut chain_check = Check::Passed;
    let mut rev_check = Check::Passed;
    match chain::build(&signer, &pool, &ctx.trust.anchors) {
        None => chain_check = v.unsure(reason(SubIndication::NoCertificateChainFound, CHAIN)),
        Some(path) => match chain::validate(&path, at, Purpose::Signer) {
            Err(f) => chain_check = chain_failure(v, f, proven),
            Ok(()) => rev_check = revocation_check(ctx, v, &path, at),
        },
    }
    if let Some(t) = &tst {
        let tsa_poe = if proof_policy {
            covering.unwrap_or(validation_time)
        } else {
            validation_time
        };
        let (tc, tr) = tsa_checks(ctx, v, t, tsa_poe);
        if chain_check.passed() {
            chain_check = tc;
        }
        if rev_check.passed() {
            rev_check = tr;
        }
    }
    checks.chain = chain_check;
    checks.revocation = if chain_check.passed() || rev_check != Check::Passed {
        rev_check
    } else {
        Check::NotRun
    };
}
