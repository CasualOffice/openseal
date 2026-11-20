//! A frozen copy of `seal()` and the revision writer as they stood before the
//! `prepare`/`complete` split (ADR-046 §3.3, `RSP-01` gate 1), kept only for the test
//! that proves `seal()` still writes the same bytes. Never edit it to follow a change:
//! a difference is what the test exists to catch.

use casual_sign_crypto::KeyProvider;
use casual_sign_crypto::cms::{max_der_len, sign_detached};
use casual_sign_pdf::{Change, IncrementalUpdate, Object};
use casual_sign_verify::SignatureKind;

use crate::check::{self, Expect};
use crate::error::{LayoutProblem, RequestProblem, SealError};
use crate::form::{self, FieldSpec};
use crate::revision::{
    BR_FILLER, BR_PLACEHOLDER, MARGIN, MAX_PLACEHOLDER, RevisionSpec, ToSign, Written,
    admit_for_update, fill_byte_range, find_once,
};
use crate::{
    Layout, Profile, RevocationSource, SealKind, SealReport, SealRequest, Sealed, TimestampSource,
    VerificationReport, document_timestamp, dss, revision_count, signature_head, take_timestamp,
    vri_key,
};

/// Write one revision with a `/Contents` placeholder of `placeholder` bytes, and fill it
/// with the DER `content` returns for the signed bytes.
fn write_once_reference(
    input: &[u8],
    spec: &RevisionSpec<'_>,
    placeholder: usize,
    content: &mut dyn FnMut(ToSign<'_>) -> Result<Vec<u8>, SealError>,
) -> Result<Written, SealError> {
    let mut admitted = admit_for_update(input, spec.limits, spec.archival)?;
    let plan = form::plan(&mut admitted, spec.field)?;
    let mut u = IncrementalUpdate::new(&admitted, Change::FillAndSign)?;
    let mut dict = spec.head.clone();
    dict.insert(
        b"ByteRange",
        Object::Array(vec![
            Object::Integer(0),
            Object::Integer(BR_FILLER),
            Object::Integer(BR_FILLER),
            Object::Integer(BR_FILLER),
        ]),
    );
    dict.insert(b"Contents", Object::String(vec![0u8; placeholder]));
    let value = u.add(Object::Dictionary(dict))?;
    form::apply(&mut u, plan, value, spec.certification)?;
    let mut out = u.finish()?;

    // Find the placeholder in the update only: `/ByteRange [...]/Contents <00…>` as the
    // serializer writes it, exactly once.
    let hex_len = placeholder.saturating_mul(2);
    let mut needle = Vec::with_capacity(hex_len.saturating_add(64));
    needle.extend_from_slice(b"/ByteRange ");
    needle.extend_from_slice(BR_PLACEHOLDER);
    needle.extend_from_slice(b"/Contents <");
    needle.resize(needle.len().saturating_add(hex_len), b'0');
    needle.push(b'>');
    let update = out.get(input.len()..).unwrap_or_default();
    let rel =
        find_once(update, &needle).map_err(|n| SealError::Layout(LayoutProblem::Placeholder(n)))?;
    let br_at = input
        .len()
        .saturating_add(rel)
        .saturating_add(b"/ByteRange ".len());
    let a = br_at
        .saturating_add(BR_PLACEHOLDER.len())
        .saturating_add(b"/Contents ".len());
    let b = a.saturating_add(hex_len).saturating_add(2);
    let c = out.len().saturating_sub(b);
    let to_u64 = |v: usize| u64::try_from(v).unwrap_or(u64::MAX);
    fill_byte_range(&mut out, br_at, [to_u64(a), to_u64(b), to_u64(c)])?;

    let der = content(ToSign {
        bytes: &out,
        ranges: [0..a, b..out.len()],
    })?;
    if der.len() > placeholder {
        return Err(SealError::Overflow {
            reserved: placeholder,
            needed: der.len(),
        });
    }
    let hex = crate::text::hex_upper(&der);
    let slot = out
        .get_mut(a.saturating_add(1)..a.saturating_add(1).saturating_add(hex.len()))
        .ok_or(SealError::Layout(LayoutProblem::Placeholder(0)))?;
    slot.copy_from_slice(hex.as_bytes());
    let mut contents = der.clone();
    contents.resize(placeholder, 0);
    Ok(Written {
        bytes: out,
        contents,
        byte_range: [0, to_u64(a), to_u64(b), to_u64(c)],
        placeholder,
        der_len: der.len(),
        attempts: 1,
    })
}

/// [`write_once`], and on overflow once more with the measured size plus [`MARGIN`]
/// (docs/31 §9). A second overflow is returned.
fn write_with_retry_reference(
    input: &[u8],
    spec: &RevisionSpec<'_>,
    placeholder: usize,
    content: &mut dyn FnMut(ToSign<'_>) -> Result<Vec<u8>, SealError>,
) -> Result<Written, SealError> {
    let first = placeholder.min(MAX_PLACEHOLDER);
    match write_once_reference(input, spec, first, content) {
        Err(SealError::Overflow { needed, .. }) => {
            let second = needed.saturating_add(MARGIN).min(MAX_PLACEHOLDER);
            let mut w = write_once_reference(input, spec, second, content)?;
            w.attempts = 2;
            Ok(w)
        }
        r => r,
    }
}

pub(crate) fn seal_reference(
    input: &[u8],
    request: &SealRequest,
    key: &dyn KeyProvider,
    timestamps: &dyn TimestampSource,
    revocation: &dyn RevocationSource,
) -> Result<Sealed, SealError> {
    let limits = &request.limits;
    let head = signature_head(request)?;
    let first_new = {
        let admitted = revision_count(input, limits)?;
        if matches!(request.kind, SealKind::Certification { .. })
            && !admitted.report.signatures.is_empty()
        {
            return Err(SealError::Request(RequestProblem::CertificationNotFirst));
        }
        admitted.document.revisions().len()
    };
    let timestamped = request.profile >= Profile::BaselineT;
    let bound = if timestamped {
        timestamps.token_len_bound()
    } else {
        0
    };
    let placeholder = max_der_len(key, bound)?.saturating_add(MARGIN);
    let alg = key.algorithm().digest_algorithm();
    let mut ts_time = None;
    let mut content = |t: ToSign<'_>| -> Result<Vec<u8>, SealError> {
        let digest = alg.digest_ranges(t.bytes, &t.ranges)?;
        let signed = sign_detached(key, &digest)?;
        let token = if timestamped {
            let tok = take_timestamp(timestamps, &alg.digest(signed.signature_value()))?;
            ts_time = Some(tok.gen_time());
            Some(tok.as_der().to_vec())
        } else {
            None
        };
        Ok(signed.to_der(token.as_deref())?)
    };
    let spec = RevisionSpec {
        limits,
        field: FieldSpec {
            name: &request.field_name,
            visible: request.visible.as_ref(),
        },
        head,
        certification: matches!(request.kind, SealKind::Certification { .. }),
        archival: false,
    };
    let written = write_with_retry_reference(input, &spec, placeholder, &mut content)?;
    let kind = match request.kind {
        SealKind::Approval => SignatureKind::Approval,
        SealKind::Certification { docmdp } => SignatureKind::Certification {
            permissions: docmdp.level(),
        },
    };
    let mut expects = vec![Expect {
        byte_range: written.byte_range,
        kind,
        timestamped,
        revocation: request.profile >= Profile::BaselineLt,
    }];
    let mut report = SealReport {
        signature: Some(Layout::from(&written)),
        signature_timestamp: ts_time,
        vri_key: None,
        dss: None,
        document_timestamp: None,
        document_timestamp_time: None,
        revisions_added: 1,
        verification: VerificationReport {
            error: None,
            revisions: 0,
            signatures: Vec::new(),
            revision_changes: Vec::new(),
            covered_by_last_signature: false,
        },
    };
    let mut bytes = written.bytes;
    if request.profile >= Profile::BaselineLt {
        let (b, d) = dss::add_dss(
            &bytes,
            core::slice::from_ref(&written.contents),
            request.signing_time,
            revocation,
            &request.trust,
            limits,
        )?;
        bytes = b;
        report.vri_key = Some(vri_key(&written.contents));
        report.dss = Some(d);
        report.revisions_added = report.revisions_added.saturating_add(1);
    }
    if request.profile >= Profile::BaselineLta {
        let (w, t) = document_timestamp(&bytes, timestamps, limits)?;
        expects.push(Expect {
            byte_range: w.byte_range,
            kind: SignatureKind::DocumentTimestamp,
            timestamped: true,
            revocation: false,
        });
        report.document_timestamp = Some(Layout::from(&w));
        report.document_timestamp_time = Some(t);
        report.revisions_added = report.revisions_added.saturating_add(1);
        bytes = w.bytes;
    }
    let validation_time = [
        Some(request.signing_time),
        report.signature_timestamp,
        report.document_timestamp_time,
    ]
    .into_iter()
    .flatten()
    .max()
    .unwrap_or(request.signing_time);
    report.verification = check::self_check(
        &bytes,
        &request.trust,
        validation_time,
        limits,
        &expects,
        first_new,
        request.profile != Profile::BaselineLt,
    )?;
    Ok(Sealed { bytes, report })
}
