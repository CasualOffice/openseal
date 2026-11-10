//! Reports as JSON (`--json`, the shapes `openseal help` documents) and as text. Codes,
//! counts, object numbers and hashes only: never document text or field values.

use casual_sign_sdk::verify::{Check, ModificationClass, SignatureKind, TimeSource};
use casual_sign_sdk::{
    AdmissionReport, ChainReport, Delivered, Indication, MetadataFix, MetadataProblem,
    MetadataRepair, NormalizationReport, PdfSignatureKind, SignatureReport, VerificationReport,
};
use serde_json::{Value, json};

fn indication(i: &Indication) -> Value {
    match i.reason() {
        None => json!({ "indication": i.name(), "subindication": null, "code": null }),
        Some(r) => json!({ "indication": i.name(), "subindication": r.sub.name(), "code": r.code }),
    }
}

fn check(c: &Check) -> Value {
    match c {
        Check::NotRun => json!("not_run"),
        Check::Passed => json!("passed"),
        Check::Failed(r) => json!({ "failed": r.sub.name(), "code": r.code }),
    }
}

fn kind(k: &SignatureKind) -> Value {
    match k {
        SignatureKind::Approval => json!({ "type": "approval" }),
        SignatureKind::Certification { permissions } => {
            json!({ "type": "certification", "docmdp": permissions })
        }
        SignatureKind::DocumentTimestamp => json!({ "type": "document_timestamp" }),
    }
}

fn class(c: &ModificationClass) -> String {
    match c {
        ModificationClass::DssUpdate => "dss".into(),
        ModificationClass::DocumentTimestamp => "document_timestamp".into(),
        ModificationClass::Metadata => "metadata".into(),
        ModificationClass::Signature => "signature".into(),
        ModificationClass::FormFill => "form_fill".into(),
        ModificationClass::Annotation => "annotation".into(),
        ModificationClass::Disallowed(d) => format!("disallowed:{d:?}"),
    }
}

fn signature(s: &SignatureReport) -> Value {
    let c = &s.checks;
    json!({
        "field": s.field,
        "value": s.value,
        "sub_filter": s.sub_filter,
        "kind": kind(&s.kind),
        "byte_range": s.byte_range,
        "signed_revision": s.signed_revision,
        "covers_whole_document": s.covers_whole_document,
        "verdict": indication(&s.indication),
        "checks": {
            "byte_range": check(&c.byte_range),
            "digest": check(&c.digest),
            "signature": check(&c.signature),
            "timestamp": check(&c.timestamp),
            "chain": check(&c.chain),
            "revocation": check(&c.revocation),
            "modifications": check(&c.modifications),
        },
        "validation_time": s.validation_time.as_secs(),
        "time_source": match s.time_source {
            TimeSource::SignatureTimestamp => "signature_timestamp",
            TimeSource::DocumentTimestamp => "document_timestamp",
            TimeSource::ValidationTime => "validation_time",
        },
        "timestamp": s.timestamp.map(|t| t.gen_time.as_secs()),
        "modifications_after": s.modifications_after.iter().map(|m| json!({
            "revision": m.revision,
            "allowed": m.allowed(),
            "classes": m.classes.iter().map(class).collect::<Vec<_>>(),
        })).collect::<Vec<_>>(),
    })
}

/// `openseal verify --json`.
pub(crate) fn verification(file: &str, r: &VerificationReport, outcome: &str) -> Value {
    json!({
        "file": file,
        "outcome": outcome,
        "error": r.error.map(|e| e.code),
        "revisions": r.revisions,
        "covered_by_last_signature": r.covered_by_last_signature,
        "signatures": r.signatures.iter().map(signature).collect::<Vec<_>>(),
    })
}

/// `openseal verify` as text.
pub(crate) fn verification_text(file: &str, r: &VerificationReport, outcome: &str) -> String {
    let mut out = format!("{file}: {outcome}\n");
    if let Some(e) = r.error {
        out.push_str(&format!("  document error {}\n", e.code));
    }
    out.push_str(&format!(
        "  {} revision(s), {} signature(s), last signature covers the file: {}\n",
        r.revisions,
        r.signatures.len(),
        r.covered_by_last_signature
    ));
    for (i, s) in r.signatures.iter().enumerate() {
        let k = match s.kind {
            SignatureKind::Approval => "approval".to_owned(),
            SignatureKind::Certification { permissions } => format!("certification P{permissions}"),
            SignatureKind::DocumentTimestamp => "document timestamp".to_owned(),
        };
        out.push_str(&format!(
            "  #{i} {k} ({}): {}\n",
            s.sub_filter.as_deref().unwrap_or("-"),
            s.indication
        ));
        let disallowed: Vec<String> = s
            .modifications_after
            .iter()
            .filter(|m| !m.allowed())
            .map(|m| format!("revision {}", m.revision))
            .collect();
        if !disallowed.is_empty() {
            out.push_str(&format!(
                "     disallowed changes after it: {}\n",
                disallowed.join(", ")
            ));
        }
    }
    out
}

/// `openseal admit --json` when admitted.
pub(crate) fn admission(file: &str, r: &AdmissionReport) -> Value {
    let mut codes: Vec<&str> = r.findings.iter().map(|f| f.code).collect();
    codes.sort_unstable();
    codes.dedup();
    json!({
        "file": file,
        "admitted": true,
        "code": null,
        "version": r.version.map(|v| format!("{}.{}", v.major, v.minor)),
        "pages": r.page_count,
        "revisions": r.revisions.len(),
        "objects": r.object_count,
        "repaired": r.repaired,
        "signed": r.is_signed(),
        "docmdp": r.docmdp,
        "encrypted": r.encryption.is_some(),
        "fields": r.fields.len(),
        "signatures": r.signatures.len(),
        "javascript_or_actions": r.actions.len(),
        "embedded_files": r.embedded_files.len(),
        "xfa": r.has_xfa,
        "findings": codes,
        "findings_count": r.findings.len().saturating_add(usize::try_from(r.findings_dropped).unwrap_or(usize::MAX)),
    })
}

fn metadata(m: Option<&MetadataRepair>) -> Value {
    let Some(m) = m else { return Value::Null };
    let fix = match m.fix {
        MetadataFix::Wrapped => "wrapped".to_owned(),
        MetadataFix::Dropped(why) => format!("dropped:{}", problem(why)),
        _ => "other".to_owned(),
    };
    json!({ "object": m.object, "fix": fix })
}

fn problem(p: MetadataProblem) -> &'static str {
    match p {
        MetadataProblem::NotStream => "not_stream",
        MetadataProblem::Unreadable => "unreadable",
        MetadataProblem::TooLarge => "too_large",
        MetadataProblem::NotXml => "not_xml",
        MetadataProblem::Doctype => "doctype",
        MetadataProblem::NotXmp => "not_xmp",
        _ => "other",
    }
}

fn pdf_signature_kind(k: PdfSignatureKind) -> &'static str {
    match k {
        PdfSignatureKind::Approval => "approval",
        PdfSignatureKind::Certification => "certification",
        PdfSignatureKind::UsageRights => "usage_rights",
        PdfSignatureKind::DocTimeStamp => "document_timestamp",
        _ => "other",
    }
}

/// `openseal normalize --json`. `written` is, per attachment, the file it was written
/// to. Attachment names are document text and are not printed.
pub(crate) fn normalization(
    out: &str,
    sha256: &str,
    r: &NormalizationReport,
    d: &Delivered,
    written: &[Option<String>],
) -> Value {
    let printed = d.printed.as_ref().map_or(Value::Null, |p| {
        json!({
            "original_sha256": p.original.hex(),
            "docmdp": p.docmdp,
            "signatures": p.signatures.iter().map(|s| json!({
                "field": s.field,
                "field_name": s.field_name,
                "value": s.value,
                "kind": pdf_signature_kind(s.kind),
                "sub_filter": s.sub_filter,
            })).collect::<Vec<_>>(),
            "appearances_drawn": p.appearances_drawn,
            "annotations_flattened": p.annotations_flattened,
            "annotations_removed": p.annotations_removed,
            "optional_content_flattened": p.optional_content_flattened,
        })
    });
    let attachments: Vec<Value> = d
        .attachments
        .iter()
        .enumerate()
        .map(|(i, a)| {
            json!({
                "object": a.object,
                "sha256": a.sha256.hex(),
                "size": a.size,
                "admitted": a.outcome.is_ok(),
                "code": a.outcome.as_ref().err(),
                "output": written.get(i).cloned().flatten(),
            })
        })
        .collect();
    json!({
        "output": out,
        "sha256": sha256,
        "objects_written": r.objects_written,
        "unreachable_dropped": r.unreachable_dropped,
        "removed": r.removed.iter().map(|x| json!({ "code": x.code, "object": x.object })).collect::<Vec<_>>(),
        "optional_content_kept": r.optional_content_kept,
        "metadata": metadata(r.metadata.as_ref()),
        "printed": printed,
        "attachments": attachments,
        "attachments_dropped": d.attachments_dropped,
    })
}

/// `openseal audit verify --json`.
pub(crate) fn chain(file: &str, r: &ChainReport) -> Value {
    json!({
        "file": file,
        "valid": r.is_valid(),
        "events": r.events,
        "envelope_id": r.envelope_id.as_ref().map(|i| i.as_str().to_owned()),
        "head": r.head.map(|h| h.hex()),
        "problems": r.problems.iter().map(|p| json!({ "index": p.index, "kind": format!("{:?}", p.kind) })).collect::<Vec<_>>(),
        "problems_dropped": r.problems_dropped,
        "unrecognised": r.unrecognised,
    })
}
