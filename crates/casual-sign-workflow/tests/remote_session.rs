//! A remote signer's session (ADR-046 §3.4, §3.7, §3.12, `RSP-01`): start (values
//! frozen), preparation (the lock point), the embedded signature, failure and the
//! envelope ending under it; each through the harness, which checks every invariant
//! after every accepted command.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use casual_sign_audit::{
    AdoptionMethod, EsignSigned, EsignStarted, EventData, Hash256, MarkKind, NameMatch, Personal,
    PreparedDocument, RemoteCertificate, RemoteFailure, RemoteProvider, RemoteSignedDocument,
};
use casual_sign_model::{FieldType, FieldValue, RecipientStatus, RecipientType, SignatureType};
use casual_sign_workflow::{Command, Decision, FieldEntry, Principal, RemoteRule, WorkflowError};
use common::*;

use RecipientType::Signer;

fn provider() -> RemoteProvider {
    RemoteProvider {
        id: id("csc-demo"),
        kind: "csc".into(),
        name: "Demo CSC".into(),
    }
}

/// r1 remote (order 1), r2 simple (order 2), sent; r1 opened and adopted a mark.
fn ready_remote(hx: &mut Harness) {
    let mut r1 = recipient("r1", Signer, 1);
    r1.signature = SignatureType::Remote {
        provider_id: id("csc-demo"),
    };
    hx.draft(&[r1, recipient("r2", Signer, 2)]);
    hx.send();
    hx.get_ready("r1");
    hx.ok(
        as_recipient("r1"),
        Command::AdoptSignature {
            recipient: id("r1"),
            mark: MarkKind::Signature,
            method: AdoptionMethod::Type,
            image_hash: h(9),
        },
    );
}

fn sig_value() -> Vec<FieldEntry> {
    vec![FieldEntry {
        field: id("sig-r1"),
        value: Personal(FieldValue::Signature(id("img-1"))),
    }]
}

fn begin(hx: &mut Harness, session: &str) -> Result<Decision, WorkflowError> {
    begin_with(hx, session, None)
}

fn begin_with(
    hx: &mut Harness,
    session: &str,
    esign: Option<EsignStarted>,
) -> Result<Decision, WorkflowError> {
    hx.run(
        as_recipient("r1"),
        Command::BeginRemoteSigning {
            recipient: id("r1"),
            session: id(session),
            provider: provider(),
            values: sig_value(),
            esign,
        },
    )
}

fn prepared_doc() -> PreparedDocument {
    PreparedDocument {
        document_id: id("doc-1"),
        base_hash: h(1),
        prepared_hash: h(2),
        byte_range: [0, 100, 200, 50],
        byte_range_digest: h(3),
        to_be_signed: h(4),
        lock_point: false,
        txn: None,
    }
}

fn prepare(hx: &mut Harness, session: &str) -> Result<Decision, WorkflowError> {
    hx.run(
        Principal::System,
        Command::RemoteSigningPrepared {
            recipient: id("r1"),
            session: id(session),
            documents: vec![prepared_doc()],
            certificate_sha256: Some(h(5)),
        },
    )
}

fn certificate() -> RemoteCertificate {
    RemoteCertificate {
        sha256: h(5),
        issuer: "CN=Test CA".into(),
        serial: "0a".into(),
        not_before: t(0),
        not_after: t(1_000_000_000),
        subject_cn: Personal("Signer r1".into()),
        key: "ec-p256".into(),
        qualifier: Some("eu_eidas_qes".into()),
        qc_statements: vec!["QcCompliance".into()],
    }
}

fn complete(hx: &mut Harness, session: &str) -> Result<Decision, WorkflowError> {
    complete_with(hx, session, None, None)
}

fn complete_with(
    hx: &mut Harness,
    session: &str,
    esign: Option<EsignSigned>,
    hashes: Option<(Hash256, Hash256)>,
) -> Result<Decision, WorkflowError> {
    hx.run(
        Principal::System,
        Command::CompleteRemoteSigning {
            recipient: id("r1"),
            session: id(session),
            provider: provider(),
            provider_reference: Some("tx-1".into()),
            certificate: Box::new(certificate()),
            name_match: NameMatch::Exact,
            documents: vec![RemoteSignedDocument {
                document_id: id("doc-1"),
                revision_hash: h(6),
                signature_sha256: h(7),
                timestamp_time: Some(t(10)),
                request_sha256: hashes.map(|x| x.0),
                response_sha256: hashes.map(|x| x.1),
                signature_format: hashes.map(|_| "adbe.pkcs7.detached".to_owned()),
            }],
            esign,
        },
    )
}

/// ADR-047 §3.8, `RSP-02` acceptance (5): an eSign session records the consent's hash
/// when it starts, and the ESP's reference, the request and response hashes and the
/// format when it is embedded; a CSC session's events carry none of these members, so
/// they hash as before.
#[test]
fn an_esign_session_records_its_consent_reference_and_xml_hashes() {
    let mut hx = Harness::new();
    ready_remote(&mut hx);
    let started = begin_with(
        &mut hx,
        "s1",
        Some(EsignStarted {
            consent_sha256: h(9),
            api_version: "2.1".into(),
            auth_mode: "otp".into(),
        }),
    )
    .unwrap();
    let json = serde_json::to_string(&started.events.last().unwrap().data).unwrap();
    assert!(json.contains(&h(9).hex()), "{json}");
    assert!(json.contains("\"api_version\":\"2.1\""), "{json}");
    prepare(&mut hx, "s1").unwrap();
    let signed = complete_with(
        &mut hx,
        "s1",
        Some(EsignSigned {
            auth_mode: "otp".into(),
            policy_oids: vec!["2.16.356.100.2.4.1".into()],
        }),
        Some((h(11), h(12))),
    )
    .unwrap();
    let remote = signed
        .events
        .iter()
        .find(|e| serde_type_name(&e.data) == "recipient.remote_signed")
        .unwrap();
    let json = serde_json::to_string(&remote.data).unwrap();
    for needle in [
        h(11).hex(),
        h(12).hex(),
        "tx-1".to_owned(),
        "adbe.pkcs7.detached".to_owned(),
        "2.16.356.100.2.4.1".to_owned(),
    ] {
        assert!(json.contains(&needle), "{needle}: {json}");
    }

    let mut csc = Harness::new();
    ready_remote(&mut csc);
    let d = begin(&mut csc, "s2").unwrap();
    let json = serde_json::to_string(&d.events.last().unwrap().data).unwrap();
    assert!(!json.contains("esign"), "{json}");
    prepare(&mut csc, "s2").unwrap();
    let d = complete(&mut csc, "s2").unwrap();
    for e in &d.events {
        let json = serde_json::to_string(&e.data).unwrap();
        assert!(
            !json.contains("esign") && !json.contains("request_sha256"),
            "{json}"
        );
    }
}

fn types(d: &Decision) -> Vec<String> {
    d.events.iter().map(|e| serde_type_name(&e.data)).collect()
}

fn rule_of(e: WorkflowError) -> RemoteRule {
    match e {
        WorkflowError::Remote { rule, .. } => rule,
        e => panic!("not a remote rule: {e}"),
    }
}

#[test]
fn a_remote_signer_starts_is_prepared_and_completes_through_the_provider() {
    let mut hx = Harness::new();
    ready_remote(&mut hx);
    // A plain finish is refused: they sign through their provider.
    let e = hx
        .run(
            as_recipient("r1"),
            Command::Finish {
                recipient: id("r1"),
                values: sig_value(),
            },
        )
        .unwrap_err();
    assert_eq!(e.code(), "CS-RSP-0007");
    assert_eq!(rule_of(e), RemoteRule::FinishThroughProvider);
    let d = begin(&mut hx, "sess-1").unwrap();
    assert_eq!(
        types(&d),
        [
            "recipient.field_completed",
            "recipient.remote_signing_started"
        ]
    );
    // Values are frozen; a second session is refused.
    let e = hx
        .run(
            as_recipient("r1"),
            Command::CompleteField {
                recipient: id("r1"),
                entry: sig_value().remove(0),
            },
        )
        .unwrap_err();
    assert_eq!(rule_of(e), RemoteRule::ValuesFrozen);
    assert_eq!(
        rule_of(begin(&mut hx, "sess-2").unwrap_err()),
        RemoteRule::SessionOpen
    );
    // The worker prepares: the document reaches its lock point.
    let d = prepare(&mut hx, "sess-1").unwrap();
    let EventData::RecipientRemoteSigningPrepared { documents, .. } = &d.events[0].data else {
        panic!("{:?}", types(&d));
    };
    assert!(documents[0].lock_point, "the first preparation locks");
    assert!(hx.state().locked_documents.contains(&id("doc-1")));
    let e = hx
        .run(
            sender(),
            Command::Correct {
                changes: vec![add_field(field(
                    "late",
                    "doc-1",
                    "r2",
                    FieldType::Text,
                    false,
                ))],
            },
        )
        .unwrap_err();
    assert_eq!(e.code(), "CS-RSP-0007");
    // A wrong session is no session.
    assert_eq!(
        complete(&mut hx, "sess-x").unwrap_err().code(),
        "CS-RSP-0003"
    );
    let d = complete(&mut hx, "sess-1").unwrap();
    assert_eq!(
        types(&d)[..3],
        [
            "recipient.remote_signed",
            "recipient.signed",
            "recipient.completed"
        ]
    );
    assert_eq!(hx.rstatus("r1"), RecipientStatus::Completed);
    assert!(hx.state().recipient(&id("r1")).unwrap().remote.is_none());
    // Routing moved on to r2.
    assert_eq!(hx.rstatus("r2"), RecipientStatus::Sent);
    // A late answer for the closed session is refused.
    assert_eq!(
        complete(&mut hx, "sess-1").unwrap_err().code(),
        "CS-RSP-0003"
    );
}

#[test]
fn a_failed_session_reopens_the_fields_and_a_new_attempt_is_a_new_session() {
    let mut hx = Harness::new();
    ready_remote(&mut hx);
    begin(&mut hx, "sess-1").unwrap();
    let d = hx
        .run(
            as_recipient("r1"),
            Command::FailRemoteSigning {
                recipient: id("r1"),
                session: id("sess-1"),
                reason: RemoteFailure::Cancelled,
                provider_code: Some("access_denied".into()),
            },
        )
        .unwrap();
    assert_eq!(types(&d), ["recipient.remote_signing_failed"]);
    let r = hx.state().recipient(&id("r1")).unwrap();
    assert!(r.remote.is_none());
    assert_eq!(r.remote_failures, 1);
    // The old session's answers are refused; a new one starts.
    assert_eq!(
        prepare(&mut hx, "sess-1").unwrap_err().code(),
        "CS-RSP-0003"
    );
    begin(&mut hx, "sess-2").unwrap();
    prepare(&mut hx, "sess-2").unwrap();
    complete(&mut hx, "sess-2").unwrap();
    assert_eq!(hx.rstatus("r1"), RecipientStatus::Completed);
}

#[test]
fn voiding_closes_an_open_session_and_a_late_answer_is_refused() {
    let mut hx = Harness::new();
    ready_remote(&mut hx);
    begin(&mut hx, "sess-1").unwrap();
    prepare(&mut hx, "sess-1").unwrap();
    let d = hx.ok(
        sender(),
        Command::Void {
            reason: text("Wrong contract"),
        },
    );
    let reason = d
        .events
        .iter()
        .find_map(|e| match &e.data {
            EventData::RecipientRemoteSigningFailed { reason, .. } => Some(*reason),
            _ => None,
        })
        .expect("the session closed");
    assert_eq!(reason, RemoteFailure::EnvelopeEnded);
    assert!(complete(&mut hx, "sess-1").is_err());
}

#[test]
fn only_the_platform_prepares_and_completes() {
    let mut hx = Harness::new();
    ready_remote(&mut hx);
    begin(&mut hx, "sess-1").unwrap();
    let e = hx
        .run(
            as_recipient("r1"),
            Command::RemoteSigningPrepared {
                recipient: id("r1"),
                session: id("sess-1"),
                documents: vec![prepared_doc()],
                certificate_sha256: None,
            },
        )
        .unwrap_err();
    assert_eq!(e.code(), "CS-WF-0003");
}
