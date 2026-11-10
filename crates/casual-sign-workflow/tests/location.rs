//! GEO-01: the envelope's `capture_location` setting carried into the signing ceremony.
//!
//! With the setting on, every recipient action (delivered, viewed, signed, approved,
//! declined) carries a location: the device's, or an IP approximation stating why the
//! device was not used. A refusal never blocks signing. With it off, nothing is required,
//! and a location that says the signer was asked is refused as inconsistent.

// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

mod common;

use casual_sign_audit::{FallbackReason, Location, LocationSource, Personal};
use casual_sign_model::{EnvelopeStatus, RecipientType, SigningOptions};
use casual_sign_workflow::{Change, Command, Decision, WorkflowError};
use common::*;

const DB: &str = "GeoLite2-City 2026-11-04";

fn code<T: core::fmt::Debug>(r: Result<T, WorkflowError>) -> &'static str {
    r.unwrap_err().code()
}

fn device() -> Location {
    Location::device(51.507_412, -0.127_758, 14.0)
        .unwrap()
        .with_place(Some("GB"), Some("England"), Some("London"))
        .unwrap()
}

fn ip(reason: FallbackReason) -> Location {
    Location::ip(reason, DB, 51.5, -0.13)
        .unwrap()
        .with_place(Some("GB"), None, Some("London"))
        .unwrap()
}

/// A draft for `recipients` with `capture_location` as given, sent.
fn sent(capture_location: bool, recipients: &[casual_sign_workflow::RecipientSpec]) -> Harness {
    let mut hx = Harness::new();
    hx.draft(recipients);
    hx.ok(
        sender(),
        Command::Edit {
            changes: vec![Change::SetSigningOptions {
                options: SigningOptions {
                    capture_location,
                    ..SigningOptions::default()
                },
            }],
        },
    );
    assert_eq!(hx.state().options.capture_location, capture_location);
    hx.send();
    hx
}

fn locate(hx: &mut Harness, l: Option<Location>) {
    hx.request.location = l.map(Personal);
}

/// The location each event of `d` carries, by type name.
fn located(d: &Decision) -> Vec<(String, Option<Location>)> {
    d.events
        .iter()
        .map(|e| {
            (
                serde_type_name(&e.data),
                e.context.location.as_ref().map(|l| l.get().clone()),
            )
        })
        .collect()
}

fn open(hx: &mut Harness, rid: &str) -> Result<Decision, WorkflowError> {
    hx.run(as_recipient(rid), Command::OpenLink { recipient: id(rid) })
}

#[test]
fn with_the_setting_on_a_recipient_action_without_a_location_is_refused() {
    let mut hx = sent(true, &[recipient("r1", RecipientType::Signer, 1)]);
    let err = open(&mut hx, "r1").unwrap_err();
    assert_eq!(err.code(), "CS-WF-0019");
    assert_eq!(
        err,
        WorkflowError::LocationRequired {
            recipient: id("r1")
        }
    );
    // Nothing was recorded.
    assert_eq!(hx.rstatus("r1"), casual_sign_model::RecipientStatus::Sent);
}

#[test]
fn with_the_setting_on_a_device_location_is_recorded_on_every_action() {
    let mut hx = sent(true, &[recipient("r1", RecipientType::Signer, 1)]);
    locate(&mut hx, Some(device()));
    let d = open(&mut hx, "r1").unwrap();
    assert_eq!(
        located(&d),
        [("recipient.delivered".to_owned(), Some(device()))]
    );
    let d = hx.sign("r1");
    let signed = located(&d);
    assert!(
        signed.contains(&("recipient.signed".to_owned(), Some(device()))),
        "{signed:?}"
    );
    // Events the platform records as a consequence carry no request context.
    assert!(
        signed.contains(&("envelope.completing".to_owned(), None)),
        "{signed:?}"
    );
    assert_eq!(hx.status(), EnvelopeStatus::Completing);
}

#[test]
fn a_refusal_never_blocks_signing_the_ip_approximation_records_it() {
    let mut hx = sent(true, &[recipient("r1", RecipientType::Signer, 1)]);
    for reason in [FallbackReason::Declined, FallbackReason::Unavailable] {
        locate(&mut hx, Some(ip(reason)));
        if reason == FallbackReason::Declined {
            open(&mut hx, "r1").unwrap();
        }
    }
    // The lookup may find nothing (a private address): the refusal is still recorded.
    locate(
        &mut hx,
        Some(Location::ip_unresolved(FallbackReason::Declined, Some(DB)).unwrap()),
    );
    let d = hx.sign("r1");
    let (_, l) = located(&d)
        .into_iter()
        .find(|(t, _)| t == "recipient.signed")
        .unwrap();
    let l = l.unwrap();
    assert!(l.declined());
    assert_eq!(l.coordinates(), None);
    assert_eq!(hx.status(), EnvelopeStatus::Completing);
}

#[test]
fn with_the_setting_on_viewed_approved_and_declined_need_a_location_too() {
    let mut hx = sent(
        true,
        &[
            recipient("a", RecipientType::Approver, 1),
            recipient("d", RecipientType::Signer, 1),
        ],
    );
    locate(&mut hx, Some(ip(FallbackReason::Unavailable)));
    hx.get_ready("a");
    hx.get_ready("d");
    locate(&mut hx, None);
    let view = Command::ViewDocument {
        recipient: id("a"),
        document: id("doc-1"),
        hash: h(101),
        pages_seen: vec![1, 2],
    };
    assert_eq!(code(hx.run(as_recipient("a"), view.clone())), "CS-WF-0019");
    let approve = Command::Approve { recipient: id("a") };
    assert_eq!(
        code(hx.run(as_recipient("a"), approve.clone())),
        "CS-WF-0019"
    );
    let decline = Command::Decline {
        recipient: id("d"),
        reason: None,
    };
    assert_eq!(
        code(hx.run(as_recipient("d"), decline.clone())),
        "CS-WF-0019"
    );
    // Commands that record no such action need none.
    hx.ok(
        as_recipient("d"),
        Command::AdoptSignature {
            recipient: id("d"),
            mark: casual_sign_audit::MarkKind::Signature,
            method: casual_sign_audit::AdoptionMethod::Type,
            image_hash: h(9),
        },
    );
    hx.ok(sender(), Command::Remind);
    locate(&mut hx, Some(device()));
    let d = hx.ok(as_recipient("a"), view);
    assert_eq!(located(&d)[0].1, Some(device()));
    let d = hx.ok(as_recipient("a"), approve);
    assert_eq!(
        located(&d)[0],
        ("recipient.approved".into(), Some(device()))
    );
    locate(&mut hx, Some(ip(FallbackReason::Declined)));
    let d = hx.ok(as_recipient("d"), decline);
    assert_eq!(
        located(&d)[0],
        (
            "recipient.declined".into(),
            Some(ip(FallbackReason::Declined))
        )
    );
    assert_eq!(hx.status(), EnvelopeStatus::Declined);
}

#[test]
fn with_the_setting_on_not_requested_contradicts_it() {
    let mut hx = sent(true, &[recipient("r1", RecipientType::Signer, 1)]);
    locate(&mut hx, Some(ip(FallbackReason::NotRequested)));
    let err = open(&mut hx, "r1").unwrap_err();
    assert_eq!(err.code(), "CS-WF-0020");
    assert_eq!(
        err,
        WorkflowError::LocationInconsistent {
            capture_location: true
        }
    );
}

#[test]
fn with_the_setting_off_nothing_is_required_and_asking_is_refused() {
    let mut hx = sent(false, &[recipient("r1", RecipientType::Signer, 1)]);
    // A device location, or a reason saying the signer was asked, contradicts the
    // setting: the signer must not have been asked.
    for l in [
        device(),
        ip(FallbackReason::Declined),
        ip(FallbackReason::Unavailable),
    ] {
        locate(&mut hx, Some(l));
        assert_eq!(code(open(&mut hx, "r1")), "CS-WF-0020");
    }
    // The host may still record an IP approximation, flagged as not requested.
    locate(&mut hx, Some(ip(FallbackReason::NotRequested)));
    let d = open(&mut hx, "r1").unwrap();
    let l = located(&d)[0].1.clone().unwrap();
    assert!(matches!(
        l.source(),
        LocationSource::Ip {
            reason: FallbackReason::NotRequested,
            ..
        }
    ));
    // And nothing at all is fine.
    locate(&mut hx, None);
    let d = hx.sign("r1");
    assert!(located(&d).iter().all(|(_, l)| l.is_none()));
    assert_eq!(hx.status(), EnvelopeStatus::Completing);
}

#[test]
fn options_written_before_the_setting_existed_hash_the_same() {
    // A stored command's fingerprint must not change: `capture_location` is absent from
    // the wire when off.
    let cmd = Command::Edit {
        changes: vec![Change::SetSigningOptions {
            options: SigningOptions::default(),
        }],
    };
    let json = serde_json::to_string(&cmd).unwrap();
    assert!(!json.contains("capture_location"), "{json}");
    let old = r#"{"command":"edit","changes":[{"op":"set_signing_options","options":{"allow_reassign":true,"allow_decline":true,"allow_finish_later":true}}]}"#;
    let back: Command = serde_json::from_str(old).unwrap();
    assert_eq!(
        casual_sign_workflow::canonical_hash(&back).unwrap(),
        casual_sign_workflow::canonical_hash(&cmd).unwrap()
    );
}
