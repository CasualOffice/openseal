//! Backward compatibility of the canonical form (GEO-01).
//!
//! The values pinned here were computed by the build before `context.location` existed
//! (commit `0bd2dd0`). An event without a location must hash exactly as it did then, so
//! every chain already stored still verifies byte for byte, and a trail written by this
//! build for such events is the same file.

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
    Actor, ActorKind, AuditEvent, AuthMethod, Chain, Context, DocumentHash, EventData, Hash256,
    Personal, Timestamp,
};
use common::*;

/// Head of `chain(2026, 300)` before GEO-01.
const PINNED_HEAD: &str = "sha256:6d598bd045b28cd5a19fd04f3b8ffb3212545dbb8e7868d6be47e30d57eb2d93";
/// SHA-256 of `audit-trail.json` for `chain(2026, 300)` before GEO-01.
const PINNED_TRAIL: &str = "sha256:dffb8bcdad168f6d093aa5ff668fc59d60438769c05c236ba82642b298204be5";
/// The canonical text of a recipient event with a full context, before GEO-01.
const PINNED_CANONICAL: &str = r#"{"actor":{"email":"ada@example.com","id":"r1","kind":"recipient","name":"Ada"},"at":"2026-11-10T09:14:03.512Z","context":{"auth":["email_link","sms_otp"],"ip":"203.0.113.7","session":"sha256:043a718774c572bd8a25adbeb1bfcd5c0256ae11cecf9f9c3f925d0e52beaf89","user_agent":"UA/1.0"},"data":{"documents":[{"document_id":"d1","hash":"sha256:139d544b821b13ebea14f1b0fe18577222e415c2966e3a3511c4196055232202"}],"field_value_hashes":{"f1":"sha256:4c94485e0c21ae6c41ce1dfe7b6bfaceea5ab68e40a2476f50208e526f506080"},"recipient_id":"r1"},"envelope_id":"0193a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b","prev":"sha256:61e516917f425d2eae239e9aa9c966e7669352b939828f765e8047ddc5600206","seq":1,"type":"recipient.signed","v":1}"#;

fn recipient_event() -> AuditEvent {
    let mut c = Chain::new(id("0193a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"));
    let first = c.next(
        t(0),
        Actor::system(),
        Context::default(),
        EventData::EnvelopeExpired {},
    );
    c.append(first).unwrap();
    c.next(
        Timestamp::parse("2026-11-10T09:14:03.512Z").unwrap(),
        Actor {
            kind: ActorKind::Recipient,
            id: Some(id("r1")),
            name: Some(Personal("Ada".into())),
            email: Some(Personal("ada@example.com".into())),
        },
        Context {
            ip: Some(Personal("203.0.113.7".into())),
            user_agent: Some(Personal("UA/1.0".into())),
            auth: vec![AuthMethod::EmailLink, AuthMethod::SmsOtp],
            session: Some(Hash256::digest(b"s")),
        },
        EventData::RecipientSigned {
            recipient_id: id("r1"),
            documents: vec![DocumentHash {
                document_id: id("d1"),
                hash: Hash256::digest(b"doc"),
            }],
            field_value_hashes: [(id("f1"), Hash256::digest(b"v"))].into(),
        },
    )
}

#[test]
fn events_without_a_location_hash_as_before() {
    let c = chain(2026, 300);
    let head = c.head().unwrap().to_string();
    let trail = Hash256::digest(&c.to_trail_json().unwrap()).to_string();
    let canonical = String::from_utf8(recipient_event().canonical().unwrap()).unwrap();
    assert_eq!(head, PINNED_HEAD);
    assert_eq!(trail, PINNED_TRAIL);
    assert_eq!(canonical, PINNED_CANONICAL);
}
