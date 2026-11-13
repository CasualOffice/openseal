//! Chains with every kind of event, and the tools an attacker would use on them.

// Not every test binary uses every helper.
#![allow(dead_code)]
// Test code: a panic is the failure report (CLAUDE.md).
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::panic
)]

use std::collections::BTreeMap;

use casual_sign_audit::json::Value;
use casual_sign_audit::{
    Actor, ActorKind, AdoptionMethod, AuthMethod, Chain, Channel, Context, DocumentHash, EventData,
    Hash256, MarkKind, Personal, Timestamp, jcs,
};
use casual_sign_model::Id;

pub fn id(s: &str) -> Id {
    Id::new(s).unwrap()
}

/// 2026-11-10T09:00:00.000Z plus `ms`.
pub fn t(ms: i64) -> Timestamp {
    Timestamp::from_unix_millis(1_794_301_200_000 + ms).unwrap()
}

/// A small deterministic generator (xorshift64*), so chains follow from a seed.
#[derive(Debug, Clone)]
pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        let mut x = self.0.max(1);
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

fn recipient(r: &mut Rng) -> (Id, Actor, Context) {
    let n = r.below(5);
    let rid = id(&format!("rcp-{n}"));
    let actor = Actor {
        kind: ActorKind::Recipient,
        id: Some(rid.clone()),
        name: Some(Personal(format!("Recipient {n} Ünïcødé"))),
        email: Some(Personal(format!("r{n}@example.com"))),
    };
    let ctx = Context {
        ip: Some(Personal(format!("203.0.113.{n}"))),
        user_agent: Some(Personal("Mozilla/5.0 (X11; Linux x86_64)".into())),
        auth: vec![AuthMethod::EmailLink, AuthMethod::SmsOtp],
        session: Some(Hash256::digest(format!("s{n}").as_bytes())),
        location: None,
    };
    (rid, actor, ctx)
}

/// One event of a kind chosen by `r`, covering every group of docs/32 §3.
pub fn random_event(r: &mut Rng) -> (Actor, Context, EventData) {
    let (rid, actor, ctx) = recipient(r);
    let doc = DocumentHash {
        document_id: id("doc-1"),
        hash: Hash256::digest(&r.next().to_be_bytes()),
    };
    let h = Hash256::digest(&r.next().to_be_bytes());
    let sys = (Actor::system(), Context::default());
    let (a, c, d) = match r.below(16) {
        0 => (
            sys.0,
            sys.1,
            EventData::EnvelopeSent {
                recipients: 3,
                documents: 1,
            },
        ),
        1 => (
            actor,
            ctx,
            EventData::InvitationSent {
                recipient_id: rid,
                channel: Channel::Email,
            },
        ),
        2 => (
            actor,
            ctx,
            EventData::RecipientDelivered { recipient_id: rid },
        ),
        3 => (
            actor,
            ctx,
            EventData::RecipientAuthPassed {
                recipient_id: rid,
                method: AuthMethod::SmsOtp,
                identity: None,
            },
        ),
        4 => (
            actor,
            ctx,
            EventData::RecipientConsented {
                recipient_id: rid,
                ersd_version: "2026-01".into(),
                ersd_hash: h,
            },
        ),
        5 => (
            actor,
            ctx,
            EventData::RecipientViewedDocument {
                recipient_id: rid,
                document: doc,
                pages_seen: vec![1, 2, 3],
            },
        ),
        6 => (
            actor,
            ctx,
            EventData::RecipientSignatureAdopted {
                recipient_id: rid,
                mark: MarkKind::Signature,
                method: AdoptionMethod::Draw,
                image_hash: h,
            },
        ),
        7 => (
            actor,
            ctx,
            EventData::RecipientFieldCompleted {
                recipient_id: rid,
                field_id: id("f-1"),
                value_hash: h,
            },
        ),
        8 => (
            actor,
            ctx,
            EventData::RecipientSigned {
                recipient_id: rid,
                documents: vec![doc],
                field_value_hashes: BTreeMap::from([(id("f-1"), h), (id("f-2"), h)]),
            },
        ),
        9 => (
            actor,
            ctx,
            EventData::RecipientDeclined {
                recipient_id: rid,
                reason: Some(Personal("Wrong \"amount\"\n\u{1}".into())),
            },
        ),
        10 => (
            sys.0,
            sys.1,
            EventData::DocumentFixed {
                document_id: id("doc-1"),
                delivered_hash: h,
                pages: 4,
            },
        ),
        11 => (
            sys.0,
            sys.1,
            EventData::DocumentSealed {
                document_id: id("doc-1"),
                sealed_hash: h,
                profile: "pades-b-lta".into(),
                certificate_fingerprint: h,
                tsa_time: Some(t(5)),
            },
        ),
        12 => (
            actor,
            ctx,
            EventData::RecipientAuthFailed {
                recipient_id: rid,
                method: AuthMethod::AccessCode,
                attempt: 2,
            },
        ),
        13 => (
            actor,
            ctx,
            EventData::AuthAssertedByHost {
                recipient_id: rid,
                host_claim: Personal("SSO via Okta".into()),
            },
        ),
        14 => (
            sys.0,
            sys.1,
            EventData::EnvelopeCorrected {
                changed: vec!["recipient.email".into()],
            },
        ),
        _ => (sys.0, sys.1, EventData::CertificateDownloaded { hash: h }),
    };
    (a, c, d)
}

/// A chain of `n` events from `seed`, times rising by 0 to 5 s.
pub fn chain(seed: u64, n: usize) -> Chain {
    let mut r = Rng(seed);
    let mut c = Chain::new(id("0193a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"));
    let mut now = 0;
    let e = c.next(
        t(now),
        Actor {
            kind: ActorKind::Sender,
            id: Some(id("u-1")),
            name: None,
            email: None,
        },
        Context::default(),
        EventData::EnvelopeCreated {
            subject_hash: Hash256::digest(b"NDA"),
        },
    );
    c.append(e).unwrap();
    while c.len() < n {
        now += i64::try_from(r.below(5_000)).unwrap();
        let (a, ctx, d) = random_event(&mut r);
        let e = c.next(t(now), a, ctx, d);
        c.append(e).unwrap();
    }
    c
}

/// The trail's events as JSON trees.
pub fn events(c: &Chain) -> Vec<Value> {
    let v = c.to_value().unwrap();
    v.get("events").unwrap().as_array().unwrap().to_vec()
}

/// Set member `name` of an object.
pub fn set(v: &mut Value, name: &str, new: Value) {
    let Value::Object(m) = v else {
        panic!("not an object")
    };
    match m.iter_mut().find(|(k, _)| k == name) {
        Some(slot) => slot.1 = new,
        None => m.push((name.to_owned(), new)),
    }
}

/// The hash an event's content gives.
pub fn content_hash(v: &Value) -> Hash256 {
    Hash256::digest(&jcs::to_vec(&v.without("hash")).unwrap())
}

/// Recompute `hash` of event `i`.
pub fn rehash(events: &mut [Value], i: usize) {
    let h = content_hash(&events[i]);
    set(&mut events[i], "hash", Value::String(h.to_string()));
}

/// What a forger with database access does after changing something: from `from` on,
/// point every `prev` at the (recomputed) hash before it and recompute every `hash`.
pub fn relink(events: &mut [Value], from: usize) {
    for i in from..events.len() {
        if i > 0 {
            let before = content_hash(&events[i - 1]);
            set(&mut events[i], "prev", Value::String(before.to_string()));
        }
        rehash(events, i);
    }
}

/// Renumber `seq` densely from 0 (a forger hiding a removal).
pub fn renumber(events: &mut [Value]) {
    for (i, e) in events.iter_mut().enumerate() {
        set(e, "seq", Value::Number(i as f64));
    }
}
