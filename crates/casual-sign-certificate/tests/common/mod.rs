//! Envelopes with any number of recipients, their chains and certificate inputs.

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
use std::path::PathBuf;

use casual_sign_audit::{
    Actor, ActorKind, AdoptionMethod, AuthMethod, Chain, Channel, Context, DocumentHash, EventData,
    Hash256, MarkKind, Personal, Timestamp,
};
use casual_sign_certificate::{
    AuthStep, CertificateInput, Consent, CopyKind, CopyRow, Disclosure, DocumentRow,
    EnvelopeSummary, Mark, Outcome, Party, RecipientRow, Role, SealInfo,
};
use casual_sign_flatten::{Art, Ink, InkPoint};
use casual_sign_model::Id;

pub const ENVELOPE: &str = "0193a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b";

pub fn never() -> bool {
    false
}

pub fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Where tests leave PDFs for the independent checks (`tools`-free: pypdf, pypdfium2).
pub fn out_dir(name: &str) -> PathBuf {
    let d = repo_root().join("target/certificate-out").join(name);
    std::fs::create_dir_all(&d).unwrap();
    d
}

pub fn t(ms: i64) -> Timestamp {
    Timestamp::from_unix_millis(1_794_301_200_000 + ms).unwrap()
}

pub fn id(s: &str) -> Id {
    Id::new(s).unwrap()
}

pub fn name(i: usize) -> String {
    const FIRST: [&str; 8] = [
        "Ada", "Grace", "Alan", "Émilie", "Søren", "Zoë", "Chidi", "Anaïs",
    ];
    const LAST: [&str; 6] = [
        "Lovelace",
        "Hopper",
        "Turing",
        "du Châtelet",
        "Kierkegaard",
        "Okafor",
    ];
    format!(
        "{} {} {}",
        FIRST[i % FIRST.len()],
        LAST[i % LAST.len()],
        i + 1
    )
}

pub fn email(i: usize) -> String {
    format!(
        "signer{}.{}@example.org",
        i + 1,
        ["legal", "ops", "finance"][i % 3]
    )
}

/// A wavy drawn signature.
pub fn ink(seed: usize) -> Ink {
    let n = 120;
    let pts = (0..n)
        .map(|k| {
            let x = k as f64 / n as f64;
            InkPoint {
                x: x * 300.0,
                y: 60.0 + 30.0 * (x * (8.0 + seed as f64)).sin(),
            }
        })
        .collect();
    Ink {
        strokes: vec![
            pts,
            vec![
                InkPoint { x: 20.0, y: 90.0 },
                InkPoint { x: 280.0, y: 95.0 },
            ],
        ],
        color: None,
    }
}

pub fn jpeg() -> Vec<u8> {
    std::fs::read(repo_root().join("crates/casual-sign-flatten/tests/data/stamp-rgb.jpg")).unwrap()
}

/// Recipient `i`'s marks: drawn, typed or an uploaded image in turn.
pub fn marks(i: usize) -> (Mark, Mark) {
    match i % 3 {
        0 => (
            Mark {
                art: Art::Drawn(ink(i)),
                method: AdoptionMethod::Draw,
            },
            Mark {
                art: Art::Drawn(ink(i + 3)),
                method: AdoptionMethod::Draw,
            },
        ),
        1 => (
            Mark {
                art: Art::Typed {
                    text: name(i),
                    style: i,
                },
                method: AdoptionMethod::Type,
            },
            Mark {
                art: Art::Typed {
                    text: initials(i),
                    style: i,
                },
                method: AdoptionMethod::Type,
            },
        ),
        _ => (
            Mark {
                art: Art::Image(jpeg()),
                method: AdoptionMethod::Upload,
            },
            Mark {
                art: Art::Typed {
                    text: initials(i),
                    style: 0,
                },
                method: AdoptionMethod::Type,
            },
        ),
    }
}

pub fn initials(i: usize) -> String {
    name(i)
        .split(' ')
        .filter_map(|w| w.chars().next())
        .take(2)
        .collect()
}

pub const ERSD: &str = "ELECTRONIC RECORD AND SIGNATURE DISCLOSURE\n\nFrom time to time, the sender may be required by law to provide you with certain written notices or disclosures. Described below are the terms and conditions for providing such notices and disclosures electronically.\n\nGetting paper copies: you may request paper copies of any record provided to you electronically at no charge.\n\nWithdrawing your consent: you may withdraw your consent to receive notices electronically at any time; doing so ends this envelope for you.\n\nRequired hardware and software: a current web browser and a PDF reader.";

/// The chain of an envelope with `n` recipients who all signed, ending at
/// `envelope.completing`, and the delivered document hash.
pub fn chain(n: usize) -> (Chain, Hash256) {
    let mut c = Chain::new(id(ENVELOPE));
    let delivered = Hash256::digest(b"delivered document bytes");
    let mut now = 0;
    let push = |c: &mut Chain, actor: Actor, ctx: Context, data: EventData, now: &mut i64| {
        *now += 1_250;
        let e = c.next(t(*now), actor, ctx, data);
        c.append(e).unwrap();
    };
    let sender = Actor {
        kind: ActorKind::Sender,
        id: Some(id("u-1")),
        name: None,
        email: None,
    };
    push(
        &mut c,
        sender.clone(),
        Context::default(),
        EventData::EnvelopeCreated {
            subject_hash: Hash256::digest(b"subject"),
        },
        &mut now,
    );
    push(
        &mut c,
        Actor::system(),
        Context::default(),
        EventData::DocumentFixed {
            document_id: id("doc-1"),
            delivered_hash: delivered,
            pages: 3,
        },
        &mut now,
    );
    push(
        &mut c,
        sender,
        Context::default(),
        EventData::EnvelopeSent {
            recipients: u32::try_from(n).unwrap(),
            documents: 1,
        },
        &mut now,
    );
    for i in 0..n {
        let rid = id(&format!("rcp-{i}"));
        let actor = Actor {
            kind: ActorKind::Recipient,
            id: Some(rid.clone()),
            name: Some(Personal(name(i))),
            email: Some(Personal(email(i))),
        };
        let ctx = Context {
            ip: Some(Personal(format!("203.0.113.{}", i + 1))),
            user_agent: Some(Personal(user_agent(i))),
            auth: vec![AuthMethod::EmailLink, AuthMethod::SmsOtp],
            session: Some(Hash256::digest(format!("session-{i}").as_bytes())),
            location: None,
        };
        push(
            &mut c,
            Actor::system(),
            Context::default(),
            EventData::InvitationSent {
                recipient_id: rid.clone(),
                channel: Channel::Email,
            },
            &mut now,
        );
        push(
            &mut c,
            actor.clone(),
            ctx.clone(),
            EventData::RecipientDelivered {
                recipient_id: rid.clone(),
            },
            &mut now,
        );
        push(
            &mut c,
            actor.clone(),
            ctx.clone(),
            EventData::RecipientAuthPassed {
                recipient_id: rid.clone(),
                method: AuthMethod::SmsOtp,
            },
            &mut now,
        );
        push(
            &mut c,
            actor.clone(),
            ctx.clone(),
            EventData::RecipientConsented {
                recipient_id: rid.clone(),
                ersd_version: "2026-01".into(),
                ersd_hash: Hash256::digest(ERSD.as_bytes()),
            },
            &mut now,
        );
        push(
            &mut c,
            actor.clone(),
            ctx.clone(),
            EventData::RecipientViewedDocument {
                recipient_id: rid.clone(),
                document: DocumentHash {
                    document_id: id("doc-1"),
                    hash: delivered,
                },
                pages_seen: vec![1, 2, 3],
            },
            &mut now,
        );
        push(
            &mut c,
            actor.clone(),
            ctx.clone(),
            EventData::RecipientSignatureAdopted {
                recipient_id: rid.clone(),
                mark: MarkKind::Signature,
                method: AdoptionMethod::Draw,
                image_hash: Hash256::digest(b"img"),
            },
            &mut now,
        );
        push(
            &mut c,
            actor,
            ctx,
            EventData::RecipientSigned {
                recipient_id: rid,
                documents: vec![DocumentHash {
                    document_id: id("doc-1"),
                    hash: delivered,
                }],
                field_value_hashes: BTreeMap::new(),
            },
            &mut now,
        );
    }
    push(
        &mut c,
        Actor::system(),
        Context::default(),
        EventData::EnvelopeCompleting {},
        &mut now,
    );
    (c, delivered)
}

pub fn user_agent(i: usize) -> String {
    format!(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_{i}) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.{i} Safari/605.1.15"
    )
}

/// The certificate input for `chain` with `n` recipients.
pub fn input(chain: &Chain, delivered: Hash256, n: usize) -> CertificateInput<'_> {
    let recipients = (0..n)
        .map(|i| {
            let (signature, initials) = marks(i);
            let base = 3 * 1_250 + i as i64 * 7 * 1_250;
            RecipientRow {
                routing_order: u32::try_from(i + 1).unwrap(),
                party: Party {
                    name: name(i),
                    email: email(i),
                },
                role: if i % 5 == 4 {
                    Role::Approver
                } else {
                    Role::Signer
                },
                auth: vec![
                    AuthStep {
                        method: AuthMethod::EmailLink,
                        passed: true,
                        at: Some(t(base + 2_500)),
                    },
                    AuthStep {
                        method: AuthMethod::SmsOtp,
                        passed: true,
                        at: Some(t(base + 3_750)),
                    },
                ],
                ip: Some(format!("203.0.113.{}", i + 1)),
                user_agent: Some(user_agent(i)),
                signature: Some(signature),
                initials: Some(initials),
                sent: Some(t(base + 1_250)),
                viewed: Some(t(base + 2_500)),
                outcome: if i % 5 == 4 {
                    Outcome::Approved(t(base + 8_750))
                } else {
                    Outcome::Signed(t(base + 8_750))
                },
                consent: Some(Consent {
                    version: "2026-01".into(),
                    hash: Hash256::digest(ERSD.as_bytes()),
                    accepted: t(base + 5_000),
                }),
            }
        })
        .collect();
    CertificateInput {
        envelope: EnvelopeSummary {
            id: ENVELOPE.into(),
            subject: "Mutual non-disclosure agreement — Q4 partnership (Ünïcødé)".into(),
            status: "Completed".into(),
            sender: Party {
                name: "Sam Sender".into(),
                email: "sam.sender@example.org".into(),
            },
            account: "Example Holdings Ltd".into(),
            created: t(1_250),
            sent: Some(t(3_750)),
            completed: None,
            seal_profile: "PAdES-B-LTA".into(),
        },
        documents: vec![DocumentRow {
            name: "Mutual NDA.pdf".into(),
            pages: 3,
            delivered,
            sealed: None,
        }],
        recipients,
        copies: vec![
            CopyRow {
                party: Party {
                    name: "Casey Copy".into(),
                    email: "casey.copy@example.org".into(),
                },
                kind: CopyKind::CarbonCopy,
                delivered: None,
            },
            CopyRow {
                party: Party {
                    name: "Vic Viewer".into(),
                    email: "vic.viewer@example.org".into(),
                },
                kind: CopyKind::Viewer,
                delivered: Some(t(9_000)),
            },
        ],
        disclosure: Some(Disclosure {
            version: "2026-01".into(),
            text: ERSD.into(),
        }),
        seal: SealInfo::Pending,
        verify_url: Some("https://sign.example.org/verify".into()),
        chain,
        generated: t(1_000_000),
    }
}
