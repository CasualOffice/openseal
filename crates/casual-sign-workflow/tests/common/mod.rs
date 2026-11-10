//! A harness that applies commands, chains their events and checks every invariant of
//! the engine after every accepted command.

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

use casual_sign_audit::{AuthMethod, Chain, EventData, Hash256, Personal, Timestamp};
use casual_sign_model::{
    EnvelopeStatus, Field, FieldType, Id, Placement, Points, RecipientStatus, RecipientType,
    RoutingOrder, Text,
};
use casual_sign_workflow::{
    Change, Command, Context, Decision, DocumentSpec, EffectKind, EnvelopeState, Policy, Principal,
    RecipientSpec, SealedDocument, WorkflowError, decide,
};
use rust_decimal::Decimal;

pub fn id(s: &str) -> Id {
    Id::new(s).unwrap()
}

/// 2026-11-10T09:00:00.000Z plus `ms`.
pub fn t(ms: i64) -> Timestamp {
    Timestamp::from_unix_millis(1_794_301_200_000 + ms).unwrap()
}

pub const DAY: i64 = 86_400_000;

pub fn h(n: u8) -> Hash256 {
    Hash256([n; 32])
}

pub fn text(s: &str) -> Personal<Text> {
    Personal(Text::new(s).unwrap())
}

pub fn sender() -> Principal {
    Principal::Sender {
        user_id: id("sender"),
    }
}

pub fn as_recipient(r: &str) -> Principal {
    Principal::Recipient {
        recipient_id: id(r),
    }
}

pub fn recipient(rid: &str, rtype: RecipientType, order: u32) -> RecipientSpec {
    RecipientSpec {
        id: id(rid),
        rtype,
        routing_order: RoutingOrder::new(order).unwrap(),
        name: text(&format!("Name {rid}")),
        email: text(&format!("{rid}@example.test")),
        phone: None,
        delivery: casual_sign_model::Delivery::Email,
        auth: Vec::new(),
        embedded_client_user_id: None,
        time_zone_offset_minutes: 0,
        date_format: None,
        witness_for: None,
    }
}

pub fn document(did: &str, n: u8, pages: u32) -> DocumentSpec {
    DocumentSpec {
        id: id(did),
        name: text(&format!("{did}.pdf")),
        upload_hash: h(n),
        bytes: 1000,
        delivered_hash: h(n.wrapping_add(100)),
        pages,
        admission: Some((h(n.wrapping_add(50)), 0)),
    }
}

pub fn field(fid: &str, did: &str, rid: &str, ft: FieldType, required: bool) -> Field {
    let p = |v: i64| Points::new(Decimal::from(v)).unwrap();
    let mut f = Field::new(
        id(fid),
        id(did),
        ft,
        Placement::new(1, p(10), p(10), p(100), p(20)).unwrap(),
    );
    f.recipient_id = Some(id(rid));
    f.required = required;
    f
}

pub fn add_field(f: Field) -> Change {
    Change::AddField { field: Personal(f) }
}

/// The seal job's honest answer for the envelope as it stands.
pub fn sealed(state: &EnvelopeState) -> Vec<SealedDocument> {
    state
        .documents
        .iter()
        .enumerate()
        .map(|(i, d)| SealedDocument {
            document_id: d.spec.id.clone(),
            delivered_hash: d.spec.delivered_hash,
            flattened_hash: h(200 + i as u8),
            sealed_hash: h(220 + i as u8),
            profile: state.seal_profile,
            certificate_fingerprint: h(250),
            tsa_time: Some(t(0)),
            verified: true,
        })
        .collect()
}

/// Which invariant checks run. Every check is on by default; the red-test demonstrations
/// in the property tests leave them all on.
#[derive(Debug, Clone)]
pub struct Harness {
    pub state: Option<EnvelopeState>,
    pub now: i64,
    pub next_command: u64,
    pub policy: Policy,
    pub chain: Chain,
    /// Every accepted (command, context) pair, for replay checks.
    pub accepted: Vec<(Command, Context)>,
    /// Events appended, by type name.
    pub event_types: Vec<String>,
}

impl Default for Harness {
    fn default() -> Self {
        Self::new()
    }
}

impl Harness {
    pub fn new() -> Self {
        Self {
            state: None,
            now: 0,
            next_command: 0,
            policy: Policy::default(),
            chain: Chain::new(id("env-1")),
            accepted: Vec::new(),
            event_types: Vec::new(),
        }
    }

    pub fn state(&self) -> &EnvelopeState {
        self.state.as_ref().unwrap()
    }

    pub fn status(&self) -> EnvelopeStatus {
        self.state().status
    }

    pub fn rstatus(&self, rid: &str) -> RecipientStatus {
        self.state().recipient(&id(rid)).unwrap().status
    }

    pub fn ctx(&mut self, principal: Principal) -> Context {
        self.next_command += 1;
        Context {
            command_id: id(&format!("cmd-{}", self.next_command)),
            now: t(self.now),
            principal,
            request: casual_sign_audit::Context::default(),
            expected_version: None,
            policy: self.policy.clone(),
        }
    }

    /// Runs `cmd` as `principal`; on success checks every invariant and keeps the state.
    pub fn run(&mut self, principal: Principal, cmd: Command) -> Result<Decision, WorkflowError> {
        let ctx = self.ctx(principal);
        self.run_ctx(cmd, ctx)
    }

    pub fn run_ctx(&mut self, cmd: Command, ctx: Context) -> Result<Decision, WorkflowError> {
        let prev = self.state.clone();
        let d = decide(prev.as_ref(), &cmd, &ctx)?;
        check_invariants(prev.as_ref(), &cmd, &ctx, &d);
        for e in &d.events {
            let ev = e.clone().into_audit(&self.chain);
            self.event_types.push(serde_type_name(&e.data));
            self.chain.append(ev).expect("events chain");
        }
        self.state = Some(d.state.clone());
        self.accepted.push((cmd, ctx));
        Ok(d)
    }

    /// Runs and unwraps.
    pub fn ok(&mut self, principal: Principal, cmd: Command) -> Decision {
        match self.run(principal, cmd) {
            Ok(d) => d,
            Err(e) => panic!("refused: {e}"),
        }
    }

    pub fn create(&mut self) {
        self.ok(
            sender(),
            Command::Create {
                envelope_id: id("env-1"),
                account_id: id("acct-1"),
                sender_user_id: id("sender"),
                subject: text("Please sign"),
                message: text("Hello"),
            },
        );
    }

    /// A draft with one document and `recipients`, each signer with a required
    /// signature field.
    pub fn draft(&mut self, recipients: &[RecipientSpec]) {
        self.create();
        let mut changes = vec![Change::AddDocument {
            document: document("doc-1", 1, 2),
        }];
        for r in recipients {
            changes.push(Change::AddRecipient {
                recipient: r.clone(),
            });
            if r.rtype.signs() {
                changes.push(add_field(field(
                    &format!("sig-{}", r.id),
                    "doc-1",
                    r.id.as_str(),
                    FieldType::Signature,
                    true,
                )));
            }
        }
        self.ok(sender(), Command::Edit { changes });
    }

    pub fn send(&mut self) -> Decision {
        self.ok(sender(), Command::Send)
    }

    /// Opens, passes auth, consents (if the policy needs it) and adopts a signature.
    pub fn get_ready(&mut self, rid: &str) {
        let p = self.principal_for(rid);
        self.ok(p.clone(), Command::OpenLink { recipient: id(rid) });
        let auth = self.state().recipient(&id(rid)).unwrap().spec.auth.clone();
        for m in auth {
            self.ok(
                p.clone(),
                Command::AuthResult {
                    recipient: id(rid),
                    method: m,
                    passed: true,
                },
            );
        }
        if let Some(e) = self.policy.ersd.clone() {
            self.ok(
                p.clone(),
                Command::Consent {
                    recipient: id(rid),
                    ersd_version: e.version,
                    ersd_hash: e.hash,
                },
            );
        }
    }

    pub fn principal_for(&self, rid: &str) -> Principal {
        let r = self.state().recipient(&id(rid)).unwrap();
        if let Some(host) = &r.in_person_host {
            return Principal::InPersonHost {
                user_id: host.clone(),
            };
        }
        as_recipient(rid)
    }

    /// Takes a signer from invitation to signed.
    pub fn sign(&mut self, rid: &str) -> Decision {
        self.get_ready(rid);
        let p = self.principal_for(rid);
        self.ok(
            p.clone(),
            Command::AdoptSignature {
                recipient: id(rid),
                mark: casual_sign_audit::MarkKind::Signature,
                method: casual_sign_audit::AdoptionMethod::Type,
                image_hash: h(9),
            },
        );
        let values = self
            .state()
            .fields
            .0
            .iter()
            .filter(|f| {
                f.recipient_id.as_ref() == Some(&id(rid)) && f.field_type == FieldType::Signature
            })
            .map(|f| casual_sign_workflow::FieldEntry {
                field: f.id.clone(),
                value: Personal(casual_sign_model::FieldValue::Signature(id("img-1"))),
            })
            .collect();
        self.ok(
            p,
            Command::Finish {
                recipient: id(rid),
                values,
            },
        )
    }

    pub fn seal(&mut self) -> Decision {
        let job = self.state().book.seal_job.clone().unwrap();
        let documents = sealed(self.state());
        self.ok(Principal::System, Command::SealSucceeded { job, documents })
    }
}

pub fn serde_type_name(data: &EventData) -> String {
    let v = serde_json::to_value(data).unwrap();
    v["type"].as_str().unwrap().to_owned()
}

pub fn auth(methods: &[AuthMethod], mut r: RecipientSpec) -> RecipientSpec {
    r.auth = methods.to_vec();
    r
}

/// Every invariant of the engine, checked on one accepted decision.
pub fn check_invariants(prev: Option<&EnvelopeState>, cmd: &Command, ctx: &Context, d: &Decision) {
    let next = &d.state;

    // Determinism: the same inputs give the same decision.
    let again = decide(prev, cmd, ctx).expect("decided once, decides again");
    assert_eq!(&again, d, "decide is not deterministic");

    // Idempotency: re-applying the command id to the new state is a replay with no
    // events and no effects, and changes nothing.
    let replay = decide(Some(next), cmd, ctx).expect("replay accepted");
    assert!(replay.replayed, "re-applied command was not recognised");
    assert!(replay.events.is_empty() && replay.effects.is_empty());
    assert_eq!(&replay.state, next, "replay changed the state");

    if d.replayed {
        return;
    }

    // Every observable state change emits at least one audit event.
    let changed = prev.is_none_or(|p| p.observable() != next.observable());
    if changed {
        assert!(
            !d.events.is_empty(),
            "state changed with no audit event on {}",
            cmd.name()
        );
    }

    if let Some(p) = prev {
        // No transition from a terminal state.
        if p.status.is_terminal() {
            assert_eq!(
                p.status,
                next.status,
                "{} moved a terminal envelope",
                cmd.name()
            );
            for e in &d.effects {
                assert!(
                    !matches!(
                        e.kind,
                        EffectKind::SendInvitation { .. }
                            | EffectKind::SendReminder { .. }
                            | EffectKind::SendExpiryWarning { .. }
                            | EffectKind::Schedule { .. }
                            | EffectKind::SealEnvelope { .. }
                            | EffectKind::ChargePayment { .. }
                    ),
                    "{} started work on a terminal envelope",
                    cmd.name()
                );
            }
        }

        // `completed` only after a verified seal input.
        if next.status == EnvelopeStatus::Completed && p.status != EnvelopeStatus::Completed {
            assert_eq!(p.status, EnvelopeStatus::Completing);
            let Command::SealSucceeded { job, documents } = cmd else {
                panic!("completed by {}", cmd.name());
            };
            assert_eq!(p.book.seal_job.as_ref(), Some(job));
            assert_eq!(documents.len(), p.documents.len());
            for doc in &p.documents {
                let s = documents
                    .iter()
                    .find(|s| s.document_id == doc.spec.id)
                    .expect("every document sealed");
                assert!(s.verified, "completed on an unverified seal");
                assert_eq!(s.delivered_hash, doc.spec.delivered_hash);
            }
            assert!(
                d.events
                    .iter()
                    .any(|e| matches!(e.data, EventData::EnvelopeCompleted { .. }))
            );
        }

        // Voided, declined or expired: every pending effect is cancelled.
        let stopped = matches!(
            next.status,
            EnvelopeStatus::Voided | EnvelopeStatus::Declined | EnvelopeStatus::Expired
        );
        if stopped && next.status != p.status {
            let cancelled: Vec<_> = d
                .effects
                .iter()
                .filter_map(|e| match &e.kind {
                    EffectKind::Cancel { effects } => Some(effects.clone()),
                    _ => None,
                })
                .flatten()
                .collect();
            // The timer that fired in this command is consumed, not pending.
            let fired = match cmd {
                Command::TimerDue { timer } => Some(timer),
                _ => None,
            };
            for pending in p.pending_effects() {
                if fired == Some(&pending) {
                    continue;
                }
                assert!(
                    cancelled.contains(&pending),
                    "pending {pending:?} not cancelled when the envelope stopped"
                );
            }
            for e in &d.effects {
                assert!(
                    !matches!(
                        e.kind,
                        EffectKind::SendInvitation { .. }
                            | EffectKind::SendReminder { .. }
                            | EffectKind::Schedule { .. }
                            | EffectKind::SealEnvelope { .. }
                    ),
                    "the stopping decision started new work"
                );
            }
        }
    }
    if next.is_finished() {
        assert!(
            next.pending_effects().is_empty(),
            "a finished envelope keeps pending effects"
        );
    }

    // Routing order: nobody is invited, or active, before their turn.
    for e in &d.effects {
        if let EffectKind::SendInvitation { recipient, .. } = &e.kind {
            let i = next.recipient_index(recipient).expect("invited exists");
            assert!(
                next.turn_reached(i),
                "{recipient} invited before their routing turn"
            );
            assert_ne!(next.recipients[i].status, RecipientStatus::Created);
        }
    }
    if next.status.is_in_flight() {
        for (i, r) in next.recipients.iter().enumerate() {
            if r.status.is_active() {
                assert!(next.turn_reached(i), "{} active out of turn", r.id());
            }
        }
    }

    // Recipient states and envelope states agree.
    if next.status == EnvelopeStatus::Draft {
        assert!(
            next.recipients
                .iter()
                .all(|r| r.status == RecipientStatus::Created)
        );
    }
    if matches!(
        next.status,
        EnvelopeStatus::Completing | EnvelopeStatus::Completed
    ) {
        assert!(
            next.recipients
                .iter()
                .filter(|r| r.is_required())
                .all(|r| r.status == RecipientStatus::Completed)
        );
    }

    // The version rises exactly when something observable changed.
    if let Some(p) = prev {
        if changed {
            assert_eq!(next.version, p.version + 1);
        } else {
            assert_eq!(next.version, p.version);
        }
    }
}
