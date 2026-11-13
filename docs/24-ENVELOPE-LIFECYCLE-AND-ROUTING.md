# 24 — Envelope lifecycle, routing and commands

**Status: Draft for owner.** How `casual-sign-workflow` moves envelopes and recipients through their states. This plays
the role OpenPresent's docs/24 (operations) plays there: **every change is a command; the engine returns the new state,
the events, and the effects.**

## 1. The command model

```rust
// Illustrative; the real signatures are in casual-sign-workflow.
fn apply(state: &EnvelopeState, cmd: Command, ctx: &Context) -> Result<Outcome, WorkflowError>;

struct Context { now: Timestamp, actor: Actor, ids: IdSource, policy: AccountPolicy }
struct Outcome { state: EnvelopeState, events: Vec<AuditEvent>, effects: Vec<Effect> }
```

- `apply` is pure: no clock, no I/O. The server loads the state, calls `apply`, and in **one database transaction**
  writes the new state, appends the events to the chain, and enqueues the effects as jobs. Only then does it answer.
- `Effect` is data: `SendInvitation{recipient}`, `SendReminder`, `SendCompletionCopies`, `ScheduleExpiry{at}`,
  `SealEnvelope`, `DeliverWebhook{event}`, `RevokeTokens{recipient}`, `ChargePayment`. Jobs perform effects
  idempotently, keyed by `(envelope_id, effect_id)`.
- Optimistic concurrency: a command carries the envelope `version` it read; a stale version is `CS-WF-0002` and the
  client re-reads. Two signers finishing at the same moment in a parallel step both succeed, because each touches only
  its recipient; the second commit re-runs `apply` on the fresh state.

## 2. Envelope states

```
            ┌───────── void ─────────┐
            │                        ▼
 draft ──send──▶ sent ──first open──▶ delivered ──last required action──▶ completing ──sealed──▶ completed
   │              │  ▲                 │   ▲                                    │
   │           correct│               correct                              seal failed: retried, stays
   │              ▼  │                 ▼   │                                    completing (alert)
   │           (correcting: same state, edits allowed, re-send on save)
   │              │                    │
   │              ├──decline──▶ declined  (any signer declines; envelope stops)
   │              └──expire───▶ expired   (expires_at passed with required actions open)
   └──delete──▶ (removed; drafts only)
                  voided  ◀── void (sender or admin, with reason, any state before completing)
```

| From | Command | To | Events | Effects |
| --- | --- | --- | --- | --- |
| `draft` | `Send` | `sent` | `envelope.sent`, `document.fixed` per document | Invitations to the first routing step; expiry; reminders |
| `sent`/`delivered` | `Void{reason}` | `voided` | `envelope.voided` | Notify active recipients; revoke tokens; webhooks |
| `sent`/`delivered` | `Correct{changes}` | same | `envelope.corrected` | Re-invite affected recipients; reset their status if a signed document changed |
| `sent`/`delivered` | recipient `Decline` | `declined` | `recipient.declined`, `envelope.declined` | Notify sender and prior signers |
| `sent`/`delivered` | timer `Expire` | `expired` | `envelope.expired` | Notify |
| `delivered` | last `Complete` | `completing` | `recipient.completed`, `envelope.completing` | `SealEnvelope` |
| `completing` | worker `SealSucceeded{hash}` | `completed` | `envelope.completed` | Completion copies; webhooks |

`delivered` is reached when **every** recipient routing has reached has viewed (DocuSign's meaning, [48](48-DOCUSIGN-STUDY.md) §6); it is a reporting state with the same permissions as `sent`.
`completing` exists so that **an envelope is never `completed` without a verified seal** ([02](02-HLD.md) §5.3).

## 3. Recipient states

```
created ──(routing reaches me)──▶ sent ──open──▶ delivered ──auth passed──▶ authenticated ──finish──▶ completed
   │                                │ ▲                                         │
   │                                │ └── resend / correct                      ├──decline──▶ declined
   │                                ├── bounce ──▶ auto_responded (sender alerted, may correct email)
   │                                └── reassign ──▶ reassigned (new recipient inserted at same routing order)
```

- Receive-a-copy (`cc`) recipients go straight to `completed` when routing reaches them (they are sent a copy, then,
  by default, the completed documents).
- Viewers complete by viewing every document to the end.
- Approvers complete with Approve or decline with Decline; they never sign.
- Editors (allowed to edit) may change later recipients and fields before signing.
- Agents (specify recipients) supply the name and email of later recipients (`POST /s/{token}/recipients`, docs/40 §6), then finish.
- In-person signers are hosted by a staff user who authenticates first; the event records both. On the server
  (`UXW-36`), `POST /envelopes/{id}/recipients/{r}/host` runs `HostInPerson` as `InPersonHost` and returns a one-time
  link whose every command runs as that host (docs/40 As built); the signer's emailed link cannot act for them.
- **Signer location (GEO-01).** When the envelope's `signing_options.capture_location` is on, the signing page asks the
  signer for their device's location; every recipient action (`recipient.delivered`, `recipient.viewed_document`,
  `recipient.signed`, `recipient.approved`, `recipient.declined`) then carries a location in its context
  ([32](32-AUDIT-TRAIL-AND-EVIDENCE.md) §2). **A refusal never blocks signing:** if the signer declines or the device
  gives nothing, the server supplies an approximation from the IP address with the reason (`declined`,
  `unavailable`), and that satisfies the engine. Only an action with no location at all is refused (`CS-WF-0019`),
  which the server prevents by always supplying the fallback. A location that contradicts the setting (the signer
  asked although it is off; `not_requested` although it is on) is `CS-WF-0020`. With the setting off nothing is
  required; the host may still record an IP approximation flagged `not_requested`.

## 4. Routing

- **Routing order** groups recipients: all recipients with order *n* are activated when every required recipient
  with order < *n* has completed. Equal numbers are parallel; distinct numbers are sequential; both together are mixed.
- **Conditional routing** (slice 29): a `RoutingRule` activates or skips a recipient or a group based on field
  values (`when amount > 10000, add role "Finance approval"`). Rules are evaluated by the engine at each step from
  values already completed; the evaluation and its inputs are audit events.
- **Signing groups** (slice 29): one of several people may act; the first to complete does so for the group.
- **Delegation and reassignment** create a new recipient at the same order and mark the old one `reassigned`, with
  both in the chain.
- An envelope **completes** when every recipient with a required action has completed. Optional signature fields do
  not block.

## 5. Field rules at completion

On `Complete`, the engine re-runs everything the browser ran, on the server: required fields present, validations,
checkbox and radio group rules, conditional visibility (a hidden field's value is dropped and recorded as dropped),
formulas recomputed and compared, `date_signed` stamped with server time in the recipient's zone, attachment uploads
admitted. A client that lied fails here with field-level codes (`CS-FLD-*`).

## 6. Correct

A correction may change recipients not yet completed, their email, auth, routing order, fields belonging to them,
reminders, expiry, and **documents** (add, remove, replace). The engine computes the impact:

| Change | Effect on completed recipients |
| --- | --- |
| A document they signed is replaced or its fields changed | Their status returns to `sent`; they re-sign; the earlier signing remains in the chain |
| A document added | Only recipients with fields on it act on it |
| A recipient not yet reached changed | None |

## 7. Timers

Reminders, expiry and the "expiring soon" warning are effects with a due time, persisted as scheduled jobs. The timer
fires a command (`RemindDue`, `Expire`) that the engine evaluates against the current state, so a timer for an envelope
that has since completed is a no-op with no event.

## 8. Bulk send

A bulk send is a template, a list (CSV or API) of rows each supplying recipients and field values, and a batch id. The
worker creates and sends one envelope per row with the same commands as a single send, rate-limited per account; each
row's success or failure is recorded on the batch. A bulk send is cancellable while rows remain unsent.

## 9. Signing links (PowerForms)

A signing link is a public URL bound to a template. The visitor supplies their name and email (verified by email OTP
by default), an envelope is created from the template with the visitor as the first role, and the flow continues as a
normal envelope. Links have use limits, expiry and rate limits; they are an abuse surface (docs/07 `SEC-L*`).

## 10. Errors

Every rejected command returns a `WorkflowError` with a stable `CS-WF-*` or `CS-FLD-*` code (docs/20) and the ids of the
objects concerned, never their content.

## As built (stage 2A, `T-2A`)

`casual_sign_workflow::decide(state: Option<&EnvelopeState>, command: &Command, ctx: &Context) -> Result<Decision, WorkflowError>`;
`Decision { state, events: Vec<PendingEvent>, effects: Vec<Effect>, replayed }`. `Context` carries `command_id`, `now`,
`principal`, the request context copied into events, `expected_version` and the account `Policy`. Builds for
`wasm32-unknown-unknown` with no `#[cfg]` fork.

**Decisions taken here** (recorded for the owner):

- **The aggregate lives in the engine.** `casual-sign-model` gained the plain vocabulary (`EnvelopeStatus`,
  `RecipientStatus`, `RecipientType`, `RoutingOrder` 1–999, `Delivery`, `SealProfile`, `SigningOptions`,
  `ReminderPolicy` ≤ 999 days); `EnvelopeState`, `RecipientState` and `DocumentState` are in `-workflow` because they
  carry `Hash256`, `Timestamp` and `Personal` from `-audit`, which `-model` does not depend on.
- **Events are the docs/32 §3 types** (`casual_sign_audit::EventData`), returned unchained; the server numbers and
  appends them with `PendingEvent::into_audit(&chain)` in the same transaction (ADR-010).
- **Ids are supplied in commands**, not drawn from an id source: new recipients, fields and documents carry their ids.
  Effect ids are `(command_id, index)`, so a re-run decision names the same jobs.
- **Idempotency.** The state records every applied command id with the SHA-256 of the command's RFC 8785 form. The same
  id and command again is `replayed` (no events, no effects, state unchanged); the same id with another command is
  `CS-WF-0006`. The record is bounded at 100,000 commands (`CS-WF-0011`).
- **Version.** Raised by every observable change; recording access, timers that do nothing, and bookkeeping (applied
  ids, pending timers, the seal job) do not raise it. `expected_version` is checked when the command carries one.
- **Correction is one command** (`Correct { changes }`): the "correcting" mode is the client's; saving sends the list,
  applied all or none, and a signer acting meanwhile makes it stale.
- **A draft's own edits** (`Edit`, including the one the server issues inside create) record `envelope.corrected` with
  the paths changed, besides a document's `document.added` and `document.admitted`: every observable change must emit
  an event (the engine's property tests hold it), and docs/32 §3 has no draft type. A correction is meant only after
  `envelope.sent`, so this is a known defect (`WEB-14`): ADR-030 (Proposed) adds `envelope.edited` for draft edits.
  Until it is Accepted, the signer's history (`GET /s/{token}/history`, docs/40 As built) shows milestones only from
  the first `envelope.sent`; the sender's audit list (`GET …/audit`) still shows the draft's `envelope.corrected`.
- **§6 "its fields changed"** is read as: a completed recipient acts again when a document they acted on is replaced or
  removed, or when **their own** fields change. Changing a not-yet-completed recipient's fields does not send others back.
- **A changed link** (WEB-06): correcting an active recipient's email, phone, delivery or authentication requirements
  revokes their links and sends a new invitation, so no session opened under the old details carries them past the
  new checks; a name change alone keeps the link. Recipients not yet reached have no link to revoke.
- **`delivered` is recomputed** after every command: when routing reaches a recipient who has not opened, the envelope
  is `sent` again until they do.
- **Routing after every change**: a recipient whose turn no longer holds (a correction added someone earlier, or sent a
  completed signer back) returns to `created` with tokens revoked; whoever's turn holds is invited. This keeps
  "nobody acts before their turn" true through corrections.
- **Timers** are `Schedule { timer, at }` effects answered by `TimerDue { timer }` (this is `RemindDue`, `Expire` and
  the expiry warning); a timer not pending is a no-op with no event. `Expire` alone is a sweeper's command.
- **Completion** is `SealSucceeded { job, documents }`: the pending job, every document exactly once, `verified: true`
  (the independent validator's verdict), sealed from the delivered hash, at the envelope's profile; otherwise
  `CS-WF-0009`. It records `document.flattened`, `document.sealed` per document, then `envelope.completed`.
  `SealFailed` keeps `completing`, alerts, and schedules a new seal job; the old job's late success is refused.
- **Delete draft** records `envelope.purged` (policy `draft_deleted`) and marks the envelope purged.
- **Delete ended** (`DeleteEnded`, `WEB-08`): the sender or an administrator removes an envelope that ended without
  completing (`declined`, `voided`, `expired`) from the lists. It records `envelope.deleted`, sets the state's
  `deleted_at`, and changes nothing else: no status change, no scrub, no effect; the chain and evidence stay and later
  access is still recorded. Any other status, a purged envelope, or a second time is `CS-WF-0001`.
  Bringing one back to the lists is a planned command `RestoreDeleted` recording `envelope.restored` (ADR-031,
  Proposed, `UXW-02`); until it is Accepted the server lists deleted envelopes (the Deleted view) but restores none.
- **The Inbox's signing link** (`POST …/sign-link`, `UXW-01`) is not a command: a signed-in member who is, by account
  email, a recipient whose turn it is and who acts through a link gets a one-time link of purpose `account` naming
  them. Opening and acting on it run as that recipient, exactly as an emailed link, every authentication the sender
  required included; the trail records `account_login` as how the link was obtained. Routing is unchanged.
- **An envelope that ends without completing** (declined, voided, expired) queues the worker's
  `seal_ended_certificate` (`UXW-30`): the envelope certificate is made and sealed on its own and the chain is not
  extended; the envelope's state and documents are untouched.
- **Attachment downloaded** (`Access::AttachmentDownloaded {field, hash}`, `WEB-08`) records `attachment.downloaded`
  only when the field's value names that hash (`CS-WF-0008` otherwise).
- **Withdrawing consent** declines for a recipient with a required action, whatever `allow_decline` says. It needs the same gate as declining (`gate_in`: opened, not locked, every authentication passed; `SEC-CER-01`), since consent outlives a correction that clears the authentication.
- **A signer with no signature field** must still adopt a signature before finishing (free-form signing, intent).
- **Sending needs a recipient with a required action**; an envelope of carbon copies only is `CS-WF-0004`.
- **Location (GEO-01)** is checked after the command is decided, against the setting as it stood before the command,
  over the events the request produced: the five recipient-action types must carry `ctx.request.location` when
  `capture_location` is on. Checking last means every other refusal (permission, state, turn) keeps its own code.
  Events the platform records as a consequence (`envelope.completing`, routing) carry no request context, so no
  location. Tested by `tests/location.rs`.

| docs/24 item | Built |
| --- | --- |
| Create; edit documents, recipients, fields, subject, message, expiry, reminders, options, seal profile while draft | Built |
| Send (validate for send returning every violation; `document.fixed`; first step invited; expiry, warning, reminders scheduled) | Built |
| Delete draft | Built |
| Delete an envelope that ended without completing from the lists (`envelope.deleted`, nothing purged; `WEB-08`) | Built |
| Deliver/open (`recipient.delivered`; envelope `delivered` per §2) | Built |
| Consent to the current ERSD; withdraw | Built |
| Authenticate: challenge, pass, fail with lockout after `max_auth_attempts`, unlock by resend; host-asserted | Built |
| View documents (hash and pages checked); viewers complete by viewing every document to the end | Built |
| Adopt signature or initials; complete fields (validated); signature values need adoption | Built |
| Sign (field rules re-run, hidden values dropped, `date_signed` stamped in the recipient's offset and format, name, email and envelope id filled, payments charged) | Built |
| Approve (approver's own field rules re-run) | Built |
| Agents and intermediaries name later recipients, editors also fields and recipients, then complete; unreachable later recipient refused | Built |
| In-person signing hosted by a staff user | Built |
| Decline (envelope declined; prior signers and sender told) | Built |
| Reassign (new recipient at the same order, fields moved, both in the chain) | Built |
| Finish later | Built |
| Correct with re-routing and the §6 impact | Built |
| Void with reason | Built |
| Expire (timer and sweep); expiry warning | Built |
| Resend (clears bounce and lock); remind; reminder timers | Built |
| Invitation dispatched, reminder dispatched, bounce (`auto_responded`) | Built |
| `completing` → `completed` only on a verified seal; seal failure retried | Built |
| Purge (terminal only; personal data scrubbed, hashes kept) | Built |
| Access events (sender viewed, document, certificate and signer attachment downloaded) | Built |
| Signer location on recipient actions when `capture_location` is on; refusal recorded, never blocking (GEO-01) | Built (engine, and the server's capture and GeoIP fallback, docs/40 §As built) |
| Routing: sequential, parallel, mixed; carbon copies complete when reached | Built |
| Conditional routing, signing groups (§4, slice 29) | **Not built**: no event type or status for a skipped recipient or a group member's act (rows proposed) |
| Bulk send (§8), signing links (§9) | **Not in the engine**: host jobs that issue `Create`/`Edit`/`Send` |
| Witness ordering, legal-entity seal recipient, notary | **Partial**: act as signers; witnessing after the witnessed signer, a `Seal` recipient acting through `RemoteSigner`, and notary steps belong to slices 16, 18, 31 |

Tested by `tests/transitions.rs` (one test per transition) and `tests/properties.rs` (256 random envelopes under up to
60 random commands each, every invariant checked after every accepted command and the chain verified; a second
property drives every valid envelope to `completed`; a seeded run shows the sequences reach every status). Each
invariant was seen to fail with its guard removed.

## As built: effects (stage 2D, `T-2D`)

`server/casual-sign-worker` runs the effects. **Decide and record** is one path, `casual_sign_host::apply_in(tx,
envelope, command, context)` (`server/casual-sign-host`, which the API server and the worker both use; neither depends
on the other): in one `TenantTx` it locks the envelope's stored engine state (`envelope_states`, migration 0008, the
`EnvelopeState` as the engine serializes it, with a row revision; the only place the state lives), calls `decide`,
appends the events to the chain (`PendingEvent::into_audit`, re-verified as read), writes the state at the revision
read, brings the relational rows into line (every projected column of the envelope, each recipient's row and status,
a draft's removed recipients pruned, missing document rows; a document removed from a draft keeps its row, whose
versions are write-once), revokes the tokens of a `RevokeTokens` effect in that transaction, and enqueues one job per
other effect. The server calls `apply_loaded` on a state it locked with `load_for_update` at the start of the request.

**The job contract** (`casual_sign_host::jobs`): `kind` is the effect's kind in snake case (the table below;
`Schedule` is `timer`); `idempotency_key` is `effect:<envelope>:<command id>:<index>`, the effect's id, so a decision
recorded again names the same job and the queue keeps one; `payload` is `{envelope_id, effect, decided_at, version,
status}` (ids and parameters only); `run_at` is a `Schedule`'s time, a `SealEnvelope`'s `not_before`, else the
decision's time. `Cancel` and `RevokeTokens` enqueue nothing. Invitation tokens are minted by the worker as it sends.

| Effect | Job | What the worker does | Result fed back |
| --- | --- | --- | --- |
| `SendInvitation` | `send_invitation` | Email (act or copy template) with a fresh link token (256 random bits, base64url; its SHA-256 stored, `SEC-A01`); `link` delivery sends nothing | `InvitationDispatched`, or `InvitationBounced` when the SMTP server refuses the address permanently |
| `SendReminder` | `send_reminder` | Reminder email with a fresh link | `ReminderDispatched` |
| `SendExpiryWarning` | `send_expiry_warning` | Warning email with a fresh link | — |
| `NotifySender` | `notify_sender` | Email to the sender's address (voided, declined, expired, completed, locked, bounced, corrected) | — |
| `NotifyRecipients` | `notify_recipients` | Email to each recipient named | — |
| `SendCompletionCopies` | `send_completion_copies` | Email to each, with a `completed_copy` link | — |
| `Schedule` | `timer` | Due at its time | `TimerDue` (a timer no longer pending is the engine's no-op) |
| `SealEnvelope` | `seal_envelope` | Only while `completing` with this job pending: fill and flatten each delivered document (from the blob store, its hash checked), certificate of completion with the stored chain as `audit-trail.json`, seal at the envelope's profile through keyd (`RemoteKey`, the development `/Reason` when keyd says its key is one) with the configured TSAs, store the sealed bytes as a `sealed` document version, read them back and verify them (docs/31 rung 1, independent of the seal's self-check); the certificate of completion is also rendered on its own with the trail embedded, sealed, verified as stored and recorded as `envelopes.certificate_sha256` (migration 0009) in the same transaction | `SealSucceeded` with `verified: true`, or `SealFailed` with the code (the engine alerts and schedules a new job) |
| `RevokeTokens` | none | Performed inside the deciding transaction (`casual_sign_host::apply`), so a revoked link stops working when the answer is given | — |
| `DeliverWebhook` | `deliver_webhook` | docs/40 §4 as built | — |
| (not an effect, `WEB-06`) | `send_user_invitation` | Mint a user invitation's one-time link (hash and 7-day expiry stored, earlier link replaced) and email it; nothing for an invitation accepted or revoked meanwhile; once per job (a job step) | — |
| `ChargePayment` | `charge_payment` | Through `PaymentGateway`; the only one built refuses (`CS-WRK-0014`, dead-lettered with an alert) until slice 13 | — |
| `AlertOperator` | `alert_operator` | To the operator's `AlertSink` (a log line by default) | — |
| `PurgeData`, `DeleteDraft` | `purge_data`, `delete_draft` | Revoke every token of the envelope; blobs stay (write-once, no delete: slice 15) | — |
| `Cancel` | none | The engine's own guards: a cancelled timer's `TimerDue` is a no-op, a cancelled seal job is not run (checked before sealing) and its result refused | — |

**Idempotency and crashes.** The claim is the store's `SKIP LOCKED` entry point under a 300 s lease, renewed every
100 s; a lapsed lease is claimed again. A job's external act (an email accepted, a webhook answered, documents sealed
and stored) is recorded as a job step (`job_steps`, insert-only) in its own transaction the moment it happens; the
result command and `complete` then commit together. The result command's id is `job-<job uuid>`, so a second
application is `replayed`. A crash leaves: before the act, nothing (the job reruns); after the act and its record, the
act skipped on rerun; between the act and its record, the act once more on rerun, the **at-least-once window**, with
the same `Message-ID` (derived from the job and recipient) or `webhook-id`, which receivers collapse. A seal crashed
after keyd signed and before the sealed bytes were recorded is sealed again on rerun (keyd's log shows two
signatures; `KEYD-03` reconciles); one crashed after the record is not. A result command the engine refuses because
the envelope moved on (voided meanwhile) is recorded as a step and the job finishes. Failures retry with exponential
back-off and equal jitter (30 s doubling, capped at 12 h) up to 15 attempts; a *final* code (docs/20 `CS-WRK-*`)
dead-letters the job at once; a dead job raises an operator alert.

**Tested** (PostgreSQL 17, an in-process SMTP sink, an HTTPS receiver; `server/casual-sign-worker/tests`): a
two-signer envelope driven through the engine and store to `completed`, its sealed PDF accepted by our verifier and
pyHanko; crash tests stopping the worker dead at every boundary (after claim, after the SMTP server accepted, after
the record, mid-webhook, after keyd signed, with the result applied but uncommitted) and restarting; an unverified
seal leaving the envelope `completing` with an alert; a bounce; a reminder timer; back-off; dead-lettering; SSRF
refusal; the seal through keyd with the development reason. Seen red: the email step check removed (two emails after
a crash past the record), the stored-seal verification removed (the envelope completed on a seal that does not
verify), the development reason dropped, both SSRF checks removed.

**Process crash tests (Phase 2 exit item 2, `P2-CRASH`).** `server/casual-sign-worker/tests/process_crash.rs` runs
the real `casual-sign-server` and `casual-sign-worker` binaries as child processes against PostgreSQL 17, an SMTP
sink, an HTTPS webhook receiver, keyd over mTLS (development file key) and an RFC 3161 TSA over HTTP, and kills them
with `SIGKILL` at named points: the test-only `crash-points` feature (`casual_sign_host::crash`, off in every release
and deployed build; `OPENSEAL_CRASH_AT=<kind>:<suffix>`) adds `before_commit:<Command>` at the end of decide and
record, `after_commit:<route>` after a handler committed and before its answer (and before an idempotency key keeps
it), and `worker:<Boundary>:<job kind>` at each worker boundary. Covered: send, ceremony finish, decline, void and
correct, each killed before and after commit, then retried (the same `Idempotency-Key` for API calls: answered 200,
a second retry replays the same body); the invitation email at claim, sent, recorded and before commit; the webhook
at claim, answered and recorded; the seal through keyd at claim, sealed, recorded and before commit; and a two-signer
envelope with seeded kills of both processes (`OPENSEAL_CRASH_SEED`) completing. After each: the chain verifies, each
operation's event is recorded once, nothing of a request killed before commit is left, repeats happen only in the
at-least-once window with the same `Message-ID` or `webhook-id`, no job is dead, and a `completed` envelope's stored
sealed PDF passes our verifier at B-T and pyHanko. **Found and fixed here:** a request killed after its
`Idempotency-Key` placeholder committed left the key "in progress" for 24 hours, so every retry got `409
CS-API-0011`; a placeholder older than five minutes is now taken over by the retry (atomically, by the store's
`created_at` condition), and the rerun is a replay because the commands' ids derive from the key. A ceremony request
carries no key: a retry after a commit finds the act done (no second event). Seen red: the abandoned-key takeover
removed (`409 CS-API-0011` on the retry of a send killed before commit), the invitation's email step check removed
(two emails after a kill at `Recorded`). In CI: the `server-db` job (and `tools/ci-local.sh`) builds the server with
the feature and runs the test.

**Integration (T-2C with T-2D, GEO-01).** `tests/end_to_end.rs` drives a two-signer envelope through the API
server's router (in process, same database, blob store and clock) and the worker to `completed`, signing through the
ceremony with the links from the worker's emails, then downloads the sealed PDF, the certificate and the combined
PDF through the API; the sealed PDF and the certificate pass our verifier and pyHanko. Seen red: the stored-seal
verification removed with a tampered seal stored (the envelope completed, and the downloaded PDF failed both
verifiers).

**Decisions taken here** (recorded for the owner): the engine state is stored whole beside the relational rows
(migration 0008, `envelope_states` only: the API server's earlier `envelopes.engine_state` column was dropped at the
integration), because `decide` needs its bookkeeping and no table holds it; engine ids of envelopes, recipients,
documents and users are canonical UUID strings; a signature capture is a JSON blob whose SHA-256 is both the adoption's
`image_hash` and the `FieldValue::Signature` id (`casual_sign_worker::capture`); a link token's stored hash is the
SHA-256 of its base64url text; the worker decides under the operator's default `Policy` (per-account settings are the
API's); emails are written by the worker, not `lettre`'s builder (licence, docs/19); webhooks and TSAs use `ureq`,
not `reqwest`.
