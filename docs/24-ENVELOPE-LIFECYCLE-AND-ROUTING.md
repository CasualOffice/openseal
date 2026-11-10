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
- Agents (specify recipients) supply the name and email of later recipients.
- In-person signers are hosted by a staff user who authenticates first; the event records both.
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
- **§6 "its fields changed"** is read as: a completed recipient acts again when a document they acted on is replaced or
  removed, or when **their own** fields change. Changing a not-yet-completed recipient's fields does not send others back.
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
- **Withdrawing consent** declines for a recipient with a required action, whatever `allow_decline` says.
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
| Access events (sender viewed, document and certificate downloaded) | Built |
| Signer location on recipient actions when `capture_location` is on; refusal recorded, never blocking (GEO-01) | Built (engine); the server's capture and GeoIP lookup are 2C's |
| Routing: sequential, parallel, mixed; carbon copies complete when reached | Built |
| Conditional routing, signing groups (§4, slice 29) | **Not built**: no event type or status for a skipped recipient or a group member's act (rows proposed) |
| Bulk send (§8), signing links (§9) | **Not in the engine**: host jobs that issue `Create`/`Edit`/`Send` |
| Witness ordering, legal-entity seal recipient, notary | **Partial**: act as signers; witnessing after the witnessed signer, a `Seal` recipient acting through `RemoteSigner`, and notary steps belong to slices 16, 18, 31 |

Tested by `tests/transitions.rs` (one test per transition) and `tests/properties.rs` (256 random envelopes under up to
60 random commands each, every invariant checked after every accepted command and the chain verified; a second
property drives every valid envelope to `completed`; a seeded run shows the sequences reach every status). Each
invariant was seen to fail with its guard removed.
