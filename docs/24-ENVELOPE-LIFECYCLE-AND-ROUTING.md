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
