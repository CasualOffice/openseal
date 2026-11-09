# 05 — What a phase, slice and task are

Adapted from OpenPresent's docs/05 at `8011d28`. This is the rule for opening and closing work. [06](06-ROADMAP-AND-DELIVERY.md) applies it to each phase and slice;
[14](14-EXECUTION-TRACKER.md) records the state. A word used here means only what is defined here.

## The levels

| Level | What it is | Size | Defined by | Example |
| --- | --- | --- | --- | --- |
| **Phase** | A foundation capability, stated as what a host can do afterwards, built bottom-up | Weeks | Its charter in 06 | Phase 1: any admitted PDF can be filled, sealed and verified offline, headless |
| **Stage** | A part of a phase with its own gate | Days to weeks | A behaviour list in 06 | Stage 1C: PAdES B-T sealing |
| **Slice** | A thin feature a user can use, cut through model, engine, API, UI and evidence, then deepened | Days | An outcome, end point and time box in 06 | Slice 3: a template with roles sends to two signers in order |
| **Task** | One reviewable change with one acceptance test | Hours to days | A tracker row | `SEC-012`: a PDF with 10⁶ objects is refused before allocation |

Phases D, 0, 1 and 2 are built bottom-up because evidence integrity cannot be retrofitted: a seal, an audit chain and a
data model that are wrong at the bottom make every later slice wrong. **After Phase 2, work runs as vertical slices**, as
OpenPresent's did after its Phase 1.

A task belongs to exactly one stage or slice. Tracker rows wider than a task are split into tasks when their stage or
slice opens.

## Lifecycle of a phase, stage or slice

```
Not opened ──entry met──▶ Open ──exit gate met, owner signs──▶ Closed
                           │  ▲
                           ▼  │ regression found: reopened, with a row
                         Blocked
```

| State | Meaning | Recorded |
| --- | --- | --- |
| **Not opened** | No task may start | — |
| **Open** | Entry criteria met, or a waiver recorded | Date, and what opened it |
| **Blocked** | A named dependency stops the exit gate | The blocking row |
| **Closed** | Every exit criterion has evidence, and the owner signed (phases and slices) | Date, evidence links, sign-off |

**Entry criteria** state what must be true to start. **Exit criteria** must each be checkable by someone who did not do
the work, by running a command or reading a named artefact. "Mostly done", "implemented" and "looks right" are not criteria.

**Only the owner closes a phase or slice.** An agent assembles the evidence and proposes closure. A stage closes on its
gate without a signature.

**Waivers.** A waiver names the unmet criterion, the risk, who accepted it, and what happens to work done under it if
the criterion fails. A waiver never removes an exit criterion.

## Task lifecycle

A task row is the only thing that authorizes work. It has an id, scope, status, severity, mechanism and gate.

| Status | Meaning | Needed to enter |
| --- | --- | --- |
| `Open` | Defined, not started | Id, scope, and an acceptance test stated in advance |
| `In progress` | Being worked | Someone owns it. The files it may touch are known |
| `Blocked` | Cannot proceed | The blocking id or decision is named |
| `Done` | Proven | All of Definition of Done below |

Severity: **P0** blocks the phase gate or is a security or evidence defect; **P1** blocks a slice; **P2** everything else.

### Definition of Done

1. **The acceptance test was seen to fail without the change,** and pass with it. The output is recorded.
2. **Someone else checks it by running it:** the fix is reverted, the test goes red, and the fix is restored. A worker's report is not evidence.
3. CI is green on the merge commit.
4. For anything that reads bytes: limits have hostile fixtures, each limit is in docs/21, and a fuzz target exists.
5. For anything that seals or verifies: the output passes the independent validators of docs/31 §Verification.
6. For anything that changes envelope state: the audit events of docs/32 are emitted and asserted by the test.
7. For API surface: the OpenAPI document in docs/40 is updated and the contract test passes.
8. Docs changed in the same change agree with the code; docs/96 status is updated for a feature.
9. Anything found and not fixed has become a new row.

**Partially done is `In progress`.** A row's mechanism says what remains.

## Evidence

| Kind | Where |
| --- | --- |
| Test proof | The tracker row: test name, and the failure output or how it was reproduced |
| Feature coverage | [96](96-FEATURE-FIT-GAP.md), each row's status with the test or slice that proves it |
| Seal validity | The verification ladder in [31](31-SEALING-AND-SIGNATURES.md), with each validator and version named |
| Phase close | A section in 06: date, each criterion, its evidence, the owner's sign-off |

## What this forbids

- Starting work with no row.
- Marking `Done` on a report, a green run of a test never seen red, or code that merely exists.
- Closing a phase with an unmet criterion.
- Changing an exit criterion to fit what was built. Changing one needs the owner, recorded with its reason.
