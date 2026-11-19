# 32 — Audit trail and evidence

**Status: Draft for owner.** What is recorded, how it is made tamper-evident, and how a third party checks it.
Crate: `casual-sign-audit`. Legal mapping is [09](09-LEGAL-AND-COMPLIANCE.md).

## 1. Principles

1. **Every legally relevant fact is an event**, written in the same transaction as the state change it describes,
   before the client hears success ([24](24-ENVELOPE-LIFECYCLE-AND-ROUTING.md) §1).
2. **Append-only.** No update or delete path exists in code; the database role cannot do either; a trigger refuses
   both ([22](22-DATA-MODEL.md) §9).
3. **Hash-chained per envelope**, so removal, insertion or reordering of any event is detectable from the chain alone.
4. **Anchored in the sealed document**, so the chain head is protected by the seal and its timestamp.
5. **Minimal personal data**: what the evidence needs, no more. Values a signer typed are recorded as hashes in the
   chain; the values themselves are in the sealed document.

## 2. Event shape

```json
{
  "v": 1,
  "envelope_id": "0193…",
  "seq": 17,
  "prev": "sha256:9f2c…",
  "at": "2026-11-10T09:14:03.512Z",
  "type": "recipient.signed",
  "actor": { "kind": "recipient", "id": "0193…", "name": "…", "email": "…" },
  "context": { "ip": "203.0.113.7", "user_agent": "…", "auth": ["email_link", "sms_otp"], "session": "sha256:…" },
  "data": { "document_hashes": ["sha256:…"], "field_value_hashes": { "0193…": "sha256:…" } }
}
```

- `hash = SHA-256(canonical JSON of the event)` with canonical JSON per **RFC 8785 (JCS)**; `prev` is the previous
  event's hash; `seq` is dense from 0.
- `at` is the server's clock (NTP-disciplined; skew monitored). Trusted time comes from the seal's timestamp and the
  optional anchors (§5).
- Event schemas are versioned (`v`) and append-only: a field is never removed or repurposed.

### Signer location (`context.location`, GEO-01)

When the envelope's `signing_options.capture_location` is on ([24](24-ENVELOPE-LIFECYCLE-AND-ROUTING.md) §3), every
recipient action (`recipient.delivered`, `recipient.viewed_document`, `recipient.signed`, `recipient.approved`,
`recipient.declined`) carries where the signer was:

```json
"location": { "source": "device", "accuracy_m": 14, "latitude": 51.5074, "longitude": -0.1278,
              "country": "GB", "region": "England", "city": "London" }
"location": { "source": "ip", "reason": "declined", "database": "GeoLite2-City 2026-11-04",
              "latitude": 51.5, "longitude": -0.13, "country": "GB", "city": "London" }
"location": { "source": "ip", "reason": "unavailable" }
```

- **`source: device`**: the signer's browser or app gave a position after the signer agreed. Coordinates are rounded
  to 4 decimal places (about 11 m) before recording; `accuracy_m` is the device's stated radius, rounded up to whole
  metres. A device coordinate with more decimals is refused on decoding.
- **`source: ip`**: an approximation from the request's IP address, by the GeoIP database named with its build date.
  `reason` says why the device was not used: `declined` (the signer refused), `unavailable` (the device gave nothing),
  `not_requested` (the envelope does not capture location, and the host recorded an approximation anyway). A refusal is
  therefore stated in the event even when the lookup found nothing (no coordinates, no place).
- **Bounds** (docs/21): latitude −90 to 90, longitude −180 to 180, finite; `country` two upper-case letters (ISO
  3166-1 alpha-2 shape); `region` and `city` 1 to 128 bytes, `database` 1 to 128 bytes, none with a control character;
  `accuracy_m` at most 20,037,509. Coordinates or a place on an IP location require `database`. Any fault is
  `CS-AUD-0011`, naming the member, never its value.
- **Personal data** ([07](07-SECURITY-THREAT-MODEL.md) data classification): wrapped like the IP address, listed as
  `context.location` in the personal members, purged with them; its `Debug` prints only the source and reason.
- **Backward compatible:** absent when unset, so every event written before GEO-01 has the same canonical form and hash
  (`crates/casual-sign-audit/tests/compat.rs` pins a 300-event chain's head, its trail file and one event's full text
  from the previous build). A reader of an earlier build ignores the member; verification hashes the event as stored.
- **The lookup is the host's.** The engine holds no GeoIP database and does no I/O: the server resolves the IP,
  builds the `Location` with the database's name and build date, and puts it in the request context. No lookup trait
  is defined in the engine.
- **As built in the server** (`casual_sign_server::geo::evidence`, docs/40 §As built): with the setting on, every
  ceremony request that records a recipient action (session, consent, viewed, adopt, finish, approve, decline,
  withdraw-consent) carries a location; the database is named `<type> <build date>` from its metadata (for example
  `GeoLite2-City 2026-11-04`); the country is recorded when the database names one in the ISO shape; the opening is
  `unavailable` (the page learns the setting from it). With the setting off the server records nothing, so
  `not_requested` is never written by this server. Tested by `server/casual-sign-server/tests/location.rs`.

## 3. Event types

| Group | Events |
| --- | --- |
| Envelope | `envelope.created`, `envelope.sent`, `envelope.corrected`, `envelope.voided`, `envelope.declined`, `envelope.expired`, `envelope.completing`, `envelope.completed`, `envelope.purged`, `envelope.deleted` (an envelope that ended without completing removed from the lists; nothing purged, `WEB-08`), `envelope.transferred` (`{from_user, to_user}`: ownership passed to another member of the same workspace, `ORG-09`; additive as ADR-027); proposed: `envelope.restored` (one brought back to the lists, ADR-031, not recorded until Accepted) |
| Document | `document.added`, `document.admitted` (report hash), `document.fixed` (delivered hash at send), `document.replaced`, `document.flattened`, `document.sealed` (sealed hash, profile, certificate fingerprint, TSA time) |
| Recipient | `invitation.sent`, `invitation.bounced`, `reminder.sent`, `recipient.delivered` (opened link), `recipient.auth_challenged`, `recipient.auth_passed` (for `sso`, `identity`: the ID token's issuer and the SHA-256 of its subject, never the subject; absent otherwise, so earlier chains hash as before; RAUTH-01), `recipient.auth_failed`, `recipient.consented` (ERSD version hash), `recipient.consent_withdrawn`, `recipient.viewed_document` (document hash, pages seen), `recipient.signature_adopted` (mark: `signature`, `initials`, `stamp` or `drawing`, the last two added by `VS-04A` and filling only a field of their own kind, never shown as the signer's mark in the certificate; method: draw/type/upload, image hash), `recipient.field_completed`, `recipient.signed` / `recipient.approved` / `recipient.completed`, `recipient.declined` (reason), `recipient.reassigned`, `recipient.finish_later`, `recipient.in_person_hosted` (host user); proposed (ADR-035, `WF-01`, not recorded until Accepted): `routing.evaluated` (rule, recipient, inputs as label and value hash, never the value, and `include` or `skip`), `recipient.skipped` (recipient, rule), `recipient.group_member_acted` (recipient, the group member who claimed it; recorded before `recipient.delivered`), and an optional `member_id` on `invitation.sent` for a group member's invitation |
| Access | `envelope.viewed_by_sender`, `document.downloaded` (by whom), `certificate.downloaded`, `attachment.downloaded` (a signer's attachment: field and hash, by whom; `WEB-08`), `envelope.exported` (`{by}`: a completed envelope's evidence package exported, `ORG-09`; additive as ADR-027, an earlier verifier lists it and `envelope.transferred` as unrecognised, not failed) |
| Integration | `auth.asserted_by_host` (embedded host claims it authenticated the signer), `webhook.delivered` is **not** in the chain (operational log only) |

`envelope.corrected` means a change after `envelope.sent`. As built, the engine also records a draft's own edits with it
(docs/24 As built, `WEB-14`); ADR-030 (Proposed) gives draft edits their own type, `envelope.edited`. A reader of a
chain built before then treats an `envelope.corrected` that precedes the first `envelope.sent` as a draft edit.
As built (`WF-04`), `envelope.corrected` also carries these, each naming the paths it changed: a draft's schedule set
or cancelled (`send_at`, `WF-02`; dropped by the platform when the draft can no longer be sent), and a resend that
clears a bounce or an authentication lock (`recipients.{id}.status`, `recipients.{id}.auth_lock`). Document visibility
and delayed routing add no type: a recipient's hidden documents are absent from the documents their act records, and
a routing delay ending changes nothing observable (the invitation's own `invitation.sent` follows). `email_otp` is an
`AuthMethod` (added after the others, so earlier chains hash as before).

### As built (stage 1I)

`prev` is `null` exactly on the first event. The trail file embedded in the PDF is canonical JSON
`{format: "openseal.audit-trail", v: 1, envelope_id, head, events: [...]}`, each event carrying its hash. Personal data
is wrapped so `Debug` never prints it. Unknown event types are listed and do not fail the chain. A chain cut short or
rewritten whole is caught only against an externally known head or count: that head is what the certificate prints
and the seal protects.

**Certificate and seal order:** the certificate prints each document's delivered hash, the chain head as of
`envelope.completing` and the trail file's SHA-256; the seal then covers the certificate pages and the embedded trail;
`document.sealed` and `envelope.completed` extend the chain afterwards, so the embedded trail is a prefix of the full
chain. A certificate issued after sealing may print sealed hashes and the seal's certificate (`SealInfo::Applied`).
Hashed events cannot be redacted in place; purge keeps a tombstone without personal data. Merkle inclusion proofs take
the tree size from the trusted side.

## 4. Chain verification

Anyone with the audit JSON can recompute every hash and check `prev` links and `seq` density. The sealed PDF's
certificate of completion prints the **chain head** (hash of the last event before sealing) and the embedded
`audit-trail.json` holds the chain; the seal covers both. So:

- altering the PDF breaks the seal;
- altering the embedded audit trail breaks the seal;
- altering the database's copy afterwards is detectable against the copy every party received.

`casual-sign-verify` checks the embedded chain as part of verifying a document; `verify.html` shows it as a timeline.

The database's copy as a whole is checked by `casual-sign-server verify-evidence` (`ASVS-14`, `Store::verify_evidence`):
run as the schema owner (a role that row-level security filters is refused, `CS-DB-0015`), it rebuilds every envelope's
chain from the stored canonical bytes, requires the envelope's stored head to be the last event's hash, re-verifies
every workspace's and organization's admin log and the platform's operator log (`CS-CON-0007`), and reads back
against its SHA-256 every blob the evidence names (`Store::evidence_blob_keys`, `EVIDENCE_BLOB_KEYS_SQL`): every
document version and template document, each envelope's certificate of completion, each adopted signature's capture,
each brand's logo, and each attachment a signer uploaded (named only in the envelope's workflow state,
`fields[*].value.attachment`). Each capture is parsed as the seal job parses it (`casual-sign-host` `capture::parse`:
drawn, typed, or `{"kind": "image", "image": "<SHA-256>"}`), and an uploaded image it names is read too; a capture
the seal job could not read fails (`CS-WRK-0016`). A
broken chain names its envelope, workspace or organization (`CS-DB-0005`, `CS-DB-0014`), a missing blob its key
(`CS-BLOB-0002`). A restore runs it before the services start again, and the backup tool reads the same keys in its
dump's snapshot and refuses a backup that lacks one (docs/65 §Backups and restore).

## 5. Anchoring (optional, slice 7)

Per account, a daily job builds a **Merkle tree of every chain head** that changed that day, gets an RFC 3161 timestamp
on the root, and publishes the root (a public transparency page or a host-supplied sink). Each envelope stores its
inclusion proof. This proves the database chain existed at that time even for envelopes still in progress, and
protects against an operator rewriting history wholesale. Nothing is published that identifies an envelope.

### As built (`FG-158`, ADR-037 accepted, migration 0041)

- **Which heads.** For UTC day `D`, an account's tree has one leaf per envelope whose chain gained an event with `at`
  in `D`: that envelope's head as of the end of `D` (its last event with `at` before `D + 1` 00:00), unless that
  head is already anchored. Leaves are ordered by envelope id; each leaf is the head's 32 bytes, hashed as RFC 6962
  leaves are (`merkle`, §3 As built). At most 1,000,000 leaves (docs/21); more fails the job (`CS-AUD-0002`).
- **What is time-stamped.** The *statement* `SHA-256("openseal.anchor.v1" ‖ 0x00 ‖ tree size as u64 big-endian ‖
  root)`, by the deployment's TSAs (the seal's, `OPENSEAL_TSA_URLS` or the console's list, `CON-07`), with a nonce,
  checked as a seal's token is before anything is stored. The size is inside the statement because an inclusion
  proof must take the size from the trusted side.
- **When.** A worker with `OPENSEAL_ANCHORING=daily` (the default) queues, from 10 minutes after `D` ends, one
  `anchor_chain_heads` job per account with an event in `D` (`openseal_enqueue_anchor_jobs`, a definer function that
  returns a count; idempotency key `anchor:D`), and up to 7 days back after downtime.
- **Stored** in `chain_anchors` (one per account and day: period, size, root, token, `genTime`) and
  `chain_anchor_leaves` (envelope, `seq` and hash of the head event, leaf index, audit path), insert-only with the
  audit chain's triggers (docs/22 §9). Anchor and leaves commit together, only after the token is checked; a job
  that finds its day anchored publishes it again and closes, so a crash at any step leaves one anchor.
- **Published** to the operator's sink: with `OPENSEAL_ANCHOR_LOG`, one canonical JSON line per anchor
  (`{format: "openseal.anchor", v: 1, id, period, tree_size, root, statement, tsa_time, timestamp_token}`, the token
  in lower-case hex) appended to a file the operator publishes (docs/65). The line names no envelope and no account.
  Publication is at least once: after a crash the same line can appear twice. Without a sink, anchors are stored
  and time-stamped only.
- **The envelope's proof** is a file `{format: "openseal.anchor-proof", v: 1, envelope_id, seq, head, leaf_index,
  path, anchor}` (`casual_sign_audit::anchor::AnchorProof`, canonical JSON), made from the stored leaf
  (`casual_sign_worker::anchor::proof_files`). `openseal anchor verify PROOF.json [--trail TRAIL.json] [--trust
  ROOT.pem]` (and `casual_sign_sdk::anchor::verify_anchor_proof`, engine code that builds for WASM) checks offline
  that the head is the leaf at its index of the tree of the anchor's size and root (`CS-AUD-0009`), the token is the
  TSA's over the statement (`CS-VER-0006`) and its TSA chains to a given root at the token's time (`CS-VER-0004`,
  else indeterminate), and with the trail that the trail verifies and its event `seq` has that hash (`CS-AUD-0012`).
  A trail rewritten after anchoring and rehashed to be internally valid fails the last check.
- **Served and shown.** `GET /api/v1/envelopes/{id}/anchor-proof` (docs/40) answers the proof file of the envelope's
  latest anchored head to staff who may read the envelope (`404 CS-API-0017` before any), made by the code the worker
  publishes with (`casual_sign_host::anchor`). `casual-sign-wasm` exports `verify_anchor`: the checks above, with the
  same verdict as the SDK and the CLI (`casual-sign-wasm/tests/anchor.rs`), plus the token's time and its TSA
  certificate's name. The web app's Verify page (`verify.html`) takes the proof file beside the PDF (or fetches it
  when opened from an envelope, and says "not anchored yet" on `404 CS-API-0017`), checks it in the browser and, when
  the proof's event is in the audit trail the PDF carries, matches it to that trail; it says "History anchored on
  <day> by <TSA>", "not confirmed" (the TSA's root is not one the person added), or that the proof does not hold,
  with each check and its code. A proof whose event comes after the PDF's trail ends (a sealed PDF's trail stops at
  sealing) is checked without the trail, and the page says so. The website's Verify page checks a proof beside the
  PDF the same way, without the trail. Playwright `verify-anchor.spec.mjs` (Chromium, WebKit) and `site.spec.mjs`.
- **Not yet:** the sealed PDF does not carry the proof files, and a signer's downloads do not include them (only staff
  fetch them, through the API); the published file is not yet mirrored to a third-party log; the TSA's revocation is not
  checked by the anchor verifier. What an anchor proves is that the head existed at the TSA's time; it carries no
  legal or regulatory effect of its own (docs/09).

## 6. Certificate of completion

Generated by `casual-sign-certificate` ([30](30-PDF-PIPELINE.md) §8). Sections:

1. **Envelope summary**: id, subject, status, sender (name, email, account), created, sent, completed, time zone, seal
   profile, document count, page count, chain head.
2. **Documents**: name, pages, SHA-256 as delivered, SHA-256 as sealed.
3. **Signer events**, per recipient in routing order: name, email (masked per account setting), role, type,
   authentication methods and their results, IP, user agent, location (GEO-01: place, coordinates, and how it was
   obtained: "device (±N m)", "approximate from IP (database …)", or "declined — approximate from IP (database …)"; the
   host passes the location recorded on the recipient's signed, approved or declined event), signature and initials
   images, adoption method, sent, viewed, signed or declined times.
4. **Consent**: ERSD version and acceptance time per recipient, and the disclosure text (or its hash with the text in
   an appendix).
5. **Carbon copies and viewers**: name, email, delivery times.
   5a. **Signer attachments** (`WEB-06`, when any): recipient, field, media type, size and SHA-256 of each file a
   signer attached. The files are kept with the envelope, not drawn into or appended to the sealed document (the
   evidence-safe choice: the sealed PDF stays the delivered document plus the drawn values and this certificate); each
   file's hash is bound into the chain by its `recipient.field_completed` event (the value is `{"attachment": "<sha256>"}`)
   and printed here, so the seal covers the listing.
6. **Seal**: certificate subject, issuer, fingerprint, timestamp authority and time.
7. **How to verify**: the verification URL, the offline verifier, and the algorithm in one paragraph.

Locale and date format follow the account; the certificate itself is never translated after sealing.

**An envelope that ended without completing (`UXW-30`)** gets an **envelope certificate**, never a certificate of
completion. `CertificateInput::ending` (`Ending {kind: declined | voided | expired, at, by, reason}`) changes only what
the certificate says: the title (page header, heading and the PDF's `/Title`) is "Envelope Certificate (not
completed)"; the opening says the envelope was declined, voided or expired on a date and that no document in it was
completed or sealed as an agreement; the summary has `Outcome` ("Declined by …", "Voided by …", "Expired"), `Ended`,
`Reason` when one was given, and `Completed: Not completed`; the seal section says the documents were not sealed and
this certificate is sealed on its own. The sections, the embedded trail and the chain head are as for completion. With
no ending the bytes are exactly those of a certificate of completion (the 1, 3 and 25 recipient certificates hash as
before). The ending is the chain's, not the caller's word: the engine refuses (`CS-AUD-0020`, member `ending`) an
ending whose kind or time differs from the chain's last terminal event (`envelope.declined`, `.voided`, `.expired`,
`.completing`, `.completed`), an ending for a chain that reached completion, and a certificate of completion for a
chain that ended (certificate `a_certificate_refuses_an_ending_the_chain_does_not_record`; seen red with the check
removed). The server queues the worker's `seal_ended_certificate` when the envelope is declined, voided or expires (and
again when one is asked for before it exists); the worker renders it, seals it on its own with the platform key at the
envelope's profile, stores it, reads it back and verifies it before recording it as the envelope's certificate. Making
it does not extend the chain (it is not an act on the agreement); each download is recorded as `certificate.downloaded`.

## 7. Retention

The audit chain is retained at least as long as the envelope's documents. Purging an envelope (by retention policy or
a controller's request) deletes documents and personal fields and keeps a **tombstone**: envelope id, chain head,
sealed hash, purge time and policy, so the fact that an agreement existed and was purged is itself evidence.

### As built (`ASVS-16`, `ASVS-18`, migration 0045, ADR-039 Accepted)

- **Retention rules.** An account sets, per data class, the days a record is kept after its last change (completion,
  for completed envelopes): `draft`, `ended` (declined, voided, expired), `completed`, `sessions` (ended staff
  sessions). None is set by default: nothing is purged unless an administrator sets a rule (`PUT /retention`, after a
  recent re-authentication; each change the admin event `retention.rule_set`). An envelope in flight is in no class.
- **The job.** Once a UTC day each account with a rule gets a `retention_sweep` job. It purges each expired envelope
  in a transaction of its own that first locks the envelope's row and skips it under **legal hold**
  (`envelopes.legal_hold_at`, set and released by `retention.manage` with an admin event), through the engine's
  `Purge`: the chain gains `envelope.purged {policy: "retention.<class>"}` and nothing else changes in it. The purge
  job then records the **tombstone** (chain head and length after `envelope.purged`, the first sealed document's
  hash, the time and policy) and deletes the envelope's relational records that hold personal data or content
  (documents and their versions, recipients with their tokens, one-time codes, SSO challenges, authentication
  requirements and adopted signatures, fields and values, comments, custom fields, the certificate's key, the bulk
  row's input). Ended sessions go under the `sessions` rule with an admin event `retention.sessions_purged {count}`.
  A dry run (`GET /retention/preview`) says what would go now and what a hold keeps; a second run purges nothing twice.
- **A controller's request** (`POST /envelopes/{id}/purge`, policy `request`) purges one ended, completed or unsent
  envelope now, the same way; refused under legal hold (`409 CS-API-0019`). This is how a signer's erasure request
  is carried out by the account that holds their envelope.
- **Kept, always:** every audit event (including the names, emails and addresses they recorded), the admin logs,
  tombstones, and the blob bytes. `verify-evidence` still rebuilds every chain; a purged envelope's documents are no
  longer named by any record, so it reads only what is kept. Reclaiming the orphaned bytes is `HRD-09`'s sweep, which
  must keep a blob any retained record still names (keys are content hashes, shared across records); until it runs,
  a purged envelope's bytes stay in the blob store, unreachable through the API.
- **Erasure of a member** (`DELETE /users/me`, `POST /users/{id}/erase`) changes no evidence: the `users` row is
  pseudonymised, the admin event `member.erased` records it, and the audit events that recorded the member's name
  and email stay as every party received them. Tests: `-worker/tests/retention.rs` (expired items of a ruled class
  only, holds, idempotent, chains and admin logs verify, sealed bytes unchanged; seen red with the hold filter and the
  record purge removed; an erased sender's sealed agreement and chain unchanged, seen red with the pseudonymisation
  removed), `-server/tests/privacy.rs`.
