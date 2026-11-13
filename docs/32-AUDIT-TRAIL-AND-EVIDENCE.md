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
| Envelope | `envelope.created`, `envelope.sent`, `envelope.corrected`, `envelope.voided`, `envelope.declined`, `envelope.expired`, `envelope.completing`, `envelope.completed`, `envelope.purged`, `envelope.deleted` (an envelope that ended without completing removed from the lists; nothing purged, `WEB-08`); proposed: `envelope.restored` (one brought back to the lists, ADR-031, not recorded until Accepted) |
| Document | `document.added`, `document.admitted` (report hash), `document.fixed` (delivered hash at send), `document.replaced`, `document.flattened`, `document.sealed` (sealed hash, profile, certificate fingerprint, TSA time) |
| Recipient | `invitation.sent`, `invitation.bounced`, `reminder.sent`, `recipient.delivered` (opened link), `recipient.auth_challenged`, `recipient.auth_passed`, `recipient.auth_failed`, `recipient.consented` (ERSD version hash), `recipient.consent_withdrawn`, `recipient.viewed_document` (document hash, pages seen), `recipient.signature_adopted` (method: draw/type/upload, image hash), `recipient.field_completed`, `recipient.signed` / `recipient.approved` / `recipient.completed`, `recipient.declined` (reason), `recipient.reassigned`, `recipient.finish_later`, `recipient.in_person_hosted` (host user) |
| Access | `envelope.viewed_by_sender`, `document.downloaded` (by whom), `certificate.downloaded`, `attachment.downloaded` (a signer's attachment: field and hash, by whom; `WEB-08`) |
| Integration | `auth.asserted_by_host` (embedded host claims it authenticated the signer), `webhook.delivered` is **not** in the chain (operational log only) |

`envelope.corrected` means a change after `envelope.sent`. As built, the engine also records a draft's own edits with it
(docs/24 As built, `WEB-14`); ADR-030 (Proposed) gives draft edits their own type, `envelope.edited`. A reader of a
chain built before then treats an `envelope.corrected` that precedes the first `envelope.sent` as a draft edit.

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

## 5. Anchoring (optional, slice 7)

Per account, a daily job builds a **Merkle tree of every chain head** that changed that day, gets an RFC 3161 timestamp
on the root, and publishes the root (a public transparency page or a host-supplied sink). Each envelope stores its
inclusion proof. This proves the database chain existed at that time even for envelopes still in progress, and
protects against an operator rewriting history wholesale. Nothing is published that identifies an envelope.

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
before). The server queues the worker's `seal_ended_certificate` when the envelope is declined, voided or expires (and
again when one is asked for before it exists); the worker renders it, seals it on its own with the platform key at the
envelope's profile, stores it, reads it back and verifies it before recording it as the envelope's certificate. Making
it does not extend the chain (it is not an act on the agreement); each download is recorded as `certificate.downloaded`.

## 7. Retention

The audit chain is retained at least as long as the envelope's documents. Purging an envelope (by retention policy or
a controller's request) deletes documents and personal fields and keeps a **tombstone**: envelope id, chain head,
sealed hash, purge time and policy, so the fact that an agreement existed and was purged is itself evidence.
