---
name: openseal-pdf
description: Rules for adding or changing anything in OpenSeal that reads, writes, flattens, seals or verifies a PDF. Use before touching casual-sign-pdf, -flatten, -seal or -verify.
---
A PDF is hostile, and a sealed PDF is evidence. Both rules apply at once.

**Reading** (`docs/30`, `docs/21`)
- Every limit (file size, object count, xref entries, nesting depth, stream inflate ratio and total, string length, page count, incremental revisions) is in `docs/21` with its default, its code in `docs/20`, and a hostile fixture that crosses it.
- Never execute or follow: JavaScript, `/Launch`, `/GoToR`, `/URI` on open, `/EmbeddedFile` auto-open, XFA, `/OpenAction`, remote fonts. Record what was present in the admission report.
- Encrypted input: refuse unless the host supplies the password; never brute force. Report `CS-PDF-` code from docs/20.
- Recovery before refusal for damaged xref (rebuild by scanning objects), but **never for a document that is already signed**: altering its bytes would break the existing signatures, so a damaged signed input is refused with its reason.
- A fuzz target exists for every entry point that takes bytes.

**Writing**
- Writes are **incremental updates only** after a document is admitted (ISO 32000-2 §7.5.6). The original bytes are a prefix of every later revision; a test asserts it.
- Output is deterministic: same model, same supplied time and keys ⇒ same bytes, apart from the CMS signature value where the algorithm is randomized (record which).
- Fonts used to flatten fields are embedded and subset; no reference to a system font.

**Sealing** (`docs/31`)
- ByteRange covers the whole file except the `/Contents` hex string; the placeholder is sized by a computed upper bound, never a guess; overflow is an error, not a truncation.
- Algorithms and profiles come only from ADR-006 and docs/31. SHA-1 and MD5 are never used to sign.
- Every sealing test verifies its output with at least two independent validators from the ladder in `docs/31` §Verification (our `casual-sign-verify`, plus pyHanko or the EU DSS library in CI). A test that only checks our own verifier does not count.

**Evidence** (`docs/32`)
- The document hash recorded in the audit chain is computed over the exact bytes delivered to the signer.
- Every state change that matters legally emits an audit event before it is acknowledged.
