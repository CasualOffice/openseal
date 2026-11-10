# Phase 1 gate run over the corpus (`P1-GATE-01`)

Phase 1 exit item 2 in [docs/06](../../../docs/06-ROADMAP-AND-DELIVERY.md): for every admitted corpus PDF, fill +
flatten + seal (B-T) + verify passes rungs 1–3 of the verification ladder
([docs/31](../../../docs/31-SEALING-AND-SIGNATURES.md) §7), and `sealed.starts_with(delivered)` holds.

[results.tsv](results.tsv) has one row per corpus file; [summary.tsv](summary.tsv) the counts by class and outcome.
**Last run 2026-11-10** (macOS, EU DSS in Docker), after `FLD-RADIO-NAME` and `FLD-RADIO-NOOPT`: 422 files, 417
admitted; **385 pass all three rungs** with the prefix holding (79 `form`, 300 `plain`, 6 `signed`); 32 `signed`
excluded by the rule below, each refused with `CS-WRT-0004`; 0 fail; 5 not admitted; 0 panics. Ours, pyHanko and EU
DSS agree on every passing row. **Gate met** (Phase 1 exit item 2); the owner accepted the exclusion rule on 2026-11-10
([docs/03](../../../docs/03-OWNER-INSTRUCTIONS.md) instruction 11).

No PDF is committed. Reproduce with the corpus fetched and the EU DSS image built:

```sh
python3 -I fixtures/corpus/fetch.py                 # if fixtures/corpus/files is missing
docker build -t openseal-eu-dss tools/eu-dss
python3 -I tools/pipeline-corpus.py --work /some/scratch/dir --dss openseal-eu-dss \
    [--corpus DIR] [--python target/tools-venv/bin/python]
```

## What runs

Our side is `crates/casual-sign-sdk/examples/pipeline_corpus.rs`, through the SDK facade (the code `openseal`
runs), with the corpus's published passwords (`user`, `usersecret`, `openpassword`, `view`, a space):

| Class | Input | Steps |
| --- | --- | --- |
| `form` | unsigned, with AcroForm fields | admit, normalize, convert the form and fill every field that is not read-only with a value of its type (text cut to `/MaxLen`, checkbox checked, first option, a drawn signature), flatten, certificate of completion with a one-signer audit chain and `audit-trail.json`, seal B-T, verify |
| `plain` | unsigned, no fields | as `form`, with one text field placed by geometry on page 1 |
| `signed` | signed (docs/30 §2) | admit, keep as delivered (no normalization, no flattening, no certificate: each would break the signatures), seal B-T as a second signature in a new field, verify |
| `refused` | not admitted | outside the gate: exit item 1 covers refusals |

Sealing uses the throwaway test PKI and in-process TSA of `crates/casual-sign-seal/tests/common`, P-256, signing
time 2026-11-01T12:00:00Z, validation time 2026-12-01.

## Columns

| Column | Meaning |
| --- | --- |
| `steps` | Steps completed, in order |
| `ours` | Rung 1, our verifier with the test PKI's CRLs supplied: every signature's verdict (for `signed`, the input's own signatures first) |
| `ours_offline` | Our verifier with no revocation data: a B-T seal is `INDETERMINATE:TRY_LATER`, as EU DSS says offline |
| `pyhanko` | Rung 2, pyHanko 0.38.1 with the test root: intact, valid, trusted, whole file covered, no change it calls `OTHER`, DocMDP respected (for `signed`: our signature so, the input's signatures as intact as before) |
| `dss` | Rung 3, EU DSS 6.5.1 offline: our signature's verdict; pass needs intact, valid, `PAdES-BASELINE-T`, 0 undefined changes, never `TOTAL_FAILED` (for `signed`: no more undefined changes than the input had) |
| `prefix` | `ok` when the delivered bytes prefix every later output |
| `ms` | Our side's time for the file |
| `outcome` | `pass`, `excluded` (by a rule below), `fail` (a named cause), `not-admitted` |

## Exclusion rules (accepted by the owner, 2026-11-10)

| Cause | Rule | Removed by |
| --- | --- | --- |
| `keep-signed CS-WRT-0004` | A certification signature with DocMDP P1 permits no change at all, another signature included (ISO 32000-2 §12.8.2.2.2). Appending a seal would invalidate it; normalizing would break it (`CS-PDF-0014`) | `NORM-02` (print to new PDF, existing signatures as pictures) |

## Fixed failures

| File | Cause | Row |
| --- | --- | --- |
| `ed-fafsa-2324.pdf` | A radio on-state name holds byte 0x90 (PDFDocEncoding U+2019, `First bachelor’s degree`); it was decoded lossily to U+FFFD, so flattening found no button and drew the option as text, which no face draws (`CS-FLT-0001`) | `FLD-RADIO-NAME`, Done |
| `ed-fafsa-2425.pdf` | Four radio buttons (`f336`, `f337`, `f406`, `f407`) with no on-state anywhere converted to groups with no options (`CS-FLD-0002`) | `FLD-RADIO-NOOPT`, Done |
