# 66 — SPK-02: crypto stack spike report

**Status: spike report for ADR-006 (`SPK-02`).** What was built in `spikes/spk-02-crypto/`, what was measured,
where, and what was not. Recommendation: **confirm ADR-006, with four amendments** (§7). Nothing here is product code;
the spike is a standalone Cargo workspace, `publish = false`, outside the product workspace.

Measured on 2026-11-10, Apple M4 (10 cores), macOS 26.3, Apple clang 17.0.0, Rust 1.96.0 (the repo's pinned dev
toolchain), `CARGO_BUILD_JOBS=2`. Nothing was measured on Linux.

## 1. What was built

| Part | Crates | Does |
| --- | --- | --- |
| `seal-native` (host path) | `aws-lc-rs` (keys, signing, SHA-256), `rcgen` (throwaway certs, dev only), `der`, `spki`, `x509-cert`, `cms` (structures) | Generates a P-256 root, a P-256 leaf and an RSA-3072 leaf at run time (no key touches disk). Writes the one-page PDF (a port of `one_page_pdf` from `tools/verify-sealed.py`), appends an incremental update with `/AcroForm`, a `/Sig` widget and a signature dictionary (`/Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached`, `/M`, fixed-width `/ByteRange` and zero `/Contents` placeholders), fills the ByteRange in place, digests the covered bytes with aws-lc-rs, builds signed attributes `content-type`, `message-digest`, `signing-certificate-v2`, signs the attributes' SHA-256 digest with `EcdsaKeyPair::sign_digest` / `RsaKeyPair::sign_digest` (PKCS#1 v1.5), assembles detached CMS SignedData with the leaf and root, and embeds it. PAdES B-B. Also writes a copy with one byte flipped inside the ByteRange, and a P-256 copy whose signed attributes are deliberately written out of DER order |
| `verify` (WASM path) | `der`, `spki`, `x509-cert`, `cms`, `sha2`, `p256`, `rsa` (feature, verify only) | Parses the last ByteRange, checks it covers the whole file except the `/Contents` string, parses the CMS, checks content-type, message-digest over the ByteRange, signing-certificate-v2 against the signer certificate, and the signature over the signed attributes. Built as `rlib` (used natively by `seal-native` for a cross-check) and as a `cdylib` for `wasm32-unknown-unknown` with a raw `alloc`/`verify` export (no wasm-bindgen) |
| `pyhanko_check.py` | pyHanko 0.38.1, pyhanko-certvalidator 0.33.0, cryptography 50.0.2, asn1crypto 1.5.1 (in `.venv`, made with `uv`) | Validates every output against the throwaway root as the only trust root, and flips its own byte in each good file |
| `run_wasm.mjs` | Node 24.22.1 | Instantiates the `.wasm` with no imports and runs it over the PDFs |

Reproduce from `spikes/spk-02-crypto/`:

```sh
CARGO_BUILD_JOBS=2 cargo run -p spk02-seal-native            # writes out/
~/.local/bin/uv venv --python 3.12 .venv && ~/.local/bin/uv pip install --python .venv/bin/python pyhanko==0.38.1 cryptography
.venv/bin/python -I pyhanko_check.py out
CARGO_BUILD_JOBS=2 cargo build -p spk02-verify --release --target wasm32-unknown-unknown [--features rsa]
node run_wasm.mjs target/wasm32-unknown-unknown/release/spk02_verify.wasm out/*.pdf
```

## 2. Results

### pyHanko (rung 2 of docs/31's ladder), verbatim

```
p256-tampered.pdf: {'intact': False, 'valid': True, 'trusted': False, 'coverage': 'ENTIRE_FILE', 'modification_level': 'NONE', 'md_algorithm': 'sha256', 'mechanism': 'sha256_ecdsa', 'subfilter': '/ETSI.CAdES.detached', 'summary': 'INVALID'}
p256-unsorted-attrs.pdf: {'intact': True, 'valid': True, 'trusted': True, 'coverage': 'ENTIRE_FILE', 'modification_level': 'NONE', 'md_algorithm': 'sha256', 'mechanism': 'sha256_ecdsa', 'subfilter': '/ETSI.CAdES.detached', 'summary': 'INTACT:TRUSTED,UNTOUCHED'}
p256-unsorted-attrs.pdf + byte 375 flipped by this script: {'intact': False, 'valid': True, 'trusted': False, 'coverage': 'ENTIRE_FILE', 'modification_level': 'NONE', 'md_algorithm': 'sha256', 'mechanism': 'sha256_ecdsa', 'subfilter': '/ETSI.CAdES.detached', 'summary': 'INVALID'}
p256.pdf: {'intact': True, 'valid': True, 'trusted': True, 'coverage': 'ENTIRE_FILE', 'modification_level': 'NONE', 'md_algorithm': 'sha256', 'mechanism': 'sha256_ecdsa', 'subfilter': '/ETSI.CAdES.detached', 'summary': 'INTACT:TRUSTED,UNTOUCHED'}
p256.pdf + byte 375 flipped by this script: {'intact': False, 'valid': True, 'trusted': False, 'coverage': 'ENTIRE_FILE', 'modification_level': 'NONE', 'md_algorithm': 'sha256', 'mechanism': 'sha256_ecdsa', 'subfilter': '/ETSI.CAdES.detached', 'summary': 'INVALID'}
rsa3072-tampered.pdf: {'intact': False, 'valid': True, 'trusted': False, 'coverage': 'ENTIRE_FILE', 'modification_level': 'NONE', 'md_algorithm': 'sha256', 'mechanism': 'sha256_rsa', 'subfilter': '/ETSI.CAdES.detached', 'summary': 'INVALID'}
rsa3072.pdf: {'intact': True, 'valid': True, 'trusted': True, 'coverage': 'ENTIRE_FILE', 'modification_level': 'NONE', 'md_algorithm': 'sha256', 'mechanism': 'sha256_rsa', 'subfilter': '/ETSI.CAdES.detached', 'summary': 'INTACT:TRUSTED,UNTOUCHED'}
rsa3072.pdf + byte 375 flipped by this script: {'intact': False, 'valid': True, 'trusted': False, 'coverage': 'ENTIRE_FILE', 'modification_level': 'NONE', 'md_algorithm': 'sha256', 'mechanism': 'sha256_rsa', 'subfilter': '/ETSI.CAdES.detached', 'summary': 'INVALID'}
pyHanko agrees with expectations on 5 files plus flipped copies
```

Both key types are `INTACT:TRUSTED,UNTOUCHED` with `ENTIRE_FILE` coverage. A flipped byte inside the ByteRange gives
`intact: False` and `INVALID`. pyHanko's `valid: True` on a tampered file is expected: in pyHanko `valid` means the
signature over the signed attributes verifies, and `intact` means the message digest matches the document; the
verdict needs both.

### Our RustCrypto verifier, native and in WASM

| File | Native, attributes as received | Native, attributes re-encoded by `der` | WASM (ECDSA-only build) | WASM (`rsa` feature) |
| --- | --- | --- | --- | --- |
| `p256.pdf` | valid | valid | valid (5.5 ms, first call) | valid |
| `p256-tampered.pdf` | invalid: Digest | invalid: Digest | invalid: 5 (Digest) | invalid: 5 |
| `rsa3072.pdf` | valid | valid | 9 (Unsupported, as built) | valid (1.6 ms) |
| `rsa3072-tampered.pdf` | invalid: Digest | invalid: Digest | — | invalid: 5 |
| `p256-unsorted-attrs.pdf` | valid | **invalid: Signature** | valid | valid |

### Sizes and build facts

| Measure | Value |
| --- | --- |
| `.wasm`, ECDSA P-256 only, release, `opt-level="z"`, LTO, `codegen-units=1`, stripped, `panic="abort"` | **330,392 bytes** (81,797 gzip -9) |
| `.wasm`, ECDSA + RSA verify | **423,754 bytes** (112,059 gzip -9) |
| `.wasm` imports | none (no wasm-bindgen, no `getrandom`) |
| No `wasm-opt` pass | not installed; sizes above are before it |
| `aws-lc-*` in the WASM dependency tree | none (`cargo tree --target wasm32-unknown-unknown`) |
| `aws-lc-sys` built for `wasm32-unknown-unknown` | fails: `'stdlib.h' file not found` (no libc headers for that target). ADR-006's premise holds |
| Clean debug build of `seal-native` (aws-lc-rs + rcgen + RustCrypto), `-j2` | 20.1 s wall; `aws-lc-sys` build script alone 13.0 s |
| Clean release build (`opt-level="z"`, fat LTO), `-j2` | 26.9 s wall |
| Release `seal-native` binary, everything linked | 1,356,128 bytes |
| `aws-lc-sys` build-script output | 20 MB (390 objects) + 6.4 MB |
| Spike `target/` at its largest (debug + release + wasm32) | 487 MB |
| Sign time | P-256 `sign_digest` 16–33 µs; RSA-3072 2.3 ms; RSA-3072 keygen 457 ms (release vs debug mixed; indicative only) |
| CMS size | P-256 with 2 P-256 certs: ~1,350 bytes; RSA-3072 leaf + P-256 root: 2,001 bytes |

**Build tools.** On macOS, `aws-lc-sys` 0.47.0 chose its `cc` builder with pre-generated bindings. It was rebuilt
from clean with `PATH=/usr/bin:/bin:~/.cargo/bin`, so with no `cmake`, `go` or `nasm` reachable, and built in 10.3 s:
**non-FIPS needs only a C compiler on macOS** (measured). For Linux the crate's README states the same ("CMake is
never required, bindgen is never required, Go is never required" for non-FIPS; NASM only on Windows x86/x86-64,
with prebuilt objects available) — **not measured here**.

**FIPS (not built).** The `fips` feature switches to `aws-lc-fips-sys` 0.14.4 (AWS-LC-FIPS 4.x), whose builder always
uses CMake, and whose README requires **CMake and Go**, plus bindgen/libclang on some targets. Not built, per the
brief.

### Versions and licences

All resolved to one RustCrypto generation (der 0.8) with no duplicate versions. `cargo deny --offline --config
../../deny.toml --workspace check licenses bans sources` against the repository's `deny.toml`: **bans ok, licenses ok,
sources ok**.

| Crate | Version | Licence (as cargo-deny reads it) | Note |
| --- | --- | --- | --- |
| `aws-lc-rs` | 1.19.0 | ISC AND (Apache-2.0 OR ISC) | |
| `aws-lc-sys` | 0.47.0 | ISC AND (Apache-2.0 OR ISC) AND Apache-2.0 AND MIT AND BSD-3-Clause AND (Apache-2.0 OR ISC OR MIT) AND (Apache-2.0 OR ISC OR MIT-0) | all in the allow-list |
| `aws-lc-fips-sys` | 0.14.4 | ISC AND (Apache-2.0 OR ISC) AND **OpenSSL** | `OpenSSL` is **not** in `deny.toml`; not resolved in this spike |
| `der` / `spki` / `x509-cert` | 0.8.3 / 0.8.1 / 0.3.0 | Apache-2.0 OR MIT | stable |
| `cms` | **0.3.0-rc.2** | Apache-2.0 OR MIT | release candidate; stable `cms` 0.2.3 is on der 0.7 / x509-cert 0.2 |
| `x509-tsp` / `x509-ocsp` | **0.2.0-rc.0** / **0.3.0-rc.1** | Apache-2.0 OR MIT | release candidates; checked to resolve and compile for wasm32 alongside the above with no duplicates; not exercised |
| `sha2` / `p256` / `p384` | 0.11.1 / 0.14.0 / 0.14.0 | Apache-2.0 OR MIT | `p384` only compiled, not exercised |
| `rsa` | 0.10.0 | MIT OR Apache-2.0 | verify only; see advisory below |
| `rcgen` | 0.14.10 | MIT OR Apache-2.0 | dev/test PKI only |

**Advisory.** `cargo deny check advisories` (offline, local advisory DB fetched 2026-11-07) **fails** on
`RUSTSEC-2023-0071` (Marvin) for `rsa` 0.10.0: the advisory has `patched = []` and covers every version. The attack
needs private-key operations observed over a network; verification with a public key is not affected. But CI's
`cargo deny check ... ` and `cargo audit --deny warnings` will go red the moment `rsa` enters the workspace graph.

## 3. Pitfalls found

1. **SET OF ordering of signed attributes.** RFC 5652 §5.4 signs the DER `SET OF` of the attributes. `der`'s
   `SetOfVec` sorts on construction, so our writer is DER by construction (for these three attributes DER order
   equals insertion order, which hides the bug in a naive writer). But `der` 0.8 **also sorts on decode**, so a
   verifier that decodes and re-encodes the attributes rejects any signer that wrote them out of order — measured:
   `p256-unsorted-attrs.pdf` is valid to pyHanko and to our verifier when it hashes the attributes **as received**
   (raw `[0]` TLV with the tag rewritten to `0x31`), and invalid when re-encoded. `casual-sign-verify`, which verifies
   PDFs that are not ours (docs/31 §7), must hash the received bytes.
2. **`ESSCertIDv2.hashAlgorithm` is `DEFAULT id-sha256`**, so DER requires it absent for SHA-256; writing it is a DER
   violation some validators reject. RustCrypto has **no type** for `SigningCertificateV2`/`ESSCertIDv2`; the spike
   defines them in ~30 lines of `der` derive (`verify/src/lib.rs` `ess`). The product will need the same in
   `casual-sign-crypto`.
3. **Placeholder sizing.** ECDSA DER signatures vary (70–72 bytes typically, shorter by chance), and DER length
   octets change size at 128 and 256. The spike sizes `/Contents` by a dry run: the real CMS with a zero digest and a
   maximal signature (72 bytes for P-256, modulus length for RSA). Measured: reserved 1,350/1,352 vs actual
   1,348–1,351 for P-256; exact for RSA. Zero padding after the DER is accepted by pyHanko. B-T will add the TSA token
   bound to the dry run, as docs/31 §4 step 2 says.
4. **`sign_digest` is not FIPS-approved in aws-lc-rs.** Both `EcdsaKeyPair::sign_digest` and
   `RsaKeyPair::sign_digest` are documented "FIPS: Not allowed" (the module's service indicator does not approve
   externally supplied digests); only `sign(message)` is. docs/31 §4 step 5 hands `KeyProvider::sign` "the digest of
   the attributes". With a file key under the `fips` feature that path is not approved. Sending the DER signed
   attributes instead (a few hundred bytes: content type, document digest, certificate hash — never the document)
   keeps the FIPS path and still keeps `keyd` away from the document. HSM/KMS backends do prehash signing inside their
   own boundary and are unaffected. (Minor: `EcdsaKeyPair::sign_digest` checks the digest algorithm after signing.)
5. **`/ByteRange` placeholder width.** Fixed 10-digit fields padded with spaces inside the array
   (`[0 1019       3725       305       ]`) were accepted by pyHanko; the writer must assert the width before patching.
6. **The CMS in `/Contents` is followed by zeros**, so a strict DER decoder must take exactly one TLV first
   (`SliceReader::tlv_bytes`) rather than `from_der` on the whole buffer.
7. **DER-only reader.** The verifier uses `der`'s DER reader. Third-party signers sometimes emit BER (indefinite
   lengths) in CMS; `casual-sign-verify` will need a BER-tolerant path for foreign signatures. Not tested here.
8. **Generation mismatch in RustCrypto.** `cms`, `x509-tsp` and `x509-ocsp` on the der 0.8 generation are release
   candidates; the stable `cms` 0.2.3 is on der 0.7. Mixing generations duplicates `der`/`spki`/`x509-cert`. Pin the
   RCs exactly (`=0.3.0-rc.2` etc.) and track their stable release, or stay wholly on the 0.2 generation.

## 4. What was not measured

- **EU DSS** (rung 3; the `SPK-02` acceptance names it): not run; no container was started for this spike.
- Linux and Windows builds of `aws-lc-sys`; the FIPS build (needs CMake + Go); `wasm-opt` on the `.wasm`.
- Adobe Acrobat (rung 4), B-T (no TSA, and no canned RFC 3161 response was parsed), B-LT/B-LTA, OCSP.
- P-384 and RSA-PSS sealing; SHA-384/512 digests; certificate-chain building and key-usage checks in our verifier
  (pyHanko did build and trust the chain).
- Hostile CMS inputs and fuzzing of the verifier; BER input.
- Advisories against a freshly fetched DB (fetching it needs github.com, outside this spike's network allowance).

## 5. Defects found in the repository's documents

Recorded here for the main session to turn into rows; this spike does not edit them.

1. **docs/31 §8 and ADR-006 offer a FIPS option** but `aws-lc-fips-sys` is licensed `... AND OpenSSL`, which
   `deny.toml` does not allow, and it needs CMake and Go in CI. Neither is stated.
2. **docs/31 §8 keeps `rsa` for verification** but the CI gates (`cargo deny check`, `cargo audit --deny warnings`)
   fail on `RUSTSEC-2023-0071` for every `rsa` version. An `ignore` entry with a reason and a tracker row is needed
   (`deny.toml` says ignores are individually listed with a row), or RSA verification moves elsewhere.
3. **docs/31 §4 step 5** (and ADR-009's "signs digests only") conflicts with aws-lc-rs's FIPS-approved API (pitfall 4).
4. **ADR-006's row in docs/08** lists `der, x509-cert, cms, x509-tsp, x509-ocsp`; docs/31 §8 also lists `spki`,
   `sha2`, `p256`, `p384`, `rsa`. The two should match.
5. Neither docs/31 nor ADR-006 says that `cms`, `x509-tsp` and `x509-ocsp` are pre-release on the current RustCrypto
   generation, nor that RustCrypto lacks ESS `SigningCertificateV2`.
6. **docs/31 §8 says aws-lc-rs is "ISC/Apache-2.0"**; the `-sys` crate also carries MIT, BSD-3-Clause and an MIT-0
   alternative (all allowed). Minor.
7. **`SPK-02`'s acceptance in docs/14** requires EU DSS, which this spike did not run (§4); the row cannot close on
   this report alone.

## 6. Disk and hygiene

Keys were generated in memory at run time and never written; only the throwaway root's certificate (`out/ca.pem`)
was written, under the git-ignored `out/`. `cargo clean` was run in the spike and `.venv/` deleted at the end.

## 7. Recommendation

**Confirm ADR-006** — aws-lc-rs for host private-key operations and hashing, RustCrypto for structures and WASM
verification. Both paths produced PAdES B-B seals that pyHanko validates as `INTACT:TRUSTED,UNTOUCHED` with P-256 and
RSA-3072; the RustCrypto-only verifier builds for `wasm32-unknown-unknown` at 330 KB (ECDSA) / 424 KB (+RSA) with no
imports, while aws-lc-sys cannot compile for that target; and non-FIPS aws-lc-rs builds in ~13 s with only a C
compiler. Amend it with:

1. **Pin the der-0.8 RustCrypto generation**, with exact pins on `cms =0.3.0-rc.2`, `x509-tsp =0.2.0-rc.0`,
   `x509-ocsp =0.3.0-rc.1`, and a row to move to stable releases.
2. **`rsa` stays verify-only and enters through a recorded advisory ignore** for `RUSTSEC-2023-0071` (reason: no
   private-key operations; tracker row). Host-side RSA verification may use aws-lc-rs instead, so `rsa` is needed only
   in the WASM build.
3. **FIPS is a build profile with its own requirements**: CMake + Go in the build image and `OpenSSL` added to the
   licence allow-list (an owner decision), and `KeyProvider::sign` takes the DER signed attributes rather than their
   digest so the file-key path uses FIPS-approved `sign`.
4. **The verifier hashes signed attributes as received** and never re-encodes them; ESS types are ours, in
   `casual-sign-crypto`.
