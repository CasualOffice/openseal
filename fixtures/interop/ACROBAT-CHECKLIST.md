# Adobe Acrobat Reader checklist for the interop packet (HRD-02, HRD-03)

This folder holds agreements sealed by OpenSeal's real pipeline (`openseal normalize`, then
`openseal seal`) under a real-style test PKI, at PAdES B-T and B-LTA, with an RFC 3161 time
stamp. `tools/interop/interop.py` made them and checks them on every CI run with our verifier,
pyHanko and EU DSS, revocation and time stamps checked (docs/31 §Verification ladder, rung 4
is this checklist). Run it by hand in Adobe Acrobat Reader on a test machine (row `HRD-03`);
never on a machine where a window may pop up unasked (docs/04 rule 17).

Everything here is test material. The root is a throwaway (its private key was discarded when
the packet was made), the parties are fictitious and every page says it is a sample. Trust
the root only for this check and remove it afterwards (step 6). Nothing here makes any legal
claim (docs/09).

## What is in the packet

| File | Seal | Expected in Acrobat |
| --- | --- | --- |
| `agreement-p256-bt.pdf` | approval seal, ECDSA P-256, PAdES B-T | valid; revocation checked online while `serve` runs |
| `agreement-p256-blta.pdf` | approval seal, ECDSA P-256, PAdES B-LTA | valid and LTV enabled, offline |
| `agreement-rsa3072-bt.pdf` | approval seal, RSA-3072, PAdES B-T | valid; revocation checked online while `serve` runs |
| `agreement-rsa3072-blta.pdf` | approval seal, RSA-3072, PAdES B-LTA | valid and LTV enabled, offline |
| `agreement-p256-certified-p2-blta.pdf` | certification seal (DocMDP P=2), P-256, B-LTA | certified (blue ribbon), valid, LTV enabled |
| `tampered-p256-blta.pdf` | `agreement-p256-blta.pdf` with "3 years" changed to "2 years" | **invalid**: altered after signing |

`SHA256SUMS` names each file's SHA-256; check it before starting (`shasum -a 256 -c SHA256SUMS`).
`trust/` holds the root (`openseal-interop-root.cer`, DER, for Acrobat; `.pem` for other tools)
and `FINGERPRINT.txt`, its SHA-256 fingerprint. `pki/` holds the public PKI material the
certificates point to: the CA certificates, the CRLs and pre-signed OCSP answers, all valid
until 2036-01-01. The certificates name `http://127.0.0.1:47380/` for them.

The PKI: `OpenSeal Interop Root CA` (RSA-4096, offline) issued `OpenSeal Interop Issuing CA`
(RSA-3072), which issued the seal certificates `OpenSeal Interop Seal (P-256)` and
`OpenSeal Interop Seal (RSA-3072)`, the time-stamping authority `OpenSeal Interop TSA` and the
delegated `OpenSeal Interop OCSP Responder`. Every name carries
`O=OpenSeal Interop Test PKI (not a real CA)`.

## Steps

1. **Use Acrobat Reader (DC or later) on a test machine.** Record the version (Help > About)
   and the operating system.

2. **Trust the test root.** Acrobat Reader > Settings (macOS) or Edit > Preferences (Windows)
   > Signatures > Identities & Trusted Certificates > More... > Trusted Certificates > Import.
   Choose `trust/openseal-interop-root.cer`, add it, and import. Select the imported
   `OpenSeal Interop Root CA`, choose Edit Trust, tick **Use this certificate as a trusted
   root** and **Certified documents**, and OK. Before that, open Certificate Details and
   compare its SHA-256 fingerprint with `trust/FINGERPRINT.txt`; stop if they differ.

3. **Set verification.** Signatures > Verification > More...: tick **Verify signatures when
   the document is opened**; under Verification Time choose **Secure time (timestamp)
   embedded in the signature**; tick **Require certificate revocation checking to succeed
   whenever possible during signature verification**; under Verification Information tick
   **Always** use the signature's embedded validation information (Acrobat's wording varies
   by version: choose the option that uses the embedded long-term validation data).

4. **The B-LTA files, offline.** With no `serve` running (and, ideally, the network off),
   open each `*-blta.pdf` and the Signature Panel. Expected:
   - the blue bar says **Signed and all signatures are valid.** (for the certified file:
     **Certified by OpenSeal Interop Seal (P-256)** with the blue ribbon, and the certifier
     allows form fill-in and signing, DocMDP P=2);
   - the seal `OpenSealInterop` expands to **Signature is valid**, **Document has not been
     modified since this signature was applied**, **Signer's identity is valid**,
     **Signature is LTV enabled**, **Signature includes an embedded timestamp** with
     `OpenSeal Interop TSA` as the time-stamp signer;
   - Signature Properties > Show Signer's Certificate shows the path
     `OpenSeal Interop Root CA` > `OpenSeal Interop Issuing CA` >
     `OpenSeal Interop Seal (P-256)` (or `(RSA-3072)`), and its Revocation tab says the
     certificate is valid (checked from the embedded OCSP response or CRL);
   - the document time stamp entry (the second item in the panel) says **Document Timestamp
     is valid**, signed by `OpenSeal Interop TSA`;
   - the Reason shows **Development key — not for production**: the packet is sealed with a
     file key (`openseal seal --insecure-file-key`), which marks every such seal (docs/31 §5).

5. **The B-T files, online.** In a terminal at the repository root, run
   `target/tools-venv/bin/python -I tools/interop/interop.py serve fixtures/interop` (it
   answers on 127.0.0.1:47380 only; Ctrl-C stops it). Open each `*-bt.pdf`. Expected: the
   same as step 4 except that the signature is **not** LTV enabled, and the Revocation tab
   shows the status fetched from `http://127.0.0.1:47380/ocsp` (or the CRL) as good. If
   Acrobat asks to connect to 127.0.0.1, allow it for this check. Then stop `serve` and
   reopen: Acrobat should now say revocation could not be checked (validity unknown, or
   valid with a revocation warning, by setting), never "invalid".

6. **The tampered file.** Open `tampered-p256-blta.pdf`. Expected: **At least one signature
   is invalid.** (red cross); the seal expands to **Signature is invalid** and **Document has
   been altered or corrupted since it was signed**. The page shows "for 2 years".

7. **Clean up.** Remove `OpenSeal Interop Root CA` from Trusted Certificates and put the
   verification settings back.

## Record the result

Fill this in docs/31 §Verification ladder (row `HRD-03`), with a screenshot of the Signature
Panel for each file:

| File | Acrobat version, OS | Panel text seen | As expected? |
| --- | --- | --- | --- |
| `agreement-p256-bt.pdf` | | | |
| `agreement-p256-blta.pdf` | | | |
| `agreement-rsa3072-bt.pdf` | | | |
| `agreement-rsa3072-blta.pdf` | | | |
| `agreement-p256-certified-p2-blta.pdf` | | | |
| `tampered-p256-blta.pdf` | | | |

Anything that differs from the expectation above is a finding: give it a docs/14 row.

## Regenerating

`target/tools-venv/bin/python -I tools/interop/interop.py packet fixtures/interop --dss
openseal-eu-dss` makes a new PKI (new keys, so a new fingerprint in `trust/FINGERPRINT.txt`),
seals the files again, writes the PKI material and validates everything before it returns.
A regenerated packet needs this checklist run again.
