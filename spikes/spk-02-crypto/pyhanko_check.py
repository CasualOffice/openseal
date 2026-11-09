#!/usr/bin/env python3
"""SPK-02: validate the spike's sealed PDFs with pyHanko (MIT), rung 2 of docs/31's ladder.

    .venv/bin/python pyhanko_check.py out/

Validates every `*.pdf` in the directory against `ca.pem` as the only trust root, then
flips one byte inside the first ByteRange part of each untampered seal (independently of
the Rust sealer's own tampered files) and validates again. Exits non-zero if any sealed
file fails, or any flipped/tampered file still validates.
"""

import io
import logging
import pathlib
import sys

from pyhanko.keys import load_cert_from_pemder
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign.validation import validate_pdf_signature
from pyhanko_certvalidator import ValidationContext


def check(data, root):
    sigs = PdfFileReader(io.BytesIO(data), strict=False).embedded_signatures
    if not sigs:
        return None
    sig = sigs[-1]
    st = validate_pdf_signature(sig, ValidationContext(trust_roots=[root]))
    return {
        "intact": st.intact,
        "valid": st.valid,
        "trusted": st.trusted,
        "coverage": st.coverage.name,
        "modification_level": st.modification_level.name if st.modification_level else None,
        "md_algorithm": st.md_algorithm,
        "mechanism": st.pkcs7_signature_mechanism,
        "subfilter": str(sig.sig_object.get("/SubFilter")),
        "summary": st.summary(),
    }


def main(d):
    logging.getLogger("pyhanko").setLevel(logging.CRITICAL)
    d = pathlib.Path(d)
    root = load_cert_from_pemder(str(d / "ca.pem"))
    bad = []
    files = sorted(p for p in d.glob("*.pdf"))
    for p in files:
        data = p.read_bytes()
        r = check(data, root)
        expect_ok = "tampered" not in p.name
        ok = bool(r and r["intact"] and r["valid"] and r["trusted"] and r["coverage"] == "ENTIRE_FILE")
        print(f"{p.name}: {r}")
        if ok != expect_ok:
            bad.append(p.name)
        if expect_ok:
            flipped = bytearray(data)
            at = data.index(b"(Agreement)") + 3  # 'r', well inside ByteRange part 1
            flipped[at] ^= 0x01
            r2 = check(bytes(flipped), root)
            ok2 = bool(r2 and r2["intact"] and r2["valid"])
            print(f"{p.name} + byte {at} flipped by this script: {r2}")
            if ok2:
                bad.append(p.name + " (flipped)")
    if bad:
        print("DISAGREE:", bad, file=sys.stderr)
        return 1
    print(f"pyHanko agrees with expectations on {len(files)} files plus flipped copies")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "out"))
