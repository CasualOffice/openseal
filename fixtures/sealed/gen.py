#!/usr/bin/env python3
"""PDFs sealed by OpenSeal at every PAdES baseline level (stage 1G, `T-1G`; docs/31).

    python3 -I fixtures/sealed/gen.py     # regenerate every PDF, manifest.tsv and trust-root.*

Writes the hostile controls `valid.pdf` and `valid_xrefstream.pdf` (from
`fixtures/tools/generate.py`) to a temporary directory and runs
`cargo run -p casual-sign-seal --example gen_sealed`, which normalizes them, seals the
matrix (P-256 and RSA-3072; B-B, B-T, B-LT, B-LTA; approval and certification P1-P3;
two signatures; visible and invisible; an existing form field; an augmentation and a
renewal) and checks every output with our verifier. The PKI, TSA and OCSP responder are
in-process and thrown away; no private key is written. Only the root certificate is kept.

manifest.tsv columns: file, expect (intact), why, level (B-B | B-T | B-LT | B-LTA: what EU
DSS must detect), ours (what casual-sign-verify must say for every signature at
2026-12-01 with the trust root: TOTAL_PASSED, or INDETERMINATE:TRY_LATER for B-B and B-T,
which carry no revocation data).

The independent validators run over the committed files:

    python3 tools/verify-sealed.py fixtures/sealed                        # pyHanko, LTV included
    python3 tools/verify-sealed.py fixtures/sealed --dss openseal-eu-dss  # and EU DSS
    cargo test -p casual-sign-seal --test fixtures                        # ours
"""

import importlib.util
import pathlib
import subprocess
import sys
import tempfile

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent


def controls(work):
    spec = importlib.util.spec_from_file_location("generate", ROOT / "fixtures" / "tools" / "generate.py")
    gen = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gen)
    builders = gen.builders()
    for name in ("valid.pdf", "valid_xrefstream.pdf"):
        (work / name).write_bytes(builders[name]())


def main(argv):
    if len(argv) != 1:
        print(__doc__, file=sys.stderr)
        return 2
    for old in HERE.glob("*.pdf"):
        old.unlink()
    with tempfile.TemporaryDirectory() as tmp:
        work = pathlib.Path(tmp)
        controls(work)
        done = subprocess.run(
            ["cargo", "run", "-q", "-p", "casual-sign-seal", "--example", "gen_sealed", "--", str(work), str(HERE)],
            cwd=ROOT, check=False)
    if done.returncode != 0:
        sys.exit("gen.py: gen_sealed failed")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
