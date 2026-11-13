#!/usr/bin/env python3
"""Judge an Adobe Acrobat Reader run over the interop packet (HRD-03, docs/31 §Verification ladder).

`.github/workflows/acrobat.yml` runs `acrobat_driver.py` on a GitHub `windows-latest` runner:
Reader opens each PDF of `fixtures/interop/`, and the driver records what Reader's window
says (UI Automation text) with screenshots, in `acrobat-report.json`. This module reads that
report and holds every file to what `ACROBAT-CHECKLIST.md` expects. It needs only the
standard library, so it runs on any OS (and its tests do, in `test_acrobat_report.py`).

    python3 -I tools/interop/acrobat_report.py acrobat-report.json [--manifest fixtures/interop/manifest.tsv]

It exits 0 only when every file in the manifest is in the report and reads as expected, and
otherwise names each file and each phrase that is missing or wrong. A report is evidence of
what Reader displayed, not a verifier of its own: every judgement here is a phrase Reader
itself wrote on screen.

A file the manifest expects `valid` must show, in Reader's words:

- the banner: "Signed and all signatures are valid" (an approval seal), or "Certified by"
  (the certification seal) with no warning beside it;
- "Signature is valid", "Document has not been modified since this signature was applied",
  "Signer's identity is valid" (the test root trusted) and an embedded timestamp;
- at B-LTA, "Signature is LTV enabled";
- none of the phrases Reader uses for a bad, unknown or altered signature.

A file the manifest expects `tampered` must show "At least one signature is invalid" or
"Document has been altered or corrupted since it was signed", and never the valid banner.
"""

import argparse
import json
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
DEFAULT_MANIFEST = HERE.parent.parent / "fixtures" / "interop" / "manifest.tsv"
SCHEMA = 1

# Reader's own wording (Acrobat Reader DC and later, English UI). Matching ignores case and
# typographic apostrophes, since Reader writes "Signer’s" in some versions.
BANNER_VALID = "signed and all signatures are valid"
BANNER_CERTIFIED = "certified by"
VALID_ALL = (
    ("signature valid", ("signature is valid",)),
    ("document unchanged", ("document has not been modified since this signature was applied",)),
    ("signer trusted", ("signer's identity is valid",)),
    ("timestamp", ("signature includes an embedded timestamp", "signature is timestamped",
                   "document timestamp is valid")),
)
VALID_BLTA = (("ltv", ("signature is ltv enabled",)),)
BAD = (
    "at least one signature is invalid",
    "at least one signature has problems",
    "signature is invalid",
    "signature validity is unknown",
    "validity of the signature is unknown",
    "signer's identity is unknown",
    "document has been altered or corrupted",
    "has been modified since",
)
TAMPERED_ANY = ("at least one signature is invalid", "document has been altered or corrupted")


def norm(text):
    return " ".join(str(text).replace("’", "'").replace("‘", "'").lower().split())


def read_manifest(path):
    lines = [ln for ln in pathlib.Path(path).read_text(encoding="utf8").splitlines() if ln.strip()]
    if not lines:
        raise ValueError(f"{path}: empty manifest")
    head = lines[0].split("\t")
    return [dict(zip(head, ln.split("\t"))) for ln in lines[1:]]


def texts_of(entry):
    """Every string Reader showed for this file: UI Automation names and values, banner first."""
    out = []
    for key in ("banner", "texts", "properties"):
        value = entry.get(key)
        if isinstance(value, str):
            value = [value]
        if isinstance(value, list):
            out.extend(v for v in value if isinstance(v, str) and v.strip())
    return [norm(t) for t in out]


def has(texts, phrase):
    return any(phrase in t for t in texts)


def judge_file(row, entry):
    """Problems for one manifest row, as a list of strings (empty: as expected)."""
    name = row["file"]
    if entry is None:
        return [f"{name}: not in the report (Reader never opened it)"]
    if entry.get("error"):
        return [f"{name}: the driver failed: {entry['error']}"]
    texts = texts_of(entry)
    if not texts:
        return [f"{name}: no text was captured from Reader"]
    problems = []
    expect = row.get("expect")
    if expect == "valid":
        certified = "certification" in row.get("why", "").lower()
        if certified:
            if not has(texts, BANNER_CERTIFIED):
                problems.append(f"{name}: no 'Certified by' banner")
        elif not has(texts, BANNER_VALID):
            problems.append(f"{name}: no 'Signed and all signatures are valid' banner")
        wanted = VALID_ALL + (VALID_BLTA if row.get("level") == "B-LTA" else ())
        for what, phrases in wanted:
            if not any(has(texts, p) for p in phrases):
                problems.append(f"{name}: {what} not shown (looked for {' / '.join(repr(p) for p in phrases)})")
        for phrase in BAD:
            if has(texts, phrase):
                problems.append(f"{name}: Reader says {phrase!r}")
    elif expect == "tampered":
        if not any(has(texts, p) for p in TAMPERED_ANY):
            problems.append(f"{name}: Reader did not report the alteration "
                            f"(looked for {' / '.join(repr(p) for p in TAMPERED_ANY)})")
        if has(texts, BANNER_VALID):
            problems.append(f"{name}: Reader says all signatures are valid on a tampered file")
    else:
        problems.append(f"{name}: unknown expectation {expect!r} in the manifest")
    return problems


def judge(report, rows):
    """All problems with a report against the manifest rows; empty means every file as expected."""
    if not isinstance(report, dict) or report.get("schema") != SCHEMA:
        return [f"not an acrobat report of schema {SCHEMA}"]
    files = report.get("files")
    if not isinstance(files, list):
        return ["the report has no file list"]
    by_name = {}
    for e in files:
        if isinstance(e, dict) and isinstance(e.get("file"), str):
            by_name.setdefault(e["file"], e)
    problems = []
    for row in rows:
        problems += judge_file(row, by_name.get(row["file"]))
    known = {r["file"] for r in rows}
    for extra in sorted(set(by_name) - known):
        problems.append(f"{extra}: in the report but not in the manifest")
    return problems


def summary(report, rows):
    """One line per file, for the job log and docs/31."""
    by_name = {e.get("file"): e for e in report.get("files", []) if isinstance(e, dict)}
    out = [f"Reader {report.get('reader_version', '?')} on {report.get('os', '?')}; "
           f"trust: {report.get('trust', {}).get('method', '?')}"]
    for row in rows:
        p = judge_file(row, by_name.get(row["file"]))
        banner = (by_name.get(row["file"]) or {}).get("banner") or "-"
        out.append(f"{row['file']}: {'as expected' if not p else 'DIFFERS'}; banner: {banner}")
    return out


def main(argv):
    ap = argparse.ArgumentParser(prog="acrobat_report.py", description=__doc__.splitlines()[0])
    ap.add_argument("report")
    ap.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    args = ap.parse_args(argv[1:])
    try:
        report = json.loads(pathlib.Path(args.report).read_text(encoding="utf8"))
        rows = read_manifest(args.manifest)
    except (OSError, ValueError) as e:
        print(f"acrobat_report: {e}", file=sys.stderr)
        return 2
    for line in summary(report, rows) if isinstance(report, dict) else []:
        print(line)
    problems = judge(report, rows)
    for p in problems:
        print(f"PROBLEM {p}")
    print("acrobat: every file as expected" if not problems else f"acrobat: {len(problems)} problem(s)")
    return 0 if not problems else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
