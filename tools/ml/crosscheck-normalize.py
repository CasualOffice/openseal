#!/usr/bin/env python3
"""Cross-checks OpenSeal's date normalisation against Python dateparser (ML-07, piece L).

The Rust rules in crates/casual-sign-fields/src/normalize/ are the product; dateparser
1.4.3 (BSD-3-Clause) is an independent reading used offline only. Both read the rows
of crates/casual-sign-fields/tests/normalize/dates.tsv: the Rust test checks the
`expected` column, this tool checks that dateparser agrees wherever the last column
is `=`, and that every row whose last column records a difference still differs (so a
stale note is caught).

dateparser is given the row's base as RELATIVE_BASE, the locale's DATE_ORDER, English
only, and REQUIRE_PARTS day, month and year, so neither side looks at the clock.

Install the pinned packages into a scratch folder, then run with -I:

    python3 -m pip install --no-deps --require-hashes --target DIR \\
        -r tools/ml/requirements-normalize.txt
    python3 -I tools/ml/crosscheck-normalize.py --site DIR

Exits 0 when every row is as recorded; otherwise non-zero, naming each row that is not
or the setup problem (dateparser missing or not 1.4.3, a malformed row).
"""

import argparse
import datetime
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
TABLE = ROOT / "crates/casual-sign-fields/tests/normalize/dates.tsv"
ORDERS = {"en-US": "MDY", "en-GB": "DMY"}


def load_dateparser(site):
    if site:
        sys.path.insert(0, str(pathlib.Path(site).resolve()))
    try:
        import dateparser  # noqa: PLC0415 (the path is only known at run time)
    except ImportError as err:
        sys.exit(f"crosscheck-normalize: cannot import dateparser ({err}); pass --site DIR")
    if dateparser.__version__ != "1.4.3":
        sys.exit(f"crosscheck-normalize: dateparser {dateparser.__version__}, expected 1.4.3")
    return dateparser


def read_rows(path):
    rows = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        cols = line.split("\t")
        if len(cols) != 6:
            sys.exit(f"crosscheck-normalize: {path.name}:{number}: {len(cols)} columns, expected 6")
        rows.append((number, *cols))
    return rows


def parse_with(dateparser, span, locale, base):
    if locale not in ORDERS:
        raise ValueError(f"unknown locale {locale}")
    year, month, day = (int(p) for p in base.split("-"))
    settings = {
        "RELATIVE_BASE": datetime.datetime(year, month, day, 12, 0, 0),
        "DATE_ORDER": ORDERS[locale],
        "REQUIRE_PARTS": ["day", "month", "year"],
        "RETURN_AS_TIMEZONE_AWARE": False,
    }
    found = dateparser.parse(span, languages=["en"], settings=settings)
    return found.date().isoformat() if found else "-"


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    parser.add_argument("--site", help="folder the pinned packages were installed into")
    parser.add_argument("--table", default=str(TABLE), help="the shared date table")
    args = parser.parse_args()
    dateparser = load_dateparser(args.site)
    problems = []
    agree = differ = 0
    for number, span, locale, base, expected, _flags, note in read_rows(pathlib.Path(args.table)):
        try:
            theirs = parse_with(dateparser, span, locale, base)
        except ValueError as err:
            problems.append(f"line {number}: {span!r}: {err}")
            continue
        if note == "=":
            if theirs != expected:
                problems.append(
                    f"line {number}: {span!r} ({locale}, base {base}): "
                    f"ours {expected}, dateparser {theirs}"
                )
            else:
                agree += 1
        elif theirs == expected:
            problems.append(
                f"line {number}: {span!r}: noted as differing ({note}) but dateparser agrees"
            )
        else:
            differ += 1
            print(f"differs, line {number}: {span!r}: ours {expected}, dateparser {theirs}: {note}")
    for problem in problems:
        print(f"crosscheck-normalize: {problem}", file=sys.stderr)
    print(f"crosscheck-normalize: {agree} rows agree, {differ} differ as recorded, {len(problems)} problems")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
