#!/usr/bin/env python3
"""Every tracker row has the columns its table declares, and a status from the vocabulary.

Ported from OpenCalc's `tools/check-tracker-shape.py` at `b23c67c`. A markdown row is
split on `|`, so an unescaped pipe in the prose adds a column and everything after it
shifts. The table still renders; anything reading a column by position reads the wrong
cell. OpenCalc found a `Done` row whose evidence column was empty for exactly that
reason, and one whose evidence column was its description.

The width comes from each table's own separator line, so tables of different shapes in
one file are each held to their own. The status column is found by its header (`St` or
`Status`), not by position.

    python3 tools/check-tracker-shape.py [ROOT]
"""

import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from tracker_rows import ID_ROW, TRACKER, cells  # noqa: E402

SEPARATOR = re.compile(r"^\|[\s:|-]+\|\s*$")
STATUS = {"Open", "In progress", "Blocked", "Done"}


def check(root):
    path = pathlib.Path(root) / TRACKER
    if not path.is_file():
        return [f"{TRACKER} is missing"], ""
    problems = []
    checked = 0
    previous = ""
    declared = None
    status_at = None
    fenced = False
    lines = path.read_text(encoding="utf8").splitlines()
    for number, line in enumerate(lines, 1):
        if line.startswith("```"):
            fenced = not fenced
            continue
        if fenced:
            continue
        header, previous = previous, line
        if SEPARATOR.match(line):
            declared = len(cells(line))
            names = cells(header) if header.startswith("|") else []
            status_at = next((i for i, n in enumerate(names) if n in ("St", "Status")), None)
            if len(names) != declared:
                problems.append(f"{TRACKER}:{number}: separator has {declared} columns, header {len(names)}")
            continue
        if not line.startswith("|"):
            declared = None
            continue
        match = ID_ROW.match(line)
        if not match:
            if line.startswith("| ") and re.match(r"^\| [A-Z0-9]+-", line):
                problems.append(f"{TRACKER}:{number}: looks like a row and is not one: {line[:50]}")
            continue
        rid = match.group(1)
        if declared is None:
            problems.append(f"{TRACKER}:{number}: {rid} is in a table with no header")
            continue
        checked += 1
        row = cells(line)
        if len(row) != declared:
            more = "an unescaped `|` in the prose" if len(row) > declared else "a missing column"
            problems.append(
                f"{TRACKER}:{number}: {rid} has {len(row)} columns where its table declares "
                f"{declared}, most likely {more}. Escape a pipe as `\\|`"
            )
            continue
        if status_at is not None and row[status_at] not in STATUS:
            problems.append(f"{TRACKER}:{number}: {rid} has status {row[status_at]!r}, not one of {sorted(STATUS)}")
    return problems, f"tracker shape: {checked} rows, each matching its table"


def main(argv):
    root = pathlib.Path(argv[1]) if len(argv) > 1 else pathlib.Path(__file__).resolve().parents[1]
    problems, summary = check(root)
    if problems:
        print("tracker rows that do not match their table:", file=sys.stderr)
        for p in problems:
            print(f"  {p}", file=sys.stderr)
        return 1
    print(summary)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
