"""What a tracker row is, defined once.

Copied from OpenCalc's `tools/tracker_rows.py` at `b23c67c`. There, three gates each
held a private row pattern, two of them narrower than the ids the tracker held, and 47
rows were invisible to them: a gate that cannot see a row cannot fail on it. Every gate
here imports this module instead, and `check-gate-selftest.py` refuses a private copy.
"""

import re

# `| SOME-ID |` at the start of a line. The header's own first cell is `ID`, which has
# no hyphenated part, so it does not match.
ID_ROW = re.compile(r"^\|\s*([A-Z][A-Za-z0-9]*(?:-[A-Za-z0-9]+)+)\s*\|")

TRACKER = "docs/14-EXECUTION-TRACKER.md"


def cells(line: str) -> list:
    r"""The row's cells, honouring `\|` as an escape, as markdown does."""
    return [c.strip() for c in re.split(r"(?<!\\)\|", line.strip().strip("|"))]


def rows(text: str):
    """Yield `(line number, id, line)` for real rows, skipping fenced examples."""
    fenced = False
    for number, line in enumerate(text.splitlines(), 1):
        if line.startswith("```"):
            fenced = not fenced
            continue
        if fenced:
            continue
        match = ID_ROW.match(line)
        if match:
            yield number, match.group(1), line
