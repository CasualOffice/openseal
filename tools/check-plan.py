#!/usr/bin/env python3
"""Every `In progress` tracker row is in the docs/06 Execution plan (owner instruction 62, `PLN-01`).

The plan's Current, Finishing and Paused lines list tracker ids in backticks. A row marked
`In progress` that none of them lists is work outside the plan, and fails.

    python3 tools/check-plan.py [ROOT]
"""

import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
from tracker_rows import TRACKER  # noqa: E402

ROADMAP = "docs/06-ROADMAP-AND-DELIVERY.md"
LINE = re.compile(r"^- (Current|Finishing|Paused)\b[^:]*:(.*)$", re.M)
ROW = re.compile(r"^\| ([A-Z][A-Z0-9]*-[0-9A-Z]+) \|", re.M)


def check(root):
    root = pathlib.Path(root)
    roadmap = (root / ROADMAP).read_text(encoding="utf8")
    section = roadmap.split("## Execution plan", 1)
    if len(section) < 2:
        return [f"{ROADMAP} has no Execution plan section"], ""
    planned = set()
    for _, ids in LINE.findall(section[1].split("\n## ", 1)[0]):
        planned.update(re.findall(r"`([A-Z][A-Z0-9]*-[0-9A-Z]+)`", ids))
    problems = []
    for line in (root / TRACKER).read_text(encoding="utf8").splitlines():
        m = ROW.match(line)
        if m and "| In progress |" in line and m.group(1) not in planned:
            problems.append(f"{m.group(1)} is In progress but not in the docs/06 Execution plan")
    return problems, f"execution plan: {len(planned)} rows planned"


if __name__ == "__main__":
    found, summary = check(sys.argv[1] if len(sys.argv) > 1 else pathlib.Path(__file__).resolve().parent.parent)
    for p in found:
        print(p, file=sys.stderr)
    print(summary)
    sys.exit(1 if found else 0)
