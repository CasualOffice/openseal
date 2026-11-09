#!/usr/bin/env python3
"""Commit messages follow Conventional Commits, as CLAUDE.md requires.

    python3 tools/check-commits.py --message-file .git/COMMIT_EDITMSG   # commit-msg hook
    python3 tools/check-commits.py --range origin/main..HEAD            # CI
    python3 tools/check-commits.py --message "feat(x): y"               # one message

The first line is `type(scope)!: summary`. The scope is optional, lower case, and may
list several (`model,import,export`). The summary is at most 100 characters and does not
end in a full stop. Merge commits git writes itself, and `Revert "..."` messages, are
accepted as git writes them; `fixup!` and `squash!` are refused, since they are notes
to a rebase that should have happened before the commit was shared.

A message is data from a person, so it is read as text and never run.
"""

import re
import subprocess
import sys

TYPES = ("feat", "fix", "docs", "chore", "refactor", "test", "perf", "ci", "build", "spike", "revert", "style")
HEADER = re.compile(
    r"^(?P<type>[a-z]+)(?:\((?P<scope>[a-z0-9][a-z0-9.-]*(?:,[a-z0-9][a-z0-9.-]*)*)\))?(?P<bang>!)?: (?P<summary>\S.*)$"
)
MAX_SUMMARY = 100


def problems_in(message):
    lines = [ln for ln in message.splitlines() if not ln.startswith("#")]
    while lines and not lines[0].strip():
        lines.pop(0)
    if not lines:
        return ["the message is empty"]
    first = lines[0].rstrip()
    if first.startswith("Merge ") or first.startswith('Revert "'):
        return []
    if first.startswith(("fixup!", "squash!", "amend!")):
        return [f"{first[:60]!r}: a rebase note, not a commit message"]
    match = HEADER.match(first)
    if not match:
        return [f"{first[:80]!r}: not `type(scope): summary`"]
    found = []
    if match["type"] not in TYPES:
        found.append(f"{first[:80]!r}: type {match['type']!r} is not one of {', '.join(TYPES)}")
    summary = match["summary"]
    if len(first) > MAX_SUMMARY:
        found.append(f"{first[:80]!r}...: first line is {len(first)} characters, over {MAX_SUMMARY}")
    if summary.endswith("."):
        found.append(f"{first[:80]!r}: the summary ends in a full stop")
    if len(lines) > 1 and lines[1].strip():
        found.append(f"{first[:80]!r}: the second line must be blank")
    return found


def commits(spec):
    done = subprocess.run(
        ["git", "log", "--no-merges", "--format=%H%x00%B%x00", spec],
        capture_output=True, text=True, check=False,
    )
    if done.returncode != 0:
        raise SystemExit(f"check-commits: cannot read {spec}: {done.stderr.strip()}")
    parts = done.stdout.split("\x00")
    return [(parts[i].strip(), parts[i + 1]) for i in range(0, len(parts) - 1, 2)]


def main(argv):
    if len(argv) != 3 or argv[1] not in ("--message-file", "--range", "--message"):
        print(__doc__, file=sys.stderr)
        return 2
    mode, value = argv[1], argv[2]
    if mode == "--message-file":
        with open(value, encoding="utf8", errors="replace") as f:
            found = problems_in(f.read())
        checked = 1
    elif mode == "--message":
        found = problems_in(value)
        checked = 1
    else:
        found = []
        listed = commits(value)
        for sha, body in listed:
            found += [f"{sha[:10]}: {p}" for p in problems_in(body)]
        checked = len(listed)
    if found:
        print("commit messages that are not Conventional Commits (CLAUDE.md, Git):", file=sys.stderr)
        for p in found:
            print(f"  {p}", file=sys.stderr)
        print("\n  e.g. feat(pdf): refuse a /Prev loop in the xref chain (T-1A)", file=sys.stderr)
        return 1
    print(f"commit messages: {checked} checked, all Conventional Commits")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
