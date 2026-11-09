#!/usr/bin/env python3
"""Every repository gate, in one command (docs/15).

Adapted from OpenPresent's `tools/check-repo.py` (docs/19 §Provenance). Its own checks:
unique tracker ids, one tracker and one roadmap, a complete doc index, working relative
links, no unsafe or `#[allow]` without a reason in crates/. Then each `tools/check-*.py`
gate in GATES. Exits non-zero and names every failure. The pre-commit hook and CI's
`checks` job run this.
"""
import importlib.util
import pathlib
import re
import subprocess
import sys
from collections import Counter

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
from tracker_rows import ID_ROW, TRACKER, rows  # noqa: E402

# Each takes the repository root and returns (problems, summary). check-commits judges
# history, not the tree, so it runs from the commit-msg hook and CI instead.
GATES = [
    "check-tracker-shape.py",
    "check-crate-deps.py",
]

SKIP_DIRS = {"target", "fuzz", ".git", "node_modules"}


def load(name):
    spec = importlib.util.spec_from_file_location(name.replace("-", "_")[:-3], HERE / name)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def own_checks(root):
    errors = []
    tracker = (root / TRACKER).read_text(encoding="utf8")
    found = list(rows(tracker))
    for line in tracker.splitlines():
        if re.match(r"^\| [A-Z0-9]+-", line) and not ID_ROW.match(line):
            errors.append(f"unreadable tracker row: {line[:50]}")
    for rid, n in Counter(rid for _, rid, _ in found).items():
        if n > 1:
            errors.append(f"tracker id used {n} times: {rid}")

    index = (root / "docs/00-README.md").read_text(encoding="utf8")
    tracked = subprocess.run(["git", "ls-files", "docs/*.md"], cwd=root, capture_output=True, text=True).stdout.split()
    for doc in (pathlib.Path(t) for t in tracked):
        if doc.parent.name == "docs" and doc.name != "00-README.md" and f"({doc.name})" not in index:
            errors.append(f"not in the doc index: {doc.name}")

    linked = [*root.glob("*.md"), *(root / "docs").glob("*.md"), *(root / ".claude/skills").glob("*/SKILL.md")]
    for md in linked:
        for link in re.findall(r"\]\(([^)#\s]+?)(?:#[^)]*)?\)", md.read_text(encoding="utf8")):
            if not link.startswith("http") and not (md.parent / link).exists():
                errors.append(f"{md.relative_to(root)}: broken link {link}")

    # CLAUDE.md: one roadmap, one tracker.
    for md in root.rglob("*.md"):
        rel = md.relative_to(root)
        if SKIP_DIRS & set(rel.parts) or rel.parts[0] == ".claude":
            continue
        text = md.read_text(encoding="utf8")
        if str(rel) != TRACKER and "| ID | Title | St |" in text:
            errors.append(f"{rel}: a second tracker; docs/14 is the only one")
        if re.search(r"(?i)(^|/)(todo|tasks?|roadmap|plan)[^/]*\.md$", str(rel)) and str(rel) != "docs/06-ROADMAP-AND-DELIVERY.md":
            errors.append(f"{rel}: a second plan; docs/06 is the only roadmap")

    # CLAUDE.md: unsafe is forbidden; no #[allow] without a comment saying why.
    for rs in (root / "crates").rglob("*.rs"):
        if SKIP_DIRS & set(rs.relative_to(root).parts):
            continue
        lines = rs.read_text(encoding="utf8").splitlines()
        for i, line in enumerate(lines):
            if re.search(r"\bunsafe\s*(\{|fn|impl)", line):
                errors.append(f"{rs.relative_to(root)}:{i + 1}: unsafe in crates/")
            if re.match(r"\s*#!?\[allow\(", line) and not (i and lines[i - 1].strip().startswith("//")):
                errors.append(f"{rs.relative_to(root)}:{i + 1}: #[allow] without a comment above saying why")
    return errors, f"repository: {len(found)} tracker rows, index, links, one tracker, one roadmap, no unsafe"


def main():
    failed = False
    for name, check in [("check-repo.py", own_checks)] + [(g, load(g).check) for g in GATES]:
        problems, summary = check(ROOT)
        if problems:
            failed = True
            print(f"{name}:", file=sys.stderr)
            for p in problems:
                print(f"  {p}", file=sys.stderr)
        else:
            print(summary)
    if failed:
        sys.exit("repository gates failed")
    print(f"repository gates pass: {len(GATES) + 1} gates")


if __name__ == "__main__":
    main()
