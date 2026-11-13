#!/usr/bin/env python3
"""The restore drill's verdict (ASVS-14; tools/backup/drill.sh runs it last). Reads what
the drill left in its work directory and writes `report.json` there, the drill's evidence
(uploaded by CI's `backup-drill` job as the artifact `backup-drill`, docs/65):

    drill_report.py WORK --started UTC --commit SHA

Inputs in WORK: `restore.json` (the restore's counts, time and keyd log summary, from
`openseal_backup.py restore --report`), `evidence-after.txt` (`verify-evidence` on B after
the resume), `oplog-after.txt` (`verify-oplog` on B), `oplog-a` and `oplog-b` (keyd's log
read from A before the backup and from B after the resume), `state.json` (drill_flow.py's
record of A), `sealed-a/`, `sealed-b/` (the sealed PDFs and each stack's seal root) and
`verify-sealed.txt` (pyHanko's verdict over them).

Each check compares the restore with something read from A before the backup, never only
with the backup or the restored database. Exits non-zero naming every problem; the report
is written either way, with `verdict` `passed` or `failed`. Standard library only; the
report holds counts, hashes and ids, never document text or personal data.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import pathlib
import re
import sys

CHECKS = [
    "backup directory holds only manifest, signature and payload (no key travels with it)",
    "backup verified with the signing key's public half, then decrypted and checked against contents.json",
    "a flipped payload byte and an edited manifest are refused, for the right reason",
    "restore: row counts, blob keys, keyd's log, verify-evidence (every audit chain, admin log, the operator log, every blob the evidence names)",
    "the backup holds the seeded envelopes (at least 2) and keyd's log",
    "sealed PDF on B byte-identical to A's (hash read from A's API before the backup)",
    "both audit chains on B begin with the event hashes A's API showed before the backup",
    "the open envelope resumed on B with the link A emailed, sealed by B's worker, its chain continued",
    "verify-evidence and keyd verify-oplog pass again after the resume, with more events, blobs and keyd lines",
    "B's keyd log begins with the bytes of A's log read before the backup",
    "B's seal root differs from A's (keys from B's own HSM, not the backup)",
    "pyHanko validates A's PDF against A's root and B's against B's, and refuses B's against A's root",
]


class ReportError(Exception):
    """An input is missing or unreadable; the message names it."""


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def summary(text: str, prefix: str) -> dict:
    """`prefix key=value …` from a tool's output, as integers."""
    m = re.search(rf"^{re.escape(prefix)} (.*)$", text, re.M)
    if not m:
        raise ReportError(f"no `{prefix}` line")
    try:
        return {k: int(v) for k, v in (kv.split("=", 1) for kv in m.group(1).split())}
    except ValueError:
        raise ReportError(f"unexpected `{prefix}` line") from None


def judge(work: pathlib.Path, started: str = "", commit: str = "") -> dict:
    def read(name: str) -> str:
        try:
            return (work / name).read_text(encoding="utf-8")
        except OSError:
            raise ReportError(f"{name} is missing") from None

    def json_of(name: str) -> dict:
        try:
            return json.loads(read(name))
        except ValueError:
            raise ReportError(f"{name} is not JSON") from None

    restore = json_of("restore.json")
    state = json_of("state.json")
    before = restore["counts"]
    after = summary(read("evidence-after.txt"), "evidence verified:")
    oplog_after = read("oplog-after.txt")
    m = re.search(r"lines=(\d+)", oplog_after)
    if not m:
        raise ReportError("oplog-after.txt names no line count")
    lines_after = int(m.group(1))
    try:
        oplog_a, oplog_b = (work / "oplog-a").read_bytes(), (work / "oplog-b").read_bytes()
    except OSError:
        raise ReportError("oplog-a or oplog-b is missing") from None
    lines_a = oplog_a.count(b"\n")
    keyd = restore.get("keyd_oplog") or {}
    validated = read("verify-sealed.txt")

    problems = []
    if before.get("envelopes", 0) < 2 or before.get("audit_events", 0) < 1:
        problems.append(f"the backup holds {before.get('envelopes', 0)} envelopes: the seeded data did not reach it")
    if after.get("envelopes") != before.get("envelopes"):
        problems.append(f"verify-evidence after the resume counted {after.get('envelopes')} envelopes, the backup {before.get('envelopes')}")
    if after.get("audit_events", 0) <= before.get("audit_events", 0):
        problems.append("no audit event recorded after the restore")
    if after.get("blobs", 0) <= before.get("blobs", 0):
        problems.append("no new blob read back after the resumed envelope was sealed")
    if lines_a == 0:
        problems.append("A's keyd log was empty before the backup although A sealed an envelope")
    if not keyd.get("present"):
        problems.append("the backup carries no keyd operation log although A sealed an envelope")
    elif keyd.get("lines", 0) < lines_a:
        problems.append(f"the backup's keyd log has {keyd.get('lines', 0)} lines, A had {lines_a} before it")
    if not oplog_b.startswith(oplog_a):
        problems.append("B's keyd log does not begin with A's log as read before the backup")
    if lines_after <= keyd.get("lines", 0):
        problems.append("keyd's log did not continue from its restored lines")
    completed = state["completed"]["sealed_sha256"]
    try:
        kept_a, resumed_b = sha256(work / "sealed-a/completed.pdf"), sha256(work / "sealed-b/resumed.pdf")
        root_a, root_b = sha256(work / "sealed-a/trust-root.pem"), sha256(work / "sealed-b/trust-root.pem")
    except OSError:
        raise ReportError("a sealed PDF or seal root is missing") from None
    if kept_a != completed:
        problems.append("the sealed PDF kept from A is not the one A's API answered")
    if root_a == root_b:
        problems.append("B's seal root is A's: keys must come from B's own HSM, not the backup")
    if not re.search(r"^verify-sealed: 3 PDFs agree with their manifests", validated, re.M):
        problems.append("the independent validator did not judge all three sealed PDFs as expected")

    return {
        "verdict": "failed" if problems else "passed",
        "problems": problems,
        "commit": commit,
        "started": started,
        "finished": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "restore_seconds": restore.get("seconds"),
        "restored": before,
        "after_resume": after,
        "keyd_oplog": {
            "lines_on_a_before_backup": lines_a,
            "restored_lines": keyd.get("lines", 0),
            "restored_head": keyd.get("head", ""),
            "lines_after_resume": lines_after,
            "b_begins_with_a": oplog_b.startswith(oplog_a),
        },
        "sealed_pdf": {"completed_sha256": completed, "resumed_sha256_on_b": resumed_b},
        "seal_roots_differ": root_a != root_b,
        "audit_chain_events_checked_against_a": {
            "completed": len(state["completed"]["chain"]),
            "open": len(state["open"]["chain"]),
        },
        "independent_validator": validated.strip().splitlines()[-1] if validated.strip() else "",
        "checks": CHECKS,
    }


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="drill_report.py")
    ap.add_argument("work")
    ap.add_argument("--started", default="")
    ap.add_argument("--commit", default="")
    args = ap.parse_args(argv)
    work = pathlib.Path(args.work)
    try:
        report = judge(work, args.started, args.commit)
    except (ReportError, KeyError, TypeError) as e:
        report = {"verdict": "failed", "problems": [f"report: {e.__class__.__name__}: {e}"], "commit": args.commit, "started": args.started}
    (work / "report.json").write_text(json.dumps(report, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    if report["problems"]:
        for p in report["problems"]:
            print(f"drill: FAILED: {p}", file=sys.stderr)
        return 1
    r, k = report["restored"], report["keyd_oplog"]
    print(
        f"drill: restore took {report['restore_seconds']} s; {r['envelopes']} envelopes, {r['audit_events']} audit events, "
        f"{r['blobs']} blobs restored; {report['after_resume']['audit_events'] - r['audit_events']} events and "
        f"{k['lines_after_resume'] - k['restored_lines']} keyd lines after the resume; {report['independent_validator']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
