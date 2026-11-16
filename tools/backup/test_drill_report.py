"""Tests of the restore drill's verdict (tools/backup/drill_report.py, ASVS-14): every way
a restore could look fine but be wrong that the drill can see must fail it.

    python3 -I -m unittest discover -s tools/backup -p 'test_*.py'
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import pathlib
import sys
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import drill_report as dr  # noqa: E402

PDF_A = b"%PDF-1.7 sealed on A"
OPLOG_A = b"1\tsign\taaaa\n2\tsign\tbbbb\n"


def counts(**over):
    c = {"envelopes": 2, "audit_events": 20, "workspaces": 1, "admin_events": 3, "organizations": 1,
         "org_admin_events": 1, "operator_events": 0, "blobs": 6}
    c.update(over)
    return c


def passing(work: pathlib.Path) -> None:
    """A work directory as a drill that passed leaves it."""
    (work / "sealed-a").mkdir()
    (work / "sealed-b").mkdir()
    (work / "sealed-a/completed.pdf").write_bytes(PDF_A)
    (work / "sealed-a/trust-root.pem").write_bytes(b"root A")
    (work / "sealed-b/resumed.pdf").write_bytes(b"%PDF-1.7 sealed on B")
    (work / "sealed-b/trust-root.pem").write_bytes(b"root B")
    (work / "state.json").write_text(json.dumps({
        "completed": {"id": "e1", "sealed_sha256": hashlib.sha256(PDF_A).hexdigest(), "chain": ["h1", "h2"]},
        "open": {"id": "e2", "status": "sent", "chain": ["h3"], "second_signer_path": "/s/x"},
    }))
    (work / "restore.json").write_text(json.dumps({"counts": counts(), "seconds": 12.5,
                                                   "keyd_oplog": {"present": True, "lines": 2, "head": "bbbb"}}))
    after = counts(audit_events=31, blobs=9)
    (work / "evidence-after.txt").write_text("evidence verified: " + " ".join(f"{k}={v}" for k, v in after.items()) + "\n")
    (work / "oplog-a").write_bytes(OPLOG_A)
    (work / "oplog-b").write_bytes(OPLOG_A + b"3\tsign\tcccc\n")
    (work / "oplog-after.txt").write_text("oplog verified: lines=3 head=cccc\n")
    (work / "verify-sealed.txt").write_text("file\t...\nverify-sealed: 3 PDFs agree with their manifests (pyHanko)\n")


class Verdict(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.work = pathlib.Path(self._t.name)
        passing(self.work)

    def tearDown(self):
        self._t.cleanup()

    def problems(self):
        return dr.judge(self.work)["problems"]

    def assertFails(self, needle):
        found = self.problems()
        self.assertTrue(any(needle in p for p in found), f"{needle!r} not in {found}")

    def test_a_good_drill_passes_and_reports_its_restore_time(self):
        r = dr.judge(self.work, "2026-11-14T00:00:00Z", "abc")
        self.assertEqual(r["verdict"], "passed", r["problems"])
        self.assertEqual(r["restore_seconds"], 12.5)
        self.assertTrue(r["keyd_oplog"]["b_begins_with_a"])
        self.assertTrue(r["seal_roots_differ"])

    def test_keyd_log_on_b_that_is_not_a_s_fails(self):
        # A restore that verified a log against itself: B's log chains, but it is not A's.
        (self.work / "oplog-b").write_bytes(b"1\tsign\tffff\n2\tsign\teeee\n3\tsign\tcccc\n")
        self.assertFails("does not begin with A's log")

    def test_a_backup_without_keyd_s_log_fails(self):
        r = json.loads((self.work / "restore.json").read_text())
        r["keyd_oplog"] = {"present": False}
        (self.work / "restore.json").write_text(json.dumps(r))
        self.assertFails("carries no keyd operation log")

    def test_a_backup_with_fewer_keyd_lines_than_a_had_fails(self):
        r = json.loads((self.work / "restore.json").read_text())
        r["keyd_oplog"]["lines"] = 1
        (self.work / "restore.json").write_text(json.dumps(r))
        self.assertFails("A had 2 before it")

    def test_keys_restored_from_the_backup_fail(self):
        (self.work / "sealed-b/trust-root.pem").write_bytes(b"root A")
        self.assertFails("B's seal root is A's")

    def test_an_empty_backup_fails_even_when_it_matches_itself(self):
        r = json.loads((self.work / "restore.json").read_text())
        r["counts"] = counts(envelopes=0, audit_events=0)
        (self.work / "restore.json").write_text(json.dumps(r))
        self.assertFails("the seeded data did not reach it")

    def test_no_independent_validation_fails(self):
        (self.work / "verify-sealed.txt").write_text("verify-sealed: 2 PDFs agree with their manifests (pyHanko)\n")
        self.assertFails("independent validator")

    def test_a_kept_pdf_other_than_the_one_a_answered_fails(self):
        (self.work / "sealed-a/completed.pdf").write_bytes(b"%PDF-1.7 other")
        self.assertFails("not the one A's API answered")

    def test_no_growth_after_the_resume_fails(self):
        before = counts()
        (self.work / "evidence-after.txt").write_text("evidence verified: " + " ".join(f"{k}={v}" for k, v in before.items()) + "\n")
        (self.work / "oplog-after.txt").write_text("oplog verified: lines=2 head=bbbb\n")
        found = self.problems()
        for needle in ("no audit event", "no new blob", "did not continue"):
            self.assertTrue(any(needle in p for p in found), f"{needle!r} not in {found}")

    def test_a_missing_input_fails_the_drill_and_still_writes_a_report(self):
        (self.work / "oplog-b").unlink()
        with contextlib.redirect_stderr(io.StringIO()) as err:
            rc = dr.main([str(self.work)])
        self.assertEqual(rc, 1)
        report = json.loads((self.work / "report.json").read_text())
        self.assertEqual(report["verdict"], "failed")
        self.assertIn("oplog-a or oplog-b is missing", err.getvalue())

    def test_main_writes_the_passing_report(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            rc = dr.main([str(self.work), "--started", "s", "--commit", "c"])
        self.assertEqual(rc, 0)
        self.assertIn("restore took 12.5 s", out.getvalue())
        self.assertEqual(json.loads((self.work / "report.json").read_text())["verdict"], "passed")


if __name__ == "__main__":
    unittest.main()
