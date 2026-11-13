"""Tests for acrobat_report.py (HRD-03): the judge of a Reader run, on any OS.

    python3 -I -m unittest discover -s tools/interop -p 'test_*.py'
"""

import copy
import importlib.util
import json
import pathlib
import tempfile
import unittest

HERE = pathlib.Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("acrobat_report", HERE / "acrobat_report.py")
ar = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ar)

MANIFEST = HERE.parent.parent / "fixtures" / "interop" / "manifest.tsv"

VALID_PANEL = [
    "Rev. 1: Signed by OpenSeal Interop Seal (P-256)",
    "Signature is valid:",
    "Document has not been modified since this signature was applied",
    "Signer’s identity is valid",
    "Signature includes an embedded timestamp.",
]


def good_entry(row):
    certified = "certification" in row["why"]
    texts = list(VALID_PANEL)
    if row["level"] == "B-LTA":
        texts.append("Signature is LTV enabled")
    if row["expect"] == "tampered":
        return {"file": row["file"], "banner": "At least one signature is invalid.",
                "texts": ["Signature is invalid:", "Document has been altered or corrupted since it was signed."]}
    banner = ("Certified by OpenSeal Interop Seal (P-256), OpenSeal Interop Test PKI (not a real CA)"
              if certified else "Signed and all signatures are valid.")
    return {"file": row["file"], "banner": banner, "texts": texts, "screenshots": [f"{row['file']}.png"]}


class Judge(unittest.TestCase):
    def setUp(self):
        self.rows = ar.read_manifest(MANIFEST)
        self.report = {"schema": 1, "reader_version": "26.2", "os": "Windows",
                       "trust": {"method": "windows-store"},
                       "files": [good_entry(r) for r in self.rows]}

    def entry(self, report, name):
        return next(e for e in report["files"] if e["file"] == name)

    def test_a_report_matching_the_checklist_passes(self):
        self.assertEqual(ar.judge(self.report, self.rows), [])

    def test_an_invalid_signature_on_a_valid_file_fails(self):
        bad = copy.deepcopy(self.report)
        e = self.entry(bad, "agreement-p256-blta.pdf")
        e["banner"] = "At least one signature is invalid."
        e["texts"] = ["Signature is invalid:", "Document has been altered or corrupted since it was signed."]
        problems = ar.judge(bad, self.rows)
        self.assertTrue(any("agreement-p256-blta.pdf" in p and "banner" in p for p in problems), problems)
        self.assertTrue(any("signature is invalid" in p for p in problems), problems)

    def test_an_untrusted_signer_fails(self):
        bad = copy.deepcopy(self.report)
        e = self.entry(bad, "agreement-rsa3072-bt.pdf")
        e["banner"] = "At least one signature has problems."
        e["texts"] = [t for t in e["texts"] if "identity" not in t] + ["Signer's identity is unknown"]
        problems = ar.judge(bad, self.rows)
        self.assertTrue(any("signer trusted" in p for p in problems), problems)
        self.assertTrue(any("at least one signature has problems" in p for p in problems), problems)

    def test_a_missing_timestamp_fails(self):
        bad = copy.deepcopy(self.report)
        e = self.entry(bad, "agreement-p256-bt.pdf")
        e["texts"] = [t for t in e["texts"] if "timestamp" not in t]
        self.assertTrue(any("timestamp not shown" in p for p in ar.judge(bad, self.rows)))

    def test_blta_must_be_ltv_enabled_and_bt_need_not(self):
        bad = copy.deepcopy(self.report)
        e = self.entry(bad, "agreement-rsa3072-blta.pdf")
        e["texts"] = [t for t in e["texts"] if "LTV" not in t]
        problems = ar.judge(bad, self.rows)
        self.assertEqual(len(problems), 1, problems)
        self.assertIn("ltv", problems[0])

    def test_the_certified_file_needs_its_ribbon_banner(self):
        bad = copy.deepcopy(self.report)
        self.entry(bad, "agreement-p256-certified-p2-blta.pdf")["banner"] = "Signed and all signatures are valid."
        self.assertTrue(any("Certified by" in p for p in ar.judge(bad, self.rows)))

    def test_a_tampered_file_shown_valid_fails(self):
        bad = copy.deepcopy(self.report)
        e = self.entry(bad, "tampered-p256-blta.pdf")
        e["banner"] = "Signed and all signatures are valid."
        e["texts"] = list(VALID_PANEL)
        problems = ar.judge(bad, self.rows)
        self.assertTrue(any("did not report the alteration" in p for p in problems), problems)
        self.assertTrue(any("tampered file" in p for p in problems), problems)

    def test_a_missing_file_or_driver_error_or_no_text_fails(self):
        bad = copy.deepcopy(self.report)
        bad["files"] = [e for e in bad["files"] if e["file"] != "agreement-p256-bt.pdf"]
        self.entry(bad, "agreement-rsa3072-bt.pdf").update({"error": "window never appeared"})
        e = self.entry(bad, "agreement-p256-blta.pdf")
        e["banner"], e["texts"] = "", []
        problems = ar.judge(bad, self.rows)
        self.assertTrue(any("agreement-p256-bt.pdf: not in the report" in p for p in problems))
        self.assertTrue(any("window never appeared" in p for p in problems))
        self.assertTrue(any("no text was captured" in p for p in problems))

    def test_a_wrong_schema_is_refused(self):
        self.assertEqual(ar.judge({"schema": 99, "files": []}, self.rows), ["not an acrobat report of schema 1"])
        self.assertEqual(ar.judge([], self.rows), ["not an acrobat report of schema 1"])

    def test_cli_exit_codes(self):
        with tempfile.TemporaryDirectory() as tmp:
            good = pathlib.Path(tmp, "good.json")
            good.write_text(json.dumps(self.report), encoding="utf8")
            self.assertEqual(ar.main(["x", str(good), "--manifest", str(MANIFEST)]), 0)
            bad = copy.deepcopy(self.report)
            self.entry(bad, "agreement-p256-blta.pdf")["banner"] = "At least one signature is invalid."
            badp = pathlib.Path(tmp, "bad.json")
            badp.write_text(json.dumps(bad), encoding="utf8")
            self.assertEqual(ar.main(["x", str(badp), "--manifest", str(MANIFEST)]), 1)
            self.assertEqual(ar.main(["x", str(pathlib.Path(tmp, "absent.json"))]), 2)


if __name__ == "__main__":
    unittest.main()
