"""Tests of the restore drill's traffic (tools/backup/drill_flow.py, ASVS-14) that need no
stack: the request the drill sends must be one the current server takes. The CI drill
failed on main (run 43508572891) with `POST /api/v1/envelopes: HTTP 422 CS-API-0001`,
after a ten-minute image build, because its Idempotency-Key held spaces; these tests catch
that, and a body member the server's DTOs would refuse, in seconds.

    python3 -I -m unittest discover -s tools/backup -p 'test_*.py'
"""

from __future__ import annotations

import io
import json
import pathlib
import re
import sys
import unittest
import urllib.error

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))

import drill_flow as df  # noqa: E402

DTO = ROOT / "server/casual-sign-server/src/dto.rs"
HTTP = ROOT / "server/casual-sign-server/src/http.rs"


def dto_members(struct: str) -> set[str]:
    """The JSON member names `struct` in dto.rs takes (its fields, serde renames applied).
    Every input DTO there denies unknown fields, so a member outside this set is a 422."""
    src = DTO.read_text(encoding="utf-8")
    m = re.search(r"pub\(crate\) struct " + struct + r" \{\n(.*?)\n\}", src, re.S)
    if not m:
        raise AssertionError(f"struct {struct} not found in {DTO}")
    names, rename = set(), None
    for line in m.group(1).splitlines():
        r = re.search(r'rename = "([^"]+)"', line)
        if r:
            rename = r.group(1)
        f = re.match(r"\s*pub (\w+):", line)
        if f:
            names.add(rename or f.group(1))
            rename = None
    return names


class Recorder:
    """An opener that records the request and answers `status` with `body`."""

    def __init__(self, status=201, body=b'{"id": "e1"}'):
        self.status, self.body, self.requests = status, body, []

    def open(self, req, timeout=None):
        self.requests.append(req)
        if self.status >= 400:
            raise urllib.error.HTTPError(req.full_url, self.status, "refused", {}, io.BytesIO(self.body))
        outer = self

        class R:
            status = outer.status

            def read(self):
                return outer.body

            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        return R()


def sent_create():
    c = df.Client("http://stack.invalid")
    c.csrf = "t"
    rec = Recorder()
    c.opener = rec
    df.create(c, "Restore drill open 1763061410000000000", [("Ben Drill", "ben@example.com"), ("Cy Drill", "cy@example.com")])
    (req,) = rec.requests
    return req


class CreateRequest(unittest.TestCase):
    def test_the_idempotency_key_is_one_the_server_takes(self):
        # The server's rule (http.rs): 1 to 255 bytes, every one visible ASCII.
        rule = HTTP.read_text(encoding="utf-8")
        self.assertIn("key.len() > 255", rule)
        self.assertIn("is_ascii_graphic", rule)
        key = sent_create().get_header("Idempotency-key")
        self.assertTrue(key and len(key) <= 255, key)
        self.assertTrue(all(0x21 <= ord(ch) <= 0x7E for ch in key), f"Idempotency-Key {key!r} has a byte the server refuses")

    def test_two_creates_with_one_subject_get_distinct_keys(self):
        self.assertNotEqual(df.idempotency_key("a b"), df.idempotency_key("a b"))

    def test_the_body_holds_only_members_the_dtos_take(self):
        body = json.loads(sent_create().data)
        self.assertLessEqual(set(body), dto_members("EnvelopeCreate"))
        for r in body["recipients"]:
            self.assertLessEqual(set(r), dto_members("RecipientIn"))
            self.assertIn(r["type"], ("signer",))
        for d in body["documents"]:
            self.assertLessEqual(set(d), dto_members("DocumentIn"))
        self.assertEqual(body["status"], "sent")
        # Signers in order, each with one required signature field of its own.
        self.assertEqual([r["routing_order"] for r in body["recipients"]], [1, 2])
        self.assertEqual(sorted(f["recipient"] for f in body["fields"]), sorted(r["ref"] for r in body["recipients"]))

    def test_the_document_is_a_pdf_with_a_correct_xref(self):
        data = df.pdf()
        xref = int(re.search(rb"startxref\n(\d+)", data).group(1))
        self.assertTrue(data[xref:].startswith(b"xref\n"))
        for i, off in enumerate(re.findall(rb"(\d{10}) 00000 n", data), 1):
            self.assertTrue(data[int(off):].startswith(b"%d 0 obj" % i))


class Refusals(unittest.TestCase):
    def test_a_refusal_names_its_code_and_pointers_not_values(self):
        c = df.Client("http://stack.invalid")
        c.opener = Recorder(422, json.dumps({"code": "CS-API-0001", "errors": [{"pointer": "/headers/Idempotency-Key", "code": "CS-API-0001"}]}).encode())
        with self.assertRaises(df.DrillError) as e:
            c.call("POST", "/api/v1/envelopes", {"subject": "private words"})
        self.assertIn("HTTP 422 CS-API-0001 at /headers/Idempotency-Key", str(e.exception))
        self.assertNotIn("private words", str(e.exception))

    def test_a_refusal_that_is_not_json_still_says_its_status(self):
        c = df.Client("http://stack.invalid")
        c.opener = Recorder(502, b"<html>bad gateway</html>")
        with self.assertRaisesRegex(df.DrillError, "HTTP 502"):
            c.call("GET", "/api/v1/envelopes/x")


class KeepsSealedPdfs(unittest.TestCase):
    def test_keep_writes_only_when_asked(self):
        import tempfile

        with tempfile.TemporaryDirectory() as t:
            ns = type("A", (), {"pdf_dir": str(pathlib.Path(t) / "sealed")})()
            df.keep(ns, "completed.pdf", b"%PDF-1.7")
            self.assertEqual((pathlib.Path(t) / "sealed/completed.pdf").read_bytes(), b"%PDF-1.7")
            df.keep(type("A", (), {"pdf_dir": None})(), "x.pdf", b"")


if __name__ == "__main__":
    unittest.main()
