#!/usr/bin/env python3
"""The restore drill's traffic (ASVS-14; tools/backup/drill.sh runs it). Talks to a
Compose stack over its public API and ceremony, and to Mailpit for the signing links.

    drill_flow.py seed   --base URL --mail URL --state FILE   # before the backup
    drill_flow.py check  --base URL --state FILE              # after the restore
    drill_flow.py resume --base URL --state FILE              # then finish the open envelope

`seed` signs in as the bootstrapped administrator (OPENSEAL_DRILL_EMAIL and _PASSWORD),
sends two envelopes and has them signed through the emailed links: "Completed" (one
signer, signed, then sealed by the worker) and "Open" (two signers in order, the first
signed, the second's link kept). It records the sealed PDF's SHA-256 and the open
envelope's state. `check`, on the restored stack, reads the completed envelope's sealed
PDF and requires the same bytes, and the open envelope as it was. `resume` signs the open
envelope's second signer with the link emailed before the backup (the link's token is
stored only as its hash, so it outlives the restore), waits for the restored worker to seal
it, and requires its sealed PDF and a longer audit trail.

Standard library only. Prints ids and hashes, never document text.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.cookiejar
import json
import os
import pathlib
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

PNG = base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==")
LINK = re.compile(r"https?://[^\s\"'<>]+(/s/[A-Za-z0-9._~%-]+)")


class DrillError(Exception):
    pass


def say(msg: str) -> None:
    print(f"drill: {msg}", file=sys.stderr, flush=True)


def pdf() -> bytes:
    """A one-page PDF with correct cross-reference offsets."""
    content = b"BT /F1 12 Tf 72 720 Td (Restore drill) Tj ET"
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << >> >>",
        b"<< /Length %d >>\nstream\n%s\nendstream" % (len(content), content),
    ]
    out = bytearray(b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
    offsets = []
    for i, o in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n%s\nendobj\n" % (i, o)
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for o in offsets:
        out += b"%010d 00000 n \n" % o
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    return bytes(out)


class Client:
    """One browser: its own cookies."""

    def __init__(self, base: str):
        self.base = base.rstrip("/")
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.csrf: str | None = None

    def call(self, method: str, path: str, body=None, *, raw=False, ok=(200, 201), headers=None):
        data = None if body is None else json.dumps(body).encode()
        h = {"Accept": "application/json"}
        if data is not None:
            h["Content-Type"] = "application/json"
        if self.csrf:
            h["X-CSRF-Token"] = self.csrf
        h.update(headers or {})
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=h)
        try:
            with self.opener.open(req, timeout=60) as r:
                status, payload = r.status, r.read()
        except urllib.error.HTTPError as e:
            status, payload = e.code, e.read()
        if status not in ok:
            raise DrillError(f"{method} {path.split('?')[0][:40]}: HTTP {status} {problem(payload)}")
        if raw:
            return payload
        return json.loads(payload) if payload else {}

    def sign_in(self, email: str, password: str) -> None:
        r = self.call("POST", "/api/v1/auth/login", {"email": email, "password": password})
        self.csrf = r["csrf_token"]


def problem(payload: bytes) -> str:
    """A refusal's code and the JSON pointers it names (problem details, docs/40): never
    values, so the drill's log can say which member the server refused."""
    try:
        p = json.loads(payload)
    except ValueError:
        return ""
    if not isinstance(p, dict):
        return ""
    pointers = [str(e.get("pointer", "")) for e in p.get("errors") or [] if isinstance(e, dict)]
    return " ".join([str(p.get("code", "")), *[f"at {x}" for x in pointers if x]]).strip()


def idempotency_key(label: str) -> str:
    """An Idempotency-Key the server takes: 1 to 255 visible ASCII characters, no space
    (casual-sign-server's http.rs; a key with a space is refused 422 CS-API-0001)."""
    key = "drill-" + re.sub(r"[^A-Za-z0-9._-]+", "-", label)[:200] + f"-{time.time_ns()}"
    return key


def signing_path(mail: str, to: str, *, timeout: float = 90) -> str:
    """The `/s/<token>` path in an email to `to` (each run's addresses are its own)."""
    deadline = time.monotonic() + timeout
    q = urllib.parse.quote(f'to:"{to}"')
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"{mail}/api/v1/search?query={q}", timeout=10) as r:
                messages = json.loads(r.read()).get("messages", [])
            for m in messages:
                with urllib.request.urlopen(f"{mail}/api/v1/message/{urllib.parse.quote(m['ID'])}", timeout=10) as r:
                    full = json.loads(r.read())
                found = LINK.search(f"{full.get('Text', '')}\n{full.get('HTML', '')}")
                if found:
                    return found.group(1)
        except (urllib.error.URLError, ValueError, KeyError):
            pass
        time.sleep(1)
    raise DrillError(f"no signing link emailed within {timeout:.0f} s")


def sign(base: str, path: str, *, last: bool) -> None:
    """One signer's ceremony over the API: session, consent if asked, adopt, fill, finish."""
    c = Client(base)
    view = c.call("POST", f"{path}/session", {})
    if view.get("consent_required"):
        c.call("POST", f"{path}/consent", {"ersd_version": view["consent_required"]["version"]})
    me = view["recipient"]["id"]
    adopted = c.call("POST", f"{path}/adopt", {"mark": "signature", "method": "draw", "image_base64": base64.b64encode(PNG).decode()})
    mine = [f for f in view["fields"] if f.get("recipient_id") == me and f.get("type") == "signature"]
    if not mine:
        raise DrillError("the signer has no signature field")
    for f in mine:
        c.call("PUT", f"{path}/fields/{f['id']}", {"value": {"signature": adopted["adoption_id"]}})
    c.call("POST", f"{path}/finish", {})
    say(f"signed ({'last signer' if last else 'not the last'})")


def envelope(c: Client, eid: str) -> dict:
    return c.call("GET", f"/api/v1/envelopes/{eid}")


def wait_status(c: Client, eid: str, want: str, timeout: float = 180) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        e = envelope(c, eid)
        if e["status"] == want:
            return e
        time.sleep(2)
    raise DrillError(f"envelope {eid} not {want} within {timeout:.0f} s (status {e['status']})")


def sealed(c: Client, e: dict) -> bytes:
    doc = e["documents"][0]["id"]
    data = c.call("GET", f"/api/v1/envelopes/{e['id']}/documents/{doc}/content?version=sealed", raw=True, headers={"Accept": "application/pdf"})
    if not data.startswith(b"%PDF-"):
        raise DrillError("the sealed document is not a PDF")
    return data


def chain(c: Client, eid: str) -> list[str]:
    """The envelope's audit chain as its event hashes, oldest first."""
    return [str(i["hash"]) for i in c.call("GET", f"/api/v1/envelopes/{eid}/audit")["items"]]


def same_start(restored: list[str], seeded: list[str], what: str) -> None:
    """The restored chain begins with every event seen before the backup. (A job the
    old worker had not finished, a notice for one, may add events after them.)"""
    if restored[: len(seeded)] != seeded:
        raise DrillError(f"the restored {what} envelope's audit chain does not begin with the events seen before the backup")


def envelope_body(subject: str, signers: list[tuple[str, str]]) -> dict:
    """The one-call create (docs/40 §3): sent at once, signers in order, one signature
    field each."""
    return {
        "subject": subject,
        "status": "sent",
        "documents": [{"name": "drill.pdf", "content_base64": base64.b64encode(pdf()).decode()}],
        "recipients": [
            {"ref": f"r{i}", "type": "signer", "name": n, "email": m, "routing_order": i + 1}
            for i, (n, m) in enumerate(signers)
        ],
        "fields": [
            {"recipient": f"r{i}", "document": 0, "type": "signature", "page": 1, "x": 72, "y": 600 - 60 * i, "width": 180, "height": 40, "required": True}
            for i in range(len(signers))
        ],
    }


def create(c: Client, subject: str, signers: list[tuple[str, str]]) -> str:
    body = envelope_body(subject, signers)
    r = c.call("POST", "/api/v1/envelopes", body, headers={"Idempotency-Key": idempotency_key(subject)})
    return r["id"]


def credentials() -> tuple[str, str]:
    email, password = os.environ.get("OPENSEAL_DRILL_EMAIL"), os.environ.get("OPENSEAL_DRILL_PASSWORD")
    if not email or not password:
        raise DrillError("set OPENSEAL_DRILL_EMAIL and OPENSEAL_DRILL_PASSWORD")
    return email, password


def keep(args, name: str, data: bytes) -> None:
    """A sealed PDF, kept for the independent validator (tools/verify-sealed.py) when
    `--pdf-dir` is given."""
    if args.pdf_dir:
        d = pathlib.Path(args.pdf_dir)
        d.mkdir(parents=True, exist_ok=True)
        (d / name).write_bytes(data)


def seed(args) -> None:
    c = Client(args.base)
    c.sign_in(*credentials())
    run = str(time.time_ns())
    done = create(c, f"Restore drill completed {run}", [("Ana Drill", f"ana-{run}@example.com")])
    opened = create(c, f"Restore drill open {run}", [("Ben Drill", f"ben-{run}@example.com"), ("Cy Drill", f"cy-{run}@example.com")])
    sign(args.base, signing_path(args.mail, f"ana-{run}@example.com"), last=True)
    sign(args.base, signing_path(args.mail, f"ben-{run}@example.com"), last=False)
    second = signing_path(args.mail, f"cy-{run}@example.com")
    e = wait_status(c, done, "completed")
    pdf_bytes = sealed(c, e)
    keep(args, "completed.pdf", pdf_bytes)
    o = envelope(c, opened)
    state = {
        "completed": {"id": done, "sealed_sha256": hashlib.sha256(pdf_bytes).hexdigest(), "chain": chain(c, done)},
        "open": {"id": opened, "status": o["status"], "chain": chain(c, opened), "second_signer_path": second},
    }
    pathlib.Path(args.state).write_text(json.dumps(state, indent=1) + "\n", encoding="utf-8")
    say(f"seeded: completed {done} sealed sha256 {state['completed']['sealed_sha256'][:16]}…, open {opened} ({o['status']})")


def check(args) -> None:
    state = json.loads(pathlib.Path(args.state).read_text(encoding="utf-8"))
    c = Client(args.base)
    c.sign_in(*credentials())
    e = envelope(c, state["completed"]["id"])
    if e["status"] != "completed":
        raise DrillError(f"restored completed envelope is {e['status']}")
    got = hashlib.sha256(sealed(c, e)).hexdigest()
    if got != state["completed"]["sealed_sha256"]:
        raise DrillError(f"restored sealed PDF differs: {got[:16]}… vs {state['completed']['sealed_sha256'][:16]}…")
    same_start(chain(c, e["id"]), state["completed"]["chain"], "completed")
    o = envelope(c, state["open"]["id"])
    if o["status"] != state["open"]["status"]:
        raise DrillError(f"restored open envelope is {o['status']}, was {state['open']['status']}")
    same_start(chain(c, o["id"]), state["open"]["chain"], "open")
    say(f"check: sealed PDF byte-identical ({got[:16]}…); both audit chains begin as before the backup; open envelope {o['status']}")


def resume(args) -> None:
    state = json.loads(pathlib.Path(args.state).read_text(encoding="utf-8"))
    c = Client(args.base)
    c.sign_in(*credentials())
    before = chain(c, state["open"]["id"])
    sign(args.base, state["open"]["second_signer_path"], last=True)
    e = wait_status(c, state["open"]["id"], "completed")
    data = sealed(c, e)
    keep(args, "resumed.pdf", data)
    after = chain(c, e["id"])
    if len(after) <= len(before) or after[: len(before)] != before:
        raise DrillError("the resumed envelope's audit chain did not continue from its restored head")
    say(f"resume: open envelope completed and sealed after the restore ({len(data)} bytes; chain {len(before)} → {len(after)} events)")


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="drill_flow.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("seed", "check", "resume"):
        p = sub.add_parser(name)
        p.add_argument("--base", required=True)
        p.add_argument("--state", required=True)
        p.add_argument("--pdf-dir", help="keep the sealed PDFs here (seed: completed.pdf; resume: resumed.pdf)")
        if name == "seed":
            p.add_argument("--mail", required=True)
    args = ap.parse_args(argv)
    try:
        {"seed": seed, "check": check, "resume": resume}[args.cmd](args)
    except DrillError as e:
        say(f"failed: {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
