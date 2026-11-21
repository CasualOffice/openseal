"""Tests of the CI-only authentication stubs (RAUTH-02), without Docker:

    python3 -I -m unittest discover -s tools/e2e -p 'test_*.py'

Each stub runs in this process on free loopback ports. The SMS gateway is reached over
TLS that must verify against a root made here (as the worker verifies it against the
development root), and is held to the worker's contract (messenger::HttpGateway). The
identity provider is taken through the authorization code flow the server runs
(idp.rs), and its ID token's RS256 signature is checked against its JWKS with nothing
but integer arithmetic. The Compose overlay is checked to stay out of every other
Compose file. Needs the `openssl` command, as the stubs do.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import pathlib
import re
import secrets
import shutil
import ssl
import subprocess
import tempfile
import threading
import unittest
from urllib.parse import parse_qs, urlencode, urlsplit

import auth_stubs as st

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
SECRET = "test-gateway-secret"
REDIRECT = "http://localhost:8080/s/oidc"


def unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def make_root(d: pathlib.Path) -> None:
    subprocess.run(["openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-out", str(d / "ca.key")], check=True, capture_output=True)
    subprocess.run(["openssl", "req", "-x509", "-new", "-key", str(d / "ca.key"), "-sha256", "-days", "2",
                    "-subj", "/CN=test root", "-out", str(d / "ca.pem"),
                    "-addext", "basicConstraints=critical,CA:TRUE",
                    "-addext", "keyUsage=critical,keyCertSign,cRLSign"], check=True, capture_output=True)


def start(server) -> None:
    threading.Thread(target=server.serve_forever, daemon=True).start()


class SmsGateway(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory()
        d = pathlib.Path(cls.dir.name)
        make_root(d)
        chain, key = st.issue_tls(d, "localhost", d)
        cls.gateway, cls.reader = st.sms_servers(("127.0.0.1", 0), ("127.0.0.1", 0), chain, key, SECRET)
        start(cls.gateway)
        start(cls.reader)
        cls.tls = ssl.create_default_context(cafile=str(d / "ca.pem"))

    @classmethod
    def tearDownClass(cls):
        for s in (cls.gateway, cls.reader):
            s.shutdown()
            s.server_close()
        cls.dir.cleanup()

    def post(self, body, auth=f"Bearer {SECRET}", raw=None):
        c = http.client.HTTPSConnection("127.0.0.1", self.gateway.server_address[1], context=self.tls, timeout=5)
        headers = {"Content-Type": "application/json"}
        if auth:
            headers["Authorization"] = auth
        c.request("POST", "/messages", body=raw if raw is not None else json.dumps(body).encode(), headers=headers)
        r = c.getresponse()
        r.read()
        c.close()
        return r.status

    def read(self, to=None):
        c = http.client.HTTPConnection("127.0.0.1", self.reader.server_address[1], timeout=5)
        c.request("GET", "/messages" + (f"?{urlencode({'to': to})}" if to else ""))
        r = c.getresponse()
        out = json.loads(r.read())
        c.close()
        return out["messages"]

    def test_the_certificate_verifies_against_the_root_that_issued_it(self):
        # The worker's view: TLS with only the issuing root trusted.
        self.assertEqual(self.post({"channel": "sms", "to": "+447700900001", "text": "code 1", "id": "a"}), 202)
        untrusted = ssl.create_default_context()
        c = http.client.HTTPSConnection("127.0.0.1", self.gateway.server_address[1], context=untrusted, timeout=5)
        with self.assertRaises(ssl.SSLError):
            c.request("GET", "/")
        c.close()

    def test_a_message_without_the_bearer_secret_is_refused_and_not_kept(self):
        to = "+447700900002"
        self.assertEqual(self.post({"channel": "sms", "to": to, "text": "x", "id": "b"}, auth=None), 401)
        self.assertEqual(self.post({"channel": "sms", "to": to, "text": "x", "id": "b"}, auth="Bearer wrong"), 401)
        self.assertEqual(self.read(to), [])

    def test_sms_and_voice_messages_are_read_back_newest_first_by_number(self):
        to = "+447700900003"
        self.assertEqual(self.post({"channel": "sms", "to": to, "text": "OpenSeal: your signing code is 123456.", "id": "c1"}), 202)
        self.assertEqual(self.post({"channel": "voice", "to": to, "text": "Your signing code is 6, 5, 4.", "id": "c2"}), 202)
        self.assertEqual(self.post({"channel": "sms", "to": "+447700900099", "text": "other", "id": "c3"}), 202)
        got = self.read(to)
        self.assertEqual([m["id"] for m in got], ["c2", "c1"])
        self.assertEqual(got[1]["channel"], "sms")
        self.assertIn("123456", got[1]["text"])

    def test_a_body_that_is_not_the_contract_is_refused(self):
        base = {"channel": "sms", "to": "+447700900004", "text": "t", "id": "d"}
        for bad in ({**base, "channel": "fax"}, {**base, "extra": 1}, {k: v for k, v in base.items() if k != "id"},
                    {**base, "to": ""}, [base]):
            self.assertEqual(self.post(bad), 400, bad)
        self.assertEqual(self.post(None, raw=b"{not json"), 400)
        self.assertEqual(self.post(None, raw=b"x" * (st.MAX_BODY + 1)), 413)
        self.assertEqual(self.read("+447700900004"), [])


class OidcProvider(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory()
        cls.file = HERE / "recipient-idps.json"
        cls.conf = json.loads(cls.file.read_text())["providers"][0]
        cls.server = st.oidc_server(("127.0.0.1", 0), st.Provider(cls.file, REDIRECT, st.Signer(pathlib.Path(cls.dir.name))))
        start(cls.server)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.dir.cleanup()

    def call(self, method, path, form=None):
        c = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=10)
        body = urlencode(form).encode() if form is not None else None
        c.request(method, path, body=body, headers={"Content-Type": "application/x-www-form-urlencoded"} if body else {})
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, r.getheader("Location"), data

    def request(self, verifier, **over):
        q = {"response_type": "code", "client_id": self.conf["client_id"], "redirect_uri": REDIRECT,
             "scope": "openid email", "state": "st-" + secrets.token_hex(4), "nonce": "n-" + secrets.token_hex(4),
             "code_challenge": st.b64url(hashlib.sha256(verifier.encode()).digest()), "code_challenge_method": "S256"}
        q.update(over)
        return q

    def sign_in(self, q, email):
        status, page_loc, page = self.call("GET", "/authorize?" + urlencode(q))
        self.assertEqual(status, 200, page)
        self.assertIn(b'<label for="email">Email</label>', page)
        status, loc, _ = self.call("POST", "/authorize", {**q, "email": email})
        self.assertEqual(status, 303)
        back = urlsplit(loc)
        self.assertEqual(f"{back.scheme}://{back.netloc}{back.path}", REDIRECT)
        got = {k: v[0] for k, v in parse_qs(back.query).items()}
        self.assertEqual(got["state"], q["state"])
        return got["code"]

    def token(self, code, verifier, **over):
        form = {"grant_type": "authorization_code", "code": code, "redirect_uri": REDIRECT,
                "client_id": self.conf["client_id"], "client_secret": self.conf["client_secret"], "code_verifier": verifier}
        form.update(over)
        status, _, data = self.call("POST", "/token", form)
        return status, json.loads(data)

    def verify_rs256(self, jwt):
        status, _, data = self.call("GET", "/jwks")
        self.assertEqual(status, 200)
        (key,) = json.loads(data)["keys"]
        head, claims, sig = jwt.split(".")
        header = json.loads(unb64(head))
        self.assertEqual((header["alg"], header["kid"]), ("RS256", key["kid"]))
        n, e = int.from_bytes(unb64(key["n"]), "big"), int.from_bytes(unb64(key["e"]), "big")
        em = pow(int.from_bytes(unb64(sig), "big"), e, n).to_bytes((n.bit_length() + 7) // 8, "big")
        # EMSA-PKCS1-v1_5 with SHA-256 (RFC 8017 §9.2).
        digest_info = bytes.fromhex("3031300d060960864801650304020105000420")
        want = digest_info + hashlib.sha256(f"{head}.{claims}".encode()).digest()
        self.assertEqual(em, b"\x00\x01" + b"\xff" * (len(em) - len(want) - 3) + b"\x00" + want)
        return json.loads(unb64(claims))

    def test_the_code_flow_answers_a_signed_id_token_for_the_email_signed_in_with(self):
        verifier = secrets.token_urlsafe(32)
        q = self.request(verifier)
        code = self.sign_in(q, "ana@example.com")
        status, body = self.token(code, verifier)
        self.assertEqual(status, 200, body)
        claims = self.verify_rs256(body["id_token"])
        self.assertEqual(claims["iss"], self.conf["issuer"])
        self.assertEqual(claims["aud"], self.conf["client_id"])
        self.assertEqual(claims["nonce"], q["nonce"])
        self.assertEqual((claims["email"], claims["email_verified"]), ("ana@example.com", True))
        self.assertGreater(claims["exp"], claims["iat"])
        self.assertLessEqual(claims["auth_time"], claims["iat"])
        self.assertTrue(claims["sub"])

    def test_a_code_works_once(self):
        verifier = secrets.token_urlsafe(32)
        code = self.sign_in(self.request(verifier), "ana@example.com")
        self.assertEqual(self.token(code, verifier)[0], 200)
        self.assertEqual(self.token(code, verifier), (400, {"error": "invalid_grant"}))

    def test_a_wrong_pkce_verifier_or_redirect_is_refused(self):
        verifier = secrets.token_urlsafe(32)
        code = self.sign_in(self.request(verifier), "ana@example.com")
        self.assertEqual(self.token(code, "another-verifier")[0], 400)
        code = self.sign_in(self.request(verifier), "ana@example.com")
        self.assertEqual(self.token(code, verifier, redirect_uri="http://localhost:8080/elsewhere")[0], 400)

    def test_a_wrong_client_secret_is_refused(self):
        verifier = secrets.token_urlsafe(32)
        code = self.sign_in(self.request(verifier), "ana@example.com")
        self.assertEqual(self.token(code, verifier, client_secret="wrong"), (401, {"error": "invalid_client"}))

    def test_an_authorization_request_unlike_the_servers_is_refused(self):
        v = "v"
        for bad in (self.request(v, redirect_uri="http://evil.test/cb"), self.request(v, client_id="other"),
                    self.request(v, code_challenge_method="plain"), self.request(v, nonce=""),
                    self.request(v, scope="email")):
            status, _, _ = self.call("GET", "/authorize?" + urlencode(bad))
            self.assertEqual(status, 400, bad)
        status, _, _ = self.call("POST", "/authorize", {**self.request(v), "email": "not-an-email"})
        self.assertEqual(status, 400)

    def test_the_request_is_escaped_into_the_sign_in_page(self):
        status, _, page = self.call("GET", "/authorize?" + urlencode(self.request("v", state='"><script>x</script>')))
        self.assertEqual(status, 200)
        self.assertNotIn(b"<script>", page)


HOOK_SECRET = "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw"


class WebhookReceiver(unittest.TestCase):
    """The slice 8 receiver (VS-08C): checks each delivery's Standard Webhooks signature as
    a receiver must, records it, and answers with the status the reader sets."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory()
        d = pathlib.Path(cls.dir.name)
        make_root(d)
        chain, key = st.issue_tls(d, "localhost", d)
        cls.receiver, cls.reader = st.hooks_servers(("127.0.0.1", 0), ("127.0.0.1", 0), chain, key, HOOK_SECRET)
        start(cls.receiver)
        start(cls.reader)
        cls.tls = ssl.create_default_context(cafile=str(d / "ca.pem"))

    @classmethod
    def tearDownClass(cls):
        for s in (cls.receiver, cls.reader):
            s.shutdown()
            s.server_close()
        cls.dir.cleanup()

    def deliver(self, msg_id, ts, body, sig):
        c = http.client.HTTPSConnection("127.0.0.1", self.receiver.server_address[1], context=self.tls, timeout=5)
        c.request("POST", "/hook", body=body, headers={"Content-Type": "application/json", "webhook-id": msg_id,
                                                       "webhook-timestamp": ts, "webhook-signature": sig})
        r = c.getresponse()
        r.read()
        c.close()
        return r.status

    def reader_call(self, method, path):
        c = http.client.HTTPConnection("127.0.0.1", self.reader.server_address[1], timeout=5)
        c.request(method, path)
        r = c.getresponse()
        out = json.loads(r.read())
        c.close()
        return r.status, out

    def test_the_standard_webhooks_example_verifies(self):
        key = st.webhook_key(HOOK_SECRET)
        body = b'{"test": 2432232314}'
        good = "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="
        self.assertTrue(st.webhook_verified(key, "msg_p5jXN8AQM9LWM0D4loKWxJek", "1614265330", body, good))
        self.assertTrue(st.webhook_verified(key, "msg_p5jXN8AQM9LWM0D4loKWxJek", "1614265330", body, f"v1,AAAA {good}"))
        self.assertFalse(st.webhook_verified(key, "msg_p5jXN8AQM9LWM0D4loKWxJek", "1614265331", body, good))
        with self.assertRaises(ValueError):
            st.webhook_key("MfKQ9r8")

    def test_deliveries_are_recorded_with_their_check_and_answered_as_set(self):
        body = json.dumps({"id": "e1", "type": "envelope.sent", "data": {"envelope_id": "env-1"}}).encode()
        key = st.webhook_key(HOOK_SECRET)
        sig = "v1," + base64.b64encode(hmac_sha256(key, b"msg-1.1700000000." + body)).decode()
        self.assertEqual(self.deliver("msg-1", "1700000000", body, sig), 200)
        self.assertEqual(self.deliver("msg-2", "1700000000", body, "v1,AAAA"), 200)
        self.assertEqual(self.reader_call("POST", "/answer?status=500")[0], 200)
        self.assertEqual(self.deliver("msg-3", "1700000000", body, sig), 500)
        self.assertEqual(self.reader_call("POST", "/answer?status=200")[0], 200)
        _, got = self.reader_call("GET", "/deliveries?type=envelope.sent&envelope=env-1")
        self.assertEqual([(d["id"], d["verified"], d["answered"]) for d in got["deliveries"]],
                         [("msg-3", False, 500), ("msg-2", False, 200), ("msg-1", True, 200)])
        self.assertEqual(self.reader_call("POST", "/answer?status=abc")[0], 400)


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    import hmac
    return hmac.new(key, data, hashlib.sha256).digest()


class Overlay(unittest.TestCase):
    def test_only_the_e2e_overlay_names_the_stubs(self):
        overlay = (HERE / "compose.e2e.yml").read_text()
        self.assertIn("auth_stubs.py", overlay)
        for f in (ROOT / "docker-compose.yml", ROOT / "deploy" / "compose.production.yml"):
            text = f.read_text()
            for name in ("auth_stubs", "sms-gateway", "tools/e2e", "OPENSEAL_SMS_GATEWAY", "OPENSEAL_RECIPIENT_IDPS_FILE"):
                self.assertNotIn(name, text, f"{f.name} names {name}")

    def test_the_providers_file_is_the_one_the_server_and_the_stub_share(self):
        overlay = (HERE / "compose.e2e.yml").read_text()
        conf = json.loads((HERE / "recipient-idps.json").read_text())["providers"][0]
        self.assertIn("OPENSEAL_RECIPIENT_IDPS_FILE: /opt/e2e/recipient-idps.json", overlay)
        self.assertIn('"--providers", "/opt/e2e/recipient-idps.json"', overlay)
        # No redirect_uri in the file: the server's default, its public URL's /s/oidc, which
        # the overlay hands the stub from the same variable as the server's.
        self.assertNotIn("redirect_uri", conf)
        self.assertIn('"--redirect-uri", "http://localhost:${OPENSEAL_HTTP_PORT:-8080}/s/oidc"', overlay)
        self.assertIn("OPENSEAL_PUBLIC_URL: http://localhost:${OPENSEAL_HTTP_PORT:-8080}", (ROOT / "docker-compose.yml").read_text())
        # The server calls these itself: plain HTTP only to the loopback address (idp.rs).
        for k in ("token_endpoint", "jwks_uri"):
            self.assertTrue(conf[k].startswith("http://127.0.0.1:8090/"), k)
        # The browser's: localhost, the same site as the signing page, for its cookie.
        self.assertTrue(conf["authorization_endpoint"].startswith("http://localhost:8090/"))


CSC_REDIRECT = "http://localhost:8080/s/rsp"
CSC_SECRET = "test-csc-secret"


class CscProvider(unittest.TestCase):
    """The CSC stub through both redirects as the server and worker run them (RSP-01)."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory()
        d = pathlib.Path(cls.dir.name)
        make_root(d)
        cls.root = d / "ca.pem"
        cls.csc = st.Csc(d, d, "Remote Signer", CSC_REDIRECT, CSC_SECRET)
        cls.server = st.ThreadingHTTPServer(("127.0.0.1", 0), st.csc_handler(cls.csc))
        start(cls.server)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.dir.cleanup()

    def call(self, method, path, body=b"", headers=None):
        c = http.client.HTTPConnection("127.0.0.1", self.server.server_address[1], timeout=10)
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        data = r.read()
        c.close()
        return r.status, dict(r.getheaders()), data

    def authorize(self, scope, extra=None, decision="allow"):
        verifier = secrets.token_urlsafe(32)
        challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
        q = {"response_type": "code", "client_id": "openseal", "redirect_uri": CSC_REDIRECT, "scope": scope,
             "state": "st-1", "code_challenge": challenge, "code_challenge_method": "S256", **(extra or {})}
        status, _, page = self.call("GET", "/oauth2/authorize?" + urlencode(q))
        self.assertEqual(status, 200, page)
        status, h, _ = self.call("POST", "/oauth2/authorize", urlencode({**q, "decision": decision}).encode(),
                                 {"Content-Type": "application/x-www-form-urlencoded"})
        self.assertEqual(status, 302)
        back = parse_qs(urlsplit(h["Location"]).query)
        self.assertTrue(h["Location"].startswith(CSC_REDIRECT))
        self.assertEqual(back["state"], ["st-1"])
        return back, verifier

    def token(self, code, verifier, secret=CSC_SECRET):
        form = urlencode({"grant_type": "authorization_code", "code": code, "redirect_uri": CSC_REDIRECT,
                          "client_id": "openseal", "client_secret": secret, "code_verifier": verifier}).encode()
        status, _, data = self.call("POST", "/oauth2/token", form, {"Content-Type": "application/x-www-form-urlencoded"})
        return status, json.loads(data)

    def api(self, path, token, body):
        status, _, data = self.call("POST", f"/csc/v2/{path}", json.dumps(body).encode(),
                                    {"Content-Type": "application/json", "Authorization": f"Bearer {token}"})
        return status, json.loads(data)

    def test_both_redirects_end_in_a_signature_that_verifies_under_the_issued_certificate(self):
        back, verifier = self.authorize("service")
        status, tok = self.token(back["code"][0], verifier)
        self.assertEqual(status, 200)
        status, listed = self.api("credentials/list", tok["access_token"], {})
        self.assertEqual(listed["credentialIDs"], ["ci-signer"])
        status, info = self.api("credentials/info", tok["access_token"], {"credentialID": "ci-signer"})
        self.assertEqual(info["SCAL"], "2")
        leaf = base64.b64decode(info["cert"]["certificates"][0])
        digest = hashlib.sha256(b"signed attributes").digest()
        hashes = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
        back, verifier = self.authorize("credential", {"credentialID": "ci-signer", "numSignatures": "1",
                                                       "hashes": hashes, "hashAlgorithmOID": "2.16.840.1.101.3.4.2.1"})
        status, cred = self.token(back["code"][0], verifier)
        # Another hash than the authorized one is refused (SCAL2).
        other = base64.b64encode(hashlib.sha256(b"other").digest()).decode()
        status, _ = self.api("signatures/signHash", cred["access_token"],
                             {"credentialID": "ci-signer", "hashes": [other], "hashAlgorithmOID": "2.16.840.1.101.3.4.2.1"})
        self.assertEqual(status, 400)
        status, signed = self.api("signatures/signHash", cred["access_token"],
                                  {"credentialID": "ci-signer", "hashes": [base64.b64encode(digest).decode()],
                                   "hashAlgorithmOID": "2.16.840.1.101.3.4.2.1"})
        self.assertEqual(status, 200)
        sig = base64.b64decode(signed["signatures"][0])
        with tempfile.TemporaryDirectory() as t:
            t = pathlib.Path(t)
            (t / "leaf.der").write_bytes(leaf)
            subprocess.run(["openssl", "x509", "-inform", "DER", "-in", str(t / "leaf.der"), "-pubkey", "-noout",
                            "-out", str(t / "pub.pem")], check=True, capture_output=True)
            (t / "msg").write_bytes(b"signed attributes")
            (t / "sig").write_bytes(sig)
            ok = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(t / "pub.pem"), "-signature",
                                 str(t / "sig"), str(t / "msg")], capture_output=True)
            self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)
            subprocess.run(["openssl", "x509", "-inform", "DER", "-in", str(t / "leaf.der"), "-out",
                            str(t / "leaf.pem")], check=True, capture_output=True)
            chain = subprocess.run(["openssl", "verify", "-CAfile", str(self.root), str(t / "leaf.pem")],
                                   capture_output=True)
            self.assertEqual(chain.returncode, 0, chain.stdout + chain.stderr)
        # The token is spent with the signature.
        status, _ = self.api("signatures/signHash", cred["access_token"], {"credentialID": "ci-signer", "hashes": []})
        self.assertEqual(status, 401)

    def test_a_denial_a_wrong_verifier_or_secret_and_a_reused_code_are_refused(self):
        back, _ = self.authorize("service", decision="deny")
        self.assertEqual(back["error"], ["access_denied"])
        back, verifier = self.authorize("service")
        self.assertEqual(self.token(back["code"][0], verifier + "x")[0], 400)
        back, verifier = self.authorize("service")
        self.assertEqual(self.token(back["code"][0], verifier, secret="wrong")[0], 400)
        back, verifier = self.authorize("service")
        self.assertEqual(self.token(back["code"][0], verifier)[0], 200)
        self.assertEqual(self.token(back["code"][0], verifier)[0], 400)

    def test_the_providers_file_is_the_one_the_server_worker_and_stub_share(self):
        overlay = (HERE / "compose.e2e.yml").read_text()
        conf = json.loads((HERE / "signing-providers.json").read_text())["providers"][0]
        self.assertEqual(conf["redirect_uri"], CSC_REDIRECT)
        self.assertIn('"--redirect-uri", "http://localhost:8080/s/rsp"', overlay)
        for k in ("base_uri", "token_endpoint"):
            self.assertTrue(conf[k].startswith("http://127.0.0.1:8091/"), k)
        self.assertTrue(conf["authorization_endpoint"].startswith("http://localhost:8091/"))


XMLSEC = shutil.which("xmlsec1")
ASP_TEMPLATE = (
    '<?xml version="1.0" encoding="UTF-8"?>\n<Esign ver="2.1" sc="Y" ts="2026-11-21T10:00:00" '
    'txn="0193a000-0000-7000-8000-0000000000e1.1" ekycId="" ekycIdType="A" aspId="ASP-CI" AuthMode="1" '
    'responseSigType="pkcs7pdf" responseUrl="http://localhost:8080/rsp/esign/esign-ci/response">'
    '<Docs><InputHash id="1" hashAlgorithm="SHA256" docInfo="Lease">' + "ab" * 32 + "</InputHash></Docs>"
    + st.DSIG_TEMPLATE + "</Esign>"
)


@unittest.skipUnless(XMLSEC or os.environ.get("OPENSEAL_REQUIRE_XMLSEC1") == "1",
                     "xmlsec1 is not installed (CI installs it)")
class EsignProvider(unittest.TestCase):
    """The eSign stub (RSP-02, ADR-047 §4): it verifies the ASP's request with xmlsec1,
    records that it carries no Aadhaar data, and answers with xmlsec1-signed answers whose
    CMS is well formed and signed over the request's hash by the one-time certificate."""

    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory()
        d = pathlib.Path(cls.dir.name)
        make_root(d)
        st.openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(d / "asp.key"))
        st.openssl("req", "-new", "-x509", "-key", str(d / "asp.key"), "-days", "1", "-subj", "/CN=ASP", "-out", str(d / "asp.pem"))
        cls.esp = st.Esign(d, d, d / "pub", d / "asp.pem", None)
        cls.d = d

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def signed_request(self, body: str) -> str:
        tmpl, out = self.d / "req.xml", self.d / "req.signed.xml"
        tmpl.write_text(body)
        subprocess.run(["xmlsec1", "--sign", "--privkey-pem", str(self.d / "asp.key"), "--output", str(out), str(tmpl)],
                       check=True, capture_output=True)
        return out.read_text()

    def test_a_signed_request_verifies_and_carries_no_aadhaar_data(self):
        req = self.esp.check_request(self.signed_request(ASP_TEMPLATE))
        self.assertTrue(req["verified"])
        self.assertTrue(req["aadhaar_free"])
        self.assertEqual(req["hash"], "ab" * 32)
        self.assertEqual(req["txn"], "0193a000-0000-7000-8000-0000000000e1.1")
        tampered = self.signed_request(ASP_TEMPLATE).replace("docInfo=\"Lease\"", "docInfo=\"Lease!\"")
        self.assertFalse(self.esp.check_request(tampered)["verified"])
        with_uid = self.esp.check_request(self.signed_request(ASP_TEMPLATE.replace('ekycId=""', 'ekycId="999988887777"')))
        self.assertFalse(with_uid["aadhaar_free"])

    def verify_answer(self, xml: str) -> bool:
        path = self.d / f"ans-{secrets.token_hex(4)}.xml"
        path.write_text(xml)
        done = subprocess.run(["xmlsec1", "--verify", "--pubkey-cert-pem", str(self.d / "pub" / "esp-response.pem"), str(path)],
                              capture_output=True, check=False)
        return done.returncode == 0

    def test_answers_are_signed_with_a_well_formed_cms_over_the_hash(self):
        req = {"txn": "t.1", "hash": hashlib.sha256(b"prepared").hexdigest()}
        for variant in ("cades", "adobe"):
            xml = self.esp.answer(req, signed=True, variant=variant)
            self.assertTrue(self.verify_answer(xml), variant)
            cms = base64.b64decode(re.search(r"<DocSignature[^>]*>([^<]+)</DocSignature>", xml).group(1))
            printed = st.openssl("cms", "-cmsout", "-print", "-inform", "DER", data=cms).decode()
            self.assertIn("messageDigest", printed)
            self.assertEqual("signingTime" in printed, variant == "adobe")
        failed = self.esp.answer(req, signed=False, err="ESP-944")
        self.assertTrue(self.verify_answer(failed))
        self.assertIn('errCode="ESP-944"', failed)

    def test_hostile_variants_fail_where_they_should(self):
        req = {"txn": "t.1", "hash": "00" * 32}
        self.assertFalse(self.verify_answer(self.esp.answer(req, signed=True, variant="wrong-key")))
        self.assertNotIn("xmldsig#", self.esp.answer(req, signed=True, variant="unsigned"))
        ber = self.esp.answer(req, signed=True, variant="ber")
        cms = base64.b64decode(re.search(r"<DocSignature[^>]*>([^<]+)</DocSignature>", ber).group(1))
        self.assertEqual(cms[:2], b"\x30\x80")


if __name__ == "__main__":
    unittest.main()
