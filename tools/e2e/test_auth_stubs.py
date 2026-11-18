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
import pathlib
import secrets
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


if __name__ == "__main__":
    unittest.main()
