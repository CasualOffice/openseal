#!/usr/bin/env python3
"""CI-only stand-ins for the providers recipient authentication calls (RAUTH-02, docs/65).

    python3 -I tools/e2e/auth_stubs.py sms --issue-from /secrets --tls-name sms-gateway \\
        --listen 0.0.0.0:8443 --read 0.0.0.0:8026
    python3 -I tools/e2e/auth_stubs.py oidc --providers tools/e2e/recipient-idps.json \\
        --listen 0.0.0.0:8090

Never deploy either: they accept any phone number and any email typed into a form. The
Compose test stack layers them on with tools/e2e/compose.e2e.yml, which only CI's
`compose-e2e` job names; neither docker-compose.yml nor deploy/compose.production.yml
mentions them.

- `sms`: the worker's SMS and voice gateway (`OPENSEAL_SMS_GATEWAY_URL`, the
  `messenger::HttpGateway` contract): HTTPS `POST /messages` with
  `{"channel": "sms"|"voice", "to", "text", "id"}` and `Authorization: Bearer` the secret
  in `OPENSEAL_E2E_SMS_SECRET`. Its TLS certificate is issued at start by the development
  root (`--issue-from`, the `secrets` volume's ca.pem and ca.key). What it received is
  read back, as Mailpit's API serves mail, over plain HTTP on `--read`:
  `GET /messages?to=+…` answers `{"messages": [...]}`, newest first.
- `oidc`: an OpenID Connect provider for the first provider in the server's
  `OPENSEAL_RECIPIENT_IDPS_FILE` (`--providers`): `GET /authorize` shows a sign-in form
  asking only for an email, `POST /authorize` sends the browser back with a code,
  `POST /token` checks the client secret, the redirect URI and the PKCE S256 verifier and
  answers an RS256 ID token for that email (`email_verified: true`) with the request's
  nonce, `GET /jwks` publishes the key. The key is drawn at start and signed with by
  OpenSSL (`openssl dgst -sign`), as deploy/devtools's TSA does; nothing here is
  cryptography of its own.
- `hooks` (slice 8, VS-08C): a webhook receiver for the worker's deliveries, over HTTPS
  with a certificate the development root issues at start (`--tls-name`, the name the
  webhook URL uses). Each delivery is recorded with whether its Standard Webhooks
  signature verifies under `OPENSEAL_E2E_WEBHOOK_SECRET` (the secret the worker signs
  with), and answered with the status last set. Read back over plain HTTP on `--read`:
  `GET /deliveries?type=…&envelope=…` answers `{"deliveries": [...]}`, newest first;
  `POST /answer?status=500` makes later deliveries fail, so the spec can redeliver one.

    python3 -I tools/e2e/auth_stubs.py hooks --issue-from /secrets --tls-name hooks.e2e.test \\
        --listen 0.0.0.0:8443 --read 0.0.0.0:8027

Standard library only (and the `openssl` command for keys and signatures). Exits
non-zero and names the problem when it cannot start.
"""

from __future__ import annotations

import argparse
import base64
import collections
import hashlib
import hmac
import html
import json
import os
import secrets
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

# The worker's longest message (messenger::MAX_TEXT) with room to spare, and the most
# messages kept: a test run sends a handful.
MAX_BODY = 4096
MAX_MESSAGES = 500
MAX_FORM = 8192
MAX_CODES = 1000
CODE_SECONDS = 120
TOKEN_SECONDS = 300


def fail(message: str) -> None:
    print(f"auth-stubs: {message}", file=sys.stderr)
    sys.exit(2)


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def openssl(*args: str, data: bytes | None = None) -> bytes:
    """Run `openssl args`, answering its standard output; raises on a failure."""
    done = subprocess.run(["openssl", *args], input=data, capture_output=True, check=False)
    if done.returncode != 0:
        raise RuntimeError(f"openssl {args[0]} failed: {done.stderr.decode(errors='replace').strip()[:200]}")
    return done.stdout


def issue_tls(ca_dir: Path, name: str, out: Path) -> tuple[Path, Path]:
    """A P-256 key and a server certificate for `name` (and 127.0.0.1) issued by the root
    in `ca_dir` (ca.pem, ca.key), written in `out`: answers (chain, key)."""
    key, csr, ext, cert, chain = (out / f"tls.{x}" for x in ("key", "csr", "ext", "pem", "chain.pem"))
    openssl("genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(key))
    openssl("req", "-new", "-key", str(key), "-subj", f"/O=OpenSeal CI/CN={name}", "-out", str(csr))
    ext.write_text("\n".join([
        "basicConstraints=critical,CA:FALSE",
        "keyUsage=critical,digitalSignature",
        "extendedKeyUsage=serverAuth",
        f"subjectAltName=DNS:{name},IP:127.0.0.1",
        "subjectKeyIdentifier=hash",
        "authorityKeyIdentifier=keyid",
    ]) + "\n")
    openssl("x509", "-req", "-in", str(csr), "-CA", str(ca_dir / "ca.pem"), "-CAkey", str(ca_dir / "ca.key"),
            "-sha256", "-days", "2", "-set_serial", "0x" + secrets.token_hex(16), "-extfile", str(ext), "-out", str(cert))
    chain.write_bytes(cert.read_bytes() + (ca_dir / "ca.pem").read_bytes())
    return chain, key


# ---------------------------------------------------------------------------------------
# SMS and voice gateway


class Outbox:
    """The messages received, newest last, at most MAX_MESSAGES."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: collections.deque[dict] = collections.deque(maxlen=MAX_MESSAGES)

    def add(self, message: dict) -> None:
        with self._lock:
            self._items.append(message)

    def find(self, to: str | None) -> list[dict]:
        with self._lock:
            items = list(self._items)
        return [m for m in reversed(items) if to is None or m["to"] == to]


def valid_text(body: object) -> dict | None:
    """The message in a gateway request body, or None when it is not the contract's."""
    if not isinstance(body, dict) or set(body) != {"channel", "to", "text", "id"}:
        return None
    if body["channel"] not in ("sms", "voice"):
        return None
    for k, limit in (("to", 32), ("text", 1024), ("id", 256)):
        if not isinstance(body[k], str) or not body[k] or len(body[k]) > limit:
            return None
    return {"channel": body["channel"], "to": body["to"], "text": body["text"], "id": body["id"]}


class _Handler(BaseHTTPRequestHandler):
    server_version = "openseal-ci-stub"
    sys_version = ""

    def log_message(self, fmt: str, *args: object) -> None:
        # Method and path only: the query of a read or a callback carries numbers and codes.
        sys.stderr.write(f"auth-stubs: {self.command} {urlsplit(self.path).path}\n")

    def answer(self, status: int, body: object | None = None, headers: dict | None = None,
               content_type: str = "application/json") -> None:
        data = b"" if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
        self.send_response(status)
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        if data:
            self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def body(self, limit: int) -> bytes | None:
        """The request body, or None (after answering) when it is missing or too long."""
        try:
            n = int(self.headers.get("Content-Length", ""))
        except ValueError:
            self.answer(411, {"error": "length required"})
            return None
        if n < 0 or n > limit:
            self.answer(413, {"error": "too large"})
            return None
        return self.rfile.read(n)


def gateway_handler(outbox: Outbox, secret: str) -> type[BaseHTTPRequestHandler]:
    """The HTTPS side: the worker's POST /messages."""
    expected = f"Bearer {secret}".encode()

    class Gateway(_Handler):
        def do_POST(self) -> None:  # noqa: N802 (http.server's name)
            if urlsplit(self.path).path != "/messages":
                self.answer(404, {"error": "not found"})
                return
            given = self.headers.get("Authorization", "").encode()
            if not hmac.compare_digest(given, expected):
                self.answer(401, {"error": "unauthorized"})
                return
            raw = self.body(MAX_BODY)
            if raw is None:
                return
            try:
                text = valid_text(json.loads(raw))
            except (ValueError, UnicodeDecodeError):
                text = None
            if text is None:
                self.answer(400, {"error": "not the gateway contract"})
                return
            text["received"] = time.time()
            outbox.add(text)
            self.answer(202, {"accepted": True})

    return Gateway


def reader_handler(outbox: Outbox) -> type[BaseHTTPRequestHandler]:
    """The plain-HTTP side the browser spec reads: GET /messages[?to=…], GET /healthz."""

    class Reader(_Handler):
        def do_GET(self) -> None:  # noqa: N802
            url = urlsplit(self.path)
            if url.path == "/healthz":
                self.answer(200, {"ok": True})
            elif url.path == "/messages":
                to = parse_qs(url.query).get("to", [None])[0]
                self.answer(200, {"messages": outbox.find(to)})
            else:
                self.answer(404, {"error": "not found"})

    return Reader


def sms_servers(listen: tuple[str, int], read: tuple[str, int], chain: Path, key: Path,
                secret: str) -> tuple[ThreadingHTTPServer, ThreadingHTTPServer]:
    """The gateway (TLS on `listen`) and its reader (plain HTTP on `read`), not started."""
    outbox = Outbox()
    gateway = ThreadingHTTPServer(listen, gateway_handler(outbox, secret))
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(str(chain), str(key))
    gateway.socket = tls.wrap_socket(gateway.socket, server_side=True)
    reader = ThreadingHTTPServer(read, reader_handler(outbox))
    return gateway, reader


# ---------------------------------------------------------------------------------------
# OpenID Connect provider


class Signer:
    """An RSA key drawn by OpenSSL at start; signs RS256 through `openssl dgst`."""

    def __init__(self, work: Path) -> None:
        self.key = work / "idp.key"
        openssl("genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(self.key))
        modulus = openssl("rsa", "-in", str(self.key), "-noout", "-modulus").decode().strip()
        n = bytes.fromhex(modulus.split("=", 1)[1])
        self.kid = hashlib.sha256(n).hexdigest()[:16]
        self.jwk = {"kty": "RSA", "use": "sig", "alg": "RS256", "kid": self.kid,
                    "n": b64url(n), "e": b64url((65537).to_bytes(3, "big"))}

    def jwt(self, claims: dict) -> str:
        header = {"alg": "RS256", "typ": "JWT", "kid": self.kid}
        signing = f"{b64url(json.dumps(header).encode())}.{b64url(json.dumps(claims).encode())}"
        sig = openssl("dgst", "-sha256", "-sign", str(self.key), data=signing.encode())
        return f"{signing}.{b64url(sig)}"


class Provider:
    """The first provider of the server's providers file, and the codes it has issued."""

    def __init__(self, providers_file: Path, redirect_uri: str, signer: Signer) -> None:
        try:
            p = json.loads(providers_file.read_text())["providers"][0]
            self.issuer = p["issuer"]
            self.client_id = p["client_id"]
            self.client_secret = p["client_secret"]
        except (OSError, ValueError, KeyError, IndexError, TypeError):
            fail(f"{providers_file}: needs providers[0] with issuer, client_id and client_secret")
        # The server's: the file's, or by default `{OPENSEAL_PUBLIC_URL}/s/oidc` (idp.rs).
        self.redirect_uri = p.get("redirect_uri") or redirect_uri
        self.signer = signer
        self._lock = threading.Lock()
        self._codes: dict[str, dict] = {}

    def check_request(self, q: dict) -> str | None:
        """Why an authorization request is refused, or None."""
        if q.get("response_type") != "code":
            return "response_type must be code"
        if q.get("client_id") != self.client_id:
            return "unknown client_id"
        if q.get("redirect_uri") != self.redirect_uri:
            return "redirect_uri is not the registered one"
        if q.get("code_challenge_method") != "S256" or not q.get("code_challenge"):
            return "PKCE S256 is required"
        if "openid" not in (q.get("scope") or "").split():
            return "scope must include openid"
        if not q.get("state") or not q.get("nonce"):
            return "state and nonce are required"
        return None

    def issue_code(self, q: dict, email: str) -> str:
        code = secrets.token_urlsafe(24)
        now = time.time()
        with self._lock:
            for c in [c for c, v in self._codes.items() if v["expires"] < now]:
                del self._codes[c]
            if len(self._codes) >= MAX_CODES:
                self._codes.pop(next(iter(self._codes)))
            self._codes[code] = {"nonce": q["nonce"], "challenge": q["code_challenge"],
                                 "redirect_uri": q["redirect_uri"], "email": email, "expires": now + CODE_SECONDS,
                                 # The sign-in just happened: OpenSeal sends max_age and checks it (ASVS-22).
                                 "auth_time": int(now)}
        return code

    def redeem(self, form: dict) -> tuple[int, dict]:
        """The token endpoint's answer to `form` (RFC 6749 §4.1.3, RFC 7636 §4.6)."""
        if not (hmac.compare_digest(form.get("client_id", "").encode(), self.client_id.encode())
                and hmac.compare_digest(form.get("client_secret", "").encode(), self.client_secret.encode())):
            return 401, {"error": "invalid_client"}
        if form.get("grant_type") != "authorization_code":
            return 400, {"error": "unsupported_grant_type"}
        with self._lock:
            grant = self._codes.pop(form.get("code", ""), None)
        if grant is None or grant["expires"] < time.time():
            return 400, {"error": "invalid_grant"}
        if form.get("redirect_uri") != grant["redirect_uri"]:
            return 400, {"error": "invalid_grant"}
        challenge = b64url(hashlib.sha256(form.get("code_verifier", "").encode()).digest())
        if not hmac.compare_digest(challenge.encode(), grant["challenge"].encode()):
            return 400, {"error": "invalid_grant"}
        now = int(time.time())
        email = grant["email"]
        claims = {"iss": self.issuer, "aud": self.client_id, "iat": now, "exp": now + TOKEN_SECONDS,
                  "sub": "ci-" + hashlib.sha256(email.lower().encode()).hexdigest()[:24],
                  "auth_time": grant["auth_time"], "nonce": grant["nonce"], "email": email, "email_verified": True}
        return 200, {"access_token": secrets.token_urlsafe(24), "token_type": "Bearer",
                     "expires_in": TOKEN_SECONDS, "id_token": self.signer.jwt(claims)}


SIGN_IN_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sign in: OpenSeal CI identity provider</title>
<style>body{{font:16px system-ui,sans-serif;max-width:28rem;margin:3rem auto;padding:0 1rem;color:#111;background:#fff}}
label,input,button{{display:block;font:inherit}}input{{width:100%;padding:.6rem;margin:.4rem 0 1rem;box-sizing:border-box}}
button{{padding:.7rem 1.4rem;background:#0b57d0;color:#fff;border:0;border-radius:6px}}</style></head>
<body><main><h1>Sign in</h1><p>OpenSeal CI identity provider (a test stand-in; never deployed).</p>
<form method="post" action="/authorize">{hidden}
<label for="email">Email</label><input id="email" name="email" type="email" autocomplete="email" required>
<button type="submit">Sign in</button></form></main></body></html>
"""

REQUEST_KEYS = ("response_type", "client_id", "redirect_uri", "scope", "state", "nonce",
                "code_challenge", "code_challenge_method")


def oidc_handler(provider: Provider) -> type[BaseHTTPRequestHandler]:

    class Oidc(_Handler):
        def do_GET(self) -> None:  # noqa: N802
            url = urlsplit(self.path)
            if url.path == "/healthz":
                self.answer(200, {"ok": True})
            elif url.path == "/jwks":
                self.answer(200, {"keys": [provider.signer.jwk]})
            elif url.path == "/.well-known/openid-configuration":
                base = provider.issuer.rstrip("/")
                self.answer(200, {"issuer": provider.issuer, "authorization_endpoint": f"{base}/authorize",
                                  "token_endpoint": f"{base}/token", "jwks_uri": f"{base}/jwks",
                                  "response_types_supported": ["code"], "id_token_signing_alg_values_supported": ["RS256"],
                                  "code_challenge_methods_supported": ["S256"]})
            elif url.path == "/authorize":
                q = {k: v[0] for k, v in parse_qs(url.query).items()}
                why = provider.check_request(q)
                if why:
                    self.answer(400, why.encode(), content_type="text/plain; charset=utf-8")
                    return
                hidden = "".join(f'<input type="hidden" name="{k}" value="{html.escape(q[k])}">'
                                 for k in REQUEST_KEYS)
                self.answer(200, SIGN_IN_PAGE.format(hidden=hidden).encode(), content_type="text/html; charset=utf-8")
            else:
                self.answer(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            path = urlsplit(self.path).path
            raw = self.body(MAX_FORM)
            if raw is None:
                return
            form = {k: v[0] for k, v in parse_qs(raw.decode("utf-8", "replace")).items()}
            if path == "/authorize":
                why = provider.check_request(form)
                email = form.get("email", "").strip()
                if why or "@" not in email or len(email) > 254:
                    self.answer(400, (why or "an email is required").encode(), content_type="text/plain; charset=utf-8")
                    return
                code = provider.issue_code(form, email)
                to = f"{form['redirect_uri']}?{urlencode({'code': code, 'state': form['state']})}"
                self.answer(303, None, headers={"Location": to})
            elif path == "/token":
                status, body = provider.redeem(form)
                self.answer(status, body)
            else:
                self.answer(404, {"error": "not found"})

    return Oidc


def oidc_server(listen: tuple[str, int], provider: Provider) -> ThreadingHTTPServer:
    return ThreadingHTTPServer(listen, oidc_handler(provider))


# ---------------------------------------------------------------------------------------


# ---------------------------------------------------------------------------------------
# Webhook receiver (slice 8, VS-08C)


def webhook_key(secret: str) -> bytes:
    """A Standard Webhooks secret (`whsec_` and base64) as its key bytes."""
    if not secret.startswith("whsec_"):
        raise ValueError("not a whsec_ secret")
    key = base64.b64decode(secret[len("whsec_"):], validate=True)
    if len(key) < 16:
        raise ValueError("a webhook secret holds at least 16 bytes")
    return key


def webhook_verified(key: bytes, msg_id: str, timestamp: str, body: bytes, signature: str) -> bool:
    """Whether one of `signature`'s space-separated `v1,<base64>` entries is the
    HMAC-SHA256 of `id.timestamp.body` under `key` (the Standard Webhooks scheme the
    worker signs with, docs/40 §4)."""
    signed = msg_id.encode() + b"." + timestamp.encode() + b"." + body
    want = base64.b64encode(hmac.new(key, signed, hashlib.sha256).digest())
    for entry in signature.split(" "):
        version, _, sig = entry.partition(",")
        if version == "v1" and hmac.compare_digest(sig.encode(), want):
            return True
    return False


class Hooks:
    """What the receiver was sent, newest last, and the status it answers with."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: collections.deque[dict] = collections.deque(maxlen=MAX_MESSAGES)
        self.status = 200

    def add(self, item: dict) -> None:
        with self._lock:
            self._items.append(item)

    def find(self, kind: str | None, envelope: str | None) -> list[dict]:
        with self._lock:
            items = list(self._items)
        return [d for d in reversed(items)
                if (kind is None or d["type"] == kind) and (envelope is None or d["envelope_id"] == envelope)]


def receiver_handler(hooks: Hooks, key: bytes) -> type[BaseHTTPRequestHandler]:
    """The HTTPS side: the worker's deliveries, checked and recorded, answered with the
    status the reader last set."""

    class Receiver(_Handler):
        def do_POST(self) -> None:  # noqa: N802
            raw = self.body(65536)
            if raw is None:
                return
            h = self.headers
            msg_id, ts, sig = h.get("webhook-id", ""), h.get("webhook-timestamp", ""), h.get("webhook-signature", "")
            try:
                event = json.loads(raw)
                kind = str(event.get("type", ""))
                data = event.get("data") or {}
                envelope = data.get("envelope_id") if isinstance(data, dict) else None
            except (ValueError, AttributeError):
                kind, envelope = "", None
            hooks.add({"id": msg_id, "timestamp": ts, "type": kind, "envelope_id": envelope,
                       "verified": bool(msg_id and ts and webhook_verified(key, msg_id, ts, raw, sig)),
                       "answered": hooks.status, "received": time.time()})
            self.answer(hooks.status, {"received": True})

    return Receiver


def hooks_reader_handler(hooks: Hooks) -> type[BaseHTTPRequestHandler]:
    """The plain-HTTP side the browser spec reads: GET /deliveries[?type=…&envelope=…],
    POST /answer?status=… (the status later deliveries get), GET /healthz."""

    class Reader(_Handler):
        def do_GET(self) -> None:  # noqa: N802
            url = urlsplit(self.path)
            q = parse_qs(url.query)
            if url.path == "/healthz":
                self.answer(200, {"ok": True})
            elif url.path == "/deliveries":
                self.answer(200, {"deliveries": hooks.find(q.get("type", [None])[0], q.get("envelope", [None])[0])})
            else:
                self.answer(404, {"error": "not found"})

        def do_POST(self) -> None:  # noqa: N802
            url = urlsplit(self.path)
            status = parse_qs(url.query).get("status", [""])[0]
            if url.path != "/answer" or not status.isdigit() or not 200 <= int(status) <= 599:
                self.answer(400, {"error": "POST /answer?status=200..599"})
                return
            hooks.status = int(status)
            self.answer(200, {"status": hooks.status})

    return Reader


def hooks_servers(listen: tuple[str, int], read: tuple[str, int], chain: Path, key_file: Path,
                  secret: str) -> tuple[ThreadingHTTPServer, ThreadingHTTPServer]:
    """The receiver (TLS on `listen`) and its reader (plain HTTP on `read`), not started."""
    hooks = Hooks()
    receiver = ThreadingHTTPServer(listen, receiver_handler(hooks, webhook_key(secret)))
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.minimum_version = ssl.TLSVersion.TLSv1_2
    tls.load_cert_chain(str(chain), str(key_file))
    receiver.socket = tls.wrap_socket(receiver.socket, server_side=True)
    reader = ThreadingHTTPServer(read, hooks_reader_handler(hooks))
    return receiver, reader


# ---------------------------------------------------------------------------------------


def address(s: str) -> tuple[str, int]:
    host, _, port = s.rpartition(":")
    try:
        return host or "0.0.0.0", int(port)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not HOST:PORT: {s}") from None


def serve(*servers: ThreadingHTTPServer) -> None:
    threads = [threading.Thread(target=s.serve_forever, daemon=True) for s in servers]
    for t in threads:
        t.start()
    for t in threads:
        t.join()


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="stub", required=True)
    s = sub.add_parser("sms", help="the SMS and voice gateway")
    s.add_argument("--listen", type=address, default=("0.0.0.0", 8443))
    s.add_argument("--read", type=address, default=("0.0.0.0", 8026))
    s.add_argument("--issue-from", type=Path, required=True, help="directory holding ca.pem and ca.key")
    s.add_argument("--tls-name", default="sms-gateway")
    o = sub.add_parser("oidc", help="the OpenID Connect provider")
    o.add_argument("--listen", type=address, default=("0.0.0.0", 8090))
    o.add_argument("--providers", type=Path, required=True)
    o.add_argument("--redirect-uri", required=True,
                   help="the server's redirect URI when the file names none: {OPENSEAL_PUBLIC_URL}/s/oidc")
    w = sub.add_parser("hooks", help="a webhook receiver (slice 8)")
    w.add_argument("--listen", type=address, default=("0.0.0.0", 8443))
    w.add_argument("--read", type=address, default=("0.0.0.0", 8027))
    w.add_argument("--issue-from", type=Path, required=True, help="directory holding ca.pem and ca.key")
    w.add_argument("--tls-name", default="hooks.e2e.test")
    args = ap.parse_args(argv)

    work = Path(tempfile.mkdtemp(prefix="auth-stubs-"))
    os.chmod(work, 0o700)
    try:
        if args.stub == "sms":
            secret = os.environ.get("OPENSEAL_E2E_SMS_SECRET", "")
            if not secret:
                fail("OPENSEAL_E2E_SMS_SECRET is not set")
            chain, key = issue_tls(args.issue_from, args.tls_name, work)
            servers = sms_servers(args.listen, args.read, chain, key, secret)
        elif args.stub == "hooks":
            secret = os.environ.get("OPENSEAL_E2E_WEBHOOK_SECRET", "")
            try:
                webhook_key(secret)
            except ValueError as e:
                fail(f"OPENSEAL_E2E_WEBHOOK_SECRET: {e}")
            chain, key = issue_tls(args.issue_from, args.tls_name, work)
            servers = hooks_servers(args.listen, args.read, chain, key, secret)
        else:
            servers = (oidc_server(args.listen, Provider(args.providers, args.redirect_uri, Signer(work))),)
    except (OSError, RuntimeError) as e:
        fail(f"cannot start: {e}")
    print(f"auth-stubs: {args.stub} ready", file=sys.stderr)
    serve(*servers)


if __name__ == "__main__":
    main()
