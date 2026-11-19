"""The OpenSeal API client for Python (slice 8, `VS-08E`, docs/40 §7).

One method per operation of api/openapi.yaml, built from the generated table in
`_operations.py` (tools/build-sdks.py). Standard library only (urllib, hmac, hashlib).

    from openseal import OpenSeal
    os_ = OpenSeal("https://sign.example.com", api_key=os.environ["OPENSEAL_API_KEY"])
    env = os_.create_envelope(body={"subject": "NDA", "status": "sent", ...})

Methods are the operationIds in snake case (`createEnvelope` -> `create_envelope`); the
camel-case name works too. Errors are `OpenSealError` with the problem's stable `code`
(docs/20), `status`, `request_id` and field `errors`.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Optional

from ._operations import OPERATIONS

JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"


class OpenSealError(Exception):
    """A refusal: RFC 9457 problem details, or an OAuth token error (its `CS-*` code in
    `error_description`), or a webhook that does not verify (`webhook_signature`)."""

    def __init__(self, status: int = 0, code: str = "", title: str = "", detail: str = "",
                 request_id: str | None = None, errors: list | None = None, oauth_error: str | None = None):
        super().__init__(f"{code or oauth_error or 'OpenSeal error'}{': ' + title if title else ''}")
        self.status = status
        self.code = code
        self.title = title
        self.detail = detail
        self.request_id = request_id
        self.errors = errors or []
        self.oauth_error = oauth_error


def snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


class Response:
    """What a transport answers: status, headers (lower-case names) and body bytes."""

    def __init__(self, status: int, headers: dict[str, str], body: bytes):
        self.status = status
        self.headers = {k.lower(): v for k, v in headers.items()}
        self.body = body


Transport = Callable[[str, str, "dict[str, str]", "Optional[bytes]"], Response]


def urllib_transport(method: str, url: str, headers: dict[str, str], body: bytes | None) -> Response:
    """The default transport: urllib, no redirects followed, 30 s timeout."""

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):  # noqa: ANN002, ANN003
            return None

    opener = urllib.request.build_opener(NoRedirect)
    req = urllib.request.Request(url, data=body, method=method, headers=headers)
    try:
        with opener.open(req, timeout=30) as r:
            return Response(r.status, dict(r.headers), r.read())
    except urllib.error.HTTPError as e:
        return Response(e.code, dict(e.headers), e.read())


class OpenSeal:
    """The client. `api_key` (`osk_…`) or `access_token` authenticates every call;
    `transport` may be supplied (tests, proxies)."""

    def __init__(self, base_url: str, api_key: str | None = None, access_token: str | None = None,
                 transport: Transport = urllib_transport, user_agent: str | None = None):
        if not base_url:
            raise ValueError("base_url is required")
        self.base_url = base_url.rstrip("/")
        self.credential = api_key or access_token
        self.transport = transport
        self.user_agent = user_agent

    def __getattr__(self, name: str) -> Callable[..., Any]:
        for op_id, op in OPERATIONS.items():
            # `token` (the token endpoint) is the form-encoded `token()` below.
            if op_id != "token" and name in (op_id, snake(op_id)):
                return lambda **params: self.call(op, **params)
        raise AttributeError(name)

    def call(self, op: dict, body: Any = None, idempotency_key: str | None = None,
             if_match: str | None = None, **params: Any) -> Any:
        """Call one operation of the table: path parameters substituted (encoded), the
        others the query, `body` the JSON body. Answers the JSON, None for 204, or the
        bytes of a file."""
        path = op["path"]
        for p in op["path_params"]:
            if params.get(p) in (None, ""):
                raise ValueError(f"{p} is required")
            path = path.replace("{" + p + "}", urllib.parse.quote(str(params[p]), safe=""))
        query = [(q, _str(params[q])) for q in op["query"] if params.get(q) is not None]
        url = f"{self.base_url}{path}" + (f"?{urllib.parse.urlencode(query)}" if query else "")
        headers = {"accept": "application/json"}
        if self.credential:
            headers["authorization"] = f"Bearer {self.credential}"
        if self.user_agent:
            headers["user-agent"] = self.user_agent
        if idempotency_key:
            headers["idempotency-key"] = idempotency_key
        if if_match:
            headers["if-match"] = if_match
        data = None
        if op["body"] and body is not None:
            headers["content-type"] = "application/json"
            data = json.dumps(body).encode()
        elif op["body_required"]:
            raise ValueError("body is required")
        return _answer(self.transport(op["method"], url, headers, data))

    # OAuth 2.1 (docs/40 §2) ---------------------------------------------------------

    def authorization_url(self, client_id: str, redirect_uri: str, scope: str | list[str],
                          state: str | None = None) -> tuple[str, str, str]:
        """The URL to send a member's browser to, with a fresh PKCE verifier and state to
        keep until the redirect returns: `(url, verifier, state)`."""
        verifier = _b64url(secrets.token_bytes(48))
        challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
        state = state or _b64url(secrets.token_bytes(16))
        q = urllib.parse.urlencode({
            "response_type": "code", "client_id": client_id, "redirect_uri": redirect_uri,
            "scope": " ".join(scope) if isinstance(scope, list) else scope, "state": state,
            "code_challenge": challenge, "code_challenge_method": "S256",
        })
        return f"{self.base_url}/api/v1/oauth/authorize?{q}", verifier, state

    def token(self, client_id: str | None = None, client_secret: str | None = None, **form: str) -> dict:
        """The token endpoint, form-encoded: `grant_type="authorization_code"` with
        `code`, `redirect_uri`, `code_verifier`; `"refresh_token"`; `"client_credentials"`;
        or `assertion=` alone for the JWT bearer grant. The access token is used for
        later calls of this client."""
        headers = {"content-type": "application/x-www-form-urlencoded", "accept": "application/json"}
        if client_id and client_secret:
            headers["authorization"] = "Basic " + base64.b64encode(f"{client_id}:{client_secret}".encode()).decode()
        if "assertion" in form and "grant_type" not in form:
            form["grant_type"] = JWT_BEARER
        t = _answer(self.transport("POST", f"{self.base_url}/api/v1/oauth/token", headers,
                                   urllib.parse.urlencode(form).encode()))
        if isinstance(t, dict) and t.get("access_token"):
            self.credential = t["access_token"]
        return t


def _str(v: Any) -> str:
    return ("true" if v else "false") if isinstance(v, bool) else str(v)


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _answer(r: Response) -> Any:
    if r.status == 204:
        return None
    ctype = r.headers.get("content-type", "")
    if 200 <= r.status < 300:
        return json.loads(r.body) if "json" in ctype else r.body
    try:
        p = json.loads(r.body or b"{}")
    except ValueError:
        p = {}
    if not isinstance(p, dict):
        p = {}
    raise OpenSealError(status=r.status, code=p.get("code") or p.get("error_description") or "",
                        title=p.get("title", ""), detail=p.get("detail", ""), request_id=p.get("request_id"),
                        errors=p.get("errors"), oauth_error=p.get("error"))


def verify_webhook(secret: str, headers: dict[str, str], body: bytes | str, tolerance_seconds: int = 300,
                   now: float | None = None) -> dict:
    """Verify a webhook delivery (docs/40 §4, the Standard Webhooks scheme) and answer the
    event. `secret`: the `whsec_…` value your operator gave you; `headers`: the request's;
    `body`: its raw bytes, exactly as received. Raises `OpenSealError`
    (`webhook_signature`) when no signature matches or the timestamp is more than
    `tolerance_seconds` from now."""
    h = {k.lower(): v for k, v in headers.items()}
    msg_id, ts, sig = h.get("webhook-id"), h.get("webhook-timestamp"), h.get("webhook-signature")

    def refuse(detail: str) -> OpenSealError:
        return OpenSealError(code="webhook_signature", detail=detail)

    if not (msg_id and ts and sig):
        raise refuse("missing headers")
    if not ts.isdigit() or abs((time.time() if now is None else now) - int(ts)) > tolerance_seconds:
        raise refuse("timestamp outside the tolerance")
    if not secret.startswith("whsec_"):
        raise refuse("not a whsec_ secret")
    raw = body.encode() if isinstance(body, str) else bytes(body)
    want = base64.b64encode(hmac.new(base64.b64decode(secret[6:]), f"{msg_id}.{ts}.".encode() + raw,
                                     hashlib.sha256).digest())
    for entry in sig.split(" "):
        version, _, value = entry.partition(",")
        if version == "v1" and hmac.compare_digest(value.encode(), want):
            return json.loads(raw)
    raise refuse("no signature matches")
