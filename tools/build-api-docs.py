#!/usr/bin/env python3
"""Render api/openapi.yaml, the API contract, into the website's API reference (SITE-01,
SITE-12): an overview page and one page per resource, laid out as developer references
are (Stripe, GitHub, Twilio): a navigation tree of resources and operations on the left,
each operation in the middle (what it does, who may call it, its parameters and its
request body as nested attribute lists), and beside it the request in curl, TypeScript
(sdk/typescript) and Python (sdk/python), the response, and the errors it can answer.

    python3 tools/build-api-docs.py           # write site/docs/api*.html
    python3 tools/build-api-docs.py --check   # fail, naming the file, if one is stale

Pages, relative to site/docs/:

- api.html: the overview (site/_src/api/overview.html), with the scopes (read from the
  server's action catalogue, server/casual-sign-server/src/authz.rs), the error codes
  (docs/20) and the resource index generated into it;
- api-<group>.html: one per resource group (GROUPS below), every operation of it;
- api-objects.html: every schema of components/schemas, which type links point to;
- openapi.yaml: the contract itself, for download.

Examples are generated from the schemas, or written in tools/api_examples.py, and each
is validated against its schema here, so the build fails (naming the operation and the
JSON pointer) before an example can drift from the contract; tools/test_build_api_docs.py
runs the same check as a test. Static HTML that reads without JavaScript; site.js only
adds the language switch, copy buttons and the phone drawer. Needs PyYAML; fails
non-zero, saying so, without it. tools/build-site.py runs this as part of the site build.
"""

from __future__ import annotations

import html
import json
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import api_examples as ax  # noqa: E402
import sitelib  # noqa: E402

ROOT = sitelib.ROOT
SPEC_PATH = ROOT / "api/openapi.yaml"
OVERVIEW = sitelib.SRC / "api/overview.html"
METHODS = ("get", "post", "put", "patch", "delete")
TABIDX = ' tabindex="-1"'
CUR = ' aria-current="page"'
BASE = "https://sign.example.com"

# slug -> (title, sidebar section, introduction). Order is the navigation's.
GROUPS = {
    "envelopes": ("Envelopes", "Core resources",
                  "An envelope is one agreement: its documents, the recipients who act on them in routing order, and "
                  "the fields each fills. Create a draft or create and send in one call, then follow it to "
                  "<code>completed</code>, when every document is sealed. Envelopes carry an <code>ETag</code>; "
                  "changing a draft needs <code>If-Match</code>."),
    "recipients": ("Recipients", "Core resources",
                   "The people (and roles) an envelope routes to: signers, approvers, viewers, copies and the other "
                   "recipient types, each with a routing order and the authentication they must pass."),
    "fields": ("Fields", "Core resources",
               "What each recipient fills: signatures, initials, dates, text, check boxes and the other field types, "
               "placed by page coordinates or by anchor text. Values are read back as form data."),
    "documents": ("Documents", "Core resources",
                  "The PDFs of an envelope: upload, read in any version (original, normalized, sealed), the combined "
                  "PDF, signer attachments, and the optional document analysis that suggests fields."),
    "evidence": ("Audit and evidence", "Core resources",
                 "The envelope's hash-chained audit trail, the certificate of completion, and the anchor proof that "
                 "ties the trail's head to a time-stamped daily anchor. Each can be checked offline."),
    "templates": ("Templates", "Core resources",
                  "Reusable documents with roles and fields. Use one or several to create an envelope, share them with "
                  "members, and keep them in folders."),
    "bulk-sends": ("Bulk send", "Core resources",
                   "One template sent to a list of people, one envelope each: check the list, then send it in batches."),
    "folders": ("Folders", "Core resources", "Each member's own folders for envelopes and templates."),
    "contacts": ("Contacts", "Core resources", "People the caller has sent to, for recipient suggestions."),
    "conversions": ("Conversions", "Core resources",
                    "A Word document converted to PDF and admitted, for a preview before it is uploaded; nothing is "
                    "stored. An upload of a Word document converts it the same way."),
    "reports": ("Reports", "Reporting",
                "The envelope, recipient and usage reports of a workspace over a window, as JSON or CSV."),
    "insights": ("Insights", "Reporting",
                 "Aggregate figures for a window: counts by outcome, time to complete, activity by day and top senders."),
    "webhooks": ("Webhooks", "Integrations",
                 "Subscriptions that receive signed event notifications (the Standard Webhooks scheme), their delivery "
                 "log, test events and redelivery. See <a href=\"webhooks.html\">Webhooks</a> for verifying them."),
    "api-clients": ("API clients", "Integrations",
                    "Personal API keys, OAuth apps and JWT integrations of a workspace. A key or secret is shown once, "
                    "when it is created."),
    "oauth": ("OAuth", "Integrations",
              "The OAuth 2.1 authorization server: the token endpoint (client credentials, authorization code with "
              "PKCE, refresh token, JWT bearer grant), consent, and discovery metadata and keys."),
    "users": ("Users", "Administration", "Members of a workspace: invite, change, disable, remove and erase, and the "
                                         "caller's own profile and data export."),
    "groups": ("Groups", "Administration", "Groups of members, used for template sharing and administrative scope."),
    "permission-profiles": ("Permission profiles", "Administration",
                            "What members may do: the built-in profiles and custom ones, as actions of the catalogue."),
    "account": ("Account settings", "Administration", "The workspace's settings: sending, signing, security, "
                                                     "branding defaults and document analysis."),
    "signing-providers": ("Signing providers", "Administration",
                          "The remote signing providers the operator offers the workspace (RSP-01): which are "
                          "enabled, and their options."),
    "ersd": ("Electronic disclosure", "Administration",
             "Versions of the electronic records and signature disclosure recipients consent to."),
    "retention": ("Retention and legal hold", "Administration",
                  "Retention rules that purge ended envelopes, their preview, legal holds and purging one envelope."),
    "admin-events": ("Admin audit log", "Administration", "The workspace's log of administrative changes, as JSON or CSV."),
    "organizations": ("Organizations", "Administration",
                      "The organization above the workspaces: its settings, workspaces, administrators and audit log."),
    "auth": ("Sessions and sign-in", "Administration",
             "Staff sign-in for the web app: sessions, second factors, passkeys and workspace switching. Integrations "
             "authenticate with API keys or OAuth instead."),
    "ceremony": ("Signing ceremony", "Not public API",
                 "The endpoints behind a recipient's signing link (<code>/s/{token}</code>), used by OpenSeal's own "
                 "signing page. They are documented for completeness and security review; they are <strong>not public "
                 "API</strong> and may change without notice. Integrations embed signing with "
                 "<a href=\"api-envelopes.html#op-createsigningview\">Create signing view</a> instead."),
}

ACRONYMS = {"Otp": "OTP", "Sso": "SSO", "Mfa": "MFA", "Totp": "TOTP", "Ersd": "ERSD", "Api": "API", "Jwks": "JWKS",
            "Oauth": "OAuth", "Ml": "ML", "Org": "organization", "Me": "me", "Csv": "CSV"}


def group_of(path: str) -> str:
    # The embedded views' own page and session (VS-09) are the ceremony's kind: not public API.
    if path.startswith("/s/") or path.startswith("/e/"):
        return "ceremony"
    if path.startswith("/.well-known/") or path.startswith("/api/v1/oauth"):
        return "oauth"
    rest = path.removeprefix("/api/v1/")
    seg = rest.split("/")[0]
    if seg == "envelopes":
        m = re.match(r"envelopes/\{id\}/([a-z-]+)", rest)
        sub = m.group(1) if m else ""
        if sub == "recipients":
            return "recipients"
        if sub in ("fields", "form-data"):
            return "fields"
        if sub in ("documents", "attachments", "suggestions"):
            return "documents"
        if sub in ("audit", "anchor-proof", "certificate", "evidence-package"):
            return "evidence"
        if sub in ("legal-hold", "purge"):
            return "retention"
        return "envelopes"
    return {"auth": "auth", "accounts": "account", "account": "account", "ersd-versions": "ersd",
            "admin-events": "admin-events", "organizations": "organizations", "users": "users",
            "retention": "retention", "api-clients": "api-clients", "contacts": "contacts", "templates": "templates",
            "folders": "folders", "bulk-sends": "bulk-sends", "groups": "groups",
            "permission-profiles": "permission-profiles", "webhooks": "webhooks", "conversions": "conversions",
            "signing-providers": "signing-providers",
            "reports": "reports", "insights": "insights"}.get(seg, "")


def esc(s) -> str:
    return html.escape(str(s), quote=True)


TRACKER_REF = re.compile(r"\s*\((?:(?:[A-Z][A-Z0-9]*-\d+[A-Z]?|ADR-\d+|docs/\d+[^,;)]*|SEC-[A-Z0-9-]+)(?:,\s*|;\s*)?)+\)")


TRACKER_LEAD = re.compile(r"^(?:[A-Z][A-Z0-9]*-\d+[A-Z]?(?:,\s*)?)+:\s*")
TRACKER_TAIL = re.compile(r"[,;]\s*`?(?:[A-Z][A-Z0-9]*-\d+[A-Z]?)`?(?=\))")


def clean(text: str) -> str:
    """Spec prose for readers: drop tracker ids (parenthesised, leading "VS-04E: ", or
    trailing inside parentheses), keep the rest."""
    out = TRACKER_REF.sub("", text or "").strip()
    out = TRACKER_TAIL.sub("", TRACKER_LEAD.sub("", out))
    return out[:1].upper() + out[1:] if out[:1].islower() and TRACKER_LEAD.match((text or "").strip()) else out


def inline(text: str) -> str:
    """Escape, then `code`, and docs/NN references to the repository."""
    out = esc(clean(text))
    out = re.sub(r"`([^`]+)`", r"<code>\1</code>", out)
    out = re.sub(r"\bdocs/(\d+)", lambda m: f'<a href="{sitelib.REPO}/tree/main/docs">docs/{m.group(1)}</a>', out)
    return out


TITLES = {"jwks": "JSON Web Key Set", "oauthMetadata": "Authorization server metadata", "token": "Token endpoint",
          "authProviders": "List sign-in providers", "login": "Sign in", "logout": "Sign out",
          "getCombined": "Get combined PDF", "getAudit": "Get audit trail", "exportMe": "Export my data",
          "eraseMe": "Erase my account", "getMe": "Get my profile", "patchMe": "Update my profile",
          "hostInPersonSigner": "Host an in-person signer", "authorizeRedirect": "Authorization endpoint",
          "authorize": "Answer a consent request", "authorizeRequest": "Check an authorization request"}


def title_of(op_id: str) -> str:
    if op_id in TITLES:
        return TITLES[op_id]
    words = re.findall(r"[A-Z]?[a-z0-9]+|[A-Z]+(?![a-z])", op_id)
    words = [ACRONYMS.get(w.capitalize(), w) for w in words]
    if words and words[0] == "patch":
        words[0] = "update"
    t = " ".join(words)
    t = t[0].upper() + t[1:].lower() if t else op_id
    for w in ACRONYMS.values():
        t = re.sub(rf"\b{re.escape(w.lower())}\b", w, t) if w not in ("organization", "me") else t
    return t


def anchor(op_id: str) -> str:
    return f"op-{op_id.lower()}"


# ---- Reading the repository's own sources ------------------------------------------------------

def scope_table() -> list[tuple[str, str, str]]:
    """(action, OAuth scope or "", description) from the server's action catalogue."""
    text = (ROOT / "server/casual-sign-server/src/authz.rs").read_text(encoding="utf8")
    body = text.split("actions! {", 1)[1].split("\n}", 1)[0]
    out = []
    doc: list[str] = []
    for line in body.splitlines():
        line = line.strip()
        if line.startswith("///"):
            doc.append(line[3:].strip())
            continue
        m = re.match(r'\w+ = "([a-z_.]+)", (?:Some\("([a-z:]+)"\)|None), (?:true|false);', line)
        if m:
            out.append((m.group(1), m.group(2) or "", " ".join(doc)))
        doc = []
    if len(out) < 10:
        raise SystemExit("build-api-docs: could not read the action catalogue from authz.rs")
    return out


def error_codes(prefixes: tuple[str, ...]) -> list[tuple[str, str]]:
    """(code, meaning) rows of docs/20 whose code starts with one of `prefixes`."""
    rows = []
    for line in (ROOT / "docs/20-ERROR-CODE-REGISTRY.md").read_text(encoding="utf8").splitlines():
        m = re.match(r"\| (CS-[A-Z]+-\d{4}) \| (.*) \|$", line)
        if m and m.group(1).startswith(prefixes):
            rows.append((m.group(1), m.group(2)))
    return rows


def api_limits() -> list[tuple[str, str, str]]:
    """The API section of docs/21: (limit, default, code)."""
    text = (ROOT / "docs/21-PARSER-LIMITS.md").read_text(encoding="utf8")
    part = text.split("## API (built", 1)[1].split("\n## ", 1)[0]
    rows = []
    for line in part.splitlines():
        cells = [c.strip() for c in line.strip().strip("|").split(" | ")]
        if line.startswith("| ") and len(cells) >= 3 and not set(cells[0]) <= set("-: ") and cells[0] != "Limit":
            rows.append((cells[0], cells[1], cells[2]))
    return rows


def limits_for(method: str, path: str, rows: list[tuple[str, str, str]]) -> list[tuple[str, str, str]]:
    """docs/21 rows that name this operation (`POST /bulk-sends`, `PUT /templates/{id}/shares`)."""
    norm = re.sub(r"\{[^}]+\}", "{}", path.removeprefix("/api/v1"))
    out = []
    for row in rows:
        for m, p in re.findall(r"\b(GET|POST|PUT|PATCH|DELETE) (/[^\s`,)]+)", row[0]):
            p = re.sub(r"\{[^}]+\}", "{}", p.replace("…", "").rstrip("."))
            if m.lower() == method and (p == norm or (p.startswith("/") and norm.endswith(p) and len(p) > 8)):
                out.append(row)
                break
    return out


def md_cell(text: str) -> str:
    """A docs/20 or docs/21 cell: escape, `code`."""
    return re.sub(r"`([^`]+)`", r"<code>\1</code>", esc(text))


# ---- Schema rendering ------------------------------------------------------------------------------

def type_label(spec: dict, schema: dict | None) -> str:
    if not schema:
        return "any"
    if "$ref" in schema:
        n = ax.ref_name(schema["$ref"])
        target = spec["components"]["schemas"][n]
        if "enum" in target or ax._types(target) not in ([], ["object"]):
            return type_label(spec, target)
        return f'<a href="api-objects.html#schema-{n.lower()}">{esc(n)}</a>'
    for key in ("oneOf", "anyOf"):
        if key in schema:
            return " or ".join(type_label(spec, s) for s in schema[key])
    if "allOf" in schema:
        return " and ".join(type_label(spec, s) for s in schema["allOf"])
    types = ax._types(schema) or (["string"] if "enum" in schema else ["object"])
    parts = []
    for t in types:
        if t == "array":
            parts.append(f"array of {type_label(spec, schema.get('items', {}))}")
        elif t == "null":
            parts.append("null")
        else:
            parts.append(esc(t))
    return " or ".join(parts)


def constraints(spec: dict, schema: dict) -> str:
    s = ax.resolve(spec, schema) if "$ref" in schema else schema
    if "allOf" in s and len(s["allOf"]) == 1:
        s = {**ax.resolve(spec, s["allOf"][0]), **{k: v for k, v in s.items() if k != "allOf"}}
    bits = []
    if "enum" in s:
        bits.append("One of " + ", ".join(f"<code>{esc(json.dumps(v) if not isinstance(v, str) else v)}</code>" for v in s["enum"]))
    if "const" in s:
        bits.append(f"Always <code>{esc(s['const'])}</code>")
    if s.get("format") and s["format"] not in ("int64", "int32"):
        bits.append({"date-time": "RFC 3339 time", "uri": "URL", "email": "email address"}.get(s["format"], esc(s["format"])))
    for k, label in (("minLength", "at least {} characters"), ("maxLength", "at most {} characters"),
                     ("minimum", "minimum {}"), ("maximum", "maximum {}"), ("minItems", "at least {} items"),
                     ("maxItems", "at most {} items"), ("pattern", "matches <code>{}</code>")):
        if k in s:
            bits.append(label.format(esc(s[k])))
    if "default" in s:
        bits.append(f"Default <code>{esc(json.dumps(s['default']) if not isinstance(s['default'], str) else s['default'])}</code>")
    return " · ".join(bits)


def children_of(spec: dict, schema: dict | None) -> tuple[dict, set]:
    """Properties and required names of an object, or of an array's object items."""
    s = ax.resolve(spec, schema or {})
    if "allOf" in s:
        props, req = {}, set()
        for part in s["allOf"]:
            p, r = children_of(spec, part)
            props.update(p)
            req |= r
        return props, req
    if ax._types(s)[:1] == ["array"] or s.get("type") == ["array", "null"]:
        return children_of(spec, s.get("items"))
    if isinstance(s.get("type"), list) and "array" in s["type"]:
        return children_of(spec, s.get("items"))
    return s.get("properties") or {}, set(s.get("required", []))


def attr_list(spec: dict, props: dict, required: set, prefix: str, depth: int = 0, stack: tuple = ()) -> str:
    """Attributes as a nested list, each with an anchor (`prefix-name`)."""
    items = []
    for name, sch in props.items():
        sch = sch or {}
        rs = ax.resolve(spec, sch)
        aid = f"{prefix}-{re.sub(r'[^a-z0-9_]+', '-', name.lower())}"
        desc = sch.get("description") or rs.get("description") or ""
        req = '<span class="param__req">Required</span>' if name in required else ""
        ro = '<span class="param__flag">Read only</span>' if rs.get("readOnly") or sch.get("readOnly") else ""
        meta = constraints(spec, sch)
        sub = ""
        ref = ax.ref_name(sch["$ref"]) if "$ref" in sch else (ax.ref_name(sch["items"]["$ref"]) if isinstance(sch.get("items"), dict) and "$ref" in sch["items"] else "")
        kids, kreq = children_of(spec, sch)
        if kids and depth < 4 and (not ref or ref not in stack):
            sub = (f'<details class="param__kids"><summary>Child attributes of <code>{esc(name)}</code></summary>'
                   f'<ul class="params">{attr_list(spec, kids, kreq, aid, depth + 1, stack + ((ref,) if ref else ()))}</ul></details>')
        items.append(
            f'<li class="param" id="{aid}"><div class="param__head"><a class="param__name" href="#{aid}"><code>{esc(name)}</code></a>'
            f'<span class="param__type">{type_label(spec, sch)}</span>{req}{ro}</div>'
            + (f'<p class="param__desc">{inline(desc)}</p>' if desc else "")
            + (f'<p class="param__meta">{meta}</p>' if meta else "") + sub + "</li>")
    return "".join(items)


# ---- Code samples ----------------------------------------------------------------------------------

def sample_param(spec: dict, path: str, p: dict) -> str:
    """An example value of a parameter. A path id is the id of the resource the segment
    before it names (`/envelopes/{id}` -> the envelope's), the same id the response
    examples use for that resource."""
    n = p["name"]
    if p.get("in") == "path":
        if n == "sha256":
            return ax.NAMES["sha256"]
        if n == "token":
            return "tok_example"
        m = re.search(r"/([a-z-]+)/\{" + re.escape(n) + r"\}", path)
        seg = (m.group(1) if m else n).replace("-", "_")
        ent = {"me": "user", "admins": "user", "deliveries": "delivery", "bulk_sends": "bulk", "api_clients": "client",
               "permission_profiles": "profile", "consents": "consent", "passkeys": "passkey"}.get(seg, seg.rstrip("s"))
        return ax.fake_id(ent)
    v = ax.example(spec, p.get("schema") or {"type": "string"}, n)
    return str(v).lower() if isinstance(v, bool) else str(v)


def js_value(v) -> str:
    """A JavaScript literal: a string holding a double quote goes in single quotes."""
    if isinstance(v, str) and '"' in v and "'" not in v:
        return "'" + v + "'"
    return json.dumps(v)


class Op:
    """One operation, with everything the page shows of it."""

    def __init__(self, spec: dict, path: str, method: str, op: dict, shared: list):
        self.spec, self.path, self.method, self.raw = spec, path, method, op
        self.id = op["operationId"]
        self.group = group_of(path)
        self.title = title_of(self.id)
        self.params = []
        for p in shared + op.get("parameters", []):
            if "$ref" in p:
                p = spec["components"]["parameters"][ax.ref_name(p["$ref"])]
            self.params.append(p)
        self.public = op.get("security") == [] or op.get("x-permission") == "public"
        self.body = op.get("requestBody")
        self.body_schema = None
        self.body_type = ""
        if self.body:
            self.body_type, content = next(iter(self.body["content"].items()))
            self.body_schema = content.get("schema")
        self.ceremony = self.group == "ceremony"

    # Examples, validated (a failure stops the build).
    def request_example(self):
        if not self.body_schema or "json" not in self.body_type:
            return None
        value = ax.REQUEST_OVERRIDES.get(self.id)
        if value is None:
            value = ax.example(self.spec, self.body_schema, full=False)
        errs = ax.validate(self.spec, self.body_schema, value)
        if errs:
            raise SystemExit(f"build-api-docs: request example of {self.id} does not fit its schema: " + "; ".join(errs[:5]))
        return value

    def success(self):
        for code, r in self.raw.get("responses", {}).items():
            if code.startswith("2") or code.startswith("3"):
                return code, r
        return None, None

    def response_example(self):
        code, r = self.success()
        if r is None:
            return None, None, None
        content = r.get("content") or {}
        if not content:
            return code, None, None
        ctype, c = next(iter(content.items()))
        if "json" not in ctype:
            return code, ctype, None
        value = ax.example(self.spec, c.get("schema"))
        errs = ax.validate(self.spec, c.get("schema"), value)
        if errs:
            raise SystemExit(f"build-api-docs: response example of {self.id} does not fit its schema: " + "; ".join(errs[:5]))
        return code, ctype, value

    def url_and_args(self):
        path, query, args = self.path, [], []
        for p in self.params:
            if p.get("in") == "path":
                v = sample_param(self.spec, self.path, p)
                path = path.replace("{" + p["name"] + "}", v)
                args.append((p["name"], v))
        for p in self.params:
            if p.get("in") == "query" and (p.get("required") or p["name"] == "limit"):
                v = sample_param(self.spec, self.path, p) if p["name"] != "limit" else "20"
                query.append((p["name"], v))
                args.append((p["name"], int(v) if v.isdigit() else v))
        qs = "?" + "&".join(f"{k}={v}" for k, v in query) if query else ""
        return path + qs, args

    def headers(self):
        h = []
        names = {p["name"] for p in self.params if p.get("in") == "header"}
        if "Idempotency-Key" in names:
            h.append(("Idempotency-Key", "order-1042", "idempotencyKey", "idempotency_key"))
        if "If-Match" in names:
            h.append(("If-Match", '"v3"', "ifMatch", "if_match"))
        return h

    def curl(self) -> str:
        url, _ = self.url_and_args()
        lines = [f"curl{' -X ' + self.method.upper() if self.method != 'get' else ''} {BASE}{url}"]
        if self.id == "token":
            return (f"curl -X POST {BASE}/api/v1/oauth/token \\\n  -u \"$CLIENT_ID:$CLIENT_SECRET\" \\\n"
                    "  -d grant_type=client_credentials \\\n  -d scope=\"envelopes:read envelopes:write\"")
        if not self.public:
            lines.append('-H "Authorization: Bearer $OPENSEAL_API_KEY"')
        for name, value, _, _ in self.headers():
            lines.append(f"-H '{name}: {value}'")
        body = self.request_example()
        if body is not None:
            lines.append('-H "Content-Type: application/json"')
            lines.append("-d '" + json.dumps(body, indent=2, ensure_ascii=False).replace("'", "'\\''") + "'")
        elif self.body_type == "application/pdf":
            lines += ['-H "Content-Type: application/pdf"', "--data-binary @contract.pdf"]
        _, ctype, _ = self.response_example()
        if ctype and "json" not in ctype:
            ext = {"application/pdf": "pdf", "text/csv": "csv", "image/png": "png", "image/jpeg": "jpg", "text/html": "html"}.get(ctype, "bin")
            lines.append(f"-o download.{ext}")
        return " \\\n  ".join(lines)

    def typescript(self) -> str:
        _, args = self.url_and_args()
        if self.id == "token":
            return ('import { OpenSeal } from "@openseal/sdk";\n\n'
                    'const os = new OpenSeal({ baseUrl: "https://sign.example.com" });\n'
                    "const token = await os.token({\n  clientId: process.env.CLIENT_ID,\n  clientSecret: process.env.CLIENT_SECRET,\n"
                    '  grant_type: "client_credentials",\n  scope: "envelopes:read envelopes:write",\n});')
        fields = [f"  {k}: {js_value(v)}," for k, v in args]
        for _, value, ts, _ in self.headers():
            fields.append(f"  {ts}: {js_value(value)},")
        body = self.request_example()
        if body is not None:
            fields.append("  body: " + json.dumps(body, indent=2, ensure_ascii=False).replace("\n", "\n  ") + ",")
        call = f"await os.{self.id}(" + ("{\n" + "\n".join(fields) + "\n})" if fields else ")")
        var = "result" if self.method != "get" else "data"
        auth = "" if self.public else ", apiKey: process.env.OPENSEAL_API_KEY"
        return (f'import {{ OpenSeal }} from "@openseal/sdk";\n\n'
                f'const os = new OpenSeal({{ baseUrl: "https://sign.example.com"{auth} }});\n'
                f"const {var} = {call};")

    def python(self) -> str:
        _, args = self.url_and_args()
        if self.id == "token":
            return ("import os\nfrom openseal import OpenSeal\n\nclient = OpenSeal(\"https://sign.example.com\")\n"
                    "token = client.token(\n    client_id=os.environ[\"CLIENT_ID\"],\n    client_secret=os.environ[\"CLIENT_SECRET\"],\n"
                    "    grant_type=\"client_credentials\",\n    scope=\"envelopes:read envelopes:write\",\n)")
        kw = [f"    {k}={ax.pyrepr(v)}," for k, v in args]
        for _, value, _, py in self.headers():
            kw.append(f"    {py}={ax.pyrepr(value)},")
        body = self.request_example()
        if body is not None:
            kw.append(f"    body={ax.pyrepr(body, 4)},")
        method = sitelib_snake(self.id)
        call = f"client.{method}(" + ("\n" + "\n".join(kw) + "\n)" if kw else ")")
        auth = "" if self.public else ', api_key=os.environ["OPENSEAL_API_KEY"]'
        return (f"import os\nfrom openseal import OpenSeal\n\n"
                f'client = OpenSeal("https://sign.example.com"{auth})\n'
                f"{'result' if self.method != 'get' else 'data'} = {call}")

    def errors(self) -> list[tuple[str, str, str]]:
        """The errors this operation can answer, from the API's conventions (docs/40 §1)."""
        out = []
        names = {p["name"] for p in self.params}
        if self.params or self.body:
            out.append(("400 / 422", "CS-API-0001", "Malformed request: a parameter or member is missing, unknown or out of range; <code>errors[]</code> points at it"))
        if not self.public:
            out.append(("401", "CS-AUTH-0001", "No credential, or one that is expired or revoked (<code>CS-AUTH-0002</code>)"))
            perm = self.raw.get("x-permission")
            if perm and perm not in ("signing-in",):
                out.append(("403", "CS-AUTH-0006", f"The credential lacks <code>{esc(perm)}</code>"))
        if "{" in self.path:
            out.append(("404", "CS-API-0002", "No such object, or one of another account (answered alike)"))
        if "Idempotency-Key" in names:
            out.append(("409", "CS-API-0004", "The idempotency key was used with a different body (<code>CS-API-0011</code> while the first is still running)"))
        if "If-Match" in names:
            out.append(("412", "CS-WF-0002", "The <code>If-Match</code> version is stale: read the object again"))
            out.append(("428", "CS-API-0008", "<code>If-Match</code> is required and absent"))
        if self.body:
            out.append(("413", "CS-API-0006", "The request body is over its limit"))
            if "json" in self.body_type:
                out.append(("415", "CS-API-0007", "The body is not <code>application/json</code>"))
        for code, r in self.raw.get("responses", {}).items():
            if code[:1] in "45" and "$ref" not in r:
                out.append((code, "", inline(r.get("description", ""))))
        out.append(("429", "CS-API-0003", "Rate limited: wait for <code>Retry-After</code> seconds"))
        return out


def sitelib_snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def code_box(op: Op) -> str:
    langs = [("curl", "curl", op.curl())]
    if not op.ceremony:
        langs += [("typescript", "TypeScript", op.typescript()), ("python", "Python", op.python())]
    a = anchor(op.id)
    tabs = "".join(
        f'<button type="button" role="tab" class="code-tab" id="{a}-tab-{k}" data-lang="{k}" aria-controls="{a}-{k}" '
        f'aria-selected="{"true" if i == 0 else "false"}"{TABIDX if i else ""}>{label}</button>'
        for i, (k, label, _) in enumerate(langs))
    panels = "".join(
        f'<div class="code-panel{" is-active" if i == 0 else ""}" id="{a}-{k}" role="tabpanel" aria-labelledby="{a}-tab-{k}" data-lang="{k}">'
        f'<p class="code-panel__label">{label}</p><pre><code>{esc(text)}</code></pre></div>'
        for i, (k, label, text) in enumerate(langs))
    head = f'<div class="codebox__bar"><span class="codebox__title"><span class="verb verb-{op.method}">{op.method.upper()}</span>{esc(op.path)}</span><div class="code-tabs" role="tablist" aria-label="Language">{tabs}</div></div>'
    return f'<div class="codebox" data-langs>{head}{panels}</div>'


def response_box(op: Op) -> str:
    code, ctype, value = op.response_example()
    if code is None:
        return ""
    if value is not None:
        body = f'<pre><code>{esc(json.dumps(value, indent=2, ensure_ascii=False))}</code></pre>'
    elif ctype:
        body = f'<p class="codebox__note">The file itself (<code>{esc(ctype)}</code>), not JSON.</p>'
    else:
        body = f'<p class="codebox__note">{"No body." if code == "204" else "No JSON body."}</p>'
    return (f'<div class="codebox codebox--response"><div class="codebox__bar"><span class="codebox__title">Response</span>'
            f'<span class="status-pill status-pill--{code[0]}xx">{esc(code)}</span></div>{body}</div>')


def errors_box(op: Op) -> str:
    rows = "".join(f'<tr><td><span class="status-pill status-pill--{s[0]}xx">{esc(s)}</span></td><td>'
                   + (f'<a href="api.html#{c.lower()}"><code>{esc(c)}</code></a>' if c and c.startswith(("CS-API", "CS-AUTH", "CS-WF")) else (f"<code>{esc(c)}</code>" if c else ""))
                   + f"</td><td>{d}</td></tr>" for s, c, d in op.errors())
    return (f'<details class="errbox"><summary>Errors this can answer</summary><div class="table-scroll" tabindex="0" role="region" '
            f'aria-label="Errors of {esc(op.title)}"><table><thead><tr><th scope="col">Status</th><th scope="col">Code</th>'
            f'<th scope="col">When</th></tr></thead><tbody>{rows}</tbody></table></div>'
            f'<p class="errbox__note">Every error is an RFC 9457 problem with a stable <code>code</code> and a <code>request_id</code>; '
            f'see <a href="api.html#errors">Errors</a>.</p></details>')


def auth_line(op: Op, scopes: dict[str, str]) -> str:
    perm = op.raw.get("x-permission")
    if op.ceremony:
        return '<p class="api-auth"><span class="api-auth__k">Auth</span><span>The signing link\'s token in the path; no API credential. Not public API.</span></p>'
    if op.public:
        return '<p class="api-auth"><span class="api-auth__k">Auth</span><span>None (public)</span></p>'
    if perm == "signing-in":
        return ('<p class="api-auth"><span class="api-auth__k">Auth</span><span>A staff session, also one that still owes its second factor</span></p>')
    cred = "API key or OAuth access token (<code>Authorization: Bearer</code>), or a staff session"
    if not perm:
        return f'<p class="api-auth"><span class="api-auth__k">Auth</span><span>{cred}; any signed-in caller</span></p>'
    scope = scopes.get(perm, "")
    sc = (f' · OAuth scope <a href="api.html#scopes"><code>{esc(scope)}</code></a>' if scope
          else ' · no OAuth scope covers it: it comes from the member\'s role' if perm.startswith("org.") or perm in ("envelopes.transfer", "envelopes.read_all") else "")
    level = op.raw.get("x-level")
    lv = f" ({esc(level)} level)" if level == "organization" else ""
    return (f'<p class="api-auth"><span class="api-auth__k">Auth</span><span>{cred}</span></p>'
            f'<p class="api-auth"><span class="api-auth__k">Permission</span><span><code>{esc(perm)}</code>{lv}{sc}</span></p>')


def op_section(op: Op, scopes: dict[str, str], limit_rows: list) -> str:
    a = anchor(op.id)
    parts = [f'<section class="api-op" aria-labelledby="{a}"><div class="api-op__doc">',
             f'<h2 class="api-op__title" id="{a}"><a class="anchor-link" href="#{a}">{esc(op.title)}</a></h2>',
             f'<p class="api-endpoint"><span class="verb verb-{op.method}">{op.method.upper()}</span><code>{esc(op.path)}</code></p>']
    summary = clean(op.raw.get("summary", ""))
    if summary:
        parts.append(f'<p class="api-op__sum">{inline(summary)}</p>')
    if op.raw.get("description"):
        parts.append(f'<p class="api-op__desc">{inline(op.raw["description"])}</p>')
    parts.append(auth_line(op, scopes))
    for where, label in (("path", "Path parameters"), ("query", "Query parameters"), ("header", "Headers")):
        ps = [p for p in op.params if p.get("in") == where]
        if ps:
            props = {p["name"]: {**(p.get("schema") or {}), **({"description": p["description"]} if p.get("description") else {})} for p in ps}
            req = {p["name"] for p in ps if p.get("required")}
            parts.append(f'<h3 class="api-h" data-nosearch>{label}</h3><ul class="params">{attr_list(op.spec, props, req, f"{a}-{where}")}</ul>')
    if op.body:
        props, req = children_of(op.spec, op.body_schema)
        kind = f'<p class="api-ctype">Content type <code>{esc(op.body_type)}</code>{" · required" if op.body.get("required") else ""}</p>'
        if props:
            parts.append(f'<h3 class="api-h" data-nosearch>Request body</h3>{kind}<ul class="params">{attr_list(op.spec, props, req, f"{a}-body")}</ul>')
        else:
            parts.append(f'<h3 class="api-h" data-nosearch>Request body</h3>{kind}<p class="param__meta">{type_label(op.spec, op.body_schema)}</p>')
    code, r = op.success()
    if r is not None:
        content = r.get("content") or {}
        ctype = next(iter(content), "")
        sch = content.get(ctype, {}).get("schema") if ctype else None
        what = f"a {type_label(op.spec, sch)} object" if sch and "$ref" in sch else (f"<code>{esc(ctype)}</code>" if ctype else "no body")
        parts.append(f'<h3 class="api-h" data-nosearch>Returns</h3><p><span class="status-pill status-pill--{code[0]}xx">{esc(code)}</span> '
                     f'{inline(r.get("description", "")) if r.get("description") not in ("OK", None) else ""}{" " if r.get("description") not in ("OK", None) else ""}with {what}.</p>')
    rows = limits_for(op.method, op.path, limit_rows)
    if rows:
        lis = "".join(f"<li>{md_cell(l)}: {md_cell(d)}</li>" for l, d, _ in rows)
        parts.append(f'<h3 class="api-h" data-nosearch>Limits</h3><ul class="api-limits">{lis}</ul>')
    parts.append('</div><div class="api-op__code" data-nosearch>')
    parts.append(code_box(op))
    parts.append(response_box(op))
    parts.append(errors_box(op))
    parts.append("</div></section>")
    return "".join(parts)


# ---- Navigation and pages -------------------------------------------------------------------------

def nav_tree(groups: dict[str, list[Op]], current: str) -> str:
    sections: dict[str, list[str]] = {}
    for slug, (title, section, _) in GROUPS.items():
        ops = groups.get(slug)
        if not ops:
            continue
        # The current resource lists its operations; the others link to their page (the
        # site search finds any operation), which keeps every page small.
        here = slug == current
        links = "".join(f'<li><a href="#{anchor(o.id)}" data-op="{anchor(o.id)}" title="{esc(o.title)}"><span class="verb verb-{o.method} verb--sm">{o.method.upper()}</span>'
                        f'<span class="api-nav__name">{esc(o.title)}</span></a></li>' for o in ops) if here else ""
        sections.setdefault(section, []).append(
            f'<li><a class="api-nav__grp" href="api-{slug}.html"{CUR if here else ""}><span>{esc(title)}</span>'
            f'<span class="api-nav__count">{len(ops)}<span class="sr-only"> operations</span></span></a>'
            + (f'<ul class="api-nav__ops">{links}</ul>' if here else "") + "</li>")
    out = [f'<ul class="api-nav__top"><li><a href="api.html"{CUR if current == "overview" else ""}>Overview</a></li>'
           '<li><a href="api.html#authentication">Authentication</a></li><li><a href="api.html#errors">Errors</a></li>'
           '<li><a href="api.html#pagination">Pagination</a></li><li><a href="webhooks.html">Webhooks guide</a></li></ul>']
    for section, items in sections.items():
        out.append(f'<h2>{esc(section)}</h2><ul class="api-nav__groups">{"".join(items)}</ul>')
    out.append(f'<h2>Reference</h2><ul class="api-nav__top"><li><a href="api-objects.html"{CUR if current == "objects" else ""}>Objects</a></li>'
               '<li><a href="openapi.yaml">OpenAPI document</a></li></ul>')
    return "".join(out)


def api_shell(groups, current: str, crumbs: list[tuple[str, str]], content: str) -> str:
    tree = nav_tree(groups, current)
    crumb = "".join(f'<li><a href="{h}">{esc(t)}</a></li>' if h else f'<li aria-current="page">{esc(t)}</li>' for t, h in crumbs)
    return f"""<div class="api-shell">
  <aside class="api-side">
    <details class="docs-nav-toggle"><summary>{sitelib.icon("list-tree", 16)}API menu</summary><nav class="api-nav" aria-label="API reference (menu)">{tree}</nav></details>
    <nav class="api-nav api-nav--wide" aria-label="API reference">{tree}</nav>
  </aside>
  <div class="api-body">
    <nav class="crumbs" aria-label="Breadcrumb"><ol>{crumb}</ol></nav>
{content}
  </div>
</div>"""


def group_page(slug: str, ops: list[Op], groups, scopes, limit_rows, order: list[str]) -> str:
    title, section, intro = GROUPS[slug]
    endpoints = "".join(f'<li><a href="#{anchor(o.id)}"><span class="verb verb-{o.method} verb--sm">{o.method.upper()}</span>'
                        f'<code>{esc(o.path)}</code></a></li>' for o in ops)
    warn = ('<div class="callout warn">' + sitelib.icon("triangle-alert") + '<div><p><strong>Not public API.</strong> These endpoints serve '
            'OpenSeal\'s own signing page and may change in any release. Do not build on them.</p></div></div>') if slug == "ceremony" else ""
    i = order.index(slug)
    pn = []
    if i > 0:
        p = order[i - 1]
        pn.append(f'<a class="pn pn-prev" href="api-{p}.html"><span class="pn-dir">{sitelib.icon("chevron-left", 16)}Previous</span><span class="pn-title">{esc(GROUPS[p][0])}</span></a>')
    if i + 1 < len(order):
        n = order[i + 1]
        pn.append(f'<a class="pn pn-next" href="api-{n}.html"><span class="pn-dir">Next{sitelib.icon("chevron-right", 16)}</span><span class="pn-title">{esc(GROUPS[n][0])}</span></a>')
    head = f"""<header class="api-head">
  <div class="api-head__text">
    <p class="api-kicker">{esc(section)}</p>
    <h1>{esc(title)}</h1>
    <p class="lede">{intro}</p>
    {warn}
  </div>
  <div class="api-head__endpoints" data-nosearch>
    <div class="codebox codebox--list"><div class="codebox__bar"><span class="codebox__title">Endpoints</span></div><ul class="endpoint-list">{endpoints}</ul></div>
  </div>
</header>"""
    body = head + "".join(op_section(o, scopes, limit_rows) for o in ops) + f'<nav class="prevnext api-prevnext" aria-label="Previous and next">{"".join(pn)}</nav>'
    content = api_shell(groups, slug, [("Docs", "index.html"), ("API reference", "api.html"), (title, "")], body)
    desc = f"OpenSeal API reference: {title}. {len(ops)} operations with parameters, request bodies, examples in curl, TypeScript and Python, responses and errors."
    return sitelib.page(title=f"{title} API", description=desc, body=content, root="../", current="api", main_class="api-main")


def objects_page(spec: dict, groups) -> str:
    parts = ['<header class="api-head api-head--single"><div class="api-head__text"><p class="api-kicker">Reference</p><h1>Objects</h1>'
             '<p class="lede">Every object the API reads or answers, with its attributes. Operations link here for the '
             'shapes they share.</p></div></header>']
    for name, s in sorted(spec["components"]["schemas"].items()):
        sid = f"schema-{name.lower()}"
        props, req = children_of(spec, {"$ref": f"#/components/schemas/{name}"})
        desc = f'<p class="api-op__desc">{inline(s["description"])}</p>' if s.get("description") else ""
        if props:
            body = f'<ul class="params">{attr_list(spec, props, req, sid, 0, (name,))}</ul>'
        else:
            meta = constraints(spec, s)
            body = f'<p class="param__meta">{type_label(spec, {k: v for k, v in s.items() if k != "description"})}{" · " + meta if meta else ""}</p>'
        parts.append(f'<section class="api-object" id="{sid}" aria-labelledby="{sid}-t"><h2 id="{sid}-t"><a class="anchor-link" href="#{sid}">{esc(name)}</a></h2>{desc}{body}</section>')
    content = api_shell(groups, "objects", [("Docs", "index.html"), ("API reference", "api.html"), ("Objects", "")], "".join(parts))
    return sitelib.page(title="API objects", description="Every object of the OpenSeal API, with its attributes, types and limits.",
                        body=content, root="../", current="api", main_class="api-main")


def overview_page(spec: dict, groups: dict[str, list[Op]], scope_rows) -> str:
    meta, body = sitelib.read_fragment(OVERVIEW)
    count = sum(len(v) for k, v in groups.items() if k != "ceremony")
    scopes: dict[str, list[tuple[str, str]]] = {}
    for action, scope, d in scope_rows:
        scopes.setdefault(scope or "", []).append((action, d))
    srows = "".join(f'<tr><td><code>{esc(s)}</code></td><td>{", ".join(f"<code>{esc(a)}</code>" for a, _ in acts)}</td></tr>'
                    for s, acts in sorted(scopes.items()) if s)
    unscoped = ", ".join(f"<code>{esc(a)}</code>" for a, _ in scopes.get("", []))
    scope_html = (f'<div class="table-scroll" tabindex="0" role="region" aria-label="OAuth scopes"><table><thead><tr><th scope="col">Scope</th>'
                  f'<th scope="col">Permissions it covers</th></tr></thead><tbody>{srows}</tbody></table></div>'
                  f'<p>No scope covers {unscoped}: they are held through a member\'s permission profile only.</p>')

    def code_table(prefixes, label):
        rows = "".join(f'<tr id="{c.lower()}"><td><code>{esc(c)}</code></td><td>{md_cell(m)}</td></tr>' for c, m in error_codes(prefixes))
        return (f'<div class="table-scroll" tabindex="0" role="region" aria-label="{esc(label)}"><table><thead><tr><th scope="col">Code</th>'
                f'<th scope="col">Meaning</th></tr></thead><tbody>{rows}</tbody></table></div>')
    cards = []
    for slug, (title, section, intro) in GROUPS.items():
        ops = groups.get(slug)
        if not ops:
            continue
        first = re.sub(r"<[^>]+>", "", intro).split(". ")[0].rstrip(".") + "."
        cards.append(f'<a class="res-card{" res-card--muted" if slug == "ceremony" else ""}" href="api-{slug}.html"><span class="res-card__t">{esc(title)}</span>'
                     f'<span class="res-card__d">{esc(first)}</span><span class="res-card__n">{len(ops)} operations</span></a>')
    rate = "".join(f"<tr><td>{md_cell(l)}</td><td>{md_cell(d)}</td><td><code>{esc(c)}</code></td></tr>"
                   for l, d, c in api_limits() if re.search(r"Requests per|requests per|attempts per|Idempotency key|Page size|JSON request body|One-call envelope|Document upload", l))
    subs = {
        "<!--api:count-->": str(count),
        "<!--api:version-->": esc(spec["info"]["version"]),
        "<!--api:scopes-->": scope_html,
        "<!--api:errors-api-->": code_table(("CS-API",), "API error codes"),
        "<!--api:errors-auth-->": code_table(("CS-AUTH",), "Authentication error codes"),
        "<!--api:errors-wf-->": code_table(("CS-WF",), "Workflow error codes"),
        "<!--api:resources-->": f'<div class="res-grid">{"".join(cards)}</div>',
        "<!--api:limits-->": (f'<div class="table-scroll" tabindex="0" role="region" aria-label="Request limits"><table><thead><tr><th scope="col">Limit</th>'
                              f'<th scope="col">Value</th><th scope="col">Code</th></tr></thead><tbody>{rate}</tbody></table></div>'),
    }
    for k, v in subs.items():
        if k not in body:
            raise SystemExit(f"build-api-docs: {OVERVIEW.relative_to(ROOT)} has no {k}")
        body = body.replace(k, v)
    body = sitelib.expand(body, "../")
    return sitelib.docs_page("api", meta["title"], meta["description"], body)


def load_spec() -> dict:
    try:
        import yaml
    except ImportError:
        raise SystemExit("build-api-docs: needs PyYAML to read api/openapi.yaml (pip install pyyaml)")
    return yaml.safe_load(SPEC_PATH.read_text(encoding="utf8"))


def operations(spec: dict) -> list[Op]:
    ops = []
    for path, item in spec["paths"].items():
        for method in METHODS:
            if method in item:
                ops.append(Op(spec, path, method, item[method], item.get("parameters", [])))
    unknown = sorted({o.path for o in ops if not o.group})
    if unknown:
        raise SystemExit(f"build-api-docs: no resource group for {unknown}; add it to group_of()")
    return ops


def render_all() -> dict[str, str]:
    """Every page of the reference, relative to site/."""
    spec = load_spec()
    ops = operations(spec)
    groups: dict[str, list[Op]] = {}
    for o in ops:
        groups.setdefault(o.group, []).append(o)
    scope_rows = scope_table()
    scopes = {a: s for a, s, _ in scope_rows}
    limit_rows = api_limits()
    order = [g for g in GROUPS if g in groups]
    pages = {"docs/api.html": overview_page(spec, groups, scope_rows)}
    for slug in order:
        pages[f"docs/api-{slug}.html"] = group_page(slug, groups[slug], groups, scopes, limit_rows, order)
    pages["docs/api-objects.html"] = objects_page(spec, groups)
    return pages


def render() -> str:
    """The overview page (kept for callers that want one page)."""
    return render_all()["docs/api.html"]


def main(argv: list[str]) -> int:
    pages = render_all()
    stale = []
    for rel, text in pages.items():
        out = sitelib.SITE / rel
        if argv == ["--check"]:
            if not out.exists() or out.read_text(encoding="utf8") != text:
                stale.append(rel)
            continue
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf8")
    if stale:
        print("build-api-docs: stale, run python3 tools/build-site.py: " + ", ".join(stale), file=sys.stderr)
        return 1
    print(f"build-api-docs: {len(pages)} pages {'up to date' if argv == ['--check'] else 'written'}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
