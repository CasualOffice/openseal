"""Examples for the API reference (SITE-12), made from api/openapi.yaml, and the
validator that keeps them true to it.

tools/build-api-docs.py shows, for every operation, a request in curl, TypeScript and
Python and the response it answers. Their JSON comes from here: generated from the
operation's schemas (realistic, non-personal values: example.com addresses, "Example"
names, fixed ids), or written by hand in REQUEST_OVERRIDES for the operations people
start with. Every example, generated or written, is checked against its schema by
`validate` when the site is built and by tools/test_build_api_docs.py, so an example can
never drift from the contract: a schema change that an example no longer meets fails
the build, naming the operation and the JSON pointer.

`validate` covers the JSON Schema keywords api/openapi.yaml uses (type, including type
lists for null; properties, required, additionalProperties; items, minItems, maxItems;
enum, const; minLength, maxLength, pattern; minimum, maximum; format date-time; oneOf,
anyOf, allOf; $ref). An unknown keyword is an error, so a new one is never silently
ignored. Standard library only; deterministic (no time or randomness).
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

# Keywords the validator understands; anything else in a schema fails loudly.
KNOWN = {"type", "properties", "required", "additionalProperties", "items", "minItems", "maxItems", "enum", "const",
         "minLength", "maxLength", "pattern", "minimum", "maximum", "format", "oneOf", "anyOf", "allOf", "$ref",
         "description", "default", "example", "title", "nullable", "readOnly", "writeOnly", "deprecated",
         "uniqueItems", "examples", "minProperties", "maxProperties", "contentEncoding", "contentMediaType"}
DATE_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")
FORMATS = {"date-time": DATE_TIME, "date": re.compile(r"^\d{4}-\d{2}-\d{2}$"),
           "uuid": re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"),
           "email": re.compile(r"^[^@\s]+@[^@\s]+$"), "uri": re.compile(r"^[a-z][a-z0-9+.-]*:"),
           "int64": None, "int32": None, "binary": None, "byte": None, "password": None}

WHEN = "2026-11-20T09:30:00Z"
EXPIRES = "2026-12-20T09:30:00Z"


def ref_name(ref: str) -> str:
    return ref.rsplit("/", 1)[-1]


def resolve(spec: dict, schema: dict | None) -> dict:
    """Follow `$ref` (to components/schemas) until a schema without one."""
    seen = 0
    while isinstance(schema, dict) and "$ref" in schema:
        schema = spec["components"]["schemas"][ref_name(schema["$ref"])]
        seen += 1
        if seen > 32:
            raise ValueError("api_examples: $ref chain too long")
    return schema or {}


def fake_id(name: str) -> str:
    """A fixed UUIDv7-shaped id for `name` (the same name, the same id, in every example)."""
    h = hashlib.sha256(name.encode()).hexdigest()
    return f"0193{h[:4]}-{h[4:8]}-7{h[8:11]}-8{h[11:14]}-{h[14:26]}"


def entity(parent: str) -> str:
    """The resource a schema describes: its name's first word (`EnvelopeSummary` -> `envelope`)."""
    m = re.match(r"[A-Z][a-z]+", parent or "")
    return m.group(0).lower() if m else (parent or "object").lower()


def _types(schema: dict) -> list[str]:
    t = schema.get("type")
    if t is None:
        return ["object"] if "properties" in schema or "additionalProperties" in schema else []
    return t if isinstance(t, list) else [t]


# ---- Generation ----------------------------------------------------------------------------

NAMES = {
    "subject": "Please sign: Mutual NDA", "message": "Please review and sign the attached agreement.",
    "reason": "Replaced by a corrected version", "title": "Mutual NDA", "label": "company_name",
    "locale": "en", "language": "en", "timezone": "UTC", "country": "US", "region": "CA", "city": "Example City",
    "phone": "+15555550100", "password": "correct-horse-battery-staple", "current_password": "an-older-passphrase-1",
    "code": "123456", "token": "tok_example", "secret": "whsec_MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw",
    "scope": "envelopes:read", "key_prefix": "osk_3f9a", "key": "osk_3f9a6c1e8b2d4f7a9c0e5b1d3f6a8c2e",
    "client_secret": "example-client-secret-shown-once", "next_cursor": "eyJpZCI6IjAxOTMifQ", "cursor": "eyJpZCI6IjAxOTMifQ",
    "access_token": "eyJhbGciOiJFUzI1NiJ9.example.signature", "refresh_token": "osr_example", "token_type": "Bearer",
    "state": "af0ifjsldkj", "description": "Signed agreements to the CRM",
    "sha256": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "csv": "name,email\nExample Signer,signer@example.com\n",
    "content_base64": "JVBERi0xLjcKJcfsj6IK", "text": "Example text", "value": "Example Corp",
    "user_agent": "Mozilla/5.0", "ip": "192.0.2.10", "public_key": "-----BEGIN PUBLIC KEY-----\n…\n-----END PUBLIC KEY-----",
    "event": "envelope.completed", "anchor": "/sig1/", "color": "#1d5fbf", "colour": "#1d5fbf",
    "detail": "subject is longer than 255 characters", "request_id": fake_id("request"),
}
NAME_BY_PARENT = (("Document", "contract.pdf"), ("Folder", "Q4 contracts"), ("Template", "Mutual NDA"),
                  ("Group", "Sales"), ("Workspace", "Example Workspace"), ("Organization", "Example Organization"),
                  ("Account", "Example Workspace"), ("Client", "Example integration"), ("Profile", "Sender"),
                  ("Passkey", "Laptop"), ("Bulk", "November renewals"), ("Brand", "Example Corp"),
                  ("Role", "Client"), ("Webhook", "CRM sync"))


def _string(spec: dict, s: dict, name: str, parent: str) -> str:
    if "enum" in s:
        return s["enum"][0]
    if "const" in s:
        return s["const"]
    if "default" in s and isinstance(s["default"], str):
        return s["default"]
    fmt = s.get("format")
    lname = name.lower()
    if fmt == "date-time" or lname.endswith("_at") or lname in ("from", "to", "at", "since", "until"):
        return EXPIRES if lname.startswith("expire") else WHEN
    if fmt == "date":
        return WHEN[:10]
    pattern = s.get("pattern")
    if pattern:
        for candidate in ("123456", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08", "en-US",
                          "CS-API-0001", "example-label", "example_label"):
            if re.search(pattern, candidate):
                return candidate
    if lname == "email" or lname.endswith("_email") or fmt == "email":
        return "signer@example.com" if "admin" not in lname else "admin@example.com"
    if lname in ("url", "uri", "return_url", "redirect_uri", "redirect_to") or lname.endswith("_url") or fmt == "uri":
        if "webhook" in parent.lower() or lname == "url" and "Webhook" in parent:
            return "https://hooks.example.com/openseal"
        return "https://app.example.com/openseal/callback"
    if lname in ("x", "y", "width", "height"):
        return {"x": "72", "y": "600", "width": "180", "height": "40"}[lname]
    if lname == "id" or lname.endswith("_id") or lname in ("user", "recipient", "document", "field", "envelope"):
        return fake_id(entity(parent) if lname == "id" else lname.removesuffix("_id"))
    if lname == "name" or lname.endswith("_name"):
        for key, val in NAME_BY_PARENT:
            if key in parent:
                return val
        return "Example Signer"
    if lname == "client_id":
        return fake_id("client")
    if lname in NAMES:
        return NAMES[lname]
    if lname.endswith("sha256") or lname.endswith("_hash"):
        return NAMES["sha256"]
    value = {"status": "sent", "type": "signature", "kind": "template", "delivery": "email", "role": "signer",
             "method": "email_otp", "format": "json", "result": "ok"}.get(lname, "example")
    if s.get("minLength") and len(value) < s["minLength"]:
        value = value.ljust(s["minLength"], "x")
    if s.get("maxLength") and len(value) > s["maxLength"]:
        value = value[: s["maxLength"]]
    return value


def _number(s: dict, name: str, integer: bool) -> int | float:
    if "enum" in s:
        return s["enum"][0]
    if "default" in s and isinstance(s["default"], (int, float)) and not isinstance(s["default"], bool):
        return s["default"]
    lname = name.lower()
    guess = {"version": 3, "page": 1, "x": 72, "y": 600, "width": 180, "height": 40, "routing_order": 1,
             "limit": 50, "count": 1, "seq": 12, "status": 422, "expires_in_days": 30, "size": 48213,
             "pages": 2, "first_after_days": 2, "then_every_days": 3, "every_days": 3}.get(lname, 1)
    lo, hi = s.get("minimum"), s.get("maximum")
    if lo is not None and guess < lo:
        guess = lo
    if hi is not None and guess > hi:
        guess = hi
    return int(guess) if integer else float(guess)


def example(spec: dict, schema: dict | None, name: str = "", parent: str = "", depth: int = 0,
            full: bool = True, stack: tuple = ()) -> Any:
    """A value that `schema` accepts. `full`: every property (responses); otherwise the
    required ones and, near the top, the rest too (request bodies stay readable)."""
    if not schema:
        return {}
    if "$ref" in schema:
        rn = ref_name(schema["$ref"])
        if rn in stack:
            return {}
        return example(spec, resolve(spec, schema), name, rn, depth, full, stack + (rn,))
    if "example" in schema:
        return schema["example"]
    if "enum" in schema:
        return schema["enum"][0]
    if "allOf" in schema:
        if len(schema["allOf"]) == 1:
            return example(spec, schema["allOf"][0], name, parent, depth, full, stack)
        merged: dict = {}
        for part in schema["allOf"]:
            v = example(spec, part, name, parent, depth, full, stack)
            if isinstance(v, dict):
                merged.update(v)
        return merged
    for key in ("oneOf", "anyOf"):
        if key in schema:
            return example(spec, schema[key][0], name, parent, depth, full, stack)
    if "const" in schema:
        return schema["const"]
    types = [t for t in _types(schema) if t != "null"] or ["string"]
    t = types[0]
    if t == "string":
        return _string(spec, schema, name, parent)
    if t in ("integer", "number"):
        return _number(schema, name, t == "integer")
    if t == "boolean":
        return bool(schema.get("default", False))
    if t == "array":
        if depth > 5:
            return []
        n = max(1, schema.get("minItems", 1))
        items = schema.get("items", {})
        out = [example(spec, items, name.rstrip("s"), parent, depth + 1, full, stack) for _ in range(n)]
        if schema.get("uniqueItems") and n > 1:
            out = out[:1]
        return out
    # object
    props = schema.get("properties") or {}
    if not props:
        extra = schema.get("additionalProperties")
        if isinstance(extra, dict) and extra:
            return {"key": example(spec, extra, "value", parent, depth + 1, full, stack)}
        return {}
    if depth > 6:
        return {}
    required = set(schema.get("required", []))
    keep_all = full or depth < 1
    out = {}
    for k, v in props.items():
        if k in required or keep_all:
            if not full and resolve(spec, v).get("deprecated"):
                continue
            out[k] = example(spec, v, k, parent, depth + 1, full, stack)
    return out


# ---- Validation ----------------------------------------------------------------------------

def validate(spec: dict, schema: dict | None, value: Any, at: str = "") -> list[str]:
    """Every way `value` breaks `schema`, as "<JSON pointer>: <what>"; empty when it fits."""
    where = at or "/"
    if not schema:
        return []
    unknown = set(schema) - KNOWN
    if unknown:
        return [f"{where}: schema keyword(s) {sorted(unknown)} not understood by tools/api_examples.py"]
    if "$ref" in schema:
        return validate(spec, resolve(spec, schema), value, at)
    errs: list[str] = []
    if "allOf" in schema:
        for part in schema["allOf"]:
            errs += validate(spec, part, value, at)
    if "anyOf" in schema and not any(not validate(spec, s, value, at) for s in schema["anyOf"]):
        errs.append(f"{where}: matches none of anyOf")
    if "oneOf" in schema:
        n = sum(1 for s in schema["oneOf"] if not validate(spec, s, value, at))
        if n != 1:
            errs.append(f"{where}: matches {n} of oneOf, not exactly one")
    if "const" in schema and value != schema["const"]:
        errs.append(f"{where}: is not the constant {schema['const']!r}")
    if "enum" in schema and value not in schema["enum"]:
        errs.append(f"{where}: {value!r} is not one of {schema['enum']}")
    types = _types(schema)
    if types:
        ok = False
        for t in types:
            if t == "null" and value is None or t == "boolean" and isinstance(value, bool) \
                    or t == "integer" and isinstance(value, int) and not isinstance(value, bool) \
                    or t == "number" and isinstance(value, (int, float)) and not isinstance(value, bool) \
                    or t == "string" and isinstance(value, str) or t == "array" and isinstance(value, list) \
                    or t == "object" and isinstance(value, dict):
                ok = True
        if not ok:
            return errs + [f"{where}: {type(value).__name__} is not {' or '.join(types)}"]
    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            errs.append(f"{where}: shorter than {schema['minLength']}")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errs.append(f"{where}: longer than {schema['maxLength']}")
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errs.append(f"{where}: does not match {schema['pattern']}")
        fmt = schema.get("format")
        if fmt and fmt not in FORMATS:
            errs.append(f"{where}: format {fmt!r} not understood by tools/api_examples.py")
        elif fmt and FORMATS[fmt] is not None and not FORMATS[fmt].search(value):
            errs.append(f"{where}: not a {fmt}")
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errs.append(f"{where}: below the minimum {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            errs.append(f"{where}: above the maximum {schema['maximum']}")
    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            errs.append(f"{where}: fewer than {schema['minItems']} items")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errs.append(f"{where}: more than {schema['maxItems']} items")
        for i, item in enumerate(value):
            errs += validate(spec, schema.get("items"), item, f"{at}/{i}")
    if isinstance(value, dict):
        props = schema.get("properties") or {}
        for k in schema.get("required", []):
            if k not in value:
                errs.append(f"{where}: missing required {k!r}")
        if "minProperties" in schema and len(value) < schema["minProperties"]:
            errs.append(f"{where}: fewer than {schema['minProperties']} members")
        if "maxProperties" in schema and len(value) > schema["maxProperties"]:
            errs.append(f"{where}: more than {schema['maxProperties']} members")
        extra = schema.get("additionalProperties", True)
        for k, v in value.items():
            if k in props:
                errs += validate(spec, props[k], v, f"{at}/{k}")
            elif extra is False:
                errs.append(f"{where}: {k!r} is not allowed (additionalProperties: false)")
            elif isinstance(extra, dict):
                errs += validate(spec, extra, v, f"{at}/{k}")
    return errs


# ---- Hand-written request bodies --------------------------------------------------------------

SIGNER = fake_id("recipient")
DOC = fake_id("document")

# operationId -> request body. Each is validated against the operation's schema.
REQUEST_OVERRIDES: dict[str, Any] = {
    "createEnvelope": {
        "subject": "Please sign: Mutual NDA",
        "message": "Please review and sign the attached agreement.",
        "status": "sent",
        "documents": [{"name": "nda.pdf", "content_base64": "JVBERi0xLjcKJcfsj6IK"}],
        "recipients": [
            {"ref": "client", "type": "signer", "name": "Example Signer", "email": "signer@example.com",
             "routing_order": 1},
            {"type": "cc", "name": "Example Legal", "email": "legal@example.com", "routing_order": 2},
        ],
        "fields": [
            {"recipient": "client", "document": 0, "type": "signature", "page": 1, "x": 72, "y": 600,
             "width": 180, "height": 40},
            {"recipient": "client", "document": 0, "type": "date_signed", "page": 1, "x": 280, "y": 600,
             "width": 120, "height": 24},
        ],
        "reminders": {"first_after_days": 2, "then_every_days": 3},
        "expires_in_days": 30,
    },
    "voidEnvelope": {"reason": "Replaced by a corrected version"},
    "createApiClient": {"name": "CRM sync", "kind": "api_key", "scopes": ["envelopes:read", "envelopes:write"],
                        "expires_in_days": 90},
    "createWebhook": {"url": "https://hooks.example.com/openseal",
                      "event_types": ["envelope.completed", "envelope.declined"],
                      "secret_refs": ["OPENSEAL_WEBHOOK_SECRET_CRM"]},
}


def pyrepr(value: Any, indent: int = 0) -> str:
    """`value` as a Python literal, indented as json.dumps(indent=4) would be."""
    pad = " " * (indent + 4)
    end = " " * indent
    if value is None:
        return "None"
    if value is True:
        return "True"
    if value is False:
        return "False"
    if isinstance(value, str):
        return repr(value) if "\n" in value else '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
    if isinstance(value, (int, float)):
        return repr(value)
    if isinstance(value, list):
        if not value:
            return "[]"
        return "[\n" + ",\n".join(pad + pyrepr(v, indent + 4) for v in value) + ",\n" + end + "]"
    if isinstance(value, dict):
        if not value:
            return "{}"
        return "{\n" + ",\n".join(f'{pad}"{k}": {pyrepr(v, indent + 4)}' for k, v in value.items()) + ",\n" + end + "}"
    raise TypeError(type(value))
