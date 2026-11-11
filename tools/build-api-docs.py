#!/usr/bin/env python3
"""Render api/openapi.yaml, the API contract, into a readable static page,
site/docs/api.html (SITE-01): operations grouped by resource with parameters, request
bodies and responses, then every schema. No JavaScript renderer and nothing from a CDN.

    python3 tools/build-api-docs.py           # write site/docs/api.html
    python3 tools/build-api-docs.py --check   # fail if it is stale

Needs PyYAML (a YAML parser is not in the standard library); fails non-zero, saying so,
without it. tools/build-site.py runs this as part of the site build.
"""

from __future__ import annotations

import html
import pathlib
import re
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import sitelib  # noqa: E402

SPEC = sitelib.ROOT / "api/openapi.yaml"
OUT = sitelib.SITE / "docs/api.html"
METHODS = ("get", "post", "put", "patch", "delete")

GROUPS = {
    "auth": "Authentication and sessions", "oauth": "OAuth", ".well-known": "Discovery", "accounts": "Account",
    "users": "Users and invitations", "api-clients": "API clients", "envelopes": "Envelopes", "templates": "Templates",
    "contacts": "Contacts", "webhooks": "Webhooks", "s": "Signing ceremony (not public API)",
}
ORDER = ["auth", "oauth", ".well-known", "envelopes", "templates", "contacts", "webhooks", "users", "api-clients", "accounts", "s"]


def esc(s) -> str:
    return html.escape(str(s), quote=True)


def inline(text: str) -> str:
    """Spec descriptions: escape, then `code` and [links](url) to the docs folder."""
    out = esc(text or "")
    out = re.sub(r"`([^`]+)`", r"<code>\1</code>", out)
    out = re.sub(r"\(docs/(\d+)[^)]*\)", lambda m: f'(<a href="{sitelib.REPO}/tree/main/docs">docs/{m.group(1)}</a>)', out)
    return out


def ref_name(ref: str) -> str:
    return ref.rsplit("/", 1)[-1]


def type_of(schema: dict | None) -> str:
    """A short type description with links to schema anchors."""
    if not schema:
        return ""
    if "$ref" in schema:
        n = ref_name(schema["$ref"])
        return f'<a href="#schema-{n.lower()}">{esc(n)}</a>'
    if "oneOf" in schema or "anyOf" in schema:
        return " or ".join(type_of(s) for s in schema.get("oneOf") or schema.get("anyOf"))
    if "allOf" in schema:
        return " and ".join(type_of(s) for s in schema["allOf"])
    t = schema.get("type", "object")
    if isinstance(t, list):
        t = " or ".join(t)
    if t == "array":
        return f"array of {type_of(schema.get('items', {}))}"
    extra = []
    if "enum" in schema:
        extra.append("one of " + ", ".join(f"<code>{esc(v)}</code>" for v in schema["enum"]))
    if "format" in schema:
        extra.append(esc(schema["format"]))
    for k, label in (("minimum", "min"), ("maximum", "max"), ("maxLength", "max length"), ("default", "default")):
        if k in schema:
            extra.append(f"{label} {esc(schema[k])}")
    return esc(t) + (f' <span class="muted">({"; ".join(extra)})</span>' if extra else "")


def resolve_param(spec: dict, p: dict) -> dict:
    if "$ref" in p:
        return spec["components"]["parameters"][ref_name(p["$ref"])]
    return p


def op_html(spec: dict, path: str, method: str, op: dict, shared_params: list) -> str:
    oid = op.get("operationId") or f"{method}-{path}"
    params = [resolve_param(spec, p) for p in shared_params + op.get("parameters", [])]
    parts = [f'<div class="op" id="op-{esc(oid.lower())}">',
             f'<div class="op-head"><span class="verb verb-{method}">{method.upper()}</span><code>{esc(path)}</code></div>',
             f'<p class="op-sum">{inline(op.get("summary", ""))}</p>']
    if op.get("description"):
        parts.append(f"<p>{inline(op['description'])}</p>")
    perm = op.get("x-permission")
    sec = op.get("security")
    if perm == "public" or sec == []:
        parts.append('<p class="op-perm">No API credential (public, or the signing link\'s token)</p>')
    elif perm:
        parts.append(f'<p class="op-perm">Needs scope <code>{esc(perm)}</code></p>')
    else:
        parts.append('<p class="op-perm">Any signed-in caller</p>')
    if params:
        rows = "".join(
            f"<tr><td><code>{esc(p['name'])}</code></td><td>{esc(p.get('in', ''))}</td><td>{'yes' if p.get('required') else 'no'}</td>"
            f"<td>{type_of(p.get('schema'))}</td><td>{inline(p.get('description', ''))}</td></tr>" for p in params)
        parts.append(f'<details><summary>Parameters ({len(params)})</summary><div class="table-scroll" tabindex="0" role="region" aria-label="Parameters of {esc(method.upper())} {esc(path)}"><table><thead><tr><th scope="col">Name</th>'
                     f'<th scope="col">In</th><th scope="col">Required</th><th scope="col">Type</th><th scope="col">Description</th></tr></thead>'
                     f"<tbody>{rows}</tbody></table></div></details>")
    body = op.get("requestBody")
    if body:
        content = body.get("content", {})
        kinds = ", ".join(f"<code>{esc(ct)}</code>: {type_of(v.get('schema'))}" for ct, v in content.items())
        parts.append(f'<p class="schema-list"><b>Request body</b>{" (required)" if body.get("required") else ""}: {kinds}</p>')
    resp = []
    for code, r in op.get("responses", {}).items():
        if "$ref" in r:
            r = spec["components"]["responses"][ref_name(r["$ref"])]
        schemas = ", ".join(type_of(v.get("schema")) for v in (r.get("content") or {}).values() if v.get("schema"))
        resp.append(f"<tr><td><code>{esc(code)}</code></td><td>{inline(r.get('description', ''))}</td><td>{schemas}</td></tr>")
    if resp:
        parts.append(f'<details><summary>Responses ({len(resp)})</summary><div class="table-scroll" tabindex="0" role="region" aria-label="Responses of {esc(method.upper())} {esc(path)}"><table><thead><tr><th scope="col">Status</th>'
                     f'<th scope="col">Description</th><th scope="col">Body</th></tr></thead><tbody>{"".join(resp)}</tbody></table></div></details>')
    parts.append("</div>")
    return "".join(parts)


def schema_html(name: str, s: dict) -> str:
    head = f'<h3 id="schema-{esc(name.lower())}">{esc(name)}</h3>'
    desc = f"<p>{inline(s['description'])}</p>" if s.get("description") else ""
    props = s.get("properties")
    if not props:
        return head + desc + f'<p class="schema-list">{type_of(s)}</p>'
    req = set(s.get("required", []))
    rows = "".join(
        f"<tr><td><code>{esc(k)}</code></td><td>{'yes' if k in req else 'no'}</td><td>{type_of(v)}</td><td>{inline(v.get('description', ''))}</td></tr>"
        for k, v in props.items())
    return (head + desc + f'<div class="table-scroll" tabindex="0" role="region" aria-label="Properties of {esc(name)}"><table><thead><tr><th scope="col">Property</th><th scope="col">Required</th>'
            f'<th scope="col">Type</th><th scope="col">Description</th></tr></thead><tbody>{rows}</tbody></table></div>')


def render() -> str:
    try:
        import yaml
    except ImportError:
        raise SystemExit("build-api-docs: needs PyYAML to read api/openapi.yaml (pip install pyyaml)")
    spec = yaml.safe_load(SPEC.read_text(encoding="utf8"))
    groups: dict[str, list[str]] = {}
    count = 0
    for path, item in spec["paths"].items():
        seg = path.split("/")[3] if path.startswith("/api/v1/") else path.split("/")[1]
        for method in METHODS:
            if method in item:
                groups.setdefault(seg, []).append(op_html(spec, path, method, item[method], item.get("parameters", [])))
                count += 1
    unknown = sorted(set(groups) - set(ORDER))
    if unknown:
        raise SystemExit(f"build-api-docs: no group title for {unknown}; add them to GROUPS and ORDER")
    info = spec["info"]
    sections = []
    for seg in ORDER:
        if seg in groups:
            sections.append(f"<h2>{esc(GROUPS[seg])}</h2>" + "".join(groups[seg]))
    schemes = "".join(f"<li><b>{esc(k)}</b>: {inline(v.get('description', ''))}</li>"
                      for k, v in spec["components"].get("securitySchemes", {}).items())
    schemas = "".join(schema_html(n, s) for n, s in sorted(spec["components"]["schemas"].items()))
    article = f"""<h1>API reference</h1>
<p class="lede">{esc(info['title'])} {esc(info['version'])}: {count} operations, rendered from <a href="{sitelib.REPO}/blob/main/api/openapi.yaml">api/openapi.yaml</a>, the contract the server's route table is tested against.</p>
<h2>Conventions</h2>
<p>{inline(info.get('description', '')).replace(chr(10), ' ')}</p>
<p>Authentication:</p>
<ul>{schemes}</ul>
<p>Webhooks, idempotency and errors are explained in <a href="webhooks.html">Webhooks</a> and the <a href="{sitelib.REPO}/blob/main/docs/40-API-DESIGN.md">API design (docs/40)</a>.</p>
{"".join(sections)}
<h2>Schemas</h2>
{schemas}"""
    return sitelib.docs_page("api", "API reference", f"Every operation of the OpenSeal REST API ({count} operations), with parameters, bodies and schemas.", article)


def main(argv: list[str]) -> int:
    out = render()
    if argv == ["--check"]:
        if not OUT.exists() or OUT.read_text(encoding="utf8") != out:
            print("build-api-docs: site/docs/api.html is stale; run python3 tools/build-api-docs.py", file=sys.stderr)
            return 1
        return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(out, encoding="utf8")
    print("build-api-docs: wrote site/docs/api.html")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
