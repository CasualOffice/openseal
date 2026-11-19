"""The configuration reference's tables (SITE-12), read from the sources they describe,
so the website cannot drift from the binaries:

- each binary's environment variables from the table in its module documentation
  (`//! | Variable | Meaning |` in server/casual-sign-{server,worker,keyd}/src/main.rs),
  with the default the text states, whether it is a secret (`(secret)`, or a `_FILE`
  form named) and whether the binary refuses to start without it (its `need("…")` reads,
  plus the few REQUIRED_EXTRA below that are read another way);
- the production profile's variables from deploy/compose.production.yml (`${VAR:?…}` is
  required, `${VAR:-default}` has that default), described in COMPOSE_DESC; a variable
  the profile gains without a description fails the build, naming it.

tools/build-site.py calls `fill(body)` on site/_src/docs/configuration.html, replacing the
`<!--config:NAME-->` markers. Standard library only.
"""

from __future__ import annotations

import html
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
BINARIES = {
    "server": "server/casual-sign-server/src/main.rs",
    "worker": "server/casual-sign-worker/src/main.rs",
    "keyd": "server/casual-sign-keyd/src/main.rs",
}
PROFILE = "deploy/compose.production.yml"

# Read other than through `need("…")`; the binary still refuses to start without them.
REQUIRED_EXTRA = {
    "server": {"OPENSEAL_DATABASE_URL": "Yes", "OPENSEAL_JWT_SIGNING_KEY": "Outside development",
               "OPENSEAL_MFA_KEY": "Outside development"},
    "worker": {"OPENSEAL_DATABASE_URL": "Yes"},
    "keyd": {},
}
# need("…") reads that apply only when a feature is used.
CONDITIONAL = {
    "OPENSEAL_S3_BUCKET": "With S3", "OPENSEAL_BLOB_DIR": "Without S3",
    "OPENSEAL_MODELD_SERVER_NAME": "With modeld", "OPENSEAL_KEYD_PKCS11_TOKEN": "With PKCS#11",
    "OPENSEAL_KEYD_ADDR": "Yes, unless a development key", "OPENSEAL_KEYD_SERVER_NAME": "Yes, unless a development key",
}
# Rows that name a secret beside a value that is not one.
NOT_SECRET = {"OPENSEAL_SMS_GATEWAY_URL", "OPENSEAL_SMTP_USER"}
# Defaults a multi-variable row cannot attach by itself.
DEFAULTS = {"OPENSEAL_SMTP_HOST": "", "OPENSEAL_SMTP_PORT": "587", "OPENSEAL_S3_ENDPOINT": "",
            "OPENSEAL_S3_BUCKET": "", "OPENSEAL_S3_REGION": "us-east-1",
            "OPENSEAL_HEALTH_FILE": "/tmp/openseal-worker-health"}

# Variables a binary reads that its module table does not list (docs/65 is their source).
EXTRA_ROWS = {
    "server": [
        ("OPENSEAL_MIGRATE_DATABASE_URL", "", True, "`migrate`, `verify-evidence` and `mfa-reseal` only: PostgreSQL URL of the schema owner; never the application role"),
        ("OPENSEAL_KEYD_SEAL_TOKEN_KEY", "", True, "`migrate` only: keyd's seal token key (64 hex digits), installed in the database after the migrations; the server itself is never given it"),
        ("OPENSEAL_RECIPIENT_IDPS_FILE", "", True, "Optional: a JSON file of the OpenID Connect providers recipients may sign in with (`sso`); it holds client secrets, so mount it as a secret"),
        ("OPENSEAL_ALERT_WINDOW_SECS", "300", False, "Abnormal-activity detection: the sliding window, 10 to 86,400 seconds"),
        ("OPENSEAL_ALERT_REQUESTS", "6000", False, "Abnormal activity: requests per principal or address per window (`0` turns the rule off)"),
        ("OPENSEAL_ALERT_RATE_LIMITED", "30", False, "Abnormal activity: `429` answers per window"),
        ("OPENSEAL_ALERT_AUTH_FAILURES", "20", False, "Abnormal activity: refused sign-ins, second factors, tokens and links per window"),
        ("OPENSEAL_ALERT_DENIED", "50", False, "Abnormal activity: `403` answers per window"),
        ("OPENSEAL_ALERT_DOCUMENT_READS", "500", False, "Abnormal activity: staff document reads per window"),
        ("OPENSEAL_ALERT_VOIDS", "25", False, "Abnormal activity: envelopes voided per window"),
        ("OPENSEAL_ALERT_SENDS", "300", False, "Abnormal activity: envelopes sent one at a time per window"),
        ("OPENSEAL_ALERT_BULK_SENDS", "10", False, "Abnormal activity: bulk sends per window"),
        ("OPENSEAL_ALERT_COOLDOWN_SECS", "900", False, "Quiet time for a subject after an alert"),
        ("OPENSEAL_ALERT_MAX_PER_MINUTE", "20", False, "Most alerts a minute across all subjects"),
        ("OPENSEAL_ALERT_MAX_TRACKED", "50000", False, "Most subjects counted, 1,000 to 10,000,000"),
        ("RUST_LOG", "info", False, "Filters the operational log lines; security events are never filtered"),
    ],
    "worker": [], "keyd": [],
}

COMPOSE_DESC = {
    "OPENSEAL_SECRETS_DIR": "Directory of the secret files `deploy/production/init-secrets.sh` wrote, plus the ones you add",
    "OPENSEAL_VERSION": "The OpenSeal image tag, for example `0.1.0`; a release's `openseal-release.env` sets it",
    "OPENSEAL_IMAGE_PREFIX": "Image name prefix: `ghcr.io/casualoffice/openseal` for published releases, `openseal` for local builds",
    "OPENSEAL_PUBLIC_URL": "The HTTPS address people and integrations use; the server's `OPENSEAL_PUBLIC_URL` and the worker's `OPENSEAL_BASE_URL`",
    "OPENSEAL_TRUSTED_PROXIES": "CIDRs whose forwarded client address is believed: include the `edge` network's subnet",
    "OPENSEAL_HTTP_PORT": "Port of the `proxy` service on the host's loopback address; your TLS edge forwards to it",
    "OPENSEAL_PKCS11_DIR": "Host directory holding the HSM vendor's PKCS#11 library, mounted read-only into keyd at the same path",
    "OPENSEAL_PKCS11_MODULE": "Path of the PKCS#11 library inside that directory",
    "OPENSEAL_PKCS11_TOKEN": "The HSM token (slot) label holding the seal key",
    "OPENSEAL_PKCS11_KEY_LABEL": "The seal key's label in the token",
    "OPENSEAL_PKCS11_NEXT_KEY_LABEL": "During a seal key rotation: the next key's label (empty otherwise)",
    "OPENSEAL_SEAL_ALIAS": "The seal key's alias, shared by keyd and the worker",
    "OPENSEAL_SEAL_NEXT_ALIAS": "During a seal key rotation: the next key's alias (empty otherwise)",
    "OPENSEAL_SEAL_NAME": "The seal's signer name, shown by PDF readers",
    "OPENSEAL_SEAL_REASON": "The seal's reason, shown by PDF readers",
    "OPENSEAL_MAIL_FROM": "The `From` address of every email",
    "OPENSEAL_MAIL_FROM_NAME": "The `From` display name",
    "OPENSEAL_MAIL_DOMAIN": "The domain of `Message-ID` headers",
    "OPENSEAL_ABUSE": "Where recipients report abuse; every email names it",
    "OPENSEAL_SMTP_HOST": "Your SMTP relay (STARTTLS)",
    "OPENSEAL_SMTP_PORT": "The relay's port",
    "OPENSEAL_SMTP_USER": "The relay's user name; the password is the `smtp-password` secret file",
    "OPENSEAL_TSA_URLS": "RFC 3161 time-stamping authorities, comma-separated, tried in order, until key custodians configure them in the console",
}

TRACKER = re.compile(r"\s*\((?:row\s+)?`?(?:[A-Z][A-Z0-9]*-\d+[A-Z]?|ASVS[- ][\d.]+)`?(?:,\s*`?(?:[A-Z][A-Z0-9]*-\d+[A-Z]?|ASVS[- ][\d.]+)`?)*\)")


def _md(text: str) -> str:
    out = html.escape(TRACKER.sub("", text).strip(), quote=False)
    return re.sub(r"`([^`]+)`", r"<code>\1</code>", out)


def module_rows(binary: str) -> list[dict]:
    """The variables of one binary: name, default, required, secret, description (HTML)."""
    src = (ROOT / BINARIES[binary]).read_text(encoding="utf8")
    needed = set(re.findall(r'need\("(OPENSEAL_[A-Z0-9_]+)"\)', src))
    rows: list[dict] = []
    seen: set[str] = set()
    for line in src.splitlines():
        m = re.match(r"^//! \| (.+?) \| (.+) \|$", line)
        if not m or m.group(1) in ("Variable", "---"):
            continue
        cell, meaning = m.group(1), m.group(2)
        names = [n for n in re.findall(r"`(OPENSEAL_[A-Z0-9_]+)(?:=[^`]*)?`", cell)]
        file_forms = {n for n in names if n.endswith("_FILE") and n[:-5] in names}
        names = [n for n in names if n not in file_forms]
        secret = "(secret" in cell or "`_FILE`" in cell or bool(file_forms)
        # A default in the variable cell belongs to the name just before it.
        cell_defaults = {}
        for dm in re.finditer(r"`(OPENSEAL_[A-Z0-9_]+)`\s*\(default `?([^`)]+)`?\)", cell):
            cell_defaults[dm.group(1)] = dm.group(2)
        mark = re.search(r"`([^`]+)` \(default\)", meaning)
        md = mark or re.search(r"\(default:? `?([^`;),]+)`?", meaning) or re.search(r"\bdefault `([^`]+)`", meaning)
        for n in names:
            if n in seen:
                continue
            seen.add(n)
            if n in DEFAULTS:
                default = DEFAULTS[n]
            elif n in cell_defaults:
                default = cell_defaults[n]
            elif md and len(names) == 1:
                default = md.group(1).strip()
            else:
                default = ""
            req = REQUIRED_EXTRA[binary].get(n) or CONDITIONAL.get(n) or ("Yes" if n in needed else "")
            sec = secret and n not in NOT_SECRET
            rows.append({"name": n, "default": default, "required": req, "secret": sec,
                         "file": f"{n}_FILE" if sec else "", "desc": _md(meaning)})
    for name, default, secret, desc in EXTRA_ROWS[binary]:
        if name not in seen:
            rows.append({"name": name, "default": default, "required": "", "secret": secret,
                         "file": f"{name}_FILE" if secret else "", "desc": _md(desc)})
    if len(rows) < 10:
        raise SystemExit(f"site_config: read only {len(rows)} variables from {BINARIES[binary]}; has its table moved?")
    return rows


def profile_rows() -> list[dict]:
    text = (ROOT / PROFILE).read_text(encoding="utf8")
    rows: dict[str, dict] = {}
    for name, kind, rest in re.findall(r"\$\{(OPENSEAL_[A-Z0-9_]+)(?:(:\?|:-)([^}]*))?\}", text):
        r = rows.setdefault(name, {"name": name, "default": "", "required": "", "secret": False, "file": ""})
        if kind == ":?":
            r["required"] = "Yes"
        elif kind == ":-":
            r["default"] = rest
    missing = sorted(set(rows) - set(COMPOSE_DESC))
    if missing:
        raise SystemExit(f"site_config: {PROFILE} uses {missing} with no description; add them to COMPOSE_DESC")
    for r in rows.values():
        r["desc"] = _md(COMPOSE_DESC[r["name"]])
    return sorted(rows.values(), key=lambda r: (r["required"] != "Yes", r["name"]))


def table(rows: list[dict], key: str, label: str) -> str:
    body = []
    for r in rows:
        rid = f"env-{key}-{r['name'].lower().replace('_', '-')}"
        default = f"<code>{html.escape(r['default'])}</code>" if r["default"] else '<span class="muted">none</span>'
        secret = ('<span class="tag tag--secret">Secret</span><span class="cfg-file">or <code>'
                  + html.escape(r["file"]) + "</code></span>") if r["secret"] else ""
        req = f'<span class="tag tag--req">{html.escape(r["required"])}</span>' if r["required"] else '<span class="muted">No</span>'
        body.append(f'<tr id="{rid}"><th scope="row"><a href="#{rid}"><code>{html.escape(r["name"])}</code></a>{secret}</th>'
                    f"<td>{default}</td><td>{req}</td><td>{r['desc']}</td></tr>")
    return (f'<div class="table-scroll cfg-table" tabindex="0" role="region" aria-label="{html.escape(label)}" data-filter-scope="config">'
            f'<table><thead><tr><th scope="col">Variable</th><th scope="col">Default</th><th scope="col">Required</th>'
            f'<th scope="col">Description</th></tr></thead><tbody>{"".join(body)}</tbody></table></div>')


def fill(body: str) -> str:
    subs = {
        "<!--config:server-->": table(module_rows("server"), "server", "Server variables"),
        "<!--config:worker-->": table(module_rows("worker"), "worker", "Worker variables"),
        "<!--config:keyd-->": table(module_rows("keyd"), "keyd", "keyd variables"),
        "<!--config:profile-->": table(profile_rows(), "profile", "Production profile variables"),
    }
    for k, v in subs.items():
        if k not in body:
            raise SystemExit(f"site_config: site/_src/docs/configuration.html has no {k}")
        body = body.replace(k, v)
    return body
