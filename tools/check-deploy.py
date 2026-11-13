#!/usr/bin/env python3
"""The production Compose profile's hardening rules, checked (`HRD-06`, docs/65).

    python3 -I tools/check-deploy.py                 # deploy/compose.production.yml
    python3 -I tools/check-deploy.py --self-test     # every rule is shown to fail first
    python3 -I tools/check-deploy.py --json FILE     # an already rendered profile

The profile is rendered by `docker compose config --format json --no-interpolate`, so
anchors, merges and defaults are read exactly as Docker reads them; nothing here parses
YAML. The rules, for every service:

- runs as a named non-root user; read-only root file system; every capability dropped
  and none added; `no-new-privileges`; not privileged, no host network or PID namespace,
  no Docker socket;
- memory, CPU and process limits; no core dumps; bounded `json-file` logs;
- a health check (only a one-shot job, `restart: "no"`, may disable it);
- each service-specific secret (keyd's PIN, seal chain and identity; the worker's,
  Postgres's and the object store's identities) mounted by its one service only;
- no secret in the environment: a variable whose name says secret is set only as
  `NAME_FILE`, pointing under `/run/secrets/` at a secret the service mounts; no
  development key switch;
- images pinned by digest, or OpenSeal's own tagged by `OPENSEAL_VERSION`;
- only the server publishes a port, on the loopback address (the edge proxy's side);
- TLS between services: the object store over `https` with the private CA, Postgres
  with `ssl=on`, TLS 1.3 and an `hba_file` with no plain `host` line, SMTP never
  `plain`; the database, object store and keyd on internal networks only;
- keyd and the worker check a configuration manifest (`OPENSEAL_CONFIG_MANIFEST`, ASVS-24);
- SeaweedFS reports nothing to its vendor and keeps its internal ports on the loopback.

Exits non-zero and names every violation as `service: rule`.
"""

from __future__ import annotations

import copy
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROFILE = ROOT / "deploy" / "compose.production.yml"

SECRET_NAME = re.compile(r"(PASSWORD|SECRET|_KEY$|TOKEN|_PIN$|DATABASE_URL$|PRIVATE)")
# Names that match the pattern but carry no secret: identifiers, labels and paths.
NOT_SECRET = {
    "OPENSEAL_S3_ACCESS_KEY",
    "OPENSEAL_KEYD_PKCS11_KEY_LABEL",
    "OPENSEAL_KEYD_PKCS11_KEY_ID",
    "OPENSEAL_KEYD_PKCS11_TOKEN",
    "OPENSEAL_SECRET_RELOAD_SECONDS",
}
# Files that hold secrets although their names do not say so.
SECRET_FILES = {"OPENSEAL_RECIPIENT_IDPS_FILE"}
# Development switches that must never reach production.
FORBIDDEN_ENV = {
    "OPENSEAL_DEV_INSECURE_KEY",
    "OPENSEAL_WORKER_DEV_KEY",
    "OPENSEAL_WORKER_DEV_CHAIN",
    "OPENSEAL_KEYD_FILE_KEY",
    "OPENSEAL_KEYD_NEXT_FILE_KEY",
    "OPENSEAL_KEYD_IMPORT_KEY",
    "OPENSEAL_KEYD_SO_PIN_FILE",
}
OWN_IMAGE = re.compile(r"^\$\{OPENSEAL_IMAGE_PREFIX[^}]*\}-[a-z]+:\$\{OPENSEAL_VERSION[^}]*\}$")
DIGEST = re.compile(r"@sha256:[0-9a-f]{64}$")
MANIFEST_SERVICES = ("keyd", "worker")
# Secrets one service alone may mount, by name prefix: the seal key's PIN and chain and
# keyd's identity never reach the server (ASVS-19), and so on.
SECRET_OWNERS = {
    "keyd-": "keyd",
    "seal-": "keyd",
    "worker-": "worker",
    "postgres-": "postgres",
    "s3-tls": "s3",
    "s3-identities": "s3",
    "migrate-": "migrate",
}
INTERNAL_ONLY = ("postgres", "s3", "keyd")


def render(path: Path) -> dict:
    """The profile as Docker reads it."""
    try:
        out = subprocess.run(
            ["docker", "compose", "-f", str(path), "config", "--format", "json", "--no-interpolate"],
            check=True,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        sys.exit("check-deploy: `docker compose` is needed to render the profile")
    except subprocess.CalledProcessError as e:
        sys.exit(f"check-deploy: docker compose could not render {path}: {e.stderr.strip()}")
    return json.loads(out.stdout)


def is_root(user: str | None) -> bool:
    if not user:
        return True
    name = user.split(":", 1)[0].strip()
    return name in ("", "0", "root")


def env_of(svc: dict) -> dict[str, str]:
    env = svc.get("environment") or {}
    if isinstance(env, list):
        env = dict(e.split("=", 1) if "=" in e else (e, "") for e in env)
    return {k: ("" if v is None else str(v)) for k, v in env.items()}


def command_of(svc: dict) -> list[str]:
    c = svc.get("command") or []
    return c.split() if isinstance(c, str) else [str(x) for x in c]


def published(port) -> tuple[str | None, bool]:
    """(host address, whether published) of one `ports` entry, long or short syntax."""
    if isinstance(port, dict):
        return port.get("host_ip"), bool(port.get("published"))
    text = str(port)
    # Short syntax, possibly with ${...} defaults holding colons.
    parts = re.split(r":(?![^{]*\})", text)
    if len(parts) == 3:
        return parts[0], True
    if len(parts) == 2:
        return None, True
    return None, False


def ulimit_core(svc: dict):
    core = (svc.get("ulimits") or {}).get("core")
    if isinstance(core, dict):
        return core.get("hard", core.get("soft"))
    return core


def hba_lines(svc: dict, base: Path) -> list[str] | None:
    """The lines of the hba file the postgres service mounts, or None."""
    cmd = command_of(svc)
    target = next((a.split("=", 1)[1] for a in cmd if a.startswith("hba_file=")), None)
    if not target:
        return None
    for v in svc.get("volumes") or []:
        if isinstance(v, dict) and v.get("target") == target and v.get("type") == "bind":
            src = Path(v["source"])
            if not src.is_absolute():
                src = base / src
            try:
                return src.read_text().splitlines()
            except OSError:
                return []
    return []


def check(doc: dict, base: Path) -> list[str]:
    problems: list[str] = []
    services = doc.get("services") or {}
    networks = doc.get("networks") or {}
    if not services:
        return ["profile: no services"]

    def bad(name: str, rule: str) -> None:
        problems.append(f"{name}: {rule}")

    for name, svc in sorted(services.items()):
        if is_root(svc.get("user")):
            bad(name, "runs as root (set `user` to a non-root uid)")
        if svc.get("read_only") is not True:
            bad(name, "root file system is writable (`read_only: true`)")
        if "ALL" not in [str(c).upper() for c in svc.get("cap_drop") or []]:
            bad(name, "capabilities not dropped (`cap_drop: [ALL]`)")
        if svc.get("cap_add"):
            bad(name, "capabilities added (`cap_add`)")
        opts = [str(o).replace(" ", "") for o in svc.get("security_opt") or []]
        if not any(o in ("no-new-privileges:true", "no-new-privileges") for o in opts):
            bad(name, "`no-new-privileges:true` missing")
        if svc.get("privileged"):
            bad(name, "privileged")
        if svc.get("network_mode") == "host" or svc.get("pid") == "host" or svc.get("ipc") == "host":
            bad(name, "shares a host namespace")
        for v in svc.get("volumes") or []:
            src = v.get("source", "") if isinstance(v, dict) else str(v).split(":", 1)[0]
            if "docker.sock" in str(src):
                bad(name, "mounts the Docker socket")
        limits = ((svc.get("deploy") or {}).get("resources") or {}).get("limits") or {}
        if not (svc.get("mem_limit") or limits.get("memory")):
            bad(name, "no memory limit")
        if not (svc.get("cpus") or limits.get("cpus")):
            bad(name, "no CPU limit")
        if not (svc.get("pids_limit") or limits.get("pids")):
            bad(name, "no process limit (`pids_limit`)")
        if str(ulimit_core(svc)) != "0":
            bad(name, "core dumps allowed (`ulimits: {core: 0}`)")
        log = svc.get("logging") or {}
        if log.get("driver") not in ("json-file", "local") or not (log.get("options") or {}).get("max-size"):
            bad(name, "logs unbounded (`logging` json-file with max-size)")
        hc = svc.get("healthcheck")
        one_shot = str(svc.get("restart", "")) == "no"
        if not hc or (hc.get("disable") and not one_shot) or (not hc.get("disable") and not hc.get("test")):
            bad(name, "no health check")
        image = str(svc.get("image", ""))
        if not (DIGEST.search(image) or OWN_IMAGE.match(image)):
            bad(name, f"image not pinned by digest or OPENSEAL_VERSION ({image or 'none'})")
        if svc.get("build"):
            bad(name, "builds an image (production runs signed, published images)")

        for s in svc.get("secrets") or []:
            source = s.get("source", "") if isinstance(s, dict) else str(s)
            owner = next((o for p, o in SECRET_OWNERS.items() if source.startswith(p)), None)
            if owner and owner != name:
                bad(name, f"mounts {source}, which only {owner} may")

        env = env_of(svc)
        mounted = {s.get("target") or f"/run/secrets/{s.get('source')}" if isinstance(s, dict) else f"/run/secrets/{s}"
                   for s in svc.get("secrets") or []}
        for var, value in sorted(env.items()):
            base_name = var.removesuffix("_FILE")
            secret = (SECRET_NAME.search(base_name) and base_name not in NOT_SECRET) or var in SECRET_FILES
            if var in FORBIDDEN_ENV:
                bad(name, f"{var} is a development switch")
            elif not secret or not value:
                continue
            elif value.startswith("/run/secrets/"):
                # NAME_FILE, or a setting that is itself a key's path (keyd's TLS key).
                if value not in mounted:
                    bad(name, f"{var} names a secret the service does not mount")
            elif var.endswith("_FILE"):
                bad(name, f"{var} is not under /run/secrets/")
            else:
                bad(name, f"{var} holds a secret in the environment (use {var}_FILE)")
        for var in ("OPENSEAL_S3_ENDPOINT",):
            if var in env and not env[var].startswith("https://"):
                bad(name, f"{var} is not https")
        if "OPENSEAL_S3_ENDPOINT" in env and "OPENSEAL_S3_CA" not in env:
            bad(name, "OPENSEAL_S3_CA missing (the object store's private CA)")
        for var in ("OPENSEAL_PUBLIC_URL", "OPENSEAL_BASE_URL"):
            if var in env and env[var].startswith("http://"):
                bad(name, f"{var} is plain http")
        if env.get("OPENSEAL_SMTP_SECURITY") == "plain":
            bad(name, "SMTP without TLS")
        if name in MANIFEST_SERVICES and not env.get("OPENSEAL_CONFIG_MANIFEST", "").startswith("/run/secrets/"):
            bad(name, "no configuration manifest (OPENSEAL_CONFIG_MANIFEST under /run/secrets/)")

        for port in svc.get("ports") or []:
            host, is_published = published(port)
            if not is_published:
                continue
            if name != "server":
                bad(name, "publishes a port (only the server does, behind the edge proxy)")
            elif host not in ("127.0.0.1", "::1", "[::1]"):
                bad(name, "publishes on a non-loopback address")

        if name in INTERNAL_ONLY:
            nets = svc.get("networks") or {}
            if not nets:
                bad(name, "on the default network (not internal)")
            for net in nets:
                if not (networks.get(net) or {}).get("internal"):
                    bad(name, f"on network {net}, which is not internal")

        cmd = command_of(svc)
        if name == "postgres":
            joined = " ".join(cmd)
            if "ssl=on" not in joined:
                bad(name, "TLS off (`-c ssl=on`)")
            if "ssl_min_protocol_version=TLSv1.3" not in joined:
                bad(name, "TLS below 1.3 accepted")
            lines = hba_lines(svc, base)
            if lines is None:
                bad(name, "no hba_file (the image's default accepts plain connections)")
            else:
                rules = [ln.split() for ln in lines if ln.strip() and not ln.lstrip().startswith("#")]
                if not rules:
                    bad(name, "hba_file missing or empty")
                for r in rules:
                    if r[0] not in ("local", "hostssl"):
                        bad(name, f"hba_file allows `{r[0]}` (only hostssl and local)")
                    elif r[-1] in ("trust", "password", "md5"):
                        bad(name, f"hba_file uses `{r[-1]}` (scram-sha-256 only)")
        if "chrislusf/seaweedfs" in image:
            if "-master.telemetry=false" not in cmd:
                bad(name, "SeaweedFS telemetry on (`-master.telemetry=false`)")
            if "-ip.bind=127.0.0.1" not in cmd:
                bad(name, "SeaweedFS internal ports reachable (`-ip.bind=127.0.0.1`)")
            if not any(a.startswith("-s3.cert.file=") for a in cmd):
                bad(name, "S3 gateway without TLS (`-s3.cert.file`)")
    return problems


# --self-test: each mutation breaks one rule; the check must name it.
def _set(path: list, value):
    def f(doc: dict) -> None:
        node = doc
        for k in path[:-1]:
            node = node.setdefault(k, {})
        if value is _DELETE:
            node.pop(path[-1], None)
        else:
            node[path[-1]] = value
    return f


_DELETE = object()


def _env(svc: str, var: str, value):
    return _set(["services", svc, "environment", var], value)


def _hba_with(text: str):
    def f(doc: dict) -> None:
        tmp = tempfile.NamedTemporaryFile("w", suffix=".conf", delete=False)
        tmp.write(text)
        tmp.close()
        _TEMPS.append(tmp.name)
        for v in doc["services"]["postgres"]["volumes"]:
            if isinstance(v, dict) and v.get("target") == "/etc/openseal/pg_hba.conf":
                v["source"] = tmp.name
    return f


_TEMPS: list[str] = []


def _command_without(svc: str, arg: str):
    def f(doc: dict) -> None:
        cmd = doc["services"][svc]["command"]
        doc["services"][svc]["command"] = [a for a in cmd if not a.startswith(arg)]
    return f


MUTATIONS = [
    ("root user", _set(["services", "server", "user"], "0:0"), "server: runs as root"),
    ("no user", _set(["services", "keyd", "user"], _DELETE), "keyd: runs as root"),
    ("writable root", _set(["services", "worker", "read_only"], False), "worker: root file system is writable"),
    ("capabilities kept", _set(["services", "postgres", "cap_drop"], []), "postgres: capabilities not dropped"),
    ("capability added", _set(["services", "s3", "cap_add"], ["NET_ADMIN"]), "s3: capabilities added"),
    ("privileges", _set(["services", "keyd", "security_opt"], []), "keyd: `no-new-privileges:true` missing"),
    ("privileged", _set(["services", "worker", "privileged"], True), "worker: privileged"),
    ("host network", _set(["services", "server", "network_mode"], "host"), "server: shares a host namespace"),
    ("docker socket", lambda d: d["services"]["worker"].setdefault("volumes", []).append(
        {"type": "bind", "source": "/var/run/docker.sock", "target": "/var/run/docker.sock"}),
     "worker: mounts the Docker socket"),
    ("memory", _set(["services", "server", "mem_limit"], _DELETE), "server: no memory limit"),
    ("cpu", _set(["services", "keyd", "cpus"], _DELETE), "keyd: no CPU limit"),
    ("pids", _set(["services", "postgres", "pids_limit"], _DELETE), "postgres: no process limit"),
    ("core dumps", _set(["services", "keyd", "ulimits"], {}), "keyd: core dumps allowed"),
    ("logs", _set(["services", "worker", "logging"], _DELETE), "worker: logs unbounded"),
    ("no health check", _set(["services", "worker", "healthcheck"], _DELETE), "worker: no health check"),
    ("health check off", _set(["services", "server", "healthcheck"], {"disable": True}), "server: no health check"),
    ("unpinned image", _set(["services", "postgres", "image"], "postgres:17-alpine"), "postgres: image not pinned"),
    ("latest tag", _set(["services", "server", "image"], "openseal-server:latest"), "server: image not pinned"),
    ("secret in env", _env("server", "OPENSEAL_DATABASE_URL", "postgres://openseal:pw@postgres/openseal"),
     "server: OPENSEAL_DATABASE_URL holds a secret"),
    ("password in env", _env("worker", "OPENSEAL_SMTP_PASSWORD", "hunter2"), "worker: OPENSEAL_SMTP_PASSWORD holds a secret"),
    ("file outside secrets", _env("server", "OPENSEAL_MFA_KEY_FILE", "/etc/mfa-key"),
     "server: OPENSEAL_MFA_KEY_FILE is not under /run/secrets/"),
    ("secret not mounted", _env("server", "OPENSEAL_SMTP_PASSWORD_FILE", "/run/secrets/smtp-password"),
     "server: OPENSEAL_SMTP_PASSWORD_FILE names a secret the service does not mount"),
    ("seal pin in server", lambda d: d["services"]["server"]["secrets"].append(
        {"source": "keyd-pkcs11-pin", "target": "/run/secrets/keyd-pkcs11-pin"}),
     "server: mounts keyd-pkcs11-pin, which only keyd may"),
    ("dev key", _env("server", "OPENSEAL_DEV_INSECURE_KEY", "1"), "server: OPENSEAL_DEV_INSECURE_KEY is a development switch"),
    ("dev file key", _env("keyd", "OPENSEAL_KEYD_FILE_KEY", "/run/secrets/seal.key"),
     "keyd: OPENSEAL_KEYD_FILE_KEY is a development switch"),
    ("plain s3", _env("worker", "OPENSEAL_S3_ENDPOINT", "http://s3:8333"), "worker: OPENSEAL_S3_ENDPOINT is not https"),
    ("no s3 ca", _env("server", "OPENSEAL_S3_CA", _DELETE), "server: OPENSEAL_S3_CA missing"),
    ("plain public url", _env("server", "OPENSEAL_PUBLIC_URL", "http://sign.example.com"),
     "server: OPENSEAL_PUBLIC_URL is plain http"),
    ("plain smtp", _env("worker", "OPENSEAL_SMTP_SECURITY", "plain"), "worker: SMTP without TLS"),
    ("no keyd manifest", _env("keyd", "OPENSEAL_CONFIG_MANIFEST", _DELETE), "keyd: no configuration manifest"),
    ("no worker manifest", _env("worker", "OPENSEAL_CONFIG_MANIFEST", _DELETE), "worker: no configuration manifest"),
    ("public port", _set(["services", "server", "ports"], ["8080:8080"]), "server: publishes on a non-loopback"),
    ("postgres port", _set(["services", "postgres", "ports"], ["127.0.0.1:5432:5432"]), "postgres: publishes a port"),
    ("postgres outside", lambda d: d["services"]["postgres"]["networks"].update({"edge": None}),
     "postgres: on network edge, which is not internal"),
    ("keyd network open", _set(["networks", "signing", "internal"], False), "keyd: on network signing, which is not internal"),
    ("postgres tls off", _command_without("postgres", "ssl=on"), "postgres: TLS off"),
    ("postgres tls 1.2", _command_without("postgres", "ssl_min_protocol_version"), "postgres: TLS below 1.3"),
    ("no hba", _command_without("postgres", "hba_file"), "postgres: no hba_file"),
    ("plain hba", _hba_with("hostssl all all 0.0.0.0/0 scram-sha-256\nhost all all 0.0.0.0/0 scram-sha-256\n"),
     "postgres: hba_file allows `host`"),
    ("trust hba", _hba_with("local all all trust\n"), "postgres: hba_file uses `trust`"),
    ("telemetry", _command_without("s3", "-master.telemetry"), "s3: SeaweedFS telemetry on"),
    ("seaweed open", _command_without("s3", "-ip.bind=127.0.0.1"), "s3: SeaweedFS internal ports reachable"),
    ("s3 plain", _command_without("s3", "-s3.cert.file"), "s3: S3 gateway without TLS"),
]


def self_test(doc: dict, base: Path) -> int:
    failures = []
    clean = check(doc, base)
    if clean:
        failures.append("the profile itself fails: " + "; ".join(clean))
    for label, mutate, expect in MUTATIONS:
        broken = copy.deepcopy(doc)
        mutate(broken)
        found = check(broken, base)
        if not any(p.startswith(expect) for p in found):
            failures.append(f"mutation `{label}` was not caught (expected `{expect}`; got {found})")
    for t in _TEMPS:
        os.unlink(t)
    if failures:
        for f in failures:
            print(f"check-deploy: self-test: {f}", file=sys.stderr)
        return 1
    print(f"check-deploy: self-test passed ({len(MUTATIONS)} violations caught, the profile clean)")
    return 0


def main(argv: list[str]) -> int:
    args = argv[1:]
    if args[:1] == ["--json"] and len(args) == 2:
        path = Path(args[1])
        doc, base = json.loads(path.read_text()), PROFILE.parent
    elif args in ([], ["--self-test"]):
        doc, base = render(PROFILE), PROFILE.parent
    else:
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 2
    if args == ["--self-test"]:
        return self_test(doc, base)
    problems = check(doc, base)
    for p in problems:
        print(f"check-deploy: {p}", file=sys.stderr)
    if problems:
        print(f"check-deploy: {len(problems)} violation(s) in the production profile", file=sys.stderr)
        return 1
    print(f"check-deploy: {len(doc['services'])} services pass every hardening rule")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
