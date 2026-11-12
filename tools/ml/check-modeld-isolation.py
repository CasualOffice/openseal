#!/usr/bin/env python3
"""Check that modeld in the Compose stack sees only its own TLS identity (ML-01, docs/33 §1).

modeld runs model code over hostile documents, so it must never read the stack's shared
`secrets` volume (CA key, seal key, JWT key, database URLs, S3 key). This script checks:

1. `docker compose --profile ml config`: modeld mounts no `secrets` volume, its own
   `modeld-secrets` volume read-only at /secrets, and every file path in its environment
   lies under a mount it has; no service other than `pki` and `modeld` mounts
   `modeld-secrets`.
2. `deploy/devtools/dev-pki.sh`, run into two temporary directories: the modeld
   directory holds exactly its TLS chain, its key, `ca.pem` and its allow list; the
   certificate chains to the root with `serverAuth` and the name `modeld`; the allow list
   names the worker's client certificate; and a re-run on a stack whose shared secrets
   already exist (an upgrade) fills an empty modeld directory without a new root.

    python3 -I tools/ml/check-modeld-isolation.py

Needs `docker compose` (part 1) and `openssl` (part 2). Standard library only. Exits
non-zero naming each problem. Run by hand when Compose or dev-pki changes; it is not a
CI gate (docs/04: no new gates unless the owner asks).
"""

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
DEV_PKI = ROOT / "deploy" / "devtools" / "dev-pki.sh"
MODELD_FILES = {"ca.pem", "modeld-tls-chain.pem", "modeld-tls.key", "modeld-allow-list"}


def check_compose(problems):
    if shutil.which("docker") is None:
        problems.append("compose: docker is not installed; part 1 not run")
        return
    run = subprocess.run(["docker", "compose", "--profile", "ml", "config", "--format", "json"],
                         cwd=ROOT, capture_output=True, text=True, check=False)
    if run.returncode != 0:
        problems.append(f"compose: `docker compose --profile ml config` exited {run.returncode}")
        return
    services = json.loads(run.stdout)["services"]
    modeld = services.get("modeld")
    if modeld is None:
        problems.append("compose: no modeld service under the ml profile")
        return
    mounts = modeld.get("volumes", [])
    for m in mounts:
        if m.get("source") == "secrets":
            problems.append(f"compose: modeld mounts the shared secrets volume at {m.get('target')}")
    own = [m for m in mounts if m.get("source") == "modeld-secrets"]
    if not own or own[0].get("target") != "/secrets" or not own[0].get("read_only"):
        problems.append("compose: modeld must mount its own modeld-secrets volume read-only at /secrets")
    targets = [m.get("target", "") for m in mounts]
    for k, v in (modeld.get("environment") or {}).items():
        if isinstance(v, str) and v.startswith("/") and k != "OPENSEAL_MODELD_LISTEN":
            if not any(v == t or v.startswith(t.rstrip("/") + "/") for t in targets):
                problems.append(f"compose: modeld {k}={v} is under none of its mounts")
    for name, svc in services.items():
        if name in ("pki", "modeld"):
            continue
        if any(m.get("source") == "modeld-secrets" for m in svc.get("volumes", [])):
            problems.append(f"compose: {name} mounts modeld-secrets")


def openssl(*args, check=True):
    return subprocess.run(["openssl", *args], capture_output=True, text=True, check=check)


def fingerprint(pem):
    der = subprocess.run(["openssl", "x509", "-in", str(pem), "-outform", "DER"],
                         capture_output=True, check=True).stdout
    import hashlib
    return hashlib.sha256(der).hexdigest()


def check_dev_pki(problems):
    if shutil.which("openssl") is None:
        problems.append("dev-pki: openssl is not installed; part 2 not run")
        return
    with tempfile.TemporaryDirectory(prefix="modeld-isolation-") as tmp:
        tmp = pathlib.Path(tmp)
        shared, own = tmp / "secrets", tmp / "modeld"
        env = dict(os.environ, OUT=str(shared), MODELD_OUT=str(own))

        def run_pki():
            r = subprocess.run(["sh", str(DEV_PKI)], env=env, capture_output=True, text=True, check=False)
            if r.returncode != 0:
                problems.append(f"dev-pki: exited {r.returncode}: {r.stderr.strip()[-300:]}")
            return r.returncode == 0

        if not run_pki():
            return
        got = {p.name for p in own.iterdir() if not p.name.startswith(".")} if own.is_dir() else set()
        if got != MODELD_FILES:
            problems.append(f"dev-pki: modeld directory holds {sorted(got)}, want exactly {sorted(MODELD_FILES)}")
            return
        if (own / "ca.pem").read_bytes() != (shared / "ca.pem").read_bytes():
            problems.append("dev-pki: modeld's ca.pem is not the stack's root")
        v = openssl("verify", "-CAfile", str(own / "ca.pem"), "-purpose", "sslserver",
                    str(own / "modeld-tls-chain.pem"), check=False)
        if v.returncode != 0:
            problems.append(f"dev-pki: modeld's certificate does not verify as a TLS server: {v.stdout.strip()}")
        text = openssl("x509", "-in", str(own / "modeld-tls-chain.pem"), "-noout", "-text").stdout
        if "DNS:modeld" not in text:
            problems.append("dev-pki: modeld's certificate does not name DNS:modeld")
        pub_key = openssl("pkey", "-in", str(own / "modeld-tls.key"), "-pubout").stdout
        pub_cert = openssl("x509", "-in", str(own / "modeld-tls-chain.pem"), "-noout", "-pubkey").stdout
        if pub_key != pub_cert:
            problems.append("dev-pki: modeld's key does not match its certificate")
        allow = (own / "modeld-allow-list").read_text(encoding="utf8").split()
        if allow[:1] != [fingerprint(shared / "worker-client.pem")]:
            problems.append("dev-pki: modeld's allow list does not name the worker's certificate")

        # An upgrade: the shared secrets exist, the modeld volume is new and empty.
        root_before = (shared / "ca.pem").read_bytes()
        shutil.rmtree(own)
        if not run_pki():
            return
        got = {p.name for p in own.iterdir() if not p.name.startswith(".")} if own.is_dir() else set()
        if got != MODELD_FILES:
            problems.append(f"dev-pki upgrade: modeld directory holds {sorted(got)}, want {sorted(MODELD_FILES)}")
        if (shared / "ca.pem").read_bytes() != root_before:
            problems.append("dev-pki upgrade: the root was regenerated")
        if (own / "ca.pem").is_file() and (own / "ca.pem").read_bytes() != root_before:
            problems.append("dev-pki upgrade: modeld's ca.pem is not the existing root")


def main():
    problems = []
    check_compose(problems)
    check_dev_pki(problems)
    for p in problems:
        print(f"check-modeld-isolation: {p}", file=sys.stderr)
    if problems:
        return 1
    print("check-modeld-isolation: modeld mounts only its own TLS identity; dev-pki fills it and nothing else")
    return 0


if __name__ == "__main__":
    sys.exit(main())
