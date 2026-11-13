#!/usr/bin/env python3
"""The HRD-01 chaos cases on the hardened Compose profile (HRD-10; docs/65 §Failure
recovery; CI job `chaos-compose`).

    python3 -I tools/chaos/chaos_compose.py run [--no-build] [--verify-python PY]
    python3 -I tools/chaos/chaos_compose.py tsa-gate --listen ADDR --target HOST:PORT --delay S

`run` needs Docker with Compose v2 on Linux (CI's ubuntu-latest). It builds the images
from this checkout (unless --no-build), writes throwaway secrets with the operator's own
deploy/production/init-secrets.sh plus a CI seal PKI (tools/chaos/prepare-secrets.sh,
inside the devtools image, so no sudo), imports the seal key into SoftHSM in keyd's
volume, records keyd's and the worker's configuration manifests, and starts
deploy/compose.production.yml with tools/chaos/compose.chaos.yml (CI only: a STARTTLS
mail sink, a TSA behind a gate that holds each request a few seconds, the evidence
verifier). Two workers run. Then, each envelope with one signer who passes an access
code, through the API and the emailed link:

1. paused: worker A paused (cgroup freeze) mid-seal past its 300 s lease; worker B takes
   the job over and seals; A, resumed, must record nothing (lease fence).
2. killed: worker B SIGKILLed (from the host's PID namespace, as the OOM killer would)
   mid-seal; Docker's restart policy must bring it back; the job runs again.
3. killed early: every worker SIGKILLed right after the signer finishes.
4. keyd: keyd stopped before the signer finishes; the seal fails with a `seal_failed`
   alert, nothing is served, the workers restarted meanwhile stay up; keyd back, sealed.
5. postgres-ceremony: PostgreSQL killed between adopt and finish; the finish answers
   5xx; PostgreSQL restarted; the retried finish signs once.
6. postgres-seal: PostgreSQL killed mid-seal and restarted.
7. object-store: the object store killed mid-seal; the seal job fails without landing
   bytes, is pushed to its last attempt and hands over to a new seal job (never dead);
   the store back, sealed.

PostgreSQL and the object store are killed with no grace period (`docker compose stop
-t 0`: SIGKILL at once, and Docker leaves them down until the driver starts them).
Retries are made due with `UPDATE jobs SET run_at = now()` (the back-off is not under
test); leases lapse in real time. Then, over every envelope: `completed` with exactly one
sealed version, served, or still `completing` with a `job_dead` alert and nothing
served; `verify-evidence` passes (every audit chain, every blob); keyd's operation log
verifies; tools/verify-sealed.py (pyHanko) validates every sealed PDF against the chaos
root. Writes target/chaos-compose/report.json and exits non-zero naming each problem.
The stack, its volumes and the secrets are removed however it ends.

`tsa-gate` is the TCP gate in front of the TSA (it runs in the devtools image).

Standard library only. Prints ids, codes and counts, never document text.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import pathlib
import re
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
TOOLS = pathlib.Path(__file__).resolve().parent
PROFILE = ROOT / "deploy" / "compose.production.yml"
OVERRIDE = TOOLS / "compose.chaos.yml"
PROJECT = "openseal-chaos"
DEVTOOLS = "openseal-devtools:dev"
HTTP_PORT, MAIL_PORT = 18380, 18325
PUBLIC_URL = "https://openseal.chaos.test"
ACCESS_CODE = "chaos-4711"
UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
PNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg=="
LEASE_WAIT = 420  # the worker's lease (300 s) and a seal after it


class ChaosError(Exception):
    pass


def say(msg: str) -> None:
    print(f"chaos: {msg}", file=sys.stderr, flush=True)


# ------------------------------------------------------------------ pure logic (unit tested)


def compose_env(work: pathlib.Path, hsm: pathlib.Path, tsa_delay: float) -> dict[str, str]:
    """Every variable the production profile and the override interpolate."""
    return {
        "OPENSEAL_SECRETS_DIR": str(work / "secrets"),
        "OPENSEAL_VERSION": "dev",
        "OPENSEAL_PUBLIC_URL": PUBLIC_URL,
        "OPENSEAL_TRUSTED_PROXIES": "127.0.0.1/32",
        "OPENSEAL_HTTP_PORT": str(HTTP_PORT),
        "OPENSEAL_PKCS11_DIR": str(hsm),
        "OPENSEAL_PKCS11_MODULE": str(hsm / "libsofthsm2.so"),
        "OPENSEAL_PKCS11_TOKEN": "chaos",
        "OPENSEAL_PKCS11_KEY_LABEL": "platform",
        "OPENSEAL_MAIL_FROM": "no-reply@openseal.chaos.test",
        "OPENSEAL_MAIL_DOMAIN": "openseal.chaos.test",
        "OPENSEAL_ABUSE": "abuse@openseal.chaos.test",
        "OPENSEAL_SMTP_HOST": "mailpit",
        "OPENSEAL_SMTP_PORT": "1025",
        "OPENSEAL_SMTP_USER": "chaos",
        "OPENSEAL_TSA_URLS": "http://tsa-gate:8318/",
        "OPENSEAL_SEAL_NAME": "OpenSeal chaos test",
        "CHAOS_WORK": str(work),
        "CHAOS_TOOLS": str(TOOLS),
        "CHAOS_MAIL_PORT": str(MAIL_PORT),
        "CHAOS_TSA_DELAY": f"{tsa_delay:g}",
    }


def required_variables(text: str) -> set[str]:
    """Variables a Compose file requires (`${NAME:?...}`)."""
    return set(re.findall(r"\$\{([A-Z0-9_]+):\?", text))


def log_events(text: str) -> list[dict]:
    """The JSON log lines (`{"ts":…,"event":…}`) in Docker's log output, any prefix."""
    out = []
    for line in text.splitlines():
        at = line.find("{")
        if at < 0:
            continue
        try:
            obj = json.loads(line[at:])
        except ValueError:
            continue
        if isinstance(obj, dict) and "event" in obj:
            out.append(obj)
    return out


def alerts_for(events: list[dict], kind: str, envelope: str) -> int:
    return sum(1 for e in events if e.get("event") == kind and e.get("envelope") == envelope)


def judge(envelopes: list[dict]) -> list[str]:
    """Each envelope ends `completed` on exactly one sealed version that is served, or
    waits safely `completing` with a `job_dead` alert and nothing sealed served. Never
    two seals."""
    problems = []
    for e in envelopes:
        name = f"{e['label']} ({e['id']})"
        if e["sealed_versions"] > 1:
            problems.append(f"{name}: sealed {e['sealed_versions']} times")
        if e["status"] == "completed":
            if e["sealed_versions"] != 1:
                problems.append(f"{name}: completed with {e['sealed_versions']} sealed versions")
            if not e["sealed_served"]:
                problems.append(f"{name}: completed but its sealed PDF is not served")
        elif e["status"] == "completing":
            if not e["job_dead_alerts"]:
                problems.append(f"{name}: still completing with no job_dead alert")
            if e["sealed_served"]:
                problems.append(f"{name}: a sealed PDF is served while completing")
        else:
            problems.append(f"{name}: ended {e['status']}")
    return problems


def manifest_tsv(names: list[str]) -> str:
    """tools/verify-sealed.py's manifest: every file must validate, whole and intact."""
    rows = ["file\texpect\twhy"] + [f"{n}\tintact\tHRD-10 chaos run, sealed on the production profile" for n in names]
    return "\n".join(rows) + "\n"


def need_uuid(value: str) -> str:
    """An id from the API, checked before it goes into SQL."""
    if not UUID.match(value or ""):
        raise ChaosError(f"not an id: {value[:40]!r}")
    return value


class Cookies:
    """A browser's cookies, sent over the plain-HTTP hop to the server's loopback port
    as the edge proxy would forward them. (The profile's cookies are `Secure` and
    `__Host-`, which Python's cookie jar keeps off plain HTTP.)"""

    def __init__(self) -> None:
        self.jar: dict[str, str] = {}

    def take(self, set_cookies: list[str]) -> None:
        for sc in set_cookies:
            parts = [p.strip() for p in sc.split(";")]
            if not parts or "=" not in parts[0]:
                continue
            name, value = parts[0].split("=", 1)
            expired = any(p.lower() == "max-age=0" for p in parts[1:])
            if expired or value == "":
                self.jar.pop(name, None)
            else:
                self.jar[name] = value

    def header(self) -> str | None:
        return "; ".join(f"{k}={v}" for k, v in self.jar.items()) or None


# ------------------------------------------------------------------ the TSA gate


class TsaGate:
    """A TCP gate: each connection that sends a request is counted, logged and held
    `delay` seconds before it is forwarded to `target`. A connection that sends nothing
    (a health check) is closed uncounted."""

    def __init__(self, listen: tuple[str, int], target: tuple[str, int], delay: float, log=None):
        self.target, self.delay = target, delay
        self.log = log or (lambda m: print(m, flush=True))
        self.count = 0
        self.lock = threading.Lock()
        self.sock = socket.create_server(listen, reuse_port=False)
        self.addr = self.sock.getsockname()

    def serve_forever(self) -> None:
        while True:
            try:
                client, _ = self.sock.accept()
            except OSError:
                return
            threading.Thread(target=self._one, args=(client,), daemon=True).start()

    def close(self) -> None:
        self.sock.close()

    def _one(self, client: socket.socket) -> None:
        try:
            client.settimeout(30)
            first = client.recv(65536)
            if not first:
                client.close()
                return
            with self.lock:
                self.count += 1
                n = self.count
            self.log(f"tsa-gate: connection {n}")
            time.sleep(self.delay)
            upstream = socket.create_connection(self.target, timeout=30)
            upstream.sendall(first)
        except OSError:
            client.close()
            return

        def pipe(a: socket.socket, b: socket.socket) -> None:
            try:
                while True:
                    data = a.recv(65536)
                    if not data:
                        break
                    b.sendall(data)
            except OSError:
                pass
            for s in (a, b):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        t = threading.Thread(target=pipe, args=(client, upstream), daemon=True)
        t.start()
        pipe(upstream, client)
        t.join(5)
        client.close()
        upstream.close()


def hostport(s: str) -> tuple[str, int]:
    host, _, port = s.rpartition(":")
    return host, int(port)


# ------------------------------------------------------------------ Docker


class Compose:
    def __init__(self, env: dict[str, str]):
        self.env = {**os.environ, **env}

    def argv(self, *args: str) -> list[str]:
        return ["docker", "compose", "-p", PROJECT, "-f", str(PROFILE), "-f", str(OVERRIDE), *args]

    def run(self, *args: str, input: bytes | None = None, check: bool = True, timeout: float = 1800) -> subprocess.CompletedProcess:
        return sh(self.argv(*args), env=self.env, input=input, check=check, timeout=timeout)

    def out(self, *args: str, **kw) -> str:
        return self.run(*args, **kw).stdout.decode("utf-8", "replace")

    def sql(self, query: str) -> str:
        script = ('PGPASSWORD="$(cat /run/secrets/postgres-password)" exec psql -X -At -v ON_ERROR_STOP=1 '
                  '-h /var/run/postgresql -U postgres -d openseal -c "$1"')
        return self.out("exec", "-T", "postgres", "sh", "-c", script, "sh", query, timeout=60).strip()

    def scalar(self, query: str) -> int:
        v = self.sql(query)
        try:
            return int(v.splitlines()[-1]) if v else 0
        except ValueError:
            raise ChaosError(f"not a number from SQL: {v[:60]!r}") from None

    def containers(self, service: str) -> list[str]:
        return self.out("ps", "-a", "-q", service).split()

    def logs(self, service: str) -> str:
        return self.out("logs", "--no-color", "--no-log-prefix", service, check=False, timeout=120)


def sh(argv: list[str], *, env=None, input: bytes | None = None, check: bool = True, timeout: float = 1800) -> subprocess.CompletedProcess:
    extra = {"input": input} if input is not None else {"stdin": subprocess.DEVNULL}
    p = subprocess.run(argv, env=env, capture_output=True, timeout=timeout, check=False, **extra)
    if check and p.returncode != 0:
        tail = p.stderr.decode("utf-8", "replace").strip().splitlines()[-5:]
        raise ChaosError(f"`{' '.join(argv[:6])} …` exited {p.returncode}: {' | '.join(tail)}")
    return p


def inspect(cid: str, fmt: str) -> str:
    return sh(["docker", "inspect", "-f", fmt, cid], timeout=60).stdout.decode().strip()


def until(what: str, timeout: float, probe, every: float = 2.0):
    deadline = time.monotonic() + timeout
    while True:
        got = probe()
        if got:
            return got
        if time.monotonic() > deadline:
            raise ChaosError(f"{what}: not within {timeout:.0f} s")
        time.sleep(every)


def host_kill(cid: str) -> None:
    """SIGKILL the container's process from the host's PID namespace (as the kernel's
    OOM killer would): Docker sees a crash, not a stop, so the restart policy applies."""
    pid = inspect(cid, "{{.State.Pid}}")
    if not pid.isdigit() or pid == "0":
        raise ChaosError(f"container {cid[:12]} has no process")
    sh(["docker", "run", "--rm", "--pid=host", "--entrypoint", "sh", DEVTOOLS, "-c", f"kill -9 {pid}"], timeout=120)


def container_logs(cid: str) -> str:
    p = sh(["docker", "logs", cid], timeout=120)
    return (p.stdout + p.stderr).decode("utf-8", "replace")


def wait_healthy(cids: list[str], timeout: float = 180) -> None:
    for cid in cids:
        until(f"container {cid[:12]} healthy", timeout, lambda c=cid: inspect(c, "{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}") in ("healthy", "running"))


# ------------------------------------------------------------------ the API


class Api:
    """One browser or API client: its own cookies and CSRF token."""

    def __init__(self, base: str):
        self.base = base.rstrip("/")
        self.cookies = Cookies()
        self.csrf: str | None = None

    def request(self, method: str, path: str, body=None, headers=None, timeout: float = 60) -> tuple[int, bytes]:
        data = None if body is None else json.dumps(body).encode()
        h = {"Accept": "application/json"}
        if data is not None:
            h["Content-Type"] = "application/json"
        if self.csrf:
            h["X-CSRF-Token"] = self.csrf
        c = self.cookies.header()
        if c:
            h["Cookie"] = c
        h.update(headers or {})
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=h)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                self.cookies.take(r.headers.get_all("Set-Cookie") or [])
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            self.cookies.take(e.headers.get_all("Set-Cookie") or [])
            return e.code, e.read()
        except (urllib.error.URLError, OSError) as e:
            return 0, str(e).encode()

    def call(self, method: str, path: str, body=None, *, ok=(200, 201), headers=None, raw=False):
        status, payload = self.request(method, path, body, headers)
        if status not in ok:
            code = ""
            try:
                code = json.loads(payload).get("code", "")
            except (ValueError, AttributeError):
                pass
            raise ChaosError(f"{method} {path.split('?')[0][:48]}: HTTP {status} {code}")
        if raw:
            return payload
        return json.loads(payload) if payload else {}

    def status(self, path: str) -> int:
        return self.request("GET", path)[0]


def one_page_pdf() -> bytes:
    sys.path.insert(0, str(ROOT / "tools" / "backup"))
    import drill_flow  # the restore drill's PDF and Mailpit reader (tools/backup)

    return drill_flow.pdf()


def signing_path(mail: str, to: str) -> str:
    sys.path.insert(0, str(ROOT / "tools" / "backup"))
    import drill_flow

    try:
        return drill_flow.signing_path(mail, to, timeout=180)
    except drill_flow.DrillError as e:
        raise ChaosError(str(e)) from None


class Ceremony:
    """One signer through the emailed link: session, access code, viewed, adopted; the
    finish is sent by the scenario, at the moment it chooses."""

    def __init__(self, base: str, path: str, field: str):
        self.api, self.path = Api(base), path
        view = self.api.call("POST", f"{path}/session", {})
        self._consent(view)
        v = self.api.call("POST", f"{path}/authenticate", {"method": "access_code", "code": ACCESS_CODE})
        self._consent(v)
        doc = v["envelope"]["documents"][0]["id"]
        self.api.call("POST", f"{path}/documents/{doc}/viewed", {"pages_seen": [1]})
        a = self.api.call("POST", f"{path}/adopt", {"mark": "signature", "method": "draw", "image_base64": PNG})
        self.body = {"values": [{"field": field, "value": {"signature": a["adoption_id"]}}]}

    def _consent(self, view: dict) -> None:
        need = view.get("consent_required")
        if need:
            self.api.call("POST", f"{self.path}/consent", {"ersd_version": need["version"]})

    def finish(self) -> int:
        return self.api.request("POST", f"{self.path}/finish", self.body)[0]


# ------------------------------------------------------------------ the run


class Run:
    def __init__(self, args):
        self.work = (ROOT / "target" / "chaos-compose").resolve()
        self.hsm = self.work / "hsm"
        self.compose = Compose(compose_env(self.work, self.hsm, args.tsa_delay))
        self.base, self.mail = f"http://127.0.0.1:{HTTP_PORT}", f"http://127.0.0.1:{MAIL_PORT}"
        self.args = args
        self.problems: list[str] = []
        self.envelopes: dict[str, str] = {}
        self.scenarios: list[dict] = []
        self.staff: Api | None = None
        self.run_tag = str(time.time_ns())
        self.started = time.monotonic()

    # ---- setup

    def helper(self, script: str, *args: str, input: bytes | None = None) -> None:
        """A shell in the devtools image, as root, with the checkout and the work folder."""
        sh(["docker", "run", "--rm", "-i", "-v", f"{ROOT}:/repo:ro", "-v", f"{self.work}:{self.work}",
            "--entrypoint", "sh", DEVTOOLS, "-c", script, "sh", *args], input=input, timeout=600)

    def setup(self) -> None:
        c = self.compose
        if self.args.build:
            say("building the images from this checkout")
            sh(["docker", "compose", "-f", str(ROOT / "docker-compose.yml"), "build", "pki", "keyd", "migrate", "worker"], timeout=5400)
        say("secrets: init-secrets.sh and the CI seal PKI")
        self.helper('sh /repo/tools/chaos/prepare-secrets.sh "$1" "$2"', str(self.work), str(os.getuid()))
        say("the PKCS#11 module, taken from the keyd image as an HSM vendor's would be installed")
        self.hsm.mkdir(parents=True, exist_ok=True)
        sh(["docker", "rm", "-f", "openseal-chaos-hsm"], check=False)
        sh(["docker", "create", "--name", "openseal-chaos-hsm", "openseal-keyd:dev"])
        try:
            sh(["docker", "cp", "-L", "openseal-chaos-hsm:/usr/lib/softhsm/libsofthsm2.so", str(self.hsm / "libsofthsm2.so")])
        finally:
            sh(["docker", "rm", "-f", "openseal-chaos-hsm"], check=False)
        say("the seal key into a SoftHSM token in keyd's volume")
        token = (
            'set -eu; mkdir -p /var/lib/keyd/tokens; '
            "printf 'directories.tokendir = /var/lib/keyd/tokens\\nobjectstore.backend = file\\nlog.level = ERROR\\n' > \"$SOFTHSM2_CONF\"; "
            'cat > /tmp/seal.key; pin="$(cat /run/secrets/keyd-pkcs11-pin)"; '
            'so="$(od -An -tx1 -N8 /dev/urandom | tr -d " \\n")"; '
            'softhsm2-util --init-token --free --label "$OPENSEAL_KEYD_PKCS11_TOKEN" --so-pin "$so" --pin "$pin" >/dev/null; '
            'softhsm2-util --import /tmp/seal.key --token "$OPENSEAL_KEYD_PKCS11_TOKEN" '
            '--label "$OPENSEAL_KEYD_PKCS11_KEY_LABEL" --id 01 --pin "$pin" >/dev/null; rm -f /tmp/seal.key'
        )
        c.run("run", "--rm", "--no-deps", "-T", "--entrypoint", "sh", "keyd", "-c", token,
              input=(self.work / "pki" / "seal.key").read_bytes(), timeout=600)
        (self.work / "pki" / "seal.key").unlink()
        say("configuration manifests recorded (docs/65 §Configuration integrity)")
        for svc in ("keyd", "worker"):
            manifest = c.run("run", "--rm", "--no-deps", "-T", svc, "config-manifest", timeout=600).stdout
            if not manifest.strip():
                raise ChaosError(f"{svc} printed an empty configuration manifest")
            target = f"{self.work}/secrets/{svc}-config-manifest"
            self.helper('cat > "$1" && chmod 0444 "$1"', target, input=manifest)
        say("the production profile up")
        c.run("up", "-d", "--wait", "--quiet-pull", timeout=1200)
        c.run("up", "-d", "--no-deps", "--no-recreate", "--wait", "--scale", "worker=2", "worker", timeout=600)
        password = "chaos-only-passphrase-" + self.run_tag
        email = "chaos@openseal.chaos.test"
        c.run("exec", "-T", "-e", f"OPENSEAL_ADMIN_PASSWORD={password}", "server",
              "casual-sign-server", "bootstrap", "Chaos", email, "Chaos Admin", timeout=120)
        self.staff = Api(self.base)
        r = self.staff.call("POST", "/api/v1/auth/login", {"email": email, "password": password})
        self.staff.csrf = r["csrf_token"]

    # ---- helpers

    def check(self, cond: bool, msg: str) -> None:
        if not cond:
            self.problems.append(msg)
            say(f"PROBLEM: {msg}")

    def create(self, label: str) -> tuple[str, str, str]:
        email = f"{label}-{self.run_tag}@example.com"
        body = {
            "subject": f"Chaos {label}",
            "status": "sent",
            "documents": [{"name": "chaos.pdf", "content_base64": base64.b64encode(one_page_pdf()).decode()}],
            "recipients": [{"ref": "r0", "type": "signer", "name": "Chaos Signer", "email": email, "routing_order": 1,
                            "auth": ["access_code"], "access_code": ACCESS_CODE}],
            "fields": [{"recipient": "r0", "document": 0, "type": "signature", "page": 1, "x": 72, "y": 100,
                        "width": 180, "height": 40, "required": True}],
        }
        e = self.staff.call("POST", "/api/v1/envelopes", body, headers={"Idempotency-Key": f"chaos-{label}-{self.run_tag}"})
        eid = need_uuid(e["id"])
        self.envelopes[label] = eid
        return eid, e["fields"][0]["id"], email

    def ceremony(self, label: str) -> tuple[str, Ceremony]:
        eid, field, email = self.create(label)
        return eid, Ceremony(self.base, signing_path(self.mail, email), field)

    def finish(self, label: str, cer: Ceremony) -> None:
        st = cer.finish()
        if st != 200:
            raise ChaosError(f"{label}: finish answered {st}")

    def gate_count(self) -> int:
        return self.compose.logs("tsa-gate").count("tsa-gate: connection")

    def wait_gate(self, before: int, what: str) -> None:
        until(f"{what}: a seal reaching the TSA", 120, lambda: self.gate_count() > before, every=0.5)

    def status(self, eid: str) -> str:
        return self.staff.call("GET", f"/api/v1/envelopes/{eid}")["status"]

    def worker_events(self) -> list[dict]:
        return log_events(self.compose.logs("worker"))

    def wait_done(self, eid: str, timeout: float = LEASE_WAIT) -> str:
        """`completed`, or a `job_dead` for it; meanwhile queued retries are made due."""
        def probe():
            self.make_due()
            try:
                s = self.status(eid)
            except ChaosError:
                return None  # the server answering 5xx while a dependency recovers
            if s == "completed" or alerts_for(self.worker_events(), "job_dead", eid):
                return s
            return None
        return until(f"envelope {eid} completed", timeout, probe, every=5)

    def make_due(self) -> None:
        try:
            self.compose.sql("UPDATE jobs SET run_at = now() WHERE status = 'queued' AND run_at > now()")
        except ChaosError:
            pass  # the database is the thing that is down

    def seal_jobs(self, eid: str, cond: str) -> int:
        return self.compose.scalar(f"SELECT count(*) FROM jobs WHERE kind = 'seal_envelope' AND envelope_id = '{need_uuid(eid)}' AND {cond}")

    def not_served(self, eid: str, what: str) -> None:
        self.check(self.status(eid) != "completed", f"{what}: completed while its dependency was down")
        e = self.staff.call("GET", f"/api/v1/envelopes/{eid}")
        doc = e["documents"][0]["id"]
        for path in (f"/api/v1/envelopes/{eid}/documents/{doc}/content?version=sealed", f"/api/v1/envelopes/{eid}/certificate"):
            st = self.staff.status(path)
            self.check(400 <= st < 500, f"{what}: {path.split('?')[0].rsplit('/', 1)[-1]} answered {st} before the seal")

    def scenario(self, name: str, fn) -> None:
        say(f"== {name}")
        t0, before = time.monotonic(), len(self.problems)
        note: dict = {}
        try:
            fn(note)
        except (ChaosError, KeyError, IndexError, TypeError, ValueError, OSError, subprocess.TimeoutExpired) as e:
            self.problems.append(f"{name}: {e}")
            say(f"PROBLEM: {name}: {e}")
        self.scenarios.append({"name": name, "seconds": round(time.monotonic() - t0, 1),
                               "passed": len(self.problems) == before, **note})

    # ---- the cases

    def paused_and_killed(self, note: dict) -> None:
        """1-3: worker A paused mid-seal past its lease; worker B killed mid-seal and
        right after a finish; all three envelopes then complete."""
        c = self.compose
        workers = c.containers("worker")
        if len(workers) != 2:
            raise ChaosError(f"{len(workers)} workers running, not 2")
        a, b = workers
        sh(["docker", "stop", b])  # A alone claims the first seal job
        eid1, cer1 = self.ceremony("paused")
        before = self.gate_count()
        self.finish("paused", cer1)
        self.wait_gate(before, "paused")
        sh(["docker", "pause", a])
        note["paused_at"] = "worker A in the TSA call, mid-seal"
        sh(["docker", "start", b])
        wait_healthy([b])
        # 2: B killed mid-seal; Docker must restart it.
        eid2, cer2 = self.ceremony("killed")
        restarts = int(inspect(b, "{{.RestartCount}}"))
        before = self.gate_count()
        self.finish("killed", cer2)
        self.wait_gate(before, "killed")
        host_kill(b)
        until("the restart policy restarting worker B", 120,
              lambda: inspect(b, "{{.RestartCount}} {{.State.Running}}") == f"{restarts + 1} true")
        note["restart_policy"] = "worker B restarted by Docker after SIGKILL"
        wait_healthy([b])
        # 3: B killed again right after a finish, before or while it claims.
        eid3, cer3 = self.ceremony("killed-early")
        restarts = int(inspect(b, "{{.RestartCount}}"))
        self.finish("killed-early", cer3)
        host_kill(b)
        until("the restart policy restarting worker B again", 120,
              lambda: inspect(b, "{{.RestartCount}} {{.State.Running}}") == f"{restarts + 1} true")
        # B seals all three once their leases lapse; A is still frozen.
        for eid in (eid1, eid2, eid3):
            self.check(self.wait_done(eid) == "completed", f"envelope {eid} did not complete after the worker failures")
        self.check(self.seal_jobs(eid1, "attempts >= 2") == 1, "paused: the seal job was not attempted by both workers")
        # A wakes holding a lease it lost: it must store nothing.
        job = self.compose.sql(f"SELECT id FROM jobs WHERE kind = 'seal_envelope' AND envelope_id = '{eid1}' ORDER BY created_at LIMIT 1")
        sh(["docker", "unpause", a])
        failed = until("worker A failing its stale seal job", 180,
                       lambda: [e for e in log_events(container_logs(a))
                                if e.get("event") == "job_failed" and e.get("job") == job.strip()])
        note["stale_worker_failed_with"] = failed[-1].get("code")
        stored = self.compose.scalar(
            f"SELECT count(*) FROM job_steps s JOIN jobs j ON j.id = s.job_id WHERE j.envelope_id = '{eid1}' AND s.step = 'seal.stored'")
        self.check(stored == 1, f"paused: {stored} seal.stored steps, not 1")
        wait_healthy([a])

    def keyd_down(self, note: dict) -> None:
        c = self.compose
        eid, cer = self.ceremony("keyd")
        c.run("stop", "keyd", timeout=120)
        self.finish("keyd", cer)
        until("a seal_failed alert while keyd is down", 240,
              lambda: alerts_for(self.worker_events(), "seal_failed", eid), every=3)
        self.not_served(eid, "keyd down")
        # Workers started while keyd is down stay up.
        c.run("restart", "worker", timeout=180)
        time.sleep(20)
        for w in c.containers("worker"):
            self.check(inspect(w, "{{.State.Running}} {{.State.Restarting}}") == "true false",
                       f"keyd down: worker {w[:12]} did not stay up")
        note["keyd_unavailable_logged"] = sum(1 for e in self.worker_events() if e.get("event") == "keyd_unavailable")
        self.not_served(eid, "keyd still down")
        c.run("start", "keyd", timeout=120)
        wait_healthy(c.containers("keyd"))
        self.check(self.wait_done(eid) == "completed", "keyd: not completed after keyd returned")

    def postgres_ceremony(self, note: dict) -> None:
        c = self.compose
        eid, cer = self.ceremony("postgres-ceremony")
        c.run("stop", "-t", "0", "postgres", timeout=120)
        st = cer.finish()
        note["finish_during_outage"] = st
        self.check(st >= 500, f"postgres-ceremony: a finish during the outage answered {st}")
        self.check(self.staff.status(f"/api/v1/envelopes/{eid}") >= 500, "postgres-ceremony: a read during the outage did not fail")
        self.check(inspect(c.containers("server")[0], "{{.State.Running}}") == "true", "postgres-ceremony: the server exited")
        c.run("start", "postgres", timeout=120)
        wait_healthy(c.containers("postgres"))
        until("the server answering after the outage", 120, lambda: self.staff.status(f"/api/v1/envelopes/{eid}") == 200)
        st = until("the retried finish", 120, lambda: cer.finish() == 200 or None)
        signed = c.scalar(f"SELECT count(*) FROM audit_events WHERE envelope_id = '{eid}' AND event_type = 'recipient.signed'")
        self.check(signed == 1, f"postgres-ceremony: recipient.signed recorded {signed} times")
        self.check(self.wait_done(eid) == "completed", "postgres-ceremony: not completed")

    def postgres_seal(self, note: dict) -> None:
        c = self.compose
        eid, cer = self.ceremony("postgres-seal")
        before = self.gate_count()
        self.finish("postgres-seal", cer)
        self.wait_gate(before, "postgres-seal")
        c.run("stop", "-t", "0", "postgres", timeout=120)
        time.sleep(10)
        c.run("start", "postgres", timeout=120)
        wait_healthy(c.containers("postgres"))
        for w in c.containers("worker"):
            self.check(inspect(w, "{{.State.Running}}") == "true", f"postgres-seal: worker {w[:12]} not running")
        self.check(self.wait_done(eid) == "completed", "postgres-seal: not completed")

    def object_store(self, note: dict) -> None:
        c = self.compose
        eid, cer = self.ceremony("object-store")
        before = self.gate_count()
        self.finish("object-store", cer)
        self.wait_gate(before, "object-store")
        c.run("stop", "-t", "0", "s3", timeout=120)
        until("the seal job failing on the store", 180,
              lambda: self.seal_jobs(eid, "status = 'queued' AND last_error_code IS NOT NULL"), every=3)
        note["seal_failed_with"] = c.sql(f"SELECT last_error_code FROM jobs WHERE kind = 'seal_envelope' AND envelope_id = '{eid}' AND status = 'queued'")
        self.not_served(eid, "object store down")
        self.check(c.scalar(f"SELECT count(*) FROM document_versions v JOIN documents d ON d.id = v.document_id "
                            f"WHERE d.envelope_id = '{eid}' AND v.kind = 'sealed'") == 0, "object store down: a sealed version recorded")
        # A long outage: the job's last attempt hands over to a new seal job.
        c.sql(f"UPDATE jobs SET attempts = max_attempts - 1, run_at = now() WHERE kind = 'seal_envelope' "
              f"AND envelope_id = '{eid}' AND status = 'queued'")
        until("the last attempt", 180, lambda: self.seal_jobs(eid, "status IN ('done', 'dead')"), every=3)
        self.check(self.seal_jobs(eid, "status = 'dead'") == 0, "object store: the seal job dead-lettered")
        self.check(self.seal_jobs(eid, "status = 'queued'") == 1, "object store: no new seal job after the last attempt")
        self.not_served(eid, "after the last attempt")
        c.run("start", "s3", timeout=120)
        wait_healthy(c.containers("s3"))
        self.check(self.wait_done(eid) == "completed", "object store: not completed after the store returned")

    def restore_everything(self) -> None:
        """Whatever a failed scenario left down comes back before the final checks."""
        c = self.compose
        for svc in ("postgres", "s3", "keyd"):
            c.run("start", svc, check=False, timeout=120)
        for w in c.containers("worker"):
            sh(["docker", "unpause", w], check=False)
        try:
            wait_healthy(c.containers("postgres") + c.containers("s3") + c.containers("keyd"))
        except ChaosError as e:
            self.problems.append(str(e))

    # ---- the verdict

    def verdict(self) -> list[dict]:
        c = self.compose
        events = self.worker_events()
        sealed_dir = self.work / "sealed"
        sealed_dir.mkdir(parents=True, exist_ok=True)
        rows, names = [], []
        for label, eid in self.envelopes.items():
            e = self.staff.call("GET", f"/api/v1/envelopes/{eid}")
            doc = e["documents"][0]["id"]
            st, pdf = self.staff.request("GET", f"/api/v1/envelopes/{eid}/documents/{doc}/content?version=sealed",
                                         headers={"Accept": "application/pdf"})
            served = st == 200 and pdf.startswith(b"%PDF-")
            if served:
                (sealed_dir / f"{label}.pdf").write_bytes(pdf)
                names.append(f"{label}.pdf")
            row = {
                "label": label, "id": eid, "status": e["status"],
                "sealed_versions": c.scalar(f"SELECT count(*) FROM document_versions v JOIN documents d ON d.id = v.document_id "
                                            f"WHERE d.envelope_id = '{eid}' AND v.kind = 'sealed'"),
                "sealed_served": served,
                "job_dead_alerts": alerts_for(events, "job_dead", eid),
                "seal_failed_alerts": alerts_for(events, "seal_failed", eid),
                "seal_jobs": self.seal_jobs(eid, "true"),
            }
            if e["status"] == "completed":
                for what in ("certificate", "audit"):
                    self.check(self.staff.status(f"/api/v1/envelopes/{eid}/{what}") == 200, f"{label}: {what} not served")
            rows.append(row)
        self.problems += judge(rows)
        self.check(bool(rows), "no envelope was sent")
        # Every audit chain, admin log and operator log, and every blob they name.
        ev = c.run("--profile", "chaos-tools", "run", "--rm", "-T", "evidence", check=False, timeout=600)
        (self.work / "evidence.txt").write_bytes(ev.stdout + ev.stderr)
        self.check(ev.returncode == 0, f"verify-evidence exited {ev.returncode}")
        op = c.run("exec", "-T", "keyd", "casual-sign-keyd", "verify-oplog", "/var/lib/keyd/oplog", check=False, timeout=120)
        (self.work / "oplog.txt").write_bytes(op.stdout + op.stderr)
        self.check(op.returncode == 0, f"keyd's operation log did not verify (exit {op.returncode})")
        # pyHanko over every sealed PDF, against the chaos root (seal and TSA).
        (sealed_dir / "trust-root.pem").write_bytes((self.work / "pki" / "trust-root.pem").read_bytes())
        (sealed_dir / "manifest.tsv").write_text(manifest_tsv(names), encoding="utf-8")
        vs = sh([self.args.verify_python, "-I", str(ROOT / "tools" / "verify-sealed.py"), str(sealed_dir)], check=False, timeout=600)
        (self.work / "verify-sealed.txt").write_bytes(vs.stdout + vs.stderr)
        self.check(vs.returncode == 0, f"tools/verify-sealed.py exited {vs.returncode} over {len(names)} sealed PDFs")
        return rows

    def teardown(self) -> None:
        if self.work.exists():
            logs = self.compose.run("logs", "--no-color", check=False, timeout=300)
            (self.work / "compose.log").write_bytes(logs.stdout + logs.stderr)
        self.compose.run("--profile", "chaos-tools", "down", "-v", "--remove-orphans", check=False, timeout=600)
        if self.work.exists():
            # Root-owned secrets and the CI PKI go; the report, logs and sealed PDFs stay.
            sh(["docker", "run", "--rm", "-v", f"{self.work}:{self.work}", "--entrypoint", "sh", DEVTOOLS, "-c",
                'rm -rf "$1/secrets" "$1/pki" "$1/hsm"', "sh", str(self.work)], check=False, timeout=120)

    def main(self) -> int:
        if self.work.exists():
            sh(["docker", "run", "--rm", "-v", f"{self.work.parent}:{self.work.parent}", "--entrypoint", "sh", DEVTOOLS, "-c",
                'rm -rf "$1"', "sh", str(self.work)], check=False, timeout=120)
            if self.work.exists():
                raise ChaosError(f"{self.work} could not be cleared")
        self.compose.run("--profile", "chaos-tools", "down", "-v", "--remove-orphans", check=False, timeout=600)
        self.work.mkdir(parents=True)
        rows: list[dict] = []
        try:
            self.setup()
            self.scenario("worker paused past its lease, killed mid-seal and after a finish", self.paused_and_killed)
            self.restore_everything()
            self.scenario("keyd down while sealing", self.keyd_down)
            self.restore_everything()
            self.scenario("PostgreSQL killed mid-ceremony", self.postgres_ceremony)
            self.restore_everything()
            self.scenario("PostgreSQL killed mid-seal", self.postgres_seal)
            self.restore_everything()
            self.scenario("object store down mid-seal through the last attempt", self.object_store)
            self.restore_everything()
            rows = self.verdict()
        except (ChaosError, KeyError, IndexError, TypeError, ValueError, OSError, subprocess.TimeoutExpired) as e:
            self.problems.append(f"setup or verdict: {e}")
        finally:
            report = {"seconds": round(time.monotonic() - self.started), "scenarios": self.scenarios,
                      "envelopes": rows, "problems": self.problems}
            (self.work / "report.json").write_text(json.dumps(report, indent=1, sort_keys=True) + "\n", encoding="utf-8")
            self.teardown()
        if self.problems:
            say("FAILED:")
            for p in self.problems:
                say(f"  {p}")
            return 1
        say(f"passed: {len(rows)} envelopes, each completed and sealed once; evidence, keyd's log and pyHanko agree "
            f"({self.work / 'report.json'})")
        return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="chaos_compose.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--no-build", dest="build", action="store_false")
    r.add_argument("--verify-python", default=os.environ.get("OPENSEAL_VERIFY_PYTHON", sys.executable))
    r.add_argument("--tsa-delay", type=float, default=6.0)
    g = sub.add_parser("tsa-gate")
    g.add_argument("--listen", required=True)
    g.add_argument("--target", required=True)
    g.add_argument("--delay", type=float, required=True)
    args = ap.parse_args(argv)
    if args.cmd == "tsa-gate":
        gate = TsaGate(hostport(args.listen), hostport(args.target), args.delay)
        print(f"tsa-gate: listening, {args.delay:g} s hold", flush=True)
        gate.serve_forever()
        return 0
    try:
        return Run(args).main()
    except ChaosError as e:
        say(f"FAILED: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
