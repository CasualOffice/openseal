#!/usr/bin/env python3
"""Load and chaos numbers on the hardened Compose profile (HRD-04; docs/65 §Load and
recovery numbers; workflow `.github/workflows/load.yml`).

    python3 -I tools/load/load_compose.py run [--no-build] [--verify-python PY]
        [--senders N] [--signers N] [--in-flight N] [--warmup S] [--baseline S]
        [--hold S] [--recover-timeout S] [--cases worker,keyd,postgres]

`run` needs Docker with Compose v2 on Linux (a GitHub runner). It brings up exactly the
stack the chaos run does (tools/chaos/chaos_compose.py: deploy/compose.production.yml
built from this checkout, throwaway secrets, SoftHSM as the PKCS#11 token, two workers,
the CI-only tools/chaos/compose.chaos.yml) with the TSA gate holding nothing, plus
tools/load/compose.load.yml (the mail sink keeps every message). Then:

- senders create and send envelopes through the API (one signer, an access code, one
  signature field), never more than --in-flight agreements open at once (a closed loop:
  a slot frees when the envelope is sealed, so a stalled seal slows the senders as it
  would a real organization's queue);
- signers take each envelope's link from the e-mail, open the session, authenticate
  with the access code, consent, view, adopt and finish, each request carrying its own
  client address as the trusted edge proxy would forward it (so the per-address ceremony
  limit counts per signer, as in production);
- the workers seal.

After --warmup seconds of load, --baseline seconds are the steady state. Then, under the
same load, each chaos case in turn: every worker SIGKILLed from the host's PID namespace
(Docker's restart policy brings them back; jobs they held wait for their lease, 300 s);
keyd stopped for --hold seconds; PostgreSQL killed (`stop -t 0`) for --hold seconds.
After each, load continues until throughput is back and every envelope sent before the
service returned is sealed, or --recover-timeout. Then the senders stop and every
envelope must complete. Nothing is made due early: back-offs and leases run in real time,
so recovery times are what an operator would see.

Numbers come from the server's own timestamps wherever it records one: the audit trail's
`envelope.sent`, `recipient.signed`, `envelope.completing` and `envelope.completed`
events and the invitation job's `finished_at`. The send and sign requests have no server
start time, so their latencies are the driver's round trips over loopback. Throughput is
completed envelopes per minute, from `envelope.completed`.

The verdict: every envelope `completed` with exactly one sealed version (never two),
every case recovered within --recover-timeout, `verify-evidence` and keyd's
`verify-oplog` pass, and pyHanko (tools/verify-sealed.py) validates a sample of the
sealed PDFs. Writes target/load-compose/report.json and report.md and exits non-zero
naming each problem. The stack, its volumes and the secrets are removed however it ends.

Standard library only. Prints ids, codes and counts, never document text.
"""

from __future__ import annotations

import argparse
import base64
import json
import math
import os
import pathlib
import platform
import queue
import subprocess
import sys
import threading
import time

TOOLS = pathlib.Path(__file__).resolve().parent
ROOT = TOOLS.parent.parent
sys.path.insert(0, str(ROOT / "tools" / "chaos"))
sys.path.insert(0, str(ROOT / "tools" / "backup"))

import chaos_compose as cc  # noqa: E402  the chaos run's stack, API client and checks
import drill_flow  # noqa: E402  the restore drill's PDF and Mailpit reader

PROJECT = "openseal-load"
LOAD_OVERRIDE = TOOLS / "compose.load.yml"
SUBJECT = "Load"
# The edge proxy is trusted as in production; Docker's default address pools are where
# the published port's connections come from on the runner.
TRUSTED_PROXIES = "127.0.0.1/32,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
CASES = ("worker", "keyd", "postgres")
WINDOW = 60.0  # seconds: the throughput window recovery is judged on
RECOVERED_FRACTION = 0.8  # of the baseline rate


def say(msg: str) -> None:
    print(f"load: {msg}", file=sys.stderr, flush=True)


# ------------------------------------------------------------------ pure logic (unit tested)


def percentile(values: list[float], p: float) -> float | None:
    """The p-th percentile (0-100), linear between closest ranks (as numpy's default)."""
    if not values:
        return None
    if not 0 <= p <= 100:
        raise ValueError(f"percentile {p} outside 0-100")
    xs = sorted(values)
    k = (len(xs) - 1) * p / 100
    lo, hi = math.floor(k), math.ceil(k)
    return xs[lo] + (xs[hi] - xs[lo]) * (k - lo)


def summarize(values: list[float]) -> dict:
    """Count, p50, p95, p99 and max, in seconds rounded to milliseconds."""
    def r(v):
        return None if v is None else round(v, 3)
    return {"n": len(values), "p50": r(percentile(values, 50)), "p95": r(percentile(values, 95)),
            "p99": r(percentile(values, 99)), "max": r(max(values) if values else None)}


def per_minute(times: list[float], start: float, end: float) -> float | None:
    """Events per minute in [start, end)."""
    if end <= start:
        return None
    return round(sum(1 for t in times if start <= t < end) * 60.0 / (end - start), 2)


def series(times: list[float], start: float, end: float, step: float = 60.0) -> list[int]:
    """Events per `step` bin from `start`, the last bin possibly partial."""
    n = max(0, math.ceil((end - start) / step))
    out = [0] * n
    for t in times:
        if start <= t < end:
            out[min(n - 1, int((t - start) // step))] += 1
    return out


def throughput_back(completed: list[float], since: float, now: float, baseline_epm: float,
                    window: float = WINDOW, fraction: float = RECOVERED_FRACTION) -> float | None:
    """The first completion at or after `since` from which a whole window [c, c + window)
    completed at least `fraction` of the baseline rate; None if none did by `now`."""
    need = max(1.0, fraction * baseline_epm * window / 60.0)
    ts = sorted(t for t in completed if t >= since)
    k = 0
    for j, c in enumerate(ts):
        if c + window > now:
            return None
        k = max(k, j)
        while k < len(ts) and ts[k] < c + window:
            k += 1
        if k - j >= need:
            return c
    return None


def recovery(case: dict, rows: list[dict], baseline_epm: float, now: float,
             window: float = WINDOW, fraction: float = RECOVERED_FRACTION) -> dict:
    """How long after the service returned (`restored`) throughput came back and every
    envelope sent before it was sealed. `rows` carry `sent` and `completed` (epoch
    seconds, `completed` None while open). Affected: sent before the return and not
    completed before the fault."""
    fault, restored = case["fault"], case["restored"]
    affected = [r for r in rows if r["sent"] is not None and r["sent"] <= restored
                and (r["completed"] is None or r["completed"] > fault)]
    open_ = [r for r in affected if r["completed"] is None]
    drained = None
    if not open_:
        last = max((r["completed"] for r in affected), default=restored)
        drained = round(max(0.0, last - restored), 1)
    back = throughput_back([r["completed"] for r in rows if r["completed"] is not None],
                           restored, now, baseline_epm, window, fraction)
    out = {"affected": len(affected), "unfinished": len(open_), "backlog_drained_s": drained,
           "throughput_back_s": None if back is None else round(back - restored, 1)}
    out["recovery_s"] = (None if drained is None or out["throughput_back_s"] is None
                         else max(drained, out["throughput_back_s"]))
    return out


def integrity(rows: list[dict]) -> list[str]:
    """Every envelope completed on exactly one sealed version; never two."""
    problems = []
    for r in rows:
        if r["sealed_versions"] > 1:
            problems.append(f"{r['id']}: sealed {r['sealed_versions']} times")
        if r["status"] != "completed":
            problems.append(f"{r['id']}: ended {r['status']}")
        elif r["sealed_versions"] != 1:
            problems.append(f"{r['id']}: completed with {r['sealed_versions']} sealed versions")
        elif r["completed"] is None:
            problems.append(f"{r['id']}: completed with no envelope.completed event")
    return problems


def parse_rows(text: str) -> list[dict]:
    """psql -At rows of ROWS_SQL: id|status|sent|signed|completing|completed|invited|sealed."""
    def num(s: str) -> float | None:
        return float(s) if s.strip() else None
    out = []
    for line in text.splitlines():
        f = line.split("|")
        if len(f) != 8:
            continue
        out.append({"id": cc.need_uuid(f[0]), "status": f[1], "sent": num(f[2]), "signed": num(f[3]),
                    "completing": num(f[4]), "completed": num(f[5]), "invited": num(f[6]),
                    "sealed_versions": int(f[7])})
    return out


def server_latencies(rows: list[dict]) -> dict:
    """From the audit trail and the job table: seal (completing -> completed), the
    invitation (sent -> its e-mail handed to SMTP) and the whole agreement (sent ->
    completed)."""
    def d(a, b):
        return [r[b] - r[a] for r in rows if r[a] is not None and r[b] is not None]
    return {"seal": summarize(d("completing", "completed")), "invitation": summarize(d("sent", "invited")),
            "end_to_end": summarize(d("sent", "completed"))}


def forwarded_for(n: int) -> str:
    """The n-th signer's client address, in 198.18.0.0/15 (RFC 2544, benchmarking)."""
    n %= 2 ** 17 - 2
    n += 1
    return f"198.{18 + n // 65536}.{(n // 256) % 256}.{n % 256}"


def verdict(report: dict, recover_timeout: float) -> list[str]:
    """The run's problems: integrity, an idle baseline, a case not recovered in time,
    and whatever the run recorded."""
    problems = list(report.get("problems", []))
    problems += integrity(report.get("envelopes", []))
    if not report.get("baseline", {}).get("completed"):
        problems.append("no envelope completed in the baseline window")
    for c in report.get("cases", []):
        rec = c.get("recovery") or {}
        if rec.get("recovery_s") is None:
            problems.append(f"{c['name']}: not recovered ({rec.get('unfinished', '?')} envelopes open, "
                            f"throughput back: {rec.get('throughput_back_s')})")
        elif rec["recovery_s"] > recover_timeout:
            problems.append(f"{c['name']}: recovered in {rec['recovery_s']} s, over {recover_timeout:g} s")
    return problems


def _cell(v) -> str:
    return "–" if v is None else (f"{v:g}" if isinstance(v, float) else str(v))


def markdown(report: dict) -> str:
    """The report as the table docs/65 publishes."""
    r, b = report["runner"], report["baseline"]
    lines = [
        f"OpenSeal load run, commit `{report.get('commit') or 'local'}`, {report.get('date', '')}",
        "",
        f"Runner: {r.get('label')} ({r.get('cpus')} CPUs, {r.get('memory_gib')} GiB), {r.get('os')}. "
        f"Hardened Compose profile, {report['config']['workers']} workers, "
        f"{report['config']['senders']} senders, {report['config']['signers']} signers, "
        f"at most {report['config']['in_flight']} agreements open.",
        "",
        "| Measure | Value |",
        "| --- | --- |",
        f"| Completed envelopes per minute (steady state, {b.get('seconds')} s) | {_cell(b.get('envelopes_per_minute'))} |",
        f"| Envelopes completed in the run | {report.get('completed', 0)} of {len(report.get('envelopes', []))} |",
        f"| Sealed twice | {report.get('sealed_twice', 0)} |",
        "",
        "| Latency (s), steady state | Source | n | p50 | p95 | p99 | max |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for name, src in (("send", "client round trip"), ("sign", "client round trip"), ("invitation", "server"),
                      ("seal", "server"), ("end_to_end", "server")):
        s = b.get("latency", {}).get(name) or {}
        lines.append(f"| {name.replace('_', ' ')} | {src} | {s.get('n', 0)} | {_cell(s.get('p50'))} | "
                     f"{_cell(s.get('p95'))} | {_cell(s.get('p99'))} | {_cell(s.get('max'))} |")
    lines += ["", "| Chaos case | Down for (s) | Affected | Throughput back (s) | Backlog sealed (s) | Recovery (s) |",
              "| --- | --- | --- | --- | --- | --- |"]
    for c in report.get("cases", []):
        rec = c.get("recovery") or {}
        lines.append(f"| {c['name']} | {_cell(c.get('down_s'))} | {_cell(rec.get('affected'))} | "
                     f"{_cell(rec.get('throughput_back_s'))} | {_cell(rec.get('backlog_drained_s'))} | "
                     f"{_cell(rec.get('recovery_s'))} |")
    lines += ["", f"Verdict: {'passed' if not report.get('verdict') else 'FAILED'}"]
    for p in report.get("verdict", [])[:50]:
        lines.append(f"- {p}")
    return "\n".join(lines) + "\n"


def runner_facts() -> dict:
    """What the numbers were measured on, read from the machine, not assumed."""
    mem = None
    try:
        for line in pathlib.Path("/proc/meminfo").read_text().splitlines():
            if line.startswith("MemTotal:"):
                mem = round(int(line.split()[1]) / 1048576, 1)
    except (OSError, ValueError, IndexError):
        pass
    return {"label": os.environ.get("OPENSEAL_LOAD_RUNNER", "unknown"), "cpus": os.cpu_count(),
            "memory_gib": mem, "os": f"{os.environ.get('ImageOS', platform.system())} {platform.release()}"}


ROWS_SQL = """
SELECT e.id, e.status,
  (SELECT extract(epoch FROM min(a.at)) FROM audit_events a WHERE a.envelope_id = e.id AND a.event_type = 'envelope.sent'),
  (SELECT extract(epoch FROM min(a.at)) FROM audit_events a WHERE a.envelope_id = e.id AND a.event_type = 'recipient.signed'),
  (SELECT extract(epoch FROM min(a.at)) FROM audit_events a WHERE a.envelope_id = e.id AND a.event_type = 'envelope.completing'),
  (SELECT extract(epoch FROM min(a.at)) FROM audit_events a WHERE a.envelope_id = e.id AND a.event_type = 'envelope.completed'),
  (SELECT extract(epoch FROM min(j.finished_at)) FROM jobs j WHERE j.envelope_id = e.id AND j.kind = 'send_invitation' AND j.status = 'done'),
  (SELECT count(*) FROM document_versions v JOIN documents d ON d.id = v.document_id WHERE d.envelope_id = e.id AND v.kind = 'sealed')
FROM envelopes e WHERE e.subject LIKE 'Load %' ORDER BY e.created_at
""".strip().replace("\n", " ")


# ------------------------------------------------------------------ the run


class Compose(cc.Compose):
    """The chaos stack under its own project name, with the load override on top."""

    def argv(self, *args: str) -> list[str]:
        return ["docker", "compose", "-p", PROJECT, "-f", str(cc.PROFILE), "-f", str(cc.OVERRIDE),
                "-f", str(LOAD_OVERRIDE), *args]


def load_env(work: pathlib.Path, hsm: pathlib.Path) -> dict[str, str]:
    env = cc.compose_env(work, hsm, 0)  # the TSA gate holds nothing
    env["OPENSEAL_TRUSTED_PROXIES"] = TRUSTED_PROXIES
    return env


class Envelope:
    __slots__ = ("id", "field", "email", "n", "send_s", "sign_s", "sent_at", "attempts")

    def __init__(self, eid: str, field: str, email: str, n: int, send_s: float, sent_at: float):
        self.id, self.field, self.email, self.n = eid, field, email, n
        self.send_s, self.sent_at, self.sign_s, self.attempts = send_s, sent_at, None, 0


class LoadRun(cc.Run):
    def __init__(self, args):
        super().__init__(args)
        self.work = (ROOT / "target" / "load-compose").resolve()
        self.hsm = self.work / "hsm"
        self.compose = Compose(load_env(self.work, self.hsm))
        self.stop_sending = threading.Event()
        self.stop_all = threading.Event()
        self.slots = threading.Semaphore(args.in_flight)
        self.todo: queue.Queue[Envelope] = queue.Queue()
        self.lock = threading.Lock()
        self.sent: dict[str, Envelope] = {}
        self.done_seen: dict[str, float] = {}  # id -> when the monitor first saw it completed
        self.counter = 0
        self.http = {"429": 0, "5xx": 0, "other": 0, "unreachable": 0}
        self.cases: list[dict] = []

    # ---- traffic

    def note_http(self, status: int) -> None:
        with self.lock:
            if status == 429:
                self.http["429"] += 1
            elif status >= 500:
                self.http["5xx"] += 1
            elif status == 0:
                self.http["unreachable"] += 1
            else:
                self.http["other"] += 1

    def retrying(self, what: str, fn, deadline: float):
        """fn() -> (status, value); retried on any failure until `deadline`, as a client
        whose request failed does. Returns (value, seconds of the successful attempt)."""
        while not self.stop_all.is_set():
            t0 = time.monotonic()
            status, value = fn()
            if 200 <= status < 300:
                return value, time.monotonic() - t0
            self.note_http(status)
            if time.monotonic() > deadline:
                raise cc.ChaosError(f"{what}: still HTTP {status} at the deadline")
            time.sleep(2 if status != 429 else 5)
        raise cc.ChaosError(f"{what}: stopped")

    def sender(self, k: int) -> None:
        api = cc.Api(self.base)
        api.cookies.jar, api.csrf = dict(self.staff.cookies.jar), self.staff.csrf
        pdf_b64 = base64.b64encode(drill_flow.pdf()).decode()
        while not self.stop_sending.is_set():
            if not self.slots.acquire(timeout=1):
                continue
            with self.lock:
                self.counter += 1
                n = self.counter
            email = f"load-{n}-{self.run_tag}@example.com"
            body = {
                "subject": f"{SUBJECT} {n}", "status": "sent",
                "documents": [{"name": "load.pdf", "content_base64": pdf_b64}],
                "recipients": [{"ref": "r0", "type": "signer", "name": "Load Signer", "email": email, "routing_order": 1,
                                "auth": ["access_code"], "access_code": cc.ACCESS_CODE}],
                "fields": [{"recipient": "r0", "document": 0, "type": "signature", "page": 1, "x": 72, "y": 100,
                            "width": 180, "height": 40, "required": True}],
            }
            key = {"Idempotency-Key": f"load-{n}-{self.run_tag}"}

            def create():
                st, payload = api.request("POST", "/api/v1/envelopes", body, key)
                return st, (json.loads(payload) if 200 <= st < 300 else None)
            try:
                e, secs = self.retrying(f"sender {k}: create", create, time.monotonic() + self.args.recover_timeout)
                env = Envelope(cc.need_uuid(e["id"]), e["fields"][0]["id"], email, n, secs, time.time())
            except (cc.ChaosError, KeyError, IndexError, TypeError, ValueError) as err:
                self.slots.release()
                if not self.stop_all.is_set():
                    self.problems.append(f"sender {k}: {err}")
                continue
            with self.lock:
                self.sent[env.id] = env
            self.todo.put(env)

    def signer(self, k: int) -> None:
        while not self.stop_all.is_set():
            try:
                env = self.todo.get(timeout=1)
            except queue.Empty:
                if self.stop_sending.is_set() and self.all_signed():
                    return
                continue
            try:
                self.sign(env)
            except (cc.ChaosError, KeyError, IndexError, TypeError, ValueError, OSError) as err:
                if not self.stop_all.is_set():
                    self.problems.append(f"signer {k}: envelope {env.id}: {err}")

    def all_signed(self) -> bool:
        with self.lock:
            return all(e.sign_s is not None for e in self.sent.values()) and self.todo.empty()

    def sign(self, env: Envelope) -> None:
        deadline = time.monotonic() + self.args.recover_timeout + 300
        path = drill_flow.signing_path(self.mail, env.email, timeout=self.args.recover_timeout + 300)
        api = cc.Api(self.base)
        xff = {"X-Forwarded-For": forwarded_for(env.n)}

        def step(method, sub, body):
            def go():
                st, payload = api.request(method, f"{path}{sub}", body, xff)
                return st, (json.loads(payload) if 200 <= st < 300 and payload else {})
            return self.retrying(f"{sub or 'ceremony'}", go, deadline)[0]

        view = step("POST", "/session", {})
        if view.get("consent_required"):
            step("POST", "/consent", {"ersd_version": view["consent_required"]["version"]})
        v = step("POST", "/authenticate", {"method": "access_code", "code": cc.ACCESS_CODE})
        if v.get("consent_required"):
            step("POST", "/consent", {"ersd_version": v["consent_required"]["version"]})
        doc = v["envelope"]["documents"][0]["id"]
        step("POST", f"/documents/{doc}/viewed", {"pages_seen": [1]})
        a = step("POST", "/adopt", {"mark": "signature", "method": "draw", "image_base64": cc.PNG})
        body = {"values": [{"field": env.field, "value": {"signature": a["adoption_id"]}}]}

        def finish():
            st, _ = api.request("POST", f"{path}/finish", body, xff)
            return st, None
        _, secs = self.retrying("finish", finish, deadline)
        with self.lock:
            env.sign_s = secs

    def monitor(self) -> None:
        """Frees a sender's slot when an envelope is sealed (seen through the database,
        so the API's per-principal limit is spent only on sends)."""
        while not self.stop_all.is_set():
            try:
                done = self.compose.sql("SELECT id FROM envelopes WHERE status = 'completed' AND subject LIKE 'Load %'")
            except (cc.ChaosError, subprocess.TimeoutExpired):
                done = ""
            now = time.time()
            for eid in done.split():
                with self.lock:
                    fresh = eid in self.sent and eid not in self.done_seen
                    if fresh:
                        self.done_seen[eid] = now
                if fresh:
                    self.slots.release()
            self.stop_all.wait(2)

    def live_rows(self) -> list[dict]:
        with self.lock:
            return [{"sent": e.sent_at, "completed": self.done_seen.get(e.id)} for e in self.sent.values()]

    # ---- chaos

    def inject(self, name: str) -> dict:
        c = self.compose
        case = {"name": name, "fault": time.time()}
        if name == "worker":
            for w in c.containers("worker"):
                cc.host_kill(w)
            case["what"] = "every worker SIGKILLed; Docker's restart policy restarts them"
            case["restored"] = time.time()
            cc.wait_healthy(c.containers("worker"))
            case["running_again_s"] = round(time.time() - case["fault"], 1)
        else:
            svc = {"keyd": "keyd", "postgres": "postgres"}[name]
            c.run("stop", "-t", "0", svc, timeout=120)
            case["what"] = f"{svc} stopped (no grace) for {self.args.hold:g} s"
            time.sleep(self.args.hold)
            c.run("start", svc, timeout=120)
            cc.wait_healthy(c.containers(svc))
            case["restored"] = time.time()
        case["down_s"] = round(case["restored"] - case["fault"], 1)
        return case

    def chaos(self, name: str, baseline_epm: float) -> None:
        say(f"== {name}")
        try:
            case = self.inject(name)
        except (cc.ChaosError, subprocess.TimeoutExpired, OSError) as e:
            self.problems.append(f"{name}: injecting the fault: {e}")
            self.restore_everything()
            return
        limit = case["restored"] + self.args.recover_timeout
        while time.time() < limit:
            rec = recovery(case, self.live_rows(), baseline_epm, time.time())
            if rec["recovery_s"] is not None:
                break
            time.sleep(5)
        case["live"] = recovery(case, self.live_rows(), baseline_epm, time.time())
        say(f"{name}: {case['live']}")
        self.cases.append(case)
        self.restore_everything()
        time.sleep(WINDOW)  # a settled minute before the next case

    # ---- the run

    def drive(self) -> dict:
        threads = [threading.Thread(target=self.monitor, daemon=True)]
        threads += [threading.Thread(target=self.sender, args=(k,), daemon=True) for k in range(self.args.senders)]
        threads += [threading.Thread(target=self.signer, args=(k,), daemon=True) for k in range(self.args.signers)]
        for t in threads:
            t.start()
        say(f"load on: {self.args.senders} senders, {self.args.signers} signers, at most {self.args.in_flight} open")
        time.sleep(self.args.warmup)
        b0 = time.time()
        time.sleep(self.args.baseline)
        b1 = time.time()
        rows = self.live_rows()
        live_epm = per_minute([r["completed"] for r in rows if r["completed"]], b0, b1) or 0.0
        say(f"baseline: about {live_epm} envelopes per minute (as the monitor saw them)")
        for name in self.args.cases:
            self.chaos(name, live_epm)
        say("senders stopped; every envelope must now complete")
        self.stop_sending.set()
        try:
            cc.until("every envelope sealed", self.args.recover_timeout,
                     lambda: all(r["completed"] for r in self.live_rows()), every=5)
        except cc.ChaosError as e:
            self.problems.append(str(e))
        self.stop_all.set()
        for t in threads:
            t.join(30)
        return {"start": b0, "end": b1}

    def collect(self, window: dict) -> dict:
        rows = parse_rows(self.compose.sql(ROWS_SQL))
        with self.lock:
            client = {e.id: e for e in self.sent.values()}
        known = {r["id"] for r in rows}
        for eid in client:
            if eid not in known:
                self.problems.append(f"{eid}: sent but not in the database")
        b0, b1 = window["start"], window["end"]
        completed = [r["completed"] for r in rows if r["completed"] is not None]
        in_base = [r for r in rows if r["sent"] is not None and b0 <= r["sent"] < b1]
        lat = server_latencies(in_base)
        lat["send"] = summarize([client[r["id"]].send_s for r in in_base if r["id"] in client])
        lat["sign"] = summarize([client[r["id"]].sign_s for r in in_base
                                 if r["id"] in client and client[r["id"]].sign_s is not None])
        baseline = {"seconds": round(b1 - b0), "completed": sum(1 for t in completed if b0 <= t < b1),
                    "envelopes_per_minute": per_minute(completed, b0, b1), "latency": lat}
        epm = baseline["envelopes_per_minute"] or 0.0
        end = max(completed, default=time.time())
        for c in self.cases:
            c["recovery"] = recovery(c, rows, epm, end)
        t0 = min((r["sent"] for r in rows if r["sent"]), default=b0)
        return {
            "baseline": baseline, "cases": self.cases, "envelopes": rows,
            "completed": sum(1 for r in rows if r["status"] == "completed"),
            "sealed_twice": sum(1 for r in rows if r["sealed_versions"] > 1),
            "whole_run_latency": server_latencies(rows),
            "per_minute_series": {"start": t0, "counts": series(completed, t0, end + 1)},
        }

    def check_evidence(self, rows: list[dict]) -> None:
        c = self.compose
        ev = c.run("--profile", "chaos-tools", "run", "--rm", "-T", "evidence", check=False, timeout=1800)
        (self.work / "evidence.txt").write_bytes(ev.stdout + ev.stderr)
        self.check(ev.returncode == 0, f"verify-evidence exited {ev.returncode}")
        op = c.run("exec", "-T", "keyd", "casual-sign-keyd", "verify-oplog", "/var/lib/keyd/oplog", check=False, timeout=600)
        (self.work / "oplog.txt").write_bytes(op.stdout + op.stderr)
        self.check(op.returncode == 0, f"keyd's operation log did not verify (exit {op.returncode})")
        sealed_dir = self.work / "sealed"
        sealed_dir.mkdir(parents=True, exist_ok=True)
        done = [r for r in rows if r["status"] == "completed"]
        step = max(1, len(done) // max(1, self.args.verify_sample))
        names = []
        for r in done[::step][: self.args.verify_sample]:
            e = self.staff.call("GET", f"/api/v1/envelopes/{r['id']}")
            doc = e["documents"][0]["id"]
            st, pdf = self.staff.request("GET", f"/api/v1/envelopes/{r['id']}/documents/{doc}/content?version=sealed",
                                         headers={"Accept": "application/pdf"})
            self.check(st == 200 and pdf.startswith(b"%PDF-"), f"{r['id']}: completed but its sealed PDF is not served")
            if st == 200:
                (sealed_dir / f"{r['id']}.pdf").write_bytes(pdf)
                names.append(f"{r['id']}.pdf")
        (sealed_dir / "trust-root.pem").write_bytes((self.work / "pki" / "trust-root.pem").read_bytes())
        (sealed_dir / "manifest.tsv").write_text(cc.manifest_tsv(names), encoding="utf-8")
        vs = cc.sh([self.args.verify_python, "-I", str(ROOT / "tools" / "verify-sealed.py"), str(sealed_dir)],
                   check=False, timeout=1800)
        (self.work / "verify-sealed.txt").write_bytes(vs.stdout + vs.stderr)
        self.check(vs.returncode == 0, f"tools/verify-sealed.py exited {vs.returncode} over {len(names)} sealed PDFs")

    def main(self) -> int:
        if self.work.exists():
            cc.sh(["docker", "run", "--rm", "-v", f"{self.work.parent}:{self.work.parent}", "--entrypoint", "sh",
                   cc.DEVTOOLS, "-c", 'rm -rf "$1"', "sh", str(self.work)], check=False, timeout=120)
        self.compose.run("--profile", "chaos-tools", "down", "-v", "--remove-orphans", check=False, timeout=600)
        self.work.mkdir(parents=True, exist_ok=True)
        report: dict = {"commit": os.environ.get("GITHUB_SHA", "")[:12], "date": time.strftime("%Y-%m-%d", time.gmtime()),
                        "runner": runner_facts(),
                        "config": {"workers": 2, "senders": self.args.senders, "signers": self.args.signers,
                                   "in_flight": self.args.in_flight, "warmup_s": self.args.warmup,
                                   "baseline_s": self.args.baseline, "hold_s": self.args.hold,
                                   "recover_timeout_s": self.args.recover_timeout, "cases": list(self.args.cases),
                                   "recovered_fraction": RECOVERED_FRACTION, "window_s": WINDOW},
                        "baseline": {}, "cases": [], "envelopes": []}
        try:
            self.setup()
            window = self.drive()
            report.update(self.collect(window))
            self.check_evidence(report["envelopes"])
        except (cc.ChaosError, KeyError, IndexError, TypeError, ValueError, OSError, subprocess.TimeoutExpired) as e:
            self.problems.append(f"setup, load or collection: {e}")
        finally:
            self.stop_all.set()
            report["http_refusals"] = dict(self.http)
            report["problems"] = self.problems
            report["seconds"] = round(time.monotonic() - self.started)
            report["verdict"] = verdict(report, self.args.recover_timeout)
            (self.work / "report.json").write_text(json.dumps(report, indent=1, sort_keys=True) + "\n", encoding="utf-8")
            if report.get("baseline"):
                (self.work / "report.md").write_text(markdown(report), encoding="utf-8")
            self.teardown()
        if report["verdict"]:
            say("FAILED:")
            for p in report["verdict"][:50]:
                say(f"  {p}")
            return 1
        say(f"passed: {report['completed']} envelopes, each sealed once ({self.work / 'report.md'})")
        return 0


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(prog="load_compose.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--no-build", dest="build", action="store_false")
    r.add_argument("--verify-python", default=os.environ.get("OPENSEAL_VERIFY_PYTHON", sys.executable))
    r.add_argument("--senders", type=int, default=2)
    r.add_argument("--signers", type=int, default=8)
    r.add_argument("--in-flight", type=int, default=16)
    r.add_argument("--warmup", type=float, default=60)
    r.add_argument("--baseline", type=float, default=300)
    r.add_argument("--hold", type=float, default=30)
    r.add_argument("--recover-timeout", type=float, default=900)
    r.add_argument("--verify-sample", type=int, default=20)
    r.add_argument("--cases", default=",".join(CASES))
    args = ap.parse_args(argv)
    args.tsa_delay = 0.0
    args.cases = [c for c in args.cases.split(",") if c]
    bad = [c for c in args.cases if c not in CASES]
    if bad or min(args.senders, args.signers, args.in_flight) < 1:
        ap.error(f"cases are {', '.join(CASES)}; senders, signers and in-flight at least 1")
    try:
        return LoadRun(args).main()
    except cc.ChaosError as e:
        say(f"FAILED: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
