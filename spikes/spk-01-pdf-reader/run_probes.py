#!/usr/bin/env python3
"""SPK-01 harness: run `probe` for every candidate over every fixture, 10 s cap each.

    python3 -I run_probes.py target/release/probe fixtures > results.md

Outcome classes: ok, error (typed), PANIC (caught), CRASH <signal> (abort, stack
overflow), HANG (killed at 10 s).

Peak RSS comes from wait4(2) rusage of the probe process (the same getrusage source
`/usr/bin/time -l` prints as "maximum resident set size"); using wait4 directly lets a run
killed at the time cap still report its peak. The probe's own allocator caps heap at 3 GiB.
"""
import os
import pathlib
import re
import signal
import subprocess
import sys
import time

CAP_S = 10.0
CANDIDATES = ["lopdf", "lopdf-strict", "pdf", "own"]


def run(probe, cand, path):
    t0 = time.monotonic()
    p = subprocess.Popen([probe, cand, str(path)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    killed = False
    while True:
        pid, status, ru = os.wait4(p.pid, os.WNOHANG)
        if pid:
            break
        if time.monotonic() - t0 > CAP_S:
            p.send_signal(signal.SIGKILL)
            killed = True
            pid, status, ru = os.wait4(p.pid, 0)
            break
        time.sleep(0.02)
    wall = time.monotonic() - t0
    out = p.stdout.read().decode(errors="replace").strip()
    err = p.stderr.read().decode(errors="replace").strip()
    rss_mib = ru.ru_maxrss / (1 << 20)  # bytes on macOS
    if killed:
        verdict = "HANG (killed at 10 s)"
    elif os.WIFSIGNALED(status):
        sig = signal.Signals(os.WTERMSIG(status)).name
        why = "stack overflow" if "overflow" in err else ("alloc cap/abort" if "allocation" in err else "")
        verdict = f"CRASH {sig} {why}".strip()
    elif out.startswith("PANIC"):
        verdict = "PANIC"
    elif out.startswith("OK"):
        verdict = "ok"
    else:
        verdict = "error (typed)"
    detail = out or err.splitlines()[-1] if (out or err) else ""
    # pdf-rs errors embed the build machine's source paths; keep only the crate-relative part.
    detail = re.sub(r"Try at \S*/registry/src/[^/]+/", "", detail).replace(str(pathlib.Path.home()), "~")
    return verdict, wall, rss_mib, detail[:150]


def main():
    probe, fixtures = sys.argv[1], pathlib.Path(sys.argv[2])
    print("| Fixture | Candidate | Outcome | Wall s | Peak RSS MiB | Detail |")
    print("| --- | --- | --- | ---: | ---: | --- |")
    for f in sorted(fixtures.glob("*.pdf")):
        for c in CANDIDATES:
            v, wall, rss, d = run(probe, c, f)
            print(f"| {f.stem} | {c} | {v} | {wall:.2f} | {rss:.0f} | `{d.replace('|', '/')}` |", flush=True)


if __name__ == "__main__":
    main()
