"""Tests of the chaos driver's logic (HRD-10), without Docker:

    python3 -I -m unittest discover -s tools/chaos -p 'test_*.py'

The run itself needs Docker and is CI's `chaos-compose` job; these check what decides its
verdict (the judge, the log reader), what it sends (cookies), the TSA gate, and that the
CI override sets no development switch and that every variable the profile requires is
supplied.
"""

import importlib.util
import json
import pathlib
import socket
import threading
import time
import unittest

import chaos_compose as cc

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent


def envelope(**over):
    e = {"label": "x", "id": "0190a0a0-0000-7000-8000-000000000001", "status": "completed",
         "sealed_versions": 1, "sealed_served": True, "job_dead_alerts": 0}
    e.update(over)
    return e


class Judge(unittest.TestCase):
    def test_a_completed_envelope_with_one_served_seal_passes(self):
        self.assertEqual(cc.judge([envelope()]), [])

    def test_a_second_seal_fails_the_run(self):
        problems = cc.judge([envelope(sealed_versions=2)])
        self.assertTrue(any("sealed 2 times" in p for p in problems), problems)

    def test_completed_without_a_seal_fails(self):
        problems = cc.judge([envelope(sealed_versions=0, sealed_served=False)])
        self.assertTrue(any("0 sealed versions" in p for p in problems), problems)
        self.assertTrue(any("not served" in p for p in problems), problems)

    def test_completing_with_a_job_dead_alert_and_nothing_served_is_a_safe_failure(self):
        self.assertEqual(cc.judge([envelope(status="completing", sealed_versions=0, sealed_served=False, job_dead_alerts=1)]), [])

    def test_completing_without_an_alert_fails(self):
        problems = cc.judge([envelope(status="completing", sealed_versions=0, sealed_served=False)])
        self.assertTrue(any("no job_dead alert" in p for p in problems), problems)

    def test_a_seal_served_while_completing_fails(self):
        problems = cc.judge([envelope(status="completing", sealed_served=True, job_dead_alerts=1)])
        self.assertTrue(any("served while completing" in p for p in problems), problems)

    def test_any_other_end_state_fails(self):
        problems = cc.judge([envelope(status="sent", sealed_versions=0, sealed_served=False)])
        self.assertTrue(any("ended sent" in p for p in problems), problems)


class Logs(unittest.TestCase):
    TEXT = "\n".join([
        'worker-1  | {"ts":"2026-11-14T00:00:00Z","level":"INFO","service":"worker","event":"seal_failed","code":"CS-SEAL-0001","envelope":"e1","job":"j1"}',
        '{"ts":"2026-11-14T00:00:01Z","level":"INFO","service":"worker","event":"job_dead","code":"CS-BLOB-0003","envelope":"e2","job":"j2"}',
        "plain text from a crash { not json",
        '{"no_event": true}',
        '{"ts":"2026-11-14T00:00:02Z","level":"INFO","service":"worker","event":"job_dead","code":"CS-DB-0008","envelope":"e2","job":"j3"}',
    ])

    def test_json_lines_are_read_with_or_without_a_prefix_and_noise_is_skipped(self):
        events = cc.log_events(self.TEXT)
        self.assertEqual([e["event"] for e in events], ["seal_failed", "job_dead", "job_dead"])

    def test_alerts_are_counted_per_envelope_and_kind(self):
        events = cc.log_events(self.TEXT)
        self.assertEqual(cc.alerts_for(events, "job_dead", "e2"), 2)
        self.assertEqual(cc.alerts_for(events, "job_dead", "e1"), 0)
        self.assertEqual(cc.alerts_for(events, "seal_failed", "e1"), 1)


class Cookies(unittest.TestCase):
    def test_secure_host_prefixed_cookies_are_kept_and_sent(self):
        c = cc.Cookies()
        c.take(["__Host-os_session=abc; Path=/; HttpOnly; Secure; SameSite=Strict",
                "os_ceremony=xyz; Path=/s/; HttpOnly; SameSite=Strict; Secure"])
        self.assertEqual(c.header(), "__Host-os_session=abc; os_ceremony=xyz")

    def test_an_expired_cookie_is_dropped(self):
        c = cc.Cookies()
        c.take(["a=1; Path=/"])
        c.take(["a=; Path=/; Max-Age=0"])
        self.assertIsNone(c.header())


class Ids(unittest.TestCase):
    def test_only_uuids_reach_sql(self):
        self.assertEqual(cc.need_uuid("0190a0a0-0000-7000-8000-000000000001"), "0190a0a0-0000-7000-8000-000000000001")
        for bad in ("", "x' OR '1'='1", "0190a0a0-0000-7000-8000-00000000000"):
            with self.assertRaises(cc.ChaosError):
                cc.need_uuid(bad)


class Manifest(unittest.TestCase):
    def test_every_sealed_pdf_is_expected_intact(self):
        text = cc.manifest_tsv(["a.pdf", "b.pdf"])
        lines = text.splitlines()
        self.assertEqual(lines[0], "file\texpect\twhy")
        self.assertEqual([ln.split("\t")[:2] for ln in lines[1:]], [["a.pdf", "intact"], ["b.pdf", "intact"]])


class Profile(unittest.TestCase):
    def test_every_variable_the_profile_and_the_override_require_is_supplied(self):
        env = cc.compose_env(pathlib.Path("/w"), pathlib.Path("/w/hsm"), 6)
        for f in (cc.PROFILE, cc.OVERRIDE):
            missing = cc.required_variables(f.read_text(encoding="utf-8")) - set(env)
            self.assertEqual(missing, set(), f.name)

    def test_the_override_sets_no_development_switch(self):
        spec = importlib.util.spec_from_file_location("check_deploy", ROOT / "tools" / "check-deploy.py")
        check_deploy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(check_deploy)
        text = cc.OVERRIDE.read_text(encoding="utf-8")
        body = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
        for name in check_deploy.FORBIDDEN_ENV:
            self.assertNotIn(name, body)
        self.assertNotIn("OPENSEAL_SMTP_SECURITY", body, "mail stays STARTTLS")
        env = cc.compose_env(pathlib.Path("/w"), pathlib.Path("/w/hsm"), 6)
        self.assertFalse(set(env) & check_deploy.FORBIDDEN_ENV)
        self.assertTrue(env["OPENSEAL_PUBLIC_URL"].startswith("https://"))

    def test_the_override_names_only_the_ci_services_and_the_worker(self):
        text = cc.OVERRIDE.read_text(encoding="utf-8")
        services = text.split("\nservices:\n", 1)[1]
        names = [ln.strip().rstrip(":") for ln in services.splitlines() if ln.startswith("  ") and not ln.startswith("   ") and ln.strip().endswith(":")]
        self.assertEqual(names, ["worker", "mailpit", "tsa", "tsa-gate", "evidence"])

    def test_the_compose_command_layers_the_override_on_the_production_profile(self):
        argv = cc.Compose({}).argv("up", "-d")
        self.assertEqual(argv[:4], ["docker", "compose", "-p", cc.PROJECT])
        self.assertEqual(argv[4:8], ["-f", str(cc.PROFILE), "-f", str(cc.OVERRIDE)])
        self.assertEqual(argv[-2:], ["up", "-d"])


class Gate(unittest.TestCase):
    def setUp(self):
        self.upstream = socket.create_server(("127.0.0.1", 0))
        self.addr = self.upstream.getsockname()

        def echo():
            while True:
                try:
                    conn, _ = self.upstream.accept()
                except OSError:
                    return
                with conn:
                    data = conn.recv(1024)
                    conn.sendall(b"reply:" + data)

        threading.Thread(target=echo, daemon=True).start()
        self.lines = []
        self.gate = cc.TsaGate(("127.0.0.1", 0), self.addr, 0.3, log=self.lines.append)
        threading.Thread(target=self.gate.serve_forever, daemon=True).start()

    def tearDown(self):
        self.gate.close()
        self.upstream.close()

    def test_a_request_is_counted_held_and_forwarded(self):
        t0 = time.monotonic()
        with socket.create_connection(self.gate.addr, timeout=5) as s:
            s.sendall(b"POST / tsq")
            got = b""
            while True:
                part = s.recv(1024)
                if not part:
                    break
                got += part
        self.assertEqual(got, b"reply:POST / tsq")
        self.assertGreaterEqual(time.monotonic() - t0, 0.3)
        self.assertEqual(self.lines, ["tsa-gate: connection 1"])

    def test_a_health_check_connection_is_not_counted(self):
        socket.create_connection(self.gate.addr, timeout=5).close()
        time.sleep(0.2)
        self.assertEqual(self.lines, [])
        self.assertEqual(self.gate.count, 0)


if __name__ == "__main__":
    unittest.main()
