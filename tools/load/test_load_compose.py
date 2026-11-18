"""Tests of the load driver's statistics and verdict (HRD-04), without Docker:

    python3 -I -m unittest discover -s tools/load -p 'test_*.py'

The run itself needs Docker and is the `load` workflow; these check what its published
numbers and its verdict are computed from: percentiles, rates, recovery times, the
integrity judge, the parsing of the server's timestamps, and that the stack it adds to is
the chaos run's with no development switch.
"""

import importlib.util
import pathlib
import unittest

import load_compose as lc

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
ID = "0190a0a0-0000-7000-8000-0000000000{:02d}"


def row(n=1, **over):
    r = {"id": ID.format(n), "status": "completed", "sent": 100.0, "signed": 110.0, "completing": 110.0,
         "completed": 115.0, "invited": 101.0, "sealed_versions": 1}
    r.update(over)
    return r


class Percentiles(unittest.TestCase):
    def test_linear_between_closest_ranks_as_numpy(self):
        xs = [float(x) for x in range(1, 101)]  # 1..100
        self.assertAlmostEqual(lc.percentile(xs, 50), 50.5)
        self.assertAlmostEqual(lc.percentile(xs, 95), 95.05)
        self.assertAlmostEqual(lc.percentile(xs, 99), 99.01)
        self.assertEqual(lc.percentile(xs, 0), 1.0)
        self.assertEqual(lc.percentile(xs, 100), 100.0)

    def test_order_of_input_does_not_matter(self):
        self.assertEqual(lc.percentile([3.0, 1.0, 2.0], 50), 2.0)

    def test_one_value_is_every_percentile_and_none_is_none(self):
        self.assertEqual(lc.percentile([7.0], 99), 7.0)
        self.assertIsNone(lc.percentile([], 95))

    def test_out_of_range_is_refused(self):
        with self.assertRaises(ValueError):
            lc.percentile([1.0], 101)

    def test_summary_rounds_to_milliseconds_and_counts(self):
        s = lc.summarize([0.0011, 0.0022, 10.0])
        self.assertEqual(s["n"], 3)
        self.assertEqual(s["p50"], 0.002)
        self.assertEqual(s["max"], 10.0)
        self.assertEqual(lc.summarize([]), {"n": 0, "p50": None, "p95": None, "p99": None, "max": None})


class Rates(unittest.TestCase):
    def test_per_minute_counts_only_the_half_open_window(self):
        times = [0.0, 10.0, 59.9, 60.0, 120.0]
        self.assertEqual(lc.per_minute(times, 0.0, 60.0), 3.0)
        self.assertEqual(lc.per_minute(times, 0.0, 120.0), 2.0)
        self.assertIsNone(lc.per_minute(times, 5.0, 5.0))

    def test_series_bins_by_minute_with_a_partial_last_bin(self):
        self.assertEqual(lc.series([0.0, 30.0, 61.0, 125.0, 500.0], 0.0, 130.0), [2, 1, 1])

    def test_throughput_back_is_the_first_full_window_at_the_fraction(self):
        # 10 a minute before; nothing for 100 s after the return; then 10 a minute again.
        completed = [float(t) for t in range(0, 100, 6)] + [float(t) for t in range(200, 400, 6)]
        back = lc.throughput_back(completed, 100.0, 400.0, 10.0)
        # 8 completions are needed in 60 s: the minute from the first one after the gap
        # holds 10.
        self.assertEqual(back, 200.0)

    def test_throughput_back_starts_at_a_completion_not_at_the_return(self):
        completed = [float(t) for t in range(150, 400)]
        self.assertEqual(lc.throughput_back(completed, 100.0, 400.0, 30.0), 150.0)

    def test_a_trickle_below_the_fraction_is_not_recovery(self):
        # Baseline 30 a minute: 24 are needed in a minute. One straggler at 150 is not it.
        completed = [150.0] + [float(t) for t in range(300, 500)]
        self.assertEqual(lc.throughput_back(completed, 100.0, 500.0, 30.0), 300.0)

    def test_throughput_back_needs_a_whole_window_and_a_completion(self):
        self.assertIsNone(lc.throughput_back([10.0], 0.0, 50.0, 1.0))
        self.assertIsNone(lc.throughput_back([], 0.0, 500.0, 0.0))

    def test_throughput_back_ignores_completions_before_the_return(self):
        before = [float(t) for t in range(0, 100)]
        self.assertIsNone(lc.throughput_back(before, 100.0, 400.0, 60.0))


class Recovery(unittest.TestCase):
    CASE = {"name": "postgres", "fault": 100.0, "restored": 130.0}

    def test_backlog_drained_is_the_last_affected_completion_after_the_return(self):
        rows = [
            {"sent": 50.0, "completed": 90.0},   # done before the fault: not affected
            {"sent": 95.0, "completed": 170.0},  # in flight at the fault
            {"sent": 120.0, "completed": 200.0},  # sent during the outage
            {"sent": 140.0, "completed": 150.0},  # sent after the return: not affected
        ]
        rec = lc.recovery(self.CASE, rows, 0.0, 300.0)
        self.assertEqual(rec["affected"], 2)
        self.assertEqual(rec["unfinished"], 0)
        self.assertEqual(rec["backlog_drained_s"], 70.0)

    def test_an_open_affected_envelope_means_not_recovered(self):
        rows = [{"sent": 95.0, "completed": None}] + [{"sent": 140.0 + i, "completed": 150.0 + i} for i in range(100)]
        rec = lc.recovery(self.CASE, rows, 1.0, 400.0)
        self.assertEqual(rec["unfinished"], 1)
        self.assertIsNone(rec["backlog_drained_s"])
        self.assertIsNone(rec["recovery_s"])

    def test_recovery_is_the_later_of_throughput_and_backlog(self):
        rows = [{"sent": 95.0, "completed": 400.0}] + [{"sent": 130.0 + i, "completed": 140.0 + i} for i in range(200)]
        rec = lc.recovery(self.CASE, rows, 30.0, 600.0)
        self.assertEqual(rec["throughput_back_s"], 10.0)
        self.assertEqual(rec["backlog_drained_s"], 270.0)
        self.assertEqual(rec["recovery_s"], 270.0)

    def test_nothing_in_flight_drains_at_once(self):
        rows = [{"sent": 140.0 + i, "completed": 141.0 + i} for i in range(100)]
        rec = lc.recovery(self.CASE, rows, 30.0, 400.0)
        self.assertEqual((rec["affected"], rec["backlog_drained_s"]), (0, 0.0))


class Integrity(unittest.TestCase):
    def test_one_seal_per_completed_envelope_passes(self):
        self.assertEqual(lc.integrity([row(1), row(2)]), [])

    def test_a_second_seal_fails(self):
        problems = lc.integrity([row(sealed_versions=2)])
        self.assertTrue(any("sealed 2 times" in p for p in problems), problems)

    def test_an_envelope_not_completed_fails(self):
        problems = lc.integrity([row(status="completing", completed=None, sealed_versions=0)])
        self.assertTrue(any("ended completing" in p for p in problems), problems)

    def test_completed_without_a_seal_or_its_event_fails(self):
        self.assertTrue(lc.integrity([row(sealed_versions=0)]))
        self.assertTrue(any("no envelope.completed" in p for p in lc.integrity([row(completed=None)])))


class ServerTimes(unittest.TestCase):
    def test_rows_are_parsed_with_empty_fields_as_none(self):
        text = (f"{ID.format(1)}|completed|100.5|110|110.25|115.75|101|1\n"
                f"{ID.format(2)}|sent|200||||201|0\n"
                "noise line\n")
        rows = lc.parse_rows(text)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["completed"], 115.75)
        self.assertIsNone(rows[1]["signed"])
        self.assertEqual(rows[1]["sealed_versions"], 0)

    def test_a_row_without_an_id_never_passes(self):
        with self.assertRaises(lc.cc.ChaosError):
            lc.parse_rows("x'; DROP|completed|1|2|3|4|5|1")

    def test_latencies_come_from_the_audit_events(self):
        lat = lc.server_latencies([row(1), row(2, completing=111.0, completed=113.0), row(3, completed=None, status="completing")])
        self.assertEqual(lat["seal"]["n"], 2)
        self.assertEqual(lat["seal"]["max"], 5.0)
        self.assertEqual(lat["seal"]["p50"], 3.5)
        self.assertEqual(lat["invitation"]["p50"], 1.0)
        self.assertEqual(lat["end_to_end"]["n"], 2)

    def test_the_query_reads_the_audit_trail_events_it_names(self):
        for ev in ("envelope.sent", "recipient.signed", "envelope.completing", "envelope.completed"):
            self.assertIn(f"'{ev}'", lc.ROWS_SQL)
        self.assertEqual(lc.ROWS_SQL.count("|"), 0)


class Verdict(unittest.TestCase):
    def report(self, **over):
        r = {"problems": [], "envelopes": [row(1)], "baseline": {"completed": 5},
             "cases": [{"name": "keyd", "recovery": {"recovery_s": 80.0, "unfinished": 0, "throughput_back_s": 20.0}}]}
        r.update(over)
        return r

    def test_a_clean_run_passes(self):
        self.assertEqual(lc.verdict(self.report(), 900), [])

    def test_an_unrecovered_case_fails(self):
        rep = self.report(cases=[{"name": "worker", "recovery": {"recovery_s": None, "unfinished": 3, "throughput_back_s": None}}])
        self.assertTrue(any("worker: not recovered" in p for p in lc.verdict(rep, 900)))

    def test_a_recovery_over_the_timeout_fails(self):
        self.assertTrue(any("over 60" in p for p in lc.verdict(self.report(), 60)))

    def test_an_idle_baseline_fails(self):
        self.assertTrue(any("baseline" in p for p in lc.verdict(self.report(baseline={"completed": 0}), 900)))

    def test_a_double_seal_and_recorded_problems_fail(self):
        problems = lc.verdict(self.report(envelopes=[row(sealed_versions=2)], problems=["signer 1: x"]), 900)
        self.assertIn("signer 1: x", problems)
        self.assertTrue(any("sealed 2 times" in p for p in problems))

    def test_the_markdown_table_carries_every_published_number(self):
        rep = self.report(runner={"label": "ubuntu-latest", "cpus": 4, "memory_gib": 15.6, "os": "ubuntu24"},
                          config={"workers": 2, "senders": 2, "signers": 8, "in_flight": 16},
                          baseline={"completed": 5, "seconds": 300, "envelopes_per_minute": 12.5,
                                    "latency": {"seal": {"n": 5, "p50": 1.5, "p95": 2.25, "p99": 2.5, "max": 3.0}}},
                          completed=1, sealed_twice=0, verdict=[])
        rep["cases"][0]["down_s"] = 31.0
        md = lc.markdown(rep)
        self.assertIn("| 12.5 |", md)
        self.assertIn("| seal | server | 5 | 1.5 | 2.25 | 2.5 | 3 |", md)
        self.assertIn("| keyd | 31 | – | 20 | – | 80 |", md)
        self.assertIn("4 CPUs, 15.6 GiB", md)
        self.assertIn("Verdict: passed", md)


class Signers(unittest.TestCase):
    def test_each_signer_has_its_own_benchmarking_address(self):
        seen = {lc.forwarded_for(n) for n in range(1, 70000)}
        self.assertEqual(len(seen), 69999)
        for a in list(seen)[:500] + [lc.forwarded_for(10 ** 9)]:
            o = [int(x) for x in a.split(".")]
            self.assertEqual(o[0], 198)
            self.assertIn(o[1], (18, 19))
            self.assertTrue(all(0 <= x <= 255 for x in o))


class Stack(unittest.TestCase):
    def test_the_load_override_sets_no_development_switch(self):
        spec = importlib.util.spec_from_file_location("check_deploy", ROOT / "tools" / "check-deploy.py")
        check_deploy = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(check_deploy)
        text = lc.LOAD_OVERRIDE.read_text(encoding="utf-8")
        body = "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))
        for name in check_deploy.FORBIDDEN_ENV:
            self.assertNotIn(name, body)
        env = lc.load_env(pathlib.Path("/w"), pathlib.Path("/w/hsm"))
        self.assertFalse(set(env) & check_deploy.FORBIDDEN_ENV)

    def test_the_load_override_touches_only_the_mail_sink(self):
        services = lc.LOAD_OVERRIDE.read_text(encoding="utf-8").split("\nservices:\n", 1)[1]
        names = [ln.strip().rstrip(":") for ln in services.splitlines()
                 if ln.startswith("  ") and not ln.startswith("   ") and ln.strip().endswith(":")]
        self.assertEqual(names, ["mailpit"])

    def test_every_required_variable_is_supplied_and_the_tsa_holds_nothing(self):
        env = lc.load_env(pathlib.Path("/w"), pathlib.Path("/w/hsm"))
        for f in (lc.cc.PROFILE, lc.cc.OVERRIDE, lc.LOAD_OVERRIDE):
            self.assertEqual(lc.cc.required_variables(f.read_text(encoding="utf-8")) - set(env), set(), f.name)
        self.assertEqual(env["CHAOS_TSA_DELAY"], "0")
        self.assertIn("172.16.0.0/12", env["OPENSEAL_TRUSTED_PROXIES"].split(","))

    def test_the_compose_command_layers_load_on_chaos_on_production(self):
        argv = lc.Compose({}).argv("up")
        self.assertEqual(argv[:4], ["docker", "compose", "-p", lc.PROJECT])
        self.assertEqual(argv[4:10], ["-f", str(lc.cc.PROFILE), "-f", str(lc.cc.OVERRIDE), "-f", str(lc.LOAD_OVERRIDE)])
        self.assertNotEqual(lc.PROJECT, lc.cc.PROJECT)


if __name__ == "__main__":
    unittest.main()
