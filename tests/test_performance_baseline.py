import importlib.util
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("performance_baseline", ROOT / "scripts/performance-baseline.py")
baseline = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(baseline)


def udp_runs(reference=1, candidate=1, shortfall=0, direct_candidate=1, rounds=3):
    runs = []
    for round_number in range(rounds):
        for label, throughput in [("reference", reference), ("candidate", candidate)]:
            if isinstance(throughput, list):
                throughput = throughput[round_number]
            runs.append({"round": round_number + 1, "case": "udp-h3", "label": label, "records": [
                {"type": "UDP_RESULT", "transport": "http3", "path": "masque", "payload_bytes": 64,
                 "app_goodput_gbps": throughput, "response_shortfall_pct": shortfall if label == "candidate" else 0},
                {"type": "UDP_RESULT", "transport": "http3", "path": "direct", "payload_bytes": 64,
                 "app_goodput_gbps": direct_candidate if label == "candidate" else 1, "response_shortfall_pct": 0},
            ]})
    return runs


class ReportingTests(unittest.TestCase):
    def comparison(self, **kwargs):
        result = baseline.compare(baseline.aggregate(udp_runs(**kwargs)), 10, 1)
        self.assertEqual(len(result), 1)  # Direct controls are never build regressions.
        return result[0]

    def test_faster_with_more_unanswered_requests_is_not_an_improvement(self):
        self.assertEqual(self.comparison(candidate=1.5, shortfall=5)["status"], "regression")

    def test_loaded_rtt_improvement_does_not_hide_more_expired_requests(self):
        runs = udp_runs(shortfall=5)
        for run in runs:
            run["records"].append({"type": "UDP_LOAD_LATENCY_RESULT", "transport": "http3",
                                   "path": "masque", "payload_bytes": 64,
                                   "load_rtt_p95_us_upper": 50 if run["label"] == "candidate" else 100})
        comparisons = baseline.compare(baseline.aggregate(runs), 10, 1)
        latency = next(r for r in comparisons if r["type"] == "UDP_LOAD_LATENCY_RESULT")
        self.assertEqual(latency["status"], "regression")

    def test_direct_path_drift_prevents_attribution_to_the_server(self):
        result = self.comparison(candidate=0.7, direct_candidate=0.7)
        self.assertTrue(result["direct_baseline_drift"])
        self.assertEqual(result["status"], "inconclusive")

    def test_noisy_or_short_runs_cannot_fail_a_regression_gate(self):
        noisy = self.comparison(candidate=[0.4, 0.7, 1.0])
        self.assertEqual(noisy["status"], "inconclusive")
        self.assertIn("high_variability", noisy["inconclusive_reasons"])
        short = self.comparison(candidate=0.7, rounds=1)
        self.assertEqual(short["status"], "inconclusive")
        self.assertIn("insufficient_samples", short["inconclusive_reasons"])

    def test_stable_speed_changes_have_the_expected_direction(self):
        self.assertEqual(self.comparison(candidate=0.7)["status"], "regression")
        self.assertEqual(self.comparison(candidate=1.3)["status"], "improvement")
        self.assertEqual(self.comparison(candidate=1.01)["status"], "unchanged")

    def test_machine_records_reject_unsafe_strings_and_non_finite_values(self):
        for line in ["UDP_RESULT path=example.invalid", "UDP_RESULT rx_pps=nan", "UDP_RESULT rx_pps=inf",
                     "UDP_RESULT rx_pps=1 rx_pps=2", "UDP_RESULT rx_pps=-1"]:
            with self.subTest(line=line), self.assertRaises(ValueError):
                baseline.parse_records(line)

    def test_failed_load_workers_and_missing_controls_are_not_valid_baselines(self):
        resources = {"type": "SERVER_RESOURCE_RESULT", "peak_rss_bytes": 1024}
        load = {"type": "LOAD_RESULT", "connections": 8, "established": 7, "setup_failures": 1, "runtime_failures": 0}
        with self.assertRaises(ValueError):
            baseline.validate_records([resources, load], {"mode": "load"})
        with self.assertRaises(ValueError):
            baseline.validate_records([resources], {"mode": "udp"})

    def test_each_case_runs_both_builds_with_alternating_order(self):
        cases = baseline.cases("standard")
        schedule = list(baseline.schedule(cases, ["reference", "candidate"], 3))
        self.assertEqual(len(schedule), len(cases) * 2 * 3)
        for round_number in (1, 2, 3):
            entries = [(c["name"], label) for r, c, label in schedule if r == round_number]
            self.assertEqual(set(entries), {(c["name"], label) for c in cases for label in ("reference", "candidate")})
        self.assertEqual(schedule[0][2], "reference")
        self.assertEqual(next(label for r, _, label in schedule if r == 2), "candidate")

    def test_sharding_is_only_scheduled_on_supported_platforms(self):
        self.assertIn("load-sharded", {c["name"] for c in baseline.cases("standard", "linux")})
        self.assertNotIn("load-sharded", {c["name"] for c in baseline.cases("standard", "darwin")})

    def test_congestion_profile_only_compares_quic_workloads(self):
        workloads = baseline.cases("congestion", "linux")
        self.assertTrue(all(c["transport"] == "http3" for c in workloads))
        self.assertEqual({c["mode"] for c in workloads}, {"udp", "tcp", "load"})


class ProcessAccountingTests(unittest.TestCase):
    def command(self, directory, code):
        return [sys.executable, str(ROOT / "scripts/bench-process.py"),
                "--pid-file", str(directory / "pid"), "--result-file", str(directory / "result"),
                "--", sys.executable, "-c", code]

    def test_exit_status_and_server_only_resource_usage_are_retained(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            result = subprocess.run(self.command(directory, "import sys; sum(range(100000)); sys.exit(7)"), capture_output=True)
            self.assertEqual(result.returncode, 7)
            record, = baseline.parse_records((directory / "result").read_text())
            self.assertGreater(record["cpu_secs"], 0)
            self.assertGreater(record["peak_rss_bytes"], 0)
            self.assertGreater(record["wall_secs"], 0)

    def test_termination_reaps_the_server_and_still_writes_resources(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            process = subprocess.Popen(self.command(directory, "import time; time.sleep(30)"), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                deadline = time.monotonic() + 5
                while not (directory / "pid").exists() or not (directory / "pid").stat().st_size:
                    if time.monotonic() > deadline:
                        self.fail("server wrapper did not start")
                    time.sleep(0.01)
                child = int((directory / "pid").read_text())
                process.send_signal(signal.SIGTERM)
                self.assertEqual(process.wait(timeout=5), 128 + signal.SIGTERM)
                self.assertEqual(len(baseline.parse_records((directory / "result").read_text())), 1)
                with self.assertRaises(ProcessLookupError):
                    os.kill(child, 0)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()


if __name__ == "__main__":
    unittest.main()
