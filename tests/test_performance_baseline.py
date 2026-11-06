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


def resource_runs(mode="udp", candidate_cpu=2, candidate_work=1000, rounds=3):
    runs = []
    for round_number in range(rounds):
        for label in ("reference", "candidate"):
            cpu = candidate_cpu if label == "candidate" else 2
            count = candidate_work if label == "candidate" else 1000
            records = [{"type": "SERVER_RESOURCE_RESULT", "cpu_secs": cpu, "peak_rss_bytes": 1024}]
            if mode == "udp":
                for size in (64, 1200):
                    for path in ("masque", "direct"):
                        records.append({"type": "UDP_RESULT", "path": path, "transport": "http3",
                                        "payload_bytes": size, "rx_packets": count if path == "masque" else 5000,
                                        "app_goodput_gbps": 1, "response_shortfall_pct": 0})
            elif mode == "load":
                records.append({"type": "LOAD_RESULT", "payload_bytes": 1200, "rx_packets": count,
                                "connections": 8, "window": 256, "expiry_ms": 1000,
                                "response_shortfall_pct": 0})
            else:
                for sample in (1, 2):
                    records.append({"type": "TCP_DOWNLOAD_RESULT", "transport": "http2",
                                    "sample": sample, "body_bytes": count, "transfer_mbps": 1})
                    records.append({"type": "DIRECT_TCP_DOWNLOAD_RESULT", "transport": "http2",
                                    "sample": sample, "body_bytes": 999999, "transfer_mbps": 1})
            runs.append({"round": round_number, "case": mode, "label": label, "records": records})
    return runs


class CpuEfficiencyTests(unittest.TestCase):
    def comparisons(self, runs):
        return [c for c in baseline.compare(baseline.aggregate(runs), 10, 1)
                if c["metric"].startswith("cpu_secs_per_")]

    def assert_cpu_status(self, runs, status, reason=None):
        results = self.comparisons(runs)
        self.assertTrue(results)
        for result in results:
            self.assertEqual(result["status"], status, result)
            if reason:
                self.assertIn(reason, result["inconclusive_reasons"])
        return results

    def test_more_work_with_proportional_cpu_is_not_a_regression(self):
        for mode in ("udp", "load", "tcp"):
            with self.subTest(mode=mode):
                runs = resource_runs(mode, candidate_cpu=4, candidate_work=2000)
                self.assert_cpu_status(runs, "unchanged")
                aggregates = baseline.aggregate(runs)
                resource = next(r for r in aggregates if r["label"] == "candidate" and r["type"] == "SERVER_RESOURCE_RESULT")
                self.assertEqual(resource["metrics"]["cpu_secs"]["median"], 4)
                self.assertNotIn("cpu_secs", {r["metric"] for r in baseline.compare(aggregates, 10, 1)})

    def test_per_work_changes_still_detect_real_regressions_and_improvements(self):
        for mode in ("udp", "load", "tcp"):
            with self.subTest(mode=mode):
                self.assert_cpu_status(resource_runs(mode, candidate_cpu=3), "regression")
                self.assert_cpu_status(resource_runs(mode, candidate_cpu=1), "improvement")
                # Lower total CPU cannot hide an even larger fall in work.
                self.assert_cpu_status(resource_runs(mode, candidate_cpu=1.5, candidate_work=500), "regression")

    def test_completed_proxy_work_excludes_direct_and_latency_records(self):
        for mode, expected_bytes, expected_packets in (("udp", 1264000, 2000), ("load", 1200000, 1000), ("tcp", 2000, None)):
            with self.subTest(mode=mode):
                records = resource_runs(mode)[0]["records"]
                records.extend([
                    {"type": "UDP_LATENCY_RESULT", "path": "masque", "payload_bytes": 64, "samples": 100},
                    {"type": "UDP_LOAD_LATENCY_RESULT", "path": "masque", "payload_bytes": 1200, "load_rtt_samples": 1000},
                    {"type": "TCP_DOWNLOAD_SUMMARY", "samples": 2},
                ])
                normalized = baseline.normalize_resources(records)
                resource = normalized[0]
                self.assertEqual(resource["completed_payload_bytes"], expected_bytes)
                self.assertEqual(resource["cpu_secs_per_gib"], 2 * 1024**3 / expected_bytes)
                self.assertEqual(resource.get("completed_responses"), expected_packets)
                self.assertEqual(normalized, baseline.normalize_resources(normalized))
                self.assertNotIn("completed_payload_bytes", records[0])

    def test_normalize_each_run_before_aggregation(self):
        runs = resource_runs("load")
        # Median(CPU)/median(work) = 4/100, but median(CPU/work) = .02.
        for run, cpu, work in zip(runs[::2], (2, 4, 100), (100, 10, 10000)):
            run["records"][0]["cpu_secs"] = cpu
            run["records"][1]["rx_packets"] = work
        resource = next(r for r in baseline.aggregate(runs) if r["label"] == "reference" and r["type"] == "SERVER_RESOURCE_RESULT")
        self.assertAlmostEqual(resource["metrics"]["cpu_secs_per_million_responses"]["median"], 20000)

    def test_missing_zero_or_partial_work_is_inconclusive(self):
        for mode in ("udp", "load", "tcp"):
            with self.subTest(mode=mode):
                self.assert_cpu_status(resource_runs(mode, candidate_work=0), "inconclusive", "missing_or_zero_completed_work")
                runs = resource_runs(mode)
                for record in baseline.work_records(runs[-1]["records"]):
                    record.pop("body_bytes" if mode == "tcp" else "rx_packets")
                self.assert_cpu_status(runs, "inconclusive", "incomplete_work_samples")

    def test_absent_traffic_is_not_a_successful_cpu_comparison(self):
        runs = resource_runs()
        for run in runs:
            run["records"] = run["records"][:1]
        self.assert_cpu_status(runs, "inconclusive", "incomparable_workload")

    def test_more_shortfall_cannot_qualify_as_cpu_improvement(self):
        for mode in ("udp", "load"):
            runs = resource_runs(mode, candidate_cpu=1)
            for run in runs:
                if run["label"] == "candidate":
                    baseline.work_records(run["records"])[0]["response_shortfall_pct"] = 5
            results = self.assert_cpu_status(runs, "regression")
            self.assertTrue(all(c["shortfall_increase_pp"] == 5 for c in results))

    def test_cpu_comparison_inherits_direct_control_drift(self):
        for mode in ("udp", "tcp"):
            runs = resource_runs(mode, candidate_cpu=1)
            for run in runs:
                if run["label"] == "candidate":
                    for record in run["records"]:
                        if record.get("path") == "direct":
                            record["app_goodput_gbps"] = 0.7
                        if record["type"] == "DIRECT_TCP_DOWNLOAD_RESULT":
                            record["transfer_mbps"] = 0.7
            results = self.assert_cpu_status(runs, "inconclusive", "direct_control_drift")
            self.assertTrue(all(c["direct_baseline_drift"] for c in results))

    def test_missing_direct_control_is_inconclusive(self):
        runs = resource_runs("tcp")
        for run in runs:
            run["records"] = [r for r in run["records"] if r["type"] != "DIRECT_TCP_DOWNLOAD_RESULT"]
        self.assert_cpu_status(runs, "inconclusive", "missing_direct_control")

    def test_changed_payload_mix_does_not_qualify_as_cpu_improvement(self):
        runs = resource_runs(candidate_cpu=1)
        for run in runs:
            if run["label"] == "candidate":
                baseline.work_records(run["records"])[0]["rx_packets"] *= 2
        self.assert_cpu_status(runs, "inconclusive", "workload_mix_drift")

    def test_noisy_payload_mix_and_changed_connection_count_are_inconclusive(self):
        runs = resource_runs()
        baseline.work_records(runs[-1]["records"])[0]["rx_packets"] *= 2
        self.assert_cpu_status(runs, "inconclusive", "high_workload_mix_variability")
        runs = resource_runs("load")
        for run in runs:
            if run["label"] == "candidate":
                baseline.work_records(run["records"])[0]["connections"] = 16
        self.assert_cpu_status(runs, "inconclusive", "incomparable_workload")

    def test_duplicate_work_and_stale_derived_metrics_cannot_hide_missing_work(self):
        runs = resource_runs("load")
        for run in runs:
            run["records"] = baseline.normalize_resources(run["records"])
        runs[-1]["records"][1]["rx_packets"] = 0
        self.assert_cpu_status(runs, "inconclusive", "incomplete_work_samples")
        runs = resource_runs("load")
        runs[-1]["records"].append(dict(runs[-1]["records"][1]))
        self.assert_cpu_status(runs, "inconclusive", "incomplete_work_samples")

    def test_missing_quality_or_direct_samples_are_inconclusive(self):
        runs = resource_runs("load")
        baseline.work_records(runs[-1]["records"])[0].pop("response_shortfall_pct")
        self.assert_cpu_status(runs, "inconclusive", "incomplete_work_samples")
        runs = resource_runs()
        direct = next(r for r in runs[-1]["records"] if r.get("path") == "direct")
        direct.pop("app_goodput_gbps")
        self.assert_cpu_status(runs, "inconclusive", "incomplete_direct_control")

    def test_changed_rate_setting_is_inconclusive(self):
        runs = resource_runs("load")
        for run in runs:
            baseline.work_records(run["records"])[0]["requested_pps_per_connection"] = 1000 if run["label"] == "reference" else 2000
        self.assert_cpu_status(runs, "inconclusive", "incomparable_workload")

    def test_one_round_and_noisy_normalized_cpu_are_inconclusive(self):
        self.assert_cpu_status(resource_runs(rounds=1), "inconclusive", "insufficient_samples")
        runs = resource_runs()
        runs[-1]["records"][0]["cpu_secs"] = 20
        self.assert_cpu_status(runs, "inconclusive", "high_variability")


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
