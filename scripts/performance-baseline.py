#!/usr/bin/env python3
"""Repeat local workloads and optionally alternate two server builds."""

from __future__ import annotations

import argparse
from collections import defaultdict
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import signal
import statistics
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
RECORD_TYPES = {
    "UDP_RESULT", "UDP_LATENCY_RESULT", "UDP_LOAD_LATENCY_RESULT", "LOAD_RESULT", "TCP_DOWNLOAD_RESULT",
    "DIRECT_TCP_DOWNLOAD_RESULT", "TCP_DOWNLOAD_SUMMARY", "SERVER_RESOURCE_RESULT",
}
IDENTITY = ("transport", "path", "payload_bytes", "sample")


def cases(profile, host_platform=None):
    host_platform = host_platform or sys.platform
    result = [{"name": "udp-h3", "mode": "udp", "transport": "http3", "shards": 1}]
    if profile != "quick":
        result += [
            {"name": "udp-h2", "mode": "udp", "transport": "http2", "shards": 1},
            {"name": "tcp-h3", "mode": "tcp", "transport": "http3", "shards": 1},
            {"name": "tcp-h2", "mode": "tcp", "transport": "http2", "shards": 1},
            {"name": "load-one", "mode": "load", "transport": "http3", "shards": 1, "connections": 1},
            {"name": "load-many", "mode": "load", "transport": "http3", "shards": 1},
            {"name": "load-sharded", "mode": "load", "transport": "http3", "shards": 2},
        ]
    if profile == "gso":
        result += [
            {"name": name, "mode": "udp", "transport": "http3", "shards": 1,
             "quic_gso": quic, "target_gso": target}
            for name, quic, target in [("gso-quic", 1, 0), ("gso-target", 0, 1), ("gso-both", 1, 1)]
        ]
    if host_platform != "linux":
        result = [case for case in result if case["name"] != "load-sharded"]
    if profile == "congestion":
        result = [case for case in result if case["transport"] == "http3"]
    return result


def schedule(workloads, labels, rounds):
    # Reverse both case order and A/B order each round to reduce order bias.
    for round_index in range(rounds):
        ordered_cases = workloads if round_index % 2 == 0 else workloads[::-1]
        ordered_labels = labels if round_index % 2 == 0 else labels[::-1]
        for case in ordered_cases:
            for label in ordered_labels:
                yield round_index + 1, case, label


def parse_records(text):
    records = []
    for line in text.splitlines():
        fields = line.split()
        if not fields or fields[0] not in RECORD_TYPES:
            continue
        record = {"type": fields[0]}
        for field in fields[1:]:
            key, separator, value = field.partition("=")
            if not separator or key in record:
                raise ValueError("malformed or duplicate benchmark field")
            if key in ("transport", "path"):
                if value not in {"http2", "http3", "direct", "masque", "masque_migrated"}:
                    raise ValueError("unknown benchmark category")
                record[key] = value
            elif value in ("true", "false"):
                record[key] = value == "true"
            else:
                number = float(value)
                if not math.isfinite(number) or number < 0:
                    raise ValueError("invalid benchmark measurement")
                record[key] = int(value) if value.isdecimal() else number
        records.append(record)
    return records


def validate_records(records, case):
    resources = [r for r in records if r["type"] == "SERVER_RESOURCE_RESULT"]
    if len(resources) != 1 or resources[0].get("peak_rss_bytes", 0) <= 0:
        raise ValueError("server resource measurement missing")
    if case["mode"] == "udp":
        measurements = {(r.get("path"), r.get("payload_bytes")) for r in records if r["type"] == "UDP_RESULT"}
        if measurements != {(path, size) for path in ("direct", "masque") for size in (64, 1200)}:
            raise ValueError("UDP payload or direct baseline measurement missing")
        latency_paths = {r.get("path") for r in records if r["type"] == "UDP_LATENCY_RESULT"}
        if latency_paths != {"direct", "masque"}:
            raise ValueError("UDP latency measurement missing; rebuild the benchmark client")
        if case["transport"] == "http3":
            loaded_payloads = {r.get("payload_bytes") for r in records if r["type"] == "UDP_LOAD_LATENCY_RESULT"}
            if loaded_payloads != {64, 1200}:
                raise ValueError("loaded UDP latency measurement missing; rebuild the benchmark client")
    elif case["mode"] == "load":
        loads = [r for r in records if r["type"] == "LOAD_RESULT"]
        if len(loads) != 1 or any(loads[0].get(k, 1) for k in ("setup_failures", "runtime_failures")):
            raise ValueError("load worker failure or measurement missing")
        if loads[0].get("established", 0) != loads[0].get("connections"):
            raise ValueError("load connections did not all establish")
    elif not any(r["type"] == "TCP_DOWNLOAD_SUMMARY" and "direct_ratio_pct" in r for r in records):
        raise ValueError("TCP direct baseline summary missing")


def identity(record):
    return (record["type"], *(record.get(key) for key in IDENTITY))


def aggregate(runs):
    grouped = defaultdict(list)
    for run in runs:
        for record in run["records"]:
            grouped[(run["case"], run["label"], identity(record))].append(record)
    result = []
    for (case, label, _), records in grouped.items():
        first = records[0]
        metrics = {}
        for key, value in first.items():
            if key in IDENTITY or key == "type" or isinstance(value, bool):
                continue
            values = [r[key] for r in records]
            metrics[key] = {"median": statistics.median(values), "min": min(values), "max": max(values)}
        result.append({"case": case, "label": label, "type": first["type"],
                       **{k: first[k] for k in IDENTITY if k in first},
                       "samples": len(records), "metrics": metrics})
    return result


def compare(aggregates, threshold, shortfall_tolerance):
    by_key = {(r["case"], r["label"], identity(r)): r for r in aggregates}
    comparisons = []
    for candidate in aggregates:
        if candidate["label"] != "candidate" or candidate.get("path") == "direct":
            continue
        reference = by_key.get((candidate["case"], "reference", identity(candidate)))
        if reference is None:
            continue
        metrics = {
            "UDP_RESULT": {"app_goodput_gbps": "higher"},
            "LOAD_RESULT": {"app_goodput_gbps": "higher", "setup_p95_ms": "lower", "setup_p99_ms": "lower",
                            "load_rtt_p95_us_upper": "lower", "load_rtt_p99_us_upper": "lower"},
            "UDP_LATENCY_RESULT": {"rtt_p95_us": "lower", "rtt_p99_us": "lower"},
            "UDP_LOAD_LATENCY_RESULT": {"load_rtt_p95_us_upper": "lower", "load_rtt_p99_us_upper": "lower"},
            "TCP_DOWNLOAD_SUMMARY": {"masque_transfer_mbps_median": "higher"},
            "SERVER_RESOURCE_RESULT": {"cpu_secs": "lower", "peak_rss_bytes": "lower"},
        }.get(candidate["type"], {})
        insufficient = min(candidate["samples"], reference["samples"]) < 3
        quality_loss = (candidate["metrics"].get("response_shortfall_pct", {}).get("median", 0)
                        - reference["metrics"].get("response_shortfall_pct", {}).get("median", 0))
        if candidate["type"] == "UDP_LOAD_LATENCY_RESULT":
            throughput_identity = ("UDP_RESULT", candidate.get("transport"), candidate.get("path"), candidate.get("payload_bytes"), None)
            a = by_key.get((candidate["case"], "reference", throughput_identity))
            b = by_key.get((candidate["case"], "candidate", throughput_identity))
            if a and b:
                quality_loss = b["metrics"]["response_shortfall_pct"]["median"] - a["metrics"]["response_shortfall_pct"]["median"]
        # Each UDP proxy run has its own direct measurements. Drift in the
        # direct path makes attribution to the server build inconclusive.
        direct_drift = False
        if candidate["type"] == "TCP_DOWNLOAD_SUMMARY":
            a = reference["metrics"].get("direct_transfer_mbps_median", {}).get("median", 0)
            b = candidate["metrics"].get("direct_transfer_mbps_median", {}).get("median", 0)
            direct_drift = a == 0 or abs(b / a - 1) * 100 > threshold
        if candidate.get("path") == "masque":
            direct_type = "UDP_RESULT" if candidate["type"] == "UDP_LOAD_LATENCY_RESULT" else candidate["type"]
            direct_identity = (direct_type, candidate.get("transport"), "direct", candidate.get("payload_bytes"), candidate.get("sample"))
            direct_a = by_key.get((candidate["case"], "reference", direct_identity))
            direct_b = by_key.get((candidate["case"], "candidate", direct_identity))
            direct_metric = "app_goodput_gbps" if direct_type == "UDP_RESULT" else "rtt_p95_us"
            if direct_a and direct_b:
                a = direct_a["metrics"].get(direct_metric, {}).get("median", 0)
                b = direct_b["metrics"].get(direct_metric, {}).get("median", 0)
                direct_drift = a == 0 or abs(b / a - 1) * 100 > threshold
        for metric, direction in metrics.items():
            if metric not in candidate["metrics"] or metric not in reference["metrics"]:
                continue
            a, b = reference["metrics"][metric], candidate["metrics"][metric]
            change = (b["median"] / a["median"] - 1) * 100 if a["median"] else None
            noisy = any(v["median"] == 0 or (v["max"] - v["min"]) / v["median"] * 100 > threshold for v in (a, b))
            reasons = []
            if insufficient:
                reasons.append("insufficient_samples")
            if change is None:
                reasons.append("zero_reference")
            if noisy:
                reasons.append("high_variability")
            if direct_drift:
                reasons.append("direct_control_drift")
            if reasons:
                status = "inconclusive"
            elif quality_loss > shortfall_tolerance:
                status = "regression"
            else:
                benefit = change if direction == "higher" else -change
                status = "regression" if benefit < -threshold else "improvement" if benefit > threshold else "unchanged"
            comparisons.append({"case": candidate["case"], "type": candidate["type"],
                                **{k: candidate[k] for k in IDENTITY if k in candidate},
                                "metric": metric, "change_pct": change, "status": status,
                                "shortfall_increase_pp": quality_loss, "direct_baseline_drift": direct_drift,
                                "insufficient_samples": insufficient, "noisy": noisy,
                                "inconclusive_reasons": reasons})
    return comparisons


def execute(case, label, server, bin_dir, directory, args):
    # Do not let ambient endpoint, interface, authentication, or tuning
    # variables turn a local benchmark into an infrastructure operation.
    environment = {k: v for k, v in os.environ.items() if not k.startswith("MASQUE_")}
    values = {
        "BENCH_BIN_DIR": bin_dir, "BENCH_SERVER_BIN": server,
        "BENCH_RESULTS_DIR": directory, "BENCH_MODE": case["mode"],
        "BENCH_TRANSPORT": case["transport"], "BENCH_SHARDS": case["shards"],
        "BENCH_CC": args.reference_cc if label == "reference" and args.reference_cc else args.cc,
        "BENCH_QUIC_GSO": case.get("quic_gso", 0),
        "BENCH_TARGET_GSO": case.get("target_gso", 0),
        "BENCH_DURATION_SECS": args.duration, "BENCH_WINDOW": args.window,
        "BENCH_EXPIRY_MS": args.expiry_ms, "BENCH_RTT_SAMPLES": args.rtt_samples,
        "TCP_DOWNLOAD_BYTES": args.tcp_bytes, "TCP_DOWNLOAD_REPEATS": 2,
        "LOAD_CONNS": case.get("connections", args.connections), "LOAD_PAYLOAD": 1200,
        "LOAD_DURATION_SECS": args.duration, "LOAD_WINDOW": args.window,
        "LOAD_EXPIRY_MS": args.expiry_ms, "LOAD_WARM_AUTH": 1,
    }
    environment.update({"MASQUE_" + k: str(v) for k, v in values.items()})
    directory.mkdir(mode=0o700)
    log_path = directory / "output.log"
    with log_path.open("w") as log:
        process = subprocess.Popen(["bash", str(ROOT / "scripts/network-bench.sh")], cwd=ROOT,
                                   env=environment, stdout=log, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        try:
            code = process.wait(timeout=max(120, args.duration * 8 + 90))
        except (subprocess.TimeoutExpired, KeyboardInterrupt):
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
            raise
    if code:
        raise ValueError("benchmark workload failed; inspect the private run log")
    records = parse_records(log_path.read_text())
    validate_records(records, case)
    return {"case": case["name"], "label": label, "records": records}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("quick", "standard", "gso", "congestion"), default="standard")
    parser.add_argument("--bin-dir", type=Path, help="prebuilt workspace binaries; skips the build")
    parser.add_argument("--server", type=Path, help="candidate server, defaults to bin-dir/masque-server")
    reference = parser.add_mutually_exclusive_group()
    reference.add_argument("--reference-server", type=Path, help="another compatible MASQUE Server build for alternating A/B runs")
    reference.add_argument("--reference-cc", choices=("cubic", "reno", "bbr2"),
                           help="compare controllers on the same server binary instead of changing the build")
    parser.add_argument("--output", type=Path, help="new private output directory outside the checkout")
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--duration", type=int, default=3)
    parser.add_argument("--window", type=int, default=256)
    parser.add_argument("--expiry-ms", type=int, default=1000)
    parser.add_argument("--rtt-samples", type=int, default=100)
    parser.add_argument("--connections", type=int, default=8)
    parser.add_argument("--tcp-bytes", type=int, default=64 * 1024 * 1024)
    parser.add_argument("--cc", choices=("cubic", "reno", "bbr2"), default="cubic")
    parser.add_argument("--regression-pct", type=float, default=10)
    parser.add_argument("--shortfall-tolerance-pp", type=float, default=1)
    parser.add_argument("--fail-on-regression", action="store_true")
    args = parser.parse_args()
    has_reference = bool(args.reference_server or args.reference_cc)
    if args.reference_cc == args.cc:
        parser.error("choose different candidate and reference controllers")
    if not 1 <= args.rounds <= 9 or not 1 <= args.duration <= 3600:
        parser.error("rounds must be 1..9 and duration 1..3600 seconds")
    if not 1 <= args.window <= 1000 or not 1 <= args.expiry_ms <= 60000 or not 1 <= args.rtt_samples <= 10000:
        parser.error("window, expiry, or RTT sample count is outside the benchmark limits")
    if not 1 <= args.connections <= 128 or not 1 <= args.tcp_bytes <= 16 * 1024**3:
        parser.error("connections must be 1..128 and TCP bytes 1..16 GiB")
    if not 0 < args.regression_pct <= 100 or not 0 <= args.shortfall_tolerance_pp <= 100:
        parser.error("invalid regression threshold")
    if args.fail_on_regression and (not has_reference or args.rounds < 3):
        parser.error("a regression gate requires a reference and at least three rounds")
    if args.profile == "gso" and sys.platform != "linux":
        parser.error("the GSO profile requires Linux")
    output = args.output.resolve() if args.output else Path(tempfile.mkdtemp(prefix="masque-baseline-"))
    if output == ROOT or ROOT in output.parents:
        parser.error("benchmark artifacts must stay outside the checkout")
    if args.output:
        output.mkdir(mode=0o700, parents=True)
    os.chmod(output, 0o700)
    if not args.output:
        print(f"Private report directory: {output}", flush=True)
    if not args.bin_dir:
        subprocess.run(["cargo", "build", "--workspace", "--release", "--locked"], cwd=ROOT, check=True)
    bin_dir = (args.bin_dir or ROOT / "target/release").resolve()
    servers = {"candidate": (args.server or bin_dir / "masque-server").resolve()}
    if has_reference:
        servers["reference"] = args.reference_server.resolve() if args.reference_server else servers["candidate"]
    for path in [*servers.values(), bin_dir / "masque-e2e"]:
        if not path.is_file() or not os.access(path, os.X_OK):
            parser.error("an executable is missing; build the release workspace first")
    labels = ["reference", "candidate"] if has_reference else ["candidate"]
    workloads = cases(args.profile)
    report = {
        "schema_version": 1, "platform": {"os": sys.platform, "arch": platform.machine()},
        "server_sha256": {label: hashlib.sha256(path.read_bytes()).hexdigest() for label, path in servers.items()},
        "client_sha256": hashlib.sha256((bin_dir / "masque-e2e").read_bytes()).hexdigest(),
        "config": {key: getattr(args, key) for key in ("rounds", "duration", "window", "expiry_ms", "rtt_samples", "connections", "tcp_bytes", "cc", "reference_cc", "regression_pct", "shortfall_tolerance_pp")},
        "controllers": {label: args.reference_cc if label == "reference" and args.reference_cc else args.cc for label in labels},
        "cases": workloads, "runs": [], "complete": False,
        "skipped_cases": ([{"name": "load-sharded", "reason": "linux_only"}]
                          if args.profile != "quick" and sys.platform != "linux" else []),
    }
    report_path = output / "report.json"
    report_path.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    for round_number, case, label in schedule(workloads, labels, args.rounds):
        print(f"round={round_number} case={case['name']} build={label}", flush=True)
        directory = output / f"{round_number}-{case['name']}-{label}"
        run = execute(case, label, servers[label], bin_dir, directory, args)
        report["runs"].append({"round": round_number, **run})
        report_path.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    report["aggregates"] = aggregate(report["runs"])
    report["comparisons"] = compare(report["aggregates"], args.regression_pct, args.shortfall_tolerance_pp) if has_reference else []
    report["complete"] = True
    report_path.write_text(json.dumps(report, indent=2, allow_nan=False) + "\n")
    summary = {"completed_runs": len(report["runs"]),
               **{status: sum(c["status"] == status for c in report["comparisons"]) for status in ("regression", "improvement", "unchanged", "inconclusive")}}
    print(json.dumps(summary))
    if args.fail_on_regression:
        if summary["regression"]:
            return 3
        if summary["inconclusive"] or not report["comparisons"]:
            return 4
    return 0


if __name__ == "__main__":
    os.umask(0o077)
    try:
        sys.exit(main())
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        # Raw process output, command arguments, and local paths stay private.
        print(f"Performance baseline failed ({type(error).__name__}); inspect private run logs.", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(130)
