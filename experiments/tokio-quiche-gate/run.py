#!/usr/bin/env python3
"""Run each bounded loopback observation in its own process.

Exit 0 means all selected compatibility contracts passed; exit 1 means a
contract is blocked; exit 2 means the harness did not produce valid evidence.
Raw stderr is never included in the sanitized JSON report.
"""

import argparse
import hashlib
import json
import platform
from pathlib import Path
import subprocess
import tempfile


CASES = (
    "stream_control",
    "empty_error",
    "cid16",
    "shutdown_read",
    "shutdown_write",
    "unknown_flow",
    "late_datagram",
    "qsid_empty",
    "qsid_truncated",
    "qsid_out_of_range",
    "event_backlog",
    "raw_cid16",
    "tls_hook",
    "raw_worker_shutdown",
    "retry_privacy",
    "native_datagram_control",
    "blocked_body_fin",
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--case", choices=CASES, action="append")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--socket-build-patch", action="store_true", help="Record the musl dependency build fix in report provenance")
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    report = {
        "schema": 1,
        "scope": "focused_driver_contracts",
        "production_compatibility": "unverified",
        "tokio_quiche": "0.23.0",
        "quiche": "0.30.1",
        "system": platform.system(),
        "architecture": platform.machine(),
        "topology": "loopback",
        "default_features": False,
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "datagram_socket_build_patch": args.socket_build_patch,
        "observations": [],
        "harness_failures": [],
    }
    with tempfile.TemporaryDirectory(prefix="tokio-quiche-gate-") as private:
        for case in args.case or CASES:
            try:
                with (Path(private) / f"{case}.stderr").open("w") as log:
                    run = subprocess.run(
                        [str(binary), case], capture_output=False, stdout=subprocess.PIPE,
                        stderr=log, text=True, timeout=20, check=False,
                    )
                observation = json.loads(run.stdout)
                if (
                    not isinstance(observation, dict)
                    or observation.get("case") != case
                    or type(observation.get("compatible")) is not bool
                    or run.returncode != (0 if observation["compatible"] else 1)
                ):
                    raise ValueError("invalid observation")
                report["observations"].append(observation)
            except (OSError, subprocess.TimeoutExpired, ValueError):
                report["harness_failures"].append(case)
    report["selected_contracts_passed"] = not report["harness_failures"] and all(
        row["compatible"] for row in report["observations"]
    )
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(text)
    print(text, end="")
    return 2 if report["harness_failures"] else (0 if report["selected_contracts_passed"] else 1)


if __name__ == "__main__":
    raise SystemExit(main())
