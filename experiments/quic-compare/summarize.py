#!/usr/bin/env python3
"""Export only allowlisted, endpoint-free numerical benchmark records."""
import argparse
import json
from pathlib import Path
import statistics


FIELDS = {
    "mode", "server", "client", "repeat", "topology", "seconds", "payload",
    "window", "target_pps", "sent", "received", "shortfall", "invalid",
    "goodput_pps", "goodput_mbps", "rtt_p50_us", "rtt_p95_us", "rtt_p99_us",
    "wall_with_drain", "bytes", "server_cpu", "client_cpu", "server_socket",
    "client_socket",
}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("inputs", nargs="+", type=Path)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--failure-input", action="append", default=[], type=Path)
    args = p.parse_args()
    runs = []
    for path in args.inputs:
        for line in path.read_text().splitlines():
            raw = json.loads(line)
            row = {k: v for k, v in raw.items() if k in FIELDS}
            for side in ("server_socket", "client_socket"):
                row[side] = {k: raw[side][k] for k in ("recv_buffer", "send_buffer")}
            if row["mode"] not in ("stream", "datagram"):
                raise ValueError("unexpected mode")
            if row["server"] not in ("quiche", "quinn") or row["client"] not in ("quiche", "quinn"):
                raise ValueError("unexpected implementation")
            if row["topology"] not in ("mac-local", "linux-local", "mac-linux", "linux-mac"):
                raise ValueError("unexpected topology")
            for k, v in row.items():
                if k not in ("mode", "server", "client", "topology", "server_socket", "client_socket") and not isinstance(v, (int, float)):
                    raise ValueError("non-numerical result")
            runs.append(row)
    failures = []
    for path in args.failure_input:
        for line in path.read_text().splitlines():
            raw = json.loads(line)
            failure = {k: raw[k] for k in ("topology", "mode", "payload", "target_pps", "server", "client", "repeat", "reason")}
            if failure["reason"] not in ("too_many_stream_gaps", "experiment_failed"):
                raise ValueError("unexpected failure reason")
            if failure["topology"] not in ("mac-local", "linux-local", "mac-linux", "linux-mac"):
                raise ValueError("unexpected failure topology")
            if failure["server"] not in ("quiche", "quinn") or failure["client"] not in ("quiche", "quinn"):
                raise ValueError("unexpected failure implementation")
            failures.append(failure)
    groups = {}
    for r in runs:
        key = (r["topology"], r["mode"], r.get("payload", 0), r.get("target_pps", 0), r["server"], r["client"])
        groups.setdefault(key, []).append(r)
    summary = []
    for key, rows in groups.items():
        topology, mode, payload, pps, server, client = key
        x = dict(topology=topology, mode=mode, payload=payload, target_pps=pps,
                 server=server, client=client, repeats=len(rows))
        x["failures"] = sum(
            (f["topology"], f["mode"], f["payload"] if f["mode"] == "datagram" else 0, f["target_pps"], f["server"], f["client"]) == key
            for f in failures
        )
        x["attempts"] = len(rows) + x["failures"]
        for field in ("goodput_mbps", "goodput_pps", "rtt_p50_us", "rtt_p99_us", "server_cpu", "client_cpu"):
            if field in rows[0]:
                values = [r[field] for r in rows]
                x[field] = dict(median=statistics.median(values), minimum=min(values), maximum=max(values))
        if mode == "datagram":
            x["sent"] = sum(r["sent"] for r in rows)
            x["shortfall"] = sum(r["shortfall"] for r in rows)
            x["shortfall_percent"] = 100 * x["shortfall"] / max(x["sent"], 1)
            x["invalid"] = sum(r["invalid"] for r in rows)
        summary.append(x)
    args.output.write_text(json.dumps({"runs": runs, "summary": summary, "failures": failures}, indent=2) + "\n")
    print(json.dumps({"runs": len(runs), "failures": len(failures), "groups": len(summary)}))


if __name__ == "__main__":
    main()
