#!/usr/bin/env python3
"""Run only the benchmark server and collect its own wait4 resource usage."""

import argparse
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--pid-file", type=Path, required=True)
    parser.add_argument("--result-file", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("a server command is required")

    started = time.monotonic()
    child = subprocess.Popen(command)

    def forward(signum, _frame):
        try:
            # Popen.send_signal polls (and may reap) the child; wait4 must be
            # its only reaper or resource accounting can race with shutdown.
            os.kill(child.pid, signum)
        except ProcessLookupError:
            pass

    signal.signal(signal.SIGTERM, forward)
    signal.signal(signal.SIGINT, forward)
    args.pid_file.write_text(str(child.pid))
    _, status, usage = os.wait4(child.pid, 0)
    child.returncode = os.waitstatus_to_exitcode(status)
    elapsed = time.monotonic() - started
    cpu = usage.ru_utime + usage.ru_stime
    # Darwin reports bytes; Linux reports KiB. This is server-only peak RSS,
    # not the combined server/client/echo resource usage of the shell script.
    peak_bytes = int(usage.ru_maxrss * (1 if sys.platform == "darwin" else 1024))
    args.result_file.write_text(
        f"SERVER_RESOURCE_RESULT wall_secs={elapsed:.6f} "
        f"user_cpu_secs={usage.ru_utime:.6f} system_cpu_secs={usage.ru_stime:.6f} "
        f"cpu_secs={cpu:.6f} cpu_percent={cpu / max(elapsed, 1e-9) * 100:.3f} "
        f"peak_rss_bytes={peak_bytes}\n"
    )
    return child.returncode if child.returncode >= 0 else 128 - child.returncode


if __name__ == "__main__":
    sys.exit(main())
