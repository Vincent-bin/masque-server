#!/usr/bin/env python3
"""Exercise the real installer prompts inside the disposable Linux runner."""
import errno
import os
import pty
import select
import sys
import time

prompts = [
    (b"Authentication mode", b"1\n"),
    (b"Enable Basic stealth mode?", b"no\n"),
    (b"Certificate choice", b"1\n"),
    (b"Public hostname or IP for certificate", b"proxy.example.com\n"),
    (b"Transport", b"2\n"),
    (b"Public http2 listen port", b"8449\n"),
]
pid, master = pty.fork()
if pid == 0:
    os.execv(sys.argv[1], [sys.argv[1]])

output = bytearray()
position = 0
deadline = time.monotonic() + 90
status = None
terminal_closed = False
try:
    while time.monotonic() < deadline:
        if select.select([master], [], [], 0.1)[0]:
            try:
                chunk = os.read(master, 65536)
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                chunk = b""
            if chunk:
                output.extend(chunk)
                if position < len(prompts) and prompts[position][0] in output:
                    os.write(master, prompts[position][1])
                    position += 1
            else:
                terminal_closed = True
                break
        waited, result = os.waitpid(pid, os.WNOHANG)
        if waited:
            status = result
            break
    if status is None:
        waited, result = os.waitpid(pid, 0 if terminal_closed else os.WNOHANG)
        if waited:
            status = result
    if status is None:
        os.kill(pid, 9)
        os.waitpid(pid, 0)
        raise SystemExit("interactive installer timed out")
    if not os.WIFEXITED(status) or os.WEXITSTATUS(status) != 0:
        raise SystemExit("interactive installer failed")
    if position != len(prompts):
        raise SystemExit(f"interactive installer stopped after prompt {position}")
    if b"Transport: http2 (tcp)" not in output or b"External reachability is unverified" not in output:
        raise SystemExit("interactive connection summary missing")
    if b"BEGIN PRIVATE KEY" in output:
        raise SystemExit("interactive installer printed a private key")
finally:
    os.close(master)
