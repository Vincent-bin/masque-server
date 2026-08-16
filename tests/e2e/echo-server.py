#!/usr/bin/env python3
"""Minimal UDP echo server for E2E testing."""

import socket
import sys

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9999

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("0.0.0.0", PORT))
print(f"UDP echo server listening on 0.0.0.0:{PORT}", flush=True)

while True:
    data, addr = sock.recvfrom(65535)
    sock.sendto(data, addr)
