#!/usr/bin/env python3
"""Minimal TCP and UDP echo server for E2E testing."""

import socket
import sys
import threading

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 9999


def echo_tcp_connection(connection):
    with connection:
        while data := connection.recv(65535):
            connection.sendall(data)


def serve_tcp(listener):
    while True:
        connection, _ = listener.accept()
        threading.Thread(
            target=echo_tcp_connection,
            args=(connection,),
            daemon=True,
        ).start()


tcp_listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp_listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
tcp_listener.bind(("0.0.0.0", PORT))
tcp_listener.listen()

udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp_socket.bind(("0.0.0.0", PORT))

threading.Thread(target=serve_tcp, args=(tcp_listener,), daemon=True).start()
print(f"TCP and UDP echo server listening on 0.0.0.0:{PORT}", flush=True)

while True:
    data, addr = udp_socket.recvfrom(65535)
    udp_socket.sendto(data, addr)
