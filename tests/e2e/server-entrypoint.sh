#!/usr/bin/env bash
set -euo pipefail

# Set up NAT masquerade for the CONNECT-IP TUN subnet so that
# tunnelled traffic can reach the echo server on the Docker network.
iptables -t nat -A POSTROUTING -s 10.89.0.0/16 -o eth0 -j MASQUERADE

exec masque-server "$@"
