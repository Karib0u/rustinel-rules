#!/usr/bin/env bash
# Atomic test - rule 300f4d0e-79ef-4c53-9461-7b3f4e468537
#   "DNS Query to Tunnel Service (Linux)"  (dns_query)
#
# Sends a single A query for a random trycloudflare.com name straight to
# 1.1.1.1:53 over UDP. The name does not exist; the query is the telemetry.
# Loopback resolvers are skipped on purpose: the sensor drops loopback traffic.
set -u
python3 - rustinel-atomic-$RANDOM.trycloudflare.com <<'PY' >/dev/null 2>&1 || true
import socket, struct, sys, time
name = sys.argv[1]
q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
pkt = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + q + struct.pack(">HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.sendto(pkt, ("1.1.1.1", 53))
try:
    s.recvfrom(512)
except OSError:
    pass
time.sleep(1)
PY
exit 0
