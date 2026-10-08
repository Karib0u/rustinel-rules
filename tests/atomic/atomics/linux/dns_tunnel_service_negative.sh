#!/usr/bin/env bash
# Negative fixture for rule 300f4d0e-79ef-4c53-9461-7b3f4e468537
# Queries a name that only resembles a tunnel domain. The rule must not alert.
set -u
python3 - <<'PY' >/dev/null 2>&1 || true
import socket, struct, time
name = "rustinel-negative.mytrycloudflare.com"
q = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"
pkt = struct.pack(">HHHHHH", 0x4321, 0x0100, 1, 0, 0, 0) + q + struct.pack(">HH", 1, 1)
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
