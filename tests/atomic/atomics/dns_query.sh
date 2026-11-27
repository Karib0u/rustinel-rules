#!/usr/bin/env bash
# Send one A query over non-loopback UDP, as in the tunnel-service atomics.
# The default name is reserved and uses a valid, 50-byte first label.
set -u
name="${1:-$(printf '%050d' "$RANDOM").rustinel-shape.invalid}"
python3 - "$name" <<'PY' >/dev/null 2>&1 || true
import socket
import struct
import sys
import time

name = sys.argv[1]
labels = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split("."))
packet = (
    struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    + labels
    + b"\x00"
    + struct.pack(">HH", 1, 1)
)
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.settimeout(3)
    sock.sendto(packet, ("1.1.1.1", 53))
    try:
        sock.recvfrom(512)
    except OSError:
        pass
    time.sleep(1)
PY
