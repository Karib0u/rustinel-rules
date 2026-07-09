#!/usr/bin/env bash
# Atomic test - rule 1adaaaca-bfcf-46fe-9bd1-4b475d7bc827
#   "Netcat or Socat Reverse Shell Execution"  (process_creation)
#
# Copies /bin/sh to a file whose basename is exactly nc and runs it with an
# execute-flag command line. The copied shell runs a harmless 'sleep 1' (via -c)
# so it lives long enough for /proc command-line enrichment; the -e /bin/sh
# tokens are the exact shape the rule keys on. Nothing connects anywhere.
set -u
DIR=/tmp/rustinel_atomic_nc.d
BIN="$DIR/nc"
mkdir -p "$DIR" 2>/dev/null || true
cp /bin/sh "$BIN" 2>/dev/null || cp /usr/bin/sh "$BIN" 2>/dev/null || true
chmod 0755 "$BIN" 2>/dev/null || true
timeout 3 "$BIN" -c 'sleep 1' -e /bin/sh >/dev/null 2>&1 || true
rm -rf "$DIR" 2>/dev/null || true
exit 0
