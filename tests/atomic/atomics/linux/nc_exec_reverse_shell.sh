#!/usr/bin/env bash
# Atomic test - rule 1adaaaca-bfcf-46fe-9bd1-4b475d7bc827
#   "Netcat or Socat Reverse Shell Execution"  (process_creation)
#
# Copies /bin/sh to a file whose basename is exactly nc and runs it with an
# execute-flag command line. The -c body is 'sleep 1; :' — the trailing no-op
# keeps the shell from tail-exec'ing into sleep (which would drop its nc Image
# and args), so it lives ~1s as nc for /proc command-line enrichment; the
# -e /bin/sh tokens are the exact shape the rule keys on. Nothing connects.
set -u
# Stage the renamed copy OUTSIDE /tmp: the engine emits one Sigma alert per
# process event (first match wins), so a /tmp path would be shadowed by the
# broad "Execution from World-Writable / Temporary Directory" rule before this
# rule is reached. /opt is not world-writable, so this rule is the sole match.
DIR=/opt/rustinel_atomic_nc.d
BIN="$DIR/nc"
mkdir -p "$DIR" 2>/dev/null || true
cp /bin/sh "$BIN" 2>/dev/null || cp /usr/bin/sh "$BIN" 2>/dev/null || true
chmod 0755 "$BIN" 2>/dev/null || true
timeout 3 "$BIN" -c 'sleep 1; :' -e /bin/sh >/dev/null 2>&1 || true
rm -rf "$DIR" 2>/dev/null || true
exit 0
