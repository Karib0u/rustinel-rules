#!/usr/bin/env bash
# Atomic test - rule 7a34ffc3-adbc-4d9d-94a4-4bd33ac05cc3
#   "SUID/SGID Bit Added via chmod"  (process_creation)
#
# Same shape as chmod_suid.sh, but with the bare "+s" mode (chmod +s /bin/bash),
# which carries no u/g prefix. Copies /bin/sh to a file whose basename is exactly
# chmod; the -c body 'sleep 1; :' keeps it alive ~1s for /proc enrichment and
# the trailing tokens are inert. No permission bits are changed.
set -u
# Stage OUTSIDE /tmp so the broad temporary-directory execution rule does not
# take the event first.
DIR=/opt/rustinel_atomic_chmod_plus_s.d
BIN="$DIR/chmod"
mkdir -p "$DIR" 2>/dev/null || true
cp /bin/sh "$BIN" 2>/dev/null || cp /usr/bin/sh "$BIN" 2>/dev/null || true
chmod 0755 "$BIN" 2>/dev/null || true
timeout 3 "$BIN" -c 'sleep 1; :' +s /tmp/rustinel_atomic_target >/dev/null 2>&1 || true
rm -rf "$DIR" 2>/dev/null || true
exit 0
