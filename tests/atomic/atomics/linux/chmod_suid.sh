#!/usr/bin/env bash
# Atomic test - rule 7a34ffc3-adbc-4d9d-94a4-4bd33ac05cc3
#   "SUID/SGID Bit Added via chmod"  (process_creation)
#
# Copies /bin/sh to a file whose basename is exactly chmod and runs it with a
# u+s command line. The -c body is 'sleep 1; :' — the trailing no-op keeps the
# shell from tail-exec'ing into sleep (which would drop its chmod Image and
# args), so it lives ~1s as chmod for /proc enrichment; no permission bits are
# actually changed.
set -u
# Stage OUTSIDE /tmp: the engine emits one Sigma alert per event (first match
# wins), so a /tmp path would be shadowed by the broad "Execution from
# World-Writable / Temporary Directory" rule. /opt is not world-writable.
DIR=/opt/rustinel_atomic_chmod.d
BIN="$DIR/chmod"
mkdir -p "$DIR" 2>/dev/null || true
cp /bin/sh "$BIN" 2>/dev/null || cp /usr/bin/sh "$BIN" 2>/dev/null || true
chmod 0755 "$BIN" 2>/dev/null || true
timeout 3 "$BIN" -c 'sleep 1; :' u+s /tmp/rustinel_atomic_target >/dev/null 2>&1 || true
rm -rf "$DIR" 2>/dev/null || true
exit 0
