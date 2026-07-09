#!/usr/bin/env bash
# Atomic test - rule 6b124b53-1d4b-48a2-86b7-4df9bf43de61
#   "System Log Clearing (journal and /var/log)"  (process_creation)
#
# Copies /bin/sh to a file whose basename is exactly journalctl and runs it with
# a --vacuum command line. The -c body is 'sleep 1; :' — the trailing no-op keeps
# the shell from tail-exec'ing into sleep (which would drop its journalctl Image
# and args), so it lives ~1s as journalctl for /proc enrichment; no journal is
# actually vacuumed.
set -u
# Stage OUTSIDE /tmp: the engine emits one Sigma alert per event (first match
# wins), so a /tmp path would be shadowed by the broad "Execution from
# World-Writable / Temporary Directory" rule. /opt is not world-writable.
DIR=/opt/rustinel_atomic_journalctl.d
BIN="$DIR/journalctl"
mkdir -p "$DIR" 2>/dev/null || true
cp /bin/sh "$BIN" 2>/dev/null || cp /usr/bin/sh "$BIN" 2>/dev/null || true
chmod 0755 "$BIN" 2>/dev/null || true
timeout 3 "$BIN" -c 'sleep 1; :' --vacuum-size=1M >/dev/null 2>&1 || true
rm -rf "$DIR" 2>/dev/null || true
exit 0
