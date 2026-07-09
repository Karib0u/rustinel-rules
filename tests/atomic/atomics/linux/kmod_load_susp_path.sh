#!/usr/bin/env bash
# Atomic test - rule 3f32d825-006a-45e9-b5a9-6e7edeeff13c
#   "Kernel Module Load from Suspicious Path"  (process_creation)
#
# Copies /bin/sh to a file whose basename is exactly insmod and runs it with a
# /tmp module path on the command line. The -c body is 'sleep 1; :' — the
# trailing no-op keeps the shell from tail-exec'ing into sleep (which would drop
# its insmod Image and args), so it lives ~1s as insmod for /proc enrichment;
# no module is loaded.
set -u
# Stage OUTSIDE /tmp: the engine emits one Sigma alert per event (first match
# wins), so a /tmp path would be shadowed by the broad "Execution from
# World-Writable / Temporary Directory" rule. /opt is not world-writable.
DIR=/opt/rustinel_atomic_insmod.d
BIN="$DIR/insmod"
mkdir -p "$DIR" 2>/dev/null || true
cp /bin/sh "$BIN" 2>/dev/null || cp /usr/bin/sh "$BIN" 2>/dev/null || true
chmod 0755 "$BIN" 2>/dev/null || true
timeout 3 "$BIN" -c 'sleep 1; :' /tmp/rustinel_atomic_mod.ko >/dev/null 2>&1 || true
rm -rf "$DIR" 2>/dev/null || true
exit 0
