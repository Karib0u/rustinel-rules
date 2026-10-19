#!/usr/bin/env bash
# Atomic test - rule 40109cc2-5bab-4d23-9761-080badad3447
#   "Linux Audit Rules Deleted or Auditing Disabled"  (process_creation)
#
# Copies /bin/sh to a file named auditctl and passes -D; the real audit
# configuration is never touched.
# The shell copy lives under /opt (not world-writable) so the broad
# execution-from-temp rule does not shadow this one. Nothing connects.
set -u
DIR=/opt/rustinel_atomic_auditctl.d
BIN="$DIR/auditctl"
mkdir -p "$DIR" 2>/dev/null || true
cp /bin/sh "$BIN" 2>/dev/null || cp /usr/bin/sh "$BIN" 2>/dev/null || true
chmod 0755 "$BIN" 2>/dev/null || true
timeout 3 "$BIN" -c 'sleep 1; :' -D >/dev/null 2>&1 || true
rm -rf "$DIR" 2>/dev/null || true
exit 0
