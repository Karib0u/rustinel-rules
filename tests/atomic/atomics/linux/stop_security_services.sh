#!/usr/bin/env bash
# Atomic test - rule 0cb59840-b420-4332-b7d1-2c3d4343901f
#   "Security Service Stop (auditd / AppArmor / SELinux / EDR)"  (process_creation)
#
# Copies /bin/sh to a file whose basename is exactly systemctl and runs it with a
# "stop auditd" command line. The -c body is 'sleep 1; :' — the trailing no-op
# keeps the shell from tail-exec'ing into sleep (which would drop its systemctl
# Image and args), so it lives ~1s as systemctl for /proc enrichment; no service
# is actually stopped.
set -u
# Stage OUTSIDE /tmp: the engine emits one Sigma alert per event (first match
# wins), so a /tmp path would be shadowed by the broad "Execution from
# World-Writable / Temporary Directory" rule. /opt is not world-writable.
DIR=/opt/rustinel_atomic_systemctl.d
BIN="$DIR/systemctl"
mkdir -p "$DIR" 2>/dev/null || true
cp /bin/sh "$BIN" 2>/dev/null || cp /usr/bin/sh "$BIN" 2>/dev/null || true
chmod 0755 "$BIN" 2>/dev/null || true
timeout 3 "$BIN" -c 'sleep 1; :' stop auditd >/dev/null 2>&1 || true
rm -rf "$DIR" 2>/dev/null || true
exit 0
