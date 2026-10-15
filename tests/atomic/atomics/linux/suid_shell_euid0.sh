#!/usr/bin/env bash
# Atomic test - rule b5df6758-24ff-49c0-ba6e-c67760177ddb
#   "Shell Running as Root Through a SUID Binary"  (process_creation)
#
# Copies bash to a temp directory, makes the copy set-uid root, then runs it as
# the unprivileged user `nobody` with -p so it keeps euid 0. The process lives a
# couple of seconds so the sensor can read it. Needs root, like the harness.
set -u
DIR=/tmp/rustinel_atomic_suid
mkdir -p "$DIR" 2>/dev/null || true
chmod 0755 "$DIR" 2>/dev/null || true
cp /bin/bash "$DIR/bash" 2>/dev/null || true
chown root:root "$DIR/bash" 2>/dev/null || true
chmod 4755 "$DIR/bash" 2>/dev/null || true
python3 - "$DIR/bash" <<'PY' >/dev/null 2>&1 || true
import os, sys
os.setgid(65534)
os.setuid(65534)
os.execv(sys.argv[1], [sys.argv[1], "-p", "-c", "sleep 2; id"])
PY
rm -rf "$DIR" 2>/dev/null || true
exit 0
