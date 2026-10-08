#!/usr/bin/env bash
# Negative fixture for rule b5df6758-24ff-49c0-ba6e-c67760177ddb
# Runs a plain (not set-uid) copy of bash as `nobody`: real and effective UID are
# both unprivileged, so the rule must not alert.
set -u
DIR=/tmp/rustinel_negative_suid
mkdir -p "$DIR" 2>/dev/null || true
chmod 0755 "$DIR" 2>/dev/null || true
cp /bin/bash "$DIR/bash" 2>/dev/null || true
chmod 0755 "$DIR/bash" 2>/dev/null || true
python3 - "$DIR/bash" <<'PY' >/dev/null 2>&1 || true
import os, sys
os.setgid(65534)
os.setuid(65534)
os.execv(sys.argv[1], [sys.argv[1], "-p", "-c", "sleep 2; id"])
PY
rm -rf "$DIR" 2>/dev/null || true
exit 0
