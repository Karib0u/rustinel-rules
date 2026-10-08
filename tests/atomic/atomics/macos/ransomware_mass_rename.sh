#!/usr/bin/env bash
# Atomic test - rule 90ae463b-19cb-4fd3-9447-dc2222792865
#   "Mass File Rename to Ransomware-Style Extension (macOS)"  (file_rename, event_count)
#
# One python3 process creates 60 files and renames each to .rustinel-locked,
# crossing the correlation threshold (50 in a minute). A single process is
# needed: the correlation groups by process ID, so 60 `mv` invocations would not
# count together.
set -u
DIR=/tmp/rustinel_atomic_mass_rename
python3 - "$DIR" <<'PY' >/dev/null 2>&1 || true
import os, shutil, sys, time
d = sys.argv[1]
os.makedirs(d, exist_ok=True)
for i in range(60):
    with open(os.path.join(d, f"doc{i}.txt"), "w") as f:
        f.write("x")
for i in range(60):
    os.rename(os.path.join(d, f"doc{i}.txt"), os.path.join(d, f"doc{i}.txt.rustinel-locked"))
time.sleep(2)
shutil.rmtree(d, ignore_errors=True)
PY
rm -rf "$DIR" 2>/dev/null || true
exit 0
