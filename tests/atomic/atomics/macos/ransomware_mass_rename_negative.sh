#!/usr/bin/env bash
# Negative fixture for rule 90ae463b-19cb-4fd3-9447-dc2222792865
# Renames 60 files to an ordinary .bak extension from one process. The
# correlation must not alert.
set -u
DIR=/tmp/rustinel_negative_mass_rename
python3 - "$DIR" <<'PY' >/dev/null 2>&1 || true
import os, shutil, sys, time
d = sys.argv[1]
os.makedirs(d, exist_ok=True)
for i in range(60):
    with open(os.path.join(d, f"doc{i}.txt"), "w") as f:
        f.write("x")
for i in range(60):
    os.rename(os.path.join(d, f"doc{i}.txt"), os.path.join(d, f"doc{i}.txt.bak"))
time.sleep(2)
shutil.rmtree(d, ignore_errors=True)
PY
rm -rf "$DIR" 2>/dev/null || true
exit 0
