#!/usr/bin/env bash
# Negative fixture for rule ae619e3b-9950-4cec-89f0-8874c142197b
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
