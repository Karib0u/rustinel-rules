#!/usr/bin/env bash
# Atomic test - rule 7a34ffc3-adbc-4d9d-94a4-4bd33ac05cc3
#   "SUID/SGID Bit Added via chmod"  (process_creation)
#
# Runs a copy of the real chmod, named exactly chmod, with the bare +s mode as its
# first argument -- the rule anchors on chmod's positional arguments, so a shell
# copy with a leading -c script no longer has the right shape. To live long
# enough for /proc command-line enrichment it walks a few thousand empty files
# under a private /opt directory (setuid on an empty file is inert), and the
# whole tree is removed afterwards.
set -u
# Stage OUTSIDE /tmp: the engine emits one Sigma alert per event (first match
# wins), so a /tmp path would be shadowed by the broad "Execution from
# World-Writable / Temporary Directory" rule. /opt is not world-writable.
DIR=/opt/rustinel_atomic_chmod_plus_s.d
BIN="$DIR/chmod"
REAL=$(command -v chmod)
mkdir -p "$DIR/tree" 2>/dev/null || true
cp "$REAL" "$BIN" 2>/dev/null || true
for n in $(seq 1 40); do mkdir -p "$DIR/tree/d$n"; done
seq 1 40000 | awk -v d="$DIR/tree" '{print d "/d" ($1 % 40 + 1) "/f" $1}' | xargs touch 2>/dev/null || true
timeout 10 "$BIN" -R +s "$DIR/tree" >/dev/null 2>&1 || true
rm -rf "$DIR" 2>/dev/null || true
exit 0
