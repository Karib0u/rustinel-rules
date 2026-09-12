#!/usr/bin/env bash
# Atomic test — rule 829cee70-a60f-4e8a-8b2f-38e1fff83e61
#   "TCC Privacy Database Targeted on a Command Line"  (process_creation)
#
# Creates a decoy file named TCC.db in a disposable directory and points a copy
# and a sqlite3 query at it. The real TCC database is never touched: the rule is
# command-line evidence, so a decoy path exercises exactly what it matches.
set -u
DIR=/tmp/rustinel_atomic_tcc
F="$DIR/TCC.db"
mkdir -p "$DIR" 2>/dev/null || true
printf 'SQLite format 3\000' > "$F" 2>/dev/null || true
cp "$F" "$DIR/TCC.db.copy" 2>/dev/null || true
sqlite3 "$F" '.tables' >/dev/null 2>&1 || true
sleep 1
rm -rf "$DIR" 2>/dev/null || true
exit 0
