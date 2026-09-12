#!/usr/bin/env bash
# Atomic test - rule d16b52ef-8048-4edd-aafc-50a5a5c3c889
#   "Shell History Destroyed in Place"  (process_creation)
#
# Empties a history file without deleting or renaming it, which is the only
# variant of history tampering that leaves nothing but a command line behind.
# Runs both covered branches: truncate -s 0, and redirecting /dev/null over the
# file. Linux CommandLine is enriched from /proc and can be missed for a very
# short-lived process, so the shell branch (which lives fractionally longer) runs
# as well as the truncate one.
set -u
DIR=/tmp/rustinel_atomic_home
F="$DIR/.bash_history"
mkdir -p "$DIR" 2>/dev/null || true
printf '%s\n' 'id' 'uname -a' > "$F" 2>/dev/null || true
truncate -s 0 "$F" 2>/dev/null || true
sleep 1
printf '%s\n' 'id' > "$F" 2>/dev/null || true
bash -c "cat /dev/null > $DIR/.bash_history" 2>/dev/null || true
sleep 1
rm -rf "$DIR" 2>/dev/null || true
exit 0
