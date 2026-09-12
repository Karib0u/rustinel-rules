#!/usr/bin/env bash
# Atomic test — rule db01bf97-33ca-4ce4-8ee7-7bbd4b4844f8
#   "Browser Credential Store Targeted on a Command Line"  (process_creation)
#
# Creates a decoy Chrome credential store and copies it. No real browser profile
# is read: the rule keys on the tool plus the targeted path, both of which a
# decoy reproduces exactly.
set -u
DIR="/tmp/rustinel_atomic_browser/Default"
F="$DIR/Login Data"
mkdir -p "$DIR" 2>/dev/null || true
printf 'SQLite format 3\000' > "$F" 2>/dev/null || true
cp "$F" "/tmp/rustinel_atomic_browser/stolen.db" 2>/dev/null || true
sleep 1
rm -rf /tmp/rustinel_atomic_browser 2>/dev/null || true
exit 0
