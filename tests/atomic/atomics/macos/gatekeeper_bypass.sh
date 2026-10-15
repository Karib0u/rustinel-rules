#!/usr/bin/env bash
# Atomic test — rule 0b4db6de-848b-48e5-bebc-9fc4a2e24db2
#   "Quarantine Attribute Removed via xattr"  (process_creation)
#
# Exercises the `-d` branch of the rule. It stamps the com.apple.quarantine attribute onto a throwaway temp file and then
# deletes it with `xattr -d com.apple.quarantine` — the exact image+argv the
# rule keys on. Only our own temp file is touched; no system state changes.
set -u
F="/tmp/rustinel_atomic_quarantine"
: > "$F"
xattr -w com.apple.quarantine "0083;00000000;Rustinel;" "$F" >/dev/null 2>&1 || true
xattr -d com.apple.quarantine "$F" >/dev/null 2>&1 || true
rm -f "$F" 2>/dev/null || true
exit 0
