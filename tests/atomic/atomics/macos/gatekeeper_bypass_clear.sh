#!/usr/bin/env bash
# Atomic test — rule 0b4db6de-848b-48e5-bebc-9fc4a2e24db2
#   "Quarantine Attribute Removed via xattr"  (process_creation)
#
# Exercises the clear-all branch: stamps com.apple.quarantine onto a throwaway
# temp file, then removes every attribute with `xattr -c`, the form fake
# installers tell victims to paste into Terminal. Only our own temp file is
# touched; no system state changes.
set -u
F="/tmp/rustinel_atomic_quarantine_clear"
: > "$F"
xattr -w com.apple.quarantine "0083;00000000;Rustinel;" "$F" >/dev/null 2>&1 || true
xattr -c "$F" >/dev/null 2>&1 || true
rm -f "$F" 2>/dev/null || true
exit 0
